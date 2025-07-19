import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import Redis from 'ioredis';
import { MobileCredential, OfflineCredentialData } from '../types/schemas';
import { BLEProtocolHandler } from '../protocols/ble-handler';
import { NFCProtocolHandler } from '../protocols/nfc-handler';
import { BLEProtocolConfig, NFCProtocolConfig } from '../types';

export class CredentialService {
  private prisma: PrismaClient;
  private redis: Redis;
  private config: any;
  private bleHandler: BLEProtocolHandler | null = null;
  private nfcHandler: NFCProtocolHandler | null = null;

  constructor(prisma: PrismaClient, redis: Redis, config: any) {
    this.prisma = prisma;
    this.redis = redis;
    this.config = config;
  }

  async enrollCredential(enrollmentData: any, userId: string, tenantId: string): Promise<any> {
    // Generate cryptographic keys
    const { publicKey, privateKey } = this.generateKeyPair();
    
    // Create credential record
    const credential = await this.prisma.mobileCredential.create({
      data: {
        userId,
        tenantId,
        deviceInfo: enrollmentData.deviceInfo,
        publicKey,
        encryptedPrivateKey: this.encryptPrivateKey(privateKey),
        credentialType: enrollmentData.credentialData.type,
        format: enrollmentData.credentialData.format,
        issuer: enrollmentData.credentialData.issuer,
        issuedAt: new Date(),
        expiresAt: enrollmentData.credentialData.expiresAt ? new Date(enrollmentData.credentialData.expiresAt) : null,
        status: 'pending_activation',
        protocolSettings: enrollmentData.protocolSettings,
        biometricSettings: enrollmentData.biometricSettings,
        meshNetworkEnabled: enrollmentData.meshNetworkEnabled ?? true,
        metadata: {}
      }
    });

    // Initialize protocol handlers if enabled
    if (enrollmentData.protocolSettings?.ble?.enabled) {
      await this.initializeBLEHandler(enrollmentData.protocolSettings.ble.config, credential);
    }
    
    if (enrollmentData.protocolSettings?.nfc?.enabled) {
      await this.initializeNFCHandler(enrollmentData.protocolSettings.nfc.config, credential);
    }

    // Cache credential for offline access
    await this.cacheCredentialForOffline(credential);

    // Create enrollment token
    const enrollmentToken = this.generateEnrollmentToken(credential.id);

    // Log enrollment event
    await this.logEvent('credential_enrolled', {
      credentialId: credential.id,
      userId,
      tenantId,
      deviceInfo: enrollmentData.deviceInfo
    });

    return {
      credentialId: credential.id,
      enrollmentToken,
      publicKey,
      activationRequired: true,
      protocolsEnabled: {
        ble: enrollmentData.protocolSettings?.ble?.enabled ?? false,
        nfc: enrollmentData.protocolSettings?.nfc?.enabled ?? false
      }
    };
  }

  async authenticateCredential(authData: any): Promise<{ valid: boolean; details: any }> {
    // Try cache first for offline capability
    let credential = await this.getCredentialFromCache(authData.credentialId);
    
    if (!credential) {
      credential = await this.prisma.mobileCredential.findUnique({
        where: { id: authData.credentialId },
        include: { user: true, accessGroups: true }
      });
      
      if (!credential) {
        return { valid: false, details: { error: 'Credential not found' } };
      }
    }

    // Validate credential status
    if (credential.status !== 'active') {
      return { valid: false, details: { error: `Credential is ${credential.status}` } };
    }

    // Validate expiry
    if (credential.expiresAt && new Date() > credential.expiresAt) {
      return { valid: false, details: { error: 'Credential expired' } };
    }

    // Protocol-specific validation
    let validationResult = { valid: false, details: {} };
    
    if (authData.protocol === 'ble' && authData.protocolSpecific?.bleData) {
      validationResult = await this.validateBLEAuthentication(authData, credential);
    } else if (authData.protocol === 'nfc' && authData.protocolSpecific?.nfcData) {
      validationResult = await this.validateNFCAuthentication(authData, credential);
    } else if (authData.offlineValidation) {
      validationResult = await this.validateOfflineAuthentication(authData, credential);
    } else {
      // Standard cryptographic validation
      validationResult = await this.validateCryptographicAuth(authData, credential);
    }

    if (validationResult.valid) {
      // Log successful authentication
      await this.logEvent('credential_authenticated', {
        credentialId: credential.id,
        userId: credential.userId,
        tenantId: credential.tenantId,
        protocol: authData.protocol,
        timestamp: new Date()
      });

      // Update last used timestamp
      await this.updateLastUsed(credential.id);
    }

    return validationResult;
  }

  async revokeCredentials(credentialIds: string[], reason: string, options: any): Promise<void> {
    // Update credential status
    await this.prisma.mobileCredential.updateMany({
      where: { id: { in: credentialIds } },
      data: {
        status: 'revoked',
        revokedAt: new Date(),
        revokedReason: reason
      }
    });

    // Remove from cache
    for (const credentialId of credentialIds) {
      await this.redis.del(`credential:${credentialId}`);
      await this.redis.del(`offline_credential:${credentialId}`);
    }

    // Add to revocation list
    const revocationListKey = 'revoked_credentials';
    for (const credentialId of credentialIds) {
      await this.redis.sadd(revocationListKey, credentialId);
    }

    // Log revocation events
    for (const credentialId of credentialIds) {
      await this.logEvent('credential_revoked', {
        credentialId,
        reason,
        remoteWipe: options.remoteWipe,
        timestamp: new Date()
      });
    }
  }

  private async initializeBLEHandler(config: BLEProtocolConfig, credential: any): Promise<void> {
    this.bleHandler = new BLEProtocolHandler(config, console);
    const peripheralConfig = await this.bleHandler.initializePeripheral(credential);
    
    // Store BLE configuration
    await this.redis.set(
      `ble_config:${credential.id}`,
      JSON.stringify(peripheralConfig),
      'EX',
      86400 // 24 hours
    );
  }

  private async initializeNFCHandler(config: NFCProtocolConfig, credential: any): Promise<void> {
    this.nfcHandler = new NFCProtocolHandler(config, console);
    const nfcTagConfig = await this.nfcHandler.initializeNFCTag(credential);
    
    // Store NFC configuration
    await this.redis.set(
      `nfc_config:${credential.id}`,
      JSON.stringify(nfcTagConfig),
      'EX',
      86400 // 24 hours
    );
  }

  private async cacheCredentialForOffline(credential: any): Promise<void> {
    const offlineData: OfflineCredentialData = {
      credentialId: credential.id,
      userId: credential.userId,
      tenantId: credential.tenantId,
      publicKey: credential.publicKey,
      encryptedPrivateKey: credential.encryptedPrivateKey,
      accessGroups: credential.accessGroups?.map((g: any) => g.id) || [],
      validFrom: credential.issuedAt,
      validUntil: credential.expiresAt || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      lastSyncTime: new Date(),
      cryptographicProof: this.generateCryptographicProof(credential.id, credential.tenantId)
    };

    await this.redis.set(
      `offline_credential:${credential.id}`,
      JSON.stringify(offlineData),
      'EX',
      604800 // 7 days
    );
  }

  private async getCredentialFromCache(credentialId: string): Promise<any> {
    const cached = await this.redis.get(`offline_credential:${credentialId}`);
    return cached ? JSON.parse(cached) : null;
  }

  private async validateBLEAuthentication(authData: any, credential: any): Promise<{ valid: boolean; details: any }> {
    const bleData = authData.protocolSpecific.bleData;
    
    // Validate RSSI range
    if (bleData.rssi < -100 || bleData.rssi > 0) {
      return { valid: false, details: { error: 'Invalid RSSI value' } };
    }

    // Validate signature
    const isValid = this.verifySignature(authData.signature, authData.credentialId, authData.challenge, authData.timestamp, credential.publicKey);
    
    return {
      valid: isValid,
      details: {
        protocol: 'ble',
        rssi: bleData.rssi,
        connectionId: bleData.connectionId
      }
    };
  }

  private async validateNFCAuthentication(authData: any, credential: any): Promise<{ valid: boolean; details: any }> {
    const nfcData = authData.protocolSpecific.nfcData;
    
    // Validate technology compatibility
    const supportedTech = credential.protocolSettings?.nfc?.config?.technology;
    if (supportedTech && supportedTech !== nfcData.technology) {
      return { valid: false, details: { error: 'Incompatible NFC technology' } };
    }

    // Validate signature
    const isValid = this.verifySignature(authData.signature, authData.credentialId, authData.timestamp, null, credential.publicKey);
    
    return {
      valid: isValid,
      details: {
        protocol: 'nfc',
        technology: nfcData.technology,
        uid: nfcData.uid
      }
    };
  }

  private async validateOfflineAuthentication(authData: any, credential: any): Promise<{ valid: boolean; details: any }> {
    const offlineData = authData.offlineValidation;
    
    // Verify cryptographic proof
    const expectedProof = this.generateCryptographicProof(credential.credentialId || credential.id, credential.tenantId);
    if (offlineData.cryptographicProof !== expectedProof) {
      return { valid: false, details: { error: 'Invalid cryptographic proof' } };
    }

    // Check sequence number to prevent replay
    const lastSequence = await this.redis.get(`offline_sequence:${credential.id}`);
    if (lastSequence && parseInt(lastSequence) >= offlineData.sequenceNumber) {
      return { valid: false, details: { error: 'Invalid sequence number' } };
    }

    await this.redis.set(`offline_sequence:${credential.id}`, offlineData.sequenceNumber);

    return {
      valid: true,
      details: {
        offline: true,
        timestamp: offlineData.localTimestamp
      }
    };
  }

  private async validateCryptographicAuth(authData: any, credential: any): Promise<{ valid: boolean; details: any }> {
    const isValid = this.verifySignature(
      authData.signature,
      authData.credentialId,
      authData.challenge,
      authData.timestamp,
      credential.publicKey
    );

    return {
      valid: isValid,
      details: {
        protocol: 'standard',
        timestamp: authData.timestamp
      }
    };
  }

  private generateKeyPair(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
  }

  private encryptPrivateKey(privateKey: string): string {
    const cipher = crypto.createCipher('aes-256-cbc', this.config.encryptionKey);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private generateEnrollmentToken(credentialId: string): string {
    return jwt.sign(
      { credentialId, type: 'enrollment' },
      this.config.jwtSecret,
      { expiresIn: '1h' }
    );
  }

  private generateCryptographicProof(credentialId: string, tenantId: string): string {
    const data = `${credentialId}:${tenantId}:${Date.now()}`;
    return crypto.createHmac('sha256', this.config.encryptionKey)
      .update(data)
      .digest('hex');
  }

  private verifySignature(signature: string, credentialId: string, challenge: string, timestamp: string, publicKey: string): boolean {
    try {
      const dataToVerify = `${credentialId}:${challenge}:${timestamp}`;
      const verify = crypto.createVerify('SHA256');
      verify.update(dataToVerify);
      return verify.verify(publicKey, signature, 'hex');
    } catch (error) {
      return false;
    }
  }

  private async updateLastUsed(credentialId: string): Promise<void> {
    await this.prisma.mobileCredential.update({
      where: { id: credentialId },
      data: { lastUsedAt: new Date() }
    });
  }

  private async logEvent(eventType: string, data: any): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        eventType,
        entityType: 'mobile_credential',
        entityId: data.credentialId,
        userId: data.userId,
        tenantId: data.tenantId,
        metadata: data,
        ipAddress: data.ipAddress || null,
        userAgent: data.userAgent || null
      }
    });
  }
}