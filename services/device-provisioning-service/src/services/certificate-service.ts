import { db } from '@db/client';
import Redis from 'ioredis';
import { 
  deviceCertificates,
  certificateTemplates,
  certificateRevocationList,
  type DeviceCertificate,
  type CertificateTemplate,
  type NewDeviceCertificate
} from '@db/schemas/device-provisioning';
import { eq, and, gte, lte, desc, isNull } from 'drizzle-orm';
import * as forge from 'node-forge';
import * as crypto from 'crypto';
import { z } from 'zod';

interface CertificateOptions {
  deviceType: string;
  manufacturer: string;
  model: string;
  validityDays?: number;
  keySize?: number;
  extensions?: Record<string, any>;
}

interface CertificateGenerationResult {
  id: string;
  certificate: string;
  privateKey: string;
  publicKey: string;
  fingerprint: string;
  serialNumber: string;
  expiresAt: Date;
}

interface CertificateValidationResult {
  valid: boolean;
  reason?: string;
  details?: {
    expired?: boolean;
    revoked?: boolean;
    untrusted?: boolean;
    invalidSignature?: boolean;
  };
}

const CertificateSubjectSchema = z.object({
  commonName: z.string(),
  organizationalUnit: z.string().optional(),
  organization: z.string(),
  locality: z.string().optional(),
  state: z.string().optional(),
  country: z.string().length(2).optional()
});

export class CertificateService {
  private rootCA?: forge.pki.Certificate;
  private rootCAKey?: forge.pki.rsa.PrivateKey;

  constructor(
    private db: typeof db,
    private redis: Redis
  ) {
    this.initializeRootCA();
  }

  // Initialize root CA (in production, load from HSM or secure storage)
  private async initializeRootCA(): Promise<void> {
    try {
      // Check if root CA exists in database
      const [existingRoot] = await this.db
        .select()
        .from(deviceCertificates)
        .where(and(
          eq(deviceCertificates.certificateType, 'root'),
          eq(deviceCertificates.status, 'active')
        ))
        .limit(1);

      if (existingRoot) {
        // Load existing root CA
        this.rootCA = forge.pki.certificateFromPem(existingRoot.publicKey);
        // In production, load private key from secure storage
        // this.rootCAKey = await this.loadPrivateKeyFromSecureStorage(existingRoot.privateKeyPath);
      } else {
        // Generate new root CA (only in development/initial setup)
        await this.generateRootCA();
      }
    } catch (error) {
      console.error('Failed to initialize root CA:', error);
    }
  }

  // Generate root CA certificate
  private async generateRootCA(): Promise<void> {
    const keys = forge.pki.rsa.generateKeyPair(4096);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = this.generateSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

    const attrs = [
      { name: 'commonName', value: 'SPARC Root CA' },
      { name: 'organizationName', value: 'SPARC Security Platform' },
      { name: 'countryName', value: 'US' }
    ];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: true,
        critical: true
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        cRLSign: true,
        critical: true
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ]);

    // Self-sign the root certificate
    cert.sign(keys.privateKey, forge.md.sha256.create());

    this.rootCA = cert;
    this.rootCAKey = keys.privateKey;

    // Store in database (in production, store private key in HSM)
    const [savedCert] = await this.db.insert(deviceCertificates).values({
      tenantId: 'system', // System-wide root CA
      deviceId: 'root-ca',
      certificateType: 'root',
      status: 'active',
      serialNumber: cert.serialNumber,
      fingerprint: this.calculateFingerprint(cert),
      publicKey: forge.pki.certificateToPem(cert),
      privateKeyPath: 'hsm://root-ca-key', // Reference to HSM
      subject: {
        commonName: 'SPARC Root CA',
        organization: 'SPARC Security Platform',
        country: 'US'
      },
      extensions: {
        basicConstraints: { cA: true },
        keyUsage: ['keyCertSign', 'digitalSignature', 'nonRepudiation', 'cRLSign']
      },
      issuedAt: cert.validity.notBefore,
      expiresAt: cert.validity.notAfter
    }).returning();
  }

  // Generate device certificate
  async generateDeviceCertificate(
    tenantId: string,
    deviceSerialNumber: string,
    options: CertificateOptions
  ): Promise<CertificateGenerationResult | null> {
    try {
      if (!this.rootCA || !this.rootCAKey) {
        throw new Error('Root CA not initialized');
      }

      // Get certificate template if available
      const template = await this.getCertificateTemplate(tenantId, options.deviceType);
      const validityDays = options.validityDays || template?.validityDays || 365;
      const keySize = options.keySize || template?.keySize || 2048;

      // Generate key pair
      const keys = forge.pki.rsa.generateKeyPair(keySize);
      const cert = forge.pki.createCertificate();

      cert.publicKey = keys.publicKey;
      cert.serialNumber = this.generateSerialNumber();
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + validityDays);

      // Set subject
      const subject = [
        { name: 'commonName', value: `device-${deviceSerialNumber}` },
        { name: 'organizationalUnitName', value: options.deviceType },
        { name: 'organizationName', value: `Tenant-${tenantId}` },
        { name: 'serialNumber', value: deviceSerialNumber }
      ];

      cert.setSubject(subject);
      cert.setIssuer(this.rootCA.subject.attributes);

      // Set extensions
      const extensions = [
        {
          name: 'basicConstraints',
          cA: false,
          critical: true
        },
        {
          name: 'keyUsage',
          digitalSignature: true,
          keyEncipherment: true,
          critical: true
        },
        {
          name: 'extKeyUsage',
          clientAuth: true,
          '1.3.6.1.5.5.7.3.28': true // IoT device authentication
        },
        {
          name: 'subjectAltName',
          altNames: [
            { type: 2, value: `device-${deviceSerialNumber}.sparc.local` },
            { type: 7, value: options.deviceType }
          ]
        },
        {
          name: 'subjectKeyIdentifier'
        },
        {
          name: 'authorityKeyIdentifier',
          keyIdentifier: true,
          authorityCertIssuer: true,
          serialNumber: this.rootCA.serialNumber
        }
      ];

      // Add custom extensions from template or options
      if (template?.extensions || options.extensions) {
        // Merge custom extensions
      }

      cert.setExtensions(extensions);

      // Sign with root CA
      cert.sign(this.rootCAKey, forge.md.sha256.create());

      // Calculate fingerprint
      const fingerprint = this.calculateFingerprint(cert);

      // Store private key securely (in production, use HSM or key vault)
      const privateKeyPath = await this.storePrivateKey(
        tenantId,
        deviceSerialNumber,
        forge.pki.privateKeyToPem(keys.privateKey)
      );

      // Save to database
      const [savedCert] = await this.db.insert(deviceCertificates).values({
        tenantId,
        deviceId: deviceSerialNumber,
        certificateType: 'device',
        status: 'active',
        serialNumber: cert.serialNumber,
        fingerprint,
        publicKey: forge.pki.certificateToPem(cert),
        privateKeyPath,
        issuerCertificateId: 'root-ca', // Should be the actual root CA ID
        subject: {
          commonName: `device-${deviceSerialNumber}`,
          organizationalUnit: options.deviceType,
          organization: `Tenant-${tenantId}`,
          serialNumber: deviceSerialNumber
        },
        extensions: {
          keyUsage: ['digitalSignature', 'keyEncipherment'],
          extKeyUsage: ['clientAuth', 'iotDevice'],
          subjectAltName: [`device-${deviceSerialNumber}.sparc.local`]
        },
        issuedAt: cert.validity.notBefore,
        expiresAt: cert.validity.notAfter
      }).returning();

      // Cache certificate for quick access
      await this.cacheCertificate(savedCert);

      return {
        id: savedCert.id,
        certificate: forge.pki.certificateToPem(cert),
        privateKey: forge.pki.privateKeyToPem(keys.privateKey),
        publicKey: forge.pki.publicKeyToPem(keys.publicKey),
        fingerprint,
        serialNumber: cert.serialNumber,
        expiresAt: cert.validity.notAfter
      };
    } catch (error) {
      console.error('Failed to generate device certificate:', error);
      return null;
    }
  }

  // Validate certificate
  async validateCertificate(
    certificatePem: string,
    options?: {
      checkRevocation?: boolean;
      checkExpiry?: boolean;
      verifyChain?: boolean;
    }
  ): Promise<CertificateValidationResult> {
    try {
      const cert = forge.pki.certificateFromPem(certificatePem);
      const result: CertificateValidationResult = {
        valid: true,
        details: {}
      };

      // Check expiry
      if (options?.checkExpiry !== false) {
        const now = new Date();
        if (now < cert.validity.notBefore || now > cert.validity.notAfter) {
          result.valid = false;
          result.reason = 'Certificate expired or not yet valid';
          result.details!.expired = true;
        }
      }

      // Check revocation
      if (options?.checkRevocation !== false) {
        const isRevoked = await this.isCertificateRevoked(cert.serialNumber);
        if (isRevoked) {
          result.valid = false;
          result.reason = 'Certificate has been revoked';
          result.details!.revoked = true;
        }
      }

      // Verify chain
      if (options?.verifyChain !== false && this.rootCA) {
        try {
          const caStore = forge.pki.createCaStore([this.rootCA]);
          forge.pki.verifyCertificateChain(caStore, [cert]);
        } catch (error) {
          result.valid = false;
          result.reason = 'Certificate chain validation failed';
          result.details!.untrusted = true;
        }
      }

      return result;
    } catch (error) {
      return {
        valid: false,
        reason: 'Invalid certificate format',
        details: { invalidSignature: true }
      };
    }
  }

  // Revoke certificate
  async revokeCertificate(
    certificateId: string,
    tenantId: string,
    reason: string,
    revokedBy: string
  ): Promise<boolean> {
    try {
      // Get certificate
      const [cert] = await this.db
        .select()
        .from(deviceCertificates)
        .where(and(
          eq(deviceCertificates.id, certificateId),
          eq(deviceCertificates.tenantId, tenantId)
        ));

      if (!cert) return false;

      // Update certificate status
      await this.db
        .update(deviceCertificates)
        .set({
          status: 'revoked',
          revokedAt: new Date(),
          revocationReason: reason,
          updatedAt: new Date()
        })
        .where(eq(deviceCertificates.id, certificateId));

      // Add to revocation list
      await this.db.insert(certificateRevocationList).values({
        tenantId,
        certificateId,
        serialNumber: cert.serialNumber,
        reason,
        revokedBy
      });

      // Update cache
      await this.redis.setex(
        `cert:revoked:${cert.serialNumber}`,
        86400 * 30, // 30 days
        JSON.stringify({ revoked: true, reason, date: new Date() })
      );

      // Remove from active certificate cache
      await this.redis.del(`cert:${cert.fingerprint}`);

      return true;
    } catch (error) {
      console.error('Failed to revoke certificate:', error);
      return false;
    }
  }

  // Renew certificate
  async renewCertificate(
    certificateId: string,
    tenantId: string,
    additionalDays?: number
  ): Promise<CertificateGenerationResult | null> {
    try {
      // Get existing certificate
      const [existingCert] = await this.db
        .select()
        .from(deviceCertificates)
        .where(and(
          eq(deviceCertificates.id, certificateId),
          eq(deviceCertificates.tenantId, tenantId)
        ));

      if (!existingCert || existingCert.status === 'revoked') {
        return null;
      }

      // Generate new certificate with same subject
      const subject = existingCert.subject as any;
      const options: CertificateOptions = {
        deviceType: subject.organizationalUnit || 'generic',
        manufacturer: 'unknown',
        model: 'unknown',
        validityDays: additionalDays
      };

      const newCert = await this.generateDeviceCertificate(
        tenantId,
        existingCert.deviceId,
        options
      );

      if (newCert) {
        // Mark old certificate as expired
        await this.db
          .update(deviceCertificates)
          .set({
            status: 'expired',
            updatedAt: new Date()
          })
          .where(eq(deviceCertificates.id, certificateId));
      }

      return newCert;
    } catch (error) {
      console.error('Failed to renew certificate:', error);
      return null;
    }
  }

  // Get certificates expiring soon
  async getExpiringCertificates(
    tenantId: string,
    daysAhead: number = 30
  ): Promise<DeviceCertificate[]> {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + daysAhead);

    return await this.db
      .select()
      .from(deviceCertificates)
      .where(and(
        eq(deviceCertificates.tenantId, tenantId),
        eq(deviceCertificates.status, 'active'),
        lte(deviceCertificates.expiresAt, expiryDate)
      ))
      .orderBy(deviceCertificates.expiresAt);
  }

  // Get certificate by fingerprint
  async getCertificateByFingerprint(
    fingerprint: string,
    tenantId?: string
  ): Promise<DeviceCertificate | null> {
    // Check cache first
    const cached = await this.redis.get(`cert:${fingerprint}`);
    if (cached) {
      return JSON.parse(cached);
    }

    const conditions = [eq(deviceCertificates.fingerprint, fingerprint)];
    if (tenantId) {
      conditions.push(eq(deviceCertificates.tenantId, tenantId));
    }

    const [cert] = await this.db
      .select()
      .from(deviceCertificates)
      .where(and(...conditions));

    if (cert) {
      await this.cacheCertificate(cert);
    }

    return cert || null;
  }

  // Private helper methods
  private generateSerialNumber(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private calculateFingerprint(cert: forge.pki.Certificate): string {
    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
    const md = forge.md.sha256.create();
    md.update(der.getBytes());
    return md.digest().toHex();
  }

  private async storePrivateKey(
    tenantId: string,
    deviceId: string,
    privateKeyPem: string
  ): Promise<string> {
    // In production, store in HSM or secure key vault
    // For now, encrypt and store in Redis
    const keyId = `key:${tenantId}:${deviceId}:${crypto.randomBytes(8).toString('hex')}`;
    
    // Encrypt private key
    const cipher = crypto.createCipher('aes-256-gcm', process.env.ENCRYPTION_KEY || 'default-key');
    const encrypted = cipher.update(privateKeyPem, 'utf8', 'hex') + cipher.final('hex');
    
    await this.redis.setex(keyId, 86400 * 365, encrypted); // 1 year
    
    return keyId;
  }

  private async getCertificateTemplate(
    tenantId: string,
    deviceType: string
  ): Promise<CertificateTemplate | null> {
    const [template] = await this.db
      .select()
      .from(certificateTemplates)
      .where(and(
        eq(certificateTemplates.tenantId, tenantId),
        eq(certificateTemplates.certificateType, 'device'),
        eq(certificateTemplates.active, true)
      ))
      .orderBy(desc(certificateTemplates.createdAt))
      .limit(1);

    return template || null;
  }

  private async isCertificateRevoked(serialNumber: string): Promise<boolean> {
    // Check cache first
    const cached = await this.redis.get(`cert:revoked:${serialNumber}`);
    if (cached) {
      return true;
    }

    // Check database
    const [revoked] = await this.db
      .select()
      .from(certificateRevocationList)
      .where(eq(certificateRevocationList.serialNumber, serialNumber))
      .limit(1);

    return !!revoked;
  }

  private async cacheCertificate(cert: DeviceCertificate): Promise<void> {
    await this.redis.setex(
      `cert:${cert.fingerprint}`,
      3600, // 1 hour
      JSON.stringify(cert)
    );
  }

  // OCSP responder endpoint data
  async getOCSPResponse(serialNumber: string): Promise<{
    status: 'good' | 'revoked' | 'unknown';
    revokedAt?: Date;
    reason?: string;
  }> {
    const isRevoked = await this.isCertificateRevoked(serialNumber);
    
    if (isRevoked) {
      const [revocation] = await this.db
        .select()
        .from(certificateRevocationList)
        .where(eq(certificateRevocationList.serialNumber, serialNumber))
        .limit(1);

      return {
        status: 'revoked',
        revokedAt: revocation?.revocationDate,
        reason: revocation?.reason
      };
    }

    // Check if certificate exists
    const [cert] = await this.db
      .select()
      .from(deviceCertificates)
      .where(eq(deviceCertificates.serialNumber, serialNumber))
      .limit(1);

    return {
      status: cert ? 'good' : 'unknown'
    };
  }
}