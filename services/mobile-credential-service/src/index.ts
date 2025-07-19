import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { EventEmitter } from 'events';
import * as dgram from 'dgram';
import * as net from 'net';
import { promisify } from 'util';

// Enhanced types and schemas for BLE/NFC protocols and mesh networking
interface BLEProtocolConfig {
  serviceUuid: string;
  characteristicUuid: string;
  advertisementInterval: number;
  connectionTimeout: number;
  powerLevel: 'low' | 'medium' | 'high';
  securityLevel: 'none' | 'encrypted' | 'authenticated';
}

interface NFCProtocolConfig {
  technology: 'iso14443a' | 'iso14443b' | 'iso15693' | 'felica';
  dataFormat: 'ndef' | 'raw';
  maxDataSize: number;
  readTimeout: number;
  writeTimeout: number;
  securityFeatures: string[];
}

interface MeshNetworkConfig {
  nodeId: string;
  networkKey: Buffer;
  multicastAddress: string;
  multicastPort: number;
  heartbeatInterval: number;
  propagationTimeout: number;
  maxHops: number;
}

interface BiometricConfig {
  enabled: boolean;
  types: ('fingerprint' | 'face' | 'voice' | 'iris')[];
  fallbackToPin: boolean;
  maxAttempts: number;
  lockoutDuration: number;
}

interface PowerManagementConfig {
  lowBatteryThreshold: number;
  criticalBatteryThreshold: number;
  powerSavingMode: boolean;
  backgroundSyncInterval: number;
  reducedFunctionalityMode: boolean;
}

interface DeviceManagementConfig {
  remoteWipeEnabled: boolean;
  deviceLockEnabled: boolean;
  locationTrackingEnabled: boolean;
  complianceCheckInterval: number;
  certificateValidationEnabled: boolean;
}

interface MeshMessage {
  id: string;
  type: 'credential_revocation' | 'device_wipe' | 'status_update' | 'heartbeat' | 'sync_request';
  sourceDeviceId: string;
  targetDeviceId?: string;
  tenantId: string;
  payload: any;
  timestamp: Date;
  ttl: number;
  signature: string;
  encrypted?: boolean;
  nonce?: string;
}

interface OfflineCredentialData {
  credentialId: string;
  userId: string;
  tenantId: string;
  publicKey: string;
  encryptedPrivateKey: string;
  accessGroups: string[];
  validFrom: Date;
  validUntil: Date;
  biometricHash?: string;
  lastSyncTime: Date;
  cryptographicProof: string;
}

const MobileCredentialSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  tenantId: z.string().uuid(),
  deviceId: z.string(),
  deviceType: z.enum(['ios', 'android']),
  credentialType: z.enum(['nfc', 'ble', 'both']),
  publicKey: z.string(),
  encryptedPrivateKey: z.string(),
  status: z.enum(['active', 'suspended', 'revoked', 'expired']),
  enrolledAt: z.date(),
  expiresAt: z.date().optional(),
  lastUsedAt: z.date().optional(),
  metadata: z.record(z.any()).optional(),
  bleConfig: z.object({
    serviceUuid: z.string(),
    characteristicUuid: z.string(),
    advertisementInterval: z.number(),
    powerLevel: z.enum(['low', 'medium', 'high'])
  }).optional(),
  nfcConfig: z.object({
    technology: z.enum(['iso14443a', 'iso14443b', 'iso15693', 'felica']),
    dataFormat: z.enum(['ndef', 'raw']),
    maxDataSize: z.number()
  }).optional(),
  biometricConfig: z.object({
    enabled: z.boolean(),
    types: z.array(z.enum(['fingerprint', 'face', 'voice', 'iris'])),
    fallbackToPin: z.boolean()
  }).optional(),
  powerManagement: z.object({
    lowBatteryThreshold: z.number(),
    powerSavingMode: z.boolean(),
    backgroundSyncInterval: z.number()
  }).optional()
});

const EnrollmentRequestSchema = z.object({
  userId: z.string().uuid(),
  deviceId: z.string().min(1),
  deviceType: z.enum(['ios', 'android']),
  credentialType: z.enum(['nfc', 'ble', 'both']),
  publicKey: z.string().min(1),
  deviceInfo: z.object({
    model: z.string(),
    osVersion: z.string(),
    appVersion: z.string(),
    capabilities: z.array(z.string()),
    batteryLevel: z.number().optional(),
    biometricCapabilities: z.array(z.enum(['fingerprint', 'face', 'voice', 'iris'])).optional(),
    nfcCapabilities: z.object({
      supported: z.boolean(),
      technologies: z.array(z.string()),
      maxDataSize: z.number()
    }).optional(),
    bleCapabilities: z.object({
      supported: z.boolean(),
      version: z.string(),
      powerLevels: z.array(z.string()),
      maxConnections: z.number()
    }).optional(),
    securityFeatures: z.array(z.string()).optional(),
    locationServices: z.boolean().optional()
  }),
  enrollmentMethod: z.enum(['self_service', 'admin', 'bulk']).default('self_service'),
  biometricEnrollment: z.object({
    enabled: z.boolean(),
    types: z.array(z.enum(['fingerprint', 'face', 'voice', 'iris'])),
    templates: z.array(z.string()).optional()
  }).optional(),
  protocolPreferences: z.object({
    preferredProtocol: z.enum(['nfc', 'ble', 'auto']),
    bleConfig: z.object({
      advertisementInterval: z.number(),
      powerLevel: z.enum(['low', 'medium', 'high']),
      securityLevel: z.enum(['none', 'encrypted', 'authenticated'])
    }).optional(),
    nfcConfig: z.object({
      technology: z.enum(['iso14443a', 'iso14443b', 'iso15693', 'felica']),
      dataFormat: z.enum(['ndef', 'raw'])
    }).optional()
  }).optional()
});

const AuthenticationRequestSchema = z.object({
  credentialId: z.string().uuid(),
  challenge: z.string(),
  signature: z.string(),
  readerId: z.string(),
  timestamp: z.number(),
  protocol: z.enum(['nfc', 'ble']),
  location: z.object({
    latitude: z.number().optional(),
    longitude: z.number().optional()
  }).optional(),
  biometricData: z.object({
    type: z.enum(['fingerprint', 'face', 'voice', 'iris']),
    template: z.string(),
    confidence: z.number(),
    liveness: z.boolean()
  }).optional(),
  deviceStatus: z.object({
    batteryLevel: z.number(),
    isCharging: z.boolean(),
    networkConnectivity: z.enum(['online', 'offline', 'limited']),
    lastSyncTime: z.string(),
    powerSavingMode: z.boolean()
  }).optional(),
  offlineValidation: z.object({
    enabled: z.boolean(),
    cryptographicProof: z.string(),
    localTimestamp: z.number(),
    sequenceNumber: z.number()
  }).optional(),
  protocolSpecific: z.object({
    bleData: z.object({
      rssi: z.number(),
      txPower: z.number(),
      connectionId: z.string(),
      serviceData: z.string()
    }).optional(),
    nfcData: z.object({
      technology: z.string(),
      uid: z.string(),
      atqa: z.string().optional(),
      sak: z.string().optional(),
      applicationData: z.string()
    }).optional()
  }).optional()
});

const RevocationRequestSchema = z.object({
  credentialIds: z.array(z.string().uuid()),
  reason: z.enum(['lost', 'stolen', 'compromised', 'terminated', 'expired', 'security_breach']),
  immediate: z.boolean().default(true),
  meshPropagation: z.boolean().default(true),
  remoteWipe: z.boolean().default(false),
  notifyUser: z.boolean().default(true),
  propagationTimeout: z.number().default(900) // 15 minutes in seconds
});

const DeviceManagementSchema = z.object({
  action: z.enum(['wipe', 'lock', 'unlock', 'locate', 'compliance_check', 'certificate_update']),
  deviceIds: z.array(z.string()),
  parameters: z.record(z.any()).optional(),
  immediate: z.boolean().default(true),
  notifyUser: z.boolean().default(true)
});

const BiometricEnrollmentSchema = z.object({
  credentialId: z.string().uuid(),
  biometricType: z.enum(['fingerprint', 'face', 'voice', 'iris']),
  template: z.string(),
  quality: z.number(),
  liveness: z.boolean(),
  metadata: z.record(z.any()).optional()
});

const OfflineSyncSchema = z.object({
  deviceId: z.string(),
  lastSyncTime: z.string(),
  events: z.array(z.object({
    id: z.string(),
    type: z.string(),
    timestamp: z.string(),
    data: z.record(z.any()),
    signature: z.string()
  })),
  credentialUpdates: z.array(z.object({
    credentialId: z.string(),
    action: z.enum(['create', 'update', 'revoke']),
    data: z.record(z.any()),
    timestamp: z.string()
  })).optional(),
  meshMessages: z.array(z.object({
    id: z.string(),
    type: z.string(),
    payload: z.record(z.any()),
    timestamp: z.string(),
    signature: z.string()
  })).optional()
});

// Initialize services with mesh networking support
const app = new Hono();
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Mesh networking and protocol management
class MobileCredentialMeshNetwork extends EventEmitter {
  private udpSocket: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private meshPeers: Map<string, any> = new Map();
  private messageCache: Map<string, Date> = new Map();
  private deviceId: string;
  private networkKey: Buffer;
  private logger: any;

  constructor(deviceId: string, logger: any) {
    super();
    this.deviceId = deviceId;
    this.networkKey = crypto.randomBytes(32);
    this.logger = logger;
  }

  async initialize(): Promise<void> {
    await this.initializeUDPSocket();
    await this.initializeTCPServer();
    this.startHeartbeat();
  }

  private async initializeUDPSocket(): Promise<void> {
    this.udpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    
    this.udpSocket.on('message', async (msg, rinfo) => {
      try {
        const message = JSON.parse(msg.toString());
        await this.processMeshMessage(message);
      } catch (error) {
        this.logger.warn('Invalid mesh message received', { error, from: rinfo.address });
      }
    });

    await promisify(this.udpSocket.bind.bind(this.udpSocket))(9998);
  }

  private async initializeTCPServer(): Promise<void> {
    this.tcpServer = net.createServer();
    
    this.tcpServer.on('connection', (socket) => {
      this.handleTCPConnection(socket);
    });

    await promisify(this.tcpServer.listen.bind(this.tcpServer))(9997);
  }

  private handleTCPConnection(socket: net.Socket): void {
    let buffer = '';
    
    socket.on('data', (data) => {
      buffer += data.toString();
      
      let newlineIndex;
      while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
        const messageStr = buffer.slice(0, newlineIndex);
        buffer = buffer.slice(newlineIndex + 1);
        
        try {
          const message = JSON.parse(messageStr);
          this.processMeshMessage(message);
        } catch (error) {
          this.logger.warn('Invalid TCP mesh message', { error });
        }
      }
    });
  }

  async broadcastCredentialRevocation(credentialIds: string[], tenantId: string, reason: string): Promise<void> {
    const message: MeshMessage = {
      id: crypto.randomUUID(),
      type: 'credential_revocation',
      sourceDeviceId: this.deviceId,
      tenantId,
      payload: { credentialIds, reason, timestamp: new Date() },
      timestamp: new Date(),
      ttl: 30,
      signature: this.signMessage({ credentialIds, reason })
    };

    await this.broadcastMessage(message);
  }

  async broadcastDeviceWipe(deviceIds: string[], tenantId: string): Promise<void> {
    const message: MeshMessage = {
      id: crypto.randomUUID(),
      type: 'device_wipe',
      sourceDeviceId: this.deviceId,
      tenantId,
      payload: { deviceIds, timestamp: new Date() },
      timestamp: new Date(),
      ttl: 30,
      signature: this.signMessage({ deviceIds })
    };

    await this.broadcastMessage(message);
  }

  private async broadcastMessage(message: MeshMessage): Promise<void> {
    const messageBuffer = Buffer.from(JSON.stringify(message));
    
    if (this.udpSocket) {
      await promisify(this.udpSocket.send.bind(this.udpSocket))(
        messageBuffer, 9998, '239.255.42.98'
      );
    }

    // Send to known TCP peers
    for (const peer of this.meshPeers.values()) {
      try {
        await this.sendMessageToPeer(message, peer);
      } catch (error) {
        this.logger.warn('Failed to send to peer', { peerId: peer.id, error: error.message });
      }
    }
  }

  private async sendMessageToPeer(message: MeshMessage, peer: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(peer.port, peer.address);
      const messageStr = JSON.stringify(message) + '\n';
      
      socket.on('connect', () => {
        socket.write(messageStr);
        socket.end();
        resolve();
      });
      
      socket.on('error', reject);
      setTimeout(() => {
        socket.destroy();
        reject(new Error('Connection timeout'));
      }, 5000);
    });
  }

  private async processMeshMessage(message: MeshMessage): Promise<void> {
    if (message.sourceDeviceId === this.deviceId) return;
    if (this.messageCache.has(message.id)) return;

    this.messageCache.set(message.id, new Date());
    this.cleanupMessageCache();

    switch (message.type) {
      case 'credential_revocation':
        this.emit('credentialRevocation', message.payload);
        break;
      case 'device_wipe':
        this.emit('deviceWipe', message.payload);
        break;
      case 'status_update':
        this.emit('statusUpdate', message.payload);
        break;
    }

    // Forward message if TTL allows
    if (message.ttl > 1) {
      message.ttl--;
      await this.broadcastMessage(message);
    }
  }

  private signMessage(payload: any): string {
    return crypto.createHmac('sha256', this.networkKey)
      .update(JSON.stringify(payload))
      .digest('hex');
  }

  private startHeartbeat(): void {
    setInterval(() => {
      this.broadcastMessage({
        id: crypto.randomUUID(),
        type: 'heartbeat',
        sourceDeviceId: this.deviceId,
        tenantId: 'system',
        payload: { timestamp: new Date(), status: 'active' },
        timestamp: new Date(),
        ttl: 3,
        signature: this.signMessage({ timestamp: new Date() })
      });
    }, 30000);
  }

  private cleanupMessageCache(): void {
    const now = new Date();
    for (const [messageId, timestamp] of this.messageCache.entries()) {
      if (now.getTime() - timestamp.getTime() > 300000) { // 5 minutes
        this.messageCache.delete(messageId);
      }
    }
  }

  async shutdown(): Promise<void> {
    if (this.udpSocket) this.udpSocket.close();
    if (this.tcpServer) await promisify(this.tcpServer.close.bind(this.tcpServer))();
  }
}

// BLE Protocol Handler
class BLEProtocolHandler {
  private config: BLEProtocolConfig;
  private logger: any;

  constructor(config: BLEProtocolConfig, logger: any) {
    this.config = config;
    this.logger = logger;
  }

  async initializePeripheral(credentialData: any): Promise<any> {
    // iOS/Android specific BLE peripheral setup
    const peripheralConfig = {
      serviceUuid: this.config.serviceUuid,
      characteristics: [{
        uuid: this.config.characteristicUuid,
        properties: ['read', 'write', 'notify'],
        value: this.encodeCredentialData(credentialData),
        descriptors: [{
          uuid: '2901',
          value: 'Mobile Credential'
        }]
      }],
      advertisementData: {
        localName: 'SPARC Mobile Credential',
        serviceUuids: [this.config.serviceUuid],
        manufacturerData: this.createManufacturerData(credentialData)
      },
      advertisementInterval: this.config.advertisementInterval,
      txPowerLevel: this.config.powerLevel
    };

    return peripheralConfig;
  }

  async initializeCentral(): Promise<any> {
    return {
      scanOptions: {
        serviceUuids: [this.config.serviceUuid],
        allowDuplicates: false,
        scanMode: 'balanced'
      },
      connectionOptions: {
        timeout: this.config.connectionTimeout,
        autoConnect: false,
        securityLevel: this.config.securityLevel
      }
    };
  }

  private encodeCredentialData(credentialData: any): Buffer {
    const data = {
      credentialId: credentialData.id,
      userId: credentialData.userId,
      tenantId: credentialData.tenantId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex')
    };

    return Buffer.from(JSON.stringify(data));
  }

  private createManufacturerData(credentialData: any): Buffer {
    // Create manufacturer-specific data for SPARC
    const manufacturerId = 0x05AC; // Apple's manufacturer ID as example
    const data = Buffer.alloc(8);
    data.writeUInt16LE(manufacturerId, 0);
    data.writeUInt32LE(credentialData.userId.hashCode(), 2);
    data.writeUInt16LE(Date.now() & 0xFFFF, 6);
    return data;
  }

  async handleAuthentication(readerId: string, credentialData: any, challenge: string): Promise<any> {
    const authData = {
      credentialId: credentialData.id,
      challenge,
      timestamp: Date.now(),
      protocol: 'ble',
      rssi: -50, // Would be actual RSSI in real implementation
      txPower: 0
    };

    const signature = this.signAuthData(authData, credentialData.privateKey);
    
    return {
      ...authData,
      signature,
      protocolSpecific: {
        bleData: {
          rssi: authData.rssi,
          txPower: authData.txPower,
          connectionId: crypto.randomUUID(),
          serviceData: this.config.serviceUuid
        }
      }
    };
  }

  private signAuthData(authData: any, privateKey: string): string {
    const dataToSign = `${authData.credentialId}:${authData.challenge}:${authData.timestamp}`;
    const sign = crypto.createSign('SHA256');
    sign.update(dataToSign);
    return sign.sign(privateKey, 'hex');
  }

  async optimizeForPowerSaving(batteryLevel: number): Promise<BLEProtocolConfig> {
    if (batteryLevel < 20) {
      return {
        ...this.config,
        advertisementInterval: this.config.advertisementInterval * 2,
        powerLevel: 'low',
        connectionTimeout: this.config.connectionTimeout / 2
      };
    }
    return this.config;
  }
}

// NFC Protocol Handler
class NFCProtocolHandler {
  private config: NFCProtocolConfig;
  private logger: any;

  constructor(config: NFCProtocolConfig, logger: any) {
    this.config = config;
    this.logger = logger;
  }

  async initializeNFCTag(credentialData: any): Promise<any> {
    const ndefRecord = this.createNDEFRecord(credentialData);
    
    return {
      technology: this.config.technology,
      dataFormat: this.config.dataFormat,
      maxDataSize: this.config.maxDataSize,
      ndefMessage: {
        records: [ndefRecord]
      },
      securityFeatures: this.config.securityFeatures,
      readTimeout: this.config.readTimeout,
      writeTimeout: this.config.writeTimeout
    };
  }

  private createNDEFRecord(credentialData: any): any {
    const payload = {
      credentialId: credentialData.id,
      userId: credentialData.userId,
      tenantId: credentialData.tenantId,
      timestamp: Date.now(),
      signature: this.signCredentialData(credentialData)
    };

    return {
      tnf: 0x02, // MIME type
      type: 'application/sparc-credential',
      payload: Buffer.from(JSON.stringify(payload)),
      id: credentialData.id
    };
  }

  async handleNFCRead(readerId: string, nfcData: any): Promise<any> {
    try {
      const payload = JSON.parse(nfcData.applicationData);
      
      return {
        credentialId: payload.credentialId,
        userId: payload.userId,
        tenantId: payload.tenantId,
        timestamp: payload.timestamp,
        signature: payload.signature,
        protocol: 'nfc',
        protocolSpecific: {
          nfcData: {
            technology: nfcData.technology,
            uid: nfcData.uid,
            atqa: nfcData.atqa,
            sak: nfcData.sak,
            applicationData: nfcData.applicationData
          }
        }
      };
    } catch (error) {
      throw new Error('Invalid NFC credential data');
    }
  }

  private signCredentialData(credentialData: any): string {
    const dataToSign = `${credentialData.id}:${credentialData.userId}:${credentialData.tenantId}`;
    return crypto.createHmac('sha256', credentialData.privateKey)
      .update(dataToSign)
      .digest('hex');
  }

  async optimizeForDevice(deviceType: 'ios' | 'android'): Promise<NFCProtocolConfig> {
    if (deviceType === 'ios') {
      return {
        ...this.config,
        technology: 'iso14443a',
        dataFormat: 'ndef',
        maxDataSize: 8192
      };
    } else {
      return {
        ...this.config,
        technology: 'iso14443a',
        dataFormat: 'ndef',
        maxDataSize: 32768
      };
    }
  }
}

// Biometric Authentication Handler
class BiometricAuthHandler {
  private logger: any;

  constructor(logger: any) {
    this.logger = logger;
  }

  async enrollBiometric(credentialId: string, biometricData: any): Promise<string> {
    // Create biometric template hash
    const template = this.createBiometricTemplate(biometricData);
    const templateHash = crypto.createHash('sha256')
      .update(template)
      .digest('hex');

    // Store encrypted template
    await redis.setex(
      `biometric:${credentialId}:${biometricData.type}`,
      86400 * 365, // 1 year
      this.encryptBiometricTemplate(template)
    );

    return templateHash;
  }

  async verifyBiometric(credentialId: string, biometricData: any): Promise<boolean> {
    try {
      const storedTemplate = await redis.get(`biometric:${credentialId}:${biometricData.type}`);
      if (!storedTemplate) return false;

      const decryptedTemplate = this.decryptBiometricTemplate(storedTemplate);
      const providedTemplate = this.createBiometricTemplate(biometricData);

      return this.compareBiometricTemplates(decryptedTemplate, providedTemplate);
    } catch (error) {
      this.logger.error('Biometric verification failed', { error, credentialId });
      return false;
    }
  }

  private createBiometricTemplate(biometricData: any): string {
    // In real implementation, this would use proper biometric template generation
    return crypto.createHash('sha256')
      .update(biometricData.template)
      .digest('hex');
  }

  private encryptBiometricTemplate(template: string): string {
    const cipher = crypto.createCipher('aes-256-gcm', config.encryptionKey);
    let encrypted = cipher.update(template, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private decryptBiometricTemplate(encryptedTemplate: string): string {
    const decipher = crypto.createDecipher('aes-256-gcm', config.encryptionKey);
    let decrypted = decipher.update(encryptedTemplate, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  private compareBiometricTemplates(template1: string, template2: string): boolean {
    // In real implementation, this would use proper biometric matching algorithms
    return template1 === template2;
  }
}

// Initialize enhanced services
const meshNetwork = new MobileCredentialMeshNetwork('mobile-credential-service', console);
const bleHandler = new BLEProtocolHandler({
  serviceUuid: '6E400001-B5A3-F393-E0A9-E50E24DCCA9E',
  characteristicUuid: '6E400002-B5A3-F393-E0A9-E50E24DCCA9E',
  advertisementInterval: 1000,
  connectionTimeout: 10000,
  powerLevel: 'medium',
  securityLevel: 'encrypted'
}, console);

const nfcHandler = new NFCProtocolHandler({
  technology: 'iso14443a',
  dataFormat: 'ndef',
  maxDataSize: 8192,
  readTimeout: 5000,
  writeTimeout: 5000,
  securityFeatures: ['encryption', 'authentication']
}, console);

const biometricHandler = new BiometricAuthHandler(console);

// Enhanced configuration
const config = {
  port: parseInt(process.env.PORT || '3007'),
  jwtSecret: process.env.JWT_SECRET || 'mobile-credential-secret',
  encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
  credentialTtl: parseInt(process.env.CREDENTIAL_TTL || '86400'), // 24 hours
  challengeTtl: parseInt(process.env.CHALLENGE_TTL || '300'), // 5 minutes
  offlineCapabilityHours: parseInt(process.env.OFFLINE_CAPABILITY_HOURS || '72'),
  meshNetworkEnabled: process.env.MESH_NETWORK_ENABLED === 'true',
  biometricEnabled: process.env.BIOMETRIC_ENABLED === 'true',
  powerManagementEnabled: process.env.POWER_MANAGEMENT_ENABLED === 'true',
  deviceManagementEnabled: process.env.DEVICE_MANAGEMENT_ENABLED === 'true',
  offlineValidationEnabled: process.env.OFFLINE_VALIDATION_ENABLED === 'true',
  meshPropagationTimeout: parseInt(process.env.MESH_PROPAGATION_TIMEOUT || '900'), // 15 minutes
  lowBatteryThreshold: parseInt(process.env.LOW_BATTERY_THRESHOLD || '20'),
  criticalBatteryThreshold: parseInt(process.env.CRITICAL_BATTERY_THRESHOLD || '5'),
  maxOfflineEvents: parseInt(process.env.MAX_OFFLINE_EVENTS || '10000'),
  biometricMaxAttempts: parseInt(process.env.BIOMETRIC_MAX_ATTEMPTS || '3'),
  complianceCheckInterval: parseInt(process.env.COMPLIANCE_CHECK_INTERVAL || '86400') // 24 hours
};

// Middleware
app.use('*', cors({
  origin: ['http://localhost:3000', 'https://*.sparc.security'],
  credentials: true
}));

app.use('*', logger());
app.use('*', prettyJSON());

// Authentication middleware
app.use('/api/*', async (c, next) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    throw new HTTPException(401, { message: 'Missing or invalid authorization header' });
  }

  try {
    const token = authHeader.substring(7);
    const payload = jwt.verify(token, config.jwtSecret) as any;
    c.set('user', payload);
    c.set('tenantId', payload.tenantId);
    await next();
  } catch (error) {
    throw new HTTPException(401, { message: 'Invalid or expired token' });
  }
});

// Utility functions
function generateKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

function encryptData(data: string, key: string): string {
  const cipher = crypto.createCipher('aes-256-cbc', key);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(encryptedData: string, key: string): string {
  const decipher = crypto.createDecipher('aes-256-cbc', key);
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function generateChallenge(): string {
  return crypto.randomBytes(32).toString('hex');
}

function verifySignature(data: string, signature: string, publicKey: string): boolean {
  try {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    return verify.verify(publicKey, signature, 'hex');
  } catch (error) {
    return false;
  }
}

async function logAuditEvent(tenantId: string, userId: string, action: string, details: any) {
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId,
      action,
      resourceType: 'mobile_credential',
      details: JSON.stringify(details),
      timestamp: new Date(),
      ipAddress: '0.0.0.0', // Would be extracted from request in real implementation
      userAgent: 'mobile-credential-service'
    }
  });
}

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'mobile-credential-service',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// Enhanced mobile credential enrollment with full protocol support
app.post('/api/credentials/enroll', async (c) => {
  try {
    const body = await c.req.json();
    const enrollmentData = EnrollmentRequestSchema.parse(body);
    const user = c.get('user');
    const tenantId = c.get('tenantId');

    // Verify user exists and has permission to enroll
    const userRecord = await prisma.user.findFirst({
      where: { id: enrollmentData.userId, tenantId }
    });

    if (!userRecord) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    // Check for existing active credentials for this device
    const existingCredential = await prisma.mobileCredential.findFirst({
      where: {
        userId: enrollmentData.userId,
        deviceId: enrollmentData.deviceId,
        status: 'active'
      }
    });

    if (existingCredential) {
      throw new HTTPException(409, { message: 'Active credential already exists for this device' });
    }

    // Generate server key pair for this credential
    const serverKeyPair = generateKeyPair();
    const credentialId = crypto.randomUUID();

    // Configure protocol-specific settings
    const bleConfig = await bleHandler.initializePeripheral({
      id: credentialId,
      userId: enrollmentData.userId,
      tenantId,
      privateKey: serverKeyPair.privateKey
    });

    const nfcConfig = await nfcHandler.initializeNFCTag({
      id: credentialId,
      userId: enrollmentData.userId,
      tenantId,
      privateKey: serverKeyPair.privateKey
    });

    // Optimize protocols for device capabilities
    const optimizedBleConfig = enrollmentData.deviceInfo.batteryLevel ? 
      await bleHandler.optimizeForPowerSaving(enrollmentData.deviceInfo.batteryLevel) : bleConfig;
    
    const optimizedNfcConfig = await nfcHandler.optimizeForDevice(enrollmentData.deviceType);

    // Handle biometric enrollment if requested
    let biometricHash: string | undefined;
    if (enrollmentData.biometricEnrollment?.enabled && config.biometricEnabled) {
      for (const template of enrollmentData.biometricEnrollment.templates || []) {
        biometricHash = await biometricHandler.enrollBiometric(credentialId, {
          type: enrollmentData.biometricEnrollment.types[0],
          template,
          quality: 0.95,
          liveness: true
        });
      }
    }

    // Create comprehensive mobile credential record
    const mobileCredential = await prisma.mobileCredential.create({
      data: {
        id: credentialId,
        userId: enrollmentData.userId,
        tenantId,
        deviceId: enrollmentData.deviceId,
        deviceType: enrollmentData.deviceType,
        credentialType: enrollmentData.credentialType,
        publicKey: enrollmentData.publicKey,
        encryptedPrivateKey: encryptData(serverKeyPair.privateKey, config.encryptionKey),
        serverPublicKey: serverKeyPair.publicKey,
        status: 'active',
        enrolledAt: new Date(),
        expiresAt: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)), // 1 year
        metadata: {
          deviceInfo: enrollmentData.deviceInfo,
          enrollmentMethod: enrollmentData.enrollmentMethod,
          bleConfig: optimizedBleConfig,
          nfcConfig: optimizedNfcConfig,
          biometricEnabled: !!biometricHash,
          biometricHash,
          protocolPreferences: enrollmentData.protocolPreferences,
          powerManagement: {
            lowBatteryThreshold: config.lowBatteryThreshold,
            powerSavingMode: enrollmentData.deviceInfo.batteryLevel ? 
              enrollmentData.deviceInfo.batteryLevel < config.lowBatteryThreshold : false,
            backgroundSyncInterval: 300000 // 5 minutes
          },
          meshNetworkEnabled: config.meshNetworkEnabled,
          offlineValidationEnabled: config.offlineValidationEnabled
        }
      }
    });

    // Create offline credential data for local validation
    const offlineCredentialData: OfflineCredentialData = {
      credentialId,
      userId: enrollmentData.userId,
      tenantId,
      publicKey: enrollmentData.publicKey,
      encryptedPrivateKey: encryptData(serverKeyPair.privateKey, config.encryptionKey),
      accessGroups: [], // Would be populated from user's access groups
      validFrom: new Date(),
      validUntil: mobileCredential.expiresAt!,
      biometricHash,
      lastSyncTime: new Date(),
      cryptographicProof: this.generateCryptographicProof(credentialId, tenantId)
    };

    // Cache credential for offline operation with extended data
    await redis.setex(
      `mobile_credential:${credentialId}`,
      config.credentialTtl,
      JSON.stringify({
        id: credentialId,
        userId: enrollmentData.userId,
        tenantId,
        publicKey: enrollmentData.publicKey,
        status: 'active',
        credentialType: enrollmentData.credentialType,
        bleConfig: optimizedBleConfig,
        nfcConfig: optimizedNfcConfig,
        biometricEnabled: !!biometricHash,
        offlineData: offlineCredentialData
      })
    );

    // Cache offline credential data separately for extended offline operation
    if (config.offlineValidationEnabled) {
      await redis.setex(
        `offline_credential:${credentialId}`,
        config.offlineCapabilityHours * 3600,
        JSON.stringify(offlineCredentialData)
      );
    }

    // Log comprehensive audit event
    await logAuditEvent(tenantId, user.id, 'mobile_credential_enrolled', {
      credentialId,
      deviceId: enrollmentData.deviceId,
      deviceType: enrollmentData.deviceType,
      credentialType: enrollmentData.credentialType,
      enrollmentMethod: enrollmentData.enrollmentMethod,
      biometricEnabled: !!biometricHash,
      protocolsEnabled: {
        ble: enrollmentData.credentialType === 'ble' || enrollmentData.credentialType === 'both',
        nfc: enrollmentData.credentialType === 'nfc' || enrollmentData.credentialType === 'both'
      }
    });

    // Prepare response with comprehensive configuration
    const response = {
      success: true,
      credentialId,
      serverPublicKey: serverKeyPair.publicKey,
      expiresAt: mobileCredential.expiresAt,
      supportedProtocols: ['nfc', 'ble'],
      offlineCapabilityHours: config.offlineCapabilityHours,
      protocolConfiguration: {
        ble: {
          serviceUuid: optimizedBleConfig.serviceUuid,
          characteristicUuid: optimizedBleConfig.characteristics[0].uuid,
          advertisementInterval: optimizedBleConfig.advertisementInterval,
          powerLevel: optimizedBleConfig.txPowerLevel
        },
        nfc: {
          technology: optimizedNfcConfig.technology,
          dataFormat: optimizedNfcConfig.dataFormat,
          maxDataSize: optimizedNfcConfig.maxDataSize
        }
      },
      biometricConfiguration: biometricHash ? {
        enabled: true,
        types: enrollmentData.biometricEnrollment?.types || [],
        maxAttempts: config.biometricMaxAttempts
      } : { enabled: false },
      powerManagement: {
        enabled: config.powerManagementEnabled,
        lowBatteryThreshold: config.lowBatteryThreshold,
        criticalBatteryThreshold: config.criticalBatteryThreshold
      },
      meshNetworking: {
        enabled: config.meshNetworkEnabled,
        propagationTimeout: config.meshPropagationTimeout
      },
      offlineValidation: {
        enabled: config.offlineValidationEnabled,
        cryptographicProof: offlineCredentialData.cryptographicProof
      }
    };

    return c.json(response);

  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid request data', cause: error.errors });
    }
    throw error;
  }
});

// Enhanced mobile credential authentication with full protocol support
app.post('/api/credentials/authenticate', async (c) => {
  try {
    const body = await c.req.json();
    const authData = AuthenticationRequestSchema.parse(body);

    // Get credential from cache first (for offline capability)
    let credential = await redis.get(`mobile_credential:${authData.credentialId}`);
    let credentialData;
    let offlineCredentialData;

    if (credential) {
      credentialData = JSON.parse(credential);
      
      // Get offline credential data if available
      if (config.offlineValidationEnabled) {
        const offlineData = await redis.get(`offline_credential:${authData.credentialId}`);
        if (offlineData) {
          offlineCredentialData = JSON.parse(offlineData);
        }
      }
    } else {
      // Fallback to database
      const dbCredential = await prisma.mobileCredential.findUnique({
        where: { id: authData.credentialId },
        include: { user: true }
      });

      if (!dbCredential) {
        throw new HTTPException(404, { message: 'Credential not found' });
      }

      credentialData = {
        id: dbCredential.id,
        userId: dbCredential.userId,
        tenantId: dbCredential.tenantId,
        publicKey: dbCredential.publicKey,
        status: dbCredential.status,
        credentialType: dbCredential.credentialType,
        bleConfig: dbCredential.metadata?.bleConfig,
        nfcConfig: dbCredential.metadata?.nfcConfig,
        biometricEnabled: dbCredential.metadata?.biometricEnabled
      };

      // Update cache
      await redis.setex(
        `mobile_credential:${authData.credentialId}`,
        config.credentialTtl,
        JSON.stringify(credentialData)
      );
    }

    // Check credential status
    if (credentialData.status !== 'active') {
      throw new HTTPException(403, { message: 'Credential is not active' });
    }

    // Handle offline validation if enabled and offline credential data is available
    if (authData.offlineValidation?.enabled && offlineCredentialData) {
      const isValidOffline = await this.validateOfflineCredential(authData, offlineCredentialData);
      if (!isValidOffline) {
        throw new HTTPException(401, { message: 'Offline validation failed' });
      }
    }

    // Verify biometric authentication if provided and enabled
    if (authData.biometricData && credentialData.biometricEnabled && config.biometricEnabled) {
      const biometricValid = await biometricHandler.verifyBiometric(
        authData.credentialId,
        authData.biometricData
      );
      
      if (!biometricValid) {
        throw new HTTPException(401, { message: 'Biometric authentication failed' });
      }
    }

    // Protocol-specific validation
    let protocolValidation = { valid: true, details: {} };
    
    if (authData.protocol === 'ble' && authData.protocolSpecific?.bleData) {
      protocolValidation = await this.validateBLEAuthentication(authData, credentialData);
    } else if (authData.protocol === 'nfc' && authData.protocolSpecific?.nfcData) {
      protocolValidation = await this.validateNFCAuthentication(authData, credentialData);
    }

    if (!protocolValidation.valid) {
      throw new HTTPException(401, { message: 'Protocol validation failed' });
    }

    // Verify challenge signature
    const challengeData = `${authData.challenge}:${authData.readerId}:${authData.timestamp}:${authData.protocol}`;
    const isValidSignature = verifySignature(challengeData, authData.signature, credentialData.publicKey);

    if (!isValidSignature) {
      throw new HTTPException(401, { message: 'Invalid signature' });
    }

    // Check timestamp (prevent replay attacks)
    const now = Date.now();
    const timeDiff = Math.abs(now - authData.timestamp);
    if (timeDiff > 300000) { // 5 minutes
      throw new HTTPException(401, { message: 'Authentication request expired' });
    }

    // Handle power management if device status is provided
    if (authData.deviceStatus && config.powerManagementEnabled) {
      await this.handlePowerManagement(authData.credentialId, authData.deviceStatus);
    }

    // Update last used timestamp and device status
    await prisma.mobileCredential.update({
      where: { id: authData.credentialId },
      data: { 
        lastUsedAt: new Date(),
        metadata: {
          ...credentialData.metadata,
          lastDeviceStatus: authData.deviceStatus,
          lastProtocolUsed: authData.protocol,
          lastBiometricAuth: !!authData.biometricData
        }
      }
    });

    // Log comprehensive access event
    await prisma.accessEvent.create({
      data: {
        tenantId: credentialData.tenantId,
        userId: credentialData.userId,
        credentialId: authData.credentialId,
        credentialType: 'mobile',
        readerId: authData.readerId,
        eventType: 'access_granted',
        timestamp: new Date(),
        location: authData.location ? JSON.stringify(authData.location) : null,
        metadata: JSON.stringify({
          authenticationMethod: 'mobile_credential',
          protocol: authData.protocol,
          deviceType: credentialData.credentialType,
          biometricUsed: !!authData.biometricData,
          biometricType: authData.biometricData?.type,
          offlineValidation: authData.offlineValidation?.enabled,
          deviceStatus: authData.deviceStatus,
          protocolDetails: protocolValidation.details
        })
      }
    });

    return c.json({
      success: true,
      accessGranted: true,
      userId: credentialData.userId,
      timestamp: new Date().toISOString(),
      authenticationDetails: {
        protocol: authData.protocol,
        biometricUsed: !!authData.biometricData,
        offlineValidation: authData.offlineValidation?.enabled,
        powerSavingMode: authData.deviceStatus?.powerSavingMode
      }
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid request data', cause: error.errors });
    }
    throw error;
  }
});

// Generate authentication challenge
app.post('/api/credentials/:credentialId/challenge', async (c) => {
  try {
    const credentialId = c.req.param('credentialId');
    const { readerId } = await c.req.json();

    if (!readerId) {
      throw new HTTPException(400, { message: 'Reader ID is required' });
    }

    const challenge = generateChallenge();
    const timestamp = Date.now();

    // Store challenge temporarily
    await redis.setex(
      `challenge:${credentialId}:${readerId}`,
      config.challengeTtl,
      JSON.stringify({ challenge, timestamp })
    );

    return c.json({
      challenge,
      timestamp,
      expiresIn: config.challengeTtl
    });

  } catch (error) {
    throw error;
  }
});

// List user's mobile credentials
app.get('/api/credentials', async (c) => {
  try {
    const user = c.get('user');
    const tenantId = c.get('tenantId');
    const { userId } = c.req.query();

    const targetUserId = userId || user.id;

    const credentials = await prisma.mobileCredential.findMany({
      where: {
        userId: targetUserId,
        tenantId
      },
      select: {
        id: true,
        deviceId: true,
        deviceType: true,
        credentialType: true,
        status: true,
        enrolledAt: true,
        expiresAt: true,
        lastUsedAt: true,
        metadata: true
      },
      orderBy: { enrolledAt: 'desc' }
    });

    return c.json({
      credentials,
      total: credentials.length
    });

  } catch (error) {
    throw error;
  }
});

// Enhanced credential revocation with mesh networking and device management
app.post('/api/credentials/revoke', async (c) => {
  try {
    const body = await c.req.json();
    const revocationData = RevocationRequestSchema.parse(body);
    const user = c.get('user');
    const tenantId = c.get('tenantId');

    // Get credential details for device management
    const credentials = await prisma.mobileCredential.findMany({
      where: {
        id: { in: revocationData.credentialIds },
        tenantId
      },
      include: { user: true }
    });

    if (credentials.length === 0) {
      throw new HTTPException(404, { message: 'No credentials found' });
    }

    // Update credentials status
    const updatedCredentials = await prisma.mobileCredential.updateMany({
      where: {
        id: { in: revocationData.credentialIds },
        tenantId
      },
      data: {
        status: 'revoked',
        revokedAt: new Date(),
        revocationReason: revocationData.reason
      }
    });

    // Remove from cache immediately
    for (const credentialId of revocationData.credentialIds) {
      await redis.del(`mobile_credential:${credentialId}`);
      await redis.del(`offline_credential:${credentialId}`);
      
      // Remove biometric data if exists
      if (config.biometricEnabled) {
        const biometricKeys = await redis.keys(`biometric:${credentialId}:*`);
        if (biometricKeys.length > 0) {
          await redis.del(...biometricKeys);
        }
      }
    }

    // Handle mesh network propagation for immediate revocation
    if (revocationData.immediate && config.meshNetworkEnabled && revocationData.meshPropagation) {
      try {
        await meshNetwork.broadcastCredentialRevocation(
          revocationData.credentialIds,
          tenantId,
          revocationData.reason
        );
        
        // Set up timeout monitoring for mesh propagation
        setTimeout(async () => {
          await this.verifyMeshPropagation(revocationData.credentialIds, tenantId);
        }, revocationData.propagationTimeout * 1000);
        
      } catch (meshError) {
        console.error('Mesh network propagation failed:', meshError);
        // Continue with other revocation steps even if mesh fails
      }
    }

    // Handle remote device wipe if requested
    if (revocationData.remoteWipe && config.deviceManagementEnabled) {
      const deviceIds = credentials.map(c => c.deviceId);
      try {
        await meshNetwork.broadcastDeviceWipe(deviceIds, tenantId);
        
        // Log device wipe commands
        for (const deviceId of deviceIds) {
          await logAuditEvent(tenantId, user.id, 'device_wipe_initiated', {
            deviceId,
            reason: revocationData.reason,
            credentialIds: revocationData.credentialIds
          });
        }
      } catch (wipeError) {
        console.error('Device wipe failed:', wipeError);
      }
    }

    // Publish revocation message to Redis for real-time updates
    if (revocationData.immediate) {
      await redis.publish('credential_revocation', JSON.stringify({
        credentialIds: revocationData.credentialIds,
        timestamp: Date.now(),
        reason: revocationData.reason,
        tenantId,
        meshPropagation: revocationData.meshPropagation,
        remoteWipe: revocationData.remoteWipe
      }));
    }

    // Send notifications to users if requested
    if (revocationData.notifyUser) {
      for (const credential of credentials) {
        try {
          await this.sendRevocationNotification(credential, revocationData.reason);
        } catch (notificationError) {
          console.error('Failed to send revocation notification:', notificationError);
        }
      }
    }

    // Log comprehensive audit events
    for (const credentialId of revocationData.credentialIds) {
      await logAuditEvent(tenantId, user.id, 'mobile_credential_revoked', {
        credentialId,
        reason: revocationData.reason,
        immediate: revocationData.immediate,
        meshPropagation: revocationData.meshPropagation,
        remoteWipe: revocationData.remoteWipe,
        propagationTimeout: revocationData.propagationTimeout
      });
    }

    return c.json({
      success: true,
      revokedCount: updatedCredentials.count,
      timestamp: new Date().toISOString(),
      meshPropagationInitiated: revocationData.meshPropagation && config.meshNetworkEnabled,
      deviceWipeInitiated: revocationData.remoteWipe && config.deviceManagementEnabled,
      notificationsSent: revocationData.notifyUser,
      propagationTimeout: revocationData.propagationTimeout
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid request data', cause: error.errors });
    }
    throw error;
  }
});

// Suspend/resume mobile credential
app.patch('/api/credentials/:credentialId/status', async (c) => {
  try {
    const credentialId = c.req.param('credentialId');
    const { status } = await c.req.json();
    const user = c.get('user');
    const tenantId = c.get('tenantId');

    if (!['active', 'suspended'].includes(status)) {
      throw new HTTPException(400, { message: 'Invalid status. Must be active or suspended' });
    }

    const credential = await prisma.mobileCredential.update({
      where: {
        id: credentialId,
        tenantId
      },
      data: { status }
    });

    // Update cache
    const cachedCredential = await redis.get(`mobile_credential:${credentialId}`);
    if (cachedCredential) {
      const credentialData = JSON.parse(cachedCredential);
      credentialData.status = status;
      await redis.setex(
        `mobile_credential:${credentialId}`,
        config.credentialTtl,
        JSON.stringify(credentialData)
      );
    }

    // Log audit event
    await logAuditEvent(tenantId, user.id, 'mobile_credential_status_changed', {
      credentialId,
      newStatus: status,
      previousStatus: credential.status
    });

    return c.json({
      success: true,
      credentialId,
      status,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    throw error;
  }
});

// Get credential details
app.get('/api/credentials/:credentialId', async (c) => {
  try {
    const credentialId = c.req.param('credentialId');
    const tenantId = c.get('tenantId');

    const credential = await prisma.mobileCredential.findFirst({
      where: {
        id: credentialId,
        tenantId
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true
          }
        }
      }
    });

    if (!credential) {
      throw new HTTPException(404, { message: 'Credential not found' });
    }

    return c.json({
      id: credential.id,
      userId: credential.userId,
      user: credential.user,
      deviceId: credential.deviceId,
      deviceType: credential.deviceType,
      credentialType: credential.credentialType,
      status: credential.status,
      enrolledAt: credential.enrolledAt,
      expiresAt: credential.expiresAt,
      lastUsedAt: credential.lastUsedAt,
      metadata: credential.metadata
    });

  } catch (error) {
    throw error;
  }
});

// Enhanced offline synchronization with mesh networking integration
app.post('/api/sync/offline-events', async (c) => {
  try {
    const body = await c.req.json();
    const syncData = OfflineSyncSchema.parse(body);
    const tenantId = c.get('tenantId');

    const processedEvents = [];
    const processedCredentialUpdates = [];
    const processedMeshMessages = [];

    // Process offline events
    for (const event of syncData.events) {
      try {
        // Verify event signature
        const isValidEvent = this.verifyEventSignature(event, tenantId);
        if (!isValidEvent) {
          console.warn('Invalid event signature:', event.id);
          continue;
        }

        // Validate and process offline event
        const accessEvent = await prisma.accessEvent.create({
          data: {
            tenantId,
            userId: event.data.userId,
            credentialId: event.data.credentialId,
            credentialType: 'mobile',
            readerId: event.data.readerId,
            eventType: event.type,
            timestamp: new Date(event.timestamp),
            location: event.data.location ? JSON.stringify(event.data.location) : null,
            metadata: JSON.stringify({
              ...event.data,
              syncedAt: new Date().toISOString(),
              offlineEvent: true,
              deviceId: syncData.deviceId,
              eventSignature: event.signature
            })
          }
        });

        processedEvents.push(accessEvent.id);
      } catch (error) {
        console.error('Failed to process offline event:', error);
      }
    }

    // Process credential updates if provided
    if (syncData.credentialUpdates) {
      for (const update of syncData.credentialUpdates) {
        try {
          switch (update.action) {
            case 'revoke':
              await this.processOfflineCredentialRevocation(update, tenantId);
              processedCredentialUpdates.push(update.credentialId);
              break;
            case 'update':
              await this.processOfflineCredentialUpdate(update, tenantId);
              processedCredentialUpdates.push(update.credentialId);
              break;
          }
        } catch (error) {
          console.error('Failed to process credential update:', error);
        }
      }
    }

    // Process mesh messages if provided
    if (syncData.meshMessages && config.meshNetworkEnabled) {
      for (const meshMessage of syncData.meshMessages) {
        try {
          // Verify mesh message signature
          const isValidMesh = this.verifyMeshMessageSignature(meshMessage);
          if (!isValidMesh) {
            console.warn('Invalid mesh message signature:', meshMessage.id);
            continue;
          }

          // Process mesh message
          await this.processSyncedMeshMessage(meshMessage, tenantId);
          processedMeshMessages.push(meshMessage.id);
        } catch (error) {
          console.error('Failed to process mesh message:', error);
        }
      }
    }

    // Update device sync status
    await redis.setex(
      `device_sync:${syncData.deviceId}`,
      86400, // 24 hours
      JSON.stringify({
        lastSyncTime: new Date().toISOString(),
        eventsProcessed: processedEvents.length,
        credentialUpdatesProcessed: processedCredentialUpdates.length,
        meshMessagesProcessed: processedMeshMessages.length
      })
    );

    // Send any pending updates to the device
    const pendingUpdates = await this.getPendingUpdatesForDevice(syncData.deviceId, tenantId);

    return c.json({
      success: true,
      processedCount: processedEvents.length,
      totalReceived: syncData.events.length,
      processedEvents,
      credentialUpdatesProcessed: processedCredentialUpdates.length,
      meshMessagesProcessed: processedMeshMessages.length,
      pendingUpdates: {
        credentialRevocations: pendingUpdates.credentialRevocations || [],
        deviceCommands: pendingUpdates.deviceCommands || [],
        configurationUpdates: pendingUpdates.configurationUpdates || []
      },
      syncTimestamp: new Date().toISOString()
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid sync data', cause: error.errors });
    }
    throw error;
  }
});

// Biometric enrollment endpoint
app.post('/api/credentials/:credentialId/biometric', async (c) => {
  try {
    const credentialId = c.req.param('credentialId');
    const body = await c.req.json();
    const biometricData = BiometricEnrollmentSchema.parse(body);
    const tenantId = c.get('tenantId');

    if (!config.biometricEnabled) {
      throw new HTTPException(400, { message: 'Biometric authentication is not enabled' });
    }

    // Verify credential exists and belongs to tenant
    const credential = await prisma.mobileCredential.findFirst({
      where: { id: credentialId, tenantId }
    });

    if (!credential) {
      throw new HTTPException(404, { message: 'Credential not found' });
    }

    // Enroll biometric
    const biometricHash = await biometricHandler.enrollBiometric(credentialId, biometricData);

    // Update credential metadata
    await prisma.mobileCredential.update({
      where: { id: credentialId },
      data: {
        metadata: {
          ...credential.metadata,
          biometricEnabled: true,
          biometricTypes: [...(credential.metadata?.biometricTypes || []), biometricData.biometricType],
          biometricHash
        }
      }
    });

    return c.json({
      success: true,
      biometricHash,
      enrolledType: biometricData.biometricType,
      quality: biometricData.quality
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid biometric data', cause: error.errors });
    }
    throw error;
  }
});

// Device management endpoint
app.post('/api/device-management', async (c) => {
  try {
    const body = await c.req.json();
    const managementData = DeviceManagementSchema.parse(body);
    const user = c.get('user');
    const tenantId = c.get('tenantId');

    if (!config.deviceManagementEnabled) {
      throw new HTTPException(400, { message: 'Device management is not enabled' });
    }

    const results = [];

    for (const deviceId of managementData.deviceIds) {
      try {
        let result;
        
        switch (managementData.action) {
          case 'wipe':
            result = await this.performDeviceWipe(deviceId, tenantId, managementData.parameters);
            break;
          case 'lock':
            result = await this.performDeviceLock(deviceId, tenantId, managementData.parameters);
            break;
          case 'unlock':
            result = await this.performDeviceUnlock(deviceId, tenantId, managementData.parameters);
            break;
          case 'locate':
            result = await this.performDeviceLocate(deviceId, tenantId);
            break;
          case 'compliance_check':
            result = await this.performComplianceCheck(deviceId, tenantId);
            break;
          case 'certificate_update':
            result = await this.performCertificateUpdate(deviceId, tenantId, managementData.parameters);
            break;
        }

        results.push({ deviceId, success: true, result });

        // Log audit event
        await logAuditEvent(tenantId, user.id, `device_${managementData.action}`, {
          deviceId,
          action: managementData.action,
          parameters: managementData.parameters,
          immediate: managementData.immediate
        });

      } catch (error) {
        results.push({ deviceId, success: false, error: error.message });
      }
    }

    return c.json({
      success: true,
      action: managementData.action,
      results,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid device management data', cause: error.errors });
    }
    throw error;
  }
});

// Self-service enrollment portal endpoint
app.post('/api/self-service/enroll', async (c) => {
  try {
    const body = await c.req.json();
    const { enrollmentToken, ...enrollmentData } = body;

    // Verify enrollment token
    const tokenData = jwt.verify(enrollmentToken, config.jwtSecret) as any;
    
    if (!tokenData.allowSelfEnrollment) {
      throw new HTTPException(403, { message: 'Self-enrollment not permitted' });
    }

    // Set enrollment method to self-service
    const enhancedEnrollmentData = {
      ...enrollmentData,
      userId: tokenData.userId,
      enrollmentMethod: 'self_service'
    };

    // Use existing enrollment logic
    c.set('user', { id: tokenData.userId });
    c.set('tenantId', tokenData.tenantId);

    // Process enrollment (reuse existing logic)
    const enrollmentResult = await this.processEnrollment(enhancedEnrollmentData, tokenData.tenantId, tokenData.userId);

    return c.json({
      success: true,
      ...enrollmentResult,
      selfServiceEnrollment: true
    });

  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new HTTPException(401, { message: 'Invalid enrollment token' });
    }
    throw error;
  }
});

// Power management status endpoint
app.get('/api/credentials/:credentialId/power-status', async (c) => {
  try {
    const credentialId = c.req.param('credentialId');
    const tenantId = c.get('tenantId');

    const powerStatus = await redis.get(`power_status:${credentialId}`);
    
    if (!powerStatus) {
      return c.json({
        credentialId,
        powerManagementEnabled: config.powerManagementEnabled,
        status: 'unknown',
        lastUpdate: null
      });
    }

    const status = JSON.parse(powerStatus);
    
    return c.json({
      credentialId,
      powerManagementEnabled: config.powerManagementEnabled,
      ...status
    });

  } catch (error) {
    throw error;
  }
});

// Mesh network status endpoint
app.get('/api/mesh/status', async (c) => {
  try {
    if (!config.meshNetworkEnabled) {
      return c.json({
        enabled: false,
        message: 'Mesh networking is not enabled'
      });
    }

    const meshStatus = {
      enabled: true,
      nodeId: meshNetwork.deviceId,
      connectedPeers: meshNetwork.meshPeers.size,
      lastHeartbeat: new Date().toISOString(),
      propagationTimeout: config.meshPropagationTimeout,
      networkHealth: 'healthy' // Would be calculated based on peer connectivity
    };

    return c.json(meshStatus);

  } catch (error) {
    throw error;
  }
});

// Helper methods for enhanced functionality
async function validateOfflineCredential(authData: any, offlineCredentialData: OfflineCredentialData): Promise<boolean> {
  try {
    // Verify cryptographic proof
    const expectedProof = generateCryptographicProof(offlineCredentialData.credentialId, offlineCredentialData.tenantId);
    if (offlineCredentialData.cryptographicProof !== expectedProof) {
      return false;
    }

    // Check validity period
    const now = new Date();
    if (now < offlineCredentialData.validFrom || now > offlineCredentialData.validUntil) {
      return false;
    }

    // Verify sequence number for replay protection
    if (authData.offlineValidation.sequenceNumber <= 0) {
      return false;
    }

    return true;
  } catch (error) {
    console.error('Offline validation error:', error);
    return false;
  }
}

async function validateBLEAuthentication(authData: any, credentialData: any): Promise<{ valid: boolean; details: any }> {
  try {
    const bleData = authData.protocolSpecific.bleData;
    
    // Validate RSSI range
    if (bleData.rssi < -100 || bleData.rssi > 0) {
      return { valid: false, details: { error: 'Invalid RSSI value' } };
    }

    // Validate service data
    if (bleData.serviceData !== credentialData.bleConfig?.serviceUuid) {
      return { valid: false, details: { error: 'Service UUID mismatch' } };
    }

    return { 
      valid: true, 
      details: { 
        rssi: bleData.rssi,
        txPower: bleData.txPower,
        connectionId: bleData.connectionId
      }
    };
  } catch (error) {
    return { valid: false, details: { error: error.message } };
  }
}

async function validateNFCAuthentication(authData: any, credentialData: any): Promise<{ valid: boolean; details: any }> {
  try {
    const nfcData = authData.protocolSpecific.nfcData;
    
    // Validate technology compatibility
    const supportedTech = credentialData.nfcConfig?.technology;
    if (nfcData.technology !== supportedTech) {
      return { valid: false, details: { error: 'NFC technology mismatch' } };
    }

    // Validate UID format
    if (!nfcData.uid || nfcData.uid.length < 8) {
      return { valid: false, details: { error: 'Invalid NFC UID' } };
    }

    return { 
      valid: true, 
      details: { 
        technology: nfcData.technology,
        uid: nfcData.uid,
        atqa: nfcData.atqa,
        sak: nfcData.sak
      }
    };
  } catch (error) {
    return { valid: false, details: { error: error.message } };
  }
}

async function handlePowerManagement(credentialId: string, deviceStatus: any): Promise<void> {
  try {
    const powerStatus = {
      batteryLevel: deviceStatus.batteryLevel,
      isCharging: deviceStatus.isCharging,
      powerSavingMode: deviceStatus.powerSavingMode,
      lastUpdate: new Date().toISOString()
    };

    // Store power status
    await redis.setex(`power_status:${credentialId}`, 3600, JSON.stringify(powerStatus));

    // Trigger power-saving optimizations if battery is low
    if (deviceStatus.batteryLevel < config.lowBatteryThreshold) {
      await this.optimizeForLowBattery(credentialId, deviceStatus.batteryLevel);
    }

    // Alert if battery is critically low
    if (deviceStatus.batteryLevel < config.criticalBatteryThreshold) {
      await this.alertCriticalBattery(credentialId, deviceStatus.batteryLevel);
    }
  } catch (error) {
    console.error('Power management error:', error);
  }
}

function generateCryptographicProof(credentialId: string, tenantId: string): string {
  const data = `${credentialId}:${tenantId}:${Date.now()}`;
  return crypto.createHmac('sha256', config.encryptionKey)
    .update(data)
    .digest('hex');
}

// Initialize mesh networking on startup
if (config.meshNetworkEnabled) {
  meshNetwork.initialize().catch(console.error);
  
  // Handle mesh network events
  meshNetwork.on('credentialRevocation', async (payload) => {
    console.log('Received credential revocation via mesh:', payload);
    // Process mesh-propagated revocation
  });
  
  meshNetwork.on('deviceWipe', async (payload) => {
    console.log('Received device wipe command via mesh:', payload);
    // Process mesh-propagated device wipe
  });
}

// Error handling
app.onError((err, c) => {
  if (err instanceof HTTPException) {
    return c.json({
      error: err.message,
      status: err.status
    }, err.status);
  }

  console.error('Unhandled error:', err);
  return c.json({
    error: 'Internal server error',
    status: 500
  }, 500);
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not found',
    status: 404
  }, 404);
});

// Graceful shutdown with mesh networking cleanup
process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  if (config.meshNetworkEnabled) {
    await meshNetwork.shutdown();
  }
  await prisma.$disconnect();
  await redis.disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('Received SIGINT, shutting down gracefully...');
  if (config.meshNetworkEnabled) {
    await meshNetwork.shutdown();
  }
  await prisma.$disconnect();
  await redis.disconnect();
  process.exit(0);
});

// Start server
const server = Bun.serve({
  port: config.port,
  fetch: app.fetch
});

console.log(`🚀 Mobile Credential Service running on port ${config.port}`);
console.log(`📱 Supporting iOS and Android mobile credentials`);
console.log(`🔐 NFC and BLE protocols enabled with device-specific optimization`);
console.log(`⚡ Offline capability: ${config.offlineCapabilityHours} hours`);
console.log(`🌐 Mesh networking: ${config.meshNetworkEnabled ? 'enabled' : 'disabled'}`);
console.log(`👆 Biometric authentication: ${config.biometricEnabled ? 'enabled' : 'disabled'}`);
console.log(`🔋 Power management: ${config.powerManagementEnabled ? 'enabled' : 'disabled'}`);
console.log(`📱 Device management: ${config.deviceManagementEnabled ? 'enabled' : 'disabled'}`);
console.log(`🔒 Offline validation: ${config.offlineValidationEnabled ? 'enabled' : 'disabled'}`);

export default app;

// ============================================================================
// COMPREHENSIVE TEST SUITE
// ============================================================================

// Only include tests when running in test environment
if (process.env.NODE_ENV === 'test') {
  
  // Test dependencies
  const { describe, test, expect, beforeEach, afterEach, beforeAll, afterAll, jest } = require('@jest/globals');
  
  // Mock dependencies for testing
  jest.mock('@prisma/client');
  jest.mock('ioredis');
  jest.mock('jsonwebtoken');
  jest.mock('crypto');
  
  const mockPrisma = {
    user: {
      findFirst: jest.fn(),
    },
    mobileCredential: {
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      findMany: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    accessEvent: {
      create: jest.fn(),
    },
    auditLog: {
      create: jest.fn(),
    },
    $disconnect: jest.fn(),
  };
  
  const mockRedis = {
    setex: jest.fn(),
    get: jest.fn(),
    del: jest.fn(),
    publish: jest.fn(),
    disconnect: jest.fn(),
  };
  
  const mockJwt = {
    verify: jest.fn(),
  };
  
  const mockCrypto = {
    randomUUID: jest.fn(),
    randomBytes: jest.fn(),
    generateKeyPairSync: jest.fn(),
    createCipher: jest.fn(),
    createDecipher: jest.fn(),
    createVerify: jest.fn(),
  };
  
  // Test data factories
  const createTestUser = () => ({
    id: 'user-123',
    email: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    tenantId: 'tenant-123',
  });
  
  const createTestCredential = () => ({
    id: 'credential-123',
    userId: 'user-123',
    tenantId: 'tenant-123',
    deviceId: 'device-123',
    deviceType: 'ios',
    credentialType: 'nfc',
    publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
    encryptedPrivateKey: 'encrypted-private-key',
    serverPublicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
    status: 'active',
    enrolledAt: new Date(),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    lastUsedAt: null,
    metadata: {
      deviceInfo: {
        model: 'iPhone 14',
        osVersion: '16.0',
        appVersion: '1.0.0',
        capabilities: ['nfc', 'biometric']
      }
    }
  });
  
  const createTestEnrollmentRequest = () => ({
    userId: 'user-123',
    deviceId: 'device-123',
    deviceType: 'ios',
    credentialType: 'nfc',
    publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
    deviceInfo: {
      model: 'iPhone 14',
      osVersion: '16.0',
      appVersion: '1.0.0',
      capabilities: ['nfc', 'biometric']
    }
  });
  
  const createTestAuthRequest = () => ({
    credentialId: 'credential-123',
    challenge: 'challenge-123',
    signature: 'signature-123',
    readerId: 'reader-123',
    timestamp: Date.now(),
    location: {
      latitude: 37.7749,
      longitude: -122.4194
    }
  });
  
  const createTestJwtPayload = () => ({
    id: 'user-123',
    email: 'test@example.com',
    tenantId: 'tenant-123',
    role: 'user'
  });
  
  // Test helper functions
  const createAuthenticatedRequest = (method: string, path: string, body?: any) => {
    const req = new Request(`http://localhost:3007${path}`, {
      method,
      headers: {
        'Authorization': 'Bearer valid-token',
        'Content-Type': 'application/json'
      },
      body: body ? JSON.stringify(body) : undefined
    });
    return req;
  };
  
  const setupMocks = () => {
    mockJwt.verify.mockReturnValue(createTestJwtPayload());
    mockCrypto.randomUUID.mockReturnValue('credential-123');
    mockCrypto.randomBytes.mockReturnValue(Buffer.from('random-bytes'));
    mockCrypto.generateKeyPairSync.mockReturnValue({
      publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
      privateKey: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----'
    });
    
    const mockCipher = {
      update: jest.fn().mockReturnValue('encrypted'),
      final: jest.fn().mockReturnValue('data')
    };
    mockCrypto.createCipher.mockReturnValue(mockCipher);
    
    const mockVerify = {
      update: jest.fn(),
      verify: jest.fn().mockReturnValue(true)
    };
    mockCrypto.createVerify.mockReturnValue(mockVerify);
  };
  
  describe('Mobile Credential Service', () => {
    beforeAll(() => {
      setupMocks();
    });
    
    beforeEach(() => {
      jest.clearAllMocks();
    });
    
    describe('Health Check', () => {
      test('should return health status', async () => {
        const req = new Request('http://localhost:3007/health');
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.status).toBe('healthy');
        expect(data.service).toBe('mobile-credential-service');
      });
    });
    
    describe('Authentication Middleware', () => {
      test('should reject requests without authorization header', async () => {
        const req = new Request('http://localhost:3007/api/credentials', {
          method: 'GET'
        });
        const res = await app.fetch(req);
        
        expect(res.status).toBe(401);
      });
      
      test('should reject requests with invalid token', async () => {
        mockJwt.verify.mockImplementationOnce(() => {
          throw new Error('Invalid token');
        });
        
        const req = createAuthenticatedRequest('GET', '/api/credentials');
        const res = await app.fetch(req);
        
        expect(res.status).toBe(401);
      });
      
      test('should accept requests with valid token', async () => {
        mockPrisma.mobileCredential.findMany.mockResolvedValue([]);
        
        const req = createAuthenticatedRequest('GET', '/api/credentials');
        const res = await app.fetch(req);
        
        expect(res.status).toBe(200);
      });
    });
    
    describe('Mobile Credential Enrollment', () => {
      test('should successfully enroll a new credential', async () => {
        const enrollmentData = createTestEnrollmentRequest();
        const user = createTestUser();
        const credential = createTestCredential();
        
        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(null);
        mockPrisma.mobileCredential.create.mockResolvedValue(credential);
        mockRedis.setex.mockResolvedValue('OK');
        mockPrisma.auditLog.create.mockResolvedValue({});
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/enroll', enrollmentData);
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.success).toBe(true);
        expect(data.credentialId).toBe('credential-123');
        expect(data.serverPublicKey).toBeDefined();
        expect(mockPrisma.mobileCredential.create).toHaveBeenCalled();
        expect(mockRedis.setex).toHaveBeenCalled();
      });
      
      test('should reject enrollment for non-existent user', async () => {
        const enrollmentData = createTestEnrollmentRequest();
        
        mockPrisma.user.findFirst.mockResolvedValue(null);
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/enroll', enrollmentData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(404);
      });
      
      test('should reject enrollment for device with existing active credential', async () => {
        const enrollmentData = createTestEnrollmentRequest();
        const user = createTestUser();
        const existingCredential = createTestCredential();
        
        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(existingCredential);
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/enroll', enrollmentData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(409);
      });
      
      test('should validate enrollment request schema', async () => {
        const invalidData = {
          userId: 'invalid-uuid',
          deviceId: '',
          deviceType: 'invalid-type'
        };
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/enroll', invalidData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(400);
      });
    });
    
    describe('Mobile Credential Authentication', () => {
      test('should successfully authenticate with valid credential', async () => {
        const authData = createTestAuthRequest();
        const credentialData = {
          id: 'credential-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          status: 'active',
          credentialType: 'nfc'
        };
        
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        mockPrisma.mobileCredential.update.mockResolvedValue({});
        mockPrisma.accessEvent.create.mockResolvedValue({});
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData);
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.success).toBe(true);
        expect(data.accessGranted).toBe(true);
        expect(mockPrisma.accessEvent.create).toHaveBeenCalled();
      });
      
      test('should reject authentication for non-existent credential', async () => {
        const authData = createTestAuthRequest();
        
        mockRedis.get.mockResolvedValue(null);
        mockPrisma.mobileCredential.findUnique.mockResolvedValue(null);
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(404);
      });
      
      test('should reject authentication for inactive credential', async () => {
        const authData = createTestAuthRequest();
        const credentialData = {
          id: 'credential-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          status: 'suspended',
          credentialType: 'nfc'
        };
        
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(403);
      });
      
      test('should reject authentication with invalid signature', async () => {
        const authData = createTestAuthRequest();
        const credentialData = {
          id: 'credential-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          status: 'active',
          credentialType: 'nfc'
        };
        
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        
        const mockVerify = {
          update: jest.fn(),
          verify: jest.fn().mockReturnValue(false)
        };
        mockCrypto.createVerify.mockReturnValue(mockVerify);
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(401);
      });
      
      test('should reject authentication with expired timestamp', async () => {
        const authData = {
          ...createTestAuthRequest(),
          timestamp: Date.now() - 400000 // 6+ minutes ago
        };
        const credentialData = {
          id: 'credential-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          status: 'active',
          credentialType: 'nfc'
        };
        
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(401);
      });
    });
    
    describe('Challenge Generation', () => {
      test('should generate authentication challenge', async () => {
        const challengeData = { readerId: 'reader-123' };
        
        mockRedis.setex.mockResolvedValue('OK');
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/credential-123/challenge', challengeData);
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.challenge).toBeDefined();
        expect(data.timestamp).toBeDefined();
        expect(data.expiresIn).toBe(300);
        expect(mockRedis.setex).toHaveBeenCalled();
      });
      
      test('should reject challenge generation without reader ID', async () => {
        const req = createAuthenticatedRequest('POST', '/api/credentials/credential-123/challenge', {});
        const res = await app.fetch(req);
        
        expect(res.status).toBe(400);
      });
    });
    
    describe('Credential Listing', () => {
      test('should list user credentials', async () => {
        const credentials = [createTestCredential()];
        
        mockPrisma.mobileCredential.findMany.mockResolvedValue(credentials);
        
        const req = createAuthenticatedRequest('GET', '/api/credentials');
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.credentials).toHaveLength(1);
        expect(data.total).toBe(1);
      });
      
      test('should list credentials for specific user', async () => {
        const credentials = [createTestCredential()];
        
        mockPrisma.mobileCredential.findMany.mockResolvedValue(credentials);
        
        const req = createAuthenticatedRequest('GET', '/api/credentials?userId=user-456');
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(mockPrisma.mobileCredential.findMany).toHaveBeenCalledWith(
          expect.objectContaining({
            where: expect.objectContaining({
              userId: 'user-456'
            })
          })
        );
      });
    });
    
    describe('Credential Revocation', () => {
      test('should successfully revoke credentials', async () => {
        const revocationData = {
          credentialIds: ['credential-123', 'credential-456'],
          reason: 'lost',
          immediate: true
        };
        
        mockPrisma.mobileCredential.updateMany.mockResolvedValue({ count: 2 });
        mockRedis.del.mockResolvedValue(1);
        mockRedis.publish.mockResolvedValue(1);
        mockPrisma.auditLog.create.mockResolvedValue({});
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/revoke', revocationData);
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.success).toBe(true);
        expect(data.revokedCount).toBe(2);
        expect(mockRedis.publish).toHaveBeenCalled();
      });
      
      test('should validate revocation request schema', async () => {
        const invalidData = {
          credentialIds: ['invalid-uuid'],
          reason: 'invalid-reason'
        };
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/revoke', invalidData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(400);
      });
    });
    
    describe('Credential Status Management', () => {
      test('should successfully update credential status', async () => {
        const credential = createTestCredential();
        
        mockPrisma.mobileCredential.update.mockResolvedValue(credential);
        mockRedis.get.mockResolvedValue(JSON.stringify(credential));
        mockRedis.setex.mockResolvedValue('OK');
        mockPrisma.auditLog.create.mockResolvedValue({});
        
        const req = createAuthenticatedRequest('PATCH', '/api/credentials/credential-123/status', { status: 'suspended' });
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.success).toBe(true);
        expect(data.status).toBe('suspended');
        expect(mockRedis.setex).toHaveBeenCalled();
      });
      
      test('should reject invalid status values', async () => {
        const req = createAuthenticatedRequest('PATCH', '/api/credentials/credential-123/status', { status: 'invalid' });
        const res = await app.fetch(req);
        
        expect(res.status).toBe(400);
      });
    });
    
    describe('Credential Details', () => {
      test('should return credential details', async () => {
        const credential = createTestCredential();
        const user = createTestUser();
        
        mockPrisma.mobileCredential.findFirst.mockResolvedValue({
          ...credential,
          user
        });
        
        const req = createAuthenticatedRequest('GET', '/api/credentials/credential-123');
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.id).toBe('credential-123');
        expect(data.user).toBeDefined();
      });
      
      test('should return 404 for non-existent credential', async () => {
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(null);
        
        const req = createAuthenticatedRequest('GET', '/api/credentials/credential-123');
        const res = await app.fetch(req);
        
        expect(res.status).toBe(404);
      });
    });
    
    describe('Offline Event Synchronization', () => {
      test('should successfully process offline events', async () => {
        const events = [
          {
            userId: 'user-123',
            credentialId: 'credential-123',
            readerId: 'reader-123',
            eventType: 'access_granted',
            timestamp: Date.now(),
            metadata: {}
          }
        ];
        
        mockPrisma.accessEvent.create.mockResolvedValue({ id: 'event-123' });
        
        const req = createAuthenticatedRequest('POST', '/api/sync/offline-events', { events });
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.success).toBe(true);
        expect(data.processedCount).toBe(1);
        expect(data.totalReceived).toBe(1);
      });
      
      test('should handle invalid events gracefully', async () => {
        const events = [
          { invalid: 'event' },
          {
            userId: 'user-123',
            credentialId: 'credential-123',
            readerId: 'reader-123',
            eventType: 'access_granted',
            timestamp: Date.now(),
            metadata: {}
          }
        ];
        
        mockPrisma.accessEvent.create
          .mockRejectedValueOnce(new Error('Invalid event'))
          .mockResolvedValueOnce({ id: 'event-123' });
        
        const req = createAuthenticatedRequest('POST', '/api/sync/offline-events', { events });
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.processedCount).toBe(1);
        expect(data.totalReceived).toBe(2);
      });
      
      test('should reject non-array events', async () => {
        const req = createAuthenticatedRequest('POST', '/api/sync/offline-events', { events: 'invalid' });
        const res = await app.fetch(req);
        
        expect(res.status).toBe(400);
      });
    });
    
    describe('Utility Functions', () => {
      test('generateKeyPair should create RSA key pair', () => {
        const keyPair = generateKeyPair();
        expect(mockCrypto.generateKeyPairSync).toHaveBeenCalledWith('rsa', expect.any(Object));
      });
      
      test('encryptData should encrypt data', () => {
        const encrypted = encryptData('test-data', 'test-key');
        expect(mockCrypto.createCipher).toHaveBeenCalledWith('aes-256-cbc', 'test-key');
        expect(encrypted).toBe('encrypteddata');
      });
      
      test('generateChallenge should create random challenge', () => {
        const challenge = generateChallenge();
        expect(mockCrypto.randomBytes).toHaveBeenCalledWith(32);
      });
      
      test('verifySignature should verify signature', () => {
        const isValid = verifySignature('test-data', 'signature', 'public-key');
        expect(mockCrypto.createVerify).toHaveBeenCalledWith('SHA256');
        expect(isValid).toBe(true);
      });
      
      test('verifySignature should handle errors gracefully', () => {
        mockCrypto.createVerify.mockImplementationOnce(() => {
          throw new Error('Crypto error');
        });
        
        const isValid = verifySignature('test-data', 'signature', 'public-key');
        expect(isValid).toBe(false);
      });
    });
    
    describe('Security Tests', () => {
      test('should prevent replay attacks with old timestamps', async () => {
        const authData = {
          ...createTestAuthRequest(),
          timestamp: Date.now() - 400000 // 6+ minutes ago
        };
        const credentialData = {
          id: 'credential-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          status: 'active',
          credentialType: 'nfc'
        };
        
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(401);
      });
      
      test('should validate tenant isolation', async () => {
        const credential = {
          ...createTestCredential(),
          tenantId: 'different-tenant'
        };
        
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(credential);
        
        const req = createAuthenticatedRequest('GET', '/api/credentials/credential-123');
        const res = await app.fetch(req);
        
        expect(mockPrisma.mobileCredential.findFirst).toHaveBeenCalledWith(
          expect.objectContaining({
            where: expect.objectContaining({
              tenantId: 'tenant-123'
            })
          })
        );
      });
      
      test('should log all security events', async () => {
        const enrollmentData = createTestEnrollmentRequest();
        const user = createTestUser();
        const credential = createTestCredential();
        
        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(null);
        mockPrisma.mobileCredential.create.mockResolvedValue(credential);
        mockRedis.setex.mockResolvedValue('OK');
        mockPrisma.auditLog.create.mockResolvedValue({});
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/enroll', enrollmentData);
        await app.fetch(req);
        
        expect(mockPrisma.auditLog.create).toHaveBeenCalledWith(
          expect.objectContaining({
            data: expect.objectContaining({
              action: 'mobile_credential_enrolled',
              resourceType: 'mobile_credential'
            })
          })
        );
      });
    });
    
    describe('Performance Tests', () => {
      test('should handle concurrent enrollment requests', async () => {
        const enrollmentData = createTestEnrollmentRequest();
        const user = createTestUser();
        const credential = createTestCredential();
        
        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(null);
        mockPrisma.mobileCredential.create.mockResolvedValue(credential);
        mockRedis.setex.mockResolvedValue('OK');
        mockPrisma.auditLog.create.mockResolvedValue({});
        
        const requests = Array(10).fill(null).map(() => 
          createAuthenticatedRequest('POST', '/api/credentials/enroll', enrollmentData)
        );
        
        const responses = await Promise.all(requests.map(req => app.fetch(req)));
        
        expect(responses.every(res => res.status === 200 || res.status === 409)).toBe(true);
      });
      
      test('should handle high-volume authentication requests', async () => {
        const authData = createTestAuthRequest();
        const credentialData = {
          id: 'credential-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          status: 'active',
          credentialType: 'nfc'
        };
        
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        mockPrisma.mobileCredential.update.mockResolvedValue({});
        mockPrisma.accessEvent.create.mockResolvedValue({});
        
        const requests = Array(50).fill(null).map(() => 
          createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData)
        );
        
        const startTime = Date.now();
        const responses = await Promise.all(requests.map(req => app.fetch(req)));
        const endTime = Date.now();
        
        expect(responses.every(res => res.status === 200)).toBe(true);
        expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
      });
    });
    
    describe('Integration Tests', () => {
      test('should complete full credential lifecycle', async () => {
        // 1. Enroll credential
        const enrollmentData = createTestEnrollmentRequest();
        const user = createTestUser();
        const credential = createTestCredential();
        
        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(null);
        mockPrisma.mobileCredential.create.mockResolvedValue(credential);
        mockRedis.setex.mockResolvedValue('OK');
        mockPrisma.auditLog.create.mockResolvedValue({});
        
        const enrollReq = createAuthenticatedRequest('POST', '/api/credentials/enroll', enrollmentData);
        const enrollRes = await app.fetch(enrollReq);
        expect(enrollRes.status).toBe(200);
        
        // 2. Generate challenge
        mockRedis.setex.mockResolvedValue('OK');
        
        const challengeReq = createAuthenticatedRequest('POST', '/api/credentials/credential-123/challenge', { readerId: 'reader-123' });
        const challengeRes = await app.fetch(challengeReq);
        expect(challengeRes.status).toBe(200);
        
        // 3. Authenticate
        const authData = createTestAuthRequest();
        const credentialData = {
          id: 'credential-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          status: 'active',
          credentialType: 'nfc'
        };
        
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        mockPrisma.mobileCredential.update.mockResolvedValue({});
        mockPrisma.accessEvent.create.mockResolvedValue({});
        
        const authReq = createAuthenticatedRequest('POST', '/api/credentials/authenticate', authData);
        const authRes = await app.fetch(authReq);
        expect(authRes.status).toBe(200);
        
        // 4. Suspend credential
        mockPrisma.mobileCredential.update.mockResolvedValue(credential);
        mockRedis.get.mockResolvedValue(JSON.stringify(credentialData));
        mockRedis.setex.mockResolvedValue('OK');
        
        const suspendReq = createAuthenticatedRequest('PATCH', '/api/credentials/credential-123/status', { status: 'suspended' });
        const suspendRes = await app.fetch(suspendReq);
        expect(suspendRes.status).toBe(200);
        
        // 5. Revoke credential
        mockPrisma.mobileCredential.updateMany.mockResolvedValue({ count: 1 });
        mockRedis.del.mockResolvedValue(1);
        mockRedis.publish.mockResolvedValue(1);
        
        const revokeReq = createAuthenticatedRequest('POST', '/api/credentials/revoke', {
          credentialIds: ['credential-123'],
          reason: 'terminated',
          immediate: true
        });
        const revokeRes = await app.fetch(revokeReq);
        expect(revokeRes.status).toBe(200);
      });
      
      test('should handle offline synchronization workflow', async () => {
        // 1. Process offline events
        const events = [
          {
            userId: 'user-123',
            credentialId: 'credential-123',
            readerId: 'reader-123',
            eventType: 'access_granted',
            timestamp: Date.now() - 3600000, // 1 hour ago
            metadata: { offlineMode: true }
          },
          {
            userId: 'user-456',
            credentialId: 'credential-456',
            readerId: 'reader-456',
            eventType: 'access_denied',
            timestamp: Date.now() - 1800000, // 30 minutes ago
            metadata: { offlineMode: true }
          }
        ];
        
        mockPrisma.accessEvent.create.mockResolvedValue({ id: 'event-123' });
        
        const syncReq = createAuthenticatedRequest('POST', '/api/sync/offline-events', { events });
        const syncRes = await app.fetch(syncReq);
        const syncData = await syncRes.json();
        
        expect(syncRes.status).toBe(200);
        expect(syncData.processedCount).toBe(2);
        expect(mockPrisma.accessEvent.create).toHaveBeenCalledTimes(2);
      });
    });
    
    describe('Error Handling', () => {
      test('should handle database connection errors', async () => {
        mockPrisma.user.findFirst.mockRejectedValue(new Error('Database connection failed'));
        
        const enrollmentData = createTestEnrollmentRequest();
        const req = createAuthenticatedRequest('POST', '/api/credentials/enroll', enrollmentData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(500);
      });
      
      test('should handle Redis connection errors', async () => {
        mockRedis.setex.mockRejectedValue(new Error('Redis connection failed'));
        
        const challengeData = { readerId: 'reader-123' };
        const req = createAuthenticatedRequest('POST', '/api/credentials/credential-123/challenge', challengeData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(500);
      });
      
      test('should handle malformed JSON requests', async () => {
        const req = new Request('http://localhost:3007/api/credentials/enroll', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer valid-token',
            'Content-Type': 'application/json'
          },
          body: 'invalid-json'
        });
        
        const res = await app.fetch(req);
        expect(res.status).toBe(400);
      });
    });
    
    describe('Edge Cases', () => {
      test('should handle credential expiration', async () => {
        const expiredCredential = {
          ...createTestCredential(),
          expiresAt: new Date(Date.now() - 86400000) // Expired yesterday
        };
        
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(expiredCredential);
        
        const req = createAuthenticatedRequest('GET', '/api/credentials/credential-123');
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(new Date(data.expiresAt) < new Date()).toBe(true);
      });
      
      test('should handle empty credential list', async () => {
        mockPrisma.mobileCredential.findMany.mockResolvedValue([]);
        
        const req = createAuthenticatedRequest('GET', '/api/credentials');
        const res = await app.fetch(req);
        const data = await res.json();
        
        expect(res.status).toBe(200);
        expect(data.credentials).toHaveLength(0);
        expect(data.total).toBe(0);
      });
      
      test('should handle missing optional fields', async () => {
        const minimalEnrollmentData = {
          userId: 'user-123',
          deviceId: 'device-123',
          deviceType: 'ios',
          credentialType: 'nfc',
          publicKey: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----',
          deviceInfo: {
            model: 'iPhone 14',
            osVersion: '16.0',
            appVersion: '1.0.0',
            capabilities: ['nfc']
          }
        };
        
        const user = createTestUser();
        const credential = createTestCredential();
        
        mockPrisma.user.findFirst.mockResolvedValue(user);
        mockPrisma.mobileCredential.findFirst.mockResolvedValue(null);
        mockPrisma.mobileCredential.create.mockResolvedValue(credential);
        mockRedis.setex.mockResolvedValue('OK');
        mockPrisma.auditLog.create.mockResolvedValue({});
        
        const req = createAuthenticatedRequest('POST', '/api/credentials/enroll', minimalEnrollmentData);
        const res = await app.fetch(req);
        
        expect(res.status).toBe(200);
      });
    });
  });
}
