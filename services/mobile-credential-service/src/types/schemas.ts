import { z } from 'zod';

export const MobileCredentialSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  tenantId: z.string().uuid(),
  deviceInfo: z.object({
    deviceId: z.string(),
    model: z.string(),
    os: z.string(),
    osVersion: z.string(),
    appVersion: z.string(),
    hardwareId: z.string().optional(),
    securityLevel: z.enum(['basic', 'enhanced', 'maximum']),
    jailbroken: z.boolean().optional()
  }),
  credentialData: z.object({
    type: z.enum(['pin', 'biometric', 'cryptographic', 'hybrid']),
    format: z.enum(['iso18013', 'iso14443', 'proprietary']),
    issuer: z.string(),
    issuedAt: z.string(),
    expiresAt: z.string().optional(),
    publicKey: z.string(),
    encryptedPrivateKey: z.string().optional(),
    certificateChain: z.array(z.string()).optional()
  }),
  accessGroups: z.array(z.string()),
  protocolSettings: z.object({
    ble: z.object({
      enabled: z.boolean(),
      config: z.any() // Will use BLEProtocolConfig
    }).optional(),
    nfc: z.object({
      enabled: z.boolean(),
      config: z.any() // Will use NFCProtocolConfig
    }).optional()
  }),
  status: z.enum(['active', 'suspended', 'revoked', 'expired', 'pending_activation']),
  meshNetworkEnabled: z.boolean().default(true),
  biometricSettings: z.object({
    enabled: z.boolean(),
    types: z.array(z.enum(['fingerprint', 'face', 'voice', 'iris'])),
    fallbackToPin: z.boolean()
  }).optional(),
  powerManagement: z.object({
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

export const RevocationRequestSchema = z.object({
  credentialIds: z.array(z.string().uuid()),
  reason: z.enum(['lost', 'stolen', 'compromised', 'terminated', 'expired', 'security_breach']),
  immediate: z.boolean().default(true),
  meshPropagation: z.boolean().default(true),
  remoteWipe: z.boolean().default(false),
  notifyUser: z.boolean().default(true),
  propagationTimeout: z.number().default(900) // 15 minutes in seconds
});

export const DeviceManagementSchema = z.object({
  action: z.enum(['wipe', 'lock', 'unlock', 'locate', 'compliance_check', 'certificate_update']),
  deviceIds: z.array(z.string()),
  parameters: z.record(z.any()).optional(),
  immediate: z.boolean().default(true),
  notifyUser: z.boolean().default(true)
});

export const BiometricEnrollmentSchema = z.object({
  credentialId: z.string().uuid(),
  biometricType: z.enum(['fingerprint', 'face', 'voice', 'iris']),
  template: z.string(),
  quality: z.number(),
  liveness: z.boolean(),
  metadata: z.record(z.any()).optional()
});

export const OfflineSyncSchema = z.object({
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

export type MobileCredential = z.infer<typeof MobileCredentialSchema>;
export type RevocationRequest = z.infer<typeof RevocationRequestSchema>;
export type DeviceManagementRequest = z.infer<typeof DeviceManagementSchema>;
export type BiometricEnrollment = z.infer<typeof BiometricEnrollmentSchema>;
export type OfflineSync = z.infer<typeof OfflineSyncSchema>;