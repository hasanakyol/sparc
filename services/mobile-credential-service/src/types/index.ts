export interface BLEProtocolConfig {
  serviceUuid: string;
  characteristicUuid: string;
  advertisementInterval: number;
  connectionTimeout: number;
  powerLevel: 'low' | 'medium' | 'high';
  securityLevel: 'none' | 'encrypted' | 'authenticated';
}

export interface NFCProtocolConfig {
  technology: 'iso14443a' | 'iso14443b' | 'iso15693' | 'felica';
  dataFormat: 'ndef' | 'raw';
  maxDataSize: number;
  readTimeout: number;
  writeTimeout: number;
  securityFeatures: string[];
}

export interface MeshNetworkConfig {
  nodeId: string;
  networkKey: Buffer;
  multicastAddress: string;
  multicastPort: number;
  heartbeatInterval: number;
  propagationTimeout: number;
  maxHops: number;
}

export interface BiometricConfig {
  enabled: boolean;
  types: ('fingerprint' | 'face' | 'voice' | 'iris')[];
  fallbackToPin: boolean;
  maxAttempts: number;
  lockoutDuration: number;
}

export interface PowerManagementConfig {
  lowBatteryThreshold: number;
  criticalBatteryThreshold: number;
  powerSavingMode: boolean;
  backgroundSyncInterval: number;
  reducedFunctionalityMode: boolean;
}

export interface DeviceManagementConfig {
  remoteWipeEnabled: boolean;
  deviceLockEnabled: boolean;
  locationTrackingEnabled: boolean;
  complianceCheckInterval: number;
  certificateValidationEnabled: boolean;
}

export interface MeshMessage {
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

export interface OfflineCredentialData {
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