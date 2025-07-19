import { z } from 'zod';

// =============================================================================
// ENVIRONMENT VALIDATION SCHEMAS
// =============================================================================

const EnvironmentSchema = z.enum(['development', 'staging', 'production', 'test']);

const LogLevelSchema = z.enum(['error', 'warn', 'info', 'debug', 'trace']);

const TenantIsolationModeSchema = z.enum(['schema', 'database', 'hybrid']);

const VideoStreamProtocolSchema = z.enum(['webrtc', 'hls', 'rtmp']);

const VideoQualitySchema = z.enum(['low', 'medium', 'high', 'ultra']);

const VideoResolutionSchema = z.enum(['720p', '1080p', '4k']);

const VideoCompressionSchema = z.enum(['h264', 'h265', 'vp9']);

const PrivacyMaskingAlgorithmSchema = z.enum(['blur', 'pixelate', 'black']);

const OfflineCacheTypeSchema = z.enum(['redis', 'memory', 'file']);

const SmsProviderSchema = z.enum(['twilio', 'aws-sns', 'nexmo']);

const EncryptionAlgorithmSchema = z.enum(['aes-256-gcm', 'aes-256-cbc']);

const LogFormatSchema = z.enum(['json', 'text']);

// =============================================================================
// CORE CONFIGURATION SCHEMAS
// =============================================================================

const DatabaseConfigSchema = z.object({
  url: z.string().url(),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  name: z.string().min(1),
  user: z.string().min(1),
  password: z.string().min(1),
  ssl: z.boolean(),
  poolMin: z.number().int().min(0).default(2),
  poolMax: z.number().int().min(1).default(10),
  connectionTimeout: z.number().int().min(1000).default(30000),
  idleTimeout: z.number().int().min(1000).default(600000),
  runMigrations: z.boolean().default(true),
  migrationTableName: z.string().default('sparc_migrations'),
});

const RedisConfigSchema = z.object({
  url: z.string().url(),
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  password: z.string().optional(),
  db: z.number().int().min(0).default(0),
  ttl: z.number().int().min(1).default(3600),
  maxRetries: z.number().int().min(0).default(3),
  retryDelay: z.number().int().min(100).default(1000),
});

const SessionRedisConfigSchema = z.object({
  url: z.string().url(),
  db: z.number().int().min(0).default(1),
  ttl: z.number().int().min(1).default(86400),
});

const JwtConfigSchema = z.object({
  secret: z.string().min(32),
  expiresIn: z.string().default('24h'),
  refreshSecret: z.string().min(32),
  refreshExpiresIn: z.string().default('7d'),
  issuer: z.string().default('sparc-platform'),
  audience: z.string().default('sparc-users'),
});

const PasswordConfigSchema = z.object({
  bcryptRounds: z.number().int().min(10).max(15).default(12),
  minLength: z.number().int().min(8).default(8),
  requireSpecialChars: z.boolean().default(true),
});

const AwsConfigSchema = z.object({
  region: z.string().min(1),
  accessKeyId: z.string().min(1),
  secretAccessKey: z.string().min(1),
  s3: z.object({
    bucket: z.string().min(1),
    region: z.string().min(1),
    videoBucket: z.string().min(1),
    backupBucket: z.string().min(1),
    presignedUrlExpires: z.number().int().min(300).default(3600),
  }),
  cloudfront: z.object({
    domain: z.string().min(1),
    distributionId: z.string().min(1),
  }),
  ses: z.object({
    region: z.string().min(1),
    fromEmail: z.string().email(),
    replyToEmail: z.string().email(),
  }),
  sns: z.object({
    region: z.string().min(1),
    smsSenderId: z.string().min(1),
  }),
});

const ServiceEndpointsSchema = z.object({
  apiGateway: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(30000),
  }),
  authService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(5000),
  }),
  tenantService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(5000),
  }),
  accessControlService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(10000),
  }),
  deviceManagementService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(15000),
  }),
  videoManagementService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(30000),
  }),
  eventProcessingService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(5000),
  }),
  analyticsService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(60000),
  }),
  reportingService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(30000),
  }),
  mobileCredentialService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(10000),
  }),
  visitorManagementService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(10000),
  }),
  environmentalService: z.object({
    url: z.string().url(),
    timeout: z.number().int().min(1000).default(10000),
  }),
});

const MultiTenantConfigSchema = z.object({
  isolationMode: TenantIsolationModeSchema.default('schema'),
  defaultTenantId: z.string().default('default'),
  subdomainEnabled: z.boolean().default(true),
  customDomainEnabled: z.boolean().default(true),
  defaultUserLimit: z.number().int().min(1).default(100),
  defaultDeviceLimit: z.number().int().min(1).default(500),
  defaultStorageLimitGb: z.number().int().min(1).default(100),
  defaultBandwidthLimitMbps: z.number().int().min(1).default(100),
  dbPoolSize: z.number().int().min(1).default(5),
  dbConnectionLimit: z.number().int().min(1).default(50),
});

const OfflineConfigSchema = z.object({
  enabled: z.boolean().default(true),
  cacheDuration: z.number().int().min(3600).default(86400),
  syncInterval: z.number().int().min(60).default(300),
  maxQueueSize: z.number().int().min(1000).default(10000),
  cacheType: OfflineCacheTypeSchema.default('redis'),
  cacheSizeMb: z.number().int().min(64).default(512),
  credentialCacheTtl: z.number().int().min(3600).default(604800),
  meshNetworkEnabled: z.boolean().default(true),
  meshNetworkPort: z.number().int().min(1024).max(65535).default(8080),
  meshDiscoveryInterval: z.number().int().min(10).default(30),
});

const VideoConfigSchema = z.object({
  streamProtocol: VideoStreamProtocolSchema.default('webrtc'),
  streamQuality: VideoQualitySchema.default('high'),
  streamMaxBitrate: z.number().int().min(500).default(5000),
  streamTimeout: z.number().int().min(5000).default(30000),
  recordingEnabled: z.boolean().default(true),
  recordingQuality: VideoResolutionSchema.default('1080p'),
  recordingFps: z.number().int().min(15).max(60).default(30),
  recordingRetentionDays: z.number().int().min(1).default(90),
  recordingCompression: VideoCompressionSchema.default('h264'),
  onvifDiscoveryEnabled: z.boolean().default(true),
  onvifDiscoveryTimeout: z.number().int().min(5000).default(10000),
  onvifUsername: z.string().min(1),
  onvifPassword: z.string().min(1),
  privacyMaskingEnabled: z.boolean().default(true),
  privacyMaskingAlgorithm: PrivacyMaskingAlgorithmSchema.default('blur'),
});

const HardwareConfigSchema = z.object({
  osdp: z.object({
    enabled: z.boolean().default(true),
    version: z.string().default('2.2'),
    secureChannel: z.boolean().default(true),
    pollInterval: z.number().int().min(100).default(1000),
  }),
  device: z.object({
    communicationTimeout: z.number().int().min(1000).default(5000),
    heartbeatInterval: z.number().int().min(10000).default(30000),
    retryAttempts: z.number().int().min(1).default(3),
  }),
  manufacturers: z.object({
    hidApiEnabled: z.boolean().default(false),
    hidApiKey: z.string().optional(),
    honeywellApiEnabled: z.boolean().default(false),
    honeywellApiKey: z.string().optional(),
    boschApiEnabled: z.boolean().default(false),
    boschApiKey: z.string().optional(),
  }),
});

const MobileCredentialConfigSchema = z.object({
  appBundleId: z.string().default('com.sparc.mobile'),
  appDeepLinkScheme: z.string().default('sparc'),
  encryptionKey: z.string().min(32),
  firebase: z.object({
    projectId: z.string().min(1),
    privateKey: z.string().min(1),
    clientEmail: z.string().email(),
  }),
  apns: z.object({
    keyId: z.string().min(1),
    teamId: z.string().min(1),
    privateKey: z.string().min(1),
  }),
  nfcEnabled: z.boolean().default(true),
  bleEnabled: z.boolean().default(true),
  bleAdvertisingInterval: z.number().int().min(20).default(100),
  bleConnectionTimeout: z.number().int().min(5000).default(10000),
});

const AnalyticsConfigSchema = z.object({
  mlServiceEnabled: z.boolean().default(false),
  mlServiceUrl: z.string().url().optional(),
  mlApiKey: z.string().optional(),
  faceRecognitionEnabled: z.boolean().default(false),
  faceRecognitionConfidenceThreshold: z.number().min(0).max(1).default(0.8),
  faceRecognitionMaxFaces: z.number().int().min(1).default(10),
  lprEnabled: z.boolean().default(false),
  lprConfidenceThreshold: z.number().min(0).max(1).default(0.9),
  lprRegions: z.array(z.string()).default(['US', 'CA', 'EU']),
  behavioralAnalyticsEnabled: z.boolean().default(false),
  occupancyTrackingEnabled: z.boolean().default(true),
  crowdDetectionEnabled: z.boolean().default(false),
});

const EnvironmentalConfigSchema = z.object({
  monitoringEnabled: z.boolean().default(true),
  temperatureMonitoring: z.boolean().default(true),
  humidityMonitoring: z.boolean().default(true),
  waterDetection: z.boolean().default(true),
  airQualityMonitoring: z.boolean().default(false),
  hvacIntegrationEnabled: z.boolean().default(false),
  hvacApiUrl: z.string().url().optional(),
  hvacApiKey: z.string().optional(),
  temperatureMinThreshold: z.number().default(15),
  temperatureMaxThreshold: z.number().default(30),
  humidityMinThreshold: z.number().default(30),
  humidityMaxThreshold: z.number().default(70),
});

const NotificationConfigSchema = z.object({
  email: z.object({
    smtpHost: z.string().min(1),
    smtpPort: z.number().int().min(1).max(65535),
    smtpSecure: z.boolean().default(true),
    smtpUser: z.string().min(1),
    smtpPassword: z.string().min(1),
  }),
  sms: z.object({
    provider: SmsProviderSchema.default('twilio'),
    twilioAccountSid: z.string().optional(),
    twilioAuthToken: z.string().optional(),
    twilioPhoneNumber: z.string().optional(),
  }),
  webhook: z.object({
    enabled: z.boolean().default(true),
    secret: z.string().min(16),
    timeout: z.number().int().min(1000).default(10000),
  }),
});

const SecurityConfigSchema = z.object({
  api: z.object({
    rateLimitWindow: z.number().int().min(60000).default(900000),
    rateLimitMaxRequests: z.number().int().min(10).default(100),
    corsOrigins: z.array(z.string().url()),
  }),
  encryption: z.object({
    algorithm: EncryptionAlgorithmSchema.default('aes-256-gcm'),
    key: z.string().length(32),
    dataEncryptionAtRest: z.boolean().default(true),
  }),
  headers: z.object({
    enabled: z.boolean().default(true),
    hstsMaxAge: z.number().int().min(0).default(31536000),
    cspEnabled: z.boolean().default(true),
  }),
});

const MonitoringConfigSchema = z.object({
  apm: z.object({
    enabled: z.boolean().default(false),
    serviceName: z.string().default('sparc-platform'),
    serviceVersion: z.string().default('1.0.0'),
  }),
  logging: z.object({
    format: LogFormatSchema.default('json'),
    timestamp: z.boolean().default(true),
    correlationId: z.boolean().default(true),
    sensitiveData: z.boolean().default(false),
  }),
  healthCheck: z.object({
    enabled: z.boolean().default(true),
    interval: z.number().int().min(10000).default(30000),
    timeout: z.number().int().min(1000).default(5000),
  }),
  metrics: z.object({
    enabled: z.boolean().default(true),
    port: z.number().int().min(1024).max(65535).default(9090),
    path: z.string().default('/metrics'),
  }),
});

const DevelopmentConfigSchema = z.object({
  debugMode: z.boolean().default(false),
  mockHardware: z.boolean().default(true),
  mockExternalApis: z.boolean().default(true),
  seedDatabase: z.boolean().default(true),
  testDatabaseUrl: z.string().url().optional(),
  testRedisUrl: z.string().url().optional(),
  testTimeout: z.number().int().min(5000).default(30000),
  hotReloadEnabled: z.boolean().default(true),
  watchFiles: z.boolean().default(true),
});

// =============================================================================
// MAIN CONFIGURATION SCHEMA
// =============================================================================

const ConfigSchema = z.object({
  env: EnvironmentSchema,
  logLevel: LogLevelSchema,
  port: z.number().int().min(1).max(65535),
  database: DatabaseConfigSchema,
  redis: RedisConfigSchema,
  sessionRedis: SessionRedisConfigSchema,
  jwt: JwtConfigSchema,
  password: PasswordConfigSchema,
  aws: AwsConfigSchema,
  services: ServiceEndpointsSchema,
  multiTenant: MultiTenantConfigSchema,
  offline: OfflineConfigSchema,
  video: VideoConfigSchema,
  hardware: HardwareConfigSchema,
  mobileCredential: MobileCredentialConfigSchema,
  analytics: AnalyticsConfigSchema,
  environmental: EnvironmentalConfigSchema,
  notifications: NotificationConfigSchema,
  security: SecurityConfigSchema,
  monitoring: MonitoringConfigSchema,
  development: DevelopmentConfigSchema,
});

// =============================================================================
// CONFIGURATION TYPES
// =============================================================================

export type Config = z.infer<typeof ConfigSchema>;
export type DatabaseConfig = z.infer<typeof DatabaseConfigSchema>;
export type RedisConfig = z.infer<typeof RedisConfigSchema>;
export type JwtConfig = z.infer<typeof JwtConfigSchema>;
export type AwsConfig = z.infer<typeof AwsConfigSchema>;
export type ServiceEndpoints = z.infer<typeof ServiceEndpointsSchema>;
export type MultiTenantConfig = z.infer<typeof MultiTenantConfigSchema>;
export type OfflineConfig = z.infer<typeof OfflineConfigSchema>;
export type VideoConfig = z.infer<typeof VideoConfigSchema>;
export type HardwareConfig = z.infer<typeof HardwareConfigSchema>;
export type MobileCredentialConfig = z.infer<typeof MobileCredentialConfigSchema>;
export type AnalyticsConfig = z.infer<typeof AnalyticsConfigSchema>;
export type EnvironmentalConfig = z.infer<typeof EnvironmentalConfigSchema>;
export type NotificationConfig = z.infer<typeof NotificationConfigSchema>;
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;
export type MonitoringConfig = z.infer<typeof MonitoringConfigSchema>;
export type DevelopmentConfig = z.infer<typeof DevelopmentConfigSchema>;

// =============================================================================
// CONFIGURATION LOADING AND VALIDATION
// =============================================================================

function loadEnvironmentVariables(): Record<string, string | undefined> {
  return {
    // Environment
    NODE_ENV: process.env.NODE_ENV,
    LOG_LEVEL: process.env.LOG_LEVEL,
    PORT: process.env.PORT,

    // Database
    DATABASE_URL: process.env.DATABASE_URL,
    DATABASE_HOST: process.env.DATABASE_HOST,
    DATABASE_PORT: process.env.DATABASE_PORT,
    DATABASE_NAME: process.env.DATABASE_NAME,
    DATABASE_USER: process.env.DATABASE_USER,
    DATABASE_PASSWORD: process.env.DATABASE_PASSWORD,
    DATABASE_SSL: process.env.DATABASE_SSL,
    DATABASE_POOL_MIN: process.env.DATABASE_POOL_MIN,
    DATABASE_POOL_MAX: process.env.DATABASE_POOL_MAX,
    DATABASE_CONNECTION_TIMEOUT: process.env.DATABASE_CONNECTION_TIMEOUT,
    DATABASE_IDLE_TIMEOUT: process.env.DATABASE_IDLE_TIMEOUT,
    RUN_MIGRATIONS: process.env.RUN_MIGRATIONS,
    MIGRATION_TABLE_NAME: process.env.MIGRATION_TABLE_NAME,

    // Redis
    REDIS_URL: process.env.REDIS_URL,
    REDIS_HOST: process.env.REDIS_HOST,
    REDIS_PORT: process.env.REDIS_PORT,
    REDIS_PASSWORD: process.env.REDIS_PASSWORD,
    REDIS_DB: process.env.REDIS_DB,
    REDIS_TTL: process.env.REDIS_TTL,
    REDIS_MAX_RETRIES: process.env.REDIS_MAX_RETRIES,
    REDIS_RETRY_DELAY: process.env.REDIS_RETRY_DELAY,

    // Session Redis
    SESSION_REDIS_URL: process.env.SESSION_REDIS_URL,
    SESSION_REDIS_DB: process.env.SESSION_REDIS_DB,
    SESSION_TTL: process.env.SESSION_TTL,

    // JWT
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN,
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
    JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN,
    JWT_ISSUER: process.env.JWT_ISSUER,
    JWT_AUDIENCE: process.env.JWT_AUDIENCE,

    // Password
    BCRYPT_ROUNDS: process.env.BCRYPT_ROUNDS,
    PASSWORD_MIN_LENGTH: process.env.PASSWORD_MIN_LENGTH,
    PASSWORD_REQUIRE_SPECIAL_CHARS: process.env.PASSWORD_REQUIRE_SPECIAL_CHARS,

    // AWS
    AWS_REGION: process.env.AWS_REGION,
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
    AWS_S3_BUCKET: process.env.AWS_S3_BUCKET,
    AWS_S3_REGION: process.env.AWS_S3_REGION,
    AWS_S3_VIDEO_BUCKET: process.env.AWS_S3_VIDEO_BUCKET,
    AWS_S3_BACKUP_BUCKET: process.env.AWS_S3_BACKUP_BUCKET,
    AWS_S3_PRESIGNED_URL_EXPIRES: process.env.AWS_S3_PRESIGNED_URL_EXPIRES,
    AWS_CLOUDFRONT_DOMAIN: process.env.AWS_CLOUDFRONT_DOMAIN,
    AWS_CLOUDFRONT_DISTRIBUTION_ID: process.env.AWS_CLOUDFRONT_DISTRIBUTION_ID,
    AWS_SES_REGION: process.env.AWS_SES_REGION,
    AWS_SES_FROM_EMAIL: process.env.AWS_SES_FROM_EMAIL,
    AWS_SES_REPLY_TO_EMAIL: process.env.AWS_SES_REPLY_TO_EMAIL,
    AWS_SNS_REGION: process.env.AWS_SNS_REGION,
    AWS_SNS_SMS_SENDER_ID: process.env.AWS_SNS_SMS_SENDER_ID,

    // Service Endpoints
    API_GATEWAY_URL: process.env.API_GATEWAY_URL,
    API_GATEWAY_TIMEOUT: process.env.API_GATEWAY_TIMEOUT,
    AUTH_SERVICE_URL: process.env.AUTH_SERVICE_URL,
    AUTH_SERVICE_TIMEOUT: process.env.AUTH_SERVICE_TIMEOUT,
    TENANT_SERVICE_URL: process.env.TENANT_SERVICE_URL,
    TENANT_SERVICE_TIMEOUT: process.env.TENANT_SERVICE_TIMEOUT,
    ACCESS_CONTROL_SERVICE_URL: process.env.ACCESS_CONTROL_SERVICE_URL,
    ACCESS_CONTROL_SERVICE_TIMEOUT: process.env.ACCESS_CONTROL_SERVICE_TIMEOUT,
    DEVICE_MANAGEMENT_SERVICE_URL: process.env.DEVICE_MANAGEMENT_SERVICE_URL,
    DEVICE_MANAGEMENT_SERVICE_TIMEOUT: process.env.DEVICE_MANAGEMENT_SERVICE_TIMEOUT,
    VIDEO_MANAGEMENT_SERVICE_URL: process.env.VIDEO_MANAGEMENT_SERVICE_URL,
    VIDEO_MANAGEMENT_SERVICE_TIMEOUT: process.env.VIDEO_MANAGEMENT_SERVICE_TIMEOUT,
    EVENT_PROCESSING_SERVICE_URL: process.env.EVENT_PROCESSING_SERVICE_URL,
    EVENT_PROCESSING_SERVICE_TIMEOUT: process.env.EVENT_PROCESSING_SERVICE_TIMEOUT,
    ANALYTICS_SERVICE_URL: process.env.ANALYTICS_SERVICE_URL,
    ANALYTICS_SERVICE_TIMEOUT: process.env.ANALYTICS_SERVICE_TIMEOUT,
    REPORTING_SERVICE_URL: process.env.REPORTING_SERVICE_URL,
    REPORTING_SERVICE_TIMEOUT: process.env.REPORTING_SERVICE_TIMEOUT,
    MOBILE_CREDENTIAL_SERVICE_URL: process.env.MOBILE_CREDENTIAL_SERVICE_URL,
    MOBILE_CREDENTIAL_SERVICE_TIMEOUT: process.env.MOBILE_CREDENTIAL_SERVICE_TIMEOUT,
    VISITOR_MANAGEMENT_SERVICE_URL: process.env.VISITOR_MANAGEMENT_SERVICE_URL,
    VISITOR_MANAGEMENT_SERVICE_TIMEOUT: process.env.VISITOR_MANAGEMENT_SERVICE_TIMEOUT,
    ENVIRONMENTAL_SERVICE_URL: process.env.ENVIRONMENTAL_SERVICE_URL,
    ENVIRONMENTAL_SERVICE_TIMEOUT: process.env.ENVIRONMENTAL_SERVICE_TIMEOUT,

    // Multi-tenant
    TENANT_ISOLATION_MODE: process.env.TENANT_ISOLATION_MODE,
    DEFAULT_TENANT_ID: process.env.DEFAULT_TENANT_ID,
    TENANT_SUBDOMAIN_ENABLED: process.env.TENANT_SUBDOMAIN_ENABLED,
    TENANT_CUSTOM_DOMAIN_ENABLED: process.env.TENANT_CUSTOM_DOMAIN_ENABLED,
    DEFAULT_TENANT_USER_LIMIT: process.env.DEFAULT_TENANT_USER_LIMIT,
    DEFAULT_TENANT_DEVICE_LIMIT: process.env.DEFAULT_TENANT_DEVICE_LIMIT,
    DEFAULT_TENANT_STORAGE_LIMIT_GB: process.env.DEFAULT_TENANT_STORAGE_LIMIT_GB,
    DEFAULT_TENANT_BANDWIDTH_LIMIT_MBPS: process.env.DEFAULT_TENANT_BANDWIDTH_LIMIT_MBPS,
    TENANT_DB_POOL_SIZE: process.env.TENANT_DB_POOL_SIZE,
    TENANT_DB_CONNECTION_LIMIT: process.env.TENANT_DB_CONNECTION_LIMIT,

    // Offline
    OFFLINE_MODE_ENABLED: process.env.OFFLINE_MODE_ENABLED,
    OFFLINE_CACHE_DURATION: process.env.OFFLINE_CACHE_DURATION,
    OFFLINE_SYNC_INTERVAL: process.env.OFFLINE_SYNC_INTERVAL,
    OFFLINE_MAX_QUEUE_SIZE: process.env.OFFLINE_MAX_QUEUE_SIZE,
    OFFLINE_CACHE_TYPE: process.env.OFFLINE_CACHE_TYPE,
    OFFLINE_CACHE_SIZE_MB: process.env.OFFLINE_CACHE_SIZE_MB,
    OFFLINE_CREDENTIAL_CACHE_TTL: process.env.OFFLINE_CREDENTIAL_CACHE_TTL,
    MESH_NETWORK_ENABLED: process.env.MESH_NETWORK_ENABLED,
    MESH_NETWORK_PORT: process.env.MESH_NETWORK_PORT,
    MESH_DISCOVERY_INTERVAL: process.env.MESH_DISCOVERY_INTERVAL,

    // Video
    VIDEO_STREAM_PROTOCOL: process.env.VIDEO_STREAM_PROTOCOL,
    VIDEO_STREAM_QUALITY: process.env.VIDEO_STREAM_QUALITY,
    VIDEO_STREAM_MAX_BITRATE: process.env.VIDEO_STREAM_MAX_BITRATE,
    VIDEO_STREAM_TIMEOUT: process.env.VIDEO_STREAM_TIMEOUT,
    VIDEO_RECORDING_ENABLED: process.env.VIDEO_RECORDING_ENABLED,
    VIDEO_RECORDING_QUALITY: process.env.VIDEO_RECORDING_QUALITY,
    VIDEO_RECORDING_FPS: process.env.VIDEO_RECORDING_FPS,
    VIDEO_RECORDING_RETENTION_DAYS: process.env.VIDEO_RECORDING_RETENTION_DAYS,
    VIDEO_RECORDING_COMPRESSION: process.env.VIDEO_RECORDING_COMPRESSION,
    ONVIF_DISCOVERY_ENABLED: process.env.ONVIF_DISCOVERY_ENABLED,
    ONVIF_DISCOVERY_TIMEOUT: process.env.ONVIF_DISCOVERY_TIMEOUT,
    ONVIF_USERNAME: process.env.ONVIF_USERNAME,
    ONVIF_PASSWORD: process.env.ONVIF_PASSWORD,
    PRIVACY_MASKING_ENABLED: process.env.PRIVACY_MASKING_ENABLED,
    PRIVACY_MASKING_ALGORITHM: process.env.PRIVACY_MASKING_ALGORITHM,

    // Hardware
    OSDP_ENABLED: process.env.OSDP_ENABLED,
    OSDP_VERSION: process.env.OSDP_VERSION,
    OSDP_SECURE_CHANNEL: process.env.OSDP_SECURE_CHANNEL,
    OSDP_POLL_INTERVAL: process.env.OSDP_POLL_INTERVAL,
    DEVICE_COMMUNICATION_TIMEOUT: process.env.DEVICE_COMMUNICATION_TIMEOUT,
    DEVICE_HEARTBEAT_INTERVAL: process.env.DEVICE_HEARTBEAT_INTERVAL,
    DEVICE_RETRY_ATTEMPTS: process.env.DEVICE_RETRY_ATTEMPTS,
    HID_API_ENABLED: process.env.HID_API_ENABLED,
    HID_API_KEY: process.env.HID_API_KEY,
    HONEYWELL_API_ENABLED: process.env.HONEYWELL_API_ENABLED,
    HONEYWELL_API_KEY: process.env.HONEYWELL_API_KEY,
    BOSCH_API_ENABLED: process.env.BOSCH_API_ENABLED,
    BOSCH_API_KEY: process.env.BOSCH_API_KEY,

    // Mobile Credentials
    MOBILE_APP_BUNDLE_ID: process.env.MOBILE_APP_BUNDLE_ID,
    MOBILE_APP_DEEP_LINK_SCHEME: process.env.MOBILE_APP_DEEP_LINK_SCHEME,
    MOBILE_CREDENTIAL_ENCRYPTION_KEY: process.env.MOBILE_CREDENTIAL_ENCRYPTION_KEY,
    FIREBASE_PROJECT_ID: process.env.FIREBASE_PROJECT_ID,
    FIREBASE_PRIVATE_KEY: process.env.FIREBASE_PRIVATE_KEY,
    FIREBASE_CLIENT_EMAIL: process.env.FIREBASE_CLIENT_EMAIL,
    APNS_KEY_ID: process.env.APNS_KEY_ID,
    APNS_TEAM_ID: process.env.APNS_TEAM_ID,
    APNS_PRIVATE_KEY: process.env.APNS_PRIVATE_KEY,
    NFC_ENABLED: process.env.NFC_ENABLED,
    BLE_ENABLED: process.env.BLE_ENABLED,
    BLE_ADVERTISING_INTERVAL: process.env.BLE_ADVERTISING_INTERVAL,
    BLE_CONNECTION_TIMEOUT: process.env.BLE_CONNECTION_TIMEOUT,

    // Analytics
    ML_SERVICE_ENABLED: process.env.ML_SERVICE_ENABLED,
    ML_SERVICE_URL: process.env.ML_SERVICE_URL,
    ML_API_KEY: process.env.ML_API_KEY,
    FACE_RECOGNITION_ENABLED: process.env.FACE_RECOGNITION_ENABLED,
    FACE_RECOGNITION_CONFIDENCE_THRESHOLD: process.env.FACE_RECOGNITION_CONFIDENCE_THRESHOLD,
    FACE_RECOGNITION_MAX_FACES: process.env.FACE_RECOGNITION_MAX_FACES,
    LPR_ENABLED: process.env.LPR_ENABLED,
    LPR_CONFIDENCE_THRESHOLD: process.env.LPR_CONFIDENCE_THRESHOLD,
    LPR_REGIONS: process.env.LPR_REGIONS,
    BEHAVIORAL_ANALYTICS_ENABLED: process.env.BEHAVIORAL_ANALYTICS_ENABLED,
    OCCUPANCY_TRACKING_ENABLED: process.env.OCCUPANCY_TRACKING_ENABLED,
    CROWD_DETECTION_ENABLED: process.env.CROWD_DETECTION_ENABLED,

    // Environmental
    ENVIRONMENTAL_MONITORING_ENABLED: process.env.ENVIRONMENTAL_MONITORING_ENABLED,
    TEMPERATURE_MONITORING: process.env.TEMPERATURE_MONITORING,
    HUMIDITY_MONITORING: process.env.HUMIDITY_MONITORING,
    WATER_DETECTION: process.env.WATER_DETECTION,
    AIR_QUALITY_MONITORING: process.env.AIR_QUALITY_MONITORING,
    HVAC_INTEGRATION_ENABLED: process.env.HVAC_INTEGRATION_ENABLED,
    HVAC_API_URL: process.env.HVAC_API_URL,
    HVAC_API_KEY: process.env.HVAC_API_KEY,
    TEMPERATURE_MIN_THRESHOLD: process.env.TEMPERATURE_MIN_THRESHOLD,
    TEMPERATURE_MAX_THRESHOLD: process.env.TEMPERATURE_MAX_THRESHOLD,
    HUMIDITY_MIN_THRESHOLD: process.env.HUMIDITY_MIN_THRESHOLD,
    HUMIDITY_MAX_THRESHOLD: process.env.HUMIDITY_MAX_THRESHOLD,

    // Notifications
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_PORT: process.env.SMTP_PORT,
    SMTP_SECURE: process.env.SMTP_SECURE,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASSWORD: process.env.SMTP_PASSWORD,
    SMS_PROVIDER: process.env.SMS_PROVIDER,
    TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
    TWILIO_PHONE_NUMBER: process.env.TWILIO_PHONE_NUMBER,
    WEBHOOK_ENABLED: process.env.WEBHOOK_ENABLED,
    WEBHOOK_SECRET: process.env.WEBHOOK_SECRET,
    WEBHOOK_TIMEOUT: process.env.WEBHOOK_TIMEOUT,

    // Security
    API_RATE_LIMIT_WINDOW: process.env.API_RATE_LIMIT_WINDOW,
    API_RATE_LIMIT_MAX_REQUESTS: process.env.API_RATE_LIMIT_MAX_REQUESTS,
    API_CORS_ORIGINS: process.env.API_CORS_ORIGINS,
    ENCRYPTION_ALGORITHM: process.env.ENCRYPTION_ALGORITHM,
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY,
    DATA_ENCRYPTION_AT_REST: process.env.DATA_ENCRYPTION_AT_REST,
    SECURITY_HEADERS_ENABLED: process.env.SECURITY_HEADERS_ENABLED,
    HSTS_MAX_AGE: process.env.HSTS_MAX_AGE,
    CSP_ENABLED: process.env.CSP_ENABLED,

    // Monitoring
    APM_ENABLED: process.env.APM_ENABLED,
    APM_SERVICE_NAME: process.env.APM_SERVICE_NAME,
    APM_SERVICE_VERSION: process.env.APM_SERVICE_VERSION,
    LOG_FORMAT: process.env.LOG_FORMAT,
    LOG_TIMESTAMP: process.env.LOG_TIMESTAMP,
    LOG_CORRELATION_ID: process.env.LOG_CORRELATION_ID,
    LOG_SENSITIVE_DATA: process.env.LOG_SENSITIVE_DATA,
    HEALTH_CHECK_ENABLED: process.env.HEALTH_CHECK_ENABLED,
    HEALTH_CHECK_INTERVAL: process.env.HEALTH_CHECK_INTERVAL,
    HEALTH_CHECK_TIMEOUT: process.env.HEALTH_CHECK_TIMEOUT,
    METRICS_ENABLED: process.env.METRICS_ENABLED,
    METRICS_PORT: process.env.METRICS_PORT,
    METRICS_PATH: process.env.METRICS_PATH,

    // Development
    DEBUG_MODE: process.env.DEBUG_MODE,
    MOCK_HARDWARE: process.env.MOCK_HARDWARE,
    MOCK_EXTERNAL_APIS: process.env.MOCK_EXTERNAL_APIS,
    SEED_DATABASE: process.env.SEED_DATABASE,
    TEST_DATABASE_URL: process.env.TEST_DATABASE_URL,
    TEST_REDIS_URL: process.env.TEST_REDIS_URL,
    TEST_TIMEOUT: process.env.TEST_TIMEOUT,
    HOT_RELOAD_ENABLED: process.env.HOT_RELOAD_ENABLED,
    WATCH_FILES: process.env.WATCH_FILES,
  };
}

function parseEnvironmentValue(value: string | undefined, type: 'string' | 'number' | 'boolean' | 'array'): any {
  if (value === undefined) return undefined;

  switch (type) {
    case 'string':
      return value;
    case 'number':
      const num = Number(value);
      return isNaN(num) ? undefined : num;
    case 'boolean':
      return value.toLowerCase() === 'true';
    case 'array':
      return value.split(',').map(item => item.trim());
    default:
      return value;
  }
}

function createConfigFromEnvironment(): Config {
  const env = loadEnvironmentVariables();

  const config: Config = {
    env: (env.NODE_ENV as any) || 'development',
    logLevel: (env.LOG_LEVEL as any) || 'info',
    port: parseEnvironmentValue(env.PORT, 'number') || 3000,

    database: {
      url: env.DATABASE_URL || '',
      host: env.DATABASE_HOST || 'localhost',
      port: parseEnvironmentValue(env.DATABASE_PORT, 'number') || 5432,
      name: env.DATABASE_NAME || 'sparc_db',
      user: env.DATABASE_USER || 'sparc_user',
      password: env.DATABASE_PASSWORD || '',
      ssl: parseEnvironmentValue(env.DATABASE_SSL, 'boolean') || false,
      poolMin: parseEnvironmentValue(env.DATABASE_POOL_MIN, 'number') || 2,
      poolMax: parseEnvironmentValue(env.DATABASE_POOL_MAX, 'number') || 10,
      connectionTimeout: parseEnvironmentValue(env.DATABASE_CONNECTION_TIMEOUT, 'number') || 30000,
      idleTimeout: parseEnvironmentValue(env.DATABASE_IDLE_TIMEOUT, 'number') || 600000,
      runMigrations: parseEnvironmentValue(env.RUN_MIGRATIONS, 'boolean') || true,
      migrationTableName: env.MIGRATION_TABLE_NAME || 'sparc_migrations',
    },

    redis: {
      url: env.REDIS_URL || 'redis://localhost:6379',
      host: env.REDIS_HOST || 'localhost',
      port: parseEnvironmentValue(env.REDIS_PORT, 'number') || 6379,
      password: env.REDIS_PASSWORD,
      db: parseEnvironmentValue(env.REDIS_DB, 'number') || 0,
      ttl: parseEnvironmentValue(env.REDIS_TTL, 'number') || 3600,
      maxRetries: parseEnvironmentValue(env.REDIS_MAX_RETRIES, 'number') || 3,
      retryDelay: parseEnvironmentValue(env.REDIS_RETRY_DELAY, 'number') || 1000,
    },

    sessionRedis: {
      url: env.SESSION_REDIS_URL || 'redis://localhost:6380',
      db: parseEnvironmentValue(env.SESSION_REDIS_DB, 'number') || 1,
      ttl: parseEnvironmentValue(env.SESSION_TTL, 'number') || 86400,
    },

    jwt: {
      secret: env.JWT_SECRET || '',
      expiresIn: env.JWT_EXPIRES_IN || '24h',
      refreshSecret: env.JWT_REFRESH_SECRET || '',
      refreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN || '7d',
      issuer: env.JWT_ISSUER || 'sparc-platform',
      audience: env.JWT_AUDIENCE || 'sparc-users',
    },

    password: {
      bcryptRounds: parseEnvironmentValue(env.BCRYPT_ROUNDS, 'number') || 12,
      minLength: parseEnvironmentValue(env.PASSWORD_MIN_LENGTH, 'number') || 8,
      requireSpecialChars: parseEnvironmentValue(env.PASSWORD_REQUIRE_SPECIAL_CHARS, 'boolean') || true,
    },

    aws: {
      region: env.AWS_REGION || 'us-east-1',
      accessKeyId: env.AWS_ACCESS_KEY_ID || '',
      secretAccessKey: env.AWS_SECRET_ACCESS_KEY || '',
      s3: {
        bucket: env.AWS_S3_BUCKET || 'sparc-video-storage',
        region: env.AWS_S3_REGION || 'us-east-1',
        videoBucket: env.AWS_S3_VIDEO_BUCKET || 'sparc-video-recordings',
        backupBucket: env.AWS_S3_BACKUP_BUCKET || 'sparc-backups',
        presignedUrlExpires: parseEnvironmentValue(env.AWS_S3_PRESIGNED_URL_EXPIRES, 'number') || 3600,
      },
      cloudfront: {
        domain: env.AWS_CLOUDFRONT_DOMAIN || '',
        distributionId: env.AWS_CLOUDFRONT_DISTRIBUTION_ID || '',
      },
      ses: {
        region: env.AWS_SES_REGION || 'us-east-1',
        fromEmail: env.AWS_SES_FROM_EMAIL || 'noreply@sparc-platform.com',
        replyToEmail: env.AWS_SES_REPLY_TO_EMAIL || 'support@sparc-platform.com',
      },
      sns: {
        region: env.AWS_SNS_REGION || 'us-east-1',
        smsSenderId: env.AWS_SNS_SMS_SENDER_ID || 'SPARC',
      },
    },

    services: {
      apiGateway: {
        url: env.API_GATEWAY_URL || 'http://localhost:3000',
        timeout: parseEnvironmentValue(env.API_GATEWAY_TIMEOUT, 'number') || 30000,
      },
      authService: {
        url: env.AUTH_SERVICE_URL || 'http://localhost:3001',
        timeout: parseEnvironmentValue(env.AUTH_SERVICE_TIMEOUT, 'number') || 5000,
      },
      tenantService: {
        url: env.TENANT_SERVICE_URL || 'http://localhost:3002',
        timeout: parseEnvironmentValue(env.TENANT_SERVICE_TIMEOUT, 'number') || 5000,
      },
      accessControlService: {
        url: env.ACCESS_CONTROL_SERVICE_URL || 'http://localhost:3003',
        timeout: parseEnvironmentValue(env.ACCESS_CONTROL_SERVICE_TIMEOUT, 'number') || 10000,
      },
      deviceManagementService: {
        url: env.DEVICE_MANAGEMENT_SERVICE_URL || 'http://localhost:3004',
        timeout: parseEnvironmentValue(env.DEVICE_MANAGEMENT_SERVICE_TIMEOUT, 'number') || 15000,
      },
      videoManagementService: {
        url: env.VIDEO_MANAGEMENT_SERVICE_URL || 'http://localhost:3005',
        timeout: parseEnvironmentValue(env.VIDEO_MANAGEMENT_SERVICE_TIMEOUT, 'number') || 30000,
      },
      eventProcessingService: {
        url: env.EVENT_PROCESSING_SERVICE_URL || 'http://localhost:3006',
        timeout: parseEnvironmentValue(env.EVENT_PROCESSING_SERVICE_TIMEOUT, 'number') || 5000,
      },
      analyticsService: {
        url: env.ANALYTICS_SERVICE_URL || 'http://localhost:3007',
        timeout: parseEnvironmentValue(env.ANALYTICS_SERVICE_TIMEOUT, 'number') || 60000,
      },
      reportingService: {
        url: env.REPORTING_SERVICE_URL || 'http://localhost:3008',
        timeout: parseEnvironmentValue(env.REPORTING_SERVICE_TIMEOUT, 'number') || 30000,
      },
      mobileCredentialService: {
        url: env.MOBILE_CREDENTIAL_SERVICE_URL || 'http://localhost:3009',
        timeout: parseEnvironmentValue(env.MOBILE_CREDENTIAL_SERVICE_TIMEOUT, 'number') || 10000,
      },
      visitorManagementService: {
        url: env.VISITOR_MANAGEMENT_SERVICE_URL || 'http://localhost:3010',
        timeout: parseEnvironmentValue(env.VISITOR_MANAGEMENT_SERVICE_TIMEOUT, 'number') || 10000,
      },
      environmentalService: {
        url: env.ENVIRONMENTAL_SERVICE_URL || 'http://localhost:3011',
        timeout: parseEnvironmentValue(env.ENVIRONMENTAL_SERVICE_TIMEOUT, 'number') || 10000,
      },
    },

    multiTenant: {
      isolationMode: (env.TENANT_ISOLATION_MODE as any) || 'schema',
      defaultTenantId: env.DEFAULT_TENANT_ID || 'default',
      subdomainEnabled: parseEnvironmentValue(env.TENANT_SUBDOMAIN_ENABLED, 'boolean') || true,
      customDomainEnabled: parseEnvironmentValue(env.TENANT_CUSTOM_DOMAIN_ENABLED, 'boolean') || true,
      defaultUserLimit: parseEnvironmentValue(env.DEFAULT_TENANT_USER_LIMIT, 'number') || 100,
      defaultDeviceLimit: parseEnvironmentValue(env.DEFAULT_TENANT_DEVICE_LIMIT, 'number') || 500,
      defaultStorageLimitGb: parseEnvironmentValue(env.DEFAULT_TENANT_STORAGE_LIMIT_GB, 'number') || 100,
      defaultBandwidthLimitMbps: parseEnvironmentValue(env.DEFAULT_TENANT_BANDWIDTH_LIMIT_MBPS, 'number') || 100,
      dbPoolSize: parseEnvironmentValue(env.TENANT_DB_POOL_SIZE, 'number') || 5,
      dbConnectionLimit: parseEnvironmentValue(env.TENANT_DB_CONNECTION_LIMIT, 'number') || 50,
    },

    offline: {
      enabled: parseEnvironmentValue(env.OFFLINE_MODE_ENABLED, 'boolean') || true,
      cacheDuration: parseEnvironmentValue(env.OFFLINE_CACHE_DURATION, 'number') || 86400,
      syncInterval: parseEnvironmentValue(env.OFFLINE_SYNC_INTERVAL, 'number') || 300,
      maxQueueSize: parseEnvironmentValue(env.OFFLINE_MAX_QUEUE_SIZE, 'number') || 10000,
      cacheType: (env.OFFLINE_CACHE_TYPE as any) || 'redis',
      cacheSizeMb: parseEnvironmentValue(env.OFFLINE_CACHE_SIZE_MB, 'number') || 512,
      credentialCacheTtl: parseEnvironmentValue(env.OFFLINE_CREDENTIAL_CACHE_TTL, 'number') || 604800,
      meshNetworkEnabled: parseEnvironmentValue(env.MESH_NETWORK_ENABLED, 'boolean') || true,
      meshNetworkPort: parseEnvironmentValue(env.MESH_NETWORK_PORT, 'number') || 8080,
      meshDiscoveryInterval: parseEnvironmentValue(env.MESH_DISCOVERY_INTERVAL, 'number') || 30,
    },

    video: {
      streamProtocol: (env.VIDEO_STREAM_PROTOCOL as any) || 'webrtc',
      streamQuality: (env.VIDEO_STREAM_QUALITY as any) || 'high',
      streamMaxBitrate: parseEnvironmentValue(env.VIDEO_STREAM_MAX_BITRATE, 'number') || 5000,
      streamTimeout: parseEnvironmentValue(env.VIDEO_STREAM_TIMEOUT, 'number') || 30000,
      recordingEnabled: parseEnvironmentValue(env.VIDEO_RECORDING_ENABLED, 'boolean') || true,
      recordingQuality: (env.VIDEO_RECORDING_QUALITY as any) || '1080p',
      recordingFps: parseEnvironmentValue(env.VIDEO_RECORDING_FPS, 'number') || 30,
      recordingRetentionDays: parseEnvironmentValue(env.VIDEO_RECORDING_RETENTION_DAYS, 'number') || 90,
      recordingCompression: (env.VIDEO_RECORDING_COMPRESSION as any) || 'h264',
      onvifDiscoveryEnabled: parseEnvironmentValue(env.ONVIF_DISCOVERY_ENABLED, 'boolean') || true,
      onvifDiscoveryTimeout: parseEnvironmentValue(env.ONVIF_DISCOVERY_TIMEOUT, 'number') || 10000,
      onvifUsername: env.ONVIF_USERNAME || '',
      onvifPassword: env.ONVIF_PASSWORD || '',
      privacyMaskingEnabled: parseEnvironmentValue(env.PRIVACY_MASKING_ENABLED, 'boolean') || true,
      privacyMaskingAlgorithm: (env.PRIVACY_MASKING_ALGORITHM as any) || 'blur',
    },

    hardware: {
      osdp: {
        enabled: parseEnvironmentValue(env.OSDP_ENABLED, 'boolean') || true,
        version: env.OSDP_VERSION || '2.2',
        secureChannel: parseEnvironmentValue(env.OSDP_SECURE_CHANNEL, 'boolean') || true,
        pollInterval: parseEnvironmentValue(env.OSDP_POLL_INTERVAL, 'number') || 1000,
      },
      device: {
        communicationTimeout: parseEnvironmentValue(env.DEVICE_COMMUNICATION_TIMEOUT, 'number') || 5000,
        heartbeatInterval: parseEnvironmentValue(env.DEVICE_HEARTBEAT_INTERVAL, 'number') || 30000,
        retryAttempts: parseEnvironmentValue(env.DEVICE_RETRY_ATTEMPTS, 'number') || 3,
      },
      manufacturers: {
        hidApiEnabled: parseEnvironmentValue(env.HID_API_ENABLED, 'boolean') || false,
        hidApiKey: env.HID_API_KEY,
        honeywellApiEnabled: parseEnvironmentValue(env.HONEYWELL_API_ENABLED, 'boolean') || false,
        honeywellApiKey: env.HONEYWELL_API_KEY,
        boschApiEnabled: parseEnvironmentValue(env.BOSCH_API_ENABLED, 'boolean') || false,
        boschApiKey: env.BOSCH_API_KEY,
      },
    },

    mobileCredential: {
      appBundleId: env.MOBILE_APP_BUNDLE_ID || 'com.sparc.mobile',
      appDeepLinkScheme: env.MOBILE_APP_DEEP_LINK_SCHEME || 'sparc',
      encryptionKey: env.MOBILE_CREDENTIAL_ENCRYPTION_KEY || '',
      firebase: {
        projectId: env.FIREBASE_PROJECT_ID || '',
        privateKey: env.FIREBASE_PRIVATE_KEY || '',
        clientEmail: env.FIREBASE_CLIENT_EMAIL || '',
      },
      apns: {
        keyId: env.APNS_KEY_ID || '',
        teamId: env.APNS_TEAM_ID || '',
        privateKey: env.APNS_PRIVATE_KEY || '',
      },
      nfcEnabled: parseEnvironmentValue(env.NFC_ENABLED, 'boolean') || true,
      bleEnabled: parseEnvironmentValue(env.BLE_ENABLED, 'boolean') || true,
      bleAdvertisingInterval: parseEnvironmentValue(env.BLE_ADVERTISING_INTERVAL, 'number') || 100,
      bleConnectionTimeout: parseEnvironmentValue(env.BLE_CONNECTION_TIMEOUT, 'number') || 10000,
    },

    analytics: {
      mlServiceEnabled: parseEnvironmentValue(env.ML_SERVICE_ENABLED, 'boolean') || false,
      mlServiceUrl: env.ML_SERVICE_URL,
      mlApiKey: env.ML_API_KEY,
      faceRecognitionEnabled: parseEnvironmentValue(env.FACE_RECOGNITION_ENABLED, 'boolean') || false,
      faceRecognitionConfidenceThreshold: parseEnvironmentValue(env.FACE_RECOGNITION_CONFIDENCE_THRESHOLD, 'number') || 0.8,
      faceRecognitionMaxFaces: parseEnvironmentValue(env.FACE_RECOGNITION_MAX_FACES, 'number') || 10,
      lprEnabled: parseEnvironmentValue(env.LPR_ENABLED, 'boolean') || false,
      lprConfidenceThreshold: parseEnvironmentValue(env.LPR_CONFIDENCE_THRESHOLD, 'number') || 0.9,
      lprRegions: parseEnvironmentValue(env.LPR_REGIONS, 'array') || ['US', 'CA', 'EU'],
      behavioralAnalyticsEnabled: parseEnvironmentValue(env.BEHAVIORAL_ANALYTICS_ENABLED, 'boolean') || false,
      occupancyTrackingEnabled: parseEnvironmentValue(env.OCCUPANCY_TRACKING_ENABLED, 'boolean') || true,
      crowdDetectionEnabled: parseEnvironmentValue(env.CROWD_DETECTION_ENABLED, 'boolean') || false,
    },

    environmental: {
      monitoringEnabled: parseEnvironmentValue(env.ENVIRONMENTAL_MONITORING_ENABLED, 'boolean') || true,
      temperatureMonitoring: parseEnvironmentValue(env.TEMPERATURE_MONITORING, 'boolean') || true,
      humidityMonitoring: parseEnvironmentValue(env.HUMIDITY_MONITORING, 'boolean') || true,
      waterDetection: parseEnvironmentValue(env.WATER_DETECTION, 'boolean') || true,
      airQualityMonitoring: parseEnvironmentValue(env.AIR_QUALITY_MONITORING, 'boolean') || false,
      hvacIntegrationEnabled: parseEnvironmentValue(env.HVAC_INTEGRATION_ENABLED, 'boolean') || false,
      hvacApiUrl: env.HVAC_API_URL,
      hvacApiKey: env.HVAC_API_KEY,
      temperatureMinThreshold: parseEnvironmentValue(env.TEMPERATURE_MIN_THRESHOLD, 'number') || 15,
      temperatureMaxThreshold: parseEnvironmentValue(env.TEMPERATURE_MAX_THRESHOLD, 'number') || 30,
      humidityMinThreshold: parseEnvironmentValue(env.HUMIDITY_MIN_THRESHOLD, 'number') || 30,
      humidityMaxThreshold: parseEnvironmentValue(env.HUMIDITY_MAX_THRESHOLD, 'number') || 70,
    },

    notifications: {
      email: {
        smtpHost: env.SMTP_HOST || 'smtp.gmail.com',
        smtpPort: parseEnvironmentValue(env.SMTP_PORT, 'number') || 587,
        smtpSecure: parseEnvironmentValue(env.SMTP_SECURE, 'boolean') || true,
        smtpUser: env.SMTP_USER || '',
        smtpPassword: env.SMTP_PASSWORD || '',
      },
      sms: {
        provider: (env.SMS_PROVIDER as any) || 'twilio',
        twilioAccountSid: env.TWILIO_ACCOUNT_SID,
        twilioAuthToken: env.TWILIO_AUTH_TOKEN,
        twilioPhoneNumber: env.TWILIO_PHONE_NUMBER,
      },
      webhook: {
        enabled: parseEnvironmentValue(env.WEBHOOK_ENABLED, 'boolean') || true,
        secret: env.WEBHOOK_SECRET || '',
        timeout: parseEnvironmentValue(env.WEBHOOK_TIMEOUT, 'number') || 10000,
      },
    },

    security: {
      api: {
        rateLimitWindow: parseEnvironmentValue(env.API_RATE_LIMIT_WINDOW, 'number') || 900000,
        rateLimitMaxRequests: parseEnvironmentValue(env.API_RATE_LIMIT_MAX_REQUESTS, 'number') || 100,
        corsOrigins: parseEnvironmentValue(env.API_CORS_ORIGINS, 'array') || ['http://localhost:3000'],
      },
      encryption: {
        algorithm: (env.ENCRYPTION_ALGORITHM as any) || 'aes-256-gcm',
        key: env.ENCRYPTION_KEY || '',
        dataEncryptionAtRest: parseEnvironmentValue(env.DATA_ENCRYPTION_AT_REST, 'boolean') || true,
      },
      headers: {
        enabled: parseEnvironmentValue(env.SECURITY_HEADERS_ENABLED, 'boolean') || true,
        hstsMaxAge: parseEnvironmentValue(env.HSTS_MAX_AGE, 'number') || 31536000,
        cspEnabled: parseEnvironmentValue(env.CSP_ENABLED, 'boolean') || true,
      },
    },

    monitoring: {
      apm: {
        enabled: parseEnvironmentValue(env.APM_ENABLED, 'boolean') || false,
        serviceName: env.APM_SERVICE_NAME || 'sparc-platform',
        serviceVersion: env.APM_SERVICE_VERSION || '1.0.0',
      },
      logging: {
        format: (env.LOG_FORMAT as any) || 'json',
        timestamp: parseEnvironmentValue(env.LOG_TIMESTAMP, 'boolean') || true,
        correlationId: parseEnvironmentValue(env.LOG_CORRELATION_ID, 'boolean') || true,
        sensitiveData: parseEnvironmentValue(env.LOG_SENSITIVE_DATA, 'boolean') || false,
      },
      healthCheck: {
        enabled: parseEnvironmentValue(env.HEALTH_CHECK_ENABLED, 'boolean') || true,
        interval: parseEnvironmentValue(env.HEALTH_CHECK_INTERVAL, 'number') || 30000,
        timeout: parseEnvironmentValue(env.HEALTH_CHECK_TIMEOUT, 'number') || 5000,
      },
      metrics: {
        enabled: parseEnvironmentValue(env.METRICS_ENABLED, 'boolean') || true,
        port: parseEnvironmentValue(env.METRICS_PORT, 'number') || 9090,
        path: env.METRICS_PATH || '/metrics',
      },
    },

    development: {
      debugMode: parseEnvironmentValue(env.DEBUG_MODE, 'boolean') || false,
      mockHardware: parseEnvironmentValue(env.MOCK_HARDWARE, 'boolean') || true,
      mockExternalApis: parseEnvironmentValue(env.MOCK_EXTERNAL_APIS, 'boolean') || true,
      seedDatabase: parseEnvironmentValue(env.SEED_DATABASE, 'boolean') || true,
      testDatabaseUrl: env.TEST_DATABASE_URL,
      testRedisUrl: env.TEST_REDIS_URL,
      testTimeout: parseEnvironmentValue(env.TEST_TIMEOUT, 'number') || 30000,
      hotReloadEnabled: parseEnvironmentValue(env.HOT_RELOAD_ENABLED, 'boolean') || true,
      watchFiles: parseEnvironmentValue(env.WATCH_FILES, 'boolean') || true,
    },
  };

  return config;
}

// =============================================================================
// CONFIGURATION VALIDATION AND EXPORT
// =============================================================================

let cachedConfig: Config | null = null;

export function getConfig(): Config {
  if (cachedConfig) {
    return cachedConfig;
  }

  try {
    const rawConfig = createConfigFromEnvironment();
    const validatedConfig = ConfigSchema.parse(rawConfig);
    cachedConfig = validatedConfig;
    return validatedConfig;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors.map(err => `${err.path.join('.')}: ${err.message}`);
      throw new Error(`Configuration validation failed:\n${errorMessages.join('\n')}`);
    }
    throw error;
  }
}

export function validateConfig(config: unknown): Config {
  return ConfigSchema.parse(config);
}

export function isProduction(): boolean {
  return getConfig().env === 'production';
}

export function isDevelopment(): boolean {
  return getConfig().env === 'development';
}

export function isTest(): boolean {
  return getConfig().env === 'test';
}

export function getServiceUrl(serviceName: keyof ServiceEndpoints): string {
  const config = getConfig();
  return config.services[serviceName].url;
}

export function getServiceTimeout(serviceName: keyof ServiceEndpoints): number {
  const config = getConfig();
  return config.services[serviceName].timeout;
}

// =============================================================================
// ENVIRONMENT-SPECIFIC CONFIGURATIONS
// =============================================================================

export function getDatabaseUrl(): string {
  const config = getConfig();
  if (isTest() && config.development.testDatabaseUrl) {
    return config.development.testDatabaseUrl;
  }
  return config.database.url;
}

export function getRedisUrl(): string {
  const config = getConfig();
  if (isTest() && config.development.testRedisUrl) {
    return config.development.testRedisUrl;
  }
  return config.redis.url;
}

export function getLogLevel(): string {
  const config = getConfig();
  return config.logLevel;
}

export function getJwtSecret(): string {
  const config = getConfig();
  return config.jwt.secret;
}

export function getEncryptionKey(): string {
  const config = getConfig();
  return config.security.encryption.key;
}

// =============================================================================
// FEATURE FLAGS
// =============================================================================

export function isFeatureEnabled(feature: string): boolean {
  const config = getConfig();
  
  switch (feature) {
    case 'offline-mode':
      return config.offline.enabled;
    case 'video-recording':
      return config.video.recordingEnabled;
    case 'privacy-masking':
      return config.video.privacyMaskingEnabled;
    case 'mobile-credentials':
      return config.mobileCredential.nfcEnabled || config.mobileCredential.bleEnabled;
    case 'environmental-monitoring':
      return config.environmental.monitoringEnabled;
    case 'analytics':
      return config.analytics.mlServiceEnabled;
    case 'face-recognition':
      return config.analytics.faceRecognitionEnabled;
    case 'license-plate-recognition':
      return config.analytics.lprEnabled;
    case 'behavioral-analytics':
      return config.analytics.behavioralAnalyticsEnabled;
    case 'occupancy-tracking':
      return config.analytics.occupancyTrackingEnabled;
    case 'crowd-detection':
      return config.analytics.crowdDetectionEnabled;
    case 'hvac-integration':
      return config.environmental.hvacIntegrationEnabled;
    case 'mesh-networking':
      return config.offline.meshNetworkEnabled;
    case 'osdp':
      return config.hardware.osdp.enabled;
    case 'onvif-discovery':
      return config.video.onvifDiscoveryEnabled;
    case 'webhooks':
      return config.notifications.webhook.enabled;
    case 'metrics':
      return config.monitoring.metrics.enabled;
    case 'health-checks':
      return config.monitoring.healthCheck.enabled;
    case 'apm':
      return config.monitoring.apm.enabled;
    case 'security-headers':
      return config.security.headers.enabled;
    case 'csp':
      return config.security.headers.cspEnabled;
    case 'data-encryption-at-rest':
      return config.security.encryption.dataEncryptionAtRest;
    case 'tenant-subdomains':
      return config.multiTenant.subdomainEnabled;
    case 'tenant-custom-domains':
      return config.multiTenant.customDomainEnabled;
    default:
      return false;
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

export {
  ConfigSchema,
  DatabaseConfigSchema,
  RedisConfigSchema,
  JwtConfigSchema,
  AwsConfigSchema,
  ServiceEndpointsSchema,
  MultiTenantConfigSchema,
  OfflineConfigSchema,
  VideoConfigSchema,
  HardwareConfigSchema,
  MobileCredentialConfigSchema,
  AnalyticsConfigSchema,
  EnvironmentalConfigSchema,
  NotificationConfigSchema,
  SecurityConfigSchema,
  MonitoringConfigSchema,
  DevelopmentConfigSchema,
};

export default getConfig;