/**
 * SPARC Platform Constants
 * 
 * This file contains all platform-wide constants including API response codes,
 * error messages, configuration defaults, roles, permissions, event types,
 * device protocols, and system limits as specified in the requirements.
 */

// =============================================================================
// HTTP Status Codes and API Response Codes
// =============================================================================

export const HTTP_STATUS = {
  // Success
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  
  // Client Errors
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  
  // Server Errors
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
} as const;

export const API_RESPONSE_CODES = {
  SUCCESS: 'SUCCESS',
  ERROR: 'ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
  NOT_FOUND_ERROR: 'NOT_FOUND_ERROR',
  CONFLICT_ERROR: 'CONFLICT_ERROR',
  RATE_LIMIT_ERROR: 'RATE_LIMIT_ERROR',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE_ERROR: 'SERVICE_UNAVAILABLE_ERROR',
} as const;

// =============================================================================
// Error Codes and Messages
// =============================================================================

export const ERROR_CODES = {
  // Authentication Errors (1000-1099)
  INVALID_CREDENTIALS: 'AUTH_1001',
  TOKEN_EXPIRED: 'AUTH_1002',
  TOKEN_INVALID: 'AUTH_1003',
  SESSION_EXPIRED: 'AUTH_1004',
  ACCOUNT_DISABLED: 'AUTH_1005',
  ACCOUNT_LOCKED: 'AUTH_1006',
  PASSWORD_EXPIRED: 'AUTH_1007',
  MFA_REQUIRED: 'AUTH_1008',
  MFA_INVALID: 'AUTH_1009',
  
  // Authorization Errors (1100-1199)
  INSUFFICIENT_PERMISSIONS: 'AUTHZ_1101',
  TENANT_ACCESS_DENIED: 'AUTHZ_1102',
  RESOURCE_ACCESS_DENIED: 'AUTHZ_1103',
  OPERATION_NOT_ALLOWED: 'AUTHZ_1104',
  ROLE_REQUIRED: 'AUTHZ_1105',
  
  // Validation Errors (1200-1299)
  INVALID_INPUT: 'VAL_1201',
  REQUIRED_FIELD_MISSING: 'VAL_1202',
  INVALID_FORMAT: 'VAL_1203',
  VALUE_OUT_OF_RANGE: 'VAL_1204',
  DUPLICATE_VALUE: 'VAL_1205',
  INVALID_RELATIONSHIP: 'VAL_1206',
  
  // Access Control Errors (1300-1399)
  ACCESS_DENIED: 'AC_1301',
  DOOR_OFFLINE: 'AC_1302',
  CREDENTIAL_INVALID: 'AC_1303',
  CREDENTIAL_EXPIRED: 'AC_1304',
  CREDENTIAL_REVOKED: 'AC_1305',
  SCHEDULE_VIOLATION: 'AC_1306',
  ANTI_PASSBACK_VIOLATION: 'AC_1307',
  DUAL_AUTH_REQUIRED: 'AC_1308',
  EMERGENCY_LOCKDOWN: 'AC_1309',
  
  // Video Management Errors (1400-1499)
  CAMERA_OFFLINE: 'VID_1401',
  STREAM_UNAVAILABLE: 'VID_1402',
  RECORDING_FAILED: 'VID_1403',
  STORAGE_FULL: 'VID_1404',
  EXPORT_FAILED: 'VID_1405',
  PRIVACY_VIOLATION: 'VID_1406',
  CODEC_UNSUPPORTED: 'VID_1407',
  
  // Device Management Errors (1500-1599)
  DEVICE_OFFLINE: 'DEV_1501',
  DEVICE_UNREACHABLE: 'DEV_1502',
  FIRMWARE_UPDATE_FAILED: 'DEV_1503',
  CONFIGURATION_FAILED: 'DEV_1504',
  DISCOVERY_FAILED: 'DEV_1505',
  PROTOCOL_ERROR: 'DEV_1506',
  
  // System Errors (1600-1699)
  DATABASE_ERROR: 'SYS_1601',
  CACHE_ERROR: 'SYS_1602',
  QUEUE_ERROR: 'SYS_1603',
  STORAGE_ERROR: 'SYS_1604',
  NETWORK_ERROR: 'SYS_1605',
  SERVICE_UNAVAILABLE: 'SYS_1606',
  RATE_LIMIT_EXCEEDED: 'SYS_1607',
  QUOTA_EXCEEDED: 'SYS_1608',
  
  // Tenant Management Errors (1700-1799)
  TENANT_NOT_FOUND: 'TNT_1701',
  TENANT_DISABLED: 'TNT_1702',
  TENANT_QUOTA_EXCEEDED: 'TNT_1703',
  ORGANIZATION_NOT_FOUND: 'TNT_1704',
  SITE_NOT_FOUND: 'TNT_1705',
  BUILDING_NOT_FOUND: 'TNT_1706',
  FLOOR_NOT_FOUND: 'TNT_1707',
} as const;

export const ERROR_MESSAGES = {
  [ERROR_CODES.INVALID_CREDENTIALS]: 'Invalid username or password',
  [ERROR_CODES.TOKEN_EXPIRED]: 'Authentication token has expired',
  [ERROR_CODES.TOKEN_INVALID]: 'Invalid authentication token',
  [ERROR_CODES.SESSION_EXPIRED]: 'Session has expired, please log in again',
  [ERROR_CODES.ACCOUNT_DISABLED]: 'Account has been disabled',
  [ERROR_CODES.ACCOUNT_LOCKED]: 'Account has been locked due to multiple failed attempts',
  [ERROR_CODES.PASSWORD_EXPIRED]: 'Password has expired and must be changed',
  [ERROR_CODES.MFA_REQUIRED]: 'Multi-factor authentication is required',
  [ERROR_CODES.MFA_INVALID]: 'Invalid multi-factor authentication code',
  
  [ERROR_CODES.INSUFFICIENT_PERMISSIONS]: 'Insufficient permissions to perform this operation',
  [ERROR_CODES.TENANT_ACCESS_DENIED]: 'Access denied to tenant resources',
  [ERROR_CODES.RESOURCE_ACCESS_DENIED]: 'Access denied to requested resource',
  [ERROR_CODES.OPERATION_NOT_ALLOWED]: 'Operation not allowed for current user role',
  [ERROR_CODES.ROLE_REQUIRED]: 'Required role not assigned to user',
  
  [ERROR_CODES.INVALID_INPUT]: 'Invalid input provided',
  [ERROR_CODES.REQUIRED_FIELD_MISSING]: 'Required field is missing',
  [ERROR_CODES.INVALID_FORMAT]: 'Invalid format for provided value',
  [ERROR_CODES.VALUE_OUT_OF_RANGE]: 'Value is outside acceptable range',
  [ERROR_CODES.DUPLICATE_VALUE]: 'Duplicate value not allowed',
  [ERROR_CODES.INVALID_RELATIONSHIP]: 'Invalid relationship between entities',
  
  [ERROR_CODES.ACCESS_DENIED]: 'Physical access denied',
  [ERROR_CODES.DOOR_OFFLINE]: 'Door controller is offline',
  [ERROR_CODES.CREDENTIAL_INVALID]: 'Invalid access credential',
  [ERROR_CODES.CREDENTIAL_EXPIRED]: 'Access credential has expired',
  [ERROR_CODES.CREDENTIAL_REVOKED]: 'Access credential has been revoked',
  [ERROR_CODES.SCHEDULE_VIOLATION]: 'Access attempted outside allowed schedule',
  [ERROR_CODES.ANTI_PASSBACK_VIOLATION]: 'Anti-passback violation detected',
  [ERROR_CODES.DUAL_AUTH_REQUIRED]: 'Dual authorization required for access',
  [ERROR_CODES.EMERGENCY_LOCKDOWN]: 'Emergency lockdown is active',
  
  [ERROR_CODES.CAMERA_OFFLINE]: 'Camera is offline or unreachable',
  [ERROR_CODES.STREAM_UNAVAILABLE]: 'Video stream is not available',
  [ERROR_CODES.RECORDING_FAILED]: 'Video recording failed',
  [ERROR_CODES.STORAGE_FULL]: 'Video storage capacity exceeded',
  [ERROR_CODES.EXPORT_FAILED]: 'Video export operation failed',
  [ERROR_CODES.PRIVACY_VIOLATION]: 'Operation violates privacy settings',
  [ERROR_CODES.CODEC_UNSUPPORTED]: 'Video codec not supported',
  
  [ERROR_CODES.DEVICE_OFFLINE]: 'Device is offline',
  [ERROR_CODES.DEVICE_UNREACHABLE]: 'Device is unreachable',
  [ERROR_CODES.FIRMWARE_UPDATE_FAILED]: 'Firmware update failed',
  [ERROR_CODES.CONFIGURATION_FAILED]: 'Device configuration failed',
  [ERROR_CODES.DISCOVERY_FAILED]: 'Device discovery failed',
  [ERROR_CODES.PROTOCOL_ERROR]: 'Protocol communication error',
  
  [ERROR_CODES.DATABASE_ERROR]: 'Database operation failed',
  [ERROR_CODES.CACHE_ERROR]: 'Cache operation failed',
  [ERROR_CODES.QUEUE_ERROR]: 'Queue operation failed',
  [ERROR_CODES.STORAGE_ERROR]: 'Storage operation failed',
  [ERROR_CODES.NETWORK_ERROR]: 'Network communication error',
  [ERROR_CODES.SERVICE_UNAVAILABLE]: 'Service is temporarily unavailable',
  [ERROR_CODES.RATE_LIMIT_EXCEEDED]: 'Rate limit exceeded',
  [ERROR_CODES.QUOTA_EXCEEDED]: 'Resource quota exceeded',
  
  [ERROR_CODES.TENANT_NOT_FOUND]: 'Tenant not found',
  [ERROR_CODES.TENANT_DISABLED]: 'Tenant is disabled',
  [ERROR_CODES.TENANT_QUOTA_EXCEEDED]: 'Tenant quota exceeded',
  [ERROR_CODES.ORGANIZATION_NOT_FOUND]: 'Organization not found',
  [ERROR_CODES.SITE_NOT_FOUND]: 'Site not found',
  [ERROR_CODES.BUILDING_NOT_FOUND]: 'Building not found',
  [ERROR_CODES.FLOOR_NOT_FOUND]: 'Floor not found',
} as const;

// =============================================================================
// Default Configuration Values
// =============================================================================

export const DEFAULT_CONFIG = {
  // API Configuration
  API_TIMEOUT: 30000, // 30 seconds
  API_RETRY_ATTEMPTS: 3,
  API_RETRY_DELAY: 1000, // 1 second
  API_RESPONSE_TIMEOUT: 200, // 200ms as per Requirement 5
  
  // Authentication Configuration
  JWT_EXPIRY: '24h',
  JWT_REFRESH_EXPIRY: '7d',
  SESSION_TIMEOUT: 3600000, // 1 hour in milliseconds
  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_COMPLEXITY_REQUIRED: true,
  MFA_TOKEN_EXPIRY: 300, // 5 minutes
  
  // Rate Limiting
  RATE_LIMIT_WINDOW: 900000, // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: 1000,
  RATE_LIMIT_PER_USER: 100,
  
  // Database Configuration
  DB_CONNECTION_TIMEOUT: 30000,
  DB_QUERY_TIMEOUT: 10000,
  DB_POOL_SIZE: 20,
  
  // Cache Configuration
  CACHE_TTL: 3600, // 1 hour
  CACHE_MAX_SIZE: 1000,
  
  // Video Configuration
  VIDEO_STREAM_TIMEOUT: 2000, // 2 seconds as per Requirement 3
  VIDEO_RECORDING_BUFFER: 30, // 30 seconds before/after events
  VIDEO_DEFAULT_RETENTION: 30, // 30 days
  VIDEO_MAX_CONCURRENT_STREAMS: 1000, // As per Requirement 12
  VIDEO_QUALITY_LEVELS: ['low', 'medium', 'high'],
  
  // Access Control Configuration
  ACCESS_EVENT_TIMEOUT: 5000, // 5 seconds
  DOOR_UNLOCK_DURATION: 5000, // 5 seconds
  OFFLINE_OPERATION_DURATION: 259200000, // 72 hours as per Requirement 27
  CREDENTIAL_SYNC_INTERVAL: 900000, // 15 minutes
  
  // Alert Configuration
  ALERT_ESCALATION_TIMEOUT: 300000, // 5 minutes
  ALERT_MAX_RETRIES: 3,
  
  // Audit Configuration
  AUDIT_LOG_RETENTION: 2555, // 7 years in days
  AUDIT_BATCH_SIZE: 1000,
  
  // Environmental Monitoring
  SENSOR_READING_INTERVAL: 60000, // 1 minute
  ENVIRONMENTAL_ALERT_THRESHOLD_TEMP: 25, // Celsius
  ENVIRONMENTAL_ALERT_THRESHOLD_HUMIDITY: 60, // Percentage
  
  // Mobile Credentials
  MOBILE_CREDENTIAL_TIMEOUT: 1000, // 1 second as per Requirement 23
  MOBILE_CREDENTIAL_OFFLINE_DURATION: 86400000, // 24 hours
  
  // Visitor Management
  VISITOR_BADGE_VALIDITY: 86400000, // 24 hours
  VISITOR_OVERSTAY_ALERT: 3600000, // 1 hour
} as const;

// =============================================================================
// Role and Permission Constants
// =============================================================================

export const ROLES = {
  // System Roles
  SUPER_ADMIN: 'super_admin',
  SYSTEM_ADMIN: 'system_admin',
  
  // Tenant Roles
  TENANT_ADMIN: 'tenant_admin',
  ORGANIZATION_ADMIN: 'organization_admin',
  SITE_ADMIN: 'site_admin',
  
  // Operational Roles
  SECURITY_MANAGER: 'security_manager',
  SECURITY_OPERATOR: 'security_operator',
  FACILITIES_MANAGER: 'facilities_manager',
  
  // Specialized Roles
  COMPLIANCE_OFFICER: 'compliance_officer',
  MAINTENANCE_TECHNICIAN: 'maintenance_technician',
  VISITOR_COORDINATOR: 'visitor_coordinator',
  
  // End User Roles
  EMPLOYEE: 'employee',
  CONTRACTOR: 'contractor',
  VISITOR: 'visitor',
  GUEST: 'guest',
} as const;

export const PERMISSIONS = {
  // System Management
  SYSTEM_ADMIN: 'system:admin',
  SYSTEM_CONFIG: 'system:config',
  SYSTEM_MONITOR: 'system:monitor',
  
  // Tenant Management
  TENANT_CREATE: 'tenant:create',
  TENANT_READ: 'tenant:read',
  TENANT_UPDATE: 'tenant:update',
  TENANT_DELETE: 'tenant:delete',
  TENANT_ADMIN: 'tenant:admin',
  
  // User Management
  USER_CREATE: 'user:create',
  USER_READ: 'user:read',
  USER_UPDATE: 'user:update',
  USER_DELETE: 'user:delete',
  USER_ADMIN: 'user:admin',
  
  // Access Control
  ACCESS_CONTROL_ADMIN: 'access:admin',
  ACCESS_CONTROL_OPERATE: 'access:operate',
  ACCESS_CONTROL_VIEW: 'access:view',
  DOOR_CONTROL: 'door:control',
  DOOR_CONFIG: 'door:config',
  CREDENTIAL_MANAGE: 'credential:manage',
  
  // Video Management
  VIDEO_ADMIN: 'video:admin',
  VIDEO_OPERATE: 'video:operate',
  VIDEO_VIEW: 'video:view',
  VIDEO_EXPORT: 'video:export',
  CAMERA_CONTROL: 'camera:control',
  CAMERA_CONFIG: 'camera:config',
  
  // Event Management
  EVENT_VIEW: 'event:view',
  EVENT_RESPOND: 'event:respond',
  ALERT_MANAGE: 'alert:manage',
  
  // Reporting and Analytics
  REPORT_VIEW: 'report:view',
  REPORT_CREATE: 'report:create',
  ANALYTICS_VIEW: 'analytics:view',
  AUDIT_VIEW: 'audit:view',
  
  // Device Management
  DEVICE_ADMIN: 'device:admin',
  DEVICE_CONFIG: 'device:config',
  DEVICE_MONITOR: 'device:monitor',
  
  // Visitor Management
  VISITOR_ADMIN: 'visitor:admin',
  VISITOR_CHECKIN: 'visitor:checkin',
  VISITOR_VIEW: 'visitor:view',
  
  // Environmental Monitoring
  ENVIRONMENTAL_VIEW: 'environmental:view',
  ENVIRONMENTAL_CONFIG: 'environmental:config',
  
  // Maintenance
  MAINTENANCE_VIEW: 'maintenance:view',
  MAINTENANCE_SCHEDULE: 'maintenance:schedule',
  MAINTENANCE_EXECUTE: 'maintenance:execute',
} as const;

// =============================================================================
// Event Types
// =============================================================================

export const ACCESS_EVENT_TYPES = {
  ACCESS_GRANTED: 'access_granted',
  ACCESS_DENIED: 'access_denied',
  DOOR_OPENED: 'door_opened',
  DOOR_CLOSED: 'door_closed',
  DOOR_FORCED: 'door_forced',
  DOOR_AJAR: 'door_ajar',
  CREDENTIAL_PRESENTED: 'credential_presented',
  CREDENTIAL_INVALID: 'credential_invalid',
  ANTI_PASSBACK_VIOLATION: 'anti_passback_violation',
  DUAL_AUTH_SUCCESS: 'dual_auth_success',
  DUAL_AUTH_TIMEOUT: 'dual_auth_timeout',
  EMERGENCY_UNLOCK: 'emergency_unlock',
  LOCKDOWN_ACTIVATED: 'lockdown_activated',
  LOCKDOWN_DEACTIVATED: 'lockdown_deactivated',
  SCHEDULE_OVERRIDE: 'schedule_override',
} as const;

export const VIDEO_EVENT_TYPES = {
  MOTION_DETECTED: 'motion_detected',
  RECORDING_STARTED: 'recording_started',
  RECORDING_STOPPED: 'recording_stopped',
  CAMERA_ONLINE: 'camera_online',
  CAMERA_OFFLINE: 'camera_offline',
  CAMERA_TAMPERED: 'camera_tampered',
  STREAM_STARTED: 'stream_started',
  STREAM_STOPPED: 'stream_stopped',
  VIDEO_EXPORTED: 'video_exported',
  PRIVACY_MASK_APPLIED: 'privacy_mask_applied',
  LINE_CROSSING: 'line_crossing',
  LOITERING_DETECTED: 'loitering_detected',
  FACE_DETECTED: 'face_detected',
  LICENSE_PLATE_DETECTED: 'license_plate_detected',
} as const;

export const SYSTEM_EVENT_TYPES = {
  USER_LOGIN: 'user_login',
  USER_LOGOUT: 'user_logout',
  USER_CREATED: 'user_created',
  USER_UPDATED: 'user_updated',
  USER_DELETED: 'user_deleted',
  ROLE_ASSIGNED: 'role_assigned',
  ROLE_REVOKED: 'role_revoked',
  CONFIGURATION_CHANGED: 'configuration_changed',
  BACKUP_STARTED: 'backup_started',
  BACKUP_COMPLETED: 'backup_completed',
  BACKUP_FAILED: 'backup_failed',
  SYSTEM_STARTUP: 'system_startup',
  SYSTEM_SHUTDOWN: 'system_shutdown',
  SERVICE_STARTED: 'service_started',
  SERVICE_STOPPED: 'service_stopped',
  DATABASE_CONNECTED: 'database_connected',
  DATABASE_DISCONNECTED: 'database_disconnected',
} as const;

export const ENVIRONMENTAL_EVENT_TYPES = {
  TEMPERATURE_ALERT: 'temperature_alert',
  HUMIDITY_ALERT: 'humidity_alert',
  WATER_DETECTED: 'water_detected',
  SMOKE_DETECTED: 'smoke_detected',
  POWER_FAILURE: 'power_failure',
  POWER_RESTORED: 'power_restored',
  SENSOR_ONLINE: 'sensor_online',
  SENSOR_OFFLINE: 'sensor_offline',
  THRESHOLD_EXCEEDED: 'threshold_exceeded',
  THRESHOLD_NORMAL: 'threshold_normal',
} as const;

// =============================================================================
// Device Types and Protocols
// =============================================================================

export const DEVICE_TYPES = {
  // Access Control Devices
  ACCESS_PANEL: 'access_panel',
  CARD_READER: 'card_reader',
  BIOMETRIC_READER: 'biometric_reader',
  KEYPAD: 'keypad',
  INTERCOM: 'intercom',
  TURNSTILE: 'turnstile',
  BARRIER_GATE: 'barrier_gate',
  
  // Door Hardware
  ELECTRIC_STRIKE: 'electric_strike',
  MAGNETIC_LOCK: 'magnetic_lock',
  MOTORIZED_LOCK: 'motorized_lock',
  DOOR_SENSOR: 'door_sensor',
  
  // Video Devices
  IP_CAMERA: 'ip_camera',
  PTZ_CAMERA: 'ptz_camera',
  THERMAL_CAMERA: 'thermal_camera',
  ANALYTICS_CAMERA: 'analytics_camera',
  NVR: 'nvr',
  VIDEO_ENCODER: 'video_encoder',
  
  // Environmental Sensors
  TEMPERATURE_SENSOR: 'temperature_sensor',
  HUMIDITY_SENSOR: 'humidity_sensor',
  WATER_SENSOR: 'water_sensor',
  SMOKE_SENSOR: 'smoke_sensor',
  MOTION_SENSOR: 'motion_sensor',
  
  // Network Infrastructure
  NETWORK_SWITCH: 'network_switch',
  WIRELESS_AP: 'wireless_ap',
  GATEWAY: 'gateway',
  
  // Mobile Devices
  MOBILE_READER: 'mobile_reader',
  SMARTPHONE: 'smartphone',
  TABLET: 'tablet',
} as const;

export const PROTOCOLS = {
  // Access Control Protocols
  OSDP: 'osdp',
  OSDP_V2_2: 'osdp_v2.2',
  WIEGAND: 'wiegand',
  RS485: 'rs485',
  TCP_IP: 'tcp_ip',
  
  // Video Protocols
  ONVIF: 'onvif',
  ONVIF_PROFILE_S: 'onvif_profile_s',
  ONVIF_PROFILE_T: 'onvif_profile_t',
  ONVIF_PROFILE_G: 'onvif_profile_g',
  RTSP: 'rtsp',
  RTMP: 'rtmp',
  HLS: 'hls',
  WEBRTC: 'webrtc',
  
  // Network Protocols
  HTTP: 'http',
  HTTPS: 'https',
  MQTT: 'mqtt',
  WEBSOCKET: 'websocket',
  SNMP: 'snmp',
  
  // Mobile Protocols
  NFC: 'nfc',
  BLE: 'ble',
  BLUETOOTH: 'bluetooth',
  
  // Discovery Protocols
  MDNS: 'mdns',
  DHCP: 'dhcp',
  UPnP: 'upnp',
} as const;

export const MANUFACTURERS = {
  // Access Control Manufacturers
  HID: 'hid',
  HONEYWELL: 'honeywell',
  BOSCH: 'bosch',
  AXIS: 'axis',
  GENETEC: 'genetec',
  LENEL: 'lenel',
  TYCO: 'tyco',
  
  // Video Manufacturers
  HIKVISION: 'hikvision',
  DAHUA: 'dahua',
  HANWHA: 'hanwha',
  AVIGILON: 'avigilon',
  MILESTONE: 'milestone',
  VERKADA: 'verkada',
  
  // Generic/Unknown
  GENERIC: 'generic',
  UNKNOWN: 'unknown',
} as const;

// =============================================================================
// Mobile Credential Types
// =============================================================================

export const MOBILE_CREDENTIAL_TYPES = {
  NFC_CARD_EMULATION: 'nfc_card_emulation',
  BLE_BEACON: 'ble_beacon',
  QR_CODE: 'qr_code',
  BIOMETRIC: 'biometric',
  PIN_CODE: 'pin_code',
  PUSH_NOTIFICATION: 'push_notification',
} as const;

export const MOBILE_PLATFORMS = {
  IOS: 'ios',
  ANDROID: 'android',
  WINDOWS: 'windows',
  WEB: 'web',
} as const;

export const MOBILE_CREDENTIAL_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  SUSPENDED: 'suspended',
  EXPIRED: 'expired',
  REVOKED: 'revoked',
  PENDING_ACTIVATION: 'pending_activation',
} as const;

// =============================================================================
// Alert Severity Levels
// =============================================================================

export const ALERT_SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
} as const;

export const ALERT_TYPES = {
  SECURITY: 'security',
  SYSTEM: 'system',
  ENVIRONMENTAL: 'environmental',
  MAINTENANCE: 'maintenance',
  COMPLIANCE: 'compliance',
  OPERATIONAL: 'operational',
} as const;

export const ALERT_STATUS = {
  OPEN: 'open',
  ACKNOWLEDGED: 'acknowledged',
  IN_PROGRESS: 'in_progress',
  RESOLVED: 'resolved',
  CLOSED: 'closed',
  ESCALATED: 'escalated',
} as const;

// =============================================================================
// Audit Log Categories
// =============================================================================

export const AUDIT_CATEGORIES = {
  AUTHENTICATION: 'authentication',
  AUTHORIZATION: 'authorization',
  ACCESS_CONTROL: 'access_control',
  VIDEO_MANAGEMENT: 'video_management',
  USER_MANAGEMENT: 'user_management',
  SYSTEM_CONFIGURATION: 'system_configuration',
  DATA_ACCESS: 'data_access',
  DEVICE_MANAGEMENT: 'device_management',
  VISITOR_MANAGEMENT: 'visitor_management',
  ENVIRONMENTAL: 'environmental',
  MAINTENANCE: 'maintenance',
  COMPLIANCE: 'compliance',
  INTEGRATION: 'integration',
  BACKUP_RECOVERY: 'backup_recovery',
  SECURITY_INCIDENT: 'security_incident',
} as const;

export const AUDIT_ACTIONS = {
  CREATE: 'create',
  READ: 'read',
  UPDATE: 'update',
  DELETE: 'delete',
  LOGIN: 'login',
  LOGOUT: 'logout',
  ACCESS_GRANTED: 'access_granted',
  ACCESS_DENIED: 'access_denied',
  EXPORT: 'export',
  IMPORT: 'import',
  BACKUP: 'backup',
  RESTORE: 'restore',
  CONFIGURE: 'configure',
  MONITOR: 'monitor',
  ALERT: 'alert',
  ACKNOWLEDGE: 'acknowledge',
  ESCALATE: 'escalate',
  RESOLVE: 'resolve',
} as const;

// =============================================================================
// System Limits (as specified in requirements)
// =============================================================================

export const SYSTEM_LIMITS = {
  // Access Control Limits (Requirement 12)
  MAX_DOORS_PER_INSTALLATION: 10000,
  MAX_USERS_PER_TENANT: 100000,
  MAX_CREDENTIALS_PER_USER: 10,
  MAX_ACCESS_GROUPS: 1000,
  MAX_SCHEDULES: 500,
  
  // Video Management Limits (Requirement 12)
  MAX_CONCURRENT_VIDEO_STREAMS: 1000,
  MAX_CAMERAS_PER_INSTALLATION: 5000,
  MAX_RECORDING_RETENTION_DAYS: 2555, // 7 years
  MAX_VIDEO_EXPORT_SIZE_GB: 100,
  MAX_CONCURRENT_EXPORTS: 10,
  
  // Multi-Tenant Limits
  MAX_TENANTS_PER_INSTALLATION: 1000,
  MAX_ORGANIZATIONS_PER_TENANT: 100,
  MAX_SITES_PER_ORGANIZATION: 50,
  MAX_BUILDINGS_PER_SITE: 20,
  MAX_FLOORS_PER_BUILDING: 100,
  MAX_ZONES_PER_FLOOR: 50,
  
  // API Limits
  MAX_API_REQUESTS_PER_MINUTE: 1000,
  MAX_API_REQUESTS_PER_HOUR: 10000,
  MAX_CONCURRENT_API_CONNECTIONS: 1000,
  MAX_REQUEST_SIZE_MB: 100,
  MAX_RESPONSE_SIZE_MB: 100,
  
  // Database Limits
  MAX_AUDIT_LOGS_PER_DAY: 1000000,
  MAX_EVENTS_PER_DAY: 500000,
  MAX_BATCH_SIZE: 1000,
  
  // File Upload Limits
  MAX_FILE_SIZE_MB: 100,
  MAX_IMAGE_SIZE_MB: 10,
  MAX_VIDEO_CLIP_SIZE_MB: 500,
  
  // Session Limits
  MAX_CONCURRENT_SESSIONS_PER_USER: 5,
  MAX_SESSION_DURATION_HOURS: 24,
  
  // Mobile Credential Limits
  MAX_MOBILE_CREDENTIALS_PER_USER: 3,
  MAX_MOBILE_DEVICES_PER_USER: 5,
  
  // Environmental Monitoring Limits
  MAX_SENSORS_PER_INSTALLATION: 10000,
  MAX_SENSOR_READINGS_PER_DAY: 1440000, // 1 reading per minute per sensor
  
  // Visitor Management Limits
  MAX_VISITORS_PER_DAY: 10000,
  MAX_VISITOR_GROUPS: 100,
  
  // Alert Limits
  MAX_ALERTS_PER_DAY: 100000,
  MAX_ALERT_RECIPIENTS: 100,
  
  // Offline Operation Limits (Requirement 27)
  OFFLINE_OPERATION_HOURS: 72,
  OFFLINE_CREDENTIAL_CACHE_SIZE: 50000,
  OFFLINE_EVENT_QUEUE_SIZE: 100000,
} as const;

// =============================================================================
// Time Constants
// =============================================================================

export const TIME_CONSTANTS = {
  MILLISECONDS_PER_SECOND: 1000,
  SECONDS_PER_MINUTE: 60,
  MINUTES_PER_HOUR: 60,
  HOURS_PER_DAY: 24,
  DAYS_PER_WEEK: 7,
  DAYS_PER_MONTH: 30,
  DAYS_PER_YEAR: 365,
  
  // Common durations in milliseconds
  ONE_SECOND: 1000,
  ONE_MINUTE: 60000,
  ONE_HOUR: 3600000,
  ONE_DAY: 86400000,
  ONE_WEEK: 604800000,
  ONE_MONTH: 2592000000,
  ONE_YEAR: 31536000000,
} as const;

// =============================================================================
// Export all constants as a single object for convenience
// =============================================================================

export const SPARC_CONSTANTS = {
  HTTP_STATUS,
  API_RESPONSE_CODES,
  ERROR_CODES,
  ERROR_MESSAGES,
  DEFAULT_CONFIG,
  ROLES,
  PERMISSIONS,
  ACCESS_EVENT_TYPES,
  VIDEO_EVENT_TYPES,
  SYSTEM_EVENT_TYPES,
  ENVIRONMENTAL_EVENT_TYPES,
  DEVICE_TYPES,
  PROTOCOLS,
  MANUFACTURERS,
  MOBILE_CREDENTIAL_TYPES,
  MOBILE_PLATFORMS,
  MOBILE_CREDENTIAL_STATUS,
  ALERT_SEVERITY,
  ALERT_TYPES,
  ALERT_STATUS,
  AUDIT_CATEGORIES,
  AUDIT_ACTIONS,
  SYSTEM_LIMITS,
  TIME_CONSTANTS,
} as const;

// Type exports for TypeScript consumers
export type HttpStatus = typeof HTTP_STATUS[keyof typeof HTTP_STATUS];
export type ApiResponseCode = typeof API_RESPONSE_CODES[keyof typeof API_RESPONSE_CODES];
export type ErrorCode = typeof ERROR_CODES[keyof typeof ERROR_CODES];
export type Role = typeof ROLES[keyof typeof ROLES];
export type Permission = typeof PERMISSIONS[keyof typeof PERMISSIONS];
export type AccessEventType = typeof ACCESS_EVENT_TYPES[keyof typeof ACCESS_EVENT_TYPES];
export type VideoEventType = typeof VIDEO_EVENT_TYPES[keyof typeof VIDEO_EVENT_TYPES];
export type SystemEventType = typeof SYSTEM_EVENT_TYPES[keyof typeof SYSTEM_EVENT_TYPES];
export type EnvironmentalEventType = typeof ENVIRONMENTAL_EVENT_TYPES[keyof typeof ENVIRONMENTAL_EVENT_TYPES];
export type DeviceType = typeof DEVICE_TYPES[keyof typeof DEVICE_TYPES];
export type Protocol = typeof PROTOCOLS[keyof typeof PROTOCOLS];
export type Manufacturer = typeof MANUFACTURERS[keyof typeof MANUFACTURERS];
export type MobileCredentialType = typeof MOBILE_CREDENTIAL_TYPES[keyof typeof MOBILE_CREDENTIAL_TYPES];
export type MobilePlatform = typeof MOBILE_PLATFORMS[keyof typeof MOBILE_PLATFORMS];
export type MobileCredentialStatus = typeof MOBILE_CREDENTIAL_STATUS[keyof typeof MOBILE_CREDENTIAL_STATUS];
export type AlertSeverity = typeof ALERT_SEVERITY[keyof typeof ALERT_SEVERITY];
export type AlertType = typeof ALERT_TYPES[keyof typeof ALERT_TYPES];
export type AlertStatus = typeof ALERT_STATUS[keyof typeof ALERT_STATUS];
export type AuditCategory = typeof AUDIT_CATEGORIES[keyof typeof AUDIT_CATEGORIES];
export type AuditAction = typeof AUDIT_ACTIONS[keyof typeof AUDIT_ACTIONS];