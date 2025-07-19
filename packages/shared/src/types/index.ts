import { z } from 'zod';

// Base schemas
const UuidSchema = z.string().uuid();
const TimestampSchema = z.string().datetime();
const EmailSchema = z.string().email();
const IpAddressSchema = z.string().ip();

// Tenant Schema
export const TenantSchema = z.object({
  id: UuidSchema,
  name: z.string().min(1).max(255),
  domain: z.string().min(1).max(255),
  settings: z.object({
    branding: z.record(z.any()).optional(),
    features: z.record(z.any()).optional(),
    limits: z.object({
      doors: z.number().int().positive(),
      cameras: z.number().int().positive(),
      storage_gb: z.number().int().positive(),
    }),
  }),
  created_at: TimestampSchema,
  updated_at: TimestampSchema,
});

// Organization Schema
export const OrganizationSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  address: z.record(z.any()).optional(),
  contact_info: z.record(z.any()).optional(),
  settings: z.record(z.any()).optional(),
  active: z.boolean(),
  created_at: TimestampSchema,
  updated_at: TimestampSchema,
});

// Site Schema
export const SiteSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  organization_id: UuidSchema,
  name: z.string().min(1).max(255),
  address: z.record(z.any()).optional(),
  timezone: z.string(),
  settings: z.record(z.any()).optional(),
  created_at: TimestampSchema,
});

// Building Schema
export const BuildingSchema = z.object({
  id: UuidSchema,
  site_id: UuidSchema,
  name: z.string().min(1).max(255),
  floors: z.number().int().positive(),
  floor_plans: z.array(z.any()).optional(),
  settings: z.record(z.any()).optional(),
  created_at: TimestampSchema,
});

// Floor Schema
export const FloorSchema = z.object({
  id: UuidSchema,
  building_id: UuidSchema,
  level: z.number().int(),
  name: z.string().min(1).max(255),
  floor_plan: z.string().url().optional(),
  zones: z.array(z.any()).optional(),
  created_at: TimestampSchema,
});

// Zone Schema
export const ZoneSchema = z.object({
  id: UuidSchema,
  floor_id: UuidSchema,
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  zone_type: z.string(),
  boundaries: z.array(z.any()).optional(),
  access_rules: z.record(z.any()).optional(),
  created_at: TimestampSchema,
});

// Door Schema
export const DoorSchema = z.object({
  id: UuidSchema,
  floor_id: UuidSchema,
  zone_id: UuidSchema.optional(),
  name: z.string().min(1).max(255),
  location: z.object({
    x: z.number(),
    y: z.number(),
  }).optional(),
  hardware: z.object({
    panel_id: UuidSchema.optional(),
    reader_ids: z.array(UuidSchema).optional(),
    lock_type: z.string().optional(),
  }).optional(),
  settings: z.object({
    unlock_duration: z.number().int().positive().optional(),
    door_ajar_timeout: z.number().int().positive().optional(),
  }).optional(),
  status: z.enum(['online', 'offline', 'error', 'maintenance']),
  created_at: TimestampSchema,
});

// User Schema
export const UserSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  username: z.string().min(1).max(255),
  email: EmailSchema,
  first_name: z.string().min(1).max(255).optional(),
  last_name: z.string().min(1).max(255).optional(),
  roles: z.array(z.string()),
  permissions: z.record(z.any()).optional(),
  credentials: z.array(UuidSchema).optional(),
  active: z.boolean(),
  last_login: TimestampSchema.optional(),
  created_at: TimestampSchema,
  updated_at: TimestampSchema,
});

// Camera Schema
export const CameraSchema = z.object({
  id: UuidSchema,
  floor_id: UuidSchema,
  zone_id: UuidSchema.optional(),
  name: z.string().min(1).max(255),
  location: z.object({
    x: z.number(),
    y: z.number(),
  }).optional(),
  hardware: z.object({
    ip_address: IpAddressSchema,
    manufacturer: z.string(),
    model: z.string(),
    streams: z.array(z.object({
      resolution: z.enum(['high', 'medium', 'low']),
      url: z.string().url(),
    })),
  }),
  settings: z.object({
    recording_enabled: z.boolean(),
    motion_detection: z.boolean(),
    retention_days: z.number().int().positive(),
  }),
  status: z.enum(['online', 'offline', 'error', 'maintenance']),
  created_at: TimestampSchema,
});

// Access Event Schema
export const AccessEventSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  door_id: UuidSchema,
  user_id: UuidSchema.optional(),
  credential_id: UuidSchema.optional(),
  event_type: z.enum(['access_granted', 'access_denied', 'door_forced', 'door_ajar', 'emergency_unlock']),
  result: z.enum(['success', 'failure', 'error']),
  timestamp: TimestampSchema,
  metadata: z.record(z.any()).optional(),
});

// Access Panel Schema
export const AccessPanelSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  floor_id: UuidSchema,
  name: z.string().min(1).max(255),
  ip_address: IpAddressSchema,
  manufacturer: z.string(),
  model: z.string(),
  firmware_version: z.string(),
  protocol: z.enum(['OSDP', 'Wiegand', 'TCP/IP', 'RS485']),
  status: z.enum(['online', 'offline', 'error', 'maintenance']),
  last_heartbeat: TimestampSchema.optional(),
  settings: z.record(z.any()).optional(),
  created_at: TimestampSchema,
});

// Card Reader Schema
export const CardReaderSchema = z.object({
  id: UuidSchema,
  panel_id: UuidSchema,
  door_id: UuidSchema,
  name: z.string().min(1).max(255),
  reader_type: z.enum(['proximity', 'smart_card', 'biometric', 'mobile', 'pin']),
  supported_formats: z.array(z.string()),
  settings: z.object({
    led_control: z.boolean().optional(),
    beep_control: z.boolean().optional(),
    tamper_detection: z.boolean().optional(),
  }).optional(),
  status: z.enum(['online', 'offline', 'error', 'maintenance']),
  created_at: TimestampSchema,
});

// Credential Schema
export const CredentialSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  user_id: UuidSchema,
  credential_type: z.enum(['card', 'pin', 'biometric', 'mobile', 'temporary']),
  card_number: z.string().optional(),
  facility_code: z.string().optional(),
  pin_code: z.string().optional(),
  biometric_template: z.string().optional(),
  mobile_credential_id: UuidSchema.optional(),
  active: z.boolean(),
  expires_at: TimestampSchema.optional(),
  created_at: TimestampSchema,
});

// Access Group Schema
export const AccessGroupSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  parent_group_id: UuidSchema.optional(),
  permissions: z.record(z.any()).optional(),
  schedules: z.array(UuidSchema).optional(),
  doors: z.array(UuidSchema).optional(),
  users: z.array(UuidSchema).optional(),
  created_at: TimestampSchema,
});

// Schedule Schema
export const ScheduleSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  time_zones: z.array(z.object({
    day_of_week: z.number().int().min(0).max(6),
    start_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    end_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
  })).optional(),
  holidays: z.array(z.string().date()).optional(),
  exceptions: z.array(z.object({
    date: z.string().date(),
    start_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    end_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
  })).optional(),
  active: z.boolean(),
  created_at: TimestampSchema,
});

// Alert Schema
export const AlertSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  alert_type: z.enum(['security', 'system', 'environmental', 'maintenance']),
  priority: z.enum(['low', 'medium', 'high', 'critical']),
  source_id: UuidSchema,
  source_type: z.enum(['door', 'camera', 'sensor', 'panel', 'system']),
  message: z.string().min(1),
  details: z.record(z.any()).optional(),
  status: z.enum(['active', 'acknowledged', 'resolved']),
  acknowledged_by: UuidSchema.optional(),
  acknowledged_at: TimestampSchema.optional(),
  resolved_at: TimestampSchema.optional(),
  created_at: TimestampSchema,
});

// Audit Log Schema
export const AuditLogSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  user_id: UuidSchema.optional(),
  action: z.string().min(1),
  resource_type: z.string(),
  resource_id: UuidSchema.optional(),
  details: z.record(z.any()).optional(),
  ip_address: IpAddressSchema.optional(),
  user_agent: z.string().optional(),
  timestamp: TimestampSchema,
});

// Video Recording Schema
export const VideoRecordingSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  camera_id: UuidSchema,
  start_time: TimestampSchema,
  end_time: TimestampSchema.optional(),
  file_path: z.string(),
  file_size: z.number().int().positive(),
  resolution: z.enum(['high', 'medium', 'low']),
  frame_rate: z.number().positive(),
  trigger_event_id: UuidSchema.optional(),
  metadata: z.object({
    motion_detected: z.boolean().optional(),
    analytics_data: z.record(z.any()).optional(),
    watermark: z.string().optional(),
  }).optional(),
  status: z.enum(['recording', 'completed', 'error', 'archived']),
  created_at: TimestampSchema,
});

// Visitor Schema
export const VisitorSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  name: z.string().min(1).max(255),
  email: EmailSchema.optional(),
  phone: z.string().optional(),
  company: z.string().optional(),
  host_user_id: UuidSchema,
  visit_purpose: z.string().optional(),
  scheduled_arrival: TimestampSchema.optional(),
  scheduled_departure: TimestampSchema.optional(),
  actual_arrival: TimestampSchema.optional(),
  actual_departure: TimestampSchema.optional(),
  temporary_credentials: z.array(UuidSchema).optional(),
  status: z.enum(['scheduled', 'checked_in', 'checked_out', 'overstay', 'cancelled']),
  created_at: TimestampSchema,
});

// Maintenance Work Order Schema
export const MaintenanceWorkOrderSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  device_id: UuidSchema,
  device_type: z.enum(['door', 'camera', 'panel', 'reader', 'sensor']),
  work_order_type: z.enum(['preventive', 'corrective', 'emergency', 'upgrade']),
  priority: z.enum(['low', 'medium', 'high', 'critical']),
  title: z.string().min(1).max(255),
  description: z.string(),
  assigned_to: UuidSchema.optional(),
  scheduled_date: TimestampSchema.optional(),
  completed_date: TimestampSchema.optional(),
  diagnostic_data: z.record(z.any()).optional(),
  parts_used: z.array(z.object({
    part_number: z.string(),
    quantity: z.number().int().positive(),
    cost: z.number().positive().optional(),
  })).optional(),
  labor_hours: z.number().positive().optional(),
  status: z.enum(['open', 'assigned', 'in_progress', 'completed', 'cancelled']),
  created_at: TimestampSchema,
});

// Incident Report Schema
export const IncidentReportSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  incident_type: z.enum(['security_breach', 'equipment_failure', 'safety_incident', 'policy_violation']),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  location: z.object({
    site_id: UuidSchema.optional(),
    building_id: UuidSchema.optional(),
    floor_id: UuidSchema.optional(),
    zone_id: UuidSchema.optional(),
  }),
  description: z.string().min(1),
  related_events: z.array(UuidSchema).optional(),
  related_recordings: z.array(UuidSchema).optional(),
  assigned_to: UuidSchema.optional(),
  status: z.enum(['open', 'investigating', 'resolved', 'closed']),
  created_at: TimestampSchema,
  resolved_at: TimestampSchema.optional(),
});

// Environmental Sensor Schema
export const EnvironmentalSensorSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  floor_id: UuidSchema,
  zone_id: UuidSchema.optional(),
  name: z.string().min(1).max(255),
  sensor_type: z.enum(['temperature', 'humidity', 'leak', 'air_quality', 'motion']),
  location: z.object({
    x: z.number(),
    y: z.number(),
  }).optional(),
  hardware: z.object({
    ip_address: IpAddressSchema.optional(),
    manufacturer: z.string(),
    model: z.string(),
    protocol: z.enum(['SNMP', 'Modbus', 'BACnet', 'HTTP']),
  }),
  thresholds: z.object({
    temperature_min: z.number().optional(),
    temperature_max: z.number().optional(),
    humidity_min: z.number().optional(),
    humidity_max: z.number().optional(),
    leak_detection: z.boolean().optional(),
  }).optional(),
  status: z.enum(['online', 'offline', 'error', 'maintenance']),
  last_reading: TimestampSchema.optional(),
  created_at: TimestampSchema,
});

// Environmental Reading Schema
export const EnvironmentalReadingSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  sensor_id: UuidSchema,
  temperature: z.number().optional(),
  humidity: z.number().optional(),
  leak_detected: z.boolean().optional(),
  air_quality_index: z.number().optional(),
  timestamp: TimestampSchema,
  alert_triggered: z.boolean(),
});

// Mobile Credential Schema
export const MobileCredentialSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  user_id: UuidSchema,
  device_id: z.string(),
  device_type: z.enum(['ios', 'android']),
  platform: z.enum(['nfc', 'ble', 'both']),
  credential_data: z.string(), // encrypted
  enrollment_date: TimestampSchema,
  last_used: TimestampSchema.optional(),
  revoked: z.boolean(),
  revoked_at: TimestampSchema.optional(),
  offline_capable: z.boolean(),
  created_at: TimestampSchema,
});

// Privacy Mask Schema
export const PrivacyMaskSchema = z.object({
  id: UuidSchema,
  camera_id: UuidSchema,
  tenant_id: UuidSchema,
  name: z.string().min(1).max(255),
  coordinates: z.array(z.object({
    x: z.number(),
    y: z.number(),
  })),
  mask_type: z.enum(['blur', 'black', 'pixelate']),
  active: z.boolean(),
  created_by: UuidSchema,
  created_at: TimestampSchema,
});

// Video Export Log Schema
export const VideoExportLogSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  user_id: UuidSchema,
  camera_ids: z.array(UuidSchema),
  start_time: TimestampSchema,
  end_time: TimestampSchema,
  export_format: z.enum(['mp4', 'avi', 'mov']),
  export_purpose: z.string(),
  file_path: z.string().optional(),
  file_size: z.number().int().positive().optional(),
  watermark_applied: z.boolean(),
  chain_of_custody: z.record(z.any()).optional(),
  status: z.enum(['pending', 'processing', 'completed', 'failed']),
  created_at: TimestampSchema,
  exported_at: TimestampSchema.optional(),
});

// Elevator Control Schema
export const ElevatorControlSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  building_id: UuidSchema,
  name: z.string().min(1).max(255),
  floors_served: z.array(z.number().int()),
  ip_address: IpAddressSchema,
  protocol: z.enum(['BACnet', 'Modbus', 'proprietary']),
  manufacturer: z.enum(['Otis', 'KONE', 'Schindler', 'ThyssenKrupp', 'other']),
  access_rules: z.record(z.any()).optional(),
  emergency_override: z.boolean(),
  status: z.enum(['online', 'offline', 'error', 'maintenance']),
  created_at: TimestampSchema,
});

// System Configuration Schema
export const SystemConfigurationSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  category: z.string(),
  key: z.string(),
  value: z.any(),
  description: z.string().optional(),
  updated_by: UuidSchema,
  updated_at: TimestampSchema,
});

// Offline Event Queue Schema
export const OfflineEventQueueSchema = z.object({
  id: UuidSchema,
  device_id: UuidSchema,
  tenant_id: UuidSchema,
  event_type: z.string(),
  event_data: z.any(),
  timestamp: TimestampSchema,
  synchronized: z.boolean(),
  sync_timestamp: TimestampSchema.optional(),
  priority: z.number().int().min(1).max(10),
});

// Policy Template Schema
export const PolicyTemplateSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  policy_type: z.enum(['access_control', 'video_retention', 'compliance', 'security']),
  template_data: z.record(z.any()),
  compliance_framework: z.enum(['SOX', 'HIPAA', 'PCI_DSS', 'GDPR', 'CCPA']).optional(),
  active: z.boolean(),
  created_at: TimestampSchema,
});

// Offline Operation Log Schema
export const OfflineOperationLogSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  device_id: UuidSchema,
  device_type: z.enum(['panel', 'camera', 'sensor']),
  offline_start: TimestampSchema,
  offline_end: TimestampSchema.optional(),
  cached_permissions: z.record(z.any()).optional(),
  events_during_offline: z.array(UuidSchema).optional(),
  sync_status: z.enum(['pending', 'in_progress', 'completed', 'failed']),
  sync_completed_at: TimestampSchema.optional(),
});

// Certificate Schema
export const CertificateSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  certificate_type: z.enum(['ssl', 'device', 'ca', 'client']),
  subject: z.string(),
  issuer: z.string(),
  serial_number: z.string(),
  valid_from: TimestampSchema,
  valid_to: TimestampSchema,
  fingerprint: z.string(),
  auto_renewal: z.boolean(),
  status: z.enum(['active', 'expired', 'revoked', 'pending']),
  created_at: TimestampSchema,
});

// Backup Job Schema
export const BackupJobSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  backup_type: z.enum(['full', 'incremental', 'differential']),
  schedule: z.string(), // cron expression
  last_run: TimestampSchema.optional(),
  next_run: TimestampSchema,
  status: z.enum(['scheduled', 'running', 'completed', 'failed']),
  backup_size: z.number().int().positive().optional(),
  retention_days: z.number().int().positive(),
  storage_location: z.string(),
  encryption_enabled: z.boolean(),
  created_at: TimestampSchema,
});

// Integration Configuration Schema
export const IntegrationConfigurationSchema = z.object({
  id: UuidSchema,
  tenant_id: UuidSchema,
  integration_type: z.enum(['ldap', 'active_directory', 'hvac', 'fire_safety', 'elevator', 'webhook']),
  name: z.string().min(1).max(255),
  endpoint_url: z.string().url().optional(),
  authentication: z.record(z.any()).optional(),
  configuration: z.record(z.any()),
  active: z.boolean(),
  last_sync: TimestampSchema.optional(),
  sync_status: z.enum(['success', 'failed', 'pending']).optional(),
  created_at: TimestampSchema,
});

// Generate TypeScript types from Zod schemas
export type Tenant = z.infer<typeof TenantSchema>;
export type Organization = z.infer<typeof OrganizationSchema>;
export type Site = z.infer<typeof SiteSchema>;
export type Building = z.infer<typeof BuildingSchema>;
export type Floor = z.infer<typeof FloorSchema>;
export type Zone = z.infer<typeof ZoneSchema>;
export type Door = z.infer<typeof DoorSchema>;
export type User = z.infer<typeof UserSchema>;
export type Camera = z.infer<typeof CameraSchema>;
export type AccessEvent = z.infer<typeof AccessEventSchema>;
export type AccessPanel = z.infer<typeof AccessPanelSchema>;
export type CardReader = z.infer<typeof CardReaderSchema>;
export type Credential = z.infer<typeof CredentialSchema>;
export type AccessGroup = z.infer<typeof AccessGroupSchema>;
export type Schedule = z.infer<typeof ScheduleSchema>;
export type Alert = z.infer<typeof AlertSchema>;
export type AuditLog = z.infer<typeof AuditLogSchema>;
export type VideoRecording = z.infer<typeof VideoRecordingSchema>;
export type Visitor = z.infer<typeof VisitorSchema>;
export type MaintenanceWorkOrder = z.infer<typeof MaintenanceWorkOrderSchema>;
export type IncidentReport = z.infer<typeof IncidentReportSchema>;
export type EnvironmentalSensor = z.infer<typeof EnvironmentalSensorSchema>;
export type EnvironmentalReading = z.infer<typeof EnvironmentalReadingSchema>;
export type MobileCredential = z.infer<typeof MobileCredentialSchema>;
export type PrivacyMask = z.infer<typeof PrivacyMaskSchema>;
export type VideoExportLog = z.infer<typeof VideoExportLogSchema>;
export type ElevatorControl = z.infer<typeof ElevatorControlSchema>;
export type SystemConfiguration = z.infer<typeof SystemConfigurationSchema>;
export type OfflineEventQueue = z.infer<typeof OfflineEventQueueSchema>;
export type PolicyTemplate = z.infer<typeof PolicyTemplateSchema>;
export type OfflineOperationLog = z.infer<typeof OfflineOperationLogSchema>;
export type Certificate = z.infer<typeof CertificateSchema>;
export type BackupJob = z.infer<typeof BackupJobSchema>;
export type IntegrationConfiguration = z.infer<typeof IntegrationConfigurationSchema>;

// DTO Types for API requests/responses
export type CreateTenantDTO = z.infer<typeof TenantSchema.omit({ id: true, created_at: true, updated_at: true })>;
export type UpdateTenantDTO = z.infer<typeof TenantSchema.partial().omit({ id: true, created_at: true })>;

export type CreateOrganizationDTO = z.infer<typeof OrganizationSchema.omit({ id: true, created_at: true, updated_at: true })>;
export type UpdateOrganizationDTO = z.infer<typeof OrganizationSchema.partial().omit({ id: true, created_at: true })>;

export type CreateSiteDTO = z.infer<typeof SiteSchema.omit({ id: true, created_at: true })>;
export type UpdateSiteDTO = z.infer<typeof SiteSchema.partial().omit({ id: true, created_at: true })>;

export type CreateBuildingDTO = z.infer<typeof BuildingSchema.omit({ id: true, created_at: true })>;
export type UpdateBuildingDTO = z.infer<typeof BuildingSchema.partial().omit({ id: true, created_at: true })>;

export type CreateFloorDTO = z.infer<typeof FloorSchema.omit({ id: true, created_at: true })>;
export type UpdateFloorDTO = z.infer<typeof FloorSchema.partial().omit({ id: true, created_at: true })>;

export type CreateZoneDTO = z.infer<typeof ZoneSchema.omit({ id: true, created_at: true })>;
export type UpdateZoneDTO = z.infer<typeof ZoneSchema.partial().omit({ id: true, created_at: true })>;

export type CreateDoorDTO = z.infer<typeof DoorSchema.omit({ id: true, created_at: true })>;
export type UpdateDoorDTO = z.infer<typeof DoorSchema.partial().omit({ id: true, created_at: true })>;

export type CreateUserDTO = z.infer<typeof UserSchema.omit({ id: true, created_at: true, updated_at: true, last_login: true })>;
export type UpdateUserDTO = z.infer<typeof UserSchema.partial().omit({ id: true, created_at: true, last_login: true })>;

export type CreateCameraDTO = z.infer<typeof CameraSchema.omit({ id: true, created_at: true })>;
export type UpdateCameraDTO = z.infer<typeof CameraSchema.partial().omit({ id: true, created_at: true })>;

export type CreateAccessEventDTO = z.infer<typeof AccessEventSchema.omit({ id: true })>;

export type CreateAccessPanelDTO = z.infer<typeof AccessPanelSchema.omit({ id: true, created_at: true, last_heartbeat: true })>;
export type UpdateAccessPanelDTO = z.infer<typeof AccessPanelSchema.partial().omit({ id: true, created_at: true })>;

export type CreateCardReaderDTO = z.infer<typeof CardReaderSchema.omit({ id: true, created_at: true })>;
export type UpdateCardReaderDTO = z.infer<typeof CardReaderSchema.partial().omit({ id: true, created_at: true })>;

export type CreateCredentialDTO = z.infer<typeof CredentialSchema.omit({ id: true, created_at: true })>;
export type UpdateCredentialDTO = z.infer<typeof CredentialSchema.partial().omit({ id: true, created_at: true })>;

export type CreateAccessGroupDTO = z.infer<typeof AccessGroupSchema.omit({ id: true, created_at: true })>;
export type UpdateAccessGroupDTO = z.infer<typeof AccessGroupSchema.partial().omit({ id: true, created_at: true })>;

export type CreateScheduleDTO = z.infer<typeof ScheduleSchema.omit({ id: true, created_at: true })>;
export type UpdateScheduleDTO = z.infer<typeof ScheduleSchema.partial().omit({ id: true, created_at: true })>;

export type CreateAlertDTO = z.infer<typeof AlertSchema.omit({ id: true, created_at: true, acknowledged_by: true, acknowledged_at: true, resolved_at: true })>;
export type UpdateAlertDTO = z.infer<typeof AlertSchema.partial().omit({ id: true, created_at: true })>;

export type CreateAuditLogDTO = z.infer<typeof AuditLogSchema.omit({ id: true })>;

export type CreateVideoRecordingDTO = z.infer<typeof VideoRecordingSchema.omit({ id: true, created_at: true })>;
export type UpdateVideoRecordingDTO = z.infer<typeof VideoRecordingSchema.partial().omit({ id: true, created_at: true })>;

export type CreateVisitorDTO = z.infer<typeof VisitorSchema.omit({ id: true, created_at: true, actual_arrival: true, actual_departure: true })>;
export type UpdateVisitorDTO = z.infer<typeof VisitorSchema.partial().omit({ id: true, created_at: true })>;

export type CreateMaintenanceWorkOrderDTO = z.infer<typeof MaintenanceWorkOrderSchema.omit({ id: true, created_at: true, completed_date: true })>;
export type UpdateMaintenanceWorkOrderDTO = z.infer<typeof MaintenanceWorkOrderSchema.partial().omit({ id: true, created_at: true })>;

export type CreateIncidentReportDTO = z.infer<typeof IncidentReportSchema.omit({ id: true, created_at: true, resolved_at: true })>;
export type UpdateIncidentReportDTO = z.infer<typeof IncidentReportSchema.partial().omit({ id: true, created_at: true })>;

export type CreateEnvironmentalSensorDTO = z.infer<typeof EnvironmentalSensorSchema.omit({ id: true, created_at: true, last_reading: true })>;
export type UpdateEnvironmentalSensorDTO = z.infer<typeof EnvironmentalSensorSchema.partial().omit({ id: true, created_at: true })>;

export type CreateEnvironmentalReadingDTO = z.infer<typeof EnvironmentalReadingSchema.omit({ id: true })>;

export type CreateMobileCredentialDTO = z.infer<typeof MobileCredentialSchema.omit({ id: true, created_at: true, last_used: true, revoked_at: true })>;
export type UpdateMobileCredentialDTO = z.infer<typeof MobileCredentialSchema.partial().omit({ id: true, created_at: true })>;

export type CreatePrivacyMaskDTO = z.infer<typeof PrivacyMaskSchema.omit({ id: true, created_at: true })>;
export type UpdatePrivacyMaskDTO = z.infer<typeof PrivacyMaskSchema.partial().omit({ id: true, created_at: true })>;

export type CreateVideoExportLogDTO = z.infer<typeof VideoExportLogSchema.omit({ id: true, created_at: true, exported_at: true, file_path: true, file_size: true })>;
export type UpdateVideoExportLogDTO = z.infer<typeof VideoExportLogSchema.partial().omit({ id: true, created_at: true })>;

export type CreateElevatorControlDTO = z.infer<typeof ElevatorControlSchema.omit({ id: true, created_at: true })>;
export type UpdateElevatorControlDTO = z.infer<typeof ElevatorControlSchema.partial().omit({ id: true, created_at: true })>;

export type CreateSystemConfigurationDTO = z.infer<typeof SystemConfigurationSchema.omit({ id: true, updated_at: true })>;
export type UpdateSystemConfigurationDTO = z.infer<typeof SystemConfigurationSchema.partial().omit({ id: true })>;

export type CreateOfflineEventQueueDTO = z.infer<typeof OfflineEventQueueSchema.omit({ id: true, synchronized: true, sync_timestamp: true })>;

export type CreatePolicyTemplateDTO = z.infer<typeof PolicyTemplateSchema.omit({ id: true, created_at: true })>;
export type UpdatePolicyTemplateDTO = z.infer<typeof PolicyTemplateSchema.partial().omit({ id: true, created_at: true })>;

export type CreateOfflineOperationLogDTO = z.infer<typeof OfflineOperationLogSchema.omit({ id: true, offline_end: true, sync_completed_at: true })>;
export type UpdateOfflineOperationLogDTO = z.infer<typeof OfflineOperationLogSchema.partial().omit({ id: true })>;

export type CreateCertificateDTO = z.infer<typeof CertificateSchema.omit({ id: true, created_at: true })>;
export type UpdateCertificateDTO = z.infer<typeof CertificateSchema.partial().omit({ id: true, created_at: true })>;

export type CreateBackupJobDTO = z.infer<typeof BackupJobSchema.omit({ id: true, created_at: true, last_run: true, backup_size: true })>;
export type UpdateBackupJobDTO = z.infer<typeof BackupJobSchema.partial().omit({ id: true, created_at: true })>;

export type CreateIntegrationConfigurationDTO = z.infer<typeof IntegrationConfigurationSchema.omit({ id: true, created_at: true, last_sync: true, sync_status: true })>;
export type UpdateIntegrationConfigurationDTO = z.infer<typeof IntegrationConfigurationSchema.partial().omit({ id: true, created_at: true })>;

// Enhanced API response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: {
    code: string;
    message: string;
    details?: Record<string, any>;
    timestamp: string;
    requestId: string;
    path?: string;
    method?: string;
    validationErrors?: Array<{
      field: string;
      message: string;
      value?: any;
    }>;
  };
  meta?: {
    requestId: string;
    timestamp: string;
    version: string;
    environment: string;
    processingTime?: number;
  };
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
    hasNext: boolean;
    hasPrev: boolean;
  };
  meta?: {
    requestId: string;
    timestamp: string;
    totalCount: number;
    filteredCount: number;
  };
}

export interface ListQueryParams {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
  search?: string;
  filters?: Record<string, any>;
  include?: string[]; // Related entities to include
  fields?: string[]; // Specific fields to return
  tenantId?: string;
}

// Standardized error types
export interface ValidationError {
  field: string;
  message: string;
  value?: any;
  code: string;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, any>;
  timestamp: string;
  requestId: string;
  path?: string;
  method?: string;
  statusCode: number;
  validationErrors?: ValidationError[];
  stack?: string; // Only in development
}

// Health check types
export interface HealthCheckResponse {
  status: 'healthy' | 'unhealthy' | 'degraded';
  service: string;
  version: string;
  timestamp: string;
  uptime: number;
  environment: string;
  checks?: {
    database?: 'healthy' | 'unhealthy';
    redis?: 'healthy' | 'unhealthy';
    external_services?: Record<string, 'healthy' | 'unhealthy'>;
  };
  details?: Record<string, any>;
}

export interface ReadinessCheckResponse {
  status: 'ready' | 'not ready';
  service: string;
  timestamp: string;
  checks: {
    database: 'healthy' | 'unhealthy';
    redis: 'healthy' | 'unhealthy';
    migrations: 'up_to_date' | 'pending' | 'error';
    external_dependencies?: Record<string, 'healthy' | 'unhealthy'>;
  };
  error?: string;
}

export interface MetricsResponse {
  service: string;
  timestamp: string;
  uptime: number;
  memory: {
    rss: string;
    heapTotal: string;
    heapUsed: string;
    external: string;
    arrayBuffers?: string;
  };
  process: {
    pid: number;
    version: string;
    platform: string;
    arch: string;
    cpuUsage?: {
      user: number;
      system: number;
    };
  };
  requests?: {
    total: number;
    successful: number;
    failed: number;
    averageResponseTime: number;
  };
  circuitBreakers?: Record<string, {
    state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
    failures: number;
    lastFailureTime: number;
  }>;
}

// Enhanced Authentication types
export interface LoginRequest {
  email: string;
  password: string;
  tenantId: string;
  rememberMe?: boolean;
  deviceInfo?: {
    userAgent: string;
    ipAddress: string;
    deviceId?: string;
  };
}

export interface SignupRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  tenantId: string;
  role?: string;
  invitationToken?: string;
}

export interface LoginResponse {
  message: string;
  user: {
    id: string;
    email: string;
    username: string;
    firstName?: string;
    lastName?: string;
    role: string;
    tenantId: string;
    permissions: Record<string, any>;
    lastLoginAt?: string;
    tenant: {
      id: string;
      name: string;
      domain: string;
      settings: Record<string, any>;
    };
  };
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
  sessionId: string;
}

export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  message: string;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: {
    id: string;
    email: string;
    username: string;
    role: string;
    tenantId: string;
  };
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  confirmPassword?: string;
}

export interface ResetPasswordRequest {
  email: string;
  tenantId: string;
}

export interface ResetPasswordConfirmRequest {
  token: string;
  newPassword: string;
  confirmPassword: string;
}

export interface LogoutRequest {
  refreshToken?: string;
  logoutAllDevices?: boolean;
}

export interface UserProfileResponse {
  user: {
    id: string;
    email: string;
    username: string;
    firstName?: string;
    lastName?: string;
    role: string;
    tenantId: string;
    permissions: Record<string, any>;
    active: boolean;
    lastLoginAt?: string;
    createdAt: string;
    updatedAt: string;
    tenant: {
      id: string;
      name: string;
      domain: string;
      settings: Record<string, any>;
    };
  };
}

export interface UpdateProfileRequest {
  firstName?: string;
  lastName?: string;
  email?: string;
  username?: string;
}

// JWT Token payload types
export interface AccessTokenPayload {
  sub: string; // user ID
  email: string;
  username: string;
  tenantId: string;
  role: string;
  permissions: Record<string, any>;
  type: 'access';
  iat: number;
  exp: number;
  jti: string; // JWT ID for token tracking
  sessionId: string;
}

export interface RefreshTokenPayload {
  sub: string; // user ID
  tenantId: string;
  type: 'refresh';
  iat: number;
  exp: number;
  jti: string;
  sessionId: string;
}

// Session management types
export interface UserSession {
  id: string;
  userId: string;
  tenantId: string;
  accessToken: string;
  refreshToken: string;
  deviceInfo: {
    userAgent: string;
    ipAddress: string;
    deviceId?: string;
  };
  createdAt: string;
  lastAccessedAt: string;
  expiresAt: string;
  active: boolean;
}

export interface SessionListResponse {
  sessions: Array<{
    id: string;
    deviceInfo: {
      userAgent: string;
      ipAddress: string;
      deviceId?: string;
    };
    createdAt: string;
    lastAccessedAt: string;
    current: boolean;
  }>;
}

// Password policy types
export interface PasswordPolicy {
  minLength: number;
  maxLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  preventReuse: number; // Number of previous passwords to prevent reuse
  maxAge: number; // Days before password expires
  lockoutThreshold: number; // Failed attempts before lockout
  lockoutDuration: number; // Minutes of lockout
}

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  strength: 'weak' | 'fair' | 'good' | 'strong';
  score: number; // 0-100
}

// Enhanced Multi-tenant types
export interface TenantContext {
  id: string;
  name: string;
  domain: string;
  settings: {
    branding?: {
      logo?: string;
      primaryColor?: string;
      secondaryColor?: string;
      theme?: 'light' | 'dark' | 'auto';
    };
    features?: {
      mobileCredentials?: boolean;
      videoAnalytics?: boolean;
      visitorManagement?: boolean;
      environmentalMonitoring?: boolean;
      offlineMode?: boolean;
    };
    limits?: {
      doors: number;
      cameras: number;
      storage_gb: number;
      users: number;
      sites: number;
    };
    security?: {
      passwordPolicy: PasswordPolicy;
      sessionTimeout: number; // minutes
      mfaRequired: boolean;
      ipWhitelist?: string[];
    };
  };
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface OrganizationHierarchy {
  tenant: TenantContext;
  organizations: Array<{
    id: string;
    name: string;
    description?: string;
    active: boolean;
    sites: Array<{
      id: string;
      name: string;
      timezone: string;
      buildings: Array<{
        id: string;
        name: string;
        floors: number;
      }>;
    }>;
  }>;
}

export interface PermissionStructure {
  role: string;
  permissions: {
    // System permissions
    system?: {
      admin?: boolean;
      config?: boolean;
      users?: boolean;
      audit?: boolean;
    };
    // Access control permissions
    access?: {
      doors?: string[]; // door IDs or 'all'
      schedules?: string[]; // schedule IDs or 'all'
      credentials?: string[]; // credential types or 'all'
      groups?: string[]; // group IDs or 'all'
    };
    // Video permissions
    video?: {
      cameras?: string[]; // camera IDs or 'all'
      live?: boolean;
      playback?: boolean;
      export?: boolean;
      privacy?: boolean;
    };
    // Visitor management permissions
    visitors?: {
      create?: boolean;
      manage?: boolean;
      checkin?: boolean;
      reports?: boolean;
    };
    // Maintenance permissions
    maintenance?: {
      view?: boolean;
      create?: boolean;
      assign?: boolean;
      complete?: boolean;
    };
    // Analytics permissions
    analytics?: {
      view?: boolean;
      export?: boolean;
      configure?: boolean;
    };
    // Environmental monitoring permissions
    environmental?: {
      view?: boolean;
      configure?: boolean;
      alerts?: boolean;
    };
  };
  restrictions?: {
    sites?: string[]; // site IDs
    buildings?: string[]; // building IDs
    floors?: string[]; // floor IDs
    timeRestrictions?: {
      allowedHours?: {
        start: string; // HH:mm
        end: string; // HH:mm
      };
      allowedDays?: number[]; // 0-6 (Sunday-Saturday)
    };
  };
}

// Enhanced Real-time event types
export interface RealtimeEvent {
  id: string;
  type: string;
  tenantId: string;
  userId?: string;
  data: any;
  timestamp: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  acknowledged?: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
}

export interface AuthenticationEventRealtime extends RealtimeEvent {
  type: 'authentication_event';
  data: {
    eventType: 'login_success' | 'login_failed' | 'logout' | 'password_changed' | 'account_locked' | 'session_expired';
    userId?: string;
    email: string;
    ipAddress: string;
    userAgent: string;
    tenantId: string;
    details?: Record<string, any>;
  };
}

export interface SessionEventRealtime extends RealtimeEvent {
  type: 'session_event';
  data: {
    eventType: 'session_created' | 'session_expired' | 'session_revoked' | 'concurrent_session_limit';
    sessionId: string;
    userId: string;
    deviceInfo: {
      userAgent: string;
      ipAddress: string;
      deviceId?: string;
    };
    details?: Record<string, any>;
  };
}

export interface SecurityAlertRealtime extends RealtimeEvent {
  type: 'security_alert';
  data: {
    alertType: 'brute_force_attempt' | 'suspicious_login' | 'privilege_escalation' | 'unauthorized_access' | 'data_breach';
    severity: 'low' | 'medium' | 'high' | 'critical';
    sourceIp: string;
    targetUserId?: string;
    targetResource?: string;
    description: string;
    details: Record<string, any>;
  };
}

export interface AccessEventRealtime extends RealtimeEvent {
  type: 'access_event';
  data: AccessEvent;
}

export interface AlertRealtime extends RealtimeEvent {
  type: 'alert';
  data: Alert;
}

export interface DeviceStatusRealtime extends RealtimeEvent {
  type: 'device_status';
  data: {
    device_id: string;
    device_type: string;
    status: string;
    timestamp: string;
    details?: Record<string, any>;
  };
}

export interface SystemEventRealtime extends RealtimeEvent {
  type: 'system_event';
  data: {
    eventType: 'service_started' | 'service_stopped' | 'backup_completed' | 'maintenance_scheduled' | 'update_available';
    service?: string;
    details: Record<string, any>;
  };
}

// Re-export alert types
export * from './alerts';

// Dashboard types
export interface DashboardWidget {
  id: string;
  type: string;
  title: string;
  position: { x: number; y: number; w: number; h: number };
  config: Record<string, any>;
}

export interface DashboardLayout {
  id: string;
  user_id: string;
  tenant_id: string;
  name: string;
  widgets: DashboardWidget[];
  is_default: boolean;
}

// Video streaming types
export interface VideoStream {
  camera_id: string;
  stream_url: string;
  resolution: 'high' | 'medium' | 'low';
  status: 'active' | 'inactive' | 'error';
}

export interface VideoPlaybackRequest {
  camera_id: string;
  start_time: string;
  end_time: string;
  resolution?: 'high' | 'medium' | 'low';
}

// Configuration types for services
export interface DatabaseConfig {
  url: string;
  host: string;
  port: number;
  database: string;
  username: string;
  password: string;
  ssl: boolean;
  poolSize: number;
  connectionTimeout: number;
  queryTimeout: number;
  retryAttempts: number;
  retryDelay: number;
}

export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  database: number;
  keyPrefix: string;
  connectTimeout: number;
  commandTimeout: number;
  retryAttempts: number;
  retryDelay: number;
  cluster?: {
    enabled: boolean;
    nodes: Array<{ host: string; port: number }>;
  };
}

export interface JwtConfig {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  accessTokenExpiry: string; // e.g., '15m'
  refreshTokenExpiry: string; // e.g., '7d'
  issuer: string;
  audience: string;
  algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';
}

export interface AuthServiceConfig {
  port: number;
  host: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  cors: {
    allowedOrigins: string[];
    allowedMethods: string[];
    allowedHeaders: string[];
    credentials: boolean;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
    skipSuccessfulRequests: boolean;
    skipFailedRequests: boolean;
  };
  security: {
    bcryptRounds: number;
    sessionTimeout: number; // minutes
    maxConcurrentSessions: number;
    bruteForce: {
      freeRetries: number;
      minWait: number; // milliseconds
      maxWait: number; // milliseconds
      lifetime: number; // seconds
    };
  };
  database: DatabaseConfig;
  redis: RedisConfig;
  jwt: JwtConfig;
}

export interface ServiceConfig {
  name: string;
  version: string;
  environment: 'development' | 'staging' | 'production' | 'test';
  port: number;
  host: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  database: DatabaseConfig;
  redis?: RedisConfig;
  monitoring: {
    enabled: boolean;
    metricsPort?: number;
    healthCheckInterval: number;
  };
  circuitBreaker: {
    threshold: number;
    timeout: number;
    monitoringPeriod: number;
  };
}

export interface AwsConfig {
  region: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  s3: {
    bucket: string;
    region: string;
    endpoint?: string;
  };
  cloudfront?: {
    distributionId: string;
    domain: string;
  };
  sns?: {
    topicArn: string;
  };
  ses?: {
    region: string;
    fromEmail: string;
  };
}

// Audit and compliance types
export interface AuditContext {
  userId?: string;
  tenantId: string;
  sessionId?: string;
  ipAddress: string;
  userAgent: string;
  requestId: string;
  timestamp: string;
}

export interface ComplianceEvent {
  id: string;
  tenantId: string;
  eventType: string;
  category: 'access' | 'data' | 'system' | 'security';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  details: Record<string, any>;
  userId?: string;
  resourceId?: string;
  resourceType?: string;
  ipAddress: string;
  userAgent: string;
  timestamp: string;
  complianceFrameworks: string[]; // e.g., ['SOX', 'HIPAA', 'GDPR']
  retentionPeriod: number; // days
}

// Notification types
export interface NotificationTemplate {
  id: string;
  name: string;
  type: 'email' | 'sms' | 'push' | 'webhook';
  subject?: string;
  body: string;
  variables: string[];
  active: boolean;
}

export interface NotificationRequest {
  templateId: string;
  recipients: Array<{
    type: 'user' | 'email' | 'phone';
    value: string;
  }>;
  variables: Record<string, any>;
  priority: 'low' | 'medium' | 'high' | 'urgent';
  scheduledAt?: string;
  tenantId: string;
}

// Webhook types
export interface WebhookEvent {
  id: string;
  tenantId: string;
  eventType: string;
  data: any;
  timestamp: string;
  signature: string;
  version: string;
}

export interface WebhookEndpoint {
  id: string;
  tenantId: string;
  url: string;
  events: string[];
  secret: string;
  active: boolean;
  retryPolicy: {
    maxRetries: number;
    backoffMultiplier: number;
    maxBackoffSeconds: number;
  };
  headers?: Record<string, string>;
}

// Export all schemas for validation including new authentication schemas
export const schemas = {
  TenantSchema,
  OrganizationSchema,
  SiteSchema,
  BuildingSchema,
  FloorSchema,
  ZoneSchema,
  DoorSchema,
  UserSchema,
  CameraSchema,
  AccessEventSchema,
  AccessPanelSchema,
  CardReaderSchema,
  CredentialSchema,
  AccessGroupSchema,
  ScheduleSchema,
  AlertSchema,
  AuditLogSchema,
  VideoRecordingSchema,
  VisitorSchema,
  MaintenanceWorkOrderSchema,
  IncidentReportSchema,
  EnvironmentalSensorSchema,
  EnvironmentalReadingSchema,
  MobileCredentialSchema,
  PrivacyMaskSchema,
  VideoExportLogSchema,
  ElevatorControlSchema,
  SystemConfigurationSchema,
  OfflineEventQueueSchema,
  PolicyTemplateSchema,
  OfflineOperationLogSchema,
  CertificateSchema,
  BackupJobSchema,
  IntegrationConfigurationSchema,
};

// Validation schemas for authentication endpoints
export const LoginRequestSchema = z.object({
  email: EmailSchema,
  password: z.string().min(1),
  tenantId: UuidSchema,
  rememberMe: z.boolean().optional(),
  deviceInfo: z.object({
    userAgent: z.string(),
    ipAddress: IpAddressSchema,
    deviceId: z.string().optional(),
  }).optional(),
});

export const SignupRequestSchema = z.object({
  email: EmailSchema,
  password: z.string().min(8).max(128),
  firstName: z.string().min(1).max(255),
  lastName: z.string().min(1).max(255),
  tenantId: UuidSchema,
  role: z.string().optional(),
  invitationToken: z.string().optional(),
});

export const RefreshTokenRequestSchema = z.object({
  refreshToken: z.string().min(1),
});

export const ChangePasswordRequestSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8).max(128),
  confirmPassword: z.string().optional(),
});

export const ResetPasswordRequestSchema = z.object({
  email: EmailSchema,
  tenantId: UuidSchema,
});

export const ResetPasswordConfirmRequestSchema = z.object({
  token: z.string().min(1),
  newPassword: z.string().min(8).max(128),
  confirmPassword: z.string().min(8).max(128),
});

export const UpdateProfileRequestSchema = z.object({
  firstName: z.string().min(1).max(255).optional(),
  lastName: z.string().min(1).max(255).optional(),
  email: EmailSchema.optional(),
  username: z.string().min(1).max(255).optional(),
});

// Add authentication schemas to the main schemas export
export const authSchemas = {
  LoginRequestSchema,
  SignupRequestSchema,
  RefreshTokenRequestSchema,
  ChangePasswordRequestSchema,
  ResetPasswordRequestSchema,
  ResetPasswordConfirmRequestSchema,
  UpdateProfileRequestSchema,
};
