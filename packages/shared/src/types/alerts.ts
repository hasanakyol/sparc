import { z } from 'zod';

// Alert priority enum
export const AlertPriority = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
} as const;

export type AlertPriority = typeof AlertPriority[keyof typeof AlertPriority];

// Alert status enum
export const AlertStatus = {
  OPEN: 'open',
  ACKNOWLEDGED: 'acknowledged',
  RESOLVED: 'resolved',
  CLOSED: 'closed'
} as const;

export type AlertStatus = typeof AlertStatus[keyof typeof AlertStatus];

// Alert type enum
export const AlertType = {
  ACCESS_DENIED: 'access_denied',
  DOOR_FORCED: 'door_forced',
  DOOR_HELD_OPEN: 'door_held_open',
  SYSTEM_OFFLINE: 'system_offline',
  CAMERA_OFFLINE: 'camera_offline',
  MOTION_DETECTED: 'motion_detected',
  TEMPERATURE_THRESHOLD: 'temperature_threshold',
  HUMIDITY_THRESHOLD: 'humidity_threshold',
  LEAK_DETECTED: 'leak_detected',
  EMERGENCY_LOCKDOWN: 'emergency_lockdown',
  SECURITY_BREACH: 'security_breach',
  MAINTENANCE_REQUIRED: 'maintenance_required'
} as const;

export type AlertType = typeof AlertType[keyof typeof AlertType];

// Source type enum
export const SourceType = {
  ACCESS_CONTROL: 'access_control',
  VIDEO: 'video',
  ENVIRONMENTAL: 'environmental',
  SYSTEM: 'system',
  SECURITY: 'security'
} as const;

export type SourceType = typeof SourceType[keyof typeof SourceType];

// Notification type enum
export const NotificationType = {
  EMAIL: 'email',
  SMS: 'sms',
  PUSH: 'push',
  WEBHOOK: 'webhook'
} as const;

export type NotificationType = typeof NotificationType[keyof typeof NotificationType];

// Validation schemas
export const createAlertSchema = z.object({
  alertType: z.nativeEnum(AlertType),
  priority: z.nativeEnum(AlertPriority),
  sourceId: z.string().min(1),
  sourceType: z.nativeEnum(SourceType),
  message: z.string().min(1),
  details: z.record(z.any()).optional().default({})
});

export const updateAlertSchema = z.object({
  status: z.nativeEnum(AlertStatus).optional(),
  acknowledgedBy: z.string().uuid().optional(),
  message: z.string().optional(),
  details: z.record(z.any()).optional()
});

export const acknowledgeAlertSchema = z.object({
  acknowledgedBy: z.string().uuid()
});

export const webhookEventSchema = z.object({
  eventType: z.string(),
  sourceId: z.string(),
  sourceType: z.string(),
  data: z.record(z.any()),
  timestamp: z.string().datetime(),
  priority: z.nativeEnum(AlertPriority).optional().default(AlertPriority.MEDIUM)
});

export const environmentalWebhookSchema = z.object({
  sensorId: z.string(),
  tenantId: z.string().uuid(),
  readings: z.record(z.any()),
  thresholds: z.record(z.any())
});

export const notificationPreferencesSchema = z.object({
  email: z.boolean().optional(),
  sms: z.boolean().optional(),
  push: z.boolean().optional(),
  criticalOnly: z.boolean().optional()
});

// DTOs
export type CreateAlertDTO = z.infer<typeof createAlertSchema>;
export type UpdateAlertDTO = z.infer<typeof updateAlertSchema>;
export type AcknowledgeAlertDTO = z.infer<typeof acknowledgeAlertSchema>;
export type WebhookEventDTO = z.infer<typeof webhookEventSchema>;
export type EnvironmentalWebhookDTO = z.infer<typeof environmentalWebhookSchema>;
export type NotificationPreferencesDTO = z.infer<typeof notificationPreferencesSchema>;

// Response types
export interface Alert {
  id: string;
  tenantId: string;
  alertType: AlertType;
  priority: AlertPriority;
  sourceId: string;
  sourceType: SourceType;
  message: string;
  details: Record<string, any>;
  status: AlertStatus;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  resolvedAt?: Date;
  closedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface AlertEscalation {
  id: string;
  alertId: string;
  escalationLevel: string;
  escalatedTo?: string;
  escalatedAt: Date;
  notes?: string;
}

export interface AlertNotification {
  id: string;
  alertId: string;
  notificationType: NotificationType;
  recipientId?: string;
  recipientAddress?: string;
  sentAt: Date;
  deliveredAt?: Date;
  failedAt?: Date;
  failureReason?: string;
  retryCount: number;
}

export interface NotificationPreferences {
  id: string;
  tenantId: string;
  userId?: string;
  email: {
    enabled: boolean;
    addresses: string[];
  };
  sms: {
    enabled: boolean;
    numbers: string[];
  };
  push: {
    enabled: boolean;
    subscriptions: any[];
  };
  webhook: {
    enabled: boolean;
    urls: string[];
  };
  criticalOnly: boolean;
  preferences: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

// Alert statistics response
export interface AlertStatistics {
  timeframe: string;
  summary: {
    total: number;
    open: number;
    acknowledged: number;
    resolved: number;
    critical: number;
  };
  byType: Record<string, number>;
  byPriority: Record<string, number>;
}

// List response with pagination
export interface AlertListResponse {
  alerts: Alert[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
}

// Alert configuration
export const PRIORITY_CONFIG = {
  [AlertPriority.LOW]: { timeout: 60, escalationLevel: 1 },
  [AlertPriority.MEDIUM]: { timeout: 30, escalationLevel: 2 },
  [AlertPriority.HIGH]: { timeout: 15, escalationLevel: 3 },
  [AlertPriority.CRITICAL]: { timeout: 5, escalationLevel: 4 }
} as const;

export const ALERT_TYPE_CONFIG = {
  [AlertType.ACCESS_DENIED]: { priority: AlertPriority.MEDIUM, autoResolve: false },
  [AlertType.DOOR_FORCED]: { priority: AlertPriority.HIGH, autoResolve: false },
  [AlertType.DOOR_HELD_OPEN]: { priority: AlertPriority.MEDIUM, autoResolve: true },
  [AlertType.SYSTEM_OFFLINE]: { priority: AlertPriority.CRITICAL, autoResolve: false },
  [AlertType.CAMERA_OFFLINE]: { priority: AlertPriority.HIGH, autoResolve: false },
  [AlertType.MOTION_DETECTED]: { priority: AlertPriority.LOW, autoResolve: true },
  [AlertType.TEMPERATURE_THRESHOLD]: { priority: AlertPriority.MEDIUM, autoResolve: true },
  [AlertType.HUMIDITY_THRESHOLD]: { priority: AlertPriority.MEDIUM, autoResolve: true },
  [AlertType.LEAK_DETECTED]: { priority: AlertPriority.CRITICAL, autoResolve: false },
  [AlertType.EMERGENCY_LOCKDOWN]: { priority: AlertPriority.CRITICAL, autoResolve: false },
  [AlertType.SECURITY_BREACH]: { priority: AlertPriority.CRITICAL, autoResolve: false },
  [AlertType.MAINTENANCE_REQUIRED]: { priority: AlertPriority.LOW, autoResolve: false }
} as const;