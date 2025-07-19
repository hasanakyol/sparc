import { pgTable, uuid, varchar, timestamp, jsonb, text, pgEnum, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { tenants, users } from './user-management';

// Enums
export const alertPriorityEnum = pgEnum('alert_priority', ['low', 'medium', 'high', 'critical']);
export const alertStatusEnum = pgEnum('alert_status', ['open', 'acknowledged', 'resolved', 'closed']);
export const alertTypeEnum = pgEnum('alert_type', [
  'access_denied', 
  'door_forced', 
  'door_held_open',
  'system_offline',
  'camera_offline',
  'motion_detected',
  'temperature_threshold',
  'humidity_threshold',
  'leak_detected',
  'emergency_lockdown',
  'security_breach',
  'maintenance_required'
]);
export const sourceTypeEnum = pgEnum('source_type', ['access_control', 'video', 'environmental', 'system', 'security']);

// Main alerts table
export const alerts = pgTable('alerts', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id),
  alertType: alertTypeEnum('alert_type').notNull(),
  priority: alertPriorityEnum('priority').notNull(),
  sourceId: varchar('source_id', { length: 255 }).notNull(),
  sourceType: sourceTypeEnum('source_type').notNull(),
  message: text('message').notNull(),
  details: jsonb('details').default({}),
  status: alertStatusEnum('status').notNull().default('open'),
  acknowledgedBy: uuid('acknowledged_by').references(() => users.id),
  acknowledgedAt: timestamp('acknowledged_at'),
  resolvedAt: timestamp('resolved_at'),
  closedAt: timestamp('closed_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => {
  return {
    tenantIdx: index('alerts_tenant_idx').on(table.tenantId),
    statusIdx: index('alerts_status_idx').on(table.status),
    priorityIdx: index('alerts_priority_idx').on(table.priority),
    createdAtIdx: index('alerts_created_at_idx').on(table.createdAt),
    sourceIdx: index('alerts_source_idx').on(table.sourceId, table.sourceType),
    alertTypeIdx: index('alerts_type_idx').on(table.alertType),
  };
});

// Alert escalations table
export const alertEscalations = pgTable('alert_escalations', {
  id: uuid('id').defaultRandom().primaryKey(),
  alertId: uuid('alert_id').notNull().references(() => alerts.id, { onDelete: 'cascade' }),
  escalationLevel: varchar('escalation_level', { length: 50 }).notNull(),
  escalatedTo: uuid('escalated_to').references(() => users.id),
  escalatedAt: timestamp('escalated_at').notNull().defaultNow(),
  notes: text('notes'),
}, (table) => {
  return {
    alertIdx: index('escalations_alert_idx').on(table.alertId),
    escalatedToIdx: index('escalations_user_idx').on(table.escalatedTo),
  };
});

// Alert notifications table
export const alertNotifications = pgTable('alert_notifications', {
  id: uuid('id').defaultRandom().primaryKey(),
  alertId: uuid('alert_id').notNull().references(() => alerts.id, { onDelete: 'cascade' }),
  notificationType: varchar('notification_type', { length: 50 }).notNull(), // email, sms, push, webhook
  recipientId: uuid('recipient_id').references(() => users.id),
  recipientAddress: varchar('recipient_address', { length: 255 }), // email, phone, webhook url
  sentAt: timestamp('sent_at').notNull().defaultNow(),
  deliveredAt: timestamp('delivered_at'),
  failedAt: timestamp('failed_at'),
  failureReason: text('failure_reason'),
  retryCount: varchar('retry_count', { length: 10 }).notNull().default('0'),
}, (table) => {
  return {
    alertIdx: index('notifications_alert_idx').on(table.alertId),
    recipientIdx: index('notifications_recipient_idx').on(table.recipientId),
    typeIdx: index('notifications_type_idx').on(table.notificationType),
  };
});

// Notification preferences table
export const notificationPreferences = pgTable('notification_preferences', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id),
  userId: uuid('user_id').references(() => users.id),
  email: jsonb('email').default({ enabled: true, addresses: [] }),
  sms: jsonb('sms').default({ enabled: false, numbers: [] }),
  push: jsonb('push').default({ enabled: true, subscriptions: [] }),
  webhook: jsonb('webhook').default({ enabled: false, urls: [] }),
  criticalOnly: varchar('critical_only', { length: 10 }).notNull().default('false'),
  preferences: jsonb('preferences').default({}),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => {
  return {
    tenantIdx: index('preferences_tenant_idx').on(table.tenantId),
    userIdx: index('preferences_user_idx').on(table.userId),
    tenantUserIdx: index('preferences_tenant_user_idx').on(table.tenantId, table.userId),
  };
});

// Relations
export const alertsRelations = relations(alerts, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [alerts.tenantId],
    references: [tenants.id],
  }),
  acknowledgedByUser: one(users, {
    fields: [alerts.acknowledgedBy],
    references: [users.id],
  }),
  escalations: many(alertEscalations),
  notifications: many(alertNotifications),
}));

export const alertEscalationsRelations = relations(alertEscalations, ({ one }) => ({
  alert: one(alerts, {
    fields: [alertEscalations.alertId],
    references: [alerts.id],
  }),
  escalatedToUser: one(users, {
    fields: [alertEscalations.escalatedTo],
    references: [users.id],
  }),
}));

export const alertNotificationsRelations = relations(alertNotifications, ({ one }) => ({
  alert: one(alerts, {
    fields: [alertNotifications.alertId],
    references: [alerts.id],
  }),
  recipient: one(users, {
    fields: [alertNotifications.recipientId],
    references: [users.id],
  }),
}));

export const notificationPreferencesRelations = relations(notificationPreferences, ({ one }) => ({
  tenant: one(tenants, {
    fields: [notificationPreferences.tenantId],
    references: [tenants.id],
  }),
  user: one(users, {
    fields: [notificationPreferences.userId],
    references: [users.id],
  }),
}));