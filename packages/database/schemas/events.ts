import { pgTable, uuid, varchar, timestamp, jsonb, text, pgEnum, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { tenants } from './user-management';
import { alerts } from './alerts';

// Event type enum
export const eventTypeEnum = pgEnum('event_type', ['access', 'video', 'environmental', 'system', 'security']);

// Event sub-type enum
export const eventSubTypeEnum = pgEnum('event_sub_type', [
  // Access events
  'access_granted',
  'access_denied',
  'door_forced',
  'door_held_open',
  'door_propped',
  // Video events
  'motion_detected',
  'camera_offline',
  'camera_tampered',
  'line_crossing',
  'loitering_detected',
  // Environmental events
  'temperature_high',
  'temperature_low',
  'humidity_high',
  'humidity_low',
  'water_detected',
  'sensor_offline',
  // System events
  'system_startup',
  'system_shutdown',
  'service_error',
  'database_error',
  // Security events
  'intrusion_detected',
  'unauthorized_access',
  'security_breach',
  'alarm_triggered'
]);

// Events table
export const events = pgTable('events', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id),
  eventType: eventTypeEnum('event_type').notNull(),
  eventSubType: eventSubTypeEnum('event_sub_type').notNull(),
  sourceId: varchar('source_id', { length: 255 }).notNull(),
  sourceType: varchar('source_type', { length: 50 }).notNull(),
  timestamp: timestamp('timestamp').notNull().defaultNow(),
  location: jsonb('location').default({}), // { buildingId, floorId, zoneId }
  metadata: jsonb('metadata').default({}),
  value: varchar('value', { length: 255 }), // For environmental readings
  threshold: varchar('threshold', { length: 255 }), // For threshold events
  confidence: varchar('confidence', { length: 10 }), // For ML-based detections
  userId: uuid('user_id'), // For access events
  description: text('description'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => {
  return {
    tenantIdx: index('events_tenant_idx').on(table.tenantId),
    typeIdx: index('events_type_idx').on(table.eventType),
    subTypeIdx: index('events_sub_type_idx').on(table.eventSubType),
    timestampIdx: index('events_timestamp_idx').on(table.timestamp),
    sourceIdx: index('events_source_idx').on(table.sourceId, table.sourceType),
    locationIdx: index('events_location_idx').using('gin', table.location),
    tenantTypeTimestampIdx: index('events_tenant_type_timestamp_idx').on(table.tenantId, table.eventType, table.timestamp),
  };
});

// Event correlations table - tracks which events led to alerts
export const eventCorrelations = pgTable('event_correlations', {
  id: uuid('id').defaultRandom().primaryKey(),
  alertId: uuid('alert_id').notNull().references(() => alerts.id, { onDelete: 'cascade' }),
  eventId: uuid('event_id').notNull().references(() => events.id, { onDelete: 'cascade' }),
  correlationRuleId: varchar('correlation_rule_id', { length: 100 }).notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => {
  return {
    alertIdx: index('correlations_alert_idx').on(table.alertId),
    eventIdx: index('correlations_event_idx').on(table.eventId),
    ruleIdx: index('correlations_rule_idx').on(table.correlationRuleId),
  };
});

// Event processing rules table
export const eventProcessingRules = pgTable('event_processing_rules', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  ruleType: varchar('rule_type', { length: 50 }).notNull(), // correlation, threshold, pattern
  eventTypes: jsonb('event_types').notNull().default([]), // Array of event types
  conditions: jsonb('conditions').notNull().default({}), // Rule conditions
  actions: jsonb('actions').notNull().default({}), // Actions to take
  timeWindow: varchar('time_window', { length: 20 }), // e.g., "5m", "1h"
  enabled: varchar('enabled', { length: 10 }).notNull().default('true'),
  priority: varchar('priority', { length: 20 }).notNull().default('medium'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => {
  return {
    tenantIdx: index('rules_tenant_idx').on(table.tenantId),
    enabledIdx: index('rules_enabled_idx').on(table.enabled),
    typeIdx: index('rules_type_idx').on(table.ruleType),
  };
});

// Relations
export const eventsRelations = relations(events, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [events.tenantId],
    references: [tenants.id],
  }),
  correlations: many(eventCorrelations),
}));

export const eventCorrelationsRelations = relations(eventCorrelations, ({ one }) => ({
  alert: one(alerts, {
    fields: [eventCorrelations.alertId],
    references: [alerts.id],
  }),
  event: one(events, {
    fields: [eventCorrelations.eventId],
    references: [events.id],
  }),
}));

export const eventProcessingRulesRelations = relations(eventProcessingRules, ({ one }) => ({
  tenant: one(tenants, {
    fields: [eventProcessingRules.tenantId],
    references: [tenants.id],
  }),
}));