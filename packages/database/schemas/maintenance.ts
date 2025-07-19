import { pgTable, uuid, text, timestamp, jsonb, integer, decimal, pgEnum, index, unique } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { tenants } from './tenant';
import { users } from './user-management';

// Enums
export const workOrderTypeEnum = pgEnum('work_order_type', ['preventive', 'corrective', 'emergency', 'upgrade']);
export const workOrderPriorityEnum = pgEnum('work_order_priority', ['low', 'medium', 'high', 'critical']);
export const workOrderStatusEnum = pgEnum('work_order_status', ['open', 'assigned', 'in_progress', 'completed', 'cancelled', 'on_hold']);
export const maintenanceIntervalEnum = pgEnum('maintenance_interval', ['daily', 'weekly', 'monthly', 'quarterly', 'annually']);
export const diagnosticResultEnum = pgEnum('diagnostic_result', ['pass', 'fail', 'warning']);

// Work Orders table
export const workOrders = pgTable('work_orders', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  deviceId: uuid('device_id').notNull(),
  deviceType: text('device_type').notNull(),
  workOrderType: workOrderTypeEnum('work_order_type').notNull(),
  priority: workOrderPriorityEnum('priority').notNull(),
  title: text('title').notNull(),
  description: text('description').notNull(),
  assignedTo: uuid('assigned_to').references(() => users.id),
  scheduledDate: timestamp('scheduled_date'),
  completedDate: timestamp('completed_date'),
  diagnosticData: jsonb('diagnostic_data').default({}),
  partsUsed: jsonb('parts_used').default([]),
  laborHours: decimal('labor_hours', { precision: 10, scale: 2 }),
  estimatedCost: decimal('estimated_cost', { precision: 10, scale: 2 }),
  actualCost: decimal('actual_cost', { precision: 10, scale: 2 }),
  status: workOrderStatusEnum('status').notNull().default('open'),
  completionNotes: text('completion_notes'),
  slaDeadline: timestamp('sla_deadline'),
  slaMet: integer('sla_met').default(sql`NULL`), // null = pending, 1 = met, 0 = missed
  createdBy: uuid('created_by').references(() => users.id),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('work_orders_tenant_id_idx').on(table.tenantId),
    deviceIdIdx: index('work_orders_device_id_idx').on(table.deviceId),
    assignedToIdx: index('work_orders_assigned_to_idx').on(table.assignedTo),
    statusIdx: index('work_orders_status_idx').on(table.status),
    priorityIdx: index('work_orders_priority_idx').on(table.priority),
    scheduledDateIdx: index('work_orders_scheduled_date_idx').on(table.scheduledDate),
    slaDeadlineIdx: index('work_orders_sla_deadline_idx').on(table.slaDeadline)
  };
});

// Preventive Maintenance Schedules table
export const preventiveMaintenanceSchedules = pgTable('preventive_maintenance_schedules', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  deviceType: text('device_type').notNull(),
  deviceIds: jsonb('device_ids').default([]), // Specific devices, empty means all of type
  interval: maintenanceIntervalEnum('interval').notNull(),
  intervalValue: integer('interval_value').notNull().default(1),
  workOrderTemplate: jsonb('work_order_template').notNull(),
  active: integer('active').notNull().default(1),
  lastGenerated: timestamp('last_generated'),
  nextGeneration: timestamp('next_generation').notNull(),
  createdBy: uuid('created_by').references(() => users.id),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('pm_schedules_tenant_id_idx').on(table.tenantId),
    activeIdx: index('pm_schedules_active_idx').on(table.active),
    nextGenerationIdx: index('pm_schedules_next_generation_idx').on(table.nextGeneration),
    deviceTypeIdx: index('pm_schedules_device_type_idx').on(table.deviceType)
  };
});

// Parts Inventory table
export const partsInventory = pgTable('parts_inventory', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  partNumber: text('part_number').notNull(),
  name: text('name').notNull(),
  description: text('description'),
  category: text('category').notNull(),
  manufacturer: text('manufacturer'),
  model: text('model'),
  quantity: integer('quantity').notNull().default(0),
  minQuantity: integer('min_quantity').notNull().default(0),
  maxQuantity: integer('max_quantity'),
  unitCost: decimal('unit_cost', { precision: 10, scale: 2 }),
  supplier: text('supplier'),
  supplierPartNumber: text('supplier_part_number'),
  location: text('location'),
  barcode: text('barcode'),
  lastOrderDate: timestamp('last_order_date'),
  lastOrderQuantity: integer('last_order_quantity'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantPartNumberUnique: unique().on(table.tenantId, table.partNumber),
    tenantIdIdx: index('parts_inventory_tenant_id_idx').on(table.tenantId),
    partNumberIdx: index('parts_inventory_part_number_idx').on(table.partNumber),
    categoryIdx: index('parts_inventory_category_idx').on(table.category),
    quantityIdx: index('parts_inventory_quantity_idx').on(table.quantity)
  };
});

// Parts Usage History table
export const partsUsageHistory = pgTable('parts_usage_history', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  partId: uuid('part_id').notNull().references(() => partsInventory.id),
  workOrderId: uuid('work_order_id').references(() => workOrders.id),
  quantity: integer('quantity').notNull(),
  unitCost: decimal('unit_cost', { precision: 10, scale: 2 }),
  totalCost: decimal('total_cost', { precision: 10, scale: 2 }),
  usedBy: uuid('used_by').references(() => users.id),
  notes: text('notes'),
  usedAt: timestamp('used_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('parts_usage_tenant_id_idx').on(table.tenantId),
    partIdIdx: index('parts_usage_part_id_idx').on(table.partId),
    workOrderIdIdx: index('parts_usage_work_order_id_idx').on(table.workOrderId),
    usedAtIdx: index('parts_usage_used_at_idx').on(table.usedAt)
  };
});

// Maintenance History table (for tracking all maintenance activities)
export const maintenanceHistory = pgTable('maintenance_history', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  deviceId: uuid('device_id').notNull(),
  workOrderId: uuid('work_order_id').references(() => workOrders.id),
  activityType: text('activity_type').notNull(), // 'maintenance', 'inspection', 'repair', 'upgrade', 'diagnostic'
  description: text('description').notNull(),
  performedBy: uuid('performed_by').references(() => users.id),
  duration: integer('duration'), // in minutes
  outcome: text('outcome'),
  recommendations: jsonb('recommendations').default([]),
  nextActionDate: timestamp('next_action_date'),
  createdAt: timestamp('created_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('maintenance_history_tenant_id_idx').on(table.tenantId),
    deviceIdIdx: index('maintenance_history_device_id_idx').on(table.deviceId),
    workOrderIdIdx: index('maintenance_history_work_order_id_idx').on(table.workOrderId),
    createdAtIdx: index('maintenance_history_created_at_idx').on(table.createdAt)
  };
});

// Device Diagnostics table
export const deviceDiagnostics = pgTable('device_diagnostics', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  deviceId: uuid('device_id').notNull(),
  diagnosticType: text('diagnostic_type').notNull(),
  results: jsonb('results').notNull(),
  overallStatus: diagnosticResultEnum('overall_status').notNull(),
  recommendations: jsonb('recommendations').default([]),
  performedBy: uuid('performed_by').references(() => users.id),
  automated: integer('automated').notNull().default(0),
  createdAt: timestamp('created_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('device_diagnostics_tenant_id_idx').on(table.tenantId),
    deviceIdIdx: index('device_diagnostics_device_id_idx').on(table.deviceId),
    createdAtIdx: index('device_diagnostics_created_at_idx').on(table.createdAt),
    overallStatusIdx: index('device_diagnostics_overall_status_idx').on(table.overallStatus)
  };
});

// Maintenance Costs table
export const maintenanceCosts = pgTable('maintenance_costs', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  workOrderId: uuid('work_order_id').references(() => workOrders.id),
  costCategory: text('cost_category').notNull(), // 'labor', 'parts', 'contractor', 'other'
  description: text('description').notNull(),
  amount: decimal('amount', { precision: 10, scale: 2 }).notNull(),
  taxAmount: decimal('tax_amount', { precision: 10, scale: 2 }).default('0'),
  invoiceNumber: text('invoice_number'),
  vendor: text('vendor'),
  approvedBy: uuid('approved_by').references(() => users.id),
  budgetCategory: text('budget_category'),
  costCenter: text('cost_center'),
  incurredAt: timestamp('incurred_at').defaultNow().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('maintenance_costs_tenant_id_idx').on(table.tenantId),
    workOrderIdIdx: index('maintenance_costs_work_order_id_idx').on(table.workOrderId),
    costCategoryIdx: index('maintenance_costs_category_idx').on(table.costCategory),
    incurredAtIdx: index('maintenance_costs_incurred_at_idx').on(table.incurredAt)
  };
});

// Maintenance SLA Configuration table
export const maintenanceSlaConfig = pgTable('maintenance_sla_config', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  deviceType: text('device_type'),
  workOrderType: workOrderTypeEnum('work_order_type'),
  priority: workOrderPriorityEnum('priority'),
  responseTime: integer('response_time').notNull(), // in minutes
  resolutionTime: integer('resolution_time').notNull(), // in minutes
  escalationLevels: jsonb('escalation_levels').default([]),
  active: integer('active').notNull().default(1),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('maintenance_sla_tenant_id_idx').on(table.tenantId),
    activeIdx: index('maintenance_sla_active_idx').on(table.active)
  };
});

// IoT Device Metrics table (for predictive maintenance)
export const iotDeviceMetrics = pgTable('iot_device_metrics', {
  id: uuid('id').defaultRandom().primaryKey(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  deviceId: uuid('device_id').notNull(),
  metricType: text('metric_type').notNull(), // 'temperature', 'vibration', 'power', 'runtime', etc.
  value: decimal('value', { precision: 20, scale: 6 }).notNull(),
  unit: text('unit').notNull(),
  threshold: decimal('threshold', { precision: 20, scale: 6 }),
  anomalyDetected: integer('anomaly_detected').default(0),
  metadata: jsonb('metadata').default({}),
  recordedAt: timestamp('recorded_at').defaultNow().notNull()
}, (table) => {
  return {
    tenantIdIdx: index('iot_metrics_tenant_id_idx').on(table.tenantId),
    deviceIdIdx: index('iot_metrics_device_id_idx').on(table.deviceId),
    metricTypeIdx: index('iot_metrics_type_idx').on(table.metricType),
    recordedAtIdx: index('iot_metrics_recorded_at_idx').on(table.recordedAt),
    anomalyIdx: index('iot_metrics_anomaly_idx').on(table.anomalyDetected)
  };
});

// Export types
export type WorkOrder = typeof workOrders.$inferSelect;
export type NewWorkOrder = typeof workOrders.$inferInsert;
export type PreventiveMaintenanceSchedule = typeof preventiveMaintenanceSchedules.$inferSelect;
export type NewPreventiveMaintenanceSchedule = typeof preventiveMaintenanceSchedules.$inferInsert;
export type PartInventory = typeof partsInventory.$inferSelect;
export type NewPartInventory = typeof partsInventory.$inferInsert;
export type PartUsageHistory = typeof partsUsageHistory.$inferSelect;
export type NewPartUsageHistory = typeof partsUsageHistory.$inferInsert;
export type MaintenanceHistory = typeof maintenanceHistory.$inferSelect;
export type NewMaintenanceHistory = typeof maintenanceHistory.$inferInsert;
export type DeviceDiagnostic = typeof deviceDiagnostics.$inferSelect;
export type NewDeviceDiagnostic = typeof deviceDiagnostics.$inferInsert;
export type MaintenanceCost = typeof maintenanceCosts.$inferSelect;
export type NewMaintenanceCost = typeof maintenanceCosts.$inferInsert;
export type MaintenanceSlaConfig = typeof maintenanceSlaConfig.$inferSelect;
export type NewMaintenanceSlaConfig = typeof maintenanceSlaConfig.$inferInsert;
export type IotDeviceMetric = typeof iotDeviceMetrics.$inferSelect;
export type NewIotDeviceMetric = typeof iotDeviceMetrics.$inferInsert;