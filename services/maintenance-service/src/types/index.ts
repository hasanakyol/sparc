import { z } from 'zod';

// Work Order schemas
export const createWorkOrderSchema = z.object({
  deviceId: z.string().uuid(),
  deviceType: z.string().min(1),
  workOrderType: z.enum(['preventive', 'corrective', 'emergency', 'upgrade']),
  priority: z.enum(['low', 'medium', 'high', 'critical']),
  title: z.string().min(1).max(200),
  description: z.string().min(1).max(2000),
  assignedTo: z.string().uuid().optional(),
  scheduledDate: z.string().datetime().optional(),
  estimatedCost: z.number().positive().optional(),
  slaDeadline: z.string().datetime().optional()
});

export const updateWorkOrderSchema = z.object({
  status: z.enum(['open', 'assigned', 'in_progress', 'completed', 'cancelled', 'on_hold']).optional(),
  assignedTo: z.string().uuid().optional().nullable(),
  scheduledDate: z.string().datetime().optional().nullable(),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  laborHours: z.number().positive().optional(),
  actualCost: z.number().positive().optional(),
  partsUsed: z.array(z.object({
    partId: z.string().uuid(),
    quantity: z.number().positive(),
    unitCost: z.number().positive()
  })).optional(),
  completionNotes: z.string().optional(),
  diagnosticData: z.record(z.any()).optional()
});

export const workOrderFilterSchema = z.object({
  status: z.enum(['open', 'assigned', 'in_progress', 'completed', 'cancelled', 'on_hold']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  workOrderType: z.enum(['preventive', 'corrective', 'emergency', 'upgrade']).optional(),
  assignedTo: z.string().uuid().optional(),
  deviceId: z.string().uuid().optional(),
  deviceType: z.string().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  slaStatus: z.enum(['pending', 'met', 'missed']).optional(),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
  sortBy: z.enum(['createdAt', 'scheduledDate', 'priority', 'status']).default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).default('desc')
});

// Preventive Maintenance schemas
export const createMaintenanceScheduleSchema = z.object({
  name: z.string().min(1).max(100),
  deviceType: z.string().min(1),
  deviceIds: z.array(z.string().uuid()).optional(),
  interval: z.enum(['daily', 'weekly', 'monthly', 'quarterly', 'annually']),
  intervalValue: z.number().int().positive().default(1),
  workOrderTemplate: z.object({
    title: z.string().min(1).max(200),
    description: z.string().min(1).max(2000),
    estimatedHours: z.number().positive(),
    requiredParts: z.array(z.string()).optional(),
    priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium')
  }),
  active: z.boolean().default(true)
});

export const updateMaintenanceScheduleSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  active: z.boolean().optional(),
  interval: z.enum(['daily', 'weekly', 'monthly', 'quarterly', 'annually']).optional(),
  intervalValue: z.number().int().positive().optional(),
  workOrderTemplate: z.object({
    title: z.string().min(1).max(200),
    description: z.string().min(1).max(2000),
    estimatedHours: z.number().positive(),
    requiredParts: z.array(z.string()).optional(),
    priority: z.enum(['low', 'medium', 'high', 'critical'])
  }).optional()
});

// Parts Inventory schemas
export const createPartSchema = z.object({
  partNumber: z.string().min(1).max(50),
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  category: z.string().min(1),
  manufacturer: z.string().optional(),
  model: z.string().optional(),
  quantity: z.number().int().min(0),
  minQuantity: z.number().int().min(0),
  maxQuantity: z.number().int().min(0).optional(),
  unitCost: z.number().positive().optional(),
  supplier: z.string().optional(),
  supplierPartNumber: z.string().optional(),
  location: z.string().optional(),
  barcode: z.string().optional()
});

export const updatePartSchema = createPartSchema.partial().omit({ partNumber: true });

export const recordPartUsageSchema = z.object({
  partId: z.string().uuid(),
  quantity: z.number().int().positive(),
  workOrderId: z.string().uuid().optional(),
  notes: z.string().optional()
});

// Diagnostics schemas
export const runDiagnosticsSchema = z.object({
  diagnosticType: z.string().min(1),
  automated: z.boolean().default(false)
});

export const diagnosticResultSchema = z.object({
  connectivity: z.enum(['pass', 'fail', 'warning']),
  hardware: z.enum(['pass', 'fail', 'warning']),
  firmware: z.enum(['pass', 'fail', 'warning']),
  configuration: z.enum(['pass', 'fail', 'warning']),
  performance: z.enum(['pass', 'fail', 'warning']).optional(),
  security: z.enum(['pass', 'fail', 'warning']).optional()
});

// SLA Configuration schemas
export const createSlaConfigSchema = z.object({
  name: z.string().min(1).max(100),
  deviceType: z.string().optional(),
  workOrderType: z.enum(['preventive', 'corrective', 'emergency', 'upgrade']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  responseTime: z.number().int().positive(), // minutes
  resolutionTime: z.number().int().positive(), // minutes
  escalationLevels: z.array(z.object({
    level: z.number().int().positive(),
    delayMinutes: z.number().int().positive(),
    notifyRoles: z.array(z.string()),
    notifyUsers: z.array(z.string().uuid()).optional()
  })).optional(),
  active: z.boolean().default(true)
});

// IoT Metrics schemas
export const iotMetricSchema = z.object({
  deviceId: z.string().uuid(),
  metricType: z.string().min(1),
  value: z.number(),
  unit: z.string().min(1),
  threshold: z.number().optional(),
  metadata: z.record(z.any()).optional()
});

export const iotMetricBatchSchema = z.object({
  metrics: z.array(iotMetricSchema).min(1).max(1000)
});

// Analytics schemas
export const analyticsFilterSchema = z.object({
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  deviceType: z.string().optional(),
  workOrderType: z.enum(['preventive', 'corrective', 'emergency', 'upgrade']).optional(),
  groupBy: z.enum(['day', 'week', 'month', 'quarter']).optional()
});

// Cost tracking schemas
export const createCostSchema = z.object({
  workOrderId: z.string().uuid().optional(),
  costCategory: z.enum(['labor', 'parts', 'contractor', 'other']),
  description: z.string().min(1),
  amount: z.number().positive(),
  taxAmount: z.number().min(0).optional(),
  invoiceNumber: z.string().optional(),
  vendor: z.string().optional(),
  budgetCategory: z.string().optional(),
  costCenter: z.string().optional()
});

// Export types
export type CreateWorkOrderInput = z.infer<typeof createWorkOrderSchema>;
export type UpdateWorkOrderInput = z.infer<typeof updateWorkOrderSchema>;
export type WorkOrderFilter = z.infer<typeof workOrderFilterSchema>;
export type CreateMaintenanceScheduleInput = z.infer<typeof createMaintenanceScheduleSchema>;
export type UpdateMaintenanceScheduleInput = z.infer<typeof updateMaintenanceScheduleSchema>;
export type CreatePartInput = z.infer<typeof createPartSchema>;
export type UpdatePartInput = z.infer<typeof updatePartSchema>;
export type RecordPartUsageInput = z.infer<typeof recordPartUsageSchema>;
export type RunDiagnosticsInput = z.infer<typeof runDiagnosticsSchema>;
export type DiagnosticResult = z.infer<typeof diagnosticResultSchema>;
export type CreateSlaConfigInput = z.infer<typeof createSlaConfigSchema>;
export type IotMetricInput = z.infer<typeof iotMetricSchema>;
export type IotMetricBatchInput = z.infer<typeof iotMetricBatchSchema>;
export type AnalyticsFilter = z.infer<typeof analyticsFilterSchema>;
export type CreateCostInput = z.infer<typeof createCostSchema>;