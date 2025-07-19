import { z } from 'zod';
import { ReportType, ExportFormat, TimeRange, WidgetType } from './index';

// Request schemas
export const ReportRequestSchema = z.object({
  type: ReportType,
  format: ExportFormat,
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  filters: z.record(z.any()).optional(),
  includeDetails: z.boolean().default(true),
  groupBy: z.array(z.string()).optional(),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).optional(),
  limit: z.number().int().positive().max(10000).optional(),
  offset: z.number().int().min(0).optional(),
  customFields: z.array(z.string()).optional(),
  locale: z.string().optional(),
  timezone: z.string().optional(),
  priority: z.number().int().min(0).max(10).default(5)
});

export type ReportRequest = z.infer<typeof ReportRequestSchema>;

export const ScheduledReportSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  type: ReportType,
  format: ExportFormat,
  schedule: z.string().regex(/^(\*|([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])|\*\/([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])) (\*|([0-9]|1[0-9]|2[0-3])|\*\/([0-9]|1[0-9]|2[0-3])) (\*|([1-9]|1[0-9]|2[0-9]|3[0-1])|\*\/([1-9]|1[0-9]|2[0-9]|3[0-1])) (\*|([1-9]|1[0-2])|\*\/([1-9]|1[0-2])) (\*|([0-6])|\*\/([0-6]))$/),
  recipients: z.array(z.string().email()).min(1),
  parameters: z.object({
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
    relativePeriod: z.enum(['last_day', 'last_week', 'last_month', 'last_quarter', 'last_year']).optional(),
    filters: z.record(z.any()).optional(),
    includeDetails: z.boolean().default(true),
    groupBy: z.array(z.string()).optional(),
    customFields: z.array(z.string()).optional(),
    locale: z.string().optional(),
    timezone: z.string().optional()
  }),
  isActive: z.boolean().default(true),
  metadata: z.record(z.any()).optional()
});

export type ScheduledReportRequest = z.infer<typeof ScheduledReportSchema>;

export const DashboardDataRequestSchema = z.object({
  widgets: z.array(WidgetType),
  timeRange: TimeRange.default('24h'),
  customDateRange: z.object({
    start: z.string().datetime(),
    end: z.string().datetime()
  }).optional(),
  filters: z.record(z.any()).optional(),
  refreshInterval: z.number().int().min(0).optional()
});

export type DashboardDataRequest = z.infer<typeof DashboardDataRequestSchema>;

export const ComplianceReportRequestSchema = z.object({
  framework: z.enum(['sox', 'hipaa', 'pci_dss', 'gdpr', 'iso27001', 'custom']),
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  format: ExportFormat.default('pdf'),
  includeEvidence: z.boolean().default(true),
  includeRecommendations: z.boolean().default(true),
  customControls: z.array(z.string()).optional(),
  excludeControls: z.array(z.string()).optional()
});

export type ComplianceReportRequest = z.infer<typeof ComplianceReportRequestSchema>;

export const ReportTemplateCreateSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000),
  type: ReportType,
  category: z.string(),
  requiredFields: z.array(z.string()).min(1),
  optionalFields: z.array(z.string()).optional(),
  defaultParameters: z.record(z.any()).optional(),
  schema: z.any().optional(),
  sampleData: z.any().optional(),
  icon: z.string().optional(),
  tags: z.array(z.string()).optional()
});

export type ReportTemplateCreate = z.infer<typeof ReportTemplateCreateSchema>;

export const BulkReportRequestSchema = z.object({
  reports: z.array(ReportRequestSchema).min(1).max(10),
  notifyOnCompletion: z.boolean().default(true),
  combineResults: z.boolean().default(false),
  outputFormat: ExportFormat.optional()
});

export type BulkReportRequest = z.infer<typeof BulkReportRequestSchema>;

// Response schemas
export const ReportStatusResponseSchema = z.object({
  id: z.string(),
  type: ReportType,
  format: ExportFormat,
  status: z.enum(['pending', 'processing', 'completed', 'failed', 'cancelled']),
  progress: z.number().min(0).max(100).optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  completedAt: z.string().datetime().optional(),
  estimatedCompletionTime: z.string().datetime().optional(),
  result: z.object({
    filename: z.string(),
    size: z.number(),
    mimeType: z.string(),
    downloadUrl: z.string().optional(),
    expiresAt: z.string().datetime().optional(),
    pageCount: z.number().optional(),
    recordCount: z.number()
  }).optional(),
  error: z.object({
    code: z.string(),
    message: z.string(),
    details: z.any().optional()
  }).optional()
});

export type ReportStatusResponse = z.infer<typeof ReportStatusResponseSchema>;

export const DashboardDataResponseSchema = z.object({
  widgets: z.record(z.any()),
  timestamp: z.string().datetime(),
  nextUpdate: z.string().datetime().optional(),
  meta: z.object({
    timeRange: TimeRange,
    filters: z.record(z.any()).optional(),
    cached: z.boolean().optional()
  })
});

export type DashboardDataResponse = z.infer<typeof DashboardDataResponseSchema>;

// Filter schemas
export const AccessEventFilterSchema = z.object({
  userId: z.string().uuid().optional(),
  doorId: z.string().uuid().optional(),
  eventType: z.array(z.string()).optional(),
  success: z.boolean().optional(),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional()
});

export const VideoEventFilterSchema = z.object({
  cameraId: z.string().uuid().optional(),
  eventType: z.array(z.string()).optional(),
  severity: z.array(z.string()).optional(),
  hasVideo: z.boolean().optional(),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional()
});

export const AuditLogFilterSchema = z.object({
  userId: z.string().uuid().optional(),
  action: z.array(z.string()).optional(),
  resource: z.array(z.string()).optional(),
  success: z.boolean().optional(),
  ipAddress: z.string().optional(),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional()
});

// Validation helpers
export function validateReportFilters(type: ReportType, filters: any): boolean {
  switch (type) {
    case 'access_events':
      return AccessEventFilterSchema.safeParse(filters).success;
    case 'video_events':
      return VideoEventFilterSchema.safeParse(filters).success;
    case 'audit_log':
      return AuditLogFilterSchema.safeParse(filters).success;
    default:
      return true; // Allow any filters for other report types
  }
}