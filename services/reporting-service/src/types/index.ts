import { z } from 'zod';

// Report types enum
export const ReportType = z.enum([
  'access_events',
  'user_activity',
  'door_status',
  'video_events',
  'audit_log',
  'compliance_sox',
  'compliance_hipaa',
  'compliance_pci_dss',
  'system_health',
  'environmental',
  'visitor_log',
  'incident_report',
  'security_assessment',
  'device_inventory',
  'alarm_history',
  'badge_audit',
  'time_attendance',
  'occupancy_analytics',
  'energy_usage',
  'maintenance_log'
]);

export type ReportType = z.infer<typeof ReportType>;

// Export formats
export const ExportFormat = z.enum(['pdf', 'csv', 'json', 'xlsx', 'html']);
export type ExportFormat = z.infer<typeof ExportFormat>;

// Report status
export const ReportStatus = z.enum(['pending', 'processing', 'completed', 'failed', 'cancelled']);
export type ReportStatus = z.infer<typeof ReportStatus>;

// Severity levels
export const SeverityLevel = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type SeverityLevel = z.infer<typeof SeverityLevel>;

// Time ranges
export const TimeRange = z.enum(['1h', '24h', '7d', '30d', '90d', 'custom']);
export type TimeRange = z.infer<typeof TimeRange>;

// Widget types for dashboards
export const WidgetType = z.enum([
  'access_summary',
  'door_status',
  'camera_status',
  'recent_events',
  'alerts',
  'system_health',
  'visitor_trends',
  'compliance_score',
  'incident_heatmap',
  'device_health',
  'user_activity_chart',
  'security_metrics'
]);

export type WidgetType = z.infer<typeof WidgetType>;

// Interfaces
export interface ReportJob {
  id: string;
  type: ReportType;
  format: ExportFormat;
  status: ReportStatus;
  tenantId: string;
  userId: string;
  parameters: ReportParameters;
  result?: ReportResult;
  error?: string;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
  retryCount: number;
  priority: number;
}

export interface ReportParameters {
  startDate: Date;
  endDate: Date;
  filters?: Record<string, any>;
  includeDetails: boolean;
  groupBy?: string[];
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
  customFields?: string[];
  locale?: string;
  timezone?: string;
}

export interface ReportResult {
  filename: string;
  size: number;
  mimeType: string;
  path?: string;
  s3Key?: string;
  checksum: string;
  pageCount?: number;
  recordCount: number;
  generationTime: number;
}

export interface ScheduledReport {
  id: string;
  name: string;
  description?: string;
  type: ReportType;
  format: ExportFormat;
  schedule: string; // Cron expression
  recipients: string[];
  parameters: ReportParameters;
  isActive: boolean;
  tenantId: string;
  createdBy: string;
  lastRun?: Date;
  nextRun?: Date;
  runCount: number;
  failureCount: number;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: ReportType;
  category: string;
  requiredFields: string[];
  optionalFields?: string[];
  defaultParameters?: Partial<ReportParameters>;
  schema?: any; // JSON Schema for validation
  sampleData?: any;
  icon?: string;
  tags?: string[];
}

export interface DashboardWidget {
  id: string;
  type: WidgetType;
  title: string;
  config: WidgetConfig;
  data?: any;
  lastUpdate?: Date;
  refreshInterval?: number;
}

export interface WidgetConfig {
  timeRange?: TimeRange;
  filters?: Record<string, any>;
  chartType?: 'line' | 'bar' | 'pie' | 'donut' | 'area' | 'scatter' | 'heatmap';
  displayOptions?: {
    showLegend?: boolean;
    showGrid?: boolean;
    showTooltip?: boolean;
    colors?: string[];
    height?: number;
    width?: number;
  };
  dataSource?: string;
  aggregation?: 'sum' | 'avg' | 'min' | 'max' | 'count';
  groupBy?: string[];
  metrics?: string[];
}

export interface ComplianceReport {
  id: string;
  framework: 'sox' | 'hipaa' | 'pci_dss' | 'gdpr' | 'iso27001' | 'custom';
  period: {
    start: Date;
    end: Date;
  };
  score: number;
  findings: ComplianceFinding[];
  recommendations: string[];
  attestations?: ComplianceAttestation[];
  evidence?: ComplianceEvidence[];
  generatedAt: Date;
  generatedBy: string;
  approvedBy?: string;
  approvedAt?: Date;
}

export interface ComplianceFinding {
  id: string;
  controlId: string;
  controlName: string;
  status: 'pass' | 'fail' | 'partial' | 'not_applicable';
  severity: SeverityLevel;
  description: string;
  evidence?: string[];
  remediation?: string;
  dueDate?: Date;
  assignedTo?: string;
}

export interface ComplianceAttestation {
  id: string;
  statement: string;
  attestedBy: string;
  attestedAt: Date;
  signature?: string;
}

export interface ComplianceEvidence {
  id: string;
  type: 'screenshot' | 'log' | 'document' | 'config' | 'other';
  description: string;
  path?: string;
  hash?: string;
  collectedAt: Date;
  collectedBy: string;
}

export interface ReportNotification {
  id: string;
  reportId: string;
  type: 'email' | 'sms' | 'webhook' | 'in_app';
  recipient: string;
  status: 'pending' | 'sent' | 'failed';
  attempts: number;
  lastAttempt?: Date;
  error?: string;
  metadata?: Record<string, any>;
}