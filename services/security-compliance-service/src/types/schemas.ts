import { z } from 'zod';
import { 
  AuditAction, 
  ResourceType, 
  Severity, 
  ComplianceFramework,
  ComplianceStatus,
  DataClassification,
  PolicyType,
  PolicyAction,
  GDPRRequestType,
  ScanType
} from './enums';

// Audit Log Schemas
export const auditLogSchema = z.object({
  action: z.nativeEnum(AuditAction),
  resourceType: z.nativeEnum(ResourceType),
  resourceId: z.string().optional(),
  details: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional()
});

export const auditLogQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(50),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  action: z.nativeEnum(AuditAction).optional(),
  resourceType: z.nativeEnum(ResourceType).optional(),
  userId: z.string().uuid().optional(),
  search: z.string().optional()
});

export const auditLogExportSchema = z.object({
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  format: z.enum(['csv', 'json', 'pdf']).default('csv'),
  framework: z.nativeEnum(ComplianceFramework).optional(),
  filters: z.object({
    actions: z.array(z.nativeEnum(AuditAction)).optional(),
    resourceTypes: z.array(z.nativeEnum(ResourceType)).optional(),
    userIds: z.array(z.string().uuid()).optional()
  }).optional()
});

// Compliance Schemas
export const complianceReportRequestSchema = z.object({
  framework: z.nativeEnum(ComplianceFramework),
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  includeEvidence: z.boolean().default(false),
  format: z.enum(['pdf', 'json', 'html']).default('pdf')
});

export const complianceFindingSchema = z.object({
  control: z.string(),
  description: z.string(),
  status: z.nativeEnum(ComplianceStatus),
  severity: z.nativeEnum(Severity),
  evidence: z.array(z.string()).optional(),
  remediationSteps: z.array(z.string()).optional(),
  dueDate: z.string().datetime().optional(),
  assignedTo: z.string().uuid().optional()
});

export const attestationSchema = z.object({
  statement: z.string().min(1),
  validUntil: z.string().datetime()
});

// Policy Schemas
export const policyConditionSchema: z.ZodType<any> = z.lazy(() => z.object({
  field: z.string(),
  operator: z.enum(['equals', 'not_equals', 'contains', 'greater_than', 'less_than', 'in', 'not_in']),
  value: z.any(),
  and: z.array(policyConditionSchema).optional(),
  or: z.array(policyConditionSchema).optional()
}));

export const policyRuleSchema = z.object({
  condition: policyConditionSchema,
  action: z.nativeEnum(PolicyAction),
  parameters: z.record(z.any()).optional(),
  exceptions: z.array(z.object({
    userId: z.string().uuid().optional(),
    roleId: z.string().uuid().optional(),
    resourceId: z.string().optional(),
    validUntil: z.string().datetime().optional(),
    reason: z.string()
  })).optional()
});

export const securityPolicySchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500),
  type: z.nativeEnum(PolicyType),
  rules: z.array(policyRuleSchema).min(1),
  enabled: z.boolean().default(true),
  priority: z.number().int().min(1).max(1000).default(100)
});

export const policyUpdateSchema = securityPolicySchema.partial().extend({
  id: z.string().uuid()
});

// GDPR Schemas
export const gdprRequestSchema = z.object({
  type: z.nativeEnum(GDPRRequestType),
  details: z.object({
    reason: z.string().optional(),
    scope: z.array(z.string()).optional(),
    format: z.enum(['json', 'csv', 'pdf']).optional()
  }),
  verificationToken: z.string().optional()
});

export const gdprProcessSchema = z.object({
  requestId: z.string().uuid(),
  action: z.enum(['approve', 'reject', 'partial']),
  response: z.object({
    data: z.any().optional(),
    format: z.enum(['json', 'csv', 'pdf']).optional(),
    notes: z.string().optional()
  }).optional(),
  reason: z.string().optional()
});

// Retention Schemas
export const retentionPolicySchema = z.object({
  dataType: z.string().min(1),
  classification: z.nativeEnum(DataClassification),
  retentionPeriodDays: z.number().int().min(1),
  deletionMethod: z.enum(['soft', 'hard', 'anonymize']),
  legalHoldEnabled: z.boolean().default(false),
  autoDelete: z.boolean().default(true)
});

export const legalHoldSchema = z.object({
  recordIds: z.array(z.string()),
  reason: z.string().min(1),
  validUntil: z.string().datetime().optional()
});

// Security Scan Schemas
export const securityScanRequestSchema = z.object({
  type: z.nativeEnum(ScanType),
  target: z.string().min(1),
  options: z.object({
    depth: z.enum(['quick', 'standard', 'deep']).default('standard'),
    includeDevDependencies: z.boolean().default(false),
    threshold: z.nativeEnum(Severity).default(Severity.MEDIUM)
  }).optional()
});

export const scanFindingUpdateSchema = z.object({
  findingId: z.string().uuid(),
  falsePositive: z.boolean().optional(),
  notes: z.string().optional(),
  status: z.enum(['open', 'resolved', 'accepted', 'ignored']).optional()
});

// Dashboard Schemas
export const dashboardQuerySchema = z.object({
  period: z.enum(['24h', '7d', '30d', '90d', '1y']).default('30d'),
  frameworks: z.array(z.nativeEnum(ComplianceFramework)).optional()
});

// Export type inference
export type AuditLogInput = z.infer<typeof auditLogSchema>;
export type AuditLogQuery = z.infer<typeof auditLogQuerySchema>;
export type AuditLogExport = z.infer<typeof auditLogExportSchema>;
export type ComplianceReportRequest = z.infer<typeof complianceReportRequestSchema>;
export type ComplianceFindingInput = z.infer<typeof complianceFindingSchema>;
export type AttestationInput = z.infer<typeof attestationSchema>;
export type SecurityPolicyInput = z.infer<typeof securityPolicySchema>;
export type PolicyUpdateInput = z.infer<typeof policyUpdateSchema>;
export type GDPRRequestInput = z.infer<typeof gdprRequestSchema>;
export type GDPRProcessInput = z.infer<typeof gdprProcessSchema>;
export type RetentionPolicyInput = z.infer<typeof retentionPolicySchema>;
export type LegalHoldInput = z.infer<typeof legalHoldSchema>;
export type SecurityScanRequest = z.infer<typeof securityScanRequestSchema>;
export type ScanFindingUpdate = z.infer<typeof scanFindingUpdateSchema>;
export type DashboardQuery = z.infer<typeof dashboardQuerySchema>;