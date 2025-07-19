import { 
  AuditAction, 
  ResourceType, 
  Severity, 
  ComplianceFramework, 
  ComplianceStatus,
  DataClassification,
  RetentionStatus,
  PolicyType,
  PolicyAction,
  GDPRRequestType,
  GDPRRequestStatus,
  ScanType,
  ScanStatus
} from './enums';

export interface AuditLog {
  id: string;
  tenantId: string;
  userId?: string;
  action: AuditAction;
  resourceType: ResourceType;
  resourceId?: string;
  details?: Record<string, any>;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
  traceId?: string;
  sessionId?: string;
  metadata?: Record<string, any>;
}

export interface ComplianceReport {
  id: string;
  tenantId: string;
  framework: ComplianceFramework;
  status: ComplianceStatus;
  score: number;
  findings: ComplianceFinding[];
  recommendations: string[];
  generatedAt: Date;
  generatedBy: string;
  validUntil: Date;
  attestations?: Attestation[];
}

export interface ComplianceFinding {
  id: string;
  control: string;
  description: string;
  status: ComplianceStatus;
  severity: Severity;
  evidence?: string[];
  remediationSteps?: string[];
  dueDate?: Date;
  assignedTo?: string;
}

export interface Attestation {
  id: string;
  attestedBy: string;
  attestedAt: Date;
  statement: string;
  validUntil: Date;
  signature?: string;
}

export interface SecurityPolicy {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  type: PolicyType;
  rules: PolicyRule[];
  enabled: boolean;
  priority: number;
  createdAt: Date;
  updatedAt: Date;
  version: number;
}

export interface PolicyRule {
  id: string;
  condition: PolicyCondition;
  action: PolicyAction;
  parameters?: Record<string, any>;
  exceptions?: PolicyException[];
}

export interface PolicyCondition {
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'greater_than' | 'less_than' | 'in' | 'not_in';
  value: any;
  and?: PolicyCondition[];
  or?: PolicyCondition[];
}

export interface PolicyException {
  userId?: string;
  roleId?: string;
  resourceId?: string;
  validUntil?: Date;
  reason: string;
}

export interface GDPRRequest {
  id: string;
  tenantId: string;
  requesterId: string;
  type: GDPRRequestType;
  status: GDPRRequestStatus;
  details: Record<string, any>;
  requestedAt: Date;
  processedAt?: Date;
  processedBy?: string;
  response?: GDPRResponse;
  verificationToken?: string;
}

export interface GDPRResponse {
  data?: any;
  format?: 'json' | 'csv' | 'pdf';
  downloadUrl?: string;
  expiresAt?: Date;
  notes?: string;
}

export interface DataRetentionPolicy {
  id: string;
  tenantId: string;
  dataType: string;
  classification: DataClassification;
  retentionPeriodDays: number;
  deletionMethod: 'soft' | 'hard' | 'anonymize';
  legalHoldEnabled: boolean;
  autoDelete: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface RetentionRecord {
  id: string;
  tenantId: string;
  dataType: string;
  recordId: string;
  status: RetentionStatus;
  retentionUntil: Date;
  deletionScheduledAt?: Date;
  deletedAt?: Date;
  legalHold?: boolean;
  legalHoldReason?: string;
}

export interface SecurityScan {
  id: string;
  tenantId: string;
  type: ScanType;
  status: ScanStatus;
  target: string;
  startedAt: Date;
  completedAt?: Date;
  findings: SecurityFinding[];
  summary: ScanSummary;
  reportUrl?: string;
}

export interface SecurityFinding {
  id: string;
  type: string;
  severity: Severity;
  title: string;
  description: string;
  location?: string;
  remediation?: string;
  cve?: string;
  cvss?: number;
  falsePositive?: boolean;
}

export interface ScanSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  score?: number;
}

export interface ComplianceCheckResult {
  framework: ComplianceFramework;
  control: string;
  status: ComplianceStatus;
  evidence: string[];
  lastChecked: Date;
  nextCheck: Date;
  automatedCheck: boolean;
  notes?: string;
}

export interface EncryptionKey {
  id: string;
  tenantId: string;
  purpose: string;
  algorithm: string;
  keySize: number;
  createdAt: Date;
  expiresAt: Date;
  rotatedFrom?: string;
  status: 'active' | 'rotating' | 'expired' | 'revoked';
  metadata?: Record<string, any>;
}

export interface Certificate {
  id: string;
  tenantId: string;
  type: 'ssl' | 'code_signing' | 'client' | 'ca';
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
  autoRenewal: boolean;
  status: 'active' | 'expiring' | 'expired' | 'revoked';
}

export interface ComplianceDashboard {
  overallScore: number;
  frameworks: FrameworkStatus[];
  recentFindings: ComplianceFinding[];
  upcomingAudits: ScheduledAudit[];
  metrics: ComplianceMetrics;
}

export interface FrameworkStatus {
  framework: ComplianceFramework;
  status: ComplianceStatus;
  score: number;
  lastAssessment: Date;
  nextAssessment: Date;
  criticalFindings: number;
}

export interface ScheduledAudit {
  id: string;
  framework: ComplianceFramework;
  scheduledDate: Date;
  auditor?: string;
  scope: string[];
  status: 'scheduled' | 'in_progress' | 'completed' | 'cancelled';
}

export interface ComplianceMetrics {
  totalControls: number;
  compliantControls: number;
  nonCompliantControls: number;
  partialControls: number;
  averageRemediationTime: number;
  trendsLast30Days: {
    date: string;
    score: number;
  }[];
}