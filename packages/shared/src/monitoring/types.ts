export interface SIEMProvider {
  name: string;
  type: 'splunk' | 'elk' | 'datadog' | 'qradar' | 'azure-sentinel' | 'sumo-logic';
  enabled: boolean;
  config: Record<string, any>;
}

export interface SecurityPattern {
  id: string;
  name: string;
  description: string;
  pattern: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'authentication' | 'authorization' | 'data-access' | 'network' | 'system';
  enabled: boolean;
  actions: string[];
}

export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'email' | 'url' | 'user-agent';
  value: string;
  confidence: number;
  source: string;
  lastSeen: Date;
  tags: string[];
}

export interface SecurityIncident {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved' | 'false-positive';
  events: string[]; // Security event IDs
  assignee?: string;
  timeline: IncidentTimelineEntry[];
  affectedResources: string[];
  containmentActions: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface IncidentTimelineEntry {
  timestamp: Date;
  action: string;
  actor: string;
  details: Record<string, any>;
}

export interface SecurityDashboard {
  id: string;
  name: string;
  widgets: DashboardWidget[];
  refreshInterval: number;
  layout: any;
}

export interface DashboardWidget {
  id: string;
  type: 'chart' | 'metric' | 'table' | 'map' | 'timeline';
  title: string;
  query: string;
  visualization: Record<string, any>;
  position: { x: number; y: number; w: number; h: number };
}

export interface SecurityMetrics {
  timeRange: { start: Date; end: Date };
  totalEvents: number;
  criticalEvents: number;
  blockedAttempts: number;
  activeIncidents: number;
  meanTimeToDetect: number;
  meanTimeToRespond: number;
  topThreats: Array<{ threat: string; count: number }>;
  eventsByHour: Array<{ hour: Date; count: number; severity: string }>;
  geoDistribution: Array<{ country: string; count: number }>;
}

export interface ComplianceReport {
  id: string;
  framework: 'soc2' | 'pci-dss' | 'hipaa' | 'gdpr' | 'iso27001';
  period: { start: Date; end: Date };
  controls: ComplianceControl[];
  summary: {
    compliant: number;
    nonCompliant: number;
    notApplicable: number;
  };
  generatedAt: Date;
}

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: 'compliant' | 'non-compliant' | 'not-applicable';
  evidence: string[];
  lastAssessed: Date;
}