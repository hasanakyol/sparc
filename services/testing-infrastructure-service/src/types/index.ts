export interface TestConfig {
  type: TestType;
  name: string;
  description: string;
  parameters: Record<string, any>;
  timeout: number;
  retries: number;
  environment: TestEnvironment;
  tenantId?: string;
  tags?: string[];
  schedule?: TestSchedule;
}

export enum TestType {
  E2E = 'e2e',
  LOAD = 'load',
  SECURITY = 'security',
  COMPLIANCE = 'compliance',
  OFFLINE = 'offline',
  HARDWARE = 'hardware',
  TENANT_ISOLATION = 'tenant-isolation',
  CHAOS = 'chaos',
  VISUAL = 'visual',
  CONTRACT = 'contract',
  PERFORMANCE = 'performance',
  ACCESSIBILITY = 'accessibility',
}

export enum TestEnvironment {
  LOCAL = 'local',
  CI = 'ci',
  DEV = 'dev',
  TEST = 'test',
  STAGING = 'staging',
  PRODUCTION = 'production',
}

export interface TestSchedule {
  cron?: string;
  interval?: number;
  runAt?: Date;
}

export interface TestExecution {
  id: string;
  testId: string;
  type: TestType;
  status: TestStatus;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  results?: TestResults;
  logs: TestLog[];
  metrics?: TestMetrics;
  artifacts: TestArtifact[];
  error?: string;
  retryCount: number;
  environment: TestEnvironment;
  tenantId?: string;
  tags?: string[];
  triggeredBy: string;
  commitSha?: string;
  branch?: string;
}

export enum TestStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
  TIMEOUT = 'timeout',
  RETRYING = 'retrying',
}

export interface TestResults {
  passed: boolean;
  summary: TestSummary;
  details: any;
  coverage?: TestCoverage;
  performance?: PerformanceMetrics;
  security?: SecurityFindings;
  accessibility?: AccessibilityResults;
}

export interface TestSummary {
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  duration: number;
  flaky?: number;
}

export interface TestCoverage {
  statements: number;
  branches: number;
  functions: number;
  lines: number;
}

export interface PerformanceMetrics {
  responseTime: ResponseTimeMetrics;
  throughput: ThroughputMetrics;
  resources: ResourceMetrics;
  errors: ErrorMetrics;
}

export interface ResponseTimeMetrics {
  min: number;
  max: number;
  mean: number;
  median: number;
  p95: number;
  p99: number;
}

export interface ThroughputMetrics {
  requestsPerSecond: number;
  bytesPerSecond: number;
  successRate: number;
}

export interface ResourceMetrics {
  cpu: CpuMetrics;
  memory: MemoryMetrics;
  network: NetworkMetrics;
}

export interface CpuMetrics {
  usage: number;
  load: number[];
}

export interface MemoryMetrics {
  used: number;
  total: number;
  percentage: number;
}

export interface NetworkMetrics {
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
  errors: number;
}

export interface ErrorMetrics {
  total: number;
  byType: Record<string, number>;
  byCode: Record<string, number>;
}

export interface SecurityFindings {
  vulnerabilities: SecurityVulnerability[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
}

export interface SecurityVulnerability {
  id: string;
  title: string;
  severity: SecuritySeverity;
  type: string;
  description: string;
  remediation: string;
  cvss?: number;
  cwe?: string;
  owasp?: string;
  affectedComponent: string;
  evidence?: string;
}

export enum SecuritySeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export interface AccessibilityResults {
  violations: AccessibilityViolation[];
  passes: number;
  incomplete: number;
  inapplicable: number;
}

export interface AccessibilityViolation {
  id: string;
  impact: string;
  description: string;
  help: string;
  helpUrl: string;
  nodes: AccessibilityNode[];
  tags: string[];
}

export interface AccessibilityNode {
  html: string;
  target: string[];
  failureSummary: string;
}

export interface TestLog {
  timestamp: Date;
  level: LogLevel;
  message: string;
  data?: any;
}

export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

export interface TestArtifact {
  id: string;
  type: ArtifactType;
  name: string;
  path: string;
  size: number;
  mimeType: string;
  createdAt: Date;
}

export enum ArtifactType {
  SCREENSHOT = 'screenshot',
  VIDEO = 'video',
  LOG = 'log',
  REPORT = 'report',
  HAR = 'har',
  TRACE = 'trace',
  COVERAGE = 'coverage',
  PROFILE = 'profile',
}

export interface TestMetrics {
  executionId: string;
  timestamp: Date;
  type: TestType;
  metrics: Record<string, any>;
}

export interface TestReport {
  id: string;
  name: string;
  type: ReportType;
  format: ReportFormat;
  timeRange: TimeRange;
  filters: ReportFilters;
  content: any;
  generatedAt: Date;
  generatedBy: string;
}

export enum ReportType {
  SUMMARY = 'summary',
  DETAILED = 'detailed',
  TREND = 'trend',
  COMPARISON = 'comparison',
  COMPLIANCE = 'compliance',
  EXECUTIVE = 'executive',
}

export enum ReportFormat {
  JSON = 'json',
  HTML = 'html',
  PDF = 'pdf',
  CSV = 'csv',
  XLSX = 'xlsx',
}

export interface TimeRange {
  start: Date;
  end: Date;
}

export interface ReportFilters {
  testTypes?: TestType[];
  environments?: TestEnvironment[];
  tenantIds?: string[];
  tags?: string[];
  status?: TestStatus[];
}

// Load test specific types
export interface LoadTestConfig {
  scenario: string;
  vusers: number;
  duration: number;
  rampUp: number;
  rampDown: number;
  thresholds?: LoadTestThresholds;
  stages?: LoadTestStage[];
}

export interface LoadTestThresholds {
  responseTime?: number;
  errorRate?: number;
  throughput?: number;
}

export interface LoadTestStage {
  duration: number;
  target: number;
}

// Chaos test specific types
export interface ChaosTestConfig {
  experiments: ChaosExperiment[];
  duration: number;
  target: ChaosTarget;
  rollback: boolean;
}

export interface ChaosExperiment {
  type: ChaosType;
  parameters: Record<string, any>;
  probability: number;
}

export enum ChaosType {
  NETWORK_DELAY = 'network-delay',
  NETWORK_LOSS = 'network-loss',
  SERVICE_CRASH = 'service-crash',
  RESOURCE_EXHAUSTION = 'resource-exhaustion',
  CLOCK_SKEW = 'clock-skew',
  DISK_FAILURE = 'disk-failure',
}

export interface ChaosTarget {
  services?: string[];
  pods?: string[];
  nodes?: string[];
  namespace?: string;
}

// Visual test specific types
export interface VisualTestConfig {
  baseline: string;
  browsers: string[];
  viewports: Viewport[];
  threshold: number;
  ignoreRegions?: IgnoreRegion[];
}

export interface Viewport {
  width: number;
  height: number;
  deviceScaleFactor?: number;
}

export interface IgnoreRegion {
  selector?: string;
  x?: number;
  y?: number;
  width?: number;
  height?: number;
}

// Contract test specific types
export interface ContractTestConfig {
  provider: string;
  consumer: string;
  pactFile?: string;
  verificationUrl: string;
  publishResults: boolean;
}

// Performance test specific types
export interface PerformanceTestConfig {
  url: string;
  iterations: number;
  throttling?: NetworkThrottling;
  cpuSlowdown?: number;
  budget?: PerformanceBudget;
}

export interface NetworkThrottling {
  downloadThroughput: number;
  uploadThroughput: number;
  latency: number;
}

export interface PerformanceBudget {
  fcp?: number; // First Contentful Paint
  lcp?: number; // Largest Contentful Paint
  tti?: number; // Time to Interactive
  cls?: number; // Cumulative Layout Shift
  fid?: number; // First Input Delay
}