import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { telemetry, telemetryMiddleware } from '@sparc/shared/telemetry';
import { mainRouter } from './routes/main';
import { auditRouter } from './routes/audit';
import { complianceRouter } from './routes/compliance';
import { gdprRouter } from './routes/gdpr';
import { policyRouter } from './routes/policy';
import { securityRouter } from './routes/security';
import { retentionRouter } from './routes/retention';
import { ComplianceService } from './services/compliance-service';
import { AuditService } from './services/audit-service';
import { PolicyEngine } from './services/policy-engine';
import { GDPRService } from './services/gdpr-service';
import { SecurityScanService } from './services/security-scan-service';
import { RetentionService } from './services/retention-service';
import { ComplianceQueue } from './services/compliance-queue';

// Service-specific configuration interface
interface SecurityComplianceConfig extends ServiceConfig {
  auditLogRetentionDays: number;
  complianceCheckInterval: number;
  encryptionKeyRotationDays: number;
  maxExportSizeMB: number;
  scannerEndpoints: {
    sonarqube?: string;
    snyk?: string;
    dependencyCheck?: string;
  };
  complianceFrameworks: string[];
  dataClassifications: string[];
}

class SecurityComplianceService extends MicroserviceBase {
  private complianceService: ComplianceService;
  private auditService: AuditService;
  private policyEngine: PolicyEngine;
  private gdprService: GDPRService;
  private securityScanService: SecurityScanService;
  private retentionService: RetentionService;
  private complianceQueue: ComplianceQueue;

  constructor(config: SecurityComplianceConfig) {
    super(config);
    
    // Initialize services
    this.complianceService = new ComplianceService(this.prisma, this.redis);
    this.auditService = new AuditService(this.prisma, this.redis);
    this.policyEngine = new PolicyEngine(this.prisma, this.redis);
    this.gdprService = new GDPRService(this.prisma, this.redis);
    this.securityScanService = new SecurityScanService(config.scannerEndpoints);
    this.retentionService = new RetentionService(this.prisma, this.redis, config.auditLogRetentionDays);
    this.complianceQueue = new ComplianceQueue(this.redis);
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    try {
      // Check compliance service
      checks.compliance_service = await this.complianceService.isHealthy();
      
      // Check policy engine
      checks.policy_engine = await this.policyEngine.isHealthy();
      
      // Check GDPR service
      checks.gdpr_service = await this.gdprService.isHealthy();
      
      // Check security scanners connectivity
      if (this.config.scannerEndpoints?.sonarqube) {
        checks.sonarqube = await this.securityScanService.checkSonarQubeHealth();
      }
      
      if (this.config.scannerEndpoints?.snyk) {
        checks.snyk = await this.securityScanService.checkSnykHealth();
      }
      
      // Check queue health
      checks.compliance_queue = await this.complianceQueue.isHealthy();
    } catch (error) {
      console.error('Health check error:', error);
    }
    
    return checks;
  }

  public setupRoutes(): void {
    // Apply telemetry middleware
    this.app.use('*', telemetryMiddleware());
    
    // Mount routes
    this.app.route('/', mainRouter);
    this.app.route('/api/audit', auditRouter(this.auditService));
    this.app.route('/api/compliance', complianceRouter(this.complianceService));
    this.app.route('/api/gdpr', gdprRouter(this.gdprService));
    this.app.route('/api/policy', policyRouter(this.policyEngine));
    this.app.route('/api/security', securityRouter(this.securityScanService));
    this.app.route('/api/retention', retentionRouter(this.retentionService));
  }

  protected async cleanup(): Promise<void> {
    // Stop background jobs
    await this.complianceQueue.stop();
    await this.retentionService.stopScheduledJobs();
    
    // Close connections
    await this.securityScanService.cleanup();
    
    console.log('Security Compliance Service cleanup completed');
  }

  public async start(): Promise<void> {
    // Initialize telemetry
    await telemetry.initialize({
      serviceName: this.config.serviceName,
      serviceVersion: this.config.version,
      environment: process.env.NODE_ENV || 'development',
      jaegerEndpoint: process.env.OTEL_EXPORTER_JAEGER_ENDPOINT,
      samplingRatio: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
      customAttributes: {
        'service.type': 'compliance',
        'service.framework': 'hono'
      }
    });

    // Start background services
    await this.complianceQueue.start();
    await this.retentionService.startScheduledJobs();
    
    // Initialize compliance frameworks
    await this.complianceService.initializeFrameworks(this.config.complianceFrameworks);
    
    // Load security policies
    await this.policyEngine.loadPolicies();
    
    // Call parent start method
    await super.start();
  }
}

// Configuration
const config: SecurityComplianceConfig = {
  serviceName: 'security-compliance-service',
  port: parseInt(process.env.PORT || '3015'),
  version: process.env.npm_package_version || '1.0.0',
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/sparc',
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  auditLogRetentionDays: parseInt(process.env.AUDIT_LOG_RETENTION_DAYS || '2555'), // 7 years default
  complianceCheckInterval: parseInt(process.env.COMPLIANCE_CHECK_INTERVAL || '3600000'), // 1 hour
  encryptionKeyRotationDays: parseInt(process.env.ENCRYPTION_KEY_ROTATION_DAYS || '90'),
  maxExportSizeMB: parseInt(process.env.MAX_EXPORT_SIZE_MB || '100'),
  scannerEndpoints: {
    sonarqube: process.env.SONARQUBE_URL,
    snyk: process.env.SNYK_API_URL,
    dependencyCheck: process.env.DEPENDENCY_CHECK_URL
  },
  complianceFrameworks: (process.env.COMPLIANCE_FRAMEWORKS || 'SOC2,HIPAA,PCI-DSS,GDPR,ISO27001').split(','),
  dataClassifications: (process.env.DATA_CLASSIFICATIONS || 'PUBLIC,INTERNAL,CONFIDENTIAL,RESTRICTED').split(',')
};

// Create and start the service
const service = new SecurityComplianceService(config);
service.start().catch(console.error);

// Graceful shutdown
process.on('SIGTERM', async () => {
  await telemetry.shutdown();
  process.exit(0);
});

export default service;