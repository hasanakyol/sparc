import { MicroserviceBase } from '@sparc/shared/patterns/service-base';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import Bull from 'bull';
import nodemailer from 'nodemailer';
import { ReportingServiceConfig, validateConfig } from '../config';
import { ReportQueueService } from './report-queue-service';
import { ReportGeneratorService } from './report-generator-service';
import { ReportStorageService } from './report-storage-service';
import { DashboardService } from './dashboard-service';
import { ScheduledReportService } from './scheduled-report-service';
import { ComplianceReportService } from './compliance-report-service';
import { ReportNotificationService } from './report-notification-service';
import { setupOpenTelemetry } from '../utils/telemetry';
import {
  ReportRequestSchema,
  ScheduledReportSchema,
  DashboardDataRequestSchema,
  ComplianceReportRequestSchema,
  BulkReportRequestSchema
} from '../types/schemas';
import { reportRoutes } from '../routes/reports';
import { dashboardRoutes } from '../routes/dashboard';
import { complianceRoutes } from '../routes/compliance';
import { scheduledRoutes } from '../routes/scheduled';
import { templatesRoutes } from '../routes/templates';

export class ReportingService extends MicroserviceBase {
  private reportQueue: Bull.Queue;
  private emailTransporter: nodemailer.Transporter;
  private queueService: ReportQueueService;
  private generatorService: ReportGeneratorService;
  private storageService: ReportStorageService;
  private dashboardService: DashboardService;
  private scheduledReportService: ScheduledReportService;
  private complianceService: ComplianceReportService;
  private notificationService: ReportNotificationService;

  constructor(config: ReportingServiceConfig) {
    // Validate configuration
    validateConfig(config);
    
    super(config);
    
    // Initialize Bull queue
    this.reportQueue = new Bull(config.reportGeneration.queueName, {
      redis: {
        host: new URL(config.redisUrl).hostname,
        port: parseInt(new URL(config.redisUrl).port || '6379'),
        password: new URL(config.redisUrl).password || undefined
      },
      defaultJobOptions: {
        removeOnComplete: 100,
        removeOnFail: 1000,
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        }
      }
    });
    
    // Initialize email transporter
    this.emailTransporter = nodemailer.createTransporter({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.port === 465,
      auth: {
        user: config.smtp.user,
        pass: config.smtp.pass
      }
    });
    
    // Initialize services (will be set up in initialize method)
    this.queueService = null as any;
    this.generatorService = null as any;
    this.storageService = null as any;
    this.dashboardService = null as any;
    this.scheduledReportService = null as any;
    this.complianceService = null as any;
    this.notificationService = null as any;
  }
  
  public async initialize(): Promise<void> {
    const config = this.config as ReportingServiceConfig;
    
    // Setup OpenTelemetry if enabled
    if (config.otel.enabled) {
      setupOpenTelemetry(config);
    }
    
    // Initialize services
    this.storageService = new ReportStorageService(config, this.redis);
    this.generatorService = new ReportGeneratorService(this.prisma, config);
    this.notificationService = new ReportNotificationService(this.emailTransporter, config);
    this.queueService = new ReportQueueService(
      this.reportQueue,
      this.generatorService,
      this.storageService,
      this.notificationService,
      this.redis,
      config
    );
    this.dashboardService = new DashboardService(this.prisma, this.redis, config);
    this.scheduledReportService = new ScheduledReportService(
      this.prisma,
      this.reportQueue,
      config
    );
    this.complianceService = new ComplianceReportService(this.prisma, config);
    
    // Initialize queue processor
    await this.queueService.initialize();
    
    // Initialize scheduled jobs
    await this.scheduledReportService.initialize();
    
    // Verify email configuration
    if (config.smtp.host) {
      try {
        await this.emailTransporter.verify();
        console.log(`[${config.serviceName}] Email transporter verified`);
      } catch (error) {
        console.warn(`[${config.serviceName}] Email transporter verification failed:`, error);
      }
    }
  }
  
  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    // Check email transporter
    try {
      await this.emailTransporter.verify();
      checks.email = true;
    } catch {
      checks.email = false;
    }
    
    // Check report queue
    try {
      const queueHealth = await this.reportQueue.isReady();
      checks.queue = queueHealth;
    } catch {
      checks.queue = false;
    }
    
    // Check storage
    try {
      checks.storage = await this.storageService.healthCheck();
    } catch {
      checks.storage = false;
    }
    
    return checks;
  }
  
  protected async getMetrics(): Promise<string> {
    const metrics = [];
    
    // Queue metrics
    const queueStats = await this.queueService.getQueueStats();
    metrics.push(`# HELP report_queue_waiting Number of reports waiting in queue`);
    metrics.push(`# TYPE report_queue_waiting gauge`);
    metrics.push(`report_queue_waiting ${queueStats.waiting}`);
    
    metrics.push(`# HELP report_queue_active Number of reports being processed`);
    metrics.push(`# TYPE report_queue_active gauge`);
    metrics.push(`report_queue_active ${queueStats.active}`);
    
    metrics.push(`# HELP report_queue_completed Total number of completed reports`);
    metrics.push(`# TYPE report_queue_completed counter`);
    metrics.push(`report_queue_completed ${queueStats.completed}`);
    
    metrics.push(`# HELP report_queue_failed Total number of failed reports`);
    metrics.push(`# TYPE report_queue_failed counter`);
    metrics.push(`report_queue_failed ${queueStats.failed}`);
    
    // Storage metrics
    const storageStats = await this.storageService.getStorageStats();
    metrics.push(`# HELP report_storage_used_bytes Storage used in bytes`);
    metrics.push(`# TYPE report_storage_used_bytes gauge`);
    metrics.push(`report_storage_used_bytes ${storageStats.usedBytes}`);
    
    metrics.push(`# HELP report_storage_file_count Number of stored report files`);
    metrics.push(`# TYPE report_storage_file_count gauge`);
    metrics.push(`report_storage_file_count ${storageStats.fileCount}`);
    
    return metrics.join('\\n');
  }
  
  public setupRoutes(): void {
    // Mount route groups
    this.app.route('/api/reports', reportRoutes(
      this.queueService,
      this.storageService,
      this.scheduledReportService
    ));
    
    this.app.route('/api/dashboard', dashboardRoutes(this.dashboardService));
    
    this.app.route('/api/compliance', complianceRoutes(
      this.complianceService,
      this.queueService
    ));
    
    this.app.route('/api/scheduled', scheduledRoutes(this.scheduledReportService));
    
    this.app.route('/api/templates', templatesRoutes(this.prisma));
    
    // API documentation endpoint
    this.app.get('/api/docs', (c) => {
      return c.json({
        openapi: '3.0.0',
        info: {
          title: 'SPARC Reporting Service API',
          version: this.config.version,
          description: 'API for generating reports, dashboards, and compliance documentation'
        },
        servers: [
          {
            url: `http://localhost:${this.config.port}`,
            description: 'Development server'
          }
        ],
        paths: {
          '/api/reports/generate': {
            post: {
              summary: 'Generate a new report',
              tags: ['Reports'],
              requestBody: {
                content: {
                  'application/json': {
                    schema: ReportRequestSchema
                  }
                }
              }
            }
          },
          '/api/dashboard/data': {
            get: {
              summary: 'Get dashboard widget data',
              tags: ['Dashboard']
            }
          },
          '/api/compliance/generate': {
            post: {
              summary: 'Generate compliance report',
              tags: ['Compliance']
            }
          },
          '/api/scheduled': {
            get: {
              summary: 'List scheduled reports',
              tags: ['Scheduled Reports']
            },
            post: {
              summary: 'Create scheduled report',
              tags: ['Scheduled Reports']
            }
          }
        }
      });
    });
    
    // Error handling
    this.app.notFound((c) => {
      return c.json({ error: 'Not found' }, 404);
    });
  }
  
  protected async cleanup(): Promise<void> {
    console.log(`[${this.config.serviceName}] Cleaning up resources...`);
    
    // Close queue
    if (this.reportQueue) {
      await this.reportQueue.close();
    }
    
    // Stop scheduled jobs
    if (this.scheduledReportService) {
      await this.scheduledReportService.shutdown();
    }
    
    // Close email transporter
    if (this.emailTransporter) {
      this.emailTransporter.close();
    }
    
    console.log(`[${this.config.serviceName}] Cleanup completed`);
  }
}