import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { trace } from '@opentelemetry/api';
import { logger } from '@sparc/shared';
import Redis from 'ioredis';
import { Queue, Worker } from 'bullmq';

// Import routers
import integrationsRouter from './routes/integrations';
import webhooksRouter from './routes/webhooks';
import oauthRouter from './routes/oauth';
import pluginsRouter from './routes/plugins';
import marketplaceRouter from './routes/marketplace';
import gatewayRouter from './routes/gateway';

// Import services
import { IntegrationService } from './services/integration.service';
import { WebhookService } from './services/webhook.service';
import { PluginService } from './services/plugin.service';
import { TransformationService } from './services/transformation.service';
import { QuotaService } from './services/quota.service';
import { HealthMonitorService } from './services/health-monitor.service';

// OpenTelemetry tracer
const tracer = trace.getTracer('integration-service');

class IntegrationServiceApp extends MicroserviceBase {
  private integrationService: IntegrationService | null = null;
  private webhookService: WebhookService | null = null;
  private pluginService: PluginService | null = null;
  private transformationService: TransformationService | null = null;
  private quotaService: QuotaService | null = null;
  private healthMonitorService: HealthMonitorService | null = null;
  
  // Message queues
  private webhookQueue: Queue | null = null;
  private syncQueue: Queue | null = null;
  private webhookWorker: Worker | null = null;
  private syncWorker: Worker | null = null;

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'integration-service',
      port: config.services?.integration?.port || 3016,
      version: process.env.npm_package_version || '1.0.0',
      jwtSecret: config.jwt?.accessTokenSecret || process.env.JWT_SECRET!,
      redisUrl: config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379',
      databaseUrl: config.database?.url || process.env.DATABASE_URL!,
      enableAuth: true,
      enableRateLimit: true,
      enableMetrics: true,
      corsOrigins: config.cors?.origins || ['http://localhost:3000']
    };
    
    super(serviceConfig);
  }

  setupRoutes(): void {
    // Mount route modules
    this.app.route('/api/integrations', integrationsRouter);
    this.app.route('/api/webhooks', webhooksRouter);
    this.app.route('/api/oauth', oauthRouter);
    this.app.route('/api/plugins', pluginsRouter);
    this.app.route('/api/marketplace', marketplaceRouter);
    this.app.route('/api/gateway', gatewayRouter);

    // Additional error handling with OpenTelemetry
    this.app.use('*', async (c, next) => {
      const span = tracer.startSpan('request', {
        attributes: {
          'http.method': c.req.method,
          'http.url': c.req.url,
          'http.target': c.req.path,
        }
      });

      try {
        await next();
        span.setAttributes({
          'http.status_code': c.res.status,
        });
      } catch (err) {
        span.recordException(err as Error);
        span.setAttributes({
          'http.status_code': c.res.status || 500,
        });

        if (err instanceof z.ZodError) {
          throw new HTTPException(400, {
            message: 'Validation failed',
            cause: err.errors
          });
        }
        throw err;
      } finally {
        span.end();
      }
    });

    // 404 handler
    this.app.notFound((c) => {
      return c.json(
        {
          error: 'Not found',
          path: c.req.path,
        },
        404
      );
    });
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    try {
      // Check services
      checks.integrationService = this.integrationService !== null;
      checks.webhookService = this.webhookService !== null;
      checks.pluginService = this.pluginService !== null;
      checks.transformationService = this.transformationService !== null;
      checks.quotaService = this.quotaService !== null;
      checks.healthMonitorService = this.healthMonitorService !== null;
      
      // Check message queues
      checks.webhookQueue = this.webhookQueue !== null;
      checks.syncQueue = this.syncQueue !== null;
      checks.webhookWorker = this.webhookWorker !== null;
      checks.syncWorker = this.syncWorker !== null;
      
      // Check external integrations (simplified)
      if (this.healthMonitorService) {
        const integrationHealths = await this.healthMonitorService.checkAllIntegrations();
        checks.externalIntegrations = integrationHealths.every(h => h.status !== 'unhealthy');
      }
    } catch (error) {
      logger.error('Health check error:', error);
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const span = tracer.startSpan('getMetrics');
    
    try {
      // Return Prometheus-formatted metrics
      const metrics: string[] = [];
      
      // Integration metrics
      metrics.push('# HELP integrations_total Total number of integrations');
      metrics.push('# TYPE integrations_total gauge');
      
      metrics.push('# HELP integrations_by_type Number of integrations by type');
      metrics.push('# TYPE integrations_by_type gauge');
      
      metrics.push('# HELP integrations_by_status Number of integrations by status');
      metrics.push('# TYPE integrations_by_status gauge');
      
      // Webhook metrics
      metrics.push('# HELP webhooks_total Total number of webhooks');
      metrics.push('# TYPE webhooks_total gauge');
      
      metrics.push('# HELP webhook_deliveries_total Total webhook deliveries');
      metrics.push('# TYPE webhook_deliveries_total counter');
      
      metrics.push('# HELP webhook_failures_total Total webhook failures');
      metrics.push('# TYPE webhook_failures_total counter');
      
      metrics.push('# HELP webhook_queue_size Current webhook queue size');
      metrics.push('# TYPE webhook_queue_size gauge');
      
      // Plugin metrics
      metrics.push('# HELP plugins_installed_total Total plugins installed');
      metrics.push('# TYPE plugins_installed_total gauge');
      
      metrics.push('# HELP plugin_executions_total Total plugin executions');
      metrics.push('# TYPE plugin_executions_total counter');
      
      // API Gateway metrics
      metrics.push('# HELP gateway_requests_total Total API gateway requests');
      metrics.push('# TYPE gateway_requests_total counter');
      
      metrics.push('# HELP gateway_response_time_seconds API gateway response time');
      metrics.push('# TYPE gateway_response_time_seconds histogram');
      
      // Quota metrics
      metrics.push('# HELP quota_usage_percent Quota usage percentage by tenant');
      metrics.push('# TYPE quota_usage_percent gauge');
      
      // Get actual metrics from Redis if available
      try {
        const integrationsTotal = await this.redis.get('metrics:integrations:total') || '0';
        metrics.push(`integrations_total ${integrationsTotal}`);
        
        const webhooksTotal = await this.redis.get('metrics:webhooks:total') || '0';
        metrics.push(`webhooks_total ${webhooksTotal}`);
        
        const webhookDeliveries = await this.redis.get('metrics:webhook:deliveries:total') || '0';
        metrics.push(`webhook_deliveries_total ${webhookDeliveries}`);
        
        const webhookFailures = await this.redis.get('metrics:webhook:failures:total') || '0';
        metrics.push(`webhook_failures_total ${webhookFailures}`);
        
        if (this.webhookQueue) {
          const queueSize = await this.webhookQueue.getWaitingCount();
          metrics.push(`webhook_queue_size ${queueSize}`);
        }
        
        const pluginsTotal = await this.redis.get('metrics:plugins:total') || '0';
        metrics.push(`plugins_installed_total ${pluginsTotal}`);
        
        const pluginExecutions = await this.redis.get('metrics:plugin:executions:total') || '0';
        metrics.push(`plugin_executions_total ${pluginExecutions}`);
        
        const gatewayRequests = await this.redis.get('metrics:gateway:requests:total') || '0';
        metrics.push(`gateway_requests_total ${gatewayRequests}`);
      } catch (error) {
        logger.error('Failed to get metrics from Redis:', error);
      }
      
      return metrics.join('\n');
    } finally {
      span.end();
    }
  }

  protected async cleanup(): Promise<void> {
    logger.info('Cleaning up integration service resources...');
    
    // Stop services
    if (this.healthMonitorService) {
      await this.healthMonitorService.stop();
    }
    
    // Stop workers
    if (this.webhookWorker) {
      await this.webhookWorker.close();
    }
    
    if (this.syncWorker) {
      await this.syncWorker.close();
    }
    
    // Close queues
    if (this.webhookQueue) {
      await this.webhookQueue.close();
    }
    
    if (this.syncQueue) {
      await this.syncQueue.close();
    }
  }

  private async setupMessageQueues(): Promise<void> {
    // Setup webhook delivery queue
    this.webhookQueue = new Queue('webhook-delivery', {
      connection: {
        host: this.redis.options.host,
        port: this.redis.options.port,
        password: this.redis.options.password,
      }
    });

    // Setup sync queue for LDAP/AD and other batch operations
    this.syncQueue = new Queue('integration-sync', {
      connection: {
        host: this.redis.options.host,
        port: this.redis.options.port,
        password: this.redis.options.password,
      }
    });

    // Setup webhook worker
    this.webhookWorker = new Worker('webhook-delivery', 
      async (job) => {
        if (this.webhookService) {
          await this.webhookService.processWebhookDelivery(job.data);
        }
      },
      {
        connection: {
          host: this.redis.options.host,
          port: this.redis.options.port,
          password: this.redis.options.password,
        },
        concurrency: 10,
      }
    );

    // Setup sync worker
    this.syncWorker = new Worker('integration-sync',
      async (job) => {
        if (this.integrationService) {
          await this.integrationService.processSyncJob(job.data);
        }
      },
      {
        connection: {
          host: this.redis.options.host,
          port: this.redis.options.port,
          password: this.redis.options.password,
        },
        concurrency: 5,
      }
    );

    // Error handlers
    this.webhookWorker.on('failed', (job, err) => {
      logger.error('Webhook delivery failed', { jobId: job?.id, error: err.message });
    });

    this.syncWorker.on('failed', (job, err) => {
      logger.error('Sync job failed', { jobId: job?.id, error: err.message });
    });
  }

  public async start(): Promise<void> {
    // Call parent start to initialize everything
    await super.start();
    
    // Initialize services
    this.integrationService = new IntegrationService(this.prisma, this.redis);
    this.webhookService = new WebhookService(this.prisma, this.redis);
    this.pluginService = new PluginService(this.prisma, this.redis);
    this.transformationService = new TransformationService();
    this.quotaService = new QuotaService(this.prisma, this.redis);
    this.healthMonitorService = new HealthMonitorService(this.integrationService, this.redis);
    
    // Start health monitor
    await this.healthMonitorService.start();
    
    // Setup message queues
    await this.setupMessageQueues();
    
    // For Node.js environment, use @hono/node-server
    if (typeof Bun === 'undefined') {
      const { serve } = await import('@hono/node-server');
      const server = serve({
        fetch: this.app.fetch,
        port: this.config.port,
      }, (info) => {
        logger.info(`[${this.config.serviceName}] Node.js server v${this.config.version} running on port ${info.port}`);
        logger.info(`[${this.config.serviceName}] Available endpoints:`);
        logger.info('  - GET  /health');
        logger.info('  - GET  /ready');
        logger.info('  - GET  /metrics');
        logger.info('  Integration Management:');
        logger.info('  - GET    /api/integrations');
        logger.info('  - POST   /api/integrations');
        logger.info('  - GET    /api/integrations/:id');
        logger.info('  - PUT    /api/integrations/:id');
        logger.info('  - DELETE /api/integrations/:id');
        logger.info('  - POST   /api/integrations/:id/test');
        logger.info('  - GET    /api/integrations/:id/health');
        logger.info('  - POST   /api/integrations/:id/sync');
        logger.info('  Webhook Management:');
        logger.info('  - GET    /api/webhooks');
        logger.info('  - POST   /api/webhooks');
        logger.info('  - GET    /api/webhooks/:id');
        logger.info('  - PUT    /api/webhooks/:id');
        logger.info('  - DELETE /api/webhooks/:id');
        logger.info('  - POST   /api/webhooks/:id/test');
        logger.info('  - GET    /api/webhooks/:id/deliveries');
        logger.info('  OAuth2/SAML:');
        logger.info('  - GET    /api/oauth/providers');
        logger.info('  - GET    /api/oauth/authorize');
        logger.info('  - POST   /api/oauth/callback');
        logger.info('  - POST   /api/oauth/refresh');
        logger.info('  - GET    /api/oauth/saml/metadata');
        logger.info('  - POST   /api/oauth/saml/callback');
        logger.info('  Plugin System:');
        logger.info('  - GET    /api/plugins');
        logger.info('  - POST   /api/plugins');
        logger.info('  - GET    /api/plugins/:id');
        logger.info('  - PUT    /api/plugins/:id');
        logger.info('  - DELETE /api/plugins/:id');
        logger.info('  - POST   /api/plugins/:id/execute');
        logger.info('  Marketplace:');
        logger.info('  - GET    /api/marketplace');
        logger.info('  - GET    /api/marketplace/:id');
        logger.info('  - POST   /api/marketplace/:id/install');
        logger.info('  - POST   /api/marketplace/:id/review');
        logger.info('  API Gateway:');
        logger.info('  - *      /api/gateway/*');
      });
      
      // Store server reference for cleanup
      this.server = server;
    }
  }
}

// Initialize OpenTelemetry
async function initializeOpenTelemetry() {
  if (process.env.ENABLE_TRACING === 'true') {
    const { NodeSDK } = await import('@opentelemetry/sdk-node');
    const { getNodeAutoInstrumentations } = await import('@opentelemetry/auto-instrumentations-node');
    const { Resource } = await import('@opentelemetry/resources');
    const { SemanticResourceAttributes } = await import('@opentelemetry/semantic-conventions');
    const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-http');

    const traceExporter = new OTLPTraceExporter({
      url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces',
    });

    const sdk = new NodeSDK({
      resource: new Resource({
        [SemanticResourceAttributes.SERVICE_NAME]: 'integration-service',
        [SemanticResourceAttributes.SERVICE_VERSION]: process.env.npm_package_version || '1.0.0',
      }),
      traceExporter,
      instrumentations: [
        getNodeAutoInstrumentations({
          '@opentelemetry/instrumentation-fs': {
            enabled: false,
          },
        }),
      ],
    });

    await sdk.start();
    logger.info('OpenTelemetry initialized');
  }
}

// Create and start the service
async function main() {
  try {
    // Initialize OpenTelemetry
    await initializeOpenTelemetry();

    // Create and start the integration service
    const integrationService = new IntegrationServiceApp();
    await integrationService.start();
  } catch (error) {
    logger.error('Failed to start integration service:', error);
    process.exit(1);
  }
}

// Run the service
main();

// Export for testing
export default IntegrationServiceApp;