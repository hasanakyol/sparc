import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import alertsRouter from './routes/alerts';
import webhooksRouter from './routes/webhooks';
import notificationsRouter from './routes/notifications';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import Redis from 'ioredis';
import { EscalationService } from './services/escalation.service';
import { checkDatabaseHealth, closeDatabaseConnection } from './db';
import { trace } from '@opentelemetry/api';
import { logger } from '@sparc/shared';

// OpenTelemetry tracer
const tracer = trace.getTracer('alert-service');

class AlertService extends MicroserviceBase {
  private io: SocketIOServer | null = null;
  private httpServer: any = null;
  private escalationService: EscalationService | null = null;
  private broadcastSubscriber: Redis | null = null;

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'alert-service',
      port: config.services?.alert?.port || 3008,
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
    this.app.route('/api/alerts', alertsRouter);
    this.app.route('/api/webhooks', webhooksRouter);
    this.app.route('/api/notifications', notificationsRouter);

    // Additional error handling specific to alert service
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
      // Check database health
      checks.database = await checkDatabaseHealth();
      
      // Check if escalation service is running
      checks.escalationService = this.escalationService !== null;
      
      // Check Socket.IO server
      checks.websocket = this.io !== null;
      
      // Check notification services
      try {
        // Email service check (simplified)
        checks.emailService = !!config.notifications?.smtp?.host;
        
        // SMS service check (simplified)
        checks.smsService = !!config.notifications?.twilio?.accountSid;
        
        // Push notification check (simplified)
        checks.pushService = !!config.notifications?.webpush?.publicKey;
      } catch {
        checks.notificationServices = false;
      }
    } catch (error) {
      console.error('Health check error:', error);
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const span = tracer.startSpan('getMetrics');
    
    try {
      // Return Prometheus-formatted metrics
      const metrics: string[] = [];
      
      // Add alert-specific metrics
      metrics.push('# HELP alerts_total Total number of alerts created');
      metrics.push('# TYPE alerts_total counter');
      
      metrics.push('# HELP alerts_by_status Current alerts by status');
      metrics.push('# TYPE alerts_by_status gauge');
      
      metrics.push('# HELP alerts_by_priority Current alerts by priority');
      metrics.push('# TYPE alerts_by_priority gauge');
      
      metrics.push('# HELP alert_escalations_total Total number of alert escalations');
      metrics.push('# TYPE alert_escalations_total counter');
      
      metrics.push('# HELP notifications_sent_total Total notifications sent by type');
      metrics.push('# TYPE notifications_sent_total counter');
      
      metrics.push('# HELP webhook_events_processed_total Total webhook events processed');
      metrics.push('# TYPE webhook_events_processed_total counter');
      
      // Get actual metrics from Redis if available
      try {
        // Aggregate metrics across all tenants (simplified for now)
        const alertsTotal = await this.redis.get('metrics:alerts:total') || '0';
        metrics.push(`alerts_total ${alertsTotal}`);
        
        const escalationsTotal = await this.redis.get('metrics:escalations:total') || '0';
        metrics.push(`alert_escalations_total ${escalationsTotal}`);
        
        const notificationsTotal = await this.redis.get('metrics:notifications:total') || '0';
        metrics.push(`notifications_sent_total ${notificationsTotal}`);
        
        const webhooksTotal = await this.redis.get('metrics:webhooks:total') || '0';
        metrics.push(`webhook_events_processed_total ${webhooksTotal}`);
      } catch (error) {
        console.error('Failed to get metrics from Redis:', error);
      }
      
      return metrics.join('\n');
    } finally {
      span.end();
    }
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up alert service resources...');
    
    // Stop escalation service
    if (this.escalationService) {
      this.escalationService.stop();
    }
    
    // Close Socket.IO connections
    if (this.io) {
      this.io.close();
    }
    
    // Close HTTP server
    if (this.httpServer) {
      this.httpServer.close();
    }
    
    // Close broadcast subscriber
    if (this.broadcastSubscriber) {
      await this.broadcastSubscriber.quit();
    }
    
    // Close database connection
    await closeDatabaseConnection();
  }

  private setupSocketIO(): void {
    // Create HTTP server
    this.httpServer = createServer();
    
    // Create Socket.IO server
    this.io = new SocketIOServer(this.httpServer, {
      cors: {
        origin: this.config.corsOrigins,
        methods: ['GET', 'POST'],
        credentials: true,
      },
    });

    // Socket.IO connection handling
    this.io.on('connection', (socket) => {
      logger.info('Client connected', { socketId: socket.id });

      socket.on('join-tenant', (tenantId: string) => {
        socket.join(`tenant:${tenantId}`);
        logger.info('Client joined tenant room', { socketId: socket.id, tenantId });
      });

      socket.on('leave-tenant', (tenantId: string) => {
        socket.leave(`tenant:${tenantId}`);
        logger.info('Client left tenant room', { socketId: socket.id, tenantId });
      });

      socket.on('disconnect', () => {
        logger.info('Client disconnected', { socketId: socket.id });
      });
    });

    // Start Socket.IO server on a different port
    const wsPort = this.config.port + 1;
    this.httpServer.listen(wsPort, () => {
      console.log(`[${this.config.serviceName}] WebSocket server running on port ${wsPort}`);
    });
  }

  private setupBroadcastSubscriber(): void {
    // Create a separate Redis connection for subscriptions
    this.broadcastSubscriber = new Redis(this.config.redisUrl);

    // Subscribe to alert broadcast channel
    this.broadcastSubscriber.subscribe('alert:broadcast', 'escalation:cancel');

    this.broadcastSubscriber.on('message', (channel, message) => {
      if (channel === 'alert:broadcast') {
        try {
          const data = JSON.parse(message);
          const { action, tenantId, alert, alertId } = data;

          // Broadcast to Socket.IO clients
          if (this.io) {
            this.io.to(`tenant:${tenantId}`).emit(`alert:${action}`, action === 'deleted' ? { alertId } : alert);
          }

          // Update metrics
          if (action === 'created') {
            this.redis.incr('metrics:alerts:total');
          }
        } catch (error) {
          logger.error('Failed to process broadcast message', { error, message });
        }
      } else if (channel === 'escalation:cancel' && this.escalationService) {
        // Cancel escalation for the alert
        this.escalationService.cancelEscalation(message);
      }
    });
  }

  public async start(): Promise<void> {
    // Call parent start to initialize everything
    await super.start();
    
    // Initialize escalation service
    this.escalationService = new EscalationService(this.redis);
    this.escalationService.start();
    
    // Setup Socket.IO server
    this.setupSocketIO();
    
    // Setup broadcast subscriber
    this.setupBroadcastSubscriber();
    
    // For Node.js environment, use @hono/node-server
    if (typeof Bun === 'undefined') {
      const { serve } = await import('@hono/node-server');
      const server = serve({
        fetch: this.app.fetch,
        port: this.config.port,
      }, (info) => {
        console.log(`[${this.config.serviceName}] Node.js server v${this.config.version} running on port ${info.port}`);
        console.log(`[${this.config.serviceName}] Available endpoints:`);
        console.log('  - GET  /health');
        console.log('  - GET  /ready');
        console.log('  - GET  /metrics');
        console.log('  - GET  /api/alerts');
        console.log('  - POST /api/alerts');
        console.log('  - GET  /api/alerts/:id');
        console.log('  - PUT  /api/alerts/:id');
        console.log('  - DELETE /api/alerts/:id');
        console.log('  - POST /api/alerts/:id/acknowledge');
        console.log('  - GET  /api/alerts/stats');
        console.log('  - POST /api/webhooks/events');
        console.log('  - POST /api/webhooks/environmental');
        console.log('  - GET  /api/notifications/preferences');
        console.log('  - PUT  /api/notifications/preferences');
        console.log(`  - WebSocket on port ${info.port + 1}`);
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
        [SemanticResourceAttributes.SERVICE_NAME]: 'alert-service',
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
    console.log('OpenTelemetry initialized');
  }
}

// Create and start the service
async function main() {
  try {
    // Initialize OpenTelemetry
    await initializeOpenTelemetry();

    // Create and start the alert service
    const alertService = new AlertService();
    await alertService.start();
  } catch (error) {
    console.error('Failed to start alert service:', error);
    process.exit(1);
  }
}

// Run the service
main();

// Export for testing
export default AlertService;