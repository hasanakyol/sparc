import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import visitorsRouter from './routes/visitors';
import badgesRouter from './routes/badges';
import watchlistRouter from './routes/watchlist';
import credentialsRouter from './routes/credentials';
import groupsRouter from './routes/groups';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import Redis from 'ioredis';
import { checkDatabaseHealth, closeDatabaseConnection } from './db';
import { trace } from '@opentelemetry/api';
import { logger } from '@sparc/shared';

// OpenTelemetry tracer
const tracer = trace.getTracer('visitor-management-service');

class VisitorManagementService extends MicroserviceBase {
  private io: SocketIOServer | null = null;
  private httpServer: any = null;
  private eventSubscriber: Redis | null = null;

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'visitor-management-service',
      port: config.services?.visitorManagement?.port || 3006,
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
    this.app.route('/api/visitors', visitorsRouter);
    this.app.route('/api/badges', badgesRouter);
    this.app.route('/api/watchlist', watchlistRouter);
    this.app.route('/api/credentials', credentialsRouter);
    this.app.route('/api/groups', groupsRouter);

    // Add Redis instance to context for routes
    this.app.use('*', async (c, next) => {
      c.set('redis', this.redis);
      await next();
    });

    // Additional error handling specific to visitor management
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
      
      // Check Socket.IO server
      checks.websocket = this.io !== null;
      
      // Check notification services
      try {
        // Email service check
        checks.emailService = !!config.notifications?.smtp?.host;
        
        // SMS service check
        checks.smsService = !!config.notifications?.twilio?.accountSid;
      } catch {
        checks.notificationServices = false;
      }

      // Check badge printing capability
      checks.badgeService = true; // Would check actual printer connection in production
      
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
      
      // Add visitor-specific metrics
      metrics.push('# HELP visitors_total Total number of visitors registered');
      metrics.push('# TYPE visitors_total counter');
      
      metrics.push('# HELP visitors_active Current active visitors on-site');
      metrics.push('# TYPE visitors_active gauge');
      
      metrics.push('# HELP visitors_checked_in_total Total check-ins');
      metrics.push('# TYPE visitors_checked_in_total counter');
      
      metrics.push('# HELP visitors_checked_out_total Total check-outs');
      metrics.push('# TYPE visitors_checked_out_total counter');
      
      metrics.push('# HELP visitor_overstays Current visitors who overstayed');
      metrics.push('# TYPE visitor_overstays gauge');
      
      metrics.push('# HELP badges_printed_total Total badges printed');
      metrics.push('# TYPE badges_printed_total counter');
      
      metrics.push('# HELP watchlist_checks_total Total watchlist checks performed');
      metrics.push('# TYPE watchlist_checks_total counter');
      
      metrics.push('# HELP watchlist_matches_total Total watchlist matches');
      metrics.push('# TYPE watchlist_matches_total counter');
      
      metrics.push('# HELP credential_validations_total Total credential validations');
      metrics.push('# TYPE credential_validations_total counter');
      
      metrics.push('# HELP credential_validation_failures_total Failed credential validations');
      metrics.push('# TYPE credential_validation_failures_total counter');
      
      // Get actual metrics from Redis if available
      try {
        const visitorsTotal = await this.redis.get('metrics:visitors:total') || '0';
        metrics.push(`visitors_total ${visitorsTotal}`);
        
        const activeVisitors = await this.redis.get('metrics:visitors:active') || '0';
        metrics.push(`visitors_active ${activeVisitors}`);
        
        const checkInsTotal = await this.redis.get('metrics:visitors:checkins') || '0';
        metrics.push(`visitors_checked_in_total ${checkInsTotal}`);
        
        const checkOutsTotal = await this.redis.get('metrics:visitors:checkouts') || '0';
        metrics.push(`visitors_checked_out_total ${checkOutsTotal}`);
        
        const overstays = await this.redis.get('metrics:visitors:overstays') || '0';
        metrics.push(`visitor_overstays ${overstays}`);
        
        const badgesPrinted = await this.redis.get('metrics:badges:printed') || '0';
        metrics.push(`badges_printed_total ${badgesPrinted}`);
        
        const watchlistChecks = await this.redis.get('metrics:watchlist:checks') || '0';
        metrics.push(`watchlist_checks_total ${watchlistChecks}`);
        
        const watchlistMatches = await this.redis.get('metrics:watchlist:matches') || '0';
        metrics.push(`watchlist_matches_total ${watchlistMatches}`);
        
        const credentialValidations = await this.redis.get('metrics:credentials:validations') || '0';
        metrics.push(`credential_validations_total ${credentialValidations}`);
        
        const credentialFailures = await this.redis.get('metrics:credentials:failures') || '0';
        metrics.push(`credential_validation_failures_total ${credentialFailures}`);
      } catch (error) {
        console.error('Failed to get metrics from Redis:', error);
      }
      
      return metrics.join('\n');
    } finally {
      span.end();
    }
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up visitor management service resources...');
    
    // Close Socket.IO connections
    if (this.io) {
      this.io.close();
    }
    
    // Close HTTP server
    if (this.httpServer) {
      this.httpServer.close();
    }
    
    // Close event subscriber
    if (this.eventSubscriber) {
      await this.eventSubscriber.quit();
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

      socket.on('join-organization', (organizationId: string) => {
        socket.join(`org:${organizationId}`);
        logger.info('Client joined organization room', { socketId: socket.id, organizationId });
      });

      socket.on('leave-organization', (organizationId: string) => {
        socket.leave(`org:${organizationId}`);
        logger.info('Client left organization room', { socketId: socket.id, organizationId });
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

  private setupEventSubscriber(): void {
    // Create a separate Redis connection for subscriptions
    this.eventSubscriber = new Redis(this.config.redisUrl);

    // Subscribe to visitor events channel
    this.eventSubscriber.subscribe('visitor:events');

    this.eventSubscriber.on('message', (channel, message) => {
      if (channel === 'visitor:events') {
        try {
          const event = JSON.parse(message);
          const { type, organizationId, data } = event;

          // Broadcast to Socket.IO clients
          if (this.io) {
            this.io.to(`org:${organizationId}`).emit(type, data);
          }

          // Update metrics based on event type
          switch (type) {
            case 'visitor:checked-in':
              this.redis.incr('metrics:visitors:checkins');
              this.redis.incr('metrics:visitors:active');
              break;
            case 'visitor:checked-out':
              this.redis.incr('metrics:visitors:checkouts');
              this.redis.decr('metrics:visitors:active');
              break;
            case 'visitor:created':
              this.redis.incr('metrics:visitors:total');
              break;
          }
        } catch (error) {
          logger.error('Failed to process event message', { error, message });
        }
      }
    });
  }

  public async start(): Promise<void> {
    // Call parent start to initialize everything
    await super.start();
    
    // Setup Socket.IO server
    this.setupSocketIO();
    
    // Setup event subscriber
    this.setupEventSubscriber();
    
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
        console.log('  - POST /api/visitors/pre-register');
        console.log('  - POST /api/visitors/check-in');
        console.log('  - POST /api/visitors/:id/check-out');
        console.log('  - GET  /api/visitors');
        console.log('  - GET  /api/visitors/:id');
        console.log('  - PUT  /api/visitors/:id');
        console.log('  - POST /api/visitors/:id/approval');
        console.log('  - GET  /api/visitors/active/all');
        console.log('  - GET  /api/visitors/overstay/all');
        console.log('  - GET  /api/visitors/analytics/summary');
        console.log('  - GET  /api/visitors/emergency/evacuation');
        console.log('  - POST /api/badges/print');
        console.log('  - GET  /api/badges/print/:visitorId/pdf');
        console.log('  - POST /api/badges/:visitorId/reprint');
        console.log('  - POST /api/badges/preview');
        console.log('  - GET  /api/badges/templates');
        console.log('  - POST /api/badges/batch-print');
        console.log('  - POST /api/watchlist/check');
        console.log('  - POST /api/watchlist');
        console.log('  - PUT  /api/watchlist/:id');
        console.log('  - DELETE /api/watchlist/:id');
        console.log('  - GET  /api/watchlist');
        console.log('  - GET  /api/watchlist/stats');
        console.log('  - POST /api/watchlist/bulk-check');
        console.log('  - POST /api/watchlist/import');
        console.log('  - GET  /api/watchlist/export');
        console.log('  - POST /api/credentials/validate');
        console.log('  - GET  /api/credentials/visitor/:visitorId');
        console.log('  - POST /api/credentials/:id/revoke');
        console.log('  - GET  /api/credentials/access-logs');
        console.log('  - POST /api/credentials/mobile');
        console.log('  - GET  /api/credentials/stats');
        console.log('  - POST /api/groups');
        console.log('  - GET  /api/groups/:id');
        console.log('  - GET  /api/groups');
        console.log('  - POST /api/groups/:id/check-in');
        console.log('  - POST /api/groups/:id/check-out');
        console.log('  - POST /api/groups/:id/members');
        console.log('  - DELETE /api/groups/:groupId/members/:visitorId');
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
        [SemanticResourceAttributes.SERVICE_NAME]: 'visitor-management-service',
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

    // Create and start the visitor management service
    const visitorManagementService = new VisitorManagementService();
    await visitorManagementService.start();
  } catch (error) {
    console.error('Failed to start visitor management service:', error);
    process.exit(1);
  }
}

// Run the service
main();

// Export for testing
export default VisitorManagementService;