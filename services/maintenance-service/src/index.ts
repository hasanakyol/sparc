import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import Redis from 'ioredis';
import { trace } from '@opentelemetry/api';
import { logger } from '@sparc/shared';

// Import routers
import workOrdersRouter from './routes/work-orders';
import preventiveMaintenanceRouter from './routes/preventive-maintenance';
import inventoryRouter from './routes/inventory';
import diagnosticsRouter from './routes/diagnostics';
import analyticsRouter from './routes/analytics';
import slaRouter from './routes/sla';
import iotRouter from './routes/iot';

// Import services
import { PreventiveMaintenanceService } from './services/preventive-maintenance.service';
import { SlaMonitoringService } from './services/sla-monitoring.service';
import { PredictiveMaintenanceService } from './services/predictive-maintenance.service';
import { NotificationService } from './services/notification.service';

// Import database
import { checkDatabaseHealth, closeDatabaseConnection } from './db';

// OpenTelemetry tracer
const tracer = trace.getTracer('maintenance-service');

class MaintenanceService extends MicroserviceBase {
  private io: SocketIOServer | null = null;
  private httpServer: any = null;
  private preventiveMaintenanceService: PreventiveMaintenanceService | null = null;
  private slaMonitoringService: SlaMonitoringService | null = null;
  private predictiveMaintenanceService: PredictiveMaintenanceService | null = null;
  private notificationService: NotificationService | null = null;
  private broadcastSubscriber: Redis | null = null;

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'maintenance-service',
      port: config.services?.maintenance?.port || 3007,
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
    this.app.route('/api/work-orders', workOrdersRouter);
    this.app.route('/api/preventive-maintenance', preventiveMaintenanceRouter);
    this.app.route('/api/inventory', inventoryRouter);
    this.app.route('/api/diagnostics', diagnosticsRouter);
    this.app.route('/api/analytics', analyticsRouter);
    this.app.route('/api/sla', slaRouter);
    this.app.route('/api/iot', iotRouter);

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
      // Check database health
      checks.database = await checkDatabaseHealth();
      
      // Check if background services are running
      checks.preventiveMaintenanceService = this.preventiveMaintenanceService !== null && this.preventiveMaintenanceService.isRunning();
      checks.slaMonitoringService = this.slaMonitoringService !== null && this.slaMonitoringService.isRunning();
      checks.predictiveMaintenanceService = this.predictiveMaintenanceService !== null && this.predictiveMaintenanceService.isRunning();
      
      // Check Socket.IO server
      checks.websocket = this.io !== null;
      
      // Check notification service
      checks.notificationService = this.notificationService !== null && await this.notificationService.isHealthy();
      
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
      
      // Add maintenance-specific metrics
      metrics.push('# HELP work_orders_total Total number of work orders created');
      metrics.push('# TYPE work_orders_total counter');
      
      metrics.push('# HELP work_orders_by_status Current work orders by status');
      metrics.push('# TYPE work_orders_by_status gauge');
      
      metrics.push('# HELP work_orders_by_priority Current work orders by priority');
      metrics.push('# TYPE work_orders_by_priority gauge');
      
      metrics.push('# HELP preventive_maintenance_generated Total preventive maintenance work orders generated');
      metrics.push('# TYPE preventive_maintenance_generated counter');
      
      metrics.push('# HELP sla_violations_total Total SLA violations');
      metrics.push('# TYPE sla_violations_total counter');
      
      metrics.push('# HELP parts_usage_total Total parts used');
      metrics.push('# TYPE parts_usage_total counter');
      
      metrics.push('# HELP maintenance_costs_total Total maintenance costs');
      metrics.push('# TYPE maintenance_costs_total counter');
      
      metrics.push('# HELP predictive_alerts_total Total predictive maintenance alerts');
      metrics.push('# TYPE predictive_alerts_total counter');
      
      // Get actual metrics from Redis if available
      try {
        const workOrdersTotal = await this.redis.get('metrics:work_orders:total') || '0';
        metrics.push(`work_orders_total ${workOrdersTotal}`);
        
        const pmGenerated = await this.redis.get('metrics:pm:generated') || '0';
        metrics.push(`preventive_maintenance_generated ${pmGenerated}`);
        
        const slaViolations = await this.redis.get('metrics:sla:violations') || '0';
        metrics.push(`sla_violations_total ${slaViolations}`);
        
        const partsUsage = await this.redis.get('metrics:parts:usage') || '0';
        metrics.push(`parts_usage_total ${partsUsage}`);
        
        const maintenanceCosts = await this.redis.get('metrics:costs:total') || '0';
        metrics.push(`maintenance_costs_total ${maintenanceCosts}`);
        
        const predictiveAlerts = await this.redis.get('metrics:predictive:alerts') || '0';
        metrics.push(`predictive_alerts_total ${predictiveAlerts}`);
        
      } catch (error) {
        console.error('Failed to get metrics from Redis:', error);
      }
      
      return metrics.join('\n');
    } finally {
      span.end();
    }
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up maintenance service resources...');
    
    // Stop background services
    if (this.preventiveMaintenanceService) {
      await this.preventiveMaintenanceService.stop();
    }
    
    if (this.slaMonitoringService) {
      await this.slaMonitoringService.stop();
    }
    
    if (this.predictiveMaintenanceService) {
      await this.predictiveMaintenanceService.stop();
    }
    
    if (this.notificationService) {
      await this.notificationService.stop();
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

      socket.on('join-work-order', (workOrderId: string) => {
        socket.join(`work-order:${workOrderId}`);
        logger.info('Client joined work order room', { socketId: socket.id, workOrderId });
      });

      socket.on('leave-work-order', (workOrderId: string) => {
        socket.leave(`work-order:${workOrderId}`);
        logger.info('Client left work order room', { socketId: socket.id, workOrderId });
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

    // Subscribe to maintenance-related channels
    this.broadcastSubscriber.subscribe(
      'maintenance:work-order:update',
      'maintenance:sla:violation',
      'maintenance:predictive:alert',
      'maintenance:inventory:low'
    );

    this.broadcastSubscriber.on('message', (channel, message) => {
      try {
        const data = JSON.parse(message);
        
        switch (channel) {
          case 'maintenance:work-order:update':
            this.handleWorkOrderUpdate(data);
            break;
          case 'maintenance:sla:violation':
            this.handleSlaViolation(data);
            break;
          case 'maintenance:predictive:alert':
            this.handlePredictiveAlert(data);
            break;
          case 'maintenance:inventory:low':
            this.handleInventoryAlert(data);
            break;
        }
      } catch (error) {
        logger.error('Failed to process broadcast message', { error, channel, message });
      }
    });
  }

  private handleWorkOrderUpdate(data: any): void {
    const { action, tenantId, workOrder } = data;
    
    if (this.io) {
      // Broadcast to tenant
      this.io.to(`tenant:${tenantId}`).emit(`work-order:${action}`, workOrder);
      
      // Broadcast to work order room
      if (workOrder.id) {
        this.io.to(`work-order:${workOrder.id}`).emit(`work-order:${action}`, workOrder);
      }
    }
    
    // Update metrics
    if (action === 'created') {
      this.redis.incr('metrics:work_orders:total');
    }
  }

  private handleSlaViolation(data: any): void {
    const { tenantId, workOrderId, violation } = data;
    
    if (this.io) {
      this.io.to(`tenant:${tenantId}`).emit('sla:violation', { workOrderId, violation });
    }
    
    // Update metrics
    this.redis.incr('metrics:sla:violations');
  }

  private handlePredictiveAlert(data: any): void {
    const { tenantId, deviceId, alert } = data;
    
    if (this.io) {
      this.io.to(`tenant:${tenantId}`).emit('predictive:alert', { deviceId, alert });
    }
    
    // Update metrics
    this.redis.incr('metrics:predictive:alerts');
  }

  private handleInventoryAlert(data: any): void {
    const { tenantId, part, alert } = data;
    
    if (this.io) {
      this.io.to(`tenant:${tenantId}`).emit('inventory:alert', { part, alert });
    }
  }

  public async start(): Promise<void> {
    // Call parent start to initialize everything
    await super.start();
    
    // Initialize services
    this.notificationService = new NotificationService(this.redis);
    await this.notificationService.start();
    
    this.preventiveMaintenanceService = new PreventiveMaintenanceService(this.redis, this.notificationService);
    await this.preventiveMaintenanceService.start();
    
    this.slaMonitoringService = new SlaMonitoringService(this.redis, this.notificationService);
    await this.slaMonitoringService.start();
    
    this.predictiveMaintenanceService = new PredictiveMaintenanceService(this.redis, this.notificationService);
    await this.predictiveMaintenanceService.start();
    
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
        console.log('  - Work Orders:');
        console.log('    - GET    /api/work-orders');
        console.log('    - POST   /api/work-orders');
        console.log('    - GET    /api/work-orders/:id');
        console.log('    - PUT    /api/work-orders/:id');
        console.log('    - DELETE /api/work-orders/:id');
        console.log('    - POST   /api/work-orders/:id/assign');
        console.log('    - POST   /api/work-orders/:id/complete');
        console.log('  - Preventive Maintenance:');
        console.log('    - GET    /api/preventive-maintenance/schedules');
        console.log('    - POST   /api/preventive-maintenance/schedules');
        console.log('    - POST   /api/preventive-maintenance/generate');
        console.log('  - Inventory:');
        console.log('    - GET    /api/inventory/parts');
        console.log('    - POST   /api/inventory/parts');
        console.log('    - POST   /api/inventory/parts/:id/usage');
        console.log('  - Diagnostics:');
        console.log('    - POST   /api/diagnostics/:deviceId/run');
        console.log('    - GET    /api/diagnostics/:deviceId/history');
        console.log('  - Analytics:');
        console.log('    - GET    /api/analytics/overview');
        console.log('    - GET    /api/analytics/costs');
        console.log('    - GET    /api/analytics/performance');
        console.log('  - SLA:');
        console.log('    - GET    /api/sla/configs');
        console.log('    - POST   /api/sla/configs');
        console.log('    - GET    /api/sla/violations');
        console.log('  - IoT:');
        console.log('    - POST   /api/iot/metrics');
        console.log('    - GET    /api/iot/metrics/:deviceId');
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
        [SemanticResourceAttributes.SERVICE_NAME]: 'maintenance-service',
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

    // Create and start the maintenance service
    const maintenanceService = new MaintenanceService();
    await maintenanceService.start();
  } catch (error) {
    console.error('Failed to start maintenance service:', error);
    process.exit(1);
  }
}

// Run the service
main();

// Export for testing
export default MaintenanceService;