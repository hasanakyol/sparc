import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import Redis from 'ioredis';
import { createEventRoutes } from './routes/events';
import { createAlertRoutes } from './routes/alerts';
import { createNotificationRoutes } from './routes/notifications';
import { EventProcessingService } from './services/event-processing-service';
import { AlertService } from './services/alert-service';
import { NotificationService } from './services/notification-service';

// Service-specific configuration interface
interface EventProcessingConfig extends ServiceConfig {
  redisStreamPrefix: string;
  correlationInterval: number;
  eventRetentionHours: number;
  smtpHost?: string;
  smtpPort?: number;
  smtpUser?: string;
  smtpPassword?: string;
  twilioAccountSid?: string;
  twilioAuthToken?: string;
  twilioFromNumber?: string;
  vapidPublicKey?: string;
  vapidPrivateKey?: string;
  vapidSubject?: string;
}

class EventProcessingMicroservice extends MicroserviceBase {
  private httpServer: any;
  private io: SocketIOServer;
  private redisSubscriber: Redis;
  private eventService: EventProcessingService;
  private alertService: AlertService;
  private notificationService: NotificationService;

  constructor(config: EventProcessingConfig) {
    super(config);
    
    // Create HTTP server for Socket.IO
    this.httpServer = createServer();
    
    // Initialize Socket.IO
    this.io = new SocketIOServer(this.httpServer, {
      cors: {
        origin: config.corsOrigins || ['http://localhost:3000'],
        credentials: true
      }
    });
    
    // Create Redis subscriber
    this.redisSubscriber = new Redis(config.redisUrl);
    
    // Initialize services
    this.notificationService = new NotificationService(this.redis, {
      smtp: {
        host: config.smtpHost,
        port: config.smtpPort,
        user: config.smtpUser,
        password: config.smtpPassword
      },
      twilio: {
        accountSid: config.twilioAccountSid,
        authToken: config.twilioAuthToken,
        fromNumber: config.twilioFromNumber
      },
      webPush: {
        publicKey: config.vapidPublicKey,
        privateKey: config.vapidPrivateKey,
        subject: config.vapidSubject
      }
    });
    
    this.alertService = new AlertService(this.prisma, this.redis, this.notificationService);
    this.eventService = new EventProcessingService(
      this.prisma, 
      this.redis, 
      this.redisSubscriber,
      this.io,
      this.alertService
    );
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    // Check Socket.IO server
    checks.socketio = this.io.engine.clientsCount >= 0;
    
    // Check Redis subscriber
    try {
      await this.redisSubscriber.ping();
      checks.redisSubscriber = true;
    } catch {
      checks.redisSubscriber = false;
    }
    
    // Check event processing status
    checks.eventProcessing = this.eventService.isProcessing();
    
    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const metrics: string[] = [];
    
    // Socket.IO metrics
    metrics.push(`# HELP socketio_clients Number of connected Socket.IO clients`);
    metrics.push(`# TYPE socketio_clients gauge`);
    metrics.push(`socketio_clients ${this.io.engine.clientsCount}`);
    
    // Event metrics
    const eventStats = await this.eventService.getStats();
    metrics.push(`# HELP events_processed_total Total number of events processed`);
    metrics.push(`# TYPE events_processed_total counter`);
    metrics.push(`events_processed_total{type="access"} ${eventStats.access}`);
    metrics.push(`events_processed_total{type="video"} ${eventStats.video}`);
    metrics.push(`events_processed_total{type="environmental"} ${eventStats.environmental}`);
    
    // Alert metrics
    const alertStats = await this.alertService.getStats();
    metrics.push(`# HELP alerts_total Total number of alerts generated`);
    metrics.push(`# TYPE alerts_total counter`);
    metrics.push(`alerts_total ${alertStats.total}`);
    metrics.push(`# HELP alerts_active Number of active alerts`);
    metrics.push(`# TYPE alerts_active gauge`);
    metrics.push(`alerts_active ${alertStats.active}`);
    
    return metrics.join('\n');
  }

  public setupRoutes(): void {
    // Mount route modules
    const eventRoutes = createEventRoutes(this.eventService);
    const alertRoutes = createAlertRoutes(this.alertService);
    const notificationRoutes = createNotificationRoutes(this.notificationService);

    this.app.route('/api/events', eventRoutes);
    this.app.route('/api/alerts', alertRoutes);
    this.app.route('/api/notifications', notificationRoutes);

    // Socket.IO info endpoint
    this.app.get('/ws/info', (c) => {
      return c.json({
        wsUrl: `ws://localhost:${this.config.port}`,
        protocol: 'socket.io',
        events: [
          'access_event',
          'video_event',
          'environmental_event',
          'alert',
          'alert_update'
        ]
      });
    });
  }

  public async start(): Promise<void> {
    // Setup Socket.IO authentication and event handlers
    this.setupSocketIO();
    
    // Start event processing
    await this.eventService.startProcessing();
    
    // Start HTTP server for Socket.IO
    this.httpServer.listen(this.config.port + 100, () => {
      console.log(`[${this.config.serviceName}] Socket.IO server listening on port ${this.config.port + 100}`);
    });
    
    // Start main HTTP server
    await super.start();
  }

  private setupSocketIO(): void {
    // Authentication middleware
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token;
        const tenantId = socket.handshake.auth.tenantId;
        
        if (!token || !tenantId) {
          return next(new Error('Authentication required'));
        }
        
        // Verify JWT token (simplified for demo)
        // In production, verify with auth service
        socket.data.tenantId = tenantId;
        socket.data.userId = socket.handshake.auth.userId;
        
        next();
      } catch (error) {
        next(new Error('Authentication failed'));
      }
    });

    // Connection handler
    this.io.on('connection', (socket) => {
      const { tenantId, userId } = socket.data;
      console.log(`[${this.config.serviceName}] Client connected: ${socket.id} (tenant: ${tenantId})`);
      
      // Join tenant room
      socket.join(`tenant_${tenantId}`);
      
      // Handle subscriptions
      socket.on('subscribe:building', (buildingId: string) => {
        socket.join(`building_${tenantId}_${buildingId}`);
        console.log(`Client ${socket.id} subscribed to building: ${buildingId}`);
      });
      
      socket.on('unsubscribe:building', (buildingId: string) => {
        socket.leave(`building_${tenantId}_${buildingId}`);
        console.log(`Client ${socket.id} unsubscribed from building: ${buildingId}`);
      });
      
      socket.on('subscribe:floor', ({ buildingId, floorId }: { buildingId: string; floorId: string }) => {
        socket.join(`floor_${tenantId}_${buildingId}_${floorId}`);
        console.log(`Client ${socket.id} subscribed to floor: ${buildingId}/${floorId}`);
      });
      
      socket.on('unsubscribe:floor', ({ buildingId, floorId }: { buildingId: string; floorId: string }) => {
        socket.leave(`floor_${tenantId}_${buildingId}_${floorId}`);
        console.log(`Client ${socket.id} unsubscribed from floor: ${buildingId}/${floorId}`);
      });
      
      // Handle alert acknowledgment
      socket.on('acknowledge:alert', async (alertId: string) => {
        try {
          await this.alertService.acknowledgeAlert(alertId, userId, tenantId);
          socket.emit('alert:acknowledged', { alertId, success: true });
        } catch (error) {
          socket.emit('alert:acknowledged', { alertId, success: false, error: error.message });
        }
      });
      
      // Handle alert resolution
      socket.on('resolve:alert', async (alertId: string) => {
        try {
          await this.alertService.resolveAlert(alertId, userId, tenantId);
          socket.emit('alert:resolved', { alertId, success: true });
        } catch (error) {
          socket.emit('alert:resolved', { alertId, success: false, error: error.message });
        }
      });
      
      socket.on('disconnect', () => {
        console.log(`[${this.config.serviceName}] Client disconnected: ${socket.id}`);
      });
    });
  }

  protected async cleanup(): Promise<void> {
    // Stop event processing
    await this.eventService.stopProcessing();
    
    // Close Socket.IO
    this.io.close();
    
    // Close HTTP server
    if (this.httpServer) {
      this.httpServer.close();
    }
    
    // Close Redis subscriber
    await this.redisSubscriber.quit();
  }
}

// Configuration
const config: EventProcessingConfig = {
  serviceName: 'event-processing-service',
  port: parseInt(process.env.PORT || '3005'),
  version: process.env.SERVICE_VERSION || '1.0.0',
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/sparc',
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  redisStreamPrefix: process.env.REDIS_STREAM_PREFIX || 'sparc:events',
  correlationInterval: parseInt(process.env.CORRELATION_INTERVAL || '5000'), // 5 seconds
  eventRetentionHours: parseInt(process.env.EVENT_RETENTION_HOURS || '24'),
  smtpHost: process.env.SMTP_HOST,
  smtpPort: parseInt(process.env.SMTP_PORT || '587'),
  smtpUser: process.env.SMTP_USER,
  smtpPassword: process.env.SMTP_PASSWORD,
  twilioAccountSid: process.env.TWILIO_ACCOUNT_SID,
  twilioAuthToken: process.env.TWILIO_AUTH_TOKEN,
  twilioFromNumber: process.env.TWILIO_FROM_NUMBER,
  vapidPublicKey: process.env.VAPID_PUBLIC_KEY,
  vapidPrivateKey: process.env.VAPID_PRIVATE_KEY,
  vapidSubject: process.env.VAPID_SUBJECT || 'mailto:admin@sparc.com',
  enableMetrics: true
};

// Create and start the service
const service = new EventProcessingMicroservice(config);
service.start().catch(console.error);

export default service;