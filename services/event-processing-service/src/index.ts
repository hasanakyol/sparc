import { MicroserviceBase } from '@sparc/shared/microservice-base';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import Redis from 'ioredis';
import { createUnifiedRoutes } from './routes/unified-routes';
import { UnifiedEventService } from './services/unified-event-service';
import { logger } from '@sparc/shared';

class EventProcessingService extends MicroserviceBase {
  private io?: SocketIOServer;
  private eventService?: UnifiedEventService;
  private redisSubscriber?: Redis;

  constructor() {
    super('event-processing-service', {
      port: parseInt(process.env.PORT || '3010', 10)
    });
  }

  protected async setupRoutes(): Promise<void> {
    // Initialize Redis clients
    const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
    const pubClient = redis.duplicate();
    const subClient = redis.duplicate();
    this.redisSubscriber = redis.duplicate();

    // Create HTTP server
    const httpServer = createServer(this.app.fetch);

    // Initialize Socket.IO with Redis adapter
    this.io = new SocketIOServer(httpServer, {
      path: '/ws',
      cors: {
        origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
        credentials: true
      },
      transports: ['websocket', 'polling']
    });

    // Set up Redis adapter for Socket.IO
    this.io.adapter(createAdapter(pubClient, subClient));

    // Initialize unified event service
    this.eventService = new UnifiedEventService(redis, this.redisSubscriber, this.io);

    // Set up Socket.IO namespaces and middleware
    this.setupSocketIO();

    // Set up HTTP routes
    const unifiedRoutes = createUnifiedRoutes(this.eventService);
    this.app.route('/api', unifiedRoutes);

    // Health check specific to this service
    this.app.get('/health/detailed', (c) => {
      return c.json({
        service: this.serviceName,
        status: 'healthy',
        processing: this.eventService?.isProcessing() || false,
        timestamp: new Date().toISOString()
      });
    });

    // Start event processing
    await this.eventService.startProcessing();
    logger.info('Event processing service initialized');
  }

  private setupSocketIO(): void {
    if (!this.io) return;

    // Authentication middleware
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.query.token;
        
        if (!token) {
          return next(new Error('Authentication required'));
        }

        // Validate token and extract tenant ID
        // In production, validate JWT and extract claims
        const tenantId = socket.handshake.auth.tenantId || socket.handshake.query.tenantId;
        
        if (!tenantId) {
          return next(new Error('Tenant ID required'));
        }

        // Attach metadata to socket
        (socket as any).tenantId = tenantId;
        (socket as any).userId = socket.handshake.auth.userId;

        next();
      } catch (error) {
        next(new Error('Authentication failed'));
      }
    });

    // Connection handling
    this.io.on('connection', (socket) => {
      const tenantId = (socket as any).tenantId;
      const userId = (socket as any).userId;

      logger.info('WebSocket client connected', { 
        socketId: socket.id, 
        tenantId,
        userId 
      });

      // Join tenant room
      socket.join(`tenant:${tenantId}`);

      // Join user-specific room if authenticated
      if (userId) {
        socket.join(`user:${userId}`);
      }

      // Handle subscription to specific locations
      socket.on('subscribe:building', (buildingId: string) => {
        socket.join(`building:${tenantId}:${buildingId}`);
        logger.debug('Client subscribed to building', { 
          socketId: socket.id, 
          buildingId 
        });
      });

      socket.on('subscribe:floor', ({ buildingId, floorId }: { buildingId: string; floorId: string }) => {
        socket.join(`floor:${tenantId}:${buildingId}:${floorId}`);
        logger.debug('Client subscribed to floor', { 
          socketId: socket.id, 
          buildingId,
          floorId 
        });
      });

      socket.on('unsubscribe:building', (buildingId: string) => {
        socket.leave(`building:${tenantId}:${buildingId}`);
      });

      socket.on('unsubscribe:floor', ({ buildingId, floorId }: { buildingId: string; floorId: string }) => {
        socket.leave(`floor:${tenantId}:${buildingId}:${floorId}`);
      });

      // Handle disconnection
      socket.on('disconnect', (reason) => {
        logger.info('WebSocket client disconnected', { 
          socketId: socket.id, 
          reason 
        });
      });

      // Send acknowledgment
      socket.emit('connected', { 
        message: 'Connected to event processing service',
        socketId: socket.id
      });
    });

    // Set up namespaces for different event types
    const alertNamespace = this.io.of('/alerts');
    const eventNamespace = this.io.of('/events');

    // Alert namespace handling
    alertNamespace.use(async (socket, next) => {
      // Same auth as main namespace
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Authentication required'));
      }
      next();
    });

    alertNamespace.on('connection', (socket) => {
      logger.info('Client connected to alerts namespace', { 
        socketId: socket.id 
      });
    });

    // Event namespace handling
    eventNamespace.use(async (socket, next) => {
      // Same auth as main namespace
      const token = socket.handshake.auth.token;
      if (!token) {
        return next(new Error('Authentication required'));
      }
      next();
    });

    eventNamespace.on('connection', (socket) => {
      logger.info('Client connected to events namespace', { 
        socketId: socket.id 
      });
    });
  }

  protected async cleanup(): Promise<void> {
    // Stop event processing
    if (this.eventService) {
      await this.eventService.stopProcessing();
    }

    // Close Socket.IO
    if (this.io) {
      await new Promise<void>((resolve) => {
        this.io!.close(() => {
          logger.info('Socket.IO server closed');
          resolve();
        });
      });
    }

    // Close Redis connections
    if (this.redisSubscriber) {
      await this.redisSubscriber.quit();
    }

    await super.cleanup();
  }
}

// Start the service
const service = new EventProcessingService();
service.start();