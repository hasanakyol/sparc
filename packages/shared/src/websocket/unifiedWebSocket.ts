import { Server as SocketIOServer, Socket, Namespace } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import { Redis } from 'ioredis';
import { createServer, Server as HTTPServer } from 'http';
import jwt from 'jsonwebtoken';
import { logger } from '../logger';
import { RateLimiter } from 'rate-limiter-flexible';
import { z } from 'zod';
import { EventEmitter } from 'events';

// WebSocket event schemas for validation
const WebSocketEventSchema = z.object({
  type: z.string(),
  data: z.any(),
  timestamp: z.string().datetime().optional(),
});

const SubscriptionSchema = z.object({
  channels: z.array(z.string()),
});

// Client metadata interface
interface ClientMetadata {
  id: string;
  userId: string;
  tenantId: string;
  organizationId?: string;
  roles: string[];
  subscriptions: Set<string>;
  isAlive: boolean;
  connectedAt: Date;
  lastActivity: Date;
}

// Namespace configuration
interface NamespaceConfig {
  name: string;
  middleware?: ((socket: Socket, next: (err?: Error) => void) => void)[];
  roomStrategy?: 'tenant' | 'organization' | 'custom';
  eventHandlers?: Record<string, (socket: Socket, data: any) => Promise<void>>;
  rateLimitOptions?: {
    points: number;
    duration: number;
  };
}

// WebSocket service configuration
export interface UnifiedWebSocketConfig {
  port?: number;
  jwtSecret: string;
  redisUrl: string;
  corsOrigins?: string[];
  pingInterval?: number;
  pingTimeout?: number;
  maxPayloadSize?: number;
  namespaces?: NamespaceConfig[];
}

export class UnifiedWebSocketService extends EventEmitter {
  private io: SocketIOServer;
  private httpServer: HTTPServer;
  private redis: Redis;
  private pubClient: Redis;
  private subClient: Redis;
  private namespaces: Map<string, Namespace> = new Map();
  private clients: Map<string, ClientMetadata> = new Map();
  private rateLimiters: Map<string, RateLimiter> = new Map();
  private heartbeatInterval?: NodeJS.Timer;
  private config: Required<UnifiedWebSocketConfig>;

  constructor(config: UnifiedWebSocketConfig) {
    super();
    
    // Set default configuration
    this.config = {
      port: config.port || 3100,
      jwtSecret: config.jwtSecret,
      redisUrl: config.redisUrl,
      corsOrigins: config.corsOrigins || ['http://localhost:3000'],
      pingInterval: config.pingInterval || 30000,
      pingTimeout: config.pingTimeout || 5000,
      maxPayloadSize: config.maxPayloadSize || 1048576, // 1MB
      namespaces: config.namespaces || [],
    };

    // Initialize Redis connections
    this.redis = new Redis(this.config.redisUrl);
    this.pubClient = this.redis.duplicate();
    this.subClient = this.redis.duplicate();

    // Create HTTP server
    this.httpServer = createServer();

    // Initialize Socket.IO with Redis adapter
    this.io = new SocketIOServer(this.httpServer, {
      cors: {
        origin: this.config.corsOrigins,
        methods: ['GET', 'POST'],
        credentials: true,
      },
      transports: ['websocket', 'polling'],
      maxHttpBufferSize: this.config.maxPayloadSize,
      pingInterval: this.config.pingInterval,
      pingTimeout: this.config.pingTimeout,
    });

    // Setup Redis adapter for horizontal scaling
    this.io.adapter(createAdapter(this.pubClient, this.subClient));

    // Setup default namespaces
    this.setupDefaultNamespaces();

    // Setup custom namespaces
    this.setupCustomNamespaces();

    // Setup global middleware
    this.setupGlobalMiddleware();

    // Setup heartbeat monitoring
    this.startHeartbeat();
  }

  private setupDefaultNamespaces(): void {
    // Video namespace
    this.createNamespace({
      name: 'video',
      roomStrategy: 'tenant',
      rateLimitOptions: { points: 100, duration: 60 },
      eventHandlers: {
        'stream:start': this.handleVideoStreamStart.bind(this),
        'stream:stop': this.handleVideoStreamStop.bind(this),
        'recording:start': this.handleRecordingStart.bind(this),
        'recording:stop': this.handleRecordingStop.bind(this),
      },
    });

    // Alerts namespace
    this.createNamespace({
      name: 'alerts',
      roomStrategy: 'tenant',
      rateLimitOptions: { points: 50, duration: 60 },
      eventHandlers: {
        'subscribe': this.handleAlertSubscribe.bind(this),
        'unsubscribe': this.handleAlertUnsubscribe.bind(this),
        'acknowledge': this.handleAlertAcknowledge.bind(this),
      },
    });

    // Monitoring namespace
    this.createNamespace({
      name: 'monitoring',
      roomStrategy: 'organization',
      rateLimitOptions: { points: 200, duration: 60 },
      eventHandlers: {
        'metrics:subscribe': this.handleMetricsSubscribe.bind(this),
        'events:subscribe': this.handleEventsSubscribe.bind(this),
      },
    });
  }

  private setupCustomNamespaces(): void {
    for (const nsConfig of this.config.namespaces) {
      this.createNamespace(nsConfig);
    }
  }

  private createNamespace(config: NamespaceConfig): Namespace {
    const namespace = this.io.of(`/${config.name}`);
    
    // Apply authentication middleware
    namespace.use(this.authMiddleware.bind(this));

    // Apply tenant validation middleware
    namespace.use(this.tenantValidationMiddleware.bind(this));

    // Apply custom middleware
    if (config.middleware) {
      for (const middleware of config.middleware) {
        namespace.use(middleware);
      }
    }

    // Setup rate limiting for this namespace
    if (config.rateLimitOptions) {
      const rateLimiter = new RateLimiter({
        storeClient: this.redis,
        points: config.rateLimitOptions.points,
        duration: config.rateLimitOptions.duration,
        keyPrefix: `ws:${config.name}`,
      });
      this.rateLimiters.set(config.name, rateLimiter);
    }

    // Handle connections
    namespace.on('connection', (socket) => {
      this.handleConnection(socket, config);
    });

    this.namespaces.set(config.name, namespace);
    logger.info(`WebSocket namespace created: /${config.name}`);

    return namespace;
  }

  private setupGlobalMiddleware(): void {
    // Global connection handling
    this.io.on('connection', (socket) => {
      logger.warn('Client connected to root namespace - redirecting', { socketId: socket.id });
      socket.emit('error', { message: 'Please connect to a specific namespace' });
      socket.disconnect();
    });
  }

  private async authMiddleware(socket: Socket, next: (err?: Error) => void): Promise<void> {
    try {
      // Extract token from handshake
      const token = socket.handshake.auth.token || socket.handshake.query.token as string;
      
      if (!token) {
        return next(new Error('Missing authentication token'));
      }

      // Verify JWT token
      const payload = jwt.verify(token, this.config.jwtSecret) as any;
      
      // Attach user data to socket
      socket.data.userId = payload.userId;
      socket.data.tenantId = payload.tenantId;
      socket.data.organizationId = payload.organizationId;
      socket.data.roles = payload.roles || [];

      next();
    } catch (error) {
      logger.error('WebSocket authentication failed', { error, socketId: socket.id });
      next(new Error('Authentication failed'));
    }
  }

  private async tenantValidationMiddleware(socket: Socket, next: (err?: Error) => void): Promise<void> {
    try {
      // Validate tenant exists and is active
      const tenantKey = `tenant:${socket.data.tenantId}:active`;
      const isActive = await this.redis.get(tenantKey);

      if (isActive === 'false') {
        return next(new Error('Tenant is not active'));
      }

      // Check tenant limits
      const limitsKey = `tenant:${socket.data.tenantId}:limits`;
      const limits = await this.redis.hgetall(limitsKey);

      if (limits.maxConnections) {
        const currentConnections = await this.redis.scard(`tenant:${socket.data.tenantId}:connections`);
        if (currentConnections >= parseInt(limits.maxConnections)) {
          return next(new Error('Connection limit exceeded'));
        }
      }

      next();
    } catch (error) {
      logger.error('Tenant validation failed', { error, socketId: socket.id });
      next(new Error('Tenant validation failed'));
    }
  }

  private async handleConnection(socket: Socket, config: NamespaceConfig): Promise<void> {
    const clientId = socket.id;
    const namespace = socket.nsp.name;

    // Create client metadata
    const client: ClientMetadata = {
      id: clientId,
      userId: socket.data.userId,
      tenantId: socket.data.tenantId,
      organizationId: socket.data.organizationId,
      roles: socket.data.roles,
      subscriptions: new Set(),
      isAlive: true,
      connectedAt: new Date(),
      lastActivity: new Date(),
    };

    this.clients.set(clientId, client);

    // Track connection in Redis
    await this.redis.sadd(`tenant:${client.tenantId}:connections`, clientId);
    await this.redis.sadd(`namespace:${namespace}:connections`, clientId);

    // Join default rooms based on strategy
    if (config.roomStrategy === 'tenant') {
      await socket.join(`tenant:${client.tenantId}`);
    } else if (config.roomStrategy === 'organization' && client.organizationId) {
      await socket.join(`org:${client.organizationId}`);
    }

    // Send welcome message
    socket.emit('connected', {
      clientId,
      namespace,
      tenantId: client.tenantId,
      timestamp: new Date().toISOString(),
    });

    // Setup event handlers
    this.setupSocketEventHandlers(socket, config);

    // Log connection
    logger.info('WebSocket client connected', {
      clientId,
      namespace,
      userId: client.userId,
      tenantId: client.tenantId,
    });

    // Emit connection event
    this.emit('client:connected', { client, namespace });
  }

  private setupSocketEventHandlers(socket: Socket, config: NamespaceConfig): void {
    // Rate limiting wrapper
    const withRateLimit = async (event: string, handler: Function) => {
      const namespace = socket.nsp.name.substring(1); // Remove leading slash
      const rateLimiter = this.rateLimiters.get(namespace);

      if (rateLimiter) {
        try {
          await rateLimiter.consume(`${socket.data.tenantId}:${socket.data.userId}`);
        } catch (error) {
          socket.emit('error', { message: 'Rate limit exceeded', event });
          return;
        }
      }

      await handler();
    };

    // Standard event handlers
    socket.on('ping', () => {
      socket.emit('pong', { timestamp: Date.now() });
    });

    socket.on('subscribe', async (data) => {
      await withRateLimit('subscribe', async () => {
        try {
          const validated = SubscriptionSchema.parse(data);
          await this.handleSubscribe(socket, validated.channels);
        } catch (error) {
          socket.emit('error', { message: 'Invalid subscription data', error });
        }
      });
    });

    socket.on('unsubscribe', async (data) => {
      await withRateLimit('unsubscribe', async () => {
        try {
          const validated = SubscriptionSchema.parse(data);
          await this.handleUnsubscribe(socket, validated.channels);
        } catch (error) {
          socket.emit('error', { message: 'Invalid unsubscription data', error });
        }
      });
    });

    // Custom event handlers
    if (config.eventHandlers) {
      for (const [event, handler] of Object.entries(config.eventHandlers)) {
        socket.on(event, async (data) => {
          await withRateLimit(event, async () => {
            try {
              await handler(socket, data);
              
              // Update last activity
              const client = this.clients.get(socket.id);
              if (client) {
                client.lastActivity = new Date();
              }
            } catch (error) {
              logger.error(`Error handling event ${event}`, { error, socketId: socket.id });
              socket.emit('error', { message: `Failed to handle ${event}`, error });
            }
          });
        });
      }
    }

    // Handle disconnection
    socket.on('disconnect', async (reason) => {
      await this.handleDisconnect(socket, reason);
    });

    // Handle errors
    socket.on('error', (error) => {
      logger.error('Socket error', { error, socketId: socket.id });
    });
  }

  private async handleSubscribe(socket: Socket, channels: string[]): Promise<void> {
    const client = this.clients.get(socket.id);
    if (!client) return;

    const authorizedChannels: string[] = [];

    for (const channel of channels) {
      if (await this.isAuthorizedForChannel(client, channel)) {
        await socket.join(channel);
        client.subscriptions.add(channel);
        authorizedChannels.push(channel);

        // Track subscription in Redis
        await this.redis.sadd(`channel:${channel}:subscribers`, socket.id);
      }
    }

    socket.emit('subscribed', {
      channels: authorizedChannels,
      timestamp: new Date().toISOString(),
    });

    logger.info('Client subscribed to channels', {
      socketId: socket.id,
      channels: authorizedChannels,
    });
  }

  private async handleUnsubscribe(socket: Socket, channels: string[]): Promise<void> {
    const client = this.clients.get(socket.id);
    if (!client) return;

    for (const channel of channels) {
      await socket.leave(channel);
      client.subscriptions.delete(channel);

      // Remove subscription from Redis
      await this.redis.srem(`channel:${channel}:subscribers`, socket.id);
    }

    socket.emit('unsubscribed', {
      channels,
      timestamp: new Date().toISOString(),
    });

    logger.info('Client unsubscribed from channels', {
      socketId: socket.id,
      channels,
    });
  }

  private async isAuthorizedForChannel(client: ClientMetadata, channel: string): Promise<boolean> {
    // Tenant-specific channels
    if (channel.startsWith('tenant:')) {
      const tenantId = channel.split(':')[1];
      return client.tenantId === tenantId;
    }

    // Organization-specific channels
    if (channel.startsWith('org:')) {
      const orgId = channel.split(':')[1];
      return client.organizationId === orgId;
    }

    // User-specific channels
    if (channel.startsWith('user:')) {
      const userId = channel.split(':')[1];
      return client.userId === userId;
    }

    // Role-based channels
    if (channel.startsWith('role:')) {
      const role = channel.split(':')[1];
      return client.roles.includes(role);
    }

    // Public channels (configurable)
    const publicChannels = ['system', 'announcements'];
    return publicChannels.includes(channel);
  }

  private async handleDisconnect(socket: Socket, reason: string): Promise<void> {
    const client = this.clients.get(socket.id);
    if (!client) return;

    // Remove from Redis sets
    await this.redis.srem(`tenant:${client.tenantId}:connections`, socket.id);
    await this.redis.srem(`namespace:${socket.nsp.name}:connections`, socket.id);

    // Remove subscriptions
    for (const channel of client.subscriptions) {
      await this.redis.srem(`channel:${channel}:subscribers`, socket.id);
    }

    // Remove from clients map
    this.clients.delete(socket.id);

    logger.info('WebSocket client disconnected', {
      socketId: socket.id,
      reason,
      userId: client.userId,
      tenantId: client.tenantId,
    });

    // Emit disconnection event
    this.emit('client:disconnected', { client, reason });
  }

  // Video namespace handlers
  private async handleVideoStreamStart(socket: Socket, data: any): Promise<void> {
    const { cameraId, quality } = data;
    
    // Validate camera access
    const hasAccess = await this.validateCameraAccess(socket.data.tenantId, cameraId);
    if (!hasAccess) {
      socket.emit('error', { message: 'Unauthorized camera access' });
      return;
    }

    // Join camera-specific room
    await socket.join(`camera:${cameraId}`);
    
    // Notify about stream start
    this.emit('video:stream:start', {
      socketId: socket.id,
      cameraId,
      quality,
      tenantId: socket.data.tenantId,
    });

    socket.emit('stream:started', { cameraId, quality });
  }

  private async handleVideoStreamStop(socket: Socket, data: any): Promise<void> {
    const { cameraId } = data;
    
    // Leave camera room
    await socket.leave(`camera:${cameraId}`);
    
    // Notify about stream stop
    this.emit('video:stream:stop', {
      socketId: socket.id,
      cameraId,
      tenantId: socket.data.tenantId,
    });

    socket.emit('stream:stopped', { cameraId });
  }

  private async handleRecordingStart(socket: Socket, data: any): Promise<void> {
    const { cameraId, duration } = data;
    
    // Validate permissions
    if (!socket.data.roles.includes('admin') && !socket.data.roles.includes('operator')) {
      socket.emit('error', { message: 'Insufficient permissions for recording' });
      return;
    }

    // Emit recording event
    this.emit('video:recording:start', {
      socketId: socket.id,
      cameraId,
      duration,
      tenantId: socket.data.tenantId,
    });

    socket.emit('recording:started', { cameraId, duration });
  }

  private async handleRecordingStop(socket: Socket, data: any): Promise<void> {
    const { cameraId } = data;
    
    // Emit recording stop event
    this.emit('video:recording:stop', {
      socketId: socket.id,
      cameraId,
      tenantId: socket.data.tenantId,
    });

    socket.emit('recording:stopped', { cameraId });
  }

  // Alert namespace handlers
  private async handleAlertSubscribe(socket: Socket, data: any): Promise<void> {
    const { alertTypes, priorities } = data;
    
    // Join alert-specific rooms
    if (alertTypes) {
      for (const type of alertTypes) {
        await socket.join(`alerts:type:${type}`);
      }
    }
    
    if (priorities) {
      for (const priority of priorities) {
        await socket.join(`alerts:priority:${priority}`);
      }
    }

    socket.emit('alerts:subscribed', { alertTypes, priorities });
  }

  private async handleAlertUnsubscribe(socket: Socket, data: any): Promise<void> {
    const { alertTypes, priorities } = data;
    
    // Leave alert-specific rooms
    if (alertTypes) {
      for (const type of alertTypes) {
        await socket.leave(`alerts:type:${type}`);
      }
    }
    
    if (priorities) {
      for (const priority of priorities) {
        await socket.leave(`alerts:priority:${priority}`);
      }
    }

    socket.emit('alerts:unsubscribed', { alertTypes, priorities });
  }

  private async handleAlertAcknowledge(socket: Socket, data: any): Promise<void> {
    const { alertId } = data;
    
    // Emit acknowledgment event
    this.emit('alert:acknowledged', {
      alertId,
      userId: socket.data.userId,
      tenantId: socket.data.tenantId,
      timestamp: new Date().toISOString(),
    });

    // Broadcast to relevant rooms
    this.io.of('/alerts')
      .to(`tenant:${socket.data.tenantId}`)
      .emit('alert:acknowledged', { alertId, userId: socket.data.userId });
  }

  // Monitoring namespace handlers
  private async handleMetricsSubscribe(socket: Socket, data: any): Promise<void> {
    const { metrics, interval } = data;
    
    // Join metric-specific rooms
    for (const metric of metrics) {
      await socket.join(`metrics:${metric}`);
    }

    // Store subscription preferences
    await this.redis.hset(
      `metrics:subscriptions:${socket.id}`,
      'metrics', JSON.stringify(metrics),
      'interval', interval.toString()
    );

    socket.emit('metrics:subscribed', { metrics, interval });
  }

  private async handleEventsSubscribe(socket: Socket, data: any): Promise<void> {
    const { eventTypes } = data;
    
    // Join event-specific rooms
    for (const eventType of eventTypes) {
      await socket.join(`events:${eventType}`);
    }

    socket.emit('events:subscribed', { eventTypes });
  }

  // Utility methods
  private async validateCameraAccess(tenantId: string, cameraId: string): Promise<boolean> {
    // Check if camera belongs to tenant
    const cameraKey = `camera:${cameraId}:tenant`;
    const cameraTenantId = await this.redis.get(cameraKey);
    
    return cameraTenantId === tenantId;
  }

  // Public broadcasting methods
  public async broadcast(namespace: string, room: string, event: string, data: any): Promise<void> {
    const ns = this.namespaces.get(namespace);
    if (!ns) {
      logger.error('Namespace not found for broadcast', { namespace });
      return;
    }

    const payload = {
      timestamp: new Date().toISOString(),
      event,
      data,
    };

    ns.to(room).emit(event, payload);

    // Also publish to Redis for other instances
    await this.pubClient.publish(
      `broadcast:${namespace}:${room}:${event}`,
      JSON.stringify(payload)
    );
  }

  public async broadcastToTenant(tenantId: string, namespace: string, event: string, data: any): Promise<void> {
    await this.broadcast(namespace, `tenant:${tenantId}`, event, data);
  }

  public async broadcastToOrganization(orgId: string, namespace: string, event: string, data: any): Promise<void> {
    await this.broadcast(namespace, `org:${orgId}`, event, data);
  }

  public async broadcastToUser(userId: string, namespace: string, event: string, data: any): Promise<void> {
    await this.broadcast(namespace, `user:${userId}`, event, data);
  }

  // Heartbeat monitoring
  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(async () => {
      const now = Date.now();

      for (const [socketId, client] of this.clients) {
        if (!client.isAlive) {
          // Client didn't respond to last ping - disconnect
          const socket = this.io.sockets.sockets.get(socketId);
          if (socket) {
            socket.disconnect();
          }
          continue;
        }

        // Mark as not alive and send ping
        client.isAlive = false;
        const socket = this.io.sockets.sockets.get(socketId);
        if (socket) {
          socket.emit('ping', { timestamp: now });
        }
      }

      // Clean up stale Redis entries
      await this.cleanupStaleConnections();
    }, this.config.pingInterval);
  }

  private async cleanupStaleConnections(): Promise<void> {
    // Get all namespaces
    for (const [name, namespace] of this.namespaces) {
      const key = `namespace:/${name}:connections`;
      const connections = await this.redis.smembers(key);

      for (const socketId of connections) {
        if (!this.clients.has(socketId)) {
          // Remove stale connection
          await this.redis.srem(key, socketId);
        }
      }
    }
  }

  // Lifecycle methods
  public async start(): Promise<void> {
    return new Promise((resolve) => {
      this.httpServer.listen(this.config.port, () => {
        logger.info(`Unified WebSocket service started on port ${this.config.port}`);
        resolve();
      });
    });
  }

  public async stop(): Promise<void> {
    // Clear heartbeat interval
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    // Disconnect all clients
    this.io.disconnectSockets();

    // Close server
    return new Promise((resolve) => {
      this.httpServer.close(() => {
        // Close Redis connections
        this.redis.disconnect();
        this.pubClient.disconnect();
        this.subClient.disconnect();

        logger.info('Unified WebSocket service stopped');
        resolve();
      });
    });
  }

  // Getters
  public getConnectedClients(): ClientMetadata[] {
    return Array.from(this.clients.values());
  }

  public getNamespaces(): string[] {
    return Array.from(this.namespaces.keys());
  }

  public async getMetrics(): Promise<Record<string, any>> {
    const metrics: Record<string, any> = {
      totalClients: this.clients.size,
      namespaces: {},
    };

    for (const [name, namespace] of this.namespaces) {
      const sockets = await namespace.fetchSockets();
      metrics.namespaces[name] = {
        connectedClients: sockets.length,
      };
    }

    return metrics;
  }
}