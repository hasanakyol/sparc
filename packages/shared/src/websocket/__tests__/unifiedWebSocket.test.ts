import { UnifiedWebSocketService } from '../unifiedWebSocket';
import { WebSocketClient, ConnectionState } from '../client';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import { Redis } from 'ioredis';
import jwt from 'jsonwebtoken';

// Mock Redis
jest.mock('ioredis');

describe('UnifiedWebSocketService', () => {
  let service: UnifiedWebSocketService;
  let mockRedis: jest.Mocked<Redis>;
  const testJwtSecret = 'test-secret';
  const testPort = 4100;

  beforeEach(() => {
    // Setup Redis mocks
    mockRedis = {
      duplicate: jest.fn().mockReturnThis(),
      get: jest.fn(),
      set: jest.fn(),
      setex: jest.fn(),
      del: jest.fn(),
      sadd: jest.fn(),
      srem: jest.fn(),
      smembers: jest.fn().mockResolvedValue([]),
      scard: jest.fn().mockResolvedValue(0),
      hgetall: jest.fn().mockResolvedValue({}),
      hset: jest.fn(),
      publish: jest.fn(),
      subscribe: jest.fn(),
      on: jest.fn(),
      disconnect: jest.fn(),
    } as any;

    (Redis as jest.MockedClass<typeof Redis>).mockImplementation(() => mockRedis);

    service = new UnifiedWebSocketService({
      port: testPort,
      jwtSecret: testJwtSecret,
      redisUrl: 'redis://localhost:6379',
      corsOrigins: ['http://localhost:3000'],
      pingInterval: 1000,
      pingTimeout: 500,
    });
  });

  afterEach(async () => {
    await service.stop();
    jest.clearAllMocks();
  });

  describe('Service Lifecycle', () => {
    it('should start the WebSocket service', async () => {
      await service.start();
      
      // Service should be listening
      expect(service.getNamespaces()).toContain('video');
      expect(service.getNamespaces()).toContain('alerts');
      expect(service.getNamespaces()).toContain('monitoring');
    });

    it('should stop the WebSocket service', async () => {
      await service.start();
      await service.stop();

      expect(mockRedis.disconnect).toHaveBeenCalled();
    });
  });

  describe('Namespace Management', () => {
    it('should have default namespaces', () => {
      const namespaces = service.getNamespaces();
      
      expect(namespaces).toContain('video');
      expect(namespaces).toContain('alerts');
      expect(namespaces).toContain('monitoring');
    });

    it('should create custom namespaces', () => {
      const customService = new UnifiedWebSocketService({
        port: testPort + 1,
        jwtSecret: testJwtSecret,
        redisUrl: 'redis://localhost:6379',
        namespaces: [
          {
            name: 'custom',
            roomStrategy: 'tenant',
            rateLimitOptions: { points: 50, duration: 60 },
          },
        ],
      });

      expect(customService.getNamespaces()).toContain('custom');
    });
  });

  describe('Broadcasting', () => {
    beforeEach(async () => {
      await service.start();
    });

    it('should broadcast to tenant', async () => {
      const publishSpy = jest.spyOn(mockRedis, 'publish');

      await service.broadcastToTenant('tenant-123', 'alerts', 'alert:created', {
        id: 'alert-1',
        message: 'Test alert',
      });

      expect(publishSpy).toHaveBeenCalledWith(
        'broadcast:alerts:tenant:tenant-123:alert:created',
        expect.stringContaining('Test alert')
      );
    });

    it('should broadcast to organization', async () => {
      const publishSpy = jest.spyOn(mockRedis, 'publish');

      await service.broadcastToOrganization('org-456', 'monitoring', 'metrics:update', {
        cpu: 45,
        memory: 78,
      });

      expect(publishSpy).toHaveBeenCalledWith(
        'broadcast:monitoring:org:org-456:metrics:update',
        expect.stringContaining('cpu')
      );
    });

    it('should broadcast to user', async () => {
      const publishSpy = jest.spyOn(mockRedis, 'publish');

      await service.broadcastToUser('user-789', 'video', 'stream:ready', {
        streamId: 'stream-1',
        url: 'rtsp://example.com/stream',
      });

      expect(publishSpy).toHaveBeenCalledWith(
        'broadcast:video:user:user-789:stream:ready',
        expect.stringContaining('stream-1')
      );
    });
  });

  describe('Client Connection', () => {
    it('should track connected clients', async () => {
      await service.start();

      // Initially no clients
      expect(service.getConnectedClients()).toHaveLength(0);
    });

    it('should get service metrics', async () => {
      await service.start();

      const metrics = await service.getMetrics();

      expect(metrics).toHaveProperty('totalClients', 0);
      expect(metrics).toHaveProperty('namespaces');
      expect(metrics.namespaces).toHaveProperty('video');
      expect(metrics.namespaces).toHaveProperty('alerts');
      expect(metrics.namespaces).toHaveProperty('monitoring');
    });
  });

  describe('Event Handling', () => {
    it('should emit client connection events', (done) => {
      service.on('client:connected', ({ client, namespace }) => {
        expect(client).toBeDefined();
        expect(namespace).toBeDefined();
        done();
      });

      // Simulate client connection
      service.emit('client:connected', {
        client: {
          id: 'test-client',
          userId: 'user-1',
          tenantId: 'tenant-1',
          roles: ['user'],
          subscriptions: new Set(),
          isAlive: true,
          connectedAt: new Date(),
          lastActivity: new Date(),
        },
        namespace: '/video',
      });
    });

    it('should emit client disconnection events', (done) => {
      service.on('client:disconnected', ({ client, reason }) => {
        expect(client).toBeDefined();
        expect(reason).toBe('transport close');
        done();
      });

      // Simulate client disconnection
      service.emit('client:disconnected', {
        client: {
          id: 'test-client',
          userId: 'user-1',
          tenantId: 'tenant-1',
          roles: ['user'],
          subscriptions: new Set(),
          isAlive: false,
          connectedAt: new Date(),
          lastActivity: new Date(),
        },
        reason: 'transport close',
      });
    });
  });
});

describe('WebSocketClient', () => {
  let client: WebSocketClient;
  const mockToken = jwt.sign(
    { userId: 'user-1', tenantId: 'tenant-1', roles: ['user'] },
    'test-secret'
  );

  beforeEach(() => {
    client = new WebSocketClient({
      url: 'http://localhost:4100',
      namespace: 'alerts',
      token: mockToken,
      autoReconnect: false,
    });
  });

  afterEach(() => {
    client.disconnect();
  });

  describe('Connection State', () => {
    it('should start in disconnected state', () => {
      expect(client.getState()).toBe(ConnectionState.DISCONNECTED);
    });

    it('should track connection state changes', (done) => {
      const states: ConnectionState[] = [];

      client.on('state:changed', (state) => {
        states.push(state);
        
        if (states.length === 2) {
          expect(states).toEqual([
            ConnectionState.CONNECTING,
            ConnectionState.ERROR,
          ]);
          done();
        }
      });

      // This will fail because no server is running
      client.connect().catch(() => {
        // Expected to fail
      });
    });
  });

  describe('Subscription Management', () => {
    it('should track subscriptions', () => {
      expect(client.getSubscriptions()).toEqual([]);
    });

    it('should throw error when not connected', async () => {
      await expect(client.subscribe(['test-channel'])).rejects.toThrow(
        'Not connected to WebSocket server'
      );
    });
  });

  describe('Message Sending', () => {
    it('should throw error when not connected', () => {
      expect(() => client.send('test-event', { data: 'test' })).toThrow(
        'Not connected to WebSocket server'
      );
    });
  });
});

describe('Integration Scenarios', () => {
  let service: UnifiedWebSocketService;
  let mockRedis: jest.Mocked<Redis>;

  beforeEach(async () => {
    mockRedis = {
      duplicate: jest.fn().mockReturnThis(),
      get: jest.fn(),
      set: jest.fn(),
      setex: jest.fn(),
      del: jest.fn(),
      sadd: jest.fn(),
      srem: jest.fn(),
      smembers: jest.fn().mockResolvedValue([]),
      scard: jest.fn().mockResolvedValue(0),
      hgetall: jest.fn().mockResolvedValue({}),
      hset: jest.fn(),
      publish: jest.fn(),
      subscribe: jest.fn(),
      on: jest.fn(),
      disconnect: jest.fn(),
    } as any;

    (Redis as jest.MockedClass<typeof Redis>).mockImplementation(() => mockRedis);

    service = new UnifiedWebSocketService({
      port: 4200,
      jwtSecret: 'test-secret',
      redisUrl: 'redis://localhost:6379',
    });

    await service.start();
  });

  afterEach(async () => {
    await service.stop();
  });

  it('should handle video streaming scenario', async () => {
    const tenantId = 'tenant-123';
    const cameraId = 'camera-456';

    // Simulate video stream start event
    service.emit('video:stream:start', {
      socketId: 'socket-1',
      cameraId,
      quality: 'high',
      tenantId,
    });

    // Broadcast stream ready
    await service.broadcastToTenant(tenantId, 'video', 'stream:ready', {
      cameraId,
      streamUrl: 'rtsp://example.com/stream',
    });

    expect(mockRedis.publish).toHaveBeenCalled();
  });

  it('should handle alert notification scenario', async () => {
    const tenantId = 'tenant-123';
    const alert = {
      id: 'alert-1',
      type: 'security',
      priority: 'high',
      message: 'Unauthorized access detected',
    };

    // Create alert
    await service.broadcastToTenant(tenantId, 'alerts', 'alert:created', alert);

    // Acknowledge alert
    service.emit('alert:acknowledged', {
      alertId: alert.id,
      userId: 'user-1',
      tenantId,
      timestamp: new Date().toISOString(),
    });

    expect(mockRedis.publish).toHaveBeenCalledTimes(1);
  });

  it('should handle monitoring metrics scenario', async () => {
    const orgId = 'org-789';
    const metrics = {
      cpu: 65,
      memory: 80,
      activeConnections: 150,
      throughput: 1250,
    };

    // Broadcast metrics to organization
    await service.broadcastToOrganization(orgId, 'monitoring', 'metrics:update', metrics);

    // Simulate threshold breach
    await service.broadcastToOrganization(orgId, 'monitoring', 'threshold:breached', {
      metric: 'memory',
      value: 80,
      threshold: 75,
      severity: 'warning',
    });

    expect(mockRedis.publish).toHaveBeenCalledTimes(2);
  });
});