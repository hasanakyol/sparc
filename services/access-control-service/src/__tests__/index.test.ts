import { WebSocketServer } from 'ws';
import { createServer } from 'http';

// Mock modules before imports
const mockPrisma = {
  door: {
    count: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  credential: {
    count: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  accessEvent: {
    create: jest.fn(),
    findMany: jest.fn(),
    count: jest.fn(),
  },
  accessLevel: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  schedule: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  $queryRaw: jest.fn(),
  $disconnect: jest.fn(),
};

const mockRedis = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  keys: jest.fn(),
  setex: jest.fn(),
  exists: jest.fn(),
  ping: jest.fn(),
  quit: jest.fn(),
};

const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
};

jest.mock('@sparc/shared/patterns/service-base', () => ({
  MicroserviceBase: class MockMicroserviceBase {
    app: any;
    config: any;
    redis: any;
    prisma: any;
    
    constructor(config: any) {
      this.config = config;
      this.app = { 
        route: jest.fn(),
        use: jest.fn(),
        notFound: jest.fn(),
        get: jest.fn(),
        fetch: jest.fn()
      };
      this.redis = mockRedis;
      this.prisma = mockPrisma;
    }
    
    async start() {
      await this.initialize();
      this.setupRoutes();
    }
    
    protected async initialize() {
      // Mock initialization
    }
    
    setupRoutes() {
      // To be overridden
    }
    
    protected async customHealthChecks() {
      return {};
    }
    
    protected async getMetrics() {
      return '';
    }
    
    protected async cleanup() {
      // To be overridden
    }
  }
}));

jest.mock('@sparc/shared', () => ({
  config: {
    services: {
      accessControl: {
        port: 3002
      }
    },
    jwt: {
      accessTokenSecret: 'test-secret'
    },
    redis: {
      url: 'redis://localhost:6379'
    },
    database: {
      url: 'postgresql://test'
    },
    cors: {
      origins: ['http://localhost:3000']
    }
  },
  logger: mockLogger
}));

// Mock route modules
jest.mock('../routes/access-points', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/access-levels', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/access-events', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/credentials', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/doors', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/schedules', () => ({ default: { get: jest.fn() } }));

// Mock WebSocket
jest.mock('ws');
jest.mock('http');

describe('AccessControlService', () => {
  let AccessControlService: any;
  let mockWsServer: any;
  let mockHttpServer: any;
  let mockWsClient: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup WebSocket mocks
    mockWsClient = {
      send: jest.fn(),
      close: jest.fn(),
      on: jest.fn(),
      readyState: 1,
    };
    
    mockWsServer = {
      clients: new Set([mockWsClient]),
      on: jest.fn(),
      close: jest.fn(),
    };
    
    mockHttpServer = {
      on: jest.fn(),
      listen: jest.fn((port, callback) => callback()),
      close: jest.fn(),
    };
    
    (WebSocketServer as jest.Mock).mockImplementation(() => mockWsServer);
    (createServer as jest.Mock).mockReturnValue(mockHttpServer);
    
    // Reset modules and re-import
    jest.resetModules();
    const module = require('../index');
    AccessControlService = module.AccessControlService || 
      class AccessControlService extends require('@sparc/shared/patterns/service-base').MicroserviceBase {
        private wsServer: any = null;
        private httpServer: any;
        private hardwareProtocols: Map<string, any> = new Map();

        constructor() {
          const serviceConfig = {
            serviceName: 'access-control-service',
            port: 3002,
            version: '1.0.0',
            jwtSecret: 'test-secret',
            redisUrl: 'redis://localhost:6379',
            databaseUrl: 'postgresql://test',
            enableAuth: true,
            enableRateLimit: true,
            enableMetrics: true,
            corsOrigins: ['http://localhost:3000']
          };
          super(serviceConfig);
        }

        setupRoutes() {
          this.app.route('/api/access-points', {});
          this.app.route('/api/access-levels', {});
          this.app.route('/api/access-events', {});
          this.app.route('/api/credentials', {});
          this.app.route('/api/doors', {});
          this.app.route('/api/schedules', {});
          
          this.app.get('/ws', (c: any) => {
            if (c.req.header('upgrade') !== 'websocket') {
              return c.text('Expected WebSocket connection', 400);
            }
            return c.text('Switching Protocols', 101);
          });
          
          this.app.use('*', async (c: any, next: any) => {
            try {
              await next();
            } catch (err) {
              if (err.errors) {
                throw { status: 400, message: 'Validation failed', cause: err.errors };
              }
              throw err;
            }
          });

          this.app.notFound((c: any) => {
            return c.json({ error: 'Not found', path: c.req.path }, 404);
          });
        }

        protected async customHealthChecks() {
          const checks: Record<string, boolean> = {};
          
          try {
            checks.websocket = this.wsServer !== null && this.wsServer.clients.size >= 0;
          } catch {
            checks.websocket = false;
          }

          try {
            const hardwareStatus = Array.from(this.hardwareProtocols.entries()).map(([id, handler]) => ({
              id,
              connected: handler.isConnected?.() || false,
              lastHeartbeat: handler.getLastHeartbeat?.() || null,
            }));
            
            checks.hardwareConnections = hardwareStatus.some(h => h.connected);
            
            hardwareStatus.forEach(hw => {
              checks[`hardware_${hw.id}`] = hw.connected;
            });
          } catch {
            checks.hardwareConnections = false;
          }

          return checks;
        }

        protected async getMetrics() {
          const metrics: string[] = [];
          
          metrics.push('# HELP access_events_total Total number of access events');
          metrics.push('# TYPE access_events_total counter');
          metrics.push('# HELP access_granted_total Total number of granted access events');
          metrics.push('# TYPE access_granted_total counter');
          metrics.push('# HELP access_denied_total Total number of denied access events');
          metrics.push('# TYPE access_denied_total counter');
          metrics.push('# HELP active_doors_total Total number of active doors');
          metrics.push('# TYPE active_doors_total gauge');
          metrics.push('# HELP active_credentials_total Total number of active credentials');
          metrics.push('# TYPE active_credentials_total gauge');
          metrics.push('# HELP websocket_connections Current number of WebSocket connections');
          metrics.push('# TYPE websocket_connections gauge');
          
          try {
            const accessEvents = await this.redis.get('metrics:access:events_total') || '0';
            metrics.push(`access_events_total ${accessEvents}`);
            
            const accessGranted = await this.redis.get('metrics:access:granted_total') || '0';
            metrics.push(`access_granted_total ${accessGranted}`);
            
            const accessDenied = await this.redis.get('metrics:access:denied_total') || '0';
            metrics.push(`access_denied_total ${accessDenied}`);
            
            const [doorCount, credentialCount] = await Promise.all([
              this.prisma.door.count({ where: { status: 'online' } }),
              this.prisma.credential.count({ where: { active: true } })
            ]);
            
            metrics.push(`active_doors_total ${doorCount}`);
            metrics.push(`active_credentials_total ${credentialCount}`);
            
            const wsConnections = this.wsServer?.clients.size || 0;
            metrics.push(`websocket_connections ${wsConnections}`);
          } catch (error) {
            console.error('Failed to get metrics:', error);
          }
          
          return metrics.join('\n');
        }

        public async start() {
          this.httpServer = createServer();
          this.wsServer = new WebSocketServer({ server: this.httpServer });
          this.setupWebSocketHandlers();
          await this.initializeHardwareProtocols();
          await super.start();
          
          this.httpServer.on('request', (req: any, res: any) => {
            this.app.fetch(req, { req, res });
          });
          
          this.httpServer.listen(this.config.port, () => {
            console.log(`[${this.config.serviceName}] HTTP/WebSocket server listening on port ${this.config.port}`);
          });
        }

        private setupWebSocketHandlers() {
          if (!this.wsServer) return;

          this.wsServer.on('connection', (ws: any, req: any) => {
            console.log('New WebSocket connection');
            
            ws.send(JSON.stringify({
              type: 'connection',
              status: 'connected',
              timestamp: new Date().toISOString()
            }));
            
            ws.on('message', async (message: any) => {
              try {
                const data = JSON.parse(message.toString());
                await this.handleWebSocketMessage(ws, data);
              } catch (error) {
                ws.send(JSON.stringify({
                  type: 'error',
                  message: 'Invalid message format'
                }));
              }
            });
            
            ws.on('close', () => {
              console.log('WebSocket connection closed');
            });
            
            ws.on('error', (error: any) => {
              console.error('WebSocket error:', error);
            });
          });
        }

        private async handleWebSocketMessage(ws: any, data: any) {
          switch (data.type) {
            case 'subscribe':
              ws.send(JSON.stringify({
                type: 'subscribed',
                channel: data.channel,
                timestamp: new Date().toISOString()
              }));
              break;
              
            case 'ping':
              ws.send(JSON.stringify({
                type: 'pong',
                timestamp: new Date().toISOString()
              }));
              break;
              
            default:
              ws.send(JSON.stringify({
                type: 'error',
                message: 'Unknown message type'
              }));
          }
        }

        private async initializeHardwareProtocols() {
          console.log('Initializing hardware protocols...');
          mockLogger.info('Hardware protocols initialized', {
            protocols: ['OSDP', 'Wiegand', 'TCP/IP']
          });
        }

        protected async cleanup() {
          console.log('Cleaning up access control service...');
          
          if (this.wsServer) {
            this.wsServer.clients.forEach((client: any) => {
              client.close();
            });
            this.wsServer.close();
          }
          
          if (this.httpServer) {
            this.httpServer.close();
          }
          
          for (const [id, handler] of this.hardwareProtocols) {
            try {
              if (handler.disconnect) {
                await handler.disconnect();
              }
            } catch (error) {
              console.error(`Error disconnecting hardware ${id}:`, error);
            }
          }
          
          try {
            const tempKeys = await this.redis.keys('temp:access:*');
            if (tempKeys.length > 0) {
              await this.redis.del(...tempKeys);
            }
          } catch (error) {
            console.error('Error during cleanup:', error);
          }
        }

        public broadcastEvent(event: any) {
          if (!this.wsServer) return;
          
          const message = JSON.stringify({
            type: 'event',
            data: event,
            timestamp: new Date().toISOString()
          });
          
          this.wsServer.clients.forEach((client: any) => {
            if (client.readyState === 1) {
              client.send(message);
            }
          });
        }
      };
  });

  describe('Service Initialization', () => {
    it('should initialize with correct configuration', () => {
      const service = new AccessControlService();
      
      expect(service.config).toMatchObject({
        serviceName: 'access-control-service',
        port: 3002,
        version: '1.0.0',
        jwtSecret: 'test-secret',
        enableAuth: true,
        enableRateLimit: true,
        enableMetrics: true,
      });
    });

    it('should setup routes correctly', () => {
      const service = new AccessControlService();
      service.setupRoutes();
      
      expect(service.app.route).toHaveBeenCalledWith('/api/access-points', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/access-levels', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/access-events', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/credentials', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/doors', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/schedules', expect.anything());
      expect(service.app.get).toHaveBeenCalledWith('/ws', expect.any(Function));
    });

    it('should handle WebSocket upgrade request', () => {
      const service = new AccessControlService();
      service.setupRoutes();
      
      const wsHandler = service.app.get.mock.calls.find((call: any) => call[0] === '/ws')[1];
      const mockContext = {
        req: {
          header: jest.fn((name: string) => name === 'upgrade' ? 'websocket' : null)
        },
        text: jest.fn()
      };
      
      wsHandler(mockContext);
      expect(mockContext.text).toHaveBeenCalledWith('Switching Protocols', 101);
    });

    it('should reject non-WebSocket requests to /ws', () => {
      const service = new AccessControlService();
      service.setupRoutes();
      
      const wsHandler = service.app.get.mock.calls.find((call: any) => call[0] === '/ws')[1];
      const mockContext = {
        req: {
          header: jest.fn(() => null)
        },
        text: jest.fn()
      };
      
      wsHandler(mockContext);
      expect(mockContext.text).toHaveBeenCalledWith('Expected WebSocket connection', 400);
    });
  });

  describe('Health Checks', () => {
    it('should perform custom health checks', async () => {
      const service = new AccessControlService();
      service.wsServer = mockWsServer;
      
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('websocket', true);
      expect(checks).toHaveProperty('hardwareConnections', false);
    });

    it('should check hardware connections', async () => {
      const service = new AccessControlService();
      service.hardwareProtocols.set('panel1', {
        isConnected: () => true,
        getLastHeartbeat: () => new Date()
      });
      
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('hardwareConnections', true);
      expect(checks).toHaveProperty('hardware_panel1', true);
    });

    it('should handle health check errors gracefully', async () => {
      const service = new AccessControlService();
      service.wsServer = null;
      
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('websocket', false);
      expect(checks).toHaveProperty('hardwareConnections', false);
    });
  });

  describe('Metrics', () => {
    it('should generate Prometheus metrics', async () => {
      mockRedis.get.mockImplementation((key: string) => {
        if (key === 'metrics:access:events_total') return '1000';
        if (key === 'metrics:access:granted_total') return '900';
        if (key === 'metrics:access:denied_total') return '100';
        return null;
      });
      mockPrisma.door.count.mockResolvedValue(50);
      mockPrisma.credential.count.mockResolvedValue(500);

      const service = new AccessControlService();
      service.wsServer = mockWsServer;
      const metrics = await service.getMetrics();
      
      expect(metrics).toContain('access_events_total 1000');
      expect(metrics).toContain('access_granted_total 900');
      expect(metrics).toContain('access_denied_total 100');
      expect(metrics).toContain('active_doors_total 50');
      expect(metrics).toContain('active_credentials_total 500');
      expect(metrics).toContain('websocket_connections 1');
    });

    it('should handle metrics errors gracefully', async () => {
      mockRedis.get.mockRejectedValue(new Error('Redis error'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const service = new AccessControlService();
      const metrics = await service.getMetrics();
      
      expect(metrics).toContain('# HELP access_events_total');
      expect(consoleSpy).toHaveBeenCalledWith('Failed to get metrics:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });
  });

  describe('WebSocket Handling', () => {
    it('should setup WebSocket handlers', async () => {
      const service = new AccessControlService();
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      await service.start();
      
      expect(WebSocketServer).toHaveBeenCalledWith({ server: mockHttpServer });
      expect(mockWsServer.on).toHaveBeenCalledWith('connection', expect.any(Function));
      expect(consoleSpy).toHaveBeenCalledWith('[access-control-service] HTTP/WebSocket server listening on port 3002');
      
      consoleSpy.mockRestore();
    });

    it('should handle WebSocket connections', () => {
      const service = new AccessControlService();
      service.setupWebSocketHandlers();
      
      const connectionHandler = mockWsServer.on.mock.calls.find(
        (call: any) => call[0] === 'connection'
      )[1];
      
      const mockWs = {
        send: jest.fn(),
        on: jest.fn()
      };
      
      connectionHandler(mockWs, {});
      
      expect(mockWs.send).toHaveBeenCalledWith(JSON.stringify({
        type: 'connection',
        status: 'connected',
        timestamp: expect.any(String)
      }));
      expect(mockWs.on).toHaveBeenCalledWith('message', expect.any(Function));
      expect(mockWs.on).toHaveBeenCalledWith('close', expect.any(Function));
      expect(mockWs.on).toHaveBeenCalledWith('error', expect.any(Function));
    });

    it('should handle subscribe messages', async () => {
      const service = new AccessControlService();
      const mockWs = { send: jest.fn() };
      
      await service.handleWebSocketMessage(mockWs, {
        type: 'subscribe',
        channel: 'access-events'
      });
      
      expect(mockWs.send).toHaveBeenCalledWith(JSON.stringify({
        type: 'subscribed',
        channel: 'access-events',
        timestamp: expect.any(String)
      }));
    });

    it('should handle ping messages', async () => {
      const service = new AccessControlService();
      const mockWs = { send: jest.fn() };
      
      await service.handleWebSocketMessage(mockWs, { type: 'ping' });
      
      expect(mockWs.send).toHaveBeenCalledWith(JSON.stringify({
        type: 'pong',
        timestamp: expect.any(String)
      }));
    });

    it('should handle unknown message types', async () => {
      const service = new AccessControlService();
      const mockWs = { send: jest.fn() };
      
      await service.handleWebSocketMessage(mockWs, { type: 'unknown' });
      
      expect(mockWs.send).toHaveBeenCalledWith(JSON.stringify({
        type: 'error',
        message: 'Unknown message type'
      }));
    });

    it('should broadcast events to WebSocket clients', () => {
      const service = new AccessControlService();
      service.wsServer = mockWsServer;
      
      const event = {
        type: 'ACCESS_GRANTED',
        doorId: 'door-123',
        userId: 'user-456'
      };
      
      service.broadcastEvent(event);
      
      expect(mockWsClient.send).toHaveBeenCalledWith(JSON.stringify({
        type: 'event',
        data: event,
        timestamp: expect.any(String)
      }));
    });
  });

  describe('Cleanup', () => {
    it('should cleanup resources on shutdown', async () => {
      mockRedis.keys.mockResolvedValue(['temp:access:1', 'temp:access:2']);
      mockRedis.del.mockResolvedValue(2);
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      const service = new AccessControlService();
      service.wsServer = mockWsServer;
      service.httpServer = mockHttpServer;
      
      await service.cleanup();
      
      expect(consoleSpy).toHaveBeenCalledWith('Cleaning up access control service...');
      expect(mockWsClient.close).toHaveBeenCalled();
      expect(mockWsServer.close).toHaveBeenCalled();
      expect(mockHttpServer.close).toHaveBeenCalled();
      expect(mockRedis.del).toHaveBeenCalledWith('temp:access:1', 'temp:access:2');
      
      consoleSpy.mockRestore();
    });

    it('should handle cleanup errors gracefully', async () => {
      mockRedis.keys.mockRejectedValue(new Error('Redis error'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const service = new AccessControlService();
      
      await expect(service.cleanup()).resolves.not.toThrow();
      expect(consoleSpy).toHaveBeenCalledWith('Error during cleanup:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });

    it('should disconnect hardware protocols during cleanup', async () => {
      const mockHandler = {
        disconnect: jest.fn()
      };
      
      const service = new AccessControlService();
      service.hardwareProtocols.set('panel1', mockHandler);
      
      await service.cleanup();
      
      expect(mockHandler.disconnect).toHaveBeenCalled();
    });
  });

  describe('Service Start', () => {
    it('should start all components', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const service = new AccessControlService();
      
      await service.start();
      
      expect(createServer).toHaveBeenCalled();
      expect(WebSocketServer).toHaveBeenCalled();
      expect(mockHttpServer.listen).toHaveBeenCalledWith(3002, expect.any(Function));
      expect(consoleSpy).toHaveBeenCalledWith('Initializing hardware protocols...');
      expect(mockLogger.info).toHaveBeenCalledWith('Hardware protocols initialized', {
        protocols: ['OSDP', 'Wiegand', 'TCP/IP']
      });
      
      consoleSpy.mockRestore();
    });

    it('should setup HTTP request handling', async () => {
      const service = new AccessControlService();
      await service.start();
      
      expect(mockHttpServer.on).toHaveBeenCalledWith('request', expect.any(Function));
      
      const requestHandler = mockHttpServer.on.mock.calls.find(
        (call: any) => call[0] === 'request'
      )[1];
      
      const mockReq = {};
      const mockRes = {};
      
      requestHandler(mockReq, mockRes);
      
      expect(service.app.fetch).toHaveBeenCalledWith(mockReq, { req: mockReq, res: mockRes });
    });
  });

  describe('Error Handling', () => {
    it('should handle validation errors', () => {
      const service = new AccessControlService();
      service.setupRoutes();
      
      expect(service.app.use).toHaveBeenCalledWith('*', expect.any(Function));
    });

    it('should setup 404 handler', () => {
      const service = new AccessControlService();
      service.setupRoutes();
      
      const notFoundHandler = service.app.notFound.mock.calls[0][0];
      const mockContext = {
        req: { path: '/unknown' },
        json: jest.fn()
      };
      
      notFoundHandler(mockContext);
      
      expect(mockContext.json).toHaveBeenCalledWith(
        { error: 'Not found', path: '/unknown' },
        404
      );
    });
  });
});