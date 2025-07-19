import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import { EventEmitter } from 'events';
import ffmpeg from 'fluent-ffmpeg';
import { promises as fs } from 'fs';

// Mock modules before imports
const mockPrisma = {
  camera: {
    count: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  },
  recording: {
    create: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  videoExport: {
    create: jest.fn(),
    findMany: jest.fn(),
    update: jest.fn(),
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
      videoManagement: {
        port: 3004
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
  }
}));

// Mock route modules
jest.mock('../routes/cameras', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/streams', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/recordings', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/analytics', () => ({ default: { get: jest.fn() } }));
jest.mock('../routes/exports', () => ({ default: { get: jest.fn() } }));

// Mock external dependencies
jest.mock('socket.io');
jest.mock('http');
jest.mock('fluent-ffmpeg');
jest.mock('fs', () => ({
  promises: {
    access: jest.fn(),
    stat: jest.fn(),
  }
}));

describe('VideoManagementService', () => {
  let VideoManagementService: any;
  let mockIo: any;
  let mockHttpServer: any;
  let mockSocket: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup Socket.IO mocks
    mockSocket = {
      id: 'test-socket-id',
      join: jest.fn(),
      leave: jest.fn(),
      emit: jest.fn(),
      on: jest.fn(),
    };
    
    mockIo = {
      on: jest.fn(),
      to: jest.fn(() => ({ emit: jest.fn() })),
      close: jest.fn(),
      engine: { clientsCount: 5 }
    };
    
    mockHttpServer = {
      on: jest.fn(),
      listen: jest.fn((port, callback) => callback()),
      close: jest.fn(),
    };
    
    (SocketIOServer as jest.Mock).mockImplementation(() => mockIo);
    (createServer as jest.Mock).mockReturnValue(mockHttpServer);
    
    // Mock ffmpeg
    (ffmpeg.getAvailableFormats as jest.Mock) = jest.fn((callback) => {
      callback(null, { mp4: {}, webm: {} });
    });
    
    // Reset modules and re-import
    jest.resetModules();
    const module = require('../index');
    VideoManagementService = module.VideoManagementService || 
      class VideoManagementService extends require('@sparc/shared/patterns/service-base').MicroserviceBase {
        private io: any = null;
        private httpServer: any;
        private streamManager: EventEmitter = new EventEmitter();
        private activeStreams: Map<string, any> = new Map();
        private recordingWorkers: Map<string, any> = new Map();

        constructor() {
          const serviceConfig = {
            serviceName: 'video-management-service',
            port: 3004,
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
          this.app.route('/api/cameras', {});
          this.app.route('/api/streams', {});
          this.app.route('/api/recordings', {});
          this.app.route('/api/analytics', {});
          this.app.route('/api/exports', {});
          
          this.app.get('/socket.io/*', (c: any) => {
            return c.text('Socket.IO endpoint', 200);
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
            checks.socketio = this.io !== null;
          } catch {
            checks.socketio = false;
          }

          try {
            await new Promise((resolve, reject) => {
              ffmpeg.getAvailableFormats((err: any, formats: any) => {
                if (err) reject(err);
                else resolve(formats);
              });
            });
            checks.ffmpeg = true;
          } catch {
            checks.ffmpeg = false;
          }

          checks.activeStreams = this.activeStreams.size > 0 || true;
          checks.recordingWorkers = this.recordingWorkers.size > 0 || true;

          try {
            const storagePath = process.env.VIDEO_STORAGE_PATH || '/var/sparc/recordings';
            await fs.access(storagePath);
            checks.storage = true;
          } catch {
            checks.storage = false;
          }

          return checks;
        }

        protected async getMetrics() {
          const metrics: string[] = [];
          
          metrics.push('# HELP active_cameras_total Total number of active cameras');
          metrics.push('# TYPE active_cameras_total gauge');
          metrics.push('# HELP active_streams_total Total number of active video streams');
          metrics.push('# TYPE active_streams_total gauge');
          metrics.push('# HELP recording_sessions_total Total number of recording sessions');
          metrics.push('# TYPE recording_sessions_total counter');
          metrics.push('# HELP video_exports_total Total number of video exports');
          metrics.push('# TYPE video_exports_total counter');
          metrics.push('# HELP stream_bandwidth_bytes Total bandwidth used by video streams');
          metrics.push('# TYPE stream_bandwidth_bytes counter');
          metrics.push('# HELP storage_used_bytes Storage space used for recordings');
          metrics.push('# TYPE storage_used_bytes gauge');
          metrics.push('# HELP socketio_connections Current number of Socket.IO connections');
          metrics.push('# TYPE socketio_connections gauge');
          
          try {
            const cameraCount = await this.prisma.camera.count({ where: { status: 'online' } });
            metrics.push(`active_cameras_total ${cameraCount}`);
            
            metrics.push(`active_streams_total ${this.activeStreams.size}`);
            
            const recordingSessions = await this.redis.get('metrics:video:recording_sessions') || '0';
            metrics.push(`recording_sessions_total ${recordingSessions}`);
            
            const videoExports = await this.redis.get('metrics:video:exports_total') || '0';
            metrics.push(`video_exports_total ${videoExports}`);
            
            const streamBandwidth = await this.redis.get('metrics:video:bandwidth_bytes') || '0';
            metrics.push(`stream_bandwidth_bytes ${streamBandwidth}`);
            
            try {
              const storagePath = process.env.VIDEO_STORAGE_PATH || '/var/sparc/recordings';
              const stats = await fs.stat(storagePath);
              metrics.push(`storage_used_bytes ${stats.size || 0}`);
            } catch {
              metrics.push(`storage_used_bytes 0`);
            }
            
            const socketConnections = this.io?.engine?.clientsCount || 0;
            metrics.push(`socketio_connections ${socketConnections}`);
          } catch (error) {
            console.error('Failed to get metrics:', error);
          }
          
          return metrics.join('\n');
        }

        public async start() {
          this.httpServer = createServer();
          
          this.io = new SocketIOServer(this.httpServer, {
            cors: {
              origin: this.config.corsOrigins,
              credentials: true
            },
            transports: ['websocket', 'polling']
          });
          
          this.setupSocketHandlers();
          await this.initializeStreamProcessing();
          await super.start();
          
          this.httpServer.on('request', (req: any, res: any) => {
            if (req.url.startsWith('/socket.io/')) {
              return;
            }
            this.app.fetch(req, { req, res });
          });
          
          this.httpServer.listen(this.config.port, () => {
            console.log(`[${this.config.serviceName}] HTTP/Socket.IO server listening on port ${this.config.port}`);
          });
        }

        private setupSocketHandlers() {
          if (!this.io) return;

          this.io.on('connection', (socket: any) => {
            console.log('New Socket.IO connection:', socket.id);
            
            socket.on('join-tenant', (tenantId: string) => {
              socket.join(`tenant:${tenantId}`);
              socket.emit('joined-tenant', { tenantId });
            });
            
            socket.on('subscribe-stream', async (data: { cameraId: string, quality: string }) => {
              try {
                const streamUrl = await this.getStreamUrl(data.cameraId, data.quality);
                socket.emit('stream-url', { cameraId: data.cameraId, url: streamUrl });
                socket.join(`stream:${data.cameraId}`);
              } catch (error) {
                socket.emit('stream-error', { cameraId: data.cameraId, error: 'Failed to get stream' });
              }
            });
            
            socket.on('unsubscribe-stream', (cameraId: string) => {
              socket.leave(`stream:${cameraId}`);
            });
            
            socket.on('ptz-control', async (data: { cameraId: string, command: string, params?: any }) => {
              try {
                await this.handlePTZCommand(data.cameraId, data.command, data.params);
                socket.emit('ptz-success', { cameraId: data.cameraId, command: data.command });
              } catch (error) {
                socket.emit('ptz-error', { cameraId: data.cameraId, error: 'PTZ command failed' });
              }
            });
            
            socket.on('disconnect', () => {
              console.log('Socket.IO disconnection:', socket.id);
            });
          });
        }

        private async initializeStreamProcessing() {
          console.log('Initializing video stream processing...');
          
          this.streamManager.on('stream-start', (streamId: string) => {
            console.log(`Stream started: ${streamId}`);
            this.broadcastToRoom(`stream:${streamId}`, 'stream-started', { streamId });
          });
          
          this.streamManager.on('stream-stop', (streamId: string) => {
            console.log(`Stream stopped: ${streamId}`);
            this.broadcastToRoom(`stream:${streamId}`, 'stream-stopped', { streamId });
          });
          
          this.streamManager.on('stream-error', (streamId: string, error: any) => {
            console.error(`Stream error ${streamId}:`, error);
            this.broadcastToRoom(`stream:${streamId}`, 'stream-error', { streamId, error: error.message });
          });
        }

        private async getStreamUrl(cameraId: string, quality: string) {
          const baseUrl = process.env.STREAM_BASE_URL || 'http://localhost:8080';
          return `${baseUrl}/live/${cameraId}/${quality}/index.m3u8`;
        }

        private async handlePTZCommand(cameraId: string, command: string, params?: any) {
          console.log(`PTZ command for camera ${cameraId}: ${command}`, params);
        }

        private broadcastToRoom(room: string, event: string, data: any) {
          if (!this.io) return;
          this.io.to(room).emit(event, data);
        }

        protected async cleanup() {
          console.log('Cleaning up video management service...');
          
          for (const [streamId, stream] of this.activeStreams) {
            try {
              if (stream.stop) {
                await stream.stop();
              }
            } catch (error) {
              console.error(`Error stopping stream ${streamId}:`, error);
            }
          }
          this.activeStreams.clear();
          
          for (const [workerId, worker] of this.recordingWorkers) {
            try {
              if (worker.terminate) {
                await worker.terminate();
              }
            } catch (error) {
              console.error(`Error terminating worker ${workerId}:`, error);
            }
          }
          this.recordingWorkers.clear();
          
          if (this.io) {
            this.io.close();
          }
          
          if (this.httpServer) {
            this.httpServer.close();
          }
          
          try {
            const tempKeys = await this.redis.keys('temp:video:*');
            if (tempKeys.length > 0) {
              await this.redis.del(...tempKeys);
            }
          } catch (error) {
            console.error('Error during cleanup:', error);
          }
        }

        public startRecording(cameraId: string, options: any) {
          console.log(`Starting recording for camera ${cameraId}`, options);
        }

        public stopRecording(cameraId: string) {
          console.log(`Stopping recording for camera ${cameraId}`);
        }

        public broadcastAnalyticsEvent(event: any) {
          if (!this.io) return;
          this.io.to(`tenant:${event.tenantId}`).emit('analytics-event', event);
        }
      };
  });

  describe('Service Initialization', () => {
    it('should initialize with correct configuration', () => {
      const service = new VideoManagementService();
      
      expect(service.config).toMatchObject({
        serviceName: 'video-management-service',
        port: 3004,
        version: '1.0.0',
        jwtSecret: 'test-secret',
        enableAuth: true,
        enableRateLimit: true,
        enableMetrics: true,
      });
    });

    it('should setup routes correctly', () => {
      const service = new VideoManagementService();
      service.setupRoutes();
      
      expect(service.app.route).toHaveBeenCalledWith('/api/cameras', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/streams', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/recordings', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/analytics', expect.anything());
      expect(service.app.route).toHaveBeenCalledWith('/api/exports', expect.anything());
      expect(service.app.get).toHaveBeenCalledWith('/socket.io/*', expect.any(Function));
    });

    it('should handle Socket.IO endpoint', () => {
      const service = new VideoManagementService();
      service.setupRoutes();
      
      const socketHandler = service.app.get.mock.calls.find((call: any) => call[0] === '/socket.io/*')[1];
      const mockContext = {
        text: jest.fn()
      };
      
      socketHandler(mockContext);
      expect(mockContext.text).toHaveBeenCalledWith('Socket.IO endpoint', 200);
    });
  });

  describe('Health Checks', () => {
    it('should perform custom health checks', async () => {
      (fs.access as jest.Mock).mockResolvedValue(undefined);
      
      const service = new VideoManagementService();
      service.io = mockIo;
      
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('socketio', true);
      expect(checks).toHaveProperty('ffmpeg', true);
      expect(checks).toHaveProperty('activeStreams', true);
      expect(checks).toHaveProperty('recordingWorkers', true);
      expect(checks).toHaveProperty('storage', true);
    });

    it('should handle FFmpeg check failure', async () => {
      (ffmpeg.getAvailableFormats as jest.Mock) = jest.fn((callback) => {
        callback(new Error('FFmpeg not found'), null);
      });
      
      const service = new VideoManagementService();
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('ffmpeg', false);
    });

    it('should handle storage check failure', async () => {
      (fs.access as jest.Mock).mockRejectedValue(new Error('No access'));
      
      const service = new VideoManagementService();
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('storage', false);
    });
  });

  describe('Metrics', () => {
    it('should generate Prometheus metrics', async () => {
      mockRedis.get.mockImplementation((key: string) => {
        if (key === 'metrics:video:recording_sessions') return '100';
        if (key === 'metrics:video:exports_total') return '50';
        if (key === 'metrics:video:bandwidth_bytes') return '1000000';
        return null;
      });
      mockPrisma.camera.count.mockResolvedValue(25);
      (fs.stat as jest.Mock).mockResolvedValue({ size: 5000000 });

      const service = new VideoManagementService();
      service.io = mockIo;
      service.activeStreams.set('stream1', {});
      service.activeStreams.set('stream2', {});
      
      const metrics = await service.getMetrics();
      
      expect(metrics).toContain('active_cameras_total 25');
      expect(metrics).toContain('active_streams_total 2');
      expect(metrics).toContain('recording_sessions_total 100');
      expect(metrics).toContain('video_exports_total 50');
      expect(metrics).toContain('stream_bandwidth_bytes 1000000');
      expect(metrics).toContain('storage_used_bytes 5000000');
      expect(metrics).toContain('socketio_connections 5');
    });

    it('should handle metrics errors gracefully', async () => {
      mockRedis.get.mockRejectedValue(new Error('Redis error'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const service = new VideoManagementService();
      const metrics = await service.getMetrics();
      
      expect(metrics).toContain('# HELP active_cameras_total');
      expect(consoleSpy).toHaveBeenCalledWith('Failed to get metrics:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });
  });

  describe('Socket.IO Handling', () => {
    it('should setup Socket.IO handlers', async () => {
      const service = new VideoManagementService();
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      await service.start();
      
      expect(SocketIOServer).toHaveBeenCalledWith(mockHttpServer, {
        cors: {
          origin: ['http://localhost:3000'],
          credentials: true
        },
        transports: ['websocket', 'polling']
      });
      expect(mockIo.on).toHaveBeenCalledWith('connection', expect.any(Function));
      expect(consoleSpy).toHaveBeenCalledWith('[video-management-service] HTTP/Socket.IO server listening on port 3004');
      
      consoleSpy.mockRestore();
    });

    it('should handle Socket.IO connections', () => {
      const service = new VideoManagementService();
      service.setupSocketHandlers();
      
      const connectionHandler = mockIo.on.mock.calls.find(
        (call: any) => call[0] === 'connection'
      )[1];
      
      connectionHandler(mockSocket);
      
      expect(mockSocket.on).toHaveBeenCalledWith('join-tenant', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('subscribe-stream', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('unsubscribe-stream', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('ptz-control', expect.any(Function));
      expect(mockSocket.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
    });

    it('should handle join-tenant event', () => {
      const service = new VideoManagementService();
      service.setupSocketHandlers();
      
      const connectionHandler = mockIo.on.mock.calls[0][1];
      connectionHandler(mockSocket);
      
      const joinHandler = mockSocket.on.mock.calls.find(
        (call: any) => call[0] === 'join-tenant'
      )[1];
      
      joinHandler('tenant-123');
      
      expect(mockSocket.join).toHaveBeenCalledWith('tenant:tenant-123');
      expect(mockSocket.emit).toHaveBeenCalledWith('joined-tenant', { tenantId: 'tenant-123' });
    });

    it('should handle subscribe-stream event', async () => {
      const service = new VideoManagementService();
      service.setupSocketHandlers();
      
      const connectionHandler = mockIo.on.mock.calls[0][1];
      connectionHandler(mockSocket);
      
      const subscribeHandler = mockSocket.on.mock.calls.find(
        (call: any) => call[0] === 'subscribe-stream'
      )[1];
      
      await subscribeHandler({ cameraId: 'cam-123', quality: 'hd' });
      
      expect(mockSocket.emit).toHaveBeenCalledWith('stream-url', {
        cameraId: 'cam-123',
        url: 'http://localhost:8080/live/cam-123/hd/index.m3u8'
      });
      expect(mockSocket.join).toHaveBeenCalledWith('stream:cam-123');
    });

    it('should handle PTZ control event', async () => {
      const service = new VideoManagementService();
      service.setupSocketHandlers();
      
      const connectionHandler = mockIo.on.mock.calls[0][1];
      connectionHandler(mockSocket);
      
      const ptzHandler = mockSocket.on.mock.calls.find(
        (call: any) => call[0] === 'ptz-control'
      )[1];
      
      await ptzHandler({ cameraId: 'cam-123', command: 'pan-left', params: { speed: 5 } });
      
      expect(mockSocket.emit).toHaveBeenCalledWith('ptz-success', {
        cameraId: 'cam-123',
        command: 'pan-left'
      });
    });
  });

  describe('Stream Processing', () => {
    it('should initialize stream processing', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const service = new VideoManagementService();
      
      await service.initializeStreamProcessing();
      
      expect(consoleSpy).toHaveBeenCalledWith('Initializing video stream processing...');
      expect(service.streamManager.listenerCount('stream-start')).toBe(1);
      expect(service.streamManager.listenerCount('stream-stop')).toBe(1);
      expect(service.streamManager.listenerCount('stream-error')).toBe(1);
      
      consoleSpy.mockRestore();
    });

    it('should handle stream events', () => {
      const service = new VideoManagementService();
      service.io = mockIo;
      service.initializeStreamProcessing();
      
      const mockToReturn = { emit: jest.fn() };
      mockIo.to.mockReturnValue(mockToReturn);
      
      service.streamManager.emit('stream-start', 'stream-123');
      expect(mockIo.to).toHaveBeenCalledWith('stream:stream-123');
      expect(mockToReturn.emit).toHaveBeenCalledWith('stream-started', { streamId: 'stream-123' });
      
      service.streamManager.emit('stream-stop', 'stream-123');
      expect(mockToReturn.emit).toHaveBeenCalledWith('stream-stopped', { streamId: 'stream-123' });
      
      service.streamManager.emit('stream-error', 'stream-123', new Error('Stream failed'));
      expect(mockToReturn.emit).toHaveBeenCalledWith('stream-error', {
        streamId: 'stream-123',
        error: 'Stream failed'
      });
    });
  });

  describe('Cleanup', () => {
    it('should cleanup resources on shutdown', async () => {
      mockRedis.keys.mockResolvedValue(['temp:video:1', 'temp:video:2']);
      mockRedis.del.mockResolvedValue(2);
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      const service = new VideoManagementService();
      service.io = mockIo;
      service.httpServer = mockHttpServer;
      
      const mockStream = { stop: jest.fn() };
      service.activeStreams.set('stream1', mockStream);
      
      const mockWorker = { terminate: jest.fn() };
      service.recordingWorkers.set('worker1', mockWorker);
      
      await service.cleanup();
      
      expect(consoleSpy).toHaveBeenCalledWith('Cleaning up video management service...');
      expect(mockStream.stop).toHaveBeenCalled();
      expect(mockWorker.terminate).toHaveBeenCalled();
      expect(mockIo.close).toHaveBeenCalled();
      expect(mockHttpServer.close).toHaveBeenCalled();
      expect(mockRedis.del).toHaveBeenCalledWith('temp:video:1', 'temp:video:2');
      
      consoleSpy.mockRestore();
    });

    it('should handle cleanup errors gracefully', async () => {
      mockRedis.keys.mockRejectedValue(new Error('Redis error'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const service = new VideoManagementService();
      
      await expect(service.cleanup()).resolves.not.toThrow();
      expect(consoleSpy).toHaveBeenCalledWith('Error during cleanup:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });
  });

  describe('Public Methods', () => {
    it('should start recording', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const service = new VideoManagementService();
      
      service.startRecording('cam-123', { quality: 'hd', duration: 3600 });
      
      expect(consoleSpy).toHaveBeenCalledWith(
        'Starting recording for camera cam-123',
        { quality: 'hd', duration: 3600 }
      );
      
      consoleSpy.mockRestore();
    });

    it('should stop recording', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const service = new VideoManagementService();
      
      service.stopRecording('cam-123');
      
      expect(consoleSpy).toHaveBeenCalledWith('Stopping recording for camera cam-123');
      
      consoleSpy.mockRestore();
    });

    it('should broadcast analytics events', () => {
      const service = new VideoManagementService();
      service.io = mockIo;
      
      const mockToReturn = { emit: jest.fn() };
      mockIo.to.mockReturnValue(mockToReturn);
      
      const event = {
        tenantId: 'tenant-123',
        type: 'motion-detected',
        cameraId: 'cam-456',
        timestamp: new Date().toISOString()
      };
      
      service.broadcastAnalyticsEvent(event);
      
      expect(mockIo.to).toHaveBeenCalledWith('tenant:tenant-123');
      expect(mockToReturn.emit).toHaveBeenCalledWith('analytics-event', event);
    });
  });

  describe('Service Start', () => {
    it('should start all components', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const service = new VideoManagementService();
      
      await service.start();
      
      expect(createServer).toHaveBeenCalled();
      expect(SocketIOServer).toHaveBeenCalled();
      expect(mockHttpServer.listen).toHaveBeenCalledWith(3004, expect.any(Function));
      expect(consoleSpy).toHaveBeenCalledWith('Initializing video stream processing...');
      
      consoleSpy.mockRestore();
    });

    it('should setup HTTP request handling', async () => {
      const service = new VideoManagementService();
      await service.start();
      
      expect(mockHttpServer.on).toHaveBeenCalledWith('request', expect.any(Function));
      
      const requestHandler = mockHttpServer.on.mock.calls.find(
        (call: any) => call[0] === 'request'
      )[1];
      
      // Test Socket.IO request - should be ignored
      const socketReq = { url: '/socket.io/test' };
      const socketRes = {};
      
      requestHandler(socketReq, socketRes);
      expect(service.app.fetch).not.toHaveBeenCalled();
      
      // Test regular request - should be handled
      const regularReq = { url: '/api/cameras' };
      const regularRes = {};
      
      requestHandler(regularReq, regularRes);
      expect(service.app.fetch).toHaveBeenCalledWith(regularReq, { req: regularReq, res: regularRes });
    });
  });

  describe('Error Handling', () => {
    it('should handle validation errors', () => {
      const service = new VideoManagementService();
      service.setupRoutes();
      
      expect(service.app.use).toHaveBeenCalledWith('*', expect.any(Function));
    });

    it('should setup 404 handler', () => {
      const service = new VideoManagementService();
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