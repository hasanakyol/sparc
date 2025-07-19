import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import { Server as SocketIOServer } from 'socket.io';
import { createServer } from 'http';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { EventEmitter } from 'events';
import ffmpeg from 'fluent-ffmpeg';
import { promises as fs } from 'fs';
import path from 'path';

// Import routes
import cameraRoutes from './routes/cameras';
import streamRoutes from './routes/streams';
import recordingRoutes from './routes/recordings';
import analyticsRoutes from './routes/analytics';
import exportRoutes from './routes/exports';

// Import schemas
import { CameraSchema, StreamRequestSchema, RecordingSearchSchema, VideoExportSchema } from './schemas';

// Import video processor
import { VideoProcessor } from './services/videoProcessor';
import { VideoMetricsCollector, videoProcessingMetrics, getVideoProcessingHealth } from './middleware/videoMetrics';

class VideoManagementService extends MicroserviceBase {
  private io: SocketIOServer | null = null;
  private httpServer: any;
  private streamManager: EventEmitter = new EventEmitter();
  private activeStreams: Map<string, any> = new Map();
  private recordingWorkers: Map<string, any> = new Map();
  private videoProcessor: VideoProcessor | null = null;
  private metricsCollector: VideoMetricsCollector | null = null;

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'video-management-service',
      port: config.services?.videoManagement?.port || 3004,
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
    // Mount API routes
    this.app.route('/api/cameras', cameraRoutes);
    this.app.route('/api/streams', streamRoutes);
    this.app.route('/api/recordings', recordingRoutes);
    this.app.route('/api/analytics', analyticsRoutes);
    this.app.route('/api/exports', exportRoutes);

    // Socket.IO endpoint
    this.app.get('/socket.io/*', (c) => {
      // Socket.IO handling will be done by the Socket.IO server
      return c.text('Socket.IO endpoint', 200);
    });

    // Additional error handling
    this.app.use('*', async (c, next) => {
      try {
        await next();
      } catch (err) {
        if (err instanceof z.ZodError) {
          throw new HTTPException(400, {
            message: 'Validation failed',
            cause: err.errors
          });
        }
        throw err;
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
    
    // Check Socket.IO server
    try {
      checks.socketio = this.io !== null;
    } catch {
      checks.socketio = false;
    }

    // Check FFmpeg availability
    try {
      await new Promise((resolve, reject) => {
        ffmpeg.getAvailableFormats((err, formats) => {
          if (err) reject(err);
          else resolve(formats);
        });
      });
      checks.ffmpeg = true;
    } catch {
      checks.ffmpeg = false;
    }

    // Check active streams
    checks.activeStreams = this.activeStreams.size > 0 || true; // Always healthy even with no streams

    // Check recording workers
    checks.recordingWorkers = this.recordingWorkers.size > 0 || true; // Always healthy even with no workers

    // Check storage availability
    try {
      const storagePath = process.env.VIDEO_STORAGE_PATH || '/var/sparc/recordings';
      await fs.access(storagePath);
      checks.storage = true;
    } catch {
      checks.storage = false;
    }

    // Check video processor health
    if (this.videoProcessor) {
      const processorHealth = await getVideoProcessingHealth(this.videoProcessor);
      checks.videoProcessor = processorHealth.healthy;
    } else {
      checks.videoProcessor = false;
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const metrics: string[] = [];
    
    // Video management specific metrics
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
    
    // Get actual metrics
    try {
      // Get camera count from database
      const cameraCount = await this.prisma.camera.count({ where: { status: 'online' } });
      metrics.push(`active_cameras_total ${cameraCount}`);
      
      // Active streams
      metrics.push(`active_streams_total ${this.activeStreams.size}`);
      
      // Get metrics from Redis
      const recordingSessions = await this.redis.get('metrics:video:recording_sessions') || '0';
      metrics.push(`recording_sessions_total ${recordingSessions}`);
      
      const videoExports = await this.redis.get('metrics:video:exports_total') || '0';
      metrics.push(`video_exports_total ${videoExports}`);
      
      const streamBandwidth = await this.redis.get('metrics:video:bandwidth_bytes') || '0';
      metrics.push(`stream_bandwidth_bytes ${streamBandwidth}`);
      
      // Check storage usage
      try {
        const storagePath = process.env.VIDEO_STORAGE_PATH || '/var/sparc/recordings';
        const stats = await fs.stat(storagePath);
        // This is a placeholder - in production you'd calculate actual usage
        metrics.push(`storage_used_bytes ${stats.size || 0}`);
      } catch {
        metrics.push(`storage_used_bytes 0`);
      }
      
      // Socket.IO connections
      const socketConnections = this.io?.engine?.clientsCount || 0;
      metrics.push(`socketio_connections ${socketConnections}`);
    } catch (error) {
      console.error('Failed to get metrics:', error);
    }
    
    return metrics.join('\n');
  }

  public async start(): Promise<void> {
    // Create HTTP server for Socket.IO support
    this.httpServer = createServer();
    
    // Initialize Socket.IO server
    this.io = new SocketIOServer(this.httpServer, {
      cors: {
        origin: this.config.corsOrigins,
        credentials: true
      },
      transports: ['websocket', 'polling']
    });
    
    this.setupSocketHandlers();
    
    // Initialize stream processing
    await this.initializeStreamProcessing();
    
    // Initialize video processor
    this.videoProcessor = new VideoProcessor();
    this.metricsCollector = new VideoMetricsCollector(this.videoProcessor);
    
    // Apply video processing metrics middleware
    this.app.use('/api/exports/*', videoProcessingMetrics());
    
    // Call parent start method
    await super.start();
    
    // Start the HTTP server with the Hono app
    this.httpServer.on('request', (req: any, res: any) => {
      // Let Socket.IO handle its own routes
      if (req.url.startsWith('/socket.io/')) {
        return;
      }
      this.app.fetch(req, { req, res });
    });
    
    this.httpServer.listen(this.config.port, () => {
      console.log(`[${this.config.serviceName}] HTTP/Socket.IO server listening on port ${this.config.port}`);
    });
  }

  private setupSocketHandlers(): void {
    if (!this.io) return;

    this.io.on('connection', (socket) => {
      console.log('New Socket.IO connection:', socket.id);
      
      // Join tenant room
      socket.on('join-tenant', (tenantId: string) => {
        socket.join(`tenant:${tenantId}`);
        socket.emit('joined-tenant', { tenantId });
      });
      
      // Stream subscription
      socket.on('subscribe-stream', async (data: { cameraId: string, quality: string }) => {
        try {
          const streamUrl = await this.getStreamUrl(data.cameraId, data.quality);
          socket.emit('stream-url', { cameraId: data.cameraId, url: streamUrl });
          socket.join(`stream:${data.cameraId}`);
        } catch (error) {
          socket.emit('stream-error', { cameraId: data.cameraId, error: 'Failed to get stream' });
        }
      });
      
      // Unsubscribe from stream
      socket.on('unsubscribe-stream', (cameraId: string) => {
        socket.leave(`stream:${cameraId}`);
      });
      
      // PTZ control
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

  private async initializeStreamProcessing(): Promise<void> {
    console.log('Initializing video stream processing...');
    
    // Set up stream event handlers
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

  private async getStreamUrl(cameraId: string, quality: string): Promise<string> {
    // Implementation would generate actual stream URL
    // This is a placeholder
    const baseUrl = process.env.STREAM_BASE_URL || 'http://localhost:8080';
    return `${baseUrl}/live/${cameraId}/${quality}/index.m3u8`;
  }

  private async handlePTZCommand(cameraId: string, command: string, params?: any): Promise<void> {
    // Implementation would send actual PTZ commands to camera
    console.log(`PTZ command for camera ${cameraId}: ${command}`, params);
  }

  private broadcastToRoom(room: string, event: string, data: any): void {
    if (!this.io) return;
    this.io.to(room).emit(event, data);
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up video management service...');
    
    // Stop all active streams
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
    
    // Stop all recording workers
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
    
    // Close Socket.IO connections
    if (this.io) {
      this.io.close();
    }
    
    // Close HTTP server
    if (this.httpServer) {
      this.httpServer.close();
    }
    
    // Shutdown video processor
    if (this.videoProcessor) {
      await this.videoProcessor.shutdown();
    }
    
    // Stop metrics collector
    if (this.metricsCollector) {
      this.metricsCollector.stop();
    }
    
    // Clear any temporary video data
    try {
      const tempKeys = await this.redis.keys('temp:video:*');
      if (tempKeys.length > 0) {
        await this.redis.del(...tempKeys);
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  // Public methods for external use
  public startRecording(cameraId: string, options: any): void {
    // Implementation for starting recording
    console.log(`Starting recording for camera ${cameraId}`, options);
  }

  public stopRecording(cameraId: string): void {
    // Implementation for stopping recording
    console.log(`Stopping recording for camera ${cameraId}`);
  }

  public broadcastAnalyticsEvent(event: any): void {
    if (!this.io) return;
    
    // Broadcast to relevant tenant
    this.io.to(`tenant:${event.tenantId}`).emit('analytics-event', event);
  }
}

// Create and start the service
const videoManagementService = new VideoManagementService();

videoManagementService.start().catch((error) => {
  console.error('Failed to start video management service:', error);
  process.exit(1);
});

// Export for testing
export default videoManagementService.app;
export { videoManagementService };