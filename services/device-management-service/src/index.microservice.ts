import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { createDeviceRoutes } from './routes/devices';
import { createDiscoveryRoutes } from './routes/discovery';
import { createHealthRoutes } from './routes/health';
import { createFirmwareRoutes } from './routes/firmware';
import { DeviceManagementService } from './services/device-management-service';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';

// Service-specific configuration interface
interface DeviceManagementConfig extends ServiceConfig {
  discoveryInterval: number;
  healthCheckInterval: number;
  corsOrigin: string;
  wsPort: number;
}

class DeviceManagementMicroservice extends MicroserviceBase {
  private deviceService: DeviceManagementService;
  private wsServer?: WebSocketServer;
  private httpServer?: any;

  constructor(config: DeviceManagementConfig) {
    super(config);
    this.deviceService = new DeviceManagementService(this.prisma, this.redis);
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    // Check WebSocket server
    if (this.wsServer) {
      checks.websocket = this.wsServer.clients.size >= 0;
    }
    
    // Check device service health
    try {
      const deviceCount = await this.prisma.device.count();
      checks.deviceService = true;
      checks.deviceCount = deviceCount >= 0;
    } catch {
      checks.deviceService = false;
    }
    
    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const metrics: string[] = [];
    
    // Device metrics
    const deviceCount = await this.prisma.device.count();
    const onlineDevices = await this.prisma.device.count({
      where: { status: 'online' }
    });
    
    metrics.push(`# HELP devices_total Total number of devices`);
    metrics.push(`# TYPE devices_total gauge`);
    metrics.push(`devices_total ${deviceCount}`);
    
    metrics.push(`# HELP devices_online Number of online devices`);
    metrics.push(`# TYPE devices_online gauge`);
    metrics.push(`devices_online ${onlineDevices}`);
    
    // WebSocket metrics
    if (this.wsServer) {
      metrics.push(`# HELP websocket_clients Number of connected WebSocket clients`);
      metrics.push(`# TYPE websocket_clients gauge`);
      metrics.push(`websocket_clients ${this.wsServer.clients.size}`);
    }
    
    return metrics.join('\n');
  }

  public setupRoutes(): void {
    // Apply tenant middleware for all API routes
    this.app.use('/api/*', async (c, next) => {
      const tenantId = c.req.header('X-Tenant-ID');
      if (!tenantId) {
        throw new HTTPException(400, { message: 'Tenant ID required' });
      }
      c.set('tenantId', tenantId);
      await next();
    });

    // Mount route modules
    const deviceRoutes = createDeviceRoutes(this.deviceService);
    const discoveryRoutes = createDiscoveryRoutes(this.deviceService);
    const healthRoutes = createHealthRoutes(this.deviceService);
    const firmwareRoutes = createFirmwareRoutes(this.deviceService);

    this.app.route('/api/devices', deviceRoutes);
    this.app.route('/api/discovery', discoveryRoutes);
    this.app.route('/api/health', healthRoutes);
    this.app.route('/api/firmware', firmwareRoutes);

    // WebSocket endpoint info
    this.app.get('/ws/info', (c) => {
      return c.json({
        wsUrl: `ws://localhost:${(this.config as DeviceManagementConfig).wsPort}`,
        protocol: 'device-management-v1',
        events: [
          'device_status_update',
          'device_health_update',
          'device_discovery',
          'firmware_update_progress'
        ]
      });
    });
  }

  public async start(): Promise<void> {
    // Start WebSocket server
    const config = this.config as DeviceManagementConfig;
    this.httpServer = createServer();
    this.wsServer = new WebSocketServer({ server: this.httpServer });

    this.wsServer.on('connection', (ws, req) => {
      const clientId = crypto.randomUUID();
      console.log(`[${this.config.serviceName}] WebSocket client connected: ${clientId}`);

      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message.toString());
          this.handleWebSocketMessage(ws, data);
        } catch (error) {
          ws.send(JSON.stringify({ error: 'Invalid message format' }));
        }
      });

      ws.on('close', () => {
        console.log(`[${this.config.serviceName}] WebSocket client disconnected: ${clientId}`);
      });
    });

    this.httpServer.listen(config.wsPort, () => {
      console.log(`[${this.config.serviceName}] WebSocket server listening on port ${config.wsPort}`);
    });

    // Pass WebSocket server to device service
    this.deviceService.setWebSocketServer(this.wsServer);

    // Start background tasks
    this.startBackgroundTasks();

    // Start main HTTP server
    await super.start();
  }

  private handleWebSocketMessage(ws: any, data: any): void {
    switch (data.type) {
      case 'subscribe':
        // Handle subscription to device updates
        ws.send(JSON.stringify({ type: 'subscribed', channels: data.channels }));
        break;
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        break;
      default:
        ws.send(JSON.stringify({ error: 'Unknown message type' }));
    }
  }

  private startBackgroundTasks(): void {
    const config = this.config as DeviceManagementConfig;

    // Device discovery task
    if (config.discoveryInterval > 0) {
      setInterval(async () => {
        try {
          console.log(`[${this.config.serviceName}] Running scheduled device discovery`);
          await this.deviceService.performNetworkDiscovery();
        } catch (error) {
          console.error(`[${this.config.serviceName}] Discovery task error:`, error);
        }
      }, config.discoveryInterval);
    }

    // Health check task
    if (config.healthCheckInterval > 0) {
      setInterval(async () => {
        try {
          console.log(`[${this.config.serviceName}] Running device health checks`);
          await this.deviceService.checkAllDeviceHealth();
        } catch (error) {
          console.error(`[${this.config.serviceName}] Health check task error:`, error);
        }
      }, config.healthCheckInterval);
    }
  }

  protected async cleanup(): Promise<void> {
    // Stop WebSocket server
    if (this.wsServer) {
      this.wsServer.clients.forEach(client => client.close());
      this.wsServer.close();
    }
    
    if (this.httpServer) {
      this.httpServer.close();
    }

    // Cleanup device service
    await this.deviceService.cleanup();
  }
}

// Configuration
const config: DeviceManagementConfig = {
  serviceName: 'device-management-service',
  port: parseInt(process.env.PORT || '3006'),
  version: process.env.SERVICE_VERSION || '1.0.0',
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/sparc',
  corsOrigin: process.env.CORS_ORIGIN || '*',
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  wsPort: parseInt(process.env.WS_PORT || '3106'),
  discoveryInterval: parseInt(process.env.DISCOVERY_INTERVAL || '300000'), // 5 minutes
  healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '60000'), // 1 minute
  enableMetrics: true
};

// Create and start the service
const service = new DeviceManagementMicroservice(config);
service.start().catch(console.error);

export default service;