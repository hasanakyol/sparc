import { MicroserviceBase } from '@sparc/shared/microservice-base';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';

// Types and interfaces for device management
interface Device {
  id: string;
  tenantId: string;
  name: string;
  type: 'access_panel' | 'card_reader' | 'ip_camera' | 'environmental_sensor';
  manufacturer: string;
  model: string;
  firmwareVersion: string;
  ipAddress: string;
  macAddress: string;
  status: 'online' | 'offline' | 'error' | 'maintenance';
  lastSeen: Date;
  location: {
    siteId: string;
    buildingId: string;
    floorId: string;
    zone?: string;
  };
  capabilities: string[];
  configuration: Record<string, any>;
  healthMetrics: {
    uptime: number;
    cpuUsage?: number;
    memoryUsage?: number;
    temperature?: number;
    powerStatus?: string;
    networkLatency?: number;
  };
  protocols: string[];
  createdAt: Date;
  updatedAt: Date;
}

interface DeviceDiscoveryResult {
  ipAddress: string;
  macAddress: string;
  manufacturer: string;
  model: string;
  firmwareVersion: string;
  deviceType: string;
  capabilities: string[];
  protocols: string[];
}

interface FirmwareUpdate {
  deviceId: string;
  firmwareVersion: string;
  updateUrl: string;
  checksum: string;
  releaseNotes: string;
  mandatory: boolean;
}

// Validation schemas
const deviceConfigSchema = z.object({
  name: z.string().min(1).max(100),
  type: z.enum(['access_panel', 'card_reader', 'ip_camera', 'environmental_sensor']),
  ipAddress: z.string().ip(),
  location: z.object({
    siteId: z.string().uuid(),
    buildingId: z.string().uuid(),
    floorId: z.string().uuid(),
    zone: z.string().optional()
  }),
  configuration: z.record(z.any()).optional()
});

const firmwareUpdateSchema = z.object({
  firmwareVersion: z.string(),
  updateUrl: z.string().url(),
  checksum: z.string(),
  releaseNotes: z.string(),
  mandatory: z.boolean().default(false)
});

// Device Management Service Core
class DeviceManagementCore {
  private discoveryInterval: NodeJS.Timeout | null = null;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private wsServer: WebSocketServer | null,
    private logger: any
  ) {}

  // Device Discovery Methods
  async startDeviceDiscovery(): Promise<void> {
    this.logger.info('Starting device discovery service...');
    
    // Run discovery every 5 minutes
    this.discoveryInterval = setInterval(async () => {
      try {
        await this.performNetworkDiscovery();
        await this.performONVIFDiscovery();
        await this.performOSDPDiscovery();
        await this.performManufacturerDiscovery();
      } catch (error) {
        this.logger.error('Device discovery error:', error);
      }
    }, 5 * 60 * 1000);

    // Run initial discovery
    await this.performNetworkDiscovery();
  }

  async performNetworkDiscovery(): Promise<DeviceDiscoveryResult[]> {
    this.logger.info('Performing network discovery...');
    const discoveries: DeviceDiscoveryResult[] = [];
    
    // Network scanning logic would go here
    // This would include DHCP monitoring, mDNS discovery, etc.
    
    return discoveries;
  }

  async performONVIFDiscovery(): Promise<DeviceDiscoveryResult[]> {
    this.logger.info('Performing ONVIF device discovery...');
    const discoveries: DeviceDiscoveryResult[] = [];
    
    // ONVIF WS-Discovery implementation would go here
    // This would discover IP cameras supporting ONVIF protocols
    
    return discoveries;
  }

  async performOSDPDiscovery(): Promise<DeviceDiscoveryResult[]> {
    this.logger.info('Performing OSDP device discovery...');
    const discoveries: DeviceDiscoveryResult[] = [];
    
    // OSDP v2.2 discovery implementation would go here
    // This would discover access control panels and readers
    
    return discoveries;
  }

  async performManufacturerDiscovery(): Promise<DeviceDiscoveryResult[]> {
    this.logger.info('Performing manufacturer-specific discovery...');
    const discoveries: DeviceDiscoveryResult[] = [];
    
    // Manufacturer-specific discovery protocols
    // HID, Honeywell, Bosch, Axis, Hikvision, Dahua, Hanwha, Genetec
    
    return discoveries;
  }

  // Device Configuration Methods
  async configureDevice(deviceId: string, configuration: Record<string, any>): Promise<boolean> {
    try {
      const device = await this.prisma.device.findUnique({
        where: { id: deviceId }
      });

      if (!device) {
        throw new Error('Device not found');
      }

      // Apply configuration based on device type and manufacturer
      switch (device.type) {
        case 'access_panel':
          return await this.configureAccessPanel(device, configuration);
        case 'card_reader':
          return await this.configureCardReader(device, configuration);
        case 'ip_camera':
          return await this.configureIPCamera(device, configuration);
        case 'environmental_sensor':
          return await this.configureEnvironmentalSensor(device, configuration);
        default:
          throw new Error('Unsupported device type');
      }
    } catch (error) {
      this.logger.error('Device configuration error:', error);
      return false;
    }
  }

  async configureAccessPanel(device: any, configuration: Record<string, any>): Promise<boolean> {
    // OSDP v2.2 configuration implementation
    this.logger.info(`Configuring access panel ${device.id} with OSDP v2.2`);
    return true;
  }

  async configureCardReader(device: any, configuration: Record<string, any>): Promise<boolean> {
    // Card reader configuration (Mifare, DESFire, iCLASS Seos, etc.)
    this.logger.info(`Configuring card reader ${device.id}`);
    return true;
  }

  async configureIPCamera(device: any, configuration: Record<string, any>): Promise<boolean> {
    // ONVIF Profile S/T/G configuration
    this.logger.info(`Configuring IP camera ${device.id} with ONVIF`);
    return true;
  }

  async configureEnvironmentalSensor(device: any, configuration: Record<string, any>): Promise<boolean> {
    // Environmental sensor configuration
    this.logger.info(`Configuring environmental sensor ${device.id}`);
    return true;
  }

  // Device Health Monitoring
  async startHealthMonitoring(): Promise<void> {
    this.logger.info('Starting device health monitoring...');
    
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.performHealthChecks();
      } catch (error) {
        this.logger.error('Health monitoring error:', error);
      }
    }, 30 * 1000); // Every 30 seconds
  }

  async performHealthChecks(): Promise<void> {
    const devices = await this.prisma.device.findMany({
      where: { status: { not: 'maintenance' } }
    });

    for (const device of devices) {
      try {
        const health = await this.checkDeviceHealth(device);
        await this.updateDeviceHealth(device.id, health);
        
        // Broadcast health updates via WebSocket
        if (this.wsServer) {
          this.broadcastHealthUpdate(device.id, health);
        }
      } catch (error) {
        this.logger.error(`Health check failed for device ${device.id}:`, error);
        await this.markDeviceOffline(device.id);
      }
    }
  }

  async checkDeviceHealth(device: any): Promise<any> {
    // Device-specific health check implementation
    switch (device.type) {
      case 'access_panel':
        return await this.checkAccessPanelHealth(device);
      case 'card_reader':
        return await this.checkCardReaderHealth(device);
      case 'ip_camera':
        return await this.checkIPCameraHealth(device);
      case 'environmental_sensor':
        return await this.checkEnvironmentalSensorHealth(device);
      default:
        return {
          uptime: 0,
          powerStatus: 'unknown',
          networkLatency: -1,
          lastResponse: new Date()
        };
    }
  }

  async checkAccessPanelHealth(device: any): Promise<any> {
    // OSDP health check implementation
    // In production, this would make actual OSDP protocol calls
    return {
      uptime: 0,
      powerStatus: 'normal',
      networkLatency: 0,
      tamperStatus: 'secure',
      lastResponse: new Date()
    };
  }

  async checkCardReaderHealth(device: any): Promise<any> {
    // Card reader health check
    // In production, this would make actual device API calls
    return {
      uptime: 0,
      powerStatus: 'normal',
      networkLatency: 0,
      rfidStatus: 'operational',
      lastResponse: new Date()
    };
  }

  async checkIPCameraHealth(device: any): Promise<any> {
    // ONVIF health check implementation
    // In production, this would make actual ONVIF calls
    return {
      uptime: 0,
      cpuUsage: 0,
      memoryUsage: 0,
      temperature: 0,
      networkLatency: 0,
      streamStatus: 'active',
      lastResponse: new Date()
    };
  }

  async checkEnvironmentalSensorHealth(device: any): Promise<any> {
    // Environmental sensor health check
    // In production, this would query actual sensor APIs
    return {
      uptime: 0,
      batteryLevel: 0,
      signalStrength: 0,
      lastReading: new Date(),
      lastResponse: new Date()
    };
  }

  async updateDeviceHealth(deviceId: string, health: any): Promise<void> {
    await this.prisma.device.update({
      where: { id: deviceId },
      data: {
        healthMetrics: health,
        lastSeen: new Date(),
        status: 'online'
      }
    });

    // Cache health data in Redis for quick access
    await this.redis.setex(`device:health:${deviceId}`, 300, JSON.stringify(health));
  }

  async markDeviceOffline(deviceId: string): Promise<void> {
    await this.prisma.device.update({
      where: { id: deviceId },
      data: { status: 'offline' }
    });
  }

  // Firmware Management
  async checkFirmwareUpdates(deviceId: string): Promise<FirmwareUpdate | null> {
    const device = await this.prisma.device.findUnique({
      where: { id: deviceId }
    });

    if (!device) return null;

    // Check for firmware updates based on manufacturer and model
    // This would integrate with manufacturer APIs or update servers
    return null;
  }

  async updateFirmware(deviceId: string, update: FirmwareUpdate): Promise<boolean> {
    try {
      const device = await this.prisma.device.findUnique({
        where: { id: deviceId }
      });

      if (!device) {
        throw new Error('Device not found');
      }

      // Mark device as in maintenance mode
      await this.prisma.device.update({
        where: { id: deviceId },
        data: { status: 'maintenance' }
      });

      // Perform firmware update based on device type
      const success = await this.performFirmwareUpdate(device, update);

      // Update device status and firmware version
      await this.prisma.device.update({
        where: { id: deviceId },
        data: {
          status: success ? 'online' : 'error',
          firmwareVersion: success ? update.firmwareVersion : device.firmwareVersion
        }
      });

      return success;
    } catch (error) {
      this.logger.error('Firmware update error:', error);
      return false;
    }
  }

  async performFirmwareUpdate(device: any, update: FirmwareUpdate): Promise<boolean> {
    this.logger.info(`Updating firmware for device ${device.id} to version ${update.firmwareVersion}`);
    
    // Device-specific firmware update implementation
    // This would handle manufacturer-specific update procedures
    
    return true;
  }

  // WebSocket broadcasting
  broadcastHealthUpdate(deviceId: string, health: any): void {
    if (!this.wsServer) return;

    const message = JSON.stringify({
      type: 'device_health_update',
      deviceId,
      health,
      timestamp: new Date().toISOString()
    });

    this.wsServer.clients.forEach(client => {
      if (client.readyState === 1) { // WebSocket.OPEN
        client.send(message);
      }
    });
  }

  // Cleanup
  async cleanup(): Promise<void> {
    if (this.discoveryInterval) {
      clearInterval(this.discoveryInterval);
    }
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
  }
}

// Device Management Service
class DeviceManagementService extends MicroserviceBase {
  private prisma: PrismaClient;
  private redis: Redis;
  private wsServer?: WebSocketServer;
  private deviceCore?: DeviceManagementCore;

  constructor() {
    super('device-management-service', {
      port: parseInt(process.env.PORT || '3006', 10)
    });

    this.prisma = new PrismaClient();
    this.redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
  }

  protected async setupRoutes(): Promise<void> {
    // Test connections
    await this.testConnections();
    
    // Setup WebSocket server
    this.setupWebSocket();
    
    // Initialize device management core
    this.deviceCore = new DeviceManagementCore(
      this.prisma,
      this.redis,
      this.wsServer || null,
      this.logger
    );
    
    // Start device discovery and health monitoring
    await this.deviceCore.startDeviceDiscovery();
    await this.deviceCore.startHealthMonitoring();
    
    // Setup routes
    this.setupDeviceRoutes();
    
    // Service-specific health check
    this.app.get('/health/detailed', async (c) => {
      const redisInfo = await this.redis.info();
      
      return c.json({
        service: this.serviceName,
        status: 'healthy',
        connections: {
          database: await this.prisma.$queryRaw`SELECT 1`,
          redis: redisInfo.includes('redis_version')
        },
        websocket: {
          clients: this.wsServer?.clients?.size || 0
        },
        timestamp: new Date().toISOString()
      });
    });
  }

  private async testConnections(): Promise<void> {
    try {
      // Connect to database
      await this.prisma.$connect();
      this.logger.info('Connected to database');
      
      // Test Redis connection
      await this.redis.ping();
      this.logger.info('Connected to Redis');
    } catch (error) {
      this.logger.error('Failed to establish connections', { error });
      throw error;
    }
  }

  private setupWebSocket(): void {
    const server = createServer();
    this.wsServer = new WebSocketServer({ server });
    
    this.wsServer.on('connection', (ws) => {
      this.logger.info('WebSocket client connected');
      
      ws.on('close', () => {
        this.logger.info('WebSocket client disconnected');
      });
      
      ws.on('error', (error) => {
        this.logger.error('WebSocket error', { error });
      });
      
      // Send welcome message
      ws.send(JSON.stringify({
        type: 'connected',
        message: 'Connected to device management service',
        timestamp: new Date().toISOString()
      }));
    });
    
    // Start WebSocket server on different port
    const wsPort = parseInt(process.env.WS_PORT || '3016', 10);
    server.listen(wsPort, () => {
      this.logger.info(`WebSocket server listening on port ${wsPort}`);
    });
  }

  private setupDeviceRoutes(): void {
    // Device discovery endpoints
    this.app.post('/api/devices/discover', async (c) => {
      try {
        const discoveries = await this.deviceCore!.performNetworkDiscovery();
        return c.json({ discoveries });
      } catch (error) {
        throw new HTTPException(500, { message: 'Discovery failed' });
      }
    });

    this.app.post('/api/devices/discover/onvif', async (c) => {
      try {
        const discoveries = await this.deviceCore!.performONVIFDiscovery();
        return c.json({ discoveries });
      } catch (error) {
        throw new HTTPException(500, { message: 'ONVIF discovery failed' });
      }
    });

    this.app.post('/api/devices/discover/osdp', async (c) => {
      try {
        const discoveries = await this.deviceCore!.performOSDPDiscovery();
        return c.json({ discoveries });
      } catch (error) {
        throw new HTTPException(500, { message: 'OSDP discovery failed' });
      }
    });

    // Device management endpoints
    this.app.get('/api/devices', async (c) => {
      try {
        const tenantId = c.get('tenantId');
        const devices = await this.prisma.device.findMany({
          where: { tenantId }
        });
        return c.json({ devices });
      } catch (error) {
        throw new HTTPException(500, { message: 'Failed to fetch devices' });
      }
    });

    this.app.get('/api/devices/:id', async (c) => {
      try {
        const deviceId = c.req.param('id');
        const tenantId = c.get('tenantId');
        
        const device = await this.prisma.device.findFirst({
          where: { id: deviceId, tenantId }
        });
        
        if (!device) {
          throw new HTTPException(404, { message: 'Device not found' });
        }
        
        return c.json({ device });
      } catch (error) {
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, { message: 'Failed to fetch device' });
      }
    });

    this.app.post('/api/devices', async (c) => {
      try {
        const tenantId = c.get('tenantId');
        const body = await c.req.json();
        const validatedData = deviceConfigSchema.parse(body);
        
        const device = await this.prisma.device.create({
          data: {
            ...validatedData,
            tenantId,
            id: crypto.randomUUID(),
            manufacturer: 'Unknown',
            model: 'Unknown',
            firmwareVersion: '1.0.0',
            macAddress: '00:00:00:00:00:00',
            status: 'offline',
            lastSeen: new Date(),
            capabilities: [],
            healthMetrics: {},
            protocols: [],
            createdAt: new Date(),
            updatedAt: new Date()
          }
        });
        
        return c.json({ device }, 201);
      } catch (error) {
        if (error instanceof z.ZodError) {
          throw new HTTPException(400, { message: 'Invalid device data' });
        }
        throw new HTTPException(500, { message: 'Failed to create device' });
      }
    });

    this.app.put('/api/devices/:id/configure', async (c) => {
      try {
        const deviceId = c.req.param('id');
        const body = await c.req.json();
        
        const success = await this.deviceCore!.configureDevice(deviceId, body.configuration);
        
        if (!success) {
          throw new HTTPException(500, { message: 'Device configuration failed' });
        }
        
        return c.json({ success: true });
      } catch (error) {
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, { message: 'Configuration failed' });
      }
    });

    // Device health endpoints
    this.app.get('/api/devices/:id/health', async (c) => {
      try {
        const deviceId = c.req.param('id');
        const healthData = await this.redis.get(`device:health:${deviceId}`);
        
        if (!healthData) {
          throw new HTTPException(404, { message: 'Health data not found' });
        }
        
        return c.json({ health: JSON.parse(healthData) });
      } catch (error) {
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, { message: 'Failed to fetch health data' });
      }
    });

    // Firmware management endpoints
    this.app.get('/api/devices/:id/firmware/updates', async (c) => {
      try {
        const deviceId = c.req.param('id');
        const update = await this.deviceCore!.checkFirmwareUpdates(deviceId);
        
        return c.json({ update });
      } catch (error) {
        throw new HTTPException(500, { message: 'Failed to check firmware updates' });
      }
    });

    this.app.post('/api/devices/:id/firmware/update', async (c) => {
      try {
        const deviceId = c.req.param('id');
        const body = await c.req.json();
        const validatedUpdate = firmwareUpdateSchema.parse(body);
        
        const update: FirmwareUpdate = {
          deviceId,
          ...validatedUpdate
        };
        
        const success = await this.deviceCore!.updateFirmware(deviceId, update);
        
        if (!success) {
          throw new HTTPException(500, { message: 'Firmware update failed' });
        }
        
        return c.json({ success: true });
      } catch (error) {
        if (error instanceof z.ZodError) {
          throw new HTTPException(400, { message: 'Invalid firmware update data' });
        }
        if (error instanceof HTTPException) throw error;
        throw new HTTPException(500, { message: 'Firmware update failed' });
      }
    });
  }

  protected async cleanup(): Promise<void> {
    try {
      // Stop device core services
      if (this.deviceCore) {
        await this.deviceCore.cleanup();
      }
      
      // Disconnect from database
      await this.prisma.$disconnect();
      this.logger.info('Disconnected from database');
      
      // Close Redis connection
      await this.redis.quit();
      this.logger.info('Disconnected from Redis');
      
      // Close WebSocket server
      if (this.wsServer) {
        await new Promise<void>((resolve) => {
          this.wsServer!.close(() => {
            this.logger.info('WebSocket server closed');
            resolve();
          });
        });
      }
    } catch (error) {
      this.logger.error('Error during cleanup', { error });
      throw error;
    }
    
    await super.cleanup();
  }
}

// Create and start the service
const service = new DeviceManagementService();
service.start();

export default service;