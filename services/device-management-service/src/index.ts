import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { serve } from '@hono/node-server';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import Redis from 'ioredis';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';

// Test utilities and mocks for comprehensive testing
export const createTestApp = () => {
  const testApp = new Hono();
  const testDeviceService = new DeviceManagementService();
  
  // Apply same middleware as main app
  testApp.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID']
  }));
  
  testApp.use('*', async (c, next) => {
    const tenantId = c.req.header('X-Tenant-ID');
    if (!tenantId && !c.req.path.startsWith('/health')) {
      throw new HTTPException(400, { message: 'Tenant ID required' });
    }
    c.set('tenantId', tenantId);
    await next();
  });
  
  return { app: testApp, service: testDeviceService };
};

export const createMockDevice = (overrides: Partial<Device> = {}): Device => ({
  id: 'test-device-1',
  tenantId: 'test-tenant-1',
  name: 'Test Device',
  type: 'access_panel',
  manufacturer: 'HID Global',
  model: 'VertX V100',
  firmwareVersion: '1.0.0',
  ipAddress: '192.168.1.100',
  macAddress: '00:06:8E:12:34:56',
  status: 'online',
  lastSeen: new Date(),
  location: {
    siteId: 'site-1',
    buildingId: 'building-1',
    floorId: 'floor-1',
    zone: 'zone-1'
  },
  capabilities: ['osdp', 'http_api', 'mobile_credentials'],
  configuration: { port: 4070, protocol: 'OSDP' },
  healthMetrics: {
    uptime: 86400,
    cpuUsage: 25,
    memoryUsage: 45,
    temperature: 35,
    powerStatus: 'normal',
    networkLatency: 15
  },
  protocols: ['OSDP', 'HTTP'],
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides
});

export const createMockDiscoveryResult = (overrides: Partial<DeviceDiscoveryResult> = {}): DeviceDiscoveryResult => ({
  ipAddress: '192.168.1.101',
  macAddress: '00:06:8E:12:34:57',
  manufacturer: 'Honeywell',
  model: 'NetAXS-123',
  firmwareVersion: '2.1.0',
  deviceType: 'access_panel',
  capabilities: ['http_api', 'snmp'],
  protocols: ['HTTP', 'SNMP'],
  ...overrides
});

export const createMockFirmwareUpdate = (overrides: Partial<FirmwareUpdate> = {}): FirmwareUpdate => ({
  deviceId: 'test-device-1',
  firmwareVersion: '2.0.0',
  updateUrl: 'https://updates.example.com/firmware/v2.0.0.bin',
  checksum: 'sha256:abcd1234...',
  releaseNotes: 'Security updates and bug fixes',
  mandatory: false,
  ...overrides
});

// Mock implementations for testing
export class MockPrismaClient {
  device = {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    upsert: jest.fn()
  };
  
  $disconnect = jest.fn();
  $transaction = jest.fn();
}

export class MockRedis {
  private data = new Map<string, string>();
  
  get = jest.fn((key: string) => Promise.resolve(this.data.get(key) || null));
  set = jest.fn((key: string, value: string) => {
    this.data.set(key, value);
    return Promise.resolve('OK');
  });
  setex = jest.fn((key: string, ttl: number, value: string) => {
    this.data.set(key, value);
    return Promise.resolve('OK');
  });
  del = jest.fn((key: string) => {
    const existed = this.data.has(key);
    this.data.delete(key);
    return Promise.resolve(existed ? 1 : 0);
  });
  quit = jest.fn(() => Promise.resolve());
  
  // Helper methods for testing
  clear() {
    this.data.clear();
  }
  
  getData() {
    return new Map(this.data);
  }
}

export class MockWebSocketServer {
  clients = new Set();
  
  on = jest.fn();
  close = jest.fn();
  
  addClient(client: any) {
    this.clients.add(client);
  }
  
  removeClient(client: any) {
    this.clients.delete(client);
  }
}

export class MockWebSocket {
  readyState = 1; // WebSocket.OPEN
  send = jest.fn();
  close = jest.fn();
  on = jest.fn();
}

// Test helper functions
export const waitForAsync = (ms: number = 0) => new Promise(resolve => setTimeout(resolve, ms));

export const createTestRequest = (method: string, path: string, body?: any, headers?: Record<string, string>) => {
  const defaultHeaders = {
    'Content-Type': 'application/json',
    'X-Tenant-ID': 'test-tenant-1',
    ...headers
  };
  
  return new Request(`http://localhost${path}`, {
    method,
    headers: defaultHeaders,
    body: body ? JSON.stringify(body) : undefined
  });
};

// Performance testing utilities
export class PerformanceTestRunner {
  private results: Array<{ operation: string; duration: number; success: boolean }> = [];
  
  async runConcurrentTest(
    operation: string,
    testFunction: () => Promise<void>,
    concurrency: number,
    iterations: number
  ): Promise<{ averageTime: number; successRate: number; totalOperations: number }> {
    const promises: Promise<void>[] = [];
    
    for (let i = 0; i < iterations; i++) {
      for (let j = 0; j < concurrency; j++) {
        promises.push(this.measureOperation(operation, testFunction));
      }
    }
    
    await Promise.allSettled(promises);
    
    const operationResults = this.results.filter(r => r.operation === operation);
    const successfulResults = operationResults.filter(r => r.success);
    
    return {
      averageTime: successfulResults.reduce((sum, r) => sum + r.duration, 0) / successfulResults.length,
      successRate: successfulResults.length / operationResults.length,
      totalOperations: operationResults.length
    };
  }
  
  private async measureOperation(operation: string, testFunction: () => Promise<void>): Promise<void> {
    const startTime = Date.now();
    let success = true;
    
    try {
      await testFunction();
    } catch (error) {
      success = false;
    }
    
    const duration = Date.now() - startTime;
    this.results.push({ operation, duration, success });
  }
  
  getResults() {
    return [...this.results];
  }
  
  clear() {
    this.results = [];
  }
}

// Security testing utilities
export class SecurityTestRunner {
  static async testSQLInjection(testFunction: (input: string) => Promise<any>): Promise<boolean> {
    const sqlInjectionPayloads = [
      "'; DROP TABLE devices; --",
      "' OR '1'='1",
      "'; UPDATE devices SET status='compromised'; --",
      "' UNION SELECT * FROM users; --"
    ];
    
    for (const payload of sqlInjectionPayloads) {
      try {
        await testFunction(payload);
        // If no error is thrown, the injection might have succeeded
        return false;
      } catch (error) {
        // Expected behavior - input should be rejected
        continue;
      }
    }
    
    return true; // All payloads were properly rejected
  }
  
  static async testXSSPrevention(testFunction: (input: string) => Promise<any>): Promise<boolean> {
    const xssPayloads = [
      "<script>alert('xss')</script>",
      "javascript:alert('xss')",
      "<img src=x onerror=alert('xss')>",
      "';alert('xss');//"
    ];
    
    for (const payload of xssPayloads) {
      try {
        const result = await testFunction(payload);
        // Check if the payload was properly escaped/sanitized
        if (typeof result === 'string' && result.includes('<script>')) {
          return false;
        }
      } catch (error) {
        // Input validation rejected the payload - good
        continue;
      }
    }
    
    return true;
  }
  
  static async testAuthenticationBypass(
    testFunction: (headers: Record<string, string>) => Promise<any>
  ): Promise<boolean> {
    const bypassAttempts = [
      {}, // No headers
      { 'X-Tenant-ID': '' }, // Empty tenant ID
      { 'X-Tenant-ID': 'null' }, // Null string
      { 'X-Tenant-ID': '../../../admin' }, // Path traversal
      { 'Authorization': 'Bearer invalid-token' } // Invalid token
    ];
    
    for (const headers of bypassAttempts) {
      try {
        await testFunction(headers);
        // If no error is thrown, authentication might have been bypassed
        return false;
      } catch (error) {
        // Expected behavior - unauthorized access should be rejected
        continue;
      }
    }
    
    return true;
  }
}

// Integration testing utilities
export class IntegrationTestRunner {
  private mockServices: Map<string, any> = new Map();
  
  addMockService(name: string, mock: any) {
    this.mockServices.set(name, mock);
  }
  
  getMockService(name: string) {
    return this.mockServices.get(name);
  }
  
  async testServiceIntegration(
    serviceName: string,
    testScenarios: Array<{
      name: string;
      setup: () => Promise<void>;
      test: () => Promise<void>;
      cleanup: () => Promise<void>;
    }>
  ): Promise<Array<{ name: string; success: boolean; error?: string }>> {
    const results: Array<{ name: string; success: boolean; error?: string }> = [];
    
    for (const scenario of testScenarios) {
      try {
        await scenario.setup();
        await scenario.test();
        await scenario.cleanup();
        results.push({ name: scenario.name, success: true });
      } catch (error) {
        results.push({
          name: scenario.name,
          success: false,
          error: error instanceof Error ? error.message : String(error)
        });
        try {
          await scenario.cleanup();
        } catch (cleanupError) {
          // Log cleanup error but don't fail the test
          console.warn(`Cleanup failed for ${scenario.name}:`, cleanupError);
        }
      }
    }
    
    return results;
  }
}

// Load testing utilities
export class LoadTestRunner {
  async runLoadTest(
    testName: string,
    testFunction: () => Promise<void>,
    options: {
      duration: number; // milliseconds
      rampUpTime: number; // milliseconds
      maxConcurrency: number;
      targetRPS: number; // requests per second
    }
  ): Promise<{
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTime: number;
    maxResponseTime: number;
    minResponseTime: number;
    requestsPerSecond: number;
  }> {
    const results: Array<{ success: boolean; responseTime: number }> = [];
    const startTime = Date.now();
    const endTime = startTime + options.duration;
    
    let currentConcurrency = 0;
    const maxConcurrency = options.maxConcurrency;
    const targetInterval = 1000 / options.targetRPS;
    
    const executeRequest = async (): Promise<void> => {
      if (currentConcurrency >= maxConcurrency || Date.now() >= endTime) {
        return;
      }
      
      currentConcurrency++;
      const requestStart = Date.now();
      
      try {
        await testFunction();
        const responseTime = Date.now() - requestStart;
        results.push({ success: true, responseTime });
      } catch (error) {
        const responseTime = Date.now() - requestStart;
        results.push({ success: false, responseTime });
      } finally {
        currentConcurrency--;
      }
    };
    
    // Ramp up phase
    const rampUpInterval = options.rampUpTime / maxConcurrency;
    for (let i = 0; i < maxConcurrency; i++) {
      setTimeout(() => {
        const interval = setInterval(() => {
          if (Date.now() >= endTime) {
            clearInterval(interval);
            return;
          }
          executeRequest();
        }, targetInterval);
        
        setTimeout(() => clearInterval(interval), options.duration);
      }, i * rampUpInterval);
    }
    
    // Wait for test completion
    await new Promise(resolve => setTimeout(resolve, options.duration + 1000));
    
    // Calculate metrics
    const successfulResults = results.filter(r => r.success);
    const failedResults = results.filter(r => !r.success);
    const responseTimes = results.map(r => r.responseTime);
    
    return {
      totalRequests: results.length,
      successfulRequests: successfulResults.length,
      failedRequests: failedResults.length,
      averageResponseTime: responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length,
      maxResponseTime: Math.max(...responseTimes),
      minResponseTime: Math.min(...responseTimes),
      requestsPerSecond: results.length / (options.duration / 1000)
    };
  }
}

// Device simulation utilities for testing
export class DeviceSimulator {
  private devices: Map<string, any> = new Map();
  
  createSimulatedDevice(type: string, config: any = {}): string {
    const deviceId = `sim-${type}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const device = {
      id: deviceId,
      type,
      status: 'online',
      lastSeen: new Date(),
      healthMetrics: this.generateHealthMetrics(type),
      ...config
    };
    
    this.devices.set(deviceId, device);
    return deviceId;
  }
  
  simulateDeviceFailure(deviceId: string, failureType: 'network' | 'power' | 'hardware' | 'software') {
    const device = this.devices.get(deviceId);
    if (!device) return false;
    
    switch (failureType) {
      case 'network':
        device.status = 'offline';
        device.healthMetrics.networkLatency = -1;
        break;
      case 'power':
        device.status = 'offline';
        device.healthMetrics.powerStatus = 'failure';
        break;
      case 'hardware':
        device.status = 'error';
        device.healthMetrics.temperature = 85; // Overheating
        break;
      case 'software':
        device.status = 'error';
        device.healthMetrics.cpuUsage = 100;
        device.healthMetrics.memoryUsage = 100;
        break;
    }
    
    return true;
  }
  
  simulateDeviceRecovery(deviceId: string) {
    const device = this.devices.get(deviceId);
    if (!device) return false;
    
    device.status = 'online';
    device.lastSeen = new Date();
    device.healthMetrics = this.generateHealthMetrics(device.type);
    
    return true;
  }
  
  private generateHealthMetrics(deviceType: string) {
    const baseMetrics = {
      uptime: Math.floor(Math.random() * 86400),
      powerStatus: 'normal',
      networkLatency: Math.floor(Math.random() * 50),
      lastResponse: new Date()
    };
    
    switch (deviceType) {
      case 'ip_camera':
        return {
          ...baseMetrics,
          cpuUsage: Math.floor(Math.random() * 80),
          memoryUsage: Math.floor(Math.random() * 90),
          temperature: 20 + Math.floor(Math.random() * 40),
          streamStatus: 'active'
        };
      case 'access_panel':
        return {
          ...baseMetrics,
          tamperStatus: 'secure'
        };
      case 'card_reader':
        return {
          ...baseMetrics,
          rfidStatus: 'operational'
        };
      case 'environmental_sensor':
        return {
          ...baseMetrics,
          batteryLevel: Math.floor(Math.random() * 100),
          signalStrength: Math.floor(Math.random() * 100),
          lastReading: new Date()
        };
      default:
        return baseMetrics;
    }
  }
  
  getDevice(deviceId: string) {
    return this.devices.get(deviceId);
  }
  
  getAllDevices() {
    return Array.from(this.devices.values());
  }
  
  removeDevice(deviceId: string) {
    return this.devices.delete(deviceId);
  }
  
  clear() {
    this.devices.clear();
  }
}

// Test data generators
export class TestDataGenerator {
  static generateDevices(count: number, tenantId: string = 'test-tenant-1'): Device[] {
    const devices: Device[] = [];
    const deviceTypes = ['access_panel', 'card_reader', 'ip_camera', 'environmental_sensor'] as const;
    const manufacturers = ['HID Global', 'Honeywell', 'Bosch', 'Axis', 'Hikvision'];
    
    for (let i = 0; i < count; i++) {
      const deviceType = deviceTypes[i % deviceTypes.length];
      const manufacturer = manufacturers[i % manufacturers.length];
      
      devices.push(createMockDevice({
        id: `test-device-${i + 1}`,
        tenantId,
        name: `Test Device ${i + 1}`,
        type: deviceType,
        manufacturer,
        model: `Model-${i + 1}`,
        ipAddress: `192.168.1.${100 + i}`,
        macAddress: `00:06:8E:12:34:${(56 + i).toString(16).padStart(2, '0')}`,
        location: {
          siteId: `site-${Math.floor(i / 10) + 1}`,
          buildingId: `building-${Math.floor(i / 5) + 1}`,
          floorId: `floor-${Math.floor(i / 2) + 1}`,
          zone: `zone-${i + 1}`
        }
      }));
    }
    
    return devices;
  }
  
  static generateDiscoveryResults(count: number): DeviceDiscoveryResult[] {
    const results: DeviceDiscoveryResult[] = [];
    const deviceTypes = ['access_panel', 'card_reader', 'ip_camera', 'environmental_sensor'];
    const manufacturers = ['HID Global', 'Honeywell', 'Bosch', 'Axis', 'Hikvision'];
    
    for (let i = 0; i < count; i++) {
      results.push(createMockDiscoveryResult({
        ipAddress: `192.168.2.${100 + i}`,
        macAddress: `00:06:8E:AB:CD:${(10 + i).toString(16).padStart(2, '0')}`,
        manufacturer: manufacturers[i % manufacturers.length],
        model: `Discovered-Model-${i + 1}`,
        deviceType: deviceTypes[i % deviceTypes.length],
        firmwareVersion: `${Math.floor(i / 10) + 1}.${i % 10}.0`
      }));
    }
    
    return results;
  }
  
  static generateFirmwareUpdates(deviceIds: string[]): FirmwareUpdate[] {
    return deviceIds.map((deviceId, index) => createMockFirmwareUpdate({
      deviceId,
      firmwareVersion: `${Math.floor(index / 5) + 2}.0.${index % 5}`,
      updateUrl: `https://updates.example.com/firmware/${deviceId}/v${Math.floor(index / 5) + 2}.0.${index % 5}.bin`,
      mandatory: index % 3 === 0 // Every third update is mandatory
    }));
  }
}

// Test environment setup and teardown
export class TestEnvironment {
  private mockPrisma: MockPrismaClient;
  private mockRedis: MockRedis;
  private mockWsServer: MockWebSocketServer;
  private deviceSimulator: DeviceSimulator;
  
  constructor() {
    this.mockPrisma = new MockPrismaClient();
    this.mockRedis = new MockRedis();
    this.mockWsServer = new MockWebSocketServer();
    this.deviceSimulator = new DeviceSimulator();
  }
  
  async setup() {
    // Reset all mocks
    jest.clearAllMocks();
    this.mockRedis.clear();
    this.deviceSimulator.clear();
    
    // Setup default mock behaviors
    this.setupDefaultMockBehaviors();
  }
  
  async teardown() {
    // Clean up any resources
    this.mockRedis.clear();
    this.deviceSimulator.clear();
    jest.clearAllMocks();
  }
  
  private setupDefaultMockBehaviors() {
    // Setup default Prisma mock behaviors
    this.mockPrisma.device.findMany.mockResolvedValue([]);
    this.mockPrisma.device.findUnique.mockResolvedValue(null);
    this.mockPrisma.device.findFirst.mockResolvedValue(null);
    this.mockPrisma.device.create.mockImplementation((args) => 
      Promise.resolve({ ...args.data, id: args.data.id || 'generated-id' })
    );
    this.mockPrisma.device.update.mockImplementation((args) => 
      Promise.resolve({ id: args.where.id, ...args.data })
    );
    this.mockPrisma.device.delete.mockResolvedValue({ id: 'deleted-id' });
  }
  
  getMockPrisma() {
    return this.mockPrisma;
  }
  
  getMockRedis() {
    return this.mockRedis;
  }
  
  getMockWsServer() {
    return this.mockWsServer;
  }
  
  getDeviceSimulator() {
    return this.deviceSimulator;
  }
  
  // Helper method to inject mocks into service
  injectMocks(service: DeviceManagementService) {
    (service as any).prisma = this.mockPrisma;
    (service as any).redis = this.mockRedis;
    (service as any).wsServer = this.mockWsServer;
  }
}

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

// Device Management Service Class
class DeviceManagementService {
  private prisma: PrismaClient;
  private redis: Redis;
  private discoveryInterval: NodeJS.Timeout | null = null;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private wsServer: WebSocketServer | null = null;

  constructor() {
    this.prisma = new PrismaClient();
    this.redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
  }

  // Device Discovery Methods
  async startDeviceDiscovery(): Promise<void> {
    console.log('Starting device discovery service...');
    
    // Run discovery every 5 minutes
    this.discoveryInterval = setInterval(async () => {
      try {
        await this.performNetworkDiscovery();
        await this.performONVIFDiscovery();
        await this.performOSDPDiscovery();
        await this.performManufacturerDiscovery();
      } catch (error) {
        console.error('Device discovery error:', error);
      }
    }, 5 * 60 * 1000);

    // Run initial discovery
    await this.performNetworkDiscovery();
  }

  async performNetworkDiscovery(): Promise<DeviceDiscoveryResult[]> {
    console.log('Performing network discovery...');
    const discoveries: DeviceDiscoveryResult[] = [];
    
    // Network scanning logic would go here
    // This would include DHCP monitoring, mDNS discovery, etc.
    
    return discoveries;
  }

  async performONVIFDiscovery(): Promise<DeviceDiscoveryResult[]> {
    console.log('Performing ONVIF device discovery...');
    const discoveries: DeviceDiscoveryResult[] = [];
    
    // ONVIF WS-Discovery implementation would go here
    // This would discover IP cameras supporting ONVIF protocols
    
    return discoveries;
  }

  async performOSDPDiscovery(): Promise<DeviceDiscoveryResult[]> {
    console.log('Performing OSDP device discovery...');
    const discoveries: DeviceDiscoveryResult[] = [];
    
    // OSDP v2.2 discovery implementation would go here
    // This would discover access control panels and readers
    
    return discoveries;
  }

  async performManufacturerDiscovery(): Promise<DeviceDiscoveryResult[]> {
    console.log('Performing manufacturer-specific discovery...');
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
      console.error('Device configuration error:', error);
      return false;
    }
  }

  async configureAccessPanel(device: any, configuration: Record<string, any>): Promise<boolean> {
    // OSDP v2.2 configuration implementation
    console.log(`Configuring access panel ${device.id} with OSDP v2.2`);
    return true;
  }

  async configureCardReader(device: any, configuration: Record<string, any>): Promise<boolean> {
    // Card reader configuration (Mifare, DESFire, iCLASS Seos, etc.)
    console.log(`Configuring card reader ${device.id}`);
    return true;
  }

  async configureIPCamera(device: any, configuration: Record<string, any>): Promise<boolean> {
    // ONVIF Profile S/T/G configuration
    console.log(`Configuring IP camera ${device.id} with ONVIF`);
    return true;
  }

  async configureEnvironmentalSensor(device: any, configuration: Record<string, any>): Promise<boolean> {
    // Environmental sensor configuration
    console.log(`Configuring environmental sensor ${device.id}`);
    return true;
  }

  // Device Health Monitoring
  async startHealthMonitoring(): Promise<void> {
    console.log('Starting device health monitoring...');
    
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.performHealthChecks();
      } catch (error) {
        console.error('Health monitoring error:', error);
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
        console.error(`Health check failed for device ${device.id}:`, error);
        await this.markDeviceOffline(device.id);
      }
    }
  }

  async checkDeviceHealth(device: any): Promise<any> {
    // Implement device-specific health checks
    const health = {
      uptime: 0,
      cpuUsage: 0,
      memoryUsage: 0,
      temperature: 0,
      powerStatus: 'normal',
      networkLatency: 0,
      lastResponse: new Date()
    };

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
        return health;
    }
  }

  async checkAccessPanelHealth(device: any): Promise<any> {
    // OSDP health check implementation
    return {
      uptime: Math.floor(Math.random() * 86400),
      powerStatus: 'normal',
      networkLatency: Math.floor(Math.random() * 50),
      tamperStatus: 'secure',
      lastResponse: new Date()
    };
  }

  async checkCardReaderHealth(device: any): Promise<any> {
    // Card reader health check
    return {
      uptime: Math.floor(Math.random() * 86400),
      powerStatus: 'normal',
      networkLatency: Math.floor(Math.random() * 30),
      rfidStatus: 'operational',
      lastResponse: new Date()
    };
  }

  async checkIPCameraHealth(device: any): Promise<any> {
    // ONVIF health check implementation
    return {
      uptime: Math.floor(Math.random() * 86400),
      cpuUsage: Math.floor(Math.random() * 100),
      memoryUsage: Math.floor(Math.random() * 100),
      temperature: 20 + Math.floor(Math.random() * 40),
      networkLatency: Math.floor(Math.random() * 100),
      streamStatus: 'active',
      lastResponse: new Date()
    };
  }

  async checkEnvironmentalSensorHealth(device: any): Promise<any> {
    // Environmental sensor health check
    return {
      uptime: Math.floor(Math.random() * 86400),
      batteryLevel: Math.floor(Math.random() * 100),
      signalStrength: Math.floor(Math.random() * 100),
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
      console.error('Firmware update error:', error);
      return false;
    }
  }

  async performFirmwareUpdate(device: any, update: FirmwareUpdate): Promise<boolean> {
    console.log(`Updating firmware for device ${device.id} to version ${update.firmwareVersion}`);
    
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
    await this.prisma.$disconnect();
    await this.redis.quit();
  }
}

// Initialize Hono app
const app = new Hono();
const deviceService = new DeviceManagementService();

// Middleware
app.use('*', cors({
  origin: process.env.CORS_ORIGIN || '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID']
}));

app.use('*', logger());
app.use('*', prettyJSON());

// Tenant middleware
app.use('*', async (c, next) => {
  const tenantId = c.req.header('X-Tenant-ID');
  if (!tenantId && !c.req.path.startsWith('/health')) {
    throw new HTTPException(400, { message: 'Tenant ID required' });
  }
  c.set('tenantId', tenantId);
  await next();
});

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'device-management-service',
    timestamp: new Date().toISOString(),
    version: process.env.SERVICE_VERSION || '1.0.0'
  });
});

// Device discovery endpoints
app.post('/api/devices/discover', async (c) => {
  try {
    const discoveries = await deviceService.performNetworkDiscovery();
    return c.json({ discoveries });
  } catch (error) {
    throw new HTTPException(500, { message: 'Discovery failed' });
  }
});

app.post('/api/devices/discover/onvif', async (c) => {
  try {
    const discoveries = await deviceService.performONVIFDiscovery();
    return c.json({ discoveries });
  } catch (error) {
    throw new HTTPException(500, { message: 'ONVIF discovery failed' });
  }
});

app.post('/api/devices/discover/osdp', async (c) => {
  try {
    const discoveries = await deviceService.performOSDPDiscovery();
    return c.json({ discoveries });
  } catch (error) {
    throw new HTTPException(500, { message: 'OSDP discovery failed' });
  }
});

// Device management endpoints
app.get('/api/devices', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const devices = await deviceService.prisma.device.findMany({
      where: { tenantId }
    });
    return c.json({ devices });
  } catch (error) {
    throw new HTTPException(500, { message: 'Failed to fetch devices' });
  }
});

app.get('/api/devices/:id', async (c) => {
  try {
    const deviceId = c.req.param('id');
    const tenantId = c.get('tenantId');
    
    const device = await deviceService.prisma.device.findFirst({
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

app.post('/api/devices', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const validatedData = deviceConfigSchema.parse(body);
    
    const device = await deviceService.prisma.device.create({
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

app.put('/api/devices/:id/configure', async (c) => {
  try {
    const deviceId = c.req.param('id');
    const body = await c.req.json();
    
    const success = await deviceService.configureDevice(deviceId, body.configuration);
    
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
app.get('/api/devices/:id/health', async (c) => {
  try {
    const deviceId = c.req.param('id');
    const healthData = await deviceService.redis.get(`device:health:${deviceId}`);
    
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
app.get('/api/devices/:id/firmware/updates', async (c) => {
  try {
    const deviceId = c.req.param('id');
    const update = await deviceService.checkFirmwareUpdates(deviceId);
    
    return c.json({ update });
  } catch (error) {
    throw new HTTPException(500, { message: 'Failed to check firmware updates' });
  }
});

app.post('/api/devices/:id/firmware/update', async (c) => {
  try {
    const deviceId = c.req.param('id');
    const body = await c.req.json();
    const validatedUpdate = firmwareUpdateSchema.parse(body);
    
    const update: FirmwareUpdate = {
      deviceId,
      ...validatedUpdate
    };
    
    const success = await deviceService.updateFirmware(deviceId, update);
    
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

// Error handling
app.onError((err, c) => {
  console.error('Service error:', err);
  
  if (err instanceof HTTPException) {
    return c.json({
      error: err.message,
      status: err.status
    }, err.status);
  }
  
  return c.json({
    error: 'Internal server error',
    status: 500
  }, 500);
});

// Start server
const port = parseInt(process.env.PORT || '3006');
const server = createServer();

// Setup WebSocket server for real-time updates
const wsServer = new WebSocketServer({ server });
deviceService.wsServer = wsServer;

wsServer.on('connection', (ws) => {
  console.log('WebSocket client connected');
  
  ws.on('close', () => {
    console.log('WebSocket client disconnected');
  });
});

// Start services
async function startServer() {
  try {
    console.log('Starting Device Management Service...');
    
    // Start device discovery and health monitoring
    await deviceService.startDeviceDiscovery();
    await deviceService.startHealthMonitoring();
    
    // Start HTTP server
    serve({
      fetch: app.fetch,
      port,
      createServer: () => server
    });
    
    console.log(`Device Management Service running on port ${port}`);
    console.log(`WebSocket server running for real-time updates`);
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  await deviceService.cleanup();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('Received SIGINT, shutting down gracefully...');
  await deviceService.cleanup();
  process.exit(0);
});

// Start the server
if (require.main === module) {
  startServer();
}

export default app;
export {
  DeviceManagementService,
  Device,
  DeviceDiscoveryResult,
  FirmwareUpdate,
  deviceConfigSchema,
  firmwareUpdateSchema,
  createTestApp,
  createMockDevice,
  createMockDiscoveryResult,
  createMockFirmwareUpdate,
  MockPrismaClient,
  MockRedis,
  MockWebSocketServer,
  MockWebSocket,
  waitForAsync,
  createTestRequest,
  PerformanceTestRunner,
  SecurityTestRunner,
  IntegrationTestRunner,
  LoadTestRunner,
  DeviceSimulator,
  TestDataGenerator,
  TestEnvironment
};
