import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { z } from 'zod';
import axios from 'axios';
import crypto from 'crypto';

// Initialize Prisma and Redis clients
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Configuration
const config = {
  port: parseInt(process.env.PORT || '3008'),
  host: process.env.HOST || '0.0.0.0',
  environment: process.env.NODE_ENV || 'development',
  alertServiceUrl: process.env.ALERT_SERVICE_URL || 'http://alert-service:3002',
  accessControlServiceUrl: process.env.ACCESS_CONTROL_SERVICE_URL || 'http://access-control-service:3003',
};

// Logger setup
const appLogger = {
  info: (message: string, meta?: any) => console.log(JSON.stringify({ level: 'info', message, ...meta, timestamp: new Date().toISOString() })),
  warn: (message: string, meta?: any) => console.log(JSON.stringify({ level: 'warn', message, ...meta, timestamp: new Date().toISOString() })),
  error: (message: string, meta?: any) => console.log(JSON.stringify({ level: 'error', message, ...meta, timestamp: new Date().toISOString() })),
  debug: (message: string, meta?: any) => console.log(JSON.stringify({ level: 'debug', message, ...meta, timestamp: new Date().toISOString() })),
};

// Validation schemas
const elevatorControlSchema = z.object({
  name: z.string().min(1).max(255),
  buildingId: z.string().cuid(),
  floorsServed: z.array(z.number().int().min(0)),
  ipAddress: z.string().ip(),
  protocol: z.enum(['REST', 'SOAP', 'TCP', 'MODBUS', 'BACNET']),
  manufacturer: z.enum(['OTIS', 'KONE', 'SCHINDLER', 'THYSSENKRUPP', 'MITSUBISHI', 'FUJITEC', 'GENERIC']),
  accessRules: z.object({
    defaultAccess: z.boolean().default(false),
    timeBasedAccess: z.boolean().default(true),
    emergencyAccess: z.boolean().default(true),
    maintenanceAccess: z.boolean().default(false),
  }).default({}),
});

const floorAccessRequestSchema = z.object({
  userId: z.string().cuid(),
  targetFloor: z.number().int().min(0),
  credentialId: z.string().cuid().optional(),
  reason: z.string().optional(),
});

const emergencyOverrideSchema = z.object({
  action: z.enum(['ENABLE', 'DISABLE', 'EVACUATE', 'LOCKDOWN']),
  reason: z.string().min(1),
  duration: z.number().int().min(1).max(86400).optional(), // Max 24 hours
});

const destinationDispatchSchema = z.object({
  userId: z.string().cuid(),
  targetFloor: z.number().int().min(0),
  priority: z.enum(['LOW', 'NORMAL', 'HIGH', 'EMERGENCY']).default('NORMAL'),
});

// Manufacturer-specific protocol adapters
class ElevatorProtocolAdapter {
  constructor(private manufacturer: string, private config: any) {}

  async sendFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    switch (this.manufacturer) {
      case 'OTIS':
        return this.otisFloorRequest(elevatorId, floor, userId);
      case 'KONE':
        return this.koneFloorRequest(elevatorId, floor, userId);
      case 'SCHINDLER':
        return this.schindlerFloorRequest(elevatorId, floor, userId);
      case 'THYSSENKRUPP':
        return this.thyssenkruppFloorRequest(elevatorId, floor, userId);
      case 'MITSUBISHI':
        return this.mitsubishiFloorRequest(elevatorId, floor, userId);
      case 'FUJITEC':
        return this.fujitecFloorRequest(elevatorId, floor, userId);
      default:
        return this.genericFloorRequest(elevatorId, floor, userId);
    }
  }

  async getElevatorStatus(elevatorId: string): Promise<any> {
    switch (this.manufacturer) {
      case 'OTIS':
        return this.otisGetStatus(elevatorId);
      case 'KONE':
        return this.koneGetStatus(elevatorId);
      case 'SCHINDLER':
        return this.schindlerGetStatus(elevatorId);
      case 'THYSSENKRUPP':
        return this.thyssenkruppGetStatus(elevatorId);
      case 'MITSUBISHI':
        return this.mitsubishiGetStatus(elevatorId);
      case 'FUJITEC':
        return this.fujitecGetStatus(elevatorId);
      default:
        return this.genericGetStatus(elevatorId);
    }
  }

  async setEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    switch (this.manufacturer) {
      case 'OTIS':
        return this.otisEmergencyOverride(elevatorId, enabled, reason);
      case 'KONE':
        return this.koneEmergencyOverride(elevatorId, enabled, reason);
      case 'SCHINDLER':
        return this.schindlerEmergencyOverride(elevatorId, enabled, reason);
      case 'THYSSENKRUPP':
        return this.thyssenkruppEmergencyOverride(elevatorId, enabled, reason);
      case 'MITSUBISHI':
        return this.mitsubishiEmergencyOverride(elevatorId, enabled, reason);
      case 'FUJITEC':
        return this.fujitecEmergencyOverride(elevatorId, enabled, reason);
      default:
        return this.genericEmergencyOverride(elevatorId, enabled, reason);
    }
  }

  // Otis-specific implementations
  private async otisFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/call`, {
        floor: floor,
        userId: userId,
        timestamp: new Date().toISOString(),
      }, {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('Otis floor request failed', { elevatorId, floor, userId, error: error.message });
      return false;
    }
  }

  private async otisGetStatus(elevatorId: string): Promise<any> {
    try {
      const response = await axios.get(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/status`, {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
        timeout: 5000,
      });
      return {
        currentFloor: response.data.currentFloor,
        direction: response.data.direction,
        doorStatus: response.data.doorStatus,
        operationalStatus: response.data.operationalStatus,
        emergencyMode: response.data.emergencyMode,
        lastUpdate: new Date().toISOString(),
      };
    } catch (error) {
      appLogger.error('Otis status request failed', { elevatorId, error: error.message });
      return null;
    }
  }

  private async otisEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/emergency`, {
        enabled: enabled,
        reason: reason,
        timestamp: new Date().toISOString(),
      }, {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('Otis emergency override failed', { elevatorId, enabled, reason, error: error.message });
      return false;
    }
  }

  // KONE-specific implementations
  private async koneFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/kone/api/elevator/${elevatorId}/destination`, {
        destination_floor: floor,
        user_id: userId,
        request_time: new Date().toISOString(),
      }, {
        headers: {
          'X-API-Key': this.config.apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 201;
    } catch (error) {
      appLogger.error('KONE floor request failed', { elevatorId, floor, userId, error: error.message });
      return false;
    }
  }

  private async koneGetStatus(elevatorId: string): Promise<any> {
    try {
      const response = await axios.get(`${this.config.baseUrl}/kone/api/elevator/${elevatorId}`, {
        headers: {
          'X-API-Key': this.config.apiKey,
        },
        timeout: 5000,
      });
      return {
        currentFloor: response.data.current_floor,
        direction: response.data.travel_direction,
        doorStatus: response.data.door_state,
        operationalStatus: response.data.operational_state,
        emergencyMode: response.data.emergency_mode,
        lastUpdate: new Date().toISOString(),
      };
    } catch (error) {
      appLogger.error('KONE status request failed', { elevatorId, error: error.message });
      return null;
    }
  }

  private async koneEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    try {
      const response = await axios.put(`${this.config.baseUrl}/kone/api/elevator/${elevatorId}/emergency`, {
        emergency_mode: enabled,
        reason: reason,
        timestamp: new Date().toISOString(),
      }, {
        headers: {
          'X-API-Key': this.config.apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('KONE emergency override failed', { elevatorId, enabled, reason, error: error.message });
      return false;
    }
  }

  // Schindler-specific implementations
  private async schindlerFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/schindler/v2/elevators/${elevatorId}/calls`, {
        floor: floor,
        user: userId,
        timestamp: Math.floor(Date.now() / 1000),
      }, {
        headers: {
          'Authorization': `ApiKey ${this.config.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 202;
    } catch (error) {
      appLogger.error('Schindler floor request failed', { elevatorId, floor, userId, error: error.message });
      return false;
    }
  }

  private async schindlerGetStatus(elevatorId: string): Promise<any> {
    try {
      const response = await axios.get(`${this.config.baseUrl}/schindler/v2/elevators/${elevatorId}/status`, {
        headers: {
          'Authorization': `ApiKey ${this.config.apiKey}`,
        },
        timeout: 5000,
      });
      return {
        currentFloor: response.data.floor,
        direction: response.data.direction,
        doorStatus: response.data.doors,
        operationalStatus: response.data.status,
        emergencyMode: response.data.emergency,
        lastUpdate: new Date().toISOString(),
      };
    } catch (error) {
      appLogger.error('Schindler status request failed', { elevatorId, error: error.message });
      return null;
    }
  }

  private async schindlerEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/schindler/v2/elevators/${elevatorId}/emergency`, {
        enable: enabled,
        reason: reason,
        timestamp: Math.floor(Date.now() / 1000),
      }, {
        headers: {
          'Authorization': `ApiKey ${this.config.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('Schindler emergency override failed', { elevatorId, enabled, reason, error: error.message });
      return false;
    }
  }

  // ThyssenKrupp-specific implementations
  private async thyssenkruppFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/tk/api/v1/elevator/${elevatorId}/request`, {
        targetFloor: floor,
        userId: userId,
        requestId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
      }, {
        headers: {
          'X-TK-API-Key': this.config.apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('ThyssenKrupp floor request failed', { elevatorId, floor, userId, error: error.message });
      return false;
    }
  }

  private async thyssenkruppGetStatus(elevatorId: string): Promise<any> {
    try {
      const response = await axios.get(`${this.config.baseUrl}/tk/api/v1/elevator/${elevatorId}`, {
        headers: {
          'X-TK-API-Key': this.config.apiKey,
        },
        timeout: 5000,
      });
      return {
        currentFloor: response.data.currentFloor,
        direction: response.data.movementDirection,
        doorStatus: response.data.doorState,
        operationalStatus: response.data.operationMode,
        emergencyMode: response.data.emergencyState,
        lastUpdate: new Date().toISOString(),
      };
    } catch (error) {
      appLogger.error('ThyssenKrupp status request failed', { elevatorId, error: error.message });
      return null;
    }
  }

  private async thyssenkruppEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    try {
      const response = await axios.put(`${this.config.baseUrl}/tk/api/v1/elevator/${elevatorId}/emergency`, {
        emergencyMode: enabled,
        reason: reason,
        operatorId: 'system',
        timestamp: new Date().toISOString(),
      }, {
        headers: {
          'X-TK-API-Key': this.config.apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('ThyssenKrupp emergency override failed', { elevatorId, enabled, reason, error: error.message });
      return false;
    }
  }

  // Mitsubishi-specific implementations
  private async mitsubishiFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/mitsubishi/api/elevator/${elevatorId}/call`, {
        floor: floor,
        user: userId,
        time: new Date().toISOString(),
      }, {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('Mitsubishi floor request failed', { elevatorId, floor, userId, error: error.message });
      return false;
    }
  }

  private async mitsubishiGetStatus(elevatorId: string): Promise<any> {
    try {
      const response = await axios.get(`${this.config.baseUrl}/mitsubishi/api/elevator/${elevatorId}/status`, {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
        },
        timeout: 5000,
      });
      return {
        currentFloor: response.data.floor,
        direction: response.data.direction,
        doorStatus: response.data.door,
        operationalStatus: response.data.operation,
        emergencyMode: response.data.emergency,
        lastUpdate: new Date().toISOString(),
      };
    } catch (error) {
      appLogger.error('Mitsubishi status request failed', { elevatorId, error: error.message });
      return null;
    }
  }

  private async mitsubishiEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/mitsubishi/api/elevator/${elevatorId}/emergency`, {
        emergency: enabled,
        reason: reason,
        timestamp: new Date().toISOString(),
      }, {
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('Mitsubishi emergency override failed', { elevatorId, enabled, reason, error: error.message });
      return false;
    }
  }

  // Fujitec-specific implementations
  private async fujitecFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    try {
      const response = await axios.post(`${this.config.baseUrl}/fujitec/api/v1/elevators/${elevatorId}/destination`, {
        destination: floor,
        userId: userId,
        requestTime: new Date().toISOString(),
      }, {
        headers: {
          'X-Fujitec-Key': this.config.apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 201;
    } catch (error) {
      appLogger.error('Fujitec floor request failed', { elevatorId, floor, userId, error: error.message });
      return false;
    }
  }

  private async fujitecGetStatus(elevatorId: string): Promise<any> {
    try {
      const response = await axios.get(`${this.config.baseUrl}/fujitec/api/v1/elevators/${elevatorId}`, {
        headers: {
          'X-Fujitec-Key': this.config.apiKey,
        },
        timeout: 5000,
      });
      return {
        currentFloor: response.data.currentFloor,
        direction: response.data.direction,
        doorStatus: response.data.doorStatus,
        operationalStatus: response.data.status,
        emergencyMode: response.data.emergencyMode,
        lastUpdate: new Date().toISOString(),
      };
    } catch (error) {
      appLogger.error('Fujitec status request failed', { elevatorId, error: error.message });
      return null;
    }
  }

  private async fujitecEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    try {
      const response = await axios.put(`${this.config.baseUrl}/fujitec/api/v1/elevators/${elevatorId}/emergency`, {
        emergencyMode: enabled,
        reason: reason,
        timestamp: new Date().toISOString(),
      }, {
        headers: {
          'X-Fujitec-Key': this.config.apiKey,
          'Content-Type': 'application/json',
        },
        timeout: 5000,
      });
      return response.status === 200;
    } catch (error) {
      appLogger.error('Fujitec emergency override failed', { elevatorId, enabled, reason, error: error.message });
      return false;
    }
  }

  // Generic implementations for unknown manufacturers
  private async genericFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    appLogger.warn('Using generic floor request implementation', { elevatorId, floor, userId, manufacturer: this.manufacturer });
    // Simulate success for generic implementation
    return true;
  }

  private async genericGetStatus(elevatorId: string): Promise<any> {
    appLogger.warn('Using generic status implementation', { elevatorId, manufacturer: this.manufacturer });
    return {
      currentFloor: 1,
      direction: 'STATIONARY',
      doorStatus: 'CLOSED',
      operationalStatus: 'NORMAL',
      emergencyMode: false,
      lastUpdate: new Date().toISOString(),
    };
  }

  private async genericEmergencyOverride(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    appLogger.warn('Using generic emergency override implementation', { elevatorId, enabled, reason, manufacturer: this.manufacturer });
    return true;
  }
}

// Access control integration service
class AccessControlIntegration {
  async checkUserAccess(userId: string, buildingId: string, targetFloor: number): Promise<boolean> {
    try {
      const response = await axios.post(`${config.accessControlServiceUrl}/api/access/check`, {
        userId,
        resourceType: 'FLOOR',
        resourceId: `${buildingId}:${targetFloor}`,
        action: 'ACCESS',
      }, {
        timeout: 3000,
      });
      return response.data.allowed;
    } catch (error) {
      appLogger.error('Access control check failed', { userId, buildingId, targetFloor, error: error.message });
      return false;
    }
  }

  async getUserSchedule(userId: string): Promise<any> {
    try {
      const response = await axios.get(`${config.accessControlServiceUrl}/api/users/${userId}/schedule`, {
        timeout: 3000,
      });
      return response.data;
    } catch (error) {
      appLogger.error('User schedule retrieval failed', { userId, error: error.message });
      return null;
    }
  }
}

// Alert service integration
class AlertServiceIntegration {
  async sendAlert(alertData: any): Promise<void> {
    try {
      await axios.post(`${config.alertServiceUrl}/api/alerts`, alertData, {
        timeout: 3000,
      });
    } catch (error) {
      appLogger.error('Alert sending failed', { alertData, error: error.message });
    }
  }

  async sendElevatorAlert(elevatorId: string, alertType: string, message: string, priority: string = 'MEDIUM'): Promise<void> {
    await this.sendAlert({
      alertType: `ELEVATOR_${alertType}`,
      priority,
      sourceId: elevatorId,
      sourceType: 'ELEVATOR',
      message,
      details: {
        elevatorId,
        timestamp: new Date().toISOString(),
      },
    });
  }
}

// Destination dispatch optimization service
class DestinationDispatchService {
  private pendingRequests = new Map<string, any[]>();

  async optimizeElevatorAssignment(buildingId: string, requests: any[]): Promise<any[]> {
    // Simple optimization algorithm - can be enhanced with more sophisticated logic
    const elevators = await prisma.elevatorControl.findMany({
      where: { buildingId },
    });

    const assignments = [];
    
    for (const request of requests) {
      const bestElevator = await this.findBestElevator(elevators, request);
      if (bestElevator) {
        assignments.push({
          elevatorId: bestElevator.id,
          userId: request.userId,
          targetFloor: request.targetFloor,
          priority: request.priority,
          estimatedArrival: this.calculateEstimatedArrival(bestElevator, request.targetFloor),
        });
      }
    }

    return assignments;
  }

  private async findBestElevator(elevators: any[], request: any): Promise<any> {
    // Simple algorithm: find elevator with shortest estimated travel time
    let bestElevator = null;
    let shortestTime = Infinity;

    for (const elevator of elevators) {
      const status = await this.getElevatorStatus(elevator.id);
      if (status && status.operationalStatus === 'NORMAL') {
        const travelTime = Math.abs(status.currentFloor - request.targetFloor);
        if (travelTime < shortestTime) {
          shortestTime = travelTime;
          bestElevator = elevator;
        }
      }
    }

    return bestElevator;
  }

  private calculateEstimatedArrival(elevator: any, targetFloor: number): Date {
    // Simple calculation: assume 3 seconds per floor
    const travelTime = Math.abs(elevator.currentFloor - targetFloor) * 3;
    return new Date(Date.now() + travelTime * 1000);
  }

  private async getElevatorStatus(elevatorId: string): Promise<any> {
    const cached = await redis.get(`elevator:status:${elevatorId}`);
    if (cached) {
      return JSON.parse(cached);
    }
    return null;
  }
}

// Initialize services
const accessControlIntegration = new AccessControlIntegration();
const alertServiceIntegration = new AlertServiceIntegration();
const destinationDispatchService = new DestinationDispatchService();

// Authentication middleware
const authMiddleware = async (c: any, next: any) => {
  const authHeader = c.req.header('Authorization');
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return c.json({ error: 'Access token required' }, 401);
  }

  try {
    // Verify token with auth service or decode JWT
    // For now, we'll use a simple validation
    const userPayload = await redis.get(`session:${token}`);
    if (!userPayload) {
      return c.json({ error: 'Invalid or expired token' }, 401);
    }

    c.set('user', JSON.parse(userPayload));
    await next();
  } catch (error) {
    return c.json({ error: 'Invalid token' }, 401);
  }
};

// Tenant isolation middleware
const tenantMiddleware = async (c: any, next: any) => {
  const user = c.get('user');
  if (!user?.tenantId) {
    return c.json({ error: 'Tenant information required' }, 400);
  }
  
  c.set('tenantId', user.tenantId);
  await next();
};

// Create Hono app
const app = new Hono();

// Global middleware
app.use('*', logger());
app.use('*', prettyJSON());
app.use('*', cors({
  origin: ['http://localhost:3000', 'https://app.sparc.com'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
  credentials: true,
}));

// Request ID middleware
app.use('*', async (c, next) => {
  const requestId = c.req.header('x-request-id') || crypto.randomUUID();
  c.set('requestId', requestId);
  c.header('x-request-id', requestId);
  await next();
});

// Health endpoints
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'elevator-control-service',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.environment,
  });
});

app.get('/ready', async (c) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    await redis.ping();

    return c.json({
      status: 'ready',
      service: 'elevator-control-service',
      timestamp: new Date().toISOString(),
      checks: {
        database: 'healthy',
        redis: 'healthy',
      },
    });
  } catch (error) {
    appLogger.error('Readiness check failed', { error: error.message });
    return c.json({
      status: 'not ready',
      service: 'elevator-control-service',
      timestamp: new Date().toISOString(),
      error: error.message,
    }, 503);
  }
});

app.get('/metrics', (c) => {
  const memUsage = process.memoryUsage();
  return c.json({
    service: 'elevator-control-service',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
      external: `${Math.round(memUsage.external / 1024 / 1024)}MB`,
    },
    process: {
      pid: process.pid,
      version: process.version,
      platform: process.platform,
      arch: process.arch,
    },
  });
});

// Elevator Control CRUD endpoints
app.get('/api/elevators', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const buildingId = c.req.query('buildingId');

    const where: any = { tenantId };
    if (buildingId) {
      where.buildingId = buildingId;
    }

    const elevators = await prisma.elevatorControl.findMany({
      where,
      include: {
        building: {
          select: {
            id: true,
            name: true,
            floors: true,
          },
        },
      },
      orderBy: { name: 'asc' },
    });

    // Get real-time status for each elevator
    const elevatorsWithStatus = await Promise.all(
      elevators.map(async (elevator) => {
        const adapter = new ElevatorProtocolAdapter(elevator.manufacturer, {
          baseUrl: `http://${elevator.ipAddress}`,
          apiKey: process.env[`${elevator.manufacturer}_API_KEY`],
        });
        
        const status = await adapter.getElevatorStatus(elevator.id);
        
        return {
          ...elevator,
          realTimeStatus: status,
        };
      })
    );

    return c.json({
      elevators: elevatorsWithStatus,
      total: elevatorsWithStatus.length,
    });
  } catch (error) {
    appLogger.error('Failed to fetch elevators', { error: error.message });
    return c.json({ error: 'Failed to fetch elevators' }, 500);
  }
});

app.get('/api/elevators/:id', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const elevatorId = c.req.param('id');

    const elevator = await prisma.elevatorControl.findFirst({
      where: { id: elevatorId, tenantId },
      include: {
        building: {
          select: {
            id: true,
            name: true,
            floors: true,
          },
        },
      },
    });

    if (!elevator) {
      return c.json({ error: 'Elevator not found' }, 404);
    }

    // Get real-time status
    const adapter = new ElevatorProtocolAdapter(elevator.manufacturer, {
      baseUrl: `http://${elevator.ipAddress}`,
      apiKey: process.env[`${elevator.manufacturer}_API_KEY`],
    });
    
    const status = await adapter.getElevatorStatus(elevator.id);

    return c.json({
      elevator: {
        ...elevator,
        realTimeStatus: status,
      },
    });
  } catch (error) {
    appLogger.error('Failed to fetch elevator', { elevatorId: c.req.param('id'), error: error.message });
    return c.json({ error: 'Failed to fetch elevator' }, 500);
  }
});

app.post('/api/elevators', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const user = c.get('user');
    const body = await c.req.json();

    const validatedData = elevatorControlSchema.parse(body);

    // Verify building exists and belongs to tenant
    const building = await prisma.building.findFirst({
      where: { id: validatedData.buildingId, site: { tenantId } },
    });

    if (!building) {
      return c.json({ error: 'Building not found' }, 404);
    }

    const elevator = await prisma.elevatorControl.create({
      data: {
        ...validatedData,
        tenantId,
      },
      include: {
        building: {
          select: {
            id: true,
            name: true,
            floors: true,
          },
        },
      },
    });

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId: user.id,
        action: 'ELEVATOR_CREATED',
        resourceType: 'ELEVATOR',
        resourceId: elevator.id,
        details: { elevatorData: validatedData },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    appLogger.info('Elevator created', { elevatorId: elevator.id, tenantId, userId: user.id });

    return c.json({ elevator }, 201);
  } catch (error) {
    if (error.name === 'ZodError') {
      return c.json({ error: 'Validation failed', details: error.errors }, 400);
    }
    appLogger.error('Failed to create elevator', { error: error.message });
    return c.json({ error: 'Failed to create elevator' }, 500);
  }
});

app.put('/api/elevators/:id', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const user = c.get('user');
    const elevatorId = c.req.param('id');
    const body = await c.req.json();

    const validatedData = elevatorControlSchema.partial().parse(body);

    const existingElevator = await prisma.elevatorControl.findFirst({
      where: { id: elevatorId, tenantId },
    });

    if (!existingElevator) {
      return c.json({ error: 'Elevator not found' }, 404);
    }

    const elevator = await prisma.elevatorControl.update({
      where: { id: elevatorId },
      data: validatedData,
      include: {
        building: {
          select: {
            id: true,
            name: true,
            floors: true,
          },
        },
      },
    });

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId: user.id,
        action: 'ELEVATOR_UPDATED',
        resourceType: 'ELEVATOR',
        resourceId: elevator.id,
        details: { changes: validatedData },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    appLogger.info('Elevator updated', { elevatorId, tenantId, userId: user.id });

    return c.json({ elevator });
  } catch (error) {
    if (error.name === 'ZodError') {
      return c.json({ error: 'Validation failed', details: error.errors }, 400);
    }
    appLogger.error('Failed to update elevator', { elevatorId: c.req.param('id'), error: error.message });
    return c.json({ error: 'Failed to update elevator' }, 500);
  }
});

app.delete('/api/elevators/:id', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const user = c.get('user');
    const elevatorId = c.req.param('id');

    const existingElevator = await prisma.elevatorControl.findFirst({
      where: { id: elevatorId, tenantId },
    });

    if (!existingElevator) {
      return c.json({ error: 'Elevator not found' }, 404);
    }

    await prisma.elevatorControl.delete({
      where: { id: elevatorId },
    });

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId: user.id,
        action: 'ELEVATOR_DELETED',
        resourceType: 'ELEVATOR',
        resourceId: elevatorId,
        details: { elevatorName: existingElevator.name },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    appLogger.info('Elevator deleted', { elevatorId, tenantId, userId: user.id });

    return c.json({ message: 'Elevator deleted successfully' });
  } catch (error) {
    appLogger.error('Failed to delete elevator', { elevatorId: c.req.param('id'), error: error.message });
    return c.json({ error: 'Failed to delete elevator' }, 500);
  }
});

// Floor access control endpoints
app.post('/api/elevators/:id/access', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const elevatorId = c.req.param('id');
    const body = await c.req.json();

    const validatedData = floorAccessRequestSchema.parse(body);

    const elevator = await prisma.elevatorControl.findFirst({
      where: { id: elevatorId, tenantId },
      include: { building: true },
    });

    if (!elevator) {
      return c.json({ error: 'Elevator not found' }, 404);
    }

    // Check if target floor is served by this elevator
    const floorsServed = elevator.floorsServed as number[];
    if (!floorsServed.includes(validatedData.targetFloor)) {
      return c.json({ error: 'Floor not served by this elevator' }, 400);
    }

    // Check user access permissions
    const hasAccess = await accessControlIntegration.checkUserAccess(
      validatedData.userId,
      elevator.buildingId,
      validatedData.targetFloor
    );

    if (!hasAccess) {
      // Log access denied event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: validatedData.userId,
          action: 'ELEVATOR_ACCESS_DENIED',
          resourceType: 'ELEVATOR',
          resourceId: elevatorId,
          details: { 
            targetFloor: validatedData.targetFloor,
            reason: 'Insufficient permissions',
          },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      return c.json({ error: 'Access denied to target floor' }, 403);
    }

    // Send floor request to elevator
    const adapter = new ElevatorProtocolAdapter(elevator.manufacturer, {
      baseUrl: `http://${elevator.ipAddress}`,
      apiKey: process.env[`${elevator.manufacturer}_API_KEY`],
    });

    const success = await adapter.sendFloorRequest(elevatorId, validatedData.targetFloor, validatedData.userId);

    if (!success) {
      await alertServiceIntegration.sendElevatorAlert(
        elevatorId,
        'COMMUNICATION_ERROR',
        `Failed to send floor request to elevator ${elevator.name}`,
        'HIGH'
      );
      return c.json({ error: 'Failed to communicate with elevator' }, 500);
    }

    // Log successful access event
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId: validatedData.userId,
        action: 'ELEVATOR_ACCESS_GRANTED',
        resourceType: 'ELEVATOR',
        resourceId: elevatorId,
        details: { 
          targetFloor: validatedData.targetFloor,
          credentialId: validatedData.credentialId,
          reason: validatedData.reason,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    appLogger.info('Elevator access granted', { 
      elevatorId, 
      userId: validatedData.userId, 
      targetFloor: validatedData.targetFloor 
    });

    return c.json({
      message: 'Floor access granted',
      elevatorId,
      targetFloor: validatedData.targetFloor,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error.name === 'ZodError') {
      return c.json({ error: 'Validation failed', details: error.errors }, 400);
    }
    appLogger.error('Failed to process floor access request', { 
      elevatorId: c.req.param('id'), 
      error: error.message 
    });
    return c.json({ error: 'Failed to process access request' }, 500);
  }
});

// Emergency override endpoints
app.post('/api/elevators/:id/emergency', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const user = c.get('user');
    const elevatorId = c.req.param('id');
    const body = await c.req.json();

    const validatedData = emergencyOverrideSchema.parse(body);

    const elevator = await prisma.elevatorControl.findFirst({
      where: { id: elevatorId, tenantId },
    });

    if (!elevator) {
      return c.json({ error: 'Elevator not found' }, 404);
    }

    // Check if user has emergency override permissions
    const userRoles = user.roles || [];
    if (!userRoles.includes('SECURITY_ADMIN') && !userRoles.includes('EMERGENCY_RESPONDER')) {
      return c.json({ error: 'Insufficient permissions for emergency override' }, 403);
    }

    const adapter = new ElevatorProtocolAdapter(elevator.manufacturer, {
      baseUrl: `http://${elevator.ipAddress}`,
      apiKey: process.env[`${elevator.manufacturer}_API_KEY`],
    });

    let success = false;
    let emergencyEnabled = false;

    switch (validatedData.action) {
      case 'ENABLE':
        success = await adapter.setEmergencyOverride(elevatorId, true, validatedData.reason);
        emergencyEnabled = true;
        break;
      case 'DISABLE':
        success = await adapter.setEmergencyOverride(elevatorId, false, validatedData.reason);
        emergencyEnabled = false;
        break;
      case 'EVACUATE':
        // Send elevator to ground floor and enable emergency mode
        await adapter.sendFloorRequest(elevatorId, 0, 'EMERGENCY_SYSTEM');
        success = await adapter.setEmergencyOverride(elevatorId, true, 'EVACUATION_MODE');
        emergencyEnabled = true;
        break;
      case 'LOCKDOWN':
        // Stop elevator at current floor and enable emergency mode
        success = await adapter.setEmergencyOverride(elevatorId, true, 'LOCKDOWN_MODE');
        emergencyEnabled = true;
        break;
    }

    if (!success) {
      await alertServiceIntegration.sendElevatorAlert(
        elevatorId,
        'EMERGENCY_OVERRIDE_FAILED',
        `Failed to ${validatedData.action.toLowerCase()} emergency override for elevator ${elevator.name}`,
        'CRITICAL'
      );
      return c.json({ error: 'Failed to execute emergency override' }, 500);
    }

    // Update elevator status in database
    await prisma.elevatorControl.update({
      where: { id: elevatorId },
      data: { 
        emergencyOverride: emergencyEnabled,
        status: emergencyEnabled ? 'emergency' : 'normal',
      },
    });

    // Log emergency override event
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId: user.id,
        action: `ELEVATOR_EMERGENCY_${validatedData.action}`,
        resourceType: 'ELEVATOR',
        resourceId: elevatorId,
        details: { 
          action: validatedData.action,
          reason: validatedData.reason,
          duration: validatedData.duration,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    // Send alert for emergency override
    await alertServiceIntegration.sendElevatorAlert(
      elevatorId,
      'EMERGENCY_OVERRIDE',
      `Emergency override ${validatedData.action.toLowerCase()} activated for elevator ${elevator.name}: ${validatedData.reason}`,
      'CRITICAL'
    );

    appLogger.info('Emergency override executed', { 
      elevatorId, 
      action: validatedData.action, 
      userId: user.id 
    });

    // Schedule automatic disable if duration is specified
    if (validatedData.duration && emergencyEnabled) {
      setTimeout(async () => {
        try {
          await adapter.setEmergencyOverride(elevatorId, false, 'Automatic timeout');
          await prisma.elevatorControl.update({
            where: { id: elevatorId },
            data: { 
              emergencyOverride: false,
              status: 'normal',
            },
          });
          
          await alertServiceIntegration.sendElevatorAlert(
            elevatorId,
            'EMERGENCY_OVERRIDE_TIMEOUT',
            `Emergency override automatically disabled for elevator ${elevator.name} after ${validatedData.duration} seconds`,
            'MEDIUM'
          );
        } catch (error) {
          appLogger.error('Failed to automatically disable emergency override', { elevatorId, error: error.message });
        }
      }, validatedData.duration * 1000);
    }

    return c.json({
      message: `Emergency override ${validatedData.action.toLowerCase()} executed successfully`,
      elevatorId,
      action: validatedData.action,
      emergencyEnabled,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error.name === 'ZodError') {
      return c.json({ error: 'Validation failed', details: error.errors }, 400);
    }
    appLogger.error('Failed to execute emergency override', { 
      elevatorId: c.req.param('id'), 
      error: error.message 
    });
    return c.json({ error: 'Failed to execute emergency override' }, 500);
  }
});

// Destination dispatch endpoints
app.post('/api/buildings/:buildingId/dispatch', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const buildingId = c.req.param('buildingId');
    const body = await c.req.json();

    const requests = z.array(destinationDispatchSchema).parse(body.requests);

    // Verify building exists and belongs to tenant
    const building = await prisma.building.findFirst({
      where: { id: buildingId, site: { tenantId } },
    });

    if (!building) {
      return c.json({ error: 'Building not found' }, 404);
    }

    // Validate all users have access to their target floors
    for (const request of requests) {
      const hasAccess = await accessControlIntegration.checkUserAccess(
        request.userId,
        buildingId,
        request.targetFloor
      );

      if (!hasAccess) {
        return c.json({ 
          error: `User ${request.userId} does not have access to floor ${request.targetFloor}` 
        }, 403);
      }
    }

    // Optimize elevator assignments
    const assignments = await destinationDispatchService.optimizeElevatorAssignment(buildingId, requests);

    // Execute assignments
    const results = [];
    for (const assignment of assignments) {
      const elevator = await prisma.elevatorControl.findUnique({
        where: { id: assignment.elevatorId },
      });

      if (elevator) {
        const adapter = new ElevatorProtocolAdapter(elevator.manufacturer, {
          baseUrl: `http://${elevator.ipAddress}`,
          apiKey: process.env[`${elevator.manufacturer}_API_KEY`],
        });

        const success = await adapter.sendFloorRequest(
          assignment.elevatorId,
          assignment.targetFloor,
          assignment.userId
        );

        results.push({
          ...assignment,
          success,
          elevatorName: elevator.name,
        });

        // Log assignment
        await prisma.auditLog.create({
          data: {
            tenantId,
            userId: assignment.userId,
            action: 'DESTINATION_DISPATCH',
            resourceType: 'ELEVATOR',
            resourceId: assignment.elevatorId,
            details: { 
              targetFloor: assignment.targetFloor,
              priority: assignment.priority,
              estimatedArrival: assignment.estimatedArrival,
            },
            ipAddress: c.req.header('x-forwarded-for') || 'unknown',
            userAgent: c.req.header('user-agent') || 'unknown',
          },
        });
      }
    }

    appLogger.info('Destination dispatch executed', { 
      buildingId, 
      requestCount: requests.length, 
      assignmentCount: assignments.length 
    });

    return c.json({
      message: 'Destination dispatch completed',
      buildingId,
      assignments: results,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    if (error.name === 'ZodError') {
      return c.json({ error: 'Validation failed', details: error.errors }, 400);
    }
    appLogger.error('Failed to execute destination dispatch', { 
      buildingId: c.req.param('buildingId'), 
      error: error.message 
    });
    return c.json({ error: 'Failed to execute destination dispatch' }, 500);
  }
});

// Real-time status monitoring endpoints
app.get('/api/elevators/:id/status', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const elevatorId = c.req.param('id');

    const elevator = await prisma.elevatorControl.findFirst({
      where: { id: elevatorId, tenantId },
    });

    if (!elevator) {
      return c.json({ error: 'Elevator not found' }, 404);
    }

    // Get real-time status from elevator
    const adapter = new ElevatorProtocolAdapter(elevator.manufacturer, {
      baseUrl: `http://${elevator.ipAddress}`,
      apiKey: process.env[`${elevator.manufacturer}_API_KEY`],
    });

    const status = await adapter.getElevatorStatus(elevatorId);

    if (!status) {
      await alertServiceIntegration.sendElevatorAlert(
        elevatorId,
        'STATUS_UNAVAILABLE',
        `Unable to retrieve status for elevator ${elevator.name}`,
        'MEDIUM'
      );
      return c.json({ error: 'Unable to retrieve elevator status' }, 503);
    }

    // Cache status in Redis for 30 seconds
    await redis.setex(`elevator:status:${elevatorId}`, 30, JSON.stringify(status));

    return c.json({
      elevatorId,
      elevatorName: elevator.name,
      status,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    appLogger.error('Failed to get elevator status', { 
      elevatorId: c.req.param('id'), 
      error: error.message 
    });
    return c.json({ error: 'Failed to get elevator status' }, 500);
  }
});

app.get('/api/buildings/:buildingId/elevators/status', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const buildingId = c.req.param('buildingId');

    const elevators = await prisma.elevatorControl.findMany({
      where: { buildingId, tenantId },
    });

    const statusResults = await Promise.all(
      elevators.map(async (elevator) => {
        const adapter = new ElevatorProtocolAdapter(elevator.manufacturer, {
          baseUrl: `http://${elevator.ipAddress}`,
          apiKey: process.env[`${elevator.manufacturer}_API_KEY`],
        });

        const status = await adapter.getElevatorStatus(elevator.id);
        
        return {
          elevatorId: elevator.id,
          elevatorName: elevator.name,
          manufacturer: elevator.manufacturer,
          floorsServed: elevator.floorsServed,
          emergencyOverride: elevator.emergencyOverride,
          status,
        };
      })
    );

    return c.json({
      buildingId,
      elevators: statusResults,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    appLogger.error('Failed to get building elevator status', { 
      buildingId: c.req.param('buildingId'), 
      error: error.message 
    });
    return c.json({ error: 'Failed to get elevator status' }, 500);
  }
});

// Integration endpoints
app.post('/api/integrations/access-control/sync', authMiddleware, tenantMiddleware, async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const user = c.get('user');

    // Sync access control permissions for all elevators
    const elevators = await prisma.elevatorControl.findMany({
      where: { tenantId },
      include: { building: true },
    });

    let syncCount = 0;
    for (const elevator of elevators) {
      try {
        // Get updated access rules from access control service
        const response = await axios.get(
          `${config.accessControlServiceUrl}/api/buildings/${elevator.buildingId}/access-rules`,
          { timeout: 5000 }
        );

        if (response.data.accessRules) {
          await prisma.elevatorControl.update({
            where: { id: elevator.id },
            data: { accessRules: response.data.accessRules },
          });
          syncCount++;
        }
      } catch (error) {
        appLogger.error('Failed to sync access rules for elevator', { 
          elevatorId: elevator.id, 
          error: error.message 
        });
      }
    }

    // Log sync event
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId: user.id,
        action: 'ACCESS_CONTROL_SYNC',
        resourceType: 'SYSTEM',
        resourceId: 'elevator-control-service',
        details: { syncedElevators: syncCount, totalElevators: elevators.length },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    appLogger.info('Access control sync completed', { tenantId, syncCount, totalElevators: elevators.length });

    return c.json({
      message: 'Access control sync completed',
      syncedElevators: syncCount,
      totalElevators: elevators.length,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    appLogger.error('Failed to sync access control', { error: error.message });
    return c.json({ error: 'Failed to sync access control' }, 500);
  }
});

// Webhook endpoint for external elevator system events
app.post('/api/webhooks/elevator-events', async (c) => {
  try {
    const body = await c.req.json();
    const signature = c.req.header('x-elevator-signature');

    // Verify webhook signature (implementation depends on manufacturer)
    // For now, we'll skip signature verification

    const { elevatorId, eventType, eventData, timestamp } = body;

    // Find elevator in database
    const elevator = await prisma.elevatorControl.findUnique({
      where: { id: elevatorId },
    });

    if (!elevator) {
      appLogger.warn('Webhook received for unknown elevator', { elevatorId });
      return c.json({ error: 'Elevator not found' }, 404);
    }

    // Process different event types
    switch (eventType) {
      case 'STATUS_CHANGE':
        await redis.setex(`elevator:status:${elevatorId}`, 300, JSON.stringify(eventData));
        break;

      case 'EMERGENCY_ACTIVATED':
        await prisma.elevatorControl.update({
          where: { id: elevatorId },
          data: { emergencyOverride: true, status: 'emergency' },
        });
        
        await alertServiceIntegration.sendElevatorAlert(
          elevatorId,
          'EMERGENCY_ACTIVATED',
          `Emergency mode activated on elevator ${elevator.name}: ${eventData.reason || 'Unknown reason'}`,
          'CRITICAL'
        );
        break;

      case 'MAINTENANCE_REQUIRED':
        await alertServiceIntegration.sendElevatorAlert(
          elevatorId,
          'MAINTENANCE_REQUIRED',
          `Maintenance required for elevator ${elevator.name}: ${eventData.description || 'Scheduled maintenance'}`,
          'MEDIUM'
        );
        break;

      case 'FAULT_DETECTED':
        await alertServiceIntegration.sendElevatorAlert(
          elevatorId,
          'FAULT_DETECTED',
          `Fault detected on elevator ${elevator.name}: ${eventData.faultCode || 'Unknown fault'}`,
          'HIGH'
        );
        break;

      case 'DOOR_OBSTRUCTION':
        await alertServiceIntegration.sendElevatorAlert(
          elevatorId,
          'DOOR_OBSTRUCTION',
          `Door obstruction detected on elevator ${elevator.name} at floor ${eventData.floor || 'unknown'}`,
          'MEDIUM'
        );
        break;

      default:
        appLogger.warn('Unknown elevator event type', { elevatorId, eventType });
    }

    // Log webhook event
    await prisma.auditLog.create({
      data: {
        tenantId: elevator.tenantId,
        userId: null,
        action: `ELEVATOR_WEBHOOK_${eventType}`,
        resourceType: 'ELEVATOR',
        resourceId: elevatorId,
        details: { eventType, eventData, webhookTimestamp: timestamp },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'webhook',
      },
    });

    appLogger.info('Elevator webhook processed', { elevatorId, eventType });

    return c.json({ message: 'Webhook processed successfully' });
  } catch (error) {
    appLogger.error('Failed to process elevator webhook', { error: error.message });
    return c.json({ error: 'Failed to process webhook' }, 500);
  }
});

// Global error handler
app.onError((err, c) => {
  const requestId = c.get('requestId');
  
  if (err instanceof HTTPException) {
    appLogger.warn('HTTP Exception', {
      requestId,
      status: err.status,
      message: err.message,
      path: c.req.path,
      method: c.req.method,
    });
    
    return c.json({
      error: {
        code: err.status,
        message: err.message,
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, err.status);
  }

  appLogger.error('Unhandled error', {
    requestId,
    error: err.message,
    stack: err.stack,
    path: c.req.path,
    method: c.req.method,
  });

  return c.json({
    error: {
      code: 500,
      message: 'Internal server error',
      requestId,
      timestamp: new Date().toISOString(),
    },
  }, 500);
});

// 404 handler
app.notFound((c) => {
  const requestId = c.get('requestId');
  
  appLogger.warn('Route not found', {
    requestId,
    path: c.req.path,
    method: c.req.method,
  });

  return c.json({
    error: {
      code: 404,
      message: 'Route not found',
      requestId,
      timestamp: new Date().toISOString(),
    },
  }, 404);
});

// Graceful shutdown handling
let server: any;

const gracefulShutdown = async (signal: string) => {
  appLogger.info(`Received ${signal}, starting graceful shutdown...`);
  
  if (server) {
    server.close(() => {
      appLogger.info('HTTP server closed');
    });
  }

  try {
    await prisma.$disconnect();
    appLogger.info('Database connections closed');
  } catch (error) {
    appLogger.error('Error closing database connections', { error: error.message });
  }

  try {
    await redis.quit();
    appLogger.info('Redis connections closed');
  } catch (error) {
    appLogger.error('Error closing Redis connections', { error: error.message });
  }

  appLogger.info('Graceful shutdown completed');
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  appLogger.error('Uncaught exception', {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  appLogger.error('Unhandled promise rejection', {
    reason: reason,
    promise: promise,
  });
  process.exit(1);
});

// Start the server
const startServer = async () => {
  try {
    appLogger.info('Starting elevator control service...', {
      port: config.port,
      host: config.host,
      environment: config.environment,
      nodeVersion: process.version,
    });

    server = serve({
      fetch: app.fetch,
      port: config.port,
      hostname: config.host,
    });

    appLogger.info('Elevator control service started successfully', {
      port: config.port,
      host: config.host,
      environment: config.environment,
    });

    // Log available routes
    appLogger.info('Available routes:', {
      routes: [
        'GET /health - Health check',
        'GET /ready - Readiness check',
        'GET /metrics - Service metrics',
        'GET /api/elevators - List elevators',
        'GET /api/elevators/:id - Get elevator details',
        'POST /api/elevators - Create elevator',
        'PUT /api/elevators/:id - Update elevator',
        'DELETE /api/elevators/:id - Delete elevator',
        'POST /api/elevators/:id/access - Request floor access',
        'POST /api/elevators/:id/emergency - Emergency override',
        'POST /api/buildings/:buildingId/dispatch - Destination dispatch',
        'GET /api/elevators/:id/status - Get elevator status',
        'GET /api/buildings/:buildingId/elevators/status - Get building elevator status',
        'POST /api/integrations/access-control/sync - Sync access control',
        'POST /api/webhooks/elevator-events - Elevator event webhook',
      ],
    });

  } catch (error) {
    appLogger.error('Failed to start elevator control service', {
      error: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;