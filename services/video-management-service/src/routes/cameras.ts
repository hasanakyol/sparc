import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { startProbe } from 'node-onvif-ts';
import { PrismaClient } from '@prisma/client';
import { createMiddleware } from 'hono/factory';
import { HTTPException } from 'hono/http-exception';

const app = new Hono();
const prisma = new PrismaClient();

// Validation schemas
const createCameraSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  ipAddress: z.string().ip(),
  port: z.number().int().min(1).max(65535).default(80),
  username: z.string().min(1),
  password: z.string().min(1),
  onvifPort: z.number().int().min(1).max(65535).default(8080),
  rtspUrl: z.string().url().optional(),
  buildingId: z.string().uuid(),
  floorId: z.string().uuid().optional(),
  zoneId: z.string().uuid().optional(),
  cameraGroupId: z.string().uuid().optional(),
  manufacturer: z.string().optional(),
  model: z.string().optional(),
  firmwareVersion: z.string().optional(),
  resolution: z.string().optional(),
  frameRate: z.number().int().min(1).max(60).optional(),
  isActive: z.boolean().default(true),
  recordingEnabled: z.boolean().default(true),
  motionDetectionEnabled: z.boolean().default(true),
  privacyMasks: z.array(z.object({
    name: z.string(),
    coordinates: z.array(z.object({
      x: z.number(),
      y: z.number()
    }))
  })).optional()
});

const updateCameraSchema = createCameraSchema.partial();

const createCameraGroupSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  buildingId: z.string().uuid(),
  floorId: z.string().uuid().optional(),
  isActive: z.boolean().default(true)
});

const updateCameraGroupSchema = createCameraGroupSchema.partial();

const discoverySchema = z.object({
  timeout: z.number().int().min(1000).max(30000).default(5000),
  buildingId: z.string().uuid()
});

const privacyMaskSchema = z.object({
  name: z.string().min(1).max(255),
  coordinates: z.array(z.object({
    x: z.number().min(0).max(1),
    y: z.number().min(0).max(1)
  })).min(3)
});

// Middleware for tenant isolation
const tenantMiddleware = createMiddleware(async (c, next) => {
  const tenantId = c.req.header('X-Tenant-ID');
  if (!tenantId) {
    throw new HTTPException(400, { message: 'Tenant ID is required' });
  }
  c.set('tenantId', tenantId);
  await next();
});

// Middleware for camera access validation
const validateCameraAccess = createMiddleware(async (c, next) => {
  const cameraId = c.req.param('id');
  const tenantId = c.get('tenantId');
  
  const camera = await prisma.camera.findFirst({
    where: {
      id: cameraId,
      tenantId: tenantId
    }
  });
  
  if (!camera) {
    throw new HTTPException(404, { message: 'Camera not found' });
  }
  
  c.set('camera', camera);
  await next();
});

// Health monitoring service
class CameraHealthMonitor {
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private reconnectionAttempts = new Map<string, number>();
  
  startMonitoring() {
    this.healthCheckInterval = setInterval(async () => {
      await this.checkAllCameras();
    }, 30000); // Check every 30 seconds
  }
  
  stopMonitoring() {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
  }
  
  private async checkAllCameras() {
    const cameras = await prisma.camera.findMany({
      where: { isActive: true }
    });
    
    for (const camera of cameras) {
      await this.checkCameraHealth(camera);
    }
  }
  
  private async checkCameraHealth(camera: any) {
    try {
      // Attempt to connect to camera
      const response = await fetch(`http://${camera.ipAddress}:${camera.port}`, {
        method: 'HEAD',
        timeout: 5000
      });
      
      const isOnline = response.ok;
      
      if (camera.status !== (isOnline ? 'online' : 'offline')) {
        await prisma.camera.update({
          where: { id: camera.id },
          data: {
            status: isOnline ? 'online' : 'offline',
            lastSeen: isOnline ? new Date() : camera.lastSeen
          }
        });
        
        // Log status change
        await prisma.auditLog.create({
          data: {
            tenantId: camera.tenantId,
            userId: 'system',
            action: 'camera_status_change',
            resourceType: 'camera',
            resourceId: camera.id,
            details: {
              previousStatus: camera.status,
              newStatus: isOnline ? 'online' : 'offline',
              ipAddress: camera.ipAddress
            }
          }
        });
      }
      
      if (!isOnline) {
        await this.attemptReconnection(camera);
      } else {
        this.reconnectionAttempts.delete(camera.id);
      }
      
    } catch (error) {
      console.error(`Health check failed for camera ${camera.id}:`, error);
    }
  }
  
  private async attemptReconnection(camera: any) {
    const attempts = this.reconnectionAttempts.get(camera.id) || 0;
    
    if (attempts < 5) { // Max 5 reconnection attempts
      this.reconnectionAttempts.set(camera.id, attempts + 1);
      
      // Exponential backoff
      setTimeout(async () => {
        await this.checkCameraHealth(camera);
      }, Math.pow(2, attempts) * 1000);
    }
  }
}

const healthMonitor = new CameraHealthMonitor();
healthMonitor.startMonitoring();

// ONVIF Discovery Service
class ONVIFDiscoveryService {
  async discoverCameras(timeout: number = 5000) {
    try {
      const devices = await startProbe(timeout);
      
      return devices.map(device => ({
        urn: device.urn,
        name: device.name,
        hardware: device.hardware,
        location: device.location,
        types: device.types,
        xaddrs: device.xaddrs,
        scopes: device.scopes
      }));
    } catch (error) {
      console.error('ONVIF discovery failed:', error);
      throw new HTTPException(500, { message: 'Camera discovery failed' });
    }
  }
  
  async getCameraCapabilities(ipAddress: string, port: number, username: string, password: string) {
    try {
      // This would integrate with ONVIF library to get camera capabilities
      // For now, returning mock data structure
      return {
        profiles: [],
        videoSources: [],
        audioSources: [],
        ptzCapabilities: null,
        imagingCapabilities: null,
        analyticsCapabilities: null
      };
    } catch (error) {
      console.error('Failed to get camera capabilities:', error);
      throw new HTTPException(500, { message: 'Failed to retrieve camera capabilities' });
    }
  }
}

const discoveryService = new ONVIFDiscoveryService();

// Routes

// Camera CRUD operations
app.get('/cameras', tenantMiddleware, async (c) => {
  const tenantId = c.get('tenantId');
  const { buildingId, floorId, groupId, status, page = '1', limit = '50' } = c.req.query();
  
  const pageNum = parseInt(page);
  const limitNum = parseInt(limit);
  const offset = (pageNum - 1) * limitNum;
  
  const where: any = { tenantId };
  
  if (buildingId) where.buildingId = buildingId;
  if (floorId) where.floorId = floorId;
  if (groupId) where.cameraGroupId = groupId;
  if (status) where.status = status;
  
  const [cameras, total] = await Promise.all([
    prisma.camera.findMany({
      where,
      include: {
        building: { select: { id: true, name: true } },
        floor: { select: { id: true, name: true } },
        zone: { select: { id: true, name: true } },
        cameraGroup: { select: { id: true, name: true } },
        privacyMasks: true
      },
      skip: offset,
      take: limitNum,
      orderBy: { name: 'asc' }
    }),
    prisma.camera.count({ where })
  ]);
  
  return c.json({
    data: cameras,
    pagination: {
      page: pageNum,
      limit: limitNum,
      total,
      pages: Math.ceil(total / limitNum)
    }
  });
});

app.get('/cameras/:id', tenantMiddleware, validateCameraAccess, async (c) => {
  const camera = c.get('camera');
  
  const fullCamera = await prisma.camera.findUnique({
    where: { id: camera.id },
    include: {
      building: { select: { id: true, name: true } },
      floor: { select: { id: true, name: true } },
      zone: { select: { id: true, name: true } },
      cameraGroup: { select: { id: true, name: true } },
      privacyMasks: true,
      videoRecordings: {
        take: 10,
        orderBy: { startTime: 'desc' },
        select: {
          id: true,
          startTime: true,
          endTime: true,
          duration: true,
          fileSize: true,
          triggerType: true
        }
      }
    }
  });
  
  return c.json({ data: fullCamera });
});

app.post('/cameras', tenantMiddleware, zValidator('json', createCameraSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const data = c.req.valid('json');
  
  // Validate building/floor hierarchy
  const building = await prisma.building.findFirst({
    where: { id: data.buildingId, tenantId }
  });
  
  if (!building) {
    throw new HTTPException(400, { message: 'Invalid building ID' });
  }
  
  if (data.floorId) {
    const floor = await prisma.floor.findFirst({
      where: { id: data.floorId, buildingId: data.buildingId, tenantId }
    });
    
    if (!floor) {
      throw new HTTPException(400, { message: 'Invalid floor ID for the specified building' });
    }
  }
  
  // Check for IP address conflicts
  const existingCamera = await prisma.camera.findFirst({
    where: {
      tenantId,
      ipAddress: data.ipAddress,
      port: data.port
    }
  });
  
  if (existingCamera) {
    throw new HTTPException(400, { message: 'Camera with this IP address and port already exists' });
  }
  
  const camera = await prisma.camera.create({
    data: {
      ...data,
      tenantId,
      status: 'offline',
      createdAt: new Date(),
      updatedAt: new Date()
    },
    include: {
      building: { select: { id: true, name: true } },
      floor: { select: { id: true, name: true } },
      zone: { select: { id: true, name: true } },
      cameraGroup: { select: { id: true, name: true } }
    }
  });
  
  // Create privacy masks if provided
  if (data.privacyMasks && data.privacyMasks.length > 0) {
    await prisma.privacyMask.createMany({
      data: data.privacyMasks.map(mask => ({
        cameraId: camera.id,
        tenantId,
        name: mask.name,
        coordinates: mask.coordinates,
        isActive: true
      }))
    });
  }
  
  // Log camera creation
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId: 'system', // Should be actual user ID from auth context
      action: 'camera_created',
      resourceType: 'camera',
      resourceId: camera.id,
      details: {
        name: camera.name,
        ipAddress: camera.ipAddress,
        buildingId: camera.buildingId
      }
    }
  });
  
  // Attempt initial connection
  setTimeout(async () => {
    await healthMonitor['checkCameraHealth'](camera);
  }, 1000);
  
  return c.json({ data: camera }, 201);
});

app.put('/cameras/:id', tenantMiddleware, validateCameraAccess, zValidator('json', updateCameraSchema), async (c) => {
  const camera = c.get('camera');
  const tenantId = c.get('tenantId');
  const data = c.req.valid('json');
  
  // Validate building/floor hierarchy if being updated
  if (data.buildingId) {
    const building = await prisma.building.findFirst({
      where: { id: data.buildingId, tenantId }
    });
    
    if (!building) {
      throw new HTTPException(400, { message: 'Invalid building ID' });
    }
  }
  
  if (data.floorId) {
    const buildingId = data.buildingId || camera.buildingId;
    const floor = await prisma.floor.findFirst({
      where: { id: data.floorId, buildingId, tenantId }
    });
    
    if (!floor) {
      throw new HTTPException(400, { message: 'Invalid floor ID for the specified building' });
    }
  }
  
  // Check for IP address conflicts if IP is being updated
  if (data.ipAddress || data.port) {
    const ipAddress = data.ipAddress || camera.ipAddress;
    const port = data.port || camera.port;
    
    const existingCamera = await prisma.camera.findFirst({
      where: {
        tenantId,
        ipAddress,
        port,
        NOT: { id: camera.id }
      }
    });
    
    if (existingCamera) {
      throw new HTTPException(400, { message: 'Camera with this IP address and port already exists' });
    }
  }
  
  const updatedCamera = await prisma.camera.update({
    where: { id: camera.id },
    data: {
      ...data,
      updatedAt: new Date()
    },
    include: {
      building: { select: { id: true, name: true } },
      floor: { select: { id: true, name: true } },
      zone: { select: { id: true, name: true } },
      cameraGroup: { select: { id: true, name: true } },
      privacyMasks: true
    }
  });
  
  // Log camera update
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId: 'system', // Should be actual user ID from auth context
      action: 'camera_updated',
      resourceType: 'camera',
      resourceId: camera.id,
      details: {
        changes: data,
        previousValues: {
          name: camera.name,
          ipAddress: camera.ipAddress,
          isActive: camera.isActive
        }
      }
    }
  });
  
  return c.json({ data: updatedCamera });
});

app.delete('/cameras/:id', tenantMiddleware, validateCameraAccess, async (c) => {
  const camera = c.get('camera');
  const tenantId = c.get('tenantId');
  
  // Soft delete - mark as inactive
  await prisma.camera.update({
    where: { id: camera.id },
    data: {
      isActive: false,
      status: 'offline',
      updatedAt: new Date()
    }
  });
  
  // Log camera deletion
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId: 'system', // Should be actual user ID from auth context
      action: 'camera_deleted',
      resourceType: 'camera',
      resourceId: camera.id,
      details: {
        name: camera.name,
        ipAddress: camera.ipAddress
      }
    }
  });
  
  return c.json({ message: 'Camera deleted successfully' });
});

// Camera Groups
app.get('/camera-groups', tenantMiddleware, async (c) => {
  const tenantId = c.get('tenantId');
  const { buildingId, floorId } = c.req.query();
  
  const where: any = { tenantId };
  if (buildingId) where.buildingId = buildingId;
  if (floorId) where.floorId = floorId;
  
  const groups = await prisma.cameraGroup.findMany({
    where,
    include: {
      building: { select: { id: true, name: true } },
      floor: { select: { id: true, name: true } },
      cameras: {
        select: {
          id: true,
          name: true,
          status: true,
          ipAddress: true
        }
      },
      _count: {
        select: { cameras: true }
      }
    },
    orderBy: { name: 'asc' }
  });
  
  return c.json({ data: groups });
});

app.post('/camera-groups', tenantMiddleware, zValidator('json', createCameraGroupSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const data = c.req.valid('json');
  
  const group = await prisma.cameraGroup.create({
    data: {
      ...data,
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date()
    },
    include: {
      building: { select: { id: true, name: true } },
      floor: { select: { id: true, name: true } }
    }
  });
  
  return c.json({ data: group }, 201);
});

// Camera Discovery
app.post('/cameras/discover', tenantMiddleware, zValidator('json', discoverySchema), async (c) => {
  const { timeout, buildingId } = c.req.valid('json');
  const tenantId = c.get('tenantId');
  
  // Validate building exists
  const building = await prisma.building.findFirst({
    where: { id: buildingId, tenantId }
  });
  
  if (!building) {
    throw new HTTPException(400, { message: 'Invalid building ID' });
  }
  
  const discoveredCameras = await discoveryService.discoverCameras(timeout);
  
  // Filter out cameras that are already registered
  const existingIPs = await prisma.camera.findMany({
    where: { tenantId },
    select: { ipAddress: true, port: true }
  });
  
  const existingIPSet = new Set(existingIPs.map(c => `${c.ipAddress}:${c.port}`));
  
  const newCameras = discoveredCameras.filter(camera => {
    const ip = camera.xaddrs[0]?.split('://')[1]?.split(':')[0];
    return ip && !existingIPSet.has(`${ip}:80`);
  });
  
  return c.json({
    data: {
      discovered: discoveredCameras.length,
      new: newCameras.length,
      cameras: newCameras
    }
  });
});

// Camera Status and Health
app.get('/cameras/:id/status', tenantMiddleware, validateCameraAccess, async (c) => {
  const camera = c.get('camera');
  
  const status = {
    id: camera.id,
    name: camera.name,
    status: camera.status,
    lastSeen: camera.lastSeen,
    ipAddress: camera.ipAddress,
    port: camera.port,
    isRecording: camera.recordingEnabled && camera.status === 'online',
    motionDetection: camera.motionDetectionEnabled,
    privacyMasksActive: camera.privacyMasks?.length > 0
  };
  
  return c.json({ data: status });
});

app.post('/cameras/:id/test-connection', tenantMiddleware, validateCameraAccess, async (c) => {
  const camera = c.get('camera');
  
  try {
    const response = await fetch(`http://${camera.ipAddress}:${camera.port}`, {
      method: 'HEAD',
      timeout: 5000
    });
    
    const isOnline = response.ok;
    
    // Update camera status
    await prisma.camera.update({
      where: { id: camera.id },
      data: {
        status: isOnline ? 'online' : 'offline',
        lastSeen: isOnline ? new Date() : camera.lastSeen
      }
    });
    
    return c.json({
      data: {
        connected: isOnline,
        responseTime: response.headers.get('response-time'),
        lastTested: new Date()
      }
    });
  } catch (error) {
    return c.json({
      data: {
        connected: false,
        error: error.message,
        lastTested: new Date()
      }
    }, 500);
  }
});

// Privacy Masks
app.get('/cameras/:id/privacy-masks', tenantMiddleware, validateCameraAccess, async (c) => {
  const camera = c.get('camera');
  
  const masks = await prisma.privacyMask.findMany({
    where: { cameraId: camera.id },
    orderBy: { name: 'asc' }
  });
  
  return c.json({ data: masks });
});

app.post('/cameras/:id/privacy-masks', tenantMiddleware, validateCameraAccess, zValidator('json', privacyMaskSchema), async (c) => {
  const camera = c.get('camera');
  const tenantId = c.get('tenantId');
  const data = c.req.valid('json');
  
  const mask = await prisma.privacyMask.create({
    data: {
      ...data,
      cameraId: camera.id,
      tenantId,
      isActive: true,
      createdAt: new Date()
    }
  });
  
  // Log privacy mask creation
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId: 'system',
      action: 'privacy_mask_created',
      resourceType: 'privacy_mask',
      resourceId: mask.id,
      details: {
        cameraId: camera.id,
        cameraName: camera.name,
        maskName: mask.name
      }
    }
  });
  
  return c.json({ data: mask }, 201);
});

app.delete('/cameras/:id/privacy-masks/:maskId', tenantMiddleware, validateCameraAccess, async (c) => {
  const camera = c.get('camera');
  const tenantId = c.get('tenantId');
  const maskId = c.req.param('maskId');
  
  const mask = await prisma.privacyMask.findFirst({
    where: {
      id: maskId,
      cameraId: camera.id,
      tenantId
    }
  });
  
  if (!mask) {
    throw new HTTPException(404, { message: 'Privacy mask not found' });
  }
  
  await prisma.privacyMask.delete({
    where: { id: maskId }
  });
  
  // Log privacy mask deletion
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId: 'system',
      action: 'privacy_mask_deleted',
      resourceType: 'privacy_mask',
      resourceId: maskId,
      details: {
        cameraId: camera.id,
        cameraName: camera.name,
        maskName: mask.name
      }
    }
  });
  
  return c.json({ message: 'Privacy mask deleted successfully' });
});

// Camera Configuration
app.get('/cameras/:id/capabilities', tenantMiddleware, validateCameraAccess, async (c) => {
  const camera = c.get('camera');
  
  try {
    const capabilities = await discoveryService.getCameraCapabilities(
      camera.ipAddress,
      camera.onvifPort,
      camera.username,
      camera.password
    );
    
    return c.json({ data: capabilities });
  } catch (error) {
    throw new HTTPException(500, { message: 'Failed to retrieve camera capabilities' });
  }
});

// Bulk operations
app.post('/cameras/bulk-update', tenantMiddleware, async (c) => {
  const tenantId = c.get('tenantId');
  const { cameraIds, updates } = await c.req.json();
  
  if (!Array.isArray(cameraIds) || cameraIds.length === 0) {
    throw new HTTPException(400, { message: 'Camera IDs array is required' });
  }
  
  // Validate all cameras belong to tenant
  const cameras = await prisma.camera.findMany({
    where: {
      id: { in: cameraIds },
      tenantId
    }
  });
  
  if (cameras.length !== cameraIds.length) {
    throw new HTTPException(400, { message: 'Some cameras not found or access denied' });
  }
  
  const result = await prisma.camera.updateMany({
    where: {
      id: { in: cameraIds },
      tenantId
    },
    data: {
      ...updates,
      updatedAt: new Date()
    }
  });
  
  // Log bulk update
  await prisma.auditLog.create({
    data: {
      tenantId,
      userId: 'system',
      action: 'cameras_bulk_updated',
      resourceType: 'camera',
      resourceId: 'bulk',
      details: {
        cameraIds,
        updates,
        affectedCount: result.count
      }
    }
  });
  
  return c.json({
    data: {
      updated: result.count,
      cameraIds
    }
  });
});

// Health check endpoint
app.get('/health', async (c) => {
  return c.json({
    status: 'healthy',
    timestamp: new Date(),
    service: 'camera-management'
  });
});

// Cleanup on shutdown
process.on('SIGTERM', () => {
  healthMonitor.stopMonitoring();
  prisma.$disconnect();
});

export default app;