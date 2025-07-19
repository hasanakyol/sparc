import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { DeviceManagementService } from '../services/device-management-service';

// Device schema
const deviceSchema = z.object({
  name: z.string().min(1),
  type: z.enum(['access_panel', 'card_reader', 'ip_camera', 'environmental_sensor']),
  manufacturer: z.string(),
  model: z.string(),
  firmwareVersion: z.string(),
  ipAddress: z.string().ip(),
  macAddress: z.string().regex(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  location: z.object({
    siteId: z.string(),
    buildingId: z.string(),
    floorId: z.string(),
    zone: z.string().optional()
  }),
  capabilities: z.array(z.string()).optional(),
  configuration: z.record(z.any()).optional()
});

const deviceUpdateSchema = deviceSchema.partial();

export function createDeviceRoutes(deviceService: DeviceManagementService): Hono {
  const app = new Hono();

  // List all devices
  app.get('/', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { type, status, location } = c.req.query();

      const where: any = { tenantId };
      if (type) where.type = type;
      if (status) where.status = status;
      if (location) where.location = { path: ['siteId'], equals: location };

      const devices = await deviceService.getDevices(where);
      return c.json({ devices });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch devices' });
    }
  });

  // Get device by ID
  app.get('/:id', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const device = await deviceService.getDevice(deviceId, tenantId);
      
      if (!device) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ device });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch device' });
    }
  });

  // Create new device
  app.post('/', zValidator('json', deviceSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const data = c.req.valid('json');
      
      const device = await deviceService.createDevice({
        ...data,
        tenantId,
        status: 'offline',
        lastSeen: new Date()
      });
      
      return c.json({ device }, 201);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to create device' });
    }
  });

  // Update device
  app.patch('/:id', zValidator('json', deviceUpdateSchema), async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      const data = c.req.valid('json');
      
      const device = await deviceService.updateDevice(deviceId, tenantId, data);
      
      if (!device) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ device });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to update device' });
    }
  });

  // Delete device
  app.delete('/:id', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const deleted = await deviceService.deleteDevice(deviceId, tenantId);
      
      if (!deleted) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ message: 'Device deleted successfully' });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to delete device' });
    }
  });

  // Reboot device
  app.post('/:id/reboot', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const result = await deviceService.rebootDevice(deviceId, tenantId);
      
      if (!result) {
        throw new HTTPException(404, { message: 'Device not found or reboot failed' });
      }
      
      return c.json({ message: 'Device reboot initiated' });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to reboot device' });
    }
  });

  // Get device configuration
  app.get('/:id/config', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const config = await deviceService.getDeviceConfiguration(deviceId, tenantId);
      
      if (!config) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ configuration: config });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch device configuration' });
    }
  });

  // Update device configuration
  app.put('/:id/config', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      const config = await c.req.json();
      
      const updated = await deviceService.updateDeviceConfiguration(deviceId, tenantId, config);
      
      if (!updated) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ message: 'Device configuration updated' });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to update device configuration' });
    }
  });

  return app;
}