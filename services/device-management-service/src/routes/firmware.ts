import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { DeviceManagementService } from '../services/device-management-service';

// Firmware update schema
const firmwareUpdateSchema = z.object({
  version: z.string(),
  updateUrl: z.string().url(),
  checksum: z.string(),
  releaseNotes: z.string().optional(),
  mandatory: z.boolean().optional()
});

export function createFirmwareRoutes(deviceService: DeviceManagementService): Hono {
  const app = new Hono();

  // Check for firmware updates for a device
  app.get('/devices/:id/check', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const update = await deviceService.checkFirmwareUpdates(deviceId, tenantId);
      
      return c.json({ 
        deviceId,
        updateAvailable: !!update,
        update,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to check firmware updates' });
    }
  });

  // Get firmware update history for a device
  app.get('/devices/:id/history', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const history = await deviceService.getFirmwareHistory(deviceId, tenantId);
      
      return c.json({ 
        deviceId,
        history,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch firmware history' });
    }
  });

  // Initiate firmware update
  app.post('/devices/:id/update', zValidator('json', firmwareUpdateSchema), async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      const updateData = c.req.valid('json');
      
      const result = await deviceService.updateFirmware(deviceId, tenantId, updateData);
      
      if (!result.success) {
        throw new HTTPException(400, { message: result.error || 'Firmware update failed' });
      }
      
      return c.json({ 
        deviceId,
        message: 'Firmware update initiated',
        updateId: result.updateId,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to initiate firmware update' });
    }
  });

  // Get firmware update status
  app.get('/updates/:updateId/status', async (c) => {
    try {
      const updateId = c.req.param('updateId');
      const tenantId = c.get('tenantId');
      
      const status = await deviceService.getFirmwareUpdateStatus(updateId, tenantId);
      
      if (!status) {
        throw new HTTPException(404, { message: 'Update not found' });
      }
      
      return c.json({ 
        updateId,
        status,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch update status' });
    }
  });

  // Cancel firmware update
  app.post('/updates/:updateId/cancel', async (c) => {
    try {
      const updateId = c.req.param('updateId');
      const tenantId = c.get('tenantId');
      
      const result = await deviceService.cancelFirmwareUpdate(updateId, tenantId);
      
      if (!result) {
        throw new HTTPException(404, { message: 'Update not found or cannot be cancelled' });
      }
      
      return c.json({ 
        updateId,
        message: 'Firmware update cancelled',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to cancel firmware update' });
    }
  });

  // Get available firmware versions for a device type
  app.get('/available/:deviceType', async (c) => {
    try {
      const deviceType = c.req.param('deviceType');
      const { manufacturer, model } = c.req.query();
      
      const versions = await deviceService.getAvailableFirmwareVersions({
        deviceType,
        manufacturer,
        model
      });
      
      return c.json({ 
        deviceType,
        manufacturer,
        model,
        versions,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch available firmware versions' });
    }
  });

  // Bulk firmware update
  app.post('/bulk-update', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { deviceIds, firmware } = await c.req.json();
      
      if (!Array.isArray(deviceIds) || deviceIds.length === 0) {
        throw new HTTPException(400, { message: 'Device IDs array required' });
      }
      
      const results = await deviceService.bulkFirmwareUpdate(deviceIds, firmware, tenantId);
      
      return c.json({ 
        message: 'Bulk firmware update initiated',
        results,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to initiate bulk firmware update' });
    }
  });

  return app;
}