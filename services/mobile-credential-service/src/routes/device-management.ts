import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { DeviceManagementService } from '../services/device-management-service';
import { DeviceManagementSchema } from '../types/schemas';
import { authMiddleware } from '@shared/middleware/auth';

export function createDeviceManagementRoutes(prisma: PrismaClient, redis: Redis, config: any) {
  const app = new Hono();
  const deviceService = new DeviceManagementService(prisma, redis, config);

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Execute device management action
  app.post('/', zValidator('json', DeviceManagementSchema), async (c) => {
    try {
      const managementData = c.req.valid('json');
      const user = c.get('user');
      const tenantId = c.get('tenantId');

      // Verify user has device management permissions
      if (!user.permissions?.includes('device.manage')) {
        return c.json({ error: 'Insufficient permissions' }, 403);
      }

      const result = await deviceService.executeDeviceAction(
        managementData,
        user.id,
        tenantId
      );

      return c.json(result);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Get device power status
  app.get('/:credentialId/power-status', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      
      const powerStatus = await deviceService.getPowerStatus(credentialId);
      
      if (!powerStatus) {
        return c.json({ error: 'Power status not available' }, 404);
      }

      return c.json(powerStatus);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Update device power status
  app.post('/:credentialId/power-status', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const deviceStatus = await c.req.json();

      await deviceService.updatePowerStatus(credentialId, deviceStatus);

      return c.json({ success: true });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Check device compliance
  app.get('/compliance/:deviceId', async (c) => {
    try {
      const deviceId = c.req.param('deviceId');
      const tenantId = c.get('tenantId');

      const result = await deviceService.executeDeviceAction(
        {
          action: 'compliance_check',
          deviceIds: [deviceId],
          immediate: true,
          notifyUser: false
        },
        c.get('user').id,
        tenantId
      );

      if (result.results && result.results.length > 0) {
        return c.json(result.results[0]);
      }

      return c.json({ error: 'Device not found' }, 404);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Locate device
  app.post('/locate/:deviceId', async (c) => {
    try {
      const deviceId = c.req.param('deviceId');
      const user = c.get('user');
      const tenantId = c.get('tenantId');

      // Verify user has location permissions
      if (!user.permissions?.includes('device.locate')) {
        return c.json({ error: 'Insufficient permissions' }, 403);
      }

      const result = await deviceService.executeDeviceAction(
        {
          action: 'locate',
          deviceIds: [deviceId],
          immediate: true,
          notifyUser: true
        },
        user.id,
        tenantId
      );

      if (result.results && result.results.length > 0) {
        return c.json(result.results[0]);
      }

      return c.json({ error: 'Device not found' }, 404);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  return app;
}