import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { DeviceProvisioningService } from '../services/device-provisioning-service';

const provisionDeviceSchema = z.object({
  deviceType: z.string(),
  manufacturer: z.string(),
  model: z.string(),
  serialNumber: z.string(),
  macAddress: z.string().regex(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  ipAddress: z.string().ip().optional(),
  location: z.object({
    siteId: z.string().uuid(),
    buildingId: z.string().uuid(),
    floorId: z.string().uuid(),
    zone: z.string().optional()
  }),
  metadata: z.record(z.any()).optional(),
  options: z.object({
    templateId: z.string().uuid().optional(),
    generateCertificate: z.boolean().default(true),
    autoActivate: z.boolean().default(true),
    validateOnly: z.boolean().default(false),
    customConfig: z.record(z.any()).optional()
  }).optional()
});

const getProvisioningHistorySchema = z.object({
  deviceId: z.string().uuid().optional(),
  status: z.enum(['pending', 'in_progress', 'completed', 'failed', 'cancelled']).optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  limit: z.coerce.number().int().positive().default(50),
  offset: z.coerce.number().int().nonnegative().default(0)
});

export function provisioningRoutes(provisioningService: DeviceProvisioningService): Hono {
  const app = new Hono();

  // Provision a single device
  app.post('/', zValidator('json', provisionDeviceSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const data = c.req.valid('json');
      
      const result = await provisioningService.provisionDevice(
        tenantId,
        {
          deviceType: data.deviceType,
          manufacturer: data.manufacturer,
          model: data.model,
          serialNumber: data.serialNumber,
          macAddress: data.macAddress,
          ipAddress: data.ipAddress,
          location: data.location,
          metadata: data.metadata
        },
        data.options
      );

      if (!result.success) {
        throw new HTTPException(400, { message: result.error || 'Provisioning failed' });
      }

      return c.json({
        success: true,
        provisioningId: result.provisioningId,
        deviceId: result.deviceId,
        certificateId: result.certificateId,
        message: data.options?.validateOnly 
          ? 'Device validation successful' 
          : 'Device provisioning started'
      }, 201);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { 
        message: 'Failed to provision device',
        cause: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Get provisioning status
  app.get('/:provisioningId/status', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const provisioningId = c.req.param('provisioningId');
      
      const status = await provisioningService.getProvisioningStatus(provisioningId, tenantId);
      
      if (!status) {
        throw new HTTPException(404, { message: 'Provisioning record not found' });
      }

      return c.json({
        success: true,
        provisioning: status
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to get provisioning status' });
    }
  });

  // Cancel provisioning
  app.post('/:provisioningId/cancel', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const provisioningId = c.req.param('provisioningId');
      
      const cancelled = await provisioningService.cancelProvisioning(provisioningId, tenantId);
      
      if (!cancelled) {
        throw new HTTPException(400, { 
          message: 'Unable to cancel provisioning. It may have already completed or failed.' 
        });
      }

      return c.json({
        success: true,
        message: 'Provisioning cancelled successfully'
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to cancel provisioning' });
    }
  });

  // Get provisioning history
  app.get('/history', zValidator('query', getProvisioningHistorySchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const filters = c.req.valid('query');
      
      const history = await provisioningService.getProvisioningHistory(tenantId, {
        deviceId: filters.deviceId,
        status: filters.status,
        startDate: filters.startDate ? new Date(filters.startDate) : undefined,
        endDate: filters.endDate ? new Date(filters.endDate) : undefined,
        limit: filters.limit,
        offset: filters.offset
      });

      return c.json({
        success: true,
        records: history.records,
        total: history.total,
        pagination: {
          limit: filters.limit,
          offset: filters.offset,
          hasMore: history.total > (filters.offset + filters.limit)
        }
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to get provisioning history' });
    }
  });

  // Retry failed provisioning
  app.post('/:provisioningId/retry', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const provisioningId = c.req.param('provisioningId');
      
      // Get original provisioning record
      const original = await provisioningService.getProvisioningStatus(provisioningId, tenantId);
      
      if (!original) {
        throw new HTTPException(404, { message: 'Provisioning record not found' });
      }

      if (original.status !== 'failed') {
        throw new HTTPException(400, { 
          message: 'Can only retry failed provisioning attempts' 
        });
      }

      // Start new provisioning with same data
      const result = await provisioningService.provisionDevice(
        tenantId,
        original.provisioningData as any,
        {
          templateId: original.templateId || undefined,
          generateCertificate: true,
          autoActivate: true
        }
      );

      if (!result.success) {
        throw new HTTPException(400, { message: result.error || 'Retry failed' });
      }

      return c.json({
        success: true,
        provisioningId: result.provisioningId,
        message: 'Provisioning retry started'
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to retry provisioning' });
    }
  });

  // Validate device before provisioning
  app.post('/validate', zValidator('json', provisionDeviceSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const data = c.req.valid('json');
      
      const result = await provisioningService.provisionDevice(
        tenantId,
        {
          deviceType: data.deviceType,
          manufacturer: data.manufacturer,
          model: data.model,
          serialNumber: data.serialNumber,
          macAddress: data.macAddress,
          ipAddress: data.ipAddress,
          location: data.location,
          metadata: data.metadata
        },
        {
          ...data.options,
          validateOnly: true
        }
      );

      if (!result.success) {
        return c.json({
          success: false,
          valid: false,
          error: result.error,
          message: 'Device validation failed'
        }, 400);
      }

      return c.json({
        success: true,
        valid: true,
        message: 'Device validation successful'
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to validate device' });
    }
  });

  // Get provisioning statistics
  app.get('/stats', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const period = c.req.query('period') || '7d';
      
      // Calculate date range based on period
      const endDate = new Date();
      const startDate = new Date();
      
      switch (period) {
        case '24h':
          startDate.setHours(startDate.getHours() - 24);
          break;
        case '7d':
          startDate.setDate(startDate.getDate() - 7);
          break;
        case '30d':
          startDate.setDate(startDate.getDate() - 30);
          break;
        case '90d':
          startDate.setDate(startDate.getDate() - 90);
          break;
        default:
          startDate.setDate(startDate.getDate() - 7);
      }

      // Get stats for different statuses
      const [completed, failed, inProgress, cancelled] = await Promise.all([
        provisioningService.getProvisioningHistory(tenantId, {
          status: 'completed',
          startDate,
          endDate,
          limit: 1,
          offset: 0
        }),
        provisioningService.getProvisioningHistory(tenantId, {
          status: 'failed',
          startDate,
          endDate,
          limit: 1,
          offset: 0
        }),
        provisioningService.getProvisioningHistory(tenantId, {
          status: 'in_progress',
          limit: 1,
          offset: 0
        }),
        provisioningService.getProvisioningHistory(tenantId, {
          status: 'cancelled',
          startDate,
          endDate,
          limit: 1,
          offset: 0
        })
      ]);

      const total = completed.total + failed.total + cancelled.total;
      const successRate = total > 0 ? (completed.total / total) * 100 : 0;

      return c.json({
        success: true,
        stats: {
          period,
          total,
          completed: completed.total,
          failed: failed.total,
          inProgress: inProgress.total,
          cancelled: cancelled.total,
          successRate: Math.round(successRate * 100) / 100
        }
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to get provisioning statistics' });
    }
  });

  return app;
}