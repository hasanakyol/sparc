import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { DeviceManagementService } from '../services/device-management-service';

export function createHealthRoutes(deviceService: DeviceManagementService): Hono {
  const app = new Hono();

  // Get health status for a specific device
  app.get('/devices/:id', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const health = await deviceService.getDeviceHealth(deviceId, tenantId);
      
      if (!health) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ 
        deviceId,
        health,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch device health' });
    }
  });

  // Get health summary for all devices
  app.get('/summary', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const summary = await deviceService.getHealthSummary(tenantId);
      
      return c.json({ 
        summary,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch health summary' });
    }
  });

  // Trigger health check for a specific device
  app.post('/devices/:id/check', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      
      const health = await deviceService.checkDeviceHealth(deviceId, tenantId);
      
      if (!health) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ 
        deviceId,
        health,
        message: 'Health check completed',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Health check failed' });
    }
  });

  // Trigger health check for all devices
  app.post('/check-all', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const results = await deviceService.checkAllDeviceHealth(tenantId);
      
      return c.json({ 
        results,
        message: 'Health check completed for all devices',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Health check failed' });
    }
  });

  // Get device metrics
  app.get('/devices/:id/metrics', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      const { period = '1h' } = c.req.query();
      
      const metrics = await deviceService.getDeviceMetrics(deviceId, tenantId, period);
      
      if (!metrics) {
        throw new HTTPException(404, { message: 'Device not found' });
      }
      
      return c.json({ 
        deviceId,
        period,
        metrics,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch device metrics' });
    }
  });

  // Get alerts for a device
  app.get('/devices/:id/alerts', async (c) => {
    try {
      const deviceId = c.req.param('id');
      const tenantId = c.get('tenantId');
      const { severity, limit = '10' } = c.req.query();
      
      const alerts = await deviceService.getDeviceAlerts(deviceId, tenantId, {
        severity,
        limit: parseInt(limit)
      });
      
      return c.json({ 
        deviceId,
        alerts,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch device alerts' });
    }
  });

  return app;
}