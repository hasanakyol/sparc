import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { AlertService } from '../services/alert-service';

// Alert schemas
const CreateAlertSchema = z.object({
  type: z.enum(['security', 'environmental', 'system', 'maintenance']),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  title: z.string(),
  description: z.string(),
  sourceEvents: z.array(z.string()).optional(),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }),
  metadata: z.record(z.any()).optional(),
});

const UpdateAlertSchema = z.object({
  acknowledged: z.boolean().optional(),
  resolved: z.boolean().optional(),
  notes: z.string().optional(),
});

export function createAlertRoutes(alertService: AlertService): Hono {
  const app = new Hono();

  // Get alerts
  app.get('/', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { 
        status, 
        type, 
        severity, 
        buildingId, 
        floorId,
        startTime,
        endTime,
        limit = '100',
        offset = '0'
      } = c.req.query();
      
      const alerts = await alertService.getAlerts(tenantId, {
        status,
        type,
        severity,
        buildingId,
        floorId,
        startTime: startTime ? new Date(startTime) : undefined,
        endTime: endTime ? new Date(endTime) : undefined,
        limit: parseInt(limit),
        offset: parseInt(offset)
      });
      
      return c.json({ 
        alerts,
        count: alerts.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch alerts' });
    }
  });

  // Get alert by ID
  app.get('/:id', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const alertId = c.req.param('id');
      
      const alert = await alertService.getAlert(alertId, tenantId);
      
      if (!alert) {
        throw new HTTPException(404, { message: 'Alert not found' });
      }
      
      return c.json({ alert });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch alert' });
    }
  });

  // Create alert manually
  app.post('/', zValidator('json', CreateAlertSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const alertData = c.req.valid('json');
      
      const alert = await alertService.createAlert(tenantId, alertData);
      
      return c.json({ 
        message: 'Alert created',
        alert
      }, 201);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to create alert' });
    }
  });

  // Update alert
  app.patch('/:id', zValidator('json', UpdateAlertSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const alertId = c.req.param('id');
      const userId = c.get('userId');
      const updates = c.req.valid('json');
      
      if (updates.acknowledged) {
        await alertService.acknowledgeAlert(alertId, userId, tenantId);
      }
      
      if (updates.resolved) {
        await alertService.resolveAlert(alertId, userId, tenantId);
      }
      
      const alert = await alertService.getAlert(alertId, tenantId);
      
      return c.json({ 
        message: 'Alert updated',
        alert
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to update alert' });
    }
  });

  // Acknowledge alert
  app.post('/:id/acknowledge', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const alertId = c.req.param('id');
      const userId = c.get('userId');
      
      const alert = await alertService.acknowledgeAlert(alertId, userId, tenantId);
      
      return c.json({ 
        message: 'Alert acknowledged',
        alert
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to acknowledge alert' });
    }
  });

  // Resolve alert
  app.post('/:id/resolve', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const alertId = c.req.param('id');
      const userId = c.get('userId');
      const { resolution } = await c.req.json();
      
      const alert = await alertService.resolveAlert(alertId, userId, tenantId, resolution);
      
      return c.json({ 
        message: 'Alert resolved',
        alert
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to resolve alert' });
    }
  });

  // Get active alerts
  app.get('/active/summary', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      
      const activeAlerts = await alertService.getActiveAlerts(tenantId);
      
      const summary = {
        total: activeAlerts.length,
        bySeverity: activeAlerts.reduce((acc, alert) => {
          acc[alert.severity] = (acc[alert.severity] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        byType: activeAlerts.reduce((acc, alert) => {
          acc[alert.type] = (acc[alert.type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>)
      };
      
      return c.json({ 
        activeAlerts: activeAlerts.length,
        summary,
        alerts: activeAlerts
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch active alerts' });
    }
  });

  // Get alert statistics
  app.get('/stats/summary', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { period = '24h' } = c.req.query();
      
      const stats = await alertService.getAlertStatistics(tenantId, period);
      
      return c.json({ 
        statistics: stats,
        period
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch alert statistics' });
    }
  });

  // Get correlation rules
  app.get('/rules/correlation', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      
      const rules = await alertService.getCorrelationRules(tenantId);
      
      return c.json({ 
        rules,
        count: rules.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch correlation rules' });
    }
  });

  // Update correlation rule
  app.put('/rules/correlation/:id', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const ruleId = c.req.param('id');
      const ruleData = await c.req.json();
      
      const rule = await alertService.updateCorrelationRule(tenantId, ruleId, ruleData);
      
      return c.json({ 
        message: 'Correlation rule updated',
        rule
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to update correlation rule' });
    }
  });

  return app;
}