import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { AlertService } from '../services/alert.service';
import { 
  createAlertSchema, 
  updateAlertSchema, 
  acknowledgeAlertSchema,
  type AlertStatus,
  type AlertPriority
} from '@sparc/shared/types/alerts';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import Redis from 'ioredis';

const alertsRouter = new Hono();

// Initialize services
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const alertService = new AlertService(redis);

// Apply auth middleware to all routes
alertsRouter.use('*', authMiddleware);

// List alerts with filtering and pagination
alertsRouter.get('/', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    
    // Parse query parameters
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const status = c.req.query('status') as AlertStatus | undefined;
    const priority = c.req.query('priority') as AlertPriority | undefined;
    const alertType = c.req.query('alertType');
    const sourceType = c.req.query('sourceType');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    const response = await alertService.listAlerts(tenantId, {
      page,
      limit,
      status,
      priority,
      alertType,
      sourceType,
      startDate,
      endDate
    });

    return c.json(response);
  } catch (error) {
    logger.error('Failed to list alerts', { error });
    throw new HTTPException(500, { message: 'Failed to fetch alerts' });
  }
});

// Get alert statistics
alertsRouter.get('/stats', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const timeframe = c.req.query('timeframe') || '24h';

    const stats = await alertService.getAlertStatistics(tenantId, timeframe);
    return c.json(stats);
  } catch (error) {
    logger.error('Failed to fetch alert statistics', { error });
    throw new HTTPException(500, { message: 'Failed to fetch statistics' });
  }
});

// Get single alert
alertsRouter.get('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const alertId = c.req.param('id');

    const alert = await alertService.getAlert(tenantId, alertId);
    
    if (!alert) {
      throw new HTTPException(404, { message: 'Alert not found' });
    }

    return c.json({ alert });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to fetch alert', { error });
    throw new HTTPException(500, { message: 'Failed to fetch alert' });
  }
});

// Create new alert
alertsRouter.post('/', zValidator('json', createAlertSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const data = c.req.valid('json');

    const alert = await alertService.createAlert(tenantId, data);

    // Broadcast alert via Socket.IO (handled by main service)
    await redis.publish('alert:broadcast', JSON.stringify({
      action: 'created',
      tenantId,
      alert
    }));

    logger.info('Alert created', { 
      alertId: alert.id, 
      tenantId,
      type: alert.alertType,
      priority: alert.priority 
    });

    return c.json({ alert }, 201);
  } catch (error) {
    logger.error('Failed to create alert', { error });
    throw new HTTPException(500, { message: 'Failed to create alert' });
  }
});

// Update alert
alertsRouter.put('/:id', zValidator('json', updateAlertSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const alertId = c.req.param('id');
    const data = c.req.valid('json');

    const alert = await alertService.updateAlert(tenantId, alertId, data);
    
    if (!alert) {
      throw new HTTPException(404, { message: 'Alert not found' });
    }

    // Broadcast update
    await redis.publish('alert:broadcast', JSON.stringify({
      action: 'updated',
      tenantId,
      alert
    }));

    logger.info('Alert updated', { 
      alertId: alert.id, 
      tenantId,
      status: alert.status 
    });

    return c.json({ alert });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to update alert', { error });
    throw new HTTPException(500, { message: 'Failed to update alert' });
  }
});

// Acknowledge alert
alertsRouter.post('/:id/acknowledge', zValidator('json', acknowledgeAlertSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const alertId = c.req.param('id');
    const { acknowledgedBy } = c.req.valid('json');

    const alert = await alertService.acknowledgeAlert(tenantId, alertId, acknowledgedBy);
    
    if (!alert) {
      throw new HTTPException(404, { message: 'Alert not found' });
    }

    // Broadcast acknowledgment
    await redis.publish('alert:broadcast', JSON.stringify({
      action: 'acknowledged',
      tenantId,
      alert
    }));

    // Cancel escalation
    await redis.publish('escalation:cancel', alertId);

    logger.info('Alert acknowledged', { 
      alertId: alert.id, 
      tenantId,
      acknowledgedBy 
    });

    return c.json({ alert });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to acknowledge alert', { error });
    throw new HTTPException(500, { message: 'Failed to acknowledge alert' });
  }
});

// Delete alert
alertsRouter.delete('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const alertId = c.req.param('id');

    const deleted = await alertService.deleteAlert(tenantId, alertId);
    
    if (!deleted) {
      throw new HTTPException(404, { message: 'Alert not found' });
    }

    // Broadcast deletion
    await redis.publish('alert:broadcast', JSON.stringify({
      action: 'deleted',
      tenantId,
      alertId
    }));

    // Cancel escalation
    await redis.publish('escalation:cancel', alertId);

    logger.info('Alert deleted', { alertId, tenantId });

    return c.json({ message: 'Alert deleted successfully' });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to delete alert', { error });
    throw new HTTPException(500, { message: 'Failed to delete alert' });
  }
});

export default alertsRouter;