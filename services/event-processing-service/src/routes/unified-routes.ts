import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';
import { UnifiedEventService } from '../services/unified-event-service';
import { 
  createAlertSchema, 
  updateAlertSchema, 
  acknowledgeAlertSchema,
  type AlertStatus,
  type AlertPriority
} from '@sparc/shared/types/alerts';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';

// Event schemas
const AccessEventSchema = z.object({
  eventSubType: z.enum(['access_granted', 'access_denied', 'door_forced', 'door_held_open', 'door_propped']),
  sourceId: z.string(),
  sourceType: z.string().default('door'),
  userId: z.string().optional(),
  cardId: z.string().optional(),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }),
  metadata: z.record(z.any()).optional(),
});

const VideoEventSchema = z.object({
  eventSubType: z.enum(['motion_detected', 'camera_offline', 'camera_tampered', 'line_crossing', 'loitering_detected']),
  sourceId: z.string(),
  sourceType: z.string().default('camera'),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }),
  confidence: z.string().optional(),
  metadata: z.record(z.any()).optional(),
});

const EnvironmentalEventSchema = z.object({
  eventSubType: z.enum(['temperature_high', 'temperature_low', 'humidity_high', 'humidity_low', 'water_detected', 'sensor_offline']),
  sourceId: z.string(),
  sourceType: z.string().default('sensor'),
  value: z.string(),
  threshold: z.string(),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }),
  metadata: z.record(z.any()).optional(),
});

const SystemEventSchema = z.object({
  eventSubType: z.enum(['system_startup', 'system_shutdown', 'service_error', 'database_error']),
  sourceId: z.string(),
  sourceType: z.string().default('system'),
  description: z.string(),
  metadata: z.record(z.any()).optional(),
});

const SecurityEventSchema = z.object({
  eventSubType: z.enum(['intrusion_detected', 'unauthorized_access', 'security_breach', 'alarm_triggered']),
  sourceId: z.string(),
  sourceType: z.string(),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }).optional(),
  description: z.string(),
  metadata: z.record(z.any()).optional(),
});

export function createUnifiedRoutes(eventService: UnifiedEventService): Hono {
  const app = new Hono();

  // Apply auth middleware to all routes
  app.use('*', authMiddleware);

  // ==================== Alert Routes ====================

  const alertsRouter = new Hono();

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

      const response = await eventService.listAlerts(tenantId, {
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

      const stats = await eventService.getAlertStatistics(tenantId, timeframe);
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

      const alert = await eventService.getAlert(tenantId, alertId);
      
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

      const alert = await eventService.createAlert(tenantId, data);

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

      const alert = await eventService.updateAlert(tenantId, alertId, data);
      
      if (!alert) {
        throw new HTTPException(404, { message: 'Alert not found' });
      }

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

      const alert = await eventService.acknowledgeAlert(tenantId, alertId, acknowledgedBy);
      
      if (!alert) {
        throw new HTTPException(404, { message: 'Alert not found' });
      }

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

      const deleted = await eventService.deleteAlert(tenantId, alertId);
      
      if (!deleted) {
        throw new HTTPException(404, { message: 'Alert not found' });
      }

      return c.json({ message: 'Alert deleted successfully' });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to delete alert', { error });
      throw new HTTPException(500, { message: 'Failed to delete alert' });
    }
  });

  // Mount alerts router
  app.route('/alerts', alertsRouter);

  // ==================== Event Routes ====================

  const eventsRouter = new Hono();

  // Submit access event
  eventsRouter.post('/access', zValidator('json', AccessEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitAccessEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'Access event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      logger.error('Failed to submit access event', { error });
      throw new HTTPException(500, { message: 'Failed to submit access event' });
    }
  });

  // Submit video event
  eventsRouter.post('/video', zValidator('json', VideoEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitVideoEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'Video event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      logger.error('Failed to submit video event', { error });
      throw new HTTPException(500, { message: 'Failed to submit video event' });
    }
  });

  // Submit environmental event
  eventsRouter.post('/environmental', zValidator('json', EnvironmentalEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitEnvironmentalEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'Environmental event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      logger.error('Failed to submit environmental event', { error });
      throw new HTTPException(500, { message: 'Failed to submit environmental event' });
    }
  });

  // Submit system event
  eventsRouter.post('/system', zValidator('json', SystemEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitSystemEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'System event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      logger.error('Failed to submit system event', { error });
      throw new HTTPException(500, { message: 'Failed to submit system event' });
    }
  });

  // Submit security event
  eventsRouter.post('/security', zValidator('json', SecurityEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitSecurityEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'Security event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      logger.error('Failed to submit security event', { error });
      throw new HTTPException(500, { message: 'Failed to submit security event' });
    }
  });

  // Get events
  eventsRouter.get('/', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const { type, subType, sourceId, startTime, endTime, limit = '100' } = c.req.query();
      
      const events = await eventService.getEvents(tenantId, {
        type,
        subType,
        sourceId,
        startTime,
        endTime,
        limit: parseInt(limit)
      });
      
      return c.json({ 
        events,
        count: events.length
      });
    } catch (error) {
      logger.error('Failed to fetch events', { error });
      throw new HTTPException(500, { message: 'Failed to fetch events' });
    }
  });

  // Get event by ID
  eventsRouter.get('/:id', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const eventId = c.req.param('id');
      
      const event = await eventService.getEvent(tenantId, eventId);
      
      if (!event) {
        throw new HTTPException(404, { message: 'Event not found' });
      }
      
      return c.json({ event });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to fetch event', { error });
      throw new HTTPException(500, { message: 'Failed to fetch event' });
    }
  });

  // Get event statistics
  eventsRouter.get('/stats/summary', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const { period = '24h' } = c.req.query();
      
      const stats = await eventService.getEventStatistics(tenantId, period);
      
      return c.json({ 
        statistics: stats,
        period
      });
    } catch (error) {
      logger.error('Failed to fetch event statistics', { error });
      throw new HTTPException(500, { message: 'Failed to fetch event statistics' });
    }
  });

  // Get event trends
  eventsRouter.get('/stats/trends', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const { startTime, endTime, interval = '1h' } = c.req.query();
      
      const trends = await eventService.getEventTrends(tenantId, {
        startTime: startTime ? new Date(startTime) : new Date(Date.now() - 24 * 60 * 60 * 1000),
        endTime: endTime ? new Date(endTime) : new Date(),
        interval
      });
      
      return c.json({ 
        trends,
        interval
      });
    } catch (error) {
      logger.error('Failed to fetch event trends', { error });
      throw new HTTPException(500, { message: 'Failed to fetch event trends' });
    }
  });

  // Bulk event submission
  eventsRouter.post('/bulk', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const { events } = await c.req.json();
      
      if (!Array.isArray(events) || events.length === 0) {
        throw new HTTPException(400, { message: 'Events array required' });
      }
      
      const results = await eventService.submitBulkEvents(tenantId, events);
      
      return c.json({ 
        message: 'Bulk events submitted',
        processed: results.processed,
        failed: results.failed,
        results: results.results
      }, 201);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to submit bulk events', { error });
      throw new HTTPException(500, { message: 'Failed to submit bulk events' });
    }
  });

  // Mount events router
  app.route('/events', eventsRouter);

  // ==================== Processing Control Routes ====================

  // Start event processing
  app.post('/processing/start', async (c) => {
    try {
      await eventService.startProcessing();
      return c.json({ message: 'Event processing started' });
    } catch (error) {
      logger.error('Failed to start processing', { error });
      throw new HTTPException(500, { message: 'Failed to start processing' });
    }
  });

  // Stop event processing
  app.post('/processing/stop', async (c) => {
    try {
      await eventService.stopProcessing();
      return c.json({ message: 'Event processing stopped' });
    } catch (error) {
      logger.error('Failed to stop processing', { error });
      throw new HTTPException(500, { message: 'Failed to stop processing' });
    }
  });

  // Get processing status
  app.get('/processing/status', async (c) => {
    try {
      const stats = await eventService.getStats();
      return c.json({
        processing: eventService.isProcessing(),
        stats
      });
    } catch (error) {
      logger.error('Failed to get processing status', { error });
      throw new HTTPException(500, { message: 'Failed to get processing status' });
    }
  });

  return app;
}