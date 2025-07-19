import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { EventProcessingService } from '../services/event-processing-service';

// Event schemas
const AccessEventSchema = z.object({
  userId: z.string().optional(),
  doorId: z.string(),
  cardId: z.string().optional(),
  eventType: z.enum(['access_granted', 'access_denied', 'door_forced', 'door_held_open', 'door_propped']),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }),
  metadata: z.record(z.any()).optional(),
});

const VideoEventSchema = z.object({
  cameraId: z.string(),
  eventType: z.enum(['motion_detected', 'camera_offline', 'camera_tampered', 'line_crossing', 'loitering_detected']),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }),
  confidence: z.number().min(0).max(1).optional(),
  metadata: z.record(z.any()).optional(),
});

const EnvironmentalEventSchema = z.object({
  sensorId: z.string(),
  eventType: z.enum(['temperature_high', 'temperature_low', 'humidity_high', 'humidity_low', 'water_detected', 'sensor_offline']),
  value: z.number(),
  threshold: z.number(),
  location: z.object({
    buildingId: z.string(),
    floorId: z.string(),
    zoneId: z.string().optional(),
  }),
  metadata: z.record(z.any()).optional(),
});

export function createEventRoutes(eventService: EventProcessingService): Hono {
  const app = new Hono();

  // Submit access event
  app.post('/access', zValidator('json', AccessEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitAccessEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'Access event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to submit access event' });
    }
  });

  // Submit video event
  app.post('/video', zValidator('json', VideoEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitVideoEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'Video event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to submit video event' });
    }
  });

  // Submit environmental event
  app.post('/environmental', zValidator('json', EnvironmentalEventSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const eventData = c.req.valid('json');
      
      const event = await eventService.submitEnvironmentalEvent(tenantId, eventData);
      
      return c.json({ 
        message: 'Environmental event submitted',
        eventId: event.id,
        timestamp: event.timestamp
      }, 201);
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to submit environmental event' });
    }
  });

  // Get events
  app.get('/', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { type, buildingId, floorId, startTime, endTime, limit = '100' } = c.req.query();
      
      const events = await eventService.getEvents(tenantId, {
        type,
        buildingId,
        floorId,
        startTime: startTime ? new Date(startTime) : undefined,
        endTime: endTime ? new Date(endTime) : undefined,
        limit: parseInt(limit)
      });
      
      return c.json({ 
        events,
        count: events.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch events' });
    }
  });

  // Get event by ID
  app.get('/:id', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const eventId = c.req.param('id');
      
      const event = await eventService.getEvent(tenantId, eventId);
      
      if (!event) {
        throw new HTTPException(404, { message: 'Event not found' });
      }
      
      return c.json({ event });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to fetch event' });
    }
  });

  // Get event statistics
  app.get('/stats/summary', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { period = '24h' } = c.req.query();
      
      const stats = await eventService.getEventStatistics(tenantId, period);
      
      return c.json({ 
        statistics: stats,
        period
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch event statistics' });
    }
  });

  // Get event trends
  app.get('/stats/trends', async (c) => {
    try {
      const tenantId = c.get('tenantId');
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
      throw new HTTPException(500, { message: 'Failed to fetch event trends' });
    }
  });

  // Bulk event submission
  app.post('/bulk', async (c) => {
    try {
      const tenantId = c.get('tenantId');
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
      throw new HTTPException(500, { message: 'Failed to submit bulk events' });
    }
  });

  return app;
}