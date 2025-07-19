import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { WebhookProcessorService } from '../services/webhook-processor.service';
import { 
  webhookEventSchema, 
  environmentalWebhookSchema 
} from '@sparc/shared/types/alerts';
import { logger } from '@sparc/shared';
import Redis from 'ioredis';

const webhooksRouter = new Hono();

// Initialize services
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const webhookProcessor = new WebhookProcessorService(redis);

// Generic webhook event endpoint
webhooksRouter.post('/events', zValidator('json', webhookEventSchema), async (c) => {
  try {
    const event = c.req.valid('json');
    
    // Track webhook stats
    await redis.hincrby(`webhook_stats:${event.data.tenantId || 'unknown'}`, 'eventsProcessed', 1);
    await redis.hset(`webhook_stats:${event.data.tenantId || 'unknown'}`, 'lastProcessed', new Date().toISOString());

    const alert = await webhookProcessor.processWebhookEvent(event);

    if (alert) {
      await redis.hincrby(`webhook_stats:${alert.tenantId}`, 'alertsCreated', 1);
      
      logger.info('Alert created from webhook', {
        alertId: alert.id,
        eventType: event.eventType,
        sourceId: event.sourceId
      });

      return c.json({ alert }, 201);
    }

    return c.json({ 
      message: 'Event processed successfully',
      alertCreated: false 
    });
  } catch (error) {
    logger.error('Failed to process webhook event', { error });
    
    // Track errors
    const tenantId = c.req.valid('json').data.tenantId || 'unknown';
    await redis.hincrby(`webhook_stats:${tenantId}`, 'processingErrors', 1);
    
    throw new HTTPException(500, { message: 'Failed to process event' });
  }
});

// Environmental monitoring webhook
webhooksRouter.post('/environmental', zValidator('json', environmentalWebhookSchema), async (c) => {
  try {
    const data = c.req.valid('json');
    
    // Track webhook stats
    await redis.hincrby(`webhook_stats:${data.tenantId}`, 'environmentalEventsProcessed', 1);
    await redis.hset(`webhook_stats:${data.tenantId}`, 'lastEnvironmentalProcessed', new Date().toISOString());

    const alerts = await webhookProcessor.processEnvironmentalWebhook(data);

    logger.info('Environmental webhook processed', {
      tenantId: data.tenantId,
      sensorId: data.sensorId,
      alertsCreated: alerts.length
    });

    return c.json({ 
      alertsCreated: alerts.length,
      alerts: alerts.map(a => ({
        id: a.id,
        type: a.alertType,
        priority: a.priority,
        message: a.message
      }))
    });
  } catch (error) {
    logger.error('Failed to process environmental webhook', { error });
    
    // Track errors
    await redis.hincrby(`webhook_stats:${c.req.valid('json').tenantId}`, 'environmentalErrors', 1);
    
    throw new HTTPException(500, { message: 'Failed to process environmental data' });
  }
});

// Webhook statistics endpoint (requires auth)
webhooksRouter.get('/stats', async (c) => {
  try {
    // Check for API key auth
    const apiKey = c.req.header('X-API-Key');
    if (!apiKey || apiKey !== process.env.WEBHOOK_API_KEY) {
      throw new HTTPException(401, { message: 'Invalid API key' });
    }

    const tenantId = c.req.query('tenantId');
    if (!tenantId) {
      throw new HTTPException(400, { message: 'tenantId is required' });
    }

    const stats = await webhookProcessor.getEventProcessingStats(tenantId);
    return c.json(stats);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to fetch webhook stats', { error });
    throw new HTTPException(500, { message: 'Failed to fetch statistics' });
  }
});

// Health check for webhook endpoints
webhooksRouter.get('/health', async (c) => {
  try {
    // Check Redis connectivity
    await redis.ping();
    
    return c.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      endpoints: [
        '/webhooks/events',
        '/webhooks/environmental',
        '/webhooks/stats'
      ]
    });
  } catch (error) {
    logger.error('Webhook health check failed', { error });
    return c.json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Redis connection failed'
    }, 503);
  }
});

// Custom webhook handlers can be added here
// Example: Security system webhook
webhooksRouter.post('/security', async (c) => {
  try {
    const body = await c.req.json();
    
    // Transform security system specific format to standard webhook event
    const event = {
      eventType: body.alert_type || 'security_breach',
      sourceId: body.device_id || 'unknown',
      sourceType: 'security',
      data: {
        tenantId: body.tenant_id,
        location: body.location,
        severity: body.severity,
        ...body
      },
      timestamp: new Date().toISOString(),
      priority: body.severity === 'critical' ? 'critical' : 'high'
    };

    const validatedEvent = webhookEventSchema.parse(event);
    const alert = await webhookProcessor.processWebhookEvent(validatedEvent);

    if (alert) {
      return c.json({ 
        success: true,
        alertId: alert.id,
        message: 'Security alert created'
      }, 201);
    }

    return c.json({ 
      success: true,
      message: 'Event processed, no alert created' 
    });
  } catch (error) {
    logger.error('Failed to process security webhook', { error });
    throw new HTTPException(500, { message: 'Failed to process security event' });
  }
});

export default webhooksRouter;