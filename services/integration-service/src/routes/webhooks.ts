import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { 
  createWebhookSchema, 
  updateWebhookSchema,
  testWebhookSchema,
  WebhookEventType,
  WebhookStatus
} from '../types';
import { WebhookService } from '../services/webhook.service';
import { z } from 'zod';
import crypto from 'crypto';

const webhooksRouter = new Hono();

// Get service instances from context
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const webhookService = new WebhookService(prisma, redis);

// Apply auth middleware to all routes
webhooksRouter.use('*', authMiddleware);

// List webhooks with filtering and pagination
webhooksRouter.get('/', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    
    // Parse query parameters
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const status = c.req.query('status') as WebhookStatus | undefined;
    const eventType = c.req.query('eventType') as WebhookEventType | undefined;
    const search = c.req.query('search');

    const response = await webhookService.listWebhooks(tenantId, {
      page,
      limit,
      status,
      eventType,
      search
    });

    return c.json(response);
  } catch (error) {
    logger.error('Failed to list webhooks', { error });
    throw new HTTPException(500, { message: 'Failed to list webhooks' });
  }
});

// Create new webhook
webhooksRouter.post('/', 
  zValidator('json', createWebhookSchema),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const data = c.req.valid('json');

      const webhook = await webhookService.createWebhook(
        tenantId,
        data
      );

      // Update metrics
      await redis.incr('metrics:webhooks:total');

      return c.json(webhook, 201);
    } catch (error) {
      logger.error('Failed to create webhook', { error });
      if (error instanceof z.ZodError) {
        throw new HTTPException(400, { 
          message: 'Invalid webhook data',
          cause: error.errors 
        });
      }
      throw new HTTPException(500, { message: 'Failed to create webhook' });
    }
  }
);

// Get webhook by ID
webhooksRouter.get('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const webhookId = c.req.param('id');

    const webhook = await webhookService.getWebhook(
      tenantId,
      webhookId
    );

    if (!webhook) {
      throw new HTTPException(404, { message: 'Webhook not found' });
    }

    return c.json(webhook);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get webhook', { error });
    throw new HTTPException(500, { message: 'Failed to get webhook' });
  }
});

// Update webhook
webhooksRouter.put('/:id',
  zValidator('json', updateWebhookSchema),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const webhookId = c.req.param('id');
      const data = c.req.valid('json');

      const webhook = await webhookService.updateWebhook(
        tenantId,
        webhookId,
        data
      );

      if (!webhook) {
        throw new HTTPException(404, { message: 'Webhook not found' });
      }

      return c.json(webhook);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to update webhook', { error });
      throw new HTTPException(500, { message: 'Failed to update webhook' });
    }
  }
);

// Delete webhook
webhooksRouter.delete('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const webhookId = c.req.param('id');

    await webhookService.deleteWebhook(
      tenantId,
      webhookId
    );

    // Update metrics
    await redis.decr('metrics:webhooks:total');

    return c.json({ success: true });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to delete webhook', { error });
    throw new HTTPException(500, { message: 'Failed to delete webhook' });
  }
});

// Test webhook
webhooksRouter.post('/:id/test',
  zValidator('json', testWebhookSchema.partial()),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const webhookId = c.req.param('id');
      const data = c.req.valid('json');

      const result = await webhookService.testWebhook(
        tenantId,
        webhookId,
        data?.eventType || 'SYSTEM_EVENT',
        data?.payload || { test: true, timestamp: new Date().toISOString() }
      );

      return c.json(result);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to test webhook', { error });
      throw new HTTPException(500, { message: 'Failed to test webhook' });
    }
  }
);

// Get webhook delivery history
webhooksRouter.get('/:id/deliveries', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const webhookId = c.req.param('id');
    
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const status = c.req.query('status');

    const deliveries = await webhookService.getWebhookDeliveries(
      tenantId,
      webhookId,
      {
        page,
        limit,
        status: status as 'SUCCESS' | 'FAILED' | undefined
      }
    );

    return c.json(deliveries);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get webhook deliveries', { error });
    throw new HTTPException(500, { message: 'Failed to get webhook deliveries' });
  }
});

// Retry failed delivery
webhooksRouter.post('/:id/deliveries/:deliveryId/retry', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const webhookId = c.req.param('id');
    const deliveryId = c.req.param('deliveryId');

    const result = await webhookService.retryWebhookDelivery(
      tenantId,
      webhookId,
      deliveryId
    );

    return c.json(result);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to retry webhook delivery', { error });
    throw new HTTPException(500, { message: 'Failed to retry webhook delivery' });
  }
});

// Get webhook statistics
webhooksRouter.get('/:id/stats', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const webhookId = c.req.param('id');
    const period = c.req.query('period') || 'day';

    const stats = await webhookService.getWebhookStats(
      tenantId,
      webhookId,
      period as 'hour' | 'day' | 'week' | 'month'
    );

    return c.json(stats);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get webhook stats', { error });
    throw new HTTPException(500, { message: 'Failed to get webhook stats' });
  }
});

// Regenerate webhook secret
webhooksRouter.post('/:id/regenerate-secret', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const webhookId = c.req.param('id');

    const secret = await webhookService.regenerateWebhookSecret(
      tenantId,
      webhookId
    );

    return c.json({ 
      success: true,
      secret,
      message: 'Webhook secret regenerated successfully'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to regenerate webhook secret', { error });
    throw new HTTPException(500, { message: 'Failed to regenerate webhook secret' });
  }
});

// Webhook event receiver endpoint (for incoming webhooks)
webhooksRouter.post('/receive/:token', async (c) => {
  try {
    const token = c.req.param('token');
    const signature = c.req.header('x-webhook-signature');
    const body = await c.req.text();
    
    // Verify webhook token and signature
    const webhook = await webhookService.verifyIncomingWebhook(token, signature || '', body);
    
    if (!webhook) {
      throw new HTTPException(401, { message: 'Invalid webhook token' });
    }

    // Process incoming webhook
    const payload = JSON.parse(body);
    await webhookService.processIncomingWebhook(webhook.id, payload);

    return c.json({ 
      success: true,
      message: 'Webhook received'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to process incoming webhook', { error });
    throw new HTTPException(500, { message: 'Failed to process webhook' });
  }
});

// Batch operations
webhooksRouter.post('/batch/enable', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const { webhookIds } = await c.req.json();

    if (!Array.isArray(webhookIds)) {
      throw new HTTPException(400, { message: 'webhookIds must be an array' });
    }

    const results = await webhookService.batchUpdateStatus(
      tenantId,
      webhookIds,
      'ACTIVE'
    );

    return c.json(results);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to batch enable webhooks', { error });
    throw new HTTPException(500, { message: 'Failed to batch enable webhooks' });
  }
});

webhooksRouter.post('/batch/disable', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const { webhookIds } = await c.req.json();

    if (!Array.isArray(webhookIds)) {
      throw new HTTPException(400, { message: 'webhookIds must be an array' });
    }

    const results = await webhookService.batchUpdateStatus(
      tenantId,
      webhookIds,
      'INACTIVE'
    );

    return c.json(results);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to batch disable webhooks', { error });
    throw new HTTPException(500, { message: 'Failed to batch disable webhooks' });
  }
});

// Get available event types
webhooksRouter.get('/events/types', async (c) => {
  try {
    const eventTypes = await webhookService.getAvailableEventTypes();
    return c.json(eventTypes);
  } catch (error) {
    logger.error('Failed to get event types', { error });
    throw new HTTPException(500, { message: 'Failed to get event types' });
  }
});

export default webhooksRouter;