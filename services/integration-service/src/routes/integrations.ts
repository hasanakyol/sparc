import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { 
  createIntegrationSchema, 
  updateIntegrationSchema,
  testIntegrationSchema,
  IntegrationType,
  IntegrationStatus
} from '../types';
import { IntegrationService } from '../services/integration.service';
import { z } from 'zod';

const integrationsRouter = new Hono();

// Get service instances from context (will be set by main app)
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const integrationService = new IntegrationService(prisma, redis);

// Apply auth middleware to all routes
integrationsRouter.use('*', authMiddleware);

// List integrations with filtering and pagination
integrationsRouter.get('/', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    
    // Parse query parameters
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const type = c.req.query('type') as IntegrationType | undefined;
    const status = c.req.query('status') as IntegrationStatus | undefined;
    const search = c.req.query('search');

    const response = await integrationService.listIntegrations(tenantId, {
      page,
      limit,
      type,
      status,
      search
    });

    return c.json(response);
  } catch (error) {
    logger.error('Failed to list integrations', { error });
    throw new HTTPException(500, { message: 'Failed to list integrations' });
  }
});

// Create new integration
integrationsRouter.post('/', 
  zValidator('json', createIntegrationSchema),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const userId = c.get('userId') as string;
      const data = c.req.valid('json');

      const integration = await integrationService.createIntegration(
        tenantId,
        userId,
        data
      );

      // Update metrics
      await redis.incr('metrics:integrations:total');

      return c.json(integration, 201);
    } catch (error) {
      logger.error('Failed to create integration', { error });
      if (error instanceof z.ZodError) {
        throw new HTTPException(400, { 
          message: 'Invalid integration data',
          cause: error.errors 
        });
      }
      throw new HTTPException(500, { message: 'Failed to create integration' });
    }
  }
);

// Get integration by ID
integrationsRouter.get('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('id');

    const integration = await integrationService.getIntegration(
      tenantId,
      integrationId
    );

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    return c.json(integration);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get integration', { error });
    throw new HTTPException(500, { message: 'Failed to get integration' });
  }
});

// Update integration
integrationsRouter.put('/:id',
  zValidator('json', updateIntegrationSchema),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const userId = c.get('userId') as string;
      const integrationId = c.req.param('id');
      const data = c.req.valid('json');

      const integration = await integrationService.updateIntegration(
        tenantId,
        userId,
        integrationId,
        data
      );

      if (!integration) {
        throw new HTTPException(404, { message: 'Integration not found' });
      }

      return c.json(integration);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to update integration', { error });
      throw new HTTPException(500, { message: 'Failed to update integration' });
    }
  }
);

// Delete integration
integrationsRouter.delete('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const integrationId = c.req.param('id');

    await integrationService.deleteIntegration(
      tenantId,
      userId,
      integrationId
    );

    // Update metrics
    await redis.decr('metrics:integrations:total');

    return c.json({ success: true });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to delete integration', { error });
    throw new HTTPException(500, { message: 'Failed to delete integration' });
  }
});

// Test integration connection
integrationsRouter.post('/:id/test',
  zValidator('json', testIntegrationSchema.partial()),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const integrationId = c.req.param('id');
      const testData = c.req.valid('json');

      const result = await integrationService.testIntegration(
        tenantId,
        integrationId,
        testData?.testData
      );

      return c.json(result);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to test integration', { error });
      throw new HTTPException(500, { message: 'Failed to test integration' });
    }
  }
);

// Get integration health status
integrationsRouter.get('/:id/health', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('id');

    const health = await integrationService.getIntegrationHealth(
      tenantId,
      integrationId
    );

    return c.json(health);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get integration health', { error });
    throw new HTTPException(500, { message: 'Failed to get integration health' });
  }
});

// Trigger sync for integration
integrationsRouter.post('/:id/sync', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const integrationId = c.req.param('id');
    const body = await c.req.json();

    const jobId = await integrationService.triggerSync(
      tenantId,
      userId,
      integrationId,
      {
        syncType: body.syncType || 'full',
        options: body.options || {}
      }
    );

    return c.json({ 
      success: true,
      jobId,
      message: 'Sync job queued successfully'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to trigger sync', { error });
    throw new HTTPException(500, { message: 'Failed to trigger sync' });
  }
});

// Get integration metrics
integrationsRouter.get('/:id/metrics', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('id');
    const period = c.req.query('period') || 'day';

    const metrics = await integrationService.getIntegrationMetrics(
      tenantId,
      integrationId,
      period as 'hour' | 'day' | 'week' | 'month'
    );

    return c.json(metrics);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get integration metrics', { error });
    throw new HTTPException(500, { message: 'Failed to get integration metrics' });
  }
});

// Get available integration types and their configurations
integrationsRouter.get('/types/available', async (c) => {
  try {
    const types = await integrationService.getAvailableIntegrationTypes();
    return c.json(types);
  } catch (error) {
    logger.error('Failed to get integration types', { error });
    throw new HTTPException(500, { message: 'Failed to get integration types' });
  }
});

// Get data mappings for integration
integrationsRouter.get('/:id/mappings', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('id');

    const mappings = await integrationService.getDataMappings(
      tenantId,
      integrationId
    );

    return c.json(mappings);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get data mappings', { error });
    throw new HTTPException(500, { message: 'Failed to get data mappings' });
  }
});

// Update data mappings for integration
integrationsRouter.put('/:id/mappings', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('id');
    const mappings = await c.req.json();

    const updated = await integrationService.updateDataMappings(
      tenantId,
      integrationId,
      mappings
    );

    return c.json(updated);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to update data mappings', { error });
    throw new HTTPException(500, { message: 'Failed to update data mappings' });
  }
});

export default integrationsRouter;