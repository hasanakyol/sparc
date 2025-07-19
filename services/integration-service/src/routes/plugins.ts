import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { 
  createPluginInstanceSchema, 
  updatePluginInstanceSchema,
  pluginExecutionContextSchema,
  PluginStatus,
  PluginType
} from '../types';
import { PluginService } from '../services/plugin.service';
import { z } from 'zod';

const pluginsRouter = new Hono();

// Get service instances
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const pluginService = new PluginService(prisma, redis);

// Apply auth middleware to all routes
pluginsRouter.use('*', authMiddleware);

// List installed plugins
pluginsRouter.get('/', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    
    // Parse query parameters
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const status = c.req.query('status') as PluginStatus | undefined;
    const type = c.req.query('type') as PluginType | undefined;
    const search = c.req.query('search');

    const response = await pluginService.listInstalledPlugins(tenantId, {
      page,
      limit,
      status,
      type,
      search
    });

    return c.json(response);
  } catch (error) {
    logger.error('Failed to list plugins', { error });
    throw new HTTPException(500, { message: 'Failed to list plugins' });
  }
});

// Install new plugin instance
pluginsRouter.post('/', 
  zValidator('json', createPluginInstanceSchema),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const userId = c.get('userId') as string;
      const data = c.req.valid('json');

      const instance = await pluginService.installPlugin(
        tenantId,
        userId,
        data
      );

      // Update metrics
      await redis.incr('metrics:plugins:total');

      return c.json(instance, 201);
    } catch (error) {
      logger.error('Failed to install plugin', { error });
      if (error instanceof z.ZodError) {
        throw new HTTPException(400, { 
          message: 'Invalid plugin data',
          cause: error.errors 
        });
      }
      throw new HTTPException(500, { message: 'Failed to install plugin' });
    }
  }
);

// Get plugin instance by ID
pluginsRouter.get('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');

    const instance = await pluginService.getPluginInstance(
      tenantId,
      instanceId
    );

    if (!instance) {
      throw new HTTPException(404, { message: 'Plugin instance not found' });
    }

    return c.json(instance);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get plugin instance', { error });
    throw new HTTPException(500, { message: 'Failed to get plugin instance' });
  }
});

// Update plugin instance
pluginsRouter.put('/:id',
  zValidator('json', updatePluginInstanceSchema),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const instanceId = c.req.param('id');
      const data = c.req.valid('json');

      const instance = await pluginService.updatePluginInstance(
        tenantId,
        instanceId,
        data
      );

      if (!instance) {
        throw new HTTPException(404, { message: 'Plugin instance not found' });
      }

      return c.json(instance);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to update plugin instance', { error });
      throw new HTTPException(500, { message: 'Failed to update plugin instance' });
    }
  }
);

// Uninstall plugin instance
pluginsRouter.delete('/:id', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const instanceId = c.req.param('id');

    await pluginService.uninstallPlugin(
      tenantId,
      userId,
      instanceId
    );

    // Update metrics
    await redis.decr('metrics:plugins:total');

    return c.json({ success: true });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to uninstall plugin', { error });
    throw new HTTPException(500, { message: 'Failed to uninstall plugin' });
  }
});

// Execute plugin
pluginsRouter.post('/:id/execute',
  zValidator('json', pluginExecutionContextSchema.pick({
    input: true,
    metadata: true
  })),
  async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const userId = c.get('userId') as string;
      const instanceId = c.req.param('id');
      const data = c.req.valid('json');

      const context = {
        tenantId,
        userId,
        requestId: c.get('requestId') as string,
        instanceId,
        input: data.input,
        configuration: {}, // Will be loaded from instance
        metadata: data.metadata || {}
      };

      const result = await pluginService.executePlugin(context);

      // Update metrics
      await redis.incr('metrics:plugin:executions:total');

      return c.json(result);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to execute plugin', { error });
      throw new HTTPException(500, { message: 'Failed to execute plugin' });
    }
  }
);

// Activate plugin
pluginsRouter.post('/:id/activate', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');

    await pluginService.activatePlugin(
      tenantId,
      instanceId
    );

    return c.json({ 
      success: true,
      message: 'Plugin activated successfully'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to activate plugin', { error });
    throw new HTTPException(500, { message: 'Failed to activate plugin' });
  }
});

// Deactivate plugin
pluginsRouter.post('/:id/deactivate', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');

    await pluginService.deactivatePlugin(
      tenantId,
      instanceId
    );

    return c.json({ 
      success: true,
      message: 'Plugin deactivated successfully'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to deactivate plugin', { error });
    throw new HTTPException(500, { message: 'Failed to deactivate plugin' });
  }
});

// Get plugin configuration schema
pluginsRouter.get('/:id/config-schema', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');

    const schema = await pluginService.getPluginConfigSchema(
      tenantId,
      instanceId
    );

    return c.json(schema);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get plugin config schema', { error });
    throw new HTTPException(500, { message: 'Failed to get plugin config schema' });
  }
});

// Validate plugin configuration
pluginsRouter.post('/:id/validate-config', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');
    const config = await c.req.json();

    const result = await pluginService.validatePluginConfig(
      tenantId,
      instanceId,
      config
    );

    return c.json(result);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to validate plugin config', { error });
    throw new HTTPException(500, { message: 'Failed to validate plugin config' });
  }
});

// Get plugin execution history
pluginsRouter.get('/:id/executions', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');
    
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const status = c.req.query('status');

    const executions = await pluginService.getPluginExecutions(
      tenantId,
      instanceId,
      {
        page,
        limit,
        status: status as 'SUCCESS' | 'FAILED' | undefined
      }
    );

    return c.json(executions);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get plugin executions', { error });
    throw new HTTPException(500, { message: 'Failed to get plugin executions' });
  }
});

// Get plugin metrics
pluginsRouter.get('/:id/metrics', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');
    const period = c.req.query('period') || 'day';

    const metrics = await pluginService.getPluginMetrics(
      tenantId,
      instanceId,
      period as 'hour' | 'day' | 'week' | 'month'
    );

    return c.json(metrics);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get plugin metrics', { error });
    throw new HTTPException(500, { message: 'Failed to get plugin metrics' });
  }
});

// Reset plugin state
pluginsRouter.post('/:id/reset', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');

    await pluginService.resetPluginState(
      tenantId,
      instanceId
    );

    return c.json({ 
      success: true,
      message: 'Plugin state reset successfully'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to reset plugin state', { error });
    throw new HTTPException(500, { message: 'Failed to reset plugin state' });
  }
});

// Get plugin logs
pluginsRouter.get('/:id/logs', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const instanceId = c.req.param('id');
    
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '100', 10);
    const level = c.req.query('level');
    const startTime = c.req.query('startTime');
    const endTime = c.req.query('endTime');

    const logs = await pluginService.getPluginLogs(
      tenantId,
      instanceId,
      {
        page,
        limit,
        level: level as 'debug' | 'info' | 'warn' | 'error' | undefined,
        startTime: startTime ? new Date(startTime) : undefined,
        endTime: endTime ? new Date(endTime) : undefined
      }
    );

    return c.json(logs);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get plugin logs', { error });
    throw new HTTPException(500, { message: 'Failed to get plugin logs' });
  }
});

export default pluginsRouter;