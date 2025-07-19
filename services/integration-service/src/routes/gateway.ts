import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { GatewayService } from '../services/gateway.service';
import { QuotaService } from '../services/quota.service';
import { TransformationService } from '../services/transformation.service';
import { z } from 'zod';
import { RateLimiterRedis } from 'rate-limiter-flexible';

const gatewayRouter = new Hono();

// Get service instances
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const gatewayService = new GatewayService(prisma, redis);
const quotaService = new QuotaService(prisma, redis);
const transformationService = new TransformationService();

// Rate limiter for API gateway
const rateLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'gateway_rate_limit',
  points: 100, // Number of requests
  duration: 60, // Per minute
  blockDuration: 60, // Block for 1 minute
});

// Apply auth middleware to all routes
gatewayRouter.use('*', authMiddleware);

// Custom rate limiting middleware for gateway
gatewayRouter.use('*', async (c, next) => {
  const tenantId = c.get('tenantId') as string;
  const path = c.req.path;
  
  try {
    // Check rate limit
    await rateLimiter.consume(`${tenantId}:${path}`);
    
    // Check quota
    const quotaCheck = await quotaService.checkQuota(tenantId, 'api_calls');
    if (!quotaCheck.allowed) {
      throw new HTTPException(429, { 
        message: 'API quota exceeded',
        quotaInfo: quotaCheck
      });
    }
    
    await next();
    
    // Increment quota usage after successful request
    await quotaService.incrementUsage(tenantId, 'api_calls', 1);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    if (error?.remainingPoints === 0) {
      throw new HTTPException(429, { 
        message: 'Rate limit exceeded',
        retryAfter: error.msBeforeNext / 1000
      });
    }
    throw error;
  }
});

// Proxy request to external API
gatewayRouter.all('/:integrationId/*', async (c) => {
  const startTime = Date.now();
  
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const integrationId = c.req.param('integrationId');
    const path = c.req.path.replace(`/api/gateway/${integrationId}`, '');
    
    // Get integration details
    const integration = await gatewayService.getIntegration(tenantId, integrationId);
    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }
    
    if (integration.status !== 'ACTIVE') {
      throw new HTTPException(503, { message: 'Integration is not active' });
    }
    
    // Check integration-specific rate limit
    const integrationRateLimit = integration.configuration?.rateLimit;
    if (integrationRateLimit) {
      const limiter = new RateLimiterRedis({
        storeClient: redis,
        keyPrefix: `integration_rate_limit:${integrationId}`,
        points: integrationRateLimit.requests,
        duration: integrationRateLimit.window,
      });
      
      try {
        await limiter.consume(tenantId);
      } catch (error) {
        throw new HTTPException(429, { 
          message: 'Integration rate limit exceeded',
          retryAfter: error.msBeforeNext / 1000
        });
      }
    }
    
    // Prepare request
    const method = c.req.method;
    const headers = Object.fromEntries(c.req.raw.headers.entries());
    const body = method !== 'GET' && method !== 'HEAD' ? await c.req.text() : undefined;
    
    // Apply request transformation if configured
    let transformedRequest = {
      path,
      method,
      headers,
      body
    };
    
    if (integration.configuration?.requestTransform) {
      transformedRequest = await transformationService.transformRequest(
        transformedRequest,
        integration.configuration.requestTransform
      );
    }
    
    // Make the request
    const response = await gatewayService.proxyRequest(
      integration,
      transformedRequest.path,
      {
        method: transformedRequest.method,
        headers: transformedRequest.headers,
        body: transformedRequest.body
      }
    );
    
    // Apply response transformation if configured
    let transformedResponse = response;
    if (integration.configuration?.responseTransform) {
      transformedResponse = await transformationService.transformResponse(
        response,
        integration.configuration.responseTransform
      );
    }
    
    // Log the request
    const duration = Date.now() - startTime;
    await gatewayService.logRequest({
      tenantId,
      userId,
      integrationId,
      path,
      method,
      statusCode: transformedResponse.status,
      duration,
      requestSize: transformedRequest.body?.length || 0,
      responseSize: transformedResponse.body?.length || 0
    });
    
    // Update metrics
    await redis.incr('metrics:gateway:requests:total');
    await redis.hincrby('metrics:gateway:requests:by_integration', integrationId, 1);
    await redis.hincrby('metrics:gateway:requests:by_status', transformedResponse.status.toString(), 1);
    
    // Return the response
    const responseHeaders: Record<string, string> = {};
    transformedResponse.headers.forEach((value: string, key: string) => {
      // Skip certain headers that shouldn't be forwarded
      if (!['content-encoding', 'content-length', 'transfer-encoding'].includes(key.toLowerCase())) {
        responseHeaders[key] = value;
      }
    });
    
    return new Response(transformedResponse.body, {
      status: transformedResponse.status,
      statusText: transformedResponse.statusText,
      headers: responseHeaders
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    // Log error
    logger.error('Gateway request failed', { 
      error,
      duration,
      path: c.req.path 
    });
    
    // Update error metrics
    await redis.incr('metrics:gateway:requests:errors');
    
    if (error instanceof HTTPException) throw error;
    
    throw new HTTPException(502, { 
      message: 'Bad gateway',
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Get gateway statistics
gatewayRouter.get('/stats', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const period = c.req.query('period') || 'day';
    
    const stats = await gatewayService.getGatewayStats(
      tenantId,
      period as 'hour' | 'day' | 'week' | 'month'
    );
    
    return c.json(stats);
  } catch (error) {
    logger.error('Failed to get gateway stats', { error });
    throw new HTTPException(500, { message: 'Failed to get gateway stats' });
  }
});

// Get gateway logs
gatewayRouter.get('/logs', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '50', 10);
    const integrationId = c.req.query('integrationId');
    const statusCode = c.req.query('statusCode');
    const startTime = c.req.query('startTime');
    const endTime = c.req.query('endTime');
    
    const logs = await gatewayService.getGatewayLogs(tenantId, {
      page,
      limit,
      integrationId,
      statusCode: statusCode ? parseInt(statusCode, 10) : undefined,
      startTime: startTime ? new Date(startTime) : undefined,
      endTime: endTime ? new Date(endTime) : undefined
    });
    
    return c.json(logs);
  } catch (error) {
    logger.error('Failed to get gateway logs', { error });
    throw new HTTPException(500, { message: 'Failed to get gateway logs' });
  }
});

// Get quota information
gatewayRouter.get('/quota', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    
    const quotaInfo = await quotaService.getQuotaInfo(tenantId);
    
    return c.json(quotaInfo);
  } catch (error) {
    logger.error('Failed to get quota info', { error });
    throw new HTTPException(500, { message: 'Failed to get quota info' });
  }
});

// Configure gateway settings for integration
gatewayRouter.put('/config/:integrationId', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('integrationId');
    const body = await c.req.json();
    
    const schema = z.object({
      rateLimit: z.object({
        requests: z.number().min(1),
        window: z.number().min(1)
      }).optional(),
      requestTransform: z.object({
        headers: z.record(z.string()).optional(),
        queryParams: z.record(z.string()).optional(),
        bodyMapping: z.array(z.object({
          source: z.string(),
          target: z.string(),
          transform: z.string().optional()
        })).optional()
      }).optional(),
      responseTransform: z.object({
        headers: z.record(z.string()).optional(),
        bodyMapping: z.array(z.object({
          source: z.string(),
          target: z.string(),
          transform: z.string().optional()
        })).optional()
      }).optional(),
      retry: z.object({
        maxAttempts: z.number().min(0).max(5),
        backoffMultiplier: z.number().min(1).max(5),
        initialDelay: z.number().min(100).max(5000)
      }).optional(),
      timeout: z.number().min(1000).max(60000).optional(),
      cache: z.object({
        enabled: z.boolean(),
        ttl: z.number().min(1).max(3600),
        keyPattern: z.string().optional()
      }).optional()
    });
    
    const config = schema.parse(body);
    
    const updated = await gatewayService.updateGatewayConfig(
      tenantId,
      integrationId,
      config
    );
    
    return c.json(updated);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { 
        message: 'Invalid configuration',
        cause: error.errors 
      });
    }
    logger.error('Failed to update gateway config', { error });
    throw new HTTPException(500, { message: 'Failed to update gateway config' });
  }
});

// Clear gateway cache
gatewayRouter.post('/cache/clear', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const body = await c.req.json();
    
    const schema = z.object({
      integrationId: z.string().uuid().optional(),
      pattern: z.string().optional()
    });
    
    const data = schema.parse(body);
    
    await gatewayService.clearCache(tenantId, data.integrationId, data.pattern);
    
    return c.json({ 
      success: true,
      message: 'Cache cleared successfully'
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { 
        message: 'Invalid request',
        cause: error.errors 
      });
    }
    logger.error('Failed to clear cache', { error });
    throw new HTTPException(500, { message: 'Failed to clear cache' });
  }
});

export default gatewayRouter;