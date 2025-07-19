import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { z } from 'zod'
import { zValidator } from '@hono/zod-validator'
import {
  initializeService,
  applyTelemetryToHono,
  telemetry,
  createHealthCheckRoute,
  TracedError,
  Trace,
  TraceDB,
  TraceCache,
  TraceService,
  TraceBusiness,
  MeasurePerformance,
  createTracedRedisClient,
  SpanKind,
  SpanStatusCode
} from '@sparc/shared/telemetry'
import { prisma } from '@sparc/shared/database/prisma'
import Redis from 'ioredis'

// Example service demonstrating comprehensive telemetry usage
class ExampleService {
  private redis: any;
  private logger: any;

  constructor(logger: any) {
    this.logger = logger;
    // Create traced Redis client
    const redisClient = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379')
    });
    this.redis = createTracedRedisClient(redisClient);
  }

  // Database operation with tracing
  @TraceDB('select', 'users')
  @MeasurePerformance(100) // Alert if takes more than 100ms
  async getUserById(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      throw new TracedError('User not found', 'USER_NOT_FOUND', { userId });
    }

    return user;
  }

  // Cache operation with tracing
  @TraceCache('get')
  async getCachedUser(userId: string) {
    const cacheKey = `user:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      telemetry.addSpanAttributes({
        'cache.hit': true,
        'cache.key': cacheKey
      });
      return JSON.parse(cached);
    }

    telemetry.addSpanAttributes({
      'cache.hit': false,
      'cache.key': cacheKey
    });
    return null;
  }

  // Service-to-service call with tracing
  @TraceService('auth-service', 'validateToken')
  async validateToken(token: string) {
    const response = await fetch('http://auth-service:3001/validate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...telemetry.injectTraceContext()
      },
      body: JSON.stringify({ token })
    });

    if (!response.ok) {
      throw new TracedError('Token validation failed', 'INVALID_TOKEN');
    }

    return response.json();
  }

  // Business logic with custom tracing
  @TraceBusiness('user-management', 'getOrCreateUser')
  async getOrCreateUser(userData: any) {
    // Check cache first
    const cached = await this.getCachedUser(userData.id);
    if (cached) {
      this.logger.info('User found in cache', { userId: userData.id });
      return cached;
    }

    // Check database
    let user = await this.getUserById(userData.id).catch(() => null);
    
    if (!user) {
      // Create new user with detailed tracing
      user = await telemetry.withSpan(
        'user.create',
        async (span) => {
          span.setAttributes({
            'user.email': userData.email,
            'user.role': userData.role,
            'user.tenant': userData.tenantId
          });

          const newUser = await prisma.user.create({
            data: userData
          });

          // Cache the new user
          await this.redis.set(
            `user:${newUser.id}`,
            JSON.stringify(newUser),
            'EX',
            3600
          );

          // Log security event
          this.logger.logSecurity('user_created', 'low', {
            userId: newUser.id,
            email: newUser.email,
            createdBy: 'system'
          });

          return newUser;
        },
        { kind: SpanKind.INTERNAL }
      );
    }

    return user;
  }

  // Complex operation with manual span management
  async processUserBatch(userIds: string[]) {
    const span = telemetry.startSpan('batch.process_users', {
      kind: SpanKind.INTERNAL,
      attributes: {
        'batch.size': userIds.length
      }
    });

    try {
      const results = await Promise.allSettled(
        userIds.map(async (userId) => {
          // Create child span for each user
          return telemetry.withSpan(
            'batch.process_single_user',
            async (childSpan) => {
              childSpan.setAttribute('user.id', userId);
              
              try {
                const user = await this.getOrCreateUser({ id: userId });
                childSpan.setStatus({ code: SpanStatusCode.OK });
                return { userId, status: 'success', user };
              } catch (error) {
                childSpan.recordException(error as Error);
                childSpan.setStatus({
                  code: SpanStatusCode.ERROR,
                  message: error instanceof Error ? error.message : 'Unknown error'
                });
                return { userId, status: 'error', error };
              }
            },
            { parent: span }
          );
        })
      );

      // Analyze results
      const succeeded = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      span.setAttributes({
        'batch.succeeded': succeeded,
        'batch.failed': failed,
        'batch.success_rate': succeeded / userIds.length
      });

      if (failed > 0) {
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: `${failed} users failed to process`
        });
      } else {
        span.setStatus({ code: SpanStatusCode.OK });
      }

      return results;
    } catch (error) {
      span.recordException(error as Error);
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: 'Batch processing failed'
      });
      throw error;
    } finally {
      span.end();
    }
  }
}

// Initialize service
async function startService() {
  const { logger, shutdown } = await initializeService({
    serviceName: 'example-telemetry-service',
    serviceVersion: '1.0.0',
    customAttributes: {
      'service.type': 'example',
      'service.framework': 'hono'
    }
  });

  const app = new Hono();
  const service = new ExampleService(logger);

  // Apply telemetry middleware
  applyTelemetryToHono(app, 'example-telemetry-service');

  // Example endpoints demonstrating different tracing patterns
  
  // Simple endpoint with automatic tracing
  app.get('/api/users/:id', async (c) => {
    const userId = c.req.param('id');
    const user = await service.getOrCreateUser({ id: userId });
    return c.json(user);
  });

  // Endpoint with custom business logic tracing
  app.post('/api/users/batch', 
    zValidator('json', z.object({ userIds: z.array(z.string()) })),
    async (c) => {
      const { userIds } = c.req.valid('json');
      
      // Add custom attributes to the current span
      telemetry.addSpanAttributes({
        'request.batch_size': userIds.length,
        'request.tenant': c.get('tenantId')
      });

      const results = await service.processUserBatch(userIds);
      
      // Log performance metrics
      logger.logPerformance('batch_processing', Date.now() - c.get('startTime'), {
        batchSize: userIds.length,
        succeeded: results.filter(r => r.status === 'fulfilled').length
      });

      return c.json(results);
    }
  );

  // Endpoint demonstrating error handling with traces
  app.get('/api/error-example', async (c) => {
    return telemetry.withSpan(
      'error.example',
      async (span) => {
        span.setAttribute('example.type', 'deliberate_error');
        
        // Simulate different error scenarios
        const errorType = c.req.query('type') || 'traced';
        
        switch (errorType) {
          case 'traced':
            throw new TracedError('This is a traced error example', 'EXAMPLE_ERROR', {
              query: c.req.query()
            });
          
          case 'validation':
            span.setStatus({
              code: SpanStatusCode.ERROR,
              message: 'Validation failed'
            });
            return c.json({ error: 'Validation failed' }, 400);
          
          case 'timeout':
            await new Promise(resolve => setTimeout(resolve, 5000));
            throw new Error('Operation timed out');
          
          default:
            throw new Error('Unknown error type');
        }
      }
    );
  });

  // Health check with custom checks
  createHealthCheckRoute(app, 'example-telemetry-service', {
    database: async () => {
      try {
        await prisma.$queryRaw`SELECT 1`;
        return true;
      } catch {
        return false;
      }
    },
    redis: async () => {
      try {
        await service.redis.ping();
        return true;
      } catch {
        return false;
      }
    },
    tracing: async () => {
      // Check if we can create spans
      const testSpan = telemetry.startSpan('health.tracing_test');
      testSpan.end();
      return true;
    }
  });

  // Metrics endpoint with trace information
  app.get('/metrics', async (c) => {
    const metrics = {
      service: 'example-telemetry-service',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      tracing: {
        enabled: true,
        traceId: telemetry.getCurrentTraceId(),
        spanId: telemetry.getCurrentSpanId()
      }
    };

    return c.json(metrics);
  });

  // Start server
  const port = parseInt(process.env.PORT || '3000');
  
  serve({
    fetch: app.fetch,
    port
  }, (info) => {
    logger.info('Example telemetry service started', {
      port: info.port,
      tracing: {
        enabled: true,
        endpoint: process.env.JAEGER_ENDPOINT
      }
    });
  });

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    logger.info('Shutting down...');
    await shutdown();
    process.exit(0);
  });

  return { app, service, logger };
}

// Start the service
if (require.main === module) {
  startService().catch((error) => {
    console.error('Failed to start service:', error);
    process.exit(1);
  });
}

export { startService };