import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { prettyJSON } from 'hono/pretty-json'
import { secureHeaders } from 'hono/secure-headers'
import { 
  telemetry, 
  telemetryMiddleware, 
  initializeService, 
  applyTelemetryToHono,
  createHealthCheckRoute,
  TraceLogger,
  correlationMiddleware,
  TracedError,
  SpanKind,
  SpanStatusCode
} from '@sparc/shared/telemetry'
import { authMiddleware } from '@sparc/shared/middleware/auth'
import { rateLimitMiddleware } from '@sparc/shared/middleware/rate-limit'
import { errorHandler } from '@sparc/shared/middleware/error-handler'
import { siemMiddleware } from './middleware/siem'
import proxyRoutes from './routes/proxy'

// Service initialization with telemetry
async function startService() {
  // Initialize telemetry
  const { logger, shutdown } = await initializeService({
    serviceName: 'api-gateway',
    serviceVersion: process.env.SERVICE_VERSION || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    jaegerEndpoint: process.env.JAEGER_ENDPOINT || 'http://jaeger-collector.observability.svc.cluster.local:4317',
    samplingRatio: parseFloat(process.env.TRACE_SAMPLING_RATIO || '0.1'),
    customAttributes: {
      'service.type': 'gateway',
      'service.tier': 'edge',
      'deployment.region': process.env.AWS_REGION || 'us-east-1'
    }
  });

  // Create Hono app
  const app = new Hono();

  // Apply telemetry middleware
  applyTelemetryToHono(app, 'api-gateway');

  // Add correlation middleware
  app.use('*', correlationMiddleware());

  // Security headers
  app.use('*', secureHeaders());

  // CORS configuration with tracing
  app.use('*', async (c, next) => {
    return telemetry.withSpan(
      'cors.check',
      async (span) => {
        span.setAttributes({
          'http.origin': c.req.header('origin') || 'none',
          'http.method': c.req.method
        });
        
        const corsMiddleware = cors({
          origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3003'],
          credentials: true,
          allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
          allowHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Trace-ID', 'X-Correlation-ID'],
          exposeHeaders: ['X-Request-ID', 'X-Trace-ID', 'X-Correlation-ID'],
          maxAge: 86400
        });
        
        return corsMiddleware(c, next);
      },
      { kind: SpanKind.INTERNAL }
    );
  });

  // Pretty JSON responses
  app.use('*', prettyJSON());

  // Request logging with trace context
  app.use('*', async (c, next) => {
    const start = Date.now();
    const requestId = c.get('correlationId');
    
    logger.logRequest(c.req, {
      requestId,
      traceId: telemetry.getCurrentTraceId()
    });

    await next();

    const duration = Date.now() - start;
    logger.logResponse(c.req, c.res, duration, {
      requestId,
      traceId: telemetry.getCurrentTraceId()
    });

    // Add performance metrics to span
    telemetry.addSpanAttributes({
      'http.request.duration': duration,
      'http.response.size': c.res.headers.get('content-length') || 0
    });
  });

  // Authentication with tracing
  app.use('*', async (c, next) => {
    // Skip auth for health checks and public endpoints
    const publicPaths = ['/health', '/metrics', '/docs', '/openapi.json'];
    if (publicPaths.some(path => c.req.path.startsWith(path))) {
      return next();
    }

    return telemetry.withSpan(
      'auth.verify',
      async (span) => {
        try {
          await authMiddleware()(c, next);
          
          const userId = c.get('userId');
          const tenantId = c.get('tenantId');
          
          span.setAttributes({
            'user.id': userId,
            'tenant.id': tenantId,
            'auth.method': 'jwt'
          });
          
        } catch (error) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: 'Authentication failed'
          });
          throw TracedError.from(error, 'AUTH_FAILED');
        }
      },
      { kind: SpanKind.INTERNAL }
    );
  });

  // Rate limiting with tracing
  app.use('*', async (c, next) => {
    return telemetry.withSpan(
      'ratelimit.check',
      async (span) => {
        const tenantId = c.get('tenantId') || 'anonymous';
        
        span.setAttributes({
          'ratelimit.tenant': tenantId,
          'ratelimit.path': c.req.path
        });

        try {
          await rateLimitMiddleware({
            points: 100,
            duration: 60,
            keyPrefix: 'api'
          })(c, next);
        } catch (error) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: 'Rate limit exceeded'
          });
          
          logger.logSecurity('rate_limit_exceeded', 'high', {
            tenantId,
            path: c.req.path,
            ip: c.req.header('x-forwarded-for') || c.req.header('x-real-ip')
          });
          
          throw error;
        }
      },
      { kind: SpanKind.INTERNAL }
    );
  });

  // SIEM middleware with tracing
  app.use('*', siemMiddleware());

  // Apply proxy routes with tracing
  app.route('/', proxyRoutes);

  // Health check with tracing
  createHealthCheckRoute(app, 'api-gateway', {
    redis: async () => {
      try {
        const redis = new (await import('ioredis')).default({
          host: process.env.REDIS_HOST || 'localhost',
          port: parseInt(process.env.REDIS_PORT || '6379')
        });
        await redis.ping();
        redis.disconnect();
        return true;
      } catch {
        return false;
      }
    },
    services: async () => {
      // Check if critical services are reachable
      const criticalServices = ['auth-service', 'tenant-service'];
      try {
        const results = await Promise.all(
          criticalServices.map(async (service) => {
            const url = `http://${service}:3000/health`;
            const response = await fetch(url, { 
              signal: AbortSignal.timeout(5000),
              headers: telemetry.injectTraceContext()
            });
            return response.ok;
          })
        );
        return results.every(r => r);
      } catch {
        return false;
      }
    }
  });

  // Metrics endpoint
  app.get('/metrics', async (c) => {
    // OpenTelemetry metrics are exposed by the SDK
    // This endpoint can be used for custom business metrics
    return c.json({
      service: 'api-gateway',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      traceId: telemetry.getCurrentTraceId()
    });
  });

  // Error handling with trace context
  app.onError(async (err, c) => {
    const error = TracedError.from(err);
    
    logger.error('Unhandled error in API Gateway', error);
    
    return c.json({
      error: {
        message: error.message,
        code: error.code || 'INTERNAL_ERROR',
        traceId: error.traceId,
        requestId: c.get('correlationId')
      }
    }, err instanceof HTTPException ? err.status : 500);
  });

  // 404 handler with tracing
  app.notFound((c) => {
    telemetry.addSpanAttributes({
      'http.route': 'not_found',
      'http.path': c.req.path
    });
    
    logger.warn('Route not found', {
      path: c.req.path,
      method: c.req.method
    });
    
    return c.json({
      error: {
        message: 'Route not found',
        code: 'NOT_FOUND',
        traceId: telemetry.getCurrentTraceId(),
        requestId: c.get('correlationId')
      }
    }, 404);
  });

  // Start server
  const port = parseInt(process.env.PORT || '3000');
  
  serve({
    fetch: app.fetch,
    port
  }, (info) => {
    logger.info(`API Gateway started`, {
      port: info.port,
      address: info.address,
      family: info.family,
      environment: process.env.NODE_ENV,
      tracing: {
        enabled: true,
        endpoint: process.env.JAEGER_ENDPOINT
      }
    });
  });

  // Graceful shutdown handling
  process.on('SIGTERM', async () => {
    logger.info('SIGTERM received, shutting down gracefully...');
    await shutdown();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    logger.info('SIGINT received, shutting down gracefully...');
    await shutdown();
    process.exit(0);
  });

  // Export for testing
  return { app, logger, shutdown };
}

// Start the service
if (require.main === module) {
  startService().catch((error) => {
    console.error('Failed to start API Gateway:', error);
    process.exit(1);
  });
}

export { startService };