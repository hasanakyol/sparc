import { telemetry, telemetryMiddleware, injectTraceContext, SpanKind, SpanStatusCode } from './index';
import { createTraceLogger, TraceLogger } from './trace-logger';
import { Hono } from 'hono';

export interface ServiceInitOptions {
  serviceName: string;
  serviceVersion?: string;
  environment?: string;
  jaegerEndpoint?: string;
  samplingRatio?: number;
  enableConsoleExporter?: boolean;
  customAttributes?: Record<string, string>;
}

export interface ServiceContext {
  logger: TraceLogger;
  shutdown: () => Promise<void>;
}

/**
 * Initialize telemetry for a microservice
 */
export async function initializeService(options: ServiceInitOptions): Promise<ServiceContext> {
  const {
    serviceName,
    serviceVersion = process.env.SERVICE_VERSION || '1.0.0',
    environment = process.env.NODE_ENV || 'development',
    jaegerEndpoint = process.env.JAEGER_ENDPOINT || 'http://jaeger-collector.observability.svc.cluster.local:4317',
    samplingRatio,
    enableConsoleExporter,
    customAttributes = {}
  } = options;

  // Initialize telemetry
  await telemetry.initialize({
    serviceName,
    serviceVersion,
    environment,
    jaegerEndpoint,
    samplingRatio,
    enableConsoleExporter,
    customAttributes: {
      'service.namespace': 'sparc',
      'deployment.environment': environment,
      'k8s.namespace': process.env.K8S_NAMESPACE || 'default',
      'k8s.pod.name': process.env.HOSTNAME || 'unknown',
      'k8s.node.name': process.env.K8S_NODE_NAME || 'unknown',
      ...customAttributes
    }
  });

  // Create trace-enabled logger
  const logger = createTraceLogger(serviceName);

  // Log service startup
  logger.info(`${serviceName} initialized with OpenTelemetry`, {
    version: serviceVersion,
    environment,
    tracing: {
      enabled: true,
      endpoint: jaegerEndpoint,
      samplingRatio: samplingRatio || (environment === 'production' ? 0.1 : 1.0)
    }
  });

  // Setup graceful shutdown
  const shutdown = async () => {
    logger.info(`Shutting down ${serviceName}...`);
    await telemetry.shutdown();
  };

  // Handle process signals
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);

  return {
    logger,
    shutdown
  };
}

/**
 * Apply telemetry middleware to Hono app
 */
export function applyTelemetryToHono(app: Hono, serviceName: string): Hono {
  // Add telemetry middleware
  app.use('*', telemetryMiddleware());

  // Add request ID propagation
  app.use('*', async (c, next) => {
    const requestId = c.req.header('x-request-id') || `${serviceName}-${Date.now()}`;
    c.set('requestId', requestId);
    
    telemetry.addSpanAttributes({
      'request.id': requestId,
      'service.name': serviceName
    });

    await next();
    
    c.header('x-request-id', requestId);
  });

  // Add tenant context to traces
  app.use('*', async (c, next) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    if (tenantId) {
      telemetry.addSpanAttributes({
        'tenant.id': tenantId,
        'user.id': userId
      });
    }
    
    await next();
  });

  return app;
}

/**
 * Wrap service calls with distributed tracing
 */
export function createTracedServiceClient<T>(
  serviceName: string,
  baseUrl: string,
  methods: string[]
): T {
  const client: any = {};

  methods.forEach(method => {
    client[method] = async (data: any) => {
      return telemetry.withSpan(
        `call.${serviceName}.${method}`,
        async (span) => {
          span.setAttributes({
            'rpc.system': 'http',
            'rpc.service': serviceName,
            'rpc.method': method,
            'net.peer.name': baseUrl
          });

          const headers = {
            'Content-Type': 'application/json',
            ...injectTraceContext()
          };

          const response = await fetch(`${baseUrl}/${method}`, {
            method: 'POST',
            headers,
            body: JSON.stringify(data)
          });

          span.setAttributes({
            'http.status_code': response.status,
            'http.response_content_length': response.headers.get('content-length') || 0
          });

          if (!response.ok) {
            span.setStatus({
              code: SpanStatusCode.ERROR,
              message: `HTTP ${response.status}`
            });
            throw new Error(`Service call failed: ${response.statusText}`);
          }

          return response.json();
        },
        {
          kind: SpanKind.CLIENT
        }
      );
    };
  });

  return client as T;
}

/**
 * Create a traced Redis client
 */
export function createTracedRedisClient(redis: any): any {
  const tracedMethods = ['get', 'set', 'del', 'exists', 'expire', 'ttl', 'mget', 'mset'];
  
  const proxy = new Proxy(redis, {
    get(target, prop) {
      if (tracedMethods.includes(prop as string)) {
        return async (...args: any[]) => {
          return telemetry.withSpan(
            `redis.${prop}`,
            async (span) => {
              span.setAttributes({
                'db.system': 'redis',
                'db.operation': prop as string,
                'db.redis.database_index': 0
              });

              if (args[0]) {
                span.setAttribute('db.redis.key', args[0]);
              }

              return target[prop](...args);
            },
            {
              kind: SpanKind.CLIENT
            }
          );
        };
      }
      return target[prop];
    }
  });

  return proxy;
}

/**
 * Health check endpoint with tracing
 */
export function createHealthCheckRoute(app: Hono, serviceName: string, checks: Record<string, () => Promise<boolean>>) {
  app.get('/health', async (c) => {
    return telemetry.withSpan(
      'health.check',
      async (span) => {
        const results: Record<string, boolean> = {};
        let allHealthy = true;

        for (const [name, check] of Object.entries(checks)) {
          try {
            const healthy = await check();
            results[name] = healthy;
            span.setAttribute(`health.${name}`, healthy);
            
            if (!healthy) {
              allHealthy = false;
            }
          } catch (error) {
            results[name] = false;
            allHealthy = false;
            span.setAttribute(`health.${name}`, false);
            span.setAttribute(`health.${name}.error`, error.message);
          }
        }

        span.setAttribute('health.overall', allHealthy);

        const status = allHealthy ? 200 : 503;
        return c.json({
          service: serviceName,
          status: allHealthy ? 'healthy' : 'unhealthy',
          checks: results,
          timestamp: new Date().toISOString(),
          traceId: telemetry.getCurrentTraceId()
        }, status);
      },
      {
        kind: SpanKind.INTERNAL,
        attributes: {
          'health.service': serviceName
        }
      }
    );
  });
}