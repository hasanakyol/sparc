import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import httpProxy from 'http-proxy-middleware'
import { 
  telemetry, 
  injectTraceContext,
  SpanKind,
  SpanStatusCode,
  TracedError,
  createTraceLogger
} from '@sparc/shared/telemetry'

const logger = createTraceLogger('api-gateway-proxy');

// Service registry with health checks
interface ServiceEndpoint {
  name: string;
  url: string;
  healthPath: string;
  timeout: number;
  circuitBreaker?: {
    failureThreshold: number;
    resetTimeout: number;
    halfOpenRequests: number;
  };
}

const serviceRegistry: Record<string, ServiceEndpoint> = {
  'auth': {
    name: 'auth-service',
    url: process.env.AUTH_SERVICE_URL || 'http://auth-service:3001',
    healthPath: '/health',
    timeout: 10000,
    circuitBreaker: {
      failureThreshold: 5,
      resetTimeout: 60000,
      halfOpenRequests: 3
    }
  },
  'users': {
    name: 'user-management-service',
    url: process.env.USER_SERVICE_URL || 'http://user-management-service:3002',
    healthPath: '/health',
    timeout: 10000
  },
  'video': {
    name: 'video-management-service',
    url: process.env.VIDEO_SERVICE_URL || 'http://video-management-service:3003',
    healthPath: '/health',
    timeout: 30000 // Higher timeout for video operations
  },
  'analytics': {
    name: 'analytics-service',
    url: process.env.ANALYTICS_SERVICE_URL || 'http://analytics-service:3004',
    healthPath: '/health',
    timeout: 20000
  },
  'access': {
    name: 'access-control-service',
    url: process.env.ACCESS_SERVICE_URL || 'http://access-control-service:3005',
    healthPath: '/health',
    timeout: 10000
  },
  'alerts': {
    name: 'alert-service',
    url: process.env.ALERT_SERVICE_URL || 'http://alert-service:3006',
    healthPath: '/health',
    timeout: 10000
  },
  'tenants': {
    name: 'tenant-service',
    url: process.env.TENANT_SERVICE_URL || 'http://tenant-service:3007',
    healthPath: '/health',
    timeout: 10000
  }
};

// Circuit breaker implementation
class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state: 'closed' | 'open' | 'halfOpen' = 'closed';
  private halfOpenRequests = 0;

  constructor(
    private config: {
      failureThreshold: number;
      resetTimeout: number;
      halfOpenRequests: number;
    }
  ) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      const now = Date.now();
      if (now - this.lastFailureTime > this.config.resetTimeout) {
        this.state = 'halfOpen';
        this.halfOpenRequests = 0;
      } else {
        throw new Error('Circuit breaker is open');
      }
    }

    if (this.state === 'halfOpen' && this.halfOpenRequests >= this.config.halfOpenRequests) {
      throw new Error('Circuit breaker is half-open, max requests reached');
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess() {
    if (this.state === 'halfOpen') {
      this.halfOpenRequests++;
      if (this.halfOpenRequests >= this.config.halfOpenRequests) {
        this.state = 'closed';
        this.failures = 0;
      }
    }
    this.failures = 0;
  }

  private onFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();
    
    if (this.failures >= this.config.failureThreshold) {
      this.state = 'open';
      logger.warn('Circuit breaker opened', {
        failures: this.failures,
        threshold: this.config.failureThreshold
      });
    }
  }

  getState() {
    return {
      state: this.state,
      failures: this.failures,
      lastFailureTime: this.lastFailureTime
    };
  }
}

// Circuit breakers for each service
const circuitBreakers = new Map<string, CircuitBreaker>();

// Get or create circuit breaker for a service
function getCircuitBreaker(service: string): CircuitBreaker | null {
  const config = serviceRegistry[service]?.circuitBreaker;
  if (!config) return null;

  if (!circuitBreakers.has(service)) {
    circuitBreakers.set(service, new CircuitBreaker(config));
  }
  
  return circuitBreakers.get(service)!;
}

const app = new Hono();

// Service health check endpoint
app.get('/services/health', async (c) => {
  return telemetry.withSpan(
    'proxy.health_check',
    async (span) => {
      const healthChecks = await Promise.all(
        Object.entries(serviceRegistry).map(async ([key, service]) => {
          const checkSpan = telemetry.startSpan(`health_check.${key}`, {
            kind: SpanKind.CLIENT,
            attributes: {
              'service.name': service.name,
              'service.url': service.url
            }
          });

          try {
            const response = await fetch(`${service.url}${service.healthPath}`, {
              method: 'GET',
              signal: AbortSignal.timeout(5000),
              headers: injectTraceContext()
            });

            const healthy = response.ok;
            checkSpan.setStatus({ code: healthy ? SpanStatusCode.OK : SpanStatusCode.ERROR });
            
            const circuitBreaker = getCircuitBreaker(key);
            
            return {
              service: key,
              name: service.name,
              healthy,
              status: response.status,
              circuitBreaker: circuitBreaker?.getState()
            };
          } catch (error) {
            checkSpan.setStatus({ 
              code: SpanStatusCode.ERROR,
              message: error instanceof Error ? error.message : 'Unknown error'
            });
            checkSpan.recordException(error as Error);
            
            return {
              service: key,
              name: service.name,
              healthy: false,
              error: error instanceof Error ? error.message : 'Unknown error',
              circuitBreaker: getCircuitBreaker(key)?.getState()
            };
          } finally {
            checkSpan.end();
          }
        })
      );

      const allHealthy = healthChecks.every(h => h.healthy);
      span.setAttribute('services.healthy', allHealthy);
      span.setAttribute('services.count', healthChecks.length);

      return c.json({
        healthy: allHealthy,
        services: healthChecks,
        timestamp: new Date().toISOString(),
        traceId: telemetry.getCurrentTraceId()
      }, allHealthy ? 200 : 503);
    },
    { kind: SpanKind.INTERNAL }
  );
});

// Proxy handler with distributed tracing
app.all('/:service/*', async (c) => {
  const service = c.req.param('service');
  const endpoint = serviceRegistry[service];

  if (!endpoint) {
    throw new HTTPException(404, { message: `Service '${service}' not found` });
  }

  const path = c.req.path.replace(`/${service}`, '');
  const method = c.req.method;

  return telemetry.withSpan(
    `proxy.${service}`,
    async (span) => {
      span.setAttributes({
        'proxy.service': service,
        'proxy.path': path,
        'proxy.method': method,
        'proxy.target': endpoint.url,
        'rpc.system': 'http',
        'rpc.service': endpoint.name,
        'rpc.method': `${method} ${path}`
      });

      // Check circuit breaker
      const circuitBreaker = getCircuitBreaker(service);
      if (circuitBreaker) {
        try {
          await circuitBreaker.execute(async () => {
            // Circuit breaker check only
            return true;
          });
        } catch (error) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: 'Circuit breaker open'
          });
          
          logger.warn('Request blocked by circuit breaker', {
            service,
            state: circuitBreaker.getState()
          });

          throw new HTTPException(503, {
            message: 'Service temporarily unavailable',
            service,
            circuitBreaker: circuitBreaker.getState()
          });
        }
      }

      try {
        // Prepare headers with trace context
        const headers: Record<string, string> = {
          ...Object.fromEntries(c.req.raw.headers.entries()),
          ...injectTraceContext(),
          'x-forwarded-for': c.req.header('x-forwarded-for') || 
                             c.req.header('x-real-ip') || 
                             c.env?.remoteAddr || 'unknown',
          'x-forwarded-host': c.req.header('host') || '',
          'x-forwarded-proto': c.req.header('x-forwarded-proto') || 'http',
          'x-original-uri': c.req.path,
          'x-tenant-id': c.get('tenantId') || '',
          'x-user-id': c.get('userId') || ''
        };

        // Remove hop-by-hop headers
        delete headers['connection'];
        delete headers['keep-alive'];
        delete headers['transfer-encoding'];
        delete headers['upgrade'];

        // Make the proxied request
        const targetUrl = `${endpoint.url}${path}${c.req.query() ? `?${c.req.query()}` : ''}`;
        
        const startTime = Date.now();
        const response = await fetch(targetUrl, {
          method: method as any,
          headers,
          body: method !== 'GET' && method !== 'HEAD' ? c.req.raw.body : undefined,
          signal: AbortSignal.timeout(endpoint.timeout),
          // @ts-ignore - duplex is needed for streaming requests
          duplex: 'half'
        });

        const duration = Date.now() - startTime;

        // Record metrics
        span.setAttributes({
          'http.status_code': response.status,
          'http.response_content_length': response.headers.get('content-length') || 0,
          'proxy.duration': duration
        });

        // Log slow requests
        if (duration > 1000) {
          logger.logPerformance(`proxy.${service}`, duration, {
            path,
            status: response.status
          });
        }

        // Set status based on response
        if (response.status >= 400) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: `HTTP ${response.status}`
          });

          // Record circuit breaker failure
          if (circuitBreaker && response.status >= 500) {
            circuitBreaker.execute(() => Promise.reject(new Error('Server error')))
              .catch(() => {}); // Ignore, just record the failure
          }
        }

        // Stream the response back
        const responseHeaders = new Headers();
        response.headers.forEach((value, key) => {
          // Skip hop-by-hop headers
          if (!['connection', 'keep-alive', 'transfer-encoding', 'upgrade'].includes(key.toLowerCase())) {
            responseHeaders.set(key, value);
          }
        });

        // Add trace headers to response
        responseHeaders.set('x-trace-id', telemetry.getCurrentTraceId() || '');
        responseHeaders.set('x-correlation-id', c.get('correlationId') || '');

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders
        });

      } catch (error) {
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error instanceof Error ? error.message : 'Proxy error'
        });
        span.recordException(error as Error);

        // Record circuit breaker failure
        if (circuitBreaker) {
          circuitBreaker.execute(() => Promise.reject(error)).catch(() => {});
        }

        logger.error(`Proxy error for service ${service}`, error);

        if (error instanceof Error && error.name === 'AbortError') {
          throw new HTTPException(504, {
            message: 'Gateway timeout',
            service,
            timeout: endpoint.timeout
          });
        }

        throw new HTTPException(502, {
          message: 'Bad gateway',
          service,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    },
    {
      kind: SpanKind.CLIENT,
      attributes: {
        'peer.service': endpoint.name
      }
    }
  );
});

export default app;