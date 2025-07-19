import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import Redis from 'ioredis';
import { createLogger } from 'winston';
import { format, transports } from 'winston';

interface ServiceConfig {
  name: string;
  url: string;
  healthPath: string;
  timeout: number;
  retries: number;
}

// Winston logger configuration
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.splat(),
    format.json()
  ),
  defaultMeta: { service: 'api-gateway-proxy' },
  transports: [
    new transports.Console({
      format: format.simple()
    })
  ]
});

// Circuit breaker implementation
class CircuitBreaker {
  private failures: number = 0;
  private successes: number = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  private nextAttempt: number = Date.now();
  private readonly failureThreshold: number = 5;
  private readonly successThreshold: number = 2;
  private readonly timeout: number = 60000; // 60 seconds

  constructor(private serviceName: string) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        throw new Error(`Circuit breaker is OPEN for ${this.serviceName}`);
      }
      this.state = 'HALF_OPEN';
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

  private onSuccess(): void {
    this.failures = 0;
    if (this.state === 'HALF_OPEN') {
      this.successes++;
      if (this.successes >= this.successThreshold) {
        this.state = 'CLOSED';
        this.successes = 0;
      }
    }
  }

  private onFailure(): void {
    this.failures++;
    this.successes = 0;
    if (this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.nextAttempt = Date.now() + this.timeout;
    }
  }

  getState(): string {
    return this.state;
  }
}

// Circuit breaker registry
const circuitBreakers = new Map<string, CircuitBreaker>();

function getCircuitBreaker(serviceName: string): CircuitBreaker {
  if (!circuitBreakers.has(serviceName)) {
    circuitBreakers.set(serviceName, new CircuitBreaker(serviceName));
  }
  return circuitBreakers.get(serviceName)!;
}

export function createProxyRoutes(serviceConfig: ServiceConfig, redis: Redis): Hono {
  const app = new Hono();

  // Proxy all requests to the target service
  app.all('/*', async (c) => {
    const requestId = c.get('requestId') || crypto.randomUUID();
    const startTime = Date.now();
    const path = c.req.path;
    const method = c.req.method;
    const circuitBreaker = getCircuitBreaker(serviceConfig.name);

    try {
      return await circuitBreaker.execute(async () => {
        // Build target URL
        const targetUrl = `${serviceConfig.url}${path}`;
        
        // Copy headers
        const headers: Record<string, string> = {};
        const relevantHeaders = [
          'authorization',
          'content-type',
          'accept',
          'user-agent',
          'x-tenant-id',
          'x-user-id',
          'x-request-id',
          'x-correlation-id'
        ];

        relevantHeaders.forEach(header => {
          const value = c.req.header(header);
          if (value) {
            headers[header] = value;
          }
        });

        // Add gateway headers
        headers['X-Request-ID'] = requestId;
        headers['X-Gateway-Service'] = serviceConfig.name;
        headers['X-Forwarded-For'] = c.req.header('x-forwarded-for') || 
                                     c.req.header('cf-connecting-ip') || 
                                     'unknown';

        // Copy user context from auth middleware
        const userId = c.get('userId');
        const tenantId = c.get('tenantId');
        const roles = c.get('roles');
        const permissions = c.get('permissions');
        
        if (userId) headers['X-User-ID'] = userId;
        if (tenantId) headers['X-Tenant-ID'] = tenantId;
        if (roles) headers['X-User-Roles'] = JSON.stringify(roles);
        if (permissions) headers['X-User-Permissions'] = JSON.stringify(permissions);

        // Prepare request options
        const requestOptions: RequestInit = {
          method,
          headers,
          signal: AbortSignal.timeout(serviceConfig.timeout)
        };

        // Add body for non-GET requests
        if (method !== 'GET' && method !== 'HEAD') {
          try {
            const contentType = c.req.header('content-type') || '';
            
            if (contentType.includes('application/json')) {
              requestOptions.body = JSON.stringify(await c.req.json());
            } else if (contentType.includes('multipart/form-data')) {
              requestOptions.body = await c.req.arrayBuffer();
            } else {
              requestOptions.body = await c.req.text();
            }
          } catch (error) {
            logger.warn('Failed to read request body', { error, requestId });
          }
        }

        // Retry logic with exponential backoff
        let lastError: Error | null = null;
        
        for (let attempt = 1; attempt <= serviceConfig.retries; attempt++) {
          try {
            logger.debug('Proxying request', {
              requestId,
              serviceName: serviceConfig.name,
              targetUrl,
              attempt,
              method
            });

            const response = await fetch(targetUrl, requestOptions);
            
            // Log response
            const duration = Date.now() - startTime;
            logger.info('Proxy request completed', {
              requestId,
              serviceName: serviceConfig.name,
              status: response.status,
              duration,
              attempt
            });

            // Cache successful GET responses
            if (method === 'GET' && response.ok && redis) {
              const cacheKey = `api-gateway:${serviceConfig.name}:${path}`;
              const responseBody = await response.text();
              
              // Cache for 5 minutes
              await redis.setex(cacheKey, 300, JSON.stringify({
                status: response.status,
                headers: Object.fromEntries(response.headers.entries()),
                body: responseBody
              }));

              return new Response(responseBody, {
                status: response.status,
                headers: response.headers
              });
            }

            return response;
            
          } catch (error) {
            lastError = error as Error;
            logger.warn('Service request failed', {
              requestId,
              serviceName: serviceConfig.name,
              attempt,
              error: lastError.message
            });

            if (attempt < serviceConfig.retries) {
              // Exponential backoff
              const backoffTime = Math.pow(2, attempt) * 100;
              await new Promise(resolve => setTimeout(resolve, backoffTime));
            }
          }
        }

        // All retries failed
        const duration = Date.now() - startTime;
        logger.error('Service unavailable after retries', {
          requestId,
          serviceName: serviceConfig.name,
          retries: serviceConfig.retries,
          duration,
          error: lastError?.message
        });

        throw new HTTPException(503, {
          message: `Service ${serviceConfig.name} is currently unavailable`
        });
      });
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      
      if (error instanceof Error && error.message.includes('Circuit breaker is OPEN')) {
        throw new HTTPException(503, {
          message: `Service ${serviceConfig.name} is temporarily unavailable due to repeated failures`
        });
      }

      throw new HTTPException(500, {
        message: 'Internal gateway error'
      });
    }
  });

  return app;
}