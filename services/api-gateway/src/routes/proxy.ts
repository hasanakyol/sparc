import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import CircuitBreaker from 'opossum';
import consul from 'consul';
import { createLogger } from '@sparc/shared/utils';
import { config } from '@sparc/shared';

const app = new Hono();
const logger = createLogger('api-gateway-proxy');

// Initialize Consul client for service discovery
const consulClient = consul({
  host: config.consul.host || 'localhost',
  port: config.consul.port || 8500,
  secure: config.consul.secure || false,
});

// Service registry cache
interface ServiceInstance {
  id: string;
  name: string;
  address: string;
  port: number;
  health: 'passing' | 'warning' | 'critical';
  lastChecked: number;
}

class ServiceRegistry {
  private services: Map<string, ServiceInstance[]> = new Map();
  private lastUpdate: Map<string, number> = new Map();
  private readonly CACHE_TTL = 30000; // 30 seconds

  async getHealthyInstances(serviceName: string): Promise<ServiceInstance[]> {
    const now = Date.now();
    const lastCheck = this.lastUpdate.get(serviceName) || 0;

    // Refresh cache if expired
    if (now - lastCheck > this.CACHE_TTL) {
      await this.refreshService(serviceName);
    }

    return this.services.get(serviceName)?.filter(s => s.health === 'passing') || [];
  }

  private async refreshService(serviceName: string): Promise<void> {
    try {
      const result = await consulClient.health.service({
        service: serviceName,
        passing: true,
      });

      const instances: ServiceInstance[] = result.map((entry: any) => ({
        id: entry.Service.ID,
        name: entry.Service.Service,
        address: entry.Service.Address,
        port: entry.Service.Port,
        health: entry.Checks.every((check: any) => check.Status === 'passing') ? 'passing' : 'warning',
        lastChecked: Date.now(),
      }));

      this.services.set(serviceName, instances);
      this.lastUpdate.set(serviceName, Date.now());

      logger.info(`Service registry updated for ${serviceName}`, {
        instanceCount: instances.length,
        instances: instances.map(i => `${i.address}:${i.port}`),
      });
    } catch (error) {
      logger.error(`Failed to refresh service registry for ${serviceName}`, {
        error: error.message,
      });
      throw error;
    }
  }
}

const serviceRegistry = new ServiceRegistry();

// Load balancer implementation
class LoadBalancer {
  private roundRobinCounters: Map<string, number> = new Map();
  private instanceHealth: Map<string, { failures: number; lastFailure: number }> = new Map();
  private readonly HEALTH_THRESHOLD = 3; // Max failures before considering unhealthy
  private readonly HEALTH_RESET_TIME = 60000; // 1 minute

  selectInstance(serviceName: string, instances: ServiceInstance[]): ServiceInstance | null {
    if (instances.length === 0) return null;
    if (instances.length === 1) return instances[0];

    // Filter out unhealthy instances based on recent failures
    const healthyInstances = instances.filter(instance => {
      const instanceKey = `${serviceName}:${instance.id}`;
      const health = this.instanceHealth.get(instanceKey);
      
      if (!health) return true;
      
      // Reset health if enough time has passed
      if (Date.now() - health.lastFailure > this.HEALTH_RESET_TIME) {
        this.instanceHealth.delete(instanceKey);
        return true;
      }
      
      return health.failures < this.HEALTH_THRESHOLD;
    });

    // Fall back to all instances if none are considered healthy
    const candidateInstances = healthyInstances.length > 0 ? healthyInstances : instances;

    // Round-robin load balancing among healthy instances
    const counter = this.roundRobinCounters.get(serviceName) || 0;
    const selectedIndex = counter % candidateInstances.length;
    this.roundRobinCounters.set(serviceName, counter + 1);

    return candidateInstances[selectedIndex];
  }

  recordFailure(serviceName: string, instanceId: string): void {
    const instanceKey = `${serviceName}:${instanceId}`;
    const health = this.instanceHealth.get(instanceKey) || { failures: 0, lastFailure: 0 };
    
    health.failures += 1;
    health.lastFailure = Date.now();
    
    this.instanceHealth.set(instanceKey, health);
    
    logger.warn(`Recorded failure for instance ${instanceKey}`, {
      failures: health.failures,
      threshold: this.HEALTH_THRESHOLD,
    });
  }

  recordSuccess(serviceName: string, instanceId: string): void {
    const instanceKey = `${serviceName}:${instanceId}`;
    this.instanceHealth.delete(instanceKey);
  }
}

const loadBalancer = new LoadBalancer();

// Circuit breaker configuration
const circuitBreakerOptions = {
  timeout: config.circuitBreaker.timeout || 5000, // 5 seconds
  errorThresholdPercentage: config.circuitBreaker.errorThreshold || 50,
  resetTimeout: config.circuitBreaker.resetTimeout || 30000, // 30 seconds
  rollingCountTimeout: config.circuitBreaker.rollingCountTimeout || 10000,
  rollingCountBuckets: config.circuitBreaker.rollingCountBuckets || 10,
  name: 'service-proxy',
  group: 'api-gateway',
};

// Service proxy function
async function proxyRequest(
  serviceName: string,
  path: string,
  method: string,
  headers: Record<string, string>,
  body?: any
): Promise<Response> {
  // Get healthy service instances
  const instances = await serviceRegistry.getHealthyInstances(serviceName);
  
  if (instances.length === 0) {
    throw new HTTPException(503, {
      message: `No healthy instances available for service: ${serviceName}`,
    });
  }

  // Select instance using load balancer
  const instance = loadBalancer.selectInstance(serviceName, instances);
  if (!instance) {
    throw new HTTPException(503, {
      message: `Failed to select instance for service: ${serviceName}`,
    });
  }

  const targetUrl = `http://${instance.address}:${instance.port}${path}`;
  
  logger.debug(`Proxying request to ${serviceName}`, {
    targetUrl,
    method,
    instanceId: instance.id,
  });

  // Prepare request options with timeout
  const requestOptions: RequestInit = {
    method,
    headers: {
      ...headers,
      'X-Forwarded-For': headers['x-forwarded-for'] || 'unknown',
      'X-Forwarded-Proto': headers['x-forwarded-proto'] || 'http',
      'X-Request-ID': headers['x-request-id'] || crypto.randomUUID(),
      'X-Gateway-Instance': instance.id,
    },
    signal: AbortSignal.timeout(config.circuitBreaker.timeout || 5000),
  };

  // Add body for non-GET requests with proper content type handling
  if (body && method !== 'GET' && method !== 'HEAD') {
    if (body instanceof ArrayBuffer) {
      requestOptions.body = body;
    } else if (typeof body === 'string') {
      requestOptions.body = body;
    } else {
      requestOptions.body = JSON.stringify(body);
      // Ensure content-type is set for JSON
      if (!headers['content-type']) {
        requestOptions.headers = {
          ...requestOptions.headers,
          'Content-Type': 'application/json',
        };
      }
    }
  }

  try {
    // Make the request
    const response = await fetch(targetUrl, requestOptions);
    
    if (!response.ok) {
      logger.warn(`Upstream service returned error`, {
        serviceName,
        status: response.status,
        statusText: response.statusText,
        targetUrl,
        instanceId: instance.id,
      });
      
      // Record failure for load balancer health tracking
      if (response.status >= 500) {
        loadBalancer.recordFailure(serviceName, instance.id);
      }
    } else {
      // Record success for load balancer health tracking
      loadBalancer.recordSuccess(serviceName, instance.id);
    }

    return response;
  } catch (error) {
    // Record failure for network/timeout errors
    loadBalancer.recordFailure(serviceName, instance.id);
    
    if (error.name === 'TimeoutError' || error.name === 'AbortError') {
      logger.error(`Request timeout to ${serviceName}`, {
        targetUrl,
        instanceId: instance.id,
        timeout: config.circuitBreaker.timeout,
      });
      throw new HTTPException(504, {
        message: `Request timeout to service: ${serviceName}`,
      });
    }
    
    throw error;
  }
}

// Create circuit breaker for each service
const circuitBreakers: Map<string, CircuitBreaker> = new Map();

function getCircuitBreaker(serviceName: string): CircuitBreaker {
  if (!circuitBreakers.has(serviceName)) {
    const breaker = new CircuitBreaker(
      (args: any) => proxyRequest(args.serviceName, args.path, args.method, args.headers, args.body),
      {
        ...circuitBreakerOptions,
        name: `${serviceName}-proxy`,
      }
    );

    // Circuit breaker event handlers
    breaker.on('open', () => {
      logger.warn(`Circuit breaker opened for service: ${serviceName}`);
    });

    breaker.on('halfOpen', () => {
      logger.info(`Circuit breaker half-open for service: ${serviceName}`);
    });

    breaker.on('close', () => {
      logger.info(`Circuit breaker closed for service: ${serviceName}`);
    });

    breaker.on('fallback', (result) => {
      logger.info(`Circuit breaker fallback executed for service: ${serviceName}`, { result });
    });

    // Fallback function
    breaker.fallback(() => {
      return new Response(
        JSON.stringify({
          error: 'Service Unavailable',
          message: `Service ${serviceName} is temporarily unavailable`,
          timestamp: new Date().toISOString(),
        }),
        {
          status: 503,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    });

    circuitBreakers.set(serviceName, breaker);
  }

  return circuitBreakers.get(serviceName)!;
}

// Service routing configuration with priority-based matching
const serviceRoutes = [
  // Authentication service
  { pattern: /^\/auth/, service: 'auth-service', priority: 1 },
  
  // Tenant management service
  { pattern: /^\/tenants/, service: 'tenant-service', priority: 1 },
  { pattern: /^\/organizations/, service: 'tenant-service', priority: 1 },
  { pattern: /^\/sites/, service: 'tenant-service', priority: 1 },
  { pattern: /^\/buildings/, service: 'tenant-service', priority: 1 },
  { pattern: /^\/floors/, service: 'tenant-service', priority: 1 },
  
  // Access control service - more specific patterns first
  { pattern: /^\/access-control/, service: 'access-control-service', priority: 1 },
  { pattern: /^\/access-events/, service: 'access-control-service', priority: 2 },
  { pattern: /^\/access-groups/, service: 'access-control-service', priority: 2 },
  { pattern: /^\/doors/, service: 'access-control-service', priority: 1 },
  { pattern: /^\/credentials/, service: 'access-control-service', priority: 1 },
  { pattern: /^\/schedules/, service: 'access-control-service', priority: 1 },
  
  // Video management service
  { pattern: /^\/video/, service: 'video-management-service', priority: 1 },
  { pattern: /^\/cameras/, service: 'video-management-service', priority: 1 },
  { pattern: /^\/recordings/, service: 'video-management-service', priority: 1 },
  { pattern: /^\/streams/, service: 'video-management-service', priority: 1 },
  
  // Event processing service
  { pattern: /^\/events/, service: 'event-processing-service', priority: 1 },
  { pattern: /^\/alerts/, service: 'event-processing-service', priority: 1 },
  { pattern: /^\/notifications/, service: 'event-processing-service', priority: 1 },
  
  // Device management service
  { pattern: /^\/devices/, service: 'device-management-service', priority: 1 },
  { pattern: /^\/device-discovery/, service: 'device-management-service', priority: 2 },
  
  // Mobile credential service
  { pattern: /^\/mobile-credentials/, service: 'mobile-credential-service', priority: 1 },
  
  // Analytics service
  { pattern: /^\/analytics/, service: 'analytics-service', priority: 1 },
  { pattern: /^\/reports/, service: 'analytics-service', priority: 1 },
  
  // Environmental service
  { pattern: /^\/environmental/, service: 'environmental-service', priority: 1 },
  { pattern: /^\/sensors/, service: 'environmental-service', priority: 1 },
  
  // Visitor management service
  { pattern: /^\/visitors/, service: 'visitor-management-service', priority: 1 },
  
  // Reporting service
  { pattern: /^\/reporting/, service: 'reporting-service', priority: 1 },
  { pattern: /^\/exports/, service: 'reporting-service', priority: 1 },
];

// Legacy service routes object for backward compatibility
const legacyServiceRoutes = {
  '/auth': 'auth-service',
  '/tenants': 'tenant-service',
  '/organizations': 'tenant-service',
  '/sites': 'tenant-service',
  '/buildings': 'tenant-service',
  '/floors': 'tenant-service',
  '/access-control': 'access-control-service',
  '/doors': 'access-control-service',
  '/access-events': 'access-control-service',
  '/credentials': 'access-control-service',
  '/access-groups': 'access-control-service',
  '/schedules': 'access-control-service',
  '/video': 'video-management-service',
  '/cameras': 'video-management-service',
  '/recordings': 'video-management-service',
  '/streams': 'video-management-service',
  '/events': 'event-processing-service',
  '/alerts': 'event-processing-service',
  '/notifications': 'event-processing-service',
  '/devices': 'device-management-service',
  '/device-discovery': 'device-management-service',
  '/mobile-credentials': 'mobile-credential-service',
  '/analytics': 'analytics-service',
  '/reports': 'analytics-service',
  '/environmental': 'environmental-service',
  '/sensors': 'environmental-service',
  '/visitors': 'visitor-management-service',
  '/reporting': 'reporting-service',
  '/exports': 'reporting-service',
};

// Helper function to determine service name from path with improved matching
function getServiceName(path: string): string | null {
  // Sort routes by priority (higher priority first)
  const sortedRoutes = serviceRoutes.sort((a, b) => b.priority - a.priority);
  
  // Find the first matching route
  for (const route of sortedRoutes) {
    if (route.pattern.test(path)) {
      logger.debug(`Matched route pattern`, {
        path,
        pattern: route.pattern.source,
        service: route.service,
        priority: route.priority,
      });
      return route.service;
    }
  }
  
  // Fallback to legacy routing for backward compatibility
  const segments = path.replace(/^\//, '').split('/');
  const firstSegment = `/${segments[0]}`;
  
  const legacyService = legacyServiceRoutes[firstSegment];
  if (legacyService) {
    logger.debug(`Matched legacy route`, {
      path,
      segment: firstSegment,
      service: legacyService,
    });
    return legacyService;
  }
  
  return null;
}

// Request transformation middleware
async function transformRequest(c: any, serviceName: string) {
  const headers: Record<string, string> = {};
  
  // Copy relevant headers
  const relevantHeaders = [
    'authorization',
    'content-type',
    'content-length',
    'accept',
    'accept-encoding',
    'accept-language',
    'user-agent',
    'x-tenant-id',
    'x-user-id',
    'x-request-id',
    'x-forwarded-for',
    'x-forwarded-proto',
    'x-forwarded-host',
    'x-real-ip',
    'cache-control',
    'if-none-match',
    'if-modified-since',
  ];

  relevantHeaders.forEach(header => {
    const value = c.req.header(header);
    if (value) {
      headers[header] = value;
    }
  });

  // Add gateway-specific headers
  headers['X-Gateway-Service'] = serviceName;
  headers['X-Gateway-Timestamp'] = new Date().toISOString();
  headers['X-Gateway-Version'] = config.version || '1.0.0';
  
  // Add client IP if not already present
  if (!headers['x-forwarded-for'] && !headers['x-real-ip']) {
    const clientIP = c.req.header('cf-connecting-ip') || 
                     c.req.header('x-forwarded-for') || 
                     c.env?.ip || 
                     'unknown';
    headers['X-Real-IP'] = clientIP;
  }
  
  // Add correlation ID for distributed tracing
  if (!headers['x-correlation-id']) {
    headers['X-Correlation-ID'] = headers['x-request-id'] || crypto.randomUUID();
  }
  
  return headers;
}

// Response transformation middleware
async function transformResponse(response: Response, serviceName: string): Promise<Response> {
  // Clone response to avoid consuming the stream
  const clonedResponse = response.clone();
  
  // Add gateway headers
  const headers = new Headers(clonedResponse.headers);
  headers.set('X-Gateway-Service', serviceName);
  headers.set('X-Gateway-Timestamp', new Date().toISOString());
  
  return new Response(clonedResponse.body, {
    status: clonedResponse.status,
    statusText: clonedResponse.statusText,
    headers,
  });
}

// Main proxy route handler
app.all('/api/*', async (c) => {
  const path = c.req.path;
  const method = c.req.method;
  const requestId = c.get('requestId') || crypto.randomUUID();
  
  logger.info('Proxying request', {
    requestId,
    method,
    path,
    userAgent: c.req.header('user-agent'),
  });

  try {
    // Determine target service
    const serviceName = getServiceName(path.replace('/api', ''));
    
    if (!serviceName) {
      logger.warn('No service found for path', { path, requestId });
      throw new HTTPException(404, {
        message: `No service configured for path: ${path}`,
      });
    }

    // Transform request headers
    const headers = await transformRequest(c, serviceName);
    
    // Get request body for non-GET requests with improved handling
    let body: any = undefined;
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const contentType = c.req.header('content-type') || '';
      
      try {
        if (contentType.includes('application/json')) {
          body = await c.req.json();
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          body = await c.req.text();
        } else if (contentType.includes('multipart/form-data')) {
          // For file uploads, pass through as ArrayBuffer
          body = await c.req.arrayBuffer();
        } else if (contentType.includes('text/')) {
          body = await c.req.text();
        } else {
          // Default to ArrayBuffer for binary data
          body = await c.req.arrayBuffer();
        }
      } catch (error) {
        logger.warn('Failed to parse request body', {
          contentType,
          method,
          path,
          error: error.message,
        });
        // If body parsing fails, try to get raw ArrayBuffer
        try {
          body = await c.req.arrayBuffer();
        } catch (fallbackError) {
          logger.error('Failed to get request body as ArrayBuffer', {
            error: fallbackError.message,
          });
          // Continue without body
        }
      }
    }

    // Remove /api prefix from path for downstream services
    const servicePath = path.replace('/api', '');
    
    // Get circuit breaker for the service
    const circuitBreaker = getCircuitBreaker(serviceName);
    
    // Execute request through circuit breaker
    const response = await circuitBreaker.fire({
      serviceName,
      path: servicePath,
      method,
      headers,
      body,
    });

    // Transform response
    const transformedResponse = await transformResponse(response, serviceName);
    
    logger.info('Request proxied successfully', {
      requestId,
      serviceName,
      status: transformedResponse.status,
      duration: Date.now() - (c.get('startTime') || Date.now()),
    });

    return transformedResponse;

  } catch (error) {
    logger.error('Proxy request failed', {
      requestId,
      path,
      method,
      error: error.message,
      stack: error.stack,
    });

    if (error instanceof HTTPException) {
      return c.json({
        error: error.message,
        requestId,
        timestamp: new Date().toISOString(),
      }, error.status);
    }

    return c.json({
      error: 'Internal proxy error',
      message: 'An unexpected error occurred while proxying the request',
      requestId,
      timestamp: new Date().toISOString(),
    }, 500);
  }
});

// Health check aggregation endpoint
app.get('/health/services', async (c) => {
  const serviceNames = Array.from(new Set([
    ...Object.values(legacyServiceRoutes),
    ...serviceRoutes.map(r => r.service)
  ]));
  const healthChecks: Record<string, any> = {};

  await Promise.allSettled(
    serviceNames.map(async (serviceName) => {
      try {
        const instances = await serviceRegistry.getHealthyInstances(serviceName);
        const circuitBreaker = circuitBreakers.get(serviceName);
        
        healthChecks[serviceName] = {
          status: instances.length > 0 ? 'healthy' : 'unhealthy',
          instanceCount: instances.length,
          instances: instances.map(i => `${i.address}:${i.port}`),
          circuitBreaker: {
            state: circuitBreaker?.stats.state || 'unknown',
            failures: circuitBreaker?.stats.failures || 0,
            successes: circuitBreaker?.stats.successes || 0,
            rejections: circuitBreaker?.stats.rejections || 0,
          },
          loadBalancer: {
            healthyInstances: instances.filter(i => i.health === 'passing').length,
            totalInstances: instances.length,
          },
        };
      } catch (error) {
        healthChecks[serviceName] = {
          status: 'error',
          error: error.message,
        };
      }
    })
  );

  const overallStatus = Object.values(healthChecks).every(
    (service: any) => service.status === 'healthy'
  ) ? 'healthy' : 'degraded';

  return c.json({
    status: overallStatus,
    timestamp: new Date().toISOString(),
    services: healthChecks,
  });
});

// Service discovery refresh endpoint
app.post('/admin/refresh-services', async (c) => {
  try {
    const serviceNames = Array.from(new Set([
      ...Object.values(legacyServiceRoutes),
      ...serviceRoutes.map(r => r.service)
    ]));
    
    const refreshResults = await Promise.allSettled(
      serviceNames.map(async serviceName => {
        try {
          await serviceRegistry.getHealthyInstances(serviceName);
          return { serviceName, status: 'success' };
        } catch (error) {
          return { serviceName, status: 'error', error: error.message };
        }
      })
    );

    const results = refreshResults.map(result => 
      result.status === 'fulfilled' ? result.value : result.reason
    );

    logger.info('Service registry refreshed manually', {
      totalServices: serviceNames.length,
      results,
    });
    
    return c.json({
      message: 'Service registry refresh completed',
      timestamp: new Date().toISOString(),
      results,
    });
  } catch (error) {
    logger.error('Failed to refresh service registry', { error: error.message });
    
    return c.json({
      error: 'Failed to refresh service registry',
      message: error.message,
      timestamp: new Date().toISOString(),
    }, 500);
  }
});

// Circuit breaker status endpoint
app.get('/admin/circuit-breakers', (c) => {
  const status: Record<string, any> = {};
  
  circuitBreakers.forEach((breaker, serviceName) => {
    status[serviceName] = {
      state: breaker.stats.state,
      failures: breaker.stats.failures,
      successes: breaker.stats.successes,
      rejections: breaker.stats.rejections,
      fires: breaker.stats.fires,
      timeouts: breaker.stats.timeouts,
    };
  });

  return c.json({
    timestamp: new Date().toISOString(),
    circuitBreakers: status,
  });
});

export default app;
