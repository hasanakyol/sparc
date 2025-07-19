import { MicroserviceBase, ServiceConfig } from '@sparc/shared/src/patterns/service-base';
import { config } from '@sparc/shared';
import tenantRoutes from './routes/tenants';
import organizationRoutes from './routes/organizations';
import siteRoutes from './routes/sites';
import buildingRoutes from './routes/buildings';
import floorRoutes from './routes/floors';
import zoneRoutes from './routes/zones';
import configRoutes from './routes/config';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { trace, context, SpanStatusCode } from '@opentelemetry/api';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';

class TenantService extends MicroserviceBase {
  private tracer = trace.getTracer('tenant-service');

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'tenant-service',
      port: config.services?.tenant?.port || 3002,
      version: process.env.npm_package_version || '1.0.0',
      jwtSecret: config.jwt?.accessTokenSecret || process.env.JWT_SECRET!,
      redisUrl: config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379',
      databaseUrl: config.database?.url || process.env.DATABASE_URL!,
      enableAuth: true, // Tenant service requires authentication
      enableRateLimit: true,
      enableMetrics: true,
      corsOrigins: config.cors?.origins || ['http://localhost:3000']
    };
    
    super(serviceConfig);
    this.setupOpenTelemetry();
  }

  private setupOpenTelemetry(): void {
    if (process.env.OTEL_EXPORTER_OTLP_ENDPOINT) {
      const sdk = new NodeSDK({
        resource: new Resource({
          [SemanticResourceAttributes.SERVICE_NAME]: this.config.serviceName,
          [SemanticResourceAttributes.SERVICE_VERSION]: this.config.version,
        }),
      });

      sdk.start();
      console.log(`[${this.config.serviceName}] OpenTelemetry instrumentation initialized`);
    }
  }

  setupRoutes(): void {
    // Service info endpoint
    this.app.get('/', (c) => {
      return c.json({
        service: this.config.serviceName,
        version: this.config.version,
        description: 'Multi-tenant management service for SPARC platform',
        endpoints: {
          health: '/health',
          ready: '/ready',
          metrics: '/metrics',
          tenants: '/api/tenants',
          organizations: '/api/organizations',
          sites: '/api/sites',
          buildings: '/api/buildings',
          floors: '/api/floors',
          zones: '/api/zones',
          config: '/api/config'
        },
      });
    });

    // Mount routes
    this.app.route('/api/tenants', tenantRoutes);
    this.app.route('/api/organizations', organizationRoutes);
    this.app.route('/api/sites', siteRoutes);
    this.app.route('/api/buildings', buildingRoutes);
    this.app.route('/api/floors', floorRoutes);
    this.app.route('/api/zones', zoneRoutes);
    this.app.route('/api/config', configRoutes);

    // Additional error handling specific to tenant service
    this.app.use('*', async (c, next) => {
      const span = this.tracer.startSpan('request', {
        attributes: {
          'http.method': c.req.method,
          'http.url': c.req.url,
          'http.target': c.req.path,
        },
      });

      try {
        await context.with(trace.setSpan(context.active(), span), async () => {
          await next();
        });
        span.setAttributes({
          'http.status_code': c.res.status,
        });
      } catch (err) {
        span.recordException(err as Error);
        span.setStatus({ code: SpanStatusCode.ERROR });
        
        if (err instanceof z.ZodError) {
          throw new HTTPException(400, {
            message: 'Validation failed',
            cause: err.errors
          });
        }
        throw err;
      } finally {
        span.end();
      }
    });

    // 404 handler
    this.app.notFound((c) => {
      return c.json(
        {
          error: 'Not found',
          path: c.req.path,
          requestId: c.get('requestId')
        },
        404
      );
    });
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    try {
      // Check if we can query tenants
      const tenantCount = await this.prisma.tenant.count();
      checks.tenantQuery = true;
      checks.tenantCount = tenantCount >= 0;
      
      // Check cache connectivity
      const cacheKey = 'health:tenant-service';
      await this.redis.setex(cacheKey, 60, 'healthy');
      const cached = await this.redis.get(cacheKey);
      checks.cacheWrite = cached === 'healthy';
    } catch (error) {
      console.error('Health check failed:', error);
      checks.tenantQuery = false;
      checks.cacheWrite = false;
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const metrics: string[] = [];
    
    // Add tenant-specific metrics
    metrics.push('# HELP tenant_total Total number of tenants');
    metrics.push('# TYPE tenant_total gauge');
    
    metrics.push('# HELP organization_total Total number of organizations');
    metrics.push('# TYPE organization_total gauge');
    
    metrics.push('# HELP site_total Total number of sites');
    metrics.push('# TYPE site_total gauge');
    
    metrics.push('# HELP tenant_api_requests_total Total number of tenant API requests');
    metrics.push('# TYPE tenant_api_requests_total counter');
    
    metrics.push('# HELP tenant_cache_hits_total Total number of cache hits');
    metrics.push('# TYPE tenant_cache_hits_total counter');
    
    metrics.push('# HELP tenant_cache_misses_total Total number of cache misses');
    metrics.push('# TYPE tenant_cache_misses_total counter');
    
    // Get actual metrics
    try {
      const [tenantCount, orgCount, siteCount] = await Promise.all([
        this.prisma.tenant.count(),
        this.prisma.organization.count(),
        this.prisma.site.count()
      ]);
      
      metrics.push(`tenant_total ${tenantCount}`);
      metrics.push(`organization_total ${orgCount}`);
      metrics.push(`site_total ${siteCount}`);
      
      // Get request metrics from Redis
      const apiRequests = await this.redis.get('metrics:tenant:api_requests') || '0';
      const cacheHits = await this.redis.get('metrics:tenant:cache_hits') || '0';
      const cacheMisses = await this.redis.get('metrics:tenant:cache_misses') || '0';
      
      metrics.push(`tenant_api_requests_total ${apiRequests}`);
      metrics.push(`tenant_cache_hits_total ${cacheHits}`);
      metrics.push(`tenant_cache_misses_total ${cacheMisses}`);
    } catch (error) {
      console.error('Failed to get metrics:', error);
    }
    
    return metrics.join('\n');
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up tenant service resources...');
    
    // Clear tenant cache
    try {
      const cacheKeys = await this.redis.keys('tenant:*');
      if (cacheKeys.length > 0) {
        await this.redis.del(...cacheKeys);
      }
      
      // Clear organization cache
      const orgKeys = await this.redis.keys('org:*');
      if (orgKeys.length > 0) {
        await this.redis.del(...orgKeys);
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  public async start(): Promise<void> {
    // Call parent start to initialize everything
    await super.start();
    
    // For Node.js environment, use @hono/node-server
    if (typeof Bun === 'undefined') {
      const { serve } = await import('@hono/node-server');
      const server = serve({
        fetch: this.app.fetch,
        port: this.config.port,
      }, (info) => {
        console.log(`[${this.config.serviceName}] Node.js server v${this.config.version} running on port ${info.port}`);
      });
      
      // Store server reference for cleanup
      this.server = server;
    }
  }

  // Helper methods for tenant operations
  public async getTenantById(tenantId: string): Promise<any> {
    const cacheKey = `tenant:${tenantId}`;
    return this.withCache(cacheKey, 300, async () => {
      return await this.prisma.tenant.findUnique({
        where: { id: tenantId },
        include: {
          _count: {
            select: {
              organizations: true,
              users: true
            }
          }
        }
      });
    });
  }

  public async invalidateTenantCache(tenantId: string): Promise<void> {
    await this.invalidateCache(`tenant:${tenantId}*`);
    await this.invalidateCache(`org:*:tenant:${tenantId}`);
  }

  public async incrementMetric(metric: string): Promise<void> {
    const key = `metrics:tenant:${metric}`;
    await this.redis.incr(key);
  }
}

// Create and start the service
const tenantService = new TenantService();

tenantService.start().catch((error) => {
  console.error('Failed to start tenant service:', error);
  process.exit(1);
});

// Export for testing
export default tenantService;
export { TenantService };