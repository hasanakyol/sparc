import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { createProxyRoutes } from './routes/proxy.modular';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from './middleware/auth';
import { rateLimitMiddleware } from './middleware/rateLimit';
import { siemMiddleware } from './middleware/siem';

// Service-specific configuration interface
interface ApiGatewayConfig extends ServiceConfig {
  services: Record<string, ServiceDefinition>;
  corsOrigin: string;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  requestTimeoutMs: number;
}

interface ServiceDefinition {
  name: string;
  url: string;
  healthPath: string;
  timeout: number;
  retries: number;
}

class ApiGatewayService extends MicroserviceBase {
  private services: Record<string, ServiceDefinition>;

  constructor(config: ApiGatewayConfig) {
    super({
      ...config,
      enableAuth: false, // We'll handle auth ourselves
      enableRateLimit: false, // We have custom rate limiting
    });
    this.services = config.services;
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    // Check connectivity to each downstream service
    for (const [key, service] of Object.entries(this.services)) {
      try {
        const response = await fetch(`${service.url}${service.healthPath}`, {
          signal: AbortSignal.timeout(3000)
        });
        checks[`service_${key}`] = response.ok;
      } catch {
        checks[`service_${key}`] = false;
      }
    }
    
    return checks;
  }

  public setupRoutes(): void {
    // Apply gateway-specific middleware
    this.app.use('*', siemMiddleware);
    
    // Rate limiting (skip for health endpoints)
    this.app.use('/api/*', rateLimitMiddleware);
    
    // Authentication (skip for health and auth endpoints)
    this.app.use('/api/*', async (c, next) => {
      const path = c.req.path;
      if (path.startsWith('/api/auth/login') || 
          path.startsWith('/api/auth/register') ||
          path.startsWith('/api/auth/refresh')) {
        return next();
      }
      return authMiddleware(c, next);
    });

    // Service discovery endpoint
    this.app.get('/services', (c) => {
      const serviceList = Object.entries(this.services).map(([key, service]) => ({
        id: key,
        name: service.name,
        healthPath: service.healthPath,
        timeout: service.timeout,
        retries: service.retries
      }));
      return c.json({ services: serviceList });
    });

    // Mount proxy routes for each service
    for (const [servicePath, serviceConfig] of Object.entries(this.services)) {
      const proxyRoutes = createProxyRoutes(serviceConfig, this.redis);
      this.app.route(`/api/${servicePath}`, proxyRoutes);
    }

    // Fallback route
    this.app.all('*', (c) => {
      throw new HTTPException(404, { message: 'Route not found' });
    });
  }

  protected async cleanup(): Promise<void> {
    // Any gateway-specific cleanup
    console.log('API Gateway cleanup completed');
  }
}

// Configuration
const config: ApiGatewayConfig = {
  serviceName: 'api-gateway',
  port: parseInt(process.env.PORT || '3000'),
  version: process.env.npm_package_version || '1.0.0',
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/sparc',
  corsOrigin: process.env.CORS_ORIGIN || '*',
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  requestTimeoutMs: parseInt(process.env.REQUEST_TIMEOUT_MS || '30000'),
  services: {
    auth: {
      name: 'auth-service',
      url: process.env.AUTH_SERVICE_URL || 'http://localhost:3001',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    tenant: {
      name: 'tenant-service',
      url: process.env.TENANT_SERVICE_URL || 'http://localhost:3002',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    'access-control': {
      name: 'access-control-service',
      url: process.env.ACCESS_CONTROL_SERVICE_URL || 'http://localhost:3003',
      healthPath: '/health',
      timeout: 10000,
      retries: 3
    },
    'video-management': {
      name: 'video-management-service',
      url: process.env.VIDEO_MANAGEMENT_SERVICE_URL || 'http://localhost:3004',
      healthPath: '/health',
      timeout: 15000,
      retries: 2
    },
    'event-processing': {
      name: 'event-processing-service',
      url: process.env.EVENT_PROCESSING_SERVICE_URL || 'http://localhost:3005',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    'device-management': {
      name: 'device-management-service',
      url: process.env.DEVICE_MANAGEMENT_SERVICE_URL || 'http://localhost:3006',
      healthPath: '/health',
      timeout: 10000,
      retries: 3
    },
    'mobile-credential': {
      name: 'mobile-credential-service',
      url: process.env.MOBILE_CREDENTIAL_SERVICE_URL || 'http://localhost:3007',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    analytics: {
      name: 'analytics-service',
      url: process.env.ANALYTICS_SERVICE_URL || 'http://localhost:3008',
      healthPath: '/health',
      timeout: 10000,
      retries: 2
    },
    environmental: {
      name: 'environmental-service',
      url: process.env.ENVIRONMENTAL_SERVICE_URL || 'http://localhost:3009',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    'visitor-management': {
      name: 'visitor-management-service',
      url: process.env.VISITOR_MANAGEMENT_SERVICE_URL || 'http://localhost:3010',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    reporting: {
      name: 'reporting-service',
      url: process.env.REPORTING_SERVICE_URL || 'http://localhost:3011',
      healthPath: '/health',
      timeout: 15000,
      retries: 2
    },
    alert: {
      name: 'alert-service',
      url: process.env.ALERT_SERVICE_URL || 'http://localhost:3012',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    integration: {
      name: 'integration-service',
      url: process.env.INTEGRATION_SERVICE_URL || 'http://localhost:3013',
      healthPath: '/health',
      timeout: 10000,
      retries: 3
    },
    'backup-recovery': {
      name: 'backup-recovery-service',
      url: process.env.BACKUP_RECOVERY_SERVICE_URL || 'http://localhost:3014',
      healthPath: '/health',
      timeout: 15000,
      retries: 2
    },
    'security-compliance': {
      name: 'security-compliance-service',
      url: process.env.SECURITY_COMPLIANCE_SERVICE_URL || 'http://localhost:3015',
      healthPath: '/health',
      timeout: 10000,
      retries: 3
    },
    maintenance: {
      name: 'maintenance-service',
      url: process.env.MAINTENANCE_SERVICE_URL || 'http://localhost:3016',
      healthPath: '/health',
      timeout: 10000,
      retries: 3
    },
    'elevator-control': {
      name: 'elevator-control-service',
      url: process.env.ELEVATOR_CONTROL_SERVICE_URL || 'http://localhost:3017',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    'api-documentation': {
      name: 'api-documentation-service',
      url: process.env.API_DOCUMENTATION_SERVICE_URL || 'http://localhost:3018',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    },
    'testing-infrastructure': {
      name: 'testing-infrastructure-service',
      url: process.env.TESTING_INFRASTRUCTURE_SERVICE_URL || 'http://localhost:3019',
      healthPath: '/health',
      timeout: 5000,
      retries: 3
    }
  }
};

// Create and start the service
const service = new ApiGatewayService(config);
service.start().catch(console.error);

export default service;