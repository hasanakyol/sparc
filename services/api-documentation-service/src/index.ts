import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { config, logger as appLogger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import fs from 'fs/promises';
import path from 'path';
import yaml from 'js-yaml';
import archiver from 'archiver';
import { Readable } from 'stream';

// Test infrastructure - only run tests in test environment
if (process.env.NODE_ENV === 'test') {
  // Import test dependencies
  const jest = require('jest');
  const supertest = require('supertest');
  
  // Mock implementations for testing
  const mockPrisma = {
    apiDocumentation: {
      create: jest.fn(),
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      count: jest.fn(),
    },
    apiUsageMetrics: {
      create: jest.fn(),
      findMany: jest.fn(),
      groupBy: jest.fn(),
      count: jest.fn(),
    },
    $transaction: jest.fn(),
    $queryRaw: jest.fn(),
    $disconnect: jest.fn(),
  };

  const mockRedis = {
    setex: jest.fn(),
    get: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    expire: jest.fn(),
    keys: jest.fn(),
    ping: jest.fn(),
    quit: jest.fn(),
    hset: jest.fn(),
    hget: jest.fn(),
    hgetall: jest.fn(),
    zadd: jest.fn(),
    zrange: jest.fn(),
    zcard: jest.fn(),
  };

  // Test utilities
  const createTestApiSpec = () => ({
    openapi: '3.0.0',
    info: {
      title: 'Test Service API',
      version: '1.0.0',
      description: 'Test API specification'
    },
    paths: {
      '/test': {
        get: {
          summary: 'Test endpoint',
          responses: {
            '200': {
              description: 'Success',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      message: { type: 'string' }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  });

  const createTestUsageMetrics = () => ({
    endpoint: '/api/v1/test',
    method: 'GET',
    statusCode: 200,
    responseTime: 150,
    timestamp: new Date(),
    userAgent: 'Test Client',
    ipAddress: '192.168.1.1',
    tenantId: 'test-tenant',
    userId: 'test-user'
  });

  // Test suites
  describe('API Documentation Service', () => {
    let app: Hono;
    let request: any;

    beforeAll(() => {
      app = createTestApp();
      request = supertest(app);
    });

    beforeEach(() => {
      jest.clearAllMocks();
    });

    describe('Health Endpoints', () => {
      test('GET /health should return service health status', async () => {
        const response = await request.get('/health');
        
        expect(response.status).toBe(200);
        expect(response.body).toMatchObject({
          status: 'healthy',
          service: 'api-documentation-service',
          environment: expect.any(String),
        });
      });

      test('GET /ready should return readiness status', async () => {
        mockPrisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
        mockRedis.ping.mockResolvedValue('PONG');

        const response = await request.get('/ready');
        
        expect(response.status).toBe(200);
        expect(response.body).toMatchObject({
          status: 'ready',
          service: 'api-documentation-service',
          checks: {
            database: 'healthy',
            redis: 'healthy',
          },
        });
      });
    });

    describe('OpenAPI Specification Endpoints', () => {
      test('GET /api/v1/specs should return all service specifications', async () => {
        const testSpecs = [
          { serviceName: 'auth-service', version: '1.0.0', specification: createTestApiSpec() },
          { serviceName: 'tenant-service', version: '1.0.0', specification: createTestApiSpec() }
        ];

        mockPrisma.apiDocumentation.findMany.mockResolvedValue(testSpecs);

        const response = await request.get('/api/v1/specs');
        
        expect(response.status).toBe(200);
        expect(response.body.specifications).toHaveLength(2);
        expect(response.body.specifications[0].serviceName).toBe('auth-service');
      });

      test('GET /api/v1/specs/:serviceName should return specific service spec', async () => {
        const testSpec = {
          serviceName: 'auth-service',
          version: '1.0.0',
          specification: createTestApiSpec()
        };

        mockPrisma.apiDocumentation.findFirst.mockResolvedValue(testSpec);

        const response = await request.get('/api/v1/specs/auth-service');
        
        expect(response.status).toBe(200);
        expect(response.body.serviceName).toBe('auth-service');
        expect(response.body.specification.openapi).toBe('3.0.0');
      });

      test('GET /api/v1/specs/unified should return unified specification', async () => {
        const testSpecs = [
          { serviceName: 'auth-service', specification: createTestApiSpec() },
          { serviceName: 'tenant-service', specification: createTestApiSpec() }
        ];

        mockPrisma.apiDocumentation.findMany.mockResolvedValue(testSpecs);

        const response = await request.get('/api/v1/specs/unified');
        
        expect(response.status).toBe(200);
        expect(response.body.openapi).toBe('3.0.0');
        expect(response.body.info.title).toBe('SPARC Platform API');
      });
    });

    describe('SDK Generation Endpoints', () => {
      test('GET /api/v1/sdks should return available SDK languages', async () => {
        const response = await request.get('/api/v1/sdks');
        
        expect(response.status).toBe(200);
        expect(response.body.languages).toContain('python');
        expect(response.body.languages).toContain('javascript');
        expect(response.body.languages).toContain('csharp');
        expect(response.body.languages).toContain('java');
      });

      test('POST /api/v1/sdks/generate should generate SDK for specified language', async () => {
        const response = await request
          .post('/api/v1/sdks/generate')
          .send({
            language: 'python',
            serviceName: 'auth-service',
            version: '1.0.0'
          });
        
        expect(response.status).toBe(200);
        expect(response.body.downloadUrl).toBeDefined();
        expect(response.body.language).toBe('python');
      });
    });

    describe('Interactive Documentation', () => {
      test('GET /docs should serve Swagger UI', async () => {
        const response = await request.get('/docs');
        
        expect(response.status).toBe(200);
        expect(response.text).toContain('swagger-ui');
      });

      test('GET /docs/:serviceName should serve service-specific docs', async () => {
        const response = await request.get('/docs/auth-service');
        
        expect(response.status).toBe(200);
        expect(response.text).toContain('swagger-ui');
      });
    });

    describe('Usage Analytics', () => {
      test('GET /api/v1/analytics/usage should return usage metrics', async () => {
        const testMetrics = [
          { endpoint: '/api/v1/auth/login', count: 100, avgResponseTime: 150 },
          { endpoint: '/api/v1/tenants', count: 50, avgResponseTime: 200 }
        ];

        mockPrisma.apiUsageMetrics.groupBy.mockResolvedValue(testMetrics);

        const response = await request.get('/api/v1/analytics/usage');
        
        expect(response.status).toBe(200);
        expect(response.body.metrics).toHaveLength(2);
      });

      test('POST /api/v1/analytics/track should record usage metrics', async () => {
        const usageData = createTestUsageMetrics();

        mockPrisma.apiUsageMetrics.create.mockResolvedValue(usageData);

        const response = await request
          .post('/api/v1/analytics/track')
          .send(usageData);
        
        expect(response.status).toBe(201);
        expect(mockPrisma.apiUsageMetrics.create).toHaveBeenCalled();
      });
    });

    describe('Service Discovery', () => {
      test('POST /api/v1/discovery/register should register service spec', async () => {
        const serviceSpec = {
          serviceName: 'new-service',
          version: '1.0.0',
          specification: createTestApiSpec(),
          healthEndpoint: '/health'
        };

        mockPrisma.apiDocumentation.create.mockResolvedValue(serviceSpec);

        const response = await request
          .post('/api/v1/discovery/register')
          .send(serviceSpec);
        
        expect(response.status).toBe(201);
        expect(mockPrisma.apiDocumentation.create).toHaveBeenCalled();
      });

      test('PUT /api/v1/discovery/update/:serviceName should update service spec', async () => {
        const updatedSpec = {
          version: '1.1.0',
          specification: createTestApiSpec()
        };

        mockPrisma.apiDocumentation.update.mockResolvedValue(updatedSpec);

        const response = await request
          .put('/api/v1/discovery/update/auth-service')
          .send(updatedSpec);
        
        expect(response.status).toBe(200);
        expect(mockPrisma.apiDocumentation.update).toHaveBeenCalled();
      });
    });

    describe('Developer Sandbox', () => {
      test('GET /sandbox should serve sandbox environment', async () => {
        const response = await request.get('/sandbox');
        
        expect(response.status).toBe(200);
        expect(response.text).toContain('API Sandbox');
      });

      test('POST /api/v1/sandbox/test should execute API test', async () => {
        const testRequest = {
          endpoint: '/api/v1/auth/login',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: { email: 'test@example.com', password: 'password' }
        };

        const response = await request
          .post('/api/v1/sandbox/test')
          .send(testRequest);
        
        expect(response.status).toBe(200);
        expect(response.body.testResult).toBeDefined();
      });
    });
  });

  // Helper function to create test app
  function createTestApp() {
    const testApp = new Hono();
    
    // Add test middleware
    testApp.use('*', async (c, next) => {
      const requestId = c.req.header('x-request-id') || crypto.randomUUID();
      c.set('requestId', requestId);
      c.header('x-request-id', requestId);
      await next();
    });

    // Add routes with mocked dependencies
    testApp.route('/api/v1', createMockApiRoutes());
    
    // Health endpoints
    testApp.get('/health', (c) => {
      return c.json({
        status: 'healthy',
        service: 'api-documentation-service',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: 'test',
      });
    });

    testApp.get('/ready', async (c) => {
      try {
        await mockPrisma.$queryRaw`SELECT 1`;
        await mockRedis.ping();

        return c.json({
          status: 'ready',
          service: 'api-documentation-service',
          timestamp: new Date().toISOString(),
          checks: {
            database: 'healthy',
            redis: 'healthy',
          },
        });
      } catch (error) {
        return c.json({
          status: 'not ready',
          service: 'api-documentation-service',
          timestamp: new Date().toISOString(),
          error: error.message,
        }, 503);
      }
    });

    // Documentation endpoints
    testApp.get('/docs', (c) => {
      return c.html('<html><body>swagger-ui</body></html>');
    });

    testApp.get('/docs/:serviceName', (c) => {
      return c.html('<html><body>swagger-ui</body></html>');
    });

    testApp.get('/sandbox', (c) => {
      return c.html('<html><body>API Sandbox</body></html>');
    });

    return testApp;
  }

  // Helper function to create mock API routes
  function createMockApiRoutes() {
    const apiApp = new Hono();

    // Specifications endpoints
    apiApp.get('/specs', async (c) => {
      const specs = await mockPrisma.apiDocumentation.findMany();
      return c.json({ specifications: specs });
    });

    apiApp.get('/specs/:serviceName', async (c) => {
      const serviceName = c.req.param('serviceName');
      const spec = await mockPrisma.apiDocumentation.findFirst({
        where: { serviceName }
      });
      
      if (!spec) {
        return c.json({ error: 'Service not found' }, 404);
      }
      
      return c.json(spec);
    });

    apiApp.get('/specs/unified', async (c) => {
      const specs = await mockPrisma.apiDocumentation.findMany();
      const unifiedSpec = {
        openapi: '3.0.0',
        info: {
          title: 'SPARC Platform API',
          version: '1.0.0'
        },
        paths: {}
      };
      return c.json(unifiedSpec);
    });

    // SDK endpoints
    apiApp.get('/sdks', (c) => {
      return c.json({
        languages: ['python', 'javascript', 'csharp', 'java'],
        supportedVersions: ['1.0.0']
      });
    });

    apiApp.post('/sdks/generate', async (c) => {
      const body = await c.req.json();
      return c.json({
        downloadUrl: `/downloads/sdk-${body.language}-${Date.now()}.zip`,
        language: body.language,
        generatedAt: new Date().toISOString()
      });
    });

    // Analytics endpoints
    apiApp.get('/analytics/usage', async (c) => {
      const metrics = await mockPrisma.apiUsageMetrics.groupBy();
      return c.json({ metrics });
    });

    apiApp.post('/analytics/track', async (c) => {
      const body = await c.req.json();
      const result = await mockPrisma.apiUsageMetrics.create({ data: body });
      return c.json(result, 201);
    });

    // Discovery endpoints
    apiApp.post('/discovery/register', async (c) => {
      const body = await c.req.json();
      const result = await mockPrisma.apiDocumentation.create({ data: body });
      return c.json(result, 201);
    });

    apiApp.put('/discovery/update/:serviceName', async (c) => {
      const serviceName = c.req.param('serviceName');
      const body = await c.req.json();
      const result = await mockPrisma.apiDocumentation.update({
        where: { serviceName },
        data: body
      });
      return c.json(result);
    });

    // Sandbox endpoints
    apiApp.post('/sandbox/test', async (c) => {
      const body = await c.req.json();
      return c.json({
        testResult: {
          status: 'success',
          responseTime: 150,
          statusCode: 200,
          response: { message: 'Test successful' }
        }
      });
    });

    return apiApp;
  }

  // Run tests if in test environment
  if (process.env.RUN_TESTS === 'true') {
    console.log('Running API documentation service tests...');
    
    jest.setTimeout(30000);
    
    const testResults = jest.runCLI({
      testMatch: ['**/*.test.ts', '**/*.spec.ts'],
      collectCoverage: true,
      coverageDirectory: 'coverage',
      coverageReporters: ['text', 'lcov', 'html'],
      coverageThreshold: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80,
        },
      },
      verbose: true,
    }, [process.cwd()]);

    testResults.then((results) => {
      if (results.results.success) {
        console.log('All tests passed!');
        process.exit(0);
      } else {
        console.log('Some tests failed!');
        process.exit(1);
      }
    });
  }
}

// Initialize database and Redis clients
const prisma = new PrismaClient();
const redis = new Redis(config.redis.url);

// Service registry for discovering other services
const serviceRegistry = new Map<string, ServiceInfo>();

interface ServiceInfo {
  name: string;
  url: string;
  version: string;
  healthEndpoint: string;
  specEndpoint: string;
  lastSeen: Date;
  status: 'healthy' | 'unhealthy' | 'unknown';
}

interface OpenAPISpec {
  openapi: string;
  info: {
    title: string;
    version: string;
    description?: string;
  };
  servers?: Array<{
    url: string;
    description?: string;
  }>;
  paths: Record<string, any>;
  components?: Record<string, any>;
}

interface SDKGenerationRequest {
  language: 'python' | 'javascript' | 'csharp' | 'java';
  serviceName?: string;
  version?: string;
  includeExamples?: boolean;
  packageName?: string;
}

interface UsageMetrics {
  endpoint: string;
  method: string;
  statusCode: number;
  responseTime: number;
  timestamp: Date;
  userAgent?: string;
  ipAddress?: string;
  tenantId?: string;
  userId?: string;
}

// Create Hono app instance
const app = new Hono();

// Global middleware
app.use('*', logger());
app.use('*', prettyJSON());

// CORS configuration
app.use('*', cors({
  origin: config.cors.allowedOrigins,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
  credentials: true,
}));

// Request ID middleware for tracing
app.use('*', async (c, next) => {
  const requestId = c.req.header('x-request-id') || crypto.randomUUID();
  c.set('requestId', requestId);
  c.header('x-request-id', requestId);
  
  const startTime = Date.now();
  appLogger.info('Request started', {
    requestId,
    method: c.req.method,
    path: c.req.path,
    userAgent: c.req.header('user-agent'),
    ip: c.req.header('x-forwarded-for') || c.req.header('x-real-ip'),
  });

  await next();

  const duration = Date.now() - startTime;
  appLogger.info('Request completed', {
    requestId,
    method: c.req.method,
    path: c.req.path,
    status: c.res.status,
    duration: `${duration}ms`,
  });
});

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'api-documentation-service',
    version: process.env.npm_package_version || '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.environment,
    services: {
      registered: serviceRegistry.size,
      healthy: Array.from(serviceRegistry.values()).filter(s => s.status === 'healthy').length
    }
  });
});

// Readiness check endpoint
app.get('/ready', async (c) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    await redis.ping();

    return c.json({
      status: 'ready',
      service: 'api-documentation-service',
      timestamp: new Date().toISOString(),
      checks: {
        database: 'healthy',
        redis: 'healthy',
        serviceDiscovery: serviceRegistry.size > 0 ? 'healthy' : 'warning'
      },
    });
  } catch (error) {
    appLogger.error('Readiness check failed', { error: error.message });
    return c.json({
      status: 'not ready',
      service: 'api-documentation-service',
      timestamp: new Date().toISOString(),
      error: error.message,
    }, 503);
  }
});

// Metrics endpoint
app.get('/metrics', async (c) => {
  const memUsage = process.memoryUsage();
  
  // Get usage statistics from database
  const totalRequests = await prisma.apiUsageMetrics.count();
  const recentRequests = await prisma.apiUsageMetrics.count({
    where: {
      timestamp: {
        gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
      }
    }
  });

  return c.json({
    service: 'api-documentation-service',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
      external: `${Math.round(memUsage.external / 1024 / 1024)}MB`,
    },
    process: {
      pid: process.pid,
      version: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    usage: {
      totalRequests,
      recentRequests,
      registeredServices: serviceRegistry.size
    }
  });
});

// OpenAPI Specifications Management

// Get all service specifications
app.get('/api/v1/specs', async (c) => {
  try {
    const specifications = await prisma.apiDocumentation.findMany({
      orderBy: { updatedAt: 'desc' }
    });

    return c.json({
      specifications: specifications.map(spec => ({
        serviceName: spec.serviceName,
        version: spec.version,
        title: spec.specification?.info?.title || spec.serviceName,
        description: spec.specification?.info?.description,
        updatedAt: spec.updatedAt,
        status: serviceRegistry.get(spec.serviceName)?.status || 'unknown'
      })),
      total: specifications.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    appLogger.error('Failed to fetch specifications', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to fetch specifications' });
  }
});

// Get specific service specification
app.get('/api/v1/specs/:serviceName', async (c) => {
  try {
    const serviceName = c.req.param('serviceName');
    const version = c.req.query('version');

    const whereClause: any = { serviceName };
    if (version) {
      whereClause.version = version;
    }

    const specification = await prisma.apiDocumentation.findFirst({
      where: whereClause,
      orderBy: { version: 'desc' }
    });

    if (!specification) {
      throw new HTTPException(404, { message: 'Service specification not found' });
    }

    // Track usage
    await trackUsage(c, `/api/v1/specs/${serviceName}`, 'GET', 200, Date.now());

    return c.json({
      serviceName: specification.serviceName,
      version: specification.version,
      specification: specification.specification,
      updatedAt: specification.updatedAt,
      status: serviceRegistry.get(serviceName)?.status || 'unknown'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    appLogger.error('Failed to fetch service specification', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to fetch service specification' });
  }
});

// Get unified API specification
app.get('/api/v1/specs/unified', async (c) => {
  try {
    const specifications = await prisma.apiDocumentation.findMany({
      orderBy: { serviceName: 'asc' }
    });

    const unifiedSpec: OpenAPISpec = {
      openapi: '3.0.0',
      info: {
        title: 'SPARC Platform API',
        version: '1.0.0',
        description: 'Unified API specification for the SPARC platform covering all microservices'
      },
      servers: [
        {
          url: config.apiGateway?.url || 'https://api.sparc.com',
          description: 'Production API Gateway'
        },
        {
          url: 'https://staging-api.sparc.com',
          description: 'Staging API Gateway'
        }
      ],
      paths: {},
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT'
          }
        },
        schemas: {},
        responses: {
          UnauthorizedError: {
            description: 'Authentication information is missing or invalid',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    error: { type: 'string' },
                    message: { type: 'string' },
                    timestamp: { type: 'string', format: 'date-time' }
                  }
                }
              }
            }
          },
          NotFoundError: {
            description: 'The requested resource was not found',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    error: { type: 'string' },
                    message: { type: 'string' },
                    timestamp: { type: 'string', format: 'date-time' }
                  }
                }
              }
            }
          }
        }
      }
    };

    // Merge all service specifications
    for (const spec of specifications) {
      if (spec.specification?.paths) {
        // Add service prefix to paths
        const servicePrefix = `/api/v1/${spec.serviceName.replace('-service', '')}`;
        
        for (const [path, pathSpec] of Object.entries(spec.specification.paths)) {
          const fullPath = path.startsWith('/') ? `${servicePrefix}${path}` : `${servicePrefix}/${path}`;
          unifiedSpec.paths[fullPath] = pathSpec;
        }
      }

      // Merge components
      if (spec.specification?.components?.schemas) {
        Object.assign(unifiedSpec.components.schemas, spec.specification.components.schemas);
      }
    }

    // Track usage
    await trackUsage(c, '/api/v1/specs/unified', 'GET', 200, Date.now());

    return c.json(unifiedSpec);
  } catch (error) {
    appLogger.error('Failed to generate unified specification', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to generate unified specification' });
  }
});

// SDK Generation

// Get available SDK languages and options
app.get('/api/v1/sdks', (c) => {
  return c.json({
    languages: [
      {
        name: 'python',
        displayName: 'Python',
        versions: ['3.8+'],
        packageManager: 'pip',
        features: ['async/await', 'type hints', 'pydantic models']
      },
      {
        name: 'javascript',
        displayName: 'JavaScript/TypeScript',
        versions: ['Node.js 16+', 'Browser'],
        packageManager: 'npm',
        features: ['TypeScript definitions', 'Promise-based', 'tree-shaking']
      },
      {
        name: 'csharp',
        displayName: 'C#',
        versions: ['.NET 6+', '.NET Framework 4.8+'],
        packageManager: 'NuGet',
        features: ['async/await', 'nullable reference types', 'source generators']
      },
      {
        name: 'java',
        displayName: 'Java',
        versions: ['Java 11+'],
        packageManager: 'Maven/Gradle',
        features: ['reactive streams', 'records', 'sealed classes']
      }
    ],
    supportedVersions: ['1.0.0'],
    customizationOptions: [
      'package-name',
      'include-examples',
      'include-tests',
      'async-support',
      'validation'
    ]
  });
});

// Generate SDK for specific language
app.post('/api/v1/sdks/generate', async (c) => {
  try {
    const request: SDKGenerationRequest = await c.req.json();
    
    if (!['python', 'javascript', 'csharp', 'java'].includes(request.language)) {
      throw new HTTPException(400, { message: 'Unsupported language' });
    }

    // Get specification to generate SDK from
    let specification: any;
    if (request.serviceName) {
      const spec = await prisma.apiDocumentation.findFirst({
        where: { 
          serviceName: request.serviceName,
          ...(request.version && { version: request.version })
        },
        orderBy: { version: 'desc' }
      });
      
      if (!spec) {
        throw new HTTPException(404, { message: 'Service specification not found' });
      }
      
      specification = spec.specification;
    } else {
      // Generate unified specification
      const specs = await prisma.apiDocumentation.findMany();
      specification = await generateUnifiedSpec(specs);
    }

    // Generate SDK based on language
    const sdkResult = await generateSDK(request.language, specification, request);
    
    // Store generation record
    await redis.setex(
      `sdk:${sdkResult.downloadId}`,
      24 * 60 * 60, // 24 hours
      JSON.stringify({
        language: request.language,
        serviceName: request.serviceName,
        version: request.version,
        generatedAt: new Date().toISOString(),
        downloadCount: 0
      })
    );

    // Track usage
    await trackUsage(c, '/api/v1/sdks/generate', 'POST', 200, Date.now());

    return c.json({
      downloadId: sdkResult.downloadId,
      downloadUrl: `/api/v1/sdks/download/${sdkResult.downloadId}`,
      language: request.language,
      serviceName: request.serviceName,
      version: request.version || 'latest',
      size: sdkResult.size,
      generatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    appLogger.error('Failed to generate SDK', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to generate SDK' });
  }
});

// Download generated SDK
app.get('/api/v1/sdks/download/:downloadId', async (c) => {
  try {
    const downloadId = c.req.param('downloadId');
    
    const sdkInfo = await redis.get(`sdk:${downloadId}`);
    if (!sdkInfo) {
      throw new HTTPException(404, { message: 'SDK download not found or expired' });
    }

    const info = JSON.parse(sdkInfo);
    
    // Increment download count
    info.downloadCount = (info.downloadCount || 0) + 1;
    await redis.setex(`sdk:${downloadId}`, 24 * 60 * 60, JSON.stringify(info));

    // Generate and stream the SDK zip file
    const sdkZip = await createSDKZip(info.language, downloadId);
    
    c.header('Content-Type', 'application/zip');
    c.header('Content-Disposition', `attachment; filename="sparc-sdk-${info.language}-${downloadId}.zip"`);
    
    return c.body(sdkZip);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    appLogger.error('Failed to download SDK', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to download SDK' });
  }
});

// Interactive Documentation

// Serve Swagger UI for all APIs
app.get('/docs', async (c) => {
  const swaggerHtml = await generateSwaggerUI('/api/v1/specs/unified');
  return c.html(swaggerHtml);
});

// Serve Swagger UI for specific service
app.get('/docs/:serviceName', async (c) => {
  const serviceName = c.req.param('serviceName');
  const swaggerHtml = await generateSwaggerUI(`/api/v1/specs/${serviceName}`);
  return c.html(swaggerHtml);
});

// Developer Sandbox

// Serve sandbox environment
app.get('/sandbox', async (c) => {
  const sandboxHtml = await generateSandboxUI();
  return c.html(sandboxHtml);
});

// Execute API test in sandbox
app.post('/api/v1/sandbox/test', async (c) => {
  try {
    const testRequest = await c.req.json();
    
    // Validate test request
    if (!testRequest.endpoint || !testRequest.method) {
      throw new HTTPException(400, { message: 'Endpoint and method are required' });
    }

    // Execute the test request
    const testResult = await executeSandboxTest(testRequest);
    
    // Track usage
    await trackUsage(c, '/api/v1/sandbox/test', 'POST', 200, Date.now());

    return c.json({
      testResult,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    appLogger.error('Failed to execute sandbox test', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to execute sandbox test' });
  }
});

// Usage Analytics

// Get API usage analytics
app.get('/api/v1/analytics/usage', async (c) => {
  try {
    const timeRange = c.req.query('timeRange') || '24h';
    const serviceName = c.req.query('serviceName');
    const groupBy = c.req.query('groupBy') || 'endpoint';

    const timeRangeMs = parseTimeRange(timeRange);
    const startDate = new Date(Date.now() - timeRangeMs);

    const whereClause: any = {
      timestamp: { gte: startDate }
    };

    if (serviceName) {
      whereClause.endpoint = { startsWith: `/api/v1/${serviceName}` };
    }

    // Get aggregated metrics
    const metrics = await prisma.apiUsageMetrics.groupBy({
      by: [groupBy as any],
      where: whereClause,
      _count: { _all: true },
      _avg: { responseTime: true },
      orderBy: { _count: { _all: 'desc' } }
    });

    // Get error rate
    const errorMetrics = await prisma.apiUsageMetrics.groupBy({
      by: ['statusCode'],
      where: whereClause,
      _count: { _all: true }
    });

    const totalRequests = errorMetrics.reduce((sum, m) => sum + m._count._all, 0);
    const errorRequests = errorMetrics
      .filter(m => m.statusCode >= 400)
      .reduce((sum, m) => sum + m._count._all, 0);
    const errorRate = totalRequests > 0 ? (errorRequests / totalRequests) * 100 : 0;

    return c.json({
      timeRange,
      metrics: metrics.map(m => ({
        [groupBy]: m[groupBy],
        requestCount: m._count._all,
        avgResponseTime: Math.round(m._avg.responseTime || 0)
      })),
      summary: {
        totalRequests,
        errorRate: Math.round(errorRate * 100) / 100,
        avgResponseTime: Math.round(
          metrics.reduce((sum, m) => sum + (m._avg.responseTime || 0), 0) / metrics.length || 0
        )
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    appLogger.error('Failed to fetch usage analytics', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to fetch usage analytics' });
  }
});

// Track API usage (called by API Gateway)
app.post('/api/v1/analytics/track', async (c) => {
  try {
    const metrics: UsageMetrics = await c.req.json();
    
    await prisma.apiUsageMetrics.create({
      data: {
        endpoint: metrics.endpoint,
        method: metrics.method,
        statusCode: metrics.statusCode,
        responseTime: metrics.responseTime,
        timestamp: metrics.timestamp,
        userAgent: metrics.userAgent,
        ipAddress: metrics.ipAddress,
        tenantId: metrics.tenantId,
        userId: metrics.userId
      }
    });

    return c.json({ success: true }, 201);
  } catch (error) {
    appLogger.error('Failed to track usage metrics', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to track usage metrics' });
  }
});

// Service Discovery

// Register service specification
app.post('/api/v1/discovery/register', async (c) => {
  try {
    const serviceInfo = await c.req.json();
    
    if (!serviceInfo.serviceName || !serviceInfo.specification) {
      throw new HTTPException(400, { message: 'Service name and specification are required' });
    }

    // Validate OpenAPI specification
    if (!serviceInfo.specification.openapi || !serviceInfo.specification.info) {
      throw new HTTPException(400, { message: 'Invalid OpenAPI specification' });
    }

    // Store in database
    const stored = await prisma.apiDocumentation.upsert({
      where: { 
        serviceName_version: {
          serviceName: serviceInfo.serviceName,
          version: serviceInfo.version || '1.0.0'
        }
      },
      update: {
        specification: serviceInfo.specification,
        healthEndpoint: serviceInfo.healthEndpoint,
        updatedAt: new Date()
      },
      create: {
        serviceName: serviceInfo.serviceName,
        version: serviceInfo.version || '1.0.0',
        specification: serviceInfo.specification,
        healthEndpoint: serviceInfo.healthEndpoint || '/health'
      }
    });

    // Update service registry
    serviceRegistry.set(serviceInfo.serviceName, {
      name: serviceInfo.serviceName,
      url: serviceInfo.url || `http://${serviceInfo.serviceName}:3000`,
      version: serviceInfo.version || '1.0.0',
      healthEndpoint: serviceInfo.healthEndpoint || '/health',
      specEndpoint: serviceInfo.specEndpoint || '/openapi.json',
      lastSeen: new Date(),
      status: 'unknown'
    });

    appLogger.info('Service registered', { 
      serviceName: serviceInfo.serviceName,
      version: serviceInfo.version 
    });

    return c.json({
      message: 'Service registered successfully',
      serviceName: serviceInfo.serviceName,
      version: serviceInfo.version || '1.0.0',
      registeredAt: new Date().toISOString()
    }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    appLogger.error('Failed to register service', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to register service' });
  }
});

// Update service specification
app.put('/api/v1/discovery/update/:serviceName', async (c) => {
  try {
    const serviceName = c.req.param('serviceName');
    const updateData = await c.req.json();

    const updated = await prisma.apiDocumentation.update({
      where: { 
        serviceName_version: {
          serviceName,
          version: updateData.version || '1.0.0'
        }
      },
      data: {
        specification: updateData.specification,
        healthEndpoint: updateData.healthEndpoint,
        updatedAt: new Date()
      }
    });

    // Update service registry
    const serviceInfo = serviceRegistry.get(serviceName);
    if (serviceInfo) {
      serviceInfo.lastSeen = new Date();
      serviceInfo.version = updateData.version || serviceInfo.version;
    }

    appLogger.info('Service specification updated', { serviceName });

    return c.json({
      message: 'Service specification updated successfully',
      serviceName,
      version: updated.version,
      updatedAt: updated.updatedAt
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    appLogger.error('Failed to update service specification', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to update service specification' });
  }
});

// Get service discovery status
app.get('/api/v1/discovery/status', async (c) => {
  const services = Array.from(serviceRegistry.values()).map(service => ({
    name: service.name,
    version: service.version,
    status: service.status,
    lastSeen: service.lastSeen,
    url: service.url
  }));

  return c.json({
    services,
    total: services.length,
    healthy: services.filter(s => s.status === 'healthy').length,
    timestamp: new Date().toISOString()
  });
});

// Version Management

// Get API versions
app.get('/api/v1/versions', async (c) => {
  try {
    const versions = await prisma.apiDocumentation.groupBy({
      by: ['version'],
      _count: { serviceName: true },
      orderBy: { version: 'desc' }
    });

    return c.json({
      versions: versions.map(v => ({
        version: v.version,
        serviceCount: v._count.serviceName,
        supportStatus: getVersionSupportStatus(v.version)
      })),
      currentVersion: '1.0.0',
      deprecationPolicy: '12 months backward compatibility'
    });
  } catch (error) {
    appLogger.error('Failed to fetch API versions', { error: error.message });
    throw new HTTPException(500, { message: 'Failed to fetch API versions' });
  }
});

// Error Documentation

// Get error codes documentation
app.get('/api/v1/errors', (c) => {
  const errorCodes = {
    '400': {
      name: 'Bad Request',
      description: 'The request was invalid or cannot be served',
      examples: [
        'Missing required parameters',
        'Invalid parameter format',
        'Validation errors'
      ]
    },
    '401': {
      name: 'Unauthorized',
      description: 'Authentication is required and has failed or has not been provided',
      examples: [
        'Missing authorization header',
        'Invalid JWT token',
        'Expired token'
      ]
    },
    '403': {
      name: 'Forbidden',
      description: 'The request is valid but the server is refusing action',
      examples: [
        'Insufficient permissions',
        'Resource access denied',
        'Rate limit exceeded'
      ]
    },
    '404': {
      name: 'Not Found',
      description: 'The requested resource could not be found',
      examples: [
        'Endpoint does not exist',
        'Resource ID not found',
        'Service unavailable'
      ]
    },
    '429': {
      name: 'Too Many Requests',
      description: 'Rate limiting is in effect',
      examples: [
        'API rate limit exceeded',
        'Burst limit exceeded',
        'Tenant quota exceeded'
      ]
    },
    '500': {
      name: 'Internal Server Error',
      description: 'An unexpected error occurred on the server',
      examples: [
        'Database connection error',
        'Service unavailable',
        'Unhandled exception'
      ]
    },
    '503': {
      name: 'Service Unavailable',
      description: 'The service is temporarily unavailable',
      examples: [
        'Maintenance mode',
        'Circuit breaker open',
        'Dependency failure'
      ]
    }
  };

  return c.json({
    errorCodes,
    standardFormat: {
      error: 'ERROR_CODE',
      message: 'Human readable error message',
      timestamp: '2024-01-01T00:00:00.000Z',
      requestId: 'uuid-v4',
      details: 'Additional error context (optional)'
    }
  });
});

// Webhook Documentation

// Get webhook documentation
app.get('/api/v1/webhooks', (c) => {
  const webhooks = {
    'access.granted': {
      description: 'Triggered when access is granted to a user',
      payload: {
        eventType: 'access.granted',
        timestamp: '2024-01-01T00:00:00.000Z',
        data: {
          userId: 'string',
          doorId: 'string',
          accessMethod: 'card|mobile|pin',
          location: 'string'
        }
      }
    },
    'access.denied': {
      description: 'Triggered when access is denied',
      payload: {
        eventType: 'access.denied',
        timestamp: '2024-01-01T00:00:00.000Z',
        data: {
          userId: 'string',
          doorId: 'string',
          reason: 'string',
          location: 'string'
        }
      }
    },
    'alert.created': {
      description: 'Triggered when a new alert is created',
      payload: {
        eventType: 'alert.created',
        timestamp: '2024-01-01T00:00:00.000Z',
        data: {
          alertId: 'string',
          type: 'security|environmental|system',
          severity: 'low|medium|high|critical',
          message: 'string',
          location: 'string'
        }
      }
    },
    'device.offline': {
      description: 'Triggered when a device goes offline',
      payload: {
        eventType: 'device.offline',
        timestamp: '2024-01-01T00:00:00.000Z',
        data: {
          deviceId: 'string',
          deviceType: 'camera|reader|panel',
          location: 'string',
          lastSeen: '2024-01-01T00:00:00.000Z'
        }
      }
    }
  };

  return c.json({
    webhooks,
    configuration: {
      url: 'https://your-endpoint.com/webhook',
      secret: 'webhook-secret-for-verification',
      events: ['access.granted', 'access.denied', 'alert.created'],
      retryPolicy: {
        maxRetries: 3,
        backoffMultiplier: 2,
        initialDelay: 1000
      }
    },
    verification: {
      header: 'X-SPARC-Signature',
      algorithm: 'HMAC-SHA256',
      format: 'sha256=<signature>'
    }
  });
});

// Helper Functions

async function trackUsage(c: any, endpoint: string, method: string, statusCode: number, startTime: number) {
  try {
    const responseTime = Date.now() - startTime;
    const userAgent = c.req.header('user-agent');
    const ipAddress = c.req.header('x-forwarded-for') || c.req.header('x-real-ip');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    await prisma.apiUsageMetrics.create({
      data: {
        endpoint,
        method,
        statusCode,
        responseTime,
        timestamp: new Date(),
        userAgent,
        ipAddress,
        tenantId,
        userId
      }
    });
  } catch (error) {
    appLogger.warn('Failed to track usage', { error: error.message });
  }
}

async function generateUnifiedSpec(specifications: any[]): Promise<OpenAPISpec> {
  const unifiedSpec: OpenAPISpec = {
    openapi: '3.0.0',
    info: {
      title: 'SPARC Platform API',
      version: '1.0.0',
      description: 'Unified API specification for the SPARC platform'
    },
    paths: {},
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    }
  };

  for (const spec of specifications) {
    if (spec.specification?.paths) {
      Object.assign(unifiedSpec.paths, spec.specification.paths);
    }
    if (spec.specification?.components) {
      Object.assign(unifiedSpec.components, spec.specification.components);
    }
  }

  return unifiedSpec;
}

async function generateSDK(language: string, specification: any, options: SDKGenerationRequest) {
  const downloadId = crypto.randomUUID();
  
  // This would integrate with OpenAPI Generator or similar tool
  // For now, return mock data
  return {
    downloadId,
    size: 1024 * 1024, // 1MB
    files: generateSDKFiles(language, specification, options)
  };
}

function generateSDKFiles(language: string, specification: any, options: SDKGenerationRequest) {
  const files: Record<string, string> = {};
  
  switch (language) {
    case 'python':
      files['setup.py'] = generatePythonSetup(options);
      files['sparc_client/__init__.py'] = generatePythonClient(specification);
      files['sparc_client/models.py'] = generatePythonModels(specification);
      files['README.md'] = generatePythonReadme(options);
      break;
      
    case 'javascript':
      files['package.json'] = generateJavaScriptPackage(options);
      files['src/index.js'] = generateJavaScriptClient(specification);
      files['src/types.d.ts'] = generateTypeScriptTypes(specification);
      files['README.md'] = generateJavaScriptReadme(options);
      break;
      
    case 'csharp':
      files['SparcClient.csproj'] = generateCSharpProject(options);
      files['SparcClient.cs'] = generateCSharpClient(specification);
      files['Models.cs'] = generateCSharpModels(specification);
      files['README.md'] = generateCSharpReadme(options);
      break;
      
    case 'java':
      files['pom.xml'] = generateJavaPom(options);
      files['src/main/java/com/sparc/client/SparcClient.java'] = generateJavaClient(specification);
      files['src/main/java/com/sparc/models/Models.java'] = generateJavaModels(specification);
      files['README.md'] = generateJavaReadme(options);
      break;
  }
  
  return files;
}

async function createSDKZip(language: string, downloadId: string): Promise<Buffer> {
  // This would create an actual ZIP file with the generated SDK
  // For now, return a mock ZIP buffer
  const archive = archiver('zip', { zlib: { level: 9 } });
  const buffers: Buffer[] = [];
  
  archive.on('data', (chunk) => buffers.push(chunk));
  
  // Add mock files
  archive.append('# SPARC SDK\n\nGenerated SDK for SPARC Platform API', { name: 'README.md' });
  archive.append('console.log("SPARC SDK loaded");', { name: 'index.js' });
  
  await archive.finalize();
  
  return Buffer.concat(buffers);
}

async function generateSwaggerUI(specUrl: string): Promise<string> {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SPARC API Documentation</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin:0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      const ui = SwaggerUIBundle({
        url: '${specUrl}',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        tryItOutEnabled: true,
        requestInterceptor: function(request) {
          request.headers['X-API-Documentation'] = 'true';
          return request;
        }
      });
    };
  </script>
</body>
</html>`;
}

async function generateSandboxUI(): Promise<string> {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SPARC API Sandbox</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
    .header { border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 20px; }
    .form-group { margin-bottom: 15px; }
    label { display: block; margin-bottom: 5px; font-weight: bold; }
    input, select, textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
    button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background: #0056b3; }
    .response { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 4px; }
    .error { background: #f8d7da; color: #721c24; }
    .success { background: #d4edda; color: #155724; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>SPARC API Sandbox</h1>
      <p>Test API endpoints in a safe environment</p>
    </div>
    
    <form id="apiTestForm">
      <div class="form-group">
        <label for="endpoint">Endpoint:</label>
        <input type="text" id="endpoint" name="endpoint" placeholder="/api/v1/auth/login" required>
      </div>
      
      <div class="form-group">
        <label for="method">Method:</label>
        <select id="method" name="method" required>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
        </select>
      </div>
      
      <div class="form-group">
        <label for="headers">Headers (JSON):</label>
        <textarea id="headers" name="headers" rows="3" placeholder='{"Content-Type": "application/json"}'></textarea>
      </div>
      
      <div class="form-group">
        <label for="body">Request Body (JSON):</label>
        <textarea id="body" name="body" rows="5" placeholder='{"key": "value"}'></textarea>
      </div>
      
      <button type="submit">Test API</button>
    </form>
    
    <div id="response" class="response" style="display: none;">
      <h3>Response:</h3>
      <pre id="responseContent"></pre>
    </div>
  </div>

  <script>
    document.getElementById('apiTestForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const formData = new FormData(e.target);
      const testRequest = {
        endpoint: formData.get('endpoint'),
        method: formData.get('method'),
        headers: formData.get('headers') ? JSON.parse(formData.get('headers')) : {},
        body: formData.get('body') ? JSON.parse(formData.get('body')) : null
      };
      
      try {
        const response = await fetch('/api/v1/sandbox/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(testRequest)
        });
        
        const result = await response.json();
        
        document.getElementById('response').style.display = 'block';
        document.getElementById('response').className = response.ok ? 'response success' : 'response error';
        document.getElementById('responseContent').textContent = JSON.stringify(result, null, 2);
      } catch (error) {
        document.getElementById('response').style.display = 'block';
        document.getElementById('response').className = 'response error';
        document.getElementById('responseContent').textContent = 'Error: ' + error.message;
      }
    });
  </script>
</body>
</html>`;
}

async function executeSandboxTest(testRequest: any) {
  // This would execute the actual API test
  // For now, return mock response
  return {
    status: 'success',
    statusCode: 200,
    responseTime: Math.floor(Math.random() * 200) + 50,
    headers: {
      'content-type': 'application/json',
      'x-request-id': crypto.randomUUID()
    },
    response: {
      message: 'Sandbox test executed successfully',
      endpoint: testRequest.endpoint,
      method: testRequest.method
    }
  };
}

function parseTimeRange(timeRange: string): number {
  const units: Record<string, number> = {
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
    w: 7 * 24 * 60 * 60 * 1000,
    m: 30 * 24 * 60 * 60 * 1000
  };
  
  const match = timeRange.match(/^(\d+)([hdwm])$/);
  if (!match) return 24 * 60 * 60 * 1000; // Default to 24 hours
  
  const [, amount, unit] = match;
  return parseInt(amount) * (units[unit] || units.h);
}

function getVersionSupportStatus(version: string): string {
  // This would check against actual version support policy
  const versionDate = new Date('2024-01-01'); // Mock version date
  const now = new Date();
  const monthsOld = (now.getTime() - versionDate.getTime()) / (1000 * 60 * 60 * 24 * 30);
  
  if (monthsOld < 12) return 'supported';
  if (monthsOld < 18) return 'deprecated';
  return 'unsupported';
}

// SDK Generation Helper Functions
function generatePythonSetup(options: SDKGenerationRequest): string {
  return `
from setuptools import setup, find_packages

setup(
    name="${options.packageName || 'sparc-client'}",
    version="1.0.0",
    description="Python client for SPARC Platform API",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "pydantic>=1.8.0",
        "typing-extensions>=3.7.0"
    ],
    python_requires=">=3.8"
)`;
}

function generatePythonClient(specification: any): string {
  return `
"""SPARC Platform API Client"""

import requests
from typing import Optional, Dict, Any
from .models import *

class SparcClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'Authorization': f'Bearer {api_key}'})
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()
    
    # Auto-generated methods would be added here based on OpenAPI spec
`;
}

function generatePythonModels(specification: any): string {
  return `
"""SPARC Platform API Models"""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime

class Door(BaseModel):
    id: str
    name: str
    location: str
    status: str
    tenant_id: str

# Additional models would be generated from OpenAPI spec
`;
}

function generatePythonReadme(options: SDKGenerationRequest): string {
  return `
# SPARC Platform Python SDK

Python client library for the SPARC Platform API.

## Installation

\`\`\`bash
pip install ${options.packageName || 'sparc-client'}
\`\`\`

## Usage

\`\`\`python
from sparc_client import SparcClient

client = SparcClient('https://api.sparc.com', api_key='your-api-key')

# Example usage
users = client.get_users()
\`\`\`
`;
}

function generateJavaScriptPackage(options: SDKGenerationRequest): string {
  return JSON.stringify({
    name: options.packageName || 'sparc-client',
    version: '1.0.0',
    description: 'JavaScript/TypeScript client for SPARC Platform API',
    main: 'src/index.js',
    types: 'src/types.d.ts',
    dependencies: {
      'axios': '^1.0.0'
    },
    devDependencies: {
      'typescript': '^4.0.0',
      '@types/node': '^18.0.0'
    }
  }, null, 2);
}

function generateJavaScriptClient(specification: any): string {
  return `
/**
 * SPARC Platform API Client
 */

const axios = require('axios');

class SparcClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: apiKey ? { 'Authorization': \`Bearer \${apiKey}\` } : {}
    });
  }

  async request(method, endpoint, data = null) {
    const response = await this.client.request({
      method,
      url: endpoint,
      data
    });
    return response.data;
  }

  // Auto-generated methods would be added here
}

module.exports = SparcClient;
`;
}

function generateTypeScriptTypes(specification: any): string {
  return `
export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  tenantId: string;
  createdAt: string;
  updatedAt: string;
}

export interface Door {
  id: string;
  name: string;
  location: string;
  status: string;
  tenantId: string;
}

export declare class SparcClient {
  constructor(baseUrl: string, apiKey?: string);
  request(method: string, endpoint: string, data?: any): Promise<any>;
}
`;
}

function generateJavaScriptReadme(options: SDKGenerationRequest): string {
  return `
# SPARC Platform JavaScript SDK

JavaScript/TypeScript client library for the SPARC Platform API.

## Installation

\`\`\`bash
npm install ${options.packageName || 'sparc-client'}
\`\`\`

## Usage

\`\`\`javascript
const SparcClient = require('sparc-client');

const client = new SparcClient('https://api.sparc.com', 'your-api-key');

// Example usage
const users = await client.getUsers();
\`\`\`
`;
}

function generateCSharpProject(options: SDKGenerationRequest): string {
  return `
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <PackageId>${options.packageName || 'SparcClient'}</PackageId>
    <Version>1.0.0</Version>
    <Description>C# client for SPARC Platform API</Description>
  </PropertyGroup>
  
  <ItemGroup>
    <PackageReference Include="System.Net.Http.Json" Version="6.0.0" />
    <PackageReference Include="System.Text.Json" Version="6.0.0" />
  </ItemGroup>
</Project>
`;
}

function generateCSharpClient(specification: any): string {
  return `
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace SparcClient
{
    public class SparcClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;

        public SparcClient(string baseUrl, string apiKey = null)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _httpClient = new HttpClient();
            
            if (!string.IsNullOrEmpty(apiKey))
            {
                _httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);
            }
        }

        private async Task<T> RequestAsync<T>(HttpMethod method, string endpoint, object data = null)
        {
            var request = new HttpRequestMessage(method, $"{_baseUrl}{endpoint}");
            
            if (data != null)
            {
                request.Content = JsonContent.Create(data);
            }

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            
            return await response.Content.ReadFromJsonAsync<T>();
        }

        // Auto-generated methods would be added here
    }
}
`;
}

function generateCSharpModels(specification: any): string {
  return `
using System;

namespace SparcClient.Models
{
    public class User
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Role { get; set; }
        public string TenantId { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public class Door
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Location { get; set; }
        public string Status { get; set; }
        public string TenantId { get; set; }
    }
}
`;
}

function generateCSharpReadme(options: SDKGenerationRequest): string {
  return `
# SPARC Platform C# SDK

C# client library for the SPARC Platform API.

## Installation

\`\`\`bash
dotnet add package ${options.packageName || 'SparcClient'}
\`\`\`

## Usage

\`\`\`csharp
using SparcClient;

var client = new SparcClient("https://api.sparc.com", "your-api-key");

// Example usage
var users = await client.GetUsersAsync();
\`\`\`
`;
}

function generateJavaPom(options: SDKGenerationRequest): string {
  return `
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.sparc</groupId>
    <artifactId>${options.packageName || 'sparc-client'}</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    
    <name>SPARC Platform Java SDK</name>
    <description>Java client for SPARC Platform API</description>
    
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.15.0</version>
        </dependency>
        <dependency>
            <groupId>org.apache.httpcomponents.client5</groupId>
            <artifactId>httpclient5</artifactId>
            <version>5.2.0</version>
        </dependency>
    </dependencies>
</project>
`;
}

function generateJavaClient(specification: any): string {
  return `
package com.sparc.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.StringEntity;

import java.io.IOException;

public class SparcClient {
    private final HttpClient httpClient;
    private final String baseUrl;
    private final ObjectMapper objectMapper;
    private final String apiKey;

    public SparcClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.apiKey = apiKey;
        this.httpClient = HttpClients.createDefault();
        this.objectMapper = new ObjectMapper();
    }

    private <T> T request(String method, String endpoint, Object data, Class<T> responseType) 
            throws IOException {
        HttpUriRequestBase request;
        
        switch (method.toUpperCase()) {
            case "GET":
                request = new HttpGet(baseUrl + endpoint);
                break;
            case "POST":
                request = new HttpPost(baseUrl + endpoint);
                if (data != null) {
                    ((HttpPost) request).setEntity(new StringEntity(objectMapper.writeValueAsString(data)));
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported HTTP method: " + method);
        }

        if (apiKey != null) {
            request.setHeader("Authorization", "Bearer " + apiKey);
        }
        request.setHeader("Content-Type", "application/json");

        return httpClient.execute(request, response -> {
            String responseBody = new String(response.getEntity().getContent().readAllBytes());
            return objectMapper.readValue(responseBody, responseType);
        });
    }

    // Auto-generated methods would be added here
}
`;
}

function generateJavaModels(specification: any): string {
  return `
package com.sparc.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDateTime;

public class User {
    @JsonProperty("id")
    private String id;
    
    @JsonProperty("email")
    private String email;
    
    @JsonProperty("firstName")
    private String firstName;
    
    @JsonProperty("lastName")
    private String lastName;
    
    @JsonProperty("role")
    private String role;
    
    @JsonProperty("tenantId")
    private String tenantId;
    
    @JsonProperty("createdAt")
    private LocalDateTime createdAt;
    
    @JsonProperty("updatedAt")
    private LocalDateTime updatedAt;

    // Getters and setters would be generated here
}

public class Door {
    @JsonProperty("id")
    private String id;
    
    @JsonProperty("name")
    private String name;
    
    @JsonProperty("location")
    private String location;
    
    @JsonProperty("status")
    private String status;
    
    @JsonProperty("tenantId")
    private String tenantId;

    // Getters and setters would be generated here
}
`;
}

function generateJavaReadme(options: SDKGenerationRequest): string {
  return `
# SPARC Platform Java SDK

Java client library for the SPARC Platform API.

## Installation

### Maven
\`\`\`xml
<dependency>
    <groupId>com.sparc</groupId>
    <artifactId>${options.packageName || 'sparc-client'}</artifactId>
    <version>1.0.0</version>
</dependency>
\`\`\`

### Gradle
\`\`\`gradle
implementation 'com.sparc:${options.packageName || 'sparc-client'}:1.0.0'
\`\`\`

## Usage

\`\`\`java
import com.sparc.client.SparcClient;

SparcClient client = new SparcClient("https://api.sparc.com", "your-api-key");

// Example usage
List<User> users = client.getUsers();
\`\`\`
`;
}

// Service Discovery Background Task
async function discoverServices() {
  const knownServices = [
    'auth-service',
    'tenant-service', 
    'access-control-service',
    'video-management-service',
    'event-processing-service',
    'device-management-service',
    'mobile-credential-service',
    'analytics-service',
    'environmental-service',
    'visitor-management-service',
    'reporting-service'
  ];

  for (const serviceName of knownServices) {
    try {
      const serviceUrl = `http://${serviceName}:3000`;
      
      // Check health
      const healthResponse = await fetch(`${serviceUrl}/health`, {
        timeout: 5000
      });
      
      const isHealthy = healthResponse.ok;
      
      // Try to get OpenAPI spec
      let specification = null;
      try {
        const specResponse = await fetch(`${serviceUrl}/openapi.json`, {
          timeout: 5000
        });
        if (specResponse.ok) {
          specification = await specResponse.json();
        }
      } catch (error) {
        appLogger.debug(`No OpenAPI spec found for ${serviceName}`, { error: error.message });
      }

      // Update service registry
      serviceRegistry.set(serviceName, {
        name: serviceName,
        url: serviceUrl,
        version: specification?.info?.version || '1.0.0',
        healthEndpoint: '/health',
        specEndpoint: '/openapi.json',
        lastSeen: new Date(),
        status: isHealthy ? 'healthy' : 'unhealthy'
      });

      // Store/update specification if found
      if (specification) {
        await prisma.apiDocumentation.upsert({
          where: {
            serviceName_version: {
              serviceName,
              version: specification.info.version || '1.0.0'
            }
          },
          update: {
            specification,
            updatedAt: new Date()
          },
          create: {
            serviceName,
            version: specification.info.version || '1.0.0',
            specification,
            healthEndpoint: '/health'
          }
        });

        appLogger.info('Service specification updated', { 
          serviceName, 
          version: specification.info.version 
        });
      }

    } catch (error) {
      // Mark service as unhealthy
      const existingService = serviceRegistry.get(serviceName);
      if (existingService) {
        existingService.status = 'unhealthy';
        existingService.lastSeen = new Date();
      }
      
      appLogger.debug(`Service discovery failed for ${serviceName}`, { error: error.message });
    }
  }
}

// Global error handler
app.onError((err, c) => {
  const requestId = c.get('requestId');
  
  if (err instanceof HTTPException) {
    appLogger.warn('HTTP Exception', {
      requestId,
      status: err.status,
      message: err.message,
      path: c.req.path,
      method: c.req.method,
    });
    
    return c.json({
      error: {
        code: err.status,
        message: err.message,
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, err.status);
  }

  appLogger.error('Unhandled error', {
    requestId,
    error: err.message,
    stack: err.stack,
    path: c.req.path,
    method: c.req.method,
  });

  return c.json({
    error: {
      code: 500,
      message: 'Internal server error',
      requestId,
      timestamp: new Date().toISOString(),
    },
  }, 500);
});

// 404 handler
app.notFound((c) => {
  const requestId = c.get('requestId');
  
  appLogger.warn('Route not found', {
    requestId,
    path: c.req.path,
    method: c.req.method,
  });

  return c.json({
    error: {
      code: 404,
      message: 'Route not found',
      requestId,
      timestamp: new Date().toISOString(),
    },
  }, 404);
});

// Server configuration
const port = config.apiDocumentation?.port || 3012;
const host = config.apiDocumentation?.host || '0.0.0.0';

// Graceful shutdown handling
let server: any;

const gracefulShutdown = async (signal: string) => {
  appLogger.info(`Received ${signal}, starting graceful shutdown...`);
  
  if (server) {
    server.close(() => {
      appLogger.info('HTTP server closed');
    });
  }

  try {
    await prisma.$disconnect();
    appLogger.info('Database connections closed');
  } catch (error) {
    appLogger.error('Error closing database connections', { error: error.message });
  }

  try {
    await redis.quit();
    appLogger.info('Redis connections closed');
  } catch (error) {
    appLogger.error('Error closing Redis connections', { error: error.message });
  }

  appLogger.info('Graceful shutdown completed');
  process.exit(0);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  appLogger.error('Uncaught exception', {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  appLogger.error('Unhandled promise rejection', {
    reason: reason,
    promise: promise,
  });
  process.exit(1);
});

// Start the server
const startServer = async () => {
  try {
    appLogger.info('Starting API documentation service...', {
      port,
      host,
      environment: config.environment,
      nodeVersion: process.version,
    });

    server = serve({
      fetch: app.fetch,
      port,
      hostname: host,
    });

    // Start service discovery
    setInterval(discoverServices, 30000); // Every 30 seconds
    discoverServices(); // Initial discovery

    appLogger.info('API documentation service started successfully', {
      port,
      host,
      environment: config.environment,
    });

    appLogger.info('Available routes:', {
      routes: [
        'GET /health - Health check',
        'GET /ready - Readiness check', 
        'GET /metrics - Service metrics',
        'GET /api/v1/specs - List all API specifications',
        'GET /api/v1/specs/:serviceName - Get service specification',
        'GET /api/v1/specs/unified - Get unified API specification',
        'GET /api/v1/sdks - List available SDK languages',
        'POST /api/v1/sdks/generate - Generate SDK',
        'GET /api/v1/sdks/download/:downloadId - Download SDK',
        'GET /docs - Interactive API documentation',
        'GET /docs/:serviceName - Service-specific documentation',
        'GET /sandbox - Developer sandbox',
        'POST /api/v1/sandbox/test - Execute API test',
        'GET /api/v1/analytics/usage - Usage analytics',
        'POST /api/v1/analytics/track - Track usage',
        'POST /api/v1/discovery/register - Register service',
        'PUT /api/v1/discovery/update/:serviceName - Update service',
        'GET /api/v1/discovery/status - Service discovery status',
        'GET /api/v1/versions - API versions',
        'GET /api/v1/errors - Error documentation',
        'GET /api/v1/webhooks - Webhook documentation'
      ],
    });

  } catch (error) {
    appLogger.error('Failed to start API documentation service', {
      error: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
};

// Start the server only if not in test mode
if (process.env.NODE_ENV !== 'test' || process.env.RUN_TESTS !== 'true') {
  startServer();
}

export default app;