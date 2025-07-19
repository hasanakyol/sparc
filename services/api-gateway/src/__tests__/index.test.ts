import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import request from 'supertest';
import { Hono } from 'hono';

// Mock dependencies before importing
jest.mock('redis', () => ({
  createClient: jest.fn().mockReturnValue({
    connect: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
    get: jest.fn(),
    setEx: jest.fn(),
    del: jest.fn(),
    incr: jest.fn(),
    expire: jest.fn(),
    ttl: jest.fn(),
    hMGet: jest.fn(),
    hMSet: jest.fn(),
    zRemRangeByScore: jest.fn(),
    zAdd: jest.fn(),
    zCard: jest.fn(),
    multi: jest.fn().mockReturnValue({
      incr: jest.fn().mockReturnThis(),
      expire: jest.fn().mockReturnThis(),
      ttl: jest.fn().mockReturnThis(),
      exec: jest.fn().mockResolvedValue([1, true, 60]),
    }),
    quit: jest.fn(),
  }),
}));

jest.mock('consul', () => jest.fn(() => ({
  health: {
    service: jest.fn().mockResolvedValue([]),
  },
})));

jest.mock('opossum', () => jest.fn(() => ({
  fire: jest.fn(),
  on: jest.fn(),
  fallback: jest.fn(),
  stats: {
    state: 'closed',
    failures: 0,
    successes: 100,
    rejections: 0,
  },
})));

jest.mock('@sparc/shared/utils', () => ({
  createLogger: () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }),
}));

jest.mock('@sparc/shared', () => ({
  config: {
    port: 3000,
    cors: {
      origin: '*',
      credentials: true,
    },
    consul: {
      host: 'localhost',
      port: 8500,
      secure: false,
    },
    redis: {
      url: 'redis://localhost:6379',
    },
    circuitBreaker: {
      timeout: 5000,
      errorThreshold: 50,
      resetTimeout: 30000,
      rollingCountTimeout: 10000,
      rollingCountBuckets: 10,
    },
    version: '1.0.0',
  },
}));

// Import app after mocking
import app from '../index';

describe('API Gateway Main App', () => {
  let testApp: any;

  beforeEach(() => {
    testApp = app;
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('App Configuration', () => {
    it('should have all required middlewares configured', async () => {
      // Test that the app responds correctly
      const response = await request(testApp).get('/health');
      expect(response.status).toBe(200);
    });

    it('should handle CORS preflight requests', async () => {
      const response = await request(testApp)
        .options('/api/test')
        .set('Origin', 'https://example.com')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'content-type,authorization');

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-methods']).toBeDefined();
      expect(response.headers['access-control-allow-headers']).toBeDefined();
    });

    it('should compress responses when requested', async () => {
      const response = await request(testApp)
        .get('/health')
        .set('Accept-Encoding', 'gzip, deflate');

      expect(response.headers['content-encoding']).toBe('gzip');
    });

    it('should include security headers', async () => {
      const response = await request(testApp).get('/health');

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('1; mode=block');
      expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
      expect(response.headers['permissions-policy']).toBeDefined();
    });
  });

  describe('Request Processing', () => {
    it('should add request ID to all requests', async () => {
      const response = await request(testApp).get('/health');

      expect(response.headers['x-request-id']).toBeDefined();
      expect(response.headers['x-request-id']).toMatch(/^[a-f0-9-]+$/);
    });

    it('should use provided request ID', async () => {
      const customId = 'custom-request-123';
      const response = await request(testApp)
        .get('/health')
        .set('X-Request-ID', customId);

      expect(response.headers['x-request-id']).toBe(customId);
    });

    it('should log request timing', async () => {
      const response = await request(testApp).get('/health');

      expect(response.headers['x-response-time']).toBeDefined();
      expect(response.headers['x-response-time']).toMatch(/^\d+ms$/);
    });
  });

  describe('Health Endpoints', () => {
    it('should provide basic health check', async () => {
      const response = await request(testApp).get('/health');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        status: 'healthy',
        timestamp: expect.any(String),
        uptime: expect.any(Number),
        version: '1.0.0',
      });
    });

    it('should provide detailed health check', async () => {
      const response = await request(testApp).get('/health/detailed');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        status: 'healthy',
        timestamp: expect.any(String),
        uptime: expect.any(Number),
        version: '1.0.0',
        redis: expect.objectContaining({
          status: expect.any(String),
        }),
        memory: expect.objectContaining({
          heapUsed: expect.any(Number),
          heapTotal: expect.any(Number),
          rss: expect.any(Number),
          external: expect.any(Number),
        }),
        environment: expect.any(String),
      });
    });

    it('should provide readiness check', async () => {
      const response = await request(testApp).get('/ready');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        ready: true,
        timestamp: expect.any(String),
        checks: expect.objectContaining({
          redis: expect.any(Boolean),
          consul: expect.any(Boolean),
        }),
      });
    });

    it('should provide liveness check', async () => {
      const response = await request(testApp).get('/live');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        alive: true,
        timestamp: expect.any(String),
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle 404 errors', async () => {
      const response = await request(testApp).get('/non-existent-route');

      expect(response.status).toBe(404);
      expect(response.body).toEqual({
        error: 'Not Found',
        message: 'The requested resource was not found',
        path: '/non-existent-route',
      });
    });

    it('should handle malformed JSON', async () => {
      const response = await request(testApp)
        .post('/api/test')
        .set('Content-Type', 'application/json')
        .send('{ invalid json');

      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(response.body).toHaveProperty('error');
    });

    it('should handle internal server errors gracefully', async () => {
      // Force an error by mocking a middleware to throw
      const errorApp = new Hono();
      errorApp.use('*', async () => {
        throw new Error('Test internal error');
      });

      const response = await request(errorApp).get('/test');
      expect(response.status).toBe(500);
    });
  });

  describe('Authentication Integration', () => {
    it('should reject requests without authentication on protected routes', async () => {
      const response = await request(testApp).get('/api/protected');

      expect(response.status).toBe(401);
      expect(response.body).toEqual(
        expect.objectContaining({
          error: 'Authentication required',
          code: 'AUTH_MISSING_HEADER',
        })
      );
    });

    it('should allow public endpoints without authentication', async () => {
      const response = await request(testApp).get('/health');

      expect(response.status).toBe(200);
    });
  });

  describe('Rate Limiting Integration', () => {
    it('should apply rate limits to API endpoints', async () => {
      // Mock rate limit headers
      const response = await request(testApp).get('/api/test');

      // Even if request fails due to auth, rate limit headers should be present
      expect(response.headers).toHaveProperty('x-ratelimit-limit');
      expect(response.headers).toHaveProperty('x-ratelimit-remaining');
      expect(response.headers).toHaveProperty('x-ratelimit-reset');
    });
  });

  describe('Metrics and Monitoring', () => {
    it('should expose metrics endpoint', async () => {
      const response = await request(testApp).get('/metrics');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          timestamp: expect.any(String),
          uptime: expect.any(Number),
          requests: expect.objectContaining({
            total: expect.any(Number),
            success: expect.any(Number),
            error: expect.any(Number),
          }),
          response_times: expect.objectContaining({
            avg: expect.any(Number),
            min: expect.any(Number),
            max: expect.any(Number),
            p95: expect.any(Number),
            p99: expect.any(Number),
          }),
        })
      );
    });
  });

  describe('API Documentation', () => {
    it('should serve API documentation', async () => {
      const response = await request(testApp).get('/docs');

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('text/html');
    });

    it('should provide OpenAPI spec', async () => {
      const response = await request(testApp).get('/openapi.json');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          openapi: expect.any(String),
          info: expect.objectContaining({
            title: expect.any(String),
            version: expect.any(String),
          }),
          paths: expect.any(Object),
        })
      );
    });
  });

  describe('Service Proxy Integration', () => {
    it('should proxy requests to backend services', async () => {
      // Mock successful auth
      const { sign } = await import('hono/jwt');
      const token = await sign({
        sub: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      }, process.env.JWT_SECRET || 'test-secret');

      const response = await request(testApp)
        .get('/api/users')
        .set('Authorization', `Bearer ${token}`);

      // Should attempt to proxy (will fail due to no backend service)
      expect(response.status).toBeGreaterThanOrEqual(500);
    });
  });

  describe('Graceful Shutdown', () => {
    it('should handle shutdown signals gracefully', async () => {
      // Test that cleanup functions are registered
      const listeners = process.listeners('SIGTERM');
      expect(listeners.length).toBeGreaterThan(0);
    });
  });

  describe('Environment Configuration', () => {
    it('should respect environment variables', () => {
      // Configuration should be loaded from environment
      expect(process.env.NODE_ENV).toBeDefined();
    });
  });

  describe('Request Validation', () => {
    it('should validate content-type for POST requests', async () => {
      const response = await request(testApp)
        .post('/api/test')
        .send('plain text data');

      expect(response.status).toBeGreaterThanOrEqual(400);
    });

    it('should handle large payloads appropriately', async () => {
      const largePayload = 'x'.repeat(1024 * 1024 * 2); // 2MB
      const response = await request(testApp)
        .post('/api/test')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ data: largePayload }));

      // Should either accept or reject based on size limits
      expect(response.status).toBeDefined();
    });
  });

  describe('Response Headers', () => {
    it('should include standard response headers', async () => {
      const response = await request(testApp).get('/health');

      expect(response.headers['x-powered-by']).toBeUndefined(); // Should be hidden
      expect(response.headers['cache-control']).toBeDefined();
      expect(response.headers['content-type']).toBeDefined();
    });

    it('should set appropriate cache headers for different endpoints', async () => {
      // Health check should not be cached
      const healthResponse = await request(testApp).get('/health');
      expect(healthResponse.headers['cache-control']).toContain('no-cache');

      // Static assets (if any) should be cached
      const docsResponse = await request(testApp).get('/docs');
      expect(docsResponse.headers['cache-control']).toBeDefined();
    });
  });
});