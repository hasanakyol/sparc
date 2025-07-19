import { describe, it, expect, jest, beforeAll, afterAll, beforeEach } from '@jest/globals';
import request from 'supertest';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { AddressInfo } from 'net';
import { createClient } from 'redis';
import consul from 'consul';

// Import the main app
import app from '../../index';

// Mock external dependencies
jest.mock('redis');
jest.mock('consul');
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
    port: 0, // Use random port for tests
    consul: { host: 'localhost', port: 8500, secure: false },
    redis: { url: 'redis://localhost:6379' },
    circuitBreaker: {
      timeout: 1000, // Shorter timeout for tests
      errorThreshold: 50,
      resetTimeout: 1000,
      rollingCountTimeout: 5000,
      rollingCountBuckets: 5,
    },
    version: '1.0.0',
  },
}));

describe('API Gateway Integration Tests', () => {
  let server: any;
  let serverUrl: string;
  let mockRedisClient: any;
  let mockConsulClient: any;

  beforeAll(async () => {
    // Setup mock Redis
    mockRedisClient = {
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
      zCount: jest.fn(),
      zRevRange: jest.fn(),
      multi: jest.fn(),
      quit: jest.fn(),
    };

    const mockMulti = {
      incr: jest.fn().mockReturnThis(),
      expire: jest.fn().mockReturnThis(),
      ttl: jest.fn().mockReturnThis(),
      zRemRangeByScore: jest.fn().mockReturnThis(),
      zAdd: jest.fn().mockReturnThis(),
      zCard: jest.fn().mockReturnThis(),
      hMSet: jest.fn().mockReturnThis(),
      exec: jest.fn().mockResolvedValue([1, true, 60]),
    };
    mockRedisClient.multi.mockReturnValue(mockMulti);

    (createClient as jest.Mock).mockReturnValue(mockRedisClient);

    // Setup mock Consul
    mockConsulClient = {
      health: {
        service: jest.fn(),
      },
    };
    (consul as jest.Mock).mockReturnValue(mockConsulClient);

    // Start the server
    server = serve({
      fetch: app.fetch,
      port: 0, // Random port
    });

    // Wait for server to start and get the actual port
    await new Promise((resolve) => {
      server.on('listening', () => {
        const address = server.address() as AddressInfo;
        serverUrl = `http://localhost:${address.port}`;
        resolve(undefined);
      });
    });
  });

  afterAll(async () => {
    // Close the server
    await new Promise((resolve) => {
      server.close(resolve);
    });
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Health Check', () => {
    it('should return healthy status', async () => {
      const response = await request(serverUrl).get('/health');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        status: 'healthy',
        timestamp: expect.any(String),
        uptime: expect.any(Number),
        version: '1.0.0',
      });
    });

    it('should provide detailed health information', async () => {
      const response = await request(serverUrl).get('/health/detailed');

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        status: 'healthy',
        timestamp: expect.any(String),
        uptime: expect.any(Number),
        version: '1.0.0',
        redis: expect.any(Object),
        memory: expect.any(Object),
        environment: expect.any(String),
      });
    });
  });

  describe('Authentication Flow', () => {
    it('should reject requests without authentication to protected endpoints', async () => {
      // Mock service discovery
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'tenant-1',
            Service: 'tenant-service',
            Address: '10.0.0.1',
            Port: 3002,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const response = await request(serverUrl).get('/api/tenants');

      expect(response.status).toBe(401);
      expect(response.body).toEqual(
        expect.objectContaining({
          error: 'Authentication required',
          code: 'AUTH_MISSING_HEADER',
        })
      );
    });

    it('should reject requests with invalid JWT token', async () => {
      const response = await request(serverUrl)
        .get('/api/tenants')
        .set('Authorization', 'Bearer invalid.jwt.token');

      expect(response.status).toBe(401);
      expect(response.body).toEqual(
        expect.objectContaining({
          error: 'Invalid token',
          code: 'AUTH_INVALID_TOKEN',
        })
      );
    });

    it('should allow requests with valid JWT token', async () => {
      // Create a valid JWT token
      const { sign } = await import('hono/jwt');
      const payload = {
        sub: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        sessionId: 'session-abc',
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      };
      const token = await sign(payload, process.env.JWT_SECRET || 'test-secret');

      // Mock session validation
      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: 'user-123',
        active: true,
      }));

      // Mock service discovery and response
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'tenant-1',
            Service: 'tenant-service',
            Address: '10.0.0.1',
            Port: 3002,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      // Mock successful proxy response
      global.fetch = jest.fn().mockResolvedValue(
        new Response(JSON.stringify({ tenants: [] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const response = await request(serverUrl)
        .get('/api/tenants')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(200);
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits on authentication endpoints', async () => {
      // Mock rate limit exceeded
      mockRedisClient.multi.mockReturnValue({
        incr: jest.fn().mockReturnThis(),
        expire: jest.fn().mockReturnThis(),
        ttl: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([6, true, 600]), // Over limit of 5
      });

      const response = await request(serverUrl)
        .post('/api/auth/login')
        .send({ email: 'test@example.com', password: 'password' });

      expect(response.status).toBe(429);
      expect(response.body).toEqual(
        expect.objectContaining({
          error: 'Rate limit exceeded',
          type: 'rate_limit_exceeded',
        })
      );
      expect(response.headers['x-ratelimit-limit']).toBe('5');
      expect(response.headers['x-ratelimit-remaining']).toBe('0');
    });

    it('should apply different rate limits for different endpoints', async () => {
      // Mock successful rate limit check for general API
      mockRedisClient.multi.mockReturnValue({
        incr: jest.fn().mockReturnThis(),
        expire: jest.fn().mockReturnThis(),
        ttl: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([50, true, 45]), // Within limit of 200
      });

      // Mock auth and service discovery
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

      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: 'user-123',
        active: true,
      }));

      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'tenant-1',
            Service: 'tenant-service',
            Address: '10.0.0.1',
            Port: 3002,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      global.fetch = jest.fn().mockResolvedValue(
        new Response('{}', { status: 200 })
      );

      const response = await request(serverUrl)
        .get('/api/tenants')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(200);
      expect(parseInt(response.headers['x-ratelimit-limit'])).toBeGreaterThan(5);
    });
  });

  describe('Service Proxying', () => {
    it('should proxy requests to the correct backend service', async () => {
      // Setup auth
      const { sign } = await import('hono/jwt');
      const token = await sign({
        sub: 'user-123',
        tenantId: 'tenant-456',
        email: 'test@example.com',
        roles: ['admin'],
        permissions: ['read', 'write'],
        sessionId: 'session-abc',
        type: 'access',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      }, process.env.JWT_SECRET || 'test-secret');

      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: 'user-123',
        active: true,
      }));

      // Mock service discovery
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'video-1',
            Service: 'video-management-service',
            Address: '10.0.0.1',
            Port: 3003,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      // Mock backend response
      const mockVideoData = {
        cameras: [
          { id: 'cam-1', name: 'Front Door' },
          { id: 'cam-2', name: 'Parking Lot' },
        ],
      };

      global.fetch = jest.fn().mockResolvedValue(
        new Response(JSON.stringify(mockVideoData), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const response = await request(serverUrl)
        .get('/api/cameras')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(200);
      expect(response.body).toEqual(mockVideoData);
      expect(global.fetch).toHaveBeenCalledWith(
        'http://10.0.0.1:3003/cameras',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            authorization: `Bearer ${token}`,
            'X-User-ID': 'user-123',
            'X-Tenant-ID': 'tenant-456',
          }),
        })
      );
    });

    it('should handle service unavailable gracefully', async () => {
      // Setup auth
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

      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: 'user-123',
        active: true,
      }));

      // Mock no healthy instances
      mockConsulClient.health.service.mockResolvedValue([]);

      const response = await request(serverUrl)
        .get('/api/devices')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(503);
      expect(response.body).toEqual(
        expect.objectContaining({
          message: expect.stringContaining('No healthy instances available'),
        })
      );
    });

    it('should handle backend service errors', async () => {
      // Setup auth
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

      mockRedisClient.get.mockResolvedValue(JSON.stringify({
        userId: 'user-123',
        active: true,
      }));

      // Mock service discovery
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'analytics-1',
            Service: 'analytics-service',
            Address: '10.0.0.1',
            Port: 3005,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      // Mock backend error
      global.fetch = jest.fn().mockResolvedValue(
        new Response('Internal Server Error', {
          status: 500,
          statusText: 'Internal Server Error',
        })
      );

      const response = await request(serverUrl)
        .get('/api/analytics/dashboard')
        .set('Authorization', `Bearer ${token}`);

      expect(response.status).toBe(500);
    });
  });

  describe('CORS Support', () => {
    it('should handle preflight requests', async () => {
      const response = await request(serverUrl)
        .options('/api/auth/login')
        .set('Origin', 'https://example.com')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'content-type');

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-methods']).toContain('POST');
    });

    it('should include CORS headers in responses', async () => {
      const response = await request(serverUrl)
        .get('/health')
        .set('Origin', 'https://example.com');

      expect(response.status).toBe(200);
      expect(response.headers['access-control-allow-origin']).toBeDefined();
    });
  });

  describe('Security Headers', () => {
    it('should include security headers in responses', async () => {
      const response = await request(serverUrl).get('/health');

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('1; mode=block');
      expect(response.headers['strict-transport-security']).toBeDefined();
    });
  });

  describe('Request ID Tracking', () => {
    it('should generate request ID if not provided', async () => {
      const response = await request(serverUrl).get('/health');

      expect(response.headers['x-request-id']).toBeDefined();
      expect(response.headers['x-request-id']).toMatch(/^[a-f0-9-]+$/);
    });

    it('should use provided request ID', async () => {
      const requestId = 'custom-request-123';
      const response = await request(serverUrl)
        .get('/health')
        .set('X-Request-ID', requestId);

      expect(response.headers['x-request-id']).toBe(requestId);
    });
  });

  describe('Compression', () => {
    it('should compress responses when requested', async () => {
      const response = await request(serverUrl)
        .get('/health')
        .set('Accept-Encoding', 'gzip');

      expect(response.headers['content-encoding']).toBe('gzip');
    });
  });

  describe('Error Handling', () => {
    it('should handle 404 for unknown routes', async () => {
      const response = await request(serverUrl).get('/unknown-route');

      expect(response.status).toBe(404);
      expect(response.body).toEqual({
        error: 'Not Found',
        message: 'The requested resource was not found',
        path: '/unknown-route',
      });
    });

    it('should handle malformed JSON in request body', async () => {
      const response = await request(serverUrl)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid json');

      expect(response.status).toBeGreaterThanOrEqual(400);
    });
  });

  describe('Admin Endpoints', () => {
    it('should provide service health status', async () => {
      // Mock service health checks
      mockConsulClient.health.service.mockImplementation(async ({ service }) => {
        return [{
          Service: {
            ID: `${service}-1`,
            Service: service,
            Address: '10.0.0.1',
            Port: 3000,
          },
          Checks: [{ Status: 'passing' }],
        }];
      });

      const response = await request(serverUrl).get('/health/services');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          status: expect.stringMatching(/healthy|degraded/),
          services: expect.any(Object),
        })
      );
    });

    it('should provide circuit breaker status', async () => {
      const response = await request(serverUrl).get('/admin/circuit-breakers');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          timestamp: expect.any(String),
          circuitBreakers: expect.any(Object),
        })
      );
    });
  });
});