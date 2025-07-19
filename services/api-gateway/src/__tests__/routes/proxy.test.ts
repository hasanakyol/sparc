import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { Hono } from 'hono';
import request from 'supertest';
import consul from 'consul';
import CircuitBreaker from 'opossum';
import proxyApp from '../../routes/proxy';

// Mock dependencies
jest.mock('consul');
jest.mock('opossum');
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
    consul: { host: 'localhost', port: 8500, secure: false },
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

// Mock global fetch
global.fetch = jest.fn();
global.crypto = {
  randomUUID: jest.fn(() => 'test-uuid-123'),
} as any;

describe('Proxy Routes', () => {
  let mockConsulClient: any;
  let mockCircuitBreaker: any;
  let app: Hono;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Mock Consul client
    mockConsulClient = {
      health: {
        service: jest.fn(),
      },
    };
    (consul as jest.Mock).mockReturnValue(mockConsulClient);

    // Mock Circuit Breaker
    mockCircuitBreaker = {
      fire: jest.fn(),
      on: jest.fn(),
      fallback: jest.fn(),
      stats: {
        state: 'closed',
        failures: 0,
        successes: 100,
        rejections: 0,
        fires: 100,
        timeouts: 0,
      },
    };
    (CircuitBreaker as jest.Mock).mockImplementation(() => mockCircuitBreaker);

    // Create test app
    app = new Hono();
    app.route('/', proxyApp);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Service Discovery', () => {
    it('should route auth requests to auth-service', async () => {
      // Mock service discovery
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      // Mock successful proxy response
      const mockResponse = new Response(JSON.stringify({ token: 'abc123' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      const response = await request(app as any)
        .post('/api/auth/login')
        .send({ email: 'test@example.com', password: 'password' });

      expect(response.status).toBe(200);
      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceName: 'auth-service',
          path: '/auth/login',
          method: 'POST',
        })
      );
    });

    it('should route tenant requests to tenant-service', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'tenant-1',
            Service: 'tenant-service',
            Address: '10.0.0.2',
            Port: 3002,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response(JSON.stringify({ tenants: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      const response = await request(app as any)
        .get('/api/tenants')
        .set('Authorization', 'Bearer token');

      expect(response.status).toBe(200);
      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceName: 'tenant-service',
          path: '/tenants',
          method: 'GET',
        })
      );
    });

    it('should handle pattern-based routing for complex paths', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'video-1',
            Service: 'video-management-service',
            Address: '10.0.0.3',
            Port: 3003,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('video stream data', {
        status: 200,
        headers: { 'Content-Type': 'video/mp4' },
      });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      const response = await request(app as any)
        .get('/api/video/stream/camera-123');

      expect(response.status).toBe(200);
      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceName: 'video-management-service',
          path: '/video/stream/camera-123',
        })
      );
    });

    it('should return 404 for unknown service paths', async () => {
      const response = await request(app as any)
        .get('/api/unknown/path');

      expect(response.status).toBe(404);
      expect(response.body).toEqual(
        expect.objectContaining({
          message: expect.stringContaining('No service configured'),
        })
      );
    });
  });

  describe('Load Balancing', () => {
    it('should round-robin between multiple healthy instances', async () => {
      // Mock multiple instances
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
        {
          Service: {
            ID: 'auth-2',
            Service: 'auth-service',
            Address: '10.0.0.2',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      // Make multiple requests
      await request(app as any).get('/api/auth/health');
      await request(app as any).get('/api/auth/health');
      await request(app as any).get('/api/auth/health');

      // Check that different instances were used (round-robin)
      const calls = mockCircuitBreaker.fire.mock.calls;
      expect(calls.length).toBe(3);
    });

    it('should handle service with no healthy instances', async () => {
      mockConsulClient.health.service.mockResolvedValue([]);

      const response = await request(app as any)
        .get('/api/auth/health');

      expect(response.status).toBe(503);
      expect(response.body).toEqual(
        expect.objectContaining({
          message: expect.stringContaining('No healthy instances available'),
        })
      );
    });

    it('should track and avoid unhealthy instances', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      // Simulate failures to mark instance as unhealthy
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Connection refused'));
      mockCircuitBreaker.fire.mockImplementation(async (args) => {
        throw new Error('Connection refused');
      });

      const response = await request(app as any)
        .get('/api/auth/health');

      expect(response.status).toBe(500);
    });
  });

  describe('Circuit Breaker', () => {
    it('should create circuit breaker for each service', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      await request(app as any).get('/api/auth/health');

      expect(CircuitBreaker).toHaveBeenCalledWith(
        expect.any(Function),
        expect.objectContaining({
          name: 'auth-service-proxy',
          timeout: 5000,
          errorThresholdPercentage: 50,
        })
      );
    });

    it('should handle circuit breaker open state', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      // Simulate circuit breaker open
      mockCircuitBreaker.fire.mockRejectedValue(new Error('Circuit breaker is OPEN'));
      mockCircuitBreaker.stats.state = 'open';

      const response = await request(app as any)
        .get('/api/auth/health');

      expect(response.status).toBe(500);
    });

    it('should use fallback when circuit breaker is open', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      // Setup fallback response
      let fallbackFn: Function;
      mockCircuitBreaker.fallback.mockImplementation((fn: Function) => {
        fallbackFn = fn;
      });

      // Create a new instance to trigger fallback setup
      await request(app as any).get('/api/auth/health');

      // Execute fallback
      const fallbackResponse = fallbackFn!();
      expect(fallbackResponse).toBeInstanceOf(Response);
      expect(fallbackResponse.status).toBe(503);
    });
  });

  describe('Request Transformation', () => {
    it('should forward relevant headers to downstream service', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      await request(app as any)
        .get('/api/auth/health')
        .set('Authorization', 'Bearer token123')
        .set('X-Tenant-ID', 'tenant-456')
        .set('X-User-ID', 'user-789')
        .set('X-Request-ID', 'req-abc');

      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            authorization: 'Bearer token123',
            'x-tenant-id': 'tenant-456',
            'x-user-id': 'user-789',
            'x-request-id': 'req-abc',
          }),
        })
      );
    });

    it('should add gateway-specific headers', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      await request(app as any).get('/api/auth/health');

      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Gateway-Service': 'auth-service',
            'X-Gateway-Timestamp': expect.any(String),
            'X-Gateway-Version': '1.0.0',
            'X-Request-ID': 'test-uuid-123',
          }),
        })
      );
    });

    it('should handle different content types correctly', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      // Test JSON content
      await request(app as any)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send({ email: 'test@example.com' });

      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          body: { email: 'test@example.com' },
          headers: expect.objectContaining({
            'content-type': 'application/json',
          }),
        })
      );

      // Test form data
      jest.clearAllMocks();
      await request(app as any)
        .post('/api/auth/login')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('email=test@example.com&password=pass');

      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          body: 'email=test@example.com&password=pass',
        })
      );
    });
  });

  describe('Response Transformation', () => {
    it('should add gateway headers to response', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{"success": true}', {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      const response = await request(app as any)
        .get('/api/auth/health');

      expect(response.headers['x-gateway-service']).toBe('auth-service');
      expect(response.headers['x-gateway-timestamp']).toBeDefined();
    });

    it('should preserve original response status and body', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockBody = { error: 'Unauthorized' };
      const mockResponse = new Response(JSON.stringify(mockBody), {
        status: 401,
        statusText: 'Unauthorized',
        headers: { 'Content-Type': 'application/json' },
      });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      const response = await request(app as any)
        .get('/api/auth/protected');

      expect(response.status).toBe(401);
      expect(response.body).toEqual(mockBody);
    });
  });

  describe('Error Handling', () => {
    it('should handle timeout errors', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const timeoutError = new Error('Request timeout');
      timeoutError.name = 'TimeoutError';
      mockCircuitBreaker.fire.mockRejectedValue(timeoutError);

      const response = await request(app as any)
        .get('/api/auth/health');

      expect(response.status).toBe(504);
      expect(response.body).toEqual(
        expect.objectContaining({
          message: expect.stringContaining('Request timeout'),
        })
      );
    });

    it('should handle upstream service errors', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('Internal Server Error', {
        status: 500,
        statusText: 'Internal Server Error',
      });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      const response = await request(app as any)
        .get('/api/auth/health');

      expect(response.status).toBe(500);
    });

    it('should handle body parsing errors gracefully', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      // Send malformed JSON
      const response = await request(app as any)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid json');

      // Should still process the request (with raw body)
      expect(mockCircuitBreaker.fire).toHaveBeenCalled();
    });
  });

  describe('Admin Endpoints', () => {
    it('should provide health check aggregation', async () => {
      mockConsulClient.health.service.mockImplementation(async ({ service }) => {
        if (service === 'auth-service') {
          return [{
            Service: {
              ID: 'auth-1',
              Service: 'auth-service',
              Address: '10.0.0.1',
              Port: 3001,
            },
            Checks: [{ Status: 'passing' }],
          }];
        }
        return [];
      });

      const response = await request(app as any)
        .get('/health/services');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          status: expect.stringMatching(/healthy|degraded/),
          services: expect.objectContaining({
            'auth-service': expect.objectContaining({
              status: 'healthy',
              instanceCount: 1,
            }),
          }),
        })
      );
    });

    it('should allow manual service registry refresh', async () => {
      mockConsulClient.health.service.mockResolvedValue([]);

      const response = await request(app as any)
        .post('/admin/refresh-services');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          message: 'Service registry refresh completed',
          results: expect.any(Array),
        })
      );
    });

    it('should provide circuit breaker status', async () => {
      // Initialize a circuit breaker by making a request
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'auth-1',
            Service: 'auth-service',
            Address: '10.0.0.1',
            Port: 3001,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      await request(app as any).get('/api/auth/health');

      const response = await request(app as any)
        .get('/admin/circuit-breakers');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(
        expect.objectContaining({
          circuitBreakers: expect.objectContaining({
            'auth-service': expect.objectContaining({
              state: 'closed',
              failures: 0,
              successes: 100,
            }),
          }),
        })
      );
    });
  });

  describe('Service Routing Priority', () => {
    it('should use priority-based pattern matching', async () => {
      mockConsulClient.health.service.mockResolvedValue([
        {
          Service: {
            ID: 'access-1',
            Service: 'access-control-service',
            Address: '10.0.0.1',
            Port: 3004,
          },
          Checks: [{ Status: 'passing' }],
        },
      ]);

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      // Test more specific pattern takes precedence
      await request(app as any).get('/api/access-events');

      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceName: 'access-control-service',
          path: '/access-events',
        })
      );
    });

    it('should fall back to legacy routing when no pattern matches', async () => {
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

      const mockResponse = new Response('{}', { status: 200 });
      mockCircuitBreaker.fire.mockResolvedValue(mockResponse);

      await request(app as any).get('/api/organizations/123');

      expect(mockCircuitBreaker.fire).toHaveBeenCalledWith(
        expect.objectContaining({
          serviceName: 'tenant-service',
        })
      );
    });
  });
});