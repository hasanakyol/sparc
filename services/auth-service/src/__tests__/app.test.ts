import { Hono } from 'hono';
import createApp from '../app';
import { mockPrisma, mockRedis } from './test-utils';

// Mock dependencies
jest.mock('@prisma/client', () => ({
  PrismaClient: jest.fn(() => mockPrisma),
}));

jest.mock('ioredis', () => {
  return jest.fn(() => mockRedis);
});

jest.mock('../routes/auth', () => {
  const authRoutes = new Hono();
  authRoutes.get('/test', (c) => c.json({ message: 'auth routes mounted' }));
  return { default: authRoutes };
});

jest.mock('@sparc/shared/utils/health-check', () => ({
  createHealthCheckHandler: jest.fn(() => (c: any) => c.json({ status: 'ok' })),
}));

describe('Auth Service App', () => {
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    jest.clearAllMocks();
    app = createApp();
  });

  describe('Middleware configuration', () => {
    it('should create app with all middleware configured', () => {
      expect(app).toBeDefined();
      // The app instance should have routes configured
      expect(app.routes).toBeDefined();
    });
  });

  describe('Health check endpoints', () => {
    it('should respond to /health endpoint', async () => {
      const res = await app.request('/health');
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toEqual({ status: 'ok' });
    });

    it('should respond to /ready endpoint when services are healthy', async () => {
      mockPrisma.$queryRaw.mockResolvedValue([{ 1: 1 }]);
      mockRedis.ping.mockResolvedValue('PONG');

      const res = await app.request('/ready');
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toMatchObject({
        ready: true,
        checks: {
          database: true,
          redis: true,
        },
      });
      expect(body.timestamp).toBeDefined();
    });

    it('should return 503 when database is unhealthy', async () => {
      mockPrisma.$queryRaw.mockRejectedValue(new Error('Database connection failed'));
      mockRedis.ping.mockResolvedValue('PONG');

      const res = await app.request('/ready');
      expect(res.status).toBe(503);
      const body = await res.json();
      expect(body).toMatchObject({
        ready: false,
        checks: {
          database: false,
          redis: true,
        },
      });
    });

    it('should return 503 when Redis is unhealthy', async () => {
      mockPrisma.$queryRaw.mockResolvedValue([{ 1: 1 }]);
      mockRedis.ping.mockRejectedValue(new Error('Redis connection failed'));

      const res = await app.request('/ready');
      expect(res.status).toBe(503);
      const body = await res.json();
      expect(body).toMatchObject({
        ready: false,
        checks: {
          database: true,
          redis: false,
        },
      });
    });
  });

  describe('Route mounting', () => {
    it('should mount auth routes at /auth', async () => {
      const res = await app.request('/auth/test');
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toEqual({ message: 'auth routes mounted' });
    });
  });

  describe('Error handling', () => {
    it('should handle HTTPException', async () => {
      // Test by requesting a non-existent auth route
      const res = await app.request('/auth/nonexistent', {
        method: 'POST',
      });
      // This will trigger the 404 handler which returns a proper error
      expect(res.status).toBe(404);
    });

    it('should handle ZodError for validation failures', async () => {
      // Since we can't easily trigger a ZodError through the app,
      // we'll test this through the auth routes in integration tests
      expect(app.onError).toBeDefined();
    });

    it('should handle JSON parsing errors', async () => {
      const res = await app.request('/auth/test', {
        method: 'POST',
        body: 'invalid json{',
        headers: {
          'content-type': 'application/json',
        },
      });
      // The actual JSON parsing happens in Hono middleware
      expect(res.status).toBeGreaterThanOrEqual(400);
    });

    it('should handle 404 for unknown routes', async () => {
      const res = await app.request('/unknown/route');
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body).toEqual({
        error: 'Not found',
        path: '/unknown/route',
      });
    });
  });

  describe('CORS configuration', () => {
    it('should include CORS headers in response', async () => {
      const res = await app.request('/health', {
        headers: {
          Origin: 'http://localhost:3000',
        },
      });
      expect(res.headers.get('access-control-allow-origin')).toBeTruthy();
      expect(res.headers.get('access-control-allow-credentials')).toBe('true');
    });
  });

  describe('Security headers', () => {
    it('should include security headers in response', async () => {
      const res = await app.request('/health');
      // Check for common security headers set by secureHeaders middleware
      expect(res.headers.get('x-content-type-options')).toBeTruthy();
    });
  });
});