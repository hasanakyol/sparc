import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { compress } from 'hono/compress';
import { secureHeaders } from 'hono/secure-headers';
import { HTTPException } from 'hono/http-exception';
import authRoutes from './routes/auth';
import { createHealthCheckHandler } from '@sparc/shared/utils/health-check';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

export default function createApp() {
  const app = new Hono();
  const prisma = new PrismaClient();
  const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

  // Middleware
  app.use('*', logger());
  app.use('*', cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  }));
  app.use('*', secureHeaders());
  app.use('*', compress());
  app.use('*', prettyJSON());

  // Health check endpoints
  app.get('/health', createHealthCheckHandler({
    serviceName: 'auth-service',
    prismaClient: prisma,
    redisClient: redis
  }));

  app.get('/ready', async (c) => {
    const checks = {
      database: false,
      redis: false,
    };

    try {
      // Check database
      const { PrismaClient } = await import('@prisma/client');
      const prisma = new PrismaClient();
      await prisma.$queryRaw`SELECT 1`;
      await prisma.$disconnect();
      checks.database = true;
    } catch (error) {
      console.error('Database check failed:', error);
    }

    try {
      // Check Redis
      const Redis = (await import('ioredis')).default;
      const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
      await redis.ping();
      await redis.quit();
      checks.redis = true;
    } catch (error) {
      console.error('Redis check failed:', error);
    }

    const isReady = Object.values(checks).every(Boolean);

    return c.json(
      {
        ready: isReady,
        checks,
        timestamp: new Date().toISOString(),
      },
      isReady ? 200 : 503
    );
  });

  // Mount auth routes
  app.route('/auth', authRoutes);

  // Error handling
  app.onError((err, c) => {
    console.error('Unhandled error:', err);

    if (err instanceof HTTPException) {
      return err.getResponse();
    }

    // Handle validation errors
    if (err.name === 'ZodError') {
      return c.json(
        {
          error: 'Validation failed',
          details: err.errors,
        },
        400
      );
    }

    // Handle JSON parsing errors
    if (err instanceof SyntaxError && err.message.includes('JSON')) {
      return c.json(
        {
          error: 'Invalid JSON',
        },
        400
      );
    }

    // Generic error response
    return c.json(
      {
        error: 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { details: err.message }),
      },
      500
    );
  });

  // 404 handler
  app.notFound((c) => {
    return c.json(
      {
        error: 'Not found',
        path: c.req.path,
      },
      404
    );
  });

  return app;
}