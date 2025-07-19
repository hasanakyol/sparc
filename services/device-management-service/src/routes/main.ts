import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { authMiddleware } from '@shared/middleware/auth';

export function createMainRoutes(prisma: PrismaClient, redis: Redis, config: any) {
  const app = new Hono();

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Define routes here
  app.get('/', async (c) => {
    return c.json({ message: 'Main route' });
  });

  return app;
}
