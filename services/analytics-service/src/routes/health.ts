import { Hono } from 'hono';
import { createHealthCheckHandler } from '@sparc/shared/utils/health-check';
import { PrismaClient } from '@sparc/shared/prisma';
import Redis from 'ioredis';
import { Client } from '@opensearch-project/opensearch';

export function createHealthRoutes(
  prisma: PrismaClient,
  redis: Redis,
  opensearch: Client
) {
  const app = new Hono();

  // Create health check handler with dependencies
  const healthCheck = createHealthCheckHandler({
    service: 'analytics-service',
    checks: {
      database: async () => {
        await prisma.$queryRaw`SELECT 1`;
        return { status: 'healthy' };
      },
      redis: async () => {
        const pong = await redis.ping();
        return { status: pong === 'PONG' ? 'healthy' : 'unhealthy' };
      },
      opensearch: async () => {
        const health = await opensearch.cluster.health();
        return { 
          status: health.body.status === 'green' || health.body.status === 'yellow' ? 'healthy' : 'unhealthy',
          cluster: health.body.cluster_name,
          nodes: health.body.number_of_nodes
        };
      }
    }
  });

  // Health check endpoint
  app.get('/', healthCheck);

  // Liveness probe (simple check)
  app.get('/live', (c) => {
    return c.json({ status: 'alive' });
  });

  // Readiness probe (check dependencies)
  app.get('/ready', async (c) => {
    try {
      await Promise.all([
        prisma.$queryRaw`SELECT 1`,
        redis.ping(),
        opensearch.ping()
      ]);
      return c.json({ status: 'ready' });
    } catch (error) {
      return c.json({ status: 'not ready', error: error.message }, 503);
    }
  });

  return app;
}