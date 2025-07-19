import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

// Import route modules
import { createMainRoutes } from './routes/main';

// Configuration
const config = {
  port: parseInt(process.env.PORT || '3000'),
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  // Add service-specific config
};

// Initialize services
const app = new Hono();
const prisma = new PrismaClient();
const redis = new Redis(config.redisUrl);

// Middleware
app.use('*', cors());
app.use('*', logger());
app.use('*', prettyJSON());

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'environmental-service',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// Mount route modules
app.route('/api', createMainRoutes(prisma, redis, config));

// Error handling
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  }, 500);
});

// Start server
async function startServer() {
  try {
    await prisma.$connect();
    console.log('Connected to database');

    const server = Bun.serve({
      port: config.port,
      fetch: app.fetch
    });

    console.log(`Service running on port ${config.port}`);
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  await prisma.$disconnect();
  await redis.quit();
  process.exit(0);
});

// Start the server
startServer();

export default app;
