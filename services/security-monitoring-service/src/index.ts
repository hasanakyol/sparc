import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { Redis } from 'ioredis';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';

// Import middleware
import { authMiddleware } from '@sparc/shared/middleware';
import { errorHandler } from '@sparc/shared/middleware';
import { requestId } from '@sparc/shared/middleware';
import { metrics } from '@sparc/shared/middleware';

// Import routes
import { securityEventsRouter } from './routes/security-events';
import { alertsRouter } from './routes/alerts';
import { dashboardRouter } from './routes/dashboards';
import { threatsRouter } from './routes/threats';
import { incidentsRouter } from './routes/incidents';
import { complianceRouter } from './routes/compliance';
import { metricsRouter } from './routes/metrics';
import { siemRouter } from './routes/siem';

// Import services
import { SecurityMonitoringService } from './services/main-service';
import { RealTimeService } from './services/realtime-service';

// Initialize Redis
const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD,
  retryStrategy: (times) => Math.min(times * 50, 2000)
});

// Initialize main service
const securityService = new SecurityMonitoringService(redis);

// Create Hono app
const app = new Hono();

// Global middleware
app.use('*', requestId());
app.use('*', logger());
app.use('*', cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));
app.use('*', metrics());

// Health check
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'security-monitoring-service',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API routes (all require authentication)
app.use('/api/*', authMiddleware);

// Mount routers
app.route('/api/security-events', securityEventsRouter(securityService));
app.route('/api/alerts', alertsRouter(securityService));
app.route('/api/dashboards', dashboardRouter(securityService));
app.route('/api/threats', threatsRouter(securityService));
app.route('/api/incidents', incidentsRouter(securityService));
app.route('/api/compliance', complianceRouter(securityService));
app.route('/api/metrics', metricsRouter(securityService));
app.route('/api/siem', siemRouter(securityService));

// Error handling
app.onError((err, c) => errorHandler(err, c));

// Create HTTP server
const server = createServer();

// Create WebSocket server for real-time updates
const wss = new WebSocketServer({ server });
const realtimeService = new RealTimeService(wss, redis, securityService);

// Start servers
const port = parseInt(process.env.PORT || '3020');

server.on('request', serve({
  fetch: app.fetch,
  port
}));

server.listen(port, () => {
  console.log(`🔒 Security Monitoring Service running on port ${port}`);
  console.log(`📊 Real-time WebSocket server ready`);
  
  // Initialize background tasks
  securityService.startBackgroundTasks();
  realtimeService.start();
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  
  server.close(() => {
    console.log('HTTP server closed');
  });
  
  wss.close(() => {
    console.log('WebSocket server closed');
  });
  
  await redis.quit();
  process.exit(0);
});

export { app };