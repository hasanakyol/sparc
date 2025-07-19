import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { compress } from 'hono/compress';
import { secureHeaders } from 'hono/secure-headers';
import { requestId } from 'hono/request-id';
import { timeout } from 'hono/timeout';
import { rateLimiter } from '@/middleware/rate-limit';
import { errorHandler } from '@/middleware/error-handler';
import { authMiddleware } from '@/middleware/auth';
import { healthRoutes } from './routes/health';
import { provisioningRoutes } from './routes/provisioning';
import { certificateRoutes } from './routes/certificates';
import { templateRoutes } from './routes/templates';
import { bulkRoutes } from './routes/bulk';
import { policyRoutes } from './routes/policies';
import { DeviceProvisioningService } from './services/device-provisioning-service';
import { CertificateService } from './services/certificate-service';
import { TemplateService } from './services/template-service';
import { db } from '@db/client';
import Redis from 'ioredis';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';

// Initialize Redis
const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD,
  db: parseInt(process.env.REDIS_DB || '0'),
  keyPrefix: 'provisioning:',
});

// Initialize services
const certificateService = new CertificateService(db, redis);
const templateService = new TemplateService(db, redis);
const provisioningService = new DeviceProvisioningService(db, redis, certificateService, templateService);

// Create Hono app
const app = new Hono();

// Global middleware
app.use('*', requestId());
app.use('*', logger());
app.use('*', secureHeaders());
app.use('*', compress());
app.use('*', timeout(30000));
app.use(
  '*',
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  })
);

// Rate limiting
app.use('*', rateLimiter({ 
  limit: 100, 
  window: 60 * 1000,
  keyGenerator: (c) => c.req.header('x-tenant-id') || 'anonymous'
}));

// Error handling
app.onError(errorHandler);

// Health check routes (no auth required)
app.route('/health', healthRoutes);

// Protected routes
app.use('/api/*', authMiddleware);

// API routes
app.route('/api/v1/provisioning', provisioningRoutes(provisioningService));
app.route('/api/v1/certificates', certificateRoutes(certificateService));
app.route('/api/v1/templates', templateRoutes(templateService));
app.route('/api/v1/bulk', bulkRoutes(provisioningService));
app.route('/api/v1/policies', policyRoutes(provisioningService));

// 404 handler
app.notFound((c) => {
  return c.json({ 
    error: 'Not Found',
    path: c.req.path,
    timestamp: new Date().toISOString()
  }, 404);
});

// Create HTTP server
const server = createServer(app.fetch);

// Create WebSocket server
const wss = new WebSocketServer({ server });

// Pass WebSocket server to provisioning service
provisioningService.setWebSocketServer(wss);

// WebSocket connection handler
wss.on('connection', (ws, req) => {
  const tenantId = new URL(req.url!, `http://${req.headers.host}`).searchParams.get('tenantId');
  
  if (!tenantId) {
    ws.close(1008, 'Missing tenantId');
    return;
  }

  console.log(`WebSocket client connected for tenant: ${tenantId}`);

  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message.toString());
      
      switch (data.type) {
        case 'subscribe':
          // Handle subscription to provisioning events
          ws.send(JSON.stringify({
            type: 'subscribed',
            channel: data.channel,
            timestamp: new Date().toISOString()
          }));
          break;
          
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;
          
        default:
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Unknown message type'
          }));
      }
    } catch (error) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Invalid message format'
      }));
    }
  });

  ws.on('close', () => {
    console.log(`WebSocket client disconnected for tenant: ${tenantId}`);
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Graceful shutdown
const gracefulShutdown = async () => {
  console.log('Shutting down gracefully...');
  
  // Close WebSocket connections
  wss.clients.forEach((client) => {
    client.close(1001, 'Server shutting down');
  });
  
  // Close Redis connection
  await redis.quit();
  
  // Close database connection
  await db.$client.end();
  
  // Close HTTP server
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
const port = process.env.PORT || 3005;
server.listen(port, () => {
  console.log(`Device Provisioning Service running on port ${port}`);
  console.log(`WebSocket server available on ws://localhost:${port}`);
});