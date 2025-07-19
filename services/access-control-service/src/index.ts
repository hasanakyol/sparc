import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config, logger as appLogger } from '@sparc/shared';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';

// Import routes
import accessPointRoutes from './routes/access-points';
import accessLevelRoutes from './routes/access-levels';
import accessEventRoutes from './routes/access-events';
import credentialRoutes from './routes/credentials';
import doorRoutes from './routes/doors';
import scheduleRoutes from './routes/schedules';

class AccessControlService extends MicroserviceBase {
  private wsServer: WebSocketServer | null = null;
  private httpServer: any;
  private hardwareProtocols: Map<string, any> = new Map();

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'access-control-service',
      port: config.services?.accessControl?.port || 3002,
      version: process.env.npm_package_version || '1.0.0',
      jwtSecret: config.jwt?.accessTokenSecret || process.env.JWT_SECRET!,
      redisUrl: config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379',
      databaseUrl: config.database?.url || process.env.DATABASE_URL!,
      enableAuth: true,
      enableRateLimit: true,
      enableMetrics: true,
      corsOrigins: config.cors?.origins || ['http://localhost:3000']
    };
    
    super(serviceConfig);
  }

  setupRoutes(): void {
    // Mount API routes
    this.app.route('/api/access-points', accessPointRoutes);
    this.app.route('/api/access-levels', accessLevelRoutes);
    this.app.route('/api/access-events', accessEventRoutes);
    this.app.route('/api/credentials', credentialRoutes);
    this.app.route('/api/doors', doorRoutes);
    this.app.route('/api/schedules', scheduleRoutes);

    // WebSocket endpoint for real-time events
    this.app.get('/ws', (c) => {
      if (c.req.header('upgrade') !== 'websocket') {
        return c.text('Expected WebSocket connection', 400);
      }
      
      // WebSocket handling will be done by the WebSocket server
      return c.text('Switching Protocols', 101);
    });

    // Additional error handling
    this.app.use('*', async (c, next) => {
      try {
        await next();
      } catch (err) {
        if (err instanceof z.ZodError) {
          throw new HTTPException(400, {
            message: 'Validation failed',
            cause: err.errors
          });
        }
        throw err;
      }
    });

    // 404 handler
    this.app.notFound((c) => {
      return c.json(
        {
          error: 'Not found',
          path: c.req.path,
        },
        404
      );
    });
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    // Check WebSocket server
    try {
      checks.websocket = this.wsServer !== null && this.wsServer.clients.size >= 0;
    } catch {
      checks.websocket = false;
    }

    // Check hardware connections
    try {
      const hardwareStatus = Array.from(this.hardwareProtocols.entries()).map(([id, handler]) => ({
        id,
        connected: handler.isConnected?.() || false,
        lastHeartbeat: handler.getLastHeartbeat?.() || null,
      }));
      
      checks.hardwareConnections = hardwareStatus.some(h => h.connected);
      
      // Add individual hardware checks
      hardwareStatus.forEach(hw => {
        checks[`hardware_${hw.id}`] = hw.connected;
      });
    } catch {
      checks.hardwareConnections = false;
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const metrics: string[] = [];
    
    // Access control specific metrics
    metrics.push('# HELP access_events_total Total number of access events');
    metrics.push('# TYPE access_events_total counter');
    
    metrics.push('# HELP access_granted_total Total number of granted access events');
    metrics.push('# TYPE access_granted_total counter');
    
    metrics.push('# HELP access_denied_total Total number of denied access events');
    metrics.push('# TYPE access_denied_total counter');
    
    metrics.push('# HELP active_doors_total Total number of active doors');
    metrics.push('# TYPE active_doors_total gauge');
    
    metrics.push('# HELP active_credentials_total Total number of active credentials');
    metrics.push('# TYPE active_credentials_total gauge');
    
    metrics.push('# HELP websocket_connections Current number of WebSocket connections');
    metrics.push('# TYPE websocket_connections gauge');
    
    // Get actual metrics
    try {
      const accessEvents = await this.redis.get('metrics:access:events_total') || '0';
      metrics.push(`access_events_total ${accessEvents}`);
      
      const accessGranted = await this.redis.get('metrics:access:granted_total') || '0';
      metrics.push(`access_granted_total ${accessGranted}`);
      
      const accessDenied = await this.redis.get('metrics:access:denied_total') || '0';
      metrics.push(`access_denied_total ${accessDenied}`);
      
      // Get counts from database
      const [doorCount, credentialCount] = await Promise.all([
        this.prisma.door.count({ where: { status: 'online' } }),
        this.prisma.credential.count({ where: { active: true } })
      ]);
      
      metrics.push(`active_doors_total ${doorCount}`);
      metrics.push(`active_credentials_total ${credentialCount}`);
      
      // WebSocket connections
      const wsConnections = this.wsServer?.clients.size || 0;
      metrics.push(`websocket_connections ${wsConnections}`);
    } catch (error) {
      console.error('Failed to get metrics:', error);
    }
    
    return metrics.join('\n');
  }

  public async start(): Promise<void> {
    // Create HTTP server for WebSocket support
    this.httpServer = createServer();
    
    // Initialize WebSocket server
    this.wsServer = new WebSocketServer({ server: this.httpServer });
    this.setupWebSocketHandlers();
    
    // Initialize hardware protocols
    await this.initializeHardwareProtocols();
    
    // Call parent start method
    await super.start();
    
    // Start the HTTP server with the Hono app
    this.httpServer.on('request', (req: any, res: any) => {
      this.app.fetch(req, { req, res });
    });
    
    this.httpServer.listen(this.config.port, () => {
      console.log(`[${this.config.serviceName}] HTTP/WebSocket server listening on port ${this.config.port}`);
    });
  }

  private setupWebSocketHandlers(): void {
    if (!this.wsServer) return;

    this.wsServer.on('connection', (ws, req) => {
      console.log('New WebSocket connection');
      
      // Send initial connection message
      ws.send(JSON.stringify({
        type: 'connection',
        status: 'connected',
        timestamp: new Date().toISOString()
      }));
      
      ws.on('message', async (message) => {
        try {
          const data = JSON.parse(message.toString());
          await this.handleWebSocketMessage(ws, data);
        } catch (error) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Invalid message format'
          }));
        }
      });
      
      ws.on('close', () => {
        console.log('WebSocket connection closed');
      });
      
      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
      });
    });
  }

  private async handleWebSocketMessage(ws: any, data: any): Promise<void> {
    // Handle different message types
    switch (data.type) {
      case 'subscribe':
        // Handle event subscription
        ws.send(JSON.stringify({
          type: 'subscribed',
          channel: data.channel,
          timestamp: new Date().toISOString()
        }));
        break;
        
      case 'ping':
        ws.send(JSON.stringify({
          type: 'pong',
          timestamp: new Date().toISOString()
        }));
        break;
        
      default:
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Unknown message type'
        }));
    }
  }

  private async initializeHardwareProtocols(): Promise<void> {
    // Initialize hardware protocol handlers (OSDP, Wiegand, etc.)
    console.log('Initializing hardware protocols...');
    
    // This would initialize actual hardware connections
    // For now, we'll just log
    appLogger.info('Hardware protocols initialized', {
      protocols: ['OSDP', 'Wiegand', 'TCP/IP']
    });
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up access control service...');
    
    // Close WebSocket connections
    if (this.wsServer) {
      this.wsServer.clients.forEach(client => {
        client.close();
      });
      this.wsServer.close();
    }
    
    // Close HTTP server
    if (this.httpServer) {
      this.httpServer.close();
    }
    
    // Disconnect hardware protocols
    for (const [id, handler] of this.hardwareProtocols) {
      try {
        if (handler.disconnect) {
          await handler.disconnect();
        }
      } catch (error) {
        console.error(`Error disconnecting hardware ${id}:`, error);
      }
    }
    
    // Clear any temporary access data
    try {
      const tempKeys = await this.redis.keys('temp:access:*');
      if (tempKeys.length > 0) {
        await this.redis.del(...tempKeys);
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  // Public method to broadcast events to WebSocket clients
  public broadcastEvent(event: any): void {
    if (!this.wsServer) return;
    
    const message = JSON.stringify({
      type: 'event',
      data: event,
      timestamp: new Date().toISOString()
    });
    
    this.wsServer.clients.forEach(client => {
      if (client.readyState === 1) { // WebSocket.OPEN
        client.send(message);
      }
    });
  }
}

// Create and start the service
const accessControlService = new AccessControlService();

accessControlService.start().catch((error) => {
  console.error('Failed to start access control service:', error);
  process.exit(1);
});

// Export for testing
export default accessControlService.app;
export { accessControlService };