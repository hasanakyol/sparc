import { MicroserviceBase, ServiceConfig } from '../../patterns/service-base';
import { UnifiedWebSocketService } from '../unifiedWebSocket';
import { logger } from '../../logger';

/**
 * Example of integrating the unified WebSocket service into a microservice
 */
export class ExampleServiceWithWebSocket extends MicroserviceBase {
  private websocketService: UnifiedWebSocketService;

  constructor() {
    const config: ServiceConfig = {
      serviceName: 'example-service',
      port: 3009,
      version: '1.0.0',
      enableAuth: true,
      enableRateLimit: true,
      enableMetrics: true,
    };
    
    super(config);

    // Initialize WebSocket service
    this.websocketService = new UnifiedWebSocketService({
      port: this.config.port + 100, // WebSocket on different port
      jwtSecret: this.config.jwtSecret!,
      redisUrl: this.config.redisUrl!,
      corsOrigins: this.config.corsOrigins,
      namespaces: [
        {
          name: 'custom',
          roomStrategy: 'tenant',
          rateLimitOptions: { points: 100, duration: 60 },
          eventHandlers: {
            'custom:action': this.handleCustomAction.bind(this),
            'data:request': this.handleDataRequest.bind(this),
          },
        },
      ],
    });
  }

  protected async onInitialize(): Promise<void> {
    // Start WebSocket service
    await this.websocketService.start();

    // Set up event listeners for service events
    this.setupServiceEventListeners();

    // Set up WebSocket event listeners
    this.setupWebSocketEventListeners();

    logger.info('Example service with WebSocket initialized');
  }

  protected setupRoutes(): void {
    // Regular HTTP routes
    this.app.get('/api/example', async (c) => {
      const tenantId = c.get('tenantId');
      
      // Broadcast to all connected clients of this tenant
      await this.websocketService.broadcastToTenant(
        tenantId,
        'custom',
        'example:event',
        { message: 'Hello from HTTP endpoint' }
      );

      return c.json({ success: true });
    });

    this.app.post('/api/example/broadcast', async (c) => {
      const { message, target } = await c.req.json();
      const tenantId = c.get('tenantId');

      // Different broadcast strategies
      switch (target) {
        case 'tenant':
          await this.websocketService.broadcastToTenant(
            tenantId,
            'custom',
            'broadcast:message',
            { message }
          );
          break;

        case 'organization':
          const orgId = c.get('organizationId');
          if (orgId) {
            await this.websocketService.broadcastToOrganization(
              orgId,
              'custom',
              'broadcast:message',
              { message }
            );
          }
          break;

        case 'user':
          const userId = c.get('userId');
          await this.websocketService.broadcastToUser(
            userId,
            'custom',
            'broadcast:message',
            { message }
          );
          break;

        default:
          // Broadcast to specific room
          await this.websocketService.broadcast(
            'custom',
            target,
            'broadcast:message',
            { message }
          );
      }

      return c.json({ success: true, target });
    });
  }

  private setupServiceEventListeners(): void {
    // Listen to internal service events and broadcast via WebSocket
    this.eventBus.on('data:updated', async (event) => {
      const { tenantId, data } = event;

      // Broadcast update to all connected clients
      await this.websocketService.broadcastToTenant(
        tenantId,
        'custom',
        'data:updated',
        data
      );
    });

    this.eventBus.on('alert:triggered', async (event) => {
      const { tenantId, alert } = event;

      // Send to alerts namespace
      await this.websocketService.broadcastToTenant(
        tenantId,
        'alerts',
        'alert:created',
        alert
      );
    });
  }

  private setupWebSocketEventListeners(): void {
    // Listen to WebSocket connection events
    this.websocketService.on('client:connected', ({ client, namespace }) => {
      logger.info('WebSocket client connected', {
        clientId: client.id,
        namespace,
        tenantId: client.tenantId,
      });

      // Track connection metrics
      this.metrics.increment('websocket.connections', {
        namespace,
        tenant: client.tenantId,
      });
    });

    this.websocketService.on('client:disconnected', ({ client, reason }) => {
      logger.info('WebSocket client disconnected', {
        clientId: client.id,
        reason,
      });

      // Update metrics
      this.metrics.decrement('websocket.connections', {
        tenant: client.tenantId,
      });
    });

    // Listen to video namespace events if needed
    this.websocketService.on('video:stream:start', async (data) => {
      logger.info('Video stream requested', data);
      
      // Could trigger video processing in another service
      await this.eventBus.emit('video:process:start', {
        ...data,
        requestedBy: 'websocket',
      });
    });
  }

  // Custom WebSocket event handlers
  private async handleCustomAction(socket: any, data: any): Promise<void> {
    const { action, payload } = data;
    const tenantId = socket.data.tenantId;
    const userId = socket.data.userId;

    logger.info('Custom action received', {
      action,
      tenantId,
      userId,
    });

    try {
      // Process the action
      const result = await this.processCustomAction(action, payload, tenantId);

      // Send response back to the specific client
      socket.emit('custom:action:response', {
        success: true,
        action,
        result,
      });

      // Optionally broadcast to others
      if (result.broadcast) {
        socket.to(`tenant:${tenantId}`).emit('custom:action:broadcast', {
          action,
          result: result.data,
          initiatedBy: userId,
        });
      }
    } catch (error) {
      logger.error('Failed to process custom action', { error, action });
      
      socket.emit('custom:action:response', {
        success: false,
        action,
        error: 'Failed to process action',
      });
    }
  }

  private async handleDataRequest(socket: any, data: any): Promise<void> {
    const { type, filters } = data;
    const tenantId = socket.data.tenantId;

    try {
      // Fetch requested data
      const result = await this.fetchData(type, filters, tenantId);

      // Send response
      socket.emit('data:response', {
        type,
        data: result,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to fetch data', { error, type });
      
      socket.emit('error', {
        message: 'Failed to fetch data',
        type,
      });
    }
  }

  // Mock service methods
  private async processCustomAction(
    action: string,
    payload: any,
    tenantId: string
  ): Promise<any> {
    // Simulate processing
    await new Promise(resolve => setTimeout(resolve, 100));

    return {
      broadcast: true,
      data: {
        action,
        processed: true,
        timestamp: new Date().toISOString(),
      },
    };
  }

  private async fetchData(
    type: string,
    filters: any,
    tenantId: string
  ): Promise<any> {
    // Simulate data fetching
    await new Promise(resolve => setTimeout(resolve, 50));

    return {
      type,
      items: [],
      total: 0,
      filters,
    };
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};

    // Check WebSocket service health
    try {
      const wsMetrics = await this.websocketService.getMetrics();
      checks.websocket = wsMetrics.totalClients >= 0;
    } catch (error) {
      checks.websocket = false;
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const metrics: string[] = [];

    // Add WebSocket metrics
    const wsMetrics = await this.websocketService.getMetrics();
    
    metrics.push('# HELP websocket_connected_clients Number of connected WebSocket clients');
    metrics.push('# TYPE websocket_connected_clients gauge');
    metrics.push(`websocket_connected_clients ${wsMetrics.totalClients}`);

    for (const [namespace, data] of Object.entries(wsMetrics.namespaces)) {
      metrics.push(`websocket_namespace_clients{namespace="${namespace}"} ${data.connectedClients}`);
    }

    return metrics.join('\n');
  }

  protected async cleanup(): Promise<void> {
    logger.info('Cleaning up example service with WebSocket...');

    // Stop WebSocket service
    await this.websocketService.stop();

    // Call parent cleanup
    await super.cleanup();
  }
}

// Usage example
async function main() {
  const service = new ExampleServiceWithWebSocket();
  await service.start();

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    await service.stop();
    process.exit(0);
  });
}

// Client usage example
export function createWebSocketClient() {
  // This would typically be in a frontend application
  /*
  import { WebSocketClient } from '@sparc/shared/websocket/client';

  const client = new WebSocketClient({
    url: 'ws://localhost:3109',
    namespace: 'custom',
    token: 'your-jwt-token',
  });

  // Connect
  await client.connect();

  // Subscribe to events
  client.on('message', (event) => {
    console.log('Received event:', event);
    
    switch (event.event) {
      case 'data:updated':
        updateLocalData(event.data);
        break;
      case 'broadcast:message':
        showNotification(event.data.message);
        break;
    }
  });

  // Send custom action
  await client.send('custom:action', {
    action: 'refresh',
    payload: { force: true }
  });

  // Request data
  const response = await client.request('data:request', {
    type: 'users',
    filters: { active: true }
  });
  */
}