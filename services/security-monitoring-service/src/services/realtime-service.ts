import { WebSocketServer, WebSocket } from 'ws';
import { Redis } from 'ioredis';
import { SecurityMonitoringService } from './main-service';
import { SecurityEvent } from '@sparc/shared/security/siem';
import { ThreatAnalysis } from '@sparc/shared/monitoring/threat-detection';
import { SecurityIncident } from '@sparc/shared/monitoring/types';
import { logger } from '@sparc/shared/utils/logger';
import jwt from 'jsonwebtoken';

interface WSClient {
  id: string;
  ws: WebSocket;
  userId: string;
  organizationId: string;
  subscriptions: Set<string>;
  isAlive: boolean;
}

export class RealTimeService {
  private wss: WebSocketServer;
  private redis: Redis;
  private pubClient: Redis;
  private subClient: Redis;
  private securityService: SecurityMonitoringService;
  private clients: Map<string, WSClient> = new Map();
  private heartbeatInterval?: NodeJS.Timer;

  constructor(
    wss: WebSocketServer,
    redis: Redis,
    securityService: SecurityMonitoringService
  ) {
    this.wss = wss;
    this.redis = redis;
    this.pubClient = redis.duplicate();
    this.subClient = redis.duplicate();
    this.securityService = securityService;
    
    this.setupWebSocketServer();
    this.setupEventListeners();
    this.setupRedisSubscriptions();
  }

  private setupWebSocketServer(): void {
    this.wss.on('connection', async (ws, req) => {
      try {
        // Extract and verify JWT token from query string
        const token = new URL(req.url!, `http://${req.headers.host}`).searchParams.get('token');
        if (!token) {
          ws.close(1008, 'Missing authentication token');
          return;
        }

        const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
        
        const client: WSClient = {
          id: crypto.randomUUID(),
          ws,
          userId: payload.userId,
          organizationId: payload.organizationId,
          subscriptions: new Set(['security:events', 'incidents', 'alerts']),
          isAlive: true
        };

        this.clients.set(client.id, client);

        // Send welcome message
        this.sendToClient(client, {
          type: 'connection',
          data: {
            clientId: client.id,
            subscriptions: Array.from(client.subscriptions)
          }
        });

        // Setup client message handlers
        ws.on('message', (data) => this.handleClientMessage(client, data));
        ws.on('pong', () => { client.isAlive = true; });
        ws.on('close', () => this.handleClientDisconnect(client));
        ws.on('error', (error) => {
          logger.error('WebSocket error', { error, clientId: client.id });
        });

        logger.info('WebSocket client connected', {
          clientId: client.id,
          userId: client.userId,
          organizationId: client.organizationId
        });

      } catch (error) {
        logger.error('WebSocket connection error', { error });
        ws.close(1008, 'Authentication failed');
      }
    });
  }

  private handleClientMessage(client: WSClient, data: any): void {
    try {
      const message = JSON.parse(data.toString());

      switch (message.type) {
        case 'subscribe':
          this.handleSubscribe(client, message.channels);
          break;
        case 'unsubscribe':
          this.handleUnsubscribe(client, message.channels);
          break;
        case 'ping':
          this.sendToClient(client, { type: 'pong', timestamp: Date.now() });
          break;
        default:
          logger.warn('Unknown message type', { type: message.type, clientId: client.id });
      }
    } catch (error) {
      logger.error('Error handling client message', { error, clientId: client.id });
    }
  }

  private handleSubscribe(client: WSClient, channels: string[]): void {
    for (const channel of channels) {
      if (this.isAuthorizedForChannel(client, channel)) {
        client.subscriptions.add(channel);
      }
    }

    this.sendToClient(client, {
      type: 'subscribed',
      channels: channels.filter(ch => client.subscriptions.has(ch))
    });
  }

  private handleUnsubscribe(client: WSClient, channels: string[]): void {
    for (const channel of channels) {
      client.subscriptions.delete(channel);
    }

    this.sendToClient(client, {
      type: 'unsubscribed',
      channels
    });
  }

  private isAuthorizedForChannel(client: WSClient, channel: string): boolean {
    // Check if client is authorized for the channel
    if (channel.startsWith('org:')) {
      const orgId = channel.split(':')[1];
      return client.organizationId === orgId;
    }
    
    if (channel.startsWith('user:')) {
      const userId = channel.split(':')[1];
      return client.userId === userId;
    }

    // Default allowed channels
    const allowedChannels = ['security:events', 'incidents', 'alerts', 'threats', 'metrics'];
    return allowedChannels.includes(channel);
  }

  private handleClientDisconnect(client: WSClient): void {
    this.clients.delete(client.id);
    logger.info('WebSocket client disconnected', { clientId: client.id });
  }

  private setupEventListeners(): void {
    // Listen to security service events
    this.securityService.on('security:event', (data: { event: SecurityEvent; analysis: ThreatAnalysis }) => {
      this.broadcastToChannel('security:events', {
        type: 'security_event',
        data
      });

      // Also broadcast to organization-specific channel
      if (data.event.organizationId) {
        this.broadcastToChannel(`org:${data.event.organizationId}`, {
          type: 'security_event',
          data
        });
      }

      // High severity events get special treatment
      if (data.analysis.riskScore > 80) {
        this.broadcastToChannel('alerts', {
          type: 'high_risk_alert',
          data: {
            event: data.event,
            riskScore: data.analysis.riskScore,
            threats: data.analysis.threats,
            recommendations: data.analysis.recommendations
          }
        });
      }
    });

    this.securityService.on('incident:created', (incident: SecurityIncident) => {
      this.broadcastToChannel('incidents', {
        type: 'incident_created',
        data: incident
      });
    });

    this.securityService.on('incident:updated', (incident: SecurityIncident) => {
      this.broadcastToChannel('incidents', {
        type: 'incident_updated',
        data: incident
      });
    });
  }

  private setupRedisSubscriptions(): void {
    // Subscribe to Redis pub/sub channels for distributed updates
    this.subClient.subscribe('security:realtime:events');
    this.subClient.subscribe('security:realtime:alerts');
    this.subClient.subscribe('security:realtime:incidents');

    this.subClient.on('message', (channel, message) => {
      try {
        const data = JSON.parse(message);
        
        // Remove the redis prefix and broadcast
        const wsChannel = channel.replace('security:realtime:', '');
        this.broadcastToChannel(wsChannel, data);
      } catch (error) {
        logger.error('Error processing Redis message', { error, channel });
      }
    });
  }

  private sendToClient(client: WSClient, message: any): void {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(message));
    }
  }

  private broadcastToChannel(channel: string, message: any): void {
    const payload = JSON.stringify(message);
    
    for (const [clientId, client] of this.clients) {
      if (client.subscriptions.has(channel) && client.ws.readyState === WebSocket.OPEN) {
        client.ws.send(payload);
      }
    }

    // Also publish to Redis for other instances
    this.pubClient.publish(`security:realtime:${channel}`, payload);
  }

  start(): void {
    // Start heartbeat to detect disconnected clients
    this.heartbeatInterval = setInterval(() => {
      for (const [clientId, client] of this.clients) {
        if (!client.isAlive) {
          client.ws.terminate();
          this.clients.delete(clientId);
          continue;
        }

        client.isAlive = false;
        client.ws.ping();
      }
    }, 30000); // 30 seconds

    // Send initial metrics to all clients
    this.broadcastSystemMetrics();
    
    // Update metrics periodically
    setInterval(() => {
      this.broadcastSystemMetrics();
    }, 60000); // Every minute

    logger.info('Real-time service started');
  }

  private async broadcastSystemMetrics(): Promise<void> {
    try {
      const metrics = await this.securityService.getSecurityMetrics({
        start: new Date(Date.now() - 3600000), // Last hour
        end: new Date()
      });

      this.broadcastToChannel('metrics', {
        type: 'system_metrics',
        data: metrics
      });
    } catch (error) {
      logger.error('Error broadcasting system metrics', { error });
    }
  }

  stop(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    // Close all client connections
    for (const [clientId, client] of this.clients) {
      client.ws.close(1001, 'Server shutting down');
    }

    this.clients.clear();
    
    // Unsubscribe from Redis
    this.subClient.unsubscribe();
    
    logger.info('Real-time service stopped');
  }
}