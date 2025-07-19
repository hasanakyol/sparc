import { MicroserviceBase } from '@sparc/shared/microservice-base';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { Client } from '@opensearch-project/opensearch';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { CacheService } from '@sparc/shared/utils/cache';

// Import routes
import { createHealthRoutes } from './routes/health';
import { createAnalyticsRoutes } from './routes/analytics';
import { createVideoRoutes } from './routes/video';
import { createPredictionsRoutes } from './routes/predictions';
import { createExportRoutes } from './routes/export';

// Import services
import { AnalyticsEngine } from './services/analytics-engine';

interface AnalyticsServiceConfig {
  opensearchUrl: string;
  opensearchIndex: string;
  opensearchUsername?: string;
  opensearchPassword?: string;
  enableWebSocket: boolean;
}

class AnalyticsService extends MicroserviceBase {
  private prisma: PrismaClient;
  private redis: Redis;
  private opensearch: Client;
  private cache: CacheService;
  private analyticsEngine?: AnalyticsEngine;
  private wss?: WebSocketServer;
  private config: AnalyticsServiceConfig;

  constructor() {
    super('analytics-service', {
      port: parseInt(process.env.PORT || '3009', 10)
    });

    this.config = {
      opensearchUrl: process.env.OPENSEARCH_URL || 'http://localhost:9200',
      opensearchIndex: process.env.OPENSEARCH_INDEX || 'sparc-analytics',
      opensearchUsername: process.env.OPENSEARCH_USERNAME,
      opensearchPassword: process.env.OPENSEARCH_PASSWORD,
      enableWebSocket: process.env.ENABLE_WEBSOCKET === 'true'
    };

    // Initialize services
    this.prisma = new PrismaClient();
    this.redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
    
    // Initialize OpenSearch client
    this.opensearch = new Client({
      node: this.config.opensearchUrl,
      auth: this.config.opensearchUsername ? {
        username: this.config.opensearchUsername,
        password: this.config.opensearchPassword!
      } : undefined
    });

    // Initialize cache service
    this.cache = new CacheService(this.redis);
  }

  protected async setupRoutes(): Promise<void> {
    // Test connections
    await this.testConnections();
    
    // Initialize OpenSearch indices
    await this.initializeOpenSearch();
    
    // Initialize WebSocket if enabled
    if (this.config.enableWebSocket) {
      this.setupWebSocket();
    }
    
    // Initialize Analytics Engine
    this.analyticsEngine = new AnalyticsEngine(
      this.prisma,
      this.redis,
      this.opensearch,
      this.cache,
      this.logger,
      this.wss,
      {
        opensearchIndex: this.config.opensearchIndex,
        enableRealtimeUpdates: this.config.enableWebSocket
      }
    );
    
    // Mount routes
    this.app.route('/health', createHealthRoutes(this.prisma, this.redis, this.opensearch));
    this.app.route('/analytics', createAnalyticsRoutes(this.analyticsEngine));
    this.app.route('/analytics/video', createVideoRoutes(this.analyticsEngine));
    this.app.route('/analytics/predictions', createPredictionsRoutes(this.analyticsEngine));
    this.app.route('/analytics/export', createExportRoutes(this.analyticsEngine, this.prisma, this.opensearch));
    
    // Service-specific health check
    this.app.get('/health/detailed', async (c) => {
      const opensearchHealth = await this.opensearch.cluster.health();
      const redisInfo = await this.redis.info();
      
      return c.json({
        service: this.serviceName,
        status: 'healthy',
        connections: {
          database: await this.prisma.$queryRaw`SELECT 1`,
          redis: redisInfo.includes('redis_version'),
          opensearch: opensearchHealth.body.status
        },
        websocket: {
          enabled: this.config.enableWebSocket,
          clients: this.wss?.clients?.size || 0
        },
        timestamp: new Date().toISOString()
      });
    });
  }

  private async testConnections(): Promise<void> {
    try {
      // Connect to database
      await this.prisma.$connect();
      this.logger.info('Connected to database');
      
      // Test Redis connection
      await this.redis.ping();
      this.logger.info('Connected to Redis');
      
      // Test OpenSearch connection
      await this.opensearch.ping();
      this.logger.info('Connected to OpenSearch');
    } catch (error) {
      this.logger.error('Failed to establish connections', { error });
      throw error;
    }
  }

  private async initializeOpenSearch(): Promise<void> {
    const indices = [
      this.config.opensearchIndex,
      `${this.config.opensearchIndex}-anomalies`,
      `${this.config.opensearchIndex}-occupancy`,
      `${this.config.opensearchIndex}-predictions`,
      `${this.config.opensearchIndex}-video`,
      `${this.config.opensearchIndex}-behavior`
    ];
    
    for (const index of indices) {
      try {
        const exists = await this.opensearch.indices.exists({ index });
        if (!exists.body) {
          await this.opensearch.indices.create({
            index,
            body: {
              settings: {
                number_of_shards: 2,
                number_of_replicas: 1
              },
              mappings: this.getIndexMappings(index)
            }
          });
          this.logger.info(`Created OpenSearch index: ${index}`);
        }
      } catch (error) {
        this.logger.error(`Failed to create index ${index}`, { error });
      }
    }
  }

  private getIndexMappings(index: string): any {
    // Define specific mappings for each index type
    if (index.includes('anomalies')) {
      return {
        properties: {
          timestamp: { type: 'date' },
          tenantId: { type: 'keyword' },
          type: { type: 'keyword' },
          severity: { type: 'keyword' },
          location: {
            properties: {
              buildingId: { type: 'keyword' },
              floorId: { type: 'keyword' },
              zoneId: { type: 'keyword' }
            }
          },
          score: { type: 'float' },
          description: { type: 'text' },
          metadata: { type: 'object' }
        }
      };
    } else if (index.includes('occupancy')) {
      return {
        properties: {
          timestamp: { type: 'date' },
          tenantId: { type: 'keyword' },
          location: {
            properties: {
              buildingId: { type: 'keyword' },
              floorId: { type: 'keyword' },
              zoneId: { type: 'keyword' }
            }
          },
          occupancy: { type: 'integer' },
          capacity: { type: 'integer' },
          utilizationRate: { type: 'float' }
        }
      };
    } else if (index.includes('video')) {
      return {
        properties: {
          timestamp: { type: 'date' },
          tenantId: { type: 'keyword' },
          cameraId: { type: 'keyword' },
          eventType: { type: 'keyword' },
          objects: {
            type: 'nested',
            properties: {
              type: { type: 'keyword' },
              confidence: { type: 'float' },
              count: { type: 'integer' }
            }
          },
          analytics: { type: 'object' },
          metadata: { type: 'object' }
        }
      };
    }
    
    // Default mapping
    return {
      properties: {
        timestamp: { type: 'date' },
        tenantId: { type: 'keyword' },
        type: { type: 'keyword' },
        data: { type: 'object' },
        metadata: { type: 'object' }
      }
    };
  }

  private setupWebSocket(): void {
    const server = createServer();
    this.wss = new WebSocketServer({ server });
    
    this.wss.on('connection', (ws, req) => {
      this.logger.info('WebSocket client connected', {
        remoteAddress: req.socket.remoteAddress
      });
      
      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message.toString());
          this.handleWebSocketMessage(ws, data);
        } catch (error) {
          this.logger.error('Invalid WebSocket message', { error });
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Invalid message format'
          }));
        }
      });
      
      ws.on('close', () => {
        this.logger.info('WebSocket client disconnected');
      });
      
      ws.on('error', (error) => {
        this.logger.error('WebSocket error', { error });
      });
      
      // Send welcome message
      ws.send(JSON.stringify({
        type: 'connected',
        message: 'Connected to analytics service',
        timestamp: new Date().toISOString()
      }));
    });
    
    // Start WebSocket server on different port
    const wsPort = parseInt(process.env.WS_PORT || '3019', 10);
    server.listen(wsPort, () => {
      this.logger.info(`WebSocket server listening on port ${wsPort}`);
    });
  }

  private handleWebSocketMessage(ws: any, data: any): void {
    switch (data.type) {
      case 'subscribe':
        // Handle subscription to specific analytics streams
        if (data.channel) {
          ws.channel = data.channel;
          ws.send(JSON.stringify({
            type: 'subscribed',
            channel: data.channel
          }));
        }
        break;
        
      case 'unsubscribe':
        // Handle unsubscription
        delete ws.channel;
        ws.send(JSON.stringify({
          type: 'unsubscribed'
        }));
        break;
        
      case 'ping':
        // Health check
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

  protected async cleanup(): Promise<void> {
    try {
      // Disconnect from database
      await this.prisma.$disconnect();
      this.logger.info('Disconnected from database');
      
      // Close Redis connection
      await this.redis.quit();
      this.logger.info('Disconnected from Redis');
      
      // Close OpenSearch connection
      await this.opensearch.close();
      this.logger.info('Disconnected from OpenSearch');
      
      // Close WebSocket server
      if (this.wss) {
        await new Promise<void>((resolve) => {
          this.wss!.close(() => {
            this.logger.info('WebSocket server closed');
            resolve();
          });
        });
      }
    } catch (error) {
      this.logger.error('Error during cleanup', { error });
      throw error;
    }
    
    await super.cleanup();
  }
}

// Create and start the service
const service = new AnalyticsService();
service.start();