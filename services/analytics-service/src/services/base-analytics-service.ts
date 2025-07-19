import { PrismaClient } from '@sparc/shared/prisma';
import Redis from 'ioredis';
import { Client } from '@opensearch-project/opensearch';
import { CacheService } from '@sparc/shared/utils/cache';
import { createLogger, Logger } from 'winston';
import { WebSocketServer } from 'ws';

export interface AnalyticsDependencies {
  prisma: PrismaClient;
  redis: Redis;
  opensearch: Client;
  cache: CacheService;
  logger: Logger;
  wss?: WebSocketServer;
  config: AnalyticsConfig;
}

export interface AnalyticsConfig {
  opensearchIndex: string;
  mlApiUrl?: string;
  mlApiKey?: string;
  enableRealtimeUpdates: boolean;
  retentionDays: number;
  anomalyThreshold: number;
}

export abstract class BaseAnalyticsService {
  protected prisma: PrismaClient;
  protected redis: Redis;
  protected opensearch: Client;
  protected cache: CacheService;
  protected logger: Logger;
  protected wss?: WebSocketServer;
  protected config: AnalyticsConfig;

  constructor(dependencies: AnalyticsDependencies) {
    this.prisma = dependencies.prisma;
    this.redis = dependencies.redis;
    this.opensearch = dependencies.opensearch;
    this.cache = dependencies.cache;
    this.logger = dependencies.logger;
    this.wss = dependencies.wss;
    this.config = dependencies.config;
  }

  protected async broadcastUpdate(channel: string, data: any): Promise<void> {
    if (this.wss && this.config.enableRealtimeUpdates) {
      this.wss.clients.forEach((client) => {
        if (client.readyState === 1) { // WebSocket.OPEN
          client.send(JSON.stringify({
            channel,
            data,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }
  }

  protected async storeInOpenSearch(index: string, data: any): Promise<void> {
    try {
      await this.opensearch.index({
        index,
        body: data,
        refresh: true
      });
    } catch (error) {
      this.logger.error('Failed to store in OpenSearch', { error, index, data });
      throw error;
    }
  }

  protected async queryOpenSearch(index: string, query: any): Promise<any[]> {
    try {
      const response = await this.opensearch.search({
        index,
        body: query
      });
      return response.body.hits.hits.map((hit: any) => hit._source);
    } catch (error) {
      this.logger.error('Failed to query OpenSearch', { error, index, query });
      throw error;
    }
  }

  protected generateId(): string {
    return crypto.randomUUID();
  }

  protected async invalidateCache(pattern: string): Promise<void> {
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }
}