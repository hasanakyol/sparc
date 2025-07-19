import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '../middleware/auth';
import { rateLimitMiddleware } from '../middleware/rate-limit';
import { globalErrorHandler } from '../middleware/error-handler';
import { requestIdMiddleware } from '../middleware/request-id';
import { metricsMiddleware } from '../middleware/metrics';

export interface ServiceConfig {
  serviceName: string;
  port: number;
  version: string;
  jwtSecret: string;
  redisUrl: string;
  databaseUrl: string;
  enableAuth?: boolean;
  enableRateLimit?: boolean;
  enableMetrics?: boolean;
  corsOrigins?: string[];
}

export abstract class MicroserviceBase {
  protected app: Hono;
  protected prisma: PrismaClient;
  protected redis: Redis;
  protected config: ServiceConfig;
  private server: any;

  constructor(config: ServiceConfig) {
    this.config = config;
    this.app = new Hono();
    this.prisma = new PrismaClient({
      datasources: {
        db: {
          url: config.databaseUrl
        }
      }
    });
    this.redis = new Redis(config.redisUrl);

    this.setupMiddleware();
    this.setupHealthCheck();
  }

  private setupMiddleware(): void {
    // CORS
    this.app.use('*', cors({
      origin: this.config.corsOrigins || ['http://localhost:3000'],
      credentials: true
    }));

    // Request ID
    this.app.use('*', requestIdMiddleware);

    // Logging
    this.app.use('*', logger());

    // Pretty JSON in development
    if (process.env.NODE_ENV !== 'production') {
      this.app.use('*', prettyJSON());
    }

    // Metrics
    if (this.config.enableMetrics !== false) {
      this.app.use('*', metricsMiddleware);
    }

    // Rate limiting
    if (this.config.enableRateLimit !== false) {
      this.app.use('*', rateLimitMiddleware);
    }

    // Authentication (skip for health endpoints)
    if (this.config.enableAuth !== false) {
      this.app.use('/api/*', authMiddleware);
    }

    // Error handling
    this.app.onError(globalErrorHandler);
  }

  private setupHealthCheck(): void {
    this.app.get('/health', async (c) => {
      const checks = await this.performHealthChecks();
      const healthy = Object.values(checks).every(check => check);

      return c.json({
        status: healthy ? 'healthy' : 'unhealthy',
        service: this.config.serviceName,
        version: this.config.version,
        timestamp: new Date().toISOString(),
        checks
      }, healthy ? 200 : 503);
    });

    this.app.get('/ready', async (c) => {
      const ready = await this.isReady();
      return c.json({ ready }, ready ? 200 : 503);
    });

    this.app.get('/metrics', async (c) => {
      const metrics = await this.getMetrics();
      return c.text(metrics);
    });
  }

  protected async performHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};

    // Database check
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      checks.database = true;
    } catch {
      checks.database = false;
    }

    // Redis check
    try {
      await this.redis.ping();
      checks.redis = true;
    } catch {
      checks.redis = false;
    }

    // Custom health checks
    const customChecks = await this.customHealthChecks();
    Object.assign(checks, customChecks);

    return checks;
  }

  protected async isReady(): Promise<boolean> {
    // Override in subclass for custom readiness logic
    const checks = await this.performHealthChecks();
    return Object.values(checks).every(check => check);
  }

  protected async getMetrics(): Promise<string> {
    // Override in subclass for custom metrics
    return '';
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    // Override in subclass for service-specific health checks
    return {};
  }

  public abstract setupRoutes(): void;

  public async start(): Promise<void> {
    try {
      // Connect to database
      await this.prisma.$connect();
      console.log(`[${this.config.serviceName}] Connected to database`);

      // Setup routes
      this.setupRoutes();

      // Start server
      // Check if running in Bun environment
      if (typeof Bun !== 'undefined') {
        this.server = Bun.serve({
          port: this.config.port,
          fetch: this.app.fetch
        });
      } else {
        // For Node.js environments, the service should override the start method
        // to use appropriate server implementation (e.g., @hono/node-server)
        console.warn(`[${this.config.serviceName}] Running in non-Bun environment. Please override start() method.`);
      }

      console.log(`[${this.config.serviceName}] Service v${this.config.version} running on port ${this.config.port}`);

      // Setup graceful shutdown
      this.setupGracefulShutdown();
    } catch (error) {
      console.error(`[${this.config.serviceName}] Failed to start:`, error);
      process.exit(1);
    }
  }

  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      console.log(`[${this.config.serviceName}] ${signal} received, shutting down gracefully...`);
      
      try {
        // Close server
        if (this.server) {
          this.server.stop();
        }

        // Disconnect from services
        await this.prisma.$disconnect();
        await this.redis.quit();

        // Custom cleanup
        await this.cleanup();

        console.log(`[${this.config.serviceName}] Shutdown complete`);
        process.exit(0);
      } catch (error) {
        console.error(`[${this.config.serviceName}] Error during shutdown:`, error);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }

  protected async cleanup(): Promise<void> {
    // Override in subclass for custom cleanup logic
  }

  // Utility methods for common patterns
  protected async withTransaction<T>(
    fn: (tx: PrismaClient) => Promise<T>
  ): Promise<T> {
    return await this.prisma.$transaction(fn);
  }

  protected async withCache<T>(
    key: string,
    ttl: number,
    fn: () => Promise<T>
  ): Promise<T> {
    const cached = await this.redis.get(key);
    if (cached) {
      return JSON.parse(cached);
    }

    const result = await fn();
    await this.redis.setex(key, ttl, JSON.stringify(result));
    return result;
  }

  protected async invalidateCache(pattern: string): Promise<void> {
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  protected async publishEvent(event: string, data: any): Promise<void> {
    await this.redis.publish(`${this.config.serviceName}:${event}`, JSON.stringify(data));
  }

  protected subscribeToEvent(event: string, handler: (data: any) => void): void {
    const subscriber = new Redis(this.config.redisUrl);
    subscriber.subscribe(`${this.config.serviceName}:${event}`);
    subscriber.on('message', (channel, message) => {
      try {
        const data = JSON.parse(message);
        handler(data);
      } catch (error) {
        console.error(`[${this.config.serviceName}] Error handling event:`, error);
      }
    });
  }
}