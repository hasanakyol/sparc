import { EventEmitter } from 'events';
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';
import { prisma } from '../database/prisma';
import * as Sentry from '@sentry/node';
import { ProfilingIntegration } from '@sentry/profiling-node';

export interface ErrorEvent {
  id: string;
  timestamp: Date;
  service: string;
  environment: string;
  errorType: string;
  message: string;
  stack?: string;
  context?: Record<string, any>;
  user?: {
    id?: string;
    email?: string;
    organizationId?: string;
  };
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: any;
  };
  tags?: Record<string, string>;
  fingerprint?: string[];
  level: 'fatal' | 'error' | 'warning' | 'info';
}

export interface ErrorMetrics {
  totalErrors: number;
  errorsByType: Record<string, number>;
  errorsByService: Record<string, number>;
  errorsByLevel: Record<string, number>;
  errorRate: number;
  topErrors: Array<{
    fingerprint: string;
    count: number;
    lastSeen: Date;
    example: ErrorEvent;
  }>;
}

export class ErrorTracker extends EventEmitter {
  private redis: Redis;
  private metricsInterval: NodeJS.Timer | null = null;
  private batchQueue: ErrorEvent[] = [];
  private batchTimer: NodeJS.Timer | null = null;
  private readonly BATCH_SIZE = 100;
  private readonly BATCH_INTERVAL = 5000; // 5 seconds

  constructor(redis: Redis) {
    super();
    this.redis = redis;
    this.initializeSentry();
    this.startMetricsCollection();
  }

  private initializeSentry(): void {
    const dsn = process.env.SENTRY_DSN;
    if (!dsn) {
      logger.warn('Sentry DSN not configured, error tracking will be limited');
      return;
    }

    Sentry.init({
      dsn,
      environment: process.env.NODE_ENV || 'development',
      integrations: [
        // Automatic instrumentation
        new Sentry.Integrations.Http({ tracing: true }),
        new Sentry.Integrations.Express({ app: true }),
        new Sentry.Integrations.Postgres(),
        new Sentry.Integrations.Redis(),
        // Performance profiling
        new ProfilingIntegration(),
      ],
      // Performance Monitoring
      tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
      profilesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
      // Release tracking
      release: process.env.APP_VERSION,
      // Before send hook for data scrubbing
      beforeSend(event, hint) {
        // Scrub sensitive data
        if (event.request?.cookies) {
          delete event.request.cookies;
        }
        if (event.request?.headers) {
          delete event.request.headers.authorization;
          delete event.request.headers.cookie;
        }
        return event;
      },
    });
  }

  async trackError(error: Error | ErrorEvent, context?: Record<string, any>): Promise<void> {
    try {
      let errorEvent: ErrorEvent;

      if (error instanceof Error) {
        errorEvent = {
          id: crypto.randomUUID(),
          timestamp: new Date(),
          service: process.env.SERVICE_NAME || 'unknown',
          environment: process.env.NODE_ENV || 'development',
          errorType: error.name,
          message: error.message,
          stack: error.stack,
          context,
          level: 'error',
        };
      } else {
        errorEvent = {
          ...error,
          id: error.id || crypto.randomUUID(),
          timestamp: error.timestamp || new Date(),
        };
      }

      // Generate fingerprint for grouping similar errors
      if (!errorEvent.fingerprint) {
        errorEvent.fingerprint = this.generateFingerprint(errorEvent);
      }

      // Send to Sentry if configured
      if (Sentry.getCurrentHub().getClient()) {
        const sentryEvent = error instanceof Error ? error : new Error(errorEvent.message);
        Sentry.captureException(sentryEvent, {
          tags: errorEvent.tags,
          level: errorEvent.level as Sentry.SeverityLevel,
          contexts: {
            custom: errorEvent.context,
          },
          user: errorEvent.user,
          fingerprint: errorEvent.fingerprint,
        });
      }

      // Add to batch queue
      this.batchQueue.push(errorEvent);

      // Store in Redis for real-time metrics
      await this.updateRedisMetrics(errorEvent);

      // Emit event for real-time monitoring
      this.emit('error', errorEvent);

      // Check if we should flush the batch
      if (this.batchQueue.length >= this.BATCH_SIZE) {
        await this.flushBatch();
      } else if (!this.batchTimer) {
        this.batchTimer = setTimeout(() => this.flushBatch(), this.BATCH_INTERVAL);
      }

    } catch (trackingError) {
      logger.error('Failed to track error', { error: trackingError });
    }
  }

  private generateFingerprint(error: ErrorEvent): string[] {
    const fingerprint: string[] = [
      error.service,
      error.errorType,
    ];

    // Add key parts of the error message (without dynamic values)
    const cleanMessage = error.message
      .replace(/\b\d+\b/g, 'N') // Replace numbers
      .replace(/\b[a-f0-9-]{36}\b/gi, 'UUID') // Replace UUIDs
      .replace(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g, 'IP'); // Replace IPs

    fingerprint.push(cleanMessage);

    // Add request path if available
    if (error.request?.url) {
      const urlPath = new URL(error.request.url, 'http://localhost').pathname;
      fingerprint.push(urlPath);
    }

    return fingerprint;
  }

  private async updateRedisMetrics(error: ErrorEvent): Promise<void> {
    const now = Date.now();
    const hourKey = `errors:${Math.floor(now / 3600000)}`; // Hour bucket

    try {
      const pipeline = this.redis.pipeline();

      // Increment counters
      pipeline.hincrby(`${hourKey}:count`, 'total', 1);
      pipeline.hincrby(`${hourKey}:count`, `type:${error.errorType}`, 1);
      pipeline.hincrby(`${hourKey}:count`, `service:${error.service}`, 1);
      pipeline.hincrby(`${hourKey}:count`, `level:${error.level}`, 1);

      // Track unique errors by fingerprint
      const fingerprintKey = error.fingerprint?.join(':') || 'unknown';
      pipeline.hincrby(`${hourKey}:fingerprints`, fingerprintKey, 1);
      
      // Store error sample
      pipeline.hset(
        `${hourKey}:samples`,
        fingerprintKey,
        JSON.stringify({
          ...error,
          stack: error.stack?.substring(0, 1000), // Truncate stack trace
        })
      );

      // Update error rate tracking
      pipeline.zadd(`errors:timeline`, now, `${now}:${error.id}`);
      pipeline.zremrangebyscore('errors:timeline', 0, now - 3600000); // Keep last hour

      // Set expiry
      pipeline.expire(hourKey, 7 * 24 * 3600); // 7 days

      await pipeline.exec();
    } catch (redisError) {
      logger.error('Failed to update Redis metrics', { error: redisError });
    }
  }

  private async flushBatch(): Promise<void> {
    if (this.batchQueue.length === 0) return;

    const batch = [...this.batchQueue];
    this.batchQueue = [];

    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = null;
    }

    try {
      // Store in database
      await prisma.$executeRawUnsafe(`
        INSERT INTO error_events (
          id, timestamp, service, environment, error_type, 
          message, stack, context, user_data, request_data, 
          tags, fingerprint, level
        ) VALUES ${batch.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ')}
      `, ...batch.flatMap(e => [
        e.id,
        e.timestamp,
        e.service,
        e.environment,
        e.errorType,
        e.message,
        e.stack,
        JSON.stringify(e.context || {}),
        JSON.stringify(e.user || {}),
        JSON.stringify(e.request || {}),
        JSON.stringify(e.tags || {}),
        JSON.stringify(e.fingerprint || []),
        e.level,
      ]));

      logger.info(`Flushed ${batch.length} error events to database`);
    } catch (dbError) {
      logger.error('Failed to flush error batch to database', { error: dbError });
      // Re-queue failed items
      this.batchQueue.unshift(...batch);
    }
  }

  async getMetrics(timeRange: { start: Date; end: Date }): Promise<ErrorMetrics> {
    const metrics: ErrorMetrics = {
      totalErrors: 0,
      errorsByType: {},
      errorsByService: {},
      errorsByLevel: {},
      errorRate: 0,
      topErrors: [],
    };

    try {
      // Get metrics from Redis for recent data
      const now = Date.now();
      const hourStart = Math.floor(timeRange.start.getTime() / 3600000);
      const hourEnd = Math.floor(timeRange.end.getTime() / 3600000);

      for (let hour = hourStart; hour <= hourEnd; hour++) {
        const hourKey = `errors:${hour}`;
        
        // Get counts
        const counts = await this.redis.hgetall(`${hourKey}:count`);
        if (counts.total) {
          metrics.totalErrors += parseInt(counts.total);
        }

        // Aggregate by type
        Object.entries(counts).forEach(([key, value]) => {
          if (key.startsWith('type:')) {
            const type = key.substring(5);
            metrics.errorsByType[type] = (metrics.errorsByType[type] || 0) + parseInt(value);
          } else if (key.startsWith('service:')) {
            const service = key.substring(8);
            metrics.errorsByService[service] = (metrics.errorsByService[service] || 0) + parseInt(value);
          } else if (key.startsWith('level:')) {
            const level = key.substring(6);
            metrics.errorsByLevel[level] = (metrics.errorsByLevel[level] || 0) + parseInt(value);
          }
        });

        // Get top errors by fingerprint
        const fingerprints = await this.redis.hgetall(`${hourKey}:fingerprints`);
        const samples = await this.redis.hgetall(`${hourKey}:samples`);

        Object.entries(fingerprints).forEach(([fingerprint, count]) => {
          const existingIndex = metrics.topErrors.findIndex(e => e.fingerprint === fingerprint);
          const sample = samples[fingerprint] ? JSON.parse(samples[fingerprint]) : null;

          if (existingIndex >= 0) {
            metrics.topErrors[existingIndex].count += parseInt(count);
            metrics.topErrors[existingIndex].lastSeen = new Date();
          } else if (sample) {
            metrics.topErrors.push({
              fingerprint,
              count: parseInt(count),
              lastSeen: new Date(),
              example: sample,
            });
          }
        });
      }

      // Sort top errors by count
      metrics.topErrors.sort((a, b) => b.count - a.count);
      metrics.topErrors = metrics.topErrors.slice(0, 10);

      // Calculate error rate
      const duration = timeRange.end.getTime() - timeRange.start.getTime();
      metrics.errorRate = metrics.totalErrors / (duration / 1000); // Errors per second

      // Get historical data from database for longer time ranges
      if (duration > 24 * 3600 * 1000) { // More than 24 hours
        const dbMetrics = await this.getHistoricalMetrics(timeRange);
        // Merge with Redis metrics
        metrics.totalErrors += dbMetrics.totalErrors;
        Object.entries(dbMetrics.errorsByType).forEach(([type, count]) => {
          metrics.errorsByType[type] = (metrics.errorsByType[type] || 0) + count;
        });
      }

    } catch (error) {
      logger.error('Failed to get error metrics', { error });
    }

    return metrics;
  }

  private async getHistoricalMetrics(timeRange: { start: Date; end: Date }): Promise<Partial<ErrorMetrics>> {
    const result = await prisma.$queryRaw<any[]>`
      SELECT 
        COUNT(*) as total,
        error_type,
        service,
        level,
        COUNT(*) as count
      FROM error_events
      WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
      GROUP BY error_type, service, level
    `;

    const metrics: Partial<ErrorMetrics> = {
      totalErrors: 0,
      errorsByType: {},
      errorsByService: {},
      errorsByLevel: {},
    };

    for (const row of result) {
      metrics.totalErrors! += parseInt(row.count);
      metrics.errorsByType![row.error_type] = (metrics.errorsByType![row.error_type] || 0) + parseInt(row.count);
      metrics.errorsByService![row.service] = (metrics.errorsByService![row.service] || 0) + parseInt(row.count);
      metrics.errorsByLevel![row.level] = (metrics.errorsByLevel![row.level] || 0) + parseInt(row.count);
    }

    return metrics;
  }

  private startMetricsCollection(): void {
    // Collect and emit metrics every minute
    this.metricsInterval = setInterval(async () => {
      const metrics = await this.getMetrics({
        start: new Date(Date.now() - 5 * 60 * 1000), // Last 5 minutes
        end: new Date(),
      });

      this.emit('metrics', metrics);

      // Log high error rates
      if (metrics.errorRate > 1) { // More than 1 error per second
        logger.warn('High error rate detected', { errorRate: metrics.errorRate });
      }
    }, 60000); // Every minute
  }

  async close(): Promise<void> {
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
    }
    await this.flushBatch();
  }
}

// Create singleton instance
export const errorTracker = new ErrorTracker(
  new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
  })
);

// Export convenience functions
export async function trackError(error: Error | ErrorEvent, context?: Record<string, any>): Promise<void> {
  return errorTracker.trackError(error, context);
}

export async function getErrorMetrics(timeRange: { start: Date; end: Date }): Promise<ErrorMetrics> {
  return errorTracker.getMetrics(timeRange);
}

// Express error handler middleware
export function errorHandler(err: Error, req: any, res: any, next: any): void {
  const errorContext = {
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.user?.id,
    organizationId: req.user?.organizationId,
  };

  trackError(err, errorContext).catch(trackingError => {
    logger.error('Failed to track error in error handler', { error: trackingError });
  });

  res.status(err.status || 500).json({
    error: {
      message: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
      code: err.code || 'INTERNAL_ERROR',
      timestamp: new Date().toISOString(),
    },
  });
}