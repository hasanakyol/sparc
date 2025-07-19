import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { logger } from '@sparc/shared';
import { RateLimiterRedis, RateLimiterRes } from 'rate-limiter-flexible';

interface QuotaConfig {
  metric: string;
  limit: number;
  window: 'minute' | 'hour' | 'day' | 'month';
  softLimit?: number; // Warning threshold
}

interface QuotaStatus {
  metric: string;
  used: number;
  limit: number;
  remaining: number;
  percentage: number;
  resetsAt: Date;
  exceeded: boolean;
  warning: boolean;
}

export class QuotaService {
  private rateLimiters: Map<string, RateLimiterRedis> = new Map();
  private defaultQuotas: QuotaConfig[] = [
    { metric: 'api_calls', limit: 10000, window: 'hour' },
    { metric: 'webhook_deliveries', limit: 5000, window: 'hour' },
    { metric: 'data_transfer', limit: 1073741824, window: 'day' }, // 1GB
    { metric: 'integrations', limit: 100, window: 'month' },
    { metric: 'plugins', limit: 50, window: 'month' }
  ];

  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {
    this.initializeRateLimiters();
  }

  private initializeRateLimiters(): void {
    for (const quota of this.defaultQuotas) {
      const duration = this.getWindowDuration(quota.window);
      
      const limiter = new RateLimiterRedis({
        storeClient: this.redis,
        keyPrefix: `quota:${quota.metric}`,
        points: quota.limit,
        duration,
        blockDuration: 0 // Don't block, just track
      });

      this.rateLimiters.set(quota.metric, limiter);
    }
  }

  async checkQuota(
    tenantId: string,
    metric: string,
    points: number = 1
  ): Promise<{ allowed: boolean; remaining: number; resetsAt: Date }> {
    try {
      const limiter = this.rateLimiters.get(metric);
      if (!limiter) {
        // No quota defined for this metric
        return { allowed: true, remaining: Infinity, resetsAt: new Date() };
      }

      // Get tenant-specific quota override if exists
      const customQuota = await this.getTenantQuota(tenantId, metric);
      if (customQuota) {
        const customLimiter = new RateLimiterRedis({
          storeClient: this.redis,
          keyPrefix: `quota:custom:${metric}`,
          points: customQuota.limit,
          duration: this.getWindowDuration(customQuota.window),
          blockDuration: 0
        });

        try {
          const result = await customLimiter.consume(tenantId, points);
          return {
            allowed: true,
            remaining: result.remainingPoints,
            resetsAt: new Date(Date.now() + result.msBeforeNext)
          };
        } catch (rateLimiterRes) {
          const res = rateLimiterRes as RateLimiterRes;
          return {
            allowed: false,
            remaining: res.remainingPoints || 0,
            resetsAt: new Date(Date.now() + res.msBeforeNext)
          };
        }
      }

      // Use default quota
      const result = await limiter.get(tenantId);
      const consumed = result ? result.consumedPoints : 0;
      const limit = limiter.points;
      const remaining = limit - consumed;

      return {
        allowed: remaining >= points,
        remaining: Math.max(0, remaining),
        resetsAt: result 
          ? new Date(Date.now() + result.msBeforeNext)
          : new Date(Date.now() + limiter.duration * 1000)
      };
    } catch (error) {
      logger.error('Failed to check quota', { error, tenantId, metric });
      // Fail open - allow the request but log the error
      return { allowed: true, remaining: 0, resetsAt: new Date() };
    }
  }

  async incrementUsage(
    tenantId: string,
    metric: string,
    points: number = 1
  ): Promise<void> {
    try {
      const limiter = this.rateLimiters.get(metric);
      if (!limiter) {
        return;
      }

      await limiter.consume(tenantId, points);

      // Check if we should send a warning
      const status = await this.getQuotaStatus(tenantId, metric);
      if (status.warning && !status.exceeded) {
        await this.sendQuotaWarning(tenantId, metric, status);
      }
    } catch (error) {
      if (error instanceof Error && error.name !== 'RateLimiterRes') {
        logger.error('Failed to increment usage', { error, tenantId, metric });
      }
    }
  }

  async getQuotaInfo(tenantId: string): Promise<{
    quotas: QuotaStatus[];
    customQuotas: any[];
  }> {
    const quotas: QuotaStatus[] = [];

    // Get status for all metrics
    for (const quota of this.defaultQuotas) {
      const status = await this.getQuotaStatus(tenantId, quota.metric);
      quotas.push(status);
    }

    // Get custom quotas
    const customQuotas = await this.prisma.tenantQuota.findMany({
      where: { tenantId }
    });

    return { quotas, customQuotas };
  }

  async getQuotaStatus(
    tenantId: string,
    metric: string
  ): Promise<QuotaStatus> {
    const limiter = this.rateLimiters.get(metric);
    const defaultQuota = this.defaultQuotas.find(q => q.metric === metric);
    
    if (!limiter || !defaultQuota) {
      return {
        metric,
        used: 0,
        limit: Infinity,
        remaining: Infinity,
        percentage: 0,
        resetsAt: new Date(),
        exceeded: false,
        warning: false
      };
    }

    // Check for custom quota
    const customQuota = await this.getTenantQuota(tenantId, metric);
    const activeQuota = customQuota || defaultQuota;

    const result = await limiter.get(tenantId);
    const used = result ? result.consumedPoints : 0;
    const limit = activeQuota.limit;
    const remaining = Math.max(0, limit - used);
    const percentage = (used / limit) * 100;
    const softLimit = activeQuota.softLimit || limit * 0.8; // 80% default warning

    return {
      metric,
      used,
      limit,
      remaining,
      percentage,
      resetsAt: result 
        ? new Date(Date.now() + result.msBeforeNext)
        : new Date(Date.now() + this.getWindowDuration(activeQuota.window) * 1000),
      exceeded: used >= limit,
      warning: used >= softLimit
    };
  }

  async setTenantQuota(
    tenantId: string,
    metric: string,
    config: QuotaConfig
  ): Promise<void> {
    await this.prisma.tenantQuota.upsert({
      where: {
        tenantId_metric: {
          tenantId,
          metric
        }
      },
      update: {
        limit: config.limit,
        window: config.window,
        softLimit: config.softLimit,
        updatedAt: new Date()
      },
      create: {
        id: crypto.randomUUID(),
        tenantId,
        metric,
        limit: config.limit,
        window: config.window,
        softLimit: config.softLimit,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });

    // Clear cache
    await this.redis.del(`tenant_quota:${tenantId}:${metric}`);
  }

  async resetQuota(
    tenantId: string,
    metric: string
  ): Promise<void> {
    const limiter = this.rateLimiters.get(metric);
    if (!limiter) {
      return;
    }

    await limiter.delete(tenantId);
    logger.info('Quota reset', { tenantId, metric });
  }

  async getUsageHistory(
    tenantId: string,
    metric: string,
    days: number = 30
  ): Promise<any[]> {
    // This would typically query from a time-series database
    // For now, return mock data
    const history = [];
    const now = new Date();

    for (let i = 0; i < days; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      
      history.push({
        date: date.toISOString().split('T')[0],
        metric,
        usage: Math.floor(Math.random() * 1000),
        limit: 10000
      });
    }

    return history.reverse();
  }

  // Private helper methods

  private async getTenantQuota(
    tenantId: string,
    metric: string
  ): Promise<QuotaConfig | null> {
    const cacheKey = `tenant_quota:${tenantId}:${metric}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const quota = await this.prisma.tenantQuota.findUnique({
      where: {
        tenantId_metric: {
          tenantId,
          metric
        }
      }
    });

    if (quota) {
      const config: QuotaConfig = {
        metric: quota.metric,
        limit: quota.limit,
        window: quota.window as any,
        softLimit: quota.softLimit || undefined
      };

      // Cache for 5 minutes
      await this.redis.setex(cacheKey, 300, JSON.stringify(config));
      return config;
    }

    return null;
  }

  private getWindowDuration(window: string): number {
    switch (window) {
      case 'minute':
        return 60;
      case 'hour':
        return 3600;
      case 'day':
        return 86400;
      case 'month':
        return 2592000; // 30 days
      default:
        return 3600;
    }
  }

  private async sendQuotaWarning(
    tenantId: string,
    metric: string,
    status: QuotaStatus
  ): Promise<void> {
    // Check if we've already sent a warning recently
    const warningKey = `quota_warning:${tenantId}:${metric}`;
    const recentWarning = await this.redis.get(warningKey);
    
    if (recentWarning) {
      return;
    }

    // Send warning (would integrate with notification service)
    logger.warn('Quota warning threshold reached', {
      tenantId,
      metric,
      percentage: status.percentage,
      used: status.used,
      limit: status.limit
    });

    // Set flag to prevent spam (expires in 1 hour)
    await this.redis.setex(warningKey, 3600, '1');

    // In production, this would trigger notifications
    // await notificationService.sendQuotaWarning(tenantId, metric, status);
  }
}