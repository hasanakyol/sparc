import { Context } from 'hono';
import { CacheService } from '../utils/cache';
import { z } from 'zod';

/**
 * Deprecation notice configuration
 */
export interface DeprecationNotice {
  version: string;
  endpoint?: string;
  feature?: string;
  deprecatedAt: Date;
  sunsetAt: Date;
  message: string;
  migrationGuide?: string;
  alternatives?: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Deprecation event for tracking
 */
export interface DeprecationEvent {
  timestamp: Date;
  version: string;
  endpoint: string;
  method: string;
  userId?: string;
  tenantId?: string;
  userAgent?: string;
  ip?: string;
}

/**
 * Deprecation notice schema for validation
 */
const deprecationNoticeSchema = z.object({
  version: z.string(),
  endpoint: z.string().optional(),
  feature: z.string().optional(),
  deprecatedAt: z.date(),
  sunsetAt: z.date(),
  message: z.string(),
  migrationGuide: z.string().optional(),
  alternatives: z.array(z.string()).optional(),
  severity: z.enum(['low', 'medium', 'high', 'critical'])
});

/**
 * Version Deprecation Service
 */
export class VersionDeprecationService {
  private notices: Map<string, DeprecationNotice[]> = new Map();
  private cache: CacheService;
  private notificationHandlers: ((notice: DeprecationNotice, event: DeprecationEvent) => void)[] = [];

  constructor(cache: CacheService) {
    this.cache = cache;
    this.loadDeprecationNotices();
  }

  /**
   * Load initial deprecation notices
   */
  private loadDeprecationNotices(): void {
    // Version-level deprecations
    this.addNotice({
      version: '1.0',
      deprecatedAt: new Date('2024-01-01'),
      sunsetAt: new Date('2024-06-30'),
      message: 'API version 1.0 is deprecated. Please upgrade to version 2.0.',
      migrationGuide: 'https://docs.sparc.io/migration/v1-to-v2',
      severity: 'high'
    });

    // Endpoint-specific deprecations
    this.addNotice({
      version: '1.1',
      endpoint: '/api/v1/incidents/bulk',
      deprecatedAt: new Date('2024-03-01'),
      sunsetAt: new Date('2024-09-01'),
      message: 'The bulk incidents endpoint is deprecated. Use the batch API instead.',
      alternatives: ['/api/v1/batch/incidents'],
      migrationGuide: 'https://docs.sparc.io/migration/bulk-to-batch',
      severity: 'medium'
    });

    // Feature deprecations
    this.addNotice({
      version: '2.0',
      feature: 'synchronous-video-processing',
      deprecatedAt: new Date('2024-04-01'),
      sunsetAt: new Date('2024-10-01'),
      message: 'Synchronous video processing is deprecated. Use async processing with webhooks.',
      alternatives: ['async-video-processing'],
      migrationGuide: 'https://docs.sparc.io/migration/sync-to-async-video',
      severity: 'medium'
    });
  }

  /**
   * Add a deprecation notice
   */
  addNotice(notice: DeprecationNotice): void {
    const validated = deprecationNoticeSchema.parse(notice);
    
    if (!this.notices.has(validated.version)) {
      this.notices.set(validated.version, []);
    }
    
    this.notices.get(validated.version)!.push(validated);
  }

  /**
   * Get deprecation notices for a version
   */
  getNotices(version: string, endpoint?: string): DeprecationNotice[] {
    const versionNotices = this.notices.get(version) || [];
    
    if (!endpoint) {
      return versionNotices;
    }

    return versionNotices.filter(notice => 
      !notice.endpoint || notice.endpoint === endpoint
    );
  }

  /**
   * Check if a version/endpoint is deprecated
   */
  isDeprecated(version: string, endpoint?: string): boolean {
    const notices = this.getNotices(version, endpoint);
    const now = new Date();
    
    return notices.some(notice => 
      notice.deprecatedAt <= now && notice.sunsetAt > now
    );
  }

  /**
   * Check if a version/endpoint is sunset
   */
  isSunset(version: string, endpoint?: string): boolean {
    const notices = this.getNotices(version, endpoint);
    const now = new Date();
    
    return notices.some(notice => notice.sunsetAt <= now);
  }

  /**
   * Get days until sunset
   */
  getDaysUntilSunset(version: string, endpoint?: string): number | null {
    const notices = this.getNotices(version, endpoint);
    const now = new Date();
    
    let minDays: number | null = null;
    
    for (const notice of notices) {
      if (notice.sunsetAt > now) {
        const days = Math.ceil(
          (notice.sunsetAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        );
        if (minDays === null || days < minDays) {
          minDays = days;
        }
      }
    }
    
    return minDays;
  }

  /**
   * Track deprecation usage
   */
  async trackUsage(event: DeprecationEvent): Promise<void> {
    const key = `deprecation:usage:${event.version}:${event.endpoint}`;
    const dayKey = new Date().toISOString().split('T')[0];
    
    // Increment daily counter
    await this.cache.increment(`${key}:${dayKey}`, 1, 86400 * 30); // 30 days retention
    
    // Track unique users
    if (event.userId) {
      await this.cache.set(
        `${key}:users:${dayKey}:${event.userId}`,
        '1',
        86400 * 30
      );
    }
    
    // Track unique tenants
    if (event.tenantId) {
      await this.cache.set(
        `${key}:tenants:${dayKey}:${event.tenantId}`,
        '1',
        86400 * 30
      );
    }
    
    // Notify handlers
    const notices = this.getNotices(event.version, event.endpoint);
    for (const notice of notices) {
      for (const handler of this.notificationHandlers) {
        handler(notice, event);
      }
    }
  }

  /**
   * Get usage statistics
   */
  async getUsageStats(
    version: string,
    endpoint?: string,
    days: number = 30
  ): Promise<{
    totalRequests: number;
    uniqueUsers: number;
    uniqueTenants: number;
    dailyBreakdown: { date: string; requests: number }[];
  }> {
    const key = `deprecation:usage:${version}:${endpoint || '*'}`;
    const stats = {
      totalRequests: 0,
      uniqueUsers: new Set<string>(),
      uniqueTenants: new Set<string>(),
      dailyBreakdown: [] as { date: string; requests: number }[]
    };
    
    const now = new Date();
    
    for (let i = 0; i < days; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      const dayKey = date.toISOString().split('T')[0];
      
      // Get daily request count
      const requests = await this.cache.get(`${key}:${dayKey}`);
      if (requests) {
        const count = parseInt(requests, 10);
        stats.totalRequests += count;
        stats.dailyBreakdown.push({ date: dayKey, requests: count });
      }
      
      // Get unique users
      const userKeys = await this.cache.keys(`${key}:users:${dayKey}:*`);
      userKeys.forEach(userKey => {
        const userId = userKey.split(':').pop();
        if (userId) stats.uniqueUsers.add(userId);
      });
      
      // Get unique tenants
      const tenantKeys = await this.cache.keys(`${key}:tenants:${dayKey}:*`);
      tenantKeys.forEach(tenantKey => {
        const tenantId = tenantKey.split(':').pop();
        if (tenantId) stats.uniqueTenants.add(tenantId);
      });
    }
    
    return {
      totalRequests: stats.totalRequests,
      uniqueUsers: stats.uniqueUsers.size,
      uniqueTenants: stats.uniqueTenants.size,
      dailyBreakdown: stats.dailyBreakdown.reverse()
    };
  }

  /**
   * Register notification handler
   */
  onDeprecationUsage(
    handler: (notice: DeprecationNotice, event: DeprecationEvent) => void
  ): void {
    this.notificationHandlers.push(handler);
  }

  /**
   * Generate deprecation report
   */
  async generateReport(days: number = 30): Promise<{
    summary: {
      totalDeprecatedVersions: number;
      totalDeprecatedEndpoints: number;
      upcomingSunsets: { version: string; endpoint?: string; daysRemaining: number }[];
    };
    usage: {
      version: string;
      endpoint?: string;
      stats: Awaited<ReturnType<typeof this.getUsageStats>>;
    }[];
  }> {
    const allNotices: DeprecationNotice[] = [];
    for (const notices of this.notices.values()) {
      allNotices.push(...notices);
    }
    
    const uniqueVersions = new Set(allNotices.map(n => n.version));
    const uniqueEndpoints = new Set(
      allNotices.filter(n => n.endpoint).map(n => n.endpoint!)
    );
    
    const now = new Date();
    const upcomingSunsets = allNotices
      .filter(n => n.sunsetAt > now)
      .map(n => ({
        version: n.version,
        endpoint: n.endpoint,
        daysRemaining: Math.ceil(
          (n.sunsetAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        )
      }))
      .sort((a, b) => a.daysRemaining - b.daysRemaining)
      .slice(0, 10); // Top 10 upcoming sunsets
    
    const usage = await Promise.all(
      allNotices.map(async notice => ({
        version: notice.version,
        endpoint: notice.endpoint,
        stats: await this.getUsageStats(notice.version, notice.endpoint, days)
      }))
    );
    
    return {
      summary: {
        totalDeprecatedVersions: uniqueVersions.size,
        totalDeprecatedEndpoints: uniqueEndpoints.size,
        upcomingSunsets
      },
      usage: usage.filter(u => u.stats.totalRequests > 0)
    };
  }

  /**
   * Send deprecation notifications
   */
  async sendNotifications(
    notice: DeprecationNotice,
    recipients: { email: string; tenantId: string }[]
  ): Promise<void> {
    // This would integrate with the email service
    console.log(`Sending deprecation notices to ${recipients.length} recipients`, {
      version: notice.version,
      endpoint: notice.endpoint,
      sunsetDate: notice.sunsetAt
    });
    
    // In a real implementation, this would:
    // 1. Send emails via the email service
    // 2. Create in-app notifications
    // 3. Post to webhooks
    // 4. Update documentation
  }
}

/**
 * Deprecation tracking middleware
 */
export const deprecationTrackingMiddleware = (service: VersionDeprecationService) => {
  return async (c: Context, next: () => Promise<void>) => {
    await next();
    
    const version = c.get('version') as any;
    const user = c.get('user') as any;
    
    if (version && service.isDeprecated(version.resolved, c.req.path)) {
      await service.trackUsage({
        timestamp: new Date(),
        version: version.resolved,
        endpoint: c.req.path,
        method: c.req.method,
        userId: user?.userId,
        tenantId: user?.tenantId,
        userAgent: c.req.header('user-agent'),
        ip: c.req.header('x-forwarded-for') || c.req.header('x-real-ip')
      });
    }
  };
};

/**
 * Sunset enforcement middleware
 */
export const sunsetEnforcementMiddleware = (service: VersionDeprecationService) => {
  return async (c: Context, next: () => Promise<void>) => {
    const version = c.get('version') as any;
    
    if (version && service.isSunset(version.resolved, c.req.path)) {
      const notices = service.getNotices(version.resolved, c.req.path);
      const relevantNotice = notices.find(n => n.sunsetAt <= new Date());
      
      return c.json({
        error: 'API version sunset',
        message: relevantNotice?.message || 'This API version is no longer available',
        code: 'VERSION_SUNSET',
        migrationGuide: relevantNotice?.migrationGuide,
        alternatives: relevantNotice?.alternatives
      }, 410); // Gone
    }
    
    await next();
  };
};