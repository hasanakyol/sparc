export * from './cacheService';
export * from './tenantCache';
export * from './sessionCache';
export * from './permissionCache';
export * from './videoCache';
export * from './analyticsCache';
export * from './invalidationStrategies';
export * from './cacheMonitoring';

import { CacheService, CacheConfig, createCacheService } from './cacheService';
import { TenantCache, TenantCacheConfig } from './tenantCache';
import { SessionCache, SessionCacheConfig } from './sessionCache';
import { PermissionCache, PermissionCacheConfig } from './permissionCache';
import { VideoCache, VideoCacheConfig } from './videoCache';
import { AnalyticsCache, AnalyticsCacheConfig } from './analyticsCache';
import { createInvalidationManager } from './invalidationStrategies';
import { CacheMonitor, MonitoringConfig } from './cacheMonitoring';

export interface CacheManagerConfig {
  cache?: CacheConfig;
  tenant?: TenantCacheConfig;
  session?: SessionCacheConfig;
  permission?: PermissionCacheConfig;
  video?: VideoCacheConfig;
  analytics?: AnalyticsCacheConfig;
  monitoring?: MonitoringConfig;
  enableInvalidation?: boolean;
}

/**
 * Unified cache manager that provides all cache services
 */
export class CacheManager {
  public readonly core: CacheService;
  public readonly tenant: TenantCache;
  public readonly session: SessionCache;
  public readonly permission: PermissionCache;
  public readonly video: VideoCache;
  public readonly analytics: AnalyticsCache;
  public readonly invalidation: ReturnType<typeof createInvalidationManager> | null;
  public readonly monitor: CacheMonitor;

  constructor(config: CacheManagerConfig = {}) {
    // Create core cache service
    this.core = createCacheService(config.cache);

    // Create specialized cache services
    this.tenant = new TenantCache(this.core, config.tenant);
    this.session = new SessionCache(this.core, config.session);
    this.permission = new PermissionCache(this.core, config.permission);
    this.video = new VideoCache(this.core, config.video);
    this.analytics = new AnalyticsCache(this.core, config.analytics);

    // Create invalidation manager if enabled
    this.invalidation = config.enableInvalidation !== false 
      ? createInvalidationManager(this.core)
      : null;

    // Create monitor
    this.monitor = new CacheMonitor(this.core, config.monitoring);
  }

  /**
   * Start cache monitoring
   */
  startMonitoring(): void {
    this.monitor.start();
  }

  /**
   * Stop cache monitoring
   */
  stopMonitoring(): void {
    this.monitor.stop();
  }

  /**
   * Warm up all caches
   */
  async warmup(data: {
    tenants?: Parameters<TenantCache['warmup']>[0];
    permissions?: Parameters<PermissionCache['warmup']>[0];
    videos?: Parameters<VideoCache['warmup']>[0];
    analytics?: Parameters<AnalyticsCache['warmup']>[0];
  }): Promise<void> {
    const operations = [];

    if (data.tenants) {
      operations.push(this.tenant.warmup(data.tenants));
    }

    if (data.permissions) {
      operations.push(this.permission.warmup(data.permissions));
    }

    if (data.videos) {
      operations.push(this.video.warmup(data.videos));
    }

    if (data.analytics) {
      operations.push(this.analytics.warmup(data.analytics));
    }

    await Promise.all(operations);
  }

  /**
   * Get health status
   */
  async getHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    services: Record<string, boolean>;
    metrics: any;
  }> {
    const metrics = this.monitor.getCurrentMetrics();
    const coreStats = this.core.getStats();

    // Check individual services
    const services = {
      core: coreStats.errors === 0,
      tenant: true, // Would check specific service health
      session: true,
      permission: true,
      video: true,
      analytics: true,
    };

    // Determine overall status
    const allHealthy = Object.values(services).every(v => v);
    const status = allHealthy 
      ? 'healthy' 
      : Object.values(services).some(v => !v) 
        ? 'unhealthy' 
        : 'degraded';

    return {
      status,
      services,
      metrics: metrics || coreStats,
    };
  }

  /**
   * Clear all caches
   */
  async clearAll(): Promise<void> {
    await this.core.clear();
  }

  /**
   * Disconnect and cleanup
   */
  async disconnect(): Promise<void> {
    this.stopMonitoring();
    
    if (this.invalidation) {
      this.invalidation.destroy();
    }

    await this.core.disconnect();
  }
}

/**
 * Create a cache manager instance with default configuration
 */
export function createCacheManager(config?: CacheManagerConfig): CacheManager {
  return new CacheManager(config);
}

/**
 * Default cache manager instance (singleton)
 */
let defaultCacheManager: CacheManager | null = null;

export function getDefaultCacheManager(): CacheManager {
  if (!defaultCacheManager) {
    defaultCacheManager = createCacheManager();
  }
  return defaultCacheManager;
}