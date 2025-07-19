import { CacheService } from './cacheService';
import { logger } from '../logger';

export interface AnalyticsMetric {
  value: number;
  timestamp: Date;
  metadata?: Record<string, any>;
}

export interface AnalyticsAggregate {
  count: number;
  sum: number;
  avg: number;
  min: number;
  max: number;
  period: string;
}

export interface AnalyticsCacheConfig {
  ttl?: {
    metric?: number;
    aggregate?: number;
    report?: number;
    dashboard?: number;
    realtime?: number;
  };
}

export class AnalyticsCache {
  private cache: CacheService;
  private config: AnalyticsCacheConfig;
  private namespace = 'analytics';

  constructor(cache: CacheService, config: AnalyticsCacheConfig = {}) {
    this.cache = cache;
    this.config = {
      ttl: {
        metric: config.ttl?.metric || 300, // 5 minutes
        aggregate: config.ttl?.aggregate || 900, // 15 minutes
        report: config.ttl?.report || 3600, // 1 hour
        dashboard: config.ttl?.dashboard || 600, // 10 minutes
        realtime: config.ttl?.realtime || 30, // 30 seconds
      },
    };
  }

  /**
   * Get metric value
   */
  async getMetric(
    tenantId: string,
    metricName: string,
    timestamp?: Date
  ): Promise<AnalyticsMetric | null> {
    const time = timestamp ? timestamp.toISOString() : 'latest';
    const key = `metric:${tenantId}:${metricName}:${time}`;
    
    return this.cache.get<AnalyticsMetric>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `metric:${metricName}`],
    });
  }

  /**
   * Set metric value
   */
  async setMetric(
    tenantId: string,
    metricName: string,
    metric: AnalyticsMetric
  ): Promise<boolean> {
    const key = `metric:${tenantId}:${metricName}:${metric.timestamp.toISOString()}`;
    
    // Also update latest
    await this.cache.set(
      `metric:${tenantId}:${metricName}:latest`,
      metric,
      {
        prefix: this.namespace,
        ttl: this.config.ttl?.metric,
        tags: [`tenant:${tenantId}`, `metric:${metricName}`],
      }
    );
    
    return this.cache.set(key, metric, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `metric:${metricName}`],
    });
  }

  /**
   * Get aggregated metrics
   */
  async getAggregate(
    tenantId: string,
    metricName: string,
    period: 'hour' | 'day' | 'week' | 'month',
    timestamp?: Date
  ): Promise<AnalyticsAggregate | null> {
    const time = timestamp ? timestamp.toISOString() : new Date().toISOString();
    const key = `aggregate:${tenantId}:${metricName}:${period}:${time}`;
    
    return this.cache.get<AnalyticsAggregate>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.aggregate,
      tags: [`tenant:${tenantId}`, `metric:${metricName}`, `aggregate:${period}`],
    });
  }

  /**
   * Set aggregated metrics
   */
  async setAggregate(
    tenantId: string,
    metricName: string,
    period: 'hour' | 'day' | 'week' | 'month',
    aggregate: AnalyticsAggregate,
    timestamp?: Date
  ): Promise<boolean> {
    const time = timestamp ? timestamp.toISOString() : new Date().toISOString();
    const key = `aggregate:${tenantId}:${metricName}:${period}:${time}`;
    
    return this.cache.set(key, aggregate, {
      prefix: this.namespace,
      ttl: this.config.ttl?.aggregate,
      tags: [`tenant:${tenantId}`, `metric:${metricName}`, `aggregate:${period}`],
    });
  }

  /**
   * Get access event statistics
   */
  async getAccessStats(
    tenantId: string,
    period: 'hour' | 'day' | 'week'
  ): Promise<{
    totalEvents: number;
    granted: number;
    denied: number;
    forced: number;
    ajar: number;
    byDoor: Record<string, number>;
    byUser: Record<string, number>;
  } | null> {
    const key = `access-stats:${tenantId}:${period}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.aggregate,
      tags: [`tenant:${tenantId}`, 'access-stats'],
    });
  }

  /**
   * Set access event statistics
   */
  async setAccessStats(
    tenantId: string,
    period: 'hour' | 'day' | 'week',
    stats: {
      totalEvents: number;
      granted: number;
      denied: number;
      forced: number;
      ajar: number;
      byDoor: Record<string, number>;
      byUser: Record<string, number>;
    }
  ): Promise<boolean> {
    const key = `access-stats:${tenantId}:${period}`;
    return this.cache.set(key, stats, {
      prefix: this.namespace,
      ttl: this.config.ttl?.aggregate,
      tags: [`tenant:${tenantId}`, 'access-stats'],
    });
  }

  /**
   * Get video analytics data
   */
  async getVideoAnalytics(
    tenantId: string,
    cameraId: string,
    analyticsType: 'motion' | 'people' | 'vehicles' | 'anomaly'
  ): Promise<{
    detections: number;
    confidence: number;
    lastDetection: Date;
    zones: Record<string, number>;
  } | null> {
    const key = `video-analytics:${tenantId}:${cameraId}:${analyticsType}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `camera:${cameraId}`, 'video-analytics'],
    });
  }

  /**
   * Set video analytics data
   */
  async setVideoAnalytics(
    tenantId: string,
    cameraId: string,
    analyticsType: 'motion' | 'people' | 'vehicles' | 'anomaly',
    data: {
      detections: number;
      confidence: number;
      lastDetection: Date;
      zones: Record<string, number>;
    }
  ): Promise<boolean> {
    const key = `video-analytics:${tenantId}:${cameraId}:${analyticsType}`;
    return this.cache.set(key, data, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `camera:${cameraId}`, 'video-analytics'],
    });
  }

  /**
   * Get environmental metrics
   */
  async getEnvironmentalMetrics(
    tenantId: string,
    sensorId: string
  ): Promise<{
    temperature?: number;
    humidity?: number;
    airQuality?: number;
    leak?: boolean;
    lastReading: Date;
  } | null> {
    const key = `environmental:${tenantId}:${sensorId}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `sensor:${sensorId}`, 'environmental'],
    });
  }

  /**
   * Set environmental metrics
   */
  async setEnvironmentalMetrics(
    tenantId: string,
    sensorId: string,
    metrics: {
      temperature?: number;
      humidity?: number;
      airQuality?: number;
      leak?: boolean;
      lastReading: Date;
    }
  ): Promise<boolean> {
    const key = `environmental:${tenantId}:${sensorId}`;
    return this.cache.set(key, metrics, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `sensor:${sensorId}`, 'environmental'],
    });
  }

  /**
   * Get dashboard data
   */
  async getDashboardData(
    tenantId: string,
    dashboardId: string
  ): Promise<Record<string, any> | null> {
    const key = `dashboard:${tenantId}:${dashboardId}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.dashboard,
      tags: [`tenant:${tenantId}`, `dashboard:${dashboardId}`],
    });
  }

  /**
   * Set dashboard data
   */
  async setDashboardData(
    tenantId: string,
    dashboardId: string,
    data: Record<string, any>
  ): Promise<boolean> {
    const key = `dashboard:${tenantId}:${dashboardId}`;
    return this.cache.set(key, data, {
      prefix: this.namespace,
      ttl: this.config.ttl?.dashboard,
      tags: [`tenant:${tenantId}`, `dashboard:${dashboardId}`],
    });
  }

  /**
   * Get report data
   */
  async getReportData(
    tenantId: string,
    reportType: string,
    reportId: string
  ): Promise<any | null> {
    const key = `report:${tenantId}:${reportType}:${reportId}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.report,
      tags: [`tenant:${tenantId}`, `report:${reportType}`],
    });
  }

  /**
   * Set report data
   */
  async setReportData(
    tenantId: string,
    reportType: string,
    reportId: string,
    data: any
  ): Promise<boolean> {
    const key = `report:${tenantId}:${reportType}:${reportId}`;
    return this.cache.set(key, data, {
      prefix: this.namespace,
      ttl: this.config.ttl?.report,
      tags: [`tenant:${tenantId}`, `report:${reportType}`],
    });
  }

  /**
   * Get real-time metrics
   */
  async getRealtimeMetrics(tenantId: string): Promise<{
    activeUsers: number;
    openDoors: number;
    activeAlerts: number;
    onlineCameras: number;
    systemLoad: number;
  } | null> {
    const key = `realtime:${tenantId}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.realtime,
      tags: [`tenant:${tenantId}`, 'realtime'],
    });
  }

  /**
   * Set real-time metrics
   */
  async setRealtimeMetrics(
    tenantId: string,
    metrics: {
      activeUsers: number;
      openDoors: number;
      activeAlerts: number;
      onlineCameras: number;
      systemLoad: number;
    }
  ): Promise<boolean> {
    const key = `realtime:${tenantId}`;
    return this.cache.set(key, metrics, {
      prefix: this.namespace,
      ttl: this.config.ttl?.realtime,
      tags: [`tenant:${tenantId}`, 'realtime'],
    });
  }

  /**
   * Get occupancy data
   */
  async getOccupancyData(
    tenantId: string,
    zoneId: string
  ): Promise<{
    current: number;
    capacity: number;
    trend: 'increasing' | 'decreasing' | 'stable';
    lastUpdate: Date;
  } | null> {
    const key = `occupancy:${tenantId}:${zoneId}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `zone:${zoneId}`, 'occupancy'],
    });
  }

  /**
   * Set occupancy data
   */
  async setOccupancyData(
    tenantId: string,
    zoneId: string,
    data: {
      current: number;
      capacity: number;
      trend: 'increasing' | 'decreasing' | 'stable';
      lastUpdate: Date;
    }
  ): Promise<boolean> {
    const key = `occupancy:${tenantId}:${zoneId}`;
    return this.cache.set(key, data, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metric,
      tags: [`tenant:${tenantId}`, `zone:${zoneId}`, 'occupancy'],
    });
  }

  /**
   * Invalidate metrics for tenant
   */
  async invalidateTenantMetrics(tenantId: string): Promise<void> {
    await this.cache.invalidateByTags([`tenant:${tenantId}`]);
    logger.info('Invalidated tenant analytics cache', { tenantId });
  }

  /**
   * Invalidate specific metric
   */
  async invalidateMetric(metricName: string): Promise<void> {
    await this.cache.invalidateByTags([`metric:${metricName}`]);
    logger.info('Invalidated metric cache', { metricName });
  }

  /**
   * Invalidate dashboard
   */
  async invalidateDashboard(dashboardId: string): Promise<void> {
    await this.cache.invalidateByTags([`dashboard:${dashboardId}`]);
    logger.info('Invalidated dashboard cache', { dashboardId });
  }

  /**
   * Batch get metrics
   */
  async batchGetMetrics(
    tenantId: string,
    metricNames: string[]
  ): Promise<Record<string, AnalyticsMetric | null>> {
    const keys = metricNames.map(name => `metric:${tenantId}:${name}:latest`);
    const results = await this.cache.mget<AnalyticsMetric>(keys, {
      prefix: this.namespace,
    });
    
    const metricsMap: Record<string, AnalyticsMetric | null> = {};
    metricNames.forEach((name, index) => {
      metricsMap[name] = results[index];
    });
    
    return metricsMap;
  }

  /**
   * Get trending metrics
   */
  async getTrendingMetrics(
    tenantId: string,
    metricName: string,
    points: number = 24
  ): Promise<AnalyticsMetric[] | null> {
    const key = `trending:${tenantId}:${metricName}:${points}`;
    return this.cache.get<AnalyticsMetric[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.aggregate,
      tags: [`tenant:${tenantId}`, `metric:${metricName}`, 'trending'],
    });
  }

  /**
   * Set trending metrics
   */
  async setTrendingMetrics(
    tenantId: string,
    metricName: string,
    metrics: AnalyticsMetric[],
    points: number = 24
  ): Promise<boolean> {
    const key = `trending:${tenantId}:${metricName}:${points}`;
    return this.cache.set(key, metrics, {
      prefix: this.namespace,
      ttl: this.config.ttl?.aggregate,
      tags: [`tenant:${tenantId}`, `metric:${metricName}`, 'trending'],
    });
  }

  /**
   * Warm up analytics cache
   */
  async warmup(data: {
    metrics?: Array<{ tenantId: string; metricName: string; metric: AnalyticsMetric }>;
    dashboards?: Array<{ tenantId: string; dashboardId: string; data: any }>;
    reports?: Array<{ tenantId: string; reportType: string; reportId: string; data: any }>;
  }): Promise<void> {
    const operations = [];

    if (data.metrics) {
      for (const item of data.metrics) {
        operations.push(
          this.setMetric(item.tenantId, item.metricName, item.metric)
        );
      }
    }

    if (data.dashboards) {
      for (const item of data.dashboards) {
        operations.push(
          this.setDashboardData(item.tenantId, item.dashboardId, item.data)
        );
      }
    }

    if (data.reports) {
      for (const item of data.reports) {
        operations.push(
          this.setReportData(item.tenantId, item.reportType, item.reportId, item.data)
        );
      }
    }

    await Promise.all(operations);
    logger.info('Analytics cache warmed up', {
      metrics: data.metrics?.length || 0,
      dashboards: data.dashboards?.length || 0,
      reports: data.reports?.length || 0,
    });
  }
}