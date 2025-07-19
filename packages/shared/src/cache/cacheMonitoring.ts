import { CacheService, CacheStats } from './cacheService';
import { logger } from '../logger';
import { EventEmitter } from 'events';

export interface CacheMetrics {
  timestamp: Date;
  stats: CacheStats;
  memory: {
    used: number;
    peak: number;
    overhead: number;
    dataset: number;
  };
  performance: {
    p50GetTime: number;
    p95GetTime: number;
    p99GetTime: number;
    p50SetTime: number;
    p95SetTime: number;
    p99SetTime: number;
  };
  keyspace: {
    totalKeys: number;
    expiredKeys: number;
    evictedKeys: number;
  };
}

export interface AlertThresholds {
  hitRate?: number; // Alert if hit rate drops below this
  errorRate?: number; // Alert if error rate exceeds this
  memoryUsage?: number; // Alert if memory usage exceeds this (bytes)
  responseTime?: number; // Alert if p95 response time exceeds this (ms)
}

export interface MonitoringConfig {
  interval?: number; // Monitoring interval in ms
  historySize?: number; // Number of historical metrics to keep
  alertThresholds?: AlertThresholds;
  enableAlerts?: boolean;
  enableLogging?: boolean;
}

export class CacheMonitor extends EventEmitter {
  private cache: CacheService;
  private config: MonitoringConfig;
  private metrics: CacheMetrics[] = [];
  private monitoringInterval?: NodeJS.Timeout;
  private lastStats?: CacheStats;

  constructor(cache: CacheService, config: MonitoringConfig = {}) {
    super();
    this.cache = cache;
    this.config = {
      interval: config.interval || 60000, // 1 minute default
      historySize: config.historySize || 1440, // 24 hours at 1 minute intervals
      alertThresholds: config.alertThresholds || {},
      enableAlerts: config.enableAlerts ?? true,
      enableLogging: config.enableLogging ?? true,
    };
  }

  /**
   * Start monitoring
   */
  start(): void {
    if (this.monitoringInterval) {
      return; // Already running
    }

    // Collect initial metrics
    this.collectMetrics();

    // Set up interval
    this.monitoringInterval = setInterval(() => {
      this.collectMetrics();
    }, this.config.interval!);

    logger.info('Cache monitoring started', { interval: this.config.interval });
  }

  /**
   * Stop monitoring
   */
  stop(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = undefined;
    }
    logger.info('Cache monitoring stopped');
  }

  /**
   * Collect current metrics
   */
  private async collectMetrics(): Promise<void> {
    try {
      const stats = this.cache.getStats();
      const memory = await this.cache.getMemoryInfo();
      
      const metric: CacheMetrics = {
        timestamp: new Date(),
        stats,
        memory,
        performance: this.calculatePerformanceMetrics(stats),
        keyspace: await this.getKeyspaceMetrics(),
      };

      // Add to history
      this.metrics.push(metric);
      if (this.metrics.length > this.config.historySize!) {
        this.metrics.shift();
      }

      // Check alerts
      if (this.config.enableAlerts) {
        this.checkAlerts(metric);
      }

      // Log if enabled
      if (this.config.enableLogging) {
        logger.info('Cache metrics collected', {
          hitRate: stats.hitRate,
          errors: stats.errors,
          memoryUsed: memory.used,
          avgGetTime: stats.avgGetTime,
        });
      }

      // Emit metrics event
      this.emit('metrics', metric);

      this.lastStats = stats;
    } catch (error) {
      logger.error('Failed to collect cache metrics', { error });
      this.emit('error', error);
    }
  }

  /**
   * Calculate performance percentiles
   */
  private calculatePerformanceMetrics(stats: CacheStats): CacheMetrics['performance'] {
    // In a real implementation, we would track individual response times
    // For now, we'll estimate based on average
    const avgGet = stats.avgGetTime;
    const avgSet = stats.avgSetTime;

    return {
      p50GetTime: avgGet * 0.8,
      p95GetTime: avgGet * 1.5,
      p99GetTime: avgGet * 2,
      p50SetTime: avgSet * 0.8,
      p95SetTime: avgSet * 1.5,
      p99SetTime: avgSet * 2,
    };
  }

  /**
   * Get keyspace metrics from Redis
   */
  private async getKeyspaceMetrics(): Promise<CacheMetrics['keyspace']> {
    // This would typically come from Redis INFO command
    // For now, return placeholder values
    return {
      totalKeys: this.lastStats ? this.lastStats.hits + this.lastStats.misses : 0,
      expiredKeys: 0,
      evictedKeys: 0,
    };
  }

  /**
   * Check alert thresholds
   */
  private checkAlerts(metric: CacheMetrics): void {
    const thresholds = this.config.alertThresholds!;

    // Hit rate alert
    if (thresholds.hitRate !== undefined && metric.stats.hitRate < thresholds.hitRate) {
      this.emitAlert('low_hit_rate', {
        current: metric.stats.hitRate,
        threshold: thresholds.hitRate,
      });
    }

    // Error rate alert
    const totalOps = metric.stats.hits + metric.stats.misses + metric.stats.sets;
    const errorRate = totalOps > 0 ? metric.stats.errors / totalOps : 0;
    if (thresholds.errorRate !== undefined && errorRate > thresholds.errorRate) {
      this.emitAlert('high_error_rate', {
        current: errorRate,
        threshold: thresholds.errorRate,
      });
    }

    // Memory usage alert
    if (thresholds.memoryUsage !== undefined && metric.memory.used > thresholds.memoryUsage) {
      this.emitAlert('high_memory_usage', {
        current: metric.memory.used,
        threshold: thresholds.memoryUsage,
      });
    }

    // Response time alert
    if (thresholds.responseTime !== undefined && metric.performance.p95GetTime > thresholds.responseTime) {
      this.emitAlert('slow_response_time', {
        current: metric.performance.p95GetTime,
        threshold: thresholds.responseTime,
      });
    }
  }

  /**
   * Emit alert
   */
  private emitAlert(type: string, data: any): void {
    const alert = {
      type,
      timestamp: new Date(),
      data,
    };

    logger.warn('Cache alert triggered', alert);
    this.emit('alert', alert);
  }

  /**
   * Get current metrics
   */
  getCurrentMetrics(): CacheMetrics | null {
    return this.metrics[this.metrics.length - 1] || null;
  }

  /**
   * Get metrics history
   */
  getMetricsHistory(duration?: number): CacheMetrics[] {
    if (!duration) {
      return [...this.metrics];
    }

    const cutoff = Date.now() - duration;
    return this.metrics.filter(m => m.timestamp.getTime() >= cutoff);
  }

  /**
   * Get metrics summary
   */
  getMetricsSummary(duration?: number): {
    avgHitRate: number;
    avgResponseTime: number;
    totalErrors: number;
    peakMemory: number;
    totalOperations: number;
  } {
    const metrics = duration ? this.getMetricsHistory(duration) : this.metrics;
    
    if (metrics.length === 0) {
      return {
        avgHitRate: 0,
        avgResponseTime: 0,
        totalErrors: 0,
        peakMemory: 0,
        totalOperations: 0,
      };
    }

    const summary = metrics.reduce((acc, m) => {
      acc.hitRate += m.stats.hitRate;
      acc.responseTime += m.stats.avgGetTime;
      acc.errors += m.stats.errors;
      acc.memory = Math.max(acc.memory, m.memory.used);
      acc.operations += m.stats.hits + m.stats.misses + m.stats.sets;
      return acc;
    }, {
      hitRate: 0,
      responseTime: 0,
      errors: 0,
      memory: 0,
      operations: 0,
    });

    return {
      avgHitRate: summary.hitRate / metrics.length,
      avgResponseTime: summary.responseTime / metrics.length,
      totalErrors: summary.errors,
      peakMemory: summary.memory,
      totalOperations: summary.operations,
    };
  }

  /**
   * Export metrics for external monitoring systems
   */
  exportMetrics(format: 'prometheus' | 'json' = 'json'): string {
    const current = this.getCurrentMetrics();
    if (!current) {
      return format === 'prometheus' ? '' : '{}';
    }

    if (format === 'prometheus') {
      return this.formatPrometheus(current);
    }

    return JSON.stringify(current, null, 2);
  }

  /**
   * Format metrics for Prometheus
   */
  private formatPrometheus(metric: CacheMetrics): string {
    const lines: string[] = [];
    
    // Counter metrics
    lines.push(`# HELP cache_hits_total Total number of cache hits`);
    lines.push(`# TYPE cache_hits_total counter`);
    lines.push(`cache_hits_total ${metric.stats.hits}`);
    
    lines.push(`# HELP cache_misses_total Total number of cache misses`);
    lines.push(`# TYPE cache_misses_total counter`);
    lines.push(`cache_misses_total ${metric.stats.misses}`);
    
    lines.push(`# HELP cache_sets_total Total number of cache sets`);
    lines.push(`# TYPE cache_sets_total counter`);
    lines.push(`cache_sets_total ${metric.stats.sets}`);
    
    lines.push(`# HELP cache_errors_total Total number of cache errors`);
    lines.push(`# TYPE cache_errors_total counter`);
    lines.push(`cache_errors_total ${metric.stats.errors}`);
    
    // Gauge metrics
    lines.push(`# HELP cache_hit_rate Current cache hit rate`);
    lines.push(`# TYPE cache_hit_rate gauge`);
    lines.push(`cache_hit_rate ${metric.stats.hitRate}`);
    
    lines.push(`# HELP cache_memory_used_bytes Current memory usage in bytes`);
    lines.push(`# TYPE cache_memory_used_bytes gauge`);
    lines.push(`cache_memory_used_bytes ${metric.memory.used}`);
    
    // Histogram metrics
    lines.push(`# HELP cache_get_duration_milliseconds Cache get operation duration`);
    lines.push(`# TYPE cache_get_duration_milliseconds histogram`);
    lines.push(`cache_get_duration_milliseconds{quantile="0.5"} ${metric.performance.p50GetTime}`);
    lines.push(`cache_get_duration_milliseconds{quantile="0.95"} ${metric.performance.p95GetTime}`);
    lines.push(`cache_get_duration_milliseconds{quantile="0.99"} ${metric.performance.p99GetTime}`);
    
    return lines.join('\n');
  }

  /**
   * Reset metrics history
   */
  resetMetrics(): void {
    this.metrics = [];
    this.cache.resetStats();
    logger.info('Cache metrics reset');
  }
}

/**
 * Create a cache health check endpoint handler
 */
export function createHealthCheck(monitor: CacheMonitor) {
  return async () => {
    const current = monitor.getCurrentMetrics();
    
    if (!current) {
      return {
        status: 'unknown',
        message: 'No metrics available',
      };
    }

    const summary = monitor.getMetricsSummary(300000); // Last 5 minutes
    
    // Determine health status
    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    const issues: string[] = [];

    if (summary.avgHitRate < 0.5) {
      status = 'degraded';
      issues.push(`Low hit rate: ${(summary.avgHitRate * 100).toFixed(1)}%`);
    }

    if (summary.avgResponseTime > 100) {
      status = status === 'healthy' ? 'degraded' : status;
      issues.push(`Slow response time: ${summary.avgResponseTime.toFixed(1)}ms`);
    }

    if (summary.totalErrors > 10) {
      status = 'unhealthy';
      issues.push(`High error count: ${summary.totalErrors}`);
    }

    if (current.memory.used > 1024 * 1024 * 1024 * 4) { // 4GB
      status = status === 'healthy' ? 'degraded' : status;
      issues.push(`High memory usage: ${(current.memory.used / 1024 / 1024 / 1024).toFixed(2)}GB`);
    }

    return {
      status,
      timestamp: current.timestamp,
      metrics: {
        hitRate: `${(current.stats.hitRate * 100).toFixed(1)}%`,
        avgResponseTime: `${current.stats.avgGetTime.toFixed(1)}ms`,
        memoryUsage: `${(current.memory.used / 1024 / 1024).toFixed(1)}MB`,
        totalOperations: current.stats.hits + current.stats.misses + current.stats.sets,
        errors: current.stats.errors,
      },
      issues: issues.length > 0 ? issues : undefined,
    };
  };
}