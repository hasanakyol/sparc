import { EventEmitter } from 'events';
import { CacheService } from './cacheService';
import { logger } from '../logger';

export interface InvalidationRule {
  event: string;
  patterns?: string[];
  tags?: string[];
  cascades?: string[];
  condition?: (data: any) => boolean;
}

export interface InvalidationConfig {
  rules: InvalidationRule[];
  enableEventDriven?: boolean;
  enableTimeBased?: boolean;
  enableManual?: boolean;
}

export class CacheInvalidationManager extends EventEmitter {
  private cache: CacheService;
  private config: InvalidationConfig;
  private rules: Map<string, InvalidationRule[]> = new Map();
  private timers: Map<string, NodeJS.Timeout> = new Map();

  constructor(cache: CacheService, config: InvalidationConfig) {
    super();
    this.cache = cache;
    this.config = config;
    
    // Index rules by event
    for (const rule of config.rules) {
      const existing = this.rules.get(rule.event) || [];
      existing.push(rule);
      this.rules.set(rule.event, existing);
    }

    if (config.enableEventDriven) {
      this.setupEventListeners();
    }
  }

  /**
   * Handle invalidation event
   */
  async handleEvent(event: string, data: any): Promise<void> {
    const rules = this.rules.get(event);
    if (!rules || rules.length === 0) return;

    logger.info('Processing cache invalidation event', { event, rulesCount: rules.length });

    for (const rule of rules) {
      try {
        // Check condition if specified
        if (rule.condition && !rule.condition(data)) {
          continue;
        }

        // Invalidate by patterns
        if (rule.patterns) {
          for (const pattern of rule.patterns) {
            const resolvedPattern = this.resolvePattern(pattern, data);
            await this.cache.invalidatePattern(resolvedPattern);
          }
        }

        // Invalidate by tags
        if (rule.tags) {
          const resolvedTags = rule.tags.map(tag => this.resolvePattern(tag, data));
          await this.cache.invalidateByTags(resolvedTags);
        }

        // Process cascades
        if (rule.cascades) {
          for (const cascade of rule.cascades) {
            await this.handleEvent(cascade, data);
          }
        }

        this.emit('invalidated', { event, rule, data });
      } catch (error) {
        logger.error('Cache invalidation error', { event, rule, error });
        this.emit('error', { event, rule, error });
      }
    }
  }

  /**
   * Resolve pattern with data placeholders
   */
  private resolvePattern(pattern: string, data: any): string {
    return pattern.replace(/\{(\w+)\}/g, (match, key) => {
      return data[key] || match;
    });
  }

  /**
   * Setup event listeners
   */
  private setupEventListeners(): void {
    // Listen for domain events
    const events = Array.from(this.rules.keys());
    
    for (const event of events) {
      this.on(event, async (data) => {
        await this.handleEvent(event, data);
      });
    }
  }

  /**
   * Schedule time-based invalidation
   */
  scheduleInvalidation(
    name: string,
    interval: number,
    patterns?: string[],
    tags?: string[]
  ): void {
    // Clear existing timer if any
    const existing = this.timers.get(name);
    if (existing) {
      clearInterval(existing);
    }

    const timer = setInterval(async () => {
      logger.info('Running scheduled cache invalidation', { name });
      
      try {
        if (patterns) {
          for (const pattern of patterns) {
            await this.cache.invalidatePattern(pattern);
          }
        }

        if (tags) {
          await this.cache.invalidateByTags(tags);
        }

        this.emit('scheduled-invalidation', { name, patterns, tags });
      } catch (error) {
        logger.error('Scheduled invalidation error', { name, error });
      }
    }, interval);

    this.timers.set(name, timer);
  }

  /**
   * Cancel scheduled invalidation
   */
  cancelScheduledInvalidation(name: string): boolean {
    const timer = this.timers.get(name);
    if (timer) {
      clearInterval(timer);
      this.timers.delete(name);
      return true;
    }
    return false;
  }

  /**
   * Manual invalidation endpoint handler
   */
  async manualInvalidate(request: {
    patterns?: string[];
    tags?: string[];
    namespace?: string;
  }): Promise<{
    success: boolean;
    invalidated: number;
    error?: string;
  }> {
    if (!this.config.enableManual) {
      return {
        success: false,
        invalidated: 0,
        error: 'Manual invalidation is not enabled',
      };
    }

    try {
      let invalidated = 0;

      if (request.patterns) {
        for (const pattern of request.patterns) {
          invalidated += await this.cache.invalidatePattern(pattern, request.namespace);
        }
      }

      if (request.tags) {
        invalidated += await this.cache.invalidateByTags(request.tags);
      }

      this.emit('manual-invalidation', { request, invalidated });

      return {
        success: true,
        invalidated,
      };
    } catch (error) {
      logger.error('Manual invalidation error', { request, error });
      return {
        success: false,
        invalidated: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get invalidation statistics
   */
  getStats(): {
    rules: number;
    scheduledTasks: number;
    events: string[];
  } {
    return {
      rules: this.config.rules.length,
      scheduledTasks: this.timers.size,
      events: Array.from(this.rules.keys()),
    };
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    // Clear all scheduled timers
    for (const timer of this.timers.values()) {
      clearInterval(timer);
    }
    this.timers.clear();
    
    // Remove all listeners
    this.removeAllListeners();
  }
}

// Predefined invalidation rules for SPARC platform
export const defaultInvalidationRules: InvalidationRule[] = [
  // Tenant changes
  {
    event: 'tenant.updated',
    tags: ['tenant:{tenantId}'],
    cascades: ['tenant.hierarchy.changed'],
  },
  {
    event: 'tenant.deleted',
    tags: ['tenant:{tenantId}'],
  },

  // Organization changes
  {
    event: 'organization.created',
    tags: ['tenant:{tenantId}', 'organization'],
  },
  {
    event: 'organization.updated',
    tags: ['org:{organizationId}', 'tenant:{tenantId}'],
  },
  {
    event: 'organization.deleted',
    tags: ['org:{organizationId}', 'tenant:{tenantId}'],
  },

  // Site changes
  {
    event: 'site.created',
    tags: ['org:{organizationId}', 'tenant:{tenantId}', 'site'],
  },
  {
    event: 'site.updated',
    tags: ['site:{siteId}', 'org:{organizationId}'],
  },
  {
    event: 'site.deleted',
    tags: ['site:{siteId}', 'org:{organizationId}'],
  },

  // User changes
  {
    event: 'user.created',
    tags: ['tenant:{tenantId}'],
  },
  {
    event: 'user.updated',
    tags: ['user:{userId}'],
    cascades: ['user.permissions.changed'],
  },
  {
    event: 'user.deleted',
    tags: ['user:{userId}'],
  },
  {
    event: 'user.permissions.changed',
    tags: ['user:{userId}'],
    patterns: ['permission:*:{userId}:*', 'effective:*:{userId}:*'],
  },
  {
    event: 'user.logout',
    tags: ['user:{userId}'],
    patterns: ['session:*'],
  },

  // Role changes
  {
    event: 'role.updated',
    tags: ['role:{roleId}'],
    cascades: ['permissions.cascade.update'],
  },
  {
    event: 'role.deleted',
    tags: ['role:{roleId}'],
  },

  // Access control changes
  {
    event: 'access.group.updated',
    tags: ['group:{groupId}'],
    patterns: ['access:*:*:door:*'],
  },
  {
    event: 'access.group.deleted',
    tags: ['group:{groupId}'],
  },
  {
    event: 'door.updated',
    tags: ['door:{doorId}'],
    patterns: ['access:*:*:door:{doorId}'],
  },
  {
    event: 'schedule.updated',
    tags: ['schedule:{scheduleId}'],
    patterns: ['access:*:*:door:*'],
  },

  // Camera changes
  {
    event: 'camera.updated',
    tags: ['camera:{cameraId}'],
    patterns: ['stream:{cameraId}:*', 'thumbnail:{cameraId}:*'],
  },
  {
    event: 'camera.deleted',
    tags: ['camera:{cameraId}'],
  },
  {
    event: 'camera.status.changed',
    tags: ['camera:{cameraId}', 'status'],
    condition: (data) => data.status === 'offline',
  },

  // Video changes
  {
    event: 'recording.created',
    tags: ['camera:{cameraId}'],
    patterns: ['camera:{cameraId}:recordings:*'],
  },
  {
    event: 'recording.deleted',
    tags: ['recording:{recordingId}', 'camera:{cameraId}'],
  },
  {
    event: 'privacy.mask.updated',
    tags: ['camera:{cameraId}', 'privacy-mask'],
  },

  // Analytics changes
  {
    event: 'analytics.data.updated',
    tags: ['analytics:{analyticsType}', 'camera:{cameraId}'],
    patterns: ['analytics:{cameraId}:*'],
  },
  {
    event: 'metric.threshold.exceeded',
    tags: ['metric:{metricName}', 'tenant:{tenantId}'],
    cascades: ['dashboard.refresh.required'],
  },
  {
    event: 'report.generated',
    tags: ['report:{reportType}', 'tenant:{tenantId}'],
  },

  // Environmental changes
  {
    event: 'sensor.reading.updated',
    tags: ['sensor:{sensorId}', 'environmental'],
    patterns: ['environmental:{tenantId}:{sensorId}'],
  },
  {
    event: 'sensor.alert.triggered',
    tags: ['sensor:{sensorId}', 'environmental'],
    cascades: ['realtime.metrics.update'],
  },

  // Session changes
  {
    event: 'session.created',
    tags: ['user:{userId}', 'tenant:{tenantId}'],
  },
  {
    event: 'session.expired',
    tags: ['user:{userId}', 'session:{sessionId}'],
    patterns: ['session:{sessionId}', 'access:{tokenId}', 'refresh:{tokenId}'],
  },
  {
    event: 'token.revoked',
    patterns: ['blacklist:*:{tokenId}'],
  },

  // Real-time updates
  {
    event: 'realtime.metrics.update',
    tags: ['realtime', 'tenant:{tenantId}'],
  },
  {
    event: 'dashboard.refresh.required',
    tags: ['dashboard:{dashboardId}', 'tenant:{tenantId}'],
  },

  // System events
  {
    event: 'system.maintenance.started',
    patterns: ['*'],
    condition: (data) => data.clearCache === true,
  },
  {
    event: 'tenant.limits.exceeded',
    tags: ['tenant:{tenantId}', 'limits'],
  },
];

/**
 * Create invalidation manager with default rules
 */
export function createInvalidationManager(
  cache: CacheService,
  customRules?: InvalidationRule[]
): CacheInvalidationManager {
  const rules = [...defaultInvalidationRules];
  if (customRules) {
    rules.push(...customRules);
  }

  return new CacheInvalidationManager(cache, {
    rules,
    enableEventDriven: true,
    enableTimeBased: true,
    enableManual: true,
  });
}