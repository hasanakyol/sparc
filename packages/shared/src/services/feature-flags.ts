import { Context } from 'hono';
import { CacheService } from '../utils/cache';
import { z } from 'zod';

/**
 * Feature flag types
 */
export interface FeatureFlag {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  type: 'boolean' | 'percentage' | 'variant' | 'version';
  value?: any;
  conditions?: FlagCondition[];
  variants?: FlagVariant[];
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface FlagCondition {
  type: 'user' | 'tenant' | 'role' | 'permission' | 'version' | 'environment' | 'custom';
  operator: 'equals' | 'contains' | 'in' | 'not_in' | 'greater_than' | 'less_than';
  value: any;
}

export interface FlagVariant {
  id: string;
  name: string;
  weight: number; // 0-100
  value: any;
}

export interface FlagEvaluation {
  flagId: string;
  enabled: boolean;
  value: any;
  variant?: string;
  reason: string;
}

/**
 * Feature flag schema
 */
const featureFlagSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  enabled: z.boolean(),
  type: z.enum(['boolean', 'percentage', 'variant', 'version']),
  value: z.any().optional(),
  conditions: z.array(z.object({
    type: z.enum(['user', 'tenant', 'role', 'permission', 'version', 'environment', 'custom']),
    operator: z.enum(['equals', 'contains', 'in', 'not_in', 'greater_than', 'less_than']),
    value: z.any()
  })).optional(),
  variants: z.array(z.object({
    id: z.string(),
    name: z.string(),
    weight: z.number().min(0).max(100),
    value: z.any()
  })).optional(),
  metadata: z.record(z.any()).optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

/**
 * Feature Flag Service
 */
export class FeatureFlagService {
  private flags: Map<string, FeatureFlag> = new Map();
  private cache: CacheService;
  private evaluationCache: Map<string, FlagEvaluation> = new Map();
  private evaluationHandlers: ((evaluation: FlagEvaluation) => void)[] = [];

  constructor(cache: CacheService) {
    this.cache = cache;
    this.initializeFlags();
  }

  /**
   * Initialize default feature flags
   */
  private initializeFlags(): void {
    // API Version flags
    this.createFlag({
      id: 'api-v2-rollout',
      name: 'API v2.0 Rollout',
      description: 'Gradual rollout of API version 2.0',
      enabled: true,
      type: 'percentage',
      value: 100, // 100% rollout
      conditions: [
        {
          type: 'environment',
          operator: 'not_in',
          value: ['test', 'development']
        }
      ]
    });

    this.createFlag({
      id: 'api-v3-preview',
      name: 'API v3.0 Preview Access',
      description: 'Enable preview access to API v3.0',
      enabled: true,
      type: 'boolean',
      conditions: [
        {
          type: 'permission',
          operator: 'contains',
          value: 'api.preview'
        }
      ]
    });

    // Version-specific features
    this.createFlag({
      id: 'async-video-processing',
      name: 'Async Video Processing',
      description: 'Enable asynchronous video processing',
      enabled: true,
      type: 'variant',
      variants: [
        { id: 'sync', name: 'Synchronous', weight: 10, value: 'sync' },
        { id: 'async', name: 'Asynchronous', weight: 90, value: 'async' }
      ]
    });

    this.createFlag({
      id: 'new-incident-model',
      name: 'New Incident Model',
      description: 'Use new incident data model v2.0',
      enabled: true,
      type: 'version',
      value: '2.0',
      conditions: [
        {
          type: 'version',
          operator: 'greater_than',
          value: '1.1'
        }
      ]
    });

    // Tenant-specific rollout
    this.createFlag({
      id: 'enhanced-analytics',
      name: 'Enhanced Analytics',
      description: 'New analytics dashboard features',
      enabled: true,
      type: 'boolean',
      conditions: [
        {
          type: 'tenant',
          operator: 'in',
          value: ['tenant-123', 'tenant-456'] // Beta tenants
        }
      ]
    });
  }

  /**
   * Create or update a feature flag
   */
  createFlag(flag: Omit<FeatureFlag, 'createdAt' | 'updatedAt'>): FeatureFlag {
    const now = new Date();
    const fullFlag: FeatureFlag = {
      ...flag,
      createdAt: this.flags.get(flag.id)?.createdAt || now,
      updatedAt: now
    };

    const validated = featureFlagSchema.parse(fullFlag);
    this.flags.set(validated.id, validated);
    this.invalidateCache();

    return validated;
  }

  /**
   * Get all flags
   */
  getAllFlags(): FeatureFlag[] {
    return Array.from(this.flags.values());
  }

  /**
   * Get flag by ID
   */
  getFlag(id: string): FeatureFlag | undefined {
    return this.flags.get(id);
  }

  /**
   * Delete flag
   */
  deleteFlag(id: string): boolean {
    const result = this.flags.delete(id);
    if (result) {
      this.invalidateCache();
    }
    return result;
  }

  /**
   * Evaluate feature flag for context
   */
  evaluate(flagId: string, context: EvaluationContext): FlagEvaluation {
    // Check cache first
    const cacheKey = this.getCacheKey(flagId, context);
    const cached = this.evaluationCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const flag = this.flags.get(flagId);
    if (!flag) {
      return {
        flagId,
        enabled: false,
        value: null,
        reason: 'Flag not found'
      };
    }

    if (!flag.enabled) {
      return {
        flagId,
        enabled: false,
        value: null,
        reason: 'Flag disabled'
      };
    }

    // Evaluate conditions
    if (flag.conditions && flag.conditions.length > 0) {
      const conditionsMet = this.evaluateConditions(flag.conditions, context);
      if (!conditionsMet) {
        return {
          flagId,
          enabled: false,
          value: null,
          reason: 'Conditions not met'
        };
      }
    }

    // Evaluate based on flag type
    let evaluation: FlagEvaluation;
    switch (flag.type) {
      case 'boolean':
        evaluation = {
          flagId,
          enabled: true,
          value: true,
          reason: 'Flag enabled'
        };
        break;

      case 'percentage':
        const percentage = flag.value as number;
        const hash = this.hashContext(context);
        const enabled = (hash % 100) < percentage;
        evaluation = {
          flagId,
          enabled,
          value: enabled,
          reason: enabled ? `Within ${percentage}% rollout` : `Outside ${percentage}% rollout`
        };
        break;

      case 'variant':
        const variant = this.selectVariant(flag.variants || [], context);
        evaluation = {
          flagId,
          enabled: true,
          value: variant?.value,
          variant: variant?.name,
          reason: `Variant selected: ${variant?.name}`
        };
        break;

      case 'version':
        evaluation = {
          flagId,
          enabled: true,
          value: flag.value,
          reason: `Version: ${flag.value}`
        };
        break;

      default:
        evaluation = {
          flagId,
          enabled: false,
          value: null,
          reason: 'Unknown flag type'
        };
    }

    // Cache the evaluation
    this.evaluationCache.set(cacheKey, evaluation);

    // Notify handlers
    for (const handler of this.evaluationHandlers) {
      handler(evaluation);
    }

    return evaluation;
  }

  /**
   * Evaluate all flags for context
   */
  evaluateAll(context: EvaluationContext): Record<string, FlagEvaluation> {
    const evaluations: Record<string, FlagEvaluation> = {};
    
    for (const flag of this.flags.values()) {
      evaluations[flag.id] = this.evaluate(flag.id, context);
    }

    return evaluations;
  }

  /**
   * Evaluate conditions
   */
  private evaluateConditions(conditions: FlagCondition[], context: EvaluationContext): boolean {
    for (const condition of conditions) {
      if (!this.evaluateCondition(condition, context)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Evaluate single condition
   */
  private evaluateCondition(condition: FlagCondition, context: EvaluationContext): boolean {
    let contextValue: any;

    switch (condition.type) {
      case 'user':
        contextValue = context.userId;
        break;
      case 'tenant':
        contextValue = context.tenantId;
        break;
      case 'role':
        contextValue = context.roles;
        break;
      case 'permission':
        contextValue = context.permissions;
        break;
      case 'version':
        contextValue = context.version;
        break;
      case 'environment':
        contextValue = context.environment;
        break;
      case 'custom':
        contextValue = context.custom?.[condition.value];
        break;
    }

    switch (condition.operator) {
      case 'equals':
        return contextValue === condition.value;
      case 'contains':
        return Array.isArray(contextValue) ? 
          contextValue.includes(condition.value) : 
          String(contextValue).includes(condition.value);
      case 'in':
        return Array.isArray(condition.value) ? 
          condition.value.includes(contextValue) : false;
      case 'not_in':
        return Array.isArray(condition.value) ? 
          !condition.value.includes(contextValue) : true;
      case 'greater_than':
        return Number(contextValue) > Number(condition.value);
      case 'less_than':
        return Number(contextValue) < Number(condition.value);
      default:
        return false;
    }
  }

  /**
   * Select variant based on weights
   */
  private selectVariant(variants: FlagVariant[], context: EvaluationContext): FlagVariant | null {
    if (variants.length === 0) return null;

    const totalWeight = variants.reduce((sum, v) => sum + v.weight, 0);
    if (totalWeight === 0) return variants[0];

    const hash = this.hashContext(context);
    const position = (hash % 100) * (totalWeight / 100);

    let cumulative = 0;
    for (const variant of variants) {
      cumulative += variant.weight;
      if (position < cumulative) {
        return variant;
      }
    }

    return variants[variants.length - 1];
  }

  /**
   * Hash context for consistent evaluation
   */
  private hashContext(context: EvaluationContext): number {
    const str = `${context.userId || ''}:${context.tenantId || ''}:${context.sessionId || ''}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }

  /**
   * Get cache key for evaluation
   */
  private getCacheKey(flagId: string, context: EvaluationContext): string {
    return `${flagId}:${context.userId || ''}:${context.tenantId || ''}:${context.version || ''}`;
  }

  /**
   * Invalidate evaluation cache
   */
  private invalidateCache(): void {
    this.evaluationCache.clear();
  }

  /**
   * Register evaluation handler
   */
  onEvaluation(handler: (evaluation: FlagEvaluation) => void): void {
    this.evaluationHandlers.push(handler);
  }

  /**
   * Get feature flag statistics
   */
  async getStatistics(flagId: string, days: number = 7): Promise<{
    evaluations: number;
    enabledCount: number;
    disabledCount: number;
    variantDistribution?: Record<string, number>;
  }> {
    // This would typically query from a metrics store
    return {
      evaluations: 1000,
      enabledCount: 850,
      disabledCount: 150,
      variantDistribution: {
        'control': 500,
        'treatment': 500
      }
    };
  }
}

/**
 * Evaluation context
 */
export interface EvaluationContext {
  userId?: string;
  tenantId?: string;
  roles?: string[];
  permissions?: string[];
  version?: string;
  environment?: string;
  sessionId?: string;
  custom?: Record<string, any>;
}

/**
 * Feature flag middleware
 */
export const featureFlagMiddleware = (service: FeatureFlagService) => {
  return async (c: Context, next: () => Promise<void>) => {
    const user = c.get('user') as any;
    const version = c.get('version') as any;

    const context: EvaluationContext = {
      userId: user?.userId,
      tenantId: user?.tenantId,
      roles: user?.roles,
      permissions: user?.permissions,
      version: version?.resolved,
      environment: process.env.NODE_ENV,
      sessionId: user?.sessionId
    };

    // Evaluate all flags and store in context
    const flags = service.evaluateAll(context);
    c.set('featureFlags', flags);

    // Helper function to check flags
    c.set('hasFeature', (flagId: string): boolean => {
      return flags[flagId]?.enabled || false;
    });

    c.set('getFeatureValue', (flagId: string): any => {
      return flags[flagId]?.value;
    });

    await next();
  };
};

/**
 * Version-based feature flag helper
 */
export const versionFeatureFlag = (
  flagId: string,
  handlers: Record<string, (c: Context) => Promise<Response> | Response>
) => {
  return async (c: Context): Promise<Response> => {
    const flags = c.get('featureFlags') as Record<string, FlagEvaluation>;
    const flag = flags[flagId];

    if (!flag || !flag.enabled) {
      // Use default handler
      const handler = handlers.default;
      if (!handler) {
        return c.json({ error: 'Feature not available' }, 404);
      }
      return await handler(c);
    }

    const version = flag.value as string;
    const handler = handlers[version] || handlers.default;

    if (!handler) {
      return c.json({ error: `No handler for version ${version}` }, 501);
    }

    return await handler(c);
  };
};