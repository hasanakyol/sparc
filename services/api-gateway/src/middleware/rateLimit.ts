import { Context, Next } from 'hono';
import { createClient, RedisClientType } from 'redis';
import { z } from 'zod';

// Rate limit configuration schema
const RateLimitConfigSchema = z.object({
  windowMs: z.number().min(1000).default(60000), // 1 minute default
  maxRequests: z.number().min(1).default(100),
  burstLimit: z.number().min(1).optional(), // Allow burst requests above normal limit
  skipSuccessfulRequests: z.boolean().default(false),
  skipFailedRequests: z.boolean().default(false),
  keyPrefix: z.string().default('rl:'),
  strategy: z.enum(['sliding_window', 'fixed_window', 'token_bucket']).default('sliding_window'),
});

type RateLimitConfig = z.infer<typeof RateLimitConfigSchema>;

// User roles with different rate limit multipliers
enum UserRole {
  GUEST = 'guest',
  USER = 'user',
  ADMIN = 'admin',
  SUPER_ADMIN = 'super_admin',
  SERVICE_ACCOUNT = 'service_account',
}

// Role-based rate limit multipliers
const ROLE_MULTIPLIERS: Record<UserRole, number> = {
  [UserRole.GUEST]: 0.5,        // 50% of base limit
  [UserRole.USER]: 1.0,         // 100% of base limit
  [UserRole.ADMIN]: 2.0,        // 200% of base limit
  [UserRole.SUPER_ADMIN]: 5.0,  // 500% of base limit
  [UserRole.SERVICE_ACCOUNT]: 10.0, // 1000% of base limit
};

// Tenant tier configurations
interface TenantQuota {
  tier: 'free' | 'basic' | 'premium' | 'enterprise';
  dailyRequestLimit: number;
  burstMultiplier: number;
  concurrentUsers: number;
}

const TENANT_QUOTAS: Record<string, TenantQuota> = {
  free: {
    tier: 'free',
    dailyRequestLimit: 10000,
    burstMultiplier: 1.5,
    concurrentUsers: 10,
  },
  basic: {
    tier: 'basic',
    dailyRequestLimit: 100000,
    burstMultiplier: 2.0,
    concurrentUsers: 50,
  },
  premium: {
    tier: 'premium',
    dailyRequestLimit: 1000000,
    burstMultiplier: 3.0,
    concurrentUsers: 200,
  },
  enterprise: {
    tier: 'enterprise',
    dailyRequestLimit: 10000000,
    burstMultiplier: 5.0,
    concurrentUsers: 1000,
  },
};

// Rate limit rule for different endpoints/users/tenants
interface RateLimitRule {
  pattern: string | RegExp;
  config: RateLimitConfig;
  priority: number; // Higher number = higher priority
  roleOverrides?: Partial<Record<UserRole, Partial<RateLimitConfig>>>;
}

// Rate limit result
interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

// Default rate limit configurations
const DEFAULT_RULES: RateLimitRule[] = [
  // Authentication endpoints - stricter limits with role overrides
  {
    pattern: /^\/api\/auth\/(login|signup|reset-password)/,
    config: { 
      windowMs: 900000, 
      maxRequests: 5, 
      burstLimit: 10,
      strategy: 'sliding_window' as const
    }, // 5 requests per 15 minutes
    priority: 100,
    roleOverrides: {
      [UserRole.ADMIN]: { maxRequests: 20 },
      [UserRole.SUPER_ADMIN]: { maxRequests: 50 },
      [UserRole.SERVICE_ACCOUNT]: { maxRequests: 100 },
    },
  },
  // Admin endpoints - moderate limits
  {
    pattern: /^\/api\/admin/,
    config: { 
      windowMs: 60000, 
      maxRequests: 50,
      burstLimit: 100,
      strategy: 'sliding_window' as const
    }, // 50 requests per minute
    priority: 90,
    roleOverrides: {
      [UserRole.SUPER_ADMIN]: { maxRequests: 200 },
      [UserRole.SERVICE_ACCOUNT]: { maxRequests: 500 },
    },
  },
  // Video streaming endpoints - higher limits
  {
    pattern: /^\/api\/video\/(stream|live)/,
    config: { 
      windowMs: 60000, 
      maxRequests: 1000,
      burstLimit: 2000,
      strategy: 'token_bucket' as const
    }, // 1000 requests per minute
    priority: 80,
    roleOverrides: {
      [UserRole.SERVICE_ACCOUNT]: { maxRequests: 5000 },
    },
  },
  // Access control events - high frequency allowed
  {
    pattern: /^\/api\/access-control\/events/,
    config: { 
      windowMs: 60000, 
      maxRequests: 500,
      burstLimit: 1000,
      strategy: 'sliding_window' as const
    }, // 500 requests per minute
    priority: 70,
    roleOverrides: {
      [UserRole.SERVICE_ACCOUNT]: { maxRequests: 2000 },
    },
  },
  // Reporting endpoints - moderate limits for data export
  {
    pattern: /^\/api\/reporting/,
    config: { 
      windowMs: 300000, 
      maxRequests: 20,
      burstLimit: 30,
      strategy: 'fixed_window' as const
    }, // 20 requests per 5 minutes
    priority: 60,
    roleOverrides: {
      [UserRole.ADMIN]: { maxRequests: 50 },
      [UserRole.SUPER_ADMIN]: { maxRequests: 100 },
    },
  },
  // Analytics endpoints - moderate limits
  {
    pattern: /^\/api\/analytics/,
    config: { 
      windowMs: 60000, 
      maxRequests: 100,
      burstLimit: 150,
      strategy: 'sliding_window' as const
    }, // 100 requests per minute
    priority: 50,
  },
  // General API endpoints
  {
    pattern: /^\/api/,
    config: { 
      windowMs: 60000, 
      maxRequests: 200,
      burstLimit: 300,
      strategy: 'sliding_window' as const
    }, // 200 requests per minute
    priority: 10,
  },
];

export class RateLimiter {
  private redis: RedisClientType;
  private rules: RateLimitRule[];
  private isConnected: boolean = false;

  constructor(
    redisUrl: string = process.env.REDIS_URL || 'redis://localhost:6379',
    customRules: RateLimitRule[] = []
  ) {
    this.redis = createClient({ url: redisUrl });
    this.rules = [...customRules, ...DEFAULT_RULES].sort((a, b) => b.priority - a.priority);
    this.initRedis();
  }

  private async initRedis(): Promise<void> {
    try {
      await this.redis.connect();
      this.isConnected = true;
      console.log('Rate limiter Redis connection established');
    } catch (error) {
      console.error('Failed to connect to Redis for rate limiting:', error);
      this.isConnected = false;
    }

    this.redis.on('error', (error) => {
      console.error('Redis rate limiter error:', error);
      this.isConnected = false;
    });

    this.redis.on('connect', () => {
      this.isConnected = true;
      console.log('Rate limiter Redis reconnected');
    });
  }

  private generateKey(identifier: string, endpoint: string, config: RateLimitConfig): string {
    const window = Math.floor(Date.now() / config.windowMs);
    return `${config.keyPrefix}${identifier}:${endpoint}:${window}`;
  }

  private findMatchingRule(path: string): RateLimitRule {
    for (const rule of this.rules) {
      if (typeof rule.pattern === 'string') {
        if (path.startsWith(rule.pattern)) {
          return rule;
        }
      } else if (rule.pattern instanceof RegExp) {
        if (rule.pattern.test(path)) {
          return rule;
        }
      }
    }
    // Fallback to most general rule
    return this.rules[this.rules.length - 1];
  }

  private extractIdentifiers(c: Context): { 
    userId?: string; 
    tenantId?: string; 
    userRole?: UserRole;
    tenantTier?: string;
    ip: string;
  } {
    // Extract user and tenant from JWT token if available
    const user = c.get('user');
    const tenant = c.get('tenant');
    
    // Get IP address from various headers
    const ip = 
      c.req.header('cf-connecting-ip') ||
      c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
      c.req.header('x-real-ip') ||
      c.req.header('x-client-ip') ||
      'unknown';

    // Extract user role from user object or default to guest
    const userRole = user?.role as UserRole || UserRole.GUEST;
    
    // Extract tenant tier from tenant object or default to free
    const tenantTier = tenant?.tier || 'free';

    return {
      userId: user?.id,
      tenantId: tenant?.id,
      userRole,
      tenantTier,
      ip,
    };
  }

  private getEffectiveConfig(
    baseConfig: RateLimitConfig, 
    rule: RateLimitRule, 
    userRole?: UserRole,
    tenantTier?: string
  ): RateLimitConfig {
    let effectiveConfig = { ...baseConfig };

    // Apply role-based overrides
    if (userRole && rule.roleOverrides?.[userRole]) {
      effectiveConfig = {
        ...effectiveConfig,
        ...rule.roleOverrides[userRole],
      };
    }

    // Apply role multiplier to maxRequests if no explicit override
    if (userRole && !rule.roleOverrides?.[userRole]?.maxRequests) {
      const multiplier = ROLE_MULTIPLIERS[userRole] || 1.0;
      effectiveConfig.maxRequests = Math.floor(effectiveConfig.maxRequests * multiplier);
    }

    // Apply tenant tier multiplier
    if (tenantTier && TENANT_QUOTAS[tenantTier]) {
      const quota = TENANT_QUOTAS[tenantTier];
      effectiveConfig.maxRequests = Math.floor(effectiveConfig.maxRequests * quota.burstMultiplier);
      
      // Set burst limit based on tenant tier
      if (!effectiveConfig.burstLimit) {
        effectiveConfig.burstLimit = Math.floor(effectiveConfig.maxRequests * 1.5);
      }
    }

    return effectiveConfig;
  }

  private async checkTenantDailyQuota(tenantId: string, tenantTier: string): Promise<boolean> {
    if (!this.isConnected || !TENANT_QUOTAS[tenantTier]) {
      return true; // Allow if Redis unavailable or unknown tier
    }

    try {
      const quota = TENANT_QUOTAS[tenantTier];
      const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
      const dailyKey = `daily_quota:${tenantId}:${today}`;
      
      const currentCount = await this.redis.get(dailyKey);
      const count = currentCount ? parseInt(currentCount, 10) : 0;
      
      return count < quota.dailyRequestLimit;
    } catch (error) {
      console.error('Failed to check tenant daily quota:', error);
      return true; // Allow on error
    }
  }

  private async incrementTenantDailyQuota(tenantId: string): Promise<void> {
    if (!this.isConnected) return;

    try {
      const today = new Date().toISOString().split('T')[0];
      const dailyKey = `daily_quota:${tenantId}:${today}`;
      
      const multi = this.redis.multi();
      multi.incr(dailyKey);
      multi.expire(dailyKey, 86400); // 24 hours
      await multi.exec();
    } catch (error) {
      console.error('Failed to increment tenant daily quota:', error);
    }
  }

  private async checkRateLimit(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    if (!this.isConnected) {
      // If Redis is not available, allow the request but log the issue
      console.warn('Rate limiter Redis not connected, allowing request');
      return {
        allowed: true,
        limit: config.maxRequests,
        remaining: config.maxRequests - 1,
        resetTime: Date.now() + config.windowMs,
      };
    }

    try {
      switch (config.strategy) {
        case 'sliding_window':
          return await this.checkSlidingWindow(key, config);
        case 'fixed_window':
          return await this.checkFixedWindow(key, config);
        case 'token_bucket':
          return await this.checkTokenBucket(key, config);
        default:
          return await this.checkSlidingWindow(key, config);
      }
    } catch (error) {
      console.error('Rate limit check failed:', error);
      // On error, allow the request to prevent blocking legitimate traffic
      return {
        allowed: true,
        limit: config.maxRequests,
        remaining: config.maxRequests - 1,
        resetTime: Date.now() + config.windowMs,
      };
    }
  }

  private async checkSlidingWindow(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = now - config.windowMs;
    const slidingKey = `${key}:sliding`;

    // Use sorted set to track requests in sliding window
    const multi = this.redis.multi();
    
    // Remove old entries
    multi.zRemRangeByScore(slidingKey, 0, windowStart);
    
    // Add current request
    multi.zAdd(slidingKey, { score: now, value: `${now}-${Math.random()}` });
    
    // Count current requests
    multi.zCard(slidingKey);
    
    // Set expiration
    multi.expire(slidingKey, Math.ceil(config.windowMs / 1000) + 1);
    
    const results = await multi.exec();
    const count = results?.[2] as number || 0;
    
    const limit = config.burstLimit || config.maxRequests;
    const allowed = count <= limit;
    const remaining = Math.max(0, limit - count);
    const resetTime = now + config.windowMs;

    return {
      allowed,
      limit,
      remaining,
      resetTime,
      retryAfter: allowed ? undefined : Math.ceil(config.windowMs / 1000),
    };
  }

  private async checkFixedWindow(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const window = Math.floor(Date.now() / config.windowMs);
    const windowKey = `${key}:${window}`;

    const multi = this.redis.multi();
    multi.incr(windowKey);
    multi.expire(windowKey, Math.ceil(config.windowMs / 1000));
    multi.ttl(windowKey);
    
    const results = await multi.exec();
    
    if (!results || results.length !== 3) {
      throw new Error('Unexpected Redis response');
    }

    const count = results[0] as number;
    const ttl = results[2] as number;
    
    const resetTime = Date.now() + (ttl * 1000);
    const limit = config.burstLimit || config.maxRequests;
    const remaining = Math.max(0, limit - count);
    const allowed = count <= limit;

    return {
      allowed,
      limit,
      remaining,
      resetTime,
      retryAfter: allowed ? undefined : ttl,
    };
  }

  private async checkTokenBucket(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const bucketKey = `${key}:bucket`;
    
    // Token bucket parameters
    const capacity = config.burstLimit || config.maxRequests;
    const refillRate = config.maxRequests / (config.windowMs / 1000); // tokens per second
    
    // Get current bucket state
    const bucketData = await this.redis.hMGet(bucketKey, ['tokens', 'lastRefill']);
    
    let tokens = bucketData[0] ? parseFloat(bucketData[0]) : capacity;
    let lastRefill = bucketData[1] ? parseInt(bucketData[1], 10) : now;
    
    // Calculate tokens to add based on time elapsed
    const timeDelta = (now - lastRefill) / 1000;
    const tokensToAdd = timeDelta * refillRate;
    tokens = Math.min(capacity, tokens + tokensToAdd);
    
    const allowed = tokens >= 1;
    
    if (allowed) {
      tokens -= 1;
    }
    
    // Update bucket state
    const multi = this.redis.multi();
    multi.hMSet(bucketKey, {
      tokens: tokens.toString(),
      lastRefill: now.toString(),
    });
    multi.expire(bucketKey, Math.ceil(config.windowMs / 1000) * 2);
    await multi.exec();
    
    const resetTime = now + ((1 - tokens) / refillRate) * 1000;
    
    return {
      allowed,
      limit: capacity,
      remaining: Math.floor(tokens),
      resetTime,
      retryAfter: allowed ? undefined : Math.ceil((1 - tokens) / refillRate),
    };
  }

  async checkLimits(c: Context): Promise<RateLimitResult[]> {
    const path = c.req.path;
    const method = c.req.method;
    const rule = this.findMatchingRule(path);
    const identifiers = this.extractIdentifiers(c);
    const endpoint = `${method}:${path}`;

    // Check tenant daily quota first
    if (identifiers.tenantId && identifiers.tenantTier) {
      const quotaAllowed = await this.checkTenantDailyQuota(
        identifiers.tenantId, 
        identifiers.tenantTier
      );
      
      if (!quotaAllowed) {
        return [{
          allowed: false,
          limit: TENANT_QUOTAS[identifiers.tenantTier]?.dailyRequestLimit || 0,
          remaining: 0,
          resetTime: Date.now() + (24 * 60 * 60 * 1000), // Next day
          retryAfter: 24 * 60 * 60, // 24 hours
        }];
      }
    }

    const checks: Promise<RateLimitResult>[] = [];

    // Get effective configuration based on user role and tenant tier
    const effectiveConfig = this.getEffectiveConfig(
      rule.config, 
      rule, 
      identifiers.userRole,
      identifiers.tenantTier
    );

    // Per-IP rate limiting (always applied) - use base config for IP limits
    const ipKey = this.generateKey(`ip:${identifiers.ip}`, endpoint, rule.config);
    checks.push(this.checkRateLimit(ipKey, rule.config));

    // Per-user rate limiting (if authenticated) - use effective config
    if (identifiers.userId) {
      const userKey = this.generateKey(`user:${identifiers.userId}`, endpoint, effectiveConfig);
      checks.push(this.checkRateLimit(userKey, effectiveConfig));
    }

    // Per-tenant rate limiting (if tenant context available)
    if (identifiers.tenantId) {
      // Tenant-wide limits (higher than per-user, based on tenant tier)
      const tenantQuota = TENANT_QUOTAS[identifiers.tenantTier || 'free'];
      const tenantConfig = {
        ...effectiveConfig,
        maxRequests: effectiveConfig.maxRequests * tenantQuota.concurrentUsers,
        burstLimit: (effectiveConfig.burstLimit || effectiveConfig.maxRequests) * tenantQuota.concurrentUsers,
      };
      const tenantKey = this.generateKey(`tenant:${identifiers.tenantId}`, endpoint, tenantConfig);
      checks.push(this.checkRateLimit(tenantKey, tenantConfig));
    }

    // Global rate limiting for the entire system (prevents abuse)
    const globalConfig = {
      ...rule.config,
      maxRequests: rule.config.maxRequests * 1000, // Very high limit for global
      strategy: 'sliding_window' as const,
    };
    const globalKey = this.generateKey('global', endpoint, globalConfig);
    checks.push(this.checkRateLimit(globalKey, globalConfig));

    return Promise.all(checks);
  }

  async cleanup(): Promise<void> {
    if (this.isConnected) {
      await this.redis.quit();
      this.isConnected = false;
    }
  }
}

// Global rate limiter instance
let rateLimiterInstance: RateLimiter | null = null;

export function getRateLimiter(): RateLimiter {
  if (!rateLimiterInstance) {
    rateLimiterInstance = new RateLimiter();
  }
  return rateLimiterInstance;
}

// Rate limiting middleware
export function rateLimitMiddleware() {
  const limiter = getRateLimiter();

  return async (c: Context, next: Next) => {
    const startTime = Date.now();

    try {
      const results = await limiter.checkLimits(c);
      
      // Find the most restrictive result (first one that's not allowed)
      const restrictiveResult = results.find(result => !result.allowed) || results[0];

      // Set comprehensive rate limit headers
      c.header('X-RateLimit-Limit', restrictiveResult.limit.toString());
      c.header('X-RateLimit-Remaining', restrictiveResult.remaining.toString());
      c.header('X-RateLimit-Reset', Math.ceil(restrictiveResult.resetTime / 1000).toString());
      c.header('X-RateLimit-Policy', 'sliding-window');

      // Add additional headers for better client understanding
      const identifiers = limiter['extractIdentifiers'](c);
      if (identifiers.userRole) {
        c.header('X-RateLimit-User-Role', identifiers.userRole);
      }
      if (identifiers.tenantTier) {
        c.header('X-RateLimit-Tenant-Tier', identifiers.tenantTier);
      }

      if (!restrictiveResult.allowed) {
        // Set retry-after header
        if (restrictiveResult.retryAfter) {
          c.header('Retry-After', restrictiveResult.retryAfter.toString());
        }

        // Increment tenant daily quota even for blocked requests to track usage
        if (identifiers.tenantId) {
          await limiter['incrementTenantDailyQuota'](identifiers.tenantId);
        }

        // Enhanced logging for rate limit violations
        console.warn('Rate limit exceeded', {
          ip: identifiers.ip,
          userId: identifiers.userId,
          tenantId: identifiers.tenantId,
          userRole: identifiers.userRole,
          tenantTier: identifiers.tenantTier,
          path: c.req.path,
          method: c.req.method,
          limit: restrictiveResult.limit,
          remaining: restrictiveResult.remaining,
          resetTime: new Date(restrictiveResult.resetTime).toISOString(),
          userAgent: c.req.header('user-agent'),
          timestamp: new Date().toISOString(),
        });

        // Determine if this is a daily quota violation or rate limit violation
        const isQuotaViolation = restrictiveResult.retryAfter && restrictiveResult.retryAfter > 3600;
        
        return c.json(
          {
            error: isQuotaViolation ? 'Daily quota exceeded' : 'Rate limit exceeded',
            message: isQuotaViolation 
              ? 'Daily request quota has been exceeded. Please upgrade your plan or try again tomorrow.'
              : 'Too many requests. Please try again later.',
            retryAfter: restrictiveResult.retryAfter,
            limit: restrictiveResult.limit,
            remaining: restrictiveResult.remaining,
            resetTime: restrictiveResult.resetTime,
            type: isQuotaViolation ? 'quota_exceeded' : 'rate_limit_exceeded',
          },
          429
        );
      }

      // Increment tenant daily quota for successful requests
      if (identifiers.tenantId) {
        await limiter['incrementTenantDailyQuota'](identifiers.tenantId);
      }

      // Continue to next middleware
      await next();

      // Log successful request processing time to ensure we meet 200ms requirement
      const processingTime = Date.now() - startTime;
      if (processingTime > 200) {
        console.warn('Request processing time exceeded 200ms', {
          path: c.req.path,
          method: c.req.method,
          processingTime,
          userId: identifiers.userId,
          tenantId: identifiers.tenantId,
        });
      }

      // Log successful requests for analytics (sample to avoid overwhelming logs)
      if (Math.random() < 0.01) { // 1% sampling
        console.info('Request processed successfully', {
          path: c.req.path,
          method: c.req.method,
          processingTime,
          userId: identifiers.userId,
          tenantId: identifiers.tenantId,
          userRole: identifiers.userRole,
          tenantTier: identifiers.tenantTier,
          rateLimitRemaining: restrictiveResult.remaining,
        });
      }

    } catch (error) {
      console.error('Rate limiting middleware error:', error);
      // On error, allow the request to continue to prevent blocking legitimate traffic
      await next();
    }
  };
}

// Middleware for specific rate limiting configurations
export function customRateLimit(config: Partial<RateLimitConfig>) {
  const validatedConfig = RateLimitConfigSchema.parse(config);
  
  return async (c: Context, next: Next) => {
    const limiter = getRateLimiter();
    const identifiers = limiter['extractIdentifiers'](c);
    const endpoint = `${c.req.method}:${c.req.path}`;
    
    const key = limiter['generateKey'](`custom:${identifiers.ip}`, endpoint, validatedConfig);
    const result = await limiter['checkRateLimit'](key, validatedConfig);

    // Set headers
    c.header('X-RateLimit-Limit', result.limit.toString());
    c.header('X-RateLimit-Remaining', result.remaining.toString());
    c.header('X-RateLimit-Reset', Math.ceil(result.resetTime / 1000).toString());

    if (!result.allowed) {
      if (result.retryAfter) {
        c.header('Retry-After', result.retryAfter.toString());
      }

      return c.json(
        {
          error: 'Rate limit exceeded',
          message: 'Too many requests. Please try again later.',
          retryAfter: result.retryAfter,
          limit: result.limit,
          resetTime: result.resetTime,
        },
        429
      );
    }

    await next();
  };
}

// Cleanup function for graceful shutdown
export async function cleanupRateLimit(): Promise<void> {
  if (rateLimiterInstance) {
    await rateLimiterInstance.cleanup();
    rateLimiterInstance = null;
  }
}

// Advanced rate limiting for specific scenarios
export function burstProtectionMiddleware(burstConfig: {
  maxBurstRequests: number;
  burstWindowMs: number;
  cooldownMs: number;
}) {
  const limiter = getRateLimiter();
  
  return async (c: Context, next: Next) => {
    const identifiers = limiter['extractIdentifiers'](c);
    const burstKey = `burst:${identifiers.ip}:${identifiers.userId || 'anon'}`;
    
    try {
      const now = Date.now();
      const windowStart = now - burstConfig.burstWindowMs;
      
      // Check burst requests in the window
      const burstCount = await limiter.redis.zCount(burstKey, windowStart, now);
      
      if (burstCount >= burstConfig.maxBurstRequests) {
        // Check if cooldown period has passed
        const lastBurst = await limiter.redis.zRevRange(burstKey, 0, 0, { BY: 'SCORE' });
        if (lastBurst.length > 0) {
          const lastBurstTime = parseInt(lastBurst[0].score?.toString() || '0', 10);
          const timeSinceLastBurst = now - lastBurstTime;
          
          if (timeSinceLastBurst < burstConfig.cooldownMs) {
            const cooldownRemaining = Math.ceil((burstConfig.cooldownMs - timeSinceLastBurst) / 1000);
            
            c.header('X-Burst-Protection', 'active');
            c.header('Retry-After', cooldownRemaining.toString());
            
            return c.json({
              error: 'Burst protection activated',
              message: 'Too many rapid requests detected. Please slow down.',
              retryAfter: cooldownRemaining,
              type: 'burst_protection',
            }, 429);
          }
        }
      }
      
      // Record this request
      const multi = limiter.redis.multi();
      multi.zAdd(burstKey, { score: now, value: `${now}-${Math.random()}` });
      multi.zRemRangeByScore(burstKey, 0, windowStart);
      multi.expire(burstKey, Math.ceil(burstConfig.burstWindowMs / 1000) + Math.ceil(burstConfig.cooldownMs / 1000));
      await multi.exec();
      
      await next();
    } catch (error) {
      console.error('Burst protection middleware error:', error);
      await next();
    }
  };
}

// Rate limiting for specific user roles
export function roleBasedRateLimit(roleConfig: Partial<Record<UserRole, RateLimitConfig>>) {
  return async (c: Context, next: Next) => {
    const limiter = getRateLimiter();
    const identifiers = limiter['extractIdentifiers'](c);
    const userRole = identifiers.userRole || UserRole.GUEST;
    
    const config = roleConfig[userRole];
    if (!config) {
      await next();
      return;
    }
    
    const endpoint = `${c.req.method}:${c.req.path}`;
    const key = limiter['generateKey'](`role:${userRole}:${identifiers.userId || identifiers.ip}`, endpoint, config);
    const result = await limiter['checkRateLimit'](key, config);
    
    // Set headers
    c.header('X-RateLimit-Limit', result.limit.toString());
    c.header('X-RateLimit-Remaining', result.remaining.toString());
    c.header('X-RateLimit-Reset', Math.ceil(result.resetTime / 1000).toString());
    c.header('X-RateLimit-Role', userRole);
    
    if (!result.allowed) {
      if (result.retryAfter) {
        c.header('Retry-After', result.retryAfter.toString());
      }
      
      return c.json({
        error: 'Role-based rate limit exceeded',
        message: `Rate limit exceeded for role: ${userRole}`,
        retryAfter: result.retryAfter,
        limit: result.limit,
        resetTime: result.resetTime,
        role: userRole,
      }, 429);
    }
    
    await next();
  };
}

// Tenant quota monitoring middleware
export function tenantQuotaMiddleware() {
  const limiter = getRateLimiter();
  
  return async (c: Context, next: Next) => {
    const identifiers = limiter['extractIdentifiers'](c);
    
    if (identifiers.tenantId && identifiers.tenantTier) {
      const quota = TENANT_QUOTAS[identifiers.tenantTier];
      if (quota) {
        // Add quota information to headers
        c.header('X-Tenant-Tier', identifiers.tenantTier);
        c.header('X-Daily-Quota-Limit', quota.dailyRequestLimit.toString());
        
        // Get current daily usage
        try {
          const today = new Date().toISOString().split('T')[0];
          const dailyKey = `daily_quota:${identifiers.tenantId}:${today}`;
          const currentUsage = await limiter.redis.get(dailyKey);
          const usage = currentUsage ? parseInt(currentUsage, 10) : 0;
          
          c.header('X-Daily-Quota-Used', usage.toString());
          c.header('X-Daily-Quota-Remaining', Math.max(0, quota.dailyRequestLimit - usage).toString());
          
          // Warn when approaching quota limits
          const usagePercentage = (usage / quota.dailyRequestLimit) * 100;
          if (usagePercentage > 80) {
            c.header('X-Quota-Warning', 'approaching-limit');
          }
          if (usagePercentage > 95) {
            c.header('X-Quota-Warning', 'near-limit');
          }
        } catch (error) {
          console.error('Failed to get tenant quota usage:', error);
        }
      }
    }
    
    await next();
  };
}

// Export types and enums for use in other modules
export type { RateLimitConfig, RateLimitRule, RateLimitResult, TenantQuota };
export { UserRole, TENANT_QUOTAS, ROLE_MULTIPLIERS };
