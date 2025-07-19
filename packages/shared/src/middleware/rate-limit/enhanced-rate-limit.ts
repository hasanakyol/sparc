/**
 * Enhanced Rate Limiting Middleware for SPARC Platform
 * Provides advanced rate limiting with multiple strategies
 */

import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import Redis from 'ioredis';
import { createHash } from 'crypto';

// Rate limiting strategies
export enum RateLimitStrategy {
  FIXED_WINDOW = 'fixed_window',
  SLIDING_WINDOW = 'sliding_window',
  TOKEN_BUCKET = 'token_bucket',
  LEAKY_BUCKET = 'leaky_bucket',
  ADAPTIVE = 'adaptive'
}

// Rate limit configuration
export interface RateLimitConfig {
  strategy?: RateLimitStrategy;
  windowMs?: number;
  max?: number;
  keyGenerator?: (c: Context) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  message?: string;
  statusCode?: number;
  headers?: boolean;
  redis: Redis;
  
  // Advanced options
  burst?: number; // For token bucket
  refillRate?: number; // Tokens per second for token bucket
  adaptiveThreshold?: number; // For adaptive strategy
  tenantQuotas?: Map<string, TenantQuota>;
  endpointLimits?: Map<string, EndpointLimit>;
  
  // Callbacks
  onLimitReached?: (c: Context, key: string) => void | Promise<void>;
  onQuotaExceeded?: (c: Context, tenantId: string) => void | Promise<void>;
}

export interface TenantQuota {
  requests: number;
  windowMs: number;
  burst?: number;
  priority?: 'low' | 'normal' | 'high';
}

export interface EndpointLimit {
  pattern: RegExp;
  max: number;
  windowMs: number;
  strategy?: RateLimitStrategy;
}

// Default configuration
const defaultConfig: Partial<RateLimitConfig> = {
  strategy: RateLimitStrategy.SLIDING_WINDOW,
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  burst: 20,
  refillRate: 2, // 2 tokens per second
  adaptiveThreshold: 0.8,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  message: 'Too many requests, please try again later.',
  statusCode: 429,
  headers: true,
  keyGenerator: (c: Context) => {
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const ip = c.req.header('x-forwarded-for')?.split(',')[0] || 
                c.req.header('x-real-ip') || 
                'unknown';
    
    if (userId && tenantId) {
      return `${tenantId}:${userId}`;
    }
    return `ip:${ip}`;
  }
};

/**
 * Enhanced rate limiting middleware factory
 */
export function createEnhancedRateLimiter(config: RateLimitConfig) {
  const finalConfig = { ...defaultConfig, ...config } as Required<RateLimitConfig>;
  
  return async (c: Context, next: Next) => {
    const key = finalConfig.keyGenerator(c);
    const endpoint = c.req.path;
    const method = c.req.method;
    
    try {
      // Check tenant-specific quotas
      const tenantId = c.get('tenantId');
      if (tenantId && finalConfig.tenantQuotas?.has(tenantId)) {
        const quotaExceeded = await checkTenantQuota(
          finalConfig.redis,
          tenantId,
          finalConfig.tenantQuotas.get(tenantId)!
        );
        
        if (quotaExceeded) {
          if (finalConfig.onQuotaExceeded) {
            await finalConfig.onQuotaExceeded(c, tenantId);
          }
          throw new HTTPException(finalConfig.statusCode, { 
            message: 'Tenant quota exceeded' 
          });
        }
      }
      
      // Check endpoint-specific limits
      const endpointLimit = findEndpointLimit(endpoint, finalConfig.endpointLimits);
      const effectiveConfig = endpointLimit ? {
        ...finalConfig,
        max: endpointLimit.max,
        windowMs: endpointLimit.windowMs,
        strategy: endpointLimit.strategy || finalConfig.strategy
      } : finalConfig;
      
      // Apply rate limiting based on strategy
      let allowed: boolean;
      let limitInfo: RateLimitInfo;
      
      switch (effectiveConfig.strategy) {
        case RateLimitStrategy.FIXED_WINDOW:
          [allowed, limitInfo] = await fixedWindowLimit(
            effectiveConfig.redis,
            key,
            effectiveConfig
          );
          break;
          
        case RateLimitStrategy.SLIDING_WINDOW:
          [allowed, limitInfo] = await slidingWindowLimit(
            effectiveConfig.redis,
            key,
            effectiveConfig
          );
          break;
          
        case RateLimitStrategy.TOKEN_BUCKET:
          [allowed, limitInfo] = await tokenBucketLimit(
            effectiveConfig.redis,
            key,
            effectiveConfig
          );
          break;
          
        case RateLimitStrategy.LEAKY_BUCKET:
          [allowed, limitInfo] = await leakyBucketLimit(
            effectiveConfig.redis,
            key,
            effectiveConfig
          );
          break;
          
        case RateLimitStrategy.ADAPTIVE:
          [allowed, limitInfo] = await adaptiveLimit(
            effectiveConfig.redis,
            key,
            effectiveConfig,
            c
          );
          break;
          
        default:
          [allowed, limitInfo] = await slidingWindowLimit(
            effectiveConfig.redis,
            key,
            effectiveConfig
          );
      }
      
      // Set rate limit headers
      if (effectiveConfig.headers) {
        c.header('X-RateLimit-Limit', limitInfo.limit.toString());
        c.header('X-RateLimit-Remaining', limitInfo.remaining.toString());
        c.header('X-RateLimit-Reset', new Date(limitInfo.resetAt).toISOString());
        
        if (!allowed) {
          c.header('Retry-After', Math.ceil((limitInfo.resetAt - Date.now()) / 1000).toString());
        }
      }
      
      // Handle rate limit exceeded
      if (!allowed) {
        if (effectiveConfig.onLimitReached) {
          await effectiveConfig.onLimitReached(c, key);
        }
        
        // Log rate limit event
        await logRateLimitEvent(effectiveConfig.redis, key, endpoint, method);
        
        throw new HTTPException(effectiveConfig.statusCode, { 
          message: effectiveConfig.message 
        });
      }
      
      // Continue to next middleware
      await next();
      
      // Handle skip options
      const status = c.res.status;
      if (
        (effectiveConfig.skipSuccessfulRequests && status < 400) ||
        (effectiveConfig.skipFailedRequests && status >= 400)
      ) {
        await refundRequest(effectiveConfig.redis, key, effectiveConfig);
      }
      
    } catch (error) {
      if (error instanceof HTTPException) {
        throw error;
      }
      // Log error but don't block request if rate limiting fails
      console.error('Rate limit error:', error);
      await next();
    }
  };
}

// Rate limit info interface
interface RateLimitInfo {
  limit: number;
  remaining: number;
  resetAt: number;
}

/**
 * Fixed window rate limiting
 */
async function fixedWindowLimit(
  redis: Redis,
  key: string,
  config: Required<RateLimitConfig>
): Promise<[boolean, RateLimitInfo]> {
  const windowKey = `rate:fixed:${key}:${Math.floor(Date.now() / config.windowMs)}`;
  
  const multi = redis.multi();
  multi.incr(windowKey);
  multi.expire(windowKey, Math.ceil(config.windowMs / 1000));
  
  const results = await multi.exec();
  const count = results?.[0]?.[1] as number || 0;
  
  const resetAt = Math.ceil(Date.now() / config.windowMs) * config.windowMs;
  const remaining = Math.max(0, config.max - count);
  
  return [
    count <= config.max,
    { limit: config.max, remaining, resetAt }
  ];
}

/**
 * Sliding window rate limiting
 */
async function slidingWindowLimit(
  redis: Redis,
  key: string,
  config: Required<RateLimitConfig>
): Promise<[boolean, RateLimitInfo]> {
  const now = Date.now();
  const windowStart = now - config.windowMs;
  const redisKey = `rate:sliding:${key}`;
  
  // Use Redis pipeline for atomic operations
  const multi = redis.multi();
  
  // Remove old entries
  multi.zremrangebyscore(redisKey, '-inf', windowStart);
  
  // Add current request
  multi.zadd(redisKey, now, `${now}-${Math.random()}`);
  
  // Count requests in window
  multi.zcount(redisKey, windowStart, '+inf');
  
  // Set expiry
  multi.expire(redisKey, Math.ceil(config.windowMs / 1000) + 1);
  
  const results = await multi.exec();
  const count = results?.[2]?.[1] as number || 0;
  
  const remaining = Math.max(0, config.max - count);
  const oldestRequest = await redis.zrange(redisKey, 0, 0, 'WITHSCORES');
  const resetAt = oldestRequest.length > 0 
    ? parseInt(oldestRequest[1]) + config.windowMs 
    : now + config.windowMs;
  
  return [
    count <= config.max,
    { limit: config.max, remaining, resetAt }
  ];
}

/**
 * Token bucket rate limiting
 */
async function tokenBucketLimit(
  redis: Redis,
  key: string,
  config: Required<RateLimitConfig>
): Promise<[boolean, RateLimitInfo]> {
  const bucketKey = `rate:bucket:${key}`;
  const now = Date.now();
  
  // Lua script for atomic token bucket operations
  const luaScript = `
    local key = KEYS[1]
    local max_tokens = tonumber(ARGV[1])
    local refill_rate = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local cost = tonumber(ARGV[4])
    
    local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
    local tokens = tonumber(bucket[1]) or max_tokens
    local last_refill = tonumber(bucket[2]) or now
    
    -- Calculate tokens to add
    local elapsed = (now - last_refill) / 1000
    local new_tokens = math.min(max_tokens, tokens + (elapsed * refill_rate))
    
    -- Try to consume tokens
    if new_tokens >= cost then
      new_tokens = new_tokens - cost
      redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
      redis.call('EXPIRE', key, 3600)
      return {1, new_tokens, max_tokens}
    else
      redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
      redis.call('EXPIRE', key, 3600)
      return {0, new_tokens, max_tokens}
    end
  `;
  
  const result = await redis.eval(
    luaScript,
    1,
    bucketKey,
    config.burst || config.max,
    config.refillRate,
    now,
    1
  ) as [number, number, number];
  
  const allowed = result[0] === 1;
  const remaining = Math.floor(result[1]);
  const resetAt = now + Math.ceil((1 - remaining) / config.refillRate * 1000);
  
  return [
    allowed,
    { limit: config.max, remaining, resetAt }
  ];
}

/**
 * Leaky bucket rate limiting
 */
async function leakyBucketLimit(
  redis: Redis,
  key: string,
  config: Required<RateLimitConfig>
): Promise<[boolean, RateLimitInfo]> {
  const bucketKey = `rate:leaky:${key}`;
  const now = Date.now();
  const leakRate = config.max / config.windowMs * 1000; // requests per second
  
  // Lua script for atomic leaky bucket operations
  const luaScript = `
    local key = KEYS[1]
    local capacity = tonumber(ARGV[1])
    local leak_rate = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    
    local bucket = redis.call('HMGET', key, 'volume', 'last_leak')
    local volume = tonumber(bucket[1]) or 0
    local last_leak = tonumber(bucket[2]) or now
    
    -- Calculate leaked amount
    local elapsed = (now - last_leak) / 1000
    local leaked = elapsed * leak_rate
    volume = math.max(0, volume - leaked)
    
    -- Try to add request
    if volume + 1 <= capacity then
      volume = volume + 1
      redis.call('HMSET', key, 'volume', volume, 'last_leak', now)
      redis.call('EXPIRE', key, 3600)
      return {1, capacity - volume}
    else
      redis.call('HMSET', key, 'volume', volume, 'last_leak', now)
      redis.call('EXPIRE', key, 3600)
      return {0, 0}
    end
  `;
  
  const result = await redis.eval(
    luaScript,
    1,
    bucketKey,
    config.max,
    leakRate,
    now
  ) as [number, number];
  
  const allowed = result[0] === 1;
  const remaining = Math.floor(result[1]);
  const resetAt = now + (config.max - remaining) / leakRate * 1000;
  
  return [
    allowed,
    { limit: config.max, remaining, resetAt }
  ];
}

/**
 * Adaptive rate limiting based on system load
 */
async function adaptiveLimit(
  redis: Redis,
  key: string,
  config: Required<RateLimitConfig>,
  context: Context
): Promise<[boolean, RateLimitInfo]> {
  // Get system metrics
  const systemLoad = await getSystemLoad(redis);
  const errorRate = await getErrorRate(redis);
  
  // Calculate adaptive limit
  let adaptiveMax = config.max;
  
  if (systemLoad > config.adaptiveThreshold) {
    // Reduce limit under high load
    adaptiveMax = Math.floor(config.max * (1 - systemLoad));
  }
  
  if (errorRate > 0.1) { // More than 10% errors
    // Further reduce limit if high error rate
    adaptiveMax = Math.floor(adaptiveMax * 0.8);
  }
  
  // Apply sliding window with adaptive limit
  const adaptedConfig = { ...config, max: adaptiveMax };
  return slidingWindowLimit(redis, key, adaptedConfig);
}

/**
 * Check tenant quota
 */
async function checkTenantQuota(
  redis: Redis,
  tenantId: string,
  quota: TenantQuota
): Promise<boolean> {
  const quotaKey = `quota:tenant:${tenantId}`;
  const now = Date.now();
  const windowStart = now - quota.windowMs;
  
  // Count requests in window
  const count = await redis.zcount(quotaKey, windowStart, '+inf');
  
  if (count >= quota.requests) {
    return true; // Quota exceeded
  }
  
  // Add current request
  await redis.zadd(quotaKey, now, `${now}-${Math.random()}`);
  await redis.expire(quotaKey, Math.ceil(quota.windowMs / 1000));
  
  return false;
}

/**
 * Find endpoint-specific limit
 */
function findEndpointLimit(
  endpoint: string,
  limits?: Map<string, EndpointLimit>
): EndpointLimit | undefined {
  if (!limits) return undefined;
  
  for (const [_, limit] of limits) {
    if (limit.pattern.test(endpoint)) {
      return limit;
    }
  }
  
  return undefined;
}

/**
 * Refund a request (for skip options)
 */
async function refundRequest(
  redis: Redis,
  key: string,
  config: Required<RateLimitConfig>
): Promise<void> {
  const now = Date.now();
  
  switch (config.strategy) {
    case RateLimitStrategy.SLIDING_WINDOW:
      // Remove the most recent entry
      const redisKey = `rate:sliding:${key}`;
      await redis.zremrangebyscore(redisKey, now - 100, now + 100);
      break;
      
    case RateLimitStrategy.TOKEN_BUCKET:
      // Add token back
      const bucketKey = `rate:bucket:${key}`;
      await redis.hincrby(bucketKey, 'tokens', 1);
      break;
      
    // Other strategies don't support refunds
  }
}

/**
 * Log rate limit event
 */
async function logRateLimitEvent(
  redis: Redis,
  key: string,
  endpoint: string,
  method: string
): Promise<void> {
  const eventKey = 'rate:events';
  const event = {
    key,
    endpoint,
    method,
    timestamp: Date.now()
  };
  
  await redis.lpush(eventKey, JSON.stringify(event));
  await redis.ltrim(eventKey, 0, 999); // Keep last 1000 events
}

/**
 * Get system load metric
 */
async function getSystemLoad(redis: Redis): Promise<number> {
  const load = await redis.get('metrics:system:load');
  return parseFloat(load || '0');
}

/**
 * Get error rate metric
 */
async function getErrorRate(redis: Redis): Promise<number> {
  const errors = await redis.get('metrics:errors:rate');
  return parseFloat(errors || '0');
}

/**
 * Create specialized rate limiters
 */
export const createAuthRateLimiter = (redis: Redis) => createEnhancedRateLimiter({
  redis,
  strategy: RateLimitStrategy.SLIDING_WINDOW,
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  skipSuccessfulRequests: true,
  message: 'Too many authentication attempts, please try again later.',
  keyGenerator: (c: Context) => {
    const email = c.req.header('x-auth-email') || c.req.json()?.email || '';
    const ip = c.req.header('x-forwarded-for')?.split(',')[0] || 'unknown';
    return `auth:${email || ip}`;
  },
  onLimitReached: async (c, key) => {
    // Could implement account lockout logic here
    console.warn(`Authentication rate limit reached for ${key}`);
  }
});

export const createApiRateLimiter = (redis: Redis) => createEnhancedRateLimiter({
  redis,
  strategy: RateLimitStrategy.TOKEN_BUCKET,
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  burst: 10,
  refillRate: 1,
  message: 'API rate limit exceeded.',
  tenantQuotas: new Map([
    ['premium', { requests: 1000, windowMs: 60000, priority: 'high' }],
    ['standard', { requests: 100, windowMs: 60000, priority: 'normal' }],
    ['free', { requests: 10, windowMs: 60000, priority: 'low' }]
  ])
});

export const createVideoStreamRateLimiter = (redis: Redis) => createEnhancedRateLimiter({
  redis,
  strategy: RateLimitStrategy.LEAKY_BUCKET,
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100,
  message: 'Video streaming rate limit exceeded.',
  endpointLimits: new Map([
    ['live', { pattern: /\/api\/videos\/live\//, max: 10, windowMs: 3600000 }],
    ['vod', { pattern: /\/api\/videos\/vod\//, max: 50, windowMs: 3600000 }],
    ['download', { pattern: /\/api\/videos\/download\//, max: 5, windowMs: 3600000 }]
  ])
});

export const createIncidentRateLimiter = (redis: Redis) => createEnhancedRateLimiter({
  redis,
  strategy: RateLimitStrategy.ADAPTIVE,
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20,
  adaptiveThreshold: 0.7,
  message: 'Incident creation rate limit exceeded.',
  keyGenerator: (c: Context) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    return `incident:${tenantId}:${userId}`;
  }
});