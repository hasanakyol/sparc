import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import Redis from 'ioredis';

interface RateLimitOptions {
  windowMs?: number; // Time window in milliseconds
  max?: number; // Max requests per window
  keyGenerator?: (c: Context) => string; // Custom key generator
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  message?: string;
  redis?: Redis;
}

const defaultOptions: Required<Omit<RateLimitOptions, 'redis'>> = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  keyGenerator: (c: Context) => {
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');
    const ip = c.req.header('x-forwarded-for')?.split(',')[0] || 
                c.req.header('x-real-ip') || 
                'unknown';
    
    // Use userId and tenantId if available, otherwise fall back to IP
    if (userId && tenantId) {
      return `rate_limit:${tenantId}:${userId}`;
    }
    return `rate_limit:ip:${ip}`;
  },
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  message: 'Too many requests, please try again later.',
};

export const rateLimitMiddleware = (options: RateLimitOptions = {}) => {
  const config = { ...defaultOptions, ...options };
  
  if (!config.redis) {
    // If no Redis provided, use in-memory rate limiting (not recommended for production)
    const store = new Map<string, { count: number; resetTime: number }>();
    
    return async (c: Context, next: Next) => {
      const key = config.keyGenerator(c);
      const now = Date.now();
      
      let entry = store.get(key);
      if (!entry || now > entry.resetTime) {
        entry = { count: 0, resetTime: now + config.windowMs };
        store.set(key, entry);
      }
      
      if (entry.count >= config.max) {
        const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
        c.header('Retry-After', retryAfter.toString());
        c.header('X-RateLimit-Limit', config.max.toString());
        c.header('X-RateLimit-Remaining', '0');
        c.header('X-RateLimit-Reset', new Date(entry.resetTime).toISOString());
        
        throw new HTTPException(429, { message: config.message });
      }
      
      entry.count++;
      
      c.header('X-RateLimit-Limit', config.max.toString());
      c.header('X-RateLimit-Remaining', (config.max - entry.count).toString());
      c.header('X-RateLimit-Reset', new Date(entry.resetTime).toISOString());
      
      await next();
    };
  }
  
  // Redis-based rate limiting
  return async (c: Context, next: Next) => {
    const key = config.keyGenerator(c);
    const windowKey = `${key}:${Math.floor(Date.now() / config.windowMs)}`;
    
    try {
      // Increment counter
      const count = await config.redis.incr(windowKey);
      
      // Set expiry on first request
      if (count === 1) {
        await config.redis.expire(windowKey, Math.ceil(config.windowMs / 1000));
      }
      
      // Check if limit exceeded
      if (count > config.max) {
        const ttl = await config.redis.ttl(windowKey);
        c.header('Retry-After', ttl.toString());
        c.header('X-RateLimit-Limit', config.max.toString());
        c.header('X-RateLimit-Remaining', '0');
        c.header('X-RateLimit-Reset', new Date(Date.now() + ttl * 1000).toISOString());
        
        throw new HTTPException(429, { message: config.message });
      }
      
      // Set rate limit headers
      const remaining = config.max - count;
      const ttl = await config.redis.ttl(windowKey);
      c.header('X-RateLimit-Limit', config.max.toString());
      c.header('X-RateLimit-Remaining', remaining.toString());
      c.header('X-RateLimit-Reset', new Date(Date.now() + ttl * 1000).toISOString());
      
      await next();
      
      // Handle skip options
      const status = c.res.status;
      if (
        (config.skipSuccessfulRequests && status < 400) ||
        (config.skipFailedRequests && status >= 400)
      ) {
        // Decrement the counter
        await config.redis.decr(windowKey);
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
};

// Specialized rate limiters for different endpoints
export const createLoginRateLimiter = (redis: Redis) => rateLimitMiddleware({
  redis,
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts
  skipSuccessfulRequests: true, // Don't count successful logins
  message: 'Too many login attempts, please try again later.',
  keyGenerator: (c: Context) => {
    const email = c.req.header('x-auth-email') || '';
    const ip = c.req.header('x-forwarded-for')?.split(',')[0] || 
                c.req.header('x-real-ip') || 
                'unknown';
    return `rate_limit:login:${email || ip}`;
  }
});

export const createApiRateLimiter = (redis: Redis) => rateLimitMiddleware({
  redis,
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: 'API rate limit exceeded.',
});

export const createVideoStreamRateLimiter = (redis: Redis) => rateLimitMiddleware({
  redis,
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // 100 stream requests per hour
  message: 'Video streaming rate limit exceeded.',
});