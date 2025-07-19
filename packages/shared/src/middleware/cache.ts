import { Context, Next } from 'hono';
import { CacheService, createCacheKey } from '../utils/cache';
import { logger } from '../logger';

export interface CacheMiddlewareOptions {
  ttl?: number;
  namespace?: string;
  keyGenerator?: (c: Context) => string;
  condition?: (c: Context) => boolean;
  excludePaths?: string[];
}

/**
 * Cache middleware for Hono routes
 */
export function cacheMiddleware(cache: CacheService, options: CacheMiddlewareOptions = {}) {
  const {
    ttl = 300, // 5 minutes default
    namespace = 'http',
    keyGenerator,
    condition,
    excludePaths = []
  } = options;

  return async (c: Context, next: Next) => {
    // Skip caching for non-GET requests
    if (c.req.method !== 'GET') {
      return next();
    }

    // Skip if path is excluded
    const path = new URL(c.req.url).pathname;
    if (excludePaths.some(excluded => path.startsWith(excluded))) {
      return next();
    }

    // Skip if condition is not met
    if (condition && !condition(c)) {
      return next();
    }

    // Generate cache key
    const cacheKey = keyGenerator 
      ? keyGenerator(c)
      : generateDefaultCacheKey(c);

    try {
      // Try to get from cache
      const cached = await cache.get<{
        body: any;
        headers: Record<string, string>;
        status: number;
      }>(cacheKey, namespace);

      if (cached) {
        // Return cached response
        Object.entries(cached.headers).forEach(([key, value]) => {
          c.header(key, value);
        });
        c.header('X-Cache', 'HIT');
        return c.json(cached.body, cached.status);
      }
    } catch (error) {
      logger.error('Cache middleware get error', { error, cacheKey });
      // Continue without cache on error
    }

    // Mark as cache miss
    c.header('X-Cache', 'MISS');

    // Store original json method
    const originalJson = c.json.bind(c);
    let responseData: any;
    let responseStatus: number = 200;

    // Override json method to capture response
    c.json = function(object: any, status?: number) {
      responseData = object;
      responseStatus = status || 200;
      return originalJson(object, status);
    };

    // Execute route handler
    await next();

    // Cache successful responses only
    if (responseStatus >= 200 && responseStatus < 300 && responseData) {
      try {
        const headers: Record<string, string> = {};
        c.res.headers.forEach((value, key) => {
          // Skip caching certain headers
          if (!['x-cache', 'date', 'age'].includes(key.toLowerCase())) {
            headers[key] = value;
          }
        });

        await cache.set(
          cacheKey,
          {
            body: responseData,
            headers,
            status: responseStatus
          },
          ttl,
          namespace
        );
      } catch (error) {
        logger.error('Cache middleware set error', { error, cacheKey });
        // Don't fail the request on cache errors
      }
    }
  };
}

/**
 * Generate default cache key from request
 */
function generateDefaultCacheKey(c: Context): string {
  const url = new URL(c.req.url);
  const params: Record<string, any> = {
    path: url.pathname,
    query: Object.fromEntries(url.searchParams),
    tenantId: c.get('tenantId'),
    userId: c.get('userId')
  };

  return createCacheKey(params);
}

/**
 * Cache invalidation middleware
 */
export function cacheInvalidationMiddleware(
  cache: CacheService,
  options: {
    triggers?: {
      method?: string[];
      paths?: string[];
    };
    invalidate?: {
      namespace?: string;
      patterns?: string[];
      tags?: string[];
    };
  } = {}
) {
  const {
    triggers = { method: ['POST', 'PUT', 'PATCH', 'DELETE'] },
    invalidate = {}
  } = options;

  return async (c: Context, next: Next) => {
    await next();

    // Check if invalidation should be triggered
    const shouldInvalidate = 
      (triggers.method?.includes(c.req.method) ?? false) ||
      (triggers.paths?.some(path => c.req.path.startsWith(path)) ?? false);

    if (!shouldInvalidate) {
      return;
    }

    // Check if response was successful
    if (c.res.status < 200 || c.res.status >= 300) {
      return;
    }

    try {
      // Invalidate by namespace
      if (invalidate.namespace) {
        await cache.clear(invalidate.namespace);
      }

      // Invalidate by patterns
      if (invalidate.patterns) {
        for (const pattern of invalidate.patterns) {
          await cache.deletePattern(pattern);
        }
      }

      // Invalidate by tags
      if (invalidate.tags) {
        await cache.invalidateByTags(invalidate.tags);
      }

      logger.info('Cache invalidated', {
        method: c.req.method,
        path: c.req.path,
        invalidate
      });
    } catch (error) {
      logger.error('Cache invalidation error', { error, invalidate });
      // Don't fail the request on cache errors
    }
  };
}

/**
 * Per-tenant cache namespace middleware
 */
export function tenantCacheMiddleware(cache: CacheService, baseTTL: number = 300) {
  return async (c: Context, next: Next) => {
    const tenantId = c.get('tenantId');
    if (!tenantId) {
      return next();
    }

    // Create tenant-specific cache service
    const tenantCache = new CacheService(cache['redis'], {
      prefix: `tenant:${tenantId}`,
      ttl: baseTTL
    });

    // Make it available in context
    c.set('cache', tenantCache);

    await next();
  };
}