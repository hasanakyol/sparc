import Redis from 'ioredis';
import { createHash } from 'crypto';
import { logger } from '../logger';

export interface CacheOptions {
  ttl?: number; // Time to live in seconds
  prefix?: string; // Key prefix for namespacing
  compress?: boolean; // Enable compression for large values
}

export interface CacheStats {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  errors: number;
}

export class CacheService {
  private redis: Redis;
  private defaultTTL: number;
  private prefix: string;
  private stats: CacheStats;

  constructor(redis: Redis, options: CacheOptions = {}) {
    this.redis = redis;
    this.defaultTTL = options.ttl || 3600; // 1 hour default
    this.prefix = options.prefix || 'cache';
    this.stats = { hits: 0, misses: 0, sets: 0, deletes: 0, errors: 0 };
  }

  /**
   * Generate a cache key with prefix and optional namespace
   */
  private generateKey(key: string, namespace?: string): string {
    const parts = [this.prefix];
    if (namespace) parts.push(namespace);
    parts.push(key);
    return parts.join(':');
  }

  /**
   * Get a value from cache
   */
  async get<T>(key: string, namespace?: string): Promise<T | null> {
    const cacheKey = this.generateKey(key, namespace);
    
    try {
      const value = await this.redis.get(cacheKey);
      
      if (value === null) {
        this.stats.misses++;
        return null;
      }
      
      this.stats.hits++;
      return JSON.parse(value) as T;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache get error', { key: cacheKey, error });
      return null;
    }
  }

  /**
   * Set a value in cache
   */
  async set<T>(key: string, value: T, ttl?: number, namespace?: string): Promise<void> {
    const cacheKey = this.generateKey(key, namespace);
    const ttlSeconds = ttl || this.defaultTTL;
    
    try {
      const serialized = JSON.stringify(value);
      await this.redis.setex(cacheKey, ttlSeconds, serialized);
      this.stats.sets++;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache set error', { key: cacheKey, error });
      throw error;
    }
  }

  /**
   * Delete a value from cache
   */
  async delete(key: string, namespace?: string): Promise<void> {
    const cacheKey = this.generateKey(key, namespace);
    
    try {
      await this.redis.del(cacheKey);
      this.stats.deletes++;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache delete error', { key: cacheKey, error });
      throw error;
    }
  }

  /**
   * Delete all keys matching a pattern
   */
  async deletePattern(pattern: string, namespace?: string): Promise<void> {
    const keyPattern = this.generateKey(pattern, namespace);
    
    try {
      const keys = await this.redis.keys(keyPattern);
      if (keys.length > 0) {
        await this.redis.del(...keys);
        this.stats.deletes += keys.length;
      }
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache delete pattern error', { pattern: keyPattern, error });
      throw error;
    }
  }

  /**
   * Clear all cache entries with the configured prefix
   */
  async clear(namespace?: string): Promise<void> {
    const pattern = this.generateKey('*', namespace);
    
    try {
      const keys = await this.redis.keys(pattern);
      if (keys.length > 0) {
        await this.redis.del(...keys);
        this.stats.deletes += keys.length;
      }
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache clear error', { pattern, error });
      throw error;
    }
  }

  /**
   * Get or set a value using a factory function
   */
  async getOrSet<T>(
    key: string,
    factory: () => Promise<T>,
    ttl?: number,
    namespace?: string
  ): Promise<T> {
    // Try to get from cache first
    const cached = await this.get<T>(key, namespace);
    if (cached !== null) {
      return cached;
    }

    // Generate value and cache it
    const value = await factory();
    await this.set(key, value, ttl, namespace);
    return value;
  }

  /**
   * Invalidate cache entries by tags
   */
  async invalidateByTags(tags: string[]): Promise<void> {
    for (const tag of tags) {
      await this.deletePattern(`*:tag:${tag}`, 'tags');
    }
  }

  /**
   * Tag a cache entry for later invalidation
   */
  async tag(key: string, tags: string[], namespace?: string): Promise<void> {
    const cacheKey = this.generateKey(key, namespace);
    
    for (const tag of tags) {
      const tagKey = this.generateKey(`${cacheKey}:tag:${tag}`, 'tags');
      await this.redis.set(tagKey, '1', 'EX', this.defaultTTL);
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    return { ...this.stats };
  }

  /**
   * Reset cache statistics
   */
  resetStats(): void {
    this.stats = { hits: 0, misses: 0, sets: 0, deletes: 0, errors: 0 };
  }
}

/**
 * Create a cache key from request parameters
 */
export function createCacheKey(params: Record<string, any>): string {
  const sorted = Object.keys(params)
    .sort()
    .reduce((acc, key) => {
      if (params[key] !== undefined && params[key] !== null) {
        acc[key] = params[key];
      }
      return acc;
    }, {} as Record<string, any>);
  
  const hash = createHash('sha256')
    .update(JSON.stringify(sorted))
    .digest('hex');
  
  return hash.substring(0, 16); // Use first 16 chars for shorter keys
}

/**
 * Cache decorator for class methods
 */
export function Cacheable(options: { ttl?: number; namespace?: string } = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      // Get cache service from the instance
      const cache = (this as any).cache as CacheService;
      if (!cache) {
        return originalMethod.apply(this, args);
      }
      
      // Generate cache key from method name and arguments
      const key = `${propertyKey}:${createCacheKey(args)}`;
      
      // Try to get from cache
      const cached = await cache.get(key, options.namespace);
      if (cached !== null) {
        return cached;
      }
      
      // Execute method and cache result
      const result = await originalMethod.apply(this, args);
      await cache.set(key, result, options.ttl, options.namespace);
      
      return result;
    };
    
    return descriptor;
  };
}

/**
 * Invalidate cache decorator
 */
export function InvalidateCache(options: { namespace?: string; tags?: string[] } = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      const result = await originalMethod.apply(this, args);
      
      // Get cache service from the instance
      const cache = (this as any).cache as CacheService;
      if (!cache) {
        return result;
      }
      
      // Invalidate by tags if specified
      if (options.tags && options.tags.length > 0) {
        await cache.invalidateByTags(options.tags);
      }
      
      // Clear namespace if specified
      if (options.namespace) {
        await cache.clear(options.namespace);
      }
      
      return result;
    };
    
    return descriptor;
  };
}