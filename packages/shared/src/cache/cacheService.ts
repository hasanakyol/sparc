import Redis, { RedisOptions } from 'ioredis';
import { CircuitBreaker } from '../utils/circuit-breaker';
import { logger } from '../logger';
import { createHash } from 'crypto';
import * as zlib from 'zlib';
import { promisify } from 'util';
import { EventEmitter } from 'events';

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

export interface CacheOptions<T = any> {
  ttl?: number; // Time to live in seconds
  prefix?: string; // Key prefix for namespacing
  compress?: boolean; // Enable compression for large values
  tags?: string[]; // Tags for invalidation
  version?: number; // Cache version for automatic invalidation
  transformer?: {
    serialize?: (value: T) => string | Buffer;
    deserialize?: (value: string | Buffer) => T;
  };
}

export interface CacheStats {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  errors: number;
  hitRate: number;
  avgGetTime: number;
  avgSetTime: number;
  compressionRatio: number;
  memoryUsage: number;
}

export interface CacheConfig {
  redis?: RedisOptions;
  defaultTTL?: number;
  compressionThreshold?: number;
  maxMemory?: number;
  evictionPolicy?: 'lru' | 'lfu' | 'ttl' | 'random';
  enableMetrics?: boolean;
  enableCircuitBreaker?: boolean;
  circuitBreakerOptions?: {
    failureThreshold?: number;
    resetTimeout?: number;
  };
}

export interface BatchOperation<T = any> {
  key: string;
  value?: T;
  options?: CacheOptions<T>;
}

export class CacheService extends EventEmitter {
  private redis: Redis;
  private circuitBreaker?: CircuitBreaker;
  private stats: CacheStats;
  private defaultTTL: number;
  private compressionThreshold: number;
  private prefix: string;
  private enableMetrics: boolean;
  private getTimings: number[] = [];
  private setTimings: number[] = [];
  private compressionStats = { original: 0, compressed: 0 };

  constructor(private config: CacheConfig = {}) {
    super();
    
    // Initialize Redis client
    this.redis = new Redis(config.redis || {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB || '0'),
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      enableOfflineQueue: true,
      maxRetriesPerRequest: 3,
    });

    this.defaultTTL = config.defaultTTL || 3600; // 1 hour default
    this.compressionThreshold = config.compressionThreshold || 1024; // 1KB
    this.prefix = 'cache';
    this.enableMetrics = config.enableMetrics ?? true;

    // Initialize stats
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      errors: 0,
      hitRate: 0,
      avgGetTime: 0,
      avgSetTime: 0,
      compressionRatio: 0,
      memoryUsage: 0,
    };

    // Setup circuit breaker if enabled
    if (config.enableCircuitBreaker) {
      this.circuitBreaker = new CircuitBreaker({
        name: 'cache-service',
        failureThreshold: config.circuitBreakerOptions?.failureThreshold || 5,
        resetTimeout: config.circuitBreakerOptions?.resetTimeout || 60000,
        errorFilter: (error) => {
          // Don't trip circuit for cache misses
          return !(error.message && error.message.includes('Cache miss'));
        },
      });
    }

    // Redis event handlers
    this.redis.on('error', (err) => {
      logger.error('Redis error:', err);
      this.emit('error', err);
    });

    this.redis.on('connect', () => {
      logger.info('Redis connected');
      this.emit('connect');
    });

    this.redis.on('ready', () => {
      logger.info('Redis ready');
      this.emit('ready');
    });

    // Start metrics collection
    if (this.enableMetrics) {
      this.startMetricsCollection();
    }
  }

  /**
   * Get a value from cache with generic type support
   */
  async get<T = any>(key: string, options: CacheOptions<T> = {}): Promise<T | null> {
    const startTime = Date.now();
    const cacheKey = this.generateKey(key, options.prefix);

    try {
      const operation = async () => {
        const value = await this.redis.get(cacheKey);
        
        if (value === null) {
          this.stats.misses++;
          this.updateHitRate();
          return null;
        }

        this.stats.hits++;
        this.updateHitRate();

        // Check version if specified
        if (options.version) {
          const versionKey = `${cacheKey}:version`;
          const storedVersion = await this.redis.get(versionKey);
          if (storedVersion && parseInt(storedVersion) !== options.version) {
            await this.delete(key, options);
            return null;
          }
        }

        return this.deserializeValue<T>(value, options);
      };

      const result = this.circuitBreaker 
        ? await this.circuitBreaker.execute(operation)
        : await operation();

      if (this.enableMetrics) {
        this.recordGetTiming(Date.now() - startTime);
      }

      return result;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache get error', { key: cacheKey, error });
      this.emit('error', { operation: 'get', key, error });
      return null;
    }
  }

  /**
   * Set a value in cache with automatic serialization
   */
  async set<T = any>(key: string, value: T, options: CacheOptions<T> = {}): Promise<boolean> {
    const startTime = Date.now();
    const cacheKey = this.generateKey(key, options.prefix);
    const ttl = options.ttl || this.defaultTTL;

    try {
      const operation = async () => {
        const serialized = await this.serializeValue(value, options);
        
        // Set with TTL
        await this.redis.setex(cacheKey, ttl, serialized);
        
        // Store version if specified
        if (options.version) {
          const versionKey = `${cacheKey}:version`;
          await this.redis.setex(versionKey, ttl, options.version.toString());
        }

        // Add to tags if specified
        if (options.tags && options.tags.length > 0) {
          await this.addToTags(cacheKey, options.tags, ttl);
        }

        this.stats.sets++;
        return true;
      };

      const result = this.circuitBreaker
        ? await this.circuitBreaker.execute(operation)
        : await operation();

      if (this.enableMetrics) {
        this.recordSetTiming(Date.now() - startTime);
      }

      this.emit('set', { key, ttl });
      return result;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache set error', { key: cacheKey, error });
      this.emit('error', { operation: 'set', key, error });
      return false;
    }
  }

  /**
   * Delete a value from cache
   */
  async delete(key: string, options: { prefix?: string } = {}): Promise<boolean> {
    const cacheKey = this.generateKey(key, options.prefix);

    try {
      const operation = async () => {
        const result = await this.redis.del(cacheKey);
        
        // Also delete version key if it exists
        await this.redis.del(`${cacheKey}:version`);
        
        this.stats.deletes++;
        return result > 0;
      };

      const result = this.circuitBreaker
        ? await this.circuitBreaker.execute(operation)
        : await operation();

      this.emit('delete', { key });
      return result;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache delete error', { key: cacheKey, error });
      this.emit('error', { operation: 'delete', key, error });
      return false;
    }
  }

  /**
   * Delete all keys matching a pattern
   */
  async invalidatePattern(pattern: string, namespace?: string): Promise<number> {
    const keyPattern = this.generateKey(pattern, namespace);
    
    try {
      const operation = async () => {
        const keys = await this.scanKeys(keyPattern);
        if (keys.length === 0) return 0;

        const pipeline = this.redis.pipeline();
        keys.forEach(key => {
          pipeline.del(key);
          pipeline.del(`${key}:version`);
        });
        
        await pipeline.exec();
        this.stats.deletes += keys.length;
        return keys.length;
      };

      const result = this.circuitBreaker
        ? await this.circuitBreaker.execute(operation)
        : await operation();

      this.emit('invalidatePattern', { pattern, count: result });
      return result;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache invalidate pattern error', { pattern: keyPattern, error });
      throw error;
    }
  }

  /**
   * Invalidate cache entries by tags
   */
  async invalidateByTags(tags: string[]): Promise<number> {
    try {
      const operation = async () => {
        const pipeline = this.redis.pipeline();
        const allKeys = new Set<string>();

        // Get all keys for each tag
        for (const tag of tags) {
          const tagKey = `${this.prefix}:tags:${tag}`;
          const keys = await this.redis.smembers(tagKey);
          keys.forEach(key => allKeys.add(key));
          pipeline.del(tagKey);
        }

        // Delete all found keys
        const keysArray = Array.from(allKeys);
        if (keysArray.length > 0) {
          keysArray.forEach(key => {
            pipeline.del(key);
            pipeline.del(`${key}:version`);
          });
        }

        await pipeline.exec();
        this.stats.deletes += keysArray.length;
        return keysArray.length;
      };

      const result = this.circuitBreaker
        ? await this.circuitBreaker.execute(operation)
        : await operation();

      this.emit('invalidateTags', { tags, count: result });
      return result;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache invalidate tags error', { tags, error });
      throw error;
    }
  }

  /**
   * Get or set a value using a factory function (cache-aside pattern)
   */
  async getOrSet<T = any>(
    key: string,
    factory: () => Promise<T> | T,
    options: CacheOptions<T> = {}
  ): Promise<T> {
    // Try to get from cache first
    const cached = await this.get<T>(key, options);
    if (cached !== null) {
      return cached;
    }

    // Generate value
    const value = await factory();
    
    // Cache it
    await this.set(key, value, options);
    
    return value;
  }

  /**
   * Batch get operation
   */
  async mget<T = any>(keys: string[], options: CacheOptions<T> = {}): Promise<(T | null)[]> {
    if (keys.length === 0) return [];

    const cacheKeys = keys.map(key => this.generateKey(key, options.prefix));
    
    try {
      const operation = async () => {
        const values = await this.redis.mget(...cacheKeys);
        
        const results = await Promise.all(
          values.map(async (value, index) => {
            if (value === null) {
              this.stats.misses++;
              return null;
            }

            this.stats.hits++;

            // Check version if specified
            if (options.version) {
              const versionKey = `${cacheKeys[index]}:version`;
              const storedVersion = await this.redis.get(versionKey);
              if (storedVersion && parseInt(storedVersion) !== options.version) {
                await this.delete(keys[index], options);
                return null;
              }
            }

            return this.deserializeValue<T>(value, options);
          })
        );

        this.updateHitRate();
        return results;
      };

      return this.circuitBreaker
        ? await this.circuitBreaker.execute(operation)
        : await operation();
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache mget error', { keys: cacheKeys, error });
      return keys.map(() => null);
    }
  }

  /**
   * Batch set operation
   */
  async mset<T = any>(operations: BatchOperation<T>[]): Promise<boolean> {
    if (operations.length === 0) return true;

    try {
      const operation = async () => {
        const pipeline = this.redis.pipeline();

        for (const op of operations) {
          const cacheKey = this.generateKey(op.key, op.options?.prefix);
          const ttl = op.options?.ttl || this.defaultTTL;
          
          if (op.value !== undefined) {
            const serialized = await this.serializeValue(op.value, op.options || {});
            pipeline.setex(cacheKey, ttl, serialized);

            // Store version if specified
            if (op.options?.version) {
              pipeline.setex(`${cacheKey}:version`, ttl, op.options.version.toString());
            }

            // Add to tags
            if (op.options?.tags && op.options.tags.length > 0) {
              for (const tag of op.options.tags) {
                const tagKey = `${this.prefix}:tags:${tag}`;
                pipeline.sadd(tagKey, cacheKey);
                pipeline.expire(tagKey, ttl);
              }
            }
          }
        }

        await pipeline.exec();
        this.stats.sets += operations.filter(op => op.value !== undefined).length;
        return true;
      };

      return this.circuitBreaker
        ? await this.circuitBreaker.execute(operation)
        : await operation();
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache mset error', { error });
      return false;
    }
  }

  /**
   * Clear all cache entries with the configured prefix
   */
  async clear(namespace?: string): Promise<number> {
    const pattern = this.generateKey('*', namespace);
    
    try {
      const operation = async () => {
        const keys = await this.scanKeys(pattern);
        if (keys.length === 0) return 0;

        const pipeline = this.redis.pipeline();
        keys.forEach(key => {
          pipeline.del(key);
          pipeline.del(`${key}:version`);
        });
        
        await pipeline.exec();
        this.stats.deletes += keys.length;
        return keys.length;
      };

      const result = this.circuitBreaker
        ? await this.circuitBreaker.execute(operation)
        : await operation();

      this.emit('clear', { namespace, count: result });
      return result;
    } catch (error) {
      this.stats.errors++;
      logger.error('Cache clear error', { pattern, error });
      throw error;
    }
  }

  /**
   * Warm the cache with predefined data
   */
  async warm<T = any>(
    data: Array<{ key: string; value: T; options?: CacheOptions<T> }>
  ): Promise<number> {
    const operations: BatchOperation<T>[] = data.map(item => ({
      key: item.key,
      value: item.value,
      options: item.options,
    }));

    const success = await this.mset(operations);
    return success ? data.length : 0;
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    return {
      ...this.stats,
      avgGetTime: this.calculateAverage(this.getTimings),
      avgSetTime: this.calculateAverage(this.setTimings),
      compressionRatio: this.calculateCompressionRatio(),
    };
  }

  /**
   * Reset cache statistics
   */
  resetStats(): void {
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      errors: 0,
      hitRate: 0,
      avgGetTime: 0,
      avgSetTime: 0,
      compressionRatio: 0,
      memoryUsage: 0,
    };
    this.getTimings = [];
    this.setTimings = [];
    this.compressionStats = { original: 0, compressed: 0 };
  }

  /**
   * Get memory usage information
   */
  async getMemoryInfo(): Promise<{
    used: number;
    peak: number;
    overhead: number;
    dataset: number;
  }> {
    try {
      const info = await this.redis.info('memory');
      const memoryData = this.parseRedisInfo(info);
      
      return {
        used: parseInt(memoryData['used_memory'] || '0'),
        peak: parseInt(memoryData['used_memory_peak'] || '0'),
        overhead: parseInt(memoryData['used_memory_overhead'] || '0'),
        dataset: parseInt(memoryData['used_memory_dataset'] || '0'),
      };
    } catch (error) {
      logger.error('Failed to get memory info', { error });
      return { used: 0, peak: 0, overhead: 0, dataset: 0 };
    }
  }

  /**
   * Disconnect from Redis
   */
  async disconnect(): Promise<void> {
    await this.redis.quit();
    this.emit('disconnect');
  }

  // Helper methods

  private generateKey(key: string, namespace?: string): string {
    const parts = [this.prefix];
    if (namespace) parts.push(namespace);
    parts.push(key);
    return parts.join(':');
  }

  private async serializeValue<T>(value: T, options: CacheOptions<T>): Promise<string> {
    let serialized: string | Buffer;

    if (options.transformer?.serialize) {
      serialized = options.transformer.serialize(value);
    } else {
      serialized = JSON.stringify(value);
    }

    // Convert Buffer to string for compression check
    const stringValue = Buffer.isBuffer(serialized) ? serialized.toString() : serialized;

    // Compress if needed
    if (options.compress !== false && stringValue.length > this.compressionThreshold) {
      const compressed = await gzip(stringValue);
      
      if (this.enableMetrics) {
        this.compressionStats.original += stringValue.length;
        this.compressionStats.compressed += compressed.length;
      }

      return `gzip:${compressed.toString('base64')}`;
    }

    return stringValue;
  }

  private async deserializeValue<T>(value: string, options: CacheOptions<T>): Promise<T> {
    let decompressed = value;

    // Decompress if needed
    if (value.startsWith('gzip:')) {
      const compressed = Buffer.from(value.slice(5), 'base64');
      const buffer = await gunzip(compressed);
      decompressed = buffer.toString();
    }

    if (options.transformer?.deserialize) {
      return options.transformer.deserialize(decompressed);
    }

    return JSON.parse(decompressed);
  }

  private async addToTags(key: string, tags: string[], ttl: number): Promise<void> {
    const pipeline = this.redis.pipeline();
    
    for (const tag of tags) {
      const tagKey = `${this.prefix}:tags:${tag}`;
      pipeline.sadd(tagKey, key);
      pipeline.expire(tagKey, ttl);
    }
    
    await pipeline.exec();
  }

  private async scanKeys(pattern: string): Promise<string[]> {
    const keys: string[] = [];
    const stream = this.redis.scanStream({
      match: pattern,
      count: 100,
    });

    return new Promise((resolve, reject) => {
      stream.on('data', (resultKeys) => {
        keys.push(...resultKeys);
      });

      stream.on('end', () => {
        resolve(keys);
      });

      stream.on('error', (err) => {
        reject(err);
      });
    });
  }

  private updateHitRate(): void {
    const total = this.stats.hits + this.stats.misses;
    this.stats.hitRate = total > 0 ? this.stats.hits / total : 0;
  }

  private recordGetTiming(time: number): void {
    this.getTimings.push(time);
    if (this.getTimings.length > 1000) {
      this.getTimings.shift();
    }
  }

  private recordSetTiming(time: number): void {
    this.setTimings.push(time);
    if (this.setTimings.length > 1000) {
      this.setTimings.shift();
    }
  }

  private calculateAverage(timings: number[]): number {
    if (timings.length === 0) return 0;
    const sum = timings.reduce((a, b) => a + b, 0);
    return sum / timings.length;
  }

  private calculateCompressionRatio(): number {
    if (this.compressionStats.original === 0) return 0;
    return 1 - (this.compressionStats.compressed / this.compressionStats.original);
  }

  private parseRedisInfo(info: string): Record<string, string> {
    const result: Record<string, string> = {};
    const lines = info.split('\r\n');
    
    for (const line of lines) {
      if (line.includes(':')) {
        const [key, value] = line.split(':');
        result[key] = value;
      }
    }
    
    return result;
  }

  private startMetricsCollection(): void {
    // Collect memory usage every minute
    setInterval(async () => {
      const memInfo = await this.getMemoryInfo();
      this.stats.memoryUsage = memInfo.used;
      this.emit('metrics', this.getStats());
    }, 60000);
  }
}

// Factory function with default configuration
export function createCacheService(config?: CacheConfig): CacheService {
  return new CacheService(config);
}

// Cache decorators
export function Cacheable<T = any>(options: CacheOptions<T> & { key?: string | ((args: any[]) => string) } = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      // Get cache service from the instance
      const cache = (this as any).cache as CacheService;
      if (!cache || !(cache instanceof CacheService)) {
        return originalMethod.apply(this, args);
      }
      
      // Generate cache key
      let cacheKey: string;
      if (typeof options.key === 'function') {
        cacheKey = options.key(args);
      } else if (options.key) {
        cacheKey = options.key;
      } else {
        cacheKey = `${propertyKey}:${createHash('sha256').update(JSON.stringify(args)).digest('hex').substring(0, 16)}`;
      }
      
      // Try to get from cache
      const cached = await cache.get<T>(cacheKey, options);
      if (cached !== null) {
        return cached;
      }
      
      // Execute method and cache result
      const result = await originalMethod.apply(this, args);
      await cache.set(cacheKey, result, options);
      
      return result;
    };
    
    return descriptor;
  };
}

export function CacheInvalidate(options: { 
  pattern?: string | ((args: any[]) => string);
  tags?: string[] | ((args: any[]) => string[]);
  namespace?: string;
} = {}) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: any[]) {
      const result = await originalMethod.apply(this, args);
      
      // Get cache service from the instance
      const cache = (this as any).cache as CacheService;
      if (!cache || !(cache instanceof CacheService)) {
        return result;
      }
      
      // Invalidate by pattern
      if (options.pattern) {
        const pattern = typeof options.pattern === 'function' 
          ? options.pattern(args) 
          : options.pattern;
        await cache.invalidatePattern(pattern, options.namespace);
      }
      
      // Invalidate by tags
      if (options.tags) {
        const tags = typeof options.tags === 'function' 
          ? options.tags(args) 
          : options.tags;
        await cache.invalidateByTags(tags);
      }
      
      return result;
    };
    
    return descriptor;
  };
}