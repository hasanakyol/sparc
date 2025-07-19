import Redis, { Cluster, RedisOptions, ClusterNode, ClusterOptions } from 'ioredis'
import { logger } from './logger'

export interface RedisClusterConfig {
  nodes: ClusterNode[]
  options?: ClusterOptions
  enableReadReplicas?: boolean
  maxRetries?: number
  retryDelay?: number
}

export interface CacheOptions {
  ttl?: number // Time to live in seconds
  prefix?: string
  compress?: boolean
  tags?: string[]
}

/**
 * Enhanced Redis cluster client with connection pooling and performance optimizations
 */
export class RedisClusterClient {
  private cluster: Cluster
  private readonly config: RedisClusterConfig
  private readonly compressionThreshold = 1024 // Compress values larger than 1KB
  
  constructor(config: RedisClusterConfig) {
    this.config = config
    
    const clusterOptions: ClusterOptions = {
      ...config.options,
      
      // Connection pool settings
      enableOfflineQueue: true,
      enableReadyCheck: true,
      maxRetriesPerRequest: config.maxRetries || 3,
      
      // Performance optimizations
      enableAutoPipelining: true,
      autoPipeliningIgnoredCommands: ['info', 'ping', 'scan'],
      
      // Read from replicas for better performance
      scaleReads: config.enableReadReplicas ? 'slave' : 'master',
      
      // Connection settings
      redisOptions: {
        connectTimeout: 10000,
        commandTimeout: 5000,
        keepAlive: 30000,
        noDelay: true,
        
        // Connection pooling
        minConnectionPoolSize: 5,
        maxConnectionPoolSize: 50,
        connectionPoolTimeout: 5000,
        
        // Retry strategy
        retryStrategy: (times: number) => {
          if (times > (config.maxRetries || 3)) {
            return null
          }
          return Math.min(times * (config.retryDelay || 100), 3000)
        },
        
        // Error handling
        reconnectOnError: (err: Error) => {
          const targetError = 'READONLY'
          if (err.message.includes(targetError)) {
            return true
          }
          return false
        }
      },
      
      // Cluster-specific settings
      clusterRetryStrategy: (times: number) => {
        if (times > 3) {
          logger.error('Redis cluster connection failed after 3 retries')
          return null
        }
        return Math.min(times * 100, 3000)
      },
      
      // Node selection for read operations
      nodeSelector: (slot: number, slaves: Redis[]) => {
        // Round-robin between slaves for read operations
        return slaves[Math.floor(Math.random() * slaves.length)]
      }
    }
    
    this.cluster = new Cluster(config.nodes, clusterOptions)
    
    // Event handlers
    this.cluster.on('connect', () => {
      logger.info('Redis cluster connected')
    })
    
    this.cluster.on('error', (err) => {
      logger.error('Redis cluster error:', err)
    })
    
    this.cluster.on('node error', (err, node) => {
      logger.error(`Redis node error [${node}]:`, err)
    })
    
    this.cluster.on('ready', () => {
      logger.info('Redis cluster ready')
    })
  }
  
  /**
   * Get value with automatic decompression
   */
  async get<T = any>(key: string): Promise<T | null> {
    try {
      const value = await this.cluster.get(key)
      if (!value) return null
      
      // Check if value is compressed
      if (value.startsWith('gzip:')) {
        const compressed = Buffer.from(value.slice(5), 'base64')
        const decompressed = await this.decompress(compressed)
        return JSON.parse(decompressed)
      }
      
      return JSON.parse(value)
    } catch (error) {
      logger.error(`Error getting key ${key}:`, error)
      return null
    }
  }
  
  /**
   * Set value with automatic compression and TTL
   */
  async set<T = any>(key: string, value: T, options?: CacheOptions): Promise<boolean> {
    try {
      const serialized = JSON.stringify(value)
      let finalValue = serialized
      
      // Compress large values
      if (options?.compress !== false && serialized.length > this.compressionThreshold) {
        const compressed = await this.compress(serialized)
        finalValue = 'gzip:' + compressed.toString('base64')
      }
      
      // Add prefix if specified
      const finalKey = options?.prefix ? `${options.prefix}:${key}` : key
      
      // Set with TTL if specified
      if (options?.ttl) {
        await this.cluster.setex(finalKey, options.ttl, finalValue)
      } else {
        await this.cluster.set(finalKey, finalValue)
      }
      
      // Add to tags if specified
      if (options?.tags) {
        await this.addToTags(finalKey, options.tags)
      }
      
      return true
    } catch (error) {
      logger.error(`Error setting key ${key}:`, error)
      return false
    }
  }
  
  /**
   * Delete keys by pattern
   */
  async deletePattern(pattern: string): Promise<number> {
    const stream = this.cluster.scanStream({
      match: pattern,
      count: 100
    })
    
    const keys: string[] = []
    
    return new Promise((resolve, reject) => {
      stream.on('data', (resultKeys) => {
        keys.push(...resultKeys)
      })
      
      stream.on('end', async () => {
        if (keys.length === 0) {
          resolve(0)
          return
        }
        
        try {
          const result = await this.cluster.del(...keys)
          resolve(result)
        } catch (error) {
          reject(error)
        }
      })
      
      stream.on('error', (err) => {
        reject(err)
      })
    })
  }
  
  /**
   * Invalidate cache by tags
   */
  async invalidateByTags(tags: string[]): Promise<void> {
    const pipeline = this.cluster.pipeline()
    
    for (const tag of tags) {
      const keys = await this.cluster.smembers(`tag:${tag}`)
      if (keys.length > 0) {
        pipeline.del(...keys)
        pipeline.del(`tag:${tag}`)
      }
    }
    
    await pipeline.exec()
  }
  
  /**
   * Get multiple values in a single operation
   */
  async mget<T = any>(keys: string[]): Promise<(T | null)[]> {
    try {
      const values = await this.cluster.mget(...keys)
      return values.map(value => {
        if (!value) return null
        try {
          if (value.startsWith('gzip:')) {
            const compressed = Buffer.from(value.slice(5), 'base64')
            const decompressed = this.decompressSync(compressed)
            return JSON.parse(decompressed)
          }
          return JSON.parse(value)
        } catch {
          return null
        }
      })
    } catch (error) {
      logger.error('Error in mget:', error)
      return keys.map(() => null)
    }
  }
  
  /**
   * Set multiple values in a single operation
   */
  async mset<T = any>(items: Array<{ key: string; value: T; options?: CacheOptions }>): Promise<boolean> {
    try {
      const pipeline = this.cluster.pipeline()
      
      for (const item of items) {
        const serialized = JSON.stringify(item.value)
        let finalValue = serialized
        
        if (item.options?.compress !== false && serialized.length > this.compressionThreshold) {
          const compressed = await this.compress(serialized)
          finalValue = 'gzip:' + compressed.toString('base64')
        }
        
        const finalKey = item.options?.prefix ? `${item.options.prefix}:${item.key}` : item.key
        
        if (item.options?.ttl) {
          pipeline.setex(finalKey, item.options.ttl, finalValue)
        } else {
          pipeline.set(finalKey, finalValue)
        }
        
        if (item.options?.tags) {
          for (const tag of item.options.tags) {
            pipeline.sadd(`tag:${tag}`, finalKey)
          }
        }
      }
      
      await pipeline.exec()
      return true
    } catch (error) {
      logger.error('Error in mset:', error)
      return false
    }
  }
  
  /**
   * Get cluster info and statistics
   */
  async getStats(): Promise<{
    connected: boolean
    nodes: number
    memory: { used: number; peak: number }
    hits: number
    misses: number
    hitRate: number
  }> {
    try {
      const info = await this.cluster.info()
      const stats = this.parseRedisInfo(info)
      
      return {
        connected: this.cluster.status === 'ready',
        nodes: this.cluster.nodes('all').length,
        memory: {
          used: stats.used_memory || 0,
          peak: stats.used_memory_peak || 0
        },
        hits: stats.keyspace_hits || 0,
        misses: stats.keyspace_misses || 0,
        hitRate: stats.keyspace_hits / (stats.keyspace_hits + stats.keyspace_misses) || 0
      }
    } catch (error) {
      logger.error('Error getting cluster stats:', error)
      return {
        connected: false,
        nodes: 0,
        memory: { used: 0, peak: 0 },
        hits: 0,
        misses: 0,
        hitRate: 0
      }
    }
  }
  
  /**
   * Close cluster connections
   */
  async disconnect(): Promise<void> {
    await this.cluster.quit()
  }
  
  // Helper methods
  
  private async addToTags(key: string, tags: string[]): Promise<void> {
    const pipeline = this.cluster.pipeline()
    for (const tag of tags) {
      pipeline.sadd(`tag:${tag}`, key)
    }
    await pipeline.exec()
  }
  
  private async compress(data: string): Promise<Buffer> {
    const zlib = await import('zlib')
    return new Promise((resolve, reject) => {
      zlib.gzip(data, (err, result) => {
        if (err) reject(err)
        else resolve(result)
      })
    })
  }
  
  private async decompress(data: Buffer): Promise<string> {
    const zlib = await import('zlib')
    return new Promise((resolve, reject) => {
      zlib.gunzip(data, (err, result) => {
        if (err) reject(err)
        else resolve(result.toString())
      })
    })
  }
  
  private decompressSync(data: Buffer): string {
    const zlib = require('zlib')
    return zlib.gunzipSync(data).toString()
  }
  
  private parseRedisInfo(info: string): Record<string, number> {
    const stats: Record<string, number> = {}
    const lines = info.split('\r\n')
    
    for (const line of lines) {
      if (line.includes(':')) {
        const [key, value] = line.split(':')
        const numValue = parseInt(value, 10)
        if (!isNaN(numValue)) {
          stats[key] = numValue
        }
      }
    }
    
    return stats
  }
}

// Factory function for creating Redis cluster client
export function createRedisCluster(config: RedisClusterConfig): RedisClusterClient {
  return new RedisClusterClient(config)
}

// Default cluster configuration
export const defaultClusterConfig: RedisClusterConfig = {
  nodes: [
    { host: process.env.REDIS_HOST_1 || 'localhost', port: 7000 },
    { host: process.env.REDIS_HOST_2 || 'localhost', port: 7001 },
    { host: process.env.REDIS_HOST_3 || 'localhost', port: 7002 }
  ],
  enableReadReplicas: true,
  maxRetries: 3,
  retryDelay: 100
}