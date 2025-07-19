import { Context, Next } from 'hono'
import { LRUCache } from 'lru-cache'
import { RedisClusterClient } from '../utils/redis-cluster'
import { logger } from '../utils/logger'
import crypto from 'crypto'

export interface CacheConfig {
  // L1 Cache (In-Memory)
  l1: {
    enabled: boolean
    maxSize: number // Max number of items
    maxAge: number // Max age in ms
    sizeCalculation?: (value: any) => number
  }
  
  // L2 Cache (Redis)
  l2: {
    enabled: boolean
    ttl: number // TTL in seconds
    prefix: string
    compress?: boolean
  }
  
  // L3 Cache (CDN)
  l3: {
    enabled: boolean
    ttl: number // TTL in seconds
    publicOnly: boolean // Only cache public endpoints
  }
  
  // Cache key generation
  keyGenerator?: (c: Context) => string
  
  // Cache conditions
  shouldCache?: (c: Context) => boolean
  shouldBypassCache?: (c: Context) => boolean
  
  // Response filters
  cacheableStatusCodes?: number[]
  excludeHeaders?: string[]
  
  // Stale-while-revalidate
  staleWhileRevalidate?: boolean
  staleIfError?: boolean
  maxStale?: number // Max stale time in seconds
}

interface CachedResponse {
  status: number
  headers: Record<string, string>
  body: any
  timestamp: number
  etag?: string
  maxAge?: number
  staleUntil?: number
}

/**
 * Advanced multi-tier caching middleware with performance optimizations
 */
export class AdvancedCacheMiddleware {
  private l1Cache?: LRUCache<string, CachedResponse>
  private l2Cache?: RedisClusterClient
  private config: CacheConfig
  private pendingRequests = new Map<string, Promise<CachedResponse | null>>()
  
  constructor(config: CacheConfig, redisClient?: RedisClusterClient) {
    this.config = config
    
    // Initialize L1 cache (in-memory)
    if (config.l1.enabled) {
      this.l1Cache = new LRUCache<string, CachedResponse>({
        max: config.l1.maxSize,
        ttl: config.l1.maxAge,
        sizeCalculation: config.l1.sizeCalculation,
        updateAgeOnGet: true,
        updateAgeOnHas: false,
        
        // Performance optimizations
        allowStale: config.staleWhileRevalidate || false,
        noDeleteOnStaleGet: true,
        
        // Disposal callback for cleanup
        dispose: (value, key) => {
          logger.debug(`L1 cache evicted: ${key}`)
        }
      })
    }
    
    // Initialize L2 cache (Redis)
    if (config.l2.enabled && redisClient) {
      this.l2Cache = redisClient
    }
  }
  
  /**
   * Main middleware function
   */
  middleware() {
    return async (c: Context, next: Next) => {
      // Check if caching should be bypassed
      if (this.config.shouldBypassCache?.(c)) {
        return next()
      }
      
      // Only cache GET and HEAD requests by default
      if (!['GET', 'HEAD'].includes(c.req.method)) {
        return next()
      }
      
      // Generate cache key
      const cacheKey = this.generateCacheKey(c)
      
      // Check for cached response
      const cachedResponse = await this.getCachedResponse(cacheKey, c)
      
      if (cachedResponse) {
        // Validate freshness
        if (this.isFresh(cachedResponse)) {
          this.sendCachedResponse(c, cachedResponse, 'HIT')
          return
        }
        
        // Handle stale-while-revalidate
        if (this.config.staleWhileRevalidate && this.isStale(cachedResponse)) {
          // Send stale response immediately
          this.sendCachedResponse(c, cachedResponse, 'STALE')
          
          // Revalidate in background
          this.revalidateInBackground(cacheKey, c, next)
          return
        }
      }
      
      // Handle request coalescing
      if (this.pendingRequests.has(cacheKey)) {
        const pendingResponse = await this.pendingRequests.get(cacheKey)
        if (pendingResponse) {
          this.sendCachedResponse(c, pendingResponse, 'COALESCED')
          return
        }
      }
      
      // Create pending request promise
      const responsePromise = this.handleRequest(c, next, cacheKey)
      this.pendingRequests.set(cacheKey, responsePromise)
      
      try {
        const response = await responsePromise
        if (response) {
          this.sendCachedResponse(c, response, 'MISS')
        }
      } finally {
        this.pendingRequests.delete(cacheKey)
      }
    }
  }
  
  /**
   * Handle the actual request and cache the response
   */
  private async handleRequest(c: Context, next: Next, cacheKey: string): Promise<CachedResponse | null> {
    const startTime = Date.now()
    
    // Execute the actual handler
    await next()
    
    // Check if response should be cached
    if (!this.shouldCacheResponse(c)) {
      return null
    }
    
    // Create cached response object
    const cachedResponse: CachedResponse = {
      status: c.res.status,
      headers: this.filterHeaders(c.res.headers),
      body: await this.getResponseBody(c),
      timestamp: Date.now(),
      etag: this.generateETag(c),
      maxAge: this.parseMaxAge(c.res.headers.get('cache-control'))
    }
    
    // Calculate stale time if configured
    if (this.config.maxStale) {
      cachedResponse.staleUntil = Date.now() + (this.config.maxStale * 1000)
    }
    
    // Store in caches
    await this.storeCachedResponse(cacheKey, cachedResponse)
    
    // Log cache storage
    logger.debug(`Cached response for ${cacheKey} in ${Date.now() - startTime}ms`)
    
    return cachedResponse
  }
  
  /**
   * Get cached response from all tiers
   */
  private async getCachedResponse(key: string, c: Context): Promise<CachedResponse | null> {
    // Try L1 cache first
    if (this.l1Cache) {
      const l1Response = this.l1Cache.get(key)
      if (l1Response) {
        logger.debug(`L1 cache hit: ${key}`)
        return l1Response
      }
    }
    
    // Try L2 cache
    if (this.l2Cache) {
      try {
        const l2Response = await this.l2Cache.get<CachedResponse>(
          `${this.config.l2.prefix}:${key}`
        )
        
        if (l2Response) {
          logger.debug(`L2 cache hit: ${key}`)
          
          // Populate L1 cache
          if (this.l1Cache) {
            this.l1Cache.set(key, l2Response)
          }
          
          return l2Response
        }
      } catch (error) {
        logger.error('L2 cache error:', error)
      }
    }
    
    return null
  }
  
  /**
   * Store cached response in all applicable tiers
   */
  private async storeCachedResponse(key: string, response: CachedResponse): Promise<void> {
    // Store in L1 cache
    if (this.l1Cache) {
      this.l1Cache.set(key, response)
    }
    
    // Store in L2 cache
    if (this.l2Cache) {
      try {
        await this.l2Cache.set(
          key,
          response,
          {
            ttl: this.config.l2.ttl,
            prefix: this.config.l2.prefix,
            compress: this.config.l2.compress
          }
        )
      } catch (error) {
        logger.error('L2 cache storage error:', error)
      }
    }
  }
  
  /**
   * Send cached response to client
   */
  private sendCachedResponse(c: Context, response: CachedResponse, cacheStatus: string): void {
    // Set status
    c.status(response.status)
    
    // Set headers
    Object.entries(response.headers).forEach(([key, value]) => {
      c.header(key, value)
    })
    
    // Set cache headers
    c.header('X-Cache-Status', cacheStatus)
    c.header('X-Cache-Key', this.generateCacheKey(c))
    
    if (response.etag) {
      c.header('ETag', response.etag)
    }
    
    // Set Age header
    const age = Math.floor((Date.now() - response.timestamp) / 1000)
    c.header('Age', age.toString())
    
    // Handle conditional requests
    if (response.etag && c.req.header('If-None-Match') === response.etag) {
      c.status(304)
      return
    }
    
    // Send body
    if (typeof response.body === 'object') {
      c.json(response.body)
    } else {
      c.text(response.body)
    }
  }
  
  /**
   * Generate cache key for request
   */
  private generateCacheKey(c: Context): string {
    if (this.config.keyGenerator) {
      return this.config.keyGenerator(c)
    }
    
    // Default key generation
    const url = c.req.url
    const method = c.req.method
    const tenantId = c.get('tenantId') || 'public'
    const acceptHeader = c.req.header('Accept') || '*/*'
    
    // Create a stable key
    const keyParts = [
      method,
      url,
      tenantId,
      acceptHeader
    ]
    
    // Add query parameters
    const queryParams = new URL(url).searchParams
    queryParams.sort() // Ensure consistent ordering
    if (queryParams.toString()) {
      keyParts.push(queryParams.toString())
    }
    
    // Generate hash for compact key
    const hash = crypto
      .createHash('sha256')
      .update(keyParts.join(':'))
      .digest('hex')
      .substring(0, 16)
    
    return `cache:${method}:${hash}`
  }
  
  /**
   * Check if cached response is fresh
   */
  private isFresh(response: CachedResponse): boolean {
    if (!response.maxAge) return true
    
    const age = (Date.now() - response.timestamp) / 1000
    return age < response.maxAge
  }
  
  /**
   * Check if cached response is stale but usable
   */
  private isStale(response: CachedResponse): boolean {
    if (!response.staleUntil) return false
    return Date.now() < response.staleUntil
  }
  
  /**
   * Revalidate cache in background
   */
  private async revalidateInBackground(key: string, c: Context, next: Next): Promise<void> {
    // Clone context for background execution
    const backgroundContext = c
    
    setTimeout(async () => {
      try {
        await this.handleRequest(backgroundContext, next, key)
        logger.debug(`Background revalidation completed for ${key}`)
      } catch (error) {
        logger.error(`Background revalidation failed for ${key}:`, error)
      }
    }, 0)
  }
  
  /**
   * Check if response should be cached
   */
  private shouldCacheResponse(c: Context): boolean {
    // Check custom condition
    if (this.config.shouldCache && !this.config.shouldCache(c)) {
      return false
    }
    
    // Check status code
    const statusCode = c.res.status
    const cacheableStatusCodes = this.config.cacheableStatusCodes || [200, 201, 203, 204, 206, 300, 301, 304]
    
    if (!cacheableStatusCodes.includes(statusCode)) {
      return false
    }
    
    // Check Cache-Control header
    const cacheControl = c.res.headers.get('cache-control')
    if (cacheControl && (cacheControl.includes('no-cache') || cacheControl.includes('no-store'))) {
      return false
    }
    
    return true
  }
  
  /**
   * Filter headers for caching
   */
  private filterHeaders(headers: Headers): Record<string, string> {
    const filtered: Record<string, string> = {}
    const excludeHeaders = this.config.excludeHeaders || [
      'set-cookie',
      'x-request-id',
      'x-trace-id',
      'x-span-id'
    ]
    
    headers.forEach((value, key) => {
      if (!excludeHeaders.includes(key.toLowerCase())) {
        filtered[key] = value
      }
    })
    
    return filtered
  }
  
  /**
   * Get response body for caching
   */
  private async getResponseBody(c: Context): Promise<any> {
    const contentType = c.res.headers.get('content-type') || ''
    
    if (contentType.includes('application/json')) {
      try {
        const text = await c.res.text()
        return JSON.parse(text)
      } catch {
        return null
      }
    }
    
    return await c.res.text()
  }
  
  /**
   * Generate ETag for response
   */
  private generateETag(c: Context): string {
    const body = c.res.body
    if (!body) return ''
    
    const hash = crypto
      .createHash('md5')
      .update(JSON.stringify(body))
      .digest('hex')
    
    return `"${hash}"`
  }
  
  /**
   * Parse max-age from Cache-Control header
   */
  private parseMaxAge(cacheControl: string | null): number | undefined {
    if (!cacheControl) return undefined
    
    const match = cacheControl.match(/max-age=(\d+)/)
    if (match) {
      return parseInt(match[1], 10)
    }
    
    return undefined
  }
  
  /**
   * Clear all caches
   */
  async clearAll(): Promise<void> {
    if (this.l1Cache) {
      this.l1Cache.clear()
    }
    
    if (this.l2Cache) {
      await this.l2Cache.deletePattern(`${this.config.l2.prefix}:*`)
    }
  }
  
  /**
   * Get cache statistics
   */
  getStats(): {
    l1: { size: number; hits: number; misses: number }
    l2: { connected: boolean }
    pendingRequests: number
  } {
    return {
      l1: {
        size: this.l1Cache?.size || 0,
        hits: 0, // Would need to track this
        misses: 0 // Would need to track this
      },
      l2: {
        connected: !!this.l2Cache
      },
      pendingRequests: this.pendingRequests.size
    }
  }
}

// Factory function
export function createAdvancedCache(
  config: Partial<CacheConfig>,
  redisClient?: RedisClusterClient
): AdvancedCacheMiddleware {
  const defaultConfig: CacheConfig = {
    l1: {
      enabled: true,
      maxSize: 1000,
      maxAge: 60 * 1000 // 1 minute
    },
    l2: {
      enabled: true,
      ttl: 300, // 5 minutes
      prefix: 'api',
      compress: true
    },
    l3: {
      enabled: false,
      ttl: 3600, // 1 hour
      publicOnly: true
    },
    cacheableStatusCodes: [200, 201, 203, 204, 206, 300, 301, 304],
    staleWhileRevalidate: true,
    maxStale: 86400 // 24 hours
  }
  
  return new AdvancedCacheMiddleware(
    { ...defaultConfig, ...config },
    redisClient
  )
}