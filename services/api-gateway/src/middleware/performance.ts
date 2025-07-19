import { Context, Next } from 'hono'
import { compress } from 'hono/compress'
import { etag } from 'hono/etag'
import { logger } from '@sparc/shared/utils/logger'
import crypto from 'crypto'

/**
 * Request deduplication cache
 */
class RequestDeduplicator {
  private pendingRequests = new Map<string, Promise<any>>()
  private requestCounts = new Map<string, number>()
  
  async deduplicate<T>(
    key: string,
    handler: () => Promise<T>
  ): Promise<T> {
    // Check if there's already a pending request
    if (this.pendingRequests.has(key)) {
      this.requestCounts.set(key, (this.requestCounts.get(key) || 0) + 1)
      logger.debug(`Request deduplicated: ${key} (${this.requestCounts.get(key)} duplicates)`)
      return this.pendingRequests.get(key) as Promise<T>
    }
    
    // Create new pending request
    const promise = handler().finally(() => {
      this.pendingRequests.delete(key)
      const count = this.requestCounts.get(key) || 0
      if (count > 0) {
        logger.info(`Request completed with ${count} deduplicated requests: ${key}`)
        this.requestCounts.delete(key)
      }
    })
    
    this.pendingRequests.set(key, promise)
    return promise
  }
  
  getStats() {
    return {
      pendingRequests: this.pendingRequests.size,
      deduplicationCounts: Array.from(this.requestCounts.entries())
    }
  }
}

/**
 * Request batching for similar requests
 */
class RequestBatcher {
  private batches = new Map<string, {
    requests: Array<{
      id: string
      params: any
      resolve: (value: any) => void
      reject: (error: any) => void
    }>
    timer?: NodeJS.Timeout
  }>()
  
  private batchWindow = 50 // ms
  private maxBatchSize = 100
  
  async batch<T>(
    endpoint: string,
    params: any,
    handler: (batchedParams: any[]) => Promise<T[]>
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const requestId = crypto.randomUUID()
      
      // Get or create batch
      if (!this.batches.has(endpoint)) {
        this.batches.set(endpoint, { requests: [] })
      }
      
      const batch = this.batches.get(endpoint)!
      batch.requests.push({ id: requestId, params, resolve, reject })
      
      // Execute batch if it reaches max size
      if (batch.requests.length >= this.maxBatchSize) {
        this.executeBatch(endpoint, handler)
        return
      }
      
      // Set timer for batch window
      if (!batch.timer) {
        batch.timer = setTimeout(() => {
          this.executeBatch(endpoint, handler)
        }, this.batchWindow)
      }
    })
  }
  
  private async executeBatch<T>(
    endpoint: string,
    handler: (batchedParams: any[]) => Promise<T[]>
  ): Promise<void> {
    const batch = this.batches.get(endpoint)
    if (!batch || batch.requests.length === 0) return
    
    // Clear timer
    if (batch.timer) {
      clearTimeout(batch.timer)
    }
    
    // Remove batch from map
    this.batches.delete(endpoint)
    
    try {
      // Execute batched request
      const batchedParams = batch.requests.map(r => r.params)
      const results = await handler(batchedParams)
      
      // Resolve individual requests
      batch.requests.forEach((request, index) => {
        request.resolve(results[index])
      })
      
      logger.info(`Batch executed for ${endpoint}: ${batch.requests.length} requests`)
    } catch (error) {
      // Reject all requests in batch
      batch.requests.forEach(request => {
        request.reject(error)
      })
      
      logger.error(`Batch failed for ${endpoint}:`, error)
    }
  }
  
  getStats() {
    return {
      activeBatches: this.batches.size,
      batchDetails: Array.from(this.batches.entries()).map(([endpoint, batch]) => ({
        endpoint,
        pendingRequests: batch.requests.length
      }))
    }
  }
}

// Global instances
const deduplicator = new RequestDeduplicator()
const batcher = new RequestBatcher()

/**
 * Performance optimization middleware
 */
export const performanceMiddleware = () => {
  return async (c: Context, next: Next) => {
    const start = Date.now()
    
    // Add performance headers
    c.header('X-Content-Type-Options', 'nosniff')
    c.header('X-Frame-Options', 'DENY')
    c.header('X-XSS-Protection', '1; mode=block')
    
    // Enable connection keep-alive
    c.header('Connection', 'keep-alive')
    c.header('Keep-Alive', 'timeout=120, max=1000')
    
    // Add request ID for tracing
    const requestId = c.req.header('X-Request-ID') || crypto.randomUUID()
    c.set('requestId', requestId)
    c.header('X-Request-ID', requestId)
    
    try {
      await next()
    } finally {
      // Add performance metrics
      const duration = Date.now() - start
      c.header('X-Response-Time', `${duration}ms`)
      
      // Log slow requests
      if (duration > 1000) {
        logger.warn(`Slow request detected: ${c.req.method} ${c.req.url} took ${duration}ms`)
      }
    }
  }
}

/**
 * Enhanced compression middleware with content negotiation
 */
export const compressionMiddleware = () => {
  return compress({
    encoding: 'gzip', // Also supports 'deflate' and 'br' (brotli)
    threshold: 1024, // Only compress responses larger than 1KB
  })
}

/**
 * ETag middleware for cache validation
 */
export const etagMiddleware = () => {
  return etag({
    weak: true, // Use weak ETags for better performance
    retainedProperties: ['headers', 'status'] // Properties to include in ETag generation
  })
}

/**
 * Request deduplication middleware
 */
export const deduplicationMiddleware = () => {
  return async (c: Context, next: Next) => {
    // Only deduplicate GET requests
    if (c.req.method !== 'GET') {
      return next()
    }
    
    // Generate deduplication key
    const url = c.req.url
    const tenantId = c.get('tenantId') || 'public'
    const key = `${tenantId}:${url}`
    
    // Check if this request can be deduplicated
    const acceptsDeduplication = c.req.header('X-Accept-Deduplication') !== 'false'
    
    if (acceptsDeduplication) {
      return deduplicator.deduplicate(key, () => next())
    }
    
    return next()
  }
}

/**
 * HTTP/2 Server Push hints
 */
export const serverPushMiddleware = () => {
  return async (c: Context, next: Next) => {
    await next()
    
    // Add Link headers for HTTP/2 push
    const contentType = c.res.headers.get('content-type') || ''
    
    if (contentType.includes('text/html')) {
      // Push critical CSS and JS
      c.header('Link', '</static/css/critical.css>; rel=preload; as=style, </static/js/app.js>; rel=preload; as=script')
    }
  }
}

/**
 * Request batching for specific endpoints
 */
export const batchingMiddleware = (config: {
  endpoints: string[]
  handler: (endpoint: string, params: any[]) => Promise<any[]>
}) => {
  return async (c: Context, next: Next) => {
    const path = c.req.path
    
    // Check if this endpoint supports batching
    const batchableEndpoint = config.endpoints.find(ep => path.startsWith(ep))
    
    if (!batchableEndpoint || c.req.method !== 'POST') {
      return next()
    }
    
    // Check if client wants batching
    if (c.req.header('X-Batch-Request') !== 'true') {
      return next()
    }
    
    try {
      const params = await c.req.json()
      
      const result = await batcher.batch(
        batchableEndpoint,
        params,
        (batchedParams) => config.handler(batchableEndpoint, batchedParams)
      )
      
      return c.json(result)
    } catch (error) {
      logger.error('Batching error:', error)
      return next()
    }
  }
}

/**
 * Response caching headers middleware
 */
export const cacheHeadersMiddleware = () => {
  return async (c: Context, next: Next) => {
    await next()
    
    // Skip if cache headers already set
    if (c.res.headers.get('Cache-Control')) {
      return
    }
    
    const method = c.req.method
    const status = c.res.status
    const contentType = c.res.headers.get('content-type') || ''
    
    // Only cache successful GET requests
    if (method !== 'GET' || status >= 300) {
      c.header('Cache-Control', 'no-cache, no-store, must-revalidate')
      return
    }
    
    // Set cache headers based on content type
    if (contentType.includes('image/') || contentType.includes('font/')) {
      // Long cache for static assets
      c.header('Cache-Control', 'public, max-age=31536000, immutable')
    } else if (contentType.includes('text/css') || contentType.includes('application/javascript')) {
      // Medium cache for CSS/JS
      c.header('Cache-Control', 'public, max-age=86400, stale-while-revalidate=604800')
    } else if (contentType.includes('application/json')) {
      // Short cache for API responses
      c.header('Cache-Control', 'private, max-age=60, stale-while-revalidate=300')
    } else {
      // Default cache
      c.header('Cache-Control', 'private, max-age=300')
    }
    
    // Add Vary header for proper caching
    c.header('Vary', 'Accept-Encoding, Accept, Authorization')
  }
}

/**
 * Get performance statistics
 */
export function getPerformanceStats() {
  return {
    deduplication: deduplicator.getStats(),
    batching: batcher.getStats(),
    timestamp: new Date().toISOString()
  }
}

/**
 * Performance monitoring endpoint
 */
export const performanceMonitoringRoutes = (app: any) => {
  app.get('/performance/stats', (c: Context) => {
    return c.json(getPerformanceStats())
  })
  
  app.get('/performance/health', async (c: Context) => {
    const stats = getPerformanceStats()
    
    // Check if system is healthy
    const isHealthy = 
      stats.deduplication.pendingRequests < 1000 &&
      stats.batching.activeBatches < 100
    
    return c.json({
      status: isHealthy ? 'healthy' : 'degraded',
      ...stats
    }, isHealthy ? 200 : 503)
  })
}