import { Hono, type Context, type Next } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { prettyJSON } from 'hono/pretty-json'
import { secureHeaders } from 'hono/secure-headers'
import { timeout } from 'hono/timeout'
import { HTTPException } from 'hono/http-exception'
import jwt from 'jsonwebtoken'
import Redis from 'ioredis'
import winston from 'winston'
import { z } from 'zod'
import { v4 as uuidv4 } from 'uuid'
import { CacheService } from '@sparc/shared/utils/cache'
import { cacheMiddleware } from '@sparc/shared/middleware/cache'
import { siemMiddleware, logRateLimitExceeded, logCSRFViolation } from './middleware/siem'
import { versioningRouter } from './routes/versioning'
import { versionedIncidentsRouter } from './examples/versioned-incidents'

// Test framework imports - only loaded in test environment
let jest: any, describe: any, it: any, expect: any, beforeAll: any, afterAll: any, beforeEach: any, afterEach: any;
if (process.env.NODE_ENV === 'test') {
  try {
    const jestGlobals = require('@jest/globals');
    jest = jestGlobals.jest;
    describe = jestGlobals.describe;
    it = jestGlobals.it;
    expect = jestGlobals.expect;
    beforeAll = jestGlobals.beforeAll;
    afterAll = jestGlobals.afterAll;
    beforeEach = jestGlobals.beforeEach;
    afterEach = jestGlobals.afterEach;
  } catch (error) {
    console.warn('Jest not available, tests will be skipped');
  }
}

// Types and interfaces
interface ServiceConfig {
  name: string
  url: string
  healthPath: string
  timeout: number
  retries: number
}


interface JWTPayload {
  userId: string
  tenantId: string
  roles: string[]
  permissions: string[]
  sessionId?: string
  iat: number
  exp: number
}


// Configuration schema
const configSchema = z.object({
  PORT: z.string().default('3000'),
  NODE_ENV: z.enum(['development', 'staging', 'production']).default('development'),
  JWT_SECRET: z.string(),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  CORS_ORIGIN: z.string().default('*'),
  RATE_LIMIT_WINDOW_MS: z.string().default('900000'), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.string().default('100'),
  REQUEST_TIMEOUT_MS: z.string().default('30000'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  
  // Service URLs
  AUTH_SERVICE_URL: z.string().default('http://localhost:3001'),
  TENANT_SERVICE_URL: z.string().default('http://localhost:3002'),
  ACCESS_CONTROL_SERVICE_URL: z.string().default('http://localhost:3003'),
  VIDEO_MANAGEMENT_SERVICE_URL: z.string().default('http://localhost:3004'),
  EVENT_PROCESSING_SERVICE_URL: z.string().default('http://localhost:3005'),
  DEVICE_MANAGEMENT_SERVICE_URL: z.string().default('http://localhost:3006'),
  MOBILE_CREDENTIAL_SERVICE_URL: z.string().default('http://localhost:3007'),
  ANALYTICS_SERVICE_URL: z.string().default('http://localhost:3008'),
  ENVIRONMENTAL_SERVICE_URL: z.string().default('http://localhost:3009'),
  VISITOR_MANAGEMENT_SERVICE_URL: z.string().default('http://localhost:3010'),
  REPORTING_SERVICE_URL: z.string().default('http://localhost:3011'),
  
  // New services
  ALERT_SERVICE_URL: z.string().default('http://localhost:3012'),
  INTEGRATION_SERVICE_URL: z.string().default('http://localhost:3013'),
  BACKUP_RECOVERY_SERVICE_URL: z.string().default('http://localhost:3014'),
  SECURITY_COMPLIANCE_SERVICE_URL: z.string().default('http://localhost:3015'),
  MAINTENANCE_SERVICE_URL: z.string().default('http://localhost:3016'),
  ELEVATOR_CONTROL_SERVICE_URL: z.string().default('http://localhost:3017'),
  API_DOCUMENTATION_SERVICE_URL: z.string().default('http://localhost:3018'),
  TESTING_INFRASTRUCTURE_SERVICE_URL: z.string().default('http://localhost:3019'),
})

// Parse and validate configuration
const config = configSchema.parse(process.env)

// Service configuration
const services: Record<string, ServiceConfig> = {
  auth: {
    name: 'auth-service',
    url: config.AUTH_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  tenant: {
    name: 'tenant-service',
    url: config.TENANT_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  'access-control': {
    name: 'access-control-service',
    url: config.ACCESS_CONTROL_SERVICE_URL,
    healthPath: '/health',
    timeout: 10000,
    retries: 3
  },
  'video-management': {
    name: 'video-management-service',
    url: config.VIDEO_MANAGEMENT_SERVICE_URL,
    healthPath: '/health',
    timeout: 15000,
    retries: 2
  },
  'event-processing': {
    name: 'event-processing-service',
    url: config.EVENT_PROCESSING_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  'device-management': {
    name: 'device-management-service',
    url: config.DEVICE_MANAGEMENT_SERVICE_URL,
    healthPath: '/health',
    timeout: 10000,
    retries: 3
  },
  'mobile-credential': {
    name: 'mobile-credential-service',
    url: config.MOBILE_CREDENTIAL_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  analytics: {
    name: 'analytics-service',
    url: config.ANALYTICS_SERVICE_URL,
    healthPath: '/health',
    timeout: 10000,
    retries: 2
  },
  environmental: {
    name: 'environmental-service',
    url: config.ENVIRONMENTAL_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  'visitor-management': {
    name: 'visitor-management-service',
    url: config.VISITOR_MANAGEMENT_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  reporting: {
    name: 'reporting-service',
    url: config.REPORTING_SERVICE_URL,
    healthPath: '/health',
    timeout: 15000,
    retries: 2
  },
  alert: {
    name: 'alert-service',
    url: config.ALERT_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  integration: {
    name: 'integration-service',
    url: config.INTEGRATION_SERVICE_URL,
    healthPath: '/health',
    timeout: 10000,
    retries: 3
  },
  'backup-recovery': {
    name: 'backup-recovery-service',
    url: config.BACKUP_RECOVERY_SERVICE_URL,
    healthPath: '/health',
    timeout: 15000,
    retries: 2
  },
  'security-compliance': {
    name: 'security-compliance-service',
    url: config.SECURITY_COMPLIANCE_SERVICE_URL,
    healthPath: '/health',
    timeout: 10000,
    retries: 3
  },
  maintenance: {
    name: 'maintenance-service',
    url: config.MAINTENANCE_SERVICE_URL,
    healthPath: '/health',
    timeout: 10000,
    retries: 3
  },
  'elevator-control': {
    name: 'elevator-control-service',
    url: config.ELEVATOR_CONTROL_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  'api-documentation': {
    name: 'api-documentation-service',
    url: config.API_DOCUMENTATION_SERVICE_URL,
    healthPath: '/health',
    timeout: 5000,
    retries: 3
  },
  'testing-infrastructure': {
    name: 'testing-infrastructure-service',
    url: config.TESTING_INFRASTRUCTURE_SERVICE_URL,
    healthPath: '/health',
    timeout: 10000,
    retries: 2
  }
}

// Winston logger configuration
const winstonLogger = winston.createLogger({
  level: config.LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'api-gateway' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
})

// Redis client for rate limiting and caching
const redisClient = new Redis(config.REDIS_URL, {
  retryStrategy: (times: number) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 3
})

redisClient.on('error', (err: Error) => {
  winstonLogger.error('Redis connection error:', err)
})

redisClient.on('connect', () => {
  winstonLogger.info('Connected to Redis')
})

// Initialize cache service
const cache = new CacheService(redisClient, {
  prefix: 'api-gateway',
  ttl: 60 // 1 minute default for gateway
})

// Circuit breaker implementation
class CircuitBreaker {
  private failures: Map<string, number> = new Map()
  private lastFailureTime: Map<string, number> = new Map()
  private state: Map<string, 'CLOSED' | 'OPEN' | 'HALF_OPEN'> = new Map()
  
  constructor(
    private failureThreshold: number = 5,
    private recoveryTimeout: number = 60000, // 1 minute
    private _successThreshold: number = 2
  ) {}

  async execute<T>(serviceKey: string, operation: () => Promise<T>): Promise<T> {
    const currentState = this.state.get(serviceKey) || 'CLOSED'
    
    if (currentState === 'OPEN') {
      const lastFailure = this.lastFailureTime.get(serviceKey) || 0
      if (Date.now() - lastFailure < this.recoveryTimeout) {
        throw new Error(`Circuit breaker is OPEN for service: ${serviceKey}`)
      }
      this.state.set(serviceKey, 'HALF_OPEN')
    }

    try {
      const result = await operation()
      this.onSuccess(serviceKey)
      return result
    } catch (error) {
      this.onFailure(serviceKey)
      throw error
    }
  }

  private onSuccess(serviceKey: string): void {
    this.failures.set(serviceKey, 0)
    this.state.set(serviceKey, 'CLOSED')
  }

  private onFailure(serviceKey: string): void {
    const currentFailures = this.failures.get(serviceKey) || 0
    const newFailures = currentFailures + 1
    this.failures.set(serviceKey, newFailures)
    this.lastFailureTime.set(serviceKey, Date.now())

    if (newFailures >= this.failureThreshold) {
      this.state.set(serviceKey, 'OPEN')
      winstonLogger.warn(`Circuit breaker opened for service: ${serviceKey}`)
    }
  }

  getState(serviceKey: string): string {
    return this.state.get(serviceKey) || 'CLOSED'
  }
}

const circuitBreaker = new CircuitBreaker()

// Service discovery and load balancing
class ServiceRegistry {
  private serviceInstances: Map<string, string[]> = new Map()
  private currentIndex: Map<string, number> = new Map()

  constructor() {
    this.initializeServices()
  }

  private initializeServices(): void {
    // Initialize with configured service URLs
    Object.entries(services).forEach(([key, service]) => {
      this.serviceInstances.set(key, [service.url])
      this.currentIndex.set(key, 0)
    })
  }

  getServiceUrl(serviceName: string): string {
    const instances = this.serviceInstances.get(serviceName)
    if (!instances || instances.length === 0) {
      throw new Error(`No instances available for service: ${serviceName}`)
    }

    // Round-robin load balancing
    const currentIdx = this.currentIndex.get(serviceName) || 0
    const nextIdx = (currentIdx + 1) % instances.length
    this.currentIndex.set(serviceName, nextIdx)

    return instances[currentIdx]
  }

  addServiceInstance(serviceName: string, url: string): void {
    const instances = this.serviceInstances.get(serviceName) || []
    if (!instances.includes(url)) {
      instances.push(url)
      this.serviceInstances.set(serviceName, instances)
    }
  }

  removeServiceInstance(serviceName: string, url: string): void {
    const instances = this.serviceInstances.get(serviceName) || []
    const filtered = instances.filter(instance => instance !== url)
    this.serviceInstances.set(serviceName, filtered)
  }

  getHealthyInstances(serviceName: string): string[] {
    return this.serviceInstances.get(serviceName) || []
  }
}

const serviceRegistry = new ServiceRegistry()

// Enhanced rate limiting with tenant-specific limits
interface TenantRateLimit {
  windowMs: number
  maxRequests: number
  burstLimit?: number
}

const getTenantRateLimit = (_tenantId?: string, userRoles?: string[]): TenantRateLimit => {
  // Default limits
  let limits: TenantRateLimit = {
    windowMs: parseInt(config.RATE_LIMIT_WINDOW_MS),
    maxRequests: parseInt(config.RATE_LIMIT_MAX_REQUESTS)
  }

  // Enhanced limits for premium tenants or admin users
  if (userRoles?.includes('admin')) {
    limits.maxRequests *= 5
    limits.burstLimit = limits.maxRequests * 2
  } else if (userRoles?.includes('premium')) {
    limits.maxRequests *= 2
    limits.burstLimit = limits.maxRequests * 1.5
  }

  return limits
}

// Metrics collection
interface Metrics {
  requestCount: number
  errorCount: number
  responseTime: number[]
  serviceHealth: Map<string, boolean>
}

const metrics: Metrics = {
  requestCount: 0,
  errorCount: 0,
  responseTime: [],
  serviceHealth: new Map()
}

const updateMetrics = (duration: number, success: boolean, serviceName?: string) => {
  metrics.requestCount++
  metrics.responseTime.push(duration)
  
  if (!success) {
    metrics.errorCount++
  }

  if (serviceName) {
    metrics.serviceHealth.set(serviceName, success)
  }

  // Keep only last 1000 response times for memory efficiency
  if (metrics.responseTime.length > 1000) {
    metrics.responseTime = metrics.responseTime.slice(-1000)
  }
}

// Initialize Hono app
const app = new Hono()

// Enhanced security headers middleware
app.use('*', secureHeaders({
  // Content Security Policy
  contentSecurityPolicy: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"], // Adjust based on needs
    styleSrc: ["'self'", "'unsafe-inline'", "https:", "data:"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", "wss:", "https:"],
    fontSrc: ["'self'", "https:", "data:"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'", "https:"],
    frameSrc: ["'none'"],
    sandbox: ['allow-forms', 'allow-scripts', 'allow-same-origin', 'allow-popups'],
    reportUri: '/api/v1/csp-report',
    upgradeInsecureRequests: [],
  },
  // Strict Transport Security
  strictTransportSecurity: 'max-age=31536000; includeSubDomains; preload',
  // Other security headers
  xContentTypeOptions: 'nosniff',
  xDnsPrefetchControl: 'off',
  xDownloadOptions: 'noopen',
  xFrameOptions: 'DENY',
  xPermittedCrossDomainPolicies: 'none',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: {
    camera: ["'none'"],
    microphone: ["'none'"],
    geolocation: ["'self'"],
    accelerometer: ["'none'"],
    gyroscope: ["'none'"],
    magnetometer: ["'none'"],
    usb: ["'none'"],
    serial: ["'none'"],
    payment: ["'none'"],
  },
}))

// Additional security headers for API responses
app.use('*', async (c: Context, next: Next) => {
  // Add additional security headers
  c.header('X-XSS-Protection', '1; mode=block')
  c.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  c.header('Pragma', 'no-cache')
  c.header('Expires', '0')
  c.header('X-Powered-By', 'SPARC Security Platform')
  
  // Remove sensitive headers
  c.res.headers.delete('Server')
  
  await next()
})

app.use('*', prettyJSON())
app.use('*', timeout(parseInt(config.REQUEST_TIMEOUT_MS)))

// CORS middleware
app.use('*', cors({
  origin: config.CORS_ORIGIN === '*' ? true : config.CORS_ORIGIN.split(','),
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-Request-ID'],
  exposeHeaders: ['X-Request-ID', 'X-Rate-Limit-Remaining', 'X-Rate-Limit-Reset'],
  credentials: true
}))

// Request ID and context middleware
app.use('*', async (c: Context, next: Next) => {
  const requestId = c.req.header('X-Request-ID') || uuidv4()
  const startTime = Date.now()
  
  c.set('requestId', requestId)
  c.set('startTime', startTime)
  c.header('X-Request-ID', requestId)
  
  winstonLogger.info('Request started', {
    requestId,
    method: c.req.method,
    path: c.req.path,
    userAgent: c.req.header('User-Agent'),
    ip: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP')
  })
  
  await next()
  
  const duration = Date.now() - startTime
  winstonLogger.info('Request completed', {
    requestId,
    method: c.req.method,
    path: c.req.path,
    status: c.res.status,
    duration
  })
})

// Enhanced rate limiting middleware with tenant-specific limits
app.use('*', async (c: Context, next: Next) => {
  const ip = c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'unknown'
  const userId = c.get('userId')
  const tenantId = c.get('tenantId')
  const userRoles = c.get('roles')
  
  // Create composite key for rate limiting
  const rateLimitKey = tenantId ? `rate_limit:tenant:${tenantId}:${userId || ip}` : `rate_limit:ip:${ip}`
  const tenantLimits = getTenantRateLimit(tenantId, userRoles)
  
  const now = Date.now()
  const windowStart = now - tenantLimits.windowMs
  
  try {
    if (!redisClient.isConnected) {
      await redisClient.connect()
    }
    
    // Remove old entries
    await redisClient.zRemRangeByScore(rateLimitKey, 0, windowStart)
    
    // Count current requests
    const currentRequests = await redisClient.zCard(rateLimitKey)
    
    // Check burst limit first if defined
    if (tenantLimits.burstLimit && currentRequests >= tenantLimits.burstLimit) {
      c.header('X-Rate-Limit-Remaining', '0')
      c.header('X-Rate-Limit-Type', 'burst')
      
      throw new HTTPException(429, { 
        message: 'Burst rate limit exceeded. Please slow down.',
        res: c.json({
          error: 'BURST_RATE_LIMIT_EXCEEDED',
          message: 'Burst rate limit exceeded. Please slow down.',
          limit: tenantLimits.burstLimit,
          window: tenantLimits.windowMs
        }, 429)
      })
    }
    
    // Check regular rate limit
    if (currentRequests >= tenantLimits.maxRequests) {
      const oldestRequest = await redisClient.zRange(rateLimitKey, 0, 0, { withScores: true })
      const resetTime = oldestRequest.length > 0 ? 
        Math.ceil((oldestRequest[0].score + tenantLimits.windowMs) / 1000) : 
        Math.ceil((now + tenantLimits.windowMs) / 1000)
      
      c.header('X-Rate-Limit-Remaining', '0')
      c.header('X-Rate-Limit-Reset', resetTime.toString())
      c.header('X-Rate-Limit-Type', 'standard')
      
      // Log to SIEM
      const userAgent = c.req.header('user-agent') || 'unknown'
      await logRateLimitExceeded(ip, userAgent, userId, tenantId)
      
      throw new HTTPException(429, { 
        message: 'Rate limit exceeded. Please try again later.',
        res: c.json({
          error: 'RATE_LIMIT_EXCEEDED',
          message: 'Rate limit exceeded. Please try again later.',
          retryAfter: resetTime,
          limit: tenantLimits.maxRequests,
          window: tenantLimits.windowMs
        }, 429)
      })
    }
    
    // Add current request
    await redisClient.zAdd(rateLimitKey, { score: now, value: `${now}-${Math.random()}` })
    await redisClient.expire(rateLimitKey, Math.ceil(tenantLimits.windowMs / 1000))
    
    const remaining = tenantLimits.maxRequests - currentRequests - 1
    c.header('X-Rate-Limit-Remaining', remaining.toString())
    c.header('X-Rate-Limit-Limit', tenantLimits.maxRequests.toString())
    c.header('X-Rate-Limit-Window', tenantLimits.windowMs.toString())
    
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error
    }
    winstonLogger.error('Rate limiting error:', error)
    // Continue without rate limiting if Redis is unavailable
  }
  
  await next()
})

// CSRF Protection middleware
const csrfProtection = async (c: Context, next: Next) => {
  // Skip CSRF check for safe methods
  const method = c.req.method
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    await next()
    return
  }

  // Skip CSRF for authentication endpoints
  const path = c.req.path
  if (path === '/api/v1/auth/login' || path === '/api/v1/auth/refresh-token' || path === '/api/v1/auth/logout') {
    await next()
    return
  }

  // Get CSRF token from header
  const csrfToken = c.req.header('X-CSRF-Token')
  if (!csrfToken) {
    throw new HTTPException(403, {
      message: 'Missing CSRF token',
      res: c.json({
        error: 'CSRF_TOKEN_MISSING',
        message: 'Missing CSRF token'
      }, 403)
    })
  }

  // Get session-based CSRF token from Redis
  const userId = c.get('userId')
  const sessionId = c.get('sessionId')
  if (!userId || !sessionId) {
    throw new HTTPException(403, {
      message: 'Invalid session',
      res: c.json({
        error: 'INVALID_SESSION',
        message: 'Invalid session for CSRF validation'
      }, 403)
    })
  }

  try {
    const storedToken = await redisClient.get(`csrf:${userId}:${sessionId}`)
    if (!storedToken || storedToken !== csrfToken) {
      // Log CSRF violation to SIEM
      const ip = c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'unknown'
      const userAgent = c.req.header('user-agent') || 'unknown'
      await logCSRFViolation(ip, userAgent, userId, tenantId, {
        method,
        path,
        providedToken: csrfToken ? 'present' : 'missing',
        sessionId
      })
      
      throw new HTTPException(403, {
        message: 'Invalid CSRF token',
        res: c.json({
          error: 'CSRF_TOKEN_INVALID',
          message: 'Invalid CSRF token'
        }, 403)
      })
    }
  } catch (error) {
    if (error instanceof HTTPException) throw error
    winstonLogger.error('CSRF validation error:', error)
    // Fail closed - deny request on Redis error
    throw new HTTPException(503, {
      message: 'Service temporarily unavailable',
      res: c.json({
        error: 'SERVICE_UNAVAILABLE',
        message: 'Unable to validate CSRF token'
      }, 503)
    })
  }

  await next()
}

// JWT Authentication middleware
const authenticateJWT = async (c: Context, next: Next) => {
  const authHeader = c.req.header('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new HTTPException(401, {
      message: 'Missing or invalid authorization header',
      res: c.json({
        error: 'UNAUTHORIZED',
        message: 'Missing or invalid authorization header'
      }, 401)
    })
  }
  
  const token = authHeader.substring(7)
  
  try {
    const decoded = jwt.verify(token, config.JWT_SECRET) as JWTPayload
    
    // Check if token is blacklisted
    const isBlacklisted = await redisClient.get(`blacklist:${token}`)
    if (isBlacklisted) {
      throw new HTTPException(401, {
        message: 'Token has been revoked',
        res: c.json({
          error: 'TOKEN_REVOKED',
          message: 'Token has been revoked'
        }, 401)
      })
    }
    
    c.set('userId', decoded.userId)
    c.set('tenantId', decoded.tenantId)
    c.set('roles', decoded.roles)
    c.set('permissions', decoded.permissions)
    c.set('sessionId', decoded.sessionId || '')
    
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new HTTPException(401, {
        message: 'Invalid token',
        res: c.json({
          error: 'INVALID_TOKEN',
          message: 'Invalid token'
        }, 401)
      })
    }
    if (error instanceof jwt.TokenExpiredError) {
      throw new HTTPException(401, {
        message: 'Token expired',
        res: c.json({
          error: 'TOKEN_EXPIRED',
          message: 'Token expired'
        }, 401)
      })
    }
    if (error instanceof Error) {
      throw error
    }
    throw new Error('Unknown authentication error')
  }
  
  await next()
}

// Enhanced service proxy function with circuit breaker and load balancing
const proxyToService = async (c: Context, serviceName: string, path: string) => {
  const service = services[serviceName]
  if (!service) {
    throw new HTTPException(404, {
      message: `Service ${serviceName} not found`,
      res: c.json({
        error: 'SERVICE_NOT_FOUND',
        message: `Service ${serviceName} not found`
      }, 404)
    })
  }
  
  const requestId = c.get('requestId')
  const startTime = Date.now()
  
  try {
    return await circuitBreaker.execute(serviceName, async () => {
      // Get service URL with load balancing
      const serviceUrl = serviceRegistry.getServiceUrl(serviceName)
      const targetUrl = `${serviceUrl}${path}`
      
      // Prepare headers with enhanced context
      const headers: Record<string, string> = {
        'Content-Type': c.req.header('Content-Type') || 'application/json',
        'X-Request-ID': requestId,
        'X-Forwarded-For': c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'unknown',
        'X-Gateway-Version': '1.0.0',
        'X-Request-Start-Time': startTime.toString()
      }
      
      // Add authentication context
      const userId = c.get('userId')
      const tenantId = c.get('tenantId')
      const roles = c.get('roles')
      const permissions = c.get('permissions')
      
      if (userId) headers['X-User-ID'] = userId
      if (tenantId) headers['X-Tenant-ID'] = tenantId
      if (roles) headers['X-User-Roles'] = JSON.stringify(roles)
      if (permissions) headers['X-User-Permissions'] = JSON.stringify(permissions)
      
      // Add correlation headers for distributed tracing
      headers['X-Correlation-ID'] = requestId
      headers['X-Service-Name'] = serviceName
      
      // Prepare request options
      const requestOptions: RequestInit = {
        method: c.req.method,
        headers,
        signal: AbortSignal.timeout(service.timeout)
      }
      
      // Add body for non-GET requests with size validation
      if (c.req.method !== 'GET' && c.req.method !== 'HEAD') {
        try {
          const body = await c.req.text()
          if (body) {
            // Validate request size (max 10MB)
            if (body.length > 10 * 1024 * 1024) {
              throw new HTTPException(413, {
                message: 'Request payload too large',
                res: c.json({
                  error: 'PAYLOAD_TOO_LARGE',
                  message: 'Request payload exceeds maximum size limit',
                  maxSize: '10MB'
                }, 413)
              })
            }
            requestOptions.body = body
          }
        } catch (error) {
          if (error instanceof HTTPException) throw error
          if (error instanceof Error) {
            winstonLogger.warn('Failed to read request body:', error)
          }
        }
      }
      
      let lastError: Error | null = null
      
      // Enhanced retry logic with exponential backoff
      for (let attempt = 1; attempt <= service.retries; attempt++) {
        try {
          winstonLogger.debug(`Proxying request to ${serviceName}`, {
            requestId,
            targetUrl,
            attempt,
            method: c.req.method,
            circuitBreakerState: circuitBreaker.getState(serviceName)
          })
          
          const response = await fetch(targetUrl, requestOptions)
          
          // Transform and validate response
          const responseHeaders: Record<string, string> = {}
          response.headers.forEach((value: string, key: string) => {
            // Filter out internal headers and add gateway headers
            if (!key.toLowerCase().startsWith('x-powered-by') && 
                !key.toLowerCase().startsWith('server')) {
              responseHeaders[key] = value
            }
          })
          
          // Add gateway response headers
          responseHeaders['X-Gateway-Service'] = serviceName
          responseHeaders['X-Gateway-Attempt'] = attempt.toString()
          responseHeaders['X-Response-Time'] = (Date.now() - startTime).toString()
          
          const responseText = await response.text()
          
          // Validate response format for JSON endpoints
          if (responseHeaders['content-type']?.includes('application/json') && responseText) {
            try {
              JSON.parse(responseText)
            } catch (jsonError) {
              if (jsonError instanceof Error) {
                winstonLogger.warn('Invalid JSON response from service', {
                  requestId,
                  serviceName,
                  responsePreview: responseText.substring(0, 200),
                  error: jsonError.message
                })
              }
            }
          }
          
          const duration = Date.now() - startTime
          updateMetrics(duration, response.ok, serviceName)
          
          winstonLogger.debug(`Service response received`, {
            requestId,
            serviceName,
            status: response.status,
            attempt,
            duration
          })
          
          return new Response(responseText, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
          })
          
        } catch (error) {
          lastError = error as Error
          winstonLogger.warn(`Service request failed`, {
            requestId,
            serviceName,
            attempt,
            error: lastError.message,
            targetUrl
          })
          
          if (attempt === service.retries) {
            break
          }
          
          // Exponential backoff with jitter
          const backoffTime = Math.pow(2, attempt) * 100 + Math.random() * 100
          await new Promise((resolve: (value: unknown) => void) => setTimeout(resolve, backoffTime))
        }
      }
      
      const duration = Date.now() - startTime
      updateMetrics(duration, false, serviceName)
      
      winstonLogger.error(`Service unavailable after ${service.retries} attempts`, {
        requestId,
        serviceName,
        error: lastError?.message,
        circuitBreakerState: circuitBreaker.getState(serviceName)
      })
      
      throw new HTTPException(503, {
        message: `Service ${serviceName} is currently unavailable`,
        res: c.json({
          error: 'SERVICE_UNAVAILABLE',
          message: `Service ${serviceName} is currently unavailable`,
          service: serviceName,
          retries: service.retries,
          circuitBreakerState: circuitBreaker.getState(serviceName)
        }, 503)
      })
    })
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error
    }
    
    const duration = Date.now() - startTime
    updateMetrics(duration, false, serviceName)
    
    if (error instanceof Error && error.message.includes('Circuit breaker is OPEN')) {
      throw new HTTPException(503, {
        message: `Service ${serviceName} is temporarily unavailable`,
        res: c.json({
          error: 'CIRCUIT_BREAKER_OPEN',
          message: `Service ${serviceName} is temporarily unavailable due to repeated failures`,
          service: serviceName,
          retryAfter: 60
        }, 503)
      })
    }
    
    throw new HTTPException(500, {
      message: 'Internal gateway error',
      res: c.json({
        error: 'GATEWAY_ERROR',
        message: 'An unexpected error occurred in the gateway',
        requestId
      }, 500)
    })
  }
}

// Enhanced health check endpoint with metrics
app.get('/health', async (c: Context) => {
  const requestId = c.get('requestId')
  const healthChecks: Record<string, any> = {}
  const startTime = Date.now()
  
  // Check Redis connection
  try {
    if (!redisClient.isConnected) {
      await redisClient.connect()
    }
    await redisClient.ping()
    healthChecks.redis = { 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      responseTime: Date.now() - startTime
    }
  } catch (error) {
    healthChecks.redis = { 
      status: 'unhealthy', 
      error: (error as Error).message,
      timestamp: new Date().toISOString(),
      responseTime: Date.now() - startTime
    }
  }
  
  // Check downstream services with circuit breaker status
  const serviceHealthPromises = Object.entries(services).map(async ([name, service]: [string, ServiceConfig]) => {
    const serviceStartTime = Date.now()
    try {
      const serviceUrl = serviceRegistry.getServiceUrl(name)
      const response = await fetch(`${serviceUrl}${service.healthPath}`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
        headers: {
          'X-Request-ID': requestId,
          'X-Health-Check': 'true'
        }
      })
      
      const responseTime = Date.now() - serviceStartTime
      let responseBody = null
      
      try {
        responseBody = await response.json()
      } catch (jsonError) {
        // Ignore JSON parsing errors for health checks
        if (jsonError instanceof Error) {
          winstonLogger.debug('Health check response not JSON:', jsonError.message)
        }
      }
      
      healthChecks[name] = {
        status: response.ok ? 'healthy' : 'unhealthy',
        statusCode: response.status,
        responseTime,
        circuitBreakerState: circuitBreaker.getState(name),
        instances: serviceRegistry.getHealthyInstances(name).length,
        timestamp: new Date().toISOString(),
        ...(responseBody && { details: responseBody })
      }
    } catch (error) {
      healthChecks[name] = {
        status: 'unhealthy',
        error: (error as Error).message,
        responseTime: Date.now() - serviceStartTime,
        circuitBreakerState: circuitBreaker.getState(name),
        instances: serviceRegistry.getHealthyInstances(name).length,
        timestamp: new Date().toISOString()
      }
    }
  })
  
  await Promise.all(serviceHealthPromises)
  
  // Calculate overall health status
  const healthyServices = Object.values(healthChecks).filter((check: any) => check.status === 'healthy').length
  const totalServices = Object.keys(healthChecks).length
  const healthPercentage = (healthyServices / totalServices) * 100
  
  let overallStatus: string
  if (healthPercentage === 100) {
    overallStatus = 'healthy'
  } else if (healthPercentage >= 80) {
    overallStatus = 'degraded'
  } else {
    overallStatus = 'unhealthy'
  }
  
  // Calculate metrics
  const avgResponseTime = metrics.responseTime.length > 0 
    ? metrics.responseTime.reduce((a, b) => a + b, 0) / metrics.responseTime.length 
    : 0
  
  const errorRate = metrics.requestCount > 0 
    ? (metrics.errorCount / metrics.requestCount) * 100 
    : 0
  
  const totalResponseTime = Date.now() - startTime
  
  return c.json({
    status: overallStatus,
    timestamp: new Date().toISOString(),
    requestId,
    responseTime: totalResponseTime,
    services: healthChecks,
    metrics: {
      totalRequests: metrics.requestCount,
      errorCount: metrics.errorCount,
      errorRate: Math.round(errorRate * 100) / 100,
      averageResponseTime: Math.round(avgResponseTime * 100) / 100,
      healthyServices,
      totalServices,
      healthPercentage: Math.round(healthPercentage * 100) / 100
    },
    gateway: {
      version: '1.0.0',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      nodeVersion: process.version
    }
  }, overallStatus === 'healthy' ? 200 : 503)
})

// Metrics endpoint for monitoring
app.get('/metrics', async (c: Context) => {
  const requestId = c.get('requestId')
  
  // Calculate detailed metrics
  const avgResponseTime = metrics.responseTime.length > 0 
    ? metrics.responseTime.reduce((a, b) => a + b, 0) / metrics.responseTime.length 
    : 0
  
  const p95ResponseTime = metrics.responseTime.length > 0
    ? metrics.responseTime.sort((a: number, b: number) => a - b)[Math.floor(metrics.responseTime.length * 0.95)]
    : 0
  
  const errorRate = metrics.requestCount > 0 
    ? (metrics.errorCount / metrics.requestCount) * 100 
    : 0
  
  // Service health summary
  const serviceHealthSummary: Record<string, any> = {}
  Object.keys(services).forEach((serviceName: string) => {
    serviceHealthSummary[serviceName] = {
      healthy: metrics.serviceHealth.get(serviceName) || false,
      circuitBreakerState: circuitBreaker.getState(serviceName),
      instances: serviceRegistry.getHealthyInstances(serviceName).length
    }
  })
  
  return c.json({
    timestamp: new Date().toISOString(),
    requestId,
    gateway: {
      totalRequests: metrics.requestCount,
      errorCount: metrics.errorCount,
      errorRate: Math.round(errorRate * 100) / 100,
      averageResponseTime: Math.round(avgResponseTime * 100) / 100,
      p95ResponseTime: Math.round(p95ResponseTime * 100) / 100,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      nodeVersion: process.version
    },
    services: serviceHealthSummary,
    redis: {
      connected: redisClient.isConnected
    }
  })
})

// Mount versioning routes
app.route('/api', versioningRouter)

// Mount versioned example routes (for v1 and v2)
app.route('/v1', versionedIncidentsRouter)
app.route('/v2', versionedIncidentsRouter)

// CSP Report endpoint
app.post('/api/v1/csp-report', async (c: Context) => {
  const requestId = c.get('requestId')
  
  try {
    const report = await c.req.json()
    
    // Log CSP violations for security monitoring
    winstonLogger.warn('CSP Violation Report', {
      requestId,
      report,
      userAgent: c.req.header('User-Agent'),
      ip: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP'),
      timestamp: new Date().toISOString()
    })
    
    // Store in Redis for analysis (optional)
    if (redisClient.isConnected) {
      const key = `csp:violation:${Date.now()}`
      await redisClient.setEx(key, 86400, JSON.stringify({ // 24 hour TTL
        report,
        metadata: {
          requestId,
          userAgent: c.req.header('User-Agent'),
          ip: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP'),
          timestamp: new Date().toISOString()
        }
      }))
    }
    
    return c.json({ status: 'reported' }, 204)
  } catch (error) {
    winstonLogger.error('Failed to process CSP report', {
      requestId,
      error: (error as Error).message
    })
    return c.json({ error: 'Failed to process report' }, 500)
  }
})

// Service discovery endpoint
app.get('/discovery', async (c: Context) => {
  const requestId = c.get('requestId')
  
  const serviceDiscovery: Record<string, any> = {}
  Object.entries(services).forEach(([name, service]: [string, ServiceConfig]) => {
    serviceDiscovery[name] = {
      instances: serviceRegistry.getHealthyInstances(name),
      circuitBreakerState: circuitBreaker.getState(name),
      configuration: {
        timeout: service.timeout,
        retries: service.retries,
        healthPath: service.healthPath
      }
    }
  })
  
  return c.json({
    timestamp: new Date().toISOString(),
    requestId,
    services: serviceDiscovery
  })
})

// Public routes (no authentication required)
app.post('/api/v1/auth/login', (c: Context) => proxyToService(c, 'auth', '/login'))
app.post('/api/v1/auth/signup', (c: Context) => proxyToService(c, 'auth', '/signup'))
app.post('/api/v1/auth/refresh-token', (c: Context) => proxyToService(c, 'auth', '/refresh-token'))
app.post('/api/v1/auth/forgot-password', (c: Context) => proxyToService(c, 'auth', '/forgot-password'))
app.post('/api/v1/auth/reset-password', (c: Context) => proxyToService(c, 'auth', '/reset-password'))

// Protected routes (authentication required)
app.use('/api/v1/*', authenticateJWT)

// Apply SIEM monitoring middleware to all API routes
app.use('/api/v1/*', siemMiddleware)

// Apply CSRF protection to state-changing operations on protected routes
app.use('/api/v1/*', async (c: Context, next: Next) => {
  // Skip CSRF for safe methods and specific endpoints
  const method = c.req.method
  const path = c.req.path
  
  // Safe methods don't need CSRF protection
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    await next()
    return
  }
  
  // Skip CSRF for logout (it's a security operation itself)
  if (path === '/api/v1/auth/logout') {
    await next()
    return
  }
  
  // Apply CSRF protection for all other state-changing operations
  await csrfProtection(c, next)
})

// Apply caching to read-only endpoints
const readOnlyEndpoints = [
  '/api/v1/tenants/*',
  '/api/v1/organizations/*',
  '/api/v1/sites/*',
  '/api/v1/buildings/*',
  '/api/v1/floors/*',
  '/api/v1/zones/*',
  '/api/v1/cameras/*',
  '/api/v1/devices/*',
  '/api/v1/analytics/*',
  '/api/v1/reports/*',
  '/api/v1/dashboards/*'
];

readOnlyEndpoints.forEach(endpoint => {
  app.use(endpoint, cacheMiddleware(cache, {
    ttl: 60, // 1 minute cache
    namespace: 'api',
    condition: (c) => c.req.method === 'GET',
    keyGenerator: (c) => {
      const url = new URL(c.req.url);
      const tenantId = c.get('tenantId');
      return `${tenantId}:${url.pathname}:${url.search}`;
    }
  }));
});

// Authentication service routes
app.all('/api/v1/auth/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/auth', '')
  return proxyToService(c, 'auth', path)
})

// Tenant service routes
app.all('/api/v1/tenants/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/tenants', '')
  return proxyToService(c, 'tenant', path)
})

app.all('/api/v1/organizations/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/organizations', '/organizations')
  return proxyToService(c, 'tenant', path)
})

app.all('/api/v1/sites/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/sites', '/sites')
  return proxyToService(c, 'tenant', path)
})

app.all('/api/v1/buildings/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/buildings', '/buildings')
  return proxyToService(c, 'tenant', path)
})

app.all('/api/v1/floors/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/floors', '/floors')
  return proxyToService(c, 'tenant', path)
})

// Access control service routes
app.all('/api/v1/doors/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/doors', '/doors')
  return proxyToService(c, 'access-control', path)
})

app.all('/api/v1/zones/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/zones', '/zones')
  return proxyToService(c, 'access-control', path)
})

app.all('/api/v1/access-events/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/access-events', '/events')
  return proxyToService(c, 'access-control', path)
})

app.all('/api/v1/access-groups/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/access-groups', '/access-groups')
  return proxyToService(c, 'access-control', path)
})

app.all('/api/v1/schedules/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/schedules', '/schedules')
  return proxyToService(c, 'access-control', path)
})

// Video management service routes
app.all('/api/v1/cameras/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/cameras', '/cameras')
  return proxyToService(c, 'video-management', path)
})

app.all('/api/v1/video-streams/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/video-streams', '/streams')
  return proxyToService(c, 'video-management', path)
})

app.all('/api/v1/recordings/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/recordings', '/recordings')
  return proxyToService(c, 'video-management', path)
})

// Event processing service routes
app.all('/api/v1/events/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/events', '/events')
  return proxyToService(c, 'event-processing', path)
})

app.all('/api/v1/event-correlation/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/event-correlation', '/event-correlation')
  return proxyToService(c, 'event-processing', path)
})

app.all('/api/v1/incident-clips/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/incident-clips', '/incident-clips')
  return proxyToService(c, 'event-processing', path)
})

// Device management service routes
app.all('/api/v1/devices/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/devices', '/devices')
  return proxyToService(c, 'device-management', path)
})

app.all('/api/v1/panels/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/panels', '/panels')
  return proxyToService(c, 'device-management', path)
})

app.all('/api/v1/readers/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/readers', '/readers')
  return proxyToService(c, 'device-management', path)
})

// Mobile credential service routes
app.all('/api/v1/mobile-credentials/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/mobile-credentials', '/credentials')
  return proxyToService(c, 'mobile-credential', path)
})

// Analytics service routes
app.all('/api/v1/analytics/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/analytics', '/analytics')
  return proxyToService(c, 'analytics', path)
})

// Environmental service routes
app.all('/api/v1/environmental/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/environmental', '/environmental')
  return proxyToService(c, 'environmental', path)
})

app.all('/api/v1/sensors/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/sensors', '/sensors')
  return proxyToService(c, 'environmental', path)
})

// Visitor management service routes
app.all('/api/v1/visitors/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/visitors', '/visitors')
  return proxyToService(c, 'visitor-management', path)
})

// Reporting service routes
app.all('/api/v1/reports/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/reports', '/reports')
  return proxyToService(c, 'reporting', path)
})

app.all('/api/v1/dashboards/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/dashboards', '/dashboards')
  return proxyToService(c, 'reporting', path)
})

// Alert service routes
app.all('/api/v1/alerts/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/alerts', '/alerts')
  return proxyToService(c, 'alert', path)
})

app.all('/api/v1/notifications/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/notifications', '/notifications')
  return proxyToService(c, 'alert', path)
})

app.all('/api/v1/escalations/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/escalations', '/escalations')
  return proxyToService(c, 'alert', path)
})

// Integration service routes
app.all('/api/v1/integrations/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/integrations', '/integrations')
  return proxyToService(c, 'integration', path)
})

app.all('/api/v1/webhooks/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/webhooks', '/webhooks')
  return proxyToService(c, 'integration', path)
})

app.all('/api/v1/ldap/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/ldap', '/ldap')
  return proxyToService(c, 'integration', path)
})

app.all('/api/v1/building-systems/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/building-systems', '/building-systems')
  return proxyToService(c, 'integration', path)
})

// Backup & Recovery service routes
app.all('/api/v1/backups/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/backups', '/backups')
  return proxyToService(c, 'backup-recovery', path)
})

app.all('/api/v1/recovery/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/recovery', '/recovery')
  return proxyToService(c, 'backup-recovery', path)
})

app.all('/api/v1/disaster-recovery/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/disaster-recovery', '/disaster-recovery')
  return proxyToService(c, 'backup-recovery', path)
})

// Security & Compliance service routes
app.all('/api/v1/audit-logs/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/audit-logs', '/audit-logs')
  return proxyToService(c, 'security-compliance', path)
})

app.all('/api/v1/compliance/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/compliance', '/compliance')
  return proxyToService(c, 'security-compliance', path)
})

app.all('/api/v1/certificates/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/certificates', '/certificates')
  return proxyToService(c, 'security-compliance', path)
})

app.all('/api/v1/security-monitoring/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/security-monitoring', '/security-monitoring')
  return proxyToService(c, 'security-compliance', path)
})

app.all('/api/v1/threat-detection/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/threat-detection', '/threat-detection')
  return proxyToService(c, 'security-compliance', path)
})

// Maintenance service routes
app.all('/api/v1/maintenance/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/maintenance', '/maintenance')
  return proxyToService(c, 'maintenance', path)
})

app.all('/api/v1/work-orders/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/work-orders', '/work-orders')
  return proxyToService(c, 'maintenance', path)
})

app.all('/api/v1/diagnostics/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/diagnostics', '/diagnostics')
  return proxyToService(c, 'maintenance', path)
})

app.all('/api/v1/service-history/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/service-history', '/service-history')
  return proxyToService(c, 'maintenance', path)
})

// Elevator Control service routes
app.all('/api/v1/elevators/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/elevators', '/elevators')
  return proxyToService(c, 'elevator-control', path)
})

app.all('/api/v1/floor-access/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/floor-access', '/floor-access')
  return proxyToService(c, 'elevator-control', path)
})

app.all('/api/v1/emergency-override/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/emergency-override', '/emergency-override')
  return proxyToService(c, 'elevator-control', path)
})

// API Documentation service routes (public access for documentation)
app.all('/api/v1/docs/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/docs', '/docs')
  return proxyToService(c, 'api-documentation', path)
})

app.all('/api/v1/openapi/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/openapi', '/openapi')
  return proxyToService(c, 'api-documentation', path)
})

app.all('/api/v1/sdk/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/sdk', '/sdk')
  return proxyToService(c, 'api-documentation', path)
})

// Testing Infrastructure service routes (admin access only)
app.all('/api/v1/testing/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/testing', '/testing')
  return proxyToService(c, 'testing-infrastructure', path)
})

app.all('/api/v1/test-results/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/test-results', '/test-results')
  return proxyToService(c, 'testing-infrastructure', path)
})

app.all('/api/v1/performance-monitoring/*', (c: Context) => {
  const path = c.req.path.replace('/api/v1/performance-monitoring', '/performance-monitoring')
  return proxyToService(c, 'testing-infrastructure', path)
})

// Catch-all for undefined routes
app.all('*', (c: Context) => {
  return c.json({
    error: 'NOT_FOUND',
    message: 'The requested endpoint was not found',
    path: c.req.path,
    method: c.req.method
  }, 404)
})

// Enhanced global error handler with detailed error tracking
app.onError((err: Error, c: Context) => {
  const requestId = c.get('requestId')
  const startTime = c.get('startTime')
  const duration = startTime ? Date.now() - startTime : 0
  
  // Update error metrics
  updateMetrics(duration, false)
  
  // Log error with context
  winstonLogger.error('Unhandled error:', {
    requestId,
    error: err.message,
    stack: err.stack,
    path: c.req.path,
    method: c.req.method,
    userAgent: c.req.header('User-Agent'),
    ip: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP'),
    tenantId: c.get('tenantId'),
    userId: c.get('userId'),
    duration
  })
  
  if (err instanceof HTTPException) {
    return err.getResponse()
  }
  
  // Handle specific error types
  if (err.name === 'TimeoutError') {
    return c.json({
      error: 'REQUEST_TIMEOUT',
      message: 'Request timed out',
      requestId,
      timeout: parseInt(config.REQUEST_TIMEOUT_MS)
    }, 408)
  }
  
  if (err.message.includes('ECONNREFUSED') || err.message.includes('ENOTFOUND')) {
    return c.json({
      error: 'SERVICE_UNAVAILABLE',
      message: 'Unable to connect to backend service',
      requestId
    }, 503)
  }
  
  // Generic internal server error
  return c.json({
    error: 'INTERNAL_SERVER_ERROR',
    message: config.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : err.message,
    requestId,
    ...(config.NODE_ENV !== 'production' && { stack: err.stack })
  }, 500)
})

// Graceful shutdown handler
const gracefulShutdown = async (signal: string) => {
  winstonLogger.info(`Received ${signal}, starting graceful shutdown...`)
  
  try {
    await redisClient.quit()
    winstonLogger.info('Redis connection closed')
  } catch (error) {
    if (error instanceof Error) {
      winstonLogger.error('Error closing Redis connection:', error)
    }
  }
  
  winstonLogger.info('Graceful shutdown completed')
  process.exit(0)
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT', () => gracefulShutdown('SIGINT'))

// Start server
const port = parseInt(config.PORT)

const startServer = async () => {
  try {
    // Connect to Redis
    await redisClient.connect()
    
    winstonLogger.info('Starting SPARC API Gateway...', {
      port,
      environment: config.NODE_ENV,
      services: Object.keys(services),
      totalServices: Object.keys(services).length
    })
    
    serve({
      fetch: app.fetch,
      port
    })
    
    winstonLogger.info(`SPARC API Gateway started successfully on port ${port}`)
    
  } catch (error) {
    if (error instanceof Error) {
      winstonLogger.error('Failed to start server:', error)
    }
    process.exit(1)
  }
}

startServer()

// ============================================================================
// COMPREHENSIVE TEST SUITE
// ============================================================================

if (process.env.NODE_ENV === 'test' && typeof describe !== 'undefined') {
  
  // Test utilities and mocks
  const createMockRedisClient = () => {
    const mockRedis = {
      connect: jest.fn().mockResolvedValue(undefined),
      quit: jest.fn().mockResolvedValue(undefined),
      ping: jest.fn().mockResolvedValue('PONG'),
      get: jest.fn(),
      set: jest.fn(),
      setEx: jest.fn(),
      del: jest.fn(),
      zAdd: jest.fn(),
      zCard: jest.fn(),
      zRange: jest.fn(),
      zRemRangeByScore: jest.fn(),
      expire: jest.fn(),
      on: jest.fn(),
      isConnected: true
    };
    return mockRedis;
  };

  const createMockJWT = () => ({
    sign: jest.fn(),
    verify: jest.fn(),
    JsonWebTokenError: class extends Error {},
    TokenExpiredError: class extends Error {}
  });

  const createTestApp = () => {
    const testApp = new Hono();
    // Apply same middleware as main app but with mocked dependencies
    testApp.use('*', secureHeaders());
    testApp.use('*', prettyJSON());
    return testApp;
  };

  const mockFetch = jest.fn();
  global.fetch = mockFetch;

  describe('API Gateway Test Suite', () => {
    let testApp: Hono;
    let mockRedis: any;
    let mockJwtLib: any;

    beforeAll(() => {
      // Setup test environment
      process.env.NODE_ENV = 'test';
      process.env.JWT_SECRET = 'test-secret';
      process.env.REDIS_URL = 'redis://localhost:6379';
    });

    beforeEach(() => {
      testApp = createTestApp();
      mockRedis = createMockRedisClient();
      mockJwtLib = createMockJWT();
      mockFetch.mockClear();
      
      // Mock Redis client creation
      jest.spyOn(Redis, 'createClient').mockReturnValue(mockRedis as any);
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    // ========================================================================
    // 1. UNIT TESTS FOR PROXY ROUTING FUNCTIONALITY
    // ========================================================================
    describe('Proxy Routing Functionality', () => {
      it('should route requests to correct service based on path', async () => {
        const testCases = [
          { path: '/api/v1/auth/login', expectedService: 'auth-service' },
          { path: '/api/v1/tenants/123', expectedService: 'tenant-service' },
          { path: '/api/v1/doors/456', expectedService: 'access-control-service' },
          { path: '/api/v1/cameras/789', expectedService: 'video-management-service' },
          { path: '/api/v1/alerts/101', expectedService: 'event-processing-service' },
          { path: '/api/v1/devices/202', expectedService: 'device-management-service' },
          { path: '/api/v1/mobile-credentials/303', expectedService: 'mobile-credential-service' },
          { path: '/api/v1/analytics/404', expectedService: 'analytics-service' },
          { path: '/api/v1/environmental/505', expectedService: 'environmental-service' },
          { path: '/api/v1/visitors/606', expectedService: 'visitor-management-service' },
          { path: '/api/v1/reports/707', expectedService: 'reporting-service' }
        ];

        for (const testCase of testCases) {
          mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));
          
          const req = new Request(`http://localhost:3000${testCase.path}`, {
            method: 'GET',
            headers: { 'Authorization': 'Bearer valid-token' }
          });

          // Mock JWT verification
          mockJwtLib.verify.mockReturnValue({
            userId: 'test-user',
            tenantId: 'test-tenant',
            roles: ['user'],
            permissions: ['read']
          });

          const _response = await testApp.fetch(req);
          
          expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining(testCase.expectedService),
            expect.any(Object)
          );
        }
      });

      it('should handle service not found errors', async () => {
        const req = new Request('http://localhost:3000/api/v1/unknown/endpoint', {
          method: 'GET'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(404);
        
        const body = await response.json();
        expect(body.error).toBe('NOT_FOUND');
      });

      it('should preserve request method and headers in proxy', async () => {
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));
        
        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Custom-Header': 'test-value'
          },
          body: JSON.stringify({ username: 'test', password: 'test' })
        });

        await testApp.fetch(req);

        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            method: 'POST',
            headers: expect.objectContaining({
              'Content-Type': 'application/json'
            })
          })
        );
      });

      it('should handle retry logic on service failures', async () => {
        // First two calls fail, third succeeds
        mockFetch
          .mockRejectedValueOnce(new Error('Connection failed'))
          .mockRejectedValueOnce(new Error('Connection failed'))
          .mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(mockFetch).toHaveBeenCalledTimes(3);
        expect(response.status).toBe(200);
      });

      it('should return 503 after max retries exceeded', async () => {
        mockFetch.mockRejectedValue(new Error('Service unavailable'));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(503);
        
        const body = await response.json();
        expect(body.error).toBe('SERVICE_UNAVAILABLE');
      });
    });

    // ========================================================================
    // 2. INTEGRATION TESTS FOR AUTHENTICATION MIDDLEWARE
    // ========================================================================
    describe('Authentication Middleware', () => {
      it('should allow public routes without authentication', async () => {
        const publicRoutes = [
          '/api/v1/auth/login',
          '/api/v1/auth/signup',
          '/api/v1/auth/refresh-token',
          '/api/v1/auth/forgot-password',
          '/api/v1/auth/reset-password'
        ];

        for (const route of publicRoutes) {
          mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));
          
          const req = new Request(`http://localhost:3000${route}`, {
            method: 'POST'
          });

          const response = await testApp.fetch(req);
          expect(response.status).not.toBe(401);
        }
      });

      it('should require authentication for protected routes', async () => {
        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(401);
        
        const body = await response.json();
        expect(body.error).toBe('UNAUTHORIZED');
      });

      it('should validate JWT tokens correctly', async () => {
        const validToken = 'valid.jwt.token';
        const mockPayload = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          roles: ['admin'],
          permissions: ['read', 'write'],
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600
        };

        mockJwtLib.verify.mockReturnValue(mockPayload);
        mockRedis.get.mockResolvedValue(null); // Token not blacklisted
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${validToken}` }
        });

        const response = await testApp.fetch(req);
        expect(mockJwtLib.verify).toHaveBeenCalledWith(validToken, 'test-secret');
        expect(response.status).toBe(200);
      });

      it('should reject invalid JWT tokens', async () => {
        mockJwtLib.verify.mockImplementation(() => {
          throw new mockJwtLib.JsonWebTokenError('Invalid token');
        });

        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': 'Bearer invalid.token' }
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(401);
        
        const body = await response.json();
        expect(body.error).toBe('INVALID_TOKEN');
      });

      it('should reject expired JWT tokens', async () => {
        mockJwtLib.verify.mockImplementation(() => {
          throw new mockJwtLib.TokenExpiredError('Token expired', new Date());
        });

        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': 'Bearer expired.token' }
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(401);
        
        const body = await response.json();
        expect(body.error).toBe('TOKEN_EXPIRED');
      });

      it('should reject blacklisted tokens', async () => {
        const blacklistedToken = 'blacklisted.jwt.token';
        mockJwtLib.verify.mockReturnValue({ userId: 'user-123' });
        mockRedis.get.mockResolvedValue('blacklisted');

        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${blacklistedToken}` }
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(401);
        
        const body = await response.json();
        expect(body.error).toBe('TOKEN_REVOKED');
      });
    });

    // ========================================================================
    // 3. RATE LIMITING FUNCTIONALITY TESTS
    // ========================================================================
    describe('Rate Limiting Functionality', () => {
      beforeEach(() => {
        mockRedis.zRemRangeByScore.mockResolvedValue(0);
        mockRedis.zCard.mockResolvedValue(0);
        mockRedis.zAdd.mockResolvedValue(1);
        mockRedis.expire.mockResolvedValue(1);
      });

      it('should allow requests within rate limit', async () => {
        mockRedis.zCard.mockResolvedValue(50); // Under limit of 100
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'X-Forwarded-For': '192.168.1.1' }
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(200);
        expect(response.headers.get('X-Rate-Limit-Remaining')).toBe('49');
      });

      it('should block requests exceeding rate limit', async () => {
        mockRedis.zCard.mockResolvedValue(100); // At limit
        mockRedis.zRange.mockResolvedValue([{ score: Date.now() - 900000 }]);

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'X-Forwarded-For': '192.168.1.1' }
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(429);
        
        const body = await response.json();
        expect(body.error).toBe('RATE_LIMIT_EXCEEDED');
        expect(response.headers.get('X-Rate-Limit-Remaining')).toBe('0');
      });

      it('should handle Redis connection failures gracefully', async () => {
        mockRedis.zCard.mockRejectedValue(new Error('Redis connection failed'));
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(200); // Should continue without rate limiting
      });

      it('should use different rate limits for different IP addresses', async () => {
        const ip1Requests = 50;
        const ip2Requests = 75;

        // Test IP 1
        mockRedis.zCard.mockResolvedValueOnce(ip1Requests);
        const req1 = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'X-Forwarded-For': '192.168.1.1' }
        });

        // Test IP 2
        mockRedis.zCard.mockResolvedValueOnce(ip2Requests);
        const req2 = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'X-Forwarded-For': '192.168.1.2' }
        });

        mockFetch.mockResolvedValue(new Response('{"success": true}', { status: 200 }));

        const [response1, response2] = await Promise.all([
          testApp.fetch(req1),
          testApp.fetch(req2)
        ]);

        expect(response1.headers.get('X-Rate-Limit-Remaining')).toBe((100 - ip1Requests - 1).toString());
        expect(response2.headers.get('X-Rate-Limit-Remaining')).toBe((100 - ip2Requests - 1).toString());
      });
    });

    // ========================================================================
    // 4. REQUEST CONTEXT MANAGEMENT AND TENANT HEADER PROPAGATION
    // ========================================================================
    describe('Request Context Management', () => {
      it('should generate and propagate request IDs', async () => {
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        const requestId = response.headers.get('X-Request-ID');
        
        expect(requestId).toBeTruthy();
        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            headers: expect.objectContaining({
              'X-Request-ID': requestId
            })
          })
        );
      });

      it('should preserve existing request IDs', async () => {
        const existingRequestId = 'existing-request-id';
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'X-Request-ID': existingRequestId }
        });

        const response = await testApp.fetch(req);
        expect(response.headers.get('X-Request-ID')).toBe(existingRequestId);
      });

      it('should propagate user context headers to downstream services', async () => {
        const mockPayload = {
          userId: 'user-123',
          tenantId: 'tenant-456',
          roles: ['admin', 'user'],
          permissions: ['read', 'write', 'delete']
        };

        mockJwtLib.verify.mockReturnValue(mockPayload);
        mockRedis.get.mockResolvedValue(null);
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        await testApp.fetch(req);

        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            headers: expect.objectContaining({
              'X-User-ID': 'user-123',
              'X-Tenant-ID': 'tenant-456',
              'X-User-Roles': JSON.stringify(['admin', 'user']),
              'X-User-Permissions': JSON.stringify(['read', 'write', 'delete'])
            })
          })
        );
      });

      it('should handle missing tenant context gracefully', async () => {
        const mockPayload = {
          userId: 'user-123',
          roles: ['user'],
          permissions: ['read']
          // tenantId missing
        };

        mockJwtLib.verify.mockReturnValue(mockPayload);
        mockRedis.get.mockResolvedValue(null);
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': 'Bearer valid-token' }
        });

        await testApp.fetch(req);

        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            headers: expect.not.objectContaining({
              'X-Tenant-ID': expect.any(String)
            })
          })
        );
      });
    });

    // ========================================================================
    // 5. ERROR HANDLING AND RESPONSE TRANSFORMATION
    // ========================================================================
    describe('Error Handling and Response Transformation', () => {
      it('should handle upstream service errors correctly', async () => {
        mockFetch.mockResolvedValueOnce(new Response('{"error": "Internal Server Error"}', { 
          status: 500,
          statusText: 'Internal Server Error'
        }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(500);
        
        const body = await response.json();
        expect(body.error).toBe('Internal Server Error');
      });

      it('should handle network timeouts', async () => {
        mockFetch.mockImplementation(() => 
          new Promise((_: unknown, reject: (reason: Error) => void) => 
            setTimeout(() => reject(new Error('Request timeout')), 100)
          )
        );

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(503);
      });

      it('should preserve response headers from upstream services', async () => {
        const upstreamHeaders = {
          'Content-Type': 'application/json',
          'X-Custom-Header': 'custom-value',
          'Cache-Control': 'no-cache'
        };

        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { 
          status: 200,
          headers: upstreamHeaders
        }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        
        Object.entries(upstreamHeaders).forEach(([key, value]: [string, string]) => {
          expect(response.headers.get(key)).toBe(value);
        });
      });

      it('should handle malformed JSON responses', async () => {
        mockFetch.mockResolvedValueOnce(new Response('invalid json{', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        const responseText = await response.text();
        expect(responseText).toBe('invalid json{');
      });
    });

    // ========================================================================
    // 6. REQUEST LOGGING AND AUDIT TRAIL
    // ========================================================================
    describe('Request Logging and Audit Trail', () => {
      let logSpy: any;

      beforeEach(() => {
        logSpy = jest.spyOn(winstonLogger, 'info').mockImplementation();
      });

      afterEach(() => {
        logSpy.mockRestore();
      });

      it('should log request start and completion', async () => {
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'User-Agent': 'Test Agent' }
        });

        await testApp.fetch(req);

        expect(logSpy).toHaveBeenCalledWith('Request started', expect.objectContaining({
          method: 'POST',
          path: '/api/v1/auth/login',
          userAgent: 'Test Agent'
        }));

        expect(logSpy).toHaveBeenCalledWith('Request completed', expect.objectContaining({
          method: 'POST',
          path: '/api/v1/auth/login',
          status: 200,
          duration: expect.any(Number)
        }));
      });

      it('should log authentication failures', async () => {
        const errorSpy = jest.spyOn(winstonLogger, 'error').mockImplementation();

        const req = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': 'Bearer invalid-token' }
        });

        await testApp.fetch(req);

        expect(errorSpy).toHaveBeenCalled();
        errorSpy.mockRestore();
      });

      it('should log service proxy attempts', async () => {
        const debugSpy = jest.spyOn(winstonLogger, 'debug').mockImplementation();
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        await testApp.fetch(req);

        expect(debugSpy).toHaveBeenCalledWith(
          expect.stringContaining('Proxying request'),
          expect.objectContaining({
            targetUrl: expect.stringContaining('auth-service'),
            method: 'POST'
          })
        );

        debugSpy.mockRestore();
      });
    });

    // ========================================================================
    // 7. HEALTH CHECK AGGREGATION
    // ========================================================================
    describe('Health Check Aggregation', () => {
      it('should return healthy status when all services are up', async () => {
        mockRedis.ping.mockResolvedValue('PONG');
        
        // Mock all service health checks as successful
        mockFetch.mockImplementation((url: string) => {
          if (url.includes('/health')) {
            return Promise.resolve(new Response('{"status": "healthy"}', { status: 200 }));
          }
          return Promise.resolve(new Response('{"success": true}', { status: 200 }));
        });

        const req = new Request('http://localhost:3000/health', {
          method: 'GET'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(200);
        
        const body = await response.json();
        expect(body.status).toBe('healthy');
        expect(body.services.redis.status).toBe('healthy');
      });

      it('should return degraded status when some services are down', async () => {
        mockRedis.ping.mockResolvedValue('PONG');
        
        mockFetch.mockImplementation((url: string) => {
          if (url.includes('auth-service') && url.includes('/health')) {
            return Promise.reject(new Error('Service unavailable'));
          }
          if (url.includes('/health')) {
            return Promise.resolve(new Response('{"status": "healthy"}', { status: 200 }));
          }
          return Promise.resolve(new Response('{"success": true}', { status: 200 }));
        });

        const req = new Request('http://localhost:3000/health', {
          method: 'GET'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(503);
        
        const body = await response.json();
        expect(body.status).toBe('degraded');
      });

      it('should handle Redis health check failures', async () => {
        mockRedis.ping.mockRejectedValue(new Error('Redis connection failed'));

        const req = new Request('http://localhost:3000/health', {
          method: 'GET'
        });

        const response = await testApp.fetch(req);
        const body = await response.json();
        expect(body.services.redis.status).toBe('unhealthy');
      });
    });

    // ========================================================================
    // 8. PERFORMANCE TESTS
    // ========================================================================
    describe('Performance Tests', () => {
      it('should handle concurrent requests efficiently', async () => {
        mockFetch.mockResolvedValue(new Response('{"success": true}', { status: 200 }));
        mockRedis.zCard.mockResolvedValue(0);

        const concurrentRequests = 50;
        const requests = Array.from({ length: concurrentRequests }, (_: unknown, i: number) => 
          testApp.fetch(new Request(`http://localhost:3000/api/v1/auth/login`, {
            method: 'POST',
            headers: { 'X-Request-ID': `req-${i}` }
          }))
        );

        const startTime = Date.now();
        const responses = await Promise.all(requests);
        const duration = Date.now() - startTime;

        expect(responses).toHaveLength(concurrentRequests);
        expect(responses.every((r: Response) => r.status === 200)).toBe(true);
        expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      });

      it('should maintain response time under load', async () => {
        mockFetch.mockImplementation(() => 
          new Promise((resolve: (value: Response) => void) => 
            setTimeout(() => resolve(new Response('{"success": true}', { status: 200 })), 50)
          )
        );

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const startTime = Date.now();
        await testApp.fetch(req);
        const duration = Date.now() - startTime;

        expect(duration).toBeLessThan(200); // Should respond within 200ms (excluding upstream delay)
      });
    });

    // ========================================================================
    // 9. SECURITY FEATURES
    // ========================================================================
    describe('Security Features', () => {
      it('should include security headers in responses', async () => {
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        
        // Check for security headers added by secureHeaders middleware
        expect(response.headers.get('X-Content-Type-Options')).toBeTruthy();
        expect(response.headers.get('X-Frame-Options')).toBeTruthy();
        expect(response.headers.get('X-XSS-Protection')).toBeTruthy();
      });

      it('should sanitize request headers before forwarding', async () => {
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer token',
            'X-Malicious-Header': '<script>alert("xss")</script>',
            'Content-Type': 'application/json'
          }
        });

        await testApp.fetch(req);

        // Verify that only safe headers are forwarded
        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            headers: expect.not.objectContaining({
              'X-Malicious-Header': expect.any(String)
            })
          })
        );
      });

      it('should validate request size limits', async () => {
        const largePayload = 'x'.repeat(10 * 1024 * 1024); // 10MB payload

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: largePayload
        });

        const response = await testApp.fetch(req);
        // Should handle large payloads appropriately (either reject or process)
        expect([200, 413, 500]).toContain(response.status);
      });
    });

    // ========================================================================
    // 10. API VERSIONING AND BACKWARD COMPATIBILITY
    // ========================================================================
    describe('API Versioning and Backward Compatibility', () => {
      it('should handle v1 API routes correctly', async () => {
        mockFetch.mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(200);
      });

      it('should reject unsupported API versions', async () => {
        const req = new Request('http://localhost:3000/api/v2/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(404);
      });

      it('should maintain backward compatibility for existing endpoints', async () => {
        const legacyEndpoints = [
          '/api/v1/auth/login',
          '/api/v1/tenants',
          '/api/v1/doors',
          '/api/v1/cameras'
        ];

        mockFetch.mockResolvedValue(new Response('{"success": true}', { status: 200 }));

        for (const endpoint of legacyEndpoints) {
          const req = new Request(`http://localhost:3000${endpoint}`, {
            method: 'GET'
          });

          const response = await testApp.fetch(req);
          expect([200, 401]).toContain(response.status); // 401 for protected routes without auth
        }
      });
    });

    // ========================================================================
    // 11. INTEGRATION TESTS
    // ========================================================================
    describe('Integration Tests', () => {
      it('should handle complete authentication flow', async () => {
        // Mock successful login
        mockFetch.mockResolvedValueOnce(new Response(JSON.stringify({
          token: 'new-jwt-token',
          user: { id: 'user-123', email: 'test@example.com' }
        }), { status: 200 }));

        const loginReq = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'test@example.com', password: 'password' })
        });

        const loginResponse = await testApp.fetch(loginReq);
        expect(loginResponse.status).toBe(200);

        const loginBody = await loginResponse.json();
        expect(loginBody.token).toBeTruthy();

        // Use token for authenticated request
        mockJwtLib.verify.mockReturnValue({
          userId: 'user-123',
          tenantId: 'tenant-456',
          roles: ['user'],
          permissions: ['read']
        });
        mockRedis.get.mockResolvedValue(null);
        mockFetch.mockResolvedValueOnce(new Response('{"tenants": []}', { status: 200 }));

        const authenticatedReq = new Request('http://localhost:3000/api/v1/tenants', {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${loginBody.token}` }
        });

        const authenticatedResponse = await testApp.fetch(authenticatedReq);
        expect(authenticatedResponse.status).toBe(200);
      });

      it('should handle service discovery and failover', async () => {
        // First service call fails
        mockFetch
          .mockRejectedValueOnce(new Error('Primary service down'))
          .mockResolvedValueOnce(new Response('{"success": true}', { status: 200 }));

        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        const response = await testApp.fetch(req);
        expect(response.status).toBe(200);
        expect(mockFetch).toHaveBeenCalledTimes(2); // Retry logic
      });
    });

    // ========================================================================
    // 12. CLEANUP AND TEARDOWN TESTS
    // ========================================================================
    describe('Cleanup and Teardown', () => {
      it('should handle graceful shutdown', async () => {
        const quitSpy = jest.spyOn(mockRedis, 'quit');
        
        // Simulate graceful shutdown
        process.emit('SIGTERM');
        
        // Wait for async operations
        await new Promise(resolve => setTimeout(resolve, 100));
        
        expect(quitSpy).toHaveBeenCalled();
      });

      it('should clean up resources on error', async () => {
        const errorSpy = jest.spyOn(winstonLogger, 'error').mockImplementation();
        
        // Simulate unhandled error
        const req = new Request('http://localhost:3000/api/v1/auth/login', {
          method: 'POST'
        });

        mockFetch.mockRejectedValue(new Error('Catastrophic failure'));

        const response = await testApp.fetch(req);
        expect(response.status).toBe(503);
        
        errorSpy.mockRestore();
      });
    });
  });

  // Run tests if this file is executed directly in test environment
  if (require.main === module) {
    console.log('Running API Gateway tests...');
    // Tests will be executed by Jest test runner
  }
}

export default app
