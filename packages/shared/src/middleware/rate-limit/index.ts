/**
 * Rate Limiting Middleware for SPARC Platform
 * Exports both basic and enhanced rate limiting functionality
 */

// Export basic rate limiting from existing module
export * from '../rate-limit';

// Export enhanced rate limiting
export * from './enhanced-rate-limit';

// Re-export commonly used configurations
import Redis from 'ioredis';
import {
  createEnhancedRateLimiter,
  createAuthRateLimiter,
  createApiRateLimiter,
  createVideoStreamRateLimiter,
  createIncidentRateLimiter,
  RateLimitStrategy,
  RateLimitConfig,
  TenantQuota,
  EndpointLimit
} from './enhanced-rate-limit';

/**
 * Default rate limiting configurations for SPARC services
 */
export const DEFAULT_RATE_LIMITS = {
  // API Gateway default limits
  api: {
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    strategy: RateLimitStrategy.SLIDING_WINDOW
  },
  
  // Authentication service limits
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    strategy: RateLimitStrategy.SLIDING_WINDOW,
    skipSuccessfulRequests: true
  },
  
  // Video streaming limits
  video: {
    live: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10,
      strategy: RateLimitStrategy.TOKEN_BUCKET
    },
    vod: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 50,
      strategy: RateLimitStrategy.TOKEN_BUCKET
    },
    download: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 5,
      strategy: RateLimitStrategy.LEAKY_BUCKET
    }
  },
  
  // Incident reporting limits
  incident: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20,
    strategy: RateLimitStrategy.ADAPTIVE
  },
  
  // Analytics service limits
  analytics: {
    windowMs: 60 * 1000, // 1 minute
    max: 200,
    strategy: RateLimitStrategy.TOKEN_BUCKET,
    burst: 50,
    refillRate: 3
  }
};

/**
 * Default tenant quotas
 */
export const DEFAULT_TENANT_QUOTAS: Map<string, TenantQuota> = new Map([
  ['enterprise', {
    requests: 10000,
    windowMs: 60 * 60 * 1000, // 1 hour
    burst: 1000,
    priority: 'high'
  }],
  ['professional', {
    requests: 5000,
    windowMs: 60 * 60 * 1000, // 1 hour
    burst: 500,
    priority: 'normal'
  }],
  ['standard', {
    requests: 1000,
    windowMs: 60 * 60 * 1000, // 1 hour
    burst: 100,
    priority: 'normal'
  }],
  ['trial', {
    requests: 100,
    windowMs: 60 * 60 * 1000, // 1 hour
    burst: 10,
    priority: 'low'
  }]
]);

/**
 * Create rate limiters for all SPARC services
 */
export function createSparcRateLimiters(redis: Redis) {
  return {
    // Basic service limiters
    auth: createAuthRateLimiter(redis),
    api: createApiRateLimiter(redis),
    video: createVideoStreamRateLimiter(redis),
    incident: createIncidentRateLimiter(redis),
    
    // Enhanced limiters with custom configurations
    analytics: createEnhancedRateLimiter({
      redis,
      ...DEFAULT_RATE_LIMITS.analytics
    }),
    
    // Endpoint-specific limiters
    endpoints: {
      upload: createEnhancedRateLimiter({
        redis,
        strategy: RateLimitStrategy.LEAKY_BUCKET,
        windowMs: 60 * 60 * 1000,
        max: 100,
        message: 'Upload rate limit exceeded. Please try again later.',
        endpointLimits: new Map([
          ['video-upload', {
            pattern: /\/api\/videos\/upload/,
            max: 10,
            windowMs: 3600000,
            strategy: RateLimitStrategy.LEAKY_BUCKET
          }],
          ['document-upload', {
            pattern: /\/api\/documents\/upload/,
            max: 50,
            windowMs: 3600000,
            strategy: RateLimitStrategy.TOKEN_BUCKET
          }]
        ])
      }),
      
      search: createEnhancedRateLimiter({
        redis,
        strategy: RateLimitStrategy.TOKEN_BUCKET,
        windowMs: 60 * 1000,
        max: 30,
        burst: 10,
        refillRate: 0.5,
        message: 'Search rate limit exceeded. Please refine your search.'
      }),
      
      export: createEnhancedRateLimiter({
        redis,
        strategy: RateLimitStrategy.FIXED_WINDOW,
        windowMs: 24 * 60 * 60 * 1000, // 24 hours
        max: 10,
        message: 'Export limit reached. Please try again tomorrow.'
      })
    },
    
    // Tenant-aware limiter
    tenant: createEnhancedRateLimiter({
      redis,
      strategy: RateLimitStrategy.SLIDING_WINDOW,
      windowMs: 60 * 60 * 1000,
      max: 1000, // Default fallback
      tenantQuotas: DEFAULT_TENANT_QUOTAS,
      onQuotaExceeded: async (c, tenantId) => {
        // Log quota exceeded event
        console.warn(`Tenant quota exceeded: ${tenantId}`);
        // Could trigger alerts or notifications here
      }
    })
  };
}

/**
 * Utility to get rate limiter by service name
 */
export function getRateLimiterForService(
  redis: Redis,
  serviceName: string,
  config?: Partial<RateLimitConfig>
): ReturnType<typeof createEnhancedRateLimiter> {
  const defaultConfig = DEFAULT_RATE_LIMITS[serviceName as keyof typeof DEFAULT_RATE_LIMITS];
  
  if (!defaultConfig) {
    // Return a default rate limiter for unknown services
    return createEnhancedRateLimiter({
      redis,
      windowMs: 60 * 1000,
      max: 100,
      ...config
    });
  }
  
  return createEnhancedRateLimiter({
    redis,
    ...defaultConfig,
    ...config
  });
}