import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { Context } from 'hono';
import { createClient } from 'redis';
import {
  RateLimiter,
  rateLimitMiddleware,
  customRateLimit,
  burstProtectionMiddleware,
  roleBasedRateLimit,
  tenantQuotaMiddleware,
  getRateLimiter,
  cleanupRateLimit,
  UserRole,
  TENANT_QUOTAS,
  ROLE_MULTIPLIERS,
  type RateLimitConfig,
  type RateLimitResult,
} from '../../middleware/rateLimit';

// Mock Redis
jest.mock('redis', () => ({
  createClient: jest.fn(),
}));

describe('Rate Limiting Middleware', () => {
  let mockContext: Context;
  let mockNext: jest.Mock;
  let mockRedisClient: any;

  beforeEach(() => {
    // Setup mock Redis client
    mockRedisClient = {
      connect: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
      get: jest.fn(),
      setEx: jest.fn(),
      del: jest.fn(),
      incr: jest.fn(),
      expire: jest.fn(),
      ttl: jest.fn(),
      hMGet: jest.fn(),
      hMSet: jest.fn(),
      zRemRangeByScore: jest.fn(),
      zAdd: jest.fn(),
      zCard: jest.fn(),
      zCount: jest.fn(),
      zRevRange: jest.fn(),
      multi: jest.fn(),
      quit: jest.fn(),
    };

    // Mock multi command
    const mockMulti = {
      incr: jest.fn().mockReturnThis(),
      expire: jest.fn().mockReturnThis(),
      ttl: jest.fn().mockReturnThis(),
      zRemRangeByScore: jest.fn().mockReturnThis(),
      zAdd: jest.fn().mockReturnThis(),
      zCard: jest.fn().mockReturnThis(),
      hMSet: jest.fn().mockReturnThis(),
      exec: jest.fn().mockResolvedValue([1, true, 60]),
    };
    mockRedisClient.multi.mockReturnValue(mockMulti);

    (createClient as jest.Mock).mockReturnValue(mockRedisClient);

    // Setup mock context
    mockContext = {
      req: {
        header: jest.fn(),
        path: '/api/test',
        method: 'GET',
      },
      header: jest.fn(),
      json: jest.fn().mockReturnValue({ json: true }),
      get: jest.fn(),
    } as any;

    mockNext = jest.fn().mockResolvedValue(undefined);

    // Clear singleton instance
    cleanupRateLimit();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('RateLimiter Class', () => {
    it('should initialize with Redis connection', async () => {
      const limiter = new RateLimiter();
      
      // Give time for async initialization
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(createClient).toHaveBeenCalledWith({ url: 'redis://localhost:6379' });
      expect(mockRedisClient.connect).toHaveBeenCalled();
    });

    it('should handle Redis connection errors gracefully', async () => {
      mockRedisClient.connect.mockRejectedValue(new Error('Connection failed'));
      
      const limiter = new RateLimiter();
      await new Promise(resolve => setTimeout(resolve, 10));

      // Should not throw error
      expect(mockRedisClient.on).toHaveBeenCalledWith('error', expect.any(Function));
    });

    it('should find matching rule for path', () => {
      const limiter = new RateLimiter();
      
      // Test authentication endpoint
      mockContext.req.path = '/api/auth/login';
      const authRule = limiter['findMatchingRule'](mockContext.req.path);
      expect(authRule.config.maxRequests).toBe(5); // Strict limit for auth

      // Test admin endpoint
      mockContext.req.path = '/api/admin/users';
      const adminRule = limiter['findMatchingRule'](mockContext.req.path);
      expect(adminRule.config.maxRequests).toBe(50);

      // Test video streaming endpoint
      mockContext.req.path = '/api/video/stream/123';
      const videoRule = limiter['findMatchingRule'](mockContext.req.path);
      expect(videoRule.config.maxRequests).toBe(1000); // High limit for video

      // Test general API endpoint
      mockContext.req.path = '/api/users';
      const generalRule = limiter['findMatchingRule'](mockContext.req.path);
      expect(generalRule.config.maxRequests).toBe(200);
    });

    it('should extract identifiers from context', () => {
      const limiter = new RateLimiter();

      // With authenticated user
      mockContext.get = jest.fn((key) => {
        if (key === 'user') {
          return {
            id: 'user-123',
            role: UserRole.USER,
          };
        }
        if (key === 'tenant') {
          return {
            id: 'tenant-456',
            tier: 'premium',
          };
        }
        return null;
      });
      mockContext.req.header = jest.fn((header) => {
        if (header === 'x-forwarded-for') return '192.168.1.1';
        return null;
      });

      const identifiers = limiter['extractIdentifiers'](mockContext);
      
      expect(identifiers).toEqual({
        userId: 'user-123',
        tenantId: 'tenant-456',
        userRole: UserRole.USER,
        tenantTier: 'premium',
        ip: '192.168.1.1',
      });
    });

    it('should apply role multipliers correctly', () => {
      const limiter = new RateLimiter();
      const baseConfig: RateLimitConfig = {
        windowMs: 60000,
        maxRequests: 100,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
        keyPrefix: 'rl:',
        strategy: 'sliding_window',
      };
      const rule = {
        pattern: '/api/test',
        config: baseConfig,
        priority: 10,
      };

      // Test different user roles
      const guestConfig = limiter['getEffectiveConfig'](baseConfig, rule, UserRole.GUEST);
      expect(guestConfig.maxRequests).toBe(50); // 50% of base

      const userConfig = limiter['getEffectiveConfig'](baseConfig, rule, UserRole.USER);
      expect(userConfig.maxRequests).toBe(100); // 100% of base

      const adminConfig = limiter['getEffectiveConfig'](baseConfig, rule, UserRole.ADMIN);
      expect(adminConfig.maxRequests).toBe(200); // 200% of base

      const superAdminConfig = limiter['getEffectiveConfig'](baseConfig, rule, UserRole.SUPER_ADMIN);
      expect(superAdminConfig.maxRequests).toBe(500); // 500% of base
    });

    it('should apply tenant tier multipliers correctly', () => {
      const limiter = new RateLimiter();
      const baseConfig: RateLimitConfig = {
        windowMs: 60000,
        maxRequests: 100,
        skipSuccessfulRequests: false,
        skipFailedRequests: false,
        keyPrefix: 'rl:',
        strategy: 'sliding_window',
      };
      const rule = {
        pattern: '/api/test',
        config: baseConfig,
        priority: 10,
      };

      // Test different tenant tiers
      const freeConfig = limiter['getEffectiveConfig'](baseConfig, rule, UserRole.USER, 'free');
      expect(freeConfig.maxRequests).toBe(150); // 100 * 1.5

      const premiumConfig = limiter['getEffectiveConfig'](baseConfig, rule, UserRole.USER, 'premium');
      expect(premiumConfig.maxRequests).toBe(300); // 100 * 3.0

      const enterpriseConfig = limiter['getEffectiveConfig'](baseConfig, rule, UserRole.USER, 'enterprise');
      expect(enterpriseConfig.maxRequests).toBe(500); // 100 * 5.0
    });

    describe('Rate Limiting Strategies', () => {
      it('should implement sliding window strategy', async () => {
        const limiter = new RateLimiter();
        const config: RateLimitConfig = {
          windowMs: 60000,
          maxRequests: 10,
          skipSuccessfulRequests: false,
          skipFailedRequests: false,
          keyPrefix: 'rl:',
          strategy: 'sliding_window',
        };

        // Mock Redis responses for sliding window
        mockRedisClient.multi.mockReturnValue({
          zRemRangeByScore: jest.fn().mockReturnThis(),
          zAdd: jest.fn().mockReturnThis(),
          zCard: jest.fn().mockReturnThis(),
          expire: jest.fn().mockReturnThis(),
          exec: jest.fn().mockResolvedValue([null, null, 5, true]), // 5 requests in window
        });

        const result = await limiter['checkSlidingWindow']('test-key', config);

        expect(result).toEqual({
          allowed: true,
          limit: 10,
          remaining: 5,
          resetTime: expect.any(Number),
        });
      });

      it('should implement fixed window strategy', async () => {
        const limiter = new RateLimiter();
        const config: RateLimitConfig = {
          windowMs: 60000,
          maxRequests: 10,
          skipSuccessfulRequests: false,
          skipFailedRequests: false,
          keyPrefix: 'rl:',
          strategy: 'fixed_window',
        };

        // Mock Redis responses for fixed window
        mockRedisClient.multi.mockReturnValue({
          incr: jest.fn().mockReturnThis(),
          expire: jest.fn().mockReturnThis(),
          ttl: jest.fn().mockReturnThis(),
          exec: jest.fn().mockResolvedValue([3, true, 45]), // 3 requests, 45s TTL
        });

        const result = await limiter['checkFixedWindow']('test-key', config);

        expect(result).toEqual({
          allowed: true,
          limit: 10,
          remaining: 7,
          resetTime: expect.any(Number),
        });
      });

      it('should implement token bucket strategy', async () => {
        const limiter = new RateLimiter();
        const config: RateLimitConfig = {
          windowMs: 60000,
          maxRequests: 10,
          burstLimit: 20,
          skipSuccessfulRequests: false,
          skipFailedRequests: false,
          keyPrefix: 'rl:',
          strategy: 'token_bucket',
        };

        // Mock Redis responses for token bucket
        mockRedisClient.hMGet.mockResolvedValue(['15', Date.now().toString()]);
        mockRedisClient.multi.mockReturnValue({
          hMSet: jest.fn().mockReturnThis(),
          expire: jest.fn().mockReturnThis(),
          exec: jest.fn().mockResolvedValue([true, true]),
        });

        const result = await limiter['checkTokenBucket']('test-key', config);

        expect(result).toEqual({
          allowed: true,
          limit: 20, // burst limit
          remaining: expect.any(Number),
          resetTime: expect.any(Number),
        });
      });

      it('should block requests when rate limit exceeded', async () => {
        const limiter = new RateLimiter();
        const config: RateLimitConfig = {
          windowMs: 60000,
          maxRequests: 10,
          skipSuccessfulRequests: false,
          skipFailedRequests: false,
          keyPrefix: 'rl:',
          strategy: 'fixed_window',
        };

        // Mock Redis responses showing limit exceeded
        mockRedisClient.multi.mockReturnValue({
          incr: jest.fn().mockReturnThis(),
          expire: jest.fn().mockReturnThis(),
          ttl: jest.fn().mockReturnThis(),
          exec: jest.fn().mockResolvedValue([11, true, 30]), // 11 requests (over limit)
        });

        const result = await limiter['checkFixedWindow']('test-key', config);

        expect(result).toEqual({
          allowed: false,
          limit: 10,
          remaining: 0,
          resetTime: expect.any(Number),
          retryAfter: 30,
        });
      });
    });

    describe('Tenant Quota Management', () => {
      it('should check tenant daily quota', async () => {
        const limiter = new RateLimiter();
        const today = new Date().toISOString().split('T')[0];

        // Under quota
        mockRedisClient.get.mockResolvedValue('5000');
        const allowed = await limiter['checkTenantDailyQuota']('tenant-123', 'premium');
        expect(allowed).toBe(true);

        // Over quota
        mockRedisClient.get.mockResolvedValue('1000001');
        const blocked = await limiter['checkTenantDailyQuota']('tenant-123', 'premium');
        expect(blocked).toBe(false);
      });

      it('should increment tenant daily quota', async () => {
        const limiter = new RateLimiter();
        const today = new Date().toISOString().split('T')[0];

        mockRedisClient.multi.mockReturnValue({
          incr: jest.fn().mockReturnThis(),
          expire: jest.fn().mockReturnThis(),
          exec: jest.fn().mockResolvedValue([1, true]),
        });

        await limiter['incrementTenantDailyQuota']('tenant-123');

        expect(mockRedisClient.multi).toHaveBeenCalled();
      });
    });
  });

  describe('rateLimitMiddleware', () => {
    it('should allow requests within rate limit', async () => {
      const middleware = rateLimitMiddleware();

      // Mock successful rate limit checks
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter, 'checkLimits').mockResolvedValue([
        {
          allowed: true,
          limit: 100,
          remaining: 95,
          resetTime: Date.now() + 60000,
        },
      ]);

      await middleware(mockContext, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockContext.header).toHaveBeenCalledWith('X-RateLimit-Limit', '100');
      expect(mockContext.header).toHaveBeenCalledWith('X-RateLimit-Remaining', '95');
      expect(mockContext.header).toHaveBeenCalledWith('X-RateLimit-Policy', 'sliding-window');
    });

    it('should block requests exceeding rate limit', async () => {
      const middleware = rateLimitMiddleware();

      // Mock rate limit exceeded
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter, 'checkLimits').mockResolvedValue([
        {
          allowed: false,
          limit: 100,
          remaining: 0,
          resetTime: Date.now() + 60000,
          retryAfter: 60,
        },
      ]);

      await middleware(mockContext, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Rate limit exceeded',
          message: 'Too many requests. Please try again later.',
          retryAfter: 60,
          type: 'rate_limit_exceeded',
        }),
        429
      );
      expect(mockContext.header).toHaveBeenCalledWith('Retry-After', '60');
    });

    it('should handle daily quota exceeded', async () => {
      const middleware = rateLimitMiddleware();

      // Mock daily quota exceeded
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter, 'checkLimits').mockResolvedValue([
        {
          allowed: false,
          limit: 1000000,
          remaining: 0,
          resetTime: Date.now() + 86400000, // 24 hours
          retryAfter: 86400, // 24 hours in seconds
        },
      ]);

      await middleware(mockContext, mockNext);

      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Daily quota exceeded',
          message: 'Daily request quota has been exceeded. Please upgrade your plan or try again tomorrow.',
          type: 'quota_exceeded',
        }),
        429
      );
    });

    it('should apply most restrictive limit from multiple checks', async () => {
      const middleware = rateLimitMiddleware();

      // Mock multiple rate limit checks with different results
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter, 'checkLimits').mockResolvedValue([
        {
          allowed: true,
          limit: 200,
          remaining: 150,
          resetTime: Date.now() + 60000,
        },
        {
          allowed: false, // This one is more restrictive
          limit: 50,
          remaining: 0,
          resetTime: Date.now() + 30000,
          retryAfter: 30,
        },
        {
          allowed: true,
          limit: 1000,
          remaining: 800,
          resetTime: Date.now() + 60000,
        },
      ]);

      await middleware(mockContext, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Rate limit exceeded',
          limit: 50,
          remaining: 0,
        }),
        429
      );
    });

    it('should handle Redis connection errors gracefully', async () => {
      const middleware = rateLimitMiddleware();

      // Mock error in rate limit check
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter, 'checkLimits').mockRejectedValue(new Error('Redis error'));

      await middleware(mockContext, mockNext);

      // Should allow request on error
      expect(mockNext).toHaveBeenCalled();
      expect(mockContext.json).not.toHaveBeenCalled();
    });
  });

  describe('customRateLimit', () => {
    it('should apply custom rate limit configuration', async () => {
      const customConfig = {
        windowMs: 300000, // 5 minutes
        maxRequests: 10,
        strategy: 'fixed_window' as const,
      };

      const middleware = customRateLimit(customConfig);

      // Mock successful rate limit check
      mockRedisClient.multi.mockReturnValue({
        incr: jest.fn().mockReturnThis(),
        expire: jest.fn().mockReturnThis(),
        ttl: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([5, true, 240]),
      });

      await middleware(mockContext, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockContext.header).toHaveBeenCalledWith('X-RateLimit-Limit', expect.any(String));
    });
  });

  describe('burstProtectionMiddleware', () => {
    it('should detect and block burst requests', async () => {
      const burstConfig = {
        maxBurstRequests: 5,
        burstWindowMs: 10000, // 10 seconds
        cooldownMs: 60000, // 1 minute
      };

      const middleware = burstProtectionMiddleware(burstConfig);

      // Mock burst detection
      mockRedisClient.zCount.mockResolvedValue(6); // Over burst limit
      mockRedisClient.zRevRange.mockResolvedValue([
        { value: 'timestamp', score: Date.now() - 5000 }, // 5 seconds ago
      ]);

      await middleware(mockContext, mockNext);

      expect(mockNext).not.toHaveBeenCalled();
      expect(mockContext.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Burst protection activated',
          type: 'burst_protection',
        }),
        429
      );
      expect(mockContext.header).toHaveBeenCalledWith('X-Burst-Protection', 'active');
    });

    it('should allow requests after cooldown period', async () => {
      const burstConfig = {
        maxBurstRequests: 5,
        burstWindowMs: 10000,
        cooldownMs: 60000,
      };

      const middleware = burstProtectionMiddleware(burstConfig);

      // Mock burst detection with old timestamp (past cooldown)
      mockRedisClient.zCount.mockResolvedValue(6);
      mockRedisClient.zRevRange.mockResolvedValue([
        { value: 'timestamp', score: Date.now() - 120000 }, // 2 minutes ago
      ]);

      mockRedisClient.multi.mockReturnValue({
        zAdd: jest.fn().mockReturnThis(),
        zRemRangeByScore: jest.fn().mockReturnThis(),
        expire: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([true, true, true]),
      });

      await middleware(mockContext, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('roleBasedRateLimit', () => {
    it('should apply role-specific rate limits', async () => {
      const roleConfig = {
        [UserRole.GUEST]: {
          windowMs: 60000,
          maxRequests: 10,
          strategy: 'fixed_window' as const,
        },
        [UserRole.USER]: {
          windowMs: 60000,
          maxRequests: 50,
          strategy: 'fixed_window' as const,
        },
        [UserRole.ADMIN]: {
          windowMs: 60000,
          maxRequests: 200,
          strategy: 'fixed_window' as const,
        },
      };

      const middleware = roleBasedRateLimit(roleConfig);

      // Mock user with USER role
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter as any, 'extractIdentifiers').mockReturnValue({
        userId: 'user-123',
        userRole: UserRole.USER,
        ip: '192.168.1.1',
      });

      // Mock successful rate limit
      mockRedisClient.multi.mockReturnValue({
        incr: jest.fn().mockReturnThis(),
        expire: jest.fn().mockReturnThis(),
        ttl: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([25, true, 30]), // Half of USER limit
      });

      await middleware(mockContext, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockContext.header).toHaveBeenCalledWith('X-RateLimit-Role', UserRole.USER);
    });

    it('should skip middleware if role not configured', async () => {
      const roleConfig = {
        [UserRole.ADMIN]: {
          windowMs: 60000,
          maxRequests: 200,
          strategy: 'fixed_window' as const,
        },
      };

      const middleware = roleBasedRateLimit(roleConfig);

      // Mock user with unconfigured role
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter as any, 'extractIdentifiers').mockReturnValue({
        userId: 'user-123',
        userRole: UserRole.USER, // Not in roleConfig
        ip: '192.168.1.1',
      });

      await middleware(mockContext, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockContext.header).not.toHaveBeenCalledWith('X-RateLimit-Role', expect.any(String));
    });
  });

  describe('tenantQuotaMiddleware', () => {
    it('should add tenant quota headers', async () => {
      const middleware = tenantQuotaMiddleware();

      // Mock tenant context
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter as any, 'extractIdentifiers').mockReturnValue({
        tenantId: 'tenant-123',
        tenantTier: 'premium',
        ip: '192.168.1.1',
      });

      // Mock current usage
      const today = new Date().toISOString().split('T')[0];
      mockRedisClient.get.mockResolvedValue('500000'); // Half of premium quota

      await middleware(mockContext, mockNext);

      expect(mockContext.header).toHaveBeenCalledWith('X-Tenant-Tier', 'premium');
      expect(mockContext.header).toHaveBeenCalledWith('X-Daily-Quota-Limit', '1000000');
      expect(mockContext.header).toHaveBeenCalledWith('X-Daily-Quota-Used', '500000');
      expect(mockContext.header).toHaveBeenCalledWith('X-Daily-Quota-Remaining', '500000');
    });

    it('should add warning headers when approaching quota', async () => {
      const middleware = tenantQuotaMiddleware();

      // Mock tenant context
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter as any, 'extractIdentifiers').mockReturnValue({
        tenantId: 'tenant-123',
        tenantTier: 'basic',
        ip: '192.168.1.1',
      });

      // Mock high usage (85%)
      mockRedisClient.get.mockResolvedValue('85000');

      await middleware(mockContext, mockNext);

      expect(mockContext.header).toHaveBeenCalledWith('X-Quota-Warning', 'approaching-limit');
    });

    it('should add critical warning when near quota limit', async () => {
      const middleware = tenantQuotaMiddleware();

      // Mock tenant context
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter as any, 'extractIdentifiers').mockReturnValue({
        tenantId: 'tenant-123',
        tenantTier: 'free',
        ip: '192.168.1.1',
      });

      // Mock very high usage (96%)
      mockRedisClient.get.mockResolvedValue('9600');

      await middleware(mockContext, mockNext);

      expect(mockContext.header).toHaveBeenCalledWith('X-Quota-Warning', 'near-limit');
    });
  });

  describe('Integration Tests', () => {
    it('should handle authentication endpoint with strict limits', async () => {
      const middleware = rateLimitMiddleware();
      mockContext.req.path = '/api/auth/login';

      // Mock rate limit for auth endpoint
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter, 'checkLimits').mockResolvedValue([
        {
          allowed: true,
          limit: 5, // Strict auth limit
          remaining: 4,
          resetTime: Date.now() + 900000, // 15 minutes
        },
      ]);

      await middleware(mockContext, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockContext.header).toHaveBeenCalledWith('X-RateLimit-Limit', '5');
    });

    it('should handle video streaming endpoint with high limits', async () => {
      const middleware = rateLimitMiddleware();
      mockContext.req.path = '/api/video/stream/camera-123';

      // Mock rate limit for video endpoint
      const mockLimiter = getRateLimiter();
      jest.spyOn(mockLimiter, 'checkLimits').mockResolvedValue([
        {
          allowed: true,
          limit: 1000, // High video limit
          remaining: 950,
          resetTime: Date.now() + 60000,
        },
      ]);

      await middleware(mockContext, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockContext.header).toHaveBeenCalledWith('X-RateLimit-Limit', '1000');
    });
  });

  describe('Cleanup', () => {
    it('should cleanup Redis connection on shutdown', async () => {
      const limiter = getRateLimiter();
      await cleanupRateLimit();

      expect(mockRedisClient.quit).toHaveBeenCalled();
    });
  });
});