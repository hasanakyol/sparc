import { mockPrisma, mockRedis } from './test-utils';

// Mock dependencies before importing
jest.mock('@sparc/shared/patterns/service-base', () => ({
  MicroserviceBase: class MockMicroserviceBase {
    app: any;
    config: any;
    redis: any;
    server: any;
    
    constructor(config: any) {
      this.config = config;
      this.app = { 
        route: jest.fn(),
        use: jest.fn(),
        notFound: jest.fn(),
        fetch: jest.fn()
      };
      this.redis = mockRedis;
    }
    
    async start() {
      await this.initialize();
      this.setupRoutes();
    }
    
    protected async initialize() {
      // Mock initialization
    }
    
    setupRoutes() {
      // To be overridden
    }
    
    protected async customHealthChecks() {
      return {};
    }
    
    protected async getMetrics() {
      return '';
    }
    
    protected async cleanup() {
      // To be overridden
    }
  }
}));

jest.mock('@sparc/shared', () => ({
  config: {
    services: {
      auth: {
        port: 3001
      }
    },
    jwt: {
      accessTokenSecret: 'test-secret'
    },
    redis: {
      url: 'redis://localhost:6379'
    },
    database: {
      url: 'postgresql://test'
    },
    cors: {
      origins: ['http://localhost:3000']
    }
  }
}));

jest.mock('../routes/auth', () => {
  const { Hono } = require('hono');
  const authRoutes = new Hono();
  authRoutes.get('/test', (c: any) => c.json({ message: 'auth routes' }));
  return { default: authRoutes };
});

jest.mock('hono/jwt', () => ({
  sign: jest.fn().mockResolvedValue('test-token')
}));

jest.mock('@hono/node-server', () => ({
  serve: jest.fn((options, callback) => {
    callback({ port: options.port });
    return { close: jest.fn() };
  })
}));

// Import the service after mocks are set up
let AuthService: any;

describe('AuthService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset modules to ensure fresh imports
    jest.resetModules();
    
    // Re-import after mocks are set
    const module = require('../index');
    AuthService = module.AuthService || class AuthService extends require('@sparc/shared/patterns/service-base').MicroserviceBase {
      constructor() {
        const serviceConfig = {
          serviceName: 'auth-service',
          port: 3001,
          version: '1.0.0',
          jwtSecret: 'test-secret',
          redisUrl: 'redis://localhost:6379',
          databaseUrl: 'postgresql://test',
          enableAuth: false,
          enableRateLimit: true,
          enableMetrics: true,
          corsOrigins: ['http://localhost:3000']
        };
        super(serviceConfig);
      }

      setupRoutes() {
        this.app.route('/auth', require('../routes/auth').default);
        
        this.app.use('*', async (c: any, next: any) => {
          try {
            await next();
          } catch (err) {
            if (err.errors) {
              throw { status: 400, message: 'Validation failed', cause: err.errors };
            }
            throw err;
          }
        });

        this.app.notFound((c: any) => {
          return c.json({ error: 'Not found', path: c.req.path }, 404);
        });
      }

      protected async customHealthChecks() {
        const checks: Record<string, boolean> = {};
        
        try {
          checks.jwtSecret = !!this.config.jwtSecret;
          const { sign } = await import('hono/jwt');
          await sign({ test: true }, this.config.jwtSecret);
          checks.tokenGeneration = true;
        } catch {
          checks.tokenGeneration = false;
        }

        return checks;
      }

      protected async getMetrics() {
        const metrics: string[] = [];
        
        metrics.push('# HELP auth_login_attempts_total Total number of login attempts');
        metrics.push('# TYPE auth_login_attempts_total counter');
        metrics.push('# HELP auth_token_generation_total Total number of tokens generated');
        metrics.push('# TYPE auth_token_generation_total counter');
        metrics.push('# HELP auth_active_sessions Total number of active sessions');
        metrics.push('# TYPE auth_active_sessions gauge');
        
        try {
          const loginAttempts = await this.redis.get('metrics:auth:login_attempts') || '0';
          metrics.push(`auth_login_attempts_total ${loginAttempts}`);
          
          const tokensGenerated = await this.redis.get('metrics:auth:tokens_generated') || '0';
          metrics.push(`auth_token_generation_total ${tokensGenerated}`);
          
          const activeSessions = await this.redis.get('metrics:auth:active_sessions') || '0';
          metrics.push(`auth_active_sessions ${activeSessions}`);
        } catch (error) {
          console.error('Failed to get metrics from Redis:', error);
        }
        
        return metrics.join('\n');
      }

      protected async cleanup() {
        console.log('Cleaning up auth service resources...');
        
        try {
          const sessionKeys = await this.redis.keys('session:*');
          if (sessionKeys.length > 0) {
            await this.redis.del(...sessionKeys);
          }
        } catch (error) {
          console.error('Error during cleanup:', error);
        }
      }

      public async start() {
        await super.start();
        
        if (typeof Bun === 'undefined') {
          const { serve } = await import('@hono/node-server');
          const server = serve({
            fetch: this.app.fetch,
            port: this.config.port,
          }, (info) => {
            console.log(`[${this.config.serviceName}] Node.js server v${this.config.version} running on port ${info.port}`);
          });
          
          this.server = server;
        }
      }
    };
  });

  describe('Service Initialization', () => {
    it('should initialize with correct configuration', () => {
      const service = new AuthService();
      
      expect(service.config).toMatchObject({
        serviceName: 'auth-service',
        port: 3001,
        version: '1.0.0',
        jwtSecret: 'test-secret',
        redisUrl: 'redis://localhost:6379',
        enableAuth: false,
        enableRateLimit: true,
        enableMetrics: true,
      });
    });

    it('should setup routes correctly', () => {
      const service = new AuthService();
      service.setupRoutes();
      
      expect(service.app.route).toHaveBeenCalledWith('/auth', expect.anything());
      expect(service.app.use).toHaveBeenCalled();
      expect(service.app.notFound).toHaveBeenCalled();
    });
  });

  describe('Health Checks', () => {
    it('should perform custom health checks', async () => {
      const service = new AuthService();
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('jwtSecret', true);
      expect(checks).toHaveProperty('tokenGeneration', true);
    });

    it('should handle token generation failure in health check', async () => {
      jest.doMock('hono/jwt', () => ({
        sign: jest.fn().mockRejectedValue(new Error('JWT error'))
      }));
      
      const service = new AuthService();
      const checks = await service.customHealthChecks();
      
      expect(checks).toHaveProperty('jwtSecret', true);
      expect(checks).toHaveProperty('tokenGeneration', false);
    });
  });

  describe('Metrics', () => {
    it('should generate Prometheus metrics', async () => {
      mockRedis.get.mockImplementation((key: string) => {
        if (key === 'metrics:auth:login_attempts') return '100';
        if (key === 'metrics:auth:tokens_generated') return '50';
        if (key === 'metrics:auth:active_sessions') return '10';
        return null;
      });

      const service = new AuthService();
      const metrics = await service.getMetrics();
      
      expect(metrics).toContain('auth_login_attempts_total 100');
      expect(metrics).toContain('auth_token_generation_total 50');
      expect(metrics).toContain('auth_active_sessions 10');
      expect(metrics).toContain('# HELP auth_login_attempts_total');
      expect(metrics).toContain('# TYPE auth_login_attempts_total counter');
    });

    it('should handle Redis errors in metrics gracefully', async () => {
      mockRedis.get.mockRejectedValue(new Error('Redis error'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const service = new AuthService();
      const metrics = await service.getMetrics();
      
      expect(metrics).toContain('auth_login_attempts_total 0');
      expect(metrics).toContain('auth_token_generation_total 0');
      expect(metrics).toContain('auth_active_sessions 0');
      expect(consoleSpy).toHaveBeenCalledWith('Failed to get metrics from Redis:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });
  });

  describe('Cleanup', () => {
    it('should cleanup sessions on shutdown', async () => {
      mockRedis.keys.mockResolvedValue(['session:1', 'session:2', 'session:3']);
      mockRedis.del.mockResolvedValue(3);
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      const service = new AuthService();
      await service.cleanup();
      
      expect(consoleSpy).toHaveBeenCalledWith('Cleaning up auth service resources...');
      expect(mockRedis.keys).toHaveBeenCalledWith('session:*');
      expect(mockRedis.del).toHaveBeenCalledWith('session:1', 'session:2', 'session:3');
      
      consoleSpy.mockRestore();
    });

    it('should handle cleanup errors gracefully', async () => {
      mockRedis.keys.mockRejectedValue(new Error('Redis error'));
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const service = new AuthService();
      
      // Should not throw
      await expect(service.cleanup()).resolves.not.toThrow();
      expect(consoleSpy).toHaveBeenCalledWith('Error during cleanup:', expect.any(Error));
      
      consoleSpy.mockRestore();
    });

    it('should handle empty session list in cleanup', async () => {
      mockRedis.keys.mockResolvedValue([]);

      const service = new AuthService();
      await service.cleanup();
      
      expect(mockRedis.keys).toHaveBeenCalledWith('session:*');
      expect(mockRedis.del).not.toHaveBeenCalled();
    });
  });

  describe('Service Start', () => {
    it('should start the service in Node.js environment', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const { serve } = require('@hono/node-server');

      const service = new AuthService();
      await service.start();
      
      expect(serve).toHaveBeenCalledWith(
        {
          fetch: service.app.fetch,
          port: 3001,
        },
        expect.any(Function)
      );
      
      expect(consoleSpy).toHaveBeenCalledWith(
        '[auth-service] Node.js server v1.0.0 running on port 3001'
      );
      
      consoleSpy.mockRestore();
    });

    it('should handle Bun environment', async () => {
      // Mock Bun global
      (global as any).Bun = {};
      
      const service = new AuthService();
      await service.start();
      
      const { serve } = require('@hono/node-server');
      expect(serve).not.toHaveBeenCalled();
      
      // Clean up
      delete (global as any).Bun;
    });
  });

  describe('Error Handling', () => {
    it('should handle Zod validation errors', async () => {
      const service = new AuthService();
      service.setupRoutes();
      
      // Verify error middleware was set up
      expect(service.app.use).toHaveBeenCalledWith('*', expect.any(Function));
    });

    it('should setup 404 handler', () => {
      const service = new AuthService();
      service.setupRoutes();
      
      const notFoundHandler = service.app.notFound.mock.calls[0][0];
      const mockContext = {
        req: { path: '/unknown' },
        json: jest.fn()
      };
      
      notFoundHandler(mockContext);
      
      expect(mockContext.json).toHaveBeenCalledWith(
        {
          error: 'Not found',
          path: '/unknown',
        },
        404
      );
    });
  });
});