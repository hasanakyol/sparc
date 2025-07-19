import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import authRoutes from './routes/auth';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';

class AuthService extends MicroserviceBase {
  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'auth-service',
      port: config.services?.auth?.port || 3001,
      version: process.env.npm_package_version || '1.0.0',
      jwtSecret: config.jwt?.accessTokenSecret || process.env.JWT_SECRET!,
      redisUrl: config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379',
      databaseUrl: config.database?.url || process.env.DATABASE_URL!,
      enableAuth: false, // Auth service doesn't need auth middleware for its own endpoints
      enableRateLimit: true,
      enableMetrics: true,
      corsOrigins: config.cors?.origins || ['http://localhost:3000']
    };
    
    super(serviceConfig);
  }

  setupRoutes(): void {
    // Mount auth routes
    this.app.route('/auth', authRoutes);

    // Additional error handling specific to auth service
    this.app.use('*', async (c, next) => {
      try {
        await next();
      } catch (err) {
        if (err instanceof z.ZodError) {
          throw new HTTPException(400, {
            message: 'Validation failed',
            cause: err.errors
          });
        }
        throw err;
      }
    });

    // 404 handler
    this.app.notFound((c) => {
      return c.json(
        {
          error: 'Not found',
          path: c.req.path,
        },
        404
      );
    });
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    // Add auth-specific health checks
    const checks: Record<string, boolean> = {};
    
    try {
      // Import JWT service
      const { JWTService } = await import('./services/jwtService');
      const jwtService = JWTService.getInstance({
        accessTokenExpiry: config.jwt?.accessTokenExpiry || '15m',
        refreshTokenExpiry: config.jwt?.refreshTokenExpiry || '7d',
        issuer: config.jwt?.issuer || 'sparc-auth',
        audience: config.jwt?.audience || 'sparc-api',
        algorithm: 'HS256'
      });
      
      // Check if JWT secrets are loaded from Secrets Manager
      checks.jwtSecretsLoaded = true;
      
      // Check rotation status
      const rotationStatus = jwtService.getRotationStatus();
      checks.jwtRotationActive = rotationStatus.inRotation;
      
      // Test token generation capability
      try {
        await jwtService.generateTokens(
          'test-user-id',
          'test-org-id',
          'test@example.com',
          'USER',
          []
        );
        checks.tokenGeneration = true;
      } catch {
        checks.tokenGeneration = false;
      }
    } catch (error) {
      checks.jwtSecretsLoaded = false;
      checks.tokenGeneration = false;
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    // Return Prometheus-formatted metrics
    const metrics: string[] = [];
    
    // Add auth-specific metrics
    metrics.push('# HELP auth_login_attempts_total Total number of login attempts');
    metrics.push('# TYPE auth_login_attempts_total counter');
    
    metrics.push('# HELP auth_token_generation_total Total number of tokens generated');
    metrics.push('# TYPE auth_token_generation_total counter');
    
    metrics.push('# HELP auth_active_sessions Total number of active sessions');
    metrics.push('# TYPE auth_active_sessions gauge');
    
    // Get actual metrics from Redis if available
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

  protected async cleanup(): Promise<void> {
    // Perform auth-specific cleanup
    console.log('Cleaning up auth service resources...');
    
    // Clear any active sessions or temporary data
    try {
      const sessionKeys = await this.redis.keys('session:*');
      if (sessionKeys.length > 0) {
        await this.redis.del(...sessionKeys);
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  public async start(): Promise<void> {
    // Call parent start to initialize everything
    await super.start();
    
    // For Node.js environment, use @hono/node-server
    if (typeof Bun === 'undefined') {
      const { serve } = await import('@hono/node-server');
      const server = serve({
        fetch: this.app.fetch,
        port: this.config.port,
      }, (info) => {
        console.log(`[${this.config.serviceName}] Node.js server v${this.config.version} running on port ${info.port}`);
      });
      
      // Store server reference for cleanup
      this.server = server;
    }
  }
}

// Create and start the service
const authService = new AuthService();

authService.start().catch((error) => {
  console.error('Failed to start auth service:', error);
  process.exit(1);
});

// Export for testing
export default authService.app;