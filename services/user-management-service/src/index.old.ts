import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import { PermissionService } from './services/permissionService';
import userRoutes from './routes/users';
import roleRoutes from './routes/roles';
import permissionRoutes from './routes/permissions';
import profileRoutes from './routes/profile';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';

class UserManagementService extends MicroserviceBase {
  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'user-management-service',
      port: config.services?.userManagement?.port || 3010,
      version: process.env.npm_package_version || '1.0.0',
      jwtSecret: config.jwt?.accessTokenSecret || process.env.JWT_SECRET!,
      redisUrl: config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379',
      databaseUrl: config.database?.url || process.env.DATABASE_URL!,
      enableAuth: true, // User management requires authentication
      enableRateLimit: true,
      enableMetrics: true,
      corsOrigins: config.cors?.origins || ['http://localhost:3000']
    };
    
    super(serviceConfig);
  }

  setupRoutes(): void {
    // Add service context middleware
    this.app.use('*', async (c, next) => {
      // Make services available to routes
      c.set('services', {
        prisma: this.prisma,
        redis: this.redis
      });
      await next();
    });

    // API routes - all require authentication
    this.app.route('/api/users', userRoutes);
    this.app.route('/api/roles', roleRoutes);
    this.app.route('/api/permissions', permissionRoutes);
    this.app.route('/api/profile', profileRoutes);

    // Additional error handling specific to user management service
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
    // Add user-management-specific health checks
    const checks: Record<string, boolean> = {};
    
    try {
      // Check if we can query users table
      const userCount = await this.prisma.usersExtended.count();
      checks.userTable = true;
      
      // Check if we can query roles table
      const roleCount = await this.prisma.roles.count();
      checks.roleTable = true;
      
      // Check if we can query permissions table
      const permissionCount = await this.prisma.permissions.count();
      checks.permissionTable = true;
    } catch {
      checks.database = false;
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    // Return Prometheus-formatted metrics
    const metrics: string[] = [];
    
    // Add user-management-specific metrics
    metrics.push('# HELP user_management_total_users Total number of users');
    metrics.push('# TYPE user_management_total_users gauge');
    
    metrics.push('# HELP user_management_total_roles Total number of roles');
    metrics.push('# TYPE user_management_total_roles gauge');
    
    metrics.push('# HELP user_management_active_users Total number of active users');
    metrics.push('# TYPE user_management_active_users gauge');
    
    // Get actual metrics
    try {
      const totalUsers = await this.prisma.usersExtended.count();
      metrics.push(`user_management_total_users ${totalUsers}`);
      
      const totalRoles = await this.prisma.roles.count();
      metrics.push(`user_management_total_roles ${totalRoles}`);
      
      const activeUsers = await this.prisma.usersExtended.count({
        where: { deactivatedAt: null }
      });
      metrics.push(`user_management_active_users ${activeUsers}`);
    } catch (error) {
      console.error('Failed to get metrics from database:', error);
    }
    
    return metrics.join('\n');
  }

  protected async cleanup(): Promise<void> {
    // Perform user-management-specific cleanup
    console.log('Cleaning up user management service resources...');
    
    // Clear any caches
    try {
      const cacheKeys = await this.redis.keys('user:cache:*');
      if (cacheKeys.length > 0) {
        await this.redis.del(...cacheKeys);
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
const userManagementService = new UserManagementService();

userManagementService.start().catch((error) => {
  console.error('Failed to start user management service:', error);
  process.exit(1);
});

// Export for testing
export default userManagementService.app;