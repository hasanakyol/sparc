import { serve } from '@hono/node-server';
import { TestingInfrastructureService } from './service';
import { config } from '@sparc/shared';

const service = new TestingInfrastructureService({
  serviceName: 'testing-infrastructure-service',
  port: config.testingInfrastructure?.port || 3012,
  version: process.env.npm_package_version || '1.0.0',
  jwtSecret: config.auth.jwtSecret,
  redisUrl: config.redis.url,
  databaseUrl: config.database.url,
  enableAuth: false, // Testing infrastructure doesn't need auth for internal use
  enableRateLimit: true,
  enableMetrics: true,
  corsOrigins: config.cors.allowedOrigins,
});

// Override start method for Node.js environment
service.start = async function() {
  try {
    // Connect to database
    await this.prisma.$connect();
    console.log(`[${this.config.serviceName}] Connected to database`);

    // Setup routes
    this.setupRoutes();

    // Start server using @hono/node-server
    const server = serve({
      fetch: this.app.fetch,
      port: this.config.port,
      hostname: '0.0.0.0',
    });

    console.log(`[${this.config.serviceName}] Service v${this.config.version} running on port ${this.config.port}`);

    // Setup graceful shutdown
    const shutdown = async (signal: string) => {
      console.log(`[${this.config.serviceName}] ${signal} received, shutting down gracefully...`);
      
      try {
        // Disconnect from services
        await this.prisma.$disconnect();
        await this.redis.quit();

        // Custom cleanup
        await this.cleanup();

        console.log(`[${this.config.serviceName}] Shutdown complete`);
        process.exit(0);
      } catch (error) {
        console.error(`[${this.config.serviceName}] Error during shutdown:`, error);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    console.error(`[${this.config.serviceName}] Failed to start:`, error);
    process.exit(1);
  }
};

service.start();