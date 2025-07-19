import { serve } from '@hono/node-server';
import { ReportingService } from './services/main-service';
import { config } from './config';

// Create and start the service
const service = new ReportingService(config);

// Override start method for Node.js environment
service.start = async function() {
  try {
    // Connect to database
    await this.prisma.$connect();
    console.log(`[${this.config.serviceName}] Connected to database`);

    // Initialize services
    await this.initialize();

    // Setup routes
    this.setupRoutes();

    // Start HTTP server
    const server = serve({
      fetch: this.app.fetch,
      port: this.config.port
    });

    console.log(`[${this.config.serviceName}] Service v${this.config.version} running on port ${this.config.port}`);

    // Setup graceful shutdown
    const shutdown = async (signal: string) => {
      console.log(`[${this.config.serviceName}] ${signal} received, shutting down gracefully...`);
      
      try {
        // Stop accepting new requests
        server.close();

        // Cleanup resources
        await this.cleanup();
        await this.prisma.$disconnect();
        await this.redis.quit();

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
}.bind(service);

// Start the service
service.start().catch(console.error);

export default service;