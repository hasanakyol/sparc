import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { serve } from '@hono/node-server';
import { createElevatorRoutes } from './routes/elevators';
import { createDispatchRoutes } from './routes/dispatch';
import { createWebhookRoutes } from './routes/webhooks';
import { createIntegrationRoutes } from './routes/integrations';
import { ElevatorService } from './services/elevator-service';
import { AccessControlIntegration } from './services/access-control-integration';
import { AlertServiceIntegration } from './services/alert-service-integration';
import { DestinationDispatchService } from './services/destination-dispatch-service';
import { ConsoleLogger } from './utils/logger';

// Service-specific configuration interface
interface ElevatorControlConfig extends ServiceConfig {
  alertServiceUrl: string;
  accessControlServiceUrl: string;
  elevatorSimulatorMode: boolean;
  defaultTimeout: number;
  maxRetries: number;
}

class ElevatorControlService extends MicroserviceBase {
  private logger: ConsoleLogger;
  private elevatorService: ElevatorService;
  private accessControl: AccessControlIntegration;
  private alertService: AlertServiceIntegration;
  private dispatchService: DestinationDispatchService;
  private server: any;

  constructor(config: ElevatorControlConfig) {
    super(config);
    this.logger = new ConsoleLogger('elevator-control-service');
    
    // Initialize services
    this.elevatorService = new ElevatorService(
      this.prisma,
      this.redis,
      this.logger,
      {
        alertServiceUrl: config.alertServiceUrl,
        accessControlServiceUrl: config.accessControlServiceUrl
      }
    );

    this.accessControl = new AccessControlIntegration(
      config.accessControlServiceUrl,
      this.logger
    );

    this.alertService = new AlertServiceIntegration(
      config.alertServiceUrl,
      this.logger
    );

    this.dispatchService = new DestinationDispatchService(
      this.prisma,
      this.redis,
      this.logger
    );
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    // Check connectivity to dependent services
    try {
      const response = await fetch(`${(this.config as ElevatorControlConfig).alertServiceUrl}/health`, {
        signal: AbortSignal.timeout(3000)
      });
      checks.alert_service = response.ok;
    } catch {
      checks.alert_service = false;
    }

    try {
      const response = await fetch(`${(this.config as ElevatorControlConfig).accessControlServiceUrl}/health`, {
        signal: AbortSignal.timeout(3000)
      });
      checks.access_control_service = response.ok;
    } catch {
      checks.access_control_service = false;
    }

    // Check if we have any connected elevators
    try {
      const elevatorCount = await this.prisma.elevatorControl.count();
      checks.elevator_configured = elevatorCount > 0;
    } catch {
      checks.elevator_configured = false;
    }

    return checks;
  }

  public setupRoutes(): void {
    // Mount elevator routes
    const elevatorRoutes = createElevatorRoutes(
      this.prisma,
      this.redis,
      this.logger,
      this.elevatorService,
      this.accessControl,
      this.alertService,
      this.dispatchService
    );
    this.app.route('/api/elevators', elevatorRoutes);

    // Mount dispatch routes
    const dispatchRoutes = createDispatchRoutes(
      this.prisma,
      this.logger,
      this.elevatorService,
      this.accessControl,
      this.dispatchService
    );
    this.app.route('/api/buildings', dispatchRoutes);

    // Mount webhook routes (no auth required)
    const webhookRoutes = createWebhookRoutes(
      this.prisma,
      this.redis,
      this.logger,
      this.alertService
    );
    this.app.route('/api/webhooks', webhookRoutes);

    // Mount integration routes
    const integrationRoutes = createIntegrationRoutes(
      this.prisma,
      this.logger,
      this.accessControl
    );
    this.app.route('/api/integrations', integrationRoutes);

    // Service info endpoint
    this.app.get('/info', (c) => {
      return c.json({
        service: 'elevator-control-service',
        version: this.config.version,
        simulatorMode: (this.config as ElevatorControlConfig).elevatorSimulatorMode,
        endpoints: [
          'GET /api/elevators - List elevators',
          'GET /api/elevators/:id - Get elevator details',
          'POST /api/elevators - Create elevator',
          'PUT /api/elevators/:id - Update elevator',
          'DELETE /api/elevators/:id - Delete elevator',
          'POST /api/elevators/:id/access - Request floor access',
          'POST /api/elevators/:id/emergency - Emergency override',
          'GET /api/elevators/:id/status - Get elevator status',
          'GET /api/elevators/:id/diagnostics - Get diagnostics',
          'POST /api/elevators/:id/maintenance - Set maintenance mode',
          'POST /api/elevators/:id/reset - Reset elevator',
          'POST /api/buildings/:id/dispatch - Destination dispatch',
          'GET /api/buildings/:id/elevators/status - Building elevator status',
          'POST /api/integrations/access-control/sync - Sync access control',
          'POST /api/integrations/test-connections - Test elevator connections',
          'POST /api/webhooks/elevator-events - Elevator event webhook',
        ],
      });
    });
  }

  protected async cleanup(): Promise<void> {
    this.logger.info('Cleaning up elevator control service...');
    
    // Cleanup elevator service connections
    await this.elevatorService.cleanup();
    
    this.logger.info('Elevator control service cleanup completed');
  }

  // Override start method for Node.js server
  public async start(): Promise<void> {
    try {
      // Connect to database
      await this.prisma.$connect();
      this.logger.info('Connected to database');

      // Setup routes
      this.setupRoutes();

      // Start Node.js server
      this.server = serve({
        fetch: this.app.fetch,
        port: this.config.port,
        hostname: '0.0.0.0',
      });

      this.logger.info(`Elevator control service v${this.config.version} running on port ${this.config.port}`);
      
      if ((this.config as ElevatorControlConfig).elevatorSimulatorMode) {
        this.logger.info('Running in SIMULATOR MODE - using mock elevator responses');
      }

      // Setup graceful shutdown
      this.setupGracefulShutdown();
    } catch (error) {
      this.logger.error('Failed to start elevator control service', { error: error.message });
      process.exit(1);
    }
  }

  private setupGracefulShutdown(): void {
    const shutdown = async (signal: string) => {
      this.logger.info(`${signal} received, shutting down gracefully...`);
      
      try {
        // Close server
        if (this.server) {
          this.server.close();
        }

        // Disconnect from services
        await this.prisma.$disconnect();
        await this.redis.quit();

        // Custom cleanup
        await this.cleanup();

        this.logger.info('Shutdown complete');
        process.exit(0);
      } catch (error) {
        this.logger.error('Error during shutdown', { error: error.message });
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }
}

// Configuration
const config: ElevatorControlConfig = {
  serviceName: 'elevator-control-service',
  port: parseInt(process.env.PORT || '3017'),
  version: process.env.npm_package_version || '1.0.0',
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/sparc',
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  enableAuth: true,
  enableRateLimit: true,
  enableMetrics: true,
  alertServiceUrl: process.env.ALERT_SERVICE_URL || 'http://alert-service:3012',
  accessControlServiceUrl: process.env.ACCESS_CONTROL_SERVICE_URL || 'http://access-control-service:3003',
  elevatorSimulatorMode: process.env.ELEVATOR_SIMULATOR_MODE === 'true',
  defaultTimeout: parseInt(process.env.DEFAULT_TIMEOUT || '5000'),
  maxRetries: parseInt(process.env.MAX_RETRIES || '3'),
};

// Create and start the service
const service = new ElevatorControlService(config);
service.start().catch(console.error);

export default service;