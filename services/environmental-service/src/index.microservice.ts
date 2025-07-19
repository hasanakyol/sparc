import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { createMainRoutes } from './routes/main';
import * as cron from 'node-cron';
import { serve } from '@hono/node-server';

class EnvironmentalService extends MicroserviceBase {
  private sensorMonitoringTask?: cron.ScheduledTask;
  private alertCheckTask?: cron.ScheduledTask;
  private dataRetentionTask?: cron.ScheduledTask;

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'environmental-service',
      port: config.services?.environmental?.port || parseInt(process.env.PORT || '3014'),
      version: process.env.npm_package_version || '1.0.0',
      jwtSecret: config.jwt?.accessTokenSecret || process.env.JWT_SECRET!,
      redisUrl: config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379',
      databaseUrl: config.database?.url || process.env.DATABASE_URL!,
      enableAuth: true,
      enableRateLimit: true,
      enableMetrics: true,
      corsOrigins: config.cors?.origins || ['http://localhost:3000']
    };
    
    super(serviceConfig);
  }

  setupRoutes(): void {
    // Mount main environmental routes
    this.app.route('/api', createMainRoutes(this.prisma, this.redis, this.config));

    // Additional error handling specific to environmental service
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
          service: 'environmental-service'
        },
        404
      );
    });
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    try {
      // Check sensor data freshness
      const latestSensorData = await this.redis.get('environmental:latest_sensor_reading');
      if (latestSensorData) {
        const data = JSON.parse(latestSensorData);
        const dataAge = Date.now() - new Date(data.timestamp).getTime();
        // Data should be less than 5 minutes old
        checks.sensorDataFresh = dataAge < 5 * 60 * 1000;
      } else {
        checks.sensorDataFresh = false;
      }

      // Check MQTT connection (if configured)
      const mqttStatus = await this.redis.get('environmental:mqtt:connected');
      checks.mqttConnected = mqttStatus === 'true';

      // Check alert processing
      const alertQueueSize = await this.redis.llen('environmental:alert_queue');
      checks.alertQueueHealthy = alertQueueSize < 1000; // Queue should not be backed up

      // Check scheduled tasks
      checks.cronJobsRunning = !!(this.sensorMonitoringTask && this.alertCheckTask);

    } catch (error) {
      console.error('Error in custom health checks:', error);
      return {
        ...checks,
        healthCheckError: false
      };
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    const metrics: string[] = [];
    
    // Environmental service specific metrics
    metrics.push('# HELP environmental_sensor_readings_total Total number of sensor readings processed');
    metrics.push('# TYPE environmental_sensor_readings_total counter');
    
    metrics.push('# HELP environmental_alerts_triggered_total Total number of environmental alerts triggered');
    metrics.push('# TYPE environmental_alerts_triggered_total counter');
    
    metrics.push('# HELP environmental_sensor_errors_total Total number of sensor reading errors');
    metrics.push('# TYPE environmental_sensor_errors_total counter');
    
    metrics.push('# HELP environmental_active_sensors Number of active sensors');
    metrics.push('# TYPE environmental_active_sensors gauge');
    
    metrics.push('# HELP environmental_temperature_celsius Current temperature readings by sensor');
    metrics.push('# TYPE environmental_temperature_celsius gauge');
    
    metrics.push('# HELP environmental_humidity_percent Current humidity readings by sensor');
    metrics.push('# TYPE environmental_humidity_percent gauge');
    
    // Get actual metrics from Redis
    try {
      const sensorReadings = await this.redis.get('metrics:environmental:sensor_readings') || '0';
      metrics.push(`environmental_sensor_readings_total ${sensorReadings}`);
      
      const alertsTriggered = await this.redis.get('metrics:environmental:alerts_triggered') || '0';
      metrics.push(`environmental_alerts_triggered_total ${alertsTriggered}`);
      
      const sensorErrors = await this.redis.get('metrics:environmental:sensor_errors') || '0';
      metrics.push(`environmental_sensor_errors_total ${sensorErrors}`);
      
      const activeSensors = await this.redis.get('metrics:environmental:active_sensors') || '0';
      metrics.push(`environmental_active_sensors ${activeSensors}`);
      
      // Get current sensor readings
      const sensorKeys = await this.redis.keys('environmental:sensor:*:current');
      for (const key of sensorKeys) {
        const reading = await this.redis.get(key);
        if (reading) {
          const data = JSON.parse(reading);
          const sensorId = key.split(':')[2];
          if (data.temperature !== undefined) {
            metrics.push(`environmental_temperature_celsius{sensor_id="${sensorId}"} ${data.temperature}`);
          }
          if (data.humidity !== undefined) {
            metrics.push(`environmental_humidity_percent{sensor_id="${sensorId}"} ${data.humidity}`);
          }
        }
      }
    } catch (error) {
      console.error('Failed to get metrics from Redis:', error);
    }
    
    return metrics.join('\n');
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up environmental service resources...');
    
    // Stop scheduled tasks
    if (this.sensorMonitoringTask) {
      this.sensorMonitoringTask.stop();
    }
    if (this.alertCheckTask) {
      this.alertCheckTask.stop();
    }
    if (this.dataRetentionTask) {
      this.dataRetentionTask.stop();
    }

    // Clear any temporary data
    try {
      const tempKeys = await this.redis.keys('environmental:temp:*');
      if (tempKeys.length > 0) {
        await this.redis.del(...tempKeys);
      }

      // Disconnect from any protocol connections (Modbus, BACnet, etc.)
      await this.redis.publish('environmental:shutdown', JSON.stringify({
        timestamp: new Date().toISOString(),
        reason: 'service_shutdown'
      }));
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  private startBackgroundTasks(): void {
    // Sensor monitoring task - runs every 30 seconds
    this.sensorMonitoringTask = cron.schedule('*/30 * * * * *', async () => {
      try {
        await this.publishEvent('sensor:monitor', {
          timestamp: new Date().toISOString(),
          task: 'sensor_monitoring'
        });
      } catch (error) {
        console.error('Error in sensor monitoring task:', error);
      }
    });

    // Alert check task - runs every minute
    this.alertCheckTask = cron.schedule('* * * * *', async () => {
      try {
        await this.publishEvent('alert:check', {
          timestamp: new Date().toISOString(),
          task: 'alert_checking'
        });
      } catch (error) {
        console.error('Error in alert check task:', error);
      }
    });

    // Data retention cleanup - runs daily at 2 AM
    this.dataRetentionTask = cron.schedule('0 2 * * *', async () => {
      try {
        await this.publishEvent('data:cleanup', {
          timestamp: new Date().toISOString(),
          task: 'data_retention_cleanup'
        });
      } catch (error) {
        console.error('Error in data retention task:', error);
      }
    });

    console.log('Background tasks started');
  }

  public async start(): Promise<void> {
    // Call parent start to initialize everything
    await super.start();
    
    // Start background tasks
    this.startBackgroundTasks();

    // For Node.js environment, use @hono/node-server
    if (typeof Bun === 'undefined') {
      const server = serve({
        fetch: this.app.fetch,
        port: this.config.port,
      }, (info) => {
        console.log(`[${this.config.serviceName}] Node.js server v${this.config.version} running on port ${info.port}`);
      });
      
      // Store server reference for cleanup
      this.server = server;
    }

    // Subscribe to environmental events
    this.subscribeToEvent('sensor:data', (data) => {
      // Handle incoming sensor data
      console.log('Received sensor data:', data);
    });

    this.subscribeToEvent('alert:triggered', (data) => {
      // Handle triggered alerts
      console.log('Alert triggered:', data);
    });
  }
}

// Create and start the service
const environmentalService = new EnvironmentalService();

environmentalService.start().catch((error) => {
  console.error('Failed to start environmental service:', error);
  process.exit(1);
});

// Export for testing
export default environmentalService.app;