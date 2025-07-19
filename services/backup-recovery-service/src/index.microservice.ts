import { MicroserviceBase, ServiceConfig } from '@sparc/shared/patterns/service-base';
import { config } from '@sparc/shared';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';
import { createMainRoutes } from './routes/main';
import * as cron from 'node-cron';
import { serve } from '@hono/node-server';
import { 
  BackupClient, 
  ListBackupJobsCommand
} from '@aws-sdk/client-backup';
import { 
  RDSClient
} from '@aws-sdk/client-rds';
import { 
  S3Client
} from '@aws-sdk/client-s3';

class BackupRecoveryService extends MicroserviceBase {
  private backupScheduler?: cron.ScheduledTask;
  private retentionCleanupTask?: cron.ScheduledTask;
  private integrityCheckTask?: cron.ScheduledTask;
  private backupClient: BackupClient;
  private rdsClient: RDSClient;
  private s3Client: S3Client;

  constructor() {
    const serviceConfig: ServiceConfig = {
      serviceName: 'backup-recovery-service',
      port: config.services?.backupRecovery?.port || parseInt(process.env.PORT || '3017'),
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

    // Initialize AWS clients
    this.backupClient = new BackupClient({ 
      region: config.aws?.region || process.env.AWS_REGION || 'us-east-1' 
    });
    this.rdsClient = new RDSClient({ 
      region: config.aws?.region || process.env.AWS_REGION || 'us-east-1' 
    });
    this.s3Client = new S3Client({ 
      region: config.aws?.region || process.env.AWS_REGION || 'us-east-1' 
    });
  }

  setupRoutes(): void {
    // Mount main backup/recovery routes
    this.app.route('/api', createMainRoutes(this.prisma, this.redis, {
      ...this.config,
      awsClients: {
        backup: this.backupClient,
        rds: this.rdsClient,
        s3: this.s3Client
      }
    }));

    // Additional error handling specific to backup service
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
          service: 'backup-recovery-service'
        },
        404
      );
    });
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    
    try {
      // Check AWS Backup connectivity
      try {
        await this.backupClient.send(new ListBackupJobsCommand({
          MaxResults: 1
        }));
        checks.awsBackup = true;
      } catch {
        checks.awsBackup = false;
      }

      // Check backup job scheduling
      const scheduledJobs = await this.redis.get('backup:scheduled_jobs_count');
      checks.backupScheduler = scheduledJobs !== null && parseInt(scheduledJobs) > 0;

      // Check active backup operations
      const activeBackups = await this.redis.get('backup:active_operations');
      checks.activeBackupsHealthy = !activeBackups || parseInt(activeBackups) < 10;

      // Check retention policy enforcement
      const retentionCheck = await this.redis.get('backup:last_retention_check');
      if (retentionCheck) {
        const lastCheck = new Date(retentionCheck).getTime();
        const daysSinceCheck = (Date.now() - lastCheck) / (1000 * 60 * 60 * 24);
        checks.retentionPolicyActive = daysSinceCheck < 2; // Should run at least every 2 days
      } else {
        checks.retentionPolicyActive = false;
      }

      // Check backup storage availability
      const storageUsage = await this.redis.get('backup:storage_usage_percent');
      checks.storageAvailable = !storageUsage || parseInt(storageUsage) < 90;

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
    
    // Backup service specific metrics
    metrics.push('# HELP backup_jobs_total Total number of backup jobs created');
    metrics.push('# TYPE backup_jobs_total counter');
    
    metrics.push('# HELP backup_jobs_active Number of currently active backup jobs');
    metrics.push('# TYPE backup_jobs_active gauge');
    
    metrics.push('# HELP backup_jobs_failed_total Total number of failed backup jobs');
    metrics.push('# TYPE backup_jobs_failed_total counter');
    
    metrics.push('# HELP backup_storage_bytes Total backup storage used in bytes');
    metrics.push('# TYPE backup_storage_bytes gauge');
    
    metrics.push('# HELP recovery_operations_total Total number of recovery operations initiated');
    metrics.push('# TYPE recovery_operations_total counter');
    
    metrics.push('# HELP recovery_time_seconds Recovery time objective (RTO) in seconds');
    metrics.push('# TYPE recovery_time_seconds histogram');
    
    metrics.push('# HELP backup_retention_days Backup retention period in days by policy');
    metrics.push('# TYPE backup_retention_days gauge');
    
    // Get actual metrics from Redis
    try {
      const backupJobsTotal = await this.redis.get('metrics:backup:jobs_total') || '0';
      metrics.push(`backup_jobs_total ${backupJobsTotal}`);
      
      const activeJobs = await this.redis.get('metrics:backup:jobs_active') || '0';
      metrics.push(`backup_jobs_active ${activeJobs}`);
      
      const failedJobs = await this.redis.get('metrics:backup:jobs_failed') || '0';
      metrics.push(`backup_jobs_failed_total ${failedJobs}`);
      
      const storageUsed = await this.redis.get('metrics:backup:storage_bytes') || '0';
      metrics.push(`backup_storage_bytes ${storageUsed}`);
      
      const recoveryOps = await this.redis.get('metrics:backup:recovery_operations') || '0';
      metrics.push(`recovery_operations_total ${recoveryOps}`);
      
      // Get retention policies
      const retentionPolicies = await this.redis.keys('backup:retention_policy:*');
      for (const policy of retentionPolicies) {
        const days = await this.redis.get(policy);
        if (days) {
          const policyType = policy.split(':')[2];
          metrics.push(`backup_retention_days{policy="${policyType}"} ${days}`);
        }
      }
    } catch (error) {
      console.error('Failed to get metrics from Redis:', error);
    }
    
    return metrics.join('\n');
  }

  protected async cleanup(): Promise<void> {
    console.log('Cleaning up backup-recovery service resources...');
    
    // Stop scheduled tasks
    if (this.backupScheduler) {
      this.backupScheduler.stop();
    }
    if (this.retentionCleanupTask) {
      this.retentionCleanupTask.stop();
    }
    if (this.integrityCheckTask) {
      this.integrityCheckTask.stop();
    }

    // Complete any pending backup operations
    try {
      const pendingOps = await this.redis.keys('backup:operation:pending:*');
      if (pendingOps.length > 0) {
        console.log(`Marking ${pendingOps.length} pending operations as interrupted`);
        for (const op of pendingOps) {
          await this.redis.set(op.replace('pending', 'interrupted'), 'service_shutdown');
        }
      }

      // Notify other services about shutdown
      await this.publishEvent('service:shutdown', {
        timestamp: new Date().toISOString(),
        reason: 'graceful_shutdown'
      });
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  private startBackgroundTasks(): void {
    // Backup scheduler - runs every hour to check scheduled backups
    this.backupScheduler = cron.schedule('0 * * * *', async () => {
      try {
        await this.publishEvent('backup:schedule:check', {
          timestamp: new Date().toISOString(),
          task: 'scheduled_backup_check'
        });
      } catch (error) {
        console.error('Error in backup scheduler:', error);
      }
    });

    // Retention cleanup - runs daily at 3 AM
    this.retentionCleanupTask = cron.schedule('0 3 * * *', async () => {
      try {
        await this.publishEvent('backup:retention:cleanup', {
          timestamp: new Date().toISOString(),
          task: 'retention_policy_enforcement'
        });
        await this.redis.set('backup:last_retention_check', new Date().toISOString());
      } catch (error) {
        console.error('Error in retention cleanup task:', error);
      }
    });

    // Integrity check - runs weekly on Sundays at 4 AM
    this.integrityCheckTask = cron.schedule('0 4 * * 0', async () => {
      try {
        await this.publishEvent('backup:integrity:check', {
          timestamp: new Date().toISOString(),
          task: 'backup_integrity_verification'
        });
      } catch (error) {
        console.error('Error in integrity check task:', error);
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

    // Subscribe to backup events
    this.subscribeToEvent('backup:requested', async (data) => {
      // Handle backup requests from other services
      console.log('Backup requested:', data);
      await this.redis.incr('metrics:backup:jobs_total');
    });

    this.subscribeToEvent('recovery:requested', async (data) => {
      // Handle recovery requests
      console.log('Recovery requested:', data);
      await this.redis.incr('metrics:backup:recovery_operations');
    });

    this.subscribeToEvent('backup:completed', async (data) => {
      // Update metrics on backup completion
      if (data.success) {
        await this.redis.decr('metrics:backup:jobs_active');
        if (data.storageUsed) {
          await this.redis.incrby('metrics:backup:storage_bytes', data.storageUsed);
        }
      } else {
        await this.redis.incr('metrics:backup:jobs_failed');
      }
    });
  }
}

// Create and start the service
const backupRecoveryService = new BackupRecoveryService();

backupRecoveryService.start().catch((error) => {
  console.error('Failed to start backup-recovery service:', error);
  process.exit(1);
});

// Export for testing
export default backupRecoveryService.app;