#!/usr/bin/env node
import { CronJob } from 'cron';
import { backupService, BackupType, BackupConfig } from '@sparc/shared/services/backup-service';
import { getPrismaClient } from '@sparc/shared/database/prisma';
import { logger } from '@sparc/shared/utils/logger';
import { config } from '@sparc/shared/config';

// Backup configurations for different environments
const backupConfigs: Record<string, BackupConfig> = {
  production: {
    type: BackupType.FULL,
    schedule: '0 3 * * *', // Daily at 3 AM
    retention: {
      daily: 7,
      weekly: 4,
      monthly: 12,
      yearly: 5,
    },
    encryption: true,
    compression: true,
    destination: {
      type: 'S3',
      bucket: process.env.BACKUP_BUCKET || 'sparc-backups-prod',
      region: process.env.AWS_REGION || 'us-east-1',
    },
  },
  staging: {
    type: BackupType.FULL,
    schedule: '0 4 * * *', // Daily at 4 AM
    retention: {
      daily: 3,
      weekly: 2,
      monthly: 3,
      yearly: 1,
    },
    encryption: true,
    compression: true,
    destination: {
      type: 'S3',
      bucket: process.env.BACKUP_BUCKET || 'sparc-backups-staging',
      region: process.env.AWS_REGION || 'us-east-1',
    },
  },
  development: {
    type: BackupType.FULL,
    schedule: '0 5 * * 0', // Weekly on Sunday at 5 AM
    retention: {
      daily: 1,
      weekly: 1,
      monthly: 1,
      yearly: 0,
    },
    encryption: false,
    compression: true,
    destination: {
      type: 'LOCAL',
      path: '/backups',
    },
  },
};

class BackupScheduler {
  private jobs: Map<string, CronJob> = new Map();
  private prisma = getPrismaClient();

  async start() {
    logger.info('Starting backup scheduler');

    // Load scheduled backups from database
    const scheduledBackups = await this.loadScheduledBackups();

    // Create cron jobs
    for (const backup of scheduledBackups) {
      this.scheduleBackupJob(backup);
    }

    // Schedule default system backup if not exists
    await this.ensureSystemBackup();

    // Monitor backup health
    this.startHealthMonitoring();

    logger.info(`Backup scheduler started with ${this.jobs.size} jobs`);
  }

  async stop() {
    logger.info('Stopping backup scheduler');

    // Stop all cron jobs
    for (const [jobId, job] of this.jobs) {
      job.stop();
      logger.info(`Stopped backup job: ${jobId}`);
    }

    this.jobs.clear();
  }

  private async loadScheduledBackups() {
    return this.prisma.backupJob.findMany({
      where: {
        status: { in: ['scheduled', 'running'] },
      },
    });
  }

  private scheduleBackupJob(backup: any) {
    const jobId = `${backup.tenantId}-${backup.backupType}`;
    
    // Don't duplicate jobs
    if (this.jobs.has(jobId)) {
      return;
    }

    const job = new CronJob(
      backup.schedule,
      async () => {
        await this.runBackup(backup);
      },
      null,
      true,
      'UTC'
    );

    this.jobs.set(jobId, job);
    logger.info(`Scheduled backup job: ${jobId}`, {
      schedule: backup.schedule,
      nextRun: job.nextDates(1),
    });
  }

  private async runBackup(backup: any) {
    const jobId = `${backup.tenantId}-${backup.backupType}`;
    logger.info(`Running backup job: ${jobId}`);

    try {
      // Update job status
      await this.prisma.backupJob.update({
        where: { id: backup.id },
        data: {
          status: 'running',
          lastRun: new Date(),
        },
      });

      // Get backup configuration
      const environment = config.environment;
      const backupConfig = backupConfigs[environment] || backupConfigs.development;

      // Override with stored configuration
      if (backup.storageLocation) {
        backupConfig.destination = JSON.parse(backup.storageLocation);
      }

      // Run backup
      const result = await backupService.createDatabaseBackup(
        backup.tenantId,
        backupConfig
      );

      // Update job with results
      await this.prisma.backupJob.update({
        where: { id: backup.id },
        data: {
          status: 'scheduled',
          nextRun: this.calculateNextRun(backup.schedule),
          backupSize: BigInt(result.size || 0),
        },
      });

      logger.info(`Backup job completed: ${jobId}`, {
        size: result.size,
        duration: result.endTime!.getTime() - result.startTime.getTime(),
      });

      // Send success notification
      await this.sendNotification('success', backup, result);

    } catch (error: any) {
      logger.error(`Backup job failed: ${jobId}`, error);

      // Update job status
      await this.prisma.backupJob.update({
        where: { id: backup.id },
        data: {
          status: 'scheduled',
          nextRun: this.calculateNextRun(backup.schedule),
        },
      });

      // Send failure notification
      await this.sendNotification('failure', backup, error);

      // Retry logic
      if (backup.retryCount < 3) {
        setTimeout(() => {
          this.runBackup({ ...backup, retryCount: (backup.retryCount || 0) + 1 });
        }, 15 * 60 * 1000); // Retry in 15 minutes
      }
    }
  }

  private async ensureSystemBackup() {
    const systemBackup = await this.prisma.backupJob.findFirst({
      where: {
        tenantId: 'system',
        backupType: BackupType.FULL,
      },
    });

    if (!systemBackup) {
      const environment = config.environment;
      const backupConfig = backupConfigs[environment] || backupConfigs.development;

      await backupService.scheduleBackup('system', backupConfig);
      
      // Reload scheduled backups
      const backups = await this.loadScheduledBackups();
      const newBackup = backups.find(b => b.tenantId === 'system');
      if (newBackup) {
        this.scheduleBackupJob(newBackup);
      }
    }
  }

  private startHealthMonitoring() {
    // Check backup health every hour
    setInterval(async () => {
      try {
        const tenants = await this.prisma.tenant.findMany({
          select: { id: true },
        });

        for (const tenant of tenants) {
          const health = await backupService.getBackupHealth(tenant.id);
          
          if (health.status === 'critical') {
            logger.error('Backup health critical', {
              tenantId: tenant.id,
              lastBackup: health.lastBackup,
            });
            
            await this.sendAlert('critical', tenant.id, health);
          } else if (health.status === 'warning') {
            logger.warn('Backup health warning', {
              tenantId: tenant.id,
              lastBackup: health.lastBackup,
            });
          }
        }
      } catch (error) {
        logger.error('Backup health check failed', error);
      }
    }, 60 * 60 * 1000); // Every hour
  }

  private calculateNextRun(schedule: string): Date {
    try {
      const job = new CronJob(schedule, () => {});
      const next = job.nextDate().toDate();
      job.stop();
      return next;
    } catch {
      // Default to tomorrow at 3 AM
      const next = new Date();
      next.setDate(next.getDate() + 1);
      next.setHours(3, 0, 0, 0);
      return next;
    }
  }

  private async sendNotification(
    type: 'success' | 'failure',
    backup: any,
    result: any
  ) {
    // Send email/Slack notification based on type
    logger.info(`Sending ${type} notification for backup`, {
      tenantId: backup.tenantId,
      type: backup.backupType,
    });

    // Implementation would depend on notification service
  }

  private async sendAlert(
    severity: string,
    tenantId: string,
    health: any
  ) {
    // Send critical alert
    logger.error('Sending backup alert', {
      severity,
      tenantId,
      health,
    });

    // Implementation would depend on alerting service
  }
}

// CLI commands
if (require.main === module) {
  const scheduler = new BackupScheduler();
  
  process.on('SIGINT', async () => {
    await scheduler.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await scheduler.stop();
    process.exit(0);
  });

  scheduler.start().catch(error => {
    logger.error('Failed to start backup scheduler', error);
    process.exit(1);
  });
}

export { BackupScheduler };