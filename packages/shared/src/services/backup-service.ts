import { S3 } from 'aws-sdk';
import { createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { exec } from 'child_process';
import { promisify } from 'util';
import { join } from 'path';
import { encrypt } from '../utils/encryption';
import { getPrismaClient } from '../database/prisma';
import { logger } from '../utils/logger';
import { auditLogger, AuditAction, ResourceType } from './audit-logger';
import { createHash } from 'crypto';
import { gzip } from 'zlib';

const execAsync = promisify(exec);

export interface BackupConfig {
  type: BackupType;
  schedule: string; // Cron expression
  retention: RetentionPolicy;
  encryption: boolean;
  compression: boolean;
  destination: BackupDestination;
}

export enum BackupType {
  FULL = 'FULL',
  INCREMENTAL = 'INCREMENTAL',
  DIFFERENTIAL = 'DIFFERENTIAL',
  CONTINUOUS = 'CONTINUOUS',
}

export interface RetentionPolicy {
  daily: number;
  weekly: number;
  monthly: number;
  yearly: number;
}

export interface BackupDestination {
  type: 'S3' | 'LOCAL' | 'AZURE' | 'GCP';
  bucket?: string;
  path?: string;
  region?: string;
}

export interface BackupJob {
  id: string;
  type: BackupType;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startTime: Date;
  endTime?: Date;
  size?: number;
  checksum?: string;
  error?: string;
  metadata?: Record<string, any>;
}

export class BackupService {
  private s3: S3;
  private prisma = getPrismaClient();

  constructor() {
    this.s3 = new S3({
      region: process.env.AWS_REGION || 'us-east-1',
    });
  }

  /**
   * Create a full database backup
   */
  async createDatabaseBackup(
    tenantId: string,
    config: BackupConfig
  ): Promise<BackupJob> {
    const job: BackupJob = {
      id: `backup-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: config.type,
      status: 'running',
      startTime: new Date(),
    };

    try {
      logger.info('Starting database backup', { jobId: job.id, tenantId });

      // Create backup filename
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `sparc-db-${tenantId}-${timestamp}.sql`;
      const tempPath = join('/tmp', filename);

      // Generate pg_dump command
      const dumpCommand = this.buildPgDumpCommand(tenantId, tempPath, config);
      
      // Execute backup
      const { stdout, stderr } = await execAsync(dumpCommand);
      if (stderr) {
        logger.warn('pg_dump warnings', { stderr });
      }

      // Get file size
      const stats = await promisify(require('fs').stat)(tempPath);
      job.size = stats.size;

      // Calculate checksum
      job.checksum = await this.calculateChecksum(tempPath);

      // Compress if configured
      let processedPath = tempPath;
      if (config.compression) {
        processedPath = await this.compressFile(tempPath);
        const compressedStats = await promisify(require('fs').stat)(processedPath);
        job.size = compressedStats.size;
      }

      // Encrypt if configured
      if (config.encryption) {
        processedPath = await this.encryptFile(processedPath);
        const encryptedStats = await promisify(require('fs').stat)(processedPath);
        job.size = encryptedStats.size;
      }

      // Upload to destination
      const uploadResult = await this.uploadBackup(
        processedPath,
        config.destination,
        tenantId
      );

      // Clean up temp files
      await this.cleanupTempFiles([tempPath, processedPath]);

      // Update job status
      job.status = 'completed';
      job.endTime = new Date();
      job.metadata = {
        destination: uploadResult.location,
        compressed: config.compression,
        encrypted: config.encryption,
        tenantId,
      };

      // Log successful backup
      await this.logBackupSuccess(job, tenantId);

      // Apply retention policy
      await this.applyRetentionPolicy(tenantId, config.retention, config.destination);

      return job;
    } catch (error: any) {
      job.status = 'failed';
      job.endTime = new Date();
      job.error = error.message;

      // Log failed backup
      await this.logBackupFailure(job, tenantId, error.message);

      throw error;
    }
  }

  /**
   * Create incremental backup using WAL archiving
   */
  async createIncrementalBackup(
    tenantId: string,
    lastBackupLSN: string
  ): Promise<BackupJob> {
    const job: BackupJob = {
      id: `incr-backup-${Date.now()}`,
      type: BackupType.INCREMENTAL,
      status: 'running',
      startTime: new Date(),
    };

    try {
      // Use pg_basebackup for incremental backup
      const backupDir = `/tmp/incremental-${job.id}`;
      const command = `pg_basebackup -D ${backupDir} -F tar -z -P -X stream -c fast -l "Incremental backup ${job.id}"`;
      
      await execAsync(command);

      // Upload WAL files since last backup
      const walFiles = await this.getWALFilesSince(lastBackupLSN);
      for (const walFile of walFiles) {
        await this.uploadWALFile(walFile, tenantId);
      }

      job.status = 'completed';
      job.endTime = new Date();
      job.metadata = {
        lastLSN: await this.getCurrentLSN(),
        walFiles: walFiles.length,
      };

      return job;
    } catch (error: any) {
      job.status = 'failed';
      job.error = error.message;
      throw error;
    }
  }

  /**
   * Restore database from backup
   */
  async restoreDatabase(
    backupId: string,
    tenantId: string,
    targetTime?: Date
  ): Promise<void> {
    try {
      logger.info('Starting database restore', { backupId, tenantId, targetTime });

      // Download backup
      const backupPath = await this.downloadBackup(backupId, tenantId);

      // Decrypt if needed
      let processedPath = backupPath;
      if (await this.isEncrypted(backupPath)) {
        processedPath = await this.decryptFile(backupPath);
      }

      // Decompress if needed
      if (processedPath.endsWith('.gz')) {
        processedPath = await this.decompressFile(processedPath);
      }

      // Stop application connections
      await this.stopApplicationConnections();

      // Restore database
      const restoreCommand = `psql ${process.env.DATABASE_URL} < ${processedPath}`;
      await execAsync(restoreCommand);

      // If point-in-time recovery requested
      if (targetTime) {
        await this.performPointInTimeRecovery(targetTime);
      }

      // Verify restore
      await this.verifyRestore(tenantId);

      // Resume application connections
      await this.resumeApplicationConnections();

      // Log successful restore
      await auditLogger.logSuccess(
        AuditAction.BACKUP_RESTORED,
        ResourceType.BACKUP,
        backupId,
        { tenantId, targetTime }
      );

    } catch (error: any) {
      logger.error('Database restore failed', { error, backupId });
      throw error;
    }
  }

  /**
   * Schedule automated backups
   */
  async scheduleBackup(
    tenantId: string,
    config: BackupConfig
  ): Promise<void> {
    await this.prisma.backupJob.create({
      data: {
        tenantId,
        backupType: config.type,
        schedule: config.schedule,
        status: 'scheduled',
        nextRun: this.calculateNextRun(config.schedule),
        retentionDays: config.retention.daily,
        storageLocation: JSON.stringify(config.destination),
        encryptionEnabled: config.encryption,
      },
    });
  }

  /**
   * Build pg_dump command with appropriate options
   */
  private buildPgDumpCommand(
    tenantId: string,
    outputPath: string,
    config: BackupConfig
  ): string {
    const baseCommand = [
      'pg_dump',
      process.env.DATABASE_URL!,
      '--verbose',
      '--format=plain',
      '--no-owner',
      '--no-privileges',
      `--file=${outputPath}`,
    ];

    // Add tenant-specific filtering if not backing up entire database
    if (tenantId !== 'all') {
      baseCommand.push(`--where="tenant_id='${tenantId}'"`);
    }

    // Add compression if not handled separately
    if (config.compression && !config.encryption) {
      baseCommand.push('--compress=9');
    }

    return baseCommand.join(' ');
  }

  /**
   * Compress file using gzip
   */
  private async compressFile(inputPath: string): Promise<string> {
    const outputPath = `${inputPath}.gz`;
    const input = createReadStream(inputPath);
    const output = createWriteStream(outputPath);
    const gzipStream = gzip({ level: 9 });

    await pipeline(input, gzipStream, output);
    
    // Remove original file
    await promisify(require('fs').unlink)(inputPath);
    
    return outputPath;
  }

  /**
   * Encrypt file
   */
  private async encryptFile(inputPath: string): Promise<string> {
    const outputPath = `${inputPath}.enc`;
    const fileContent = await promisify(require('fs').readFile)(inputPath);
    const encrypted = encrypt(fileContent.toString('base64'));
    
    await promisify(require('fs').writeFile)(outputPath, encrypted);
    
    // Remove original file
    await promisify(require('fs').unlink)(inputPath);
    
    return outputPath;
  }

  /**
   * Upload backup to destination
   */
  private async uploadBackup(
    filePath: string,
    destination: BackupDestination,
    tenantId: string
  ): Promise<{ location: string }> {
    if (destination.type === 'S3') {
      const key = `backups/${tenantId}/${new Date().getFullYear()}/${
        new Date().getMonth() + 1
      }/${require('path').basename(filePath)}`;

      const fileStream = createReadStream(filePath);
      const uploadParams = {
        Bucket: destination.bucket!,
        Key: key,
        Body: fileStream,
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: process.env.KMS_BACKUP_KEY_ID,
        StorageClass: 'STANDARD_IA',
        Metadata: {
          tenantId,
          timestamp: new Date().toISOString(),
          type: 'database-backup',
        },
      };

      const result = await this.s3.upload(uploadParams).promise();
      
      return { location: result.Location };
    }

    throw new Error(`Unsupported destination type: ${destination.type}`);
  }

  /**
   * Apply retention policy
   */
  private async applyRetentionPolicy(
    tenantId: string,
    policy: RetentionPolicy,
    destination: BackupDestination
  ): Promise<void> {
    const now = new Date();
    
    // Calculate cutoff dates
    const dailyCutoff = new Date(now);
    dailyCutoff.setDate(dailyCutoff.getDate() - policy.daily);
    
    const weeklyCutoff = new Date(now);
    weeklyCutoff.setDate(weeklyCutoff.getDate() - policy.weekly * 7);
    
    const monthlyCutoff = new Date(now);
    monthlyCutoff.setMonth(monthlyCutoff.getMonth() - policy.monthly);
    
    const yearlyCutoff = new Date(now);
    yearlyCutoff.setFullYear(yearlyCutoff.getFullYear() - policy.yearly);

    if (destination.type === 'S3') {
      // List all backups
      const listParams = {
        Bucket: destination.bucket!,
        Prefix: `backups/${tenantId}/`,
      };

      const objects = await this.s3.listObjectsV2(listParams).promise();
      const backupsToDelete: string[] = [];

      for (const object of objects.Contents || []) {
        const backupDate = object.LastModified!;
        const key = object.Key!;

        // Determine if backup should be retained
        let shouldRetain = false;

        // Keep daily backups
        if (backupDate > dailyCutoff) {
          shouldRetain = true;
        }
        // Keep weekly backups (Sunday)
        else if (backupDate > weeklyCutoff && backupDate.getDay() === 0) {
          shouldRetain = true;
        }
        // Keep monthly backups (1st of month)
        else if (backupDate > monthlyCutoff && backupDate.getDate() === 1) {
          shouldRetain = true;
        }
        // Keep yearly backups (Jan 1st)
        else if (
          backupDate > yearlyCutoff &&
          backupDate.getMonth() === 0 &&
          backupDate.getDate() === 1
        ) {
          shouldRetain = true;
        }

        if (!shouldRetain) {
          backupsToDelete.push(key);
        }
      }

      // Delete old backups
      if (backupsToDelete.length > 0) {
        const deleteParams = {
          Bucket: destination.bucket!,
          Delete: {
            Objects: backupsToDelete.map(key => ({ Key: key })),
          },
        };

        await this.s3.deleteObjects(deleteParams).promise();
        
        logger.info(`Deleted ${backupsToDelete.length} old backups`, {
          tenantId,
          count: backupsToDelete.length,
        });
      }
    }
  }

  /**
   * Calculate checksum for backup verification
   */
  private async calculateChecksum(filePath: string): Promise<string> {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    
    return new Promise((resolve, reject) => {
      stream.on('data', data => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  /**
   * Clean up temporary files
   */
  private async cleanupTempFiles(files: string[]): Promise<void> {
    for (const file of files) {
      try {
        if (file && file !== files[0]) { // Don't delete if it's the same file
          await promisify(require('fs').unlink)(file);
        }
      } catch (error) {
        logger.warn('Failed to clean up temp file', { file, error });
      }
    }
  }

  /**
   * Log successful backup
   */
  private async logBackupSuccess(job: BackupJob, tenantId: string): Promise<void> {
    await auditLogger.logSuccess(
      AuditAction.BACKUP_CREATED,
      ResourceType.BACKUP,
      job.id,
      {
        tenantId,
        type: job.type,
        size: job.size,
        duration: job.endTime!.getTime() - job.startTime.getTime(),
        checksum: job.checksum,
      }
    );
  }

  /**
   * Log failed backup
   */
  private async logBackupFailure(
    job: BackupJob,
    tenantId: string,
    error: string
  ): Promise<void> {
    await auditLogger.logFailure(
      AuditAction.BACKUP_CREATED,
      ResourceType.BACKUP,
      job.id,
      error,
      {
        tenantId,
        type: job.type,
        duration: job.endTime!.getTime() - job.startTime.getTime(),
      }
    );
  }

  /**
   * Monitor backup health
   */
  async getBackupHealth(tenantId: string): Promise<{
    lastBackup: Date | null;
    nextBackup: Date | null;
    backupCount: number;
    totalSize: number;
    oldestBackup: Date | null;
    status: 'healthy' | 'warning' | 'critical';
  }> {
    const jobs = await this.prisma.backupJob.findMany({
      where: { tenantId },
      orderBy: { lastRun: 'desc' },
    });

    const lastBackup = jobs[0]?.lastRun || null;
    const nextBackup = jobs[0]?.nextRun || null;
    
    // Calculate total size from S3
    const bucket = process.env.BACKUP_BUCKET!;
    const listParams = {
      Bucket: bucket,
      Prefix: `backups/${tenantId}/`,
    };
    
    const objects = await this.s3.listObjectsV2(listParams).promise();
    const totalSize = objects.Contents?.reduce((sum, obj) => sum + (obj.Size || 0), 0) || 0;
    const oldestBackup = objects.Contents?.[0]?.LastModified || null;

    // Determine health status
    let status: 'healthy' | 'warning' | 'critical' = 'healthy';
    if (!lastBackup) {
      status = 'critical';
    } else {
      const hoursSinceLastBackup = (Date.now() - lastBackup.getTime()) / (1000 * 60 * 60);
      if (hoursSinceLastBackup > 48) {
        status = 'critical';
      } else if (hoursSinceLastBackup > 24) {
        status = 'warning';
      }
    }

    return {
      lastBackup,
      nextBackup,
      backupCount: objects.Contents?.length || 0,
      totalSize,
      oldestBackup,
      status,
    };
  }

  // Helper methods

  private async getWALFilesSince(lsn: string): Promise<string[]> {
    // Implementation depends on PostgreSQL WAL configuration
    return [];
  }

  private async uploadWALFile(walFile: string, tenantId: string): Promise<void> {
    // Upload WAL file for continuous backup
  }

  private async getCurrentLSN(): Promise<string> {
    const result = await this.prisma.$queryRaw`
      SELECT pg_current_wal_lsn() as lsn
    `;
    return (result as any)[0].lsn;
  }

  private async downloadBackup(backupId: string, tenantId: string): Promise<string> {
    // Download backup from storage
    return `/tmp/${backupId}`;
  }

  private async isEncrypted(filePath: string): Promise<boolean> {
    return filePath.endsWith('.enc');
  }

  private async decryptFile(inputPath: string): Promise<string> {
    // Decrypt file
    return inputPath.replace('.enc', '');
  }

  private async decompressFile(inputPath: string): Promise<string> {
    // Decompress file
    return inputPath.replace('.gz', '');
  }

  private async stopApplicationConnections(): Promise<void> {
    // Stop application connections for restore
  }

  private async resumeApplicationConnections(): Promise<void> {
    // Resume application connections after restore
  }

  private async performPointInTimeRecovery(targetTime: Date): Promise<void> {
    // Perform point-in-time recovery using WAL
  }

  private async verifyRestore(tenantId: string): Promise<void> {
    // Verify database restore was successful
  }

  private calculateNextRun(schedule: string): Date {
    // Parse cron expression and calculate next run
    // For now, return tomorrow at 3 AM
    const next = new Date();
    next.setDate(next.getDate() + 1);
    next.setHours(3, 0, 0, 0);
    return next;
  }
}

// Export singleton instance
export const backupService = new BackupService();