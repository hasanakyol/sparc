import { promises as fs } from 'fs';
import { join, dirname } from 'path';
import crypto from 'crypto';
import Redis from 'ioredis';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { ReportingServiceConfig } from '../config';
import { ExportFormat } from '../types';
import { logger } from '../utils/logger';
import { createTracer } from '../utils/telemetry';

const tracer = createTracer('report-storage-service');

export interface StoredReport {
  filename: string;
  size: number;
  mimeType: string;
  path?: string;
  s3Key?: string;
  checksum: string;
}

export class ReportStorageService {
  private s3Client?: S3Client;
  private useS3: boolean;

  constructor(
    private config: ReportingServiceConfig,
    private redis: Redis
  ) {
    this.useS3 = !!config.storage.s3;
    
    if (this.useS3 && config.storage.s3) {
      this.s3Client = new S3Client({
        region: config.storage.s3.region,
        credentials: config.storage.s3.accessKeyId ? {
          accessKeyId: config.storage.s3.accessKeyId,
          secretAccessKey: config.storage.s3.secretAccessKey!
        } : undefined
      });
    }
  }

  async storeReport(
    reportId: string,
    report: { data: Buffer; mimeType: string; filename: string },
    format: ExportFormat,
    tenantId: string
  ): Promise<StoredReport> {
    return tracer.startActiveSpan('store-report', async (span) => {
      try {
        span.setAttributes({
          'report.id': reportId,
          'report.format': format,
          'report.tenant_id': tenantId,
          'report.size': report.data.length
        });

        // Calculate checksum
        const checksum = crypto.createHash('sha256').update(report.data).digest('hex');
        
        // Generate filename
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${tenantId}/${reportId}/${timestamp}_${report.filename}`;
        
        let stored: StoredReport;
        
        if (this.useS3) {
          stored = await this.storeToS3(filename, report, checksum);
        } else {
          stored = await this.storeToFileSystem(filename, report, checksum);
        }
        
        // Store metadata in Redis
        await this.redis.setex(
          `report:storage:${reportId}`,
          30 * 24 * 60 * 60, // 30 days
          JSON.stringify({
            ...stored,
            reportId,
            tenantId,
            format,
            storedAt: new Date().toISOString()
          })
        );
        
        logger.info('Report stored successfully', {
          reportId,
          filename: stored.filename,
          size: stored.size
        });
        
        return stored;
      } finally {
        span.end();
      }
    });
  }

  async retrieveReport(reportId: string, tenantId: string): Promise<Buffer | null> {
    return tracer.startActiveSpan('retrieve-report', async (span) => {
      try {
        span.setAttributes({
          'report.id': reportId,
          'report.tenant_id': tenantId
        });

        // Get metadata from Redis
        const metadataStr = await this.redis.get(`report:storage:${reportId}`);
        if (!metadataStr) {
          return null;
        }
        
        const metadata = JSON.parse(metadataStr);
        
        // Verify tenant access
        if (metadata.tenantId !== tenantId) {
          return null;
        }
        
        let data: Buffer;
        
        if (metadata.s3Key) {
          data = await this.retrieveFromS3(metadata.s3Key);
        } else if (metadata.path) {
          data = await this.retrieveFromFileSystem(metadata.path);
        } else {
          return null;
        }
        
        // Verify checksum
        const checksum = crypto.createHash('sha256').update(data).digest('hex');
        if (checksum !== metadata.checksum) {
          logger.error('Report checksum mismatch', {
            reportId,
            expected: metadata.checksum,
            actual: checksum
          });
          throw new Error('Report integrity check failed');
        }
        
        return data;
      } finally {
        span.end();
      }
    });
  }

  async getDownloadUrl(reportId: string, tenantId: string): Promise<string | null> {
    // Get metadata from Redis
    const metadataStr = await this.redis.get(`report:storage:${reportId}`);
    if (!metadataStr) {
      return null;
    }
    
    const metadata = JSON.parse(metadataStr);
    
    // Verify tenant access
    if (metadata.tenantId !== tenantId) {
      return null;
    }
    
    if (metadata.s3Key && this.s3Client && this.config.storage.s3) {
      // Generate pre-signed URL for S3
      const command = new GetObjectCommand({
        Bucket: this.config.storage.s3.bucket,
        Key: metadata.s3Key
      });
      
      return await getSignedUrl(this.s3Client, command, { expiresIn: 3600 });
    }
    
    // For file system storage, return a download endpoint
    return `/api/reports/${reportId}/download`;
  }

  async deleteReport(reportId: string, tenantId: string): Promise<boolean> {
    try {
      // Get metadata from Redis
      const metadataStr = await this.redis.get(`report:storage:${reportId}`);
      if (!metadataStr) {
        return false;
      }
      
      const metadata = JSON.parse(metadataStr);
      
      // Verify tenant access
      if (metadata.tenantId !== tenantId) {
        return false;
      }
      
      // Delete file
      if (metadata.s3Key) {
        await this.deleteFromS3(metadata.s3Key);
      } else if (metadata.path) {
        await this.deleteFromFileSystem(metadata.path);
      }
      
      // Delete metadata
      await this.redis.del(`report:storage:${reportId}`);
      
      logger.info('Report deleted', { reportId });
      return true;
    } catch (error) {
      logger.error('Failed to delete report', { reportId, error });
      return false;
    }
  }

  async cleanupOldReports(): Promise<void> {
    const retentionDays = this.config.storage.retentionDays;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
    
    logger.info('Starting report cleanup', {
      retentionDays,
      cutoffDate: cutoffDate.toISOString()
    });
    
    // Get all report metadata keys
    const keys = await this.redis.keys('report:storage:*');
    let deletedCount = 0;
    
    for (const key of keys) {
      try {
        const metadataStr = await this.redis.get(key);
        if (!metadataStr) continue;
        
        const metadata = JSON.parse(metadataStr);
        const storedAt = new Date(metadata.storedAt);
        
        if (storedAt < cutoffDate) {
          const reportId = key.replace('report:storage:', '');
          await this.deleteReport(reportId, metadata.tenantId);
          deletedCount++;
        }
      } catch (error) {
        logger.error('Failed to cleanup report', { key, error });
      }
    }
    
    logger.info('Report cleanup completed', { deletedCount });
  }

  async getStorageStats(): Promise<{
    usedBytes: number;
    fileCount: number;
    oldestReport?: Date;
    newestReport?: Date;
  }> {
    const keys = await this.redis.keys('report:storage:*');
    let totalSize = 0;
    let oldestDate: Date | undefined;
    let newestDate: Date | undefined;
    
    for (const key of keys) {
      try {
        const metadataStr = await this.redis.get(key);
        if (!metadataStr) continue;
        
        const metadata = JSON.parse(metadataStr);
        totalSize += metadata.size || 0;
        
        const storedAt = new Date(metadata.storedAt);
        if (!oldestDate || storedAt < oldestDate) {
          oldestDate = storedAt;
        }
        if (!newestDate || storedAt > newestDate) {
          newestDate = storedAt;
        }
      } catch (error) {
        logger.error('Failed to get report stats', { key, error });
      }
    }
    
    return {
      usedBytes: totalSize,
      fileCount: keys.length,
      oldestReport: oldestDate,
      newestReport: newestDate
    };
  }

  async healthCheck(): Promise<boolean> {
    try {
      if (this.useS3 && this.s3Client && this.config.storage.s3) {
        // Check S3 access
        const command = new PutObjectCommand({
          Bucket: this.config.storage.s3.bucket,
          Key: '.health-check',
          Body: Buffer.from('health-check'),
          ContentType: 'text/plain'
        });
        await this.s3Client.send(command);
        
        // Clean up
        const deleteCommand = new DeleteObjectCommand({
          Bucket: this.config.storage.s3.bucket,
          Key: '.health-check'
        });
        await this.s3Client.send(deleteCommand);
      } else {
        // Check file system access
        const testPath = join(this.config.storage.path, '.health-check');
        await fs.writeFile(testPath, 'health-check');
        await fs.unlink(testPath);
      }
      
      return true;
    } catch (error) {
      logger.error('Storage health check failed', { error });
      return false;
    }
  }

  private async storeToS3(
    key: string,
    report: { data: Buffer; mimeType: string },
    checksum: string
  ): Promise<StoredReport> {
    if (!this.s3Client || !this.config.storage.s3) {
      throw new Error('S3 not configured');
    }
    
    const command = new PutObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: key,
      Body: report.data,
      ContentType: report.mimeType,
      Metadata: {
        checksum
      }
    });
    
    await this.s3Client.send(command);
    
    return {
      filename: key.split('/').pop()!,
      size: report.data.length,
      mimeType: report.mimeType,
      s3Key: key,
      checksum
    };
  }

  private async storeToFileSystem(
    filename: string,
    report: { data: Buffer; mimeType: string },
    checksum: string
  ): Promise<StoredReport> {
    const fullPath = join(this.config.storage.path, filename);
    const dir = dirname(fullPath);
    
    // Ensure directory exists
    await fs.mkdir(dir, { recursive: true });
    
    // Write file
    await fs.writeFile(fullPath, report.data);
    
    return {
      filename: filename.split('/').pop()!,
      size: report.data.length,
      mimeType: report.mimeType,
      path: fullPath,
      checksum
    };
  }

  private async retrieveFromS3(key: string): Promise<Buffer> {
    if (!this.s3Client || !this.config.storage.s3) {
      throw new Error('S3 not configured');
    }
    
    const command = new GetObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: key
    });
    
    const response = await this.s3Client.send(command);
    const chunks: Uint8Array[] = [];
    
    for await (const chunk of response.Body as any) {
      chunks.push(chunk);
    }
    
    return Buffer.concat(chunks);
  }

  private async retrieveFromFileSystem(path: string): Promise<Buffer> {
    return await fs.readFile(path);
  }

  private async deleteFromS3(key: string): Promise<void> {
    if (!this.s3Client || !this.config.storage.s3) {
      throw new Error('S3 not configured');
    }
    
    const command = new DeleteObjectCommand({
      Bucket: this.config.storage.s3.bucket,
      Key: key
    });
    
    await this.s3Client.send(command);
  }

  private async deleteFromFileSystem(path: string): Promise<void> {
    await fs.unlink(path);
  }
}