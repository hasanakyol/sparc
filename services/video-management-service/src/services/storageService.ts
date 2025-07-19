import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  CopyObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  PutObjectTaggingCommand,
  PutBucketLifecycleConfigurationCommand,
  StorageClass,
  S3ServiceException,
} from '@aws-sdk/client-s3';
import { CloudFrontClient, CreateInvalidationCommand } from '@aws-sdk/client-cloudfront';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Upload } from '@aws-sdk/lib-storage';
import { Readable, Transform } from 'stream';
import { createHash } from 'crypto';
import { EventEmitter } from 'events';
import Redis from 'ioredis';
import { config } from '@sparc/shared';
import { promisify } from 'util';
import { pipeline } from 'stream/promises';
import { createReadStream, createWriteStream, statSync } from 'fs';
import { join, basename } from 'path';
import pRetry from 'p-retry';
import { logger } from '../utils/logger';

export interface StorageConfig {
  bucket: string;
  region: string;
  cloudfrontDomain?: string;
  cloudfrontDistributionId?: string;
  multipartThreshold?: number; // Size in bytes to trigger multipart upload
  multipartChunkSize?: number; // Size of each part in multipart upload
  maxRetries?: number;
  signedUrlExpiration?: number; // In seconds
}

export interface UploadOptions {
  tenantId: string;
  cameraId: string;
  timestamp?: Date;
  storageClass?: StorageClass;
  metadata?: Record<string, string>;
  tags?: Record<string, string>;
  contentType?: string;
  onProgress?: (progress: UploadProgress) => void;
}

export interface UploadProgress {
  loaded: number;
  total: number;
  percentage: number;
  speed: number; // bytes per second
  remainingTime: number; // seconds
}

export interface StreamingOptions {
  format?: 'hls' | 'dash' | 'mp4';
  quality?: 'auto' | '1080p' | '720p' | '480p' | '360p';
  startTime?: number;
  endTime?: number;
}

export interface StorageMetrics {
  totalSize: number;
  fileCount: number;
  byStorageClass: Record<string, { size: number; count: number }>;
  byTenant: Record<string, { size: number; count: number }>;
  oldestFile: Date;
  newestFile: Date;
}

export interface MigrationOptions {
  sourcePath: string;
  batchSize?: number;
  dryRun?: boolean;
  verify?: boolean;
  deleteAfterMigration?: boolean;
  onProgress?: (progress: MigrationProgress) => void;
}

export interface MigrationProgress {
  totalFiles: number;
  processedFiles: number;
  successCount: number;
  errorCount: number;
  totalBytes: number;
  processedBytes: number;
  currentFile?: string;
  errors: Array<{ file: string; error: string }>;
}

export class CloudStorageService extends EventEmitter {
  private s3Client: S3Client;
  private cloudfrontClient?: CloudFrontClient;
  private redis: Redis;
  private config: StorageConfig;
  private uploadTrackers: Map<string, UploadTracker> = new Map();

  constructor(config: StorageConfig) {
    super();
    this.config = {
      multipartThreshold: 100 * 1024 * 1024, // 100MB
      multipartChunkSize: 10 * 1024 * 1024, // 10MB
      maxRetries: 3,
      signedUrlExpiration: 3600, // 1 hour
      ...config,
    };

    // Initialize S3 client
    this.s3Client = new S3Client({
      region: this.config.region,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
      },
      maxAttempts: this.config.maxRetries,
    });

    // Initialize CloudFront client if configured
    if (this.config.cloudfrontDomain && this.config.cloudfrontDistributionId) {
      this.cloudfrontClient = new CloudFrontClient({
        region: this.config.region,
        credentials: {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
      });
    }

    // Initialize Redis for caching and coordination
    this.redis = new Redis(config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379');

    // Set up lifecycle policies
    this.setupLifecyclePolicies().catch(err => {
      logger.error('Failed to setup lifecycle policies:', err);
    });
  }

  /**
   * Upload a video file with multipart support and progress tracking
   */
  async uploadVideo(
    input: string | Buffer | Readable,
    key: string,
    options: UploadOptions
  ): Promise<string> {
    const uploadId = this.generateUploadId();
    const tracker = new UploadTracker(uploadId);
    this.uploadTrackers.set(uploadId, tracker);

    try {
      // Determine input size for progress tracking
      let contentLength: number | undefined;
      if (typeof input === 'string') {
        contentLength = statSync(input).size;
      } else if (Buffer.isBuffer(input)) {
        contentLength = input.length;
      }

      // Create stream with progress tracking
      const progressStream = this.createProgressStream(tracker, contentLength);
      let bodyStream: Readable;

      if (typeof input === 'string') {
        bodyStream = createReadStream(input).pipe(progressStream);
      } else if (Buffer.isBuffer(input)) {
        bodyStream = Readable.from(input).pipe(progressStream);
      } else {
        bodyStream = input.pipe(progressStream);
      }

      // Prepare metadata and tags
      const metadata: Record<string, string> = {
        tenantId: options.tenantId,
        cameraId: options.cameraId,
        timestamp: (options.timestamp || new Date()).toISOString(),
        uploadId,
        ...options.metadata,
      };

      const tags = {
        TenantId: options.tenantId,
        CameraId: options.cameraId,
        Type: 'video',
        ...options.tags,
      };

      // Use multipart upload for large files
      const upload = new Upload({
        client: this.s3Client,
        params: {
          Bucket: this.config.bucket,
          Key: key,
          Body: bodyStream,
          ContentType: options.contentType || 'video/mp4',
          StorageClass: options.storageClass || StorageClass.STANDARD,
          Metadata: metadata,
        },
        queueSize: 4, // Concurrent parts
        partSize: this.config.multipartChunkSize,
        leavePartsOnError: false,
      });

      // Track upload progress
      upload.on('httpUploadProgress', (progress) => {
        if (progress.loaded && progress.total) {
          tracker.updateProgress(progress.loaded, progress.total);
          
          if (options.onProgress) {
            const progressData = tracker.getProgress();
            options.onProgress(progressData);
          }

          this.emit('upload:progress', {
            uploadId,
            key,
            progress: progressData,
          });
        }
      });

      // Perform upload with retry
      const result = await pRetry(
        async () => {
          try {
            return await upload.done();
          } catch (error) {
            logger.error('Upload attempt failed:', error);
            throw error;
          }
        },
        {
          retries: this.config.maxRetries,
          onFailedAttempt: (error) => {
            logger.warn(`Upload attempt ${error.attemptNumber} failed. Retrying...`);
          },
        }
      );

      // Apply tags after successful upload
      await this.applyTags(key, tags);

      // Cache metadata for quick access
      await this.cacheMetadata(key, metadata);

      // Generate URL
      const url = await this.getStreamingUrl(key);

      // Emit success event
      this.emit('upload:complete', {
        uploadId,
        key,
        url,
        size: tracker.getTotalBytes(),
        duration: tracker.getDuration(),
      });

      return url;

    } catch (error) {
      logger.error('Video upload failed:', error);
      
      // Emit failure event
      this.emit('upload:failed', {
        uploadId,
        key,
        error,
      });

      throw error;

    } finally {
      this.uploadTrackers.delete(uploadId);
    }
  }

  /**
   * Generate CloudFront URL for video streaming
   */
  async getStreamingUrl(key: string, options?: StreamingOptions): Promise<string> {
    if (!this.config.cloudfrontDomain) {
      // Return S3 URL if CloudFront not configured
      return `https://${this.config.bucket}.s3.${this.config.region}.amazonaws.com/${key}`;
    }

    // Build CloudFront URL with optional parameters
    let url = `https://${this.config.cloudfrontDomain}/${key}`;

    if (options?.format === 'hls') {
      // Convert key to HLS manifest path
      const basePath = key.replace(/\.[^/.]+$/, '');
      url = `https://${this.config.cloudfrontDomain}/${basePath}/playlist.m3u8`;
    }

    if (options?.quality && options.quality !== 'auto') {
      url += `?quality=${options.quality}`;
    }

    if (options?.startTime !== undefined) {
      url += `${url.includes('?') ? '&' : '?'}start=${options.startTime}`;
    }

    if (options?.endTime !== undefined) {
      url += `&end=${options.endTime}`;
    }

    return url;
  }

  /**
   * Generate signed URL for secure access
   */
  async generateSignedUrl(
    key: string,
    expiresIn?: number,
    options?: { download?: boolean; filename?: string }
  ): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.config.bucket,
      Key: key,
      ResponseContentDisposition: options?.download
        ? `attachment; filename="${options.filename || basename(key)}"`
        : undefined,
    });

    const signedUrl = await getSignedUrl(this.s3Client, command, {
      expiresIn: expiresIn || this.config.signedUrlExpiration,
    });

    // Cache signed URL
    const cacheKey = `signed-url:${key}:${options?.download ? 'download' : 'stream'}`;
    await this.redis.setex(
      cacheKey,
      (expiresIn || this.config.signedUrlExpiration) - 60, // Cache for slightly less than expiration
      signedUrl
    );

    return signedUrl;
  }

  /**
   * Migrate existing files from local storage to S3
   */
  async migrateFromLocalStorage(options: MigrationOptions): Promise<MigrationProgress> {
    const progress: MigrationProgress = {
      totalFiles: 0,
      processedFiles: 0,
      successCount: 0,
      errorCount: 0,
      totalBytes: 0,
      processedBytes: 0,
      errors: [],
    };

    try {
      // Scan source directory for video files
      const files = await this.scanDirectory(options.sourcePath);
      progress.totalFiles = files.length;

      logger.info(`Starting migration of ${files.length} files from ${options.sourcePath}`);

      // Process files in batches
      const batchSize = options.batchSize || 5;
      for (let i = 0; i < files.length; i += batchSize) {
        const batch = files.slice(i, i + batchSize);
        
        await Promise.all(
          batch.map(async (file) => {
            progress.currentFile = file.path;
            
            try {
              // Extract metadata from file path/name
              const metadata = this.extractMetadataFromPath(file.path);
              
              if (options.dryRun) {
                logger.info(`[DRY RUN] Would migrate: ${file.path}`);
                progress.processedFiles++;
                progress.successCount++;
                return;
              }

              // Generate S3 key
              const key = this.generateKeyFromMetadata(metadata);

              // Upload file
              await this.uploadVideo(file.path, key, {
                tenantId: metadata.tenantId,
                cameraId: metadata.cameraId,
                timestamp: metadata.timestamp,
                metadata: metadata.extra,
              });

              // Verify upload if requested
              if (options.verify) {
                const verified = await this.verifyUpload(key, file.path);
                if (!verified) {
                  throw new Error('Upload verification failed');
                }
              }

              // Delete local file if requested
              if (options.deleteAfterMigration) {
                await promisify(require('fs').unlink)(file.path);
              }

              progress.processedFiles++;
              progress.processedBytes += file.size;
              progress.successCount++;

              logger.info(`Migrated: ${file.path} -> ${key}`);

            } catch (error) {
              progress.errorCount++;
              progress.errors.push({
                file: file.path,
                error: error instanceof Error ? error.message : String(error),
              });
              
              logger.error(`Failed to migrate ${file.path}:`, error);
            }

            // Report progress
            if (options.onProgress) {
              options.onProgress(progress);
            }
          })
        );
      }

      logger.info(`Migration completed: ${progress.successCount}/${progress.totalFiles} files migrated successfully`);

      return progress;

    } catch (error) {
      logger.error('Migration failed:', error);
      throw error;
    }
  }

  /**
   * Set up lifecycle policies for automatic archival
   */
  private async setupLifecyclePolicies(): Promise<void> {
    const rules = [
      {
        ID: 'archive-old-footage',
        Status: 'Enabled',
        Filter: {
          Prefix: 'video-recordings/',
        },
        Transitions: [
          {
            Days: 30,
            StorageClass: StorageClass.STANDARD_IA,
          },
          {
            Days: 90,
            StorageClass: StorageClass.GLACIER_FLEXIBLE_RETRIEVAL,
          },
          {
            Days: 365,
            StorageClass: StorageClass.DEEP_ARCHIVE,
          },
        ],
      },
      {
        ID: 'delete-temp-files',
        Status: 'Enabled',
        Filter: {
          Prefix: 'temp/',
        },
        Expiration: {
          Days: 1,
        },
      },
      {
        ID: 'delete-old-thumbnails',
        Status: 'Enabled',
        Filter: {
          Prefix: 'thumbnails/',
        },
        Expiration: {
          Days: 30,
        },
      },
    ];

    try {
      await this.s3Client.send(
        new PutBucketLifecycleConfigurationCommand({
          Bucket: this.config.bucket,
          LifecycleConfiguration: {
            Rules: rules,
          },
        })
      );

      logger.info('Lifecycle policies configured successfully');
    } catch (error) {
      if (error instanceof S3ServiceException && error.name === 'NoSuchBucket') {
        logger.warn(`Bucket ${this.config.bucket} does not exist. Skipping lifecycle setup.`);
      } else {
        throw error;
      }
    }
  }

  /**
   * Invalidate CloudFront cache for updated content
   */
  async invalidateCache(paths: string[]): Promise<void> {
    if (!this.cloudfrontClient || !this.config.cloudfrontDistributionId) {
      logger.warn('CloudFront not configured. Skipping cache invalidation.');
      return;
    }

    try {
      const command = new CreateInvalidationCommand({
        DistributionId: this.config.cloudfrontDistributionId,
        InvalidationBatch: {
          CallerReference: Date.now().toString(),
          Paths: {
            Quantity: paths.length,
            Items: paths.map(p => `/${p}`),
          },
        },
      });

      const result = await this.cloudfrontClient.send(command);
      logger.info(`Cache invalidation created: ${result.Invalidation?.Id}`);

    } catch (error) {
      logger.error('Cache invalidation failed:', error);
      throw error;
    }
  }

  /**
   * Get storage metrics and analytics
   */
  async getStorageMetrics(tenantId?: string): Promise<StorageMetrics> {
    const metrics: StorageMetrics = {
      totalSize: 0,
      fileCount: 0,
      byStorageClass: {},
      byTenant: {},
      oldestFile: new Date(),
      newestFile: new Date(0),
    };

    try {
      let continuationToken: string | undefined;
      const prefix = tenantId ? `video-recordings/${tenantId}/` : 'video-recordings/';

      do {
        const command = new ListObjectsV2Command({
          Bucket: this.config.bucket,
          Prefix: prefix,
          ContinuationToken: continuationToken,
          MaxKeys: 1000,
        });

        const response = await this.s3Client.send(command);

        if (response.Contents) {
          for (const object of response.Contents) {
            metrics.fileCount++;
            metrics.totalSize += object.Size || 0;

            // Track by storage class
            const storageClass = object.StorageClass || 'STANDARD';
            if (!metrics.byStorageClass[storageClass]) {
              metrics.byStorageClass[storageClass] = { size: 0, count: 0 };
            }
            metrics.byStorageClass[storageClass].size += object.Size || 0;
            metrics.byStorageClass[storageClass].count++;

            // Track by tenant
            const tenantMatch = object.Key?.match(/video-recordings\/([^/]+)\//);
            if (tenantMatch) {
              const tenant = tenantMatch[1];
              if (!metrics.byTenant[tenant]) {
                metrics.byTenant[tenant] = { size: 0, count: 0 };
              }
              metrics.byTenant[tenant].size += object.Size || 0;
              metrics.byTenant[tenant].count++;
            }

            // Track oldest/newest
            if (object.LastModified) {
              if (object.LastModified < metrics.oldestFile) {
                metrics.oldestFile = object.LastModified;
              }
              if (object.LastModified > metrics.newestFile) {
                metrics.newestFile = object.LastModified;
              }
            }
          }
        }

        continuationToken = response.NextContinuationToken;
      } while (continuationToken);

      // Cache metrics
      await this.redis.setex(
        `storage-metrics:${tenantId || 'all'}`,
        300, // 5 minutes
        JSON.stringify(metrics)
      );

      return metrics;

    } catch (error) {
      logger.error('Failed to get storage metrics:', error);
      throw error;
    }
  }

  /**
   * Clean up temporary files and optimize storage
   */
  async cleanupStorage(options?: {
    deleteEmptyFolders?: boolean;
    compactSmallFiles?: boolean;
    removeOrphaned?: boolean;
  }): Promise<{
    deletedFiles: number;
    freedSpace: number;
    errors: string[];
  }> {
    const result = {
      deletedFiles: 0,
      freedSpace: 0,
      errors: [],
    };

    try {
      // Clean up temp files older than 24 hours
      const tempFiles = await this.listObjects('temp/', {
        modifiedBefore: new Date(Date.now() - 24 * 60 * 60 * 1000),
      });

      for (const file of tempFiles) {
        try {
          await this.deleteObject(file.Key!);
          result.deletedFiles++;
          result.freedSpace += file.Size || 0;
        } catch (error) {
          result.errors.push(`Failed to delete ${file.Key}: ${error}`);
        }
      }

      // Remove orphaned chunks from failed multipart uploads
      if (options?.removeOrphaned) {
        // Implementation would go here
        // This would involve listing and aborting incomplete multipart uploads
      }

      logger.info(`Cleanup completed: ${result.deletedFiles} files deleted, ${result.freedSpace} bytes freed`);

      return result;

    } catch (error) {
      logger.error('Storage cleanup failed:', error);
      throw error;
    }
  }

  // Helper methods

  private createProgressStream(tracker: UploadTracker, totalSize?: number): Transform {
    return new Transform({
      transform(chunk, encoding, callback) {
        tracker.addBytes(chunk.length);
        callback(null, chunk);
      },
    });
  }

  private generateUploadId(): string {
    return `upload_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateKeyFromMetadata(metadata: any): string {
    const date = metadata.timestamp || new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    
    return `video-recordings/${metadata.tenantId}/${year}/${month}/${day}/${metadata.cameraId}/${metadata.filename || `${Date.now()}.mp4`}`;
  }

  private extractMetadataFromPath(filePath: string): any {
    // Example path: /storage/tenant1/camera1/2024-01-15_10-30-00.mp4
    const pathParts = filePath.split('/');
    const filename = pathParts[pathParts.length - 1];
    const dateMatch = filename.match(/(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})/);

    return {
      tenantId: pathParts[pathParts.length - 3] || 'unknown',
      cameraId: pathParts[pathParts.length - 2] || 'unknown',
      timestamp: dateMatch
        ? new Date(`${dateMatch[1]}-${dateMatch[2]}-${dateMatch[3]}T${dateMatch[4]}:${dateMatch[5]}:${dateMatch[6]}`)
        : new Date(),
      filename,
      extra: {
        originalPath: filePath,
      },
    };
  }

  private async scanDirectory(dir: string): Promise<Array<{ path: string; size: number }>> {
    const { readdir, stat } = require('fs').promises;
    const files: Array<{ path: string; size: number }> = [];

    async function scan(currentDir: string) {
      const entries = await readdir(currentDir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(currentDir, entry.name);

        if (entry.isDirectory()) {
          await scan(fullPath);
        } else if (entry.isFile() && /\.(mp4|avi|mov|mkv|webm)$/i.test(entry.name)) {
          const stats = await stat(fullPath);
          files.push({ path: fullPath, size: stats.size });
        }
      }
    }

    await scan(dir);
    return files;
  }

  private async applyTags(key: string, tags: Record<string, string>): Promise<void> {
    const tagSet = Object.entries(tags).map(([Key, Value]) => ({ Key, Value }));

    await this.s3Client.send(
      new PutObjectTaggingCommand({
        Bucket: this.config.bucket,
        Key: key,
        Tagging: { TagSet: tagSet },
      })
    );
  }

  private async cacheMetadata(key: string, metadata: Record<string, string>): Promise<void> {
    await this.redis.setex(
      `video-metadata:${key}`,
      86400, // 24 hours
      JSON.stringify(metadata)
    );
  }

  private async verifyUpload(key: string, localPath: string): Promise<boolean> {
    try {
      const headCommand = new HeadObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      });

      const response = await this.s3Client.send(headCommand);
      const localStats = statSync(localPath);

      return response.ContentLength === localStats.size;
    } catch (error) {
      return false;
    }
  }

  private async listObjects(
    prefix: string,
    options?: { modifiedBefore?: Date; modifiedAfter?: Date }
  ): Promise<any[]> {
    const objects: any[] = [];
    let continuationToken: string | undefined;

    do {
      const command = new ListObjectsV2Command({
        Bucket: this.config.bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken,
      });

      const response = await this.s3Client.send(command);

      if (response.Contents) {
        const filtered = response.Contents.filter((obj) => {
          if (options?.modifiedBefore && obj.LastModified && obj.LastModified > options.modifiedBefore) {
            return false;
          }
          if (options?.modifiedAfter && obj.LastModified && obj.LastModified < options.modifiedAfter) {
            return false;
          }
          return true;
        });

        objects.push(...filtered);
      }

      continuationToken = response.NextContinuationToken;
    } while (continuationToken);

    return objects;
  }

  private async deleteObject(key: string): Promise<void> {
    await this.s3Client.send(
      new DeleteObjectCommand({
        Bucket: this.config.bucket,
        Key: key,
      })
    );
  }

  async shutdown(): Promise<void> {
    await this.redis.quit();
    this.removeAllListeners();
    logger.info('Cloud storage service shut down');
  }
}

// Helper class for tracking upload progress
class UploadTracker {
  private startTime: number;
  private bytesUploaded: number = 0;
  private totalBytes: number = 0;
  private speeds: number[] = [];
  private lastUpdate: number;

  constructor(public uploadId: string) {
    this.startTime = Date.now();
    this.lastUpdate = this.startTime;
  }

  updateProgress(loaded: number, total: number): void {
    const now = Date.now();
    const timeDiff = (now - this.lastUpdate) / 1000; // seconds
    const bytesDiff = loaded - this.bytesUploaded;
    
    if (timeDiff > 0) {
      const speed = bytesDiff / timeDiff;
      this.speeds.push(speed);
      
      // Keep only last 10 speed measurements
      if (this.speeds.length > 10) {
        this.speeds.shift();
      }
    }

    this.bytesUploaded = loaded;
    this.totalBytes = total;
    this.lastUpdate = now;
  }

  addBytes(bytes: number): void {
    this.bytesUploaded += bytes;
  }

  getProgress(): UploadProgress {
    const percentage = this.totalBytes > 0 ? (this.bytesUploaded / this.totalBytes) * 100 : 0;
    const avgSpeed = this.speeds.length > 0
      ? this.speeds.reduce((a, b) => a + b, 0) / this.speeds.length
      : 0;
    
    const remainingBytes = this.totalBytes - this.bytesUploaded;
    const remainingTime = avgSpeed > 0 ? remainingBytes / avgSpeed : 0;

    return {
      loaded: this.bytesUploaded,
      total: this.totalBytes,
      percentage: Math.round(percentage * 100) / 100,
      speed: Math.round(avgSpeed),
      remainingTime: Math.round(remainingTime),
    };
  }

  getTotalBytes(): number {
    return this.bytesUploaded;
  }

  getDuration(): number {
    return Date.now() - this.startTime;
  }
}

export default CloudStorageService;