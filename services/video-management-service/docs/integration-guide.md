# Cloud Storage Integration Guide

## Overview

This guide explains how to integrate the new cloud storage capabilities into the existing video management service, ensuring a smooth transition from local file storage to S3 with CloudFront CDN.

## Integration Steps

### 1. Update Video Processor

Modify the existing `videoProcessor.ts` to use the new CloudStorageService:

```typescript
import { CloudStorageService } from './storageService';

export class VideoProcessor extends EventEmitter {
  private storageService: CloudStorageService;

  constructor() {
    super();
    
    // Initialize cloud storage
    this.storageService = new CloudStorageService({
      bucket: process.env.S3_BUCKET!,
      region: process.env.AWS_REGION!,
      cloudfrontDomain: process.env.CLOUDFRONT_DOMAIN,
    });
    
    // ... existing initialization
  }

  // Update upload method to use cloud storage
  private async uploadToS3(localPath: string, s3Key: string, tenantId: string, videoId: string): Promise<string> {
    // Use the new storage service with progress tracking
    return await this.storageService.uploadVideo(
      localPath,
      s3Key,
      {
        tenantId,
        cameraId: videoId,
        timestamp: new Date(),
        onProgress: (progress) => {
          this.emit('upload:progress', {
            videoId,
            progress
          });
        }
      }
    );
  }
}
```

### 2. Update Recording Service

Modify `recordingService.ts` to save directly to S3:

```typescript
import { CloudStorageService } from './storageService';

export class RecordingService {
  private storageService: CloudStorageService;
  
  async saveRecording(stream: Readable, metadata: RecordingMetadata): Promise<string> {
    const key = this.generateRecordingKey(metadata);
    
    // Upload with appropriate storage class based on retention policy
    const storageClass = this.determineStorageClass(metadata.retentionDays);
    
    return await this.storageService.uploadVideo(
      stream,
      key,
      {
        tenantId: metadata.tenantId,
        cameraId: metadata.cameraId,
        timestamp: metadata.startTime,
        storageClass,
        metadata: {
          duration: metadata.duration.toString(),
          format: metadata.format,
          resolution: metadata.resolution,
        },
        tags: {
          RecordingType: metadata.type,
          TriggeredBy: metadata.triggeredBy,
        }
      }
    );
  }
  
  private determineStorageClass(retentionDays: number): StorageClass {
    if (retentionDays <= 7) return StorageClass.STANDARD;
    if (retentionDays <= 30) return StorageClass.STANDARD_IA;
    if (retentionDays <= 90) return StorageClass.GLACIER_INSTANT_RETRIEVAL;
    return StorageClass.GLACIER_FLEXIBLE_RETRIEVAL;
  }
}
```

### 3. Update Streaming Routes

Replace the existing streaming routes with the cloud-enabled version:

```typescript
// In src/index.ts or main router file
import streamingRoutes from './routes/streaming';
import cloudStreamingRoutes from './routes/streaming-cloud';

// Use cloud streaming if enabled
if (process.env.ENABLE_CLOUD_STORAGE === 'true') {
  app.route('/api/v1/streaming', cloudStreamingRoutes);
} else {
  app.route('/api/v1/streaming', streamingRoutes);
}
```

### 4. Database Schema Updates

Add cloud storage metadata to your database schema:

```sql
-- Add cloud storage fields to video_recordings table
ALTER TABLE video_recordings
ADD COLUMN s3_key VARCHAR(512),
ADD COLUMN cloudfront_url VARCHAR(1024),
ADD COLUMN storage_class VARCHAR(50) DEFAULT 'STANDARD',
ADD COLUMN upload_status VARCHAR(50) DEFAULT 'pending',
ADD COLUMN upload_progress INTEGER DEFAULT 0,
ADD COLUMN file_hash VARCHAR(64),
ADD COLUMN archived_at TIMESTAMP,
ADD INDEX idx_s3_key (s3_key),
ADD INDEX idx_upload_status (upload_status);

-- Add cloud export tracking table
CREATE TABLE video_exports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  camera_id UUID NOT NULL REFERENCES cameras(id),
  user_id UUID NOT NULL REFERENCES users(id),
  export_id VARCHAR(255) UNIQUE NOT NULL,
  start_time TIMESTAMP NOT NULL,
  end_time TIMESTAMP NOT NULL,
  format VARCHAR(20) NOT NULL,
  quality VARCHAR(20) NOT NULL,
  s3_key VARCHAR(512),
  cloudfront_url VARCHAR(1024),
  file_size BIGINT,
  file_hash VARCHAR(64),
  watermark_id VARCHAR(255),
  status VARCHAR(50) NOT NULL DEFAULT 'processing',
  reason TEXT NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP,
  expires_at TIMESTAMP,
  INDEX idx_export_status (status),
  INDEX idx_tenant_camera (tenant_id, camera_id),
  INDEX idx_created_at (created_at)
);
```

### 5. Background Jobs

Set up background jobs for storage optimization:

```typescript
// src/jobs/storageOptimizer.ts
import { CronJob } from 'cron';
import { CloudStorageService } from '../services/storageService';

export function setupStorageJobs() {
  const storageService = new CloudStorageService({
    bucket: process.env.S3_BUCKET!,
    region: process.env.AWS_REGION!,
  });

  // Daily storage optimization
  new CronJob('0 2 * * *', async () => {
    console.log('Running daily storage optimization...');
    
    try {
      // Clean up temporary files
      const cleanupResult = await storageService.cleanupStorage({
        deleteEmptyFolders: true,
        removeOrphaned: true,
      });
      
      console.log(`Cleaned up ${cleanupResult.deletedFiles} files`);
      
      // Get storage metrics
      const metrics = await storageService.getStorageMetrics();
      
      // Log metrics to monitoring system
      await logMetrics(metrics);
      
    } catch (error) {
      console.error('Storage optimization failed:', error);
    }
  }).start();

  // Hourly migration check for hybrid mode
  if (process.env.VIDEO_STORAGE_PATH) {
    new CronJob('0 * * * *', async () => {
      console.log('Checking for videos to migrate...');
      
      // Migrate videos older than 1 hour
      await migrateOldVideos(storageService);
    }).start();
  }
}
```

### 6. Migration Strategy

For existing deployments, use a phased migration approach:

```typescript
// src/services/hybridStorage.ts
export class HybridStorageService {
  private localStorage: LocalStorageService;
  private cloudStorage: CloudStorageService;
  
  async getVideoUrl(videoId: string): Promise<string> {
    // Check cloud storage first
    const cloudUrl = await this.getCloudUrl(videoId);
    if (cloudUrl) return cloudUrl;
    
    // Fall back to local storage
    const localPath = await this.getLocalPath(videoId);
    if (localPath) {
      // Queue for migration
      await this.queueForMigration(videoId, localPath);
      return this.generateLocalUrl(localPath);
    }
    
    throw new Error('Video not found');
  }
  
  private async queueForMigration(videoId: string, localPath: string) {
    // Add to migration queue for background processing
    await this.redis.lpush('migration-queue', JSON.stringify({
      videoId,
      localPath,
      priority: 'low'
    }));
  }
}
```

### 7. Monitoring Integration

Add CloudWatch metrics to your monitoring dashboard:

```typescript
// src/services/monitoring.ts
import { CloudWatch } from '@aws-sdk/client-cloudwatch';

export class MonitoringService {
  private cloudWatch: CloudWatch;
  
  async recordStorageMetrics(metrics: StorageMetrics) {
    const putMetricData = {
      Namespace: 'SPARC/VideoStorage',
      MetricData: [
        {
          MetricName: 'TotalStorageSize',
          Value: metrics.totalSize,
          Unit: 'Bytes',
          Timestamp: new Date(),
        },
        {
          MetricName: 'FileCount',
          Value: metrics.fileCount,
          Unit: 'Count',
          Timestamp: new Date(),
        },
        // Add more metrics as needed
      ],
    };
    
    await this.cloudWatch.putMetricData(putMetricData);
  }
}
```

### 8. API Updates

Update your API responses to include CloudFront URLs:

```typescript
// Before
{
  "videoId": "123",
  "url": "/api/video/stream/123",
  "thumbnailUrl": "/api/video/thumbnail/123"
}

// After
{
  "videoId": "123",
  "url": "https://cdn.sparc.io/videos/123/playlist.m3u8",
  "thumbnailUrl": "https://cdn.sparc.io/thumbnails/123.jpg",
  "urls": {
    "hls": "https://cdn.sparc.io/videos/123/playlist.m3u8",
    "mp4": "https://cdn.sparc.io/videos/123/video.mp4",
    "dash": "https://cdn.sparc.io/videos/123/manifest.mpd"
  },
  "adaptiveBitrate": true,
  "storageClass": "STANDARD"
}
```

### 9. Error Handling

Implement proper error handling for cloud storage operations:

```typescript
export class CloudStorageErrorHandler {
  async handleUploadError(error: any, context: UploadContext) {
    if (error.name === 'NoSuchBucket') {
      // Bucket doesn't exist
      await this.notifyOps('S3 bucket not found', context);
      throw new ServiceUnavailableError('Storage service unavailable');
    }
    
    if (error.name === 'AccessDenied') {
      // Permission issue
      await this.notifyOps('S3 access denied', context);
      throw new ServiceUnavailableError('Storage access denied');
    }
    
    if (error.name === 'RequestTimeout') {
      // Network issue - retry with exponential backoff
      return await this.retryWithBackoff(context);
    }
    
    // Unknown error
    await this.logError(error, context);
    throw new InternalServerError('Upload failed');
  }
}
```

### 10. Testing

Update your tests to work with cloud storage:

```typescript
// src/__tests__/cloudStorage.test.ts
import { CloudStorageService } from '../services/storageService';
import { mockClient } from 'aws-sdk-client-mock';
import { S3Client } from '@aws-sdk/client-s3';

describe('CloudStorageService', () => {
  const s3Mock = mockClient(S3Client);
  
  beforeEach(() => {
    s3Mock.reset();
  });
  
  it('should upload video with progress tracking', async () => {
    const storage = new CloudStorageService({
      bucket: 'test-bucket',
      region: 'us-east-1',
    });
    
    const progressUpdates: any[] = [];
    
    const url = await storage.uploadVideo(
      Buffer.from('test video data'),
      'test-key.mp4',
      {
        tenantId: 'tenant1',
        cameraId: 'camera1',
        onProgress: (progress) => {
          progressUpdates.push(progress);
        },
      }
    );
    
    expect(url).toContain('test-bucket');
    expect(progressUpdates.length).toBeGreaterThan(0);
  });
});
```

## Performance Considerations

### 1. Connection Pooling

```typescript
// Reuse S3 client instances
const s3ClientPool = new Map<string, S3Client>();

function getS3Client(region: string): S3Client {
  if (!s3ClientPool.has(region)) {
    s3ClientPool.set(region, new S3Client({
      region,
      maxAttempts: 3,
      requestHandler: new NodeHttpHandler({
        connectionTimeout: 5000,
        socketTimeout: 120000,
      }),
    }));
  }
  return s3ClientPool.get(region)!;
}
```

### 2. Request Batching

```typescript
// Batch multiple small uploads
class UploadBatcher {
  private queue: UploadRequest[] = [];
  private timer: NodeJS.Timeout | null = null;
  
  async add(request: UploadRequest) {
    this.queue.push(request);
    
    if (this.queue.length >= 10) {
      await this.flush();
    } else if (!this.timer) {
      this.timer = setTimeout(() => this.flush(), 1000);
    }
  }
  
  private async flush() {
    const batch = this.queue.splice(0);
    if (batch.length === 0) return;
    
    // Process batch in parallel
    await Promise.all(
      batch.map(req => this.processUpload(req))
    );
  }
}
```

### 3. Caching Strategy

```typescript
// Cache CloudFront URLs
class UrlCache {
  private cache = new LRUCache<string, string>({
    max: 10000,
    ttl: 1000 * 60 * 60, // 1 hour
  });
  
  async getUrl(key: string): Promise<string> {
    const cached = this.cache.get(key);
    if (cached) return cached;
    
    const url = await this.storageService.getStreamingUrl(key);
    this.cache.set(key, url);
    return url;
  }
}
```

## Rollback Plan

If issues arise, you can rollback to local storage:

1. Set `ENABLE_CLOUD_STORAGE=false` in environment
2. Ensure local storage paths are still accessible
3. Use hybrid storage mode during transition
4. Keep local copies for 30 days after migration

## Support

For issues or questions:
- Check CloudWatch logs: `sparc-video-storage-logs`
- Monitor S3 metrics in CloudWatch dashboard
- Review error logs in `/var/log/sparc/video-storage.log`
- Contact DevOps team for infrastructure issues