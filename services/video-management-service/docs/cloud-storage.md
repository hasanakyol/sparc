# Cloud Storage Implementation Guide

## Overview

The SPARC platform now includes a comprehensive cloud storage solution for video files, supporting 100,000+ concurrent video streams with automatic archival, CDN distribution, and cost optimization.

## Architecture

### Components

1. **CloudStorageService** - Core service for S3 operations
2. **CloudFront CDN** - Global content distribution
3. **Storage Lifecycle Management** - Automatic archival
4. **Migration Tools** - Batch migration from local storage
5. **Optimization Tools** - Cost reduction through intelligent tiering

### Storage Classes

- **Standard** - Frequently accessed videos (< 30 days)
- **Standard-IA** - Infrequent access (30-90 days)
- **Glacier** - Long-term storage (90-365 days)
- **Deep Archive** - Compliance/legal hold (> 365 days)

## Configuration

### Environment Variables

```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1

# S3 Configuration
S3_BUCKET=sparc-video-storage
S3_ENDPOINT=https://s3.amazonaws.com  # Optional for S3-compatible services

# CloudFront Configuration
CLOUDFRONT_DOMAIN=d1234567890.cloudfront.net
CLOUDFRONT_DISTRIBUTION_ID=E1234567890
CLOUDFRONT_PRIVATE_KEY=your-private-key  # For signed URLs

# Storage Configuration
VIDEO_STORAGE_PATH=/var/video  # Legacy local storage path
VIDEO_TEMP_DIR=/tmp/video-processing
MULTIPART_THRESHOLD=104857600  # 100MB
MULTIPART_CHUNK_SIZE=10485760  # 10MB
```

### Terraform Infrastructure

```hcl
# infra/terraform/modules/storage/main.tf
module "video_storage" {
  source = "./modules/s3"
  
  bucket_name = "sparc-video-storage-${var.environment}"
  versioning  = true
  
  lifecycle_rules = [
    {
      id      = "archive_old_videos"
      enabled = true
      
      transitions = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
        {
          days          = 90
          storage_class = "GLACIER"
        },
        {
          days          = 365
          storage_class = "DEEP_ARCHIVE"
        }
      ]
    }
  ]
  
  cors_rules = [{
    allowed_methods = ["GET", "HEAD"]
    allowed_origins = ["https://*.sparc.io"]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3600
  }]
}

module "cdn" {
  source = "./modules/cloudfront"
  
  s3_bucket_id     = module.video_storage.bucket_id
  s3_bucket_domain = module.video_storage.bucket_domain_name
  
  behaviors = {
    "video-recordings/*" = {
      cache_policy_id            = "658327ea-f89f-4fab-a63d-7e9047e9d1f0"  # Managed-CachingOptimized
      origin_request_policy_id   = "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf"  # Managed-CORS-S3Origin
      response_headers_policy_id = "60669652-455b-4ae9-85a4-c4c58d6a7e77"  # Managed-CORS-and-SecurityHeaders
    }
  }
  
  geo_restriction = {
    restriction_type = "none"
  }
}
```

## Usage

### Basic Upload

```typescript
import { CloudStorageService } from './services/storageService';

const storage = new CloudStorageService({
  bucket: process.env.S3_BUCKET!,
  region: process.env.AWS_REGION!,
  cloudfrontDomain: process.env.CLOUDFRONT_DOMAIN,
});

// Upload video with progress tracking
const url = await storage.uploadVideo(
  '/path/to/video.mp4',
  'video-recordings/tenant1/camera1/2024-01-15.mp4',
  {
    tenantId: 'tenant1',
    cameraId: 'camera1',
    timestamp: new Date(),
    storageClass: 'STANDARD',
    onProgress: (progress) => {
      console.log(`Upload progress: ${progress.percentage}%`);
      console.log(`Speed: ${progress.speed} bytes/sec`);
      console.log(`Remaining: ${progress.remainingTime} seconds`);
    }
  }
);
```

### Streaming with Adaptive Bitrate

```typescript
// Generate HLS streaming URLs
const streamingUrl = await storage.getStreamingUrl(videoKey, {
  format: 'hls',
  quality: 'auto',  // Enables adaptive bitrate
});

// Generate signed URL for secure access
const signedUrl = await storage.generateSignedUrl(
  videoKey,
  3600,  // 1 hour expiration
  { download: false }
);
```

### Migration from Local Storage

```bash
# Dry run to see what would be migrated
npm run migrate:s3 -- \
  --source /var/video \
  --bucket sparc-video-storage \
  --region us-east-1 \
  --dry-run

# Perform actual migration with verification
npm run migrate:s3 -- \
  --source /var/video \
  --bucket sparc-video-storage \
  --region us-east-1 \
  --batch-size 10 \
  --verify

# Migration with cleanup (deletes local files after successful upload)
npm run migrate:s3 -- \
  --source /var/video \
  --bucket sparc-video-storage \
  --region us-east-1 \
  --delete \
  --continue-on-error
```

### Storage Optimization

```bash
# Analyze storage and show optimization opportunities
npm run optimize:storage -- \
  --bucket sparc-video-storage \
  --region us-east-1 \
  --dry-run

# Optimize storage for a specific tenant
npm run optimize:storage -- \
  --bucket sparc-video-storage \
  --region us-east-1 \
  --tenant tenant1 \
  --archive-after 30 \
  --glacier-after 90 \
  --deep-archive-after 365

# Aggressive optimization with deletion
npm run optimize:storage -- \
  --bucket sparc-video-storage \
  --region us-east-1 \
  --archive-after 7 \
  --glacier-after 30 \
  --deep-archive-after 90 \
  --delete-after 730  # Delete after 2 years
```

## API Endpoints

### Cloud Streaming

```typescript
// POST /stream/cloud
// Request CloudFront streaming URLs
{
  "cameraId": "camera1",
  "startTime": "2024-01-15T10:00:00Z",
  "endTime": "2024-01-15T11:00:00Z",
  "format": "hls",
  "quality": "auto"
}

// Response
{
  "sessionId": "session123",
  "format": "hls",
  "quality": "auto",
  "urls": {
    "master": "https://cdn.sparc.io/streams/master.m3u8?token=...",
    "1080p": "https://cdn.sparc.io/streams/1080p/playlist.m3u8?token=...",
    "720p": "https://cdn.sparc.io/streams/720p/playlist.m3u8?token=...",
    "480p": "https://cdn.sparc.io/streams/480p/playlist.m3u8?token=...",
    "360p": "https://cdn.sparc.io/streams/360p/playlist.m3u8?token=..."
  },
  "adaptiveBitrate": true,
  "bandwidth": 6500000,
  "expiresIn": 3600
}
```

### Export with CDN

```typescript
// POST /export/cloud
// Export video with CloudFront acceleration
{
  "cameraId": "camera1",
  "startTime": "2024-01-15T10:00:00Z",
  "endTime": "2024-01-15T11:00:00Z",
  "format": "mp4",
  "quality": "high",
  "includeWatermark": true,
  "reason": "Legal request #12345"
}

// Response
{
  "exportId": "export123",
  "status": "processing",
  "downloadUrl": "https://cdn.sparc.io/exports/export123.mp4?token=...",
  "expiresIn": 86400,
  "estimatedTime": 5  // minutes
}
```

## Performance Optimization

### Multipart Upload

For files larger than 100MB, the system automatically uses multipart upload:

- **Concurrent Parts**: 4 simultaneous uploads
- **Part Size**: 10MB per part
- **Automatic Retry**: 3 attempts with exponential backoff
- **Resume Support**: Failed uploads can be resumed

### CDN Caching Strategy

```
Cache-Control Headers:
- Live Streams: no-cache (always fresh)
- Recent Recordings: max-age=3600 (1 hour)
- Archived Videos: max-age=86400 (24 hours)
- Thumbnails: max-age=604800 (7 days)
```

### Bandwidth Optimization

1. **Adaptive Bitrate Streaming**
   - Automatic quality adjustment based on bandwidth
   - Reduces buffering and improves playback

2. **Range Requests**
   - Supports video seeking without downloading entire file
   - Reduces bandwidth for partial views

3. **Compression**
   - Gzip compression for playlists and metadata
   - Brotli compression for modern browsers

## Cost Management

### Storage Costs (per GB/month)

- Standard: $0.023
- Standard-IA: $0.0125 (45% savings)
- Glacier: $0.004 (83% savings)
- Deep Archive: $0.00099 (96% savings)

### Transfer Costs

- CloudFront to Internet: $0.085/GB (first 10TB)
- S3 to CloudFront: $0.00 (free)
- Cross-region replication: $0.02/GB

### Cost Optimization Tips

1. **Enable Lifecycle Policies**
   ```bash
   # Automatic transitions save 70-95% on old footage
   30 days → Standard-IA: 45% savings
   90 days → Glacier: 83% savings
   365 days → Deep Archive: 96% savings
   ```

2. **Use CloudFront**
   - Reduces S3 request costs
   - Lower transfer costs than S3 direct
   - Better global performance

3. **Clean Temporary Files**
   ```bash
   # Run daily cleanup job
   0 2 * * * cd /app && npm run optimize:storage -- --cleanup-only
   ```

## Monitoring

### CloudWatch Metrics

```typescript
// Key metrics to monitor
- BucketSizeBytes: Total storage used
- NumberOfObjects: Total file count
- AllRequests: Request rate
- 4xxErrors: Client errors
- 5xxErrors: Server errors
- BytesDownloaded: Transfer volume
- FirstByteLatency: Response time
```

### Alarms

```hcl
# terraform/modules/monitoring/storage-alarms.tf
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "video-storage-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "4xxErrors"
  namespace           = "AWS/S3"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "S3 bucket experiencing high error rate"
}

resource "aws_cloudwatch_metric_alarm" "storage_limit" {
  alarm_name          = "video-storage-approaching-limit"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "BucketSizeBytes"
  namespace           = "AWS/S3"
  period              = "3600"
  statistic           = "Average"
  threshold           = "5000000000000"  # 5TB
  alarm_description   = "Video storage approaching limit"
}
```

## Security

### Encryption

- **At Rest**: AES-256 encryption (SSE-S3)
- **In Transit**: TLS 1.2+ for all transfers
- **Key Management**: AWS KMS for sensitive videos

### Access Control

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::cloudfront:user/CloudFront-OAI"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::sparc-video-storage/*"
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::sparc-video-storage/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### Signed URLs

For sensitive content, use time-limited signed URLs:

```typescript
const signedUrl = await storage.generateSignedUrl(
  videoKey,
  300,  // 5 minutes
  {
    download: true,
    filename: 'evidence_video.mp4'
  }
);
```

## Troubleshooting

### Common Issues

1. **Upload Failures**
   - Check AWS credentials
   - Verify bucket permissions
   - Ensure sufficient disk space for temp files

2. **Slow Uploads**
   - Increase multipart chunk size
   - Check network bandwidth
   - Use transfer acceleration

3. **CDN Not Working**
   - Verify CloudFront distribution status
   - Check origin access identity
   - Clear CDN cache if needed

### Debug Mode

```bash
# Enable verbose logging
export LOG_LEVEL=debug
export AWS_SDK_LOAD_CONFIG=1
export AWS_SDK_LOG_LEVEL=debug

# Test S3 connectivity
aws s3 ls s3://sparc-video-storage --debug

# Test CloudFront
curl -I https://cdn.sparc.io/test.mp4
```

## Best Practices

1. **Use Appropriate Storage Classes**
   - Hot data: Standard
   - Warm data: Standard-IA
   - Cold data: Glacier
   - Archive: Deep Archive

2. **Implement Retry Logic**
   - Use exponential backoff
   - Set reasonable timeout values
   - Log all retry attempts

3. **Monitor Costs**
   - Set up billing alerts
   - Review storage class distribution
   - Optimize lifecycle policies

4. **Plan for Scale**
   - Use consistent key naming
   - Implement request throttling
   - Design for multi-region

5. **Security First**
   - Never expose S3 buckets publicly
   - Use signed URLs for sensitive content
   - Enable access logging
   - Regular security audits