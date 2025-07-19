# Video Management Service

## Overview

The Video Management Service handles all video-related operations for the SPARC security platform, including:
- Video surveillance and streaming
- Recording management
- Async video processing with Bull queue
- Camera management
- Video exports and transformations

## Async Video Processing

### Architecture

The service implements async video processing using Bull queue for handling CPU-intensive operations without blocking the main service:

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   API       │────▶│  Bull Queue  │────▶│   Worker     │
│  Endpoint   │     │   (Redis)    │     │  Process     │
└─────────────┘     └──────────────┘     └──────────────┘
                            │                     │
                            ▼                     ▼
                    ┌──────────────┐     ┌──────────────┐
                    │ Job Status   │     │   FFmpeg     │
                    │   Updates    │     │ Processing   │
                    └──────────────┘     └──────────────┘
```

### Features

- **Async Processing**: Video operations are queued and processed by dedicated workers
- **Retry Logic**: Automatic retry with exponential backoff for failed jobs
- **Progress Tracking**: Real-time progress updates for long-running operations
- **S3 Integration**: Automatic download/upload of video files from/to S3
- **Multiple Operations**: Support for transcoding, thumbnail generation, watermarking, trimming, compression

### Starting the Service

```bash
# Start the main service
npm run dev

# Start the video processing worker (in separate terminal)
npm run dev:worker

# For production
npm run build
npm start
npm run start:worker
```

### API Endpoints

#### Create Video Export
```http
POST /api/exports
Content-Type: application/json

{
  "videoId": "uuid",
  "operations": [
    {
      "type": "transcode",
      "options": {
        "codec": "h264",
        "bitrate": "1000k",
        "resolution": "1920x1080"
      }
    },
    {
      "type": "thumbnail",
      "options": {
        "timestamps": ["50%"],
        "size": "320x240"
      }
    }
  ]
}
```

#### Check Export Status
```http
GET /api/exports/{jobId}
```

Response:
```json
{
  "id": "jobId",
  "status": "processing",
  "jobStatus": {
    "state": "active",
    "progress": 45,
    "detailedProgress": {
      "percent": 45,
      "currentOperation": "transcode",
      "timemark": "00:02:15"
    }
  }
}
```

#### Get Export Download URL
```http
GET /api/exports/{jobId}/download
```

#### Cancel Export
```http
DELETE /api/exports/{jobId}
```

#### Queue Statistics (Admin)
```http
GET /api/exports/queue/stats
```

### Supported Operations

1. **Transcode**
   - Change video codec
   - Adjust bitrate
   - Change resolution
   - Preset options (ultrafast, fast, medium, slow)

2. **Convert**
   - Change container format (mp4, avi, mov)
   - Audio/video codec conversion

3. **Compress**
   - CRF-based compression
   - Bitrate limiting
   - Quality presets

4. **Watermark**
   - Add image overlay
   - Position control
   - Opacity settings

5. **Trim**
   - Start/end time trimming
   - Duration-based cutting

6. **Thumbnail**
   - Extract frames at specific timestamps
   - Multiple thumbnails per video
   - Custom dimensions

### Configuration

Environment variables:
```env
# Redis for Bull queue
REDIS_URL=redis://localhost:6379

# S3 Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
S3_BUCKET=sparc-videos

# CloudFront (optional)
CLOUDFRONT_DOMAIN=d1234567890.cloudfront.net

# Worker Configuration
VIDEO_WORKER_CONCURRENCY=2
VIDEO_TEMP_DIR=/tmp/video-processing

# Performance
MAX_VIDEO_UPLOAD_SIZE=5GB
VIDEO_PROCESSING_TIMEOUT=3600000
```

### Monitoring

The service exposes Prometheus metrics for monitoring:

- `video_processing_jobs_total`: Total jobs by status
- `video_processing_job_duration_seconds`: Job processing duration
- `video_processing_queue_size`: Current queue size by state
- `video_processing_errors_total`: Processing errors
- `video_storage_used_bytes`: Storage usage metrics
- `video_export_size_bytes`: Export file sizes

Access metrics at `/metrics` endpoint.

### Health Checks

The service provides health checks including:
- Database connectivity
- Redis connectivity
- FFmpeg availability
- Video processor status
- Storage availability

Access health status at `/health` endpoint.

### Error Handling

Jobs automatically retry on failure with exponential backoff:
- 3 retry attempts
- Initial delay: 5 seconds
- Backoff multiplier: 2

Failed jobs are kept for 500 iterations for debugging.

### Scaling

To scale video processing:

1. **Horizontal Scaling**: Run multiple worker processes
   ```bash
   # Worker 1
   VIDEO_WORKER_CONCURRENCY=3 npm run start:worker
   
   # Worker 2
   VIDEO_WORKER_CONCURRENCY=3 npm run start:worker
   ```

2. **Vertical Scaling**: Increase concurrency per worker
   ```env
   VIDEO_WORKER_CONCURRENCY=5
   ```

3. **Distributed Processing**: Workers can run on separate machines sharing the same Redis instance

### Best Practices

1. **File Size Limits**: Implement reasonable file size limits
2. **Operation Timeouts**: Set appropriate timeouts for long operations
3. **Storage Management**: Regularly clean up processed files
4. **Queue Monitoring**: Monitor queue depth and adjust workers accordingly
5. **Error Alerting**: Set up alerts for high failure rates

### Troubleshooting

1. **Jobs Stuck in Queue**
   - Check if workers are running
   - Verify Redis connectivity
   - Check worker logs for errors

2. **High Memory Usage**
   - Reduce worker concurrency
   - Process smaller video chunks
   - Increase available memory

3. **S3 Upload Failures**
   - Verify AWS credentials
   - Check S3 bucket permissions
   - Ensure bucket exists

4. **FFmpeg Errors**
   - Verify FFmpeg installation
   - Check codec support
   - Review input file format

### Development

Run tests:
```bash
npm test
```

Build for production:
```bash
npm run build
```

Clean build artifacts:
```bash
npm run clean
```