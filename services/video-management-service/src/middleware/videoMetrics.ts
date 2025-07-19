import { Context, Next } from 'hono';
import { VideoProcessor } from '../services/videoProcessor';
import prom from 'prom-client';

// Create metrics
const videoJobsTotal = new prom.Counter({
  name: 'video_processing_jobs_total',
  help: 'Total number of video processing jobs',
  labelNames: ['status', 'operation_type']
});

const videoJobDuration = new prom.Histogram({
  name: 'video_processing_job_duration_seconds',
  help: 'Duration of video processing jobs in seconds',
  labelNames: ['operation_type'],
  buckets: [10, 30, 60, 120, 300, 600, 1800, 3600] // 10s to 1h
});

const videoQueueSize = new prom.Gauge({
  name: 'video_processing_queue_size',
  help: 'Current size of video processing queue',
  labelNames: ['state']
});

const videoProcessingErrors = new prom.Counter({
  name: 'video_processing_errors_total',
  help: 'Total number of video processing errors',
  labelNames: ['error_type', 'operation_type']
});

const videoStorageUsed = new prom.Gauge({
  name: 'video_storage_used_bytes',
  help: 'Amount of storage used for video files',
  labelNames: ['tenant_id', 'storage_type']
});

const videoExportSize = new prom.Histogram({
  name: 'video_export_size_bytes',
  help: 'Size of exported video files',
  labelNames: ['format', 'quality'],
  buckets: [1e6, 10e6, 50e6, 100e6, 500e6, 1e9, 5e9] // 1MB to 5GB
});

// Initialize metrics collector
export class VideoMetricsCollector {
  private processor: VideoProcessor;
  private updateInterval: NodeJS.Timer | null = null;

  constructor(processor: VideoProcessor) {
    this.processor = processor;
    this.setupEventListeners();
    this.startPeriodicUpdate();
  }

  private setupEventListeners(): void {
    // Job lifecycle events
    this.processor.on('job:queued', ({ jobId, videoId }) => {
      videoJobsTotal.inc({ status: 'queued', operation_type: 'unknown' });
    });

    this.processor.on('job:active', ({ jobId }) => {
      videoJobsTotal.inc({ status: 'active', operation_type: 'unknown' });
    });

    this.processor.on('job:completed', ({ jobId, result }) => {
      videoJobsTotal.inc({ status: 'completed', operation_type: 'unknown' });
      
      // Record file size
      if (result.fileSize) {
        videoExportSize.observe(
          { format: result.format || 'mp4', quality: 'high' },
          result.fileSize
        );
      }
    });

    this.processor.on('job:failed', ({ jobId, error }) => {
      videoJobsTotal.inc({ status: 'failed', operation_type: 'unknown' });
      videoProcessingErrors.inc({ 
        error_type: error?.code || 'unknown',
        operation_type: 'unknown'
      });
    });

    this.processor.on('job:progress', ({ jobId, progress }) => {
      // Could track progress metrics if needed
    });

    this.processor.on('queue:error', (error) => {
      videoProcessingErrors.inc({ 
        error_type: 'queue_error',
        operation_type: 'system'
      });
    });
  }

  private startPeriodicUpdate(): void {
    // Update queue metrics every 30 seconds
    this.updateInterval = setInterval(async () => {
      try {
        const stats = await this.processor.getQueueStats();
        
        videoQueueSize.set({ state: 'waiting' }, stats.waiting);
        videoQueueSize.set({ state: 'active' }, stats.active);
        videoQueueSize.set({ state: 'completed' }, stats.completed);
        videoQueueSize.set({ state: 'failed' }, stats.failed);
        videoQueueSize.set({ state: 'delayed' }, stats.delayed);
        videoQueueSize.set({ state: 'paused' }, stats.paused);
        
      } catch (error) {
        console.error('Failed to update queue metrics:', error);
      }
    }, 30000);
  }

  stop(): void {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }

  // Track job duration
  startJobTimer(jobId: string, operationType: string): () => void {
    const start = Date.now();
    return () => {
      const duration = (Date.now() - start) / 1000;
      videoJobDuration.observe({ operation_type: operationType }, duration);
    };
  }

  // Update storage metrics
  updateStorageMetrics(tenantId: string, storageType: string, bytes: number): void {
    videoStorageUsed.set({ tenant_id: tenantId, storage_type: storageType }, bytes);
  }
}

// Middleware to track API metrics
export const videoProcessingMetrics = () => {
  return async (c: Context, next: Next) => {
    const path = c.req.path;
    const method = c.req.method;

    // Track video export requests
    if (path.includes('/exports') && method === 'POST') {
      const start = Date.now();
      await next();
      
      const duration = (Date.now() - start) / 1000;
      // Could add specific export API metrics here
    } else {
      await next();
    }
  };
};

// Export metrics for Prometheus
export const getVideoMetrics = (): string => {
  return prom.register.metrics();
};

// Health check for video processing
export const getVideoProcessingHealth = async (processor: VideoProcessor): Promise<{
  healthy: boolean;
  queue: any;
  issues: string[];
}> => {
  const issues: string[] = [];
  let healthy = true;

  try {
    const stats = await processor.getQueueStats();
    
    // Check for high failure rate
    if (stats.failed > stats.completed * 0.1) {
      issues.push('High failure rate detected');
      healthy = false;
    }

    // Check for queue backlog
    if (stats.waiting > 100) {
      issues.push('Large queue backlog');
      healthy = false;
    }

    // Check for stalled jobs
    if (stats.active > 0 && stats.waiting > 50) {
      issues.push('Possible stalled jobs');
    }

    return {
      healthy,
      queue: stats,
      issues
    };
  } catch (error) {
    return {
      healthy: false,
      queue: null,
      issues: ['Failed to get queue statistics']
    };
  }
};