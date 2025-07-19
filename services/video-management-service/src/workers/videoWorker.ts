import { VideoProcessor } from '../services/videoProcessor';
import { config } from '@sparc/shared';
import * as dotenv from 'dotenv';
import { mkdir } from 'fs/promises';
import { join } from 'path';

// Load environment variables
dotenv.config();

class VideoProcessingWorker {
  private processor: VideoProcessor;
  private isShuttingDown: boolean = false;

  constructor() {
    this.processor = new VideoProcessor();
    this.setupSignalHandlers();
  }

  async start(): Promise<void> {
    try {
      console.log('Starting video processing worker...');

      // Ensure temp directory exists
      const tempDir = process.env.VIDEO_TEMP_DIR || '/tmp/video-processing';
      await mkdir(tempDir, { recursive: true });

      // Get concurrency from env or use default
      const concurrency = parseInt(process.env.VIDEO_WORKER_CONCURRENCY || '2', 10);

      // Start processing jobs
      this.processor.startWorker(concurrency);

      // Set up event listeners for monitoring
      this.setupEventListeners();

      // Start cleanup task
      this.startCleanupTask();

      console.log(`Video processing worker started with concurrency: ${concurrency}`);
      console.log('Waiting for jobs...');

    } catch (error) {
      console.error('Failed to start video processing worker:', error);
      process.exit(1);
    }
  }

  private setupEventListeners(): void {
    // Job lifecycle events
    this.processor.on('job:queued', ({ jobId, videoId }) => {
      console.log(`Job queued: ${jobId} for video: ${videoId}`);
    });

    this.processor.on('job:active', ({ jobId }) => {
      console.log(`Job active: ${jobId}`);
    });

    this.processor.on('job:progress', ({ jobId, progress }) => {
      console.log(`Job ${jobId} progress: ${progress}%`);
    });

    this.processor.on('job:completed', ({ jobId, result }) => {
      console.log(`Job completed: ${jobId}`, {
        videoId: result.videoId,
        outputUrl: result.outputUrl,
        duration: result.duration,
        format: result.format
      });
    });

    this.processor.on('job:failed', ({ jobId, error }) => {
      console.error(`Job failed: ${jobId}`, error);
    });

    this.processor.on('job:stalled', ({ jobId }) => {
      console.warn(`Job stalled: ${jobId}`);
    });

    // Queue events
    this.processor.on('queue:error', (error) => {
      console.error('Queue error:', error);
    });
  }

  private startCleanupTask(): void {
    // Clean old jobs every hour
    setInterval(async () => {
      if (!this.isShuttingDown) {
        try {
          console.log('Running cleanup task...');
          await this.processor.cleanOldJobs();
          console.log('Cleanup task completed');
        } catch (error) {
          console.error('Cleanup task failed:', error);
        }
      }
    }, 60 * 60 * 1000); // 1 hour
  }

  private setupSignalHandlers(): void {
    const gracefulShutdown = async (signal: string) => {
      if (this.isShuttingDown) {
        return;
      }

      this.isShuttingDown = true;
      console.log(`\n${signal} received, shutting down gracefully...`);

      try {
        // Give jobs 30 seconds to complete
        const shutdownTimeout = setTimeout(() => {
          console.error('Shutdown timeout reached, forcing exit');
          process.exit(1);
        }, 30000);

        await this.processor.shutdown();
        clearTimeout(shutdownTimeout);

        console.log('Worker shut down successfully');
        process.exit(0);
      } catch (error) {
        console.error('Error during shutdown:', error);
        process.exit(1);
      }
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  }

  async getStats(): Promise<void> {
    try {
      const stats = await this.processor.getQueueStats();
      console.log('Queue statistics:', stats);
    } catch (error) {
      console.error('Failed to get queue stats:', error);
    }
  }
}

// Start the worker if this file is run directly
if (require.main === module) {
  const worker = new VideoProcessingWorker();
  
  worker.start().catch((error) => {
    console.error('Worker startup failed:', error);
    process.exit(1);
  });

  // Log stats every minute
  setInterval(() => {
    worker.getStats();
  }, 60000);
}

export default VideoProcessingWorker;