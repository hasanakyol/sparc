import Bull from 'bull';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import ffmpeg from 'fluent-ffmpeg';
import { createReadStream, createWriteStream, unlink } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { promisify } from 'util';
import { config } from '@sparc/shared';
import Redis from 'ioredis';
import { EventEmitter } from 'events';

const unlinkAsync = promisify(unlink);

export interface VideoProcessingParams {
  videoId: string;
  tenantId: string;
  operations: VideoOperation[];
  metadata?: Record<string, any>;
}

export interface VideoOperation {
  type: 'transcode' | 'thumbnail' | 'convert' | 'watermark' | 'trim' | 'compress';
  options: any;
}

export interface VideoJobData extends VideoProcessingParams {
  inputS3Key: string;
  outputS3Key?: string;
  startTime: Date;
}

export interface VideoJobResult {
  videoId: string;
  outputUrl: string;
  duration: number;
  format: string;
  fileSize: number;
  thumbnailUrl?: string;
  metadata: Record<string, any>;
}

export interface ProcessingProgress {
  percent: number;
  frames: number;
  currentFps: number;
  currentKbps: number;
  targetSize: number;
  timemark: string;
  currentOperation?: string;
}

export class VideoProcessor extends EventEmitter {
  private queue: Bull.Queue<VideoJobData>;
  private s3Client: S3Client;
  private tempDir: string;
  private redis: Redis;

  constructor() {
    super();
    
    // Initialize S3 client
    this.s3Client = new S3Client({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!
      }
    });

    // Initialize Redis for Bull
    this.redis = new Redis(config.redis?.url || process.env.REDIS_URL || 'redis://localhost:6379');

    // Initialize Bull queue with retry configuration
    this.queue = new Bull('video-processing', {
      redis: {
        port: this.redis.options.port,
        host: this.redis.options.host,
        password: this.redis.options.password
      },
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 5000
        },
        removeOnComplete: 100,
        removeOnFail: 500
      }
    });

    // Set temporary directory for video processing
    this.tempDir = process.env.VIDEO_TEMP_DIR || '/tmp/video-processing';

    // Set up queue event handlers
    this.setupQueueEvents();
  }

  /**
   * Queue a video for processing
   */
  async queueVideoProcessing(params: VideoProcessingParams): Promise<{ jobId: string; status: string }> {
    try {
      // Generate S3 keys
      const inputS3Key = this.generateS3Key(params.tenantId, params.videoId, 'input');
      const outputS3Key = this.generateS3Key(params.tenantId, params.videoId, 'output');

      const jobData: VideoJobData = {
        ...params,
        inputS3Key,
        outputS3Key,
        startTime: new Date()
      };

      // Add job to queue with priority based on operations
      const priority = this.calculatePriority(params.operations);
      const job = await this.queue.add('process-video', jobData, {
        priority,
        delay: 0
      });

      // Store job metadata in Redis for quick lookup
      await this.redis.setex(
        `video-job:${job.id}`,
        86400, // 24 hours
        JSON.stringify({
          videoId: params.videoId,
          tenantId: params.tenantId,
          status: 'queued',
          queuedAt: new Date()
        })
      );

      this.emit('job:queued', { jobId: job.id, videoId: params.videoId });

      return { jobId: job.id.toString(), status: 'queued' };
    } catch (error) {
      console.error('Failed to queue video processing:', error);
      throw error;
    }
  }

  /**
   * Process video job (worker)
   */
  async processVideo(job: Bull.Job<VideoJobData>): Promise<VideoJobResult> {
    const { videoId, operations, inputS3Key, outputS3Key, tenantId } = job.data;
    const jobId = job.id;

    let tempInputPath: string | null = null;
    let tempOutputPath: string | null = null;

    try {
      // Update job status
      await this.updateJobStatus(jobId.toString(), 'processing');

      // Download video from S3
      job.progress(5);
      tempInputPath = await this.downloadFromS3(inputS3Key, videoId);

      // Process video operations sequentially
      let currentPath = tempInputPath;
      let operationIndex = 0;

      for (const operation of operations) {
        job.progress(10 + (operationIndex * 30) / operations.length);
        
        const outputPath = join(this.tempDir, `${videoId}_${operation.type}_${uuidv4()}.mp4`);
        
        await this.executeOperation(
          operation,
          currentPath,
          outputPath,
          (progress) => {
            const overallProgress = 10 + (operationIndex * 30) / operations.length + 
              (progress.percent * 30) / operations.length / 100;
            job.progress(overallProgress);
            
            // Update detailed progress
            this.updateDetailedProgress(jobId.toString(), {
              ...progress,
              currentOperation: operation.type
            });
          }
        );

        // Clean up previous temp file if not the original
        if (currentPath !== tempInputPath) {
          await unlinkAsync(currentPath);
        }

        currentPath = outputPath;
        operationIndex++;
      }

      tempOutputPath = currentPath;

      // Get video metadata
      job.progress(70);
      const metadata = await this.getVideoMetadata(tempOutputPath);

      // Upload to S3
      job.progress(80);
      const outputUrl = await this.uploadToS3(tempOutputPath, outputS3Key!, tenantId, videoId);

      // Generate thumbnail if requested
      let thumbnailUrl: string | undefined;
      const thumbnailOp = operations.find(op => op.type === 'thumbnail');
      if (thumbnailOp) {
        job.progress(90);
        const thumbnailPath = await this.generateThumbnail(tempOutputPath, thumbnailOp.options);
        const thumbnailS3Key = this.generateS3Key(tenantId, videoId, 'thumbnail');
        thumbnailUrl = await this.uploadToS3(thumbnailPath, thumbnailS3Key, tenantId, videoId);
        await unlinkAsync(thumbnailPath);
      }

      job.progress(100);

      // Update job status
      await this.updateJobStatus(jobId.toString(), 'completed');

      const result: VideoJobResult = {
        videoId,
        outputUrl,
        duration: metadata.duration,
        format: metadata.format,
        fileSize: metadata.fileSize,
        thumbnailUrl,
        metadata
      };

      this.emit('job:completed', { jobId: jobId.toString(), result });

      return result;

    } catch (error) {
      console.error(`Failed to process video ${videoId}:`, error);
      await this.updateJobStatus(jobId.toString(), 'failed', error);
      this.emit('job:failed', { jobId: jobId.toString(), error });
      throw error;

    } finally {
      // Clean up temp files
      if (tempInputPath) {
        try {
          await unlinkAsync(tempInputPath);
        } catch (e) {
          console.error('Failed to clean up input file:', e);
        }
      }
      if (tempOutputPath && tempOutputPath !== tempInputPath) {
        try {
          await unlinkAsync(tempOutputPath);
        } catch (e) {
          console.error('Failed to clean up output file:', e);
        }
      }
    }
  }

  /**
   * Get job status
   */
  async getJobStatus(jobId: string): Promise<any> {
    const job = await this.queue.getJob(jobId);
    if (!job) {
      return null;
    }

    const progress = job.progress();
    const state = await job.getState();
    
    // Get detailed progress from Redis
    const detailedProgress = await this.redis.get(`video-job-progress:${jobId}`);

    return {
      id: job.id,
      state,
      progress,
      detailedProgress: detailedProgress ? JSON.parse(detailedProgress) : null,
      data: {
        videoId: job.data.videoId,
        tenantId: job.data.tenantId,
        operations: job.data.operations
      },
      attemptsMade: job.attemptsMade,
      finishedOn: job.finishedOn,
      processedOn: job.processedOn,
      failedReason: job.failedReason
    };
  }

  /**
   * Cancel a job
   */
  async cancelJob(jobId: string): Promise<void> {
    const job = await this.queue.getJob(jobId);
    if (job) {
      await job.remove();
      await this.updateJobStatus(jobId, 'cancelled');
      this.emit('job:cancelled', { jobId });
    }
  }

  /**
   * Get queue statistics
   */
  async getQueueStats(): Promise<any> {
    const [waiting, active, completed, failed, delayed, paused] = await Promise.all([
      this.queue.getWaitingCount(),
      this.queue.getActiveCount(),
      this.queue.getCompletedCount(),
      this.queue.getFailedCount(),
      this.queue.getDelayedCount(),
      this.queue.getPausedCount()
    ]);

    return {
      waiting,
      active,
      completed,
      failed,
      delayed,
      paused,
      total: waiting + active + completed + failed + delayed + paused
    };
  }

  /**
   * Clean old jobs
   */
  async cleanOldJobs(grace: number = 86400000): Promise<void> {
    await this.queue.clean(grace, 'completed');
    await this.queue.clean(grace, 'failed');
  }

  // Private methods

  private setupQueueEvents(): void {
    this.queue.on('error', (error) => {
      console.error('Queue error:', error);
      this.emit('queue:error', error);
    });

    this.queue.on('waiting', (jobId) => {
      console.log(`Job ${jobId} is waiting`);
    });

    this.queue.on('active', (job) => {
      console.log(`Job ${job.id} has started`);
      this.emit('job:active', { jobId: job.id.toString() });
    });

    this.queue.on('stalled', (job) => {
      console.log(`Job ${job.id} has stalled`);
      this.emit('job:stalled', { jobId: job.id.toString() });
    });

    this.queue.on('progress', (job, progress) => {
      this.emit('job:progress', { jobId: job.id.toString(), progress });
    });

    this.queue.on('completed', (job, result) => {
      console.log(`Job ${job.id} completed`);
    });

    this.queue.on('failed', (job, error) => {
      console.error(`Job ${job.id} failed:`, error);
    });
  }

  private async downloadFromS3(s3Key: string, videoId: string): Promise<string> {
    const localPath = join(this.tempDir, `${videoId}_input_${uuidv4()}.mp4`);
    
    try {
      const command = new GetObjectCommand({
        Bucket: process.env.S3_BUCKET!,
        Key: s3Key
      });

      const response = await this.s3Client.send(command);
      const stream = response.Body as NodeJS.ReadableStream;
      const writeStream = createWriteStream(localPath);

      return new Promise((resolve, reject) => {
        stream.pipe(writeStream)
          .on('error', reject)
          .on('finish', () => resolve(localPath));
      });
    } catch (error) {
      console.error(`Failed to download from S3: ${s3Key}`, error);
      throw error;
    }
  }

  private async uploadToS3(localPath: string, s3Key: string, tenantId: string, videoId: string): Promise<string> {
    try {
      const fileStream = createReadStream(localPath);
      
      const command = new PutObjectCommand({
        Bucket: process.env.S3_BUCKET!,
        Key: s3Key,
        Body: fileStream,
        ContentType: 'video/mp4',
        Metadata: {
          tenantId,
          videoId,
          processedAt: new Date().toISOString()
        }
      });

      await this.s3Client.send(command);

      // Return CloudFront URL if configured, otherwise S3 URL
      if (process.env.CLOUDFRONT_DOMAIN) {
        return `https://${process.env.CLOUDFRONT_DOMAIN}/${s3Key}`;
      } else {
        return `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3Key}`;
      }
    } catch (error) {
      console.error(`Failed to upload to S3: ${s3Key}`, error);
      throw error;
    }
  }

  private async executeOperation(
    operation: VideoOperation,
    inputPath: string,
    outputPath: string,
    onProgress: (progress: ProcessingProgress) => void
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      let command = ffmpeg(inputPath);

      switch (operation.type) {
        case 'transcode':
          command = this.applyTranscodeOptions(command, operation.options);
          break;
        case 'convert':
          command = this.applyConvertOptions(command, operation.options);
          break;
        case 'compress':
          command = this.applyCompressOptions(command, operation.options);
          break;
        case 'watermark':
          command = this.applyWatermarkOptions(command, operation.options);
          break;
        case 'trim':
          command = this.applyTrimOptions(command, operation.options);
          break;
        case 'thumbnail':
          // Thumbnail generation is handled separately
          resolve();
          return;
        default:
          reject(new Error(`Unknown operation type: ${operation.type}`));
          return;
      }

      command
        .on('progress', (progress) => {
          onProgress({
            percent: progress.percent || 0,
            frames: progress.frames || 0,
            currentFps: progress.currentFps || 0,
            currentKbps: progress.currentKbps || 0,
            targetSize: progress.targetSize || 0,
            timemark: progress.timemark || '00:00:00'
          });
        })
        .on('error', (err) => {
          console.error(`FFmpeg error for ${operation.type}:`, err);
          reject(err);
        })
        .on('end', () => {
          console.log(`Completed ${operation.type} operation`);
          resolve();
        })
        .save(outputPath);
    });
  }

  private applyTranscodeOptions(command: ffmpeg.FfmpegCommand, options: any): ffmpeg.FfmpegCommand {
    const { codec = 'h264', bitrate = '1000k', resolution, preset = 'medium' } = options;

    command.videoCodec(codec);
    
    if (bitrate) {
      command.videoBitrate(bitrate);
    }
    
    if (resolution) {
      command.size(resolution);
    }
    
    if (preset) {
      command.outputOptions(`-preset ${preset}`);
    }

    // Add audio codec
    command.audioCodec('aac');

    return command;
  }

  private applyConvertOptions(command: ffmpeg.FfmpegCommand, options: any): ffmpeg.FfmpegCommand {
    const { format = 'mp4', videoCodec = 'h264', audioCodec = 'aac' } = options;

    command.format(format);
    
    if (videoCodec) {
      command.videoCodec(videoCodec);
    }
    
    if (audioCodec) {
      command.audioCodec(audioCodec);
    }

    return command;
  }

  private applyCompressOptions(command: ffmpeg.FfmpegCommand, options: any): ffmpeg.FfmpegCommand {
    const { crf = 23, preset = 'medium', maxBitrate } = options;

    command
      .videoCodec('libx264')
      .outputOptions([
        `-crf ${crf}`,
        `-preset ${preset}`
      ]);

    if (maxBitrate) {
      command.videoBitrate(maxBitrate);
    }

    return command;
  }

  private applyWatermarkOptions(command: ffmpeg.FfmpegCommand, options: any): ffmpeg.FfmpegCommand {
    const { imagePath, position = 'bottomright', opacity = 0.8 } = options;

    if (!imagePath) {
      throw new Error('Watermark image path is required');
    }

    const positionMap: Record<string, string> = {
      'topleft': '10:10',
      'topright': 'main_w-overlay_w-10:10',
      'bottomleft': '10:main_h-overlay_h-10',
      'bottomright': 'main_w-overlay_w-10:main_h-overlay_h-10',
      'center': '(main_w-overlay_w)/2:(main_h-overlay_h)/2'
    };

    const overlayPosition = positionMap[position] || positionMap.bottomright;

    command
      .input(imagePath)
      .complexFilter([
        `[1:v]format=rgba,colorchannelmixer=aa=${opacity}[watermark]`,
        `[0:v][watermark]overlay=${overlayPosition}`
      ]);

    return command;
  }

  private applyTrimOptions(command: ffmpeg.FfmpegCommand, options: any): ffmpeg.FfmpegCommand {
    const { startTime, duration, endTime } = options;

    if (startTime) {
      command.setStartTime(startTime);
    }

    if (duration) {
      command.duration(duration);
    } else if (endTime && startTime) {
      const durationSeconds = this.timecodeToSeconds(endTime) - this.timecodeToSeconds(startTime);
      command.duration(durationSeconds);
    }

    return command;
  }

  private async generateThumbnail(videoPath: string, options: any = {}): Promise<string> {
    const { 
      timestamps = ['50%'], 
      size = '320x240',
      folder = this.tempDir 
    } = options;

    const thumbnailPath = join(folder, `thumbnail_${uuidv4()}.jpg`);

    return new Promise((resolve, reject) => {
      ffmpeg(videoPath)
        .screenshots({
          timestamps,
          filename: thumbnailPath,
          size
        })
        .on('error', reject)
        .on('end', () => resolve(thumbnailPath));
    });
  }

  private async getVideoMetadata(videoPath: string): Promise<any> {
    return new Promise((resolve, reject) => {
      ffmpeg.ffprobe(videoPath, (err, metadata) => {
        if (err) {
          reject(err);
          return;
        }

        const videoStream = metadata.streams.find(s => s.codec_type === 'video');
        const audioStream = metadata.streams.find(s => s.codec_type === 'audio');

        resolve({
          duration: metadata.format.duration,
          format: metadata.format.format_name,
          fileSize: metadata.format.size,
          bitrate: metadata.format.bit_rate,
          videoCodec: videoStream?.codec_name,
          videoWidth: videoStream?.width,
          videoHeight: videoStream?.height,
          fps: videoStream ? eval(videoStream.r_frame_rate) : null,
          audioCodec: audioStream?.codec_name,
          audioBitrate: audioStream?.bit_rate,
          audioSampleRate: audioStream?.sample_rate
        });
      });
    });
  }

  private generateS3Key(tenantId: string, videoId: string, type: string): string {
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    
    return `video-processing/${tenantId}/${year}/${month}/${day}/${videoId}/${type}.mp4`;
  }

  private calculatePriority(operations: VideoOperation[]): number {
    // Higher priority for simpler operations
    const weights: Record<string, number> = {
      thumbnail: 10,
      trim: 8,
      watermark: 6,
      compress: 4,
      convert: 2,
      transcode: 1
    };

    const totalWeight = operations.reduce((sum, op) => sum + (weights[op.type] || 0), 0);
    return Math.min(10, Math.max(1, Math.floor(totalWeight / operations.length)));
  }

  private timecodeToSeconds(timecode: string): number {
    const parts = timecode.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid timecode format. Expected HH:MM:SS');
    }
    
    const hours = parseInt(parts[0], 10);
    const minutes = parseInt(parts[1], 10);
    const seconds = parseFloat(parts[2]);
    
    return hours * 3600 + minutes * 60 + seconds;
  }

  private async updateJobStatus(jobId: string, status: string, error?: any): Promise<void> {
    const key = `video-job:${jobId}`;
    const data = await this.redis.get(key);
    
    if (data) {
      const jobData = JSON.parse(data);
      jobData.status = status;
      jobData.updatedAt = new Date();
      
      if (error) {
        jobData.error = error.message || error;
      }
      
      await this.redis.setex(key, 86400, JSON.stringify(jobData));
    }
  }

  private async updateDetailedProgress(jobId: string, progress: ProcessingProgress): Promise<void> {
    await this.redis.setex(
      `video-job-progress:${jobId}`,
      3600, // 1 hour
      JSON.stringify({
        ...progress,
        updatedAt: new Date()
      })
    );
  }

  /**
   * Start processing jobs
   */
  startWorker(concurrency: number = 2): void {
    this.queue.process('process-video', concurrency, async (job) => {
      return this.processVideo(job);
    });

    console.log(`Video processing worker started with concurrency: ${concurrency}`);
  }

  /**
   * Gracefully shutdown the processor
   */
  async shutdown(): Promise<void> {
    await this.queue.close();
    await this.redis.quit();
    this.removeAllListeners();
    console.log('Video processor shut down gracefully');
  }
}

export default VideoProcessor;