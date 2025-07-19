import Bull from 'bull';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { ReportingServiceConfig } from '../config';
import { ReportGeneratorService } from './report-generator-service';
import { ReportStorageService } from './report-storage-service';
import { ReportNotificationService } from './report-notification-service';
import {
  ReportJob,
  ReportType,
  ExportFormat,
  ReportStatus,
  ReportParameters,
  ReportResult
} from '../types';
import { ReportRequest } from '../types/schemas';
import { logger } from '../utils/logger';
import { createTracer } from '../utils/telemetry';

const tracer = createTracer('report-queue-service');

export class ReportQueueService {
  private concurrencyLimit: number;

  constructor(
    private queue: Bull.Queue,
    private generatorService: ReportGeneratorService,
    private storageService: ReportStorageService,
    private notificationService: ReportNotificationService,
    private redis: Redis,
    private config: ReportingServiceConfig
  ) {
    this.concurrencyLimit = config.reportGeneration.maxConcurrent;
  }

  async initialize(): Promise<void> {
    // Process report generation jobs
    this.queue.process('generate-report', this.concurrencyLimit, async (job) => {
      return tracer.startActiveSpan('process-report-job', async (span) => {
        try {
          span.setAttributes({
            'report.id': job.data.id,
            'report.type': job.data.type,
            'report.format': job.data.format,
            'report.tenant_id': job.data.tenantId
          });

          await this.processReportJob(job);
          span.setStatus({ code: 1 }); // OK
        } catch (error) {
          span.recordException(error as Error);
          span.setStatus({ code: 2, message: (error as Error).message }); // ERROR
          throw error;
        } finally {
          span.end();
        }
      });
    });

    // Handle job events
    this.queue.on('completed', async (job, result) => {
      logger.info('Report job completed', {
        jobId: job.id,
        reportId: job.data.id,
        duration: Date.now() - job.timestamp
      });
    });

    this.queue.on('failed', async (job, error) => {
      logger.error('Report job failed', {
        jobId: job.id,
        reportId: job.data.id,
        error: error.message,
        stack: error.stack
      });

      // Send failure notification
      if (job.data.userId) {
        await this.notificationService.sendReportFailureNotification(
          job.data.userId,
          job.data.id,
          error.message
        );
      }
    });

    this.queue.on('stalled', async (job) => {
      logger.warn('Report job stalled', {
        jobId: job.id,
        reportId: job.data.id
      });
    });

    // Clean up old jobs periodically
    setInterval(async () => {
      await this.cleanupOldJobs();
    }, 60 * 60 * 1000); // Every hour
  }

  async queueReport(request: ReportRequest & { tenantId: string; userId: string }): Promise<string> {
    const reportId = `rpt_${uuidv4()}`;
    const jobData: ReportJob = {
      id: reportId,
      type: request.type,
      format: request.format,
      status: 'pending',
      tenantId: request.tenantId,
      userId: request.userId,
      parameters: {
        startDate: new Date(request.startDate),
        endDate: new Date(request.endDate),
        filters: request.filters,
        includeDetails: request.includeDetails,
        groupBy: request.groupBy,
        sortBy: request.sortBy,
        sortOrder: request.sortOrder,
        limit: request.limit,
        offset: request.offset,
        customFields: request.customFields,
        locale: request.locale,
        timezone: request.timezone
      },
      createdAt: new Date(),
      updatedAt: new Date(),
      retryCount: 0,
      priority: request.priority || 5
    };

    // Store job metadata in Redis
    await this.redis.setex(
      `report:${reportId}`,
      24 * 60 * 60, // 24 hours
      JSON.stringify(jobData)
    );

    // Add to queue
    const job = await this.queue.add('generate-report', jobData, {
      priority: request.priority || 5,
      timeout: this.config.reportGeneration.timeoutMs,
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000
      }
    });

    logger.info('Report queued', {
      reportId,
      jobId: job.id,
      type: request.type,
      format: request.format
    });

    return reportId;
  }

  async getReportStatus(reportId: string, tenantId: string): Promise<ReportJob | null> {
    const reportData = await this.redis.get(`report:${reportId}`);
    if (!reportData) {
      return null;
    }

    const report = JSON.parse(reportData) as ReportJob;
    
    // Verify tenant access
    if (report.tenantId !== tenantId) {
      return null;
    }

    return report;
  }

  async cancelReport(reportId: string, tenantId: string): Promise<boolean> {
    const report = await this.getReportStatus(reportId, tenantId);
    if (!report || report.status !== 'pending' && report.status !== 'processing') {
      return false;
    }

    // Find and remove job from queue
    const jobs = await this.queue.getJobs(['waiting', 'active']);
    const job = jobs.find(j => j.data.id === reportId);
    
    if (job) {
      await job.remove();
    }

    // Update status
    report.status = 'cancelled';
    report.updatedAt = new Date();
    await this.redis.setex(
      `report:${reportId}`,
      24 * 60 * 60,
      JSON.stringify(report)
    );

    logger.info('Report cancelled', { reportId });
    return true;
  }

  async getQueueStats(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
    delayed: number;
  }> {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.queue.getWaitingCount(),
      this.queue.getActiveCount(),
      this.queue.getCompletedCount(),
      this.queue.getFailedCount(),
      this.queue.getDelayedCount()
    ]);

    return { waiting, active, completed, failed, delayed };
  }

  private async processReportJob(job: Bull.Job<ReportJob>): Promise<void> {
    const reportJob = job.data;
    
    try {
      // Update status to processing
      await this.updateReportStatus(reportJob.id, 'processing');

      // Generate report
      const startTime = Date.now();
      const reportData = await this.generatorService.generateReport(
        reportJob.type,
        reportJob.parameters,
        reportJob.tenantId,
        (progress) => {
          // Update job progress
          job.progress(progress);
        }
      );

      // Convert to requested format
      const formatted = await this.generatorService.formatReport(
        reportData,
        reportJob.format,
        reportJob.type,
        reportJob.parameters
      );

      // Store report
      const stored = await this.storageService.storeReport(
        reportJob.id,
        formatted,
        reportJob.format,
        reportJob.tenantId
      );

      // Update job with result
      const result: ReportResult = {
        filename: stored.filename,
        size: stored.size,
        mimeType: stored.mimeType,
        path: stored.path,
        s3Key: stored.s3Key,
        checksum: stored.checksum,
        pageCount: formatted.pageCount,
        recordCount: reportData.length,
        generationTime: Date.now() - startTime
      };

      reportJob.result = result;
      reportJob.status = 'completed';
      reportJob.completedAt = new Date();
      reportJob.updatedAt = new Date();

      // Update Redis
      await this.redis.setex(
        `report:${reportJob.id}`,
        7 * 24 * 60 * 60, // 7 days for completed reports
        JSON.stringify(reportJob)
      );

      // Send completion notification
      await this.notificationService.sendReportCompletionNotification(
        reportJob.userId,
        reportJob.id,
        result.filename
      );

      logger.info('Report generated successfully', {
        reportId: reportJob.id,
        duration: result.generationTime,
        size: result.size
      });

    } catch (error) {
      logger.error('Report generation failed', {
        reportId: reportJob.id,
        error: (error as Error).message
      });

      // Update status to failed
      reportJob.status = 'failed';
      reportJob.error = (error as Error).message;
      reportJob.updatedAt = new Date();
      reportJob.retryCount++;

      await this.redis.setex(
        `report:${reportJob.id}`,
        24 * 60 * 60,
        JSON.stringify(reportJob)
      );

      throw error;
    }
  }

  private async updateReportStatus(reportId: string, status: ReportStatus): Promise<void> {
    const reportData = await this.redis.get(`report:${reportId}`);
    if (!reportData) {
      return;
    }

    const report = JSON.parse(reportData) as ReportJob;
    report.status = status;
    report.updatedAt = new Date();

    await this.redis.setex(
      `report:${reportId}`,
      24 * 60 * 60,
      JSON.stringify(report)
    );
  }

  private async cleanupOldJobs(): Promise<void> {
    try {
      // Clean completed jobs older than 7 days
      const completedJobs = await this.queue.getCompleted();
      const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      
      for (const job of completedJobs) {
        if (job.finishedOn && job.finishedOn < sevenDaysAgo) {
          await job.remove();
        }
      }

      // Clean failed jobs older than 30 days
      const failedJobs = await this.queue.getFailed();
      const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
      
      for (const job of failedJobs) {
        if (job.finishedOn && job.finishedOn < thirtyDaysAgo) {
          await job.remove();
        }
      }

      logger.info('Old jobs cleaned up');
    } catch (error) {
      logger.error('Failed to cleanup old jobs', { error });
    }
  }

  async shutdown(): Promise<void> {
    await this.queue.pause();
    await this.queue.close();
  }
}