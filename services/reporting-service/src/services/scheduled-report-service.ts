import { PrismaClient } from '@prisma/client';
import Bull from 'bull';
import cron from 'node-cron';
import { v4 as uuidv4 } from 'uuid';
import { ReportingServiceConfig } from '../config';
import { ScheduledReport, ReportType, ExportFormat } from '../types';
import { ScheduledReportRequest } from '../types/schemas';
import { logger } from '../utils/logger';
import { createTracer } from '../utils/telemetry';

const tracer = createTracer('scheduled-report-service');

export class ScheduledReportService {
  private scheduledJobs: Map<string, cron.ScheduledTask> = new Map();

  constructor(
    private prisma: PrismaClient,
    private reportQueue: Bull.Queue,
    private config: ReportingServiceConfig
  ) {}

  async initialize(): Promise<void> {
    logger.info('Initializing scheduled report service');
    
    // Load all active scheduled reports
    const activeReports = await this.prisma.scheduledReport.findMany({
      where: { isActive: true }
    });

    // Schedule jobs for active reports
    for (const report of activeReports) {
      try {
        this.scheduleJob(report);
      } catch (error) {
        logger.error('Failed to schedule report job', {
          reportId: report.id,
          error: (error as Error).message
        });
      }
    }

    logger.info(`Scheduled ${activeReports.length} report jobs`);
  }

  async createScheduledReport(
    request: ScheduledReportRequest & { tenantId: string; userId: string }
  ): Promise<string> {
    return tracer.startActiveSpan('create-scheduled-report', async (span) => {
      try {
        const reportId = `sched_${uuidv4()}`;
        
        span.setAttributes({
          'scheduled_report.id': reportId,
          'scheduled_report.type': request.type,
          'scheduled_report.schedule': request.schedule
        });

        // Validate cron expression
        if (!cron.validate(request.schedule)) {
          throw new Error('Invalid cron expression');
        }

        // Create scheduled report in database
        const scheduledReport = await this.prisma.scheduledReport.create({
          data: {
            id: reportId,
            name: request.name,
            description: request.description,
            type: request.type,
            format: request.format,
            schedule: request.schedule,
            recipients: request.recipients,
            parameters: request.parameters,
            isActive: request.isActive,
            tenantId: request.tenantId,
            createdBy: request.userId,
            metadata: request.metadata || {},
            nextRun: this.getNextRunTime(request.schedule),
            runCount: 0,
            failureCount: 0
          }
        });

        // Schedule the job if active
        if (scheduledReport.isActive) {
          this.scheduleJob(scheduledReport);
        }

        logger.info('Scheduled report created', {
          reportId,
          name: request.name,
          schedule: request.schedule
        });

        return reportId;
      } finally {
        span.end();
      }
    });
  }

  async updateScheduledReport(
    reportId: string,
    tenantId: string,
    updates: Partial<ScheduledReportRequest>
  ): Promise<void> {
    return tracer.startActiveSpan('update-scheduled-report', async (span) => {
      try {
        span.setAttributes({
          'scheduled_report.id': reportId,
          'scheduled_report.tenant_id': tenantId
        });

        // Get existing report
        const existingReport = await this.prisma.scheduledReport.findFirst({
          where: { id: reportId, tenantId }
        });

        if (!existingReport) {
          throw new Error('Scheduled report not found');
        }

        // Validate cron expression if schedule is being updated
        if (updates.schedule && !cron.validate(updates.schedule)) {
          throw new Error('Invalid cron expression');
        }

        // Update report
        const updatedReport = await this.prisma.scheduledReport.update({
          where: { id: reportId },
          data: {
            ...updates,
            nextRun: updates.schedule ? this.getNextRunTime(updates.schedule) : undefined,
            updatedAt: new Date()
          }
        });

        // Reschedule job if needed
        if (this.scheduledJobs.has(reportId)) {
          this.unscheduleJob(reportId);
        }

        if (updatedReport.isActive) {
          this.scheduleJob(updatedReport);
        }

        logger.info('Scheduled report updated', { reportId });
      } finally {
        span.end();
      }
    });
  }

  async deleteScheduledReport(reportId: string, tenantId: string): Promise<void> {
    return tracer.startActiveSpan('delete-scheduled-report', async (span) => {
      try {
        span.setAttributes({
          'scheduled_report.id': reportId,
          'scheduled_report.tenant_id': tenantId
        });

        // Unschedule job
        this.unscheduleJob(reportId);

        // Delete from database
        await this.prisma.scheduledReport.deleteMany({
          where: { id: reportId, tenantId }
        });

        logger.info('Scheduled report deleted', { reportId });
      } finally {
        span.end();
      }
    });
  }

  async getScheduledReports(tenantId: string): Promise<ScheduledReport[]> {
    const reports = await this.prisma.scheduledReport.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' }
    });

    return reports.map(report => ({
      ...report,
      type: report.type as ReportType,
      format: report.format as ExportFormat,
      parameters: report.parameters as any,
      metadata: report.metadata as any
    }));
  }

  async getScheduledReport(reportId: string, tenantId: string): Promise<ScheduledReport | null> {
    const report = await this.prisma.scheduledReport.findFirst({
      where: { id: reportId, tenantId }
    });

    if (!report) {
      return null;
    }

    return {
      ...report,
      type: report.type as ReportType,
      format: report.format as ExportFormat,
      parameters: report.parameters as any,
      metadata: report.metadata as any
    };
  }

  async toggleScheduledReport(reportId: string, tenantId: string, isActive: boolean): Promise<void> {
    const report = await this.prisma.scheduledReport.update({
      where: { id: reportId },
      data: { isActive }
    });

    if (isActive) {
      this.scheduleJob(report);
    } else {
      this.unscheduleJob(reportId);
    }

    logger.info('Scheduled report toggled', { reportId, isActive });
  }

  async executeScheduledReport(reportId: string): Promise<void> {
    return tracer.startActiveSpan('execute-scheduled-report', async (span) => {
      try {
        span.setAttributes({ 'scheduled_report.id': reportId });

        const report = await this.prisma.scheduledReport.findUnique({
          where: { id: reportId }
        });

        if (!report || !report.isActive) {
          logger.warn('Scheduled report not found or inactive', { reportId });
          return;
        }

        logger.info('Executing scheduled report', {
          reportId,
          name: report.name,
          type: report.type
        });

        // Calculate date range based on parameters
        const { startDate, endDate } = this.calculateDateRange(report.parameters as any);

        // Queue the report generation
        const jobData = {
          type: report.type,
          format: report.format,
          startDate: startDate.toISOString(),
          endDate: endDate.toISOString(),
          filters: (report.parameters as any).filters,
          includeDetails: (report.parameters as any).includeDetails ?? true,
          groupBy: (report.parameters as any).groupBy,
          customFields: (report.parameters as any).customFields,
          locale: (report.parameters as any).locale,
          timezone: (report.parameters as any).timezone,
          tenantId: report.tenantId,
          userId: report.createdBy,
          scheduledReportId: reportId,
          recipients: report.recipients
        };

        await this.reportQueue.add('generate-report', jobData, {
          priority: 3, // Lower priority for scheduled reports
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 5000
          }
        });

        // Update last run and next run times
        await this.prisma.scheduledReport.update({
          where: { id: reportId },
          data: {
            lastRun: new Date(),
            nextRun: this.getNextRunTime(report.schedule),
            runCount: { increment: 1 }
          }
        });

        logger.info('Scheduled report queued', { reportId });
      } catch (error) {
        logger.error('Failed to execute scheduled report', {
          reportId,
          error: (error as Error).message
        });

        // Update failure count
        await this.prisma.scheduledReport.update({
          where: { id: reportId },
          data: {
            failureCount: { increment: 1 }
          }
        });

        throw error;
      } finally {
        span.end();
      }
    });
  }

  private scheduleJob(report: any): void {
    if (this.scheduledJobs.has(report.id)) {
      logger.warn('Job already scheduled', { reportId: report.id });
      return;
    }

    const job = cron.schedule(report.schedule, async () => {
      try {
        await this.executeScheduledReport(report.id);
      } catch (error) {
        logger.error('Scheduled job execution failed', {
          reportId: report.id,
          error: (error as Error).message
        });
      }
    }, {
      scheduled: true,
      timezone: (report.parameters as any).timezone || 'UTC'
    });

    this.scheduledJobs.set(report.id, job);
    logger.info('Job scheduled', {
      reportId: report.id,
      name: report.name,
      schedule: report.schedule
    });
  }

  private unscheduleJob(reportId: string): void {
    const job = this.scheduledJobs.get(reportId);
    if (job) {
      job.stop();
      this.scheduledJobs.delete(reportId);
      logger.info('Job unscheduled', { reportId });
    }
  }

  private getNextRunTime(cronExpression: string): Date {
    const interval = cron.parseExpression(cronExpression);
    return interval.next().toDate();
  }

  private calculateDateRange(parameters: any): { startDate: Date; endDate: Date } {
    const now = new Date();
    let startDate: Date;
    let endDate: Date = now;

    if (parameters.startDate && parameters.endDate) {
      // Fixed date range
      startDate = new Date(parameters.startDate);
      endDate = new Date(parameters.endDate);
    } else if (parameters.relativePeriod) {
      // Relative period
      switch (parameters.relativePeriod) {
        case 'last_day':
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
          break;
        case 'last_week':
          startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          break;
        case 'last_month':
          startDate = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
          break;
        case 'last_quarter':
          startDate = new Date(now.getFullYear(), now.getMonth() - 3, now.getDate());
          break;
        case 'last_year':
          startDate = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate());
          break;
        default:
          startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      }
    } else {
      // Default to last 24 hours
      startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }

    return { startDate, endDate };
  }

  async shutdown(): Promise<void> {
    logger.info('Shutting down scheduled report service');
    
    // Stop all scheduled jobs
    for (const [reportId, job] of this.scheduledJobs) {
      job.stop();
      logger.debug('Stopped scheduled job', { reportId });
    }
    
    this.scheduledJobs.clear();
  }

  // Utility method to validate and test cron expressions
  static validateCronExpression(expression: string): { valid: boolean; nextRuns?: Date[]; error?: string } {
    try {
      if (!cron.validate(expression)) {
        return { valid: false, error: 'Invalid cron expression' };
      }

      const interval = cron.parseExpression(expression);
      const nextRuns: Date[] = [];
      
      for (let i = 0; i < 5; i++) {
        nextRuns.push(interval.next().toDate());
      }

      return { valid: true, nextRuns };
    } catch (error) {
      return { valid: false, error: (error as Error).message };
    }
  }
}