import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { ReportQueueService } from '../services/report-queue-service';
import { ReportStorageService } from '../services/report-storage-service';
import { ScheduledReportService } from '../services/scheduled-report-service';
import { ReportRequestSchema, BulkReportRequestSchema } from '../types/schemas';
import { logger } from '../utils/logger';

export function reportRoutes(
  queueService: ReportQueueService,
  storageService: ReportStorageService,
  scheduledReportService: ScheduledReportService
): Hono {
  const app = new Hono();

  // Generate a new report
  app.post('/generate',
    zValidator('json', ReportRequestSchema),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        const reportId = await queueService.queueReport({
          ...body,
          tenantId,
          userId
        });

        return c.json({
          success: true,
          reportId,
          message: 'Report generation started'
        }, 202);
      } catch (error) {
        logger.error('Failed to generate report', { error });
        throw new HTTPException(500, { message: 'Failed to generate report' });
      }
    }
  );

  // Generate multiple reports in bulk
  app.post('/bulk-generate',
    zValidator('json', BulkReportRequestSchema),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        const reportIds: string[] = [];
        
        for (const report of body.reports) {
          const reportId = await queueService.queueReport({
            ...report,
            tenantId,
            userId
          });
          reportIds.push(reportId);
        }

        return c.json({
          success: true,
          reportIds,
          message: `${reportIds.length} reports queued for generation`
        }, 202);
      } catch (error) {
        logger.error('Failed to generate bulk reports', { error });
        throw new HTTPException(500, { message: 'Failed to generate bulk reports' });
      }
    }
  );

  // Get report status
  app.get('/:reportId/status', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;

      const status = await queueService.getReportStatus(reportId, tenantId);
      
      if (!status) {
        throw new HTTPException(404, { message: 'Report not found' });
      }

      return c.json({
        success: true,
        status: {
          id: status.id,
          type: status.type,
          format: status.format,
          status: status.status,
          createdAt: status.createdAt,
          updatedAt: status.updatedAt,
          completedAt: status.completedAt,
          result: status.result,
          error: status.error
        }
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to get report status', { error });
      throw new HTTPException(500, { message: 'Failed to get report status' });
    }
  });

  // Download report
  app.get('/:reportId/download', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;

      // Check if report is ready
      const status = await queueService.getReportStatus(reportId, tenantId);
      if (!status) {
        throw new HTTPException(404, { message: 'Report not found' });
      }

      if (status.status !== 'completed') {
        throw new HTTPException(400, { message: 'Report not ready for download' });
      }

      // Retrieve report file
      const reportData = await storageService.retrieveReport(reportId, tenantId);
      if (!reportData) {
        throw new HTTPException(404, { message: 'Report file not found' });
      }

      // Set appropriate headers
      c.header('Content-Type', status.result!.mimeType);
      c.header('Content-Disposition', `attachment; filename="${status.result!.filename}"`);
      c.header('Content-Length', reportData.length.toString());

      return c.body(reportData);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to download report', { error });
      throw new HTTPException(500, { message: 'Failed to download report' });
    }
  });

  // Get download URL (for S3 storage)
  app.get('/:reportId/url', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;

      const url = await storageService.getDownloadUrl(reportId, tenantId);
      
      if (!url) {
        throw new HTTPException(404, { message: 'Report not found' });
      }

      return c.json({
        success: true,
        url,
        expiresIn: 3600 // 1 hour
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to get download URL', { error });
      throw new HTTPException(500, { message: 'Failed to get download URL' });
    }
  });

  // Cancel report generation
  app.delete('/:reportId', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;

      const cancelled = await queueService.cancelReport(reportId, tenantId);
      
      if (!cancelled) {
        throw new HTTPException(400, { message: 'Report cannot be cancelled' });
      }

      return c.json({
        success: true,
        message: 'Report generation cancelled'
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to cancel report', { error });
      throw new HTTPException(500, { message: 'Failed to cancel report' });
    }
  });

  // Get report history
  app.get('/history', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const limit = parseInt(c.req.query('limit') || '10');
      const offset = parseInt(c.req.query('offset') || '0');
      const type = c.req.query('type');
      const status = c.req.query('status');

      // This would be implemented to fetch from database
      const history: any[] = [];

      return c.json({
        success: true,
        data: history,
        pagination: {
          limit,
          offset,
          total: 0
        }
      });
    } catch (error) {
      logger.error('Failed to get report history', { error });
      throw new HTTPException(500, { message: 'Failed to get report history' });
    }
  });

  // Get queue statistics
  app.get('/queue/stats', async (c) => {
    try {
      const stats = await queueService.getQueueStats();

      return c.json({
        success: true,
        stats
      });
    } catch (error) {
      logger.error('Failed to get queue stats', { error });
      throw new HTTPException(500, { message: 'Failed to get queue statistics' });
    }
  });

  // Get storage statistics
  app.get('/storage/stats', async (c) => {
    try {
      const stats = await storageService.getStorageStats();

      return c.json({
        success: true,
        stats
      });
    } catch (error) {
      logger.error('Failed to get storage stats', { error });
      throw new HTTPException(500, { message: 'Failed to get storage statistics' });
    }
  });

  return app;
}