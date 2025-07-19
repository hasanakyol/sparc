import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { ScheduledReportService } from '../services/scheduled-report-service';
import { ScheduledReportSchema } from '../types/schemas';
import { logger } from '../utils/logger';

export function scheduledRoutes(scheduledReportService: ScheduledReportService): Hono {
  const app = new Hono();

  // Create scheduled report
  app.post('/',
    zValidator('json', ScheduledReportSchema),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        const reportId = await scheduledReportService.createScheduledReport({
          ...body,
          tenantId,
          userId
        });

        return c.json({
          success: true,
          reportId,
          message: 'Scheduled report created'
        }, 201);
      } catch (error) {
        logger.error('Failed to create scheduled report', { error });
        throw new HTTPException(500, { message: 'Failed to create scheduled report' });
      }
    }
  );

  // Get all scheduled reports
  app.get('/', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const isActive = c.req.query('active');

      let reports = await scheduledReportService.getScheduledReports(tenantId);

      if (isActive !== undefined) {
        reports = reports.filter(r => r.isActive === (isActive === 'true'));
      }

      return c.json({
        success: true,
        reports
      });
    } catch (error) {
      logger.error('Failed to get scheduled reports', { error });
      throw new HTTPException(500, { message: 'Failed to get scheduled reports' });
    }
  });

  // Get specific scheduled report
  app.get('/:reportId', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;

      const report = await scheduledReportService.getScheduledReport(reportId, tenantId);

      if (!report) {
        throw new HTTPException(404, { message: 'Scheduled report not found' });
      }

      return c.json({
        success: true,
        report
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to get scheduled report', { error });
      throw new HTTPException(500, { message: 'Failed to get scheduled report' });
    }
  });

  // Update scheduled report
  app.put('/:reportId',
    zValidator('json', ScheduledReportSchema.partial()),
    async (c) => {
      try {
        const reportId = c.req.param('reportId');
        const tenantId = c.get('tenantId') as string;
        const updates = c.req.valid('json');

        await scheduledReportService.updateScheduledReport(reportId, tenantId, updates);

        return c.json({
          success: true,
          message: 'Scheduled report updated'
        });
      } catch (error) {
        logger.error('Failed to update scheduled report', { error });
        throw new HTTPException(500, { message: 'Failed to update scheduled report' });
      }
    }
  );

  // Delete scheduled report
  app.delete('/:reportId', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;

      await scheduledReportService.deleteScheduledReport(reportId, tenantId);

      return c.json({
        success: true,
        message: 'Scheduled report deleted'
      });
    } catch (error) {
      logger.error('Failed to delete scheduled report', { error });
      throw new HTTPException(500, { message: 'Failed to delete scheduled report' });
    }
  });

  // Toggle scheduled report active status
  app.patch('/:reportId/toggle',
    zValidator('json', z.object({
      isActive: z.boolean()
    })),
    async (c) => {
      try {
        const reportId = c.req.param('reportId');
        const tenantId = c.get('tenantId') as string;
        const { isActive } = c.req.valid('json');

        await scheduledReportService.toggleScheduledReport(reportId, tenantId, isActive);

        return c.json({
          success: true,
          message: `Scheduled report ${isActive ? 'activated' : 'deactivated'}`
        });
      } catch (error) {
        logger.error('Failed to toggle scheduled report', { error });
        throw new HTTPException(500, { message: 'Failed to toggle scheduled report' });
      }
    }
  );

  // Execute scheduled report immediately
  app.post('/:reportId/execute', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;

      // Verify report exists and belongs to tenant
      const report = await scheduledReportService.getScheduledReport(reportId, tenantId);
      if (!report) {
        throw new HTTPException(404, { message: 'Scheduled report not found' });
      }

      await scheduledReportService.executeScheduledReport(reportId);

      return c.json({
        success: true,
        message: 'Report execution started'
      }, 202);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to execute scheduled report', { error });
      throw new HTTPException(500, { message: 'Failed to execute scheduled report' });
    }
  });

  // Validate cron expression
  app.post('/validate-cron',
    zValidator('json', z.object({
      expression: z.string()
    })),
    async (c) => {
      try {
        const { expression } = c.req.valid('json');

        const validation = ScheduledReportService.validateCronExpression(expression);

        return c.json({
          success: true,
          valid: validation.valid,
          nextRuns: validation.nextRuns,
          error: validation.error
        });
      } catch (error) {
        logger.error('Failed to validate cron expression', { error });
        throw new HTTPException(500, { message: 'Failed to validate cron expression' });
      }
    }
  );

  // Get scheduled report execution history
  app.get('/:reportId/history', async (c) => {
    try {
      const reportId = c.req.param('reportId');
      const tenantId = c.get('tenantId') as string;
      const limit = parseInt(c.req.query('limit') || '10');

      // This would fetch execution history from database
      const history: any[] = [];

      return c.json({
        success: true,
        history
      });
    } catch (error) {
      logger.error('Failed to get execution history', { error });
      throw new HTTPException(500, { message: 'Failed to get execution history' });
    }
  });

  return app;
}