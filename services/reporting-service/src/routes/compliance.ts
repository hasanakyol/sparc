import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { ComplianceReportService } from '../services/compliance-report-service';
import { ReportQueueService } from '../services/report-queue-service';
import { ComplianceReportRequestSchema } from '../types/schemas';
import { logger } from '../utils/logger';

export function complianceRoutes(
  complianceService: ComplianceReportService,
  queueService: ReportQueueService
): Hono {
  const app = new Hono();

  // Get available compliance templates
  app.get('/templates', async (c) => {
    try {
      const templates = await complianceService.getComplianceTemplates();

      return c.json({
        success: true,
        templates
      });
    } catch (error) {
      logger.error('Failed to get compliance templates', { error });
      throw new HTTPException(500, { message: 'Failed to get compliance templates' });
    }
  });

  // Generate compliance report
  app.post('/generate',
    zValidator('json', ComplianceReportRequestSchema),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        // Queue the compliance report generation
        const reportId = await queueService.queueReport({
          type: `compliance_${body.framework}` as any,
          format: body.format,
          startDate: body.startDate,
          endDate: body.endDate,
          filters: {
            framework: body.framework,
            includeEvidence: body.includeEvidence,
            includeRecommendations: body.includeRecommendations,
            customControls: body.customControls,
            excludeControls: body.excludeControls
          },
          includeDetails: true,
          tenantId,
          userId
        });

        return c.json({
          success: true,
          reportId,
          message: 'Compliance report generation started'
        }, 202);
      } catch (error) {
        logger.error('Failed to generate compliance report', { error });
        throw new HTTPException(500, { message: 'Failed to generate compliance report' });
      }
    }
  );

  // Get compliance report history
  app.get('/history', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const limit = parseInt(c.req.query('limit') || '10');
      const framework = c.req.query('framework');

      const history = await complianceService.getComplianceHistory(tenantId, limit);

      const filtered = framework
        ? history.filter(h => h.framework === framework)
        : history;

      return c.json({
        success: true,
        reports: filtered
      });
    } catch (error) {
      logger.error('Failed to get compliance history', { error });
      throw new HTTPException(500, { message: 'Failed to get compliance history' });
    }
  });

  // Get current compliance score
  app.get('/score/:framework', async (c) => {
    try {
      const framework = c.req.param('framework');
      const tenantId = c.get('tenantId') as string;

      // Get the most recent compliance report for this framework
      const history = await complianceService.getComplianceHistory(tenantId, 1);
      const latestReport = history.find(h => h.framework === framework);

      if (!latestReport) {
        return c.json({
          success: true,
          score: null,
          message: 'No compliance report found for this framework'
        });
      }

      return c.json({
        success: true,
        score: latestReport.score,
        generatedAt: latestReport.generatedAt,
        reportId: latestReport.id
      });
    } catch (error) {
      logger.error('Failed to get compliance score', { error });
      throw new HTTPException(500, { message: 'Failed to get compliance score' });
    }
  });

  // Schedule compliance report
  app.post('/schedule',
    zValidator('json', z.object({
      name: z.string(),
      framework: z.enum(['sox', 'hipaa', 'pci_dss', 'gdpr', 'iso27001']),
      schedule: z.string(), // Cron expression
      recipients: z.array(z.string().email()),
      includeEvidence: z.boolean().default(true),
      includeRecommendations: z.boolean().default(true)
    })),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        // This would create a scheduled compliance report
        const scheduleId = `comp_sched_${Date.now()}`;

        return c.json({
          success: true,
          scheduleId,
          message: 'Compliance report scheduled'
        });
      } catch (error) {
        logger.error('Failed to schedule compliance report', { error });
        throw new HTTPException(500, { message: 'Failed to schedule compliance report' });
      }
    }
  );

  // Get compliance controls for a framework
  app.get('/controls/:framework', async (c) => {
    try {
      const framework = c.req.param('framework');
      
      const templates = await complianceService.getComplianceTemplates();
      const template = templates.find(t => t.id === framework);

      if (!template) {
        throw new HTTPException(404, { message: 'Framework not found' });
      }

      return c.json({
        success: true,
        framework: template.name,
        controls: template.controls
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to get compliance controls', { error });
      throw new HTTPException(500, { message: 'Failed to get compliance controls' });
    }
  });

  // Generate compliance evidence package
  app.post('/evidence',
    zValidator('json', z.object({
      framework: z.enum(['sox', 'hipaa', 'pci_dss', 'gdpr', 'iso27001']),
      controlIds: z.array(z.string()),
      startDate: z.string().datetime(),
      endDate: z.string().datetime(),
      format: z.enum(['pdf', 'zip']).default('zip')
    })),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        // This would generate an evidence package
        const packageId = `evidence_${Date.now()}`;

        return c.json({
          success: true,
          packageId,
          message: 'Evidence package generation started'
        }, 202);
      } catch (error) {
        logger.error('Failed to generate evidence package', { error });
        throw new HTTPException(500, { message: 'Failed to generate evidence package' });
      }
    }
  );

  // Get compliance trends
  app.get('/trends/:framework', async (c) => {
    try {
      const framework = c.req.param('framework');
      const tenantId = c.get('tenantId') as string;
      const months = parseInt(c.req.query('months') || '12');

      // This would calculate compliance score trends
      const trends = {
        framework,
        period: `${months} months`,
        data: [] as any[]
      };

      return c.json({
        success: true,
        trends
      });
    } catch (error) {
      logger.error('Failed to get compliance trends', { error });
      throw new HTTPException(500, { message: 'Failed to get compliance trends' });
    }
  });

  return app;
}