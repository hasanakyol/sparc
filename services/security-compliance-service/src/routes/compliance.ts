import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { tenantMiddleware } from '@sparc/shared/middleware/tenant';
import { telemetry, SpanStatusCode } from '@sparc/shared/telemetry';
import { 
  complianceReportRequestSchema,
  complianceFindingSchema,
  attestationSchema,
  dashboardQuerySchema
} from '../types/schemas';
import { ComplianceService } from '../services/compliance-service';

export const complianceRouter = (complianceService: ComplianceService) => {
  const router = new Hono();

  // Apply middleware
  router.use('*', authMiddleware);
  router.use('*', tenantMiddleware);

  // Get compliance dashboard
  router.get('/dashboard', zValidator('query', dashboardQuerySchema), async (c) => {
    return telemetry.withSpan('compliance.getDashboard', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const query = c.req.valid('query');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'dashboard.period': query.period
        });

        const dashboard = await complianceService.getComplianceDashboard(tenantId, query);

        return c.json(dashboard);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get available compliance frameworks
  router.get('/frameworks', async (c) => {
    return telemetry.withSpan('compliance.getFrameworks', async (span) => {
      try {
        const frameworks = await complianceService.getAvailableFrameworks();
        
        span.setAttribute('frameworks.count', frameworks.length);

        return c.json({ frameworks });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Generate compliance report
  router.post('/reports', zValidator('json', complianceReportRequestSchema), async (c) => {
    return telemetry.withSpan('compliance.generateReport', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const request = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'report.framework': request.framework,
          'report.format': request.format
        });

        const report = await complianceService.generateComplianceReport(
          tenantId,
          userId,
          request
        );
        
        span.setAttribute('report.id', report.id);

        // Return report metadata with download URL
        return c.json({
          reportId: report.id,
          framework: report.framework,
          status: report.status,
          score: report.score,
          downloadUrl: `/api/compliance/reports/${report.id}/download`,
          generatedAt: report.generatedAt
        }, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get compliance reports
  router.get('/reports', async (c) => {
    return telemetry.withSpan('compliance.getReports', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const framework = c.req.query('framework');
        const status = c.req.query('status');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.framework': framework,
          'filter.status': status
        });

        const reports = await complianceService.getComplianceReports(tenantId, {
          framework,
          status
        });
        
        span.setAttribute('reports.count', reports.length);

        return c.json({ reports });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Download compliance report
  router.get('/reports/:reportId/download', async (c) => {
    return telemetry.withSpan('compliance.downloadReport', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const reportId = c.req.param('reportId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'report.id': reportId
        });

        const { data, format, filename } = await complianceService.downloadReport(
          tenantId,
          reportId
        );

        // Set appropriate headers
        const contentType = format === 'pdf' ? 'application/pdf' : 
                          format === 'html' ? 'text/html' : 'application/json';
        
        c.header('Content-Type', contentType);
        c.header('Content-Disposition', `attachment; filename="${filename}"`);

        return c.body(data);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get compliance status for a specific framework
  router.get('/status/:framework', async (c) => {
    return telemetry.withSpan('compliance.getFrameworkStatus', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const framework = c.req.param('framework');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'compliance.framework': framework
        });

        const status = await complianceService.getFrameworkStatus(tenantId, framework);

        return c.json(status);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get compliance findings
  router.get('/findings', async (c) => {
    return telemetry.withSpan('compliance.getFindings', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const framework = c.req.query('framework');
        const severity = c.req.query('severity');
        const status = c.req.query('status');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.framework': framework,
          'filter.severity': severity,
          'filter.status': status
        });

        const findings = await complianceService.getComplianceFindings(tenantId, {
          framework,
          severity,
          status
        });
        
        span.setAttribute('findings.count', findings.length);

        return c.json({ findings });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Create compliance finding
  router.post('/findings', zValidator('json', complianceFindingSchema), async (c) => {
    return telemetry.withSpan('compliance.createFinding', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const finding = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'finding.control': finding.control,
          'finding.severity': finding.severity
        });

        const createdFinding = await complianceService.createComplianceFinding(
          tenantId,
          userId,
          finding
        );
        
        span.setAttribute('finding.id', createdFinding.id);

        return c.json(createdFinding, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Update compliance finding
  router.put('/findings/:findingId', async (c) => {
    return telemetry.withSpan('compliance.updateFinding', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const findingId = c.req.param('findingId');
        const updates = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'finding.id': findingId
        });

        const updatedFinding = await complianceService.updateComplianceFinding(
          tenantId,
          findingId,
          userId,
          updates
        );

        return c.json(updatedFinding);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Create attestation
  router.post('/attestations', zValidator('json', attestationSchema), async (c) => {
    return telemetry.withSpan('compliance.createAttestation', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const attestation = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'attestation.validUntil': attestation.validUntil
        });

        const createdAttestation = await complianceService.createAttestation(
          tenantId,
          userId,
          attestation
        );
        
        span.setAttribute('attestation.id', createdAttestation.id);

        return c.json(createdAttestation, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Run compliance check
  router.post('/check/:framework', async (c) => {
    return telemetry.withSpan('compliance.runCheck', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const framework = c.req.param('framework');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'compliance.framework': framework
        });

        const result = await complianceService.runComplianceCheck(
          tenantId,
          framework,
          userId
        );
        
        span.setAttributes({
          'check.status': result.status,
          'check.score': result.score
        });

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get compliance controls
  router.get('/controls/:framework', async (c) => {
    return telemetry.withSpan('compliance.getControls', async (span) => {
      try {
        const framework = c.req.param('framework');
        
        span.setAttribute('compliance.framework', framework);

        const controls = await complianceService.getFrameworkControls(framework);
        
        span.setAttribute('controls.count', controls.length);

        return c.json({ controls });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  return router;
};