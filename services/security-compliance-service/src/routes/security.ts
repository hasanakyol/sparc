import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { tenantMiddleware } from '@sparc/shared/middleware/tenant';
import { telemetry, SpanStatusCode } from '@sparc/shared/telemetry';
import { securityScanRequestSchema, scanFindingUpdateSchema } from '../types/schemas';
import { SecurityScanService } from '../services/security-scan-service';

export const securityRouter = (scanService: SecurityScanService) => {
  const router = new Hono();

  // Apply middleware
  router.use('*', authMiddleware);
  router.use('*', tenantMiddleware);

  // Initiate security scan
  router.post('/scans', zValidator('json', securityScanRequestSchema), async (c) => {
    return telemetry.withSpan('security.createScan', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const scanRequest = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'scan.type': scanRequest.type,
          'scan.target': scanRequest.target
        });

        const scan = await scanService.initiateScan(
          tenantId,
          userId,
          scanRequest
        );
        
        span.setAttribute('scan.id', scan.id);

        return c.json(scan, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get security scans
  router.get('/scans', async (c) => {
    return telemetry.withSpan('security.getScans', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const type = c.req.query('type');
        const status = c.req.query('status');
        const target = c.req.query('target');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.type': type,
          'filter.status': status,
          'filter.target': target
        });

        const scans = await scanService.getScans(tenantId, {
          type,
          status,
          target
        });
        
        span.setAttribute('scans.count', scans.length);

        return c.json({ scans });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get scan by ID
  router.get('/scans/:scanId', async (c) => {
    return telemetry.withSpan('security.getScanById', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const scanId = c.req.param('scanId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'scan.id': scanId
        });

        const scan = await scanService.getScanById(tenantId, scanId);
        
        if (!scan) {
          return c.json({ error: 'Scan not found' }, 404);
        }

        return c.json(scan);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get scan findings
  router.get('/scans/:scanId/findings', async (c) => {
    return telemetry.withSpan('security.getScanFindings', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const scanId = c.req.param('scanId');
        const severity = c.req.query('severity');
        const falsePositive = c.req.query('falsePositive');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'scan.id': scanId,
          'filter.severity': severity,
          'filter.falsePositive': falsePositive
        });

        const findings = await scanService.getScanFindings(tenantId, scanId, {
          severity,
          falsePositive: falsePositive === 'true'
        });
        
        span.setAttribute('findings.count', findings.length);

        return c.json({ findings });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Update scan finding
  router.patch('/findings/:findingId', zValidator('json', scanFindingUpdateSchema), async (c) => {
    return telemetry.withSpan('security.updateFinding', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const findingId = c.req.param('findingId');
        const updates = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'finding.id': findingId
        });

        const updatedFinding = await scanService.updateFinding(
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

  // Cancel scan
  router.post('/scans/:scanId/cancel', async (c) => {
    return telemetry.withSpan('security.cancelScan', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const scanId = c.req.param('scanId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'scan.id': scanId
        });

        const result = await scanService.cancelScan(tenantId, scanId, userId);

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get security dashboard
  router.get('/dashboard', async (c) => {
    return telemetry.withSpan('security.getDashboard', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const period = c.req.query('period') || '30d';
        
        span.setAttributes({
          'tenant.id': tenantId,
          'dashboard.period': period
        });

        const dashboard = await scanService.getSecurityDashboard(tenantId, period);

        return c.json(dashboard);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get vulnerability trends
  router.get('/vulnerabilities/trends', async (c) => {
    return telemetry.withSpan('security.getVulnerabilityTrends', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const days = parseInt(c.req.query('days') || '30');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'trends.days': days
        });

        const trends = await scanService.getVulnerabilityTrends(tenantId, days);

        return c.json(trends);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get security posture score
  router.get('/posture', async (c) => {
    return telemetry.withSpan('security.getPostureScore', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        
        span.setAttribute('tenant.id', tenantId);

        const posture = await scanService.getSecurityPosture(tenantId);

        return c.json(posture);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Schedule recurring scan
  router.post('/scans/schedule', async (c) => {
    return telemetry.withSpan('security.scheduleScan', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const scheduleRequest = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'schedule.type': scheduleRequest.type,
          'schedule.frequency': scheduleRequest.frequency
        });

        const schedule = await scanService.scheduleScan(
          tenantId,
          userId,
          scheduleRequest
        );
        
        span.setAttribute('schedule.id', schedule.id);

        return c.json(schedule, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get scan schedules
  router.get('/scans/schedules', async (c) => {
    return telemetry.withSpan('security.getScanSchedules', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        
        span.setAttribute('tenant.id', tenantId);

        const schedules = await scanService.getScanSchedules(tenantId);
        
        span.setAttribute('schedules.count', schedules.length);

        return c.json({ schedules });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Delete scan schedule
  router.delete('/scans/schedules/:scheduleId', async (c) => {
    return telemetry.withSpan('security.deleteScanSchedule', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const scheduleId = c.req.param('scheduleId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'schedule.id': scheduleId
        });

        await scanService.deleteScanSchedule(tenantId, scheduleId, userId);

        return c.json({ message: 'Schedule deleted successfully' });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get scan report
  router.get('/scans/:scanId/report', async (c) => {
    return telemetry.withSpan('security.getScanReport', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const scanId = c.req.param('scanId');
        const format = c.req.query('format') || 'pdf';
        
        span.setAttributes({
          'tenant.id': tenantId,
          'scan.id': scanId,
          'report.format': format
        });

        const report = await scanService.generateScanReport(
          tenantId,
          scanId,
          format as 'pdf' | 'html' | 'json'
        );

        // Set headers based on format
        if (format === 'pdf') {
          c.header('Content-Type', 'application/pdf');
          c.header('Content-Disposition', `attachment; filename="scan-report-${scanId}.pdf"`);
        } else if (format === 'html') {
          c.header('Content-Type', 'text/html');
        } else {
          c.header('Content-Type', 'application/json');
          c.header('Content-Disposition', `attachment; filename="scan-report-${scanId}.json"`);
        }

        return c.body(report);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Integration status
  router.get('/integrations', async (c) => {
    return telemetry.withSpan('security.getIntegrations', async (span) => {
      try {
        const integrations = await scanService.getIntegrationStatus();
        
        span.setAttribute('integrations.count', Object.keys(integrations).length);

        return c.json({ integrations });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  return router;
};