import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { tenantMiddleware } from '@sparc/shared/middleware/tenant';
import { telemetry, SpanStatusCode } from '@sparc/shared/telemetry';
import { 
  auditLogSchema, 
  auditLogQuerySchema, 
  auditLogExportSchema 
} from '../types/schemas';
import { AuditService } from '../services/audit-service';

export const auditRouter = (auditService: AuditService) => {
  const router = new Hono();

  // Apply middleware
  router.use('*', authMiddleware);
  router.use('*', tenantMiddleware);

  // Get audit logs with filtering and pagination
  router.get('/', zValidator('query', auditLogQuerySchema), async (c) => {
    return telemetry.withSpan('audit.getLogs', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const query = c.req.valid('query');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'query.page': query.page,
          'query.limit': query.limit
        });

        const result = await auditService.getAuditLogs(tenantId, query);
        
        span.setAttributes({
          'result.count': result.logs.length,
          'result.total': result.pagination.total
        });

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Create audit log entry
  router.post('/', zValidator('json', auditLogSchema), async (c) => {
    return telemetry.withSpan('audit.createLog', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const data = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'user.id': userId,
          'audit.action': data.action,
          'audit.resourceType': data.resourceType
        });

        const auditLog = await auditService.createAuditLog({
          tenantId,
          userId,
          ...data,
          ipAddress: c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
          traceId: telemetry.getCurrentTraceId(),
          sessionId: c.get('sessionId')
        });

        span.setAttribute('audit.id', auditLog.id);

        return c.json(auditLog, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get audit log statistics
  router.get('/stats', async (c) => {
    return telemetry.withSpan('audit.getStats', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const period = c.req.query('period') || '7d';
        
        span.setAttributes({
          'tenant.id': tenantId,
          'stats.period': period
        });

        const stats = await auditService.getAuditStats(tenantId, period);

        return c.json(stats);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Export audit logs
  router.post('/export', zValidator('json', auditLogExportSchema), async (c) => {
    return telemetry.withSpan('audit.exportLogs', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const exportRequest = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'export.format': exportRequest.format,
          'export.startDate': exportRequest.startDate,
          'export.endDate': exportRequest.endDate
        });

        // Log the export action
        await auditService.createAuditLog({
          tenantId,
          userId,
          action: 'EXPORT',
          resourceType: 'AUDIT_LOG',
          details: {
            format: exportRequest.format,
            dateRange: {
              start: exportRequest.startDate,
              end: exportRequest.endDate
            }
          },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown'
        });

        const exportData = await auditService.exportAuditLogs(tenantId, exportRequest);
        
        span.setAttribute('export.size', exportData.length);

        // Set appropriate headers based on format
        if (exportRequest.format === 'csv') {
          c.header('Content-Type', 'text/csv');
          c.header('Content-Disposition', `attachment; filename="audit-logs-${Date.now()}.csv"`);
        } else if (exportRequest.format === 'json') {
          c.header('Content-Type', 'application/json');
          c.header('Content-Disposition', `attachment; filename="audit-logs-${Date.now()}.json"`);
        } else {
          c.header('Content-Type', 'application/pdf');
          c.header('Content-Disposition', `attachment; filename="audit-logs-${Date.now()}.pdf"`);
        }

        return c.body(exportData);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Search audit logs
  router.post('/search', async (c) => {
    return telemetry.withSpan('audit.searchLogs', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const searchQuery = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'search.query': JSON.stringify(searchQuery)
        });

        const results = await auditService.searchAuditLogs(tenantId, searchQuery);
        
        span.setAttribute('search.results', results.length);

        return c.json({ results });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get audit log by ID
  router.get('/:id', async (c) => {
    return telemetry.withSpan('audit.getLogById', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const logId = c.req.param('id');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'audit.id': logId
        });

        const auditLog = await auditService.getAuditLogById(tenantId, logId);
        
        if (!auditLog) {
          return c.json({ error: 'Audit log not found' }, 404);
        }

        return c.json(auditLog);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Retention management
  router.get('/retention/status', async (c) => {
    return telemetry.withSpan('audit.getRetentionStatus', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        
        span.setAttribute('tenant.id', tenantId);

        const status = await auditService.getRetentionStatus(tenantId);

        return c.json(status);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  return router;
};