import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { tenantMiddleware } from '@sparc/shared/middleware/tenant';
import { telemetry, SpanStatusCode } from '@sparc/shared/telemetry';
import { retentionPolicySchema, legalHoldSchema } from '../types/schemas';
import { RetentionService } from '../services/retention-service';

export const retentionRouter = (retentionService: RetentionService) => {
  const router = new Hono();

  // Apply middleware
  router.use('*', authMiddleware);
  router.use('*', tenantMiddleware);

  // Get retention policies
  router.get('/policies', async (c) => {
    return telemetry.withSpan('retention.getPolicies', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const dataType = c.req.query('dataType');
        const classification = c.req.query('classification');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.dataType': dataType,
          'filter.classification': classification
        });

        const policies = await retentionService.getRetentionPolicies(tenantId, {
          dataType,
          classification
        });
        
        span.setAttribute('policies.count', policies.length);

        return c.json({ policies });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Create retention policy
  router.post('/policies', zValidator('json', retentionPolicySchema), async (c) => {
    return telemetry.withSpan('retention.createPolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const policy = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.dataType': policy.dataType,
          'policy.retentionDays': policy.retentionPeriodDays
        });

        const createdPolicy = await retentionService.createRetentionPolicy(
          tenantId,
          userId,
          policy
        );
        
        span.setAttribute('policy.id', createdPolicy.id);

        return c.json(createdPolicy, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Update retention policy
  router.put('/policies/:policyId', async (c) => {
    return telemetry.withSpan('retention.updatePolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const policyId = c.req.param('policyId');
        const updates = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.id': policyId
        });

        const updatedPolicy = await retentionService.updateRetentionPolicy(
          tenantId,
          policyId,
          userId,
          updates
        );

        return c.json(updatedPolicy);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Delete retention policy
  router.delete('/policies/:policyId', async (c) => {
    return telemetry.withSpan('retention.deletePolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const policyId = c.req.param('policyId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.id': policyId
        });

        await retentionService.deleteRetentionPolicy(
          tenantId,
          policyId,
          userId
        );

        return c.json({ message: 'Retention policy deleted successfully' });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get retention status
  router.get('/status', async (c) => {
    return telemetry.withSpan('retention.getStatus', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const dataType = c.req.query('dataType');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.dataType': dataType
        });

        const status = await retentionService.getRetentionStatus(tenantId, dataType);

        return c.json(status);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Apply legal hold
  router.post('/legal-hold', zValidator('json', legalHoldSchema), async (c) => {
    return telemetry.withSpan('retention.applyLegalHold', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const holdRequest = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'hold.recordCount': holdRequest.recordIds.length
        });

        const result = await retentionService.applyLegalHold(
          tenantId,
          userId,
          holdRequest
        );
        
        span.setAttribute('hold.applied', result.appliedCount);

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Remove legal hold
  router.delete('/legal-hold', async (c) => {
    return telemetry.withSpan('retention.removeLegalHold', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const { recordIds } = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'hold.recordCount': recordIds.length
        });

        const result = await retentionService.removeLegalHold(
          tenantId,
          userId,
          recordIds
        );
        
        span.setAttribute('hold.removed', result.removedCount);

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get records pending deletion
  router.get('/pending-deletion', async (c) => {
    return telemetry.withSpan('retention.getPendingDeletion', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const days = parseInt(c.req.query('days') || '7');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'pending.days': days
        });

        const records = await retentionService.getRecordsPendingDeletion(
          tenantId,
          days
        );
        
        span.setAttribute('records.count', records.length);

        return c.json({ records });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Execute retention
  router.post('/execute', async (c) => {
    return telemetry.withSpan('retention.executeRetention', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const { dryRun = false, dataType } = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'retention.dryRun': dryRun,
          'retention.dataType': dataType
        });

        const result = await retentionService.executeRetention(
          tenantId,
          userId,
          { dryRun, dataType }
        );
        
        span.setAttributes({
          'retention.processed': result.processed,
          'retention.deleted': result.deleted,
          'retention.archived': result.archived
        });

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get retention dashboard
  router.get('/dashboard', async (c) => {
    return telemetry.withSpan('retention.getDashboard', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        
        span.setAttribute('tenant.id', tenantId);

        const dashboard = await retentionService.getRetentionDashboard(tenantId);

        return c.json(dashboard);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get retention history
  router.get('/history', async (c) => {
    return telemetry.withSpan('retention.getHistory', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const days = parseInt(c.req.query('days') || '30');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'history.days': days
        });

        const history = await retentionService.getRetentionHistory(
          tenantId,
          days
        );
        
        span.setAttribute('history.count', history.length);

        return c.json({ history });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Export retention report
  router.get('/report', async (c) => {
    return telemetry.withSpan('retention.exportReport', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const format = c.req.query('format') || 'pdf';
        const startDate = c.req.query('startDate');
        const endDate = c.req.query('endDate');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'report.format': format,
          'report.startDate': startDate,
          'report.endDate': endDate
        });

        const report = await retentionService.generateRetentionReport(
          tenantId,
          {
            format: format as 'pdf' | 'csv' | 'json',
            startDate,
            endDate
          }
        );

        // Set headers based on format
        if (format === 'pdf') {
          c.header('Content-Type', 'application/pdf');
          c.header('Content-Disposition', 'attachment; filename="retention-report.pdf"');
        } else if (format === 'csv') {
          c.header('Content-Type', 'text/csv');
          c.header('Content-Disposition', 'attachment; filename="retention-report.csv"');
        } else {
          c.header('Content-Type', 'application/json');
          c.header('Content-Disposition', 'attachment; filename="retention-report.json"');
        }

        return c.body(report);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  return router;
};