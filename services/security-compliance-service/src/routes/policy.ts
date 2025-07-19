import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { tenantMiddleware } from '@sparc/shared/middleware/tenant';
import { telemetry, SpanStatusCode } from '@sparc/shared/telemetry';
import { securityPolicySchema, policyUpdateSchema } from '../types/schemas';
import { PolicyEngine } from '../services/policy-engine';

export const policyRouter = (policyEngine: PolicyEngine) => {
  const router = new Hono();

  // Apply middleware
  router.use('*', authMiddleware);
  router.use('*', tenantMiddleware);

  // Get all policies
  router.get('/', async (c) => {
    return telemetry.withSpan('policy.getPolicies', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const type = c.req.query('type');
        const enabled = c.req.query('enabled');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.type': type,
          'filter.enabled': enabled
        });

        const policies = await policyEngine.getPolicies(tenantId, {
          type,
          enabled: enabled ? enabled === 'true' : undefined
        });
        
        span.setAttribute('policies.count', policies.length);

        return c.json({ policies });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Create policy
  router.post('/', zValidator('json', securityPolicySchema), async (c) => {
    return telemetry.withSpan('policy.createPolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const policy = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.name': policy.name,
          'policy.type': policy.type
        });

        const createdPolicy = await policyEngine.createPolicy(
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

  // Get policy by ID
  router.get('/:policyId', async (c) => {
    return telemetry.withSpan('policy.getPolicyById', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const policyId = c.req.param('policyId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.id': policyId
        });

        const policy = await policyEngine.getPolicyById(tenantId, policyId);
        
        if (!policy) {
          return c.json({ error: 'Policy not found' }, 404);
        }

        return c.json(policy);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Update policy
  router.put('/:policyId', zValidator('json', policyUpdateSchema), async (c) => {
    return telemetry.withSpan('policy.updatePolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const policyId = c.req.param('policyId');
        const updates = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.id': policyId
        });

        const updatedPolicy = await policyEngine.updatePolicy(
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

  // Delete policy
  router.delete('/:policyId', async (c) => {
    return telemetry.withSpan('policy.deletePolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const policyId = c.req.param('policyId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.id': policyId
        });

        await policyEngine.deletePolicy(tenantId, policyId, userId);

        return c.json({ message: 'Policy deleted successfully' });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Evaluate policy
  router.post('/evaluate', async (c) => {
    return telemetry.withSpan('policy.evaluatePolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const context = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'evaluation.context': JSON.stringify(context)
        });

        const result = await policyEngine.evaluatePolicies(tenantId, context);
        
        span.setAttributes({
          'evaluation.action': result.action,
          'evaluation.matchedPolicies': result.matchedPolicies.length
        });

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Test policy
  router.post('/:policyId/test', async (c) => {
    return telemetry.withSpan('policy.testPolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const policyId = c.req.param('policyId');
        const testContext = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.id': policyId
        });

        const result = await policyEngine.testPolicy(
          tenantId,
          policyId,
          testContext
        );
        
        span.setAttribute('test.matched', result.matched);

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Clone policy
  router.post('/:policyId/clone', async (c) => {
    return telemetry.withSpan('policy.clonePolicy', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const policyId = c.req.param('policyId');
        const { name, description } = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'policy.id': policyId,
          'clone.name': name
        });

        const clonedPolicy = await policyEngine.clonePolicy(
          tenantId,
          policyId,
          userId,
          { name, description }
        );
        
        span.setAttribute('clone.id', clonedPolicy.id);

        return c.json(clonedPolicy, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get policy violations
  router.get('/violations', async (c) => {
    return telemetry.withSpan('policy.getViolations', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const startDate = c.req.query('startDate');
        const endDate = c.req.query('endDate');
        const policyId = c.req.query('policyId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.startDate': startDate,
          'filter.endDate': endDate,
          'filter.policyId': policyId
        });

        const violations = await policyEngine.getPolicyViolations(tenantId, {
          startDate,
          endDate,
          policyId
        });
        
        span.setAttribute('violations.count', violations.length);

        return c.json({ violations });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Export policies
  router.get('/export', async (c) => {
    return telemetry.withSpan('policy.exportPolicies', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const format = c.req.query('format') || 'json';
        
        span.setAttributes({
          'tenant.id': tenantId,
          'export.format': format
        });

        const exportData = await policyEngine.exportPolicies(tenantId, format);
        
        // Set headers based on format
        if (format === 'yaml') {
          c.header('Content-Type', 'application/x-yaml');
          c.header('Content-Disposition', 'attachment; filename="policies.yaml"');
        } else {
          c.header('Content-Type', 'application/json');
          c.header('Content-Disposition', 'attachment; filename="policies.json"');
        }

        return c.body(exportData);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Import policies
  router.post('/import', async (c) => {
    return telemetry.withSpan('policy.importPolicies', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const { policies, overwrite = false } = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'import.count': policies.length,
          'import.overwrite': overwrite
        });

        const result = await policyEngine.importPolicies(
          tenantId,
          userId,
          policies,
          overwrite
        );
        
        span.setAttributes({
          'import.created': result.created,
          'import.updated': result.updated,
          'import.skipped': result.skipped
        });

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get policy templates
  router.get('/templates', async (c) => {
    return telemetry.withSpan('policy.getTemplates', async (span) => {
      try {
        const type = c.req.query('type');
        
        span.setAttribute('filter.type', type);

        const templates = await policyEngine.getPolicyTemplates(type);
        
        span.setAttribute('templates.count', templates.length);

        return c.json({ templates });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  return router;
};