import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { SecurityMonitoringService } from '../services/main-service';
import { prisma } from '@sparc/shared/database/prisma';

const alertRuleSchema = z.object({
  name: z.string(),
  description: z.string(),
  conditions: z.array(z.object({
    field: z.string(),
    operator: z.enum(['equals', 'contains', 'greater_than', 'less_than', 'in', 'not_in']),
    value: z.any(),
    aggregation: z.object({
      window: z.number(),
      threshold: z.number()
    }).optional()
  })),
  actions: z.array(z.object({
    type: z.enum(['email', 'webhook', 'sms', 'slack', 'pagerduty']),
    config: z.record(z.any())
  })),
  enabled: z.boolean().default(true),
  cooldownMinutes: z.number().optional()
});

const alertStatusSchema = z.object({
  acknowledged: z.boolean().optional(),
  resolved: z.boolean().optional(),
  assignee: z.string().optional(),
  notes: z.string().optional()
});

export function alertsRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Get all alert rules
  app.get('/rules', async (c) => {
    const tenantId = c.get('tenantId');

    const rules = await prisma.$queryRaw`
      SELECT * FROM alert_rules
      WHERE organization_id = ${tenantId}
      ORDER BY created_at DESC
    `;

    return c.json(rules);
  });

  // Create alert rule
  app.post('/rules', zValidator('json', alertRuleSchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const rule = {
      id: crypto.randomUUID(),
      ...data,
      organization_id: tenantId,
      created_by: userId,
      created_at: new Date(),
      updated_at: new Date()
    };

    await prisma.$executeRawUnsafe(`
      INSERT INTO alert_rules (
        id, name, description, conditions, actions, 
        enabled, cooldown_minutes, organization_id, 
        created_by, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `,
      rule.id,
      rule.name,
      rule.description,
      JSON.stringify(rule.conditions),
      JSON.stringify(rule.actions),
      rule.enabled,
      rule.cooldownMinutes || null,
      rule.organization_id,
      rule.created_by,
      rule.created_at,
      rule.updated_at
    );

    return c.json(rule, 201);
  });

  // Update alert rule
  app.put('/rules/:id', zValidator('json', alertRuleSchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      UPDATE alert_rules
      SET name = $1, description = $2, conditions = $3, 
          actions = $4, enabled = $5, cooldown_minutes = $6,
          updated_at = $7
      WHERE id = $8 AND organization_id = $9
    `,
      data.name,
      data.description,
      JSON.stringify(data.conditions),
      JSON.stringify(data.actions),
      data.enabled,
      data.cooldownMinutes || null,
      new Date(),
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Delete alert rule
  app.delete('/rules/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      DELETE FROM alert_rules
      WHERE id = $1 AND organization_id = $2
    `,
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Get active alerts
  app.get('/active', async (c) => {
    const tenantId = c.get('tenantId');
    const { severity, acknowledged } = c.req.query();

    const conditions: string[] = [`a.organization_id = '${tenantId}'`];
    
    if (severity) {
      conditions.push(`a.severity = '${severity}'`);
    }

    if (acknowledged !== undefined) {
      conditions.push(`a.acknowledged = ${acknowledged === 'true'}`);
    }

    const alerts = await prisma.$queryRawUnsafe(`
      SELECT 
        a.*,
        r.name as rule_name,
        e.event_type,
        e.details as event_details
      FROM security_alerts a
      JOIN alert_rules r ON a.rule_id = r.id
      LEFT JOIN security_events e ON a.event_id = e.id
      WHERE ${conditions.join(' AND ')}
        AND a.resolved = false
      ORDER BY a.created_at DESC
      LIMIT 100
    `);

    return c.json(alerts);
  });

  // Get alert by ID
  app.get('/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    const alert = await prisma.$queryRaw`
      SELECT 
        a.*,
        r.name as rule_name,
        r.conditions as rule_conditions,
        e.event_type,
        e.details as event_details,
        e.timestamp as event_timestamp
      FROM security_alerts a
      JOIN alert_rules r ON a.rule_id = r.id
      LEFT JOIN security_events e ON a.event_id = e.id
      WHERE a.id = ${id} AND a.organization_id = ${tenantId}
      LIMIT 1
    `;

    if (!alert || (alert as any[]).length === 0) {
      return c.json({ error: 'Alert not found' }, 404);
    }

    return c.json((alert as any[])[0]);
  });

  // Update alert status
  app.patch('/:id', zValidator('json', alertStatusSchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const updates: string[] = ['updated_at = NOW()'];
    const params: any[] = [];

    if (data.acknowledged !== undefined) {
      updates.push(`acknowledged = $${params.length + 1}`);
      params.push(data.acknowledged);
      
      if (data.acknowledged) {
        updates.push(`acknowledged_by = $${params.length + 1}`);
        params.push(userId);
        updates.push(`acknowledged_at = NOW()`);
      }
    }

    if (data.resolved !== undefined) {
      updates.push(`resolved = $${params.length + 1}`);
      params.push(data.resolved);
      
      if (data.resolved) {
        updates.push(`resolved_by = $${params.length + 1}`);
        params.push(userId);
        updates.push(`resolved_at = NOW()`);
      }
    }

    if (data.assignee) {
      updates.push(`assignee = $${params.length + 1}`);
      params.push(data.assignee);
    }

    if (data.notes) {
      updates.push(`notes = notes || $${params.length + 1}::jsonb`);
      params.push(JSON.stringify([{
        timestamp: new Date(),
        user_id: userId,
        note: data.notes
      }]));
    }

    params.push(id, tenantId);

    await prisma.$executeRawUnsafe(`
      UPDATE security_alerts
      SET ${updates.join(', ')}
      WHERE id = $${params.length - 1} AND organization_id = $${params.length}
    `, ...params);

    return c.json({ success: true });
  });

  // Get alert statistics
  app.get('/stats/summary', async (c) => {
    const tenantId = c.get('tenantId');
    const { days = '7' } = c.req.query();

    const stats = await prisma.$queryRaw`
      SELECT 
        COUNT(*) FILTER (WHERE resolved = false) as active_alerts,
        COUNT(*) FILTER (WHERE resolved = false AND acknowledged = false) as unacknowledged,
        COUNT(*) FILTER (WHERE severity = 'critical' AND resolved = false) as critical_alerts,
        COUNT(*) FILTER (WHERE severity = 'high' AND resolved = false) as high_alerts,
        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '${parseInt(days)} days') as alerts_last_n_days,
        AVG(EXTRACT(EPOCH FROM (COALESCE(acknowledged_at, NOW()) - created_at)) / 60)::int as avg_time_to_acknowledge,
        AVG(EXTRACT(EPOCH FROM (COALESCE(resolved_at, NOW()) - created_at)) / 60)::int as avg_time_to_resolve
      FROM security_alerts
      WHERE organization_id = ${tenantId}
        AND created_at >= NOW() - INTERVAL '${parseInt(days)} days'
    `;

    return c.json((stats as any[])[0]);
  });

  // Test alert rule
  app.post('/rules/:id/test', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    // Get the rule
    const ruleResult = await prisma.$queryRaw<any[]>`
      SELECT * FROM alert_rules
      WHERE id = ${id} AND organization_id = ${tenantId}
      LIMIT 1
    `;

    if (!ruleResult || ruleResult.length === 0) {
      return c.json({ error: 'Rule not found' }, 404);
    }

    const rule = ruleResult[0];

    // Create a test event
    const testEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      eventType: 'TEST_EVENT',
      severity: 'INFO',
      source: 'alert-test',
      organizationId: tenantId,
      details: { test: true, ruleId: id },
      metadata: {}
    };

    // Test the rule actions
    const results: any[] = [];
    for (const action of rule.actions) {
      try {
        // Simulate action execution
        results.push({
          action: action.type,
          success: true,
          message: `Test ${action.type} notification would be sent`
        });
      } catch (error: any) {
        results.push({
          action: action.type,
          success: false,
          error: error.message
        });
      }
    }

    return c.json({
      rule: {
        id: rule.id,
        name: rule.name
      },
      testEvent,
      results
    });
  });

  return app;
}