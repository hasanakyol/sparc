import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { SecurityMonitoringService } from '../services/main-service';
import { SecurityDashboard, DashboardWidget } from '@sparc/shared/monitoring/types';
import { prisma } from '@sparc/shared/database/prisma';

const widgetSchema = z.object({
  id: z.string().optional(),
  type: z.enum(['chart', 'metric', 'table', 'map', 'timeline']),
  title: z.string(),
  query: z.string(),
  visualization: z.record(z.any()),
  position: z.object({
    x: z.number(),
    y: z.number(),
    w: z.number(),
    h: z.number()
  })
});

const dashboardSchema = z.object({
  name: z.string(),
  widgets: z.array(widgetSchema),
  refreshInterval: z.number().default(60),
  layout: z.any().optional()
});

export function dashboardRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Get all dashboards
  app.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const dashboards = await prisma.$queryRaw`
      SELECT 
        d.*,
        CASE WHEN d.created_by = ${userId} THEN true ELSE false END as is_owner,
        u.name as created_by_name
      FROM security_dashboards d
      LEFT JOIN users u ON d.created_by = u.id
      WHERE d.organization_id = ${tenantId}
        AND (d.is_public = true OR d.created_by = ${userId})
      ORDER BY d.created_at DESC
    `;

    return c.json(dashboards);
  });

  // Get dashboard by ID
  app.get('/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const dashboard = await prisma.$queryRaw`
      SELECT * FROM security_dashboards
      WHERE id = ${id} 
        AND organization_id = ${tenantId}
        AND (is_public = true OR created_by = ${userId})
      LIMIT 1
    `;

    if (!dashboard || (dashboard as any[]).length === 0) {
      return c.json({ error: 'Dashboard not found' }, 404);
    }

    return c.json((dashboard as any[])[0]);
  });

  // Create dashboard
  app.post('/', zValidator('json', dashboardSchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const dashboard: SecurityDashboard = await securityService.createDashboard({
      ...data,
      widgets: data.widgets.map(w => ({
        ...w,
        id: w.id || crypto.randomUUID()
      }))
    });

    // Store in database with additional metadata
    await prisma.$executeRawUnsafe(`
      INSERT INTO security_dashboards (
        id, name, widgets, refresh_interval, layout,
        organization_id, created_by, is_public,
        created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `,
      dashboard.id,
      dashboard.name,
      JSON.stringify(dashboard.widgets),
      dashboard.refreshInterval,
      JSON.stringify(dashboard.layout),
      tenantId,
      userId,
      false,
      new Date(),
      new Date()
    );

    return c.json(dashboard, 201);
  });

  // Update dashboard
  app.put('/:id', zValidator('json', dashboardSchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    // Check ownership
    const existing = await prisma.$queryRaw<any[]>`
      SELECT created_by FROM security_dashboards
      WHERE id = ${id} AND organization_id = ${tenantId}
      LIMIT 1
    `;

    if (!existing || existing.length === 0) {
      return c.json({ error: 'Dashboard not found' }, 404);
    }

    if (existing[0].created_by !== userId) {
      return c.json({ error: 'Unauthorized' }, 403);
    }

    await prisma.$executeRawUnsafe(`
      UPDATE security_dashboards
      SET name = $1, widgets = $2, refresh_interval = $3, 
          layout = $4, updated_at = $5
      WHERE id = $6 AND organization_id = $7
    `,
      data.name,
      JSON.stringify(data.widgets),
      data.refreshInterval,
      JSON.stringify(data.layout),
      new Date(),
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Delete dashboard
  app.delete('/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    // Check ownership
    const existing = await prisma.$queryRaw<any[]>`
      SELECT created_by FROM security_dashboards
      WHERE id = ${id} AND organization_id = ${tenantId}
      LIMIT 1
    `;

    if (!existing || existing.length === 0) {
      return c.json({ error: 'Dashboard not found' }, 404);
    }

    if (existing[0].created_by !== userId) {
      return c.json({ error: 'Unauthorized' }, 403);
    }

    await prisma.$executeRawUnsafe(`
      DELETE FROM security_dashboards
      WHERE id = $1 AND organization_id = $2
    `,
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Clone dashboard
  app.post('/:id/clone', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const { name } = await c.req.json();

    const original = await prisma.$queryRaw<any[]>`
      SELECT * FROM security_dashboards
      WHERE id = ${id} 
        AND organization_id = ${tenantId}
        AND (is_public = true OR created_by = ${userId})
      LIMIT 1
    `;

    if (!original || original.length === 0) {
      return c.json({ error: 'Dashboard not found' }, 404);
    }

    const cloned = {
      id: crypto.randomUUID(),
      name: name || `${original[0].name} (Copy)`,
      widgets: original[0].widgets,
      refresh_interval: original[0].refresh_interval,
      layout: original[0].layout,
      organization_id: tenantId,
      created_by: userId,
      is_public: false,
      created_at: new Date(),
      updated_at: new Date()
    };

    await prisma.$executeRawUnsafe(`
      INSERT INTO security_dashboards (
        id, name, widgets, refresh_interval, layout,
        organization_id, created_by, is_public,
        created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `,
      cloned.id,
      cloned.name,
      cloned.widgets,
      cloned.refresh_interval,
      cloned.layout,
      cloned.organization_id,
      cloned.created_by,
      cloned.is_public,
      cloned.created_at,
      cloned.updated_at
    );

    return c.json(cloned, 201);
  });

  // Share dashboard
  app.post('/:id/share', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const { isPublic } = await c.req.json();

    // Check ownership
    const existing = await prisma.$queryRaw<any[]>`
      SELECT created_by FROM security_dashboards
      WHERE id = ${id} AND organization_id = ${tenantId}
      LIMIT 1
    `;

    if (!existing || existing.length === 0) {
      return c.json({ error: 'Dashboard not found' }, 404);
    }

    if (existing[0].created_by !== userId) {
      return c.json({ error: 'Unauthorized' }, 403);
    }

    await prisma.$executeRawUnsafe(`
      UPDATE security_dashboards
      SET is_public = $1, updated_at = $2
      WHERE id = $3 AND organization_id = $4
    `,
      isPublic,
      new Date(),
      id,
      tenantId
    );

    return c.json({ success: true, isPublic });
  });

  // Execute widget query
  app.post('/widgets/query', async (c) => {
    const { query, timeRange, variables } = await c.req.json();
    const tenantId = c.get('tenantId');

    try {
      // Parse and validate query
      const parsedQuery = parseWidgetQuery(query, {
        ...variables,
        tenantId,
        timeRange
      });

      // Execute query based on type
      let results;
      
      if (parsedQuery.type === 'events') {
        results = await executeEventsQuery(parsedQuery, tenantId);
      } else if (parsedQuery.type === 'metrics') {
        results = await executeMetricsQuery(parsedQuery, tenantId);
      } else if (parsedQuery.type === 'alerts') {
        results = await executeAlertsQuery(parsedQuery, tenantId);
      } else {
        return c.json({ error: 'Invalid query type' }, 400);
      }

      return c.json(results);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Get default dashboards
  app.get('/defaults', async (c) => {
    const defaults = [
      {
        id: 'security-overview',
        name: 'Security Overview',
        description: 'High-level security metrics and trends',
        widgets: getDefaultSecurityOverviewWidgets()
      },
      {
        id: 'threat-analysis',
        name: 'Threat Analysis',
        description: 'Detailed threat detection and analysis',
        widgets: getDefaultThreatAnalysisWidgets()
      },
      {
        id: 'compliance-monitoring',
        name: 'Compliance Monitoring',
        description: 'Compliance status and control effectiveness',
        widgets: getDefaultComplianceWidgets()
      }
    ];

    return c.json(defaults);
  });

  return app;
}

function parseWidgetQuery(query: string, variables: Record<string, any>) {
  // Simple query parser - in production would be more sophisticated
  let parsed = query;
  
  // Replace variables
  Object.entries(variables).forEach(([key, value]) => {
    parsed = parsed.replace(new RegExp(`\\$${key}`, 'g'), value);
  });

  // Determine query type
  const type = parsed.includes('FROM security_events') ? 'events' :
               parsed.includes('FROM security_alerts') ? 'alerts' : 'metrics';

  return { type, query: parsed };
}

async function executeEventsQuery(query: any, tenantId: string) {
  // Execute events query
  const results = await prisma.$queryRawUnsafe(query.query);
  return results;
}

async function executeMetricsQuery(query: any, tenantId: string) {
  // Execute metrics query
  const results = await prisma.$queryRawUnsafe(query.query);
  return results;
}

async function executeAlertsQuery(query: any, tenantId: string) {
  // Execute alerts query
  const results = await prisma.$queryRawUnsafe(query.query);
  return results;
}

function getDefaultSecurityOverviewWidgets(): DashboardWidget[] {
  return [
    {
      id: crypto.randomUUID(),
      type: 'metric',
      title: 'Total Security Events',
      query: 'SELECT COUNT(*) as value FROM security_events WHERE timestamp > NOW() - INTERVAL \'24 hours\' AND organization_id = $tenantId',
      visualization: { format: 'number', trend: true },
      position: { x: 0, y: 0, w: 3, h: 2 }
    },
    {
      id: crypto.randomUUID(),
      type: 'metric',
      title: 'Critical Alerts',
      query: 'SELECT COUNT(*) as value FROM security_alerts WHERE severity = \'critical\' AND resolved = false AND organization_id = $tenantId',
      visualization: { format: 'number', color: 'red' },
      position: { x: 3, y: 0, w: 3, h: 2 }
    },
    {
      id: crypto.randomUUID(),
      type: 'chart',
      title: 'Events Over Time',
      query: `
        SELECT 
          DATE_TRUNC('hour', timestamp) as time,
          severity,
          COUNT(*) as count
        FROM security_events
        WHERE timestamp > NOW() - INTERVAL '24 hours'
          AND organization_id = $tenantId
        GROUP BY time, severity
        ORDER BY time
      `,
      visualization: { 
        chartType: 'line',
        xAxis: 'time',
        yAxis: 'count',
        series: 'severity'
      },
      position: { x: 0, y: 2, w: 6, h: 4 }
    }
  ];
}

function getDefaultThreatAnalysisWidgets(): DashboardWidget[] {
  return [
    {
      id: crypto.randomUUID(),
      type: 'table',
      title: 'Top Threats',
      query: `
        SELECT 
          event_type as threat,
          COUNT(*) as occurrences,
          MAX(severity) as max_severity
        FROM security_events
        WHERE timestamp > NOW() - INTERVAL '7 days'
          AND organization_id = $tenantId
          AND severity IN ('high', 'critical')
        GROUP BY event_type
        ORDER BY occurrences DESC
        LIMIT 10
      `,
      visualization: { 
        columns: ['threat', 'occurrences', 'max_severity'],
        sortable: true
      },
      position: { x: 0, y: 0, w: 6, h: 4 }
    }
  ];
}

function getDefaultComplianceWidgets(): DashboardWidget[] {
  return [
    {
      id: crypto.randomUUID(),
      type: 'chart',
      title: 'Compliance Status',
      query: `
        SELECT 
          framework,
          SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant,
          SUM(CASE WHEN status = 'non-compliant' THEN 1 ELSE 0 END) as non_compliant
        FROM compliance_controls
        WHERE organization_id = $tenantId
        GROUP BY framework
      `,
      visualization: { 
        chartType: 'bar',
        xAxis: 'framework',
        yAxis: ['compliant', 'non_compliant']
      },
      position: { x: 0, y: 0, w: 6, h: 4 }
    }
  ];
}