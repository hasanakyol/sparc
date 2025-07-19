import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { SecurityMonitoringService } from '../services/main-service';
import { ComplianceReport, ComplianceControl } from '@sparc/shared/monitoring/types';
import { prisma } from '@sparc/shared/database/prisma';

const complianceFrameworkSchema = z.enum(['soc2', 'pci-dss', 'hipaa', 'gdpr', 'iso27001']);

const controlUpdateSchema = z.object({
  status: z.enum(['compliant', 'non-compliant', 'not-applicable']),
  evidence: z.array(z.string()).optional(),
  notes: z.string().optional()
});

export function complianceRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Get compliance reports
  app.get('/reports', async (c) => {
    const tenantId = c.get('tenantId');
    const { framework, startDate, endDate } = c.req.query();

    const conditions: string[] = [`organization_id = '${tenantId}'`];
    
    if (framework) {
      conditions.push(`framework = '${framework}'`);
    }
    
    if (startDate) {
      conditions.push(`period_start >= '${startDate}'`);
    }
    
    if (endDate) {
      conditions.push(`period_end <= '${endDate}'`);
    }

    const reports = await prisma.$queryRawUnsafe(`
      SELECT * FROM compliance_reports
      WHERE ${conditions.join(' AND ')}
      ORDER BY generated_at DESC
      LIMIT 100
    `);

    return c.json(reports);
  });

  // Generate compliance report
  app.post('/reports/generate', async (c) => {
    const { framework, startDate, endDate } = await c.req.json();
    const tenantId = c.get('tenantId');

    if (!complianceFrameworkSchema.safeParse(framework).success) {
      return c.json({ error: 'Invalid compliance framework' }, 400);
    }

    const period = {
      start: new Date(startDate || Date.now() - 30 * 24 * 60 * 60 * 1000),
      end: new Date(endDate || Date.now())
    };

    const report = await securityService.getComplianceReport(framework, period);

    // Store additional metadata
    await prisma.$executeRawUnsafe(`
      UPDATE compliance_reports
      SET organization_id = $1
      WHERE id = $2
    `, tenantId, report.id);

    return c.json(report, 201);
  });

  // Get report by ID
  app.get('/reports/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    const report = await prisma.$queryRaw`
      SELECT * FROM compliance_reports
      WHERE id = ${id} AND organization_id = ${tenantId}
      LIMIT 1
    `;

    if (!report || (report as any[]).length === 0) {
      return c.json({ error: 'Report not found' }, 404);
    }

    return c.json((report as any[])[0]);
  });

  // Get compliance controls
  app.get('/controls', async (c) => {
    const tenantId = c.get('tenantId');
    const { framework, status } = c.req.query();

    const conditions: string[] = [`organization_id = '${tenantId}'`];
    
    if (framework) {
      conditions.push(`framework = '${framework}'`);
    }
    
    if (status) {
      conditions.push(`status = '${status}'`);
    }

    const controls = await prisma.$queryRawUnsafe(`
      SELECT * FROM compliance_controls
      WHERE ${conditions.join(' AND ')}
      ORDER BY framework, id
    `);

    return c.json(controls);
  });

  // Update control status
  app.patch('/controls/:id', zValidator('json', controlUpdateSchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const updates: string[] = ['last_assessed = NOW()', 'assessed_by = $1'];
    const params: any[] = [userId];

    if (data.status) {
      updates.push(`status = $${params.length + 1}`);
      params.push(data.status);
    }

    if (data.evidence) {
      updates.push(`evidence = $${params.length + 1}`);
      params.push(JSON.stringify(data.evidence));
    }

    if (data.notes) {
      updates.push(`notes = $${params.length + 1}`);
      params.push(data.notes);
    }

    params.push(id, tenantId);

    await prisma.$executeRawUnsafe(`
      UPDATE compliance_controls
      SET ${updates.join(', ')}
      WHERE id = $${params.length - 1} AND organization_id = $${params.length}
    `, ...params);

    // Log the change
    await prisma.$executeRawUnsafe(`
      INSERT INTO compliance_audit_log (
        id, control_id, action, actor, details, timestamp
      ) VALUES ($1, $2, $3, $4, $5, $6)
    `,
      crypto.randomUUID(),
      id,
      'control_updated',
      userId,
      JSON.stringify(data),
      new Date()
    );

    return c.json({ success: true });
  });

  // Get compliance dashboard
  app.get('/dashboard', async (c) => {
    const tenantId = c.get('tenantId');

    // Get compliance status by framework
    const frameworkStatus = await prisma.$queryRaw`
      SELECT 
        framework,
        COUNT(*) as total_controls,
        COUNT(*) FILTER (WHERE status = 'compliant') as compliant,
        COUNT(*) FILTER (WHERE status = 'non-compliant') as non_compliant,
        COUNT(*) FILTER (WHERE status = 'not-applicable') as not_applicable,
        ROUND(
          COUNT(*) FILTER (WHERE status = 'compliant')::numeric / 
          NULLIF(COUNT(*) FILTER (WHERE status != 'not-applicable'), 0) * 100, 
          2
        ) as compliance_percentage
      FROM compliance_controls
      WHERE organization_id = ${tenantId}
      GROUP BY framework
    `;

    // Get critical non-compliant controls
    const criticalControls = await prisma.$queryRaw`
      SELECT * FROM compliance_controls
      WHERE organization_id = ${tenantId}
        AND status = 'non-compliant'
        AND criticality = 'high'
      ORDER BY last_assessed DESC
      LIMIT 10
    `;

    // Get recent assessments
    const recentAssessments = await prisma.$queryRaw`
      SELECT 
        c.*,
        u.name as assessed_by_name
      FROM compliance_controls c
      LEFT JOIN users u ON c.assessed_by = u.id
      WHERE c.organization_id = ${tenantId}
        AND c.last_assessed > NOW() - INTERVAL '7 days'
      ORDER BY c.last_assessed DESC
      LIMIT 20
    `;

    // Get compliance trends
    const trends = await prisma.$queryRaw`
      SELECT 
        DATE_TRUNC('month', generated_at) as month,
        framework,
        AVG((summary->>'compliant')::int) as avg_compliant,
        AVG((summary->>'non_compliant')::int) as avg_non_compliant
      FROM compliance_reports
      WHERE organization_id = ${tenantId}
        AND generated_at > NOW() - INTERVAL '12 months'
      GROUP BY month, framework
      ORDER BY month
    `;

    return c.json({
      frameworkStatus,
      criticalControls,
      recentAssessments,
      trends
    });
  });

  // Get audit log
  app.get('/audit-log', async (c) => {
    const tenantId = c.get('tenantId');
    const { controlId, actor, startDate, endDate } = c.req.query();

    const conditions: string[] = [
      `c.organization_id = '${tenantId}'`
    ];
    
    if (controlId) {
      conditions.push(`l.control_id = '${controlId}'`);
    }
    
    if (actor) {
      conditions.push(`l.actor = '${actor}'`);
    }
    
    if (startDate) {
      conditions.push(`l.timestamp >= '${startDate}'`);
    }
    
    if (endDate) {
      conditions.push(`l.timestamp <= '${endDate}'`);
    }

    const logs = await prisma.$queryRawUnsafe(`
      SELECT 
        l.*,
        c.name as control_name,
        c.framework,
        u.name as actor_name
      FROM compliance_audit_log l
      JOIN compliance_controls c ON l.control_id = c.id
      LEFT JOIN users u ON l.actor = u.id
      WHERE ${conditions.join(' AND ')}
      ORDER BY l.timestamp DESC
      LIMIT 500
    `);

    return c.json(logs);
  });

  // Export compliance data
  app.post('/export', async (c) => {
    const { framework, format = 'csv' } = await c.req.json();
    const tenantId = c.get('tenantId');

    const controls = await prisma.$queryRawUnsafe(`
      SELECT 
        id as control_id,
        framework,
        name as control_name,
        description,
        status,
        criticality,
        last_assessed,
        notes
      FROM compliance_controls
      WHERE organization_id = $1
        ${framework ? `AND framework = $2` : ''}
      ORDER BY framework, id
    `, tenantId, ...(framework ? [framework] : []));

    if (format === 'csv') {
      const csv = convertToCSV(controls as any[]);
      return new Response(csv, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="compliance-${framework || 'all'}-${new Date().toISOString().split('T')[0]}.csv"`
        }
      });
    }

    return c.json(controls);
  });

  // Get compliance frameworks
  app.get('/frameworks', async (c) => {
    const frameworks = [
      {
        id: 'soc2',
        name: 'SOC 2',
        description: 'Service Organization Control 2',
        categories: ['Security', 'Availability', 'Processing Integrity', 'Confidentiality', 'Privacy'],
        controlCount: 64
      },
      {
        id: 'pci-dss',
        name: 'PCI DSS',
        description: 'Payment Card Industry Data Security Standard',
        categories: ['Build and Maintain', 'Protect Cardholder Data', 'Vulnerability Management', 'Access Control', 'Monitor and Test', 'Security Policies'],
        controlCount: 248
      },
      {
        id: 'hipaa',
        name: 'HIPAA',
        description: 'Health Insurance Portability and Accountability Act',
        categories: ['Administrative', 'Physical', 'Technical', 'Organizational', 'Policies and Procedures'],
        controlCount: 54
      },
      {
        id: 'gdpr',
        name: 'GDPR',
        description: 'General Data Protection Regulation',
        categories: ['Lawfulness', 'Purpose Limitation', 'Data Minimization', 'Accuracy', 'Storage Limitation', 'Security', 'Accountability'],
        controlCount: 99
      },
      {
        id: 'iso27001',
        name: 'ISO 27001',
        description: 'Information Security Management System',
        categories: ['Context', 'Leadership', 'Planning', 'Support', 'Operation', 'Performance', 'Improvement'],
        controlCount: 114
      }
    ];

    return c.json(frameworks);
  });

  // Schedule compliance assessment
  app.post('/assessments/schedule', async (c) => {
    const { framework, frequency, startDate } = await c.req.json();
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const schedule = {
      id: crypto.randomUUID(),
      framework,
      frequency, // daily, weekly, monthly, quarterly
      nextRun: new Date(startDate || Date.now()),
      organizationId: tenantId,
      createdBy: userId,
      enabled: true
    };

    await prisma.$executeRawUnsafe(`
      INSERT INTO compliance_assessment_schedules (
        id, framework, frequency, next_run, 
        organization_id, created_by, enabled
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `,
      schedule.id,
      schedule.framework,
      schedule.frequency,
      schedule.nextRun,
      schedule.organizationId,
      schedule.createdBy,
      schedule.enabled
    );

    return c.json(schedule, 201);
  });

  return app;
}

function convertToCSV(data: any[]): string {
  if (data.length === 0) return '';

  const headers = Object.keys(data[0]);
  const csv = [
    headers.join(','),
    ...data.map(row => 
      headers.map(header => {
        const value = row[header];
        if (value === null || value === undefined) return '""';
        if (typeof value === 'object') {
          return `"${JSON.stringify(value).replace(/"/g, '""')}"`;
        }
        return `"${value.toString().replace(/"/g, '""')}"`;
      }).join(',')
    )
  ].join('\n');

  return csv;
}