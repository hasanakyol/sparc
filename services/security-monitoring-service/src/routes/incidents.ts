import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { SecurityMonitoringService } from '../services/main-service';
import { SecurityIncident } from '@sparc/shared/monitoring/types';
import { prisma } from '@sparc/shared/database/prisma';

const incidentCreateSchema = z.object({
  title: z.string(),
  description: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  affectedResources: z.array(z.string()),
  eventIds: z.array(z.string()).optional()
});

const incidentUpdateSchema = z.object({
  title: z.string().optional(),
  description: z.string().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  status: z.enum(['open', 'investigating', 'contained', 'resolved', 'false-positive']).optional(),
  assignee: z.string().optional(),
  affectedResources: z.array(z.string()).optional(),
  containmentActions: z.array(z.string()).optional()
});

const timelineEntrySchema = z.object({
  action: z.string(),
  details: z.record(z.any())
});

export function incidentsRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Get all incidents
  app.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const { status, severity, assignee } = c.req.query();

    const incidents = await prisma.securityIncident.findMany({
      where: {
        organizationId: tenantId,
        ...(status && { status }),
        ...(severity && { severity }),
        ...(assignee && { assignee })
      },
      include: {
        assigneeUser: {
          select: { name: true }
        },
        _count: {
          select: { events: true }
        }
      },
      orderBy: [
        {
          status: {
            sort: 'asc',
            nulls: 'last'
          }
        },
        { createdAt: 'desc' }
      ],
      take: 100
    });

    // Transform to match expected format
    const transformedIncidents = incidents.map(incident => ({
      ...incident,
      assignee_name: incident.assigneeUser?.name,
      event_count: incident._count.events
    }));

    return c.json(transformedIncidents);
  });

  // Get incident by ID
  app.get('/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    const incident = await prisma.securityIncident.findFirst({
      where: {
        id,
        organizationId: tenantId
      },
      include: {
        assigneeUser: {
          select: { name: true }
        },
        events: {
          select: {
            id: true,
            timestamp: true,
            eventType: true,
            severity: true
          }
        }
      }
    });

    if (!incident) {
      return c.json({ error: 'Incident not found' }, 404);
    }

    // Transform to match expected format
    const transformedIncident = {
      ...incident,
      assignee_name: incident.assigneeUser?.name,
      related_events: incident.events
    };

    return c.json(transformedIncident);
  });

  // Create incident
  app.post('/', zValidator('json', incidentCreateSchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const incident = await prisma.securityIncident.create({
      data: {
        title: data.title,
        description: data.description,
        severity: data.severity,
        status: 'open',
        events: data.eventIds ? {
          connect: data.eventIds.map(id => ({ id }))
        } : undefined,
        timeline: [{
          timestamp: new Date(),
          action: 'incident_created',
          actor: userId,
          details: { createdBy: userId }
        }],
        affectedResources: data.affectedResources,
        containmentActions: [],
        organizationId: tenantId,
        createdBy: userId,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });

    return c.json(incident, 201);
  });

  // Update incident
  app.patch('/:id', zValidator('json', incidentUpdateSchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    // Get current incident
    const currentIncident = await prisma.securityIncident.findFirst({
      where: {
        id,
        organizationId: tenantId
      }
    });

    if (!currentIncident) {
      return c.json({ error: 'Incident not found' }, 404);
    }

    // Build timeline entry
    const timelineEntry = {
      timestamp: new Date(),
      action: 'incident_updated',
      actor: userId,
      details: {} as any
    };

    // Track changes for timeline
    const updateData: any = {
      updatedAt: new Date()
    };

    if (data.title && data.title !== currentIncident.title) {
      updateData.title = data.title;
      timelineEntry.details.title = { from: currentIncident.title, to: data.title };
    }

    if (data.description) {
      updateData.description = data.description;
    }

    if (data.severity && data.severity !== currentIncident.severity) {
      updateData.severity = data.severity;
      timelineEntry.details.severity = { from: currentIncident.severity, to: data.severity };
    }

    if (data.status && data.status !== currentIncident.status) {
      updateData.status = data.status;
      timelineEntry.details.status = { from: currentIncident.status, to: data.status };
      
      if (data.status === 'resolved') {
        updateData.resolvedAt = new Date();
      }
    }

    if (data.assignee !== undefined) {
      updateData.assignee = data.assignee || null;
      timelineEntry.details.assignee = { from: currentIncident.assignee, to: data.assignee };
    }

    if (data.affectedResources) {
      updateData.affectedResources = data.affectedResources;
    }

    if (data.containmentActions) {
      updateData.containmentActions = data.containmentActions;
    }

    // Update timeline
    const existingTimeline = currentIncident.timeline as any[] || [];
    updateData.timeline = [...existingTimeline, timelineEntry];

    await prisma.securityIncident.update({
      where: { id },
      data: updateData
    });

    return c.json({ success: true });
  });

  // Add timeline entry
  app.post('/:id/timeline', zValidator('json', timelineEntrySchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const incident = await prisma.securityIncident.findFirst({
      where: {
        id,
        organizationId: tenantId
      }
    });

    if (!incident) {
      return c.json({ error: 'Incident not found' }, 404);
    }

    const entry = {
      timestamp: new Date(),
      action: data.action,
      actor: userId,
      details: data.details
    };

    const existingTimeline = incident.timeline as any[] || [];

    await prisma.securityIncident.update({
      where: { id },
      data: {
        timeline: [...existingTimeline, entry],
        updatedAt: new Date()
      }
    });

    return c.json({ success: true });
  });

  // Link events to incident
  app.post('/:id/events', async (c) => {
    const { id } = c.param();
    const { eventIds } = await c.req.json();
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const incident = await prisma.securityIncident.findFirst({
      where: {
        id,
        organizationId: tenantId
      }
    });

    if (!incident) {
      return c.json({ error: 'Incident not found' }, 404);
    }

    const existingTimeline = incident.timeline as any[] || [];
    const timelineEntry = {
      timestamp: new Date(),
      action: 'events_linked',
      actor: userId,
      details: { eventIds }
    };

    await prisma.securityIncident.update({
      where: { id },
      data: {
        events: {
          connect: eventIds.map((eventId: string) => ({ id: eventId }))
        },
        timeline: [...existingTimeline, timelineEntry],
        updatedAt: new Date()
      }
    });

    return c.json({ success: true });
  });

  // Get incident statistics
  app.get('/stats/summary', async (c) => {
    const tenantId = c.get('tenantId');
    const { days = '30' } = c.req.query();
    const daysInt = parseInt(days);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysInt);

    const [incidents, activeCount, resolvedCount, falsePositiveCount, criticalCount, highCount, last24hCount] = await Promise.all([
      // Get all incidents for calculations
      prisma.securityIncident.findMany({
        where: {
          organizationId: tenantId,
          createdAt: { gte: startDate }
        },
        select: {
          status: true,
          severity: true,
          createdAt: true,
          resolvedAt: true
        }
      }),
      // Count active incidents
      prisma.securityIncident.count({
        where: {
          organizationId: tenantId,
          createdAt: { gte: startDate },
          status: { in: ['open', 'investigating'] }
        }
      }),
      // Count resolved incidents
      prisma.securityIncident.count({
        where: {
          organizationId: tenantId,
          createdAt: { gte: startDate },
          status: 'resolved'
        }
      }),
      // Count false positives
      prisma.securityIncident.count({
        where: {
          organizationId: tenantId,
          createdAt: { gte: startDate },
          status: 'false-positive'
        }
      }),
      // Count critical
      prisma.securityIncident.count({
        where: {
          organizationId: tenantId,
          createdAt: { gte: startDate },
          severity: 'critical'
        }
      }),
      // Count high
      prisma.securityIncident.count({
        where: {
          organizationId: tenantId,
          createdAt: { gte: startDate },
          severity: 'high'
        }
      }),
      // Count last 24h
      prisma.securityIncident.count({
        where: {
          organizationId: tenantId,
          createdAt: { gte: new Date(Date.now() - 86400000) }
        }
      })
    ]);

    // Calculate average resolution time
    const resolutionTimes = incidents
      .filter(i => i.resolvedAt)
      .map(i => (i.resolvedAt!.getTime() - i.createdAt.getTime()) / 3600000);
    
    const avgResolutionHours = resolutionTimes.length > 0
      ? Math.round(resolutionTimes.reduce((a, b) => a + b, 0) / resolutionTimes.length)
      : 0;

    // Get trends data
    const trends = await prisma.securityIncident.groupBy({
      by: ['severity'],
      where: {
        organizationId: tenantId,
        createdAt: { gte: startDate }
      },
      _count: true,
      orderBy: {
        severity: 'asc'
      }
    });

    const summary = {
      total_incidents: incidents.length,
      active_incidents: activeCount,
      resolved_incidents: resolvedCount,
      false_positives: falsePositiveCount,
      critical_count: criticalCount,
      high_count: highCount,
      avg_resolution_hours: avgResolutionHours,
      incidents_24h: last24hCount
    };

    return c.json({
      summary,
      trends: trends.map(t => ({
        severity: t.severity,
        count: t._count
      }))
    });
  });

  // Generate incident report
  app.post('/:id/report', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');
    const { format = 'json' } = await c.req.json();

    // Get full incident details
    const incident = await prisma.securityIncident.findFirst({
      where: {
        id,
        organizationId: tenantId
      },
      include: {
        assigneeUser: {
          select: { name: true }
        },
        createdByUser: {
          select: { name: true }
        },
        events: {
          orderBy: { timestamp: 'asc' }
        }
      }
    });

    if (!incident) {
      return c.json({ error: 'Incident not found' }, 404);
    }

    const report = {
      incident: {
        ...incident,
        assignee_name: incident.assigneeUser?.name,
        created_by_name: incident.createdByUser?.name
      },
      events: incident.events,
      generatedAt: new Date(),
      generatedBy: c.get('userId')
    };

    if (format === 'pdf') {
      // In production, would generate actual PDF
      return c.json({ 
        message: 'PDF generation not implemented',
        data: report 
      });
    }

    return c.json(report);
  });

  // Get incident playbooks
  app.get('/playbooks', async (c) => {
    const playbooks = [
      {
        id: 'ransomware',
        name: 'Ransomware Response',
        description: 'Steps for responding to ransomware incidents',
        severity: ['critical'],
        steps: [
          'Isolate affected systems',
          'Preserve evidence',
          'Identify ransomware variant',
          'Check backups',
          'Notify stakeholders',
          'Begin recovery process'
        ]
      },
      {
        id: 'data-breach',
        name: 'Data Breach Response',
        description: 'Steps for responding to data breach incidents',
        severity: ['critical', 'high'],
        steps: [
          'Contain the breach',
          'Assess the scope',
          'Identify affected data',
          'Notify legal/compliance',
          'Prepare breach notifications',
          'Implement remediation'
        ]
      },
      {
        id: 'phishing',
        name: 'Phishing Response',
        description: 'Steps for responding to phishing incidents',
        severity: ['medium', 'high'],
        steps: [
          'Identify affected users',
          'Reset compromised credentials',
          'Block malicious URLs/domains',
          'Scan for malware',
          'User awareness communication'
        ]
      }
    ];

    return c.json(playbooks);
  });

  return app;
}