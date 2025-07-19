import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { SecurityMonitoringService } from '../services/main-service';
import { SecurityEventType, SecuritySeverity } from '@sparc/shared/security/siem';

const securityEventSchema = z.object({
  eventType: z.nativeEnum(SecurityEventType),
  severity: z.nativeEnum(SecuritySeverity),
  source: z.string(),
  userId: z.string().optional(),
  organizationId: z.string().optional(),
  ipAddress: z.string().optional(),
  userAgent: z.string().optional(),
  details: z.record(z.any()),
  metadata: z.record(z.any()).optional()
});

const querySchema = z.object({
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  eventType: z.nativeEnum(SecurityEventType).optional(),
  severity: z.nativeEnum(SecuritySeverity).optional(),
  userId: z.string().optional(),
  organizationId: z.string().optional(),
  limit: z.string().transform(Number).default('100'),
  offset: z.string().transform(Number).default('0')
});

export function securityEventsRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Record a security event
  app.post('/', zValidator('json', securityEventSchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');

    const event = await securityService.recordSecurityEvent({
      ...data,
      organizationId: data.organizationId || tenantId
    });

    return c.json(event, 201);
  });

  // Query security events
  app.get('/', zValidator('query', querySchema), async (c) => {
    const query = c.req.valid('query');
    const tenantId = c.get('tenantId');

    const { prisma } = await import('@sparc/shared/database/prisma');

    const where: any = {
      organizationId: query.organizationId || tenantId
    };

    if (query.startTime) {
      where.timestamp = { ...where.timestamp, gte: new Date(query.startTime) };
    }

    if (query.endTime) {
      where.timestamp = { ...where.timestamp, lte: new Date(query.endTime) };
    }

    if (query.eventType) {
      where.eventType = query.eventType;
    }

    if (query.severity) {
      where.severity = query.severity;
    }

    if (query.userId) {
      where.userId = query.userId;
    }

    const [events, total] = await Promise.all([
      prisma.securityEvent.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: query.limit,
        skip: query.offset
      }),
      prisma.securityEvent.count({ where })
    ]);

    return c.json({
      events,
      total,
      limit: query.limit,
      offset: query.offset
    });
  });

  // Get event by ID
  app.get('/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    const { prisma } = await import('@sparc/shared/database/prisma');
    
    const event = await prisma.securityEvent.findFirst({
      where: {
        id,
        organizationId: tenantId
      }
    });

    if (!event) {
      return c.json({ error: 'Event not found' }, 404);
    }

    return c.json(event);
  });

  // Get event statistics
  app.get('/stats/summary', async (c) => {
    const tenantId = c.get('tenantId');
    const { timeRange } = c.req.query();

    const now = new Date();
    const start = timeRange === '24h' 
      ? new Date(now.getTime() - 86400000)
      : timeRange === '7d'
      ? new Date(now.getTime() - 604800000)
      : new Date(now.getTime() - 2592000000); // 30d default

    const metrics = await securityService.getSecurityMetrics(
      { start, end: now },
      tenantId
    );

    return c.json(metrics);
  });

  // Get event timeline
  app.get('/timeline', async (c) => {
    const tenantId = c.get('tenantId');
    const { hours = '24' } = c.req.query();
    const hoursInt = parseInt(hours);
    const startTime = new Date(Date.now() - hoursInt * 3600000);

    const { prisma } = await import('@sparc/shared/database/prisma');
    
    const events = await prisma.securityEvent.findMany({
      where: {
        organizationId: tenantId,
        timestamp: { gte: startTime }
      },
      select: {
        timestamp: true,
        eventType: true,
        severity: true
      }
    });

    // Group by hour manually
    const timelineMap = new Map<string, { eventType: string; severity: string; count: number }[]>();
    
    events.forEach(event => {
      const hour = new Date(event.timestamp);
      hour.setMinutes(0, 0, 0);
      const hourKey = hour.toISOString();
      
      if (!timelineMap.has(hourKey)) {
        timelineMap.set(hourKey, []);
      }
      
      const hourData = timelineMap.get(hourKey)!;
      const existing = hourData.find(d => d.eventType === event.eventType && d.severity === event.severity);
      
      if (existing) {
        existing.count++;
      } else {
        hourData.push({
          eventType: event.eventType,
          severity: event.severity,
          count: 1
        });
      }
    });

    const timeline = Array.from(timelineMap.entries())
      .map(([hour, data]) => data.map(d => ({ hour, ...d })))
      .flat()
      .sort((a, b) => new Date(b.hour).getTime() - new Date(a.hour).getTime());

    return c.json(timeline);
  });

  // Export events
  app.post('/export', async (c) => {
    const { format = 'json', ...query } = await c.req.json();
    const tenantId = c.get('tenantId');

    const { prisma } = await import('@sparc/shared/database/prisma');

    const where: any = {
      organizationId: tenantId
    };
    
    if (query.startTime) {
      where.timestamp = { ...where.timestamp, gte: new Date(query.startTime) };
    }

    if (query.endTime) {
      where.timestamp = { ...where.timestamp, lte: new Date(query.endTime) };
    }

    const events = await prisma.securityEvent.findMany({
      where,
      orderBy: { timestamp: 'desc' }
    });

    if (format === 'csv') {
      // Convert to CSV
      const csv = convertToCSV(events as any[]);
      return new Response(csv, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="security-events.csv"'
        }
      });
    }

    return c.json(events);
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
        if (typeof value === 'object') {
          return `"${JSON.stringify(value).replace(/"/g, '""')}"`;
        }
        return `"${value?.toString().replace(/"/g, '""') || ''}"`;
      }).join(',')
    )
  ].join('\n');

  return csv;
}