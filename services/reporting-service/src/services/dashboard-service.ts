import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { ReportingServiceConfig } from '../config';
import { DashboardWidget, WidgetType, TimeRange, WidgetConfig } from '../types';
import { logger } from '../utils/logger';
import { createTracer } from '../utils/telemetry';

const tracer = createTracer('dashboard-service');

export class DashboardService {
  private cachePrefix = 'dashboard:';
  private cacheTTL = 300; // 5 minutes

  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private config: ReportingServiceConfig
  ) {}

  async getDashboardData(
    widgets: WidgetType[],
    timeRange: TimeRange,
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<Record<string, any>> {
    return tracer.startActiveSpan('get-dashboard-data', async (span) => {
      try {
        span.setAttributes({
          'dashboard.widget_count': widgets.length,
          'dashboard.time_range': timeRange,
          'dashboard.tenant_id': tenantId
        });

        const data: Record<string, any> = {};
        const { startDate, endDate } = this.getDateRange(timeRange);

        // Process widgets in parallel
        const widgetPromises = widgets.map(async (widgetType) => {
          try {
            // Check cache first
            const cached = await this.getCachedWidget(widgetType, tenantId, timeRange, filters);
            if (cached) {
              return { widgetType, data: cached };
            }

            // Generate widget data
            const widgetData = await this.generateWidgetData(
              widgetType,
              startDate,
              endDate,
              tenantId,
              filters
            );

            // Cache the result
            await this.cacheWidget(widgetType, tenantId, timeRange, filters, widgetData);

            return { widgetType, data: widgetData };
          } catch (error) {
            logger.error('Failed to generate widget data', {
              widgetType,
              error: (error as Error).message
            });
            return { widgetType, data: null, error: (error as Error).message };
          }
        });

        const results = await Promise.all(widgetPromises);
        
        for (const result of results) {
          data[result.widgetType] = result.data;
        }

        return data;
      } finally {
        span.end();
      }
    });
  }

  async getRealtimeData(tenantId: string): Promise<Record<string, any>> {
    return tracer.startActiveSpan('get-realtime-data', async (span) => {
      try {
        span.setAttributes({ 'dashboard.tenant_id': tenantId });

        const now = new Date();
        const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);

        const [accessEvents, alerts, doorStatus, systemMetrics] = await Promise.all([
          // Recent access events
          this.prisma.accessEvent.findMany({
            where: {
              tenantId,
              timestamp: { gte: fiveMinutesAgo }
            },
            orderBy: { timestamp: 'desc' },
            take: 10,
            include: {
              user: { select: { firstName: true, lastName: true } },
              door: { select: { name: true, location: true } }
            }
          }),

          // Active alerts
          this.prisma.alert.findMany({
            where: {
              tenantId,
              status: 'active',
              createdAt: { gte: fiveMinutesAgo }
            },
            orderBy: { severity: 'desc' },
            take: 5
          }),

          // Door status summary
          this.prisma.door.groupBy({
            by: ['status', 'locked'],
            where: { tenantId },
            _count: true
          }),

          // System metrics (from Redis)
          this.getSystemMetrics(tenantId)
        ]);

        return {
          accessEvents: accessEvents.map(event => ({
            id: event.id,
            timestamp: event.timestamp,
            user: `${event.user.firstName} ${event.user.lastName}`,
            door: event.door.name,
            location: event.door.location,
            success: event.success
          })),
          alerts: alerts.map(alert => ({
            id: alert.id,
            type: alert.type,
            severity: alert.severity,
            message: alert.message,
            timestamp: alert.createdAt
          })),
          doorStatus: this.transformDoorStatus(doorStatus),
          systemMetrics,
          timestamp: now.toISOString()
        };
      } finally {
        span.end();
      }
    });
  }

  private async generateWidgetData(
    widgetType: WidgetType,
    startDate: Date,
    endDate: Date,
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    switch (widgetType) {
      case 'access_summary':
        return this.generateAccessSummary(startDate, endDate, tenantId, filters);
      
      case 'door_status':
        return this.generateDoorStatus(tenantId, filters);
      
      case 'camera_status':
        return this.generateCameraStatus(tenantId, filters);
      
      case 'recent_events':
        return this.generateRecentEvents(startDate, endDate, tenantId, filters);
      
      case 'alerts':
        return this.generateAlerts(tenantId, filters);
      
      case 'system_health':
        return this.generateSystemHealth(tenantId);
      
      case 'visitor_trends':
        return this.generateVisitorTrends(startDate, endDate, tenantId, filters);
      
      case 'compliance_score':
        return this.generateComplianceScore(startDate, endDate, tenantId);
      
      case 'incident_heatmap':
        return this.generateIncidentHeatmap(startDate, endDate, tenantId, filters);
      
      case 'device_health':
        return this.generateDeviceHealth(tenantId);
      
      case 'user_activity_chart':
        return this.generateUserActivityChart(startDate, endDate, tenantId, filters);
      
      case 'security_metrics':
        return this.generateSecurityMetrics(startDate, endDate, tenantId);
      
      default:
        throw new Error(`Unsupported widget type: ${widgetType}`);
    }
  }

  private async generateAccessSummary(
    startDate: Date,
    endDate: Date,
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    const [totalEvents, successfulEvents, uniqueUsers, peakHour] = await Promise.all([
      // Total events
      this.prisma.accessEvent.count({
        where: {
          tenantId,
          timestamp: { gte: startDate, lte: endDate },
          ...filters
        }
      }),

      // Successful events
      this.prisma.accessEvent.count({
        where: {
          tenantId,
          timestamp: { gte: startDate, lte: endDate },
          success: true,
          ...filters
        }
      }),

      // Unique users
      this.prisma.accessEvent.findMany({
        where: {
          tenantId,
          timestamp: { gte: startDate, lte: endDate },
          ...filters
        },
        select: { userId: true },
        distinct: ['userId']
      }),

      // Peak hour
      this.prisma.$queryRaw`
        SELECT DATE_PART('hour', timestamp) as hour, COUNT(*) as count
        FROM "AccessEvent"
        WHERE "tenantId" = ${tenantId}
          AND timestamp >= ${startDate}
          AND timestamp <= ${endDate}
        GROUP BY hour
        ORDER BY count DESC
        LIMIT 1
      `
    ]);

    const peakHourData = peakHour as any[];
    
    return {
      totalEvents,
      successfulAccess: successfulEvents,
      deniedAccess: totalEvents - successfulEvents,
      uniqueUsers: uniqueUsers.length,
      successRate: totalEvents > 0 ? (successfulEvents / totalEvents * 100).toFixed(1) : 0,
      peakHour: peakHourData[0]?.hour || 0
    };
  }

  private async generateDoorStatus(
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    const doors = await this.prisma.door.findMany({
      where: {
        tenantId,
        ...filters
      },
      select: {
        id: true,
        status: true,
        online: true,
        locked: true
      }
    });

    return {
      total: doors.length,
      online: doors.filter(d => d.online).length,
      offline: doors.filter(d => !d.online).length,
      locked: doors.filter(d => d.locked).length,
      unlocked: doors.filter(d => !d.locked).length,
      alarmed: doors.filter(d => d.status === 'alarm').length
    };
  }

  private async generateCameraStatus(
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    const cameras = await this.prisma.camera.findMany({
      where: {
        tenantId,
        ...filters
      },
      select: {
        id: true,
        status: true,
        recording: true
      }
    });

    return {
      total: cameras.length,
      online: cameras.filter(c => c.status === 'online').length,
      offline: cameras.filter(c => c.status === 'offline').length,
      recording: cameras.filter(c => c.recording).length,
      notRecording: cameras.filter(c => !c.recording).length,
      maintenance: cameras.filter(c => c.status === 'maintenance').length
    };
  }

  private async generateRecentEvents(
    startDate: Date,
    endDate: Date,
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    const events = await this.prisma.accessEvent.findMany({
      where: {
        tenantId,
        timestamp: { gte: startDate, lte: endDate },
        ...filters
      },
      orderBy: { timestamp: 'desc' },
      take: 20,
      include: {
        user: { select: { firstName: true, lastName: true } },
        door: { select: { name: true, location: true } }
      }
    });

    return events.map(event => ({
      id: event.id,
      timestamp: event.timestamp,
      type: event.eventType,
      user: `${event.user.firstName} ${event.user.lastName}`,
      door: event.door.name,
      location: event.door.location,
      success: event.success,
      reason: event.failureReason
    }));
  }

  private async generateAlerts(
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    const alerts = await this.prisma.alert.findMany({
      where: {
        tenantId,
        status: 'active',
        ...filters
      },
      orderBy: [
        { severity: 'desc' },
        { createdAt: 'desc' }
      ],
      take: 10
    });

    const grouped = {
      critical: alerts.filter(a => a.severity === 'critical'),
      high: alerts.filter(a => a.severity === 'high'),
      medium: alerts.filter(a => a.severity === 'medium'),
      low: alerts.filter(a => a.severity === 'low')
    };

    return {
      total: alerts.length,
      byPriority: grouped,
      alerts: alerts.map(alert => ({
        id: alert.id,
        type: alert.type,
        severity: alert.severity,
        message: alert.message,
        location: alert.location,
        timestamp: alert.createdAt,
        acknowledged: alert.acknowledged
      }))
    };
  }

  private async generateSystemHealth(tenantId: string): Promise<any> {
    // Get service health from Redis
    const services = [
      'access-control',
      'video-management',
      'event-processing',
      'device-management',
      'analytics',
      'environmental'
    ];

    const healthChecks = await Promise.all(
      services.map(async (service) => {
        const health = await this.redis.get(`health:${service}:${tenantId}`);
        return {
          service,
          status: health ? JSON.parse(health).status : 'unknown',
          lastCheck: health ? JSON.parse(health).timestamp : null
        };
      })
    );

    const overallHealth = healthChecks.every(h => h.status === 'healthy') ? 'healthy' :
                         healthChecks.some(h => h.status === 'critical') ? 'critical' :
                         healthChecks.some(h => h.status === 'warning') ? 'warning' : 'degraded';

    return {
      overall: overallHealth,
      services: healthChecks,
      uptime: '99.9%', // This would be calculated from actual uptime data
      lastIncident: null, // This would be fetched from incident data
      maintenanceScheduled: false
    };
  }

  private async generateVisitorTrends(
    startDate: Date,
    endDate: Date,
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    // This would be implemented with actual visitor data
    // For now, returning mock data
    return {
      totalVisitors: 1250,
      uniqueVisitors: 890,
      averageVisitDuration: '2h 15m',
      peakDay: 'Wednesday',
      trend: '+12%',
      chartData: {
        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        datasets: [{
          label: 'Visitors',
          data: [180, 210, 295, 220, 195, 120, 80]
        }]
      }
    };
  }

  private async generateComplianceScore(
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<any> {
    // This would calculate actual compliance metrics
    return {
      overallScore: 92,
      categories: {
        accessControl: 95,
        dataProtection: 89,
        physicalSecurity: 94,
        incidentResponse: 90,
        documentation: 88
      },
      trend: '+3%',
      nextAudit: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      criticalFindings: 0,
      recommendations: 5
    };
  }

  private async generateIncidentHeatmap(
    startDate: Date,
    endDate: Date,
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    const incidents = await this.prisma.incident.findMany({
      where: {
        tenantId,
        createdAt: { gte: startDate, lte: endDate },
        ...filters
      },
      select: {
        location: true,
        severity: true,
        createdAt: true
      }
    });

    // Group by location and hour
    const heatmapData = incidents.reduce((acc, incident) => {
      const hour = incident.createdAt.getHours();
      const key = `${incident.location}-${hour}`;
      
      if (!acc[key]) {
        acc[key] = { location: incident.location, hour, count: 0, severity: 0 };
      }
      
      acc[key].count++;
      acc[key].severity += incident.severity === 'critical' ? 3 :
                          incident.severity === 'high' ? 2 : 1;
      
      return acc;
    }, {} as Record<string, any>);

    return {
      data: Object.values(heatmapData),
      maxCount: Math.max(...Object.values(heatmapData).map((d: any) => d.count)),
      totalIncidents: incidents.length
    };
  }

  private async generateDeviceHealth(tenantId: string): Promise<any> {
    const [doors, cameras, sensors, readers] = await Promise.all([
      this.prisma.door.groupBy({
        by: ['status'],
        where: { tenantId },
        _count: true
      }),
      this.prisma.camera.groupBy({
        by: ['status'],
        where: { tenantId },
        _count: true
      }),
      this.prisma.sensor.groupBy({
        by: ['status'],
        where: { tenantId },
        _count: true
      }),
      this.prisma.cardReader.groupBy({
        by: ['status'],
        where: { tenantId },
        _count: true
      })
    ]);

    const calculateHealth = (devices: any[]) => {
      const total = devices.reduce((sum, d) => sum + d._count, 0);
      const healthy = devices.find(d => d.status === 'online')?._count || 0;
      return total > 0 ? (healthy / total * 100).toFixed(1) : 100;
    };

    return {
      doors: { total: doors.reduce((sum, d) => sum + d._count, 0), health: calculateHealth(doors) },
      cameras: { total: cameras.reduce((sum, d) => sum + d._count, 0), health: calculateHealth(cameras) },
      sensors: { total: sensors.reduce((sum, d) => sum + d._count, 0), health: calculateHealth(sensors) },
      readers: { total: readers.reduce((sum, d) => sum + d._count, 0), health: calculateHealth(readers) },
      overallHealth: 95.5 // This would be calculated
    };
  }

  private async generateUserActivityChart(
    startDate: Date,
    endDate: Date,
    tenantId: string,
    filters?: Record<string, any>
  ): Promise<any> {
    const dailyActivity = await this.prisma.$queryRaw`
      SELECT DATE(timestamp) as date, COUNT(*) as count
      FROM "AccessEvent"
      WHERE "tenantId" = ${tenantId}
        AND timestamp >= ${startDate}
        AND timestamp <= ${endDate}
        AND success = true
      GROUP BY DATE(timestamp)
      ORDER BY date
    `;

    const data = dailyActivity as any[];
    
    return {
      chartType: 'line',
      labels: data.map(d => d.date),
      datasets: [{
        label: 'Daily Access Events',
        data: data.map(d => d.count),
        borderColor: 'rgb(75, 192, 192)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)'
      }],
      summary: {
        total: data.reduce((sum, d) => sum + Number(d.count), 0),
        average: Math.round(data.reduce((sum, d) => sum + Number(d.count), 0) / data.length),
        peak: Math.max(...data.map(d => Number(d.count)))
      }
    };
  }

  private async generateSecurityMetrics(
    startDate: Date,
    endDate: Date,
    tenantId: string
  ): Promise<any> {
    const [failedAttempts, unauthorizedAttempts, tailgating, forcedEntries] = await Promise.all([
      this.prisma.accessEvent.count({
        where: {
          tenantId,
          timestamp: { gte: startDate, lte: endDate },
          success: false
        }
      }),
      this.prisma.accessEvent.count({
        where: {
          tenantId,
          timestamp: { gte: startDate, lte: endDate },
          eventType: 'unauthorized_attempt'
        }
      }),
      this.prisma.accessEvent.count({
        where: {
          tenantId,
          timestamp: { gte: startDate, lte: endDate },
          eventType: 'tailgating_detected'
        }
      }),
      this.prisma.alert.count({
        where: {
          tenantId,
          createdAt: { gte: startDate, lte: endDate },
          type: 'forced_entry'
        }
      })
    ]);

    return {
      metrics: {
        failedAttempts,
        unauthorizedAttempts,
        tailgating,
        forcedEntries
      },
      riskLevel: failedAttempts > 100 || forcedEntries > 0 ? 'high' :
                 failedAttempts > 50 || unauthorizedAttempts > 20 ? 'medium' : 'low',
      trends: {
        failedAttempts: '-15%',
        unauthorizedAttempts: '+5%',
        tailgating: '-20%',
        forcedEntries: '0%'
      }
    };
  }

  private getDateRange(timeRange: TimeRange): { startDate: Date; endDate: Date } {
    const endDate = new Date();
    const startDate = new Date();

    switch (timeRange) {
      case '1h':
        startDate.setHours(startDate.getHours() - 1);
        break;
      case '24h':
        startDate.setHours(startDate.getHours() - 24);
        break;
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(startDate.getDate() - 90);
        break;
      default:
        startDate.setHours(startDate.getHours() - 24);
    }

    return { startDate, endDate };
  }

  private async getCachedWidget(
    widgetType: WidgetType,
    tenantId: string,
    timeRange: TimeRange,
    filters?: Record<string, any>
  ): Promise<any | null> {
    const cacheKey = this.getCacheKey(widgetType, tenantId, timeRange, filters);
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      logger.debug('Widget cache hit', { widgetType, tenantId });
      return JSON.parse(cached);
    }
    
    return null;
  }

  private async cacheWidget(
    widgetType: WidgetType,
    tenantId: string,
    timeRange: TimeRange,
    filters: Record<string, any> | undefined,
    data: any
  ): Promise<void> {
    const cacheKey = this.getCacheKey(widgetType, tenantId, timeRange, filters);
    await this.redis.setex(cacheKey, this.cacheTTL, JSON.stringify(data));
  }

  private getCacheKey(
    widgetType: WidgetType,
    tenantId: string,
    timeRange: TimeRange,
    filters?: Record<string, any>
  ): string {
    const filterStr = filters ? crypto.createHash('md5').update(JSON.stringify(filters)).digest('hex') : 'no-filters';
    return `${this.cachePrefix}${tenantId}:${widgetType}:${timeRange}:${filterStr}`;
  }

  private transformDoorStatus(doorStatus: any[]): any {
    const result = {
      online: 0,
      offline: 0,
      locked: 0,
      unlocked: 0
    };

    for (const status of doorStatus) {
      if (status.status === 'online') {
        result.online += status._count;
        if (status.locked) {
          result.locked += status._count;
        } else {
          result.unlocked += status._count;
        }
      } else {
        result.offline += status._count;
      }
    }

    return result;
  }

  private async getSystemMetrics(tenantId: string): Promise<any> {
    // Get system metrics from Redis
    const metrics = await this.redis.hgetall(`metrics:${tenantId}`);
    
    return {
      cpu: parseFloat(metrics.cpu || '0'),
      memory: parseFloat(metrics.memory || '0'),
      disk: parseFloat(metrics.disk || '0'),
      network: parseFloat(metrics.network || '0'),
      timestamp: metrics.timestamp || new Date().toISOString()
    };
  }
}