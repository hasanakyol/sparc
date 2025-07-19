import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { DashboardService } from '../services/dashboard-service';
import { DashboardDataRequestSchema } from '../types/schemas';
import { WidgetType, TimeRange } from '../types';
import { logger } from '../utils/logger';

export function dashboardRoutes(dashboardService: DashboardService): Hono {
  const app = new Hono();

  // Get dashboard widget data
  app.get('/data',
    zValidator('query', z.object({
      widgets: z.string().transform(val => val.split(',') as WidgetType[]).optional(),
      timeRange: z.enum(['1h', '24h', '7d', '30d', '90d', 'custom']).optional(),
      filters: z.string().optional()
    })),
    async (c) => {
      try {
        const query = c.req.valid('query');
        const tenantId = c.get('tenantId') as string;

        const widgets = query.widgets || ['access_summary', 'door_status', 'alerts'];
        const timeRange = (query.timeRange || '24h') as TimeRange;
        const filters = query.filters ? JSON.parse(query.filters) : undefined;

        const data = await dashboardService.getDashboardData(
          widgets,
          timeRange,
          tenantId,
          filters
        );

        return c.json({
          success: true,
          data,
          meta: {
            timeRange,
            widgets: widgets.length,
            timestamp: new Date().toISOString()
          }
        });
      } catch (error) {
        logger.error('Failed to get dashboard data', { error });
        throw new HTTPException(500, { message: 'Failed to get dashboard data' });
      }
    }
  );

  // Get real-time dashboard data
  app.get('/realtime', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;

      const data = await dashboardService.getRealtimeData(tenantId);

      return c.json({
        success: true,
        data,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Failed to get realtime data', { error });
      throw new HTTPException(500, { message: 'Failed to get realtime data' });
    }
  });

  // WebSocket endpoint for real-time updates
  app.get('/ws', async (c) => {
    const tenantId = c.get('tenantId') as string;
    
    // In a real implementation, this would upgrade to WebSocket
    // For now, returning connection info
    return c.json({
      success: true,
      message: 'WebSocket endpoint',
      wsUrl: `/ws/dashboard/${tenantId}`
    });
  });

  // Get available widgets
  app.get('/widgets', async (c) => {
    const widgets = [
      {
        id: 'access_summary',
        name: 'Access Summary',
        description: 'Overview of access events and statistics',
        category: 'access',
        refreshInterval: 300
      },
      {
        id: 'door_status',
        name: 'Door Status',
        description: 'Current status of all doors',
        category: 'physical',
        refreshInterval: 60
      },
      {
        id: 'camera_status',
        name: 'Camera Status',
        description: 'Current status of all cameras',
        category: 'video',
        refreshInterval: 60
      },
      {
        id: 'recent_events',
        name: 'Recent Events',
        description: 'Latest access events',
        category: 'activity',
        refreshInterval: 30
      },
      {
        id: 'alerts',
        name: 'Active Alerts',
        description: 'Current security alerts',
        category: 'security',
        refreshInterval: 10
      },
      {
        id: 'system_health',
        name: 'System Health',
        description: 'Overall system health status',
        category: 'system',
        refreshInterval: 60
      },
      {
        id: 'visitor_trends',
        name: 'Visitor Trends',
        description: 'Visitor patterns and trends',
        category: 'analytics',
        refreshInterval: 600
      },
      {
        id: 'compliance_score',
        name: 'Compliance Score',
        description: 'Current compliance status',
        category: 'compliance',
        refreshInterval: 3600
      },
      {
        id: 'incident_heatmap',
        name: 'Incident Heatmap',
        description: 'Geographic distribution of incidents',
        category: 'security',
        refreshInterval: 900
      },
      {
        id: 'device_health',
        name: 'Device Health',
        description: 'Health status of all devices',
        category: 'system',
        refreshInterval: 300
      },
      {
        id: 'user_activity_chart',
        name: 'User Activity Chart',
        description: 'User activity over time',
        category: 'analytics',
        refreshInterval: 600
      },
      {
        id: 'security_metrics',
        name: 'Security Metrics',
        description: 'Key security performance indicators',
        category: 'security',
        refreshInterval: 300
      }
    ];

    return c.json({
      success: true,
      widgets
    });
  });

  // Save dashboard configuration
  app.post('/config',
    zValidator('json', z.object({
      name: z.string(),
      description: z.string().optional(),
      widgets: z.array(z.object({
        id: z.string(),
        type: z.string(),
        position: z.object({
          x: z.number(),
          y: z.number(),
          w: z.number(),
          h: z.number()
        }),
        config: z.any()
      })),
      isDefault: z.boolean().optional()
    })),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        // This would save the dashboard configuration to database
        const dashboardId = `dash_${Date.now()}`;

        return c.json({
          success: true,
          dashboardId,
          message: 'Dashboard configuration saved'
        });
      } catch (error) {
        logger.error('Failed to save dashboard config', { error });
        throw new HTTPException(500, { message: 'Failed to save dashboard configuration' });
      }
    }
  );

  // Get saved dashboard configurations
  app.get('/configs', async (c) => {
    try {
      const tenantId = c.get('tenantId') as string;
      const userId = c.get('userId') as string;

      // This would fetch saved configurations from database
      const configs: any[] = [];

      return c.json({
        success: true,
        configs
      });
    } catch (error) {
      logger.error('Failed to get dashboard configs', { error });
      throw new HTTPException(500, { message: 'Failed to get dashboard configurations' });
    }
  });

  // Export dashboard data
  app.post('/export',
    zValidator('json', z.object({
      widgets: z.array(z.string()),
      timeRange: z.enum(['1h', '24h', '7d', '30d', '90d', 'custom']),
      format: z.enum(['pdf', 'xlsx', 'png']),
      customDateRange: z.object({
        start: z.string().datetime(),
        end: z.string().datetime()
      }).optional()
    })),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;

        // This would generate a dashboard export
        const exportId = `export_${Date.now()}`;

        return c.json({
          success: true,
          exportId,
          message: 'Dashboard export started'
        }, 202);
      } catch (error) {
        logger.error('Failed to export dashboard', { error });
        throw new HTTPException(500, { message: 'Failed to export dashboard' });
      }
    }
  );

  return app;
}