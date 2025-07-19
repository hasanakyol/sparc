import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { cacheMiddleware } from '@sparc/shared/middleware/cache';
import { AnalyticsEngine } from '../services/analytics-engine';
import { 
  AnalyticsQuerySchema,
  AnomalyDetectionSchema,
  OccupancyQuerySchema 
} from '../types';

export function createAnalyticsRoutes(analyticsEngine: AnalyticsEngine) {
  const app = new Hono();

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Security analytics
  app.get(
    '/security',
    cacheMiddleware({ ttl: 300 }), // Cache for 5 minutes
    zValidator('query', AnalyticsQuerySchema),
    async (c) => {
      const query = c.req.valid('query');
      const tenantId = c.get('tenantId');

      const startDate = query.startDate ? new Date(query.startDate) : new Date(Date.now() - 24 * 60 * 60 * 1000);
      const endDate = query.endDate ? new Date(query.endDate) : new Date();

      const [
        accessPatterns,
        anomalies,
        predictions
      ] = await Promise.all([
        analyticsEngine.analyzeAccessPatterns(tenantId, 'all', startDate, endDate),
        analyticsEngine.detectAnomalies(tenantId, 'user', 'all'),
        analyticsEngine.generatePredictiveAlerts(tenantId)
      ]);

      return c.json({
        period: { startDate, endDate },
        accessPatterns,
        anomalies,
        predictions,
        summary: {
          totalEvents: accessPatterns.totalAccesses || 0,
          anomaliesDetected: anomalies.length,
          predictiveAlerts: predictions.length,
          riskLevel: calculateOverallRisk(anomalies, predictions)
        }
      });
    }
  );

  // Occupancy analytics
  app.get(
    '/occupancy',
    cacheMiddleware({ ttl: 60 }), // Cache for 1 minute
    zValidator('query', OccupancyQuerySchema),
    async (c) => {
      const query = c.req.valid('query');
      const tenantId = c.get('tenantId');

      const location = {
        buildingId: query.buildingId!,
        floorId: query.floorId,
        zoneId: query.zoneId
      };

      const [currentOccupancy, trends] = await Promise.all([
        analyticsEngine.trackOccupancy(tenantId, location),
        query.startDate && query.endDate
          ? analyticsEngine.analyzeOccupancyTrends(
              tenantId,
              query.buildingId!,
              new Date(query.startDate),
              new Date(query.endDate),
              query.granularity
            )
          : Promise.resolve(null)
      ]);

      return c.json({
        current: currentOccupancy,
        trends,
        location
      });
    }
  );

  // Anomaly detection
  app.post(
    '/anomalies',
    zValidator('json', AnomalyDetectionSchema),
    async (c) => {
      const body = c.req.valid('json');
      const tenantId = c.get('tenantId');

      const anomalies = await analyticsEngine.detectAnomalies(
        tenantId,
        body.entityType,
        body.entityId,
        body.threshold,
        body.timeWindow
      );

      return c.json({
        entityType: body.entityType,
        entityId: body.entityId,
        anomalies,
        detectedAt: new Date().toISOString()
      });
    }
  );

  // Predictive alerts
  app.get(
    '/alerts/predictive',
    cacheMiddleware({ ttl: 300 }), // Cache for 5 minutes
    async (c) => {
      const tenantId = c.get('tenantId');
      const entityType = c.req.query('entityType');
      const entityId = c.req.query('entityId');

      const alerts = await analyticsEngine.generatePredictiveAlerts(
        tenantId,
        entityType,
        entityId
      );

      return c.json({
        alerts,
        count: alerts.length,
        severityCounts: {
          critical: alerts.filter(a => a.severity === 'critical').length,
          high: alerts.filter(a => a.severity === 'high').length,
          medium: alerts.filter(a => a.severity === 'medium').length,
          low: alerts.filter(a => a.severity === 'low').length
        }
      });
    }
  );

  // Behavior analysis
  app.get(
    '/behavior/:entityType/:entityId',
    cacheMiddleware({ ttl: 600 }), // Cache for 10 minutes
    async (c) => {
      const tenantId = c.get('tenantId');
      const { entityType, entityId } = c.req.param();
      
      const startDate = c.req.query('startDate') 
        ? new Date(c.req.query('startDate')!) 
        : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const endDate = c.req.query('endDate')
        ? new Date(c.req.query('endDate')!)
        : new Date();

      const analysis = await analyticsEngine.analyzeBehaviorPatterns(
        tenantId,
        entityType,
        entityId,
        startDate,
        endDate
      );

      return c.json(analysis);
    }
  );

  // Trend analysis
  app.get(
    '/trends',
    cacheMiddleware({ ttl: 3600 }), // Cache for 1 hour
    async (c) => {
      const tenantId = c.get('tenantId');
      const metric = c.req.query('metric') || 'all';
      const period = c.req.query('period') || '7d';
      
      const endDate = new Date();
      const startDate = new Date();
      
      switch (period) {
        case '24h':
          startDate.setDate(endDate.getDate() - 1);
          break;
        case '7d':
          startDate.setDate(endDate.getDate() - 7);
          break;
        case '30d':
          startDate.setDate(endDate.getDate() - 30);
          break;
        case '90d':
          startDate.setDate(endDate.getDate() - 90);
          break;
        default:
          startDate.setDate(endDate.getDate() - 7);
      }

      // Get trend data based on metric type
      const trends = await getTrendData(analyticsEngine, tenantId, metric, startDate, endDate);

      return c.json({
        metric,
        period,
        startDate,
        endDate,
        trends
      });
    }
  );

  // Dashboard data
  app.get(
    '/dashboard',
    cacheMiddleware({ ttl: 60 }), // Cache for 1 minute
    async (c) => {
      const tenantId = c.get('tenantId');
      const timeRange = c.req.query('timeRange') || '24h';

      const dashboardData = await analyticsEngine.getDashboardData(tenantId, timeRange);

      return c.json(dashboardData);
    }
  );

  // Device health analysis
  app.get(
    '/device-health',
    cacheMiddleware({ ttl: 300 }), // Cache for 5 minutes
    async (c) => {
      const tenantId = c.get('tenantId');
      const deviceType = c.req.query('deviceType');
      const deviceId = c.req.query('deviceId');

      const healthAnalysis = await analyticsEngine.analyzeDeviceHealth(
        tenantId,
        deviceType,
        deviceId
      );

      return c.json(healthAnalysis);
    }
  );

  return app;
}

// Helper functions
function calculateOverallRisk(anomalies: any[], predictions: any[]): string {
  const criticalCount = predictions.filter(p => p.severity === 'critical').length;
  const highCount = predictions.filter(p => p.severity === 'high').length;
  const anomalyCount = anomalies.filter(a => a.severity === 'high' || a.severity === 'critical').length;

  if (criticalCount > 0 || anomalyCount > 2) return 'critical';
  if (highCount > 2 || anomalyCount > 0) return 'high';
  if (highCount > 0 || anomalies.length > 3) return 'medium';
  return 'low';
}

async function getTrendData(
  analyticsEngine: AnalyticsEngine,
  tenantId: string,
  metric: string,
  startDate: Date,
  endDate: Date
): Promise<any> {
  switch (metric) {
    case 'occupancy':
      // Get occupancy trends for all buildings
      return {};
    case 'security':
      // Get security event trends
      return {};
    case 'anomalies':
      // Get anomaly trends
      return {};
    case 'all':
    default:
      // Get all metrics
      return {};
  }
}