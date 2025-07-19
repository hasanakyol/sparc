import { Hono } from 'hono';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { cacheMiddleware } from '@sparc/shared/middleware/cache';
import { AnalyticsEngine } from '../services/analytics-engine';

export function createPredictionsRoutes(analyticsEngine: AnalyticsEngine) {
  const app = new Hono();

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Get incident predictions
  app.get(
    '/',
    cacheMiddleware({ ttl: 300 }), // Cache for 5 minutes
    async (c) => {
      const tenantId = c.get('tenantId');
      const buildingId = c.req.query('buildingId');

      const predictions = await analyticsEngine.generateIncidentPredictions(
        tenantId,
        buildingId
      );

      return c.json({
        predictions,
        count: predictions.length,
        typeCounts: {
          security_breach: predictions.filter(p => p.type === 'security_breach').length,
          crowd_incident: predictions.filter(p => p.type === 'crowd_incident').length,
          equipment_failure: predictions.filter(p => p.type === 'equipment_failure').length,
          safety_violation: predictions.filter(p => p.type === 'safety_violation').length
        }
      });
    }
  );

  return app;
}