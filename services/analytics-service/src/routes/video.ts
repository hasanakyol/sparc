import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { AnalyticsEngine } from '../services/analytics-engine';
import {
  VideoAnalyticsConfigSchema,
  FaceRecognitionEventSchema,
  LicensePlateEventSchema,
  BehaviorEventSchema
} from '../types';

export function createVideoRoutes(analyticsEngine: AnalyticsEngine) {
  const app = new Hono();

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Configure video analytics
  app.post(
    '/configure',
    zValidator('json', VideoAnalyticsConfigSchema),
    async (c) => {
      const config = c.req.valid('json');
      const tenantId = c.get('tenantId');

      const result = await analyticsEngine.configureVideoAnalytics(tenantId, config);

      return c.json({
        message: 'Video analytics configured successfully',
        config: result
      });
    }
  );

  // Process face recognition event
  app.post(
    '/face-recognition',
    zValidator('json', FaceRecognitionEventSchema),
    async (c) => {
      const event = c.req.valid('json');
      const tenantId = c.get('tenantId');

      const result = await analyticsEngine.processFaceRecognitionEvent(tenantId, event);

      return c.json(result);
    }
  );

  // Process license plate event
  app.post(
    '/license-plate',
    zValidator('json', LicensePlateEventSchema),
    async (c) => {
      const event = c.req.valid('json');
      const tenantId = c.get('tenantId');

      const result = await analyticsEngine.processLicensePlateEvent(tenantId, event);

      return c.json(result);
    }
  );

  // Process behavior event
  app.post(
    '/behavior',
    zValidator('json', BehaviorEventSchema),
    async (c) => {
      const event = c.req.valid('json');
      const tenantId = c.get('tenantId');

      const result = await analyticsEngine.processBehaviorEvent(tenantId, event);

      return c.json(result);
    }
  );

  // Perform crowd analysis
  app.post(
    '/crowd-analysis',
    async (c) => {
      const tenantId = c.get('tenantId');
      const { cameraId, imageData } = await c.req.json();

      if (!cameraId || !imageData) {
        return c.json({ error: 'Missing cameraId or imageData' }, 400);
      }

      const result = await analyticsEngine.performCrowdAnalysis(tenantId, cameraId, imageData);

      return c.json(result);
    }
  );

  // Enroll face
  app.post(
    '/face-enrollment',
    async (c) => {
      const tenantId = c.get('tenantId');
      const { personId, imageData, metadata } = await c.req.json();

      if (!personId || !imageData) {
        return c.json({ error: 'Missing personId or imageData' }, 400);
      }

      const result = await analyticsEngine.enrollFace(tenantId, personId, imageData, metadata);

      return c.json(result);
    }
  );

  // Update watchlists
  app.post(
    '/watchlist',
    async (c) => {
      const tenantId = c.get('tenantId');
      const { type, action, items } = await c.req.json();

      if (!type || !action || !items || !Array.isArray(items)) {
        return c.json({ error: 'Invalid watchlist update request' }, 400);
      }

      await analyticsEngine.updateWatchlists(tenantId, type, action, items);

      return c.json({
        message: 'Watchlist updated successfully',
        type,
        action,
        itemsCount: items.length
      });
    }
  );

  // Query face recognition data
  app.get('/face-recognition', async (c) => {
    const tenantId = c.get('tenantId');
    const cameraId = c.req.query('cameraId');
    const personId = c.req.query('personId');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // This would query face recognition events from OpenSearch
    return c.json({
      events: [],
      query: { cameraId, personId, startDate, endDate }
    });
  });

  // Query license plate data
  app.get('/license-plate', async (c) => {
    const tenantId = c.get('tenantId');
    const cameraId = c.req.query('cameraId');
    const plateNumber = c.req.query('plateNumber');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // This would query license plate events from OpenSearch
    return c.json({
      events: [],
      query: { cameraId, plateNumber, startDate, endDate }
    });
  });

  // Query behavior data
  app.get('/behavior', async (c) => {
    const tenantId = c.get('tenantId');
    const cameraId = c.req.query('cameraId');
    const eventType = c.req.query('eventType');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // This would query behavior events from OpenSearch
    return c.json({
      events: [],
      query: { cameraId, eventType, startDate, endDate }
    });
  });

  // Person tracking
  app.get('/person-tracking/:personId', async (c) => {
    const tenantId = c.get('tenantId');
    const { personId } = c.req.param();
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // This would track a person's movement across cameras
    return c.json({
      personId,
      tracking: [],
      period: { startDate, endDate }
    });
  });

  // Vehicle correlations
  app.get('/vehicle-correlations', async (c) => {
    const tenantId = c.get('tenantId');
    const plateNumber = c.req.query('plateNumber');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');

    // This would correlate vehicle movements with access events
    return c.json({
      plateNumber,
      correlations: [],
      period: { startDate, endDate }
    });
  });

  return app;
}