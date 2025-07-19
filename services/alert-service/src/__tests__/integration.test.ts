import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Hono } from 'hono';
import request from 'supertest';
import AlertService from '../index';
import { db, pool } from '../db';
import Redis from 'ioredis';
import { alerts, notificationPreferences } from '@sparc/database/schemas/alerts';
import { eq } from 'drizzle-orm';

// Test configuration
const TEST_PORT = 4008;
const TEST_WS_PORT = TEST_PORT + 1;

describe('Alert Service Integration Tests', () => {
  let app: Hono;
  let redis: Redis;
  let server: any;

  beforeAll(async () => {
    // Setup test database
    await pool.query(`
      CREATE SCHEMA IF NOT EXISTS test;
      SET search_path TO test;
    `);

    // Setup Redis connection
    redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      db: 1, // Use a different DB for tests
    });

    // Clear Redis test data
    await redis.flushdb();

    // Create alert service instance
    const alertService = new AlertService();
    app = alertService.app;

    // Override the port for testing
    process.env.PORT = TEST_PORT.toString();
  });

  afterAll(async () => {
    // Cleanup
    await pool.query('DROP SCHEMA IF EXISTS test CASCADE');
    await redis.quit();
    await pool.end();
    
    if (server) {
      server.close();
    }
  });

  beforeEach(async () => {
    // Clear test data before each test
    await db.delete(alerts).where(eq(alerts.tenantId, 'test-tenant'));
    await db.delete(notificationPreferences).where(eq(notificationPreferences.tenantId, 'test-tenant'));
    await redis.flushdb();
  });

  describe('Health Check Endpoints', () => {
    it('should return healthy status', async () => {
      const response = await request(app.fetch)
        .get('/health')
        .expect(200);

      expect(response.body).toMatchObject({
        status: 'healthy',
        service: 'alert-service',
        checks: expect.objectContaining({
          database: true,
          redis: true,
        }),
      });
    });

    it('should return ready status', async () => {
      const response = await request(app.fetch)
        .get('/ready')
        .expect(200);

      expect(response.body).toMatchObject({
        ready: true,
      });
    });

    it('should return metrics', async () => {
      const response = await request(app.fetch)
        .get('/metrics')
        .expect(200);

      expect(response.text).toContain('# HELP alerts_total');
      expect(response.text).toContain('# TYPE alerts_total counter');
    });
  });

  describe('Alert CRUD Operations', () => {
    const authToken = 'test-jwt-token';
    
    beforeEach(async () => {
      // Mock authenticated session in Redis
      await redis.setex(`session:${authToken}`, 3600, JSON.stringify({
        userId: 'test-user',
        tenantId: 'test-tenant',
      }));
    });

    it('should create, read, update, and delete an alert', async () => {
      // Create alert
      const createResponse = await request(app.fetch)
        .post('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          alertType: 'system_offline',
          priority: 'high',
          sourceId: 'server-001',
          sourceType: 'system',
          message: 'Production server is offline',
          details: { server: 'prod-api-1' },
        })
        .expect(201);

      const alertId = createResponse.body.alert.id;
      expect(alertId).toBeDefined();
      expect(createResponse.body.alert.status).toBe('open');

      // Read alert
      const readResponse = await request(app.fetch)
        .get(`/api/alerts/${alertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      expect(readResponse.body.alert.id).toBe(alertId);
      expect(readResponse.body.alert.message).toBe('Production server is offline');

      // Update alert
      const updateResponse = await request(app.fetch)
        .put(`/api/alerts/${alertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          status: 'acknowledged',
          acknowledgedBy: 'test-user',
        })
        .expect(200);

      expect(updateResponse.body.alert.status).toBe('acknowledged');
      expect(updateResponse.body.alert.acknowledgedBy).toBe('test-user');

      // Acknowledge alert (alternative method)
      const ackResponse = await request(app.fetch)
        .post(`/api/alerts/${alertId}/acknowledge`)
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          acknowledgedBy: 'test-user-2',
        })
        .expect(200);

      expect(ackResponse.body.alert.acknowledgedBy).toBe('test-user-2');

      // List alerts
      const listResponse = await request(app.fetch)
        .get('/api/alerts')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      expect(listResponse.body.alerts).toHaveLength(1);
      expect(listResponse.body.pagination.total).toBe(1);

      // Get statistics
      const statsResponse = await request(app.fetch)
        .get('/api/alerts/stats?timeframe=24h')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      expect(statsResponse.body.summary.total).toBe(1);
      expect(statsResponse.body.byPriority.high).toBe(1);

      // Delete alert
      await request(app.fetch)
        .delete(`/api/alerts/${alertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      // Verify deletion
      const verifyResponse = await request(app.fetch)
        .get(`/api/alerts/${alertId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(404);
    });

    it('should filter alerts by various criteria', async () => {
      // Create multiple alerts
      const alerts = [
        {
          alertType: 'system_offline',
          priority: 'critical',
          sourceId: 'server-001',
          sourceType: 'system',
          message: 'Critical system failure',
        },
        {
          alertType: 'camera_offline',
          priority: 'high',
          sourceId: 'camera-001',
          sourceType: 'video',
          message: 'Camera offline',
        },
        {
          alertType: 'motion_detected',
          priority: 'low',
          sourceId: 'camera-002',
          sourceType: 'video',
          message: 'Motion detected',
        },
      ];

      for (const alert of alerts) {
        await request(app.fetch)
          .post('/api/alerts')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', 'test-tenant')
          .send(alert)
          .expect(201);
      }

      // Filter by priority
      const criticalResponse = await request(app.fetch)
        .get('/api/alerts?priority=critical')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      expect(criticalResponse.body.alerts).toHaveLength(1);
      expect(criticalResponse.body.alerts[0].priority).toBe('critical');

      // Filter by source type
      const videoResponse = await request(app.fetch)
        .get('/api/alerts?sourceType=video')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      expect(videoResponse.body.alerts).toHaveLength(2);

      // Pagination
      const paginatedResponse = await request(app.fetch)
        .get('/api/alerts?page=1&limit=2')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      expect(paginatedResponse.body.alerts).toHaveLength(2);
      expect(paginatedResponse.body.pagination.pages).toBe(2);
    });
  });

  describe('Webhook Processing', () => {
    it('should process generic webhook events', async () => {
      const response = await request(app.fetch)
        .post('/api/webhooks/events')
        .send({
          eventType: 'door_forced',
          sourceId: 'door-001',
          sourceType: 'access_control',
          data: {
            tenantId: 'test-tenant',
            location: 'Main Entrance',
            timestamp: new Date().toISOString(),
          },
          timestamp: new Date().toISOString(),
          priority: 'high',
        })
        .expect(201);

      expect(response.body.alert).toBeDefined();
      expect(response.body.alert.alertType).toBe('door_forced');
      expect(response.body.alert.priority).toBe('high');
    });

    it('should process environmental webhook data', async () => {
      const response = await request(app.fetch)
        .post('/api/webhooks/environmental')
        .send({
          sensorId: 'sensor-001',
          tenantId: 'test-tenant',
          readings: {
            temperature: 45, // Above threshold
            humidity: 85,    // Above threshold
            leakDetected: true,
          },
          thresholds: {
            temperature: { min: 10, max: 30 },
            humidity: { min: 30, max: 70 },
          },
        })
        .expect(200);

      expect(response.body.alertsCreated).toBe(3); // Temperature, humidity, and leak alerts
      expect(response.body.alerts).toHaveLength(3);
      expect(response.body.alerts.some((a: any) => a.type === 'temperature_threshold')).toBe(true);
      expect(response.body.alerts.some((a: any) => a.type === 'humidity_threshold')).toBe(true);
      expect(response.body.alerts.some((a: any) => a.type === 'leak_detected')).toBe(true);
    });
  });

  describe('Notification Preferences', () => {
    const authToken = 'test-jwt-token';
    
    beforeEach(async () => {
      await redis.setex(`session:${authToken}`, 3600, JSON.stringify({
        userId: 'test-user',
        tenantId: 'test-tenant',
      }));
    });

    it('should manage notification preferences', async () => {
      // Get default preferences
      const defaultResponse = await request(app.fetch)
        .get('/api/notifications/preferences')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .expect(200);

      expect(defaultResponse.body.preferences).toBeDefined();

      // Update preferences
      const updateResponse = await request(app.fetch)
        .put('/api/notifications/preferences')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          email: true,
          sms: true,
          push: false,
          criticalOnly: true,
        })
        .expect(200);

      expect(updateResponse.body.preferences.criticalOnly).toBe(true);

      // Add email addresses
      const emailResponse = await request(app.fetch)
        .post('/api/notifications/preferences/email')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          addresses: ['admin@example.com', 'alerts@example.com'],
        })
        .expect(200);

      expect(emailResponse.body.preferences.email.addresses).toContain('admin@example.com');

      // Add SMS numbers
      const smsResponse = await request(app.fetch)
        .post('/api/notifications/preferences/sms')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          numbers: ['+1234567890', '+0987654321'],
        })
        .expect(200);

      expect(smsResponse.body.preferences.sms.numbers).toHaveLength(2);

      // Register push subscription
      const pushResponse = await request(app.fetch)
        .post('/api/notifications/preferences/push/subscribe')
        .set('Authorization', `Bearer ${authToken}`)
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          endpoint: 'https://fcm.googleapis.com/push/test',
          keys: {
            p256dh: 'test-public-key',
            auth: 'test-auth-secret',
          },
        })
        .expect(200);

      expect(pushResponse.body.preferences.push.subscriptions).toHaveLength(1);
    });
  });

  describe('Error Handling', () => {
    it('should handle 404 for non-existent routes', async () => {
      const response = await request(app.fetch)
        .get('/api/non-existent')
        .expect(404);

      expect(response.body.error).toBe('Not found');
    });

    it('should require authentication', async () => {
      const response = await request(app.fetch)
        .get('/api/alerts')
        .expect(401);

      expect(response.body.message).toBe('Access token required');
    });

    it('should require tenant ID', async () => {
      await redis.setex('session:no-tenant-token', 3600, JSON.stringify({
        userId: 'test-user',
      }));

      const response = await request(app.fetch)
        .get('/api/alerts')
        .set('Authorization', 'Bearer no-tenant-token')
        .expect(401);

      expect(response.body.message).toBe('Tenant ID required');
    });

    it('should validate request bodies', async () => {
      await redis.setex('session:test-token', 3600, JSON.stringify({
        userId: 'test-user',
        tenantId: 'test-tenant',
      }));

      const response = await request(app.fetch)
        .post('/api/alerts')
        .set('Authorization', 'Bearer test-token')
        .set('X-Tenant-ID', 'test-tenant')
        .send({
          // Invalid alert data
          alertType: 'invalid_type',
          priority: 'invalid_priority',
        })
        .expect(400);

      expect(response.body.message).toBe('Validation failed');
    });
  });
});