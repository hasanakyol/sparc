import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import request from 'supertest';
import { Hono } from 'hono';
import Redis from 'ioredis';
import { MaintenanceService } from '../index';
import { db, schema } from '../db';
import { eq, and } from 'drizzle-orm';
import jwt from 'jsonwebtoken';

// Test configuration
const TEST_JWT_SECRET = process.env.JWT_SECRET || 'test-secret';
const TEST_TENANT_ID = 'test-tenant-123';
const TEST_USER_ID = 'test-user-123';
const TEST_DEVICE_ID = 'test-device-123';

// Create test JWT token
const createTestToken = (userId: string = TEST_USER_ID, tenantId: string = TEST_TENANT_ID) => {
  return jwt.sign({ sub: userId, tenantId }, TEST_JWT_SECRET, { expiresIn: '1h' });
};

describe('Maintenance Service Integration Tests', () => {
  let service: MaintenanceService;
  let app: Hono;
  let testToken: string;
  let redis: Redis;

  beforeAll(async () => {
    // Initialize service
    service = new MaintenanceService();
    app = new Hono();
    service.setupRoutes(app);
    
    // Initialize Redis
    redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      db: parseInt(process.env.REDIS_TEST_DB || '1')
    });

    // Create test token
    testToken = createTestToken();

    // Setup test data
    await setupTestData();
  });

  afterAll(async () => {
    // Cleanup test data
    await cleanupTestData();
    
    // Close connections
    await service.cleanup();
    await redis.quit();
  });

  beforeEach(async () => {
    // Clear Redis test data
    const keys = await redis.keys('test:*');
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  });

  describe('Work Orders API', () => {
    describe('POST /work-orders', () => {
      it('should create a new work order', async () => {
        const workOrderData = {
          title: 'Test Work Order',
          description: 'Test maintenance task',
          deviceId: TEST_DEVICE_ID,
          deviceType: 'Camera',
          workOrderType: 'corrective',
          priority: 'medium',
          scheduledDate: new Date().toISOString()
        };

        const response = await request(app.request)
          .post('/work-orders')
          .set('Authorization', `Bearer ${testToken}`)
          .send(workOrderData);

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('id');
        expect(response.body.title).toBe(workOrderData.title);
        expect(response.body.status).toBe('open');
        expect(response.body.tenantId).toBe(TEST_TENANT_ID);
      });

      it('should validate required fields', async () => {
        const response = await request(app.request)
          .post('/work-orders')
          .set('Authorization', `Bearer ${testToken}`)
          .send({
            title: 'Missing required fields'
          });

        expect(response.status).toBe(400);
        expect(response.body).toHaveProperty('error');
      });

      it('should require authentication', async () => {
        const response = await request(app.request)
          .post('/work-orders')
          .send({
            title: 'Unauthorized'
          });

        expect(response.status).toBe(401);
      });
    });

    describe('GET /work-orders', () => {
      it('should list work orders for tenant', async () => {
        const response = await request(app.request)
          .get('/work-orders')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('data');
        expect(response.body).toHaveProperty('pagination');
        expect(Array.isArray(response.body.data)).toBe(true);
      });

      it('should filter work orders by status', async () => {
        const response = await request(app.request)
          .get('/work-orders?status=open')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        response.body.data.forEach((wo: any) => {
          expect(wo.status).toBe('open');
        });
      });

      it('should filter work orders by priority', async () => {
        const response = await request(app.request)
          .get('/work-orders?priority=critical')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        response.body.data.forEach((wo: any) => {
          expect(wo.priority).toBe('critical');
        });
      });
    });

    describe('PUT /work-orders/:id', () => {
      let workOrderId: string;

      beforeEach(async () => {
        // Create test work order
        const [workOrder] = await db.insert(schema.workOrders)
          .values({
            tenantId: TEST_TENANT_ID,
            title: 'Test Update WO',
            deviceId: TEST_DEVICE_ID,
            deviceType: 'Camera',
            workOrderType: 'corrective',
            priority: 'medium',
            status: 'open',
            createdBy: TEST_USER_ID
          })
          .returning();
        workOrderId = workOrder.id;
      });

      it('should update work order', async () => {
        const response = await request(app.request)
          .put(`/work-orders/${workOrderId}`)
          .set('Authorization', `Bearer ${testToken}`)
          .send({
            status: 'in_progress',
            assignedTo: TEST_USER_ID
          });

        expect(response.status).toBe(200);
        expect(response.body.status).toBe('in_progress');
        expect(response.body.assignedTo).toBe(TEST_USER_ID);
      });

      it('should track status history', async () => {
        await request(app.request)
          .put(`/work-orders/${workOrderId}`)
          .set('Authorization', `Bearer ${testToken}`)
          .send({ status: 'assigned' });

        const history = await db.select()
          .from(schema.maintenanceHistory)
          .where(and(
            eq(schema.maintenanceHistory.workOrderId, workOrderId),
            eq(schema.maintenanceHistory.activityType, 'status_change')
          ));

        expect(history.length).toBeGreaterThan(0);
      });
    });

    describe('POST /work-orders/:id/complete', () => {
      let workOrderId: string;

      beforeEach(async () => {
        const [workOrder] = await db.insert(schema.workOrders)
          .values({
            tenantId: TEST_TENANT_ID,
            title: 'Test Complete WO',
            deviceId: TEST_DEVICE_ID,
            deviceType: 'Camera',
            workOrderType: 'corrective',
            priority: 'medium',
            status: 'in_progress',
            assignedTo: TEST_USER_ID,
            createdBy: TEST_USER_ID
          })
          .returning();
        workOrderId = workOrder.id;
      });

      it('should complete work order with details', async () => {
        const completionData = {
          resolutionNotes: 'Fixed the issue',
          laborHours: '2.5',
          partsUsed: [
            { partId: 'part-123', quantity: 2 }
          ]
        };

        const response = await request(app.request)
          .post(`/work-orders/${workOrderId}/complete`)
          .set('Authorization', `Bearer ${testToken}`)
          .send(completionData);

        expect(response.status).toBe(200);
        expect(response.body.status).toBe('completed');
        expect(response.body.resolutionNotes).toBe(completionData.resolutionNotes);
        expect(response.body.laborHours).toBe(completionData.laborHours);
        expect(response.body.completedDate).toBeDefined();
      });
    });
  });

  describe('Preventive Maintenance API', () => {
    describe('POST /preventive-maintenance/schedules', () => {
      it('should create maintenance schedule', async () => {
        const scheduleData = {
          name: 'Monthly Camera Inspection',
          frequency: 'monthly',
          deviceType: 'Camera',
          scope: 'device_type',
          taskTemplate: {
            title: 'Monthly Camera Inspection',
            description: 'Perform monthly inspection',
            estimatedHours: 1,
            priority: 'medium',
            requiredParts: []
          }
        };

        const response = await request(app.request)
          .post('/preventive-maintenance/schedules')
          .set('Authorization', `Bearer ${testToken}`)
          .send(scheduleData);

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('id');
        expect(response.body.name).toBe(scheduleData.name);
        expect(response.body.isActive).toBe(true);
      });
    });

    describe('GET /preventive-maintenance/schedules', () => {
      it('should list maintenance schedules', async () => {
        const response = await request(app.request)
          .get('/preventive-maintenance/schedules')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('data');
        expect(Array.isArray(response.body.data)).toBe(true);
      });
    });

    describe('POST /preventive-maintenance/schedules/:id/generate', () => {
      let scheduleId: string;

      beforeEach(async () => {
        const [schedule] = await db.insert(schema.preventiveMaintenanceSchedules)
          .values({
            tenantId: TEST_TENANT_ID,
            name: 'Test Schedule',
            frequency: 'monthly',
            deviceType: 'Camera',
            scope: 'device_type',
            taskTemplate: {
              title: 'Test Task',
              description: 'Test',
              estimatedHours: 1
            },
            isActive: true,
            createdBy: TEST_USER_ID
          })
          .returning();
        scheduleId = schedule.id;
      });

      it('should generate work orders from schedule', async () => {
        const response = await request(app.request)
          .post(`/preventive-maintenance/schedules/${scheduleId}/generate`)
          .set('Authorization', `Bearer ${testToken}`)
          .send();

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('generated');
        expect(response.body.generated).toBeGreaterThanOrEqual(0);
      });
    });
  });

  describe('Inventory API', () => {
    describe('POST /inventory/parts', () => {
      it('should create new part', async () => {
        const partData = {
          partNumber: 'CAM-LENS-001',
          name: 'Camera Lens',
          category: 'camera_parts',
          quantityOnHand: 10,
          unitCost: 50.00,
          reorderPoint: 5,
          reorderQuantity: 20
        };

        const response = await request(app.request)
          .post('/inventory/parts')
          .set('Authorization', `Bearer ${testToken}`)
          .send(partData);

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('id');
        expect(response.body.partNumber).toBe(partData.partNumber);
      });
    });

    describe('GET /inventory/parts/low-stock', () => {
      it('should list parts below reorder point', async () => {
        // Create test part with low stock
        await db.insert(schema.partsInventory)
          .values({
            tenantId: TEST_TENANT_ID,
            partNumber: 'LOW-STOCK-001',
            name: 'Low Stock Part',
            category: 'test',
            quantityOnHand: 2,
            reorderPoint: 5,
            reorderQuantity: 10,
            unitCost: '10.00',
            createdBy: TEST_USER_ID
          });

        const response = await request(app.request)
          .get('/inventory/parts/low-stock')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
        response.body.forEach((part: any) => {
          expect(part.quantityOnHand).toBeLessThan(part.reorderPoint);
        });
      });
    });

    describe('POST /inventory/parts/:id/usage', () => {
      let partId: string;

      beforeEach(async () => {
        const [part] = await db.insert(schema.partsInventory)
          .values({
            tenantId: TEST_TENANT_ID,
            partNumber: 'USE-PART-001',
            name: 'Usage Test Part',
            category: 'test',
            quantityOnHand: 10,
            unitCost: '25.00',
            createdBy: TEST_USER_ID
          })
          .returning();
        partId = part.id;
      });

      it('should record part usage', async () => {
        const usageData = {
          workOrderId: 'wo-123',
          quantity: 2,
          notes: 'Used for repair'
        };

        const response = await request(app.request)
          .post(`/inventory/parts/${partId}/usage`)
          .set('Authorization', `Bearer ${testToken}`)
          .send(usageData);

        expect(response.status).toBe(200);
        expect(response.body.quantityOnHand).toBe(8); // 10 - 2

        // Check history
        const history = await db.select()
          .from(schema.maintenanceHistory)
          .where(eq(schema.maintenanceHistory.activityType, 'parts_used'));
        
        expect(history.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Diagnostics API', () => {
    describe('POST /diagnostics/run', () => {
      it('should run device diagnostics', async () => {
        const diagnosticData = {
          deviceId: TEST_DEVICE_ID,
          deviceType: 'Camera',
          checkTypes: ['connectivity', 'performance', 'configuration']
        };

        const response = await request(app.request)
          .post('/diagnostics/run')
          .set('Authorization', `Bearer ${testToken}`)
          .send(diagnosticData);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('id');
        expect(response.body).toHaveProperty('results');
        expect(response.body.overallStatus).toBeDefined();
      });
    });

    describe('GET /diagnostics/history/:deviceId', () => {
      it('should get diagnostic history for device', async () => {
        const response = await request(app.request)
          .get(`/diagnostics/history/${TEST_DEVICE_ID}`)
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
      });
    });
  });

  describe('Analytics API', () => {
    describe('GET /analytics/overview', () => {
      it('should return maintenance analytics overview', async () => {
        const response = await request(app.request)
          .get('/analytics/overview?period=30d')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('workOrderStats');
        expect(response.body).toHaveProperty('deviceStats');
        expect(response.body).toHaveProperty('costStats');
        expect(response.body).toHaveProperty('performanceMetrics');
      });
    });

    describe('GET /analytics/trends', () => {
      it('should return maintenance trends', async () => {
        const response = await request(app.request)
          .get('/analytics/trends?period=30d&groupBy=day')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
      });
    });

    describe('GET /analytics/costs', () => {
      it('should return cost analysis', async () => {
        const response = await request(app.request)
          .get('/analytics/costs?period=30d')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('totalCost');
        expect(response.body).toHaveProperty('laborCost');
        expect(response.body).toHaveProperty('partsCost');
        expect(response.body).toHaveProperty('byCategory');
      });
    });
  });

  describe('SLA API', () => {
    describe('POST /sla/config', () => {
      it('should create SLA configuration', async () => {
        const slaConfig = {
          name: 'Critical Equipment SLA',
          priority: 'critical',
          deviceTypes: ['Camera', 'Sensor'],
          responseTimeHours: 1,
          resolutionTimeHours: 4
        };

        const response = await request(app.request)
          .post('/sla/config')
          .set('Authorization', `Bearer ${testToken}`)
          .send(slaConfig);

        expect(response.status).toBe(201);
        expect(response.body).toHaveProperty('id');
        expect(response.body.isActive).toBe(true);
      });
    });

    describe('GET /sla/violations', () => {
      it('should list SLA violations', async () => {
        const response = await request(app.request)
          .get('/sla/violations')
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('data');
        expect(response.body).toHaveProperty('pagination');
      });
    });
  });

  describe('IoT Integration API', () => {
    describe('POST /iot/metrics', () => {
      it('should ingest IoT metrics', async () => {
        const metricsData = {
          deviceId: TEST_DEVICE_ID,
          metrics: [
            {
              metricType: 'temperature',
              value: 75.5,
              unit: 'fahrenheit',
              timestamp: new Date().toISOString()
            },
            {
              metricType: 'vibration',
              value: 0.05,
              unit: 'g',
              timestamp: new Date().toISOString()
            }
          ]
        };

        const response = await request(app.request)
          .post('/iot/metrics')
          .set('Authorization', `Bearer ${testToken}`)
          .send(metricsData);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('processed');
        expect(response.body).toHaveProperty('anomalies');
      });
    });

    describe('GET /iot/devices/:deviceId/health', () => {
      it('should get device health score', async () => {
        const response = await request(app.request)
          .get(`/iot/devices/${TEST_DEVICE_ID}/health`)
          .set('Authorization', `Bearer ${testToken}`);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('healthScore');
        expect(response.body).toHaveProperty('riskLevel');
        expect(response.body).toHaveProperty('recommendations');
      });
    });
  });

  describe('Real-time Updates', () => {
    it('should publish work order updates to Redis', async () => {
      const workOrderData = {
        title: 'Real-time Test',
        deviceId: TEST_DEVICE_ID,
        deviceType: 'Camera',
        workOrderType: 'corrective',
        priority: 'high'
      };

      // Subscribe to Redis channel
      const messages: any[] = [];
      await redis.subscribe('maintenance:work-order:created');
      redis.on('message', (channel, message) => {
        messages.push({ channel, data: JSON.parse(message) });
      });

      // Create work order
      await request(app.request)
        .post('/work-orders')
        .set('Authorization', `Bearer ${testToken}`)
        .send(workOrderData);

      // Wait for message
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(messages.length).toBeGreaterThan(0);
      expect(messages[0].channel).toBe('maintenance:work-order:created');
      expect(messages[0].data).toHaveProperty('id');
    });
  });
});

// Helper functions
async function setupTestData() {
  // Create test tenant
  await db.insert(schema.organizations)
    .values({
      id: TEST_TENANT_ID,
      name: 'Test Organization',
      createdAt: new Date()
    })
    .onConflictDoNothing();

  // Create test user
  await db.insert(schema.users)
    .values({
      id: TEST_USER_ID,
      organizationId: TEST_TENANT_ID,
      email: 'test@example.com',
      name: 'Test User',
      role: 'admin',
      createdAt: new Date()
    })
    .onConflictDoNothing();

  // Create test device
  await db.insert(schema.devices)
    .values({
      id: TEST_DEVICE_ID,
      tenantId: TEST_TENANT_ID,
      name: 'Test Camera',
      type: 'Camera',
      status: 'active',
      metadata: {},
      createdAt: new Date()
    })
    .onConflictDoNothing();
}

async function cleanupTestData() {
  // Clean up in reverse order of dependencies
  await db.delete(schema.maintenanceHistory)
    .where(eq(schema.maintenanceHistory.tenantId, TEST_TENANT_ID));
  
  await db.delete(schema.workOrders)
    .where(eq(schema.workOrders.tenantId, TEST_TENANT_ID));
  
  await db.delete(schema.preventiveMaintenanceSchedules)
    .where(eq(schema.preventiveMaintenanceSchedules.tenantId, TEST_TENANT_ID));
  
  await db.delete(schema.partsInventory)
    .where(eq(schema.partsInventory.tenantId, TEST_TENANT_ID));
  
  await db.delete(schema.deviceDiagnostics)
    .where(eq(schema.deviceDiagnostics.tenantId, TEST_TENANT_ID));
  
  await db.delete(schema.maintenanceCosts)
    .where(eq(schema.maintenanceCosts.tenantId, TEST_TENANT_ID));
  
  await db.delete(schema.maintenanceSlaConfig)
    .where(eq(schema.maintenanceSlaConfig.tenantId, TEST_TENANT_ID));
  
  await db.delete(schema.iotDeviceMetrics)
    .where(eq(schema.iotDeviceMetrics.deviceId, TEST_DEVICE_ID));
}