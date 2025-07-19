import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { TenantService } from '../index';
import request from 'supertest';
import { app } from '../index';
import { db } from '@sparc/database';
import { tenants, organizations } from '@sparc/database/schemas/tenant';
import { eq } from 'drizzle-orm';

describe('Tenant Service Integration Tests', () => {
  let service: TenantService;
  let authToken: string;

  beforeAll(async () => {
    // Start the service
    service = new TenantService();
    await service.start();
    
    // Get auth token (mock for testing)
    authToken = 'Bearer test-token';
  });

  afterAll(async () => {
    // Cleanup
    await service.cleanup();
  });

  beforeEach(async () => {
    // Clean up test data
    await db.delete(organizations).where(eq(organizations.tenantId, 'test-tenant-id'));
    await db.delete(tenants).where(eq(tenants.domain, 'test-domain'));
  });

  describe('Health Endpoints', () => {
    it('should return healthy status', async () => {
      const response = await request(app.fetch)
        .get('/health')
        .expect(200);

      expect(response.body).toHaveProperty('status');
      expect(response.body.status).toBe('healthy');
      expect(response.body.service).toBe('tenant-service');
    });

    it('should return ready status', async () => {
      const response = await request(app.fetch)
        .get('/ready')
        .expect(200);

      expect(response.body).toHaveProperty('ready');
      expect(response.body.ready).toBe(true);
    });

    it('should return metrics', async () => {
      const response = await request(app.fetch)
        .get('/metrics')
        .expect(200);

      expect(response.text).toContain('tenant_total');
      expect(response.text).toContain('organization_total');
    });
  });

  describe('Tenant API', () => {
    it('should create a new tenant', async () => {
      const newTenant = {
        name: 'Test Tenant',
        domain: 'test-domain',
        contactEmail: 'admin@test.com',
        contactName: 'Test Admin',
        timezone: 'UTC'
      };

      const response = await request(app.fetch)
        .post('/api/tenants')
        .set('Authorization', authToken)
        .send(newTenant)
        .expect(201);

      expect(response.body.data).toHaveProperty('id');
      expect(response.body.data.name).toBe('Test Tenant');
      expect(response.body.data.domain).toBe('test-domain');
      expect(response.body.data.status).toBe('ACTIVE');
    });

    it('should not create tenant with duplicate domain', async () => {
      // Create first tenant
      await db.insert(tenants).values({
        name: 'Existing Tenant',
        domain: 'test-domain',
        contactEmail: 'existing@test.com',
        status: 'ACTIVE',
        plan: 'FREE'
      });

      const newTenant = {
        name: 'Another Tenant',
        domain: 'test-domain',
        contactEmail: 'another@test.com'
      };

      await request(app.fetch)
        .post('/api/tenants')
        .set('Authorization', authToken)
        .send(newTenant)
        .expect(409);
    });

    it('should list tenants with pagination', async () => {
      // Create test tenants
      await db.insert(tenants).values([
        {
          name: 'Tenant 1',
          domain: 'tenant1',
          contactEmail: 'admin@tenant1.com',
          status: 'ACTIVE',
          plan: 'FREE'
        },
        {
          name: 'Tenant 2',
          domain: 'tenant2',
          contactEmail: 'admin@tenant2.com',
          status: 'ACTIVE',
          plan: 'STARTER'
        }
      ]);

      const response = await request(app.fetch)
        .get('/api/tenants?page=1&limit=10')
        .set('Authorization', authToken)
        .expect(200);

      expect(response.body.data).toBeInstanceOf(Array);
      expect(response.body.data.length).toBeGreaterThanOrEqual(2);
      expect(response.body.pagination).toHaveProperty('page', 1);
      expect(response.body.pagination).toHaveProperty('limit', 10);
      expect(response.body.pagination).toHaveProperty('total');
    });

    it('should filter tenants by status', async () => {
      // Create test tenants
      await db.insert(tenants).values([
        {
          name: 'Active Tenant',
          domain: 'active',
          contactEmail: 'admin@active.com',
          status: 'ACTIVE',
          plan: 'FREE'
        },
        {
          name: 'Suspended Tenant',
          domain: 'suspended',
          contactEmail: 'admin@suspended.com',
          status: 'SUSPENDED',
          plan: 'FREE'
        }
      ]);

      const response = await request(app.fetch)
        .get('/api/tenants?status=ACTIVE')
        .set('Authorization', authToken)
        .expect(200);

      expect(response.body.data).toBeInstanceOf(Array);
      response.body.data.forEach((tenant: any) => {
        expect(tenant.status).toBe('ACTIVE');
      });
    });

    it('should update tenant', async () => {
      // Create a tenant
      const [created] = await db.insert(tenants).values({
        name: 'Original Name',
        domain: 'test-update',
        contactEmail: 'original@test.com',
        status: 'ACTIVE',
        plan: 'FREE'
      }).returning();

      const updateData = {
        name: 'Updated Name',
        contactEmail: 'updated@test.com'
      };

      const response = await request(app.fetch)
        .put(`/api/tenants/${created.id}`)
        .set('Authorization', authToken)
        .send(updateData)
        .expect(200);

      expect(response.body.data.name).toBe('Updated Name');
      expect(response.body.data.contactEmail).toBe('updated@test.com');
      expect(response.body.data.domain).toBe('test-update'); // Domain should not change
    });

    it('should get tenant resource usage', async () => {
      // Create a tenant
      const [created] = await db.insert(tenants).values({
        name: 'Usage Test',
        domain: 'usage-test',
        contactEmail: 'usage@test.com',
        status: 'ACTIVE',
        plan: 'FREE',
        resourceQuotas: {
          maxUsers: 100,
          maxDoors: 50,
          maxCameras: 10,
          storageQuotaGB: 100
        }
      }).returning();

      const response = await request(app.fetch)
        .get(`/api/tenants/${created.id}/usage`)
        .set('Authorization', authToken)
        .expect(200);

      expect(response.body.data).toHaveProperty('users');
      expect(response.body.data).toHaveProperty('doors');
      expect(response.body.data).toHaveProperty('cameras');
      expect(response.body.data).toHaveProperty('storage');
      
      expect(response.body.data.users).toHaveProperty('current');
      expect(response.body.data.users).toHaveProperty('quota');
      expect(response.body.data.users).toHaveProperty('percentage');
    });

    it('should delete tenant without organizations', async () => {
      // Create a tenant
      const [created] = await db.insert(tenants).values({
        name: 'To Delete',
        domain: 'to-delete',
        contactEmail: 'delete@test.com',
        status: 'ACTIVE',
        plan: 'FREE'
      }).returning();

      await request(app.fetch)
        .delete(`/api/tenants/${created.id}`)
        .set('Authorization', authToken)
        .expect(200);

      // Verify tenant is deleted
      const deleted = await db.query.tenants.findFirst({
        where: eq(tenants.id, created.id)
      });
      expect(deleted).toBeUndefined();
    });

    it('should not delete tenant with organizations', async () => {
      // Create a tenant
      const [created] = await db.insert(tenants).values({
        name: 'Has Organizations',
        domain: 'has-orgs',
        contactEmail: 'orgs@test.com',
        status: 'ACTIVE',
        plan: 'FREE'
      }).returning();

      // Create an organization for this tenant
      await db.insert(organizations).values({
        tenantId: created.id,
        name: 'Test Organization',
        timezone: 'UTC'
      });

      await request(app.fetch)
        .delete(`/api/tenants/${created.id}`)
        .set('Authorization', authToken)
        .expect(409);
    });
  });

  describe('Authorization', () => {
    it('should require authentication', async () => {
      await request(app.fetch)
        .get('/api/tenants')
        .expect(401);
    });

    it('should require super admin role', async () => {
      const userToken = 'Bearer user-token'; // Mock user token without super admin role
      
      await request(app.fetch)
        .get('/api/tenants')
        .set('Authorization', userToken)
        .expect(403);
    });
  });
});