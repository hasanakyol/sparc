import { Hono, Context } from 'hono';
import jwt from 'jsonwebtoken';
import {
  tenantMiddleware,
  getTenantContext,
  getUserId,
  hasPermission,
  requirePermission,
  createTenantFilter,
  validateTenantSwitch,
  enforceResourceLimits,
  auditTenantOperation,
} from '../../middleware/tenant';

// Mock environment variables
process.env.JWT_SECRET = 'test-secret';

// Mock jwt module
jest.mock('jsonwebtoken');

describe('Tenant Middleware', () => {
  let app: Hono;
  let mockContext: any;

  const validJWTPayload = {
    userId: '123e4567-e89b-12d3-a456-426614174000',
    tenantId: '123e4567-e89b-12d3-a456-426614174001',
    organizationId: '123e4567-e89b-12d3-a456-426614174002',
    siteId: '123e4567-e89b-12d3-a456-426614174003',
    permissions: ['read:users', 'write:users'],
    deploymentModel: 'ssp-managed' as const,
    isSSPTechnician: false,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    app = new Hono();
    
    // Mock JWT verification
    (jwt.verify as jest.Mock).mockReturnValue(validJWTPayload);
  });

  describe('tenantMiddleware', () => {
    it('should extract and validate tenant context from valid JWT', async () => {
      app.use('*', tenantMiddleware);
      app.get('/test', (c) => {
        const tenant = c.get('tenant');
        const userId = c.get('userId');
        return c.json({ tenant, userId });
      });

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.tenant).toMatchObject({
        tenantId: validJWTPayload.tenantId,
        organizationId: validJWTPayload.organizationId,
        siteId: validJWTPayload.siteId,
        permissions: validJWTPayload.permissions,
        deploymentModel: validJWTPayload.deploymentModel,
        isSSPTechnician: false,
      });
      expect(body.userId).toBe(validJWTPayload.userId);
    });

    it('should reject requests without authorization header', async () => {
      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const res = await app.request('/test');

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.message).toBe('Missing or invalid authorization header');
    });

    it('should reject requests with invalid authorization format', async () => {
      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Invalid token-format',
        },
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.message).toBe('Missing or invalid authorization header');
    });

    it('should reject invalid JWT tokens', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer invalid-token',
        },
      });

      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.message).toBe('Invalid or expired token');
    });

    it('should enforce tenant isolation', async () => {
      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const res = await app.request('/test?tenantId=different-tenant-id', {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.message).toBe('Access denied: Cannot access data from different tenant');
    });

    it('should allow SSP technicians to switch tenants', async () => {
      const sspPayload = { ...validJWTPayload, isSSPTechnician: true };
      (jwt.verify as jest.Mock).mockReturnValue(sspPayload);

      app.use('*', tenantMiddleware);
      app.get('/test', (c) => {
        const tenant = c.get('tenant');
        return c.json({ effectiveTenantId: tenant.tenantId });
      });

      const targetTenantId = '123e4567-e89b-12d3-a456-426614174999';
      const res = await app.request(`/test?tenantId=${targetTenantId}`, {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.effectiveTenantId).toBe(targetTenantId);
    });

    it('should validate organization access', async () => {
      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const differentOrgId = '123e4567-e89b-12d3-a456-426614179999';
      const res = await app.request(`/test?organizationId=${differentOrgId}`, {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.message).toBe('Access denied: Insufficient permissions for requested organization');
    });

    it('should allow access to all organizations with permission', async () => {
      const permissionPayload = {
        ...validJWTPayload,
        permissions: ['access:all-organizations'],
      };
      (jwt.verify as jest.Mock).mockReturnValue(permissionPayload);

      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const differentOrgId = '123e4567-e89b-12d3-a456-426614179999';
      const res = await app.request(`/test?organizationId=${differentOrgId}`, {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(200);
    });

    it('should handle missing JWT secret configuration', async () => {
      const originalSecret = process.env.JWT_SECRET;
      delete process.env.JWT_SECRET;

      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.message).toBe('JWT secret not configured');

      process.env.JWT_SECRET = originalSecret;
    });

    it('should handle ZodError for invalid JWT payload', async () => {
      (jwt.verify as jest.Mock).mockReturnValue({
        invalidField: 'test',
      });

      app.use('*', tenantMiddleware);
      app.get('/test', (c) => c.text('OK'));

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.message).toBe('Invalid request format');
    });

    it('should add effective tenant headers to request', async () => {
      const headers: Record<string, string> = {};
      
      app.use('*', tenantMiddleware);
      app.get('/test', (c) => {
        // Capture headers that would be added
        return c.json({
          tenantId: c.get('tenant').tenantId,
          organizationId: c.get('tenant').organizationId,
          siteId: c.get('tenant').siteId,
        });
      });

      const res = await app.request('/test', {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.tenantId).toBe(validJWTPayload.tenantId);
      expect(body.organizationId).toBe(validJWTPayload.organizationId);
      expect(body.siteId).toBe(validJWTPayload.siteId);
    });
  });

  describe('Utility Functions', () => {
    beforeEach(() => {
      // Create a mock context with tenant data
      mockContext = {
        get: jest.fn((key: string) => {
          if (key === 'tenant') {
            return {
              tenantId: validJWTPayload.tenantId,
              organizationId: validJWTPayload.organizationId,
              siteId: validJWTPayload.siteId,
              permissions: validJWTPayload.permissions,
              deploymentModel: validJWTPayload.deploymentModel,
              isSSPTechnician: false,
              resourceLimits: {
                maxDoors: 10000,
                maxCameras: 1000,
                maxUsers: 10000,
                storageQuotaGB: 1000,
              },
            };
          }
          if (key === 'userId') {
            return validJWTPayload.userId;
          }
          return undefined;
        }),
      };
    });

    describe('getTenantContext', () => {
      it('should return tenant context', () => {
        const tenant = getTenantContext(mockContext);
        expect(tenant).toBeDefined();
        expect(tenant.tenantId).toBe(validJWTPayload.tenantId);
      });

      it('should throw error if tenant context not available', () => {
        mockContext.get = jest.fn(() => undefined);
        expect(() => getTenantContext(mockContext)).toThrow('Tenant context not available');
      });
    });

    describe('getUserId', () => {
      it('should return user ID', () => {
        const userId = getUserId(mockContext);
        expect(userId).toBe(validJWTPayload.userId);
      });

      it('should throw error if user ID not available', () => {
        mockContext.get = jest.fn((key: string) => {
          if (key === 'userId') return undefined;
          return null;
        });
        expect(() => getUserId(mockContext)).toThrow('User ID not available');
      });
    });

    describe('hasPermission', () => {
      it('should return true for granted permission', () => {
        expect(hasPermission(mockContext, 'read:users')).toBe(true);
      });

      it('should return false for missing permission', () => {
        expect(hasPermission(mockContext, 'delete:users')).toBe(false);
      });

      it('should return true for admin:all permission', () => {
        mockContext.get = jest.fn(() => ({
          permissions: ['admin:all'],
          isSSPTechnician: false,
        }));
        expect(hasPermission(mockContext, 'any:permission')).toBe(true);
      });

      it('should return true for SSP technician with ssp:all permission', () => {
        mockContext.get = jest.fn(() => ({
          permissions: ['ssp:all'],
          isSSPTechnician: true,
        }));
        expect(hasPermission(mockContext, 'any:permission')).toBe(true);
      });
    });

    describe('requirePermission', () => {
      it('should allow access with required permission', async () => {
        app.use('*', async (c, next) => {
          c.set('tenant', {
            tenantId: validJWTPayload.tenantId,
            permissions: ['read:users'],
            isSSPTechnician: false,
          } as any);
          await next();
        });
        app.get('/test', requirePermission('read:users'), (c) => c.text('OK'));

        const res = await app.request('/test');
        expect(res.status).toBe(200);
      });

      it('should deny access without required permission', async () => {
        app.use('*', async (c, next) => {
          c.set('tenant', {
            tenantId: validJWTPayload.tenantId,
            permissions: ['read:users'],
            isSSPTechnician: false,
          } as any);
          await next();
        });
        app.get('/test', requirePermission('delete:users'), (c) => c.text('OK'));

        const res = await app.request('/test');
        expect(res.status).toBe(403);
        const body = await res.json();
        expect(body.message).toBe("Access denied: Required permission 'delete:users' not found");
      });
    });

    describe('createTenantFilter', () => {
      it('should create basic tenant filter', () => {
        const filter = createTenantFilter(mockContext);
        expect(filter).toEqual({
          tenantId: validJWTPayload.tenantId,
          organizationId: validJWTPayload.organizationId,
          siteId: validJWTPayload.siteId,
        });
      });

      it('should merge additional filters', () => {
        const filter = createTenantFilter(mockContext, { active: true, type: 'admin' });
        expect(filter).toEqual({
          tenantId: validJWTPayload.tenantId,
          organizationId: validJWTPayload.organizationId,
          siteId: validJWTPayload.siteId,
          active: true,
          type: 'admin',
        });
      });

      it('should exclude organization filter with all-org permission', () => {
        mockContext.get = jest.fn((key: string) => {
          if (key === 'tenant') {
            return {
              tenantId: validJWTPayload.tenantId,
              organizationId: validJWTPayload.organizationId,
              permissions: ['access:all-organizations'],
            };
          }
          return undefined;
        });

        const filter = createTenantFilter(mockContext);
        expect(filter).toEqual({
          tenantId: validJWTPayload.tenantId,
        });
      });
    });

    describe('validateTenantSwitch', () => {
      it('should allow SSP technician to switch tenants', async () => {
        mockContext.get = jest.fn(() => ({
          isSSPTechnician: true,
          tenantId: validJWTPayload.tenantId,
        }));

        const result = await validateTenantSwitch(mockContext, 'target-tenant-id');
        expect(result).toBe(true);
      });

      it('should deny non-SSP technician from switching tenants', async () => {
        const result = await validateTenantSwitch(mockContext, 'target-tenant-id');
        expect(result).toBe(false);
      });
    });

    describe('enforceResourceLimits', () => {
      it('should allow operation within resource limits', async () => {
        app.use('*', async (c, next) => {
          c.set('tenant', {
            tenantId: validJWTPayload.tenantId,
            resourceLimits: {
              maxUsers: 100,
            },
          } as any);
          await next();
        });
        app.post('/users', enforceResourceLimits('maxUsers'), (c) => c.text('Created'));

        const res = await app.request('/users', { method: 'POST' });
        expect(res.status).toBe(200);
      });

      it('should reject operation exceeding resource limits', async () => {
        // Mock getCurrentResourceUsage to return limit reached
        app.use('*', async (c, next) => {
          c.set('tenant', {
            tenantId: validJWTPayload.tenantId,
            resourceLimits: {
              maxUsers: 0, // Set limit to 0 to trigger rejection
            },
          } as any);
          await next();
        });
        app.post('/users', enforceResourceLimits('maxUsers'), (c) => c.text('Created'));

        const res = await app.request('/users', { method: 'POST' });
        expect(res.status).toBe(429);
        const body = await res.json();
        expect(body.message).toContain('Resource limit exceeded');
      });
    });

    describe('auditTenantOperation', () => {
      it('should log tenant operations', async () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
        
        mockContext.req = {
          header: jest.fn((name: string) => {
            if (name === 'X-Forwarded-For') return '192.168.1.1';
            if (name === 'User-Agent') return 'Test Agent';
            return null;
          }),
        };

        await auditTenantOperation(
          mockContext,
          'CREATE',
          'user',
          'user-123',
          { email: 'test@example.com' }
        );

        expect(consoleSpy).toHaveBeenCalledWith(
          'Audit log:',
          expect.objectContaining({
            tenantId: validJWTPayload.tenantId,
            userId: validJWTPayload.userId,
            operation: 'CREATE',
            resourceType: 'user',
            resourceId: 'user-123',
            ipAddress: '192.168.1.1',
            userAgent: 'Test Agent',
            additionalData: { email: 'test@example.com' },
          })
        );

        consoleSpy.mockRestore();
      });

      it('should handle audit logging errors gracefully', async () => {
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
        mockContext.get = jest.fn(() => {
          throw new Error('Context error');
        });

        // Should not throw
        await expect(
          auditTenantOperation(mockContext, 'CREATE', 'user')
        ).resolves.not.toThrow();

        expect(consoleSpy).toHaveBeenCalled();
        consoleSpy.mockRestore();
      });
    });
  });
});