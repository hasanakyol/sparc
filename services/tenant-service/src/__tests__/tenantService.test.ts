import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TenantService } from '../services/tenantService';
import Redis from 'ioredis';
import { HTTPException } from 'hono/http-exception';

// Mock Redis
vi.mock('ioredis');

// Mock database
vi.mock('@sparc/database', () => ({
  db: {
    select: vi.fn().mockReturnThis(),
    from: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    offset: vi.fn().mockReturnThis(),
    orderBy: vi.fn().mockReturnThis(),
    insert: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    returning: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    delete: vi.fn().mockReturnThis(),
    query: {
      tenants: {
        findFirst: vi.fn()
      },
      organizations: {
        findFirst: vi.fn()
      }
    }
  }
}));

describe('TenantService', () => {
  let service: TenantService;
  let mockRedis: any;

  beforeEach(() => {
    mockRedis = {
      get: vi.fn(),
      setex: vi.fn(),
      del: vi.fn(),
      keys: vi.fn(),
      incr: vi.fn()
    };
    service = new TenantService(mockRedis as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('getTenantById', () => {
    it('should return cached tenant if available', async () => {
      const mockTenant = {
        id: 'tenant-1',
        name: 'Test Tenant',
        domain: 'test',
        stats: {}
      };
      
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockTenant));
      
      const result = await service.getTenantById('tenant-1');
      
      expect(result).toEqual(mockTenant);
      expect(mockRedis.get).toHaveBeenCalledWith('tenant:tenant-1:false');
      expect(mockRedis.incr).toHaveBeenCalledWith('metrics:tenant:cache_hits');
    });

    it('should fetch from database if not cached', async () => {
      const mockTenant = {
        id: 'tenant-1',
        name: 'Test Tenant',
        domain: 'test'
      };
      
      mockRedis.get.mockResolvedValueOnce(null);
      const { db } = await import('@sparc/database');
      (db.query.tenants.findFirst as any).mockResolvedValueOnce(mockTenant);
      
      // Mock the stats query
      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue([{ count: 0 }])
        })
      });
      
      const result = await service.getTenantById('tenant-1');
      
      expect(result).toBeDefined();
      expect(result?.id).toBe('tenant-1');
      expect(mockRedis.incr).toHaveBeenCalledWith('metrics:tenant:cache_misses');
      expect(mockRedis.setex).toHaveBeenCalled();
    });

    it('should return null if tenant not found', async () => {
      mockRedis.get.mockResolvedValueOnce(null);
      const { db } = await import('@sparc/database');
      (db.query.tenants.findFirst as any).mockResolvedValueOnce(null);
      
      const result = await service.getTenantById('non-existent');
      
      expect(result).toBeNull();
    });
  });

  describe('createTenant', () => {
    it('should create a new tenant', async () => {
      const newTenantData = {
        name: 'New Tenant',
        domain: 'new-tenant',
        contactEmail: 'admin@newtenant.com'
      };
      
      const { db } = await import('@sparc/database');
      (db.query.tenants.findFirst as any).mockResolvedValueOnce(null);
      (db.insert as any).mockReturnValue({
        values: vi.fn().mockReturnValue({
          returning: vi.fn().mockResolvedValue([{ id: 'new-id', ...newTenantData }])
        })
      });
      
      const result = await service.createTenant(newTenantData, 'user-1');
      
      expect(result).toBeDefined();
      expect(result.name).toBe('New Tenant');
    });

    it('should throw error if domain already exists', async () => {
      const newTenantData = {
        name: 'New Tenant',
        domain: 'existing-domain',
        contactEmail: 'admin@newtenant.com'
      };
      
      const { db } = await import('@sparc/database');
      (db.query.tenants.findFirst as any).mockResolvedValueOnce({ id: 'existing-id' });
      
      await expect(service.createTenant(newTenantData)).rejects.toThrow(HTTPException);
    });
  });

  describe('updateTenant', () => {
    it('should update an existing tenant', async () => {
      const updateData = {
        name: 'Updated Tenant'
      };
      
      // Mock getTenantById
      const existingTenant = {
        id: 'tenant-1',
        name: 'Old Name',
        domain: 'test'
      };
      
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(existingTenant));
      
      const { db } = await import('@sparc/database');
      (db.update as any).mockReturnValue({
        set: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            returning: vi.fn().mockResolvedValue([{ id: 'tenant-1', ...updateData }])
          })
        })
      });
      
      const result = await service.updateTenant('tenant-1', updateData, 'user-1');
      
      expect(result).toBeDefined();
      expect(result.name).toBe('Updated Tenant');
    });

    it('should throw error if tenant not found', async () => {
      mockRedis.get.mockResolvedValueOnce(null);
      const { db } = await import('@sparc/database');
      (db.query.tenants.findFirst as any).mockResolvedValueOnce(null);
      
      await expect(service.updateTenant('non-existent', {})).rejects.toThrow(HTTPException);
    });
  });

  describe('deleteTenant', () => {
    it('should delete tenant if no organizations exist', async () => {
      const { db } = await import('@sparc/database');
      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue([{ count: 0 }])
        })
      });
      
      (db.delete as any).mockReturnValue({
        where: vi.fn().mockResolvedValue(undefined)
      });
      
      await service.deleteTenant('tenant-1');
      
      expect(db.delete).toHaveBeenCalled();
    });

    it('should throw error if tenant has organizations', async () => {
      const { db } = await import('@sparc/database');
      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue([{ count: 1 }])
        })
      });
      
      await expect(service.deleteTenant('tenant-1')).rejects.toThrow(HTTPException);
    });
  });

  describe('getTenantStats', () => {
    it('should return cached stats if available', async () => {
      const mockStats = {
        organizationCount: 5,
        siteCount: 10,
        buildingCount: 20,
        floorCount: 50,
        zoneCount: 100,
        userCount: 0,
        doorCount: 0,
        cameraCount: 0
      };
      
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockStats));
      
      const result = await service.getTenantStats('tenant-1');
      
      expect(result).toEqual(mockStats);
      expect(mockRedis.get).toHaveBeenCalledWith('tenant:stats:tenant-1');
    });

    it('should calculate stats if not cached', async () => {
      mockRedis.get.mockResolvedValueOnce(null);
      
      const { db } = await import('@sparc/database');
      // Mock all count queries
      (db.select as any).mockReturnValue({
        from: vi.fn().mockReturnValue({
          where: vi.fn().mockResolvedValue([{ count: 5 }])
        })
      });
      
      const result = await service.getTenantStats('tenant-1');
      
      expect(result).toBeDefined();
      expect(result.organizationCount).toBe(5);
      expect(mockRedis.setex).toHaveBeenCalled();
    });
  });

  describe('getTenantResourceUsage', () => {
    it('should calculate resource usage percentages', async () => {
      const mockTenant = {
        id: 'tenant-1',
        name: 'Test Tenant',
        domain: 'test',
        resourceQuotas: {
          maxUsers: 100,
          maxDoors: 50,
          maxCameras: 10,
          storageQuotaGB: 100
        }
      };
      
      const mockStats = {
        userCount: 25,
        doorCount: 10,
        cameraCount: 5,
        organizationCount: 1,
        siteCount: 1,
        buildingCount: 1,
        floorCount: 1,
        zoneCount: 1
      };
      
      // Mock getTenantById
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockTenant));
      
      // Mock getTenantStats
      mockRedis.get.mockResolvedValueOnce(JSON.stringify(mockStats));
      
      const result = await service.getTenantResourceUsage('tenant-1');
      
      expect(result.users.current).toBe(25);
      expect(result.users.quota).toBe(100);
      expect(result.users.percentage).toBe('25.0');
      expect(result.doors.percentage).toBe('20.0');
      expect(result.cameras.percentage).toBe('50.0');
    });

    it('should throw error if tenant not found', async () => {
      mockRedis.get.mockResolvedValueOnce(null);
      const { db } = await import('@sparc/database');
      (db.query.tenants.findFirst as any).mockResolvedValueOnce(null);
      
      await expect(service.getTenantResourceUsage('non-existent')).rejects.toThrow(HTTPException);
    });
  });
});