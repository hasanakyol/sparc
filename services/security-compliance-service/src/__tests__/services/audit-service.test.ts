import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { AuditService } from '../../services/audit-service';
import { AuditAction, ResourceType } from '../../types/enums';

describe('AuditService', () => {
  let auditService: AuditService;
  let mockPrisma: jest.Mocked<PrismaClient>;
  let mockRedis: jest.Mocked<Redis>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as any;
    mockRedis = new Redis() as any;
    auditService = new AuditService(mockPrisma as any, mockRedis as any);
  });

  describe('createAuditLog', () => {
    it('should create an audit log entry', async () => {
      const auditData = {
        tenantId: 'tenant-123',
        userId: 'user-123',
        action: AuditAction.CREATE,
        resourceType: ResourceType.USER,
        resourceId: 'resource-123',
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0'
      };

      const expectedLog = {
        id: 'log-123',
        ...auditData,
        timestamp: new Date()
      };

      mockPrisma.auditLog.create.mockResolvedValue(expectedLog);
      mockRedis.publish.mockResolvedValue(1);
      mockRedis.hincrby.mockResolvedValue(1);

      const result = await auditService.createAuditLog(auditData);

      expect(result).toEqual(expectedLog);
      expect(mockPrisma.auditLog.create).toHaveBeenCalledWith({
        data: expect.objectContaining(auditData)
      });
      expect(mockRedis.publish).toHaveBeenCalledWith(
        'audit:created',
        JSON.stringify(expectedLog)
      );
    });
  });

  describe('getAuditLogs', () => {
    it('should retrieve paginated audit logs', async () => {
      const tenantId = 'tenant-123';
      const query = {
        page: 1,
        limit: 50,
        action: AuditAction.CREATE
      };

      const mockLogs = [
        {
          id: 'log-1',
          action: AuditAction.CREATE,
          timestamp: new Date()
        },
        {
          id: 'log-2',
          action: AuditAction.CREATE,
          timestamp: new Date()
        }
      ];

      mockPrisma.auditLog.count.mockResolvedValue(100);
      mockPrisma.auditLog.findMany.mockResolvedValue(mockLogs);

      const result = await auditService.getAuditLogs(tenantId, query);

      expect(result.logs).toEqual(mockLogs);
      expect(result.pagination).toEqual({
        page: 1,
        limit: 50,
        total: 100,
        pages: 2
      });
    });

    it('should apply filters correctly', async () => {
      const tenantId = 'tenant-123';
      const query = {
        page: 1,
        limit: 50,
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        userId: 'user-123'
      };

      mockPrisma.auditLog.count.mockResolvedValue(0);
      mockPrisma.auditLog.findMany.mockResolvedValue([]);

      await auditService.getAuditLogs(tenantId, query);

      expect(mockPrisma.auditLog.findMany).toHaveBeenCalledWith({
        where: expect.objectContaining({
          tenantId,
          userId: 'user-123',
          timestamp: {
            gte: new Date(query.startDate),
            lte: new Date(query.endDate)
          }
        }),
        orderBy: { timestamp: 'desc' },
        skip: 0,
        take: 50,
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true
            }
          }
        }
      });
    });
  });

  describe('exportAuditLogs', () => {
    it('should export audit logs as CSV', async () => {
      const tenantId = 'tenant-123';
      const exportRequest = {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        format: 'csv' as const
      };

      const mockLogs = [
        {
          id: 'log-1',
          timestamp: new Date(),
          action: AuditAction.CREATE,
          resourceType: ResourceType.USER,
          resourceId: 'res-1',
          userId: 'user-1',
          ipAddress: '192.168.1.1',
          userAgent: 'Mozilla',
          details: {},
          user: { email: 'user@example.com' }
        }
      ];

      mockPrisma.auditLog.findMany.mockResolvedValue(mockLogs);

      const result = await auditService.exportAuditLogs(tenantId, exportRequest);

      expect(result).toBeInstanceOf(Buffer);
      expect(result.toString()).toContain('header');
      expect(result.toString()).toContain('records');
    });

    it('should export audit logs as JSON', async () => {
      const tenantId = 'tenant-123';
      const exportRequest = {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        format: 'json' as const
      };

      const mockLogs = [{ id: 'log-1' }];
      mockPrisma.auditLog.findMany.mockResolvedValue(mockLogs);

      const result = await auditService.exportAuditLogs(tenantId, exportRequest);

      expect(result).toBeInstanceOf(Buffer);
      expect(JSON.parse(result.toString())).toEqual(mockLogs);
    });
  });

  describe('getAuditStats', () => {
    it('should return audit statistics', async () => {
      const tenantId = 'tenant-123';
      const period = '7d';

      mockPrisma.auditLog.groupBy
        .mockResolvedValueOnce([
          { action: AuditAction.CREATE, _count: { action: 10 } },
          { action: AuditAction.UPDATE, _count: { action: 5 } }
        ])
        .mockResolvedValueOnce([
          { resourceType: ResourceType.USER, _count: { resourceType: 8 } }
        ])
        .mockResolvedValueOnce([
          { userId: 'user-1', _count: { userId: 12 } }
        ]);

      mockPrisma.$queryRaw.mockResolvedValue([
        { hour: new Date(), count: 5 }
      ]);

      const result = await auditService.getAuditStats(tenantId, period);

      expect(result).toHaveProperty('period', period);
      expect(result).toHaveProperty('actions');
      expect(result).toHaveProperty('resources');
      expect(result).toHaveProperty('topUsers');
      expect(result).toHaveProperty('hourlyActivity');
    });
  });

  describe('getRetentionStatus', () => {
    it('should return retention status', async () => {
      const tenantId = 'tenant-123';

      const mockPolicy = {
        id: 'policy-1',
        retentionPeriodDays: 2555
      };

      const oldestLog = {
        timestamp: new Date('2020-01-01')
      };

      mockPrisma.dataRetentionPolicy.findFirst.mockResolvedValue(mockPolicy);
      mockPrisma.auditLog.count
        .mockResolvedValueOnce(10000) // total
        .mockResolvedValueOnce(100); // to delete
      mockPrisma.auditLog.findFirst.mockResolvedValue(oldestLog);

      const result = await auditService.getRetentionStatus(tenantId);

      expect(result).toHaveProperty('policy', mockPolicy);
      expect(result).toHaveProperty('totalLogs', 10000);
      expect(result).toHaveProperty('oldestLog', oldestLog.timestamp);
      expect(result).toHaveProperty('logsToDelete', 100);
    });
  });

  describe('isHealthy', () => {
    it('should return true when database is accessible', async () => {
      mockPrisma.$queryRaw.mockResolvedValue([{ result: 1 }]);

      const result = await auditService.isHealthy();

      expect(result).toBe(true);
      expect(mockPrisma.$queryRaw).toHaveBeenCalledWith(expect.anything());
    });

    it('should return false when database is not accessible', async () => {
      mockPrisma.$queryRaw.mockRejectedValue(new Error('Connection failed'));

      const result = await auditService.isHealthy();

      expect(result).toBe(false);
    });
  });
});