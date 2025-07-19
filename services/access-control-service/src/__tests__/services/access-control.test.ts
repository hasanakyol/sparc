import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AccessControlService } from '../../services/access-control-service';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

// Mock dependencies
vi.mock('@prisma/client');
vi.mock('ioredis');

describe('AccessControlService', () => {
  let service: AccessControlService;
  let mockPrisma: any;
  let mockRedis: any;

  beforeEach(() => {
    // Create mock instances
    mockPrisma = {
      accessRules: {
        findMany: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn()
      },
      accessLogs: {
        create: vi.fn(),
        findMany: vi.fn()
      },
      users: {
        findUnique: vi.fn()
      },
      $transaction: vi.fn()
    };

    mockRedis = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
      expire: vi.fn()
    };

    service = new AccessControlService(mockPrisma, mockRedis);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('checkAccess', () => {
    it('should allow access when user has valid permissions', async () => {
      const userId = 'user-123';
      const resource = 'door-456';
      const action = 'open';

      mockPrisma.accessRules.findMany.mockResolvedValue([{
        id: 'rule-1',
        userId,
        resource,
        action,
        isActive: true,
        expiresAt: new Date(Date.now() + 86400000) // Tomorrow
      }]);

      const result = await service.checkAccess(userId, resource, action);

      expect(result).toEqual({
        allowed: true,
        reason: 'User has active permission',
        ruleId: 'rule-1'
      });
    });

    it('should deny access when no rules exist', async () => {
      mockPrisma.accessRules.findMany.mockResolvedValue([]);

      const result = await service.checkAccess('user-123', 'door-456', 'open');

      expect(result).toEqual({
        allowed: false,
        reason: 'No matching access rules found'
      });
    });

    it('should deny access for expired rules', async () => {
      mockPrisma.accessRules.findMany.mockResolvedValue([{
        id: 'rule-1',
        userId: 'user-123',
        resource: 'door-456',
        action: 'open',
        isActive: true,
        expiresAt: new Date(Date.now() - 86400000) // Yesterday
      }]);

      const result = await service.checkAccess('user-123', 'door-456', 'open');

      expect(result).toEqual({
        allowed: false,
        reason: 'Access rule has expired'
      });
    });

    it('should use cache when available', async () => {
      const cacheKey = 'access:user-123:door-456:open';
      mockRedis.get.mockResolvedValue(JSON.stringify({
        allowed: true,
        reason: 'Cached permission'
      }));

      const result = await service.checkAccess('user-123', 'door-456', 'open');

      expect(mockRedis.get).toHaveBeenCalledWith(cacheKey);
      expect(mockPrisma.accessRules.findMany).not.toHaveBeenCalled();
      expect(result.allowed).toBe(true);
    });
  });

  describe('createAccessRule', () => {
    it('should create a new access rule', async () => {
      const ruleData = {
        userId: 'user-123',
        resource: 'door-456',
        action: 'open',
        expiresAt: new Date(Date.now() + 86400000)
      };

      const createdRule = { id: 'rule-1', ...ruleData, isActive: true };
      mockPrisma.accessRules.create.mockResolvedValue(createdRule);

      const result = await service.createAccessRule(ruleData);

      expect(mockPrisma.accessRules.create).toHaveBeenCalledWith({
        data: expect.objectContaining(ruleData)
      });
      expect(result).toEqual(createdRule);
    });

    it('should invalidate cache after creating rule', async () => {
      const ruleData = {
        userId: 'user-123',
        resource: 'door-456',
        action: 'open'
      };

      await service.createAccessRule(ruleData);

      expect(mockRedis.del).toHaveBeenCalledWith(
        expect.stringContaining('access:user-123:door-456:open')
      );
    });
  });

  describe('revokeAccess', () => {
    it('should deactivate access rule', async () => {
      const ruleId = 'rule-1';
      mockPrisma.accessRules.update.mockResolvedValue({
        id: ruleId,
        isActive: false
      });

      await service.revokeAccess(ruleId);

      expect(mockPrisma.accessRules.update).toHaveBeenCalledWith({
        where: { id: ruleId },
        data: { isActive: false }
      });
    });
  });

  describe('logAccess', () => {
    it('should create access log entry', async () => {
      const logData = {
        userId: 'user-123',
        resource: 'door-456',
        action: 'open',
        allowed: true,
        timestamp: new Date()
      };

      await service.logAccess(logData);

      expect(mockPrisma.accessLogs.create).toHaveBeenCalledWith({
        data: expect.objectContaining(logData)
      });
    });

    it('should handle logging errors gracefully', async () => {
      mockPrisma.accessLogs.create.mockRejectedValue(new Error('DB error'));

      // Should not throw
      await expect(service.logAccess({
        userId: 'user-123',
        resource: 'door-456',
        action: 'open',
        allowed: false
      })).resolves.not.toThrow();
    });
  });

  describe('getAccessHistory', () => {
    it('should return user access history', async () => {
      const userId = 'user-123';
      const mockLogs = [
        { id: 'log-1', userId, resource: 'door-456', action: 'open', timestamp: new Date() },
        { id: 'log-2', userId, resource: 'door-789', action: 'open', timestamp: new Date() }
      ];

      mockPrisma.accessLogs.findMany.mockResolvedValue(mockLogs);

      const result = await service.getAccessHistory(userId, { limit: 10 });

      expect(mockPrisma.accessLogs.findMany).toHaveBeenCalledWith({
        where: { userId },
        orderBy: { timestamp: 'desc' },
        take: 10
      });
      expect(result).toEqual(mockLogs);
    });

    it('should filter by date range', async () => {
      const userId = 'user-123';
      const startDate = new Date('2024-01-01');
      const endDate = new Date('2024-01-31');

      await service.getAccessHistory(userId, { startDate, endDate });

      expect(mockPrisma.accessLogs.findMany).toHaveBeenCalledWith({
        where: {
          userId,
          timestamp: {
            gte: startDate,
            lte: endDate
          }
        },
        orderBy: { timestamp: 'desc' }
      });
    });
  });

  describe('bulkCheckAccess', () => {
    it('should check multiple access requests efficiently', async () => {
      const requests = [
        { userId: 'user-1', resource: 'door-1', action: 'open' },
        { userId: 'user-2', resource: 'door-2', action: 'open' }
      ];

      mockPrisma.accessRules.findMany.mockResolvedValue([
        { userId: 'user-1', resource: 'door-1', action: 'open', isActive: true },
        { userId: 'user-2', resource: 'door-2', action: 'open', isActive: true }
      ]);

      const results = await service.bulkCheckAccess(requests);

      expect(results).toHaveLength(2);
      expect(results.every(r => r.allowed)).toBe(true);
    });
  });
});