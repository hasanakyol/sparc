import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { AlertService } from '../alert.service';
import Redis from 'ioredis';
import { db } from '../../db';
import type { CreateAlertDTO, UpdateAlertDTO } from '@sparc/shared/types/alerts';

// Mock dependencies
jest.mock('../../db');
jest.mock('ioredis');

const mockRedis = {
  setex: jest.fn(),
  get: jest.fn(),
  del: jest.fn(),
  hincrby: jest.fn(),
  expire: jest.fn(),
  hgetall: jest.fn(),
  zadd: jest.fn(),
  zrem: jest.fn(),
  zrange: jest.fn(),
  zrangebyscore: jest.fn(),
};

const mockDb = {
  insert: jest.fn(),
  select: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
};

describe('AlertService', () => {
  let alertService: AlertService;
  let redisInstance: any;

  beforeEach(() => {
    jest.clearAllMocks();
    redisInstance = mockRedis as any;
    alertService = new AlertService(redisInstance);

    // Setup default mocks
    (db.insert as jest.Mock).mockReturnValue({
      values: jest.fn().mockReturnValue({
        returning: jest.fn().mockResolvedValue([{
          id: 'test-alert-id',
          tenantId: 'test-tenant',
          alertType: 'system_offline',
          priority: 'high',
          sourceId: 'test-source',
          sourceType: 'system',
          message: 'Test alert',
          details: {},
          status: 'open',
          createdAt: new Date(),
          updatedAt: new Date(),
        }]),
      }),
    });

    (db.select as jest.Mock).mockReturnValue({
      from: jest.fn().mockReturnValue({
        where: jest.fn().mockReturnValue({
          limit: jest.fn().mockResolvedValue([{
            id: 'test-alert-id',
            tenantId: 'test-tenant',
            alertType: 'system_offline',
            priority: 'high',
            sourceId: 'test-source',
            sourceType: 'system',
            message: 'Test alert',
            details: {},
            status: 'open',
            createdAt: new Date(),
            updatedAt: new Date(),
          }]),
          orderBy: jest.fn().mockReturnValue({
            limit: jest.fn().mockReturnValue({
              offset: jest.fn().mockResolvedValue([]),
            }),
          }),
        }),
      }),
    });
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('createAlert', () => {
    it('should create a new alert successfully', async () => {
      const createAlertDto: CreateAlertDTO = {
        alertType: 'system_offline',
        priority: 'high',
        sourceId: 'test-source',
        sourceType: 'system',
        message: 'System is offline',
        details: { reason: 'Network failure' },
      };

      const alert = await alertService.createAlert('test-tenant', createAlertDto);

      expect(alert).toBeDefined();
      expect(alert.id).toBe('test-alert-id');
      expect(alert.tenantId).toBe('test-tenant');
      expect(alert.alertType).toBe('system_offline');
      expect(alert.priority).toBe('high');
      expect(alert.message).toBe('Test alert');

      // Verify cache was set
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'alert:test-alert-id',
        3600,
        expect.any(String)
      );

      // Verify stats were updated
      expect(mockRedis.hincrby).toHaveBeenCalledWith('alert_stats:test-tenant', 'high', 1);
      expect(mockRedis.hincrby).toHaveBeenCalledWith('alert_stats:test-tenant', 'open', 1);
      expect(mockRedis.hincrby).toHaveBeenCalledWith('alert_stats:test-tenant', 'total', 1);
    });

    it('should handle database errors gracefully', async () => {
      (db.insert as jest.Mock).mockReturnValue({
        values: jest.fn().mockReturnValue({
          returning: jest.fn().mockRejectedValue(new Error('Database error')),
        }),
      });

      const createAlertDto: CreateAlertDTO = {
        alertType: 'system_offline',
        priority: 'high',
        sourceId: 'test-source',
        sourceType: 'system',
        message: 'System is offline',
      };

      await expect(alertService.createAlert('test-tenant', createAlertDto))
        .rejects.toThrow('Database error');
    });
  });

  describe('getAlert', () => {
    it('should return cached alert if available', async () => {
      const cachedAlert = {
        id: 'cached-alert-id',
        tenantId: 'test-tenant',
        alertType: 'camera_offline',
        priority: 'medium',
        sourceId: 'camera-001',
        sourceType: 'video',
        message: 'Camera offline',
        details: {},
        status: 'open',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(cachedAlert));

      const alert = await alertService.getAlert('test-tenant', 'cached-alert-id');

      expect(alert).toBeDefined();
      expect(alert?.id).toBe('cached-alert-id');
      expect(alert?.alertType).toBe('camera_offline');
      expect(mockRedis.get).toHaveBeenCalledWith('alert:cached-alert-id');
      expect(db.select).not.toHaveBeenCalled();
    });

    it('should fetch from database if not cached', async () => {
      mockRedis.get.mockResolvedValue(null);

      const alert = await alertService.getAlert('test-tenant', 'test-alert-id');

      expect(alert).toBeDefined();
      expect(alert?.id).toBe('test-alert-id');
      expect(db.select).toHaveBeenCalled();
      expect(mockRedis.setex).toHaveBeenCalled();
    });

    it('should return null for non-existent alert', async () => {
      mockRedis.get.mockResolvedValue(null);
      (db.select as jest.Mock).mockReturnValue({
        from: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue([]),
          }),
        }),
      });

      const alert = await alertService.getAlert('test-tenant', 'non-existent');

      expect(alert).toBeNull();
    });

    it('should not return alert from different tenant', async () => {
      const cachedAlert = {
        id: 'cached-alert-id',
        tenantId: 'different-tenant',
        alertType: 'camera_offline',
        priority: 'medium',
        sourceId: 'camera-001',
        sourceType: 'video',
        message: 'Camera offline',
        details: {},
        status: 'open',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(cachedAlert));

      const alert = await alertService.getAlert('test-tenant', 'cached-alert-id');

      expect(alert).toBeNull();
      expect(db.select).toHaveBeenCalled();
    });
  });

  describe('updateAlert', () => {
    it('should update alert status to acknowledged', async () => {
      const updateDto: UpdateAlertDTO = {
        status: 'acknowledged',
        acknowledgedBy: 'user-123',
      };

      (db.update as jest.Mock).mockReturnValue({
        set: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            returning: jest.fn().mockResolvedValue([{
              id: 'test-alert-id',
              tenantId: 'test-tenant',
              alertType: 'system_offline',
              priority: 'high',
              sourceId: 'test-source',
              sourceType: 'system',
              message: 'Test alert',
              details: {},
              status: 'acknowledged',
              acknowledgedBy: 'user-123',
              acknowledgedAt: new Date(),
              createdAt: new Date(),
              updatedAt: new Date(),
            }]),
          }),
        }),
      });

      const alert = await alertService.updateAlert('test-tenant', 'test-alert-id', updateDto);

      expect(alert).toBeDefined();
      expect(alert?.status).toBe('acknowledged');
      expect(alert?.acknowledgedBy).toBe('user-123');
      expect(db.update).toHaveBeenCalled();
      expect(mockRedis.setex).toHaveBeenCalled();
    });

    it('should update alert status to resolved', async () => {
      const updateDto: UpdateAlertDTO = {
        status: 'resolved',
      };

      (db.update as jest.Mock).mockReturnValue({
        set: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            returning: jest.fn().mockResolvedValue([{
              id: 'test-alert-id',
              tenantId: 'test-tenant',
              alertType: 'system_offline',
              priority: 'high',
              sourceId: 'test-source',
              sourceType: 'system',
              message: 'Test alert',
              details: {},
              status: 'resolved',
              resolvedAt: new Date(),
              createdAt: new Date(),
              updatedAt: new Date(),
            }]),
          }),
        }),
      });

      const alert = await alertService.updateAlert('test-tenant', 'test-alert-id', updateDto);

      expect(alert).toBeDefined();
      expect(alert?.status).toBe('resolved');
      expect(db.update).toHaveBeenCalled();
    });

    it('should return null if alert not found', async () => {
      (db.update as jest.Mock).mockReturnValue({
        set: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            returning: jest.fn().mockResolvedValue([]),
          }),
        }),
      });

      const updateDto: UpdateAlertDTO = {
        status: 'resolved',
      };

      const alert = await alertService.updateAlert('test-tenant', 'non-existent', updateDto);

      expect(alert).toBeNull();
    });
  });

  describe('deleteAlert', () => {
    it('should delete alert successfully', async () => {
      (db.delete as jest.Mock).mockReturnValue({
        where: jest.fn().mockReturnValue({
          returning: jest.fn().mockResolvedValue([{
            id: 'test-alert-id',
            priority: 'high',
          }]),
        }),
      });

      const result = await alertService.deleteAlert('test-tenant', 'test-alert-id');

      expect(result).toBe(true);
      expect(db.delete).toHaveBeenCalled();
      expect(mockRedis.del).toHaveBeenCalledWith('alert:test-alert-id');
      expect(mockRedis.hincrby).toHaveBeenCalledWith('alert_stats:test-tenant', 'high', -1);
      expect(mockRedis.hincrby).toHaveBeenCalledWith('alert_stats:test-tenant', 'total', -1);
    });

    it('should return false if alert not found', async () => {
      (db.delete as jest.Mock).mockReturnValue({
        where: jest.fn().mockReturnValue({
          returning: jest.fn().mockResolvedValue([]),
        }),
      });

      const result = await alertService.deleteAlert('test-tenant', 'non-existent');

      expect(result).toBe(false);
      expect(mockRedis.del).not.toHaveBeenCalled();
    });
  });

  describe('getAlertStatistics', () => {
    it('should return alert statistics for specified timeframe', async () => {
      // Mock the count queries
      (db.select as jest.Mock)
        .mockReturnValueOnce({
          from: jest.fn().mockReturnValue({
            where: jest.fn().mockReturnValue({
              groupBy: jest.fn().mockResolvedValue([
                { status: 'open', count: '10' },
                { status: 'acknowledged', count: '5' },
                { status: 'resolved', count: '15' },
              ]),
            }),
          }),
        })
        .mockReturnValueOnce({
          from: jest.fn().mockReturnValue({
            where: jest.fn().mockReturnValue({
              groupBy: jest.fn().mockResolvedValue([
                { priority: 'low', count: '8' },
                { priority: 'medium', count: '12' },
                { priority: 'high', count: '7' },
                { priority: 'critical', count: '3' },
              ]),
            }),
          }),
        })
        .mockReturnValueOnce({
          from: jest.fn().mockReturnValue({
            where: jest.fn().mockReturnValue({
              groupBy: jest.fn().mockResolvedValue([
                { alertType: 'system_offline', count: '5' },
                { alertType: 'camera_offline', count: '10' },
                { alertType: 'motion_detected', count: '15' },
              ]),
            }),
          }),
        });

      const stats = await alertService.getAlertStatistics('test-tenant', '24h');

      expect(stats).toBeDefined();
      expect(stats.timeframe).toBe('24h');
      expect(stats.summary.total).toBe(30);
      expect(stats.summary.open).toBe(10);
      expect(stats.summary.acknowledged).toBe(5);
      expect(stats.summary.resolved).toBe(15);
      expect(stats.summary.critical).toBe(3);
      expect(stats.byPriority.low).toBe(8);
      expect(stats.byPriority.medium).toBe(12);
      expect(stats.byPriority.high).toBe(7);
      expect(stats.byPriority.critical).toBe(3);
      expect(stats.byType.system_offline).toBe(5);
      expect(stats.byType.camera_offline).toBe(10);
      expect(stats.byType.motion_detected).toBe(15);
    });
  });
});