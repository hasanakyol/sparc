import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { Hono } from 'hono';
import alertsRouter from '../alerts';
import { AlertService } from '../../services/alert.service';
import type { Alert } from '@sparc/shared/types/alerts';

// Mock dependencies
jest.mock('../../services/alert.service');
jest.mock('ioredis', () => ({
  default: jest.fn().mockImplementation(() => ({
    publish: jest.fn(),
  })),
}));

// Mock auth middleware
jest.mock('@sparc/shared/middleware/auth', () => ({
  authMiddleware: jest.fn((c, next) => {
    c.set('tenantId', 'test-tenant');
    c.set('userId', 'test-user');
    return next();
  }),
}));

const mockAlert: Alert = {
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
};

describe('Alerts Routes', () => {
  let app: Hono;
  let mockAlertService: jest.Mocked<AlertService>;

  beforeEach(() => {
    jest.clearAllMocks();
    app = new Hono();
    app.route('/api/alerts', alertsRouter);

    // Setup alert service mock
    mockAlertService = {
      createAlert: jest.fn().mockResolvedValue(mockAlert),
      getAlert: jest.fn().mockResolvedValue(mockAlert),
      listAlerts: jest.fn().mockResolvedValue({
        alerts: [mockAlert],
        pagination: {
          page: 1,
          limit: 50,
          total: 1,
          pages: 1,
        },
      }),
      updateAlert: jest.fn().mockResolvedValue(mockAlert),
      acknowledgeAlert: jest.fn().mockResolvedValue({
        ...mockAlert,
        status: 'acknowledged',
        acknowledgedBy: 'test-user',
      }),
      deleteAlert: jest.fn().mockResolvedValue(true),
      getAlertStatistics: jest.fn().mockResolvedValue({
        timeframe: '24h',
        summary: {
          total: 100,
          open: 20,
          acknowledged: 30,
          resolved: 50,
          critical: 5,
        },
        byType: { system_offline: 10 },
        byPriority: { high: 25 },
      }),
    } as any;

    (AlertService as jest.MockedClass<typeof AlertService>).mockImplementation(() => mockAlertService);
  });

  describe('GET /api/alerts', () => {
    it('should list alerts with default pagination', async () => {
      const res = await app.request('/api/alerts', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.alerts).toHaveLength(1);
      expect(data.pagination.page).toBe(1);
      expect(data.pagination.limit).toBe(50);
      expect(mockAlertService.listAlerts).toHaveBeenCalledWith('test-tenant', {
        page: 1,
        limit: 50,
        status: undefined,
        priority: undefined,
        alertType: undefined,
        sourceType: undefined,
        startDate: undefined,
        endDate: undefined,
      });
    });

    it('should list alerts with filters', async () => {
      const res = await app.request('/api/alerts?status=open&priority=high&page=2&limit=20', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(200);
      expect(mockAlertService.listAlerts).toHaveBeenCalledWith('test-tenant', {
        page: 2,
        limit: 20,
        status: 'open',
        priority: 'high',
        alertType: undefined,
        sourceType: undefined,
        startDate: undefined,
        endDate: undefined,
      });
    });

    it('should handle service errors', async () => {
      mockAlertService.listAlerts.mockRejectedValue(new Error('Database error'));

      const res = await app.request('/api/alerts', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(500);
      const data = await res.json();
      expect(data.message).toBe('Failed to fetch alerts');
    });
  });

  describe('GET /api/alerts/stats', () => {
    it('should return alert statistics', async () => {
      const res = await app.request('/api/alerts/stats?timeframe=7d', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.timeframe).toBe('24h'); // Mocked value
      expect(data.summary.total).toBe(100);
      expect(mockAlertService.getAlertStatistics).toHaveBeenCalledWith('test-tenant', '7d');
    });

    it('should use default timeframe', async () => {
      const res = await app.request('/api/alerts/stats', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(200);
      expect(mockAlertService.getAlertStatistics).toHaveBeenCalledWith('test-tenant', '24h');
    });
  });

  describe('GET /api/alerts/:id', () => {
    it('should return a single alert', async () => {
      const res = await app.request('/api/alerts/test-alert-id', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.alert.id).toBe('test-alert-id');
      expect(mockAlertService.getAlert).toHaveBeenCalledWith('test-tenant', 'test-alert-id');
    });

    it('should return 404 for non-existent alert', async () => {
      mockAlertService.getAlert.mockResolvedValue(null);

      const res = await app.request('/api/alerts/non-existent', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(404);
      const data = await res.json();
      expect(data.message).toBe('Alert not found');
    });
  });

  describe('POST /api/alerts', () => {
    it('should create a new alert', async () => {
      const createData = {
        alertType: 'system_offline',
        priority: 'high',
        sourceId: 'test-source',
        sourceType: 'system',
        message: 'System is offline',
        details: { reason: 'Network failure' },
      };

      const res = await app.request('/api/alerts', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(createData),
      });

      expect(res.status).toBe(201);
      const data = await res.json();
      expect(data.alert.id).toBe('test-alert-id');
      expect(mockAlertService.createAlert).toHaveBeenCalledWith('test-tenant', createData);
    });

    it('should validate request body', async () => {
      const invalidData = {
        alertType: 'invalid_type',
        priority: 'invalid_priority',
        // missing required fields
      };

      const res = await app.request('/api/alerts', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(invalidData),
      });

      expect(res.status).toBe(400);
    });
  });

  describe('PUT /api/alerts/:id', () => {
    it('should update an alert', async () => {
      const updateData = {
        status: 'resolved',
        message: 'Issue resolved',
      };

      const res = await app.request('/api/alerts/test-alert-id', {
        method: 'PUT',
        headers: {
          Authorization: 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(updateData),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.alert.id).toBe('test-alert-id');
      expect(mockAlertService.updateAlert).toHaveBeenCalledWith(
        'test-tenant',
        'test-alert-id',
        updateData
      );
    });

    it('should return 404 for non-existent alert', async () => {
      mockAlertService.updateAlert.mockResolvedValue(null);

      const res = await app.request('/api/alerts/non-existent', {
        method: 'PUT',
        headers: {
          Authorization: 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ status: 'resolved' }),
      });

      expect(res.status).toBe(404);
    });
  });

  describe('POST /api/alerts/:id/acknowledge', () => {
    it('should acknowledge an alert', async () => {
      const res = await app.request('/api/alerts/test-alert-id/acknowledge', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ acknowledgedBy: 'test-user' }),
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.alert.status).toBe('acknowledged');
      expect(mockAlertService.acknowledgeAlert).toHaveBeenCalledWith(
        'test-tenant',
        'test-alert-id',
        'test-user'
      );
    });

    it('should validate acknowledgedBy field', async () => {
      const res = await app.request('/api/alerts/test-alert-id/acknowledge', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });

      expect(res.status).toBe(400);
    });
  });

  describe('DELETE /api/alerts/:id', () => {
    it('should delete an alert', async () => {
      const res = await app.request('/api/alerts/test-alert-id', {
        method: 'DELETE',
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.message).toBe('Alert deleted successfully');
      expect(mockAlertService.deleteAlert).toHaveBeenCalledWith('test-tenant', 'test-alert-id');
    });

    it('should return 404 for non-existent alert', async () => {
      mockAlertService.deleteAlert.mockResolvedValue(false);

      const res = await app.request('/api/alerts/non-existent', {
        method: 'DELETE',
        headers: {
          Authorization: 'Bearer test-token',
        },
      });

      expect(res.status).toBe(404);
    });
  });

  describe('Authentication', () => {
    it('should require authentication for all endpoints', async () => {
      // Mock auth middleware to reject
      jest.isolateModules(() => {
        jest.doMock('@sparc/shared/middleware/auth', () => ({
          authMiddleware: jest.fn(() => {
            throw new Error('Unauthorized');
          }),
        }));
      });

      const res = await app.request('/api/alerts', {
        // No auth header
      });

      expect(res.status).toBe(500); // Auth middleware throws error
    });
  });
});