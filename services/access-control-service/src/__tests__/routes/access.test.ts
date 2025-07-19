import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';
import request from 'supertest';
import { accessRoutes } from '../../routes/access';

// Mock the service
const mockAccessService = {
  checkAccess: vi.fn(),
  createAccessRule: vi.fn(),
  revokeAccess: vi.fn(),
  updateAccessRule: vi.fn(),
  getAccessRules: vi.fn(),
  getAccessHistory: vi.fn(),
  bulkCheckAccess: vi.fn()
};

describe('Access Routes', () => {
  let app: Hono;

  beforeEach(() => {
    vi.clearAllMocks();
    app = new Hono();
    app.route('/access', accessRoutes(mockAccessService));
  });

  describe('POST /access/check', () => {
    it('should check access and return allowed result', async () => {
      mockAccessService.checkAccess.mockResolvedValue({
        allowed: true,
        reason: 'User has permission'
      });

      const response = await request(app.fetch)
        .post('/access/check')
        .send({
          userId: 'user-123',
          resource: 'door-456',
          action: 'open'
        });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        allowed: true,
        reason: 'User has permission'
      });
    });

    it('should return 400 for invalid request', async () => {
      const response = await request(app.fetch)
        .post('/access/check')
        .send({
          userId: 'user-123'
          // Missing required fields
        });

      expect(response.status).toBe(400);
    });

    it('should handle service errors', async () => {
      mockAccessService.checkAccess.mockRejectedValue(new Error('Service error'));

      const response = await request(app.fetch)
        .post('/access/check')
        .send({
          userId: 'user-123',
          resource: 'door-456',
          action: 'open'
        });

      expect(response.status).toBe(500);
      expect(response.body).toEqual({
        error: 'Internal server error'
      });
    });
  });

  describe('POST /access/rules', () => {
    it('should create new access rule', async () => {
      const newRule = {
        id: 'rule-1',
        userId: 'user-123',
        resource: 'door-456',
        action: 'open',
        expiresAt: new Date().toISOString()
      };

      mockAccessService.createAccessRule.mockResolvedValue(newRule);

      const response = await request(app.fetch)
        .post('/access/rules')
        .send({
          userId: 'user-123',
          resource: 'door-456',
          action: 'open',
          expiresAt: newRule.expiresAt
        });

      expect(response.status).toBe(201);
      expect(response.body).toEqual(newRule);
    });

    it('should validate required fields', async () => {
      const response = await request(app.fetch)
        .post('/access/rules')
        .send({
          userId: 'user-123'
          // Missing resource and action
        });

      expect(response.status).toBe(400);
    });
  });

  describe('DELETE /access/rules/:id', () => {
    it('should revoke access rule', async () => {
      mockAccessService.revokeAccess.mockResolvedValue({ success: true });

      const response = await request(app.fetch)
        .delete('/access/rules/rule-123');

      expect(response.status).toBe(200);
      expect(mockAccessService.revokeAccess).toHaveBeenCalledWith('rule-123');
    });

    it('should handle non-existent rule', async () => {
      mockAccessService.revokeAccess.mockRejectedValue(new Error('Rule not found'));

      const response = await request(app.fetch)
        .delete('/access/rules/invalid-rule');

      expect(response.status).toBe(500);
    });
  });

  describe('GET /access/rules', () => {
    it('should return user access rules', async () => {
      const rules = [
        { id: 'rule-1', resource: 'door-1', action: 'open' },
        { id: 'rule-2', resource: 'door-2', action: 'open' }
      ];

      mockAccessService.getAccessRules.mockResolvedValue(rules);

      const response = await request(app.fetch)
        .get('/access/rules?userId=user-123');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(rules);
    });

    it('should require userId parameter', async () => {
      const response = await request(app.fetch)
        .get('/access/rules');

      expect(response.status).toBe(400);
    });
  });

  describe('GET /access/history', () => {
    it('should return access history', async () => {
      const history = [
        { id: 'log-1', resource: 'door-1', action: 'open', timestamp: new Date() },
        { id: 'log-2', resource: 'door-2', action: 'open', timestamp: new Date() }
      ];

      mockAccessService.getAccessHistory.mockResolvedValue(history);

      const response = await request(app.fetch)
        .get('/access/history?userId=user-123');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(history);
    });

    it('should support pagination', async () => {
      mockAccessService.getAccessHistory.mockResolvedValue([]);

      const response = await request(app.fetch)
        .get('/access/history?userId=user-123&limit=20&offset=40');

      expect(mockAccessService.getAccessHistory).toHaveBeenCalledWith('user-123', {
        limit: 20,
        offset: 40
      });
    });
  });

  describe('POST /access/bulk-check', () => {
    it('should check multiple access requests', async () => {
      const requests = [
        { userId: 'user-1', resource: 'door-1', action: 'open' },
        { userId: 'user-2', resource: 'door-2', action: 'open' }
      ];

      const results = [
        { ...requests[0], allowed: true },
        { ...requests[1], allowed: false }
      ];

      mockAccessService.bulkCheckAccess.mockResolvedValue(results);

      const response = await request(app.fetch)
        .post('/access/bulk-check')
        .send({ requests });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ results });
    });

    it('should validate request array', async () => {
      const response = await request(app.fetch)
        .post('/access/bulk-check')
        .send({ requests: 'not-an-array' });

      expect(response.status).toBe(400);
    });

    it('should limit bulk request size', async () => {
      const requests = Array(101).fill({
        userId: 'user-1',
        resource: 'door-1',
        action: 'open'
      });

      const response = await request(app.fetch)
        .post('/access/bulk-check')
        .send({ requests });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Too many requests');
    });
  });
});