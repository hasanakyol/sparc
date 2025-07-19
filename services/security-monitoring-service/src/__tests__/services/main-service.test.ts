import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SecurityMonitoringService } from '../../services/main-service';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

describe('SecurityMonitoringService', () => {
  let service: SecurityMonitoringService;
  let mockPrisma: any;
  let mockRedis: any;
  let mockPubSub: any;
  let mockConfig: any;

  beforeEach(() => {
    // Mock Prisma
    mockPrisma = {
      securityEvents: {
        create: vi.fn(),
        findMany: vi.fn(),
        count: vi.fn(),
        groupBy: vi.fn()
      },
      incidents: {
        create: vi.fn(),
        update: vi.fn(),
        findMany: vi.fn(),
        findUnique: vi.fn()
      },
      threats: {
        create: vi.fn(),
        findMany: vi.fn(),
        update: vi.fn()
      },
      $transaction: vi.fn()
    };

    // Mock Redis
    mockRedis = {
      get: vi.fn(),
      set: vi.fn(),
      del: vi.fn(),
      incr: vi.fn(),
      expire: vi.fn(),
      zadd: vi.fn(),
      zrange: vi.fn()
    };

    mockPubSub = {
      publish: vi.fn(),
      subscribe: vi.fn()
    };

    // Mock config
    mockConfig = {
      serviceName: 'security-monitoring-service',
      port: 3009,
      alertThresholds: {
        failedLogins: 5,
        suspiciousActivity: 3,
        highRiskEvents: 1
      },
      retentionDays: 90
    };

    service = new SecurityMonitoringService(mockPrisma, mockRedis, mockPubSub, mockConfig);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('processSecurityEvent', () => {
    it('should process and store security event', async () => {
      const event = {
        type: 'failed_login',
        severity: 'medium',
        userId: 'user-123',
        source: 'auth-service',
        details: { ip: '192.168.1.1' }
      };

      mockPrisma.securityEvents.create.mockResolvedValue({
        id: 'event-1',
        ...event,
        timestamp: new Date()
      });

      const result = await service.processSecurityEvent(event);

      expect(mockPrisma.securityEvents.create).toHaveBeenCalledWith({
        data: expect.objectContaining(event)
      });
      expect(result.id).toBe('event-1');
    });

    it('should trigger alert for high-risk events', async () => {
      const event = {
        type: 'privilege_escalation',
        severity: 'critical',
        userId: 'user-123',
        source: 'access-control'
      };

      await service.processSecurityEvent(event);

      expect(mockPubSub.publish).toHaveBeenCalledWith(
        'security-alerts',
        expect.stringContaining('critical')
      );
    });

    it('should track event patterns in Redis', async () => {
      const event = {
        type: 'failed_login',
        severity: 'low',
        userId: 'user-123',
        source: 'auth-service'
      };

      await service.processSecurityEvent(event);

      expect(mockRedis.incr).toHaveBeenCalledWith(
        expect.stringContaining('user-123:failed_login')
      );
      expect(mockRedis.expire).toHaveBeenCalled();
    });
  });

  describe('detectThreats', () => {
    it('should detect brute force attempts', async () => {
      mockRedis.get.mockResolvedValue('10'); // 10 failed logins

      const threat = await service.detectThreats('user-123', 'failed_login');

      expect(threat).toEqual({
        type: 'brute_force',
        severity: 'high',
        confidence: expect.any(Number),
        description: expect.stringContaining('brute force')
      });
    });

    it('should detect account takeover patterns', async () => {
      mockPrisma.securityEvents.findMany.mockResolvedValue([
        { type: 'login', details: { ip: '1.1.1.1', location: 'US' } },
        { type: 'login', details: { ip: '2.2.2.2', location: 'CN' } }
      ]);

      const threat = await service.detectThreats('user-123', 'suspicious_login');

      expect(threat).toEqual({
        type: 'account_takeover',
        severity: 'critical',
        confidence: expect.any(Number)
      });
    });

    it('should return null for no threats', async () => {
      mockRedis.get.mockResolvedValue('1');
      mockPrisma.securityEvents.findMany.mockResolvedValue([]);

      const threat = await service.detectThreats('user-123', 'normal_activity');

      expect(threat).toBeNull();
    });
  });

  describe('createIncident', () => {
    it('should create security incident', async () => {
      const incidentData = {
        title: 'Multiple Failed Login Attempts',
        description: 'User account under brute force attack',
        severity: 'high',
        affectedUsers: ['user-123'],
        source: 'threat-detection'
      };

      mockPrisma.incidents.create.mockResolvedValue({
        id: 'incident-1',
        ...incidentData,
        status: 'open',
        createdAt: new Date()
      });

      const result = await service.createIncident(incidentData);

      expect(mockPrisma.incidents.create).toHaveBeenCalled();
      expect(result.id).toBe('incident-1');
      expect(result.status).toBe('open');
    });

    it('should notify security team', async () => {
      await service.createIncident({
        title: 'Critical Security Event',
        severity: 'critical'
      });

      expect(mockPubSub.publish).toHaveBeenCalledWith(
        'security-incidents',
        expect.any(String)
      );
    });
  });

  describe('getSecurityMetrics', () => {
    it('should calculate security metrics', async () => {
      const mockData = {
        totalEvents: 1000,
        criticalEvents: 10,
        highEvents: 50,
        mediumEvents: 200,
        lowEvents: 740,
        incidents: 5,
        resolvedIncidents: 3
      };

      mockPrisma.securityEvents.count.mockImplementation(({ where }) => {
        if (where?.severity === 'critical') return mockData.criticalEvents;
        if (where?.severity === 'high') return mockData.highEvents;
        if (where?.severity === 'medium') return mockData.mediumEvents;
        if (where?.severity === 'low') return mockData.lowEvents;
        return mockData.totalEvents;
      });

      mockPrisma.incidents.count.mockImplementation(({ where }) => {
        if (where?.status === 'resolved') return mockData.resolvedIncidents;
        return mockData.incidents;
      });

      const metrics = await service.getSecurityMetrics();

      expect(metrics).toEqual({
        totalEvents: 1000,
        eventsBySeverity: {
          critical: 10,
          high: 50,
          medium: 200,
          low: 740
        },
        activeIncidents: 2,
        resolvedIncidents: 3,
        averageResolutionTime: expect.any(Number),
        riskScore: expect.any(Number)
      });
    });
  });

  describe('correlateEvents', () => {
    it('should correlate related security events', async () => {
      const events = [
        { id: '1', userId: 'user-123', type: 'failed_login', timestamp: new Date() },
        { id: '2', userId: 'user-123', type: 'password_reset', timestamp: new Date() },
        { id: '3', userId: 'user-123', type: 'successful_login', timestamp: new Date() }
      ];

      mockPrisma.securityEvents.findMany.mockResolvedValue(events);

      const correlation = await service.correlateEvents('user-123', 3600);

      expect(correlation).toEqual({
        userId: 'user-123',
        pattern: 'password_recovery_attack',
        events: events,
        confidence: expect.any(Number),
        recommendation: expect.any(String)
      });
    });
  });

  describe('generateComplianceReport', () => {
    it('should generate compliance report', async () => {
      mockPrisma.securityEvents.groupBy.mockResolvedValue([
        { type: 'access_granted', _count: 100 },
        { type: 'access_denied', _count: 20 }
      ]);

      const report = await service.generateComplianceReport('SOC2', {
        startDate: new Date('2024-01-01'),
        endDate: new Date('2024-01-31')
      });

      expect(report).toEqual({
        framework: 'SOC2',
        period: expect.any(Object),
        controls: expect.any(Array),
        findings: expect.any(Array),
        recommendations: expect.any(Array),
        complianceScore: expect.any(Number)
      });
    });
  });

  describe('realTimeAlerts', () => {
    it('should send real-time alerts for critical events', async () => {
      const criticalEvent = {
        type: 'data_breach',
        severity: 'critical',
        details: { affectedRecords: 1000 }
      };

      await service.processSecurityEvent(criticalEvent);

      expect(mockPubSub.publish).toHaveBeenCalledWith(
        'security-alerts:critical',
        expect.stringContaining('data_breach')
      );
    });

    it('should batch low-severity alerts', async () => {
      const lowEvent = {
        type: 'config_change',
        severity: 'low',
        details: { setting: 'timeout' }
      };

      await service.processSecurityEvent(lowEvent);

      // Should not immediately publish
      expect(mockPubSub.publish).not.toHaveBeenCalled();
    });
  });
});