import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { Hono } from 'hono';
import Redis from 'ioredis';
import { Server } from 'socket.io';
import { MaintenanceService } from '../index';
import { db } from '../db';
import { PreventiveMaintenanceService } from '../services/preventive-maintenance.service';
import { SLAMonitoringService } from '../services/sla-monitoring.service';
import { PredictiveMaintenanceService } from '../services/predictive-maintenance.service';
import { NotificationService } from '../services/notification.service';

// Mock dependencies
jest.mock('ioredis');
jest.mock('socket.io');
jest.mock('../db');
jest.mock('../services/preventive-maintenance.service');
jest.mock('../services/sla-monitoring.service');
jest.mock('../services/predictive-maintenance.service');
jest.mock('../services/notification.service');
jest.mock('@sparc/shared/telemetry', () => ({
  telemetry: {
    shutdown: jest.fn()
  }
}));

describe('MaintenanceService', () => {
  let service: MaintenanceService;
  let mockRedis: jest.Mocked<Redis>;
  let mockIo: jest.Mocked<Server>;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Setup Redis mock
    mockRedis = {
      on: jest.fn(),
      ping: jest.fn().mockResolvedValue('PONG'),
      quit: jest.fn().mockResolvedValue(undefined),
      subscribe: jest.fn().mockResolvedValue(undefined),
      publish: jest.fn().mockResolvedValue(1),
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue('OK'),
      del: jest.fn().mockResolvedValue(1),
      incr: jest.fn().mockResolvedValue(1),
      expire: jest.fn().mockResolvedValue(1)
    } as any;

    (Redis as jest.MockedClass<typeof Redis>).mockImplementation(() => mockRedis);

    // Setup Socket.IO mock
    mockIo = {
      on: jest.fn(),
      emit: jest.fn(),
      close: jest.fn(),
      engine: {
        clientsCount: 0
      }
    } as any;

    (Server as jest.MockedClass<typeof Server>).mockImplementation(() => mockIo);

    // Create service instance
    service = new MaintenanceService();
  });

  afterEach(async () => {
    // Cleanup
    await service.cleanup();
  });

  describe('initialization', () => {
    it('should initialize with correct service name and version', () => {
      expect(service.serviceName).toBe('maintenance-service');
      expect(service.version).toBe('1.0.0');
    });

    it('should initialize Redis clients', () => {
      expect(Redis).toHaveBeenCalledTimes(2); // Main Redis and subscriber
    });

    it('should setup Redis event handlers', () => {
      expect(mockRedis.on).toHaveBeenCalledWith('message', expect.any(Function));
    });
  });

  describe('setupRoutes', () => {
    let app: Hono;

    beforeEach(() => {
      app = new Hono();
      service.setupRoutes(app);
    });

    it('should register all route modules', () => {
      const routes = app.routes;
      const paths = routes.map(r => r.path);

      expect(paths).toContain('/work-orders/*');
      expect(paths).toContain('/preventive-maintenance/*');
      expect(paths).toContain('/inventory/*');
      expect(paths).toContain('/diagnostics/*');
      expect(paths).toContain('/analytics/*');
      expect(paths).toContain('/sla/*');
      expect(paths).toContain('/iot/*');
    });
  });

  describe('Socket.IO setup', () => {
    it('should create Socket.IO server on start', async () => {
      const server = { listen: jest.fn() } as any;
      await service.start(server);

      expect(Server).toHaveBeenCalledWith(server, expect.objectContaining({
        cors: {
          origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
          credentials: true
        }
      }));
    });

    it('should handle Socket.IO connections', async () => {
      const server = { listen: jest.fn() } as any;
      await service.start(server);

      const connectionHandler = (mockIo.on as jest.Mock).mock.calls.find(
        call => call[0] === 'connection'
      )?.[1];

      expect(connectionHandler).toBeDefined();

      // Test connection handling
      const mockSocket = {
        on: jest.fn(),
        join: jest.fn(),
        emit: jest.fn(),
        handshake: { auth: { tenantId: 'test-tenant' } }
      };

      await connectionHandler(mockSocket);

      expect(mockSocket.join).toHaveBeenCalledWith('tenant:test-tenant');
      expect(mockSocket.emit).toHaveBeenCalledWith('connected', { status: 'ok' });
    });
  });

  describe('background services', () => {
    it('should start all background services', async () => {
      const server = { listen: jest.fn() } as any;
      await service.start(server);

      expect(PreventiveMaintenanceService).toHaveBeenCalled();
      expect(SLAMonitoringService).toHaveBeenCalled();
      expect(PredictiveMaintenanceService).toHaveBeenCalled();
      expect(NotificationService).toHaveBeenCalled();

      const mockPreventive = (PreventiveMaintenanceService as jest.MockedClass<typeof PreventiveMaintenanceService>).mock.instances[0];
      const mockSLA = (SLAMonitoringService as jest.MockedClass<typeof SLAMonitoringService>).mock.instances[0];
      const mockPredictive = (PredictiveMaintenanceService as jest.MockedClass<typeof PredictiveMaintenanceService>).mock.instances[0];

      expect(mockPreventive.start).toHaveBeenCalled();
      expect(mockSLA.start).toHaveBeenCalled();
      expect(mockPredictive.start).toHaveBeenCalled();
    });

    it('should stop all background services on cleanup', async () => {
      const server = { listen: jest.fn() } as any;
      await service.start(server);
      await service.cleanup();

      const mockPreventive = (PreventiveMaintenanceService as jest.MockedClass<typeof PreventiveMaintenanceService>).mock.instances[0];
      const mockSLA = (SLAMonitoringService as jest.MockedClass<typeof SLAMonitoringService>).mock.instances[0];
      const mockPredictive = (PredictiveMaintenanceService as jest.MockedClass<typeof PredictiveMaintenanceService>).mock.instances[0];

      expect(mockPreventive.stop).toHaveBeenCalled();
      expect(mockSLA.stop).toHaveBeenCalled();
      expect(mockPredictive.stop).toHaveBeenCalled();
    });
  });

  describe('Redis pub/sub', () => {
    it('should subscribe to maintenance channels', async () => {
      expect(mockRedis.subscribe).toHaveBeenCalledWith(
        'maintenance:work-order:created',
        'maintenance:work-order:updated',
        'maintenance:work-order:completed',
        'maintenance:inventory:low-stock',
        'maintenance:sla:violation',
        'maintenance:predictive:alert'
      );
    });

    it('should handle work order created messages', async () => {
      const messageHandler = (mockRedis.on as jest.Mock).mock.calls.find(
        call => call[0] === 'message'
      )?.[1];

      const workOrder = { id: 'wo-123', tenantId: 'tenant-123' };
      await messageHandler('maintenance:work-order:created', JSON.stringify(workOrder));

      expect(mockIo.emit).toHaveBeenCalledWith('work-order:created', workOrder);
    });

    it('should handle Redis errors gracefully', () => {
      const errorHandler = (mockRedis.on as jest.Mock).mock.calls.find(
        call => call[0] === 'error'
      )?.[1];

      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      errorHandler(new Error('Redis connection failed'));

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Redis error:',
        expect.any(Error)
      );

      consoleErrorSpy.mockRestore();
    });
  });

  describe('health checks', () => {
    it('should perform custom health checks', async () => {
      const server = { listen: jest.fn() } as any;
      await service.start(server);

      const checks = await service.customHealthChecks();

      expect(checks).toHaveProperty('redis');
      expect(checks).toHaveProperty('database');
      expect(checks).toHaveProperty('backgroundServices');
      expect(checks).toHaveProperty('socketConnections');
    });

    it('should handle health check failures', async () => {
      mockRedis.ping.mockRejectedValueOnce(new Error('Connection failed'));

      const checks = await service.customHealthChecks();

      expect(checks.redis).toEqual({
        status: 'unhealthy',
        error: 'Connection failed'
      });
    });
  });

  describe('metrics', () => {
    it('should return service metrics', async () => {
      const server = { listen: jest.fn() } as any;
      await service.start(server);

      // Set up mock metrics
      mockRedis.get.mockImplementation((key: string) => {
        const metrics: Record<string, string> = {
          'metrics:work_orders:created': '100',
          'metrics:work_orders:completed': '80',
          'metrics:preventive:scheduled': '50',
          'metrics:predictive:alerts': '10',
          'metrics:sla:violations': '5'
        };
        return Promise.resolve(metrics[key] || '0');
      });

      const metrics = await service.getMetrics();

      expect(metrics).toHaveProperty('workOrders');
      expect(metrics).toHaveProperty('preventiveMaintenance');
      expect(metrics).toHaveProperty('predictiveMaintenance');
      expect(metrics).toHaveProperty('sla');
      expect(metrics).toHaveProperty('backgroundServices');
    });
  });

  describe('cleanup', () => {
    it('should cleanup all resources', async () => {
      const server = { listen: jest.fn() } as any;
      await service.start(server);
      await service.cleanup();

      expect(mockIo.close).toHaveBeenCalled();
      expect(mockRedis.quit).toHaveBeenCalled();
    });

    it('should handle cleanup errors gracefully', async () => {
      mockRedis.quit.mockRejectedValueOnce(new Error('Quit failed'));
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();

      await service.cleanup();

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Error during Redis cleanup:',
        expect.any(Error)
      );

      consoleErrorSpy.mockRestore();
    });
  });

  describe('message handling', () => {
    let messageHandler: (channel: string, message: string) => void;

    beforeEach(() => {
      messageHandler = (mockRedis.on as jest.Mock).mock.calls.find(
        call => call[0] === 'message'
      )?.[1];
    });

    it('should handle work order updated messages', async () => {
      const update = { id: 'wo-123', status: 'in_progress', tenantId: 'tenant-123' };
      await messageHandler('maintenance:work-order:updated', JSON.stringify(update));

      expect(mockIo.emit).toHaveBeenCalledWith('work-order:updated', update);
    });

    it('should handle inventory low stock alerts', async () => {
      const alert = { partId: 'part-123', quantity: 5, tenantId: 'tenant-123' };
      await messageHandler('maintenance:inventory:low-stock', JSON.stringify(alert));

      expect(mockIo.emit).toHaveBeenCalledWith('inventory:low-stock', alert);
    });

    it('should handle SLA violations', async () => {
      const violation = { workOrderId: 'wo-123', type: 'response', tenantId: 'tenant-123' };
      await messageHandler('maintenance:sla:violation', JSON.stringify(violation));

      expect(mockIo.emit).toHaveBeenCalledWith('sla:violation', violation);
    });

    it('should handle predictive maintenance alerts', async () => {
      const alert = { deviceId: 'device-123', riskLevel: 'high', tenantId: 'tenant-123' };
      await messageHandler('maintenance:predictive:alert', JSON.stringify(alert));

      expect(mockIo.emit).toHaveBeenCalledWith('predictive:alert', alert);
    });

    it('should handle invalid JSON messages', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      
      await messageHandler('maintenance:work-order:created', 'invalid-json');

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        'Failed to process Redis message:',
        expect.any(Error)
      );

      consoleErrorSpy.mockRestore();
    });
  });
});