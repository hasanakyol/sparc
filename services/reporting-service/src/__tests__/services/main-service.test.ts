import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { ReportingService } from '../../services/main-service';
import { ReportingServiceConfig } from '../../config';

describe('ReportingService', () => {
  let service: ReportingService;
  let mockConfig: ReportingServiceConfig;

  beforeEach(() => {
    mockConfig = global.testUtils.createMockConfig();
    service = new ReportingService(mockConfig);
  });

  afterEach(async () => {
    await service.cleanup();
    jest.clearAllMocks();
  });

  describe('initialization', () => {
    it('should initialize successfully with valid config', async () => {
      await expect(service.initialize()).resolves.not.toThrow();
    });

    it('should verify email configuration when SMTP is configured', async () => {
      const emailTransporter = (service as any).emailTransporter;
      emailTransporter.verify = jest.fn().mockResolvedValue(true);

      await service.initialize();

      expect(emailTransporter.verify).toHaveBeenCalled();
    });

    it('should handle email verification failure gracefully', async () => {
      const emailTransporter = (service as any).emailTransporter;
      emailTransporter.verify = jest.fn().mockRejectedValue(new Error('SMTP error'));

      await expect(service.initialize()).resolves.not.toThrow();
    });
  });

  describe('customHealthChecks', () => {
    it('should perform custom health checks', async () => {
      await service.initialize();

      const emailTransporter = (service as any).emailTransporter;
      const reportQueue = (service as any).reportQueue;
      const storageService = (service as any).storageService;

      emailTransporter.verify = jest.fn().mockResolvedValue(true);
      reportQueue.isReady = jest.fn().mockResolvedValue(true);
      storageService.healthCheck = jest.fn().mockResolvedValue(true);

      const checks = await service['customHealthChecks']();

      expect(checks).toEqual({
        email: true,
        queue: true,
        storage: true
      });
    });

    it('should handle health check failures', async () => {
      await service.initialize();

      const emailTransporter = (service as any).emailTransporter;
      const reportQueue = (service as any).reportQueue;
      const storageService = (service as any).storageService;

      emailTransporter.verify = jest.fn().mockRejectedValue(new Error('SMTP down'));
      reportQueue.isReady = jest.fn().mockResolvedValue(false);
      storageService.healthCheck = jest.fn().mockResolvedValue(false);

      const checks = await service['customHealthChecks']();

      expect(checks).toEqual({
        email: false,
        queue: false,
        storage: false
      });
    });
  });

  describe('getMetrics', () => {
    it('should return formatted metrics', async () => {
      await service.initialize();

      const queueService = (service as any).queueService;
      const storageService = (service as any).storageService;

      queueService.getQueueStats = jest.fn().mockResolvedValue({
        waiting: 5,
        active: 2,
        completed: 100,
        failed: 3
      });

      storageService.getStorageStats = jest.fn().mockResolvedValue({
        usedBytes: 1048576,
        fileCount: 25
      });

      const metrics = await service['getMetrics']();

      expect(metrics).toContain('report_queue_waiting 5');
      expect(metrics).toContain('report_queue_active 2');
      expect(metrics).toContain('report_queue_completed 100');
      expect(metrics).toContain('report_queue_failed 3');
      expect(metrics).toContain('report_storage_used_bytes 1048576');
      expect(metrics).toContain('report_storage_file_count 25');
    });
  });

  describe('setupRoutes', () => {
    it('should set up all routes', () => {
      const routeSpy = jest.spyOn(service['app'], 'route');
      
      service.setupRoutes();

      expect(routeSpy).toHaveBeenCalledWith('/api/reports', expect.any(Object));
      expect(routeSpy).toHaveBeenCalledWith('/api/dashboard', expect.any(Object));
      expect(routeSpy).toHaveBeenCalledWith('/api/compliance', expect.any(Object));
      expect(routeSpy).toHaveBeenCalledWith('/api/scheduled', expect.any(Object));
      expect(routeSpy).toHaveBeenCalledWith('/api/templates', expect.any(Object));
    });

    it('should set up API documentation endpoint', () => {
      const getSpy = jest.spyOn(service['app'], 'get');
      
      service.setupRoutes();

      expect(getSpy).toHaveBeenCalledWith('/api/docs', expect.any(Function));
    });
  });

  describe('cleanup', () => {
    it('should clean up resources properly', async () => {
      await service.initialize();

      const reportQueue = (service as any).reportQueue;
      const scheduledReportService = (service as any).scheduledReportService;
      const emailTransporter = (service as any).emailTransporter;

      reportQueue.close = jest.fn().mockResolvedValue(undefined);
      scheduledReportService.shutdown = jest.fn().mockResolvedValue(undefined);
      emailTransporter.close = jest.fn();

      await service['cleanup']();

      expect(reportQueue.close).toHaveBeenCalled();
      expect(scheduledReportService.shutdown).toHaveBeenCalled();
      expect(emailTransporter.close).toHaveBeenCalled();
    });
  });

  describe('configuration validation', () => {
    it('should throw error for missing required config', () => {
      const invalidConfig = { ...mockConfig };
      delete (invalidConfig as any).jwtSecret;

      expect(() => new ReportingService(invalidConfig as any)).toThrow();
    });

    it('should validate SMTP configuration when provided', () => {
      const invalidConfig = { ...mockConfig };
      invalidConfig.smtp = {
        host: 'smtp.test.com',
        port: 587,
        user: '',
        pass: '',
        from: 'test@test.com'
      };

      expect(() => new ReportingService(invalidConfig)).toThrow('SMTP configuration incomplete');
    });

    it('should validate S3 configuration when provided', () => {
      const invalidConfig = { ...mockConfig };
      invalidConfig.storage.s3 = {
        bucket: '',
        region: 'us-east-1'
      };

      expect(() => new ReportingService(invalidConfig)).toThrow('S3 configuration incomplete');
    });
  });

  describe('integration', () => {
    it('should handle concurrent operations', async () => {
      await service.initialize();

      const operations = [];
      
      // Simulate concurrent health checks and metrics
      for (let i = 0; i < 10; i++) {
        operations.push(service['customHealthChecks']());
        operations.push(service['getMetrics']());
      }

      await expect(Promise.all(operations)).resolves.not.toThrow();
    });
  });
});