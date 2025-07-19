import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import Bull from 'bull';
import Redis from 'ioredis';
import { ReportQueueService } from '../../services/report-queue-service';
import { ReportGeneratorService } from '../../services/report-generator-service';
import { ReportStorageService } from '../../services/report-storage-service';
import { ReportNotificationService } from '../../services/report-notification-service';
import { ReportRequest } from '../../types/schemas';

describe('ReportQueueService', () => {
  let queueService: ReportQueueService;
  let mockQueue: jest.Mocked<Bull.Queue>;
  let mockRedis: jest.Mocked<Redis>;
  let mockGeneratorService: jest.Mocked<ReportGeneratorService>;
  let mockStorageService: jest.Mocked<ReportStorageService>;
  let mockNotificationService: jest.Mocked<ReportNotificationService>;
  let mockConfig: any;

  beforeEach(() => {
    // Create mocks
    mockQueue = new Bull('test-queue') as jest.Mocked<Bull.Queue>;
    mockRedis = new Redis() as jest.Mocked<Redis>;
    mockConfig = global.testUtils.createMockConfig();
    
    mockGeneratorService = {
      generateReport: jest.fn().mockResolvedValue([{ id: '1', data: 'test' }]),
      formatReport: jest.fn().mockResolvedValue({
        data: Buffer.from('test report'),
        mimeType: 'application/pdf',
        filename: 'report.pdf',
        pageCount: 5
      })
    } as any;
    
    mockStorageService = {
      storeReport: jest.fn().mockResolvedValue({
        filename: 'report.pdf',
        size: 1024,
        mimeType: 'application/pdf',
        path: '/tmp/report.pdf',
        checksum: 'abc123'
      }),
      retrieveReport: jest.fn().mockResolvedValue(Buffer.from('test report')),
      getDownloadUrl: jest.fn().mockResolvedValue('https://example.com/report.pdf'),
      deleteReport: jest.fn().mockResolvedValue(true),
      getStorageStats: jest.fn().mockResolvedValue({
        usedBytes: 1048576,
        fileCount: 10
      })
    } as any;
    
    mockNotificationService = {
      sendReportCompletionNotification: jest.fn().mockResolvedValue(undefined),
      sendReportFailureNotification: jest.fn().mockResolvedValue(undefined)
    } as any;
    
    // Create service instance
    queueService = new ReportQueueService(
      mockQueue,
      mockGeneratorService,
      mockStorageService,
      mockNotificationService,
      mockRedis,
      mockConfig
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('initialize', () => {
    it('should set up queue processor and event handlers', async () => {
      await queueService.initialize();
      
      expect(mockQueue.process).toHaveBeenCalledWith(
        'generate-report',
        mockConfig.reportGeneration.maxConcurrent,
        expect.any(Function)
      );
      expect(mockQueue.on).toHaveBeenCalledWith('completed', expect.any(Function));
      expect(mockQueue.on).toHaveBeenCalledWith('failed', expect.any(Function));
      expect(mockQueue.on).toHaveBeenCalledWith('stalled', expect.any(Function));
    });
  });

  describe('queueReport', () => {
    it('should queue a report successfully', async () => {
      const request: ReportRequest & { tenantId: string; userId: string } = {
        type: 'access_events',
        format: 'pdf',
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        includeDetails: true,
        tenantId: 'tenant-123',
        userId: 'user-123',
        priority: 5
      };

      mockRedis.setex.mockResolvedValue('OK' as any);
      mockQueue.add.mockResolvedValue({ id: 'job-123' } as any);

      const reportId = await queueService.queueReport(request);

      expect(reportId).toMatch(/^rpt_/);
      expect(mockRedis.setex).toHaveBeenCalledWith(
        expect.stringMatching(/^report:rpt_/),
        86400,
        expect.stringContaining('"type":"access_events"')
      );
      expect(mockQueue.add).toHaveBeenCalledWith(
        'generate-report',
        expect.objectContaining({
          id: reportId,
          type: 'access_events',
          format: 'pdf',
          status: 'pending',
          tenantId: 'tenant-123',
          userId: 'user-123'
        }),
        expect.objectContaining({
          priority: 5,
          timeout: mockConfig.reportGeneration.timeoutMs,
          attempts: 3
        })
      );
    });

    it('should handle queue errors', async () => {
      const request: ReportRequest & { tenantId: string; userId: string } = {
        type: 'access_events',
        format: 'pdf',
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        includeDetails: true,
        tenantId: 'tenant-123',
        userId: 'user-123'
      };

      mockRedis.setex.mockRejectedValue(new Error('Redis error'));

      await expect(queueService.queueReport(request)).rejects.toThrow('Redis error');
    });
  });

  describe('getReportStatus', () => {
    it('should return report status for valid tenant', async () => {
      const reportData = {
        id: 'rpt_123',
        status: 'completed',
        tenantId: 'tenant-123',
        result: {
          filename: 'report.pdf',
          size: 1024
        }
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(reportData));

      const status = await queueService.getReportStatus('rpt_123', 'tenant-123');

      expect(status).toEqual(reportData);
      expect(mockRedis.get).toHaveBeenCalledWith('report:rpt_123');
    });

    it('should return null for non-existent report', async () => {
      mockRedis.get.mockResolvedValue(null);

      const status = await queueService.getReportStatus('rpt_123', 'tenant-123');

      expect(status).toBeNull();
    });

    it('should return null for wrong tenant', async () => {
      const reportData = {
        id: 'rpt_123',
        status: 'completed',
        tenantId: 'tenant-456'
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(reportData));

      const status = await queueService.getReportStatus('rpt_123', 'tenant-123');

      expect(status).toBeNull();
    });
  });

  describe('cancelReport', () => {
    it('should cancel a pending report', async () => {
      const reportData = {
        id: 'rpt_123',
        status: 'pending',
        tenantId: 'tenant-123'
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(reportData));
      mockRedis.setex.mockResolvedValue('OK' as any);
      mockQueue.getJobs.mockResolvedValue([
        { data: { id: 'rpt_123' }, remove: jest.fn() } as any
      ]);

      const cancelled = await queueService.cancelReport('rpt_123', 'tenant-123');

      expect(cancelled).toBe(true);
      expect(mockQueue.getJobs).toHaveBeenCalledWith(['waiting', 'active']);
    });

    it('should not cancel a completed report', async () => {
      const reportData = {
        id: 'rpt_123',
        status: 'completed',
        tenantId: 'tenant-123'
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(reportData));

      const cancelled = await queueService.cancelReport('rpt_123', 'tenant-123');

      expect(cancelled).toBe(false);
    });
  });

  describe('getQueueStats', () => {
    it('should return queue statistics', async () => {
      mockQueue.getWaitingCount.mockResolvedValue(5);
      mockQueue.getActiveCount.mockResolvedValue(2);
      mockQueue.getCompletedCount.mockResolvedValue(100);
      mockQueue.getFailedCount.mockResolvedValue(3);
      mockQueue.getDelayedCount.mockResolvedValue(1);

      const stats = await queueService.getQueueStats();

      expect(stats).toEqual({
        waiting: 5,
        active: 2,
        completed: 100,
        failed: 3,
        delayed: 1
      });
    });
  });

  describe('processReportJob', () => {
    it('should process a report job successfully', async () => {
      const job = {
        data: {
          id: 'rpt_123',
          type: 'access_events',
          format: 'pdf',
          status: 'processing',
          tenantId: 'tenant-123',
          userId: 'user-123',
          parameters: {
            startDate: new Date('2024-01-01'),
            endDate: new Date('2024-01-31'),
            includeDetails: true
          }
        },
        progress: jest.fn()
      };

      // Mock private method behavior
      mockRedis.get.mockResolvedValue(JSON.stringify(job.data));
      mockRedis.setex.mockResolvedValue('OK' as any);

      // Simulate job processing
      const processFunction = (mockQueue.process as jest.Mock).mock.calls[0]?.[1];
      if (processFunction) {
        await queueService.initialize();
        await processFunction(job);
      }

      expect(mockGeneratorService.generateReport).toHaveBeenCalled();
      expect(mockGeneratorService.formatReport).toHaveBeenCalled();
      expect(mockStorageService.storeReport).toHaveBeenCalled();
      expect(mockNotificationService.sendReportCompletionNotification).toHaveBeenCalled();
    });

    it('should handle job processing errors', async () => {
      const job = {
        data: {
          id: 'rpt_123',
          type: 'access_events',
          format: 'pdf',
          status: 'processing',
          tenantId: 'tenant-123',
          userId: 'user-123',
          parameters: {
            startDate: new Date('2024-01-01'),
            endDate: new Date('2024-01-31'),
            includeDetails: true
          }
        },
        progress: jest.fn()
      };

      mockGeneratorService.generateReport.mockRejectedValue(new Error('Generation failed'));
      mockRedis.get.mockResolvedValue(JSON.stringify(job.data));
      mockRedis.setex.mockResolvedValue('OK' as any);

      // Simulate job processing
      const processFunction = (mockQueue.process as jest.Mock).mock.calls[0]?.[1];
      if (processFunction) {
        await queueService.initialize();
        await expect(processFunction(job)).rejects.toThrow('Generation failed');
      }

      expect(mockNotificationService.sendReportFailureNotification).not.toHaveBeenCalled();
    });
  });
});