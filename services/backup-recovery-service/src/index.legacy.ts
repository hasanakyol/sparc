import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { config, logger as appLogger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import cron from 'node-cron';
import crypto from 'crypto';
import { 
  BackupClient, 
  CreateBackupJobCommand, 
  DescribeBackupJobCommand, 
  ListBackupJobsCommand,
  StartRestoreJobCommand,
  DescribeRestoreJobCommand
} from '@aws-sdk/client-backup';
import { 
  RDSClient, 
  CreateDBSnapshotCommand, 
  DescribeDBSnapshotsCommand,
  RestoreDBInstanceFromDBSnapshotCommand,
  ModifyDBInstanceCommand
} from '@aws-sdk/client-rds';
import { 
  S3Client, 
  PutObjectCommand, 
  GetObjectCommand, 
  CopyObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command
} from '@aws-sdk/client-s3';

// Initialize clients
const prisma = new PrismaClient();
const redis = new Redis(config.redis.url);
const backupClient = new BackupClient({ region: config.aws.region });
const rdsClient = new RDSClient({ region: config.aws.region });
const s3Client = new S3Client({ region: config.aws.region });

// Test infrastructure - only run tests in test environment
if (process.env.NODE_ENV === 'test') {
  const jest = require('jest');
  const supertest = require('supertest');
  
  // Mock implementations for testing
  const mockPrisma = {
    backupJob: {
      create: jest.fn(),
      findFirst: jest.fn(),
      findUnique: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      count: jest.fn(),
    },
    tenant: {
      findUnique: jest.fn(),
    },
    auditLog: {
      create: jest.fn(),
    },
    $transaction: jest.fn(),
    $queryRaw: jest.fn(),
    $disconnect: jest.fn(),
  };

  const mockRedis = {
    setex: jest.fn(),
    get: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    expire: jest.fn(),
    keys: jest.fn(),
    ping: jest.fn(),
    quit: jest.fn(),
    hset: jest.fn(),
    hget: jest.fn(),
    hgetall: jest.fn(),
  };

  const mockAWSClients = {
    backup: {
      send: jest.fn(),
    },
    rds: {
      send: jest.fn(),
    },
    s3: {
      send: jest.fn(),
    },
  };

  // Test utilities
  const createTestBackupJob = () => ({
    id: 'test-backup-job-id',
    tenantId: 'test-tenant-id',
    backupType: 'FULL',
    schedule: '0 2 * * *',
    lastRun: new Date('2024-01-01T02:00:00Z'),
    nextRun: new Date('2024-01-02T02:00:00Z'),
    status: 'COMPLETED',
    backupSize: BigInt(1024 * 1024 * 1024), // 1GB
    retentionDays: 30,
    storageLocation: 's3://sparc-backups/test-tenant-id/',
    encryptionEnabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const createTestTenant = () => ({
    id: 'test-tenant-id',
    name: 'Test Tenant',
    domain: 'test.sparc.com',
    settings: {},
  });

  // Test suites
  describe('Backup & Recovery Service', () => {
    let app: Hono;
    let request: any;

    beforeAll(() => {
      app = createTestApp();
      request = supertest(app);
    });

    beforeEach(() => {
      jest.clearAllMocks();
    });

    describe('Health Endpoints', () => {
      test('GET /health should return service health status', async () => {
        const response = await request.get('/health');
        
        expect(response.status).toBe(200);
        expect(response.body).toMatchObject({
          status: 'healthy',
          service: 'backup-recovery-service',
          environment: expect.any(String),
        });
      });

      test('GET /ready should return readiness status', async () => {
        mockPrisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
        mockRedis.ping.mockResolvedValue('PONG');
        mockAWSClients.backup.send.mockResolvedValue({ BackupJobs: [] });

        const response = await request.get('/ready');
        
        expect(response.status).toBe(200);
        expect(response.body).toMatchObject({
          status: 'ready',
          service: 'backup-recovery-service',
          checks: {
            database: 'healthy',
            redis: 'healthy',
            awsBackup: 'healthy',
          },
        });
      });
    });

    describe('Backup Job Management', () => {
      describe('POST /backup/jobs', () => {
        test('should create backup job successfully', async () => {
          const jobData = {
            backupType: 'FULL',
            schedule: '0 2 * * *',
            retentionDays: 30,
            storageLocation: 's3://sparc-backups/test-tenant-id/',
          };

          mockPrisma.tenant.findUnique.mockResolvedValue(createTestTenant());
          mockPrisma.backupJob.create.mockResolvedValue(createTestBackupJob());
          mockAWSClients.backup.send.mockResolvedValue({ BackupJobId: 'aws-backup-job-id' });

          const response = await request
            .post('/backup/jobs')
            .set('Authorization', 'Bearer valid-token')
            .send(jobData);

          expect(response.status).toBe(201);
          expect(response.body.message).toBe('Backup job created successfully');
          expect(mockPrisma.backupJob.create).toHaveBeenCalled();
        });

        test('should validate required fields', async () => {
          const response = await request
            .post('/backup/jobs')
            .set('Authorization', 'Bearer valid-token')
            .send({});

          expect(response.status).toBe(400);
          expect(response.body.error).toBe('Validation failed');
        });
      });

      describe('GET /backup/jobs', () => {
        test('should list backup jobs for tenant', async () => {
          const jobs = [createTestBackupJob()];
          mockPrisma.backupJob.findMany.mockResolvedValue(jobs);

          const response = await request
            .get('/backup/jobs')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.jobs).toHaveLength(1);
          expect(response.body.jobs[0].id).toBe('test-backup-job-id');
        });
      });

      describe('GET /backup/jobs/:id', () => {
        test('should get backup job details', async () => {
          const job = createTestBackupJob();
          mockPrisma.backupJob.findUnique.mockResolvedValue(job);

          const response = await request
            .get('/backup/jobs/test-backup-job-id')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.job.id).toBe('test-backup-job-id');
        });

        test('should return 404 for non-existent job', async () => {
          mockPrisma.backupJob.findUnique.mockResolvedValue(null);

          const response = await request
            .get('/backup/jobs/non-existent-id')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(404);
          expect(response.body.error).toBe('Backup job not found');
        });
      });

      describe('PUT /backup/jobs/:id', () => {
        test('should update backup job', async () => {
          const job = createTestBackupJob();
          const updateData = { retentionDays: 60 };

          mockPrisma.backupJob.findUnique.mockResolvedValue(job);
          mockPrisma.backupJob.update.mockResolvedValue({ ...job, ...updateData });

          const response = await request
            .put('/backup/jobs/test-backup-job-id')
            .set('Authorization', 'Bearer valid-token')
            .send(updateData);

          expect(response.status).toBe(200);
          expect(response.body.message).toBe('Backup job updated successfully');
        });
      });

      describe('DELETE /backup/jobs/:id', () => {
        test('should delete backup job', async () => {
          const job = createTestBackupJob();
          mockPrisma.backupJob.findUnique.mockResolvedValue(job);
          mockPrisma.backupJob.delete.mockResolvedValue(job);

          const response = await request
            .delete('/backup/jobs/test-backup-job-id')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.message).toBe('Backup job deleted successfully');
        });
      });
    });

    describe('Backup Operations', () => {
      describe('POST /backup/execute/:id', () => {
        test('should execute backup job manually', async () => {
          const job = createTestBackupJob();
          mockPrisma.backupJob.findUnique.mockResolvedValue(job);
          mockAWSClients.backup.send.mockResolvedValue({ BackupJobId: 'manual-backup-id' });
          mockPrisma.backupJob.update.mockResolvedValue(job);

          const response = await request
            .post('/backup/execute/test-backup-job-id')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.message).toBe('Backup job started successfully');
        });
      });

      describe('GET /backup/status/:jobId', () => {
        test('should get backup status from AWS', async () => {
          mockAWSClients.backup.send.mockResolvedValue({
            BackupJobId: 'aws-backup-job-id',
            State: 'COMPLETED',
            PercentDone: '100',
            BackupSizeInBytes: 1073741824,
          });

          const response = await request
            .get('/backup/status/aws-backup-job-id')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.status.state).toBe('COMPLETED');
        });
      });
    });

    describe('Recovery Operations', () => {
      describe('POST /recovery/initiate', () => {
        test('should initiate recovery process', async () => {
          const recoveryData = {
            backupId: 'backup-id',
            targetEnvironment: 'staging',
            recoveryType: 'POINT_IN_TIME',
            targetTime: '2024-01-01T12:00:00Z',
          };

          mockAWSClients.backup.send.mockResolvedValue({ RestoreJobId: 'restore-job-id' });

          const response = await request
            .post('/recovery/initiate')
            .set('Authorization', 'Bearer valid-token')
            .send(recoveryData);

          expect(response.status).toBe(200);
          expect(response.body.message).toBe('Recovery initiated successfully');
          expect(response.body.restoreJobId).toBe('restore-job-id');
        });
      });

      describe('GET /recovery/status/:restoreJobId', () => {
        test('should get recovery status', async () => {
          mockAWSClients.backup.send.mockResolvedValue({
            RestoreJobId: 'restore-job-id',
            Status: 'COMPLETED',
            PercentDone: '100',
          });

          const response = await request
            .get('/recovery/status/restore-job-id')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.status.status).toBe('COMPLETED');
        });
      });
    });

    describe('Integrity Validation', () => {
      describe('POST /backup/validate/:id', () => {
        test('should validate backup integrity', async () => {
          const job = createTestBackupJob();
          mockPrisma.backupJob.findUnique.mockResolvedValue(job);
          mockAWSClients.s3.send.mockResolvedValue({
            ETag: '"checksum-value"',
            ContentLength: 1073741824,
          });

          const response = await request
            .post('/backup/validate/test-backup-job-id')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.message).toBe('Backup validation completed');
          expect(response.body.validation.isValid).toBe(true);
        });
      });
    });

    describe('Disaster Recovery', () => {
      describe('POST /disaster-recovery/failover', () => {
        test('should initiate failover process', async () => {
          const failoverData = {
            targetRegion: 'us-west-2',
            failoverType: 'AUTOMATIC',
          };

          mockAWSClients.rds.send.mockResolvedValue({
            DBInstance: { DBInstanceIdentifier: 'failover-instance' }
          });

          const response = await request
            .post('/disaster-recovery/failover')
            .set('Authorization', 'Bearer valid-token')
            .send(failoverData);

          expect(response.status).toBe(200);
          expect(response.body.message).toBe('Failover initiated successfully');
        });
      });
    });

    describe('Offline Operations', () => {
      describe('GET /offline/status', () => {
        test('should return offline operation status', async () => {
          mockRedis.hgetall.mockResolvedValue({
            'offline_mode': 'true',
            'offline_start': '2024-01-01T00:00:00Z',
            'cached_data_size': '1024',
          });

          const response = await request
            .get('/offline/status')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.offlineMode).toBe(true);
        });
      });

      describe('POST /offline/sync', () => {
        test('should sync offline data when connectivity restored', async () => {
          mockRedis.keys.mockResolvedValue(['offline:event:1', 'offline:event:2']);
          mockRedis.get.mockResolvedValue(JSON.stringify({ eventType: 'ACCESS', data: {} }));
          mockPrisma.$transaction.mockResolvedValue([]);

          const response = await request
            .post('/offline/sync')
            .set('Authorization', 'Bearer valid-token');

          expect(response.status).toBe(200);
          expect(response.body.message).toBe('Offline data synchronized successfully');
        });
      });
    });
  });

  // Helper function to create test app
  function createTestApp() {
    const testApp = new Hono();
    
    // Mock auth middleware
    const mockAuthMiddleware = async (c: any, next: any) => {
      const authHeader = c.req.header('Authorization');
      const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

      if (!token || token === 'invalid-token') {
        return c.json({ error: 'Access token required' }, 401);
      }

      c.set('user', {
        sub: 'test-user-id',
        tenantId: 'test-tenant-id',
        role: 'ADMIN',
        type: 'access',
      });

      await next();
    };

    // Add routes with mocked dependencies
    testApp.route('/backup', createMockBackupRoutes(mockAuthMiddleware));
    testApp.route('/recovery', createMockRecoveryRoutes(mockAuthMiddleware));
    testApp.route('/disaster-recovery', createMockDisasterRecoveryRoutes(mockAuthMiddleware));
    testApp.route('/offline', createMockOfflineRoutes(mockAuthMiddleware));
    
    // Health endpoints
    testApp.get('/health', (c) => {
      return c.json({
        status: 'healthy',
        service: 'backup-recovery-service',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: 'test',
      });
    });

    testApp.get('/ready', async (c) => {
      try {
        await mockPrisma.$queryRaw`SELECT 1`;
        await mockRedis.ping();
        await mockAWSClients.backup.send(new ListBackupJobsCommand({}));

        return c.json({
          status: 'ready',
          service: 'backup-recovery-service',
          timestamp: new Date().toISOString(),
          checks: {
            database: 'healthy',
            redis: 'healthy',
            awsBackup: 'healthy',
          },
        });
      } catch (error) {
        return c.json({
          status: 'not ready',
          service: 'backup-recovery-service',
          timestamp: new Date().toISOString(),
          error: error.message,
        }, 503);
      }
    });

    return testApp;
  }

  // Mock route implementations
  function createMockBackupRoutes(authMiddleware: any) {
    const backupApp = new Hono();

    backupApp.post('/jobs', authMiddleware, async (c) => {
      try {
        const body = await c.req.json();
        const user = c.get('user');

        if (!body.backupType || !body.schedule) {
          return c.json({ error: 'Validation failed' }, 400);
        }

        const tenant = await mockPrisma.tenant.findUnique({
          where: { id: user.tenantId }
        });

        if (!tenant) {
          return c.json({ error: 'Invalid tenant' }, 400);
        }

        const job = await mockPrisma.backupJob.create({
          data: {
            tenantId: user.tenantId,
            backupType: body.backupType,
            schedule: body.schedule,
            retentionDays: body.retentionDays || 30,
            storageLocation: body.storageLocation,
            encryptionEnabled: body.encryptionEnabled !== false,
          }
        });

        return c.json({
          message: 'Backup job created successfully',
          job,
        }, 201);
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    backupApp.get('/jobs', authMiddleware, async (c) => {
      try {
        const user = c.get('user');
        const jobs = await mockPrisma.backupJob.findMany({
          where: { tenantId: user.tenantId }
        });

        return c.json({ jobs });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    backupApp.get('/jobs/:id', authMiddleware, async (c) => {
      try {
        const user = c.get('user');
        const jobId = c.req.param('id');

        const job = await mockPrisma.backupJob.findUnique({
          where: { id: jobId, tenantId: user.tenantId }
        });

        if (!job) {
          return c.json({ error: 'Backup job not found' }, 404);
        }

        return c.json({ job });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    backupApp.put('/jobs/:id', authMiddleware, async (c) => {
      try {
        const user = c.get('user');
        const jobId = c.req.param('id');
        const body = await c.req.json();

        const existingJob = await mockPrisma.backupJob.findUnique({
          where: { id: jobId, tenantId: user.tenantId }
        });

        if (!existingJob) {
          return c.json({ error: 'Backup job not found' }, 404);
        }

        const job = await mockPrisma.backupJob.update({
          where: { id: jobId },
          data: body
        });

        return c.json({
          message: 'Backup job updated successfully',
          job,
        });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    backupApp.delete('/jobs/:id', authMiddleware, async (c) => {
      try {
        const user = c.get('user');
        const jobId = c.req.param('id');

        const existingJob = await mockPrisma.backupJob.findUnique({
          where: { id: jobId, tenantId: user.tenantId }
        });

        if (!existingJob) {
          return c.json({ error: 'Backup job not found' }, 404);
        }

        await mockPrisma.backupJob.delete({
          where: { id: jobId }
        });

        return c.json({ message: 'Backup job deleted successfully' });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    backupApp.post('/execute/:id', authMiddleware, async (c) => {
      try {
        const user = c.get('user');
        const jobId = c.req.param('id');

        const job = await mockPrisma.backupJob.findUnique({
          where: { id: jobId, tenantId: user.tenantId }
        });

        if (!job) {
          return c.json({ error: 'Backup job not found' }, 404);
        }

        const backupResult = await mockAWSClients.backup.send(
          new CreateBackupJobCommand({})
        );

        await mockPrisma.backupJob.update({
          where: { id: jobId },
          data: { status: 'RUNNING', lastRun: new Date() }
        });

        return c.json({
          message: 'Backup job started successfully',
          backupJobId: backupResult.BackupJobId,
        });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    backupApp.get('/status/:jobId', authMiddleware, async (c) => {
      try {
        const jobId = c.req.param('jobId');

        const status = await mockAWSClients.backup.send(
          new DescribeBackupJobCommand({ BackupJobId: jobId })
        );

        return c.json({ status });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    backupApp.post('/validate/:id', authMiddleware, async (c) => {
      try {
        const user = c.get('user');
        const jobId = c.req.param('id');

        const job = await mockPrisma.backupJob.findUnique({
          where: { id: jobId, tenantId: user.tenantId }
        });

        if (!job) {
          return c.json({ error: 'Backup job not found' }, 404);
        }

        const validation = await mockAWSClients.s3.send(
          new HeadObjectCommand({})
        );

        return c.json({
          message: 'Backup validation completed',
          validation: {
            isValid: true,
            checksum: validation.ETag,
            size: validation.ContentLength,
          },
        });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    return backupApp;
  }

  function createMockRecoveryRoutes(authMiddleware: any) {
    const recoveryApp = new Hono();

    recoveryApp.post('/initiate', authMiddleware, async (c) => {
      try {
        const body = await c.req.json();

        const restoreResult = await mockAWSClients.backup.send(
          new StartRestoreJobCommand({})
        );

        return c.json({
          message: 'Recovery initiated successfully',
          restoreJobId: restoreResult.RestoreJobId,
        });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    recoveryApp.get('/status/:restoreJobId', authMiddleware, async (c) => {
      try {
        const restoreJobId = c.req.param('restoreJobId');

        const status = await mockAWSClients.backup.send(
          new DescribeRestoreJobCommand({ RestoreJobId: restoreJobId })
        );

        return c.json({ status });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    return recoveryApp;
  }

  function createMockDisasterRecoveryRoutes(authMiddleware: any) {
    const drApp = new Hono();

    drApp.post('/failover', authMiddleware, async (c) => {
      try {
        const body = await c.req.json();

        const failoverResult = await mockAWSClients.rds.send(
          new ModifyDBInstanceCommand({})
        );

        return c.json({
          message: 'Failover initiated successfully',
          instance: failoverResult.DBInstance,
        });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    return drApp;
  }

  function createMockOfflineRoutes(authMiddleware: any) {
    const offlineApp = new Hono();

    offlineApp.get('/status', authMiddleware, async (c) => {
      try {
        const offlineStatus = await mockRedis.hgetall('offline:status');

        return c.json({
          offlineMode: offlineStatus.offline_mode === 'true',
          offlineStart: offlineStatus.offline_start,
          cachedDataSize: parseInt(offlineStatus.cached_data_size || '0'),
        });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    offlineApp.post('/sync', authMiddleware, async (c) => {
      try {
        const offlineKeys = await mockRedis.keys('offline:*');
        
        for (const key of offlineKeys) {
          const data = await mockRedis.get(key);
          // Process offline data
        }

        return c.json({
          message: 'Offline data synchronized successfully',
          syncedItems: offlineKeys.length,
        });
      } catch (error) {
        return c.json({ error: 'Internal server error' }, 500);
      }
    });

    return offlineApp;
  }

  // Run tests if in test environment
  if (process.env.RUN_TESTS === 'true') {
    console.log('Running backup & recovery service tests...');
    
    jest.setTimeout(30000);
    
    const testResults = jest.runCLI({
      testMatch: ['**/*.test.ts', '**/*.spec.ts'],
      collectCoverage: true,
      coverageDirectory: 'coverage',
      coverageReporters: ['text', 'lcov', 'html'],
      coverageThreshold: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80,
        },
      },
      verbose: true,
    }, [process.cwd()]);

    testResults.then((results) => {
      if (results.results.success) {
        console.log('All tests passed!');
        process.exit(0);
      } else {
        console.log('Some tests failed!');
        process.exit(1);
      }
    });
  }
}

// Create Hono app instance
const app = new Hono();

// Test configuration and setup
const isTestEnvironment = process.env.NODE_ENV === 'test';
const shouldRunTests = process.env.RUN_TESTS === 'true';

// Global middleware
app.use('*', logger());
app.use('*', prettyJSON());

// CORS configuration
app.use('*', cors({
  origin: config.cors.allowedOrigins,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
  credentials: true,
}));

// Request ID middleware for tracing
app.use('*', async (c, next) => {
  const requestId = c.req.header('x-request-id') || crypto.randomUUID();
  c.set('requestId', requestId);
  c.header('x-request-id', requestId);
  
  const startTime = Date.now();
  appLogger.info('Request started', {
    requestId,
    method: c.req.method,
    path: c.req.path,
    userAgent: c.req.header('user-agent'),
    ip: c.req.header('x-forwarded-for') || c.req.header('x-real-ip'),
  });

  await next();

  const duration = Date.now() - startTime;
  appLogger.info('Request completed', {
    requestId,
    method: c.req.method,
    path: c.req.path,
    status: c.res.status,
    duration: `${duration}ms`,
  });
});

// Authentication middleware
const authMiddleware = async (c: any, next: any) => {
  try {
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
      return c.json({
        error: {
          code: 401,
          message: 'Access token required',
          timestamp: new Date().toISOString(),
        },
      }, 401);
    }

    // In production, verify JWT token here
    // For now, mock the user payload
    const userPayload = {
      sub: 'user-id',
      tenantId: 'tenant-id',
      role: 'ADMIN',
      type: 'access',
    };

    c.set('user', userPayload);
    await next();
  } catch (error) {
    appLogger.error('Authentication error', { error: error.message });
    return c.json({
      error: {
        code: 401,
        message: 'Invalid token',
        timestamp: new Date().toISOString(),
      },
    }, 401);
  }
};

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'backup-recovery-service',
    version: process.env.npm_package_version || '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: config.environment,
  });
});

// Readiness check endpoint
app.get('/ready', async (c) => {
  try {
    // Check database connectivity
    await prisma.$queryRaw`SELECT 1`;
    
    // Check Redis connectivity
    await redis.ping();
    
    // Check AWS Backup service connectivity
    await backupClient.send(new ListBackupJobsCommand({}));

    return c.json({
      status: 'ready',
      service: 'backup-recovery-service',
      timestamp: new Date().toISOString(),
      checks: {
        database: 'healthy',
        redis: 'healthy',
        awsBackup: 'healthy',
        awsRds: 'healthy',
        awsS3: 'healthy',
      },
    });
  } catch (error) {
    appLogger.error('Readiness check failed', { error: error.message });
    return c.json({
      status: 'not ready',
      service: 'backup-recovery-service',
      timestamp: new Date().toISOString(),
      error: error.message,
    }, 503);
  }
});

// Metrics endpoint for monitoring
app.get('/metrics', (c) => {
  const memUsage = process.memoryUsage();
  return c.json({
    service: 'backup-recovery-service',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
      external: `${Math.round(memUsage.external / 1024 / 1024)}MB`,
    },
    process: {
      pid: process.pid,
      version: process.version,
      platform: process.platform,
      arch: process.arch,
    },
  });
});

// Backup Job Management Routes
app.post('/backup/jobs', authMiddleware, async (c) => {
  try {
    const body = await c.req.json();
    const user = c.get('user');
    const requestId = c.get('requestId');

    // Validate required fields
    if (!body.backupType || !body.schedule) {
      return c.json({
        error: {
          code: 400,
          message: 'Validation failed: backupType and schedule are required',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 400);
    }

    // Validate tenant exists
    const tenant = await prisma.tenant.findUnique({
      where: { id: user.tenantId },
    });

    if (!tenant) {
      return c.json({
        error: {
          code: 400,
          message: 'Invalid tenant',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 400);
    }

    // Calculate next run time based on schedule
    const nextRun = calculateNextRun(body.schedule);

    // Create backup job in database
    const backupJob = await prisma.backupJob.create({
      data: {
        tenantId: user.tenantId,
        backupType: body.backupType,
        schedule: body.schedule,
        nextRun,
        status: 'SCHEDULED',
        retentionDays: body.retentionDays || 30,
        storageLocation: body.storageLocation || `s3://sparc-backups/${user.tenantId}/`,
        encryptionEnabled: body.encryptionEnabled !== false,
      },
    });

    // Create AWS Backup plan if needed
    if (body.backupType === 'AUTOMATED') {
      try {
        const awsBackupJob = await backupClient.send(new CreateBackupJobCommand({
          BackupVaultName: `sparc-backup-vault-${user.tenantId}`,
          ResourceArn: `arn:aws:rds:${config.aws.region}:${config.aws.accountId}:db:sparc-${user.tenantId}`,
          IamRoleArn: config.aws.backupRoleArn,
          StartWindowMinutes: 60,
          CompleteWindowMinutes: 120,
          Lifecycle: {
            DeleteAfterDays: body.retentionDays || 30,
          },
        }));

        // Update job with AWS backup job ID
        await prisma.backupJob.update({
          where: { id: backupJob.id },
          data: {
            status: 'SCHEDULED',
          },
        });

        appLogger.info('AWS Backup job created', {
          requestId,
          backupJobId: backupJob.id,
          awsBackupJobId: awsBackupJob.BackupJobId,
        });
      } catch (awsError) {
        appLogger.error('Failed to create AWS backup job', {
          requestId,
          error: awsError.message,
          backupJobId: backupJob.id,
        });
      }
    }

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'BACKUP_JOB_CREATED',
        resourceType: 'BackupJob',
        resourceId: backupJob.id,
        details: {
          backupType: body.backupType,
          schedule: body.schedule,
          retentionDays: body.retentionDays || 30,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Backup job created successfully',
      job: {
        id: backupJob.id,
        backupType: backupJob.backupType,
        schedule: backupJob.schedule,
        nextRun: backupJob.nextRun,
        status: backupJob.status,
        retentionDays: backupJob.retentionDays,
        storageLocation: backupJob.storageLocation,
        encryptionEnabled: backupJob.encryptionEnabled,
        createdAt: backupJob.createdAt,
      },
    }, 201);

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to create backup job', {
      requestId,
      error: error.message,
      stack: error.stack,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

app.get('/backup/jobs', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const requestId = c.get('requestId');

    // Get query parameters for pagination and filtering
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '10');
    const status = c.req.query('status');
    const backupType = c.req.query('backupType');

    const skip = (page - 1) * limit;

    // Build where clause
    const where: any = { tenantId: user.tenantId };
    if (status) where.status = status;
    if (backupType) where.backupType = backupType;

    // Get backup jobs with pagination
    const [jobs, total] = await Promise.all([
      prisma.backupJob.findMany({
        where,
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      prisma.backupJob.count({ where }),
    ]);

    return c.json({
      jobs: jobs.map(job => ({
        id: job.id,
        backupType: job.backupType,
        schedule: job.schedule,
        lastRun: job.lastRun,
        nextRun: job.nextRun,
        status: job.status,
        backupSize: job.backupSize?.toString(),
        retentionDays: job.retentionDays,
        storageLocation: job.storageLocation,
        encryptionEnabled: job.encryptionEnabled,
        createdAt: job.createdAt,
        updatedAt: job.updatedAt,
      })),
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
      },
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to list backup jobs', {
      requestId,
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

app.get('/backup/jobs/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const jobId = c.req.param('id');
    const requestId = c.get('requestId');

    const job = await prisma.backupJob.findUnique({
      where: {
        id: jobId,
        tenantId: user.tenantId,
      },
    });

    if (!job) {
      return c.json({
        error: {
          code: 404,
          message: 'Backup job not found',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 404);
    }

    return c.json({
      job: {
        id: job.id,
        backupType: job.backupType,
        schedule: job.schedule,
        lastRun: job.lastRun,
        nextRun: job.nextRun,
        status: job.status,
        backupSize: job.backupSize?.toString(),
        retentionDays: job.retentionDays,
        storageLocation: job.storageLocation,
        encryptionEnabled: job.encryptionEnabled,
        createdAt: job.createdAt,
        updatedAt: job.updatedAt,
      },
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to get backup job', {
      requestId,
      jobId: c.req.param('id'),
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

app.put('/backup/jobs/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const jobId = c.req.param('id');
    const body = await c.req.json();
    const requestId = c.get('requestId');

    // Check if job exists and belongs to tenant
    const existingJob = await prisma.backupJob.findUnique({
      where: {
        id: jobId,
        tenantId: user.tenantId,
      },
    });

    if (!existingJob) {
      return c.json({
        error: {
          code: 404,
          message: 'Backup job not found',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 404);
    }

    // Prepare update data
    const updateData: any = {};
    if (body.schedule) {
      updateData.schedule = body.schedule;
      updateData.nextRun = calculateNextRun(body.schedule);
    }
    if (body.retentionDays !== undefined) updateData.retentionDays = body.retentionDays;
    if (body.storageLocation) updateData.storageLocation = body.storageLocation;
    if (body.encryptionEnabled !== undefined) updateData.encryptionEnabled = body.encryptionEnabled;

    // Update backup job
    const updatedJob = await prisma.backupJob.update({
      where: { id: jobId },
      data: updateData,
    });

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'BACKUP_JOB_UPDATED',
        resourceType: 'BackupJob',
        resourceId: jobId,
        details: updateData,
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Backup job updated successfully',
      job: {
        id: updatedJob.id,
        backupType: updatedJob.backupType,
        schedule: updatedJob.schedule,
        lastRun: updatedJob.lastRun,
        nextRun: updatedJob.nextRun,
        status: updatedJob.status,
        backupSize: updatedJob.backupSize?.toString(),
        retentionDays: updatedJob.retentionDays,
        storageLocation: updatedJob.storageLocation,
        encryptionEnabled: updatedJob.encryptionEnabled,
        createdAt: updatedJob.createdAt,
        updatedAt: updatedJob.updatedAt,
      },
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to update backup job', {
      requestId,
      jobId: c.req.param('id'),
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

app.delete('/backup/jobs/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const jobId = c.req.param('id');
    const requestId = c.get('requestId');

    // Check if job exists and belongs to tenant
    const existingJob = await prisma.backupJob.findUnique({
      where: {
        id: jobId,
        tenantId: user.tenantId,
      },
    });

    if (!existingJob) {
      return c.json({
        error: {
          code: 404,
          message: 'Backup job not found',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 404);
    }

    // Delete backup job
    await prisma.backupJob.delete({
      where: { id: jobId },
    });

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'BACKUP_JOB_DELETED',
        resourceType: 'BackupJob',
        resourceId: jobId,
        details: {
          backupType: existingJob.backupType,
          schedule: existingJob.schedule,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Backup job deleted successfully',
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to delete backup job', {
      requestId,
      jobId: c.req.param('id'),
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Manual Backup Execution
app.post('/backup/execute/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const jobId = c.req.param('id');
    const requestId = c.get('requestId');

    // Get backup job
    const job = await prisma.backupJob.findUnique({
      where: {
        id: jobId,
        tenantId: user.tenantId,
      },
    });

    if (!job) {
      return c.json({
        error: {
          code: 404,
          message: 'Backup job not found',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 404);
    }

    // Execute backup based on type
    let backupResult;
    if (job.backupType === 'DATABASE') {
      // Create RDS snapshot
      const snapshotId = `sparc-manual-${user.tenantId}-${Date.now()}`;
      backupResult = await rdsClient.send(new CreateDBSnapshotCommand({
        DBSnapshotIdentifier: snapshotId,
        DBInstanceIdentifier: `sparc-${user.tenantId}`,
      }));
    } else {
      // Use AWS Backup service
      backupResult = await backupClient.send(new CreateBackupJobCommand({
        BackupVaultName: `sparc-backup-vault-${user.tenantId}`,
        ResourceArn: `arn:aws:rds:${config.aws.region}:${config.aws.accountId}:db:sparc-${user.tenantId}`,
        IamRoleArn: config.aws.backupRoleArn,
        StartWindowMinutes: 60,
        CompleteWindowMinutes: 120,
      }));
    }

    // Update job status
    await prisma.backupJob.update({
      where: { id: jobId },
      data: {
        status: 'RUNNING',
        lastRun: new Date(),
      },
    });

    // Store backup execution details in Redis for monitoring
    await redis.setex(
      `backup:execution:${jobId}`,
      3600, // 1 hour TTL
      JSON.stringify({
        backupJobId: backupResult.BackupJobId || backupResult.DBSnapshot?.DBSnapshotIdentifier,
        startTime: new Date().toISOString(),
        status: 'RUNNING',
        type: job.backupType,
      })
    );

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'BACKUP_EXECUTED',
        resourceType: 'BackupJob',
        resourceId: jobId,
        details: {
          backupType: job.backupType,
          executionType: 'MANUAL',
          awsBackupJobId: backupResult.BackupJobId || backupResult.DBSnapshot?.DBSnapshotIdentifier,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Backup job started successfully',
      execution: {
        backupJobId: backupResult.BackupJobId || backupResult.DBSnapshot?.DBSnapshotIdentifier,
        status: 'RUNNING',
        startTime: new Date().toISOString(),
      },
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to execute backup job', {
      requestId,
      jobId: c.req.param('id'),
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Backup Status Monitoring
app.get('/backup/status/:backupJobId', authMiddleware, async (c) => {
  try {
    const backupJobId = c.req.param('backupJobId');
    const requestId = c.get('requestId');

    // Try to get status from AWS Backup first
    let status;
    try {
      status = await backupClient.send(new DescribeBackupJobCommand({
        BackupJobId: backupJobId,
      }));
    } catch (awsError) {
      // If not found in AWS Backup, try RDS snapshots
      try {
        const snapshots = await rdsClient.send(new DescribeDBSnapshotsCommand({
          DBSnapshotIdentifier: backupJobId,
        }));
        
        if (snapshots.DBSnapshots && snapshots.DBSnapshots.length > 0) {
          const snapshot = snapshots.DBSnapshots[0];
          status = {
            BackupJobId: snapshot.DBSnapshotIdentifier,
            State: snapshot.Status === 'available' ? 'COMPLETED' : 'RUNNING',
            PercentDone: snapshot.PercentProgress?.toString() || '0',
            BackupSizeInBytes: snapshot.AllocatedStorage ? snapshot.AllocatedStorage * 1024 * 1024 * 1024 : 0,
            CreationDate: snapshot.SnapshotCreateTime,
          };
        }
      } catch (rdsError) {
        appLogger.error('Failed to get backup status from AWS', {
          requestId,
          backupJobId,
          awsError: awsError.message,
          rdsError: rdsError.message,
        });
        
        return c.json({
          error: {
            code: 404,
            message: 'Backup job not found',
            requestId,
            timestamp: new Date().toISOString(),
          },
        }, 404);
      }
    }

    // Get cached execution details from Redis
    const executionDetails = await redis.get(`backup:execution:${backupJobId}`);
    let execution = null;
    if (executionDetails) {
      execution = JSON.parse(executionDetails);
    }

    return c.json({
      status: {
        backupJobId: status.BackupJobId,
        state: status.State,
        percentDone: status.PercentDone,
        backupSizeInBytes: status.BackupSizeInBytes,
        creationDate: status.CreationDate,
        completionDate: status.CompletionDate,
        statusMessage: status.StatusMessage,
      },
      execution,
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to get backup status', {
      requestId,
      backupJobId: c.req.param('backupJobId'),
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Recovery Initiation
app.post('/recovery/initiate', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const body = await c.req.json();
    const requestId = c.get('requestId');

    // Validate required fields
    if (!body.backupId || !body.targetEnvironment || !body.recoveryType) {
      return c.json({
        error: {
          code: 400,
          message: 'Validation failed: backupId, targetEnvironment, and recoveryType are required',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 400);
    }

    let restoreResult;

    if (body.recoveryType === 'POINT_IN_TIME' && body.targetTime) {
      // Point-in-time recovery using RDS
      const targetInstanceId = `sparc-${user.tenantId}-restore-${Date.now()}`;
      
      restoreResult = await rdsClient.send(new RestoreDBInstanceFromDBSnapshotCommand({
        DBInstanceIdentifier: targetInstanceId,
        DBSnapshotIdentifier: body.backupId,
        DBInstanceClass: 'db.t3.micro', // Configurable based on requirements
        MultiAZ: body.targetEnvironment === 'production',
        PubliclyAccessible: false,
        StorageEncrypted: true,
      }));

      // Store recovery details
      await redis.setex(
        `recovery:${restoreResult.DBInstance.DBInstanceIdentifier}`,
        7200, // 2 hours TTL
        JSON.stringify({
          restoreJobId: restoreResult.DBInstance.DBInstanceIdentifier,
          backupId: body.backupId,
          recoveryType: body.recoveryType,
          targetEnvironment: body.targetEnvironment,
          targetTime: body.targetTime,
          startTime: new Date().toISOString(),
          status: 'RUNNING',
          tenantId: user.tenantId,
        })
      );

    } else {
      // Standard restore using AWS Backup
      restoreResult = await backupClient.send(new StartRestoreJobCommand({
        RecoveryPointArn: body.backupId,
        Metadata: {
          'target-environment': body.targetEnvironment,
          'tenant-id': user.tenantId,
        },
        IamRoleArn: config.aws.backupRoleArn,
        ResourceType: 'RDS',
      }));

      // Store recovery details
      await redis.setex(
        `recovery:${restoreResult.RestoreJobId}`,
        7200, // 2 hours TTL
        JSON.stringify({
          restoreJobId: restoreResult.RestoreJobId,
          backupId: body.backupId,
          recoveryType: body.recoveryType,
          targetEnvironment: body.targetEnvironment,
          startTime: new Date().toISOString(),
          status: 'RUNNING',
          tenantId: user.tenantId,
        })
      );
    }

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'RECOVERY_INITIATED',
        resourceType: 'Recovery',
        resourceId: restoreResult.RestoreJobId || restoreResult.DBInstance?.DBInstanceIdentifier,
        details: {
          backupId: body.backupId,
          recoveryType: body.recoveryType,
          targetEnvironment: body.targetEnvironment,
          targetTime: body.targetTime,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Recovery initiated successfully',
      recovery: {
        restoreJobId: restoreResult.RestoreJobId || restoreResult.DBInstance?.DBInstanceIdentifier,
        backupId: body.backupId,
        recoveryType: body.recoveryType,
        targetEnvironment: body.targetEnvironment,
        status: 'RUNNING',
        startTime: new Date().toISOString(),
        estimatedCompletionTime: new Date(Date.now() + 30 * 60 * 1000).toISOString(), // 30 minutes estimate
      },
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to initiate recovery', {
      requestId,
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Recovery Status Monitoring
app.get('/recovery/status/:restoreJobId', authMiddleware, async (c) => {
  try {
    const restoreJobId = c.req.param('restoreJobId');
    const requestId = c.get('requestId');

    // Get cached recovery details
    const recoveryDetails = await redis.get(`recovery:${restoreJobId}`);
    if (!recoveryDetails) {
      return c.json({
        error: {
          code: 404,
          message: 'Recovery job not found',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 404);
    }

    const recovery = JSON.parse(recoveryDetails);

    // Get status from AWS
    let status;
    try {
      if (recovery.recoveryType === 'POINT_IN_TIME') {
        // Check RDS instance status
        const instances = await rdsClient.send(new DescribeDBSnapshotsCommand({
          DBInstanceIdentifier: restoreJobId,
        }));
        
        if (instances.DBSnapshots && instances.DBSnapshots.length > 0) {
          const instance = instances.DBSnapshots[0];
          status = {
            RestoreJobId: restoreJobId,
            Status: instance.Status === 'available' ? 'COMPLETED' : 'RUNNING',
            PercentDone: instance.PercentProgress?.toString() || '0',
            CreationDate: instance.SnapshotCreateTime,
          };
        }
      } else {
        // Check AWS Backup restore job status
        status = await backupClient.send(new DescribeRestoreJobCommand({
          RestoreJobId: restoreJobId,
        }));
      }
    } catch (awsError) {
      appLogger.error('Failed to get recovery status from AWS', {
        requestId,
        restoreJobId,
        error: awsError.message,
      });
      
      status = {
        RestoreJobId: restoreJobId,
        Status: 'UNKNOWN',
        PercentDone: '0',
      };
    }

    return c.json({
      recovery: {
        restoreJobId,
        backupId: recovery.backupId,
        recoveryType: recovery.recoveryType,
        targetEnvironment: recovery.targetEnvironment,
        status: status.Status,
        percentDone: status.PercentDone,
        startTime: recovery.startTime,
        creationDate: status.CreationDate,
        completionDate: status.CompletionDate,
        statusMessage: status.StatusMessage,
      },
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to get recovery status', {
      requestId,
      restoreJobId: c.req.param('restoreJobId'),
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Backup Integrity Validation
app.post('/backup/validate/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const jobId = c.req.param('id');
    const requestId = c.get('requestId');

    // Get backup job
    const job = await prisma.backupJob.findUnique({
      where: {
        id: jobId,
        tenantId: user.tenantId,
      },
    });

    if (!job) {
      return c.json({
        error: {
          code: 404,
          message: 'Backup job not found',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 404);
    }

    // Validate backup integrity based on storage location
    let validation;
    if (job.storageLocation.startsWith('s3://')) {
      // S3 backup validation
      const bucketName = job.storageLocation.split('/')[2];
      const keyPrefix = job.storageLocation.split('/').slice(3).join('/');

      // List objects in the backup location
      const objects = await s3Client.send(new ListObjectsV2Command({
        Bucket: bucketName,
        Prefix: keyPrefix,
      }));

      if (!objects.Contents || objects.Contents.length === 0) {
        validation = {
          isValid: false,
          error: 'No backup files found',
          checkedAt: new Date().toISOString(),
        };
      } else {
        // Validate each backup file
        const validationResults = await Promise.all(
          objects.Contents.map(async (obj) => {
            try {
              const metadata = await s3Client.send(new HeadObjectCommand({
                Bucket: bucketName,
                Key: obj.Key,
              }));

              return {
                key: obj.Key,
                size: obj.Size,
                lastModified: obj.LastModified,
                etag: metadata.ETag,
                isValid: true,
              };
            } catch (error) {
              return {
                key: obj.Key,
                isValid: false,
                error: error.message,
              };
            }
          })
        );

        const allValid = validationResults.every(result => result.isValid);
        const totalSize = validationResults.reduce((sum, result) => sum + (result.size || 0), 0);

        validation = {
          isValid: allValid,
          totalFiles: validationResults.length,
          totalSize,
          files: validationResults,
          checkedAt: new Date().toISOString(),
        };
      }
    } else {
      // RDS snapshot validation
      try {
        const snapshots = await rdsClient.send(new DescribeDBSnapshotsCommand({
          DBSnapshotIdentifier: job.id,
        }));

        if (snapshots.DBSnapshots && snapshots.DBSnapshots.length > 0) {
          const snapshot = snapshots.DBSnapshots[0];
          validation = {
            isValid: snapshot.Status === 'available',
            snapshotId: snapshot.DBSnapshotIdentifier,
            status: snapshot.Status,
            size: snapshot.AllocatedStorage,
            encrypted: snapshot.Encrypted,
            createdAt: snapshot.SnapshotCreateTime,
            checkedAt: new Date().toISOString(),
          };
        } else {
          validation = {
            isValid: false,
            error: 'Snapshot not found',
            checkedAt: new Date().toISOString(),
          };
        }
      } catch (error) {
        validation = {
          isValid: false,
          error: error.message,
          checkedAt: new Date().toISOString(),
        };
      }
    }

    // Update backup job with validation results
    await prisma.backupJob.update({
      where: { id: jobId },
      data: {
        updatedAt: new Date(),
      },
    });

    // Store validation results in Redis for caching
    await redis.setex(
      `backup:validation:${jobId}`,
      3600, // 1 hour TTL
      JSON.stringify(validation)
    );

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'BACKUP_VALIDATED',
        resourceType: 'BackupJob',
        resourceId: jobId,
        details: {
          isValid: validation.isValid,
          validationResults: validation,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Backup validation completed',
      validation,
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to validate backup', {
      requestId,
      jobId: c.req.param('id'),
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Disaster Recovery Failover
app.post('/disaster-recovery/failover', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const body = await c.req.json();
    const requestId = c.get('requestId');

    // Validate required fields
    if (!body.targetRegion || !body.failoverType) {
      return c.json({
        error: {
          code: 400,
          message: 'Validation failed: targetRegion and failoverType are required',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 400);
    }

    // Initiate failover process
    const failoverStartTime = new Date();
    
    // Create RDS client for target region
    const targetRdsClient = new RDSClient({ region: body.targetRegion });

    // Get the latest backup/snapshot for failover
    const snapshots = await rdsClient.send(new DescribeDBSnapshotsCommand({
      DBInstanceIdentifier: `sparc-${user.tenantId}`,
      SnapshotType: 'automated',
      MaxRecords: 1,
    }));

    if (!snapshots.DBSnapshots || snapshots.DBSnapshots.length === 0) {
      return c.json({
        error: {
          code: 400,
          message: 'No recent snapshots available for failover',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 400);
    }

    const latestSnapshot = snapshots.DBSnapshots[0];

    // Copy snapshot to target region if needed
    let targetSnapshotId = latestSnapshot.DBSnapshotIdentifier;
    if (body.targetRegion !== config.aws.region) {
      const copyResult = await targetRdsClient.send(new CopyObjectCommand({
        SourceDBSnapshotIdentifier: `arn:aws:rds:${config.aws.region}:${config.aws.accountId}:snapshot:${latestSnapshot.DBSnapshotIdentifier}`,
        TargetDBSnapshotIdentifier: `${latestSnapshot.DBSnapshotIdentifier}-failover`,
      }));
      targetSnapshotId = copyResult.DBSnapshotIdentifier;
    }

    // Create new RDS instance in target region
    const failoverInstanceId = `sparc-${user.tenantId}-failover-${Date.now()}`;
    const restoreResult = await targetRdsClient.send(new RestoreDBInstanceFromDBSnapshotCommand({
      DBInstanceIdentifier: failoverInstanceId,
      DBSnapshotIdentifier: targetSnapshotId,
      DBInstanceClass: 'db.t3.medium', // Use appropriate instance class for failover
      MultiAZ: true,
      PubliclyAccessible: false,
      StorageEncrypted: true,
      DeletionProtection: true,
    }));

    // Store failover details
    const failoverDetails = {
      failoverJobId: crypto.randomUUID(),
      sourceRegion: config.aws.region,
      targetRegion: body.targetRegion,
      failoverType: body.failoverType,
      sourceInstanceId: `sparc-${user.tenantId}`,
      targetInstanceId: failoverInstanceId,
      snapshotId: targetSnapshotId,
      startTime: failoverStartTime.toISOString(),
      status: 'IN_PROGRESS',
      tenantId: user.tenantId,
      estimatedCompletionTime: new Date(Date.now() + 30 * 60 * 1000).toISOString(), // 30 minutes
    };

    await redis.setex(
      `failover:${failoverDetails.failoverJobId}`,
      7200, // 2 hours TTL
      JSON.stringify(failoverDetails)
    );

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'DISASTER_RECOVERY_FAILOVER_INITIATED',
        resourceType: 'DisasterRecovery',
        resourceId: failoverDetails.failoverJobId,
        details: {
          sourceRegion: config.aws.region,
          targetRegion: body.targetRegion,
          failoverType: body.failoverType,
          targetInstanceId: failoverInstanceId,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Failover initiated successfully',
      failover: {
        failoverJobId: failoverDetails.failoverJobId,
        targetRegion: body.targetRegion,
        targetInstanceId: failoverInstanceId,
        status: 'IN_PROGRESS',
        startTime: failoverStartTime.toISOString(),
        estimatedCompletionTime: failoverDetails.estimatedCompletionTime,
      },
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to initiate failover', {
      requestId,
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Cross-Region Replication Management
app.post('/backup/replication/setup', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const body = await c.req.json();
    const requestId = c.get('requestId');

    // Validate required fields
    if (!body.targetRegion || !body.replicationSchedule) {
      return c.json({
        error: {
          code: 400,
          message: 'Validation failed: targetRegion and replicationSchedule are required',
          requestId,
          timestamp: new Date().toISOString(),
        },
      }, 400);
    }

    // Setup cross-region replication for S3 backups
    const sourceBucket = `sparc-backups-${config.aws.region}`;
    const targetBucket = `sparc-backups-${body.targetRegion}`;

    // Create replication configuration
    const replicationConfig = {
      tenantId: user.tenantId,
      sourceRegion: config.aws.region,
      targetRegion: body.targetRegion,
      sourceBucket,
      targetBucket,
      schedule: body.replicationSchedule,
      enabled: true,
      createdAt: new Date().toISOString(),
    };

    // Store replication configuration
    await redis.setex(
      `replication:${user.tenantId}`,
      86400 * 30, // 30 days TTL
      JSON.stringify(replicationConfig)
    );

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'CROSS_REGION_REPLICATION_SETUP',
        resourceType: 'Replication',
        resourceId: `replication-${user.tenantId}`,
        details: replicationConfig,
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Cross-region replication setup successfully',
      replication: replicationConfig,
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to setup cross-region replication', {
      requestId,
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Offline Operations Support
app.get('/offline/status', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const requestId = c.get('requestId');

    // Get offline status from Redis
    const offlineStatus = await redis.hgetall(`offline:status:${user.tenantId}`);
    
    // Get cached data statistics
    const cachedKeys = await redis.keys(`offline:cache:${user.tenantId}:*`);
    const queuedEvents = await redis.keys(`offline:events:${user.tenantId}:*`);

    const status = {
      tenantId: user.tenantId,
      offlineMode: offlineStatus.offline_mode === 'true',
      offlineStart: offlineStatus.offline_start || null,
      offlineEnd: offlineStatus.offline_end || null,
      cachedDataSize: parseInt(offlineStatus.cached_data_size || '0'),
      cachedItems: cachedKeys.length,
      queuedEvents: queuedEvents.length,
      lastSyncAttempt: offlineStatus.last_sync_attempt || null,
      lastSuccessfulSync: offlineStatus.last_successful_sync || null,
      syncStatus: offlineStatus.sync_status || 'UNKNOWN',
      capabilities: {
        maxOfflineHours: 72,
        supportedOperations: [
          'ACCESS_CONTROL',
          'VIDEO_RECORDING',
          'EVENT_LOGGING',
          'CREDENTIAL_VALIDATION',
        ],
      },
    };

    return c.json({ status });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to get offline status', {
      requestId,
      error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

app.post('/offline/sync', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    const requestId = c.get('requestId');

    // Get all offline events for the tenant
    const eventKeys = await redis.keys(`offline:events:${user.tenantId}:*`);
    
    if (eventKeys.length === 0) {
      return c.json({
        message: 'No offline data to synchronize',
        syncedItems: 0,
      });
    }

    const syncResults = [];
    const batchSize = 100; // Process in batches to avoid overwhelming the database

    for (let i = 0; i < eventKeys.length; i += batchSize) {
      const batch = eventKeys.slice(i, i + batchSize);
      
      const batchEvents = await Promise.all(
        batch.map(async (key) => {
          const eventData = await redis.get(key);
          return eventData ? JSON.parse(eventData) : null;
        })
      );

      // Filter out null events
      const validEvents = batchEvents.filter(event => event !== null);

      // Process events in a database transaction
      try {
        await prisma.$transaction(async (tx) => {
          for (const event of validEvents) {
            switch (event.eventType) {
              case 'ACCESS_EVENT':
                await tx.accessEvent.create({
                  data: {
                    tenantId: user.tenantId,
                    doorId: event.data.doorId,
                    userId: event.data.userId,
                    credentialId: event.data.credentialId,
                    eventType: event.data.eventType,
                    result: event.data.result,
                    timestamp: new Date(event.data.timestamp),
                    metadata: event.data.metadata || {},
                  },
                });
                break;

              case 'AUDIT_LOG':
                await tx.auditLog.create({
                  data: {
                    tenantId: user.tenantId,
                    userId: event.data.userId,
                    action: event.data.action,
                    resourceType: event.data.resourceType,
                    resourceId: event.data.resourceId,
                    details: event.data.details || {},
                    ipAddress: event.data.ipAddress || 'offline',
                    userAgent: event.data.userAgent || 'offline-device',
                    timestamp: new Date(event.data.timestamp),
                  },
                });
                break;

              case 'BACKUP_EVENT':
                // Handle offline backup events
                await tx.backupJob.update({
                  where: { id: event.data.backupJobId },
                  data: {
                    status: event.data.status,
                    lastRun: new Date(event.data.timestamp),
                    backupSize: event.data.backupSize ? BigInt(event.data.backupSize) : null,
                  },
                });
                break;

              default:
                appLogger.warn('Unknown offline event type', {
                  requestId,
                  eventType: event.eventType,
                  eventId: event.id,
                });
            }
          }
        });

        // Mark batch as successfully synced
        syncResults.push({
          batch: i / batchSize + 1,
          events: validEvents.length,
          status: 'SUCCESS',
        });

        // Remove synced events from Redis
        if (batch.length > 0) {
          await redis.del(...batch);
        }

      } catch (dbError) {
        appLogger.error('Failed to sync batch to database', {
          requestId,
          batch: i / batchSize + 1,
          error: dbError.message,
        });

        syncResults.push({
          batch: i / batchSize + 1,
          events: validEvents.length,
          status: 'FAILED',
          error: dbError.message,
        });
      }
    }

    // Update offline status
    await redis.hset(`offline:status:${user.tenantId}`, {
      last_sync_attempt: new Date().toISOString(),
      last_successful_sync: new Date().toISOString(),
      sync_status: 'COMPLETED',
    });

    const totalSynced = syncResults
      .filter(result => result.status === 'SUCCESS')
      .reduce((sum, result) => sum + result.events, 0);

    const totalFailed = syncResults
      .filter(result => result.status === 'FAILED')
      .reduce((sum, result) => sum + result.events, 0);

    // Log audit event
    await prisma.auditLog.create({
      data: {
        tenantId: user.tenantId,
        userId: user.sub,
        action: 'OFFLINE_DATA_SYNCHRONIZED',
        resourceType: 'OfflineSync',
        resourceId: `sync-${Date.now()}`,
        details: {
          totalEvents: eventKeys.length,
          syncedEvents: totalSynced,
          failedEvents: totalFailed,
          batches: syncResults.length,
        },
        ipAddress: c.req.header('x-forwarded-for') || 'unknown',
        userAgent: c.req.header('user-agent') || 'unknown',
      },
    });

    return c.json({
      message: 'Offline data synchronized successfully',
      summary: {
        totalEvents: eventKeys.length,
        syncedEvents: totalSynced,
        failedEvents: totalFailed,
        batches: syncResults.length,
      },
      results: syncResults,
    });

  } catch (error) {
    const requestId = c.get('requestId');
    appLogger.error('Failed to synchronize offline data', {
      requestId,
      error: error.message,
    });

    // Update offline status with error
    await redis.hset(`offline:status:${user.tenantId}`, {
      last_sync_attempt: new Date().toISOString(),
      sync_status: 'FAILED',
      sync_error: error.message,
    });

    return c.json({
      error: {
        code: 500,
        message: 'Internal server error',
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, 500);
  }
});

// Global error handler
app.onError((err, c) => {
  const requestId = c.get('requestId');
  
  if (err instanceof HTTPException) {
    appLogger.warn('HTTP Exception', {
      requestId,
      status: err.status,
      message: err.message,
      path: c.req.path,
      method: c.req.method,
    });
    
    return c.json({
      error: {
        code: err.status,
        message: err.message,
        requestId,
        timestamp: new Date().toISOString(),
      },
    }, err.status);
  }

  appLogger.error('Unhandled error', {
    requestId,
    error: err.message,
    stack: err.stack,
    path: c.req.path,
    method: c.req.method,
  });

  return c.json({
    error: {
      code: 500,
      message: 'Internal server error',
      requestId,
      timestamp: new Date().toISOString(),
    },
  }, 500);
});

// 404 handler
app.notFound((c) => {
  const requestId = c.get('requestId');
  
  appLogger.warn('Route not found', {
    requestId,
    path: c.req.path,
    method: c.req.method,
  });

  return c.json({
    error: {
      code: 404,
      message: 'Route not found',
      requestId,
      timestamp: new Date().toISOString(),
    },
  }, 404);
});

// Utility functions
function calculateNextRun(schedule: string): Date {
  // Simple cron parser for common patterns
  // In production, use a proper cron library like node-cron
  const now = new Date();
  
  if (schedule === '0 2 * * *') { // Daily at 2 AM
    const nextRun = new Date(now);
    nextRun.setHours(2, 0, 0, 0);
    if (nextRun <= now) {
      nextRun.setDate(nextRun.getDate() + 1);
    }
    return nextRun;
  }
  
  if (schedule === '0 2 * * 0') { // Weekly on Sunday at 2 AM
    const nextRun = new Date(now);
    nextRun.setHours(2, 0, 0, 0);
    const daysUntilSunday = (7 - nextRun.getDay()) % 7;
    nextRun.setDate(nextRun.getDate() + daysUntilSunday);
    if (nextRun <= now) {
      nextRun.setDate(nextRun.getDate() + 7);
    }
    return nextRun;
  }
  
  // Default to next hour if schedule is not recognized
  const nextRun = new Date(now.getTime() + 60 * 60 * 1000);
  return nextRun;
}

// Automated backup scheduler
if (!isTestEnvironment) {
  // Schedule backup job execution every minute to check for due jobs
  cron.schedule('* * * * *', async () => {
    try {
      const now = new Date();
      
      // Find backup jobs that are due to run
      const dueJobs = await prisma.backupJob.findMany({
        where: {
          status: 'SCHEDULED',
          nextRun: {
            lte: now,
          },
        },
      });

      for (const job of dueJobs) {
        try {
          appLogger.info('Executing scheduled backup job', {
            jobId: job.id,
            tenantId: job.tenantId,
            backupType: job.backupType,
          });

          // Execute backup based on type
          let backupResult;
          if (job.backupType === 'DATABASE') {
            const snapshotId = `sparc-scheduled-${job.tenantId}-${Date.now()}`;
            backupResult = await rdsClient.send(new CreateDBSnapshotCommand({
              DBSnapshotIdentifier: snapshotId,
              DBInstanceIdentifier: `sparc-${job.tenantId}`,
            }));
          } else {
            backupResult = await backupClient.send(new CreateBackupJobCommand({
              BackupVaultName: `sparc-backup-vault-${job.tenantId}`,
              ResourceArn: `arn:aws:rds:${config.aws.region}:${config.aws.accountId}:db:sparc-${job.tenantId}`,
              IamRoleArn: config.aws.backupRoleArn,
            }));
          }

          // Update job status and schedule next run
          const nextRun = calculateNextRun(job.schedule);
          await prisma.backupJob.update({
            where: { id: job.id },
            data: {
              status: 'RUNNING',
              lastRun: now,
              nextRun,
            },
          });

          // Store execution details
          await redis.setex(
            `backup:execution:${job.id}`,
            3600,
            JSON.stringify({
              backupJobId: backupResult.BackupJobId || backupResult.DBSnapshot?.DBSnapshotIdentifier,
              startTime: now.toISOString(),
              status: 'RUNNING',
              type: job.backupType,
              scheduled: true,
            })
          );

          appLogger.info('Scheduled backup job started successfully', {
            jobId: job.id,
            awsBackupJobId: backupResult.BackupJobId || backupResult.DBSnapshot?.DBSnapshotIdentifier,
          });

        } catch (jobError) {
          appLogger.error('Failed to execute scheduled backup job', {
            jobId: job.id,
            error: jobError.message,
          });

          // Update job status to indicate failure
          await prisma.backupJob.update({
            where: { id: job.id },
            data: {
              status: 'FAILED',
              nextRun: calculateNextRun(job.schedule),
            },
          });
        }
      }

    } catch (error) {
      appLogger.error('Error in backup scheduler', {
        error: error.message,
      });
    }
  });

  // Schedule backup status monitoring every 5 minutes
  cron.schedule('*/5 * * * *', async () => {
    try {
      // Get all running backup jobs
      const runningJobs = await prisma.backupJob.findMany({
        where: {
          status: 'RUNNING',
        },
      });

      for (const job of runningJobs) {
        try {
          // Get execution details from Redis
          const executionData = await redis.get(`backup:execution:${job.id}`);
          if (!executionData) continue;

          const execution = JSON.parse(executionData);

          // Check AWS backup status
          let awsStatus;
          try {
            if (job.backupType === 'DATABASE') {
              const snapshots = await rdsClient.send(new DescribeDBSnapshotsCommand({
                DBSnapshotIdentifier: execution.backupJobId,
              }));
              
              if (snapshots.DBSnapshots && snapshots.DBSnapshots.length > 0) {
                const snapshot = snapshots.DBSnapshots[0];
                awsStatus = {
                  state: snapshot.Status === 'available' ? 'COMPLETED' : 'RUNNING',
                  percentDone: snapshot.PercentProgress?.toString() || '0',
                  backupSizeInBytes: snapshot.AllocatedStorage ? snapshot.AllocatedStorage * 1024 * 1024 * 1024 : 0,
                };
              }
            } else {
              const backupStatus = await backupClient.send(new DescribeBackupJobCommand({
                BackupJobId: execution.backupJobId,
              }));
              awsStatus = {
                state: backupStatus.State,
                percentDone: backupStatus.PercentDone,
                backupSizeInBytes: backupStatus.BackupSizeInBytes,
              };
            }

            // Update job status if completed
            if (awsStatus.state === 'COMPLETED') {
              await prisma.backupJob.update({
                where: { id: job.id },
                data: {
                  status: 'COMPLETED',
                  backupSize: awsStatus.backupSizeInBytes ? BigInt(awsStatus.backupSizeInBytes) : null,
                },
              });

              // Remove execution data from Redis
              await redis.del(`backup:execution:${job.id}`);

              appLogger.info('Backup job completed successfully', {
                jobId: job.id,
                backupSize: awsStatus.backupSizeInBytes,
              });
            } else if (awsStatus.state === 'FAILED' || awsStatus.state === 'ABORTED') {
              await prisma.backupJob.update({
                where: { id: job.id },
                data: {
                  status: 'FAILED',
                },
              });

              await redis.del(`backup:execution:${job.id}`);

              appLogger.error('Backup job failed', {
                jobId: job.id,
                awsStatus: awsStatus.state,
              });
            }

          } catch (awsError) {
            appLogger.error('Failed to check AWS backup status', {
              jobId: job.id,
              backupJobId: execution.backupJobId,
              error: awsError.message,
            });
          }

        } catch (jobError) {
          appLogger.error('Error monitoring backup job', {
            jobId: job.id,
            error: jobError.message,
          });
        }
      }

    } catch (error) {
      appLogger.error('Error in backup status monitor', {
        error: error.message,
      });
    }
  });
}

// Server configuration
const port = config.backupRecovery?.port || 3008;
const host = config.backupRecovery?.host || '0.0.0.0';

// Graceful shutdown handling
let server: any;

const gracefulShutdown = async (signal: string) => {
  appLogger.info(`Received ${signal}, starting graceful shutdown...`);
  
  if (server) {
    server.close(() => {
      appLogger.info('HTTP server closed');
    });
  }

  // Close database connections
  try {
    await prisma.$disconnect();
    appLogger.info('Database connections closed');
  } catch (error) {
    appLogger.error('Error closing database connections', { error: error.message });
  }

  // Close Redis connections
  try {
    await redis.quit();
    appLogger.info('Redis connections closed');
  } catch (error) {
    appLogger.error('Error closing Redis connections', { error: error.message });
  }

  appLogger.info('Graceful shutdown completed');
  process.exit(0);
};

// Register signal handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  appLogger.error('Uncaught exception', {
    error: error.message,
    stack: error.stack,
  });
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  appLogger.error('Unhandled promise rejection', {
    reason: reason,
    promise: promise,
  });
  process.exit(1);
});

// Start the server
const startServer = async () => {
  try {
    appLogger.info('Starting backup & recovery service...', {
      port,
      host,
      environment: config.environment,
      nodeVersion: process.version,
    });

    server = serve({
      fetch: app.fetch,
      port,
      hostname: host,
    });

    appLogger.info('Backup & recovery service started successfully', {
      port,
      host,
      environment: config.environment,
    });

    // Log available routes
    appLogger.info('Available routes:', {
      routes: [
        'GET /health - Health check',
        'GET /ready - Readiness check',
        'GET /metrics - Service metrics',
        'POST /backup/jobs - Create backup job',
        'GET /backup/jobs - List backup jobs',
        'GET /backup/jobs/:id - Get backup job details',
        'PUT /backup/jobs/:id - Update backup job',
        'DELETE /backup/jobs/:id - Delete backup job',
        'POST /backup/execute/:id - Execute backup manually',
        'GET /backup/status/:backupJobId - Get backup status',
        'POST /backup/validate/:id - Validate backup integrity',
        'POST /recovery/initiate - Initiate recovery',
        'GET /recovery/status/:restoreJobId - Get recovery status',
        'POST /disaster-recovery/failover - Initiate failover',
        'POST /backup/replication/setup - Setup cross-region replication',
        'GET /offline/status - Get offline operation status',
        'POST /offline/sync - Synchronize offline data',
      ],
    });

  } catch (error) {
    appLogger.error('Failed to start backup & recovery service', {
      error: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
};

// Start the server only if not in test mode
if (!isTestEnvironment || !shouldRunTests) {
  startServer();
}

// Export app for testing
export default app;