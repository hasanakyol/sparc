import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { IntegrationService } from '../src/services/integration.service';
import { CreateIntegration, IntegrationType } from '../src/types';

// Mock dependencies
jest.mock('@prisma/client');
jest.mock('ioredis');
jest.mock('../src/services/encryption.service');
jest.mock('../src/services/ldap.service');

describe('IntegrationService', () => {
  let service: IntegrationService;
  let mockPrisma: jest.Mocked<PrismaClient>;
  let mockRedis: jest.Mocked<Redis>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    mockRedis = new Redis() as jest.Mocked<Redis>;
    
    // Setup default mocks
    mockPrisma.integration = {
      findMany: jest.fn(),
      count: jest.fn(),
      create: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    } as any;

    mockPrisma.$transaction = jest.fn().mockImplementation((fn) => fn);
    mockPrisma.webhook = {
      deleteMany: jest.fn(),
    } as any;

    mockPrisma.auditLog = {
      create: jest.fn(),
    } as any;

    service = new IntegrationService(mockPrisma, mockRedis);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('listIntegrations', () => {
    it('should list integrations with pagination', async () => {
      const mockIntegrations = [
        {
          id: '123',
          name: 'Test Integration',
          type: 'LDAP',
          status: 'ACTIVE',
          createdAt: new Date(),
        },
      ];

      mockPrisma.integration.findMany.mockResolvedValue(mockIntegrations);
      mockPrisma.integration.count.mockResolvedValue(1);

      const result = await service.listIntegrations('tenant-123', {
        page: 1,
        limit: 10,
      });

      expect(result.data).toEqual(mockIntegrations);
      expect(result.pagination).toEqual({
        page: 1,
        limit: 10,
        total: 1,
        totalPages: 1,
      });

      expect(mockPrisma.integration.findMany).toHaveBeenCalledWith({
        where: { tenantId: 'tenant-123' },
        skip: 0,
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: expect.any(Object),
      });
    });

    it('should filter integrations by type', async () => {
      mockPrisma.integration.findMany.mockResolvedValue([]);
      mockPrisma.integration.count.mockResolvedValue(0);

      await service.listIntegrations('tenant-123', {
        page: 1,
        limit: 10,
        type: 'OAUTH2' as IntegrationType,
      });

      expect(mockPrisma.integration.findMany).toHaveBeenCalledWith({
        where: {
          tenantId: 'tenant-123',
          type: 'OAUTH2',
        },
        skip: 0,
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: expect.any(Object),
      });
    });

    it('should search integrations by name or description', async () => {
      mockPrisma.integration.findMany.mockResolvedValue([]);
      mockPrisma.integration.count.mockResolvedValue(0);

      await service.listIntegrations('tenant-123', {
        page: 1,
        limit: 10,
        search: 'test',
      });

      expect(mockPrisma.integration.findMany).toHaveBeenCalledWith({
        where: {
          tenantId: 'tenant-123',
          OR: [
            { name: { contains: 'test', mode: 'insensitive' } },
            { description: { contains: 'test', mode: 'insensitive' } },
          ],
        },
        skip: 0,
        take: 10,
        orderBy: { createdAt: 'desc' },
        select: expect.any(Object),
      });
    });
  });

  describe('createIntegration', () => {
    it('should create a new integration', async () => {
      const createData: CreateIntegration = {
        name: 'New Integration',
        type: 'WEBHOOK' as IntegrationType,
        authMethod: 'API_KEY',
        endpoint: 'https://api.example.com',
      };

      const mockCreated = {
        id: 'new-123',
        tenantId: 'tenant-123',
        ...createData,
        status: 'CONFIGURING',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      mockPrisma.integration.create.mockResolvedValue(mockCreated);
      mockPrisma.integration.update.mockResolvedValue({
        ...mockCreated,
        status: 'ACTIVE',
      });

      const result = await service.createIntegration(
        'tenant-123',
        'user-123',
        createData
      );

      expect(result).toMatchObject({
        id: 'new-123',
        name: 'New Integration',
        type: 'WEBHOOK',
      });

      expect(mockPrisma.integration.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          tenantId: 'tenant-123',
          name: 'New Integration',
          type: 'WEBHOOK',
          status: 'CONFIGURING',
          createdBy: 'user-123',
        }),
      });
    });

    it('should encrypt authentication data', async () => {
      const createData: CreateIntegration = {
        name: 'Secure Integration',
        type: 'REST_API' as IntegrationType,
        authMethod: 'API_KEY',
        authentication: {
          apiKey: 'secret-key',
        },
      };

      mockPrisma.integration.create.mockResolvedValue({
        id: 'secure-123',
        tenantId: 'tenant-123',
        ...createData,
        authentication: 'encrypted-data',
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any);

      await service.createIntegration('tenant-123', 'user-123', createData);

      expect(mockPrisma.integration.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          authentication: expect.stringContaining('encrypted'),
        }),
      });
    });
  });

  describe('updateIntegration', () => {
    it('should update an existing integration', async () => {
      const existingIntegration = {
        id: 'existing-123',
        tenantId: 'tenant-123',
        name: 'Old Name',
        type: 'WEBHOOK',
        status: 'ACTIVE',
      };

      mockPrisma.integration.findFirst.mockResolvedValue(existingIntegration);
      mockPrisma.integration.update.mockResolvedValue({
        ...existingIntegration,
        name: 'New Name',
        updatedAt: new Date(),
      });

      const result = await service.updateIntegration(
        'tenant-123',
        'user-123',
        'existing-123',
        { name: 'New Name' }
      );

      expect(result?.name).toBe('New Name');
      expect(mockPrisma.integration.update).toHaveBeenCalledWith({
        where: { id: 'existing-123' },
        data: expect.objectContaining({
          name: 'New Name',
          updatedBy: 'user-123',
        }),
      });
    });

    it('should return null if integration not found', async () => {
      mockPrisma.integration.findFirst.mockResolvedValue(null);

      const result = await service.updateIntegration(
        'tenant-123',
        'user-123',
        'non-existent',
        { name: 'New Name' }
      );

      expect(result).toBeNull();
      expect(mockPrisma.integration.update).not.toHaveBeenCalled();
    });
  });

  describe('deleteIntegration', () => {
    it('should delete an integration and related data', async () => {
      const integration = {
        id: 'delete-123',
        tenantId: 'tenant-123',
        name: 'To Delete',
        type: 'WEBHOOK',
      };

      mockPrisma.integration.findFirst.mockResolvedValue(integration);
      mockPrisma.$transaction.mockImplementation(async (operations) => {
        for (const op of operations) {
          await op;
        }
      });
      mockRedis.keys.mockResolvedValue([]);

      await service.deleteIntegration('tenant-123', 'user-123', 'delete-123');

      expect(mockPrisma.webhook.deleteMany).toHaveBeenCalledWith({
        where: { integrationId: 'delete-123' },
      });
      expect(mockPrisma.integration.delete).toHaveBeenCalledWith({
        where: { id: 'delete-123' },
      });
    });

    it('should throw 404 if integration not found', async () => {
      mockPrisma.integration.findFirst.mockResolvedValue(null);

      await expect(
        service.deleteIntegration('tenant-123', 'user-123', 'non-existent')
      ).rejects.toThrow('Integration not found');
    });
  });

  describe('testIntegration', () => {
    it('should test webhook integration', async () => {
      const integration = {
        id: 'webhook-123',
        tenantId: 'tenant-123',
        type: 'WEBHOOK',
      };

      mockPrisma.integration.findFirst.mockResolvedValue(integration);

      const result = await service.testIntegration('tenant-123', 'webhook-123');

      expect(result).toEqual({
        success: true,
        message: 'Webhook configuration is valid',
      });
    });

    it('should return error for failed test', async () => {
      mockPrisma.integration.findFirst.mockResolvedValue(null);

      await expect(
        service.testIntegration('tenant-123', 'non-existent')
      ).rejects.toThrow('Integration not found');
    });
  });

  describe('getIntegrationHealth', () => {
    it('should return health status from cache if available', async () => {
      const cachedHealth = {
        status: 'healthy',
        lastCheck: new Date().toISOString(),
        responseTime: 100,
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(cachedHealth));

      const result = await service.getIntegrationHealth('tenant-123', 'int-123');

      expect(result.status).toBe('healthy');
      expect(mockRedis.get).toHaveBeenCalledWith('health:int-123');
    });

    it('should perform health check if not cached', async () => {
      const integration = {
        id: 'int-123',
        tenantId: 'tenant-123',
        type: 'WEBHOOK',
      };

      mockRedis.get.mockResolvedValue(null);
      mockPrisma.integration.findFirst.mockResolvedValue(integration);
      mockRedis.setex.mockResolvedValue('OK');

      const result = await service.getIntegrationHealth('tenant-123', 'int-123');

      expect(result.status).toBe('healthy');
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'health:int-123',
        300,
        expect.any(String)
      );
    });
  });

  describe('triggerSync', () => {
    it('should queue sync job for active integration', async () => {
      const integration = {
        id: 'ldap-123',
        tenantId: 'tenant-123',
        type: 'LDAP',
        status: 'ACTIVE',
      };

      mockPrisma.integration.findFirst.mockResolvedValue(integration);

      const jobId = await service.triggerSync('tenant-123', 'user-123', 'ldap-123', {
        syncType: 'full',
      });

      expect(jobId).toBeDefined();
      expect(mockPrisma.auditLog.create).toHaveBeenCalled();
    });

    it('should throw error for inactive integration', async () => {
      const integration = {
        id: 'ldap-123',
        tenantId: 'tenant-123',
        type: 'LDAP',
        status: 'INACTIVE',
      };

      mockPrisma.integration.findFirst.mockResolvedValue(integration);

      await expect(
        service.triggerSync('tenant-123', 'user-123', 'ldap-123', {
          syncType: 'full',
        })
      ).rejects.toThrow('Integration is not active');
    });
  });
});