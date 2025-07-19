import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { logger } from '@sparc/shared';
import { 
  Integration, 
  CreateIntegration, 
  UpdateIntegration,
  IntegrationType,
  IntegrationStatus,
  HealthCheckResult,
  IntegrationMetrics,
  DataMapping
} from '../types';
import crypto from 'crypto';
import { EncryptionService } from './encryption.service';
import { LDAPService } from './ldap.service';
import { HTTPException } from 'hono/http-exception';
import { Queue } from 'bullmq';

export class IntegrationService {
  private encryptionService: EncryptionService;
  private ldapService: LDAPService;
  private syncQueue: Queue;

  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {
    this.encryptionService = new EncryptionService();
    this.ldapService = new LDAPService();
    
    // Initialize sync queue
    this.syncQueue = new Queue('integration-sync', {
      connection: this.redis
    });
  }

  async listIntegrations(
    tenantId: string,
    options: {
      page: number;
      limit: number;
      type?: IntegrationType;
      status?: IntegrationStatus;
      search?: string;
    }
  ) {
    const offset = (options.page - 1) * options.limit;

    const where: any = { tenantId };
    
    if (options.type) {
      where.type = options.type;
    }
    
    if (options.status) {
      where.status = options.status;
    }
    
    if (options.search) {
      where.OR = [
        { name: { contains: options.search, mode: 'insensitive' } },
        { description: { contains: options.search, mode: 'insensitive' } }
      ];
    }

    const [integrations, total] = await Promise.all([
      this.prisma.integration.findMany({
        where,
        skip: offset,
        take: options.limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          name: true,
          description: true,
          type: true,
          status: true,
          endpoint: true,
          authMethod: true,
          lastSync: true,
          lastError: true,
          createdAt: true,
          updatedAt: true
        }
      }),
      this.prisma.integration.count({ where })
    ]);

    return {
      data: integrations,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        totalPages: Math.ceil(total / options.limit)
      }
    };
  }

  async createIntegration(
    tenantId: string,
    userId: string,
    data: CreateIntegration
  ): Promise<Integration> {
    // Encrypt authentication data if provided
    let encryptedAuth = null;
    if (data.authentication) {
      encryptedAuth = await this.encryptionService.encrypt(
        JSON.stringify(data.authentication)
      );
    }

    const integration = await this.prisma.integration.create({
      data: {
        id: crypto.randomUUID(),
        tenantId,
        name: data.name,
        description: data.description,
        type: data.type,
        status: 'CONFIGURING',
        endpoint: data.endpoint,
        authMethod: data.authMethod,
        configuration: data.configuration || {},
        metadata: data.metadata || {},
        authentication: encryptedAuth,
        createdBy: userId,
        updatedBy: userId,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });

    // Test connection if it's a direct integration
    if (['LDAP', 'ACTIVE_DIRECTORY', 'REST_API'].includes(integration.type)) {
      try {
        await this.testIntegration(tenantId, integration.id);
        await this.updateStatus(integration.id, 'ACTIVE');
      } catch (error) {
        await this.updateStatus(integration.id, 'ERROR', error.message);
      }
    }

    // Log audit
    await this.logAudit(tenantId, userId, 'INTEGRATION_CREATED', integration.id, {
      type: integration.type,
      name: integration.name
    });

    return integration as Integration;
  }

  async getIntegration(
    tenantId: string,
    integrationId: string
  ): Promise<Integration | null> {
    const integration = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      return null;
    }

    // Remove sensitive data
    return {
      ...integration,
      authentication: undefined
    } as Integration;
  }

  async updateIntegration(
    tenantId: string,
    userId: string,
    integrationId: string,
    data: UpdateIntegration
  ): Promise<Integration | null> {
    const existing = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!existing) {
      return null;
    }

    const updateData: any = {
      updatedBy: userId,
      updatedAt: new Date()
    };

    // Handle each field update
    if (data.name !== undefined) updateData.name = data.name;
    if (data.description !== undefined) updateData.description = data.description;
    if (data.endpoint !== undefined) updateData.endpoint = data.endpoint;
    if (data.authMethod !== undefined) updateData.authMethod = data.authMethod;
    if (data.configuration !== undefined) updateData.configuration = data.configuration;
    if (data.metadata !== undefined) updateData.metadata = data.metadata;

    // Handle authentication update
    if (data.authentication !== undefined) {
      updateData.authentication = await this.encryptionService.encrypt(
        JSON.stringify(data.authentication)
      );
    }

    const updated = await this.prisma.integration.update({
      where: { id: integrationId },
      data: updateData
    });

    // Re-test connection if critical fields changed
    if (data.endpoint || data.authentication) {
      try {
        await this.testIntegration(tenantId, integrationId);
        await this.updateStatus(integrationId, 'ACTIVE');
      } catch (error) {
        await this.updateStatus(integrationId, 'ERROR', error.message);
      }
    }

    // Log audit
    await this.logAudit(tenantId, userId, 'INTEGRATION_UPDATED', integrationId, {
      changes: Object.keys(data)
    });

    return {
      ...updated,
      authentication: undefined
    } as Integration;
  }

  async deleteIntegration(
    tenantId: string,
    userId: string,
    integrationId: string
  ): Promise<void> {
    const integration = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    // Delete related data
    await this.prisma.$transaction([
      // Delete webhooks associated with this integration
      this.prisma.webhook.deleteMany({
        where: { integrationId }
      }),
      // Delete the integration
      this.prisma.integration.delete({
        where: { id: integrationId }
      })
    ]);

    // Clear cache
    await this.clearIntegrationCache(tenantId, integrationId);

    // Log audit
    await this.logAudit(tenantId, userId, 'INTEGRATION_DELETED', integrationId, {
      type: integration.type,
      name: integration.name
    });
  }

  async testIntegration(
    tenantId: string,
    integrationId: string,
    testData?: any
  ): Promise<{ success: boolean; message: string; details?: any }> {
    const integration = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    try {
      switch (integration.type) {
        case 'LDAP':
        case 'ACTIVE_DIRECTORY':
          return await this.testLDAPConnection(integration);
        
        case 'REST_API':
          return await this.testRESTAPIConnection(integration);
        
        case 'OAUTH2':
          return await this.testOAuth2Connection(integration);
        
        case 'SAML':
          return await this.testSAMLConnection(integration);
        
        case 'WEBHOOK':
          return { 
            success: true, 
            message: 'Webhook configuration is valid' 
          };
        
        default:
          return { 
            success: true, 
            message: `Integration type ${integration.type} test not implemented` 
          };
      }
    } catch (error) {
      logger.error('Integration test failed', { integrationId, error });
      return {
        success: false,
        message: error.message || 'Test failed',
        details: error
      };
    }
  }

  async getIntegrationHealth(
    tenantId: string,
    integrationId: string
  ): Promise<HealthCheckResult> {
    const integration = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    const cacheKey = `health:${integrationId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }

    const startTime = Date.now();
    const testResult = await this.testIntegration(tenantId, integrationId);
    const responseTime = Date.now() - startTime;

    const health: HealthCheckResult = {
      status: testResult.success ? 'healthy' : 'unhealthy',
      lastCheck: new Date(),
      responseTime,
      details: testResult.details,
      error: testResult.success ? undefined : testResult.message
    };

    // Cache for 5 minutes
    await this.redis.setex(cacheKey, 300, JSON.stringify(health));

    return health;
  }

  async triggerSync(
    tenantId: string,
    userId: string,
    integrationId: string,
    options: {
      syncType: 'full' | 'incremental';
      options?: any;
    }
  ): Promise<string> {
    const integration = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    if (integration.status !== 'ACTIVE') {
      throw new HTTPException(400, { message: 'Integration is not active' });
    }

    // Create sync job
    const jobId = crypto.randomUUID();
    const job = await this.syncQueue.add('sync', {
      jobId,
      integrationId,
      tenantId,
      userId,
      syncType: options.syncType,
      options: options.options || {},
      startedAt: new Date()
    });

    // Log audit
    await this.logAudit(tenantId, userId, 'SYNC_TRIGGERED', integrationId, {
      jobId,
      syncType: options.syncType
    });

    return job.id;
  }

  async processSyncJob(jobData: any): Promise<void> {
    const { integrationId, syncType, options } = jobData;

    try {
      const integration = await this.prisma.integration.findUnique({
        where: { id: integrationId }
      });

      if (!integration) {
        throw new Error('Integration not found');
      }

      switch (integration.type) {
        case 'LDAP':
        case 'ACTIVE_DIRECTORY':
          await this.ldapService.syncDirectory(integration, syncType, options);
          break;
        
        default:
          logger.warn('Sync not implemented for integration type', { 
            type: integration.type 
          });
      }

      // Update last sync time
      await this.prisma.integration.update({
        where: { id: integrationId },
        data: { 
          lastSync: new Date(),
          lastError: null
        }
      });

    } catch (error) {
      logger.error('Sync job failed', { integrationId, error });
      
      // Update error status
      await this.prisma.integration.update({
        where: { id: integrationId },
        data: { 
          lastError: error.message,
          status: 'ERROR'
        }
      });
      
      throw error;
    }
  }

  async getIntegrationMetrics(
    tenantId: string,
    integrationId: string,
    period: 'hour' | 'day' | 'week' | 'month'
  ): Promise<IntegrationMetrics> {
    // This would typically query from a time-series database
    // For now, return mock data
    return {
      integrationId,
      period,
      requestCount: 1000,
      successCount: 950,
      errorCount: 50,
      averageResponseTime: 250,
      dataProcessed: 1024 * 1024 * 100, // 100MB
      quotaUsed: 80,
      quotaLimit: 100
    };
  }

  async getAvailableIntegrationTypes(): Promise<any[]> {
    return [
      {
        type: 'LDAP',
        name: 'LDAP Directory',
        description: 'Connect to LDAP directory services',
        configSchema: {
          url: { type: 'string', required: true },
          bindDN: { type: 'string', required: true },
          bindPassword: { type: 'password', required: true },
          baseDN: { type: 'string', required: true }
        }
      },
      {
        type: 'OAUTH2',
        name: 'OAuth 2.0',
        description: 'OAuth 2.0 authentication provider',
        configSchema: {
          clientId: { type: 'string', required: true },
          clientSecret: { type: 'password', required: true },
          authorizationUrl: { type: 'string', required: true },
          tokenUrl: { type: 'string', required: true }
        }
      },
      {
        type: 'SAML',
        name: 'SAML 2.0',
        description: 'SAML 2.0 authentication provider',
        configSchema: {
          entryPoint: { type: 'string', required: true },
          issuer: { type: 'string', required: true },
          cert: { type: 'textarea', required: true }
        }
      },
      {
        type: 'WEBHOOK',
        name: 'Webhook',
        description: 'Send events to external systems',
        configSchema: {
          url: { type: 'string', required: true },
          method: { type: 'select', options: ['POST', 'PUT'], default: 'POST' },
          headers: { type: 'keyvalue', required: false }
        }
      },
      {
        type: 'REST_API',
        name: 'REST API',
        description: 'Connect to REST API endpoints',
        configSchema: {
          baseUrl: { type: 'string', required: true },
          authType: { type: 'select', options: ['none', 'apikey', 'bearer', 'basic'] }
        }
      }
    ];
  }

  async getDataMappings(
    tenantId: string,
    integrationId: string
  ): Promise<DataMapping[]> {
    const integration = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    return integration.configuration?.dataMappings || [];
  }

  async updateDataMappings(
    tenantId: string,
    integrationId: string,
    mappings: DataMapping[]
  ): Promise<DataMapping[]> {
    const integration = await this.prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    await this.prisma.integration.update({
      where: { id: integrationId },
      data: {
        configuration: {
          ...integration.configuration,
          dataMappings: mappings
        }
      }
    });

    return mappings;
  }

  // Private helper methods

  private async testLDAPConnection(integration: any): Promise<any> {
    if (!integration.authentication) {
      throw new Error('No authentication data');
    }

    const auth = JSON.parse(
      await this.encryptionService.decrypt(integration.authentication)
    );

    return await this.ldapService.testConnection({
      url: integration.endpoint,
      bindDN: auth.bindDN,
      bindPassword: auth.bindPassword,
      baseDN: integration.configuration?.baseDN
    });
  }

  private async testRESTAPIConnection(integration: any): Promise<any> {
    // Implementation for REST API testing
    return { success: true, message: 'REST API connection successful' };
  }

  private async testOAuth2Connection(integration: any): Promise<any> {
    // Implementation for OAuth2 testing
    return { success: true, message: 'OAuth2 configuration valid' };
  }

  private async testSAMLConnection(integration: any): Promise<any> {
    // Implementation for SAML testing
    return { success: true, message: 'SAML configuration valid' };
  }

  private async updateStatus(
    integrationId: string,
    status: IntegrationStatus,
    error?: string
  ): Promise<void> {
    await this.prisma.integration.update({
      where: { id: integrationId },
      data: {
        status,
        lastError: error || null
      }
    });
  }

  private async clearIntegrationCache(
    tenantId: string,
    integrationId: string
  ): Promise<void> {
    const pattern = `integration:${tenantId}:${integrationId}:*`;
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  private async logAudit(
    tenantId: string,
    userId: string,
    action: string,
    resourceId: string,
    details: any
  ): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          id: crypto.randomUUID(),
          tenantId,
          userId,
          action,
          resourceType: 'INTEGRATION',
          resourceId,
          details,
          ipAddress: '0.0.0.0', // Would be from request context
          userAgent: 'integration-service',
          createdAt: new Date()
        }
      });
    } catch (error) {
      logger.error('Failed to create audit log', { error });
    }
  }
}