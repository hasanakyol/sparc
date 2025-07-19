import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { logger } from '@sparc/shared';
import { 
  PluginInstance,
  CreatePluginInstance,
  UpdatePluginInstance,
  PluginExecutionContext,
  PluginExecutionResult,
  PluginStatus,
  PluginType
} from '../types';
import crypto from 'crypto';
import { HTTPException } from 'hono/http-exception';
import { VM } from 'vm2'; // In production, use proper sandboxing
import { validate } from 'jsonschema';

export class PluginService {
  private pluginCache: Map<string, any> = new Map();

  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async listInstalledPlugins(
    tenantId: string,
    options: {
      page: number;
      limit: number;
      status?: PluginStatus;
      type?: PluginType;
      search?: string;
    }
  ) {
    const offset = (options.page - 1) * options.limit;

    const where: any = { tenantId };
    
    if (options.status) {
      where.status = options.status;
    }
    
    if (options.type) {
      where.plugin = { type: options.type };
    }
    
    if (options.search) {
      where.OR = [
        { name: { contains: options.search, mode: 'insensitive' } },
        { description: { contains: options.search, mode: 'insensitive' } }
      ];
    }

    const [instances, total] = await Promise.all([
      this.prisma.pluginInstance.findMany({
        where,
        skip: offset,
        take: options.limit,
        orderBy: { createdAt: 'desc' },
        include: {
          plugin: {
            select: {
              id: true,
              name: true,
              version: true,
              type: true,
              runtime: true,
              manifest: true
            }
          }
        }
      }),
      this.prisma.pluginInstance.count({ where })
    ]);

    return {
      data: instances,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        totalPages: Math.ceil(total / options.limit)
      }
    };
  }

  async installPlugin(
    tenantId: string,
    userId: string,
    data: CreatePluginInstance
  ): Promise<PluginInstance> {
    // Verify plugin exists
    const plugin = await this.prisma.plugin.findUnique({
      where: { id: data.pluginId }
    });

    if (!plugin) {
      throw new HTTPException(404, { message: 'Plugin not found' });
    }

    // Validate configuration against schema
    if (plugin.manifest?.configuration?.schema) {
      const validation = validate(
        data.configuration,
        plugin.manifest.configuration.schema
      );
      
      if (!validation.valid) {
        throw new HTTPException(400, { 
          message: 'Invalid configuration',
          cause: validation.errors 
        });
      }
    }

    // Create instance
    const instance = await this.prisma.pluginInstance.create({
      data: {
        id: crypto.randomUUID(),
        tenantId,
        pluginId: data.pluginId,
        name: data.name,
        description: data.description,
        version: plugin.version,
        status: 'INSTALLED',
        configuration: data.configuration || {},
        metadata: {},
        installedAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date()
      },
      include: {
        plugin: true
      }
    });

    // Log audit
    await this.logAudit(tenantId, userId, 'PLUGIN_INSTALLED', instance.id, {
      pluginId: plugin.id,
      pluginName: plugin.name
    });

    return instance as PluginInstance;
  }

  async getPluginInstance(
    tenantId: string,
    instanceId: string
  ): Promise<PluginInstance | null> {
    const instance = await this.prisma.pluginInstance.findFirst({
      where: {
        id: instanceId,
        tenantId
      },
      include: {
        plugin: true
      }
    });

    return instance as PluginInstance | null;
  }

  async updatePluginInstance(
    tenantId: string,
    instanceId: string,
    data: UpdatePluginInstance
  ): Promise<PluginInstance | null> {
    const existing = await this.prisma.pluginInstance.findFirst({
      where: {
        id: instanceId,
        tenantId
      },
      include: {
        plugin: true
      }
    });

    if (!existing) {
      return null;
    }

    // Validate new configuration if provided
    if (data.configuration && existing.plugin.manifest?.configuration?.schema) {
      const validation = validate(
        data.configuration,
        existing.plugin.manifest.configuration.schema
      );
      
      if (!validation.valid) {
        throw new HTTPException(400, { 
          message: 'Invalid configuration',
          cause: validation.errors 
        });
      }
    }

    const updated = await this.prisma.pluginInstance.update({
      where: { id: instanceId },
      data: {
        ...data,
        updatedAt: new Date()
      },
      include: {
        plugin: true
      }
    });

    // Clear cache
    this.pluginCache.delete(instanceId);

    return updated as PluginInstance;
  }

  async uninstallPlugin(
    tenantId: string,
    userId: string,
    instanceId: string
  ): Promise<void> {
    const instance = await this.prisma.pluginInstance.findFirst({
      where: {
        id: instanceId,
        tenantId
      }
    });

    if (!instance) {
      throw new HTTPException(404, { message: 'Plugin instance not found' });
    }

    await this.prisma.pluginInstance.delete({
      where: { id: instanceId }
    });

    // Clear cache
    this.pluginCache.delete(instanceId);

    // Log audit
    await this.logAudit(tenantId, userId, 'PLUGIN_UNINSTALLED', instanceId, {
      pluginId: instance.pluginId
    });
  }

  async executePlugin(
    context: PluginExecutionContext
  ): Promise<PluginExecutionResult> {
    const startTime = Date.now();
    const logs: any[] = [];

    try {
      // Get plugin instance
      const instance = await this.getPluginInstance(
        context.tenantId,
        context.instanceId
      );

      if (!instance) {
        throw new Error('Plugin instance not found');
      }

      if (instance.status !== 'ACTIVE') {
        throw new Error('Plugin is not active');
      }

      // Load plugin code
      const pluginCode = await this.loadPluginCode(instance);

      // Merge configuration
      const fullContext = {
        ...context,
        configuration: {
          ...instance.configuration,
          ...context.configuration
        }
      };

      // Execute based on runtime
      let result: any;
      switch (instance.plugin.runtime) {
        case 'JAVASCRIPT':
          result = await this.executeJavaScript(
            pluginCode,
            fullContext,
            logs
          );
          break;
        
        case 'WEBASSEMBLY':
          result = await this.executeWebAssembly(
            pluginCode,
            fullContext,
            logs
          );
          break;
        
        default:
          throw new Error(`Unsupported runtime: ${instance.plugin.runtime}`);
      }

      // Update execution count
      await this.prisma.pluginInstance.update({
        where: { id: instance.id },
        data: {
          lastExecuted: new Date(),
          executionCount: { increment: 1 }
        }
      });

      // Log execution
      await this.logExecution(instance.id, context, result, logs, Date.now() - startTime);

      return {
        success: true,
        output: result,
        metrics: {
          executionTime: Date.now() - startTime
        },
        logs,
        duration: Date.now() - startTime
      };

    } catch (error) {
      logger.error('Plugin execution failed', { 
        instanceId: context.instanceId, 
        error 
      });

      // Update error count
      await this.prisma.pluginInstance.update({
        where: { id: context.instanceId },
        data: {
          errorCount: { increment: 1 },
          lastError: error.message
        }
      });

      // Log failed execution
      await this.logExecution(
        context.instanceId, 
        context, 
        null, 
        logs, 
        Date.now() - startTime,
        error.message
      );

      return {
        success: false,
        error: error.message,
        logs,
        duration: Date.now() - startTime
      };
    }
  }

  async activatePlugin(
    tenantId: string,
    instanceId: string
  ): Promise<void> {
    await this.updatePluginStatus(tenantId, instanceId, 'ACTIVE');
  }

  async deactivatePlugin(
    tenantId: string,
    instanceId: string
  ): Promise<void> {
    await this.updatePluginStatus(tenantId, instanceId, 'INACTIVE');
  }

  async getPluginConfigSchema(
    tenantId: string,
    instanceId: string
  ): Promise<any> {
    const instance = await this.getPluginInstance(tenantId, instanceId);
    
    if (!instance) {
      throw new HTTPException(404, { message: 'Plugin instance not found' });
    }

    return instance.plugin.manifest?.configuration?.schema || {};
  }

  async validatePluginConfig(
    tenantId: string,
    instanceId: string,
    config: any
  ): Promise<{ valid: boolean; errors?: any[] }> {
    const schema = await this.getPluginConfigSchema(tenantId, instanceId);
    const validation = validate(config, schema);

    return {
      valid: validation.valid,
      errors: validation.errors
    };
  }

  async getPluginExecutions(
    tenantId: string,
    instanceId: string,
    options: {
      page: number;
      limit: number;
      status?: 'SUCCESS' | 'FAILED';
    }
  ) {
    const instance = await this.getPluginInstance(tenantId, instanceId);
    
    if (!instance) {
      throw new HTTPException(404, { message: 'Plugin instance not found' });
    }

    const offset = (options.page - 1) * options.limit;
    const where: any = { pluginInstanceId: instanceId };
    
    if (options.status) {
      where.success = options.status === 'SUCCESS';
    }

    const [executions, total] = await Promise.all([
      this.prisma.pluginExecution.findMany({
        where,
        skip: offset,
        take: options.limit,
        orderBy: { createdAt: 'desc' }
      }),
      this.prisma.pluginExecution.count({ where })
    ]);

    return {
      data: executions,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        totalPages: Math.ceil(total / options.limit)
      }
    };
  }

  async getPluginMetrics(
    tenantId: string,
    instanceId: string,
    period: 'hour' | 'day' | 'week' | 'month'
  ): Promise<any> {
    const instance = await this.getPluginInstance(tenantId, instanceId);
    
    if (!instance) {
      throw new HTTPException(404, { message: 'Plugin instance not found' });
    }

    // This would aggregate from time-series data
    // For now, return basic metrics
    return {
      instanceId,
      period,
      totalExecutions: instance.executionCount,
      successfulExecutions: instance.executionCount - instance.errorCount,
      failedExecutions: instance.errorCount,
      averageExecutionTime: 150, // milliseconds
      lastExecuted: instance.lastExecuted
    };
  }

  async resetPluginState(
    tenantId: string,
    instanceId: string
  ): Promise<void> {
    const instance = await this.getPluginInstance(tenantId, instanceId);
    
    if (!instance) {
      throw new HTTPException(404, { message: 'Plugin instance not found' });
    }

    await this.prisma.pluginInstance.update({
      where: { id: instanceId },
      data: {
        executionCount: 0,
        errorCount: 0,
        lastError: null,
        lastExecuted: null,
        metadata: {}
      }
    });

    // Clear cache
    this.pluginCache.delete(instanceId);
  }

  async getPluginLogs(
    tenantId: string,
    instanceId: string,
    options: {
      page: number;
      limit: number;
      level?: 'debug' | 'info' | 'warn' | 'error';
      startTime?: Date;
      endTime?: Date;
    }
  ): Promise<any> {
    // This would query from a log storage system
    // For now, return mock data
    return {
      data: [],
      pagination: {
        page: options.page,
        limit: options.limit,
        total: 0,
        totalPages: 0
      }
    };
  }

  // Private helper methods

  private async updatePluginStatus(
    tenantId: string,
    instanceId: string,
    status: PluginStatus
  ): Promise<void> {
    const instance = await this.getPluginInstance(tenantId, instanceId);
    
    if (!instance) {
      throw new HTTPException(404, { message: 'Plugin instance not found' });
    }

    await this.prisma.pluginInstance.update({
      where: { id: instanceId },
      data: {
        status,
        activatedAt: status === 'ACTIVE' ? new Date() : undefined
      }
    });
  }

  private async loadPluginCode(instance: any): Promise<string> {
    // Check cache
    if (this.pluginCache.has(instance.id)) {
      return this.pluginCache.get(instance.id);
    }

    // Load from storage
    const code = await this.prisma.pluginCode.findUnique({
      where: { 
        pluginId_version: {
          pluginId: instance.pluginId,
          version: instance.version
        }
      }
    });

    if (!code) {
      throw new Error('Plugin code not found');
    }

    // Cache for future use
    this.pluginCache.set(instance.id, code.code);

    return code.code;
  }

  private async executeJavaScript(
    code: string,
    context: PluginExecutionContext,
    logs: any[]
  ): Promise<any> {
    // Create sandboxed environment
    const vm = new VM({
      timeout: 30000, // 30 seconds
      sandbox: {
        context,
        console: {
          log: (...args: any[]) => logs.push({ 
            level: 'info', 
            message: args.join(' '), 
            timestamp: new Date() 
          }),
          error: (...args: any[]) => logs.push({ 
            level: 'error', 
            message: args.join(' '), 
            timestamp: new Date() 
          }),
          warn: (...args: any[]) => logs.push({ 
            level: 'warn', 
            message: args.join(' '), 
            timestamp: new Date() 
          }),
          debug: (...args: any[]) => logs.push({ 
            level: 'debug', 
            message: args.join(' '), 
            timestamp: new Date() 
          })
        },
        // Provide limited APIs
        fetch: undefined, // Would provide controlled fetch
        crypto: {
          randomUUID: () => crypto.randomUUID()
        }
      }
    });

    // Execute plugin
    return vm.run(code);
  }

  private async executeWebAssembly(
    code: string,
    context: PluginExecutionContext,
    logs: any[]
  ): Promise<any> {
    // WebAssembly execution would go here
    throw new Error('WebAssembly runtime not implemented');
  }

  private async logExecution(
    instanceId: string,
    context: PluginExecutionContext,
    result: any,
    logs: any[],
    duration: number,
    error?: string
  ): Promise<void> {
    await this.prisma.pluginExecution.create({
      data: {
        id: crypto.randomUUID(),
        pluginInstanceId: instanceId,
        context,
        result,
        logs,
        duration,
        success: !error,
        error,
        createdAt: new Date()
      }
    });
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
          resourceType: 'PLUGIN',
          resourceId,
          details,
          ipAddress: '0.0.0.0',
          userAgent: 'integration-service',
          createdAt: new Date()
        }
      });
    } catch (error) {
      logger.error('Failed to create audit log', { error });
    }
  }
}