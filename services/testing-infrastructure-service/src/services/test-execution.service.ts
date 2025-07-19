import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  TestConfig,
  TestExecution,
  TestStatus,
  TestLog,
  LogLevel,
  TestArtifact,
  TestResults,
} from '../types';

export class TestExecutionService extends EventEmitter {
  private executions: Map<string, TestExecution> = new Map();
  
  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {
    super();
    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.on('execution:started', async (execution) => {
      await this.publishEvent('test.execution.started', execution);
    });

    this.on('execution:completed', async (execution) => {
      await this.publishEvent('test.execution.completed', execution);
    });

    this.on('execution:failed', async (execution) => {
      await this.publishEvent('test.execution.failed', execution);
    });

    this.on('execution:cancelled', async (execution) => {
      await this.publishEvent('test.execution.cancelled', execution);
    });
  }

  async createExecution(config: TestConfig, triggeredBy: string): Promise<TestExecution> {
    const executionId = uuidv4();
    const execution: TestExecution = {
      id: executionId,
      testId: config.name,
      type: config.type,
      status: TestStatus.PENDING,
      startTime: new Date(),
      logs: [],
      artifacts: [],
      retryCount: 0,
      environment: config.environment,
      tenantId: config.tenantId,
      tags: config.tags,
      triggeredBy,
    };

    // Store in memory
    this.executions.set(executionId, execution);

    // Store in database
    await this.prisma.testExecution.create({
      data: {
        id: executionId,
        testId: config.name,
        type: config.type,
        status: TestStatus.PENDING,
        startTime: execution.startTime,
        environment: config.environment,
        tenantId: config.tenantId,
        tags: config.tags,
        triggeredBy,
        config: JSON.stringify(config),
      },
    });

    // Cache in Redis
    await this.redis.setex(
      `execution:${executionId}`,
      3600, // 1 hour TTL
      JSON.stringify(execution)
    );

    return execution;
  }

  async updateExecution(
    executionId: string,
    updates: Partial<TestExecution>
  ): Promise<TestExecution> {
    const execution = await this.getExecution(executionId);
    if (!execution) {
      throw new Error(`Execution ${executionId} not found`);
    }

    // Update in memory
    Object.assign(execution, updates);
    this.executions.set(executionId, execution);

    // Update in database
    await this.prisma.testExecution.update({
      where: { id: executionId },
      data: {
        status: updates.status,
        endTime: updates.endTime,
        duration: updates.duration,
        results: updates.results ? JSON.stringify(updates.results) : undefined,
        metrics: updates.metrics ? JSON.stringify(updates.metrics) : undefined,
        error: updates.error,
        retryCount: updates.retryCount,
      },
    });

    // Update cache
    await this.redis.setex(
      `execution:${executionId}`,
      3600,
      JSON.stringify(execution)
    );

    // Emit events based on status
    if (updates.status === TestStatus.RUNNING) {
      this.emit('execution:started', execution);
    } else if (updates.status === TestStatus.COMPLETED) {
      this.emit('execution:completed', execution);
    } else if (updates.status === TestStatus.FAILED) {
      this.emit('execution:failed', execution);
    } else if (updates.status === TestStatus.CANCELLED) {
      this.emit('execution:cancelled', execution);
    }

    return execution;
  }

  async getExecution(executionId: string): Promise<TestExecution | null> {
    // Check memory first
    if (this.executions.has(executionId)) {
      return this.executions.get(executionId)!;
    }

    // Check cache
    const cached = await this.redis.get(`execution:${executionId}`);
    if (cached) {
      const execution = JSON.parse(cached);
      this.executions.set(executionId, execution);
      return execution;
    }

    // Check database
    const dbExecution = await this.prisma.testExecution.findUnique({
      where: { id: executionId },
      include: {
        logs: true,
        artifacts: true,
      },
    });

    if (!dbExecution) {
      return null;
    }

    const execution: TestExecution = {
      id: dbExecution.id,
      testId: dbExecution.testId,
      type: dbExecution.type as any,
      status: dbExecution.status as TestStatus,
      startTime: dbExecution.startTime,
      endTime: dbExecution.endTime || undefined,
      duration: dbExecution.duration || undefined,
      results: dbExecution.results ? JSON.parse(dbExecution.results) : undefined,
      logs: dbExecution.logs.map((log: any) => ({
        timestamp: log.timestamp,
        level: log.level as LogLevel,
        message: log.message,
        data: log.data ? JSON.parse(log.data) : undefined,
      })),
      metrics: dbExecution.metrics ? JSON.parse(dbExecution.metrics) : undefined,
      artifacts: dbExecution.artifacts.map((artifact: any) => ({
        id: artifact.id,
        type: artifact.type,
        name: artifact.name,
        path: artifact.path,
        size: artifact.size,
        mimeType: artifact.mimeType,
        createdAt: artifact.createdAt,
      })),
      error: dbExecution.error || undefined,
      retryCount: dbExecution.retryCount,
      environment: dbExecution.environment as any,
      tenantId: dbExecution.tenantId || undefined,
      tags: dbExecution.tags,
      triggeredBy: dbExecution.triggeredBy,
      commitSha: dbExecution.commitSha || undefined,
      branch: dbExecution.branch || undefined,
    };

    // Store in memory and cache
    this.executions.set(executionId, execution);
    await this.redis.setex(
      `execution:${executionId}`,
      3600,
      JSON.stringify(execution)
    );

    return execution;
  }

  async addLog(
    executionId: string,
    level: LogLevel,
    message: string,
    data?: any
  ): Promise<void> {
    const log: TestLog = {
      timestamp: new Date(),
      level,
      message,
      data,
    };

    // Update in memory
    const execution = await this.getExecution(executionId);
    if (execution) {
      execution.logs.push(log);
      this.executions.set(executionId, execution);
    }

    // Store in database
    await this.prisma.testLog.create({
      data: {
        executionId,
        timestamp: log.timestamp,
        level,
        message,
        data: data ? JSON.stringify(data) : undefined,
      },
    });

    // Publish log event
    await this.publishEvent('test.log', {
      executionId,
      log,
    });
  }

  async addArtifact(
    executionId: string,
    artifact: Omit<TestArtifact, 'id' | 'createdAt'>
  ): Promise<TestArtifact> {
    const artifactId = uuidv4();
    const fullArtifact: TestArtifact = {
      id: artifactId,
      ...artifact,
      createdAt: new Date(),
    };

    // Update in memory
    const execution = await this.getExecution(executionId);
    if (execution) {
      execution.artifacts.push(fullArtifact);
      this.executions.set(executionId, execution);
    }

    // Store in database
    await this.prisma.testArtifact.create({
      data: {
        id: artifactId,
        executionId,
        type: artifact.type,
        name: artifact.name,
        path: artifact.path,
        size: artifact.size,
        mimeType: artifact.mimeType,
        createdAt: fullArtifact.createdAt,
      },
    });

    return fullArtifact;
  }

  async listExecutions(filters: {
    type?: string;
    status?: TestStatus;
    environment?: string;
    tenantId?: string;
    tags?: string[];
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  }): Promise<{ executions: TestExecution[]; total: number }> {
    const where: any = {};

    if (filters.type) where.type = filters.type;
    if (filters.status) where.status = filters.status;
    if (filters.environment) where.environment = filters.environment;
    if (filters.tenantId) where.tenantId = filters.tenantId;
    if (filters.tags && filters.tags.length > 0) {
      where.tags = { hasSome: filters.tags };
    }
    if (filters.startDate || filters.endDate) {
      where.startTime = {};
      if (filters.startDate) where.startTime.gte = filters.startDate;
      if (filters.endDate) where.startTime.lte = filters.endDate;
    }

    const [executions, total] = await Promise.all([
      this.prisma.testExecution.findMany({
        where,
        orderBy: { startTime: 'desc' },
        take: filters.limit || 50,
        skip: filters.offset || 0,
        include: {
          logs: {
            orderBy: { timestamp: 'desc' },
            take: 10,
          },
          artifacts: true,
        },
      }),
      this.prisma.testExecution.count({ where }),
    ]);

    return {
      executions: executions.map((e) => this.mapDbExecutionToExecution(e)),
      total,
    };
  }

  async cancelExecution(executionId: string): Promise<void> {
    const execution = await this.getExecution(executionId);
    if (!execution) {
      throw new Error(`Execution ${executionId} not found`);
    }

    if (execution.status !== TestStatus.RUNNING) {
      throw new Error(`Execution ${executionId} is not running`);
    }

    await this.updateExecution(executionId, {
      status: TestStatus.CANCELLED,
      endTime: new Date(),
      duration: Date.now() - execution.startTime.getTime(),
    });

    await this.addLog(
      executionId,
      LogLevel.INFO,
      'Test execution cancelled by user'
    );
  }

  async cancelAllRunningTests(): Promise<void> {
    const runningExecutions = await this.prisma.testExecution.findMany({
      where: { status: TestStatus.RUNNING },
    });

    for (const execution of runningExecutions) {
      await this.cancelExecution(execution.id);
    }
  }

  async retryExecution(executionId: string): Promise<string> {
    const originalExecution = await this.getExecution(executionId);
    if (!originalExecution) {
      throw new Error(`Execution ${executionId} not found`);
    }

    const configStr = await this.prisma.testExecution.findUnique({
      where: { id: executionId },
      select: { config: true },
    });

    if (!configStr?.config) {
      throw new Error(`No config found for execution ${executionId}`);
    }

    const config: TestConfig = JSON.parse(configStr.config);
    const newExecution = await this.createExecution(
      config,
      `retry:${originalExecution.triggeredBy}`
    );

    await this.updateExecution(newExecution.id, {
      retryCount: originalExecution.retryCount + 1,
    });

    return newExecution.id;
  }

  private mapDbExecutionToExecution(dbExecution: any): TestExecution {
    return {
      id: dbExecution.id,
      testId: dbExecution.testId,
      type: dbExecution.type,
      status: dbExecution.status,
      startTime: dbExecution.startTime,
      endTime: dbExecution.endTime,
      duration: dbExecution.duration,
      results: dbExecution.results ? JSON.parse(dbExecution.results) : undefined,
      logs: dbExecution.logs.map((log: any) => ({
        timestamp: log.timestamp,
        level: log.level,
        message: log.message,
        data: log.data ? JSON.parse(log.data) : undefined,
      })),
      metrics: dbExecution.metrics ? JSON.parse(dbExecution.metrics) : undefined,
      artifacts: dbExecution.artifacts.map((artifact: any) => ({
        id: artifact.id,
        type: artifact.type,
        name: artifact.name,
        path: artifact.path,
        size: artifact.size,
        mimeType: artifact.mimeType,
        createdAt: artifact.createdAt,
      })),
      error: dbExecution.error,
      retryCount: dbExecution.retryCount,
      environment: dbExecution.environment,
      tenantId: dbExecution.tenantId,
      tags: dbExecution.tags,
      triggeredBy: dbExecution.triggeredBy,
      commitSha: dbExecution.commitSha,
      branch: dbExecution.branch,
    };
  }

  private async publishEvent(event: string, data: any): Promise<void> {
    await this.redis.publish(
      `testing-infrastructure:${event}`,
      JSON.stringify({
        timestamp: new Date().toISOString(),
        event,
        data,
      })
    );
  }
}