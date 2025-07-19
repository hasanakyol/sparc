import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { logger } from '@sparc/shared';
import { 
  Webhook, 
  CreateWebhook, 
  UpdateWebhook,
  WebhookEvent,
  WebhookDeliveryLog,
  WebhookStats,
  WebhookStatus,
  WebhookEventType
} from '../types';
import crypto from 'crypto';
import axios from 'axios';
import { Queue } from 'bullmq';
import { HTTPException } from 'hono/http-exception';
import retry from 'retry';

export class WebhookService {
  private webhookQueue: Queue;

  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {
    // Initialize webhook delivery queue
    this.webhookQueue = new Queue('webhook-delivery', {
      connection: this.redis
    });
  }

  async listWebhooks(
    tenantId: string,
    options: {
      page: number;
      limit: number;
      status?: WebhookStatus;
      eventType?: WebhookEventType;
      search?: string;
    }
  ) {
    const offset = (options.page - 1) * options.limit;

    const where: any = { tenantId };
    
    if (options.status) {
      where.status = options.status;
    }
    
    if (options.eventType) {
      where.events = { has: options.eventType };
    }
    
    if (options.search) {
      where.OR = [
        { name: { contains: options.search, mode: 'insensitive' } },
        { description: { contains: options.search, mode: 'insensitive' } },
        { url: { contains: options.search, mode: 'insensitive' } }
      ];
    }

    const [webhooks, total] = await Promise.all([
      this.prisma.webhook.findMany({
        where,
        skip: offset,
        take: options.limit,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          name: true,
          description: true,
          url: true,
          method: true,
          events: true,
          status: true,
          lastTriggered: true,
          lastSuccess: true,
          lastError: true,
          createdAt: true,
          updatedAt: true
        }
      }),
      this.prisma.webhook.count({ where })
    ]);

    return {
      data: webhooks,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        totalPages: Math.ceil(total / options.limit)
      }
    };
  }

  async createWebhook(
    tenantId: string,
    data: CreateWebhook
  ): Promise<Webhook> {
    // Generate webhook secret
    const secret = crypto.randomBytes(32).toString('hex');

    const webhook = await this.prisma.webhook.create({
      data: {
        id: crypto.randomUUID(),
        tenantId,
        name: data.name,
        description: data.description,
        url: data.url,
        method: data.method || 'POST',
        headers: data.headers || {},
        events: data.events,
        filters: data.filters || {},
        transform: data.transform || { enabled: false },
        retry: data.retry || {
          enabled: true,
          strategy: 'EXPONENTIAL_BACKOFF',
          maxAttempts: 3,
          initialDelay: 1000,
          maxDelay: 60000,
          factor: 2
        },
        security: {
          ...data.security,
          secret,
          signatureHeader: data.security?.signatureHeader || 'X-Webhook-Signature',
          signatureAlgorithm: data.security?.signatureAlgorithm || 'hmac-sha256',
          validateSsl: data.security?.validateSsl !== false
        },
        status: 'ACTIVE',
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });

    return webhook as Webhook;
  }

  async getWebhook(
    tenantId: string,
    webhookId: string
  ): Promise<Webhook | null> {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!webhook) {
      return null;
    }

    // Hide secret in response
    return {
      ...webhook,
      security: {
        ...webhook.security,
        secret: undefined
      }
    } as Webhook;
  }

  async updateWebhook(
    tenantId: string,
    webhookId: string,
    data: UpdateWebhook
  ): Promise<Webhook | null> {
    const existing = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!existing) {
      return null;
    }

    const updateData: any = {
      updatedAt: new Date()
    };

    // Handle each field update
    if (data.name !== undefined) updateData.name = data.name;
    if (data.description !== undefined) updateData.description = data.description;
    if (data.url !== undefined) updateData.url = data.url;
    if (data.method !== undefined) updateData.method = data.method;
    if (data.headers !== undefined) updateData.headers = data.headers;
    if (data.events !== undefined) updateData.events = data.events;
    if (data.filters !== undefined) updateData.filters = data.filters;
    if (data.transform !== undefined) updateData.transform = data.transform;
    if (data.retry !== undefined) updateData.retry = data.retry;
    if (data.security !== undefined) {
      updateData.security = {
        ...existing.security,
        ...data.security
      };
    }

    const updated = await this.prisma.webhook.update({
      where: { id: webhookId },
      data: updateData
    });

    return {
      ...updated,
      security: {
        ...updated.security,
        secret: undefined
      }
    } as Webhook;
  }

  async deleteWebhook(
    tenantId: string,
    webhookId: string
  ): Promise<void> {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!webhook) {
      throw new HTTPException(404, { message: 'Webhook not found' });
    }

    await this.prisma.webhook.delete({
      where: { id: webhookId }
    });
  }

  async testWebhook(
    tenantId: string,
    webhookId: string,
    eventType: WebhookEventType,
    payload: any
  ): Promise<{ success: boolean; response?: any; error?: string }> {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!webhook) {
      throw new HTTPException(404, { message: 'Webhook not found' });
    }

    try {
      const result = await this.deliverWebhook(webhook, {
        id: crypto.randomUUID(),
        webhookId: webhook.id,
        eventType,
        payload,
        attempt: 0,
        status: 'PROCESSING',
        createdAt: new Date()
      });

      return {
        success: result.success,
        response: result.response
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async triggerWebhookEvent(
    tenantId: string,
    eventType: WebhookEventType,
    payload: any
  ): Promise<void> {
    // Find all active webhooks subscribed to this event
    const webhooks = await this.prisma.webhook.findMany({
      where: {
        tenantId,
        status: 'ACTIVE',
        events: { has: eventType }
      }
    });

    // Queue webhook deliveries
    for (const webhook of webhooks) {
      // Check filters
      if (webhook.filters && Object.keys(webhook.filters).length > 0) {
        if (!this.matchFilters(payload, webhook.filters)) {
          continue;
        }
      }

      // Create webhook event
      const event: WebhookEvent = {
        id: crypto.randomUUID(),
        webhookId: webhook.id,
        eventType,
        payload,
        attempt: 0,
        status: 'PENDING',
        createdAt: new Date()
      };

      // Queue for delivery
      await this.webhookQueue.add('deliver', event, {
        attempts: webhook.retry?.maxAttempts || 3,
        backoff: {
          type: webhook.retry?.strategy === 'LINEAR_BACKOFF' ? 'fixed' : 'exponential',
          delay: webhook.retry?.initialDelay || 1000
        }
      });
    }
  }

  async processWebhookDelivery(event: WebhookEvent): Promise<void> {
    const webhook = await this.prisma.webhook.findUnique({
      where: { id: event.webhookId }
    });

    if (!webhook || webhook.status !== 'ACTIVE') {
      logger.warn('Webhook not found or inactive', { webhookId: event.webhookId });
      return;
    }

    try {
      const result = await this.deliverWebhook(webhook, event);
      
      if (result.success) {
        await this.updateWebhookStatus(webhook.id, {
          lastTriggered: new Date(),
          lastSuccess: new Date(),
          lastError: null
        });
      } else {
        throw new Error(result.error || 'Delivery failed');
      }
    } catch (error) {
      await this.updateWebhookStatus(webhook.id, {
        lastTriggered: new Date(),
        lastError: error.message
      });
      
      // Update metrics
      await this.redis.incr('metrics:webhook:failures:total');
      
      throw error; // Re-throw to trigger retry
    }
  }

  async getWebhookDeliveries(
    tenantId: string,
    webhookId: string,
    options: {
      page: number;
      limit: number;
      status?: 'SUCCESS' | 'FAILED';
    }
  ) {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!webhook) {
      throw new HTTPException(404, { message: 'Webhook not found' });
    }

    const offset = (options.page - 1) * options.limit;
    const where: any = { webhookId };
    
    if (options.status) {
      where.success = options.status === 'SUCCESS';
    }

    const [deliveries, total] = await Promise.all([
      this.prisma.webhookDeliveryLog.findMany({
        where,
        skip: offset,
        take: options.limit,
        orderBy: { createdAt: 'desc' }
      }),
      this.prisma.webhookDeliveryLog.count({ where })
    ]);

    return {
      data: deliveries,
      pagination: {
        page: options.page,
        limit: options.limit,
        total,
        totalPages: Math.ceil(total / options.limit)
      }
    };
  }

  async retryWebhookDelivery(
    tenantId: string,
    webhookId: string,
    deliveryId: string
  ): Promise<any> {
    const delivery = await this.prisma.webhookDeliveryLog.findFirst({
      where: {
        id: deliveryId,
        webhookId
      }
    });

    if (!delivery) {
      throw new HTTPException(404, { message: 'Delivery log not found' });
    }

    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!webhook) {
      throw new HTTPException(404, { message: 'Webhook not found' });
    }

    // Re-queue the delivery
    const event: WebhookEvent = {
      id: crypto.randomUUID(),
      webhookId: webhook.id,
      eventType: 'SYSTEM_EVENT', // Would be stored in delivery log
      payload: delivery.payload,
      attempt: 0,
      status: 'PENDING',
      createdAt: new Date()
    };

    await this.webhookQueue.add('deliver', event);

    return { success: true, message: 'Webhook delivery re-queued' };
  }

  async getWebhookStats(
    tenantId: string,
    webhookId: string,
    period: 'hour' | 'day' | 'week' | 'month'
  ): Promise<WebhookStats> {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!webhook) {
      throw new HTTPException(404, { message: 'Webhook not found' });
    }

    // This would typically aggregate from time-series data
    // For now, return mock data
    const stats = await this.prisma.webhookDeliveryLog.aggregate({
      where: { webhookId },
      _count: true,
      _avg: {
        duration: true
      }
    });

    const successCount = await this.prisma.webhookDeliveryLog.count({
      where: { webhookId, success: true }
    });

    const failureCount = await this.prisma.webhookDeliveryLog.count({
      where: { webhookId, success: false }
    });

    return {
      webhookId,
      period,
      totalEvents: stats._count,
      successfulDeliveries: successCount,
      failedDeliveries: failureCount,
      averageResponseTime: stats._avg.duration || 0,
      errorRate: stats._count > 0 ? (failureCount / stats._count) * 100 : 0,
      lastDelivery: webhook.lastTriggered || undefined
    };
  }

  async regenerateWebhookSecret(
    tenantId: string,
    webhookId: string
  ): Promise<string> {
    const webhook = await this.prisma.webhook.findFirst({
      where: {
        id: webhookId,
        tenantId
      }
    });

    if (!webhook) {
      throw new HTTPException(404, { message: 'Webhook not found' });
    }

    const newSecret = crypto.randomBytes(32).toString('hex');

    await this.prisma.webhook.update({
      where: { id: webhookId },
      data: {
        security: {
          ...webhook.security,
          secret: newSecret
        }
      }
    });

    return newSecret;
  }

  async verifyIncomingWebhook(
    token: string,
    signature: string,
    body: string
  ): Promise<any> {
    // This would verify incoming webhooks for bi-directional integration
    // For now, return null
    return null;
  }

  async processIncomingWebhook(
    webhookId: string,
    payload: any
  ): Promise<void> {
    // Process incoming webhook data
    logger.info('Processing incoming webhook', { webhookId, payload });
  }

  async batchUpdateStatus(
    tenantId: string,
    webhookIds: string[],
    status: WebhookStatus
  ): Promise<any> {
    const result = await this.prisma.webhook.updateMany({
      where: {
        id: { in: webhookIds },
        tenantId
      },
      data: {
        status,
        updatedAt: new Date()
      }
    });

    return {
      updated: result.count,
      status
    };
  }

  async getAvailableEventTypes(): Promise<any[]> {
    return Object.values(WebhookEventType).map(type => ({
      value: type,
      label: type.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase()),
      description: this.getEventTypeDescription(type)
    }));
  }

  // Private helper methods

  private async deliverWebhook(
    webhook: any,
    event: WebhookEvent
  ): Promise<any> {
    const startTime = Date.now();
    let transformedPayload = event.payload;

    // Apply transformation if configured
    if (webhook.transform?.enabled && webhook.transform?.template) {
      transformedPayload = this.applyTransformation(
        event.payload,
        webhook.transform.template
      );
    }

    // Generate signature
    const signature = this.generateSignature(
      webhook.security.secret,
      transformedPayload,
      webhook.security.signatureAlgorithm
    );

    // Prepare headers
    const headers = {
      ...webhook.headers,
      'Content-Type': 'application/json',
      [webhook.security.signatureHeader]: signature,
      'X-Webhook-ID': webhook.id,
      'X-Event-Type': event.eventType,
      'X-Event-ID': event.id,
      'X-Attempt': event.attempt.toString()
    };

    try {
      const response = await axios({
        method: webhook.method,
        url: webhook.url,
        headers,
        data: transformedPayload,
        timeout: 30000, // 30 seconds
        validateStatus: null // Don't throw on non-2xx
      });

      const duration = Date.now() - startTime;
      const success = response.status >= 200 && response.status < 300;

      // Log delivery
      await this.logDelivery({
        id: crypto.randomUUID(),
        webhookId: webhook.id,
        eventId: event.id,
        attempt: event.attempt,
        url: webhook.url,
        method: webhook.method,
        headers,
        payload: transformedPayload,
        responseStatus: response.status,
        responseHeaders: response.headers,
        responseBody: response.data,
        duration,
        success,
        createdAt: new Date()
      });

      // Update metrics
      await this.redis.incr('metrics:webhook:deliveries:total');
      if (success) {
        await this.redis.incr('metrics:webhook:deliveries:success');
      } else {
        await this.redis.incr('metrics:webhook:deliveries:failed');
      }

      return {
        success,
        response: {
          status: response.status,
          data: response.data
        }
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      // Log failed delivery
      await this.logDelivery({
        id: crypto.randomUUID(),
        webhookId: webhook.id,
        eventId: event.id,
        attempt: event.attempt,
        url: webhook.url,
        method: webhook.method,
        headers,
        payload: transformedPayload,
        error: error.message,
        duration,
        success: false,
        createdAt: new Date()
      });

      return {
        success: false,
        error: error.message
      };
    }
  }

  private matchFilters(payload: any, filters: any): boolean {
    for (const [key, value] of Object.entries(filters)) {
      const payloadValue = this.getNestedValue(payload, key);
      if (payloadValue !== value) {
        return false;
      }
    }
    return true;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((acc, part) => acc?.[part], obj);
  }

  private applyTransformation(payload: any, template: string): any {
    // Simple template replacement for now
    // In production, use a proper template engine
    let transformed = template;
    
    const replaceTokens = (str: string, data: any, prefix = ''): string => {
      Object.entries(data).forEach(([key, value]) => {
        const token = prefix ? `${prefix}.${key}` : key;
        if (typeof value === 'object' && value !== null) {
          str = replaceTokens(str, value, token);
        } else {
          str = str.replace(new RegExp(`{{${token}}}`, 'g'), String(value));
        }
      });
      return str;
    };

    transformed = replaceTokens(transformed, payload);
    
    try {
      return JSON.parse(transformed);
    } catch {
      return transformed;
    }
  }

  private generateSignature(
    secret: string,
    payload: any,
    algorithm: string
  ): string {
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    
    switch (algorithm) {
      case 'hmac-sha256':
        return crypto.createHmac('sha256', secret).update(data).digest('hex');
      case 'hmac-sha512':
        return crypto.createHmac('sha512', secret).update(data).digest('hex');
      default:
        return crypto.createHmac('sha256', secret).update(data).digest('hex');
    }
  }

  private async updateWebhookStatus(
    webhookId: string,
    updates: any
  ): Promise<void> {
    await this.prisma.webhook.update({
      where: { id: webhookId },
      data: updates
    });
  }

  private async logDelivery(log: WebhookDeliveryLog): Promise<void> {
    await this.prisma.webhookDeliveryLog.create({
      data: log
    });
  }

  private getEventTypeDescription(type: WebhookEventType): string {
    const descriptions: Record<WebhookEventType, string> = {
      ALERT_CREATED: 'Triggered when a new alert is created',
      ALERT_UPDATED: 'Triggered when an alert is updated',
      ALERT_RESOLVED: 'Triggered when an alert is resolved',
      INCIDENT_CREATED: 'Triggered when a new incident is created',
      INCIDENT_UPDATED: 'Triggered when an incident is updated',
      ACCESS_GRANTED: 'Triggered when access is granted',
      ACCESS_DENIED: 'Triggered when access is denied',
      USER_CREATED: 'Triggered when a new user is created',
      USER_UPDATED: 'Triggered when a user is updated',
      USER_DELETED: 'Triggered when a user is deleted',
      DEVICE_ONLINE: 'Triggered when a device comes online',
      DEVICE_OFFLINE: 'Triggered when a device goes offline',
      SYSTEM_EVENT: 'General system events',
      CUSTOM: 'Custom events defined by integrations'
    };
    
    return descriptions[type] || 'No description available';
  }
}