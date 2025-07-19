import { z } from 'zod';

// Webhook event types
export const WebhookEventType = z.enum([
  'ALERT_CREATED',
  'ALERT_UPDATED',
  'ALERT_RESOLVED',
  'INCIDENT_CREATED',
  'INCIDENT_UPDATED',
  'ACCESS_GRANTED',
  'ACCESS_DENIED',
  'USER_CREATED',
  'USER_UPDATED',
  'USER_DELETED',
  'DEVICE_ONLINE',
  'DEVICE_OFFLINE',
  'SYSTEM_EVENT',
  'CUSTOM'
]);

export const WebhookStatus = z.enum([
  'ACTIVE',
  'INACTIVE',
  'FAILED',
  'SUSPENDED'
]);

export const WebhookMethod = z.enum([
  'POST',
  'PUT',
  'PATCH'
]);

export const WebhookRetryStrategy = z.enum([
  'EXPONENTIAL_BACKOFF',
  'LINEAR_BACKOFF',
  'FIXED_DELAY'
]);

// Webhook schema
export const webhookSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  url: z.string().url(),
  method: WebhookMethod.default('POST'),
  headers: z.record(z.string()).default({}),
  events: z.array(WebhookEventType),
  filters: z.record(z.any()).default({}),
  transform: z.object({
    enabled: z.boolean().default(false),
    template: z.string().optional(),
    mappings: z.array(z.object({
      source: z.string(),
      target: z.string(),
      transform: z.string().optional()
    })).default([])
  }).default({}),
  retry: z.object({
    enabled: z.boolean().default(true),
    strategy: WebhookRetryStrategy.default('EXPONENTIAL_BACKOFF'),
    maxAttempts: z.number().min(0).max(10).default(3),
    initialDelay: z.number().min(1000).default(1000), // milliseconds
    maxDelay: z.number().min(1000).default(60000), // milliseconds
    factor: z.number().min(1).default(2)
  }).default({}),
  security: z.object({
    signatureHeader: z.string().optional(),
    signatureAlgorithm: z.enum(['hmac-sha256', 'hmac-sha512']).optional(),
    secret: z.string().optional(),
    validateSsl: z.boolean().default(true)
  }).default({}),
  status: WebhookStatus.default('ACTIVE'),
  lastTriggered: z.date().optional(),
  lastSuccess: z.date().optional(),
  lastError: z.string().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

// Create webhook schema
export const createWebhookSchema = webhookSchema.omit({
  id: true,
  tenantId: true,
  status: true,
  lastTriggered: true,
  lastSuccess: true,
  lastError: true,
  createdAt: true,
  updatedAt: true
});

// Update webhook schema
export const updateWebhookSchema = createWebhookSchema.partial();

// Webhook event schema
export const webhookEventSchema = z.object({
  id: z.string().uuid(),
  webhookId: z.string().uuid(),
  eventType: WebhookEventType,
  payload: z.record(z.any()),
  attempt: z.number().default(0),
  status: z.enum(['PENDING', 'PROCESSING', 'SUCCESS', 'FAILED']),
  response: z.object({
    status: z.number().optional(),
    headers: z.record(z.string()).optional(),
    body: z.any().optional(),
    error: z.string().optional()
  }).optional(),
  nextRetry: z.date().optional(),
  createdAt: z.date(),
  processedAt: z.date().optional()
});

// Webhook delivery log schema
export const webhookDeliveryLogSchema = z.object({
  id: z.string().uuid(),
  webhookId: z.string().uuid(),
  eventId: z.string().uuid(),
  attempt: z.number(),
  url: z.string().url(),
  method: WebhookMethod,
  headers: z.record(z.string()),
  payload: z.record(z.any()),
  responseStatus: z.number().optional(),
  responseHeaders: z.record(z.string()).optional(),
  responseBody: z.string().optional(),
  error: z.string().optional(),
  duration: z.number(), // milliseconds
  success: z.boolean(),
  createdAt: z.date()
});

// Webhook test schema
export const testWebhookSchema = z.object({
  webhookId: z.string().uuid(),
  eventType: WebhookEventType,
  payload: z.record(z.any()).default({})
});

// Webhook statistics schema
export const webhookStatsSchema = z.object({
  webhookId: z.string().uuid(),
  period: z.enum(['hour', 'day', 'week', 'month']),
  totalEvents: z.number(),
  successfulDeliveries: z.number(),
  failedDeliveries: z.number(),
  averageResponseTime: z.number(), // milliseconds
  errorRate: z.number(), // percentage
  lastDelivery: z.date().optional()
});

// Types
export type WebhookEventType = z.infer<typeof WebhookEventType>;
export type WebhookStatus = z.infer<typeof WebhookStatus>;
export type WebhookMethod = z.infer<typeof WebhookMethod>;
export type WebhookRetryStrategy = z.infer<typeof WebhookRetryStrategy>;
export type Webhook = z.infer<typeof webhookSchema>;
export type CreateWebhook = z.infer<typeof createWebhookSchema>;
export type UpdateWebhook = z.infer<typeof updateWebhookSchema>;
export type WebhookEvent = z.infer<typeof webhookEventSchema>;
export type WebhookDeliveryLog = z.infer<typeof webhookDeliveryLogSchema>;
export type WebhookStats = z.infer<typeof webhookStatsSchema>;