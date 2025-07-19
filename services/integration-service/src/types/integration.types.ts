import { z } from 'zod';

// Integration types
export const IntegrationType = z.enum([
  'LDAP',
  'ACTIVE_DIRECTORY',
  'OAUTH2',
  'SAML',
  'WEBHOOK',
  'REST_API',
  'GRAPHQL',
  'SOAP',
  'DATABASE',
  'MESSAGE_QUEUE',
  'CUSTOM'
]);

export const IntegrationStatus = z.enum([
  'ACTIVE',
  'INACTIVE',
  'ERROR',
  'CONFIGURING',
  'TESTING'
]);

export const AuthMethod = z.enum([
  'NONE',
  'API_KEY',
  'BEARER_TOKEN',
  'BASIC_AUTH',
  'OAUTH2',
  'SAML',
  'CUSTOM'
]);

// Base integration schema
export const integrationBaseSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  type: IntegrationType,
  status: IntegrationStatus,
  endpoint: z.string().url().optional(),
  authMethod: AuthMethod,
  configuration: z.record(z.any()).default({}),
  metadata: z.record(z.any()).default({}),
  lastSync: z.date().optional(),
  lastError: z.string().optional(),
  createdAt: z.date(),
  updatedAt: z.date(),
  createdBy: z.string().uuid(),
  updatedBy: z.string().uuid()
});

// Create integration schema
export const createIntegrationSchema = integrationBaseSchema.omit({
  id: true,
  tenantId: true,
  status: true,
  lastSync: true,
  lastError: true,
  createdAt: true,
  updatedAt: true,
  createdBy: true,
  updatedBy: true
}).extend({
  authentication: z.record(z.any()).optional() // Sensitive data that will be encrypted
});

// Update integration schema
export const updateIntegrationSchema = createIntegrationSchema.partial();

// Integration test schema
export const testIntegrationSchema = z.object({
  integrationId: z.string().uuid(),
  testData: z.record(z.any()).optional()
});

// OAuth2 configuration schema
export const oauth2ConfigSchema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  authorizationUrl: z.string().url(),
  tokenUrl: z.string().url(),
  redirectUri: z.string().url(),
  scope: z.array(z.string()).default([]),
  grantType: z.enum(['authorization_code', 'client_credentials', 'refresh_token']).default('authorization_code'),
  pkce: z.boolean().default(false)
});

// SAML configuration schema
export const samlConfigSchema = z.object({
  entryPoint: z.string().url(),
  issuer: z.string(),
  cert: z.string(),
  privateKey: z.string().optional(),
  callbackUrl: z.string().url(),
  signatureAlgorithm: z.enum(['sha1', 'sha256', 'sha512']).default('sha256'),
  identifierFormat: z.string().optional(),
  acceptedClockSkewMs: z.number().default(5000),
  attributeMapping: z.record(z.string()).default({})
});

// LDAP configuration schema
export const ldapConfigSchema = z.object({
  url: z.string().url(),
  bindDN: z.string(),
  bindPassword: z.string(),
  baseDN: z.string(),
  userFilter: z.string().default('(objectClass=person)'),
  groupFilter: z.string().default('(objectClass=group)'),
  userAttributes: z.array(z.string()).default(['cn', 'mail', 'sAMAccountName']),
  groupAttributes: z.array(z.string()).default(['cn', 'description', 'member']),
  tlsOptions: z.object({
    rejectUnauthorized: z.boolean().default(true),
    ca: z.string().optional(),
    cert: z.string().optional(),
    key: z.string().optional()
  }).optional(),
  syncConfig: z.object({
    enabled: z.boolean().default(false),
    interval: z.number().default(3600), // seconds
    batchSize: z.number().default(100),
    syncUsers: z.boolean().default(true),
    syncGroups: z.boolean().default(true)
  }).default({})
});

// Data mapping configuration
export const dataMappingSchema = z.object({
  source: z.string(),
  target: z.string(),
  transform: z.enum(['direct', 'template', 'jsonpath', 'javascript']).default('direct'),
  template: z.string().optional(),
  script: z.string().optional(),
  defaultValue: z.any().optional()
});

// Integration health check result
export const healthCheckResultSchema = z.object({
  status: z.enum(['healthy', 'unhealthy', 'degraded']),
  lastCheck: z.date(),
  responseTime: z.number(), // milliseconds
  details: z.record(z.any()).optional(),
  error: z.string().optional()
});

// Integration metrics
export const integrationMetricsSchema = z.object({
  integrationId: z.string().uuid(),
  period: z.enum(['hour', 'day', 'week', 'month']),
  requestCount: z.number(),
  successCount: z.number(),
  errorCount: z.number(),
  averageResponseTime: z.number(),
  dataProcessed: z.number(), // bytes
  quotaUsed: z.number().optional(),
  quotaLimit: z.number().optional()
});

// Types
export type IntegrationType = z.infer<typeof IntegrationType>;
export type IntegrationStatus = z.infer<typeof IntegrationStatus>;
export type AuthMethod = z.infer<typeof AuthMethod>;
export type Integration = z.infer<typeof integrationBaseSchema>;
export type CreateIntegration = z.infer<typeof createIntegrationSchema>;
export type UpdateIntegration = z.infer<typeof updateIntegrationSchema>;
export type OAuth2Config = z.infer<typeof oauth2ConfigSchema>;
export type SAMLConfig = z.infer<typeof samlConfigSchema>;
export type LDAPConfig = z.infer<typeof ldapConfigSchema>;
export type DataMapping = z.infer<typeof dataMappingSchema>;
export type HealthCheckResult = z.infer<typeof healthCheckResultSchema>;
export type IntegrationMetrics = z.infer<typeof integrationMetricsSchema>;