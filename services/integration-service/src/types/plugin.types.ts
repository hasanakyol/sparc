import { z } from 'zod';

// Plugin types
export const PluginType = z.enum([
  'TRANSFORMER',
  'VALIDATOR',
  'ENRICHER',
  'ROUTER',
  'FILTER',
  'CUSTOM'
]);

export const PluginStatus = z.enum([
  'INSTALLED',
  'ACTIVE',
  'INACTIVE',
  'ERROR',
  'UPDATING'
]);

export const PluginRuntime = z.enum([
  'JAVASCRIPT',
  'WEBASSEMBLY',
  'DOCKER',
  'NATIVE'
]);

// Plugin manifest schema
export const pluginManifestSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(255),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  description: z.string(),
  author: z.object({
    name: z.string(),
    email: z.string().email().optional(),
    url: z.string().url().optional()
  }),
  type: PluginType,
  runtime: PluginRuntime,
  category: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([]),
  icon: z.string().url().optional(),
  homepage: z.string().url().optional(),
  repository: z.string().url().optional(),
  license: z.string().default('UNLICENSED'),
  requirements: z.object({
    minVersion: z.string().optional(),
    maxVersion: z.string().optional(),
    dependencies: z.array(z.object({
      id: z.string(),
      version: z.string()
    })).default([]),
    permissions: z.array(z.string()).default([])
  }).default({}),
  configuration: z.object({
    schema: z.record(z.any()).optional(),
    defaults: z.record(z.any()).optional(),
    ui: z.record(z.any()).optional()
  }).default({}),
  hooks: z.array(z.object({
    name: z.string(),
    description: z.string().optional(),
    inputs: z.record(z.any()).optional(),
    outputs: z.record(z.any()).optional()
  })).default([]),
  metrics: z.array(z.object({
    name: z.string(),
    type: z.enum(['counter', 'gauge', 'histogram']),
    description: z.string().optional()
  })).default([])
});

// Plugin instance schema
export const pluginInstanceSchema = z.object({
  id: z.string().uuid(),
  tenantId: z.string().uuid(),
  pluginId: z.string(),
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  version: z.string(),
  status: PluginStatus,
  configuration: z.record(z.any()).default({}),
  metadata: z.record(z.any()).default({}),
  installedAt: z.date(),
  activatedAt: z.date().optional(),
  lastExecuted: z.date().optional(),
  executionCount: z.number().default(0),
  errorCount: z.number().default(0),
  lastError: z.string().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
});

// Create plugin instance schema
export const createPluginInstanceSchema = z.object({
  pluginId: z.string(),
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  configuration: z.record(z.any()).default({})
});

// Update plugin instance schema
export const updatePluginInstanceSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().optional(),
  configuration: z.record(z.any()).optional(),
  status: PluginStatus.optional()
});

// Plugin execution context
export const pluginExecutionContextSchema = z.object({
  tenantId: z.string().uuid(),
  userId: z.string().uuid(),
  requestId: z.string().uuid(),
  instanceId: z.string().uuid(),
  input: z.record(z.any()),
  configuration: z.record(z.any()),
  metadata: z.record(z.any()).default({})
});

// Plugin execution result
export const pluginExecutionResultSchema = z.object({
  success: z.boolean(),
  output: z.record(z.any()).optional(),
  error: z.string().optional(),
  metrics: z.record(z.number()).optional(),
  logs: z.array(z.object({
    level: z.enum(['debug', 'info', 'warn', 'error']),
    message: z.string(),
    timestamp: z.date(),
    data: z.record(z.any()).optional()
  })).default([]),
  duration: z.number() // milliseconds
});

// Plugin marketplace schema
export const pluginMarketplaceItemSchema = z.object({
  id: z.string(),
  manifest: pluginManifestSchema,
  pricing: z.object({
    model: z.enum(['FREE', 'ONE_TIME', 'SUBSCRIPTION', 'USAGE_BASED']),
    price: z.number().optional(),
    currency: z.string().default('USD'),
    billingPeriod: z.enum(['MONTHLY', 'YEARLY']).optional(),
    usageRates: z.array(z.object({
      metric: z.string(),
      rate: z.number(),
      unit: z.string()
    })).optional()
  }),
  stats: z.object({
    downloads: z.number().default(0),
    rating: z.number().min(0).max(5).optional(),
    reviews: z.number().default(0),
    activeInstalls: z.number().default(0)
  }),
  verified: z.boolean().default(false),
  featured: z.boolean().default(false),
  screenshots: z.array(z.string().url()).default([]),
  documentation: z.string().url().optional(),
  supportUrl: z.string().url().optional(),
  publishedAt: z.date(),
  updatedAt: z.date()
});

// Plugin review schema
export const pluginReviewSchema = z.object({
  id: z.string().uuid(),
  pluginId: z.string(),
  userId: z.string().uuid(),
  rating: z.number().min(1).max(5),
  title: z.string().max(255).optional(),
  comment: z.string().max(1000).optional(),
  helpful: z.number().default(0),
  verified: z.boolean().default(false),
  createdAt: z.date()
});

// Types
export type PluginType = z.infer<typeof PluginType>;
export type PluginStatus = z.infer<typeof PluginStatus>;
export type PluginRuntime = z.infer<typeof PluginRuntime>;
export type PluginManifest = z.infer<typeof pluginManifestSchema>;
export type PluginInstance = z.infer<typeof pluginInstanceSchema>;
export type CreatePluginInstance = z.infer<typeof createPluginInstanceSchema>;
export type UpdatePluginInstance = z.infer<typeof updatePluginInstanceSchema>;
export type PluginExecutionContext = z.infer<typeof pluginExecutionContextSchema>;
export type PluginExecutionResult = z.infer<typeof pluginExecutionResultSchema>;
export type PluginMarketplaceItem = z.infer<typeof pluginMarketplaceItemSchema>;
export type PluginReview = z.infer<typeof pluginReviewSchema>;