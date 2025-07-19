import { Hono } from 'hono';
import { 
  versionMiddleware, 
  versionDiscoveryHandler,
  versionRegistry,
  VersionContext
} from '@sparc/shared/middleware/versioning';
import {
  compatibilityMiddleware
} from '@sparc/shared/middleware/compatibility';
import {
  VersionDeprecationService,
  deprecationTrackingMiddleware,
  sunsetEnforcementMiddleware
} from '@sparc/shared/services/version-deprecation';
import {
  FeatureFlagService,
  featureFlagMiddleware
} from '@sparc/shared/services/feature-flags';
import { CacheService } from '@sparc/shared/utils/cache';
import { z } from 'zod';

// Initialize services
const cache = new CacheService();
const deprecationService = new VersionDeprecationService(cache);
const featureFlagService = new FeatureFlagService(cache);

// Create versioning router
const app = new Hono();

// Apply middleware stack
app.use('*', versionMiddleware);
app.use('*', sunsetEnforcementMiddleware(deprecationService));
app.use('*', deprecationTrackingMiddleware(deprecationService));
app.use('*', compatibilityMiddleware);
app.use('*', featureFlagMiddleware(featureFlagService));

/**
 * Version discovery endpoint
 */
app.get('/versions', versionDiscoveryHandler);

/**
 * Version-specific API documentation
 */
app.get('/versions/:version/docs', async (c) => {
  const version = c.req.param('version');
  
  if (!versionRegistry.isVersionSupported(version)) {
    return c.json({
      error: 'Version not found',
      message: `API version ${version} does not exist`
    }, 404);
  }

  // Return OpenAPI spec for the version
  return c.json({
    openapi: '3.0.0',
    info: {
      title: 'SPARC API',
      version: version,
      description: `API documentation for version ${version}`
    },
    servers: [
      {
        url: `/v${version.split('.')[0]}`,
        description: `Version ${version} endpoint`
      }
    ],
    paths: {
      // This would be populated with actual API paths
      '/incidents': {
        get: {
          summary: 'List incidents',
          tags: ['Incidents'],
          parameters: [
            {
              name: 'Accept-Version',
              in: 'header',
              schema: { type: 'string' },
              description: 'API version'
            }
          ],
          responses: {
            200: {
              description: 'Success',
              content: {
                'application/json': {
                  schema: {
                    type: 'array',
                    items: { $ref: '#/components/schemas/Incident' }
                  }
                }
              }
            }
          }
        }
      }
    },
    components: {
      schemas: {
        Incident: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            category: { type: 'string' },
            priority: { type: 'string' },
            status: { type: 'string' }
          }
        }
      }
    }
  });
});

/**
 * Deprecation report endpoint
 */
app.get('/versions/deprecations', async (c) => {
  const days = parseInt(c.req.query('days') || '30');
  const report = await deprecationService.generateReport(days);
  
  return c.json(report);
});

/**
 * Deprecation notices for specific version
 */
app.get('/versions/:version/deprecations', async (c) => {
  const version = c.req.param('version');
  const notices = deprecationService.getNotices(version);
  
  return c.json({
    version,
    notices: notices.map(notice => ({
      endpoint: notice.endpoint,
      feature: notice.feature,
      deprecatedAt: notice.deprecatedAt,
      sunsetAt: notice.sunsetAt,
      message: notice.message,
      migrationGuide: notice.migrationGuide,
      alternatives: notice.alternatives,
      severity: notice.severity,
      daysUntilSunset: deprecationService.getDaysUntilSunset(version, notice.endpoint)
    }))
  });
});

/**
 * Feature flags endpoint
 */
app.get('/versions/features', async (c) => {
  const user = c.get('user') as any;
  const version = c.get('version') as VersionContext;
  
  const context = {
    userId: user?.userId,
    tenantId: user?.tenantId,
    roles: user?.roles,
    permissions: user?.permissions,
    version: version?.resolved
  };
  
  const flags = featureFlagService.evaluateAll(context);
  
  return c.json({
    flags: Object.entries(flags).map(([id, evaluation]) => ({
      id,
      enabled: evaluation.enabled,
      value: evaluation.value,
      variant: evaluation.variant,
      reason: evaluation.reason
    }))
  });
});

/**
 * Migration validation endpoint
 */
const migrationValidationSchema = z.object({
  fromVersion: z.string(),
  toVersion: z.string(),
  model: z.string(),
  data: z.any()
});

app.post('/versions/validate-migration', async (c) => {
  try {
    const body = await c.req.json();
    const { fromVersion, toVersion, model, data } = migrationValidationSchema.parse(body);
    
    // Import model transformer
    const { modelTransformer } = await import('@sparc/shared/services/version-transformer');
    
    // Attempt transformation
    const transformed = await modelTransformer.transform(
      model,
      data,
      fromVersion,
      toVersion
    );
    
    return c.json({
      success: true,
      original: data,
      transformed,
      changes: generateChangeSummary(data, transformed)
    });
  } catch (error: any) {
    return c.json({
      success: false,
      error: error.message,
      details: error.cause
    }, 400);
  }
});

/**
 * Version compatibility check endpoint
 */
app.post('/versions/check-compatibility', async (c) => {
  const body = await c.req.json();
  const { clientVersion, requiredFeatures = [] } = body;
  
  const compatibility = {
    compatible: true,
    warnings: [] as string[],
    errors: [] as string[],
    recommendations: [] as string[]
  };
  
  // Check if version is supported
  if (!versionRegistry.isVersionSupported(clientVersion)) {
    compatibility.compatible = false;
    compatibility.errors.push(`Version ${clientVersion} is not supported`);
  }
  
  // Check if version is deprecated
  if (versionRegistry.isVersionDeprecated(clientVersion)) {
    compatibility.warnings.push(`Version ${clientVersion} is deprecated`);
    const config = versionRegistry.getVersion(clientVersion);
    if (config?.migrationGuide) {
      compatibility.recommendations.push(`Upgrade guide: ${config.migrationGuide}`);
    }
  }
  
  // Check feature availability
  for (const feature of requiredFeatures) {
    const flag = featureFlagService.getFlag(feature);
    if (!flag) {
      compatibility.warnings.push(`Feature '${feature}' not found`);
    } else if (!flag.enabled) {
      compatibility.warnings.push(`Feature '${feature}' is disabled`);
    }
  }
  
  // Add recommendations
  const currentVersion = versionRegistry.getDefaultVersion();
  if (versionRegistry.compareVersions(clientVersion, currentVersion) < 0) {
    compatibility.recommendations.push(
      `Consider upgrading to version ${currentVersion} for latest features`
    );
  }
  
  return c.json(compatibility);
});

/**
 * Version migration status endpoint
 */
app.get('/versions/migration-status', async (c) => {
  const user = c.get('user') as any;
  
  if (!user?.tenantId) {
    return c.json({ error: 'Tenant context required' }, 400);
  }
  
  // This would check actual migration status from database
  const status = {
    tenantId: user.tenantId,
    currentVersion: '1.1',
    targetVersion: '2.0',
    migrationStarted: '2024-01-15T10:00:00Z',
    progress: {
      total: 1000,
      completed: 750,
      failed: 5,
      percentage: 75
    },
    estimatedCompletion: '2024-01-15T14:00:00Z',
    steps: [
      { name: 'Data validation', status: 'completed' },
      { name: 'Schema migration', status: 'completed' },
      { name: 'Data transformation', status: 'in_progress' },
      { name: 'Verification', status: 'pending' }
    ]
  };
  
  return c.json(status);
});

/**
 * Helper function to generate change summary
 */
function generateChangeSummary(original: any, transformed: any): any {
  const changes = {
    added: [] as string[],
    removed: [] as string[],
    modified: [] as { field: string; from: any; to: any }[]
  };
  
  // Simple comparison (would be more sophisticated in production)
  const originalKeys = new Set(Object.keys(original));
  const transformedKeys = new Set(Object.keys(transformed));
  
  // Added fields
  for (const key of transformedKeys) {
    if (!originalKeys.has(key)) {
      changes.added.push(key);
    }
  }
  
  // Removed fields
  for (const key of originalKeys) {
    if (!transformedKeys.has(key)) {
      changes.removed.push(key);
    }
  }
  
  // Modified fields
  for (const key of originalKeys) {
    if (transformedKeys.has(key) && original[key] !== transformed[key]) {
      changes.modified.push({
        field: key,
        from: original[key],
        to: transformed[key]
      });
    }
  }
  
  return changes;
}

export { app as versioningRouter };