import { Context, Next } from 'hono';
import { VersionContext } from './versioning';

/**
 * Field mapping configuration for backward compatibility
 */
export interface FieldMapping {
  from: string;
  to: string;
  transform?: (value: any) => any;
}

/**
 * Compatibility configuration for different versions
 */
export interface CompatibilityConfig {
  request?: {
    fieldMappings?: FieldMapping[];
    defaults?: Record<string, any>;
    validators?: Record<string, (value: any) => boolean>;
  };
  response?: {
    fieldMappings?: FieldMapping[];
    excludeFields?: string[];
    addFields?: Record<string, any>;
  };
}

/**
 * Version compatibility registry
 */
export class CompatibilityRegistry {
  private rules: Map<string, Map<string, CompatibilityConfig>> = new Map();

  /**
   * Register compatibility rules between versions
   */
  registerCompatibility(
    fromVersion: string,
    toVersion: string,
    config: CompatibilityConfig
  ): void {
    if (!this.rules.has(fromVersion)) {
      this.rules.set(fromVersion, new Map());
    }
    this.rules.get(fromVersion)!.set(toVersion, config);
  }

  /**
   * Get compatibility configuration
   */
  getCompatibility(fromVersion: string, toVersion: string): CompatibilityConfig | undefined {
    return this.rules.get(fromVersion)?.get(toVersion);
  }
}

// Global compatibility registry
export const compatibilityRegistry = new CompatibilityRegistry();

// Initialize with common compatibility rules
compatibilityRegistry.registerCompatibility('1.0', '1.1', {
  request: {
    fieldMappings: [
      { from: 'user_id', to: 'userId' },
      { from: 'tenant_id', to: 'tenantId' },
      { from: 'created_at', to: 'createdAt' },
      { from: 'updated_at', to: 'updatedAt' }
    ],
    defaults: {
      apiVersion: '1.1'
    }
  },
  response: {
    fieldMappings: [
      { from: 'userId', to: 'user_id' },
      { from: 'tenantId', to: 'tenant_id' },
      { from: 'createdAt', to: 'created_at' },
      { from: 'updatedAt', to: 'updated_at' }
    ],
    excludeFields: ['apiVersion', '_metadata']
  }
});

compatibilityRegistry.registerCompatibility('1.1', '2.0', {
  request: {
    fieldMappings: [
      { 
        from: 'name', 
        to: 'displayName',
        transform: (value: string) => value?.trim()
      },
      {
        from: 'active',
        to: 'status',
        transform: (value: boolean) => value ? 'active' : 'inactive'
      }
    ],
    defaults: {
      organizationId: null,
      metadata: {}
    }
  },
  response: {
    fieldMappings: [
      {
        from: 'status',
        to: 'active',
        transform: (value: string) => value === 'active'
      },
      { from: 'displayName', to: 'name' }
    ],
    excludeFields: ['organizationId', 'metadata']
  }
});

/**
 * Deep object field mapper
 */
export class ObjectMapper {
  /**
   * Apply field mappings to an object
   */
  static applyMappings(obj: any, mappings: FieldMapping[]): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    const result = Array.isArray(obj) ? [] : {};
    const mapped = new Set<string>();

    // Apply mappings
    for (const mapping of mappings) {
      const value = this.getNestedValue(obj, mapping.from);
      if (value !== undefined) {
        const transformedValue = mapping.transform ? mapping.transform(value) : value;
        this.setNestedValue(result, mapping.to, transformedValue);
        mapped.add(mapping.from);
      }
    }

    // Copy unmapped fields
    this.copyUnmappedFields(obj, result, mapped);

    return result;
  }

  /**
   * Get nested object value
   */
  private static getNestedValue(obj: any, path: string): any {
    const parts = path.split('.');
    let current = obj;

    for (const part of parts) {
      if (current && typeof current === 'object' && part in current) {
        current = current[part];
      } else {
        return undefined;
      }
    }

    return current;
  }

  /**
   * Set nested object value
   */
  private static setNestedValue(obj: any, path: string, value: any): void {
    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current)) {
        current[part] = {};
      }
      current = current[part];
    }

    current[parts[parts.length - 1]] = value;
  }

  /**
   * Copy fields that weren't mapped
   */
  private static copyUnmappedFields(source: any, target: any, mapped: Set<string>): void {
    if (Array.isArray(source)) {
      for (let i = 0; i < source.length; i++) {
        if (!mapped.has(String(i))) {
          target[i] = source[i];
        }
      }
    } else {
      for (const key in source) {
        if (source.hasOwnProperty(key) && !mapped.has(key)) {
          target[key] = source[key];
        }
      }
    }
  }

  /**
   * Remove fields from object
   */
  static removeFields(obj: any, fields: string[]): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    const result = Array.isArray(obj) ? [...obj] : { ...obj };

    for (const field of fields) {
      this.deleteNestedValue(result, field);
    }

    return result;
  }

  /**
   * Delete nested object value
   */
  private static deleteNestedValue(obj: any, path: string): void {
    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (current && typeof current === 'object' && part in current) {
        current = current[part];
      } else {
        return;
      }
    }

    if (current && typeof current === 'object') {
      delete current[parts[parts.length - 1]];
    }
  }

  /**
   * Add default values to object
   */
  static addDefaults(obj: any, defaults: Record<string, any>): any {
    if (!obj || typeof obj !== 'object') {
      return obj;
    }

    const result = Array.isArray(obj) ? [...obj] : { ...obj };

    for (const [key, value] of Object.entries(defaults)) {
      if (this.getNestedValue(result, key) === undefined) {
        this.setNestedValue(result, key, value);
      }
    }

    return result;
  }
}

/**
 * Request compatibility middleware
 */
export const requestCompatibilityMiddleware = async (c: Context, next: Next) => {
  const versionContext = c.get('version') as VersionContext;
  if (!versionContext) {
    await next();
    return;
  }

  // Check if request has JSON body
  const contentType = c.req.header('content-type');
  if (!contentType?.includes('application/json')) {
    await next();
    return;
  }

  try {
    const body = await c.req.json();
    
    // Find compatibility rules from client version to current API version
    const compatibility = compatibilityRegistry.getCompatibility(
      versionContext.requested,
      versionContext.resolved
    );

    if (compatibility?.request) {
      let transformedBody = body;

      // Apply field mappings
      if (compatibility.request.fieldMappings) {
        transformedBody = ObjectMapper.applyMappings(
          transformedBody,
          compatibility.request.fieldMappings
        );
      }

      // Add defaults
      if (compatibility.request.defaults) {
        transformedBody = ObjectMapper.addDefaults(
          transformedBody,
          compatibility.request.defaults
        );
      }

      // Validate fields
      if (compatibility.request.validators) {
        for (const [field, validator] of Object.entries(compatibility.request.validators)) {
          const value = ObjectMapper.getNestedValue(transformedBody, field);
          if (value !== undefined && !validator(value)) {
            throw new Error(`Invalid value for field: ${field}`);
          }
        }
      }

      // Update request with transformed body
      c.req.raw = new Request(c.req.raw, {
        body: JSON.stringify(transformedBody)
      });
    }
  } catch (error) {
    console.error('Request compatibility transformation failed:', error);
    // Continue with original request if transformation fails
  }

  await next();
};

/**
 * Response compatibility middleware
 */
export const responseCompatibilityMiddleware = async (c: Context, next: Next) => {
  await next();

  const versionContext = c.get('version') as VersionContext;
  if (!versionContext || versionContext.requested === versionContext.resolved) {
    return;
  }

  // Check if response has JSON body
  const contentType = c.res.headers.get('content-type');
  if (!contentType?.includes('application/json')) {
    return;
  }

  try {
    const body = await c.res.json();
    
    // Find compatibility rules from current API version to client version
    const compatibility = compatibilityRegistry.getCompatibility(
      versionContext.resolved,
      versionContext.requested
    );

    if (compatibility?.response) {
      let transformedBody = body;

      // Apply field mappings
      if (compatibility.response.fieldMappings) {
        transformedBody = ObjectMapper.applyMappings(
          transformedBody,
          compatibility.response.fieldMappings
        );
      }

      // Remove fields
      if (compatibility.response.excludeFields) {
        transformedBody = ObjectMapper.removeFields(
          transformedBody,
          compatibility.response.excludeFields
        );
      }

      // Add fields
      if (compatibility.response.addFields) {
        transformedBody = { ...transformedBody, ...compatibility.response.addFields };
      }

      // Update response with transformed body
      c.res = new Response(JSON.stringify(transformedBody), {
        status: c.res.status,
        headers: c.res.headers
      });
    }
  } catch (error) {
    console.error('Response compatibility transformation failed:', error);
    // Keep original response if transformation fails
  }
};

/**
 * Combined compatibility middleware
 */
export const compatibilityMiddleware = async (c: Context, next: Next) => {
  await requestCompatibilityMiddleware(c, async () => {
    await responseCompatibilityMiddleware(c, next);
  });
};

/**
 * Version-specific data transformer
 */
export class DataTransformer {
  private transformers: Map<string, (data: any) => any> = new Map();

  /**
   * Register a transformer for a specific version transition
   */
  registerTransformer(fromVersion: string, toVersion: string, transformer: (data: any) => any): void {
    const key = `${fromVersion}->${toVersion}`;
    this.transformers.set(key, transformer);
  }

  /**
   * Transform data between versions
   */
  transform(data: any, fromVersion: string, toVersion: string): any {
    const key = `${fromVersion}->${toVersion}`;
    const transformer = this.transformers.get(key);
    
    if (transformer) {
      return transformer(data);
    }

    // If no direct transformer, try to chain transformations
    const fromMajor = parseInt(fromVersion.split('.')[0]);
    const toMajor = parseInt(toVersion.split('.')[0]);

    if (fromMajor < toMajor) {
      // Transform forward through versions
      let result = data;
      for (let i = fromMajor; i < toMajor; i++) {
        const stepKey = `${i}.0->${i + 1}.0`;
        const stepTransformer = this.transformers.get(stepKey);
        if (stepTransformer) {
          result = stepTransformer(result);
        }
      }
      return result;
    } else if (fromMajor > toMajor) {
      // Transform backward through versions
      let result = data;
      for (let i = fromMajor; i > toMajor; i--) {
        const stepKey = `${i}.0->${i - 1}.0`;
        const stepTransformer = this.transformers.get(stepKey);
        if (stepTransformer) {
          result = stepTransformer(result);
        }
      }
      return result;
    }

    return data;
  }
}

// Global data transformer
export const dataTransformer = new DataTransformer();

// Register common transformers
dataTransformer.registerTransformer('1.0', '2.0', (data) => {
  // Transform incident structure from v1 to v2
  if (data.type === 'incident') {
    return {
      ...data,
      severity: data.priority || 'medium',
      category: data.type || 'security',
      metadata: {
        legacyId: data.id,
        migratedAt: new Date().toISOString()
      }
    };
  }
  return data;
});

dataTransformer.registerTransformer('2.0', '1.0', (data) => {
  // Transform incident structure from v2 to v1
  if (data.category === 'security') {
    const { severity, category, metadata, ...rest } = data;
    return {
      ...rest,
      priority: severity,
      type: category
    };
  }
  return data;
});