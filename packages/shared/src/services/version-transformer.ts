import { z } from 'zod';

/**
 * Transformation rule types
 */
export type TransformationRule = 
  | RenameFieldRule
  | AddFieldRule
  | RemoveFieldRule
  | TransformFieldRule
  | MergeFieldsRule
  | SplitFieldRule
  | ConditionalRule
  | NestedTransformRule;

interface BaseRule {
  type: string;
  description?: string;
}

interface RenameFieldRule extends BaseRule {
  type: 'rename';
  from: string;
  to: string;
}

interface AddFieldRule extends BaseRule {
  type: 'add';
  field: string;
  value: any;
  condition?: (data: any) => boolean;
}

interface RemoveFieldRule extends BaseRule {
  type: 'remove';
  field: string;
}

interface TransformFieldRule extends BaseRule {
  type: 'transform';
  field: string;
  transformer: (value: any, data: any) => any;
}

interface MergeFieldsRule extends BaseRule {
  type: 'merge';
  from: string[];
  to: string;
  merger: (values: any[]) => any;
}

interface SplitFieldRule extends BaseRule {
  type: 'split';
  from: string;
  to: string[];
  splitter: (value: any) => any[];
}

interface ConditionalRule extends BaseRule {
  type: 'conditional';
  condition: (data: any) => boolean;
  then: TransformationRule[];
  else?: TransformationRule[];
}

interface NestedTransformRule extends BaseRule {
  type: 'nested';
  field: string;
  rules: TransformationRule[];
}

/**
 * Model transformation registry
 */
export class ModelTransformationRegistry {
  private transformations: Map<string, Map<string, TransformationRule[]>> = new Map();
  private schemas: Map<string, Map<string, z.ZodSchema>> = new Map();

  /**
   * Register transformation rules between model versions
   */
  registerTransformation(
    modelName: string,
    fromVersion: string,
    toVersion: string,
    rules: TransformationRule[]
  ): void {
    const key = `${modelName}:${fromVersion}→${toVersion}`;
    if (!this.transformations.has(modelName)) {
      this.transformations.set(modelName, new Map());
    }
    this.transformations.get(modelName)!.set(`${fromVersion}→${toVersion}`, rules);
  }

  /**
   * Register model schema for validation
   */
  registerSchema(modelName: string, version: string, schema: z.ZodSchema): void {
    if (!this.schemas.has(modelName)) {
      this.schemas.set(modelName, new Map());
    }
    this.schemas.get(modelName)!.set(version, schema);
  }

  /**
   * Get transformation rules
   */
  getTransformation(
    modelName: string,
    fromVersion: string,
    toVersion: string
  ): TransformationRule[] | undefined {
    return this.transformations.get(modelName)?.get(`${fromVersion}→${toVersion}`);
  }

  /**
   * Get model schema
   */
  getSchema(modelName: string, version: string): z.ZodSchema | undefined {
    return this.schemas.get(modelName)?.get(version);
  }
}

/**
 * Model transformer
 */
export class ModelTransformer {
  constructor(private registry: ModelTransformationRegistry) {}

  /**
   * Transform data between versions
   */
  async transform(
    modelName: string,
    data: any,
    fromVersion: string,
    toVersion: string
  ): Promise<any> {
    // Validate input data
    const fromSchema = this.registry.getSchema(modelName, fromVersion);
    if (fromSchema) {
      const validation = fromSchema.safeParse(data);
      if (!validation.success) {
        throw new Error(`Invalid ${modelName} v${fromVersion} data: ${validation.error.message}`);
      }
    }

    // Get transformation rules
    const rules = this.registry.getTransformation(modelName, fromVersion, toVersion);
    if (!rules) {
      // Try to find a path through intermediate versions
      const path = this.findTransformationPath(modelName, fromVersion, toVersion);
      if (path) {
        let result = data;
        for (let i = 0; i < path.length - 1; i++) {
          result = await this.applyRules(
            result,
            this.registry.getTransformation(modelName, path[i], path[i + 1]) || []
          );
        }
        return result;
      }
      throw new Error(`No transformation found from ${modelName} v${fromVersion} to v${toVersion}`);
    }

    // Apply transformation rules
    const transformed = await this.applyRules(data, rules);

    // Validate output data
    const toSchema = this.registry.getSchema(modelName, toVersion);
    if (toSchema) {
      const validation = toSchema.safeParse(transformed);
      if (!validation.success) {
        throw new Error(`Transformation resulted in invalid ${modelName} v${toVersion} data: ${validation.error.message}`);
      }
    }

    return transformed;
  }

  /**
   * Apply transformation rules to data
   */
  private async applyRules(data: any, rules: TransformationRule[]): Promise<any> {
    let result = this.deepClone(data);

    for (const rule of rules) {
      result = await this.applyRule(result, rule);
    }

    return result;
  }

  /**
   * Apply a single transformation rule
   */
  private async applyRule(data: any, rule: TransformationRule): Promise<any> {
    switch (rule.type) {
      case 'rename':
        return this.applyRenameRule(data, rule);
      case 'add':
        return this.applyAddRule(data, rule);
      case 'remove':
        return this.applyRemoveRule(data, rule);
      case 'transform':
        return this.applyTransformRule(data, rule);
      case 'merge':
        return this.applyMergeRule(data, rule);
      case 'split':
        return this.applySplitRule(data, rule);
      case 'conditional':
        return this.applyConditionalRule(data, rule);
      case 'nested':
        return this.applyNestedRule(data, rule);
      default:
        throw new Error(`Unknown transformation rule type: ${(rule as any).type}`);
    }
  }

  private applyRenameRule(data: any, rule: RenameFieldRule): any {
    const value = this.getField(data, rule.from);
    if (value !== undefined) {
      this.deleteField(data, rule.from);
      this.setField(data, rule.to, value);
    }
    return data;
  }

  private applyAddRule(data: any, rule: AddFieldRule): any {
    if (!rule.condition || rule.condition(data)) {
      const value = typeof rule.value === 'function' ? rule.value(data) : rule.value;
      this.setField(data, rule.field, value);
    }
    return data;
  }

  private applyRemoveRule(data: any, rule: RemoveFieldRule): any {
    this.deleteField(data, rule.field);
    return data;
  }

  private applyTransformRule(data: any, rule: TransformFieldRule): any {
    const value = this.getField(data, rule.field);
    if (value !== undefined) {
      const transformed = rule.transformer(value, data);
      this.setField(data, rule.field, transformed);
    }
    return data;
  }

  private applyMergeRule(data: any, rule: MergeFieldsRule): any {
    const values = rule.from.map(field => this.getField(data, field));
    const merged = rule.merger(values);
    rule.from.forEach(field => this.deleteField(data, field));
    this.setField(data, rule.to, merged);
    return data;
  }

  private applySplitRule(data: any, rule: SplitFieldRule): any {
    const value = this.getField(data, rule.from);
    if (value !== undefined) {
      const values = rule.splitter(value);
      this.deleteField(data, rule.from);
      rule.to.forEach((field, index) => {
        if (values[index] !== undefined) {
          this.setField(data, field, values[index]);
        }
      });
    }
    return data;
  }

  private async applyConditionalRule(data: any, rule: ConditionalRule): Promise<any> {
    const rules = rule.condition(data) ? rule.then : (rule.else || []);
    return await this.applyRules(data, rules);
  }

  private async applyNestedRule(data: any, rule: NestedTransformRule): Promise<any> {
    const nestedData = this.getField(data, rule.field);
    if (nestedData !== undefined) {
      if (Array.isArray(nestedData)) {
        const transformed = await Promise.all(
          nestedData.map(item => this.applyRules(item, rule.rules))
        );
        this.setField(data, rule.field, transformed);
      } else if (typeof nestedData === 'object' && nestedData !== null) {
        const transformed = await this.applyRules(nestedData, rule.rules);
        this.setField(data, rule.field, transformed);
      }
    }
    return data;
  }

  /**
   * Find transformation path between versions
   */
  private findTransformationPath(
    modelName: string,
    fromVersion: string,
    toVersion: string
  ): string[] | null {
    // Simple BFS to find path
    const queue: { version: string; path: string[] }[] = [
      { version: fromVersion, path: [fromVersion] }
    ];
    const visited = new Set<string>([fromVersion]);

    while (queue.length > 0) {
      const { version, path } = queue.shift()!;

      if (version === toVersion) {
        return path;
      }

      // Check all possible transformations from this version
      const modelTransforms = this.registry['transformations'].get(modelName);
      if (modelTransforms) {
        for (const key of modelTransforms.keys()) {
          if (key.startsWith(`${version}→`)) {
            const nextVersion = key.split('→')[1];
            if (!visited.has(nextVersion)) {
              visited.add(nextVersion);
              queue.push({
                version: nextVersion,
                path: [...path, nextVersion]
              });
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Field manipulation helpers
   */
  private getField(obj: any, path: string): any {
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

  private setField(obj: any, path: string, value: any): void {
    const parts = path.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current) || typeof current[part] !== 'object') {
        current[part] = {};
      }
      current = current[part];
    }
    current[parts[parts.length - 1]] = value;
  }

  private deleteField(obj: any, path: string): void {
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

  private deepClone(obj: any): any {
    return JSON.parse(JSON.stringify(obj));
  }
}

// Global registry and transformer
export const modelTransformationRegistry = new ModelTransformationRegistry();
export const modelTransformer = new ModelTransformer(modelTransformationRegistry);

// Register common model transformations
// Incident model v1.0 to v2.0
modelTransformationRegistry.registerTransformation('Incident', '1.0', '2.0', [
  {
    type: 'rename',
    from: 'incident_id',
    to: 'id'
  },
  {
    type: 'rename',
    from: 'incident_type',
    to: 'category'
  },
  {
    type: 'transform',
    field: 'priority',
    transformer: (value: string) => {
      const mapping: Record<string, string> = {
        'low': 'P4',
        'medium': 'P3',
        'high': 'P2',
        'critical': 'P1'
      };
      return mapping[value] || value;
    }
  },
  {
    type: 'add',
    field: 'metadata',
    value: (data: any) => ({
      version: '2.0',
      migratedAt: new Date().toISOString(),
      legacyId: data.incident_id
    })
  },
  {
    type: 'merge',
    from: ['created_by', 'created_at'],
    to: 'createdInfo',
    merger: (values: any[]) => ({
      userId: values[0],
      timestamp: values[1]
    })
  },
  {
    type: 'nested',
    field: 'attachments',
    rules: [
      {
        type: 'rename',
        from: 'file_name',
        to: 'fileName'
      },
      {
        type: 'rename',
        from: 'file_size',
        to: 'fileSize'
      }
    ]
  }
]);

// User model v1.0 to v2.0
modelTransformationRegistry.registerTransformation('User', '1.0', '2.0', [
  {
    type: 'rename',
    from: 'user_id',
    to: 'id'
  },
  {
    type: 'split',
    from: 'full_name',
    to: ['firstName', 'lastName'],
    splitter: (value: string) => {
      const parts = value.split(' ');
      return [parts[0], parts.slice(1).join(' ')];
    }
  },
  {
    type: 'transform',
    field: 'roles',
    transformer: (value: string[]) => {
      // Convert old role names to new format
      return value.map(role => {
        const mapping: Record<string, string> = {
          'admin': 'system.admin',
          'user': 'tenant.user',
          'viewer': 'tenant.viewer'
        };
        return mapping[role] || role;
      });
    }
  },
  {
    type: 'conditional',
    condition: (data: any) => data.is_active === false,
    then: [
      {
        type: 'add',
        field: 'status',
        value: 'inactive'
      },
      {
        type: 'add',
        field: 'deactivatedAt',
        value: new Date().toISOString()
      }
    ],
    else: [
      {
        type: 'add',
        field: 'status',
        value: 'active'
      }
    ]
  },
  {
    type: 'remove',
    field: 'is_active'
  }
]);

// Camera model v2.0 to v2.1
modelTransformationRegistry.registerTransformation('Camera', '2.0', '2.1', [
  {
    type: 'add',
    field: 'capabilities',
    value: (data: any) => {
      const caps = [];
      if (data.has_ptz) caps.push('ptz');
      if (data.has_audio) caps.push('audio');
      if (data.has_analytics) caps.push('analytics');
      return caps;
    }
  },
  {
    type: 'remove',
    field: 'has_ptz'
  },
  {
    type: 'remove',
    field: 'has_audio'
  },
  {
    type: 'remove',
    field: 'has_analytics'
  },
  {
    type: 'add',
    field: 'streamProfiles',
    value: [
      {
        name: 'high',
        resolution: '1920x1080',
        fps: 30,
        bitrate: 4000
      },
      {
        name: 'low',
        resolution: '640x480',
        fps: 15,
        bitrate: 500
      }
    ]
  }
]);

// Register schemas for validation
modelTransformationRegistry.registerSchema('Incident', '2.0', z.object({
  id: z.string().uuid(),
  category: z.string(),
  priority: z.enum(['P1', 'P2', 'P3', 'P4']),
  description: z.string(),
  status: z.string(),
  createdInfo: z.object({
    userId: z.string(),
    timestamp: z.string().datetime()
  }),
  metadata: z.object({
    version: z.string(),
    migratedAt: z.string().datetime(),
    legacyId: z.string().optional()
  }),
  attachments: z.array(z.object({
    fileName: z.string(),
    fileSize: z.number(),
    mimeType: z.string()
  })).optional()
}));

modelTransformationRegistry.registerSchema('User', '2.0', z.object({
  id: z.string().uuid(),
  firstName: z.string(),
  lastName: z.string(),
  email: z.string().email(),
  roles: z.array(z.string()),
  permissions: z.array(z.string()).optional(),
  status: z.enum(['active', 'inactive']),
  deactivatedAt: z.string().datetime().optional()
}));

modelTransformationRegistry.registerSchema('Camera', '2.1', z.object({
  id: z.string().uuid(),
  name: z.string(),
  location: z.string(),
  capabilities: z.array(z.string()),
  streamProfiles: z.array(z.object({
    name: z.string(),
    resolution: z.string(),
    fps: z.number(),
    bitrate: z.number()
  }))
}));