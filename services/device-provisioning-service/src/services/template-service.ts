import { db } from '@db/client';
import Redis from 'ioredis';
import { 
  configurationTemplates,
  certificateTemplates,
  type ConfigurationTemplate,
  type CertificateTemplate,
  type NewConfigurationTemplate,
  type NewCertificateTemplate
} from '@db/schemas/device-provisioning';
import { eq, and, desc, or, ilike } from 'drizzle-orm';
import { z } from 'zod';
import Ajv from 'ajv';

const ajv = new Ajv({ allErrors: true });

interface TemplateValidationResult {
  valid: boolean;
  errors?: Array<{
    field: string;
    message: string;
  }>;
}

interface TemplateApplicationResult {
  success: boolean;
  configuration?: Record<string, any>;
  error?: string;
}

const ConfigurationTemplateCreateSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  deviceType: z.string().min(1).max(100),
  manufacturer: z.string().optional(),
  model: z.string().optional(),
  configuration: z.record(z.any()),
  validationSchema: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional()
});

const CertificateTemplateCreateSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  certificateType: z.enum(['root', 'intermediate', 'device', 'client']),
  validityDays: z.number().int().min(1).max(3650),
  keyAlgorithm: z.enum(['RSA', 'ECDSA']).default('RSA'),
  keySize: z.number().int().min(2048).max(4096).default(2048),
  signatureAlgorithm: z.string().default('SHA256withRSA'),
  subjectTemplate: z.object({
    commonName: z.string().optional(),
    organizationalUnit: z.string().optional(),
    organization: z.string().optional(),
    locality: z.string().optional(),
    state: z.string().optional(),
    country: z.string().length(2).optional()
  }),
  extensions: z.record(z.any())
});

export class TemplateService {
  constructor(
    private db: typeof db,
    private redis: Redis
  ) {}

  // Configuration Templates

  async createConfigurationTemplate(
    tenantId: string,
    userId: string,
    data: z.infer<typeof ConfigurationTemplateCreateSchema>
  ): Promise<ConfigurationTemplate> {
    try {
      // Validate input
      const validated = ConfigurationTemplateCreateSchema.parse(data);

      // Check if template with same name exists
      const existing = await this.db
        .select()
        .from(configurationTemplates)
        .where(and(
          eq(configurationTemplates.tenantId, tenantId),
          eq(configurationTemplates.name, validated.name),
          eq(configurationTemplates.active, true)
        ))
        .limit(1);

      if (existing.length > 0) {
        throw new Error('Template with this name already exists');
      }

      // Validate the configuration against schema if provided
      if (validated.validationSchema) {
        const validationResult = this.validateConfiguration(
          validated.configuration,
          validated.validationSchema
        );
        if (!validationResult.valid) {
          throw new Error(`Invalid configuration: ${JSON.stringify(validationResult.errors)}`);
        }
      }

      // Create template
      const [template] = await this.db.insert(configurationTemplates).values({
        tenantId,
        name: validated.name,
        description: validated.description,
        deviceType: validated.deviceType,
        manufacturer: validated.manufacturer,
        model: validated.model,
        configuration: validated.configuration,
        validationSchema: validated.validationSchema,
        metadata: validated.metadata,
        createdBy: userId,
        version: 1,
        isDefault: false,
        active: true
      }).returning();

      // Cache template
      await this.cacheTemplate(template);

      return template;
    } catch (error) {
      throw new Error(`Failed to create configuration template: ${error}`);
    }
  }

  async updateConfigurationTemplate(
    templateId: string,
    tenantId: string,
    userId: string,
    updates: Partial<z.infer<typeof ConfigurationTemplateCreateSchema>>
  ): Promise<ConfigurationTemplate> {
    try {
      // Get existing template
      const [existing] = await this.db
        .select()
        .from(configurationTemplates)
        .where(and(
          eq(configurationTemplates.id, templateId),
          eq(configurationTemplates.tenantId, tenantId)
        ));

      if (!existing) {
        throw new Error('Template not found');
      }

      // If configuration is being updated, validate it
      if (updates.configuration && (updates.validationSchema || existing.validationSchema)) {
        const schema = updates.validationSchema || existing.validationSchema;
        const validationResult = this.validateConfiguration(
          updates.configuration,
          schema as any
        );
        if (!validationResult.valid) {
          throw new Error(`Invalid configuration: ${JSON.stringify(validationResult.errors)}`);
        }
      }

      // Create new version
      const newVersion = existing.version + 1;
      const [updated] = await this.db.insert(configurationTemplates).values({
        ...existing,
        ...updates,
        id: undefined, // Generate new ID
        version: newVersion,
        createdBy: userId,
        createdAt: new Date(),
        updatedAt: new Date()
      }).returning();

      // Mark old version as inactive
      await this.db
        .update(configurationTemplates)
        .set({ active: false })
        .where(eq(configurationTemplates.id, templateId));

      // Update cache
      await this.invalidateTemplateCache(templateId);
      await this.cacheTemplate(updated);

      return updated;
    } catch (error) {
      throw new Error(`Failed to update configuration template: ${error}`);
    }
  }

  async getTemplate(templateId: string, tenantId: string): Promise<ConfigurationTemplate | null> {
    // Check cache first
    const cached = await this.redis.get(`template:config:${templateId}`);
    if (cached) {
      const template = JSON.parse(cached);
      if (template.tenantId === tenantId) {
        return template;
      }
    }

    const [template] = await this.db
      .select()
      .from(configurationTemplates)
      .where(and(
        eq(configurationTemplates.id, templateId),
        eq(configurationTemplates.tenantId, tenantId),
        eq(configurationTemplates.active, true)
      ));

    if (template) {
      await this.cacheTemplate(template);
    }

    return template || null;
  }

  async listConfigurationTemplates(
    tenantId: string,
    filters?: {
      deviceType?: string;
      manufacturer?: string;
      search?: string;
      includeInactive?: boolean;
    }
  ): Promise<ConfigurationTemplate[]> {
    const conditions = [eq(configurationTemplates.tenantId, tenantId)];

    if (!filters?.includeInactive) {
      conditions.push(eq(configurationTemplates.active, true));
    }

    if (filters?.deviceType) {
      conditions.push(eq(configurationTemplates.deviceType, filters.deviceType));
    }

    if (filters?.manufacturer) {
      conditions.push(eq(configurationTemplates.manufacturer, filters.manufacturer));
    }

    if (filters?.search) {
      conditions.push(
        or(
          ilike(configurationTemplates.name, `%${filters.search}%`),
          ilike(configurationTemplates.description, `%${filters.search}%`)
        )!
      );
    }

    return await this.db
      .select()
      .from(configurationTemplates)
      .where(and(...conditions))
      .orderBy(desc(configurationTemplates.createdAt));
  }

  async deleteConfigurationTemplate(
    templateId: string,
    tenantId: string
  ): Promise<boolean> {
    const [updated] = await this.db
      .update(configurationTemplates)
      .set({ 
        active: false,
        updatedAt: new Date()
      })
      .where(and(
        eq(configurationTemplates.id, templateId),
        eq(configurationTemplates.tenantId, tenantId)
      ))
      .returning();

    if (updated) {
      await this.invalidateTemplateCache(templateId);
    }

    return !!updated;
  }

  async setDefaultTemplate(
    templateId: string,
    tenantId: string,
    deviceType: string
  ): Promise<boolean> {
    // Remove default flag from other templates of same type
    await this.db
      .update(configurationTemplates)
      .set({ isDefault: false })
      .where(and(
        eq(configurationTemplates.tenantId, tenantId),
        eq(configurationTemplates.deviceType, deviceType),
        eq(configurationTemplates.isDefault, true)
      ));

    // Set new default
    const [updated] = await this.db
      .update(configurationTemplates)
      .set({ 
        isDefault: true,
        updatedAt: new Date()
      })
      .where(and(
        eq(configurationTemplates.id, templateId),
        eq(configurationTemplates.tenantId, tenantId)
      ))
      .returning();

    return !!updated;
  }

  async applyTemplate(
    templateId: string,
    tenantId: string,
    deviceData: Record<string, any>
  ): Promise<TemplateApplicationResult> {
    try {
      const template = await this.getTemplate(templateId, tenantId);
      if (!template) {
        return {
          success: false,
          error: 'Template not found'
        };
      }

      // Apply template configuration with device-specific overrides
      const configuration = this.mergeConfigurations(
        template.configuration as Record<string, any>,
        deviceData
      );

      // Validate final configuration
      if (template.validationSchema) {
        const validationResult = this.validateConfiguration(
          configuration,
          template.validationSchema as any
        );
        if (!validationResult.valid) {
          return {
            success: false,
            error: `Configuration validation failed: ${JSON.stringify(validationResult.errors)}`
          };
        }
      }

      return {
        success: true,
        configuration
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Certificate Templates

  async createCertificateTemplate(
    tenantId: string,
    data: z.infer<typeof CertificateTemplateCreateSchema>
  ): Promise<CertificateTemplate> {
    try {
      const validated = CertificateTemplateCreateSchema.parse(data);

      const [template] = await this.db.insert(certificateTemplates).values({
        tenantId,
        ...validated,
        active: true
      }).returning();

      return template;
    } catch (error) {
      throw new Error(`Failed to create certificate template: ${error}`);
    }
  }

  async updateCertificateTemplate(
    templateId: string,
    tenantId: string,
    updates: Partial<z.infer<typeof CertificateTemplateCreateSchema>>
  ): Promise<CertificateTemplate> {
    const [updated] = await this.db
      .update(certificateTemplates)
      .set({
        ...updates,
        updatedAt: new Date()
      })
      .where(and(
        eq(certificateTemplates.id, templateId),
        eq(certificateTemplates.tenantId, tenantId)
      ))
      .returning();

    if (!updated) {
      throw new Error('Certificate template not found');
    }

    return updated;
  }

  async getCertificateTemplate(
    templateId: string,
    tenantId: string
  ): Promise<CertificateTemplate | null> {
    const [template] = await this.db
      .select()
      .from(certificateTemplates)
      .where(and(
        eq(certificateTemplates.id, templateId),
        eq(certificateTemplates.tenantId, tenantId)
      ));

    return template || null;
  }

  async listCertificateTemplates(
    tenantId: string,
    certificateType?: string
  ): Promise<CertificateTemplate[]> {
    const conditions = [
      eq(certificateTemplates.tenantId, tenantId),
      eq(certificateTemplates.active, true)
    ];

    if (certificateType) {
      conditions.push(eq(certificateTemplates.certificateType, certificateType as any));
    }

    return await this.db
      .select()
      .from(certificateTemplates)
      .where(and(...conditions))
      .orderBy(desc(certificateTemplates.createdAt));
  }

  async deleteCertificateTemplate(
    templateId: string,
    tenantId: string
  ): Promise<boolean> {
    const [updated] = await this.db
      .update(certificateTemplates)
      .set({ 
        active: false,
        updatedAt: new Date()
      })
      .where(and(
        eq(certificateTemplates.id, templateId),
        eq(certificateTemplates.tenantId, tenantId)
      ))
      .returning();

    return !!updated;
  }

  // Helper methods

  private validateConfiguration(
    configuration: Record<string, any>,
    schema: Record<string, any>
  ): TemplateValidationResult {
    try {
      const validate = ajv.compile(schema);
      const valid = validate(configuration);

      if (!valid) {
        return {
          valid: false,
          errors: validate.errors?.map(error => ({
            field: error.instancePath || error.schemaPath,
            message: error.message || 'Validation error'
          }))
        };
      }

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        errors: [{ field: 'schema', message: 'Invalid validation schema' }]
      };
    }
  }

  private mergeConfigurations(
    template: Record<string, any>,
    overrides: Record<string, any>
  ): Record<string, any> {
    const merged: Record<string, any> = {};

    // Deep merge template and overrides
    const deepMerge = (target: any, source: any) => {
      for (const key in source) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
          target[key] = target[key] || {};
          deepMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
    };

    deepMerge(merged, template);
    deepMerge(merged, overrides);

    // Apply variable substitution
    const substituteVariables = (obj: any, vars: Record<string, any>): any => {
      if (typeof obj === 'string') {
        return obj.replace(/\${(\w+)}/g, (match, key) => vars[key] || match);
      } else if (Array.isArray(obj)) {
        return obj.map(item => substituteVariables(item, vars));
      } else if (obj && typeof obj === 'object') {
        const result: any = {};
        for (const key in obj) {
          result[key] = substituteVariables(obj[key], vars);
        }
        return result;
      }
      return obj;
    };

    return substituteVariables(merged, overrides);
  }

  private async cacheTemplate(template: ConfigurationTemplate): Promise<void> {
    await this.redis.setex(
      `template:config:${template.id}`,
      3600, // 1 hour
      JSON.stringify(template)
    );
  }

  private async invalidateTemplateCache(templateId: string): Promise<void> {
    await this.redis.del(`template:config:${templateId}`);
  }

  // Template versioning

  async getTemplateVersions(
    templateName: string,
    tenantId: string
  ): Promise<ConfigurationTemplate[]> {
    return await this.db
      .select()
      .from(configurationTemplates)
      .where(and(
        eq(configurationTemplates.tenantId, tenantId),
        eq(configurationTemplates.name, templateName)
      ))
      .orderBy(desc(configurationTemplates.version));
  }

  async rollbackTemplate(
    templateId: string,
    targetVersion: number,
    tenantId: string,
    userId: string
  ): Promise<ConfigurationTemplate> {
    // Get the target version
    const [targetTemplate] = await this.db
      .select()
      .from(configurationTemplates)
      .where(and(
        eq(configurationTemplates.name, 
          this.db
            .select({ name: configurationTemplates.name })
            .from(configurationTemplates)
            .where(eq(configurationTemplates.id, templateId))
            .limit(1) as any
        ),
        eq(configurationTemplates.version, targetVersion),
        eq(configurationTemplates.tenantId, tenantId)
      ));

    if (!targetTemplate) {
      throw new Error('Target template version not found');
    }

    // Create new version based on target
    return await this.createConfigurationTemplate(tenantId, userId, {
      name: targetTemplate.name,
      description: `Rollback to version ${targetVersion}`,
      deviceType: targetTemplate.deviceType,
      manufacturer: targetTemplate.manufacturer || undefined,
      model: targetTemplate.model || undefined,
      configuration: targetTemplate.configuration as Record<string, any>,
      validationSchema: targetTemplate.validationSchema as Record<string, any> | undefined,
      metadata: {
        ...(targetTemplate.metadata as any || {}),
        rollbackFrom: templateId,
        rollbackToVersion: targetVersion
      }
    });
  }

  // Template import/export

  async exportTemplate(
    templateId: string,
    tenantId: string
  ): Promise<Record<string, any>> {
    const template = await this.getTemplate(templateId, tenantId);
    if (!template) {
      throw new Error('Template not found');
    }

    return {
      name: template.name,
      description: template.description,
      deviceType: template.deviceType,
      manufacturer: template.manufacturer,
      model: template.model,
      configuration: template.configuration,
      validationSchema: template.validationSchema,
      metadata: {
        exportedAt: new Date().toISOString(),
        exportedFrom: tenantId,
        originalId: template.id,
        version: template.version
      }
    };
  }

  async importTemplate(
    tenantId: string,
    userId: string,
    templateData: Record<string, any>
  ): Promise<ConfigurationTemplate> {
    // Validate imported data
    const validated = ConfigurationTemplateCreateSchema.parse({
      name: `${templateData.name} (Imported)`,
      description: templateData.description,
      deviceType: templateData.deviceType,
      manufacturer: templateData.manufacturer,
      model: templateData.model,
      configuration: templateData.configuration,
      validationSchema: templateData.validationSchema,
      metadata: {
        ...templateData.metadata,
        importedAt: new Date().toISOString(),
        importedBy: userId
      }
    });

    return await this.createConfigurationTemplate(tenantId, userId, validated);
  }
}