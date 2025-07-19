import { db } from '@db/client';
import Redis from 'ioredis';
import { WebSocketServer } from 'ws';
import { 
  deviceProvisioningRecords, 
  provisioningSteps,
  deviceCertificates,
  bulkProvisioningJobs,
  provisioningPolicies,
  deviceTrustStore,
  type DeviceProvisioningRecord,
  type ProvisioningStep,
  type BulkProvisioningJob,
  type ProvisioningPolicy
} from '@db/schemas/device-provisioning';
import { CertificateService } from './certificate-service';
import { TemplateService } from './template-service';
import { eq, and, desc, inArray, gte, lte } from 'drizzle-orm';
import { parse } from 'csv-parse/sync';
import { z } from 'zod';

interface ProvisioningOptions {
  templateId?: string;
  generateCertificate?: boolean;
  autoActivate?: boolean;
  validateOnly?: boolean;
  customConfig?: Record<string, any>;
}

interface ProvisioningResult {
  success: boolean;
  provisioningId?: string;
  deviceId?: string;
  certificateId?: string;
  error?: string;
  steps?: ProvisioningStep[];
}

interface BulkProvisioningOptions {
  templateId: string;
  validateOnly?: boolean;
  continueOnError?: boolean;
  parallelLimit?: number;
}

const DeviceProvisioningRequestSchema = z.object({
  deviceType: z.string(),
  manufacturer: z.string(),
  model: z.string(),
  serialNumber: z.string(),
  macAddress: z.string().regex(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  ipAddress: z.string().ip().optional(),
  location: z.object({
    siteId: z.string().uuid(),
    buildingId: z.string().uuid(),
    floorId: z.string().uuid(),
    zone: z.string().optional()
  }),
  metadata: z.record(z.any()).optional()
});

type DeviceProvisioningRequest = z.infer<typeof DeviceProvisioningRequestSchema>;

export class DeviceProvisioningService {
  private wsServer?: WebSocketServer;

  constructor(
    private db: typeof db,
    private redis: Redis,
    private certificateService: CertificateService,
    private templateService: TemplateService
  ) {}

  setWebSocketServer(wsServer: WebSocketServer): void {
    this.wsServer = wsServer;
  }

  // Single device provisioning
  async provisionDevice(
    tenantId: string,
    request: DeviceProvisioningRequest,
    options: ProvisioningOptions = {}
  ): Promise<ProvisioningResult> {
    try {
      // Validate request
      const validatedRequest = DeviceProvisioningRequestSchema.parse(request);

      // Check if device already exists
      const existingDevice = await this.checkExistingDevice(tenantId, validatedRequest.serialNumber, validatedRequest.macAddress);
      if (existingDevice) {
        return {
          success: false,
          error: 'Device already exists with this serial number or MAC address'
        };
      }

      // Apply provisioning policies
      const policies = await this.getApplicablePolicies(tenantId, validatedRequest.deviceType);
      const policyValidation = await this.validateAgainstPolicies(validatedRequest, policies);
      if (!policyValidation.valid) {
        return {
          success: false,
          error: `Policy validation failed: ${policyValidation.reason}`
        };
      }

      // Create provisioning record
      const [provisioningRecord] = await this.db.insert(deviceProvisioningRecords).values({
        tenantId,
        deviceId: crypto.randomUUID(), // Temporary ID until device is created
        provisioningMethod: 'api',
        status: 'pending',
        templateId: options.templateId,
        provisioningData: validatedRequest as any,
        metadata: {
          options,
          requestedBy: 'api', // Should come from auth context
          requestedAt: new Date().toISOString()
        }
      }).returning();

      // If validate only, stop here
      if (options.validateOnly) {
        return {
          success: true,
          provisioningId: provisioningRecord.id,
          steps: []
        };
      }

      // Start provisioning workflow
      this.startProvisioningWorkflow(provisioningRecord.id, tenantId, validatedRequest, options);

      return {
        success: true,
        provisioningId: provisioningRecord.id,
        deviceId: provisioningRecord.deviceId
      };
    } catch (error) {
      console.error('Provisioning error:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  // Bulk device provisioning
  async bulkProvisionDevices(
    tenantId: string,
    file: Buffer,
    options: BulkProvisioningOptions
  ): Promise<BulkProvisioningJob> {
    try {
      // Parse CSV file
      const records = parse(file, {
        columns: true,
        skip_empty_lines: true,
        trim: true
      });

      // Create bulk job
      const [bulkJob] = await this.db.insert(bulkProvisioningJobs).values({
        tenantId,
        jobName: `Bulk provisioning - ${new Date().toISOString()}`,
        templateId: options.templateId,
        totalDevices: records.length,
        status: 'pending',
        options: options as any,
        createdBy: 'api' // Should come from auth context
      }).returning();

      // Start bulk provisioning in background
      this.processBulkProvisioning(bulkJob.id, tenantId, records, options);

      return bulkJob;
    } catch (error) {
      throw new Error(`Failed to start bulk provisioning: ${error}`);
    }
  }

  // Get provisioning status
  async getProvisioningStatus(provisioningId: string, tenantId: string): Promise<DeviceProvisioningRecord | null> {
    const [record] = await this.db
      .select()
      .from(deviceProvisioningRecords)
      .where(and(
        eq(deviceProvisioningRecords.id, provisioningId),
        eq(deviceProvisioningRecords.tenantId, tenantId)
      ));

    if (!record) return null;

    // Get steps
    const steps = await this.db
      .select()
      .from(provisioningSteps)
      .where(eq(provisioningSteps.provisioningRecordId, provisioningId))
      .orderBy(provisioningSteps.stepOrder);

    return {
      ...record,
      steps
    } as any;
  }

  // Cancel provisioning
  async cancelProvisioning(provisioningId: string, tenantId: string): Promise<boolean> {
    const [updated] = await this.db
      .update(deviceProvisioningRecords)
      .set({
        status: 'cancelled',
        updatedAt: new Date()
      })
      .where(and(
        eq(deviceProvisioningRecords.id, provisioningId),
        eq(deviceProvisioningRecords.tenantId, tenantId),
        inArray(deviceProvisioningRecords.status, ['pending', 'in_progress'])
      ))
      .returning();

    if (updated) {
      // Notify via WebSocket
      this.broadcastProvisioningUpdate(tenantId, {
        type: 'provisioning_cancelled',
        provisioningId,
        timestamp: new Date().toISOString()
      });
    }

    return !!updated;
  }

  // Get provisioning history
  async getProvisioningHistory(
    tenantId: string,
    filters?: {
      deviceId?: string;
      status?: string;
      startDate?: Date;
      endDate?: Date;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ records: DeviceProvisioningRecord[]; total: number }> {
    const conditions = [eq(deviceProvisioningRecords.tenantId, tenantId)];

    if (filters?.deviceId) {
      conditions.push(eq(deviceProvisioningRecords.deviceId, filters.deviceId));
    }
    if (filters?.status) {
      conditions.push(eq(deviceProvisioningRecords.status, filters.status as any));
    }
    if (filters?.startDate) {
      conditions.push(gte(deviceProvisioningRecords.createdAt, filters.startDate));
    }
    if (filters?.endDate) {
      conditions.push(lte(deviceProvisioningRecords.createdAt, filters.endDate));
    }

    const records = await this.db
      .select()
      .from(deviceProvisioningRecords)
      .where(and(...conditions))
      .orderBy(desc(deviceProvisioningRecords.createdAt))
      .limit(filters?.limit || 50)
      .offset(filters?.offset || 0);

    // Get total count
    const [{ count }] = await this.db
      .select({ count: countDistinct(deviceProvisioningRecords.id) })
      .from(deviceProvisioningRecords)
      .where(and(...conditions));

    return {
      records,
      total: Number(count)
    };
  }

  // Private methods
  private async checkExistingDevice(tenantId: string, serialNumber: string, macAddress: string): Promise<boolean> {
    // Check in device management service
    // For now, return false (device doesn't exist)
    return false;
  }

  private async getApplicablePolicies(tenantId: string, deviceType: string): Promise<ProvisioningPolicy[]> {
    return await this.db
      .select()
      .from(provisioningPolicies)
      .where(and(
        eq(provisioningPolicies.tenantId, tenantId),
        eq(provisioningPolicies.active, true),
        or(
          eq(provisioningPolicies.deviceType, deviceType),
          isNull(provisioningPolicies.deviceType)
        )
      ))
      .orderBy(desc(provisioningPolicies.priority));
  }

  private async validateAgainstPolicies(
    request: DeviceProvisioningRequest,
    policies: ProvisioningPolicy[]
  ): Promise<{ valid: boolean; reason?: string }> {
    for (const policy of policies) {
      const rules = policy.rules as any;
      
      // Validate required fields
      if (rules.requiredFields) {
        for (const field of rules.requiredFields) {
          if (!request[field as keyof DeviceProvisioningRequest]) {
            return { valid: false, reason: `Missing required field: ${field}` };
          }
        }
      }

      // Validate allowed manufacturers
      if (rules.allowedManufacturers && !rules.allowedManufacturers.includes(request.manufacturer)) {
        return { valid: false, reason: `Manufacturer ${request.manufacturer} not allowed by policy` };
      }

      // Validate IP range
      if (rules.allowedIpRanges && request.ipAddress) {
        // Implement IP range validation
      }

      // Validate location restrictions
      if (rules.locationRestrictions) {
        // Implement location validation
      }
    }

    return { valid: true };
  }

  private async startProvisioningWorkflow(
    provisioningId: string,
    tenantId: string,
    request: DeviceProvisioningRequest,
    options: ProvisioningOptions
  ): Promise<void> {
    try {
      // Update status to in_progress
      await this.db
        .update(deviceProvisioningRecords)
        .set({
          status: 'in_progress',
          startedAt: new Date()
        })
        .where(eq(deviceProvisioningRecords.id, provisioningId));

      // Define provisioning steps
      const steps = [
        { name: 'validate_device', order: 1 },
        { name: 'generate_certificate', order: 2, skip: !options.generateCertificate },
        { name: 'apply_template', order: 3 },
        { name: 'configure_device', order: 4 },
        { name: 'establish_trust', order: 5 },
        { name: 'validate_configuration', order: 6 },
        { name: 'activate_device', order: 7, skip: !options.autoActivate }
      ];

      // Create step records
      for (const step of steps.filter(s => !s.skip)) {
        await this.db.insert(provisioningSteps).values({
          provisioningRecordId: provisioningId,
          stepName: step.name,
          stepOrder: step.order,
          status: 'pending'
        });
      }

      // Execute steps
      for (const step of steps.filter(s => !s.skip)) {
        const success = await this.executeProvisioningStep(
          provisioningId,
          tenantId,
          step.name,
          request,
          options
        );

        if (!success) {
          await this.failProvisioning(provisioningId, `Failed at step: ${step.name}`);
          return;
        }
      }

      // Complete provisioning
      await this.completeProvisioning(provisioningId);
    } catch (error) {
      await this.failProvisioning(provisioningId, error instanceof Error ? error.message : 'Unknown error');
    }
  }

  private async executeProvisioningStep(
    provisioningId: string,
    tenantId: string,
    stepName: string,
    request: DeviceProvisioningRequest,
    options: ProvisioningOptions
  ): Promise<boolean> {
    try {
      // Update step status
      await this.db
        .update(provisioningSteps)
        .set({
          status: 'in_progress',
          startedAt: new Date()
        })
        .where(and(
          eq(provisioningSteps.provisioningRecordId, provisioningId),
          eq(provisioningSteps.stepName, stepName)
        ));

      let success = false;
      let stepData: any = {};

      switch (stepName) {
        case 'validate_device':
          // Validate device connectivity and compatibility
          success = true; // Placeholder
          break;

        case 'generate_certificate':
          // Generate device certificate
          const certificate = await this.certificateService.generateDeviceCertificate(
            tenantId,
            request.serialNumber,
            {
              deviceType: request.deviceType,
              manufacturer: request.manufacturer,
              model: request.model
            }
          );
          if (certificate) {
            stepData = { certificateId: certificate.id };
            success = true;
          }
          break;

        case 'apply_template':
          // Apply configuration template
          if (options.templateId) {
            const template = await this.templateService.getTemplate(options.templateId, tenantId);
            if (template) {
              stepData = { templateApplied: template.name };
              success = true;
            }
          } else {
            success = true; // No template required
          }
          break;

        case 'configure_device':
          // Apply device-specific configuration
          success = true; // Placeholder
          break;

        case 'establish_trust':
          // Set up mutual trust between device and server
          success = true; // Placeholder
          break;

        case 'validate_configuration':
          // Validate final configuration
          success = true; // Placeholder
          break;

        case 'activate_device':
          // Activate device in production
          success = true; // Placeholder
          break;

        default:
          throw new Error(`Unknown provisioning step: ${stepName}`);
      }

      // Update step status
      await this.db
        .update(provisioningSteps)
        .set({
          status: success ? 'completed' : 'failed',
          completedAt: new Date(),
          stepData: stepData
        })
        .where(and(
          eq(provisioningSteps.provisioningRecordId, provisioningId),
          eq(provisioningSteps.stepName, stepName)
        ));

      // Broadcast progress
      this.broadcastProvisioningProgress(tenantId, provisioningId, stepName, success);

      return success;
    } catch (error) {
      console.error(`Error in step ${stepName}:`, error);
      
      await this.db
        .update(provisioningSteps)
        .set({
          status: 'failed',
          errorMessage: error instanceof Error ? error.message : 'Unknown error',
          completedAt: new Date()
        })
        .where(and(
          eq(provisioningSteps.provisioningRecordId, provisioningId),
          eq(provisioningSteps.stepName, stepName)
        ));

      return false;
    }
  }

  private async failProvisioning(provisioningId: string, error: string): Promise<void> {
    await this.db
      .update(deviceProvisioningRecords)
      .set({
        status: 'failed',
        errorMessage: error,
        completedAt: new Date()
      })
      .where(eq(deviceProvisioningRecords.id, provisioningId));
  }

  private async completeProvisioning(provisioningId: string): Promise<void> {
    await this.db
      .update(deviceProvisioningRecords)
      .set({
        status: 'completed',
        completedAt: new Date()
      })
      .where(eq(deviceProvisioningRecords.id, provisioningId));

    // Notify completion
    const [record] = await this.db
      .select()
      .from(deviceProvisioningRecords)
      .where(eq(deviceProvisioningRecords.id, provisioningId));

    if (record) {
      this.broadcastProvisioningComplete(record.tenantId, provisioningId, record.deviceId);
    }
  }

  private async processBulkProvisioning(
    jobId: string,
    tenantId: string,
    records: any[],
    options: BulkProvisioningOptions
  ): Promise<void> {
    try {
      // Update job status
      await this.db
        .update(bulkProvisioningJobs)
        .set({
          status: 'in_progress',
          startedAt: new Date()
        })
        .where(eq(bulkProvisioningJobs.id, jobId));

      const results = [];
      const parallelLimit = options.parallelLimit || 10;
      
      // Process in batches
      for (let i = 0; i < records.length; i += parallelLimit) {
        const batch = records.slice(i, i + parallelLimit);
        const batchResults = await Promise.allSettled(
          batch.map(record => this.provisionDevice(tenantId, record, {
            templateId: options.templateId,
            validateOnly: options.validateOnly,
            generateCertificate: true,
            autoActivate: true
          }))
        );
        
        results.push(...batchResults);

        // Update progress
        const successCount = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
        const failureCount = results.filter(r => r.status === 'rejected' || (r.status === 'fulfilled' && !r.value.success)).length;

        await this.db
          .update(bulkProvisioningJobs)
          .set({
            successCount,
            failureCount
          })
          .where(eq(bulkProvisioningJobs.id, jobId));

        // Broadcast progress
        this.broadcastBulkProgress(tenantId, jobId, {
          processed: results.length,
          total: records.length,
          successCount,
          failureCount
        });

        // Stop on error if configured
        if (!options.continueOnError && failureCount > 0) {
          break;
        }
      }

      // Complete job
      await this.db
        .update(bulkProvisioningJobs)
        .set({
          status: 'completed',
          completedAt: new Date(),
          resultFile: JSON.stringify(results) // Should save to S3 instead
        })
        .where(eq(bulkProvisioningJobs.id, jobId));

    } catch (error) {
      await this.db
        .update(bulkProvisioningJobs)
        .set({
          status: 'failed',
          errorSummary: {
            error: error instanceof Error ? error.message : 'Unknown error',
            timestamp: new Date().toISOString()
          } as any
        })
        .where(eq(bulkProvisioningJobs.id, jobId));
    }
  }

  // WebSocket broadcasting methods
  private broadcast(message: any): void {
    if (!this.wsServer) return;

    const messageStr = JSON.stringify(message);
    this.wsServer.clients.forEach(client => {
      if (client.readyState === 1) { // WebSocket.OPEN
        client.send(messageStr);
      }
    });
  }

  private broadcastProvisioningUpdate(tenantId: string, data: any): void {
    this.broadcast({
      type: 'provisioning_update',
      tenantId,
      ...data,
      timestamp: new Date().toISOString()
    });
  }

  private broadcastProvisioningProgress(
    tenantId: string,
    provisioningId: string,
    stepName: string,
    success: boolean
  ): void {
    this.broadcast({
      type: 'provisioning_progress',
      tenantId,
      provisioningId,
      stepName,
      success,
      timestamp: new Date().toISOString()
    });
  }

  private broadcastProvisioningComplete(
    tenantId: string,
    provisioningId: string,
    deviceId: string
  ): void {
    this.broadcast({
      type: 'provisioning_complete',
      tenantId,
      provisioningId,
      deviceId,
      timestamp: new Date().toISOString()
    });
  }

  private broadcastBulkProgress(
    tenantId: string,
    jobId: string,
    progress: any
  ): void {
    this.broadcast({
      type: 'bulk_provisioning_progress',
      tenantId,
      jobId,
      progress,
      timestamp: new Date().toISOString()
    });
  }
}

// Helper function that might not be available in all environments
function countDistinct(column: any): any {
  // This is a placeholder - in real implementation, use proper SQL function
  return column;
}

function or(...conditions: any[]): any {
  // This is a placeholder - implement OR logic
  return conditions;
}

function isNull(column: any): any {
  // This is a placeholder - implement IS NULL check
  return column;
}