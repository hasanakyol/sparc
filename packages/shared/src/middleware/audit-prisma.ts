import { Prisma } from '@prisma/client';
import { auditLogger, AuditAction, ResourceType } from '../services/audit-logger';

// Map Prisma models to ResourceTypes
const modelToResourceType: Record<string, ResourceType> = {
  User: ResourceType.USER,
  Organization: ResourceType.ORGANIZATION,
  Site: ResourceType.SITE,
  Building: ResourceType.BUILDING,
  Floor: ResourceType.FLOOR,
  Zone: ResourceType.ZONE,
  Door: ResourceType.DOOR,
  Camera: ResourceType.CAMERA,
  AccessEvent: ResourceType.ACCESS_EVENT,
  AccessPanel: ResourceType.ACCESS_PANEL,
  Credential: ResourceType.CREDENTIAL,
  AccessGroup: ResourceType.ACCESS_GROUP,
  Schedule: ResourceType.SCHEDULE,
  Alert: ResourceType.ALERT,
  VideoRecording: ResourceType.VIDEO_RECORDING,
  Visitor: ResourceType.VISITOR,
  IncidentReport: ResourceType.INCIDENT_REPORT,
  SystemConfiguration: ResourceType.SYSTEM_CONFIG,
  IntegrationConfiguration: ResourceType.INTEGRATION,
  BackupJob: ResourceType.BACKUP,
};

// Map Prisma actions to AuditActions
const actionToAuditAction: Record<string, AuditAction> = {
  create: AuditAction.CREATE,
  createMany: AuditAction.BULK_CREATE,
  update: AuditAction.UPDATE,
  updateMany: AuditAction.BULK_UPDATE,
  delete: AuditAction.DELETE,
  deleteMany: AuditAction.BULK_DELETE,
  findUnique: AuditAction.READ,
  findFirst: AuditAction.READ,
  findMany: AuditAction.READ,
};

// Models that should not be audited
const excludedModels = ['AuditLog', 'OfflineEventQueue'];

// Sensitive fields that should not be logged
const sensitiveFields = [
  'passwordHash',
  'mfaSecret',
  'mfaBackupCodes',
  'encryptionKey',
  'apiKey',
  'privateKey',
];

/**
 * Creates Prisma middleware for automatic audit logging
 */
export function createAuditMiddleware(options?: {
  excludeReads?: boolean;
  excludeModels?: string[];
  includeOnlyModels?: string[];
}): Prisma.Middleware {
  return async (params, next) => {
    // Skip if model is excluded
    if (!params.model || excludedModels.includes(params.model)) {
      return next(params);
    }

    // Check model filters
    if (options?.excludeModels?.includes(params.model)) {
      return next(params);
    }
    if (options?.includeOnlyModels && !options.includeOnlyModels.includes(params.model)) {
      return next(params);
    }

    // Skip read operations if configured
    if (options?.excludeReads && ['findUnique', 'findFirst', 'findMany'].includes(params.action)) {
      return next(params);
    }

    const resourceType = modelToResourceType[params.model];
    const auditAction = actionToAuditAction[params.action];

    if (!resourceType || !auditAction) {
      return next(params);
    }

    // Capture old values for updates
    let oldValues: any = null;
    if (params.action === 'update' && params.args.where) {
      try {
        const model = (params as any).model;
        oldValues = await (params as any).__prismaClient[model].findUnique({
          where: params.args.where,
        });
      } catch (error) {
        // Ignore errors fetching old values
      }
    }

    try {
      // Execute the operation
      const result = await next(params);

      // Log successful operations
      if (result) {
        const resourceId = extractResourceId(params, result);
        
        if (params.action === 'update' && oldValues) {
          // Log with before/after values
          await auditLogger.logChange(
            auditAction,
            resourceType,
            resourceId,
            sanitizeData(oldValues),
            sanitizeData(result)
          );
        } else {
          // Log without change tracking
          await auditLogger.logSuccess(
            auditAction,
            resourceType,
            resourceId,
            {
              model: params.model,
              action: params.action,
              args: sanitizeArgs(params.args),
            }
          );
        }
      }

      return result;
    } catch (error: any) {
      // Log failed operations
      const resourceId = extractResourceIdFromArgs(params);
      
      await auditLogger.logFailure(
        auditAction,
        resourceType,
        resourceId || 'unknown',
        error.message,
        {
          model: params.model,
          action: params.action,
          args: sanitizeArgs(params.args),
          errorCode: error.code,
        }
      );

      throw error;
    }
  };
}

/**
 * Extract resource ID from operation result
 */
function extractResourceId(params: Prisma.MiddlewareParams, result: any): string {
  // Handle different operation types
  switch (params.action) {
    case 'create':
    case 'update':
    case 'findUnique':
    case 'findFirst':
      return result?.id || 'unknown';
    
    case 'createMany':
      return `batch:${result.count}`;
    
    case 'updateMany':
    case 'deleteMany':
      return `batch:${result.count}`;
    
    case 'delete':
      return params.args?.where?.id || 'unknown';
    
    case 'findMany':
      return `list:${Array.isArray(result) ? result.length : 0}`;
    
    default:
      return 'unknown';
  }
}

/**
 * Extract resource ID from operation arguments
 */
function extractResourceIdFromArgs(params: Prisma.MiddlewareParams): string | null {
  if (params.args?.where?.id) {
    return params.args.where.id;
  }
  
  if (params.args?.data?.id) {
    return params.args.data.id;
  }
  
  return null;
}

/**
 * Sanitize data by removing sensitive fields
 */
function sanitizeData(data: any): any {
  if (!data || typeof data !== 'object') {
    return data;
  }

  const sanitized = { ...data };
  
  for (const field of sensitiveFields) {
    if (field in sanitized) {
      sanitized[field] = '[REDACTED]';
    }
  }

  // Handle nested objects
  for (const [key, value] of Object.entries(sanitized)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      sanitized[key] = sanitizeData(value);
    }
  }

  return sanitized;
}

/**
 * Sanitize operation arguments
 */
function sanitizeArgs(args: any): any {
  if (!args) return args;

  const sanitized = JSON.parse(JSON.stringify(args));

  // Sanitize data fields
  if (sanitized.data) {
    sanitized.data = sanitizeData(sanitized.data);
  }

  // Sanitize where clauses
  if (sanitized.where) {
    // Keep where clauses but remove sensitive values
    for (const field of sensitiveFields) {
      if (field in sanitized.where) {
        sanitized.where[field] = '[REDACTED]';
      }
    }
  }

  return sanitized;
}

/**
 * Create specialized audit middleware for specific use cases
 */
export function createComplianceAuditMiddleware(): Prisma.Middleware {
  const complianceModels = [
    'User',
    'Credential',
    'AccessEvent',
    'VideoRecording',
    'VideoExportLog',
    'AuditLog',
    'Visitor',
  ];

  return createAuditMiddleware({
    includeOnlyModels: complianceModels,
    excludeReads: false, // Include reads for compliance
  });
}

/**
 * Create security audit middleware
 */
export function createSecurityAuditMiddleware(): Prisma.Middleware {
  return async (params, next) => {
    // Track authentication-related operations
    if (params.model === 'User' && params.action === 'update') {
      const updates = params.args.data;
      
      // Check for password changes
      if (updates.passwordHash) {
        await auditLogger.logSuccess(
          AuditAction.PASSWORD_CHANGED,
          ResourceType.USER,
          params.args.where?.id || 'unknown',
          { source: 'prisma-middleware' }
        );
      }
      
      // Check for MFA changes
      if ('mfaEnabled' in updates) {
        await auditLogger.logSuccess(
          updates.mfaEnabled ? AuditAction.MFA_ENABLED : AuditAction.MFA_DISABLED,
          ResourceType.USER,
          params.args.where?.id || 'unknown',
          { source: 'prisma-middleware' }
        );
      }
    }

    // Track access events
    if (params.model === 'AccessEvent' && params.action === 'create') {
      const event = params.args.data;
      await auditLogger.logSuccess(
        event.result === 'granted' ? AuditAction.ACCESS_GRANTED : AuditAction.ACCESS_DENIED,
        ResourceType.DOOR,
        event.doorId,
        {
          userId: event.userId,
          credentialId: event.credentialId,
          eventType: event.eventType,
        }
      );
    }

    return next(params);
  };
}