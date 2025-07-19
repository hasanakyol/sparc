import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4, v5 as uuidv5 } from 'uuid';
import { format, parseISO, isValid, addDays, subDays, startOfDay, endOfDay } from 'date-fns';
import { zonedTimeToUtc, utcToZonedTime, format as formatTz } from 'date-fns-tz';
import winston from 'winston';
import { z } from 'zod';
import { isObject, omit, pick, merge } from 'lodash';

// ============================================================================
// TYPES AND INTERFACES
// ============================================================================

export interface JWTPayload {
  userId: string;
  tenantId: string;
  roles: string[];
  permissions: string[];
  iat?: number;
  exp?: number;
  jti?: string;
}

export interface TenantContext {
  tenantId: string;
  organizationId?: string;
  siteId?: string;
  buildingId?: string;
  floorId?: string;
}

export interface ErrorDetails {
  code: string;
  message: string;
  details?: Record<string, any>;
  timestamp: string;
  requestId: string;
  tenantId?: string;
}

export interface APIResponse<T = any> {
  success: boolean;
  data?: T;
  error?: ErrorDetails;
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    hasNext?: boolean;
    hasPrev?: boolean;
  };
}

export interface LogContext {
  requestId: string;
  tenantId?: string;
  userId?: string;
  action?: string;
  resource?: string;
  ip?: string;
  userAgent?: string;
}

// ============================================================================
// ERROR HANDLING UTILITIES
// ============================================================================

export enum ErrorCodes {
  // Authentication Errors (401)
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  EXPIRED_TOKEN = 'EXPIRED_TOKEN',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',
  INVALID_TOKEN = 'INVALID_TOKEN',
  
  // Validation Errors (400)
  INVALID_INPUT = 'INVALID_INPUT',
  MISSING_REQUIRED_FIELD = 'MISSING_REQUIRED_FIELD',
  BUSINESS_RULE_VIOLATION = 'BUSINESS_RULE_VIOLATION',
  INVALID_FORMAT = 'INVALID_FORMAT',
  
  // Resource Errors (404, 409)
  RESOURCE_NOT_FOUND = 'RESOURCE_NOT_FOUND',
  RESOURCE_CONFLICT = 'RESOURCE_CONFLICT',
  TENANT_ISOLATION_VIOLATION = 'TENANT_ISOLATION_VIOLATION',
  DUPLICATE_RESOURCE = 'DUPLICATE_RESOURCE',
  
  // System Errors (500, 503)
  DATABASE_CONNECTION_FAILED = 'DATABASE_CONNECTION_FAILED',
  EXTERNAL_SERVICE_UNAVAILABLE = 'EXTERNAL_SERVICE_UNAVAILABLE',
  HARDWARE_COMMUNICATION_ERROR = 'HARDWARE_COMMUNICATION_ERROR',
  INTERNAL_SERVER_ERROR = 'INTERNAL_SERVER_ERROR',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  
  // Multi-tenant Errors
  TENANT_NOT_FOUND = 'TENANT_NOT_FOUND',
  TENANT_SUSPENDED = 'TENANT_SUSPENDED',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',
  
  // Offline/Network Errors
  NETWORK_UNAVAILABLE = 'NETWORK_UNAVAILABLE',
  SYNC_CONFLICT = 'SYNC_CONFLICT',
  OFFLINE_OPERATION_FAILED = 'OFFLINE_OPERATION_FAILED'
}

export class SPARCError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details: Record<string, any>;
  public readonly requestId: string;
  public readonly tenantId?: string;
  public readonly timestamp: string;

  constructor(
    code: string,
    message: string,
    statusCode: number = 500,
    details: Record<string, any> = {},
    requestId: string = generateRequestId(),
    tenantId?: string
  ) {
    super(message);
    this.name = 'SPARCError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    this.requestId = requestId;
    this.tenantId = tenantId;
    this.timestamp = new Date().toISOString();
    
    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SPARCError);
    }
  }

  toJSON(): ErrorDetails {
    return {
      code: this.code,
      message: this.message,
      details: this.details,
      timestamp: this.timestamp,
      requestId: this.requestId,
      tenantId: this.tenantId
    };
  }
}

export function createError(
  code: ErrorCodes,
  message: string,
  statusCode?: number,
  details?: Record<string, any>,
  requestId?: string,
  tenantId?: string
): SPARCError {
  const defaultStatusCodes: Record<string, number> = {
    [ErrorCodes.INVALID_CREDENTIALS]: 401,
    [ErrorCodes.EXPIRED_TOKEN]: 401,
    [ErrorCodes.INSUFFICIENT_PERMISSIONS]: 403,
    [ErrorCodes.INVALID_TOKEN]: 401,
    [ErrorCodes.INVALID_INPUT]: 400,
    [ErrorCodes.MISSING_REQUIRED_FIELD]: 400,
    [ErrorCodes.BUSINESS_RULE_VIOLATION]: 400,
    [ErrorCodes.INVALID_FORMAT]: 400,
    [ErrorCodes.RESOURCE_NOT_FOUND]: 404,
    [ErrorCodes.RESOURCE_CONFLICT]: 409,
    [ErrorCodes.TENANT_ISOLATION_VIOLATION]: 403,
    [ErrorCodes.DUPLICATE_RESOURCE]: 409,
    [ErrorCodes.DATABASE_CONNECTION_FAILED]: 503,
    [ErrorCodes.EXTERNAL_SERVICE_UNAVAILABLE]: 503,
    [ErrorCodes.HARDWARE_COMMUNICATION_ERROR]: 503,
    [ErrorCodes.INTERNAL_SERVER_ERROR]: 500,
    [ErrorCodes.SERVICE_UNAVAILABLE]: 503,
    [ErrorCodes.TENANT_NOT_FOUND]: 404,
    [ErrorCodes.TENANT_SUSPENDED]: 403,
    [ErrorCodes.QUOTA_EXCEEDED]: 429,
    [ErrorCodes.NETWORK_UNAVAILABLE]: 503,
    [ErrorCodes.SYNC_CONFLICT]: 409,
    [ErrorCodes.OFFLINE_OPERATION_FAILED]: 503
  };

  return new SPARCError(
    code,
    message,
    statusCode || defaultStatusCodes[code] || 500,
    details,
    requestId,
    tenantId
  );
}

// ============================================================================
// JWT TOKEN UTILITIES
// ============================================================================

export interface JWTOptions {
  secret: string;
  expiresIn?: string | number;
  issuer?: string;
  audience?: string;
}

export function generateJWT(
  payload: Omit<JWTPayload, 'iat' | 'exp' | 'jti'>,
  options: JWTOptions
): string {
  const jwtPayload: JWTPayload = {
    ...payload,
    jti: uuidv4()
  };

  return jwt.sign(jwtPayload, options.secret, {
    expiresIn: options.expiresIn || '1h',
    issuer: options.issuer || 'sparc-platform',
    audience: options.audience || 'sparc-api'
  });
}

export function verifyJWT(token: string, secret: string): JWTPayload {
  try {
    const decoded = jwt.verify(token, secret) as JWTPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw createError(ErrorCodes.EXPIRED_TOKEN, 'JWT token has expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw createError(ErrorCodes.INVALID_TOKEN, 'Invalid JWT token');
    } else {
      throw createError(ErrorCodes.INVALID_TOKEN, 'Token verification failed');
    }
  }
}

export function parseJWT(token: string): JWTPayload | null {
  try {
    const decoded = jwt.decode(token) as JWTPayload;
    return decoded;
  } catch {
    return null;
  }
}

export function isJWTExpired(token: string): boolean {
  const decoded = parseJWT(token);
  if (!decoded || !decoded.exp) return true;
  
  return Date.now() >= decoded.exp * 1000;
}

export function refreshJWT(
  token: string,
  secret: string,
  options: JWTOptions
): string {
  const decoded = verifyJWT(token, secret);
  const newPayload = omit(decoded, ['iat', 'exp', 'jti']);
  return generateJWT(newPayload, options);
}

// ============================================================================
// PASSWORD UTILITIES
// ============================================================================

export interface PasswordOptions {
  saltRounds?: number;
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
}

const DEFAULT_PASSWORD_OPTIONS: Required<PasswordOptions> = {
  saltRounds: 12,
  minLength: 8,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true
};

export async function hashPassword(
  password: string,
  options: PasswordOptions = {}
): Promise<string> {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  
  if (!validatePasswordStrength(password, opts)) {
    throw createError(
      ErrorCodes.INVALID_INPUT,
      'Password does not meet security requirements'
    );
  }

  return bcrypt.hash(password, opts.saltRounds);
}

export async function verifyPassword(
  password: string,
  hashedPassword: string
): Promise<boolean> {
  return bcrypt.compare(password, hashedPassword);
}

export function validatePasswordStrength(
  password: string,
  options: PasswordOptions = {}
): boolean {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };

  if (password.length < opts.minLength) return false;
  if (opts.requireUppercase && !/[A-Z]/.test(password)) return false;
  if (opts.requireLowercase && !/[a-z]/.test(password)) return false;
  if (opts.requireNumbers && !/\d/.test(password)) return false;
  if (opts.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false;

  return true;
}

export function generateSecurePassword(length: number = 16): string {
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const special = '!@#$%^&*(),.?":{}|<>';
  
  const allChars = uppercase + lowercase + numbers + special;
  let password = '';
  
  // Ensure at least one character from each category
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  password += special[Math.floor(Math.random() * special.length)];
  
  // Fill the rest randomly
  for (let i = 4; i < length; i++) {
    password += allChars[Math.floor(Math.random() * allChars.length)];
  }
  
  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

// ============================================================================
// UUID UTILITIES
// ============================================================================

export function generateUUID(): string {
  return uuidv4();
}

export function generateNamespaceUUID(name: string, namespace: string): string {
  return uuidv5(name, namespace);
}

export function generateRequestId(): string {
  return `req_${uuidv4()}`;
}

export function generateCorrelationId(): string {
  return `corr_${uuidv4()}`;
}

export function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// ============================================================================
// DATE/TIME UTILITIES
// ============================================================================

export interface DateTimeOptions {
  timezone?: string;
  format?: string;
}

export function formatDateTime(
  date: Date | string,
  options: DateTimeOptions = {}
): string {
  const { timezone = 'UTC', format: formatStr = 'yyyy-MM-dd HH:mm:ss' } = options;
  
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  
  if (!isValid(dateObj)) {
    throw createError(ErrorCodes.INVALID_FORMAT, 'Invalid date format');
  }

  if (timezone === 'UTC') {
    return format(dateObj, formatStr);
  }

  const zonedDate = utcToZonedTime(dateObj, timezone);
  return formatTz(zonedDate, formatStr, { timeZone: timezone });
}

export function parseDateTime(
  dateString: string,
  timezone: string = 'UTC'
): Date {
  const parsed = parseISO(dateString);
  
  if (!isValid(parsed)) {
    throw createError(ErrorCodes.INVALID_FORMAT, 'Invalid date string');
  }

  return timezone === 'UTC' ? parsed : zonedTimeToUtc(parsed, timezone);
}

export function getCurrentTimestamp(): string {
  return new Date().toISOString();
}

export function addDaysToDate(date: Date | string, days: number): Date {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  return addDays(dateObj, days);
}

export function subtractDaysFromDate(date: Date | string, days: number): Date {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  return subDays(dateObj, days);
}

export function getStartOfDay(date: Date | string, timezone?: string): Date {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  
  if (timezone && timezone !== 'UTC') {
    const zonedDate = utcToZonedTime(dateObj, timezone);
    const startOfDayZoned = startOfDay(zonedDate);
    return zonedTimeToUtc(startOfDayZoned, timezone);
  }
  
  return startOfDay(dateObj);
}

export function getEndOfDay(date: Date | string, timezone?: string): Date {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  
  if (timezone && timezone !== 'UTC') {
    const zonedDate = utcToZonedTime(dateObj, timezone);
    const endOfDayZoned = endOfDay(zonedDate);
    return zonedTimeToUtc(endOfDayZoned, timezone);
  }
  
  return endOfDay(dateObj);
}

export function isDateInRange(
  date: Date | string,
  startDate: Date | string,
  endDate: Date | string
): boolean {
  const dateObj = typeof date === 'string' ? parseISO(date) : date;
  const startObj = typeof startDate === 'string' ? parseISO(startDate) : startDate;
  const endObj = typeof endDate === 'string' ? parseISO(endDate) : endDate;
  
  return dateObj >= startObj && dateObj <= endObj;
}

// ============================================================================
// LOGGING UTILITIES
// ============================================================================

export interface LoggerConfig {
  level?: string;
  service?: string;
  environment?: string;
  enableConsole?: boolean;
  enableFile?: boolean;
  filename?: string;
}

const DEFAULT_LOGGER_CONFIG: Required<LoggerConfig> = {
  level: 'info',
  service: 'sparc-service',
  environment: 'development',
  enableConsole: true,
  enableFile: false,
  filename: 'sparc.log'
};

export function createLogger(config: LoggerConfig = {}): winston.Logger {
  const opts = { ...DEFAULT_LOGGER_CONFIG, ...config };
  
  const transports: winston.transport[] = [];
  
  if (opts.enableConsole) {
    transports.push(
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp(),
          winston.format.printf(({ timestamp, level, message, ...meta }) => {
            const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
            return `${timestamp} [${level}]: ${message} ${metaStr}`;
          })
        )
      })
    );
  }
  
  if (opts.enableFile) {
    transports.push(
      new winston.transports.File({
        filename: opts.filename,
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      })
    );
  }

  return winston.createLogger({
    level: opts.level,
    defaultMeta: {
      service: opts.service,
      environment: opts.environment
    },
    transports
  });
}

export function logWithContext(
  logger: winston.Logger,
  level: string,
  message: string,
  context: LogContext,
  additionalData?: Record<string, any>
): void {
  logger.log(level, message, {
    ...context,
    ...additionalData,
    timestamp: getCurrentTimestamp()
  });
}

export function logError(
  logger: winston.Logger,
  error: Error | SPARCError,
  context: LogContext,
  additionalData?: Record<string, any>
): void {
  const errorData = error instanceof SPARCError ? error.toJSON() : {
    name: error.name,
    message: error.message,
    stack: error.stack
  };

  logWithContext(logger, 'error', error.message, context, {
    error: errorData,
    ...additionalData
  });
}

export function logAudit(
  logger: winston.Logger,
  action: string,
  resource: string,
  context: LogContext,
  result: 'success' | 'failure',
  additionalData?: Record<string, any>
): void {
  logWithContext(logger, 'info', `Audit: ${action} ${resource}`, context, {
    audit: true,
    action,
    resource,
    result,
    ...additionalData
  });
}

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

export const CommonSchemas = {
  uuid: z.string().uuid(),
  email: z.string().email(),
  password: z.string().min(8),
  tenantId: z.string().uuid(),
  userId: z.string().uuid(),
  timestamp: z.string().datetime(),
  pagination: z.object({
    page: z.number().int().min(1).default(1),
    limit: z.number().int().min(1).max(100).default(20)
  }),
  tenantContext: z.object({
    tenantId: z.string().uuid(),
    organizationId: z.string().uuid().optional(),
    siteId: z.string().uuid().optional(),
    buildingId: z.string().uuid().optional(),
    floorId: z.string().uuid().optional()
  })
};

export function validateInput<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  requestId?: string
): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw createError(
        ErrorCodes.INVALID_INPUT,
        'Validation failed',
        400,
        { validationErrors: error.errors },
        requestId
      );
    }
    throw error;
  }
}

export function validatePartialInput<T>(
  schema: z.ZodSchema<T>,
  data: unknown,
  requestId?: string
): Partial<T> {
  return validateInput(schema.partial(), data, requestId);
}

export function createValidationError(
  field: string,
  message: string,
  requestId?: string
): SPARCError {
  return createError(
    ErrorCodes.INVALID_INPUT,
    `Validation error: ${field} - ${message}`,
    400,
    { field, validationMessage: message },
    requestId
  );
}

// ============================================================================
// MULTI-TENANT UTILITIES
// ============================================================================

export function extractTenantContext(headers: Record<string, string>): TenantContext {
  const tenantId = headers['x-tenant-id'];
  
  if (!tenantId) {
    throw createError(
      ErrorCodes.MISSING_REQUIRED_FIELD,
      'Tenant ID is required',
      400
    );
  }

  if (!isValidUUID(tenantId)) {
    throw createError(
      ErrorCodes.INVALID_FORMAT,
      'Invalid tenant ID format',
      400
    );
  }

  return {
    tenantId,
    organizationId: headers['x-organization-id'],
    siteId: headers['x-site-id'],
    buildingId: headers['x-building-id'],
    floorId: headers['x-floor-id']
  };
}

export function validateTenantAccess(
  userTenantId: string,
  resourceTenantId: string,
  requestId?: string
): void {
  if (userTenantId !== resourceTenantId) {
    throw createError(
      ErrorCodes.TENANT_ISOLATION_VIOLATION,
      'Access denied: tenant isolation violation',
      403,
      { userTenantId, resourceTenantId },
      requestId
    );
  }
}

export function addTenantFilter<T extends Record<string, any>>(
  query: T,
  tenantId: string
): T & { tenantId: string } {
  return { ...query, tenantId };
}

export function createTenantAwareId(tenantId: string, resourceType: string): string {
  return `${tenantId}_${resourceType}_${generateUUID()}`;
}

export function parseTenantAwareId(id: string): { tenantId: string; resourceType: string; uuid: string } | null {
  const parts = id.split('_');
  if (parts.length !== 3) return null;
  
  const [tenantId, resourceType, uuid] = parts;
  if (!isValidUUID(tenantId) || !isValidUUID(uuid)) return null;
  
  return { tenantId, resourceType, uuid };
}

// ============================================================================
// API RESPONSE FORMATTERS
// ============================================================================

export function createSuccessResponse<T>(
  data: T,
  meta?: APIResponse<T>['meta']
): APIResponse<T> {
  return {
    success: true,
    data,
    meta
  };
}

export function createErrorResponse(
  error: SPARCError | Error,
  requestId?: string
): APIResponse {
  if (error instanceof SPARCError) {
    return {
      success: false,
      error: error.toJSON()
    };
  }

  return {
    success: false,
    error: {
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
      message: error.message,
      timestamp: getCurrentTimestamp(),
      requestId: requestId || generateRequestId()
    }
  };
}

export function createPaginatedResponse<T>(
  data: T[],
  page: number,
  limit: number,
  total: number
): APIResponse<T[]> {
  const totalPages = Math.ceil(total / limit);
  
  return createSuccessResponse(data, {
    page,
    limit,
    total,
    hasNext: page < totalPages,
    hasPrev: page > 1
  });
}

export function createEmptyResponse(): APIResponse<null> {
  return createSuccessResponse(null);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

export function sanitizeObject<T extends Record<string, any>>(
  obj: T,
  allowedFields: string[]
): Partial<T> {
  return pick(obj, allowedFields);
}

export function removeNullUndefined<T extends Record<string, any>>(obj: T): Partial<T> {
  const result: Partial<T> = {};
  
  for (const [key, value] of Object.entries(obj)) {
    if (value !== null && value !== undefined) {
      result[key as keyof T] = value;
    }
  }
  
  return result;
}

export function deepMerge<T extends Record<string, any>>(target: T, source: Partial<T>): T {
  return merge({}, target, source);
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function retry<T>(
  fn: () => Promise<T>,
  maxAttempts: number = 3,
  delay: number = 1000
): Promise<T> {
  return new Promise(async (resolve, reject) => {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const result = await fn();
        resolve(result);
        return;
      } catch (error) {
        if (attempt === maxAttempts) {
          reject(error);
          return;
        }
        await sleep(delay * attempt); // Exponential backoff
      }
    }
  });
}

export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

export * from './types';
export * from './encryption';
export * from './credential-service';
export * from './env-validation';
export * from './secret-rotation';
export * from './service-auth';

// Re-export commonly used external utilities
export { z } from 'zod';
export { format as formatDate, parseISO, isValid as isValidDate } from 'date-fns';