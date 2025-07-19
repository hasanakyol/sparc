import { HTTPException } from 'hono/http-exception';

/**
 * Validates UUID format
 */
export function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Validates email format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validates phone number format
 */
export function isValidPhone(phone: string): boolean {
  const phoneRegex = /^[+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/;
  return phoneRegex.test(phone);
}

/**
 * Sanitizes user input to prevent XSS
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Generates a display name from first and last name
 */
export function generateDisplayName(firstName: string, lastName: string): string {
  return `${firstName} ${lastName}`.trim();
}

/**
 * Validates password strength
 */
export function validatePasswordStrength(password: string): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }

  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Masks sensitive data for logging
 */
export function maskSensitiveData(data: any): any {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const masked = { ...data };
  const sensitiveFields = ['password', 'passwordHash', 'token', 'secret', 'apiKey'];

  for (const field of sensitiveFields) {
    if (field in masked) {
      masked[field] = '***';
    }
  }

  return masked;
}

/**
 * Validates pagination parameters
 */
export function validatePagination(page: number, limit: number): {
  page: number;
  limit: number;
  skip: number;
} {
  const validPage = Math.max(1, page);
  const validLimit = Math.min(100, Math.max(1, limit));
  const skip = (validPage - 1) * validLimit;

  return {
    page: validPage,
    limit: validLimit,
    skip
  };
}

/**
 * Builds a standardized error response
 */
export function buildErrorResponse(error: unknown): {
  message: string;
  code?: string;
  details?: any;
} {
  if (error instanceof HTTPException) {
    return {
      message: error.message,
      code: `E${error.status}`,
      details: error.cause
    };
  }

  if (error instanceof Error) {
    return {
      message: error.message,
      code: 'E500'
    };
  }

  return {
    message: 'An unexpected error occurred',
    code: 'E500'
  };
}

/**
 * Checks if a user has a specific role
 */
export function hasRole(userRoles: any[], roleName: string): boolean {
  return userRoles.some(ur => ur.role?.name === roleName || ur.name === roleName);
}

/**
 * Checks if a role has a specific permission
 */
export function hasPermission(
  permissions: any[],
  resource: string,
  action: string
): boolean {
  return permissions.some(p => p.resource === resource && p.action === action);
}

/**
 * Formats a date for consistent API responses
 */
export function formatDate(date: Date | string | null): string | null {
  if (!date) return null;
  
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toISOString();
}

/**
 * Generates a cache key with consistent formatting
 */
export function generateCacheKey(...parts: string[]): string {
  return parts.filter(Boolean).join(':');
}

/**
 * Parses sort parameters from query string
 */
export function parseSortParams(
  sortBy?: string,
  sortOrder?: string,
  allowedFields: string[] = []
): { field: string; order: 'asc' | 'desc' } | null {
  if (!sortBy) return null;

  const field = allowedFields.includes(sortBy) ? sortBy : allowedFields[0];
  const order = sortOrder === 'desc' ? 'desc' : 'asc';

  return { field, order };
}