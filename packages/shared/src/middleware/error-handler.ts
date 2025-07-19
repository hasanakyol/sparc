import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { logger } from '../logger';
import { ZodError } from 'zod';

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    requestId?: string;
    path?: string;
  };
}

/**
 * Global error handler middleware for Hono applications
 */
export function globalErrorHandler(err: Error, c: Context): Response {
  const requestId = c.get('requestId') || 'unknown';
  const path = c.req.path;
  const method = c.req.method;
  const userAgent = c.req.header('user-agent');
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';

  // Log error details
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    requestId,
    path,
    method,
    userAgent,
    clientIp,
    name: err.name
  });

  // Handle different error types
  if (err instanceof HTTPException) {
    // HTTPException already has proper status and message
    const response = err.getResponse();
    return response;
  }

  if (err instanceof ZodError) {
    // Validation errors
    const errorResponse: ErrorResponse = {
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        details: err.errors.map(e => ({
          field: e.path.join('.'),
          message: e.message,
          code: e.code
        })),
        timestamp: new Date().toISOString(),
        requestId,
        path
      }
    };
    return c.json(errorResponse, 400);
  }

  if (err.name === 'UnauthorizedError') {
    // JWT errors
    const errorResponse: ErrorResponse = {
      error: {
        code: 'UNAUTHORIZED',
        message: err.message || 'Authentication required',
        timestamp: new Date().toISOString(),
        requestId,
        path
      }
    };
    return c.json(errorResponse, 401);
  }

  if (err.name === 'PrismaClientKnownRequestError') {
    // Database errors
    const prismaError = err as any;
    let code = 'DATABASE_ERROR';
    let message = 'Database operation failed';
    let status = 500;

    switch (prismaError.code) {
      case 'P2002':
        code = 'DUPLICATE_ENTRY';
        message = 'A record with this value already exists';
        status = 409;
        break;
      case 'P2025':
        code = 'NOT_FOUND';
        message = 'Record not found';
        status = 404;
        break;
      case 'P2003':
        code = 'FOREIGN_KEY_CONSTRAINT';
        message = 'Operation would violate a foreign key constraint';
        status = 400;
        break;
      case 'P2014':
        code = 'INVALID_RELATION';
        message = 'The requested relation does not exist';
        status = 400;
        break;
    }

    const errorResponse: ErrorResponse = {
      error: {
        code,
        message,
        timestamp: new Date().toISOString(),
        requestId,
        path
      }
    };
    return c.json(errorResponse, status);
  }

  if (err.message?.includes('ECONNREFUSED')) {
    // Connection errors
    const errorResponse: ErrorResponse = {
      error: {
        code: 'SERVICE_UNAVAILABLE',
        message: 'Service temporarily unavailable',
        timestamp: new Date().toISOString(),
        requestId,
        path
      }
    };
    return c.json(errorResponse, 503);
  }

  if (err.name === 'TimeoutError' || err.message?.includes('timeout')) {
    // Timeout errors
    const errorResponse: ErrorResponse = {
      error: {
        code: 'TIMEOUT',
        message: 'Request timeout',
        timestamp: new Date().toISOString(),
        requestId,
        path
      }
    };
    return c.json(errorResponse, 504);
  }

  // Generic error response for production
  const errorResponse: ErrorResponse = {
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: process.env.NODE_ENV === 'production' 
        ? 'An unexpected error occurred' 
        : err.message,
      timestamp: new Date().toISOString(),
      requestId,
      path,
      ...(process.env.NODE_ENV !== 'production' && { 
        details: {
          stack: err.stack,
          name: err.name
        }
      })
    }
  };

  return c.json(errorResponse, 500);
}

/**
 * Not found handler
 */
export function notFoundHandler(c: Context): Response {
  const errorResponse: ErrorResponse = {
    error: {
      code: 'NOT_FOUND',
      message: 'The requested endpoint was not found',
      timestamp: new Date().toISOString(),
      requestId: c.get('requestId'),
      path: c.req.path
    }
  };
  return c.json(errorResponse, 404);
}

/**
 * Error boundary for async route handlers
 */
export function asyncErrorBoundary<T extends (...args: any[]) => Promise<any>>(
  handler: T
): T {
  return (async (...args: any[]) => {
    try {
      return await handler(...args);
    } catch (error) {
      // Re-throw to be caught by global error handler
      throw error;
    }
  }) as T;
}

/**
 * Create error response helper
 */
export function createErrorResponse(
  code: string,
  message: string,
  status: number,
  details?: any
): Response {
  const errorResponse: ErrorResponse = {
    error: {
      code,
      message,
      details,
      timestamp: new Date().toISOString()
    }
  };
  return Response.json(errorResponse, { status });
}

/**
 * Common error codes
 */
export const ErrorCodes = {
  // Client errors
  BAD_REQUEST: 'BAD_REQUEST',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  
  // Server errors
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
  TIMEOUT: 'TIMEOUT',
  
  // Business logic errors
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  RESOURCE_LOCKED: 'RESOURCE_LOCKED',
  OPERATION_NOT_ALLOWED: 'OPERATION_NOT_ALLOWED',
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED',
  
  // Auth errors
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  MFA_REQUIRED: 'MFA_REQUIRED',
  MFA_INVALID: 'MFA_INVALID',
  
  // Database errors
  DUPLICATE_ENTRY: 'DUPLICATE_ENTRY',
  FOREIGN_KEY_CONSTRAINT: 'FOREIGN_KEY_CONSTRAINT',
  DATABASE_ERROR: 'DATABASE_ERROR'
} as const;