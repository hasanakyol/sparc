import { Context, Next } from 'hono';
import { logSecurityEvent, SecurityEventType, SecuritySeverity } from '@sparc/shared/security/siem';
import { logger } from '@sparc/shared';

// Patterns for detecting various attacks
const SQL_INJECTION_PATTERNS = [
  /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|where|table|database|schema)\b)/i,
  /(\b(or|and)\b\s*\d+\s*=\s*\d+)/i,
  /(\b(or|and)\b\s*'[^']*'\s*=\s*'[^']*')/i,
  /(\/\*.*\*\/)/,
  /(--\s*$)/m,
  /(\bsleep\s*\(\s*\d+\s*\))/i,
  /(\bbenchmark\s*\(.*\))/i,
  /(\bwaitfor\s+delay\s*'[^']*')/i,
  /(;\s*shutdown\s*;)/i,
  /(;\s*drop\s+table\s+)/i,
];

const XSS_PATTERNS = [
  /<script[^>]*>.*?<\/script>/gi,
  /<iframe[^>]*>.*?<\/iframe>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
  /<img[^>]*onerror\s*=/gi,
  /<svg[^>]*onload\s*=/gi,
  /eval\s*\(/gi,
  /expression\s*\(/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/g,
  /\.\.%2[fF]/g,
  /\.\.%5[cC]/g,
  /%2e%2e[\/\\]/gi,
  /\.\.[\/\\]\.\.[\/\\]/g,
];

const COMMAND_INJECTION_PATTERNS = [
  /[;&|`].*?(ls|cat|rm|mv|cp|wget|curl|nc|netcat|bash|sh|cmd|powershell)/i,
  /\$\(.*?\)/,
  /`.*?`/,
  /\|\|.*?&&/,
];

// Check if a value contains potential injection attacks
function detectInjectionAttacks(value: string): {
  type: SecurityEventType | null;
  pattern: string | null;
} {
  // Check for SQL injection
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(value)) {
      return { type: SecurityEventType.SQL_INJECTION_ATTEMPT, pattern: pattern.toString() };
    }
  }

  // Check for XSS
  for (const pattern of XSS_PATTERNS) {
    if (pattern.test(value)) {
      return { type: SecurityEventType.XSS_ATTEMPT, pattern: pattern.toString() };
    }
  }

  // Check for path traversal
  for (const pattern of PATH_TRAVERSAL_PATTERNS) {
    if (pattern.test(value)) {
      return { type: SecurityEventType.SUSPICIOUS_ACTIVITY, pattern: 'Path traversal attempt' };
    }
  }

  // Check for command injection
  for (const pattern of COMMAND_INJECTION_PATTERNS) {
    if (pattern.test(value)) {
      return { type: SecurityEventType.SUSPICIOUS_ACTIVITY, pattern: 'Command injection attempt' };
    }
  }

  return { type: null, pattern: null };
}

// Recursively check all values in an object
function checkObjectForAttacks(obj: any, path: string = ''): Array<{
  field: string;
  value: string;
  type: SecurityEventType;
  pattern: string;
}> {
  const detections: Array<{
    field: string;
    value: string;
    type: SecurityEventType;
    pattern: string;
  }> = [];

  if (typeof obj === 'string') {
    const result = detectInjectionAttacks(obj);
    if (result.type) {
      detections.push({
        field: path || 'value',
        value: obj.substring(0, 200), // Truncate for logging
        type: result.type,
        pattern: result.pattern!,
      });
    }
  } else if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      detections.push(...checkObjectForAttacks(item, `${path}[${index}]`));
    });
  } else if (obj !== null && typeof obj === 'object') {
    Object.entries(obj).forEach(([key, value]) => {
      const newPath = path ? `${path}.${key}` : key;
      detections.push(...checkObjectForAttacks(value, newPath));
    });
  }

  return detections;
}

// SIEM middleware for detecting and logging security events
export const siemMiddleware = async (c: Context, next: Next) => {
  const startTime = Date.now();
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';
  const userAgent = c.req.header('user-agent') || 'unknown';
  const method = c.req.method;
  const path = c.req.path;
  const user = c.get('user');

  try {
    // Check URL parameters
    const urlParams = c.req.query();
    const urlDetections = checkObjectForAttacks(urlParams, 'query');

    // Check request body if present
    let bodyDetections: any[] = [];
    if (method !== 'GET' && method !== 'HEAD') {
      try {
        const contentType = c.req.header('content-type') || '';
        if (contentType.includes('application/json')) {
          const body = await c.req.json();
          c.set('parsedBody', body); // Store for later use
          bodyDetections = checkObjectForAttacks(body, 'body');
        }
      } catch (error) {
        // Body parsing failed, might be malformed
        logger.warn('Failed to parse request body for security scanning', { error });
      }
    }

    // Check headers for suspicious content
    const suspiciousHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'referer',
      'user-agent',
    ];

    const headerDetections: any[] = [];
    for (const header of suspiciousHeaders) {
      const value = c.req.header(header);
      if (value) {
        const result = detectInjectionAttacks(value);
        if (result.type) {
          headerDetections.push({
            field: `header.${header}`,
            value: value.substring(0, 200),
            type: result.type,
            pattern: result.pattern,
          });
        }
      }
    }

    // Combine all detections
    const allDetections = [...urlDetections, ...bodyDetections, ...headerDetections];

    // Log security events if attacks detected
    if (allDetections.length > 0) {
      for (const detection of allDetections) {
        await logSecurityEvent(detection.type, {
          severity: SecuritySeverity.HIGH,
          source: 'api-gateway',
          userId: user?.sub,
          organizationId: user?.tenantId,
          ipAddress: clientIp,
          userAgent,
          details: {
            method,
            path,
            field: detection.field,
            value: detection.value,
            pattern: detection.pattern,
            requestId: c.get('requestId'),
          },
        });
      }

      // Optionally block the request based on severity
      const shouldBlock = allDetections.some(d => 
        d.type === SecurityEventType.SQL_INJECTION_ATTEMPT ||
        d.type === SecurityEventType.XSS_ATTEMPT
      );

      if (shouldBlock) {
        logger.warn('Blocking request due to detected attack', {
          detections: allDetections,
          clientIp,
          path,
        });

        return c.json({
          error: {
            code: 'SECURITY_VIOLATION',
            message: 'Request blocked due to security violation',
            timestamp: new Date().toISOString(),
          },
        }, 403);
      }
    }

    // Continue with request
    await next();

    // Log successful requests for sensitive operations
    const responseTime = Date.now() - startTime;
    const status = c.res.status;

    // Log sensitive data access
    if (status === 200 && isSensitiveEndpoint(path, method)) {
      await logSecurityEvent(SecurityEventType.SENSITIVE_DATA_ACCESS, {
        severity: SecuritySeverity.INFO,
        source: 'api-gateway',
        userId: user?.sub,
        organizationId: user?.tenantId,
        ipAddress: clientIp,
        userAgent,
        details: {
          method,
          path,
          responseTime,
          requestId: c.get('requestId'),
        },
      });
    }

    // Log bulk operations
    if (status === 200 && isBulkOperation(path, method)) {
      await logSecurityEvent(SecurityEventType.BULK_OPERATION, {
        severity: SecuritySeverity.MEDIUM,
        source: 'api-gateway',
        userId: user?.sub,
        organizationId: user?.tenantId,
        ipAddress: clientIp,
        userAgent,
        details: {
          method,
          path,
          responseTime,
          requestId: c.get('requestId'),
        },
      });
    }

  } catch (error) {
    logger.error('SIEM middleware error', { error });
    // Don't block the request on SIEM errors
    await next();
  }
};

// Helper functions to identify sensitive endpoints
function isSensitiveEndpoint(path: string, method: string): boolean {
  const sensitivePatterns = [
    /\/users$/,
    /\/audit-logs/,
    /\/credentials/,
    /\/export/,
    /\/reports.*sensitive/,
    /\/analytics.*detailed/,
  ];

  return sensitivePatterns.some(pattern => pattern.test(path)) && method === 'GET';
}

function isBulkOperation(path: string, method: string): boolean {
  const bulkPatterns = [
    /\/bulk/,
    /\/import/,
    /\/batch/,
    /\/mass/,
  ];

  return bulkPatterns.some(pattern => pattern.test(path)) || 
    (method === 'DELETE' && path.includes('/all'));
}

// Export rate limit exceeded logger
export async function logRateLimitExceeded(
  clientIp: string,
  userAgent: string,
  userId?: string,
  organizationId?: string
): Promise<void> {
  await logSecurityEvent(SecurityEventType.RATE_LIMIT_EXCEEDED, {
    severity: SecuritySeverity.MEDIUM,
    source: 'api-gateway',
    userId,
    organizationId,
    ipAddress: clientIp,
    userAgent,
    details: {
      reason: 'Rate limit exceeded',
    },
  });
}

// Export CSRF violation logger
export async function logCSRFViolation(
  clientIp: string,
  userAgent: string,
  userId?: string,
  organizationId?: string,
  details?: any
): Promise<void> {
  await logSecurityEvent(SecurityEventType.CSRF_VIOLATION, {
    severity: SecuritySeverity.HIGH,
    source: 'api-gateway',
    userId,
    organizationId,
    ipAddress: clientIp,
    userAgent,
    details: {
      reason: 'CSRF token validation failed',
      ...details,
    },
  });
}