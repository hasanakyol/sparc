/**
 * Security Headers Middleware for SPARC Platform
 * Implements comprehensive HTTP security headers following OWASP best practices
 */

import { Context, Next } from 'hono';
import { MiddlewareHandler } from 'hono';
import crypto from 'crypto';

export interface SecurityHeadersConfig {
  enableHSTS?: boolean;
  enableCSP?: boolean;
  enableNonce?: boolean;
  reportUri?: string;
  frameAncestors?: string[];
  trustedDomains?: string[];
  allowInlineScripts?: boolean;
  allowInlineStyles?: boolean;
}

const defaultConfig: SecurityHeadersConfig = {
  enableHSTS: true,
  enableCSP: true,
  enableNonce: true,
  reportUri: '/api/security/csp-report',
  frameAncestors: ["'none'"],
  trustedDomains: [],
  allowInlineScripts: false,
  allowInlineStyles: false,
};

/**
 * Generate CSP nonce for inline scripts/styles
 */
function generateNonce(): string {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * Build Content Security Policy header
 */
function buildCSP(config: SecurityHeadersConfig, nonce?: string): string {
  const directives: Record<string, string[]> = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'"],
    'img-src': ["'self'", 'data:', 'blob:'],
    'font-src': ["'self'", 'data:'],
    'connect-src': ["'self'", 'wss:', 'https:'],
    'media-src': ["'self'", 'blob:'],
    'object-src': ["'none'"],
    'frame-src': ["'none'"],
    'frame-ancestors': config.frameAncestors || ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'manifest-src': ["'self'"],
    'worker-src': ["'self'", 'blob:"],
    'child-src': ["'self'", 'blob:"],
    'require-trusted-types-for': ["'script'"],
    'trusted-types': ['default'],
    'upgrade-insecure-requests': [],
  };

  // Add trusted domains
  if (config.trustedDomains && config.trustedDomains.length > 0) {
    directives['script-src'].push(...config.trustedDomains);
    directives['style-src'].push(...config.trustedDomains);
    directives['img-src'].push(...config.trustedDomains);
    directives['connect-src'].push(...config.trustedDomains);
  }

  // Handle inline scripts/styles with nonce
  if (config.allowInlineScripts && nonce) {
    directives['script-src'].push(`'nonce-${nonce}'`);
    directives['script-src'].push("'strict-dynamic'");
  } else if (config.allowInlineScripts) {
    directives['script-src'].push("'unsafe-inline'");
  }

  if (config.allowInlineStyles && nonce) {
    directives['style-src'].push(`'nonce-${nonce}'`);
  } else if (config.allowInlineStyles) {
    directives['style-src'].push("'unsafe-inline'");
  }

  // Add report URI if configured
  if (config.reportUri) {
    directives['report-uri'] = [config.reportUri];
    directives['report-to'] = ['csp-endpoint'];
  }

  // Build the CSP string
  return Object.entries(directives)
    .map(([directive, values]) => {
      if (values.length === 0) return directive;
      return `${directive} ${values.join(' ')}`;
    })
    .join('; ');
}

/**
 * Security Headers Middleware
 */
export function securityHeaders(config: SecurityHeadersConfig = {}): MiddlewareHandler {
  const finalConfig = { ...defaultConfig, ...config };

  return async (c: Context, next: Next) => {
    // Generate nonce if enabled
    const nonce = finalConfig.enableNonce ? generateNonce() : undefined;
    if (nonce) {
      c.set('cspNonce', nonce);
    }

    // Process request
    await next();

    // Core security headers
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');
    c.header('X-XSS-Protection', '0'); // Disabled in modern browsers, rely on CSP
    c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    c.header('X-Permitted-Cross-Domain-Policies', 'none');
    c.header('X-DNS-Prefetch-Control', 'off');
    c.header('X-Download-Options', 'noopen');

    // Permissions Policy (formerly Feature Policy)
    c.header('Permissions-Policy', [
      'accelerometer=()',
      'ambient-light-sensor=()',
      'autoplay=()',
      'battery=()',
      'camera=(self)',
      'cross-origin-isolated=()',
      'display-capture=()',
      'document-domain=()',
      'encrypted-media=()',
      'execution-while-not-rendered=()',
      'execution-while-out-of-viewport=()',
      'fullscreen=(self)',
      'geolocation=()',
      'gyroscope=()',
      'keyboard-map=()',
      'magnetometer=()',
      'microphone=(self)',
      'midi=()',
      'navigation-override=()',
      'payment=()',
      'picture-in-picture=()',
      'publickey-credentials-get=()',
      'screen-wake-lock=()',
      'sync-xhr=()',
      'usb=()',
      'web-share=()',
      'xr-spatial-tracking=()',
    ].join(', '));

    // HSTS - only on HTTPS
    if (finalConfig.enableHSTS && (c.req.header('x-forwarded-proto') === 'https' || c.req.url.startsWith('https://'))) {
      c.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }

    // Content Security Policy
    if (finalConfig.enableCSP) {
      const csp = buildCSP(finalConfig, nonce);
      c.header('Content-Security-Policy', csp);

      // Report-To header for CSP reporting
      if (finalConfig.reportUri) {
        c.header('Report-To', JSON.stringify({
          group: 'csp-endpoint',
          max_age: 10886400,
          endpoints: [{ url: finalConfig.reportUri }],
          include_subdomains: true,
        }));
      }
    }

    // Additional security headers
    c.header('Cross-Origin-Embedder-Policy', 'require-corp');
    c.header('Cross-Origin-Opener-Policy', 'same-origin');
    c.header('Cross-Origin-Resource-Policy', 'same-origin');

    // Clear sensitive headers
    c.header('X-Powered-By', '');
    c.header('Server', '');

    // Cache control for sensitive content
    const isAPI = c.req.path.startsWith('/api/');
    if (isAPI) {
      c.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      c.header('Pragma', 'no-cache');
      c.header('Expires', '0');
      c.header('Surrogate-Control', 'no-store');
    }

    // Expect-CT header for certificate transparency
    c.header('Expect-CT', 'max-age=86400, enforce');

    // Security headers for specific content types
    const contentType = c.res.headers.get('content-type');
    if (contentType?.includes('text/html')) {
      c.header('X-UA-Compatible', 'IE=edge');
    }
  };
}

/**
 * CSP Report Handler
 */
export async function handleCSPReport(c: Context) {
  try {
    const report = await c.req.json();
    
    // Log CSP violation
    console.error('CSP Violation:', {
      documentUri: report['csp-report']?.['document-uri'],
      violatedDirective: report['csp-report']?.['violated-directive'],
      blockedUri: report['csp-report']?.['blocked-uri'],
      lineNumber: report['csp-report']?.['line-number'],
      columnNumber: report['csp-report']?.['column-number'],
      sourceFile: report['csp-report']?.['source-file'],
      timestamp: new Date().toISOString(),
    });

    // You can also send this to your SIEM or monitoring system
    // await sendToSIEM(report);

    return c.json({ received: true }, 204);
  } catch (error) {
    console.error('Error processing CSP report:', error);
    return c.json({ error: 'Invalid report' }, 400);
  }
}

/**
 * Security headers for API responses
 */
export function apiSecurityHeaders(): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    await next();

    // API-specific security headers
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');
    c.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    c.header('Pragma', 'no-cache');
    c.header('Expires', '0');
    c.header('X-API-Version', process.env.API_VERSION || '1.0.0');

    // CORS headers (configure based on your needs)
    const origin = c.req.header('origin');
    if (origin && isAllowedOrigin(origin)) {
      c.header('Access-Control-Allow-Origin', origin);
      c.header('Access-Control-Allow-Credentials', 'true');
      c.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
      c.header('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Requested-With, X-Tenant-ID');
      c.header('Access-Control-Max-Age', '86400');
      c.header('Access-Control-Expose-Headers', 'X-Total-Count, X-Page-Count');
    }

    // Vary header for proper caching
    c.header('Vary', 'Origin, Accept-Encoding');
  };
}

/**
 * Check if origin is allowed for CORS
 */
function isAllowedOrigin(origin: string): boolean {
  const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
  
  // In development, allow localhost
  if (process.env.NODE_ENV === 'development') {
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return true;
    }
  }

  return allowedOrigins.includes(origin);
}

/**
 * Trusted Types Policy for XSS prevention
 */
export const trustedTypesPolicy = `
  if (typeof trustedTypes !== 'undefined' && trustedTypes.createPolicy) {
    trustedTypes.createPolicy('default', {
      createHTML: (input) => {
        // Sanitize HTML input
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
      },
      createScript: (input) => {
        // Only allow specific scripts
        if (input.includes('trusted-script')) {
          return input;
        }
        throw new Error('Untrusted script blocked');
      },
      createScriptURL: (input) => {
        // Only allow same-origin scripts
        const url = new URL(input, window.location.origin);
        if (url.origin === window.location.origin) {
          return input;
        }
        throw new Error('Cross-origin script blocked');
      }
    });
  }
`;

export default securityHeaders;