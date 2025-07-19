/**
 * Input Sanitization and Validation Utilities for SPARC Platform
 * Provides comprehensive protection against injection attacks
 */

import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';
import validator from 'validator';
import { createHash } from 'crypto';

/**
 * SQL Injection Prevention
 */
export class SQLSanitizer {
  private static readonly DANGEROUS_PATTERNS = [
    /(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/gi,
    /(--|#|\/\*|\*\/|;|\||\\x[0-9a-fA-F]{2}|\\[0-7]{1,3})/g,
    /(\bOR\b\s*\d+\s*=\s*\d+|\bAND\b\s*\d+\s*=\s*\d+)/gi,
    /(\'|\")\s*\bOR\b\s*(\'|\")\s*=\s*(\'|\")/gi,
  ];

  /**
   * Sanitize input for SQL queries (use parameterized queries instead when possible)
   */
  static sanitize(input: string): string {
    if (!input) return '';
    
    let sanitized = input;
    
    // Remove dangerous patterns
    for (const pattern of this.DANGEROUS_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }
    
    // Escape special characters
    sanitized = sanitized
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "''")
      .replace(/"/g, '""')
      .replace(/\0/g, '\\0')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\x1a/g, '\\Z');
    
    return sanitized;
  }

  /**
   * Validate identifier (table name, column name, etc.)
   */
  static validateIdentifier(identifier: string): boolean {
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(identifier);
  }
}

/**
 * NoSQL Injection Prevention
 */
export class NoSQLSanitizer {
  /**
   * Sanitize MongoDB query operators
   */
  static sanitizeQuery(query: any): any {
    if (typeof query !== 'object' || query === null) {
      return query;
    }

    const sanitized: any = Array.isArray(query) ? [] : {};

    for (const key in query) {
      if (key.startsWith('$')) {
        // Remove MongoDB operators from user input
        continue;
      }

      if (typeof query[key] === 'object' && query[key] !== null) {
        sanitized[key] = this.sanitizeQuery(query[key]);
      } else {
        sanitized[key] = query[key];
      }
    }

    return sanitized;
  }

  /**
   * Validate and sanitize MongoDB ObjectId
   */
  static sanitizeObjectId(id: string): string | null {
    const objectIdPattern = /^[0-9a-fA-F]{24}$/;
    return objectIdPattern.test(id) ? id : null;
  }
}

/**
 * XSS Prevention
 */
export class XSSSanitizer {
  private static domPurify = DOMPurify;

  /**
   * Sanitize HTML content
   */
  static sanitizeHTML(
    input: string,
    options?: {
      allowedTags?: string[];
      allowedAttributes?: Record<string, string[]>;
      allowDataUri?: boolean;
    }
  ): string {
    const defaultConfig = {
      ALLOWED_TAGS: options?.allowedTags || ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
      ALLOWED_ATTR: options?.allowedAttributes || { 'a': ['href', 'title', 'target'] },
      ALLOW_DATA_ATTR: false,
      ALLOW_UNKNOWN_PROTOCOLS: false,
      SAFE_FOR_TEMPLATES: true,
      WHOLE_DOCUMENT: false,
      RETURN_DOM: false,
      RETURN_DOM_FRAGMENT: false,
      FORCE_BODY: true,
      SANITIZE_DOM: true,
      KEEP_CONTENT: true,
      IN_PLACE: false,
      ALLOWED_URI_REGEXP: options?.allowDataUri 
        ? /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp|data):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
        : /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
    };

    return this.domPurify.sanitize(input, defaultConfig);
  }

  /**
   * Escape HTML entities
   */
  static escapeHTML(input: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
    };
    
    return input.replace(/[&<>"'/]/g, (char) => map[char]);
  }

  /**
   * Sanitize JSON for safe output
   */
  static sanitizeJSON(data: any): string {
    return JSON.stringify(data)
      .replace(/</g, '\\u003C')
      .replace(/>/g, '\\u003E')
      .replace(/&/g, '\\u0026')
      .replace(/'/g, '\\u0027');
  }
}

/**
 * Path Traversal Prevention
 */
export class PathSanitizer {
  private static readonly DANGEROUS_PATH_PATTERNS = [
    /\.\./g,
    /\.\.\\/, 
    /%2e%2e/gi,
    /%252e%252e/gi,
    /\x00/g,
    /\0/g,
  ];

  /**
   * Sanitize file paths
   */
  static sanitizePath(path: string, basePath?: string): string {
    if (!path) return '';

    // Remove dangerous patterns
    let sanitized = path;
    for (const pattern of this.DANGEROUS_PATH_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Normalize path
    sanitized = sanitized
      .split(/[/\\]+/)
      .filter(segment => segment && segment !== '.' && segment !== '..')
      .join('/');

    // Ensure path is within base path if provided
    if (basePath) {
      const fullPath = `${basePath}/${sanitized}`.replace(/\/+/g, '/');
      if (!fullPath.startsWith(basePath)) {
        throw new Error('Path traversal attempt detected');
      }
      return fullPath;
    }

    return sanitized;
  }

  /**
   * Validate filename
   */
  static validateFilename(filename: string): boolean {
    // Allow alphanumeric, dots, hyphens, underscores
    const pattern = /^[a-zA-Z0-9._-]+$/;
    return pattern.test(filename) && !filename.startsWith('.') && filename.length <= 255;
  }
}

/**
 * Command Injection Prevention
 */
export class CommandSanitizer {
  private static readonly SHELL_METACHARACTERS = [
    ';', '|', '&', '$', '(', ')', '<', '>', '`', '\\', '"', "'",
    '\n', '\r', '\t', '*', '?', '[', ']', '#', '~', '!', '{', '}',
  ];

  /**
   * Escape shell arguments
   */
  static escapeShellArg(arg: string): string {
    if (!arg) return "''";

    // If arg contains only safe characters, quote it
    if (/^[a-zA-Z0-9._\-\/]+$/.test(arg)) {
      return arg;
    }

    // Escape single quotes and wrap in single quotes
    return "'" + arg.replace(/'/g, "'\"'\"'") + "'";
  }

  /**
   * Validate command arguments
   */
  static validateCommandArg(arg: string): boolean {
    for (const char of this.SHELL_METACHARACTERS) {
      if (arg.includes(char)) {
        return false;
      }
    }
    return true;
  }
}

/**
 * LDAP Injection Prevention
 */
export class LDAPSanitizer {
  private static readonly LDAP_SPECIAL_CHARS: Record<string, string> = {
    '\\': '\\5c',
    '*': '\\2a',
    '(': '\\28',
    ')': '\\29',
    '\0': '\\00',
    '/': '\\2f',
  };

  /**
   * Sanitize LDAP filter input
   */
  static sanitizeFilter(input: string): string {
    if (!input) return '';

    let sanitized = input;
    for (const [char, escaped] of Object.entries(this.LDAP_SPECIAL_CHARS)) {
      sanitized = sanitized.replace(new RegExp(`\\${char}`, 'g'), escaped);
    }

    return sanitized;
  }

  /**
   * Sanitize LDAP DN input
   */
  static sanitizeDN(input: string): string {
    if (!input) return '';

    return input
      .replace(/\\/g, '\\\\')
      .replace(/,/g, '\\,')
      .replace(/\+/g, '\\+')
      .replace(/"/g, '\\"')
      .replace(/</g, '\\<')
      .replace(/>/g, '\\>')
      .replace(/;/g, '\\;')
      .replace(/\r/g, '\\0D')
      .replace(/\n/g, '\\0A');
  }
}

/**
 * Email Validation and Sanitization
 */
export class EmailSanitizer {
  /**
   * Validate and sanitize email address
   */
  static sanitize(email: string): string | null {
    const trimmed = email.trim().toLowerCase();
    
    if (!validator.isEmail(trimmed)) {
      return null;
    }

    // Additional validation for common email injection attempts
    if (trimmed.includes('\n') || trimmed.includes('\r') || trimmed.includes('\0')) {
      return null;
    }

    return trimmed;
  }

  /**
   * Validate email domain
   */
  static validateDomain(email: string, allowedDomains?: string[]): boolean {
    const domain = email.split('@')[1];
    
    if (!domain) return false;
    
    if (allowedDomains && allowedDomains.length > 0) {
      return allowedDomains.includes(domain);
    }
    
    return true;
  }
}

/**
 * URL Validation and Sanitization
 */
export class URLSanitizer {
  private static readonly SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:'];

  /**
   * Sanitize URL
   */
  static sanitize(url: string, options?: { allowedProtocols?: string[] }): string | null {
    try {
      const parsed = new URL(url);
      
      const allowedProtocols = options?.allowedProtocols || this.SAFE_PROTOCOLS;
      if (!allowedProtocols.includes(parsed.protocol)) {
        return null;
      }

      // Prevent javascript: and data: URLs
      if (parsed.protocol === 'javascript:' || parsed.protocol === 'data:') {
        return null;
      }

      // Remove authentication info from URL
      parsed.username = '';
      parsed.password = '';

      return parsed.toString();
    } catch {
      return null;
    }
  }

  /**
   * Validate URL format
   */
  static validate(url: string, options?: validator.IsURLOptions): boolean {
    return validator.isURL(url, {
      protocols: ['http', 'https'],
      require_protocol: true,
      require_valid_protocol: true,
      require_host: true,
      require_port: false,
      allow_protocol_relative_urls: false,
      allow_fragments: true,
      allow_query_components: true,
      validate_length: true,
      ...options,
    });
  }
}

/**
 * Phone Number Sanitization
 */
export class PhoneSanitizer {
  /**
   * Sanitize phone number
   */
  static sanitize(phone: string, locale?: string): string | null {
    const cleaned = phone.replace(/[^\d+\-\s()]/g, '');
    
    if (!validator.isMobilePhone(cleaned, locale as any)) {
      return null;
    }
    
    return cleaned;
  }
}

/**
 * Credit Card Sanitization
 */
export class CreditCardSanitizer {
  /**
   * Mask credit card number
   */
  static mask(cardNumber: string): string {
    const cleaned = cardNumber.replace(/\D/g, '');
    
    if (!validator.isCreditCard(cleaned)) {
      throw new Error('Invalid credit card number');
    }
    
    // Show only last 4 digits
    return cleaned.replace(/\d(?=\d{4})/g, '*');
  }

  /**
   * Hash credit card for storage
   */
  static hash(cardNumber: string): string {
    const cleaned = cardNumber.replace(/\D/g, '');
    
    if (!validator.isCreditCard(cleaned)) {
      throw new Error('Invalid credit card number');
    }
    
    return createHash('sha256')
      .update(cleaned + process.env.CARD_HASH_SALT)
      .digest('hex');
  }
}

/**
 * General Input Validator
 */
export class InputValidator {
  /**
   * Create a sanitized string schema
   */
  static string(options?: {
    minLength?: number;
    maxLength?: number;
    pattern?: RegExp;
    transform?: (val: string) => string;
  }) {
    let schema = z.string();

    if (options?.minLength) {
      schema = schema.min(options.minLength);
    }

    if (options?.maxLength) {
      schema = schema.max(options.maxLength);
    }

    if (options?.pattern) {
      schema = schema.regex(options.pattern);
    }

    // Default sanitization
    schema = schema.transform((val) => {
      let sanitized = val.trim();
      
      // Apply custom transform if provided
      if (options?.transform) {
        sanitized = options.transform(sanitized);
      }
      
      // Remove null bytes
      sanitized = sanitized.replace(/\0/g, '');
      
      return sanitized;
    });

    return schema;
  }

  /**
   * Create a sanitized email schema
   */
  static email() {
    return z.string()
      .email()
      .transform((val) => EmailSanitizer.sanitize(val) || '')
      .refine((val) => val !== '', 'Invalid email address');
  }

  /**
   * Create a sanitized URL schema
   */
  static url(options?: { allowedProtocols?: string[] }) {
    return z.string()
      .url()
      .transform((val) => URLSanitizer.sanitize(val, options) || '')
      .refine((val) => val !== '', 'Invalid URL');
  }

  /**
   * Create a sanitized phone schema
   */
  static phone(locale?: string) {
    return z.string()
      .transform((val) => PhoneSanitizer.sanitize(val, locale) || '')
      .refine((val) => val !== '', 'Invalid phone number');
  }

  /**
   * Create a safe JSON schema
   */
  static json() {
    return z.string()
      .transform((val) => {
        try {
          return JSON.parse(val);
        } catch {
          throw new Error('Invalid JSON');
        }
      });
  }

  /**
   * Create a safe number schema
   */
  static number(options?: { min?: number; max?: number; int?: boolean }) {
    let schema = z.number();

    if (options?.min !== undefined) {
      schema = schema.min(options.min);
    }

    if (options?.max !== undefined) {
      schema = schema.max(options.max);
    }

    if (options?.int) {
      schema = schema.int();
    }

    return schema;
  }

  /**
   * Create a safe boolean schema
   */
  static boolean() {
    return z.union([
      z.boolean(),
      z.string().transform((val) => val === 'true' || val === '1'),
      z.number().transform((val) => val === 1),
    ]);
  }

  /**
   * Create a safe date schema
   */
  static date(options?: { min?: Date; max?: Date }) {
    let schema = z.union([
      z.date(),
      z.string().datetime().transform((val) => new Date(val)),
    ]);

    return schema.refine((date) => {
      if (options?.min && date < options.min) return false;
      if (options?.max && date > options.max) return false;
      return true;
    }, 'Date out of range');
  }

  /**
   * Create a safe enum schema
   */
  static enum<T extends readonly [string, ...string[]]>(values: T) {
    return z.enum(values);
  }

  /**
   * Create a safe UUID schema
   */
  static uuid() {
    return z.string().uuid();
  }

  /**
   * Create a safe object ID schema (MongoDB)
   */
  static objectId() {
    return z.string()
      .regex(/^[0-9a-fA-F]{24}$/, 'Invalid ObjectId')
      .transform((val) => NoSQLSanitizer.sanitizeObjectId(val) || '')
      .refine((val) => val !== '', 'Invalid ObjectId');
  }
}

// Export all sanitizers and validators
export {
  SQLSanitizer,
  NoSQLSanitizer,
  XSSSanitizer,
  PathSanitizer,
  CommandSanitizer,
  LDAPSanitizer,
  EmailSanitizer,
  URLSanitizer,
  PhoneSanitizer,
  CreditCardSanitizer,
  InputValidator,
};

export default {
  SQL: SQLSanitizer,
  NoSQL: NoSQLSanitizer,
  XSS: XSSSanitizer,
  Path: PathSanitizer,
  Command: CommandSanitizer,
  LDAP: LDAPSanitizer,
  Email: EmailSanitizer,
  URL: URLSanitizer,
  Phone: PhoneSanitizer,
  CreditCard: CreditCardSanitizer,
  Validator: InputValidator,
};