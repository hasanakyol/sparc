import { Hono, type Context, type Next } from 'hono';
import { sign, verify } from 'hono/jwt';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import Redis from 'ioredis';
import crypto from 'crypto';
import { 
  LoginRequestSchema, 
  SignupRequestSchema, 
  RefreshTokenRequestSchema,
  ChangePasswordRequestSchema,
  ResetPasswordRequestSchema,
  ResetPasswordConfirmRequestSchema,
  UpdateProfileRequestSchema,
  ApiResponse,
  AccessTokenPayload,
  RefreshTokenPayload,
  PasswordPolicy,
  PasswordValidationResult
} from '@sparc/shared/types';
import { config, logger as appLogger, prisma, withRetry } from '@sparc/shared';
import { JWTBlacklistService } from '@sparc/shared/utils/jwt-blacklist';
import { sendVerificationEmail as sendVerificationEmailService, sendPasswordResetEmail as sendPasswordResetEmailService } from '@sparc/shared/services/email';
import { MFAService } from '@sparc/shared/services/mfa';
import { PasswordSecurityService } from '@sparc/shared/utils/password-security';
import { logSecurityEvent, SecurityEventType, SecuritySeverity } from '@sparc/shared/security/siem';
import { JWTService } from '../services/jwtService';

const app = new Hono();

// Initialize Redis with connection pooling and error handling
let redis: Redis;

const initializeConnections = () => {
  try {

    redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      password: config.redis.password,
      db: config.redis.database,
      keyPrefix: config.redis.keyPrefix,
      connectTimeout: config.redis.connectTimeout,
      commandTimeout: config.redis.commandTimeout,
      retryDelayOnFailover: config.redis.retryDelay,
      maxRetriesPerRequest: config.redis.retryAttempts,
      lazyConnect: true,
      keepAlive: 30000,
    });

    // Redis error handling
    redis.on('error', (error) => {
      appLogger.error('Redis connection error', { error: error.message });
    });

    redis.on('connect', () => {
      appLogger.info('Redis connected successfully');
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Failed to initialize connections', { error: errorMessage });
    throw error;
  }
};

// Initialize connections
initializeConnections();

// Initialize JWT blacklist service
let jwtBlacklist: JWTBlacklistService;
try {
  jwtBlacklist = new JWTBlacklistService({
    redis,
    keyPrefix: 'jwt:blacklist',
    defaultTTL: 86400 // 24 hours
  });
  appLogger.info('JWT blacklist service initialized');
} catch (error) {
  appLogger.error('Failed to initialize JWT blacklist service', { error });
  throw error;
}

// Initialize MFA service
const mfaService = new MFAService();

// Initialize password security service
const passwordSecurity = new PasswordSecurityService(prisma, {
  passwordHistoryLimit: 5
});

// Configuration
const JWT_CONFIG = {
  accessTokenSecret: config.jwt.accessTokenSecret,
  refreshTokenSecret: config.jwt.refreshTokenSecret,
  accessTokenExpiry: config.jwt.accessTokenExpiry,
  refreshTokenExpiry: config.jwt.refreshTokenExpiry,
  issuer: config.jwt.issuer,
  audience: config.jwt.audience,
  algorithm: config.jwt.algorithm as 'HS256',
};

// Initialize JWT service
const jwtService = JWTService.getInstance(JWT_CONFIG);

const SECURITY_CONFIG = {
  bcryptRounds: config.security.bcryptRounds,
  sessionTimeout: config.security.sessionTimeout * 60, // Convert minutes to seconds
  maxConcurrentSessions: config.security.maxConcurrentSessions,
  bruteForce: config.security.bruteForce,
  passwordPolicy: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventReuse: 5,
    maxAge: 90, // days
    lockoutThreshold: 5,
    lockoutDuration: 15, // minutes
  } as PasswordPolicy,
};

// Circuit Breaker Implementation
class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  
  constructor(
    private threshold = 5,
    private timeout = 60000, // 1 minute
    private name = 'default'
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = 'HALF_OPEN';
        appLogger.info(`Circuit breaker ${this.name} moved to HALF_OPEN`);
      } else {
        throw new Error(`Circuit breaker ${this.name} is OPEN`);
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess() {
    this.failures = 0;
    this.state = 'CLOSED';
  }

  private onFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();
    
    if (this.failures >= this.threshold) {
      this.state = 'OPEN';
      appLogger.error(`Circuit breaker ${this.name} opened`, { failures: this.failures });
    }
  }

  getState() {
    return {
      state: this.state,
      failures: this.failures,
      lastFailureTime: this.lastFailureTime,
    };
  }
}

// Create circuit breakers for external dependencies
const databaseCircuitBreaker = new CircuitBreaker(5, 60000, 'database');
const redisCircuitBreaker = new CircuitBreaker(3, 30000, 'redis');

// Rate limiting configuration
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 100;
const BRUTE_FORCE_PREFIX = 'bruteforce:';
const RATE_LIMIT_PREFIX = 'ratelimit:';

// Enhanced validation schemas with better password policies
const passwordValidationSchema = z.string()
  .min(SECURITY_CONFIG.passwordPolicy.minLength, `Password must be at least ${SECURITY_CONFIG.passwordPolicy.minLength} characters`)
  .max(SECURITY_CONFIG.passwordPolicy.maxLength, `Password must not exceed ${SECURITY_CONFIG.passwordPolicy.maxLength} characters`)
  .regex(/^(?=.*[a-z])/, 'Password must contain at least one lowercase letter')
  .regex(/^(?=.*[A-Z])/, 'Password must contain at least one uppercase letter')
  .regex(/^(?=.*\d)/, 'Password must contain at least one number')
  .regex(/^(?=.*[@$!%*?&])/, 'Password must contain at least one special character');

const signupSchema = SignupRequestSchema.extend({
  password: passwordValidationSchema,
});

const loginSchema = LoginRequestSchema.extend({
  mfaToken: z.string().optional(),
});
const changePasswordSchema = ChangePasswordRequestSchema.extend({
  newPassword: passwordValidationSchema,
});
const refreshTokenSchema = RefreshTokenRequestSchema;
const resetPasswordSchema = ResetPasswordRequestSchema;
const resetPasswordConfirmSchema = ResetPasswordConfirmRequestSchema.extend({
  newPassword: passwordValidationSchema,
});
const updateProfileSchema = UpdateProfileRequestSchema;

// Enhanced utility functions with circuit breaker protection
const generateTokens = async (userId: string, tenantId: string, role: string, email: string, permissions: Record<string, any> = {}) => {
  // Convert permissions object to array format expected by JWTService
  const permissionsArray = Object.entries(permissions)
    .filter(([_, value]) => value === true)
    .map(([key, _]) => key);
  
  // Use JWT service to generate tokens
  return await jwtService.generateTokens(
    userId,
    tenantId, // Using tenantId as organizationId
    email,
    role,
    permissionsArray
  );
};

const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, SECURITY_CONFIG.bcryptRounds);
};

const verifyPassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  // Add timing attack protection
  const startTime = Date.now();
  const result = await bcrypt.compare(password, hashedPassword);
  const endTime = Date.now();
  
  // Ensure minimum processing time to prevent timing attacks
  const minTime = 100; // 100ms minimum
  const elapsed = endTime - startTime;
  if (elapsed < minTime) {
    await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
  }
  
  return result;
};

const validatePassword = (password: string): PasswordValidationResult => {
  const errors: string[] = [];
  let score = 0;

  // Length check
  if (password.length < SECURITY_CONFIG.passwordPolicy.minLength) {
    errors.push(`Password must be at least ${SECURITY_CONFIG.passwordPolicy.minLength} characters long`);
  } else {
    score += 20;
  }

  // Character type checks
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  } else {
    score += 20;
  }

  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  } else {
    score += 20;
  }

  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  } else {
    score += 20;
  }

  if (!/[@$!%*?&]/.test(password)) {
    errors.push('Password must contain at least one special character');
  } else {
    score += 20;
  }

  // Additional scoring for complexity
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;

  let strength: 'weak' | 'fair' | 'good' | 'strong' = 'weak';
  if (score >= 80) strength = 'strong';
  else if (score >= 60) strength = 'good';
  else if (score >= 40) strength = 'fair';

  return {
    valid: errors.length === 0,
    errors,
    strength,
    score,
  };
};

const auditLog = async (action: string, userId: string | null, tenantId: string | null, details: Record<string, unknown>, ipAddress?: string, userAgent?: string) => {
  try {
    await databaseCircuitBreaker.execute(async () => {
      await prisma.auditLog.create({
        data: {
          action,
          userId,
          tenantId,
          details: JSON.stringify(details),
          ipAddress,
          userAgent,
          timestamp: new Date(),
        },
      });
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Failed to create audit log', { 
      error: errorMessage, 
      action, 
      userId, 
      tenantId 
    });
  }
};

const invalidateUserSessions = async (userId: string, excludeSessionId?: string) => {
  try {
    await redisCircuitBreaker.execute(async () => {
      const pattern = `session:${userId}:*`;
      const keys = await redis.keys(pattern);
      
      if (keys.length > 0) {
        const keysToDelete = excludeSessionId 
          ? keys.filter(key => !key.includes(excludeSessionId))
          : keys;
        
        if (keysToDelete.length > 0) {
          await redis.del(...keysToDelete);
        }
      }
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Failed to invalidate user sessions', { error: errorMessage, userId });
  }
};

const checkBruteForce = async (identifier: string): Promise<boolean> => {
  try {
    return await redisCircuitBreaker.execute(async () => {
      const key = `${BRUTE_FORCE_PREFIX}${identifier}`;
      const recordStr = await redis.get(key);
      
      if (!recordStr) return true; // No previous attempts
      
      const record = JSON.parse(recordStr);
      const now = Date.now();
      
      if (record.lockUntil && now < record.lockUntil) {
        return false; // Still locked
      }
      
      if (record.lockUntil && now >= record.lockUntil) {
        // Lock expired, reset attempts
        await redis.del(key);
        return true;
      }
      
      return record.attempts < SECURITY_CONFIG.bruteForce.freeRetries;
    });
  } catch (error) {
    appLogger.error('Failed to check brute force', { error, identifier });
    // On Redis failure, allow the request (fail open)
    return true;
  }
};

const recordFailedAttempt = async (identifier: string): Promise<void> => {
  try {
    await redisCircuitBreaker.execute(async () => {
      const key = `${BRUTE_FORCE_PREFIX}${identifier}`;
      const recordStr = await redis.get(key);
      const record = recordStr ? JSON.parse(recordStr) : { attempts: 0 };
      const now = Date.now();
      
      record.attempts++;
      
      if (record.attempts >= SECURITY_CONFIG.bruteForce.freeRetries) {
        record.lockUntil = now + (SECURITY_CONFIG.bruteForce.minWait * Math.pow(2, record.attempts - SECURITY_CONFIG.bruteForce.freeRetries));
      }
      
      // Set with expiration (24 hours)
      await redis.setex(key, 86400, JSON.stringify(record));
    });
  } catch (error) {
    appLogger.error('Failed to record failed attempt', { error, identifier });
  }
};

const resetFailedAttempts = async (identifier: string): Promise<void> => {
  try {
    await redisCircuitBreaker.execute(async () => {
      const key = `${BRUTE_FORCE_PREFIX}${identifier}`;
      await redis.del(key);
    });
  } catch (error) {
    appLogger.error('Failed to reset failed attempts', { error, identifier });
  }
};

const checkRateLimit = async (identifier: string): Promise<boolean> => {
  try {
    return await redisCircuitBreaker.execute(async () => {
      const key = `${RATE_LIMIT_PREFIX}${identifier}`;
      const now = Date.now();
      const windowStart = now - RATE_LIMIT_WINDOW;
      
      // Use Redis sorted set for efficient rate limiting
      // Remove old entries outside the window
      await redis.zremrangebyscore(key, '-inf', windowStart);
      
      // Count requests in current window
      const count = await redis.zcard(key);
      
      if (count >= RATE_LIMIT_MAX_REQUESTS) {
        return false;
      }
      
      // Add current request with timestamp as score
      await redis.zadd(key, now, `${now}-${Math.random()}`);
      
      // Set expiration on the key
      await redis.expire(key, Math.ceil(RATE_LIMIT_WINDOW / 1000));
      
      return true;
    });
  } catch (error) {
    appLogger.error('Failed to check rate limit', { error, identifier });
    // On Redis failure, allow the request (fail open)
    return true;
  }
};

const generateEmailVerificationToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

const generatePasswordResetToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

const generateCSRFToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

const sendVerificationEmail = async (email: string, token: string, tenantId: string) => {
  try {
    // Get tenant name for email template
    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
      select: { name: true },
    });
    
    const tenantName = tenant?.name || 'SPARC Security Platform';
    
    // Send actual verification email
    await sendVerificationEmailService(email, token, tenantName);
    
    appLogger.info('Verification email sent', { email, tenantId });
  } catch (error) {
    appLogger.error('Failed to send verification email', { email, tenantId, error });
    // Don't throw error to avoid blocking signup process
  }
};

const sendPasswordResetEmail = async (email: string, token: string, tenantId: string) => {
  try {
    // Send actual password reset email
    await sendPasswordResetEmailService(email, token);
    
    appLogger.info('Password reset email sent', { email, tenantId });
  } catch (error) {
    appLogger.error('Failed to send password reset email', { email, tenantId, error });
    // Don't throw error to avoid exposing whether email exists
  }
};

const checkPasswordHistory = async (userId: string, newPassword: string): Promise<boolean> => {
  try {
    const passwordHistory = await databaseCircuitBreaker.execute(async () => {
      return await prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: SECURITY_CONFIG.passwordPolicy.preventReuse,
      });
    });

    for (const historyEntry of passwordHistory) {
      if (await verifyPassword(newPassword, historyEntry.passwordHash)) {
        return false; // Password was used before
      }
    }

    return true; // Password is new
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Failed to check password history', { error: errorMessage, userId });
    return true; // Allow password change if history check fails
  }
};

const savePasswordHistory = async (userId: string, passwordHash: string) => {
  try {
    await databaseCircuitBreaker.execute(async () => {
      await prisma.passwordHistory.create({
        data: {
          userId,
          passwordHash,
          createdAt: new Date(),
        },
      });

      // Clean up old password history entries
      const oldEntries = await prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        skip: SECURITY_CONFIG.passwordPolicy.preventReuse,
      });

      if (oldEntries.length > 0) {
        await prisma.passwordHistory.deleteMany({
          where: {
            id: { in: oldEntries.map(entry => entry.id) },
          },
        });
      }
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Failed to save password history', { error: errorMessage, userId });
  }
};

// Enhanced middleware with circuit breaker protection
const authMiddleware = async (c: Context, next: Next) => {
  try {
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : getCookie(c, 'accessToken');

    if (!token) {
      return c.json({ 
        error: { 
          code: 'AUTH_TOKEN_REQUIRED',
          message: 'Access token required',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    const payload = await jwtService.verifyAccessToken(token);
    
    if (payload.type !== 'access') {
      return c.json({ 
        error: { 
          code: 'INVALID_TOKEN_TYPE',
          message: 'Invalid token type',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Check if session exists in Redis with circuit breaker
    const sessionExists = await redisCircuitBreaker.execute(async () => {
      const sessionKey = `session:${payload.sub}:${payload.tenantId}:${payload.sessionId}`;
      return await redis.exists(sessionKey);
    });
    
    if (!sessionExists) {
      return c.json({ 
        error: { 
          code: 'SESSION_EXPIRED',
          message: 'Session expired',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Extend session with circuit breaker
    await redisCircuitBreaker.execute(async () => {
      const sessionKey = `session:${payload.sub}:${payload.tenantId}:${payload.sessionId}`;
      await redis.expire(sessionKey, SECURITY_CONFIG.sessionTimeout);
    });

    c.set('user', payload);
    await next();
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Authentication middleware error', { error: errorMessage });
    return c.json({ 
      error: { 
        code: 'AUTH_INVALID_TOKEN',
        message: 'Invalid or expired token',
        timestamp: new Date().toISOString(),
      } 
    }, 401);
  }
};

// Rate limiting middleware
const rateLimitMiddleware = async (c: Context, next: Next) => {
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';
  
  if (!(await checkRateLimit(clientIp))) {
    appLogger.warn('Rate limit exceeded', { clientIp });
    return c.json({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests',
        retryAfter: Math.ceil(RATE_LIMIT_WINDOW / 1000),
        timestamp: new Date().toISOString(),
      },
    }, 429);
  }

  await next();
};

// Request context middleware
const requestContextMiddleware = async (c: Context, next: Next) => {
  const requestId = c.req.header('x-request-id') || crypto.randomUUID();
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';
  const userAgent = c.req.header('user-agent') || 'unknown';
  
  c.set('requestId', requestId);
  c.set('clientIp', clientIp);
  c.set('userAgent', userAgent);
  
  c.header('x-request-id', requestId);
  
  await next();
};

// Apply middleware to all routes
app.use('*', requestContextMiddleware);
app.use('*', rateLimitMiddleware);

// Enhanced routes with comprehensive error handling and security

// POST /signup - User Registration with email verification
app.post('/signup', async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const body = await c.req.json();
    const validatedData = signupSchema.parse(body);

    // Check brute force protection
    const bruteForceKey = `signup:${clientIp}`;
    if (!(await checkBruteForce(bruteForceKey))) {
      await auditLog('SIGNUP_BLOCKED', null, validatedData.tenantId, 
        { reason: 'Brute force protection', email: validatedData.email }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'SIGNUP_BLOCKED',
          message: 'Too many failed attempts. Please try again later.',
          timestamp: new Date().toISOString(),
        } 
      }, 429);
    }

    // Validate password strength with enhanced security
    const passwordValidation = await passwordSecurity.validatePassword(validatedData.password);
    if (!passwordValidation.valid) {
      await recordFailedAttempt(bruteForceKey);
      return c.json({ 
        error: { 
          code: 'WEAK_PASSWORD',
          message: 'Password does not meet security requirements',
          details: passwordValidation.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Check if user already exists with circuit breaker
    const existingUser = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findFirst({
        where: {
          email: validatedData.email,
          tenantId: validatedData.tenantId,
        },
      });
    });

    if (existingUser) {
      await recordFailedAttempt(bruteForceKey);
      await auditLog('SIGNUP_FAILED', null, validatedData.tenantId, 
        { reason: 'User already exists', email: validatedData.email }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'USER_EXISTS',
          message: 'User already exists',
          timestamp: new Date().toISOString(),
        } 
      }, 409);
    }

    // Verify tenant exists and is active
    const tenant = await databaseCircuitBreaker.execute(async () => {
      return await prisma.tenant.findUnique({
        where: { id: validatedData.tenantId },
        select: { id: true, name: true, isActive: true },
      });
    });

    if (!tenant || !tenant.isActive) {
      await recordFailedAttempt(bruteForceKey);
      await auditLog('SIGNUP_FAILED', null, validatedData.tenantId, 
        { reason: 'Invalid or inactive tenant', email: validatedData.email }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'INVALID_TENANT',
          message: 'Invalid or inactive tenant',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Hash password with enhanced security
    const hashedPassword = await passwordSecurity.hashPassword(validatedData.password);

    // Generate email verification token
    const emailVerificationToken = generateEmailVerificationToken();
    const emailVerificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user with transaction
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: {
            email: validatedData.email,
            passwordHash: hashedPassword,
            firstName: validatedData.firstName,
            lastName: validatedData.lastName,
            tenantId: validatedData.tenantId,
            role: validatedData.role || 'VIEWER',
            isActive: false, // Require email verification
            emailVerified: false,
            emailVerificationToken,
            emailVerificationExpiry,
            createdAt: new Date(),
            updatedAt: new Date(),
          },
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            role: true,
            tenantId: true,
            isActive: true,
            emailVerified: true,
            createdAt: true,
          },
        });

        // Save password to history
        // Note: We'll save to history after transaction completes to avoid circular dependency

        return newUser;
      });
    });
    
    // Add password to history after user creation
    await passwordSecurity.addToPasswordHistory(user.id, hashedPassword);

    // Send verification email
    await sendVerificationEmail(user.email, emailVerificationToken, user.tenantId);

    // Reset brute force attempts on success
    await resetFailedAttempts(bruteForceKey);

    await auditLog('USER_CREATED', user.id, user.tenantId, 
      { email: user.email, role: user.role, emailVerificationRequired: true }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'User created successfully. Please check your email to verify your account.',
      data: { user },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response, 201);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: { 
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: error.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Signup error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /verify-email - Email verification
app.post('/verify-email', async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const body = await c.req.json();
    const { token } = z.object({ token: z.string().min(1) }).parse(body);

    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findFirst({
        where: {
          emailVerificationToken: token,
          emailVerificationExpiry: { gt: new Date() },
        },
      });
    });

    if (!user) {
      return c.json({ 
        error: { 
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired verification token',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Update user as verified and active
    await databaseCircuitBreaker.execute(async () => {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          isActive: true,
          emailVerified: true,
          emailVerificationToken: null,
          emailVerificationExpiry: null,
          updatedAt: new Date(),
        },
      });
    });

    await auditLog('EMAIL_VERIFIED', user.id, user.tenantId, 
      { email: user.email }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'Email verified successfully. You can now log in.',
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: { 
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: error.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Email verification error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /login - Enhanced user authentication with brute force protection
app.post('/login', async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const body = await c.req.json();
    const validatedData = loginSchema.parse(body);

    // Check brute force protection
    const bruteForceKey = `login:${clientIp}:${validatedData.email}`;
    if (!checkBruteForce(bruteForceKey)) {
      await auditLog('LOGIN_BLOCKED', null, validatedData.tenantId, 
        { reason: 'Brute force protection', email: validatedData.email }, clientIp, userAgent);
      
      // Log to SIEM
      await logSecurityEvent(SecurityEventType.BRUTE_FORCE_DETECTED, {
        severity: SecuritySeverity.HIGH,
        source: 'auth-service',
        organizationId: validatedData.tenantId,
        ipAddress: clientIp,
        userAgent,
        details: {
          email: validatedData.email,
          reason: 'Multiple failed login attempts'
        }
      });
      
      return c.json({ 
        error: { 
          code: 'LOGIN_BLOCKED',
          message: 'Too many failed attempts. Please try again later.',
          timestamp: new Date().toISOString(),
        } 
      }, 429);
    }

    // Find user with circuit breaker
    const whereClause: { email: string; tenantId?: string } = { email: validatedData.email };
    if (validatedData.tenantId) {
      whereClause.tenantId = validatedData.tenantId;
    }

    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findFirst({
        where: whereClause,
        include: {
          tenant: {
            select: {
              id: true,
              name: true,
              isActive: true,
              settings: true,
            },
          },
        },
      });
    });

    if (!user || !user.isActive || !user.tenant?.isActive) {
      recordFailedAttempt(bruteForceKey);
      await auditLog('LOGIN_FAILED', null, validatedData.tenantId, 
        { reason: 'Invalid credentials', email: validatedData.email }, clientIp, userAgent);
      
      // Log to SIEM
      await logSecurityEvent(SecurityEventType.LOGIN_FAILURE, {
        severity: SecuritySeverity.MEDIUM,
        source: 'auth-service',
        organizationId: validatedData.tenantId,
        ipAddress: clientIp,
        userAgent,
        details: {
          email: validatedData.email,
          reason: 'User not found or inactive'
        }
      });
      
      return c.json({ 
        error: { 
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid credentials',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    if (!user.emailVerified) {
      recordFailedAttempt(bruteForceKey);
      await auditLog('LOGIN_FAILED', user.id, user.tenantId, 
        { reason: 'Email not verified', email: user.email }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'EMAIL_NOT_VERIFIED',
          message: 'Please verify your email address before logging in',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Verify password with timing attack protection
    const isValidPassword = await verifyPassword(validatedData.password, user.passwordHash);
    if (!isValidPassword) {
      recordFailedAttempt(bruteForceKey);
      await auditLog('LOGIN_FAILED', user.id, user.tenantId, 
        { reason: 'Invalid password', email: user.email }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid credentials',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Check if MFA is enabled
    if (user.mfaEnabled) {
      // If no MFA token provided, return requiring MFA
      if (!validatedData.mfaToken) {
        await auditLog('LOGIN_MFA_REQUIRED', user.id, user.tenantId, 
          { email: user.email }, clientIp, userAgent);
        return c.json({ 
          mfaRequired: true,
          message: 'MFA token required',
          timestamp: new Date().toISOString(),
        }, 200);
      }

      // Verify MFA token
      const mfaResult = await mfaService.verifyToken(
        user.mfaSecret!,
        validatedData.mfaToken
      );

      if (!mfaResult.verified) {
        recordFailedAttempt(bruteForceKey);
        await auditLog('LOGIN_MFA_FAILED', user.id, user.tenantId, 
          { reason: mfaResult.error || 'Invalid MFA token', email: user.email }, clientIp, userAgent);
        return c.json({ 
          error: { 
            code: 'INVALID_MFA_TOKEN',
            message: 'Invalid MFA token',
            timestamp: new Date().toISOString(),
          } 
        }, 401);
      }
    }

    // Check for concurrent session limits
    const existingSessions = await redisCircuitBreaker.execute(async () => {
      const pattern = `session:${user.id}:${user.tenantId}:*`;
      return await redis.keys(pattern);
    });

    if (existingSessions.length >= SECURITY_CONFIG.maxConcurrentSessions) {
      // Remove oldest session
      const oldestSession = existingSessions[0];
      await redisCircuitBreaker.execute(async () => {
        await redis.del(oldestSession);
      });
    }

    // Generate tokens with user permissions
    const permissions = user.tenant?.settings?.permissions || {};
    const { accessToken, refreshToken, sessionId } = await generateTokens(
      user.id, 
      user.tenantId, 
      user.role, 
      user.email,
      permissions
    );

    // Generate CSRF token
    const csrfToken = generateCSRFToken();

    // Store session in Redis with circuit breaker
    const sessionKey = `session:${user.id}:${user.tenantId}:${sessionId}`;
    const sessionData = {
      userId: user.id,
      tenantId: user.tenantId,
      role: user.role,
      email: user.email,
      sessionId,
      loginTime: new Date().toISOString(),
      ipAddress: clientIp,
      userAgent,
      lastActivity: new Date().toISOString(),
    };

    await redisCircuitBreaker.execute(async () => {
      await redis.setex(sessionKey, SECURITY_CONFIG.sessionTimeout, JSON.stringify(sessionData));
      await redis.setex(`refresh:${user.id}:${user.tenantId}:${sessionId}`, SECURITY_CONFIG.sessionTimeout, refreshToken);
      // Store CSRF token associated with the session
      await redis.setex(`csrf:${user.id}:${sessionId}`, SECURITY_CONFIG.sessionTimeout, csrfToken);
    });

    // Update last login with circuit breaker
    await databaseCircuitBreaker.execute(async () => {
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      });
    });

    // Reset brute force attempts on success
    resetFailedAttempts(bruteForceKey);

    await auditLog('LOGIN_SUCCESS', user.id, user.tenantId, 
      { email: user.email, sessionId }, clientIp, userAgent);
    
    // Log successful login to SIEM
    await logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, {
      severity: SecuritySeverity.INFO,
      source: 'auth-service',
      userId: user.id,
      organizationId: user.tenantId,
      ipAddress: clientIp,
      userAgent,
      details: {
        email: user.email,
        sessionId,
        mfaUsed: user.mfaEnabled
      }
    });

    // Set secure cookies
    const isProduction = config.environment === 'production';
    setCookie(c, 'accessToken', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'Strict',
      maxAge: 15 * 60, // 15 minutes
      path: '/',
    });

    setCookie(c, 'refreshToken', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
    });

    // Set CSRF token in a readable cookie (not HttpOnly)
    setCookie(c, 'csrfToken', csrfToken, {
      httpOnly: false, // Must be readable by JavaScript
      secure: isProduction,
      sameSite: 'Strict',
      maxAge: 15 * 60, // 15 minutes, same as access token
      path: '/',
    });

    const response: ApiResponse = {
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          email: user.email,
          username: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          tenantId: user.tenantId,
          permissions,
          lastLoginAt: user.lastLoginAt?.toISOString(),
          tenant: user.tenant,
        },
        accessToken,
        refreshToken,
        expiresIn: 15 * 60, // 15 minutes
        tokenType: 'Bearer' as const,
        sessionId,
        csrfToken, // Include CSRF token in response
      },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: { 
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: error.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Login error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /logout - Enhanced user logout with session cleanup and JWT blacklisting
app.post('/logout', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const user = c.get('user') as AccessTokenPayload;
    const body = await c.req.json().catch(() => ({}));
    const logoutAllDevices = body.logoutAllDevices || false;

    // Extract tokens for blacklisting
    const authHeader = c.req.header('Authorization');
    const accessToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : getCookie(c, 'accessToken');
    const refreshToken = getCookie(c, 'refreshToken');

    if (logoutAllDevices) {
      // Blacklist all user tokens
      const blacklistedCount = await jwtBlacklist.blacklistUserTokens(
        user.sub, 
        user.tenantId, 
        'User logout - all devices'
      );
      appLogger.info('Blacklisted user tokens', { userId: user.sub, count: blacklistedCount });
      
      // Remove all sessions for the user
      await invalidateUserSessions(user.sub);
      // Remove all CSRF tokens for the user
      await redisCircuitBreaker.execute(async () => {
        const csrfPattern = `csrf:${user.sub}:*`;
        const keys = await redis.keys(csrfPattern);
        if (keys.length > 0) {
          await redis.del(...keys);
        }
      });
    } else {
      // Blacklist current session tokens
      if (accessToken) {
        await jwtBlacklist.blacklistToken(accessToken, 'User logout');
      }
      if (refreshToken) {
        await jwtBlacklist.blacklistToken(refreshToken, 'User logout');
      }
      
      // Remove only current session
      await redisCircuitBreaker.execute(async () => {
        const sessionKey = `session:${user.sub}:${user.tenantId}:${user.sessionId}`;
        const refreshKey = `refresh:${user.sub}:${user.tenantId}:${user.sessionId}`;
        const csrfKey = `csrf:${user.sub}:${user.sessionId}`;
        
        await redis.del(sessionKey);
        await redis.del(refreshKey);
        await redis.del(csrfKey);
      });
    }

    // Clear cookies
    deleteCookie(c, 'accessToken');
    deleteCookie(c, 'refreshToken');
    deleteCookie(c, 'csrfToken');

    await auditLog('LOGOUT', user.sub, user.tenantId, 
      { sessionId: user.sessionId, logoutAllDevices }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'Logout successful',
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Logout error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /refresh-token - Enhanced token refresh with blacklisting and rotation
app.post('/refresh-token', async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const body = await c.req.json().catch(() => ({}));
    const refreshTokenFromBody = body.refreshToken;
    const refreshTokenFromCookie = getCookie(c, 'refreshToken');
    const refreshToken = refreshTokenFromBody || refreshTokenFromCookie;

    if (!refreshToken) {
      return c.json({ 
        error: { 
          code: 'REFRESH_TOKEN_REQUIRED',
          message: 'Refresh token required',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    const payload = await jwtService.verifyRefreshToken(refreshToken);
    
    if (payload.type !== 'refresh') {
      return c.json({ 
        error: { 
          code: 'INVALID_TOKEN_TYPE',
          message: 'Invalid token type',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Check if refresh token is blacklisted using JWT blacklist service
    const isBlacklisted = await jwtBlacklist.isBlacklisted(refreshToken);
    
    if (isBlacklisted) {
      return c.json({ 
        error: { 
          code: 'TOKEN_BLACKLISTED',
          message: 'Refresh token has been revoked',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Verify refresh token exists in Redis
    const refreshKey = `refresh:${payload.sub}:${payload.tenantId}:${payload.sessionId}`;
    const storedToken = await redisCircuitBreaker.execute(async () => {
      return await redis.get(refreshKey);
    });
    
    if (!storedToken || storedToken !== refreshToken) {
      return c.json({ 
        error: { 
          code: 'INVALID_REFRESH_TOKEN',
          message: 'Invalid refresh token',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Get user details with circuit breaker
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findUnique({
        where: { id: payload.sub },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          role: true,
          tenantId: true,
          isActive: true,
          emailVerified: true,
          tenant: {
            select: {
              id: true,
              name: true,
              isActive: true,
              settings: true,
            },
          },
        },
      });
    });

    if (!user || !user.isActive || !user.emailVerified || !user.tenant?.isActive) {
      // Blacklist the refresh token
      await redisCircuitBreaker.execute(async () => {
        await redis.setex(blacklistKey, 7 * 24 * 60 * 60, 'revoked'); // 7 days
      });

      return c.json({ 
        error: { 
          code: 'USER_INACTIVE',
          message: 'User not found or inactive',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Blacklist the old refresh token
    await redisCircuitBreaker.execute(async () => {
      await redis.setex(blacklistKey, 7 * 24 * 60 * 60, 'rotated'); // 7 days
    });

    // Generate new tokens with user permissions
    const permissions = user.tenant?.settings?.permissions || {};
    const { accessToken, refreshToken: newRefreshToken, sessionId } = await generateTokens(
      user.id, 
      user.tenantId, 
      user.role, 
      user.email,
      permissions
    );

    // Blacklist the old tokens before creating new session
    await jwtBlacklist.blacklistToken(refreshToken, 'Token refresh - old refresh token');
    
    // Also blacklist the old access token if we can get it
    const authHeader = c.req.header('Authorization');
    const oldAccessToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : getCookie(c, 'accessToken');
    if (oldAccessToken) {
      await jwtBlacklist.blacklistToken(oldAccessToken, 'Token refresh - old access token');
    }

    // Update session and refresh token in Redis
    await redisCircuitBreaker.execute(async () => {
      const newSessionKey = `session:${user.id}:${user.tenantId}:${sessionId}`;
      const newRefreshKey = `refresh:${user.id}:${user.tenantId}:${sessionId}`;
      
      // Remove old session
      await redis.del(refreshKey);
      const oldSessionKey = `session:${payload.sub}:${payload.tenantId}:${payload.sessionId}`;
      await redis.del(oldSessionKey);

      // Create new session
      const sessionData = {
        userId: user.id,
        tenantId: user.tenantId,
        role: user.role,
        email: user.email,
        sessionId,
        loginTime: new Date().toISOString(),
        ipAddress: clientIp,
        userAgent,
        lastActivity: new Date().toISOString(),
        refreshedAt: new Date().toISOString(),
      };

      await redis.setex(newSessionKey, SECURITY_CONFIG.sessionTimeout, JSON.stringify(sessionData));
      await redis.setex(newRefreshKey, SECURITY_CONFIG.sessionTimeout, newRefreshToken);
    });

    // Set new cookies
    const isProduction = config.environment === 'production';
    setCookie(c, 'accessToken', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'Strict',
      maxAge: 15 * 60, // 15 minutes
      path: '/',
    });

    setCookie(c, 'refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
    });

    await auditLog('TOKEN_REFRESH', user.id, user.tenantId, 
      { oldSessionId: payload.sessionId, newSessionId: sessionId }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken,
        refreshToken: newRefreshToken,
        expiresIn: 15 * 60, // 15 minutes
        user: {
          id: user.id,
          email: user.email,
          username: user.email,
          role: user.role,
          tenantId: user.tenantId,
        },
      },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Token refresh error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INVALID_REFRESH_TOKEN',
        message: 'Invalid or expired refresh token',
        timestamp: new Date().toISOString(),
      } 
    }, 401);
  }
});

// GET /me - Enhanced user profile retrieval with comprehensive data
app.get('/me', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');

  try {
    const userPayload = c.get('user') as AccessTokenPayload;

    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findUnique({
        where: { id: userPayload.sub },
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
          role: true,
          tenantId: true,
          isActive: true,
          emailVerified: true,
          lastLoginAt: true,
          createdAt: true,
          updatedAt: true,
          tenant: {
            select: {
              id: true,
              name: true,
              domain: true,
              isActive: true,
              settings: true,
            },
          },
        },
      });
    });

    if (!user || !user.isActive) {
      return c.json({ 
        error: { 
          code: 'USER_NOT_FOUND',
          message: 'User not found or inactive',
          timestamp: new Date().toISOString(),
        } 
      }, 404);
    }

    const response: ApiResponse = {
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          username: user.username || user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          tenantId: user.tenantId,
          permissions: userPayload.permissions,
          active: user.isActive,
          lastLoginAt: user.lastLoginAt?.toISOString(),
          createdAt: user.createdAt.toISOString(),
          updatedAt: user.updatedAt.toISOString(),
          tenant: user.tenant,
        },
      },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Get user error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// PUT /me - Update user profile
app.put('/me', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const userPayload = c.get('user') as AccessTokenPayload;
    const body = await c.req.json();
    const validatedData = updateProfileSchema.parse(body);

    // Check if email is being changed and if it's already taken
    if (validatedData.email && validatedData.email !== userPayload.email) {
      const existingUser = await databaseCircuitBreaker.execute(async () => {
        return await prisma.user.findFirst({
          where: {
            email: validatedData.email,
            tenantId: userPayload.tenantId,
            id: { not: userPayload.sub },
          },
        });
      });

      if (existingUser) {
        return c.json({ 
          error: { 
            code: 'EMAIL_TAKEN',
            message: 'Email address is already in use',
            timestamp: new Date().toISOString(),
          } 
        }, 409);
      }
    }

    // Update user profile
    const updatedUser = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.update({
        where: { id: userPayload.sub },
        data: {
          ...validatedData,
          updatedAt: new Date(),
        },
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
          role: true,
          tenantId: true,
          isActive: true,
          lastLoginAt: true,
          createdAt: true,
          updatedAt: true,
        },
      });
    });

    await auditLog('PROFILE_UPDATED', userPayload.sub, userPayload.tenantId, 
      { changes: validatedData }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'Profile updated successfully',
      data: { user: updatedUser },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: { 
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: error.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Update profile error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /change-password - Enhanced password change with history tracking
app.post('/change-password', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const body = await c.req.json();
    const validatedData = changePasswordSchema.parse(body);
    const userPayload = c.get('user') as AccessTokenPayload;

    // Validate new password strength with history check
    const passwordValidation = await passwordSecurity.validatePassword(
      validatedData.newPassword,
      userPayload.sub
    );
    if (!passwordValidation.valid) {
      return c.json({ 
        error: { 
          code: 'WEAK_PASSWORD',
          message: 'Password does not meet security requirements',
          details: passwordValidation.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Get current user with circuit breaker
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findUnique({
        where: { id: userPayload.sub },
        select: {
          id: true,
          email: true,
          passwordHash: true,
          tenantId: true,
        },
      });
    });

    if (!user) {
      return c.json({ 
        error: { 
          code: 'USER_NOT_FOUND',
          message: 'User not found',
          timestamp: new Date().toISOString(),
        } 
      }, 404);
    }

    // Verify current password
    const isValidCurrentPassword = await verifyPassword(validatedData.currentPassword, user.passwordHash);
    if (!isValidCurrentPassword) {
      await auditLog('PASSWORD_CHANGE_FAILED', user.id, user.tenantId, 
        { reason: 'Invalid current password' }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'INVALID_CURRENT_PASSWORD',
          message: 'Current password is incorrect',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Check password history
    const isPasswordReused = !(await checkPasswordHistory(user.id, validatedData.newPassword));
    if (isPasswordReused) {
      await auditLog('PASSWORD_CHANGE_FAILED', user.id, user.tenantId, 
        { reason: 'Password reuse detected' }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'PASSWORD_REUSED',
          message: `Password cannot be one of the last ${SECURITY_CONFIG.passwordPolicy.preventReuse} passwords`,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Hash new password with enhanced security
    const newHashedPassword = await passwordSecurity.hashPassword(validatedData.newPassword);

    // Update password and save to history with transaction
    await databaseCircuitBreaker.execute(async () => {
      await prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: user.id },
          data: {
            passwordHash: newHashedPassword,
            updatedAt: new Date(),
          },
        });

        // Add to password history
        await passwordSecurity.addToPasswordHistory(user.id, newHashedPassword);
      });
    });

    // Invalidate all user sessions except current one
    await invalidateUserSessions(user.id, userPayload.sessionId);

    await auditLog('PASSWORD_CHANGED', user.id, user.tenantId, 
      { sessionId: userPayload.sessionId }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'Password changed successfully',
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: { 
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: error.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Change password error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /reset-password - Password reset request
app.post('/reset-password', async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const body = await c.req.json();
    const validatedData = resetPasswordSchema.parse(body);

    // Check brute force protection
    const bruteForceKey = `reset:${clientIp}:${validatedData.email}`;
    if (!(await checkBruteForce(bruteForceKey))) {
      return c.json({ 
        error: { 
          code: 'RESET_BLOCKED',
          message: 'Too many reset attempts. Please try again later.',
          timestamp: new Date().toISOString(),
        } 
      }, 429);
    }

    // Find user
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findFirst({
        where: {
          email: validatedData.email,
          tenantId: validatedData.tenantId,
          isActive: true,
          emailVerified: true,
        },
      });
    });

    if (!user) {
      await recordFailedAttempt(bruteForceKey);
      // Don't reveal if user exists or not
      const response: ApiResponse = {
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.',
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          environment: config.environment,
        },
      };
      return c.json(response);
    }

    // Generate reset token
    const resetToken = generatePasswordResetToken();
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Save reset token
    await databaseCircuitBreaker.execute(async () => {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordResetToken: resetToken,
          passwordResetExpiry: resetExpiry,
          updatedAt: new Date(),
        },
      });
    });

    // Send reset email
    await sendPasswordResetEmail(user.email, resetToken, user.tenantId);

    await resetFailedAttempts(bruteForceKey);

    await auditLog('PASSWORD_RESET_REQUESTED', user.id, user.tenantId, 
      { email: user.email }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.',
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: { 
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: error.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Password reset error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /reset-password/confirm - Password reset confirmation
app.post('/reset-password/confirm', async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const body = await c.req.json();
    const validatedData = resetPasswordConfirmSchema.parse(body);

    if (validatedData.newPassword !== validatedData.confirmPassword) {
      return c.json({ 
        error: { 
          code: 'PASSWORD_MISMATCH',
          message: 'Passwords do not match',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Validate password strength
    const passwordValidation = validatePassword(validatedData.newPassword);
    if (!passwordValidation.valid) {
      return c.json({ 
        error: { 
          code: 'WEAK_PASSWORD',
          message: 'Password does not meet security requirements',
          details: passwordValidation.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Find user with valid reset token
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findFirst({
        where: {
          passwordResetToken: validatedData.token,
          passwordResetExpiry: { gt: new Date() },
          isActive: true,
        },
      });
    });

    if (!user) {
      return c.json({ 
        error: { 
          code: 'INVALID_RESET_TOKEN',
          message: 'Invalid or expired reset token',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Check password history
    const isPasswordReused = !(await checkPasswordHistory(user.id, validatedData.newPassword));
    if (isPasswordReused) {
      return c.json({ 
        error: { 
          code: 'PASSWORD_REUSED',
          message: `Password cannot be one of the last ${SECURITY_CONFIG.passwordPolicy.preventReuse} passwords`,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Hash new password with enhanced security
    const newHashedPassword = await passwordSecurity.hashPassword(validatedData.newPassword);

    // Update password and clear reset token
    await databaseCircuitBreaker.execute(async () => {
      await prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: user.id },
          data: {
            passwordHash: newHashedPassword,
            passwordResetToken: null,
            passwordResetExpiry: null,
            updatedAt: new Date(),
          },
        });

        // Add to password history
        await passwordSecurity.addToPasswordHistory(user.id, newHashedPassword);
      });
    });

    // Invalidate all user sessions
    await invalidateUserSessions(user.id);

    await auditLog('PASSWORD_RESET_COMPLETED', user.id, user.tenantId, 
      { email: user.email }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'Password reset successfully. Please log in with your new password.',
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    if (error instanceof z.ZodError) {
      return c.json({ 
        error: { 
          code: 'VALIDATION_FAILED',
          message: 'Validation failed',
          details: error.errors,
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Password reset confirm error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// GET /sessions - List user sessions
app.get('/sessions', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');

  try {
    const userPayload = c.get('user') as AccessTokenPayload;

    const sessionKeys = await redisCircuitBreaker.execute(async () => {
      return await redis.keys(`session:${userPayload.sub}:${userPayload.tenantId}:*`);
    });

    const sessions = [];
    for (const key of sessionKeys) {
      try {
        const sessionData = await redisCircuitBreaker.execute(async () => {
          return await redis.get(key);
        });

        if (sessionData) {
          const session = JSON.parse(sessionData);
          sessions.push({
            id: session.sessionId,
            deviceInfo: {
              userAgent: session.userAgent,
              ipAddress: session.ipAddress,
            },
            createdAt: session.loginTime,
            lastAccessedAt: session.lastActivity || session.loginTime,
            current: session.sessionId === userPayload.sessionId,
          });
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        appLogger.warn('Failed to parse session data', { key, error: errorMessage });
      }
    }

    const response: ApiResponse = {
      success: true,
      data: { sessions },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Get sessions error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// DELETE /sessions/:sessionId - Revoke specific session
app.delete('/sessions/:sessionId', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const userPayload = c.get('user') as AccessTokenPayload;
    const sessionId = c.req.param('sessionId');

    if (sessionId === userPayload.sessionId) {
      return c.json({ 
        error: { 
          code: 'CANNOT_REVOKE_CURRENT_SESSION',
          message: 'Cannot revoke current session. Use logout instead.',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    await redisCircuitBreaker.execute(async () => {
      const sessionKey = `session:${userPayload.sub}:${userPayload.tenantId}:${sessionId}`;
      const refreshKey = `refresh:${userPayload.sub}:${userPayload.tenantId}:${sessionId}`;
      
      await redis.del(sessionKey);
      await redis.del(refreshKey);
    });

    await auditLog('SESSION_REVOKED', userPayload.sub, userPayload.tenantId, 
      { revokedSessionId: sessionId }, clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'Session revoked successfully',
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Revoke session error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /admin/revoke-user-sessions - Admin endpoint to revoke all sessions for a user
app.post('/admin/revoke-user-sessions', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');

  try {
    const adminUser = c.get('user') as AccessTokenPayload;
    
    // Check if user has admin privileges
    if (adminUser.role !== 'SUPER_ADMIN' && adminUser.role !== 'ADMIN') {
      return c.json({ 
        error: { 
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'Admin privileges required',
          timestamp: new Date().toISOString(),
        } 
      }, 403);
    }

    const body = await c.req.json();
    const { userId, tenantId, reason } = body;

    if (!userId || !tenantId) {
      return c.json({ 
        error: { 
          code: 'MISSING_PARAMETERS',
          message: 'userId and tenantId are required',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Ensure admin can only revoke sessions within their tenant (unless SUPER_ADMIN)
    if (adminUser.role !== 'SUPER_ADMIN' && adminUser.tenantId !== tenantId) {
      return c.json({ 
        error: { 
          code: 'TENANT_ISOLATION_VIOLATION',
          message: 'Cannot revoke sessions for users in other tenants',
          timestamp: new Date().toISOString(),
        } 
      }, 403);
    }

    // Blacklist all tokens for the user
    const blacklistedCount = await jwtBlacklist.blacklistUserTokens(
      userId,
      tenantId,
      reason || `Admin revoked by ${adminUser.email}`
    );

    // Remove all sessions for the user
    await invalidateUserSessions(userId);

    // Remove all CSRF tokens for the user
    await redisCircuitBreaker.execute(async () => {
      const csrfPattern = `csrf:${userId}:*`;
      const keys = await redis.keys(csrfPattern);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    });

    await auditLog('ADMIN_REVOKE_USER_SESSIONS', adminUser.sub, adminUser.tenantId, 
      { targetUserId: userId, targetTenantId: tenantId, reason, blacklistedCount }, 
      clientIp, userAgent);

    const response: ApiResponse = {
      success: true,
      message: 'User sessions revoked successfully',
      data: {
        userId,
        tenantId,
        blacklistedTokens: blacklistedCount,
        revokedAt: new Date().toISOString(),
      },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: config.environment,
      },
    };

    return c.json(response);

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Admin revoke sessions error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// GET /check-role - Check if user has specific role(s)
app.get('/check-role', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  
  try {
    const roles = c.req.query('roles');
    if (!roles) {
      return c.json({ 
        error: { 
          code: 'MISSING_PARAMETER',
          message: 'Roles parameter is required',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    const userPayload = c.get('user') as AccessTokenPayload;
    const requiredRoles = roles.split(',').map(r => r.trim());
    const hasRole = requiredRoles.includes(userPayload.role);

    await auditLog('ROLE_CHECK', userPayload.sub, userPayload.tenantId, 
      { requiredRoles, userRole: userPayload.role, hasRole }, c.get('clientIp'), c.get('userAgent'));

    return c.json({ 
      hasRole,
      userRole: userPayload.role,
      requiredRoles 
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Role check error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// GET /check-permission - Check if user has specific permission(s)
app.get('/check-permission', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  
  try {
    const permission = c.req.query('permission');
    if (!permission) {
      return c.json({ 
        error: { 
          code: 'MISSING_PARAMETER',
          message: 'Permission parameter is required',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    const userPayload = c.get('user') as AccessTokenPayload;
    
    // Define role-based permissions (same as frontend but server-side)
    const rolePermissions: Record<string, string[]> = {
      SUPER_ADMIN: ['*'], // All permissions
      TENANT_ADMIN: [
        'tenant:manage',
        'users:manage',
        'access:manage',
        'video:manage',
        'reports:view',
        'settings:manage',
      ],
      SITE_ADMIN: [
        'site:manage',
        'access:manage',
        'video:manage',
        'reports:view',
      ],
      OPERATOR: [
        'access:control',
        'video:view',
        'events:view',
      ],
      VIEWER: [
        'access:view',
        'video:view',
        'events:view',
      ],
    };

    const userPermissions = rolePermissions[userPayload.role] || [];
    const hasPermission = userPermissions.includes('*') || userPermissions.includes(permission);

    await auditLog('PERMISSION_CHECK', userPayload.sub, userPayload.tenantId, 
      { requiredPermission: permission, userRole: userPayload.role, hasPermission }, 
      c.get('clientIp'), c.get('userAgent'));

    return c.json({ 
      hasPermission,
      userRole: userPayload.role,
      permission,
      userPermissions: userPermissions.filter(p => p !== '*') // Don't expose wildcard
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Permission check error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /check-permissions - Batch check multiple permissions
app.post('/check-permissions', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  
  try {
    const body = await c.req.json();
    const permissions = body.permissions;
    
    if (!permissions || !Array.isArray(permissions)) {
      return c.json({ 
        error: { 
          code: 'INVALID_REQUEST',
          message: 'Permissions array is required',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    const userPayload = c.get('user') as AccessTokenPayload;
    
    // Define role-based permissions
    const rolePermissions: Record<string, string[]> = {
      SUPER_ADMIN: ['*'],
      TENANT_ADMIN: [
        'tenant:manage',
        'users:manage',
        'access:manage',
        'video:manage',
        'reports:view',
        'settings:manage',
      ],
      SITE_ADMIN: [
        'site:manage',
        'access:manage',
        'video:manage',
        'reports:view',
      ],
      OPERATOR: [
        'access:control',
        'video:view',
        'events:view',
      ],
      VIEWER: [
        'access:view',
        'video:view',
        'events:view',
      ],
    };

    const userPermissions = rolePermissions[userPayload.role] || [];
    const hasAllPermissions = userPermissions.includes('*');
    
    const results: Record<string, boolean> = {};
    permissions.forEach((permission: string) => {
      results[permission] = hasAllPermissions || userPermissions.includes(permission);
    });

    await auditLog('BATCH_PERMISSION_CHECK', userPayload.sub, userPayload.tenantId, 
      { permissions, userRole: userPayload.role, results }, 
      c.get('clientIp'), c.get('userAgent'));

    return c.json({ 
      permissions: results,
      userRole: userPayload.role
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Batch permission check error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// GET /user-permissions - Get all permissions for the current user
app.get('/user-permissions', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  
  try {
    const userPayload = c.get('user') as AccessTokenPayload;
    
    // Define role-based permissions
    const rolePermissions: Record<string, string[]> = {
      SUPER_ADMIN: ['*'],
      TENANT_ADMIN: [
        'tenant:manage',
        'users:manage',
        'access:manage',
        'video:manage',
        'reports:view',
        'settings:manage',
      ],
      SITE_ADMIN: [
        'site:manage',
        'access:manage',
        'video:manage',
        'reports:view',
      ],
      OPERATOR: [
        'access:control',
        'video:view',
        'events:view',
      ],
      VIEWER: [
        'access:view',
        'video:view',
        'events:view',
      ],
    };

    const userPermissions = rolePermissions[userPayload.role] || [];
    const effectivePermissions = userPermissions.includes('*') 
      ? Object.values(rolePermissions).flat().filter(p => p !== '*').filter((v, i, a) => a.indexOf(v) === i) 
      : userPermissions;

    await auditLog('USER_PERMISSIONS_RETRIEVED', userPayload.sub, userPayload.tenantId, 
      { userRole: userPayload.role }, c.get('clientIp'), c.get('userAgent'));

    return c.json({ 
      role: userPayload.role,
      permissions: effectivePermissions,
      isAdmin: userPayload.role === 'SUPER_ADMIN' || userPayload.role === 'TENANT_ADMIN'
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('User permissions retrieval error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /mfa/setup - Set up MFA for the current user
app.post('/mfa/setup', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  const userPayload = c.get('user') as AccessTokenPayload;
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');
  
  try {
    // Get user from database
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findUnique({
        where: { id: userPayload.sub },
        include: { tenant: true }
      });
    });

    if (!user) {
      return c.json({ 
        error: { 
          code: 'USER_NOT_FOUND',
          message: 'User not found',
          timestamp: new Date().toISOString(),
        } 
      }, 404);
    }

    // Check if MFA is already enabled
    if (user.mfaEnabled && user.mfaVerifiedAt) {
      return c.json({ 
        error: { 
          code: 'MFA_ALREADY_ENABLED',
          message: 'MFA is already enabled for this account',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Generate MFA secret
    const mfaSecret = await mfaService.generateSecret(
      user.email, 
      user.tenant?.name
    );

    // Generate backup codes
    const backupCodes = await mfaService.generateBackupCodes();

    // Store MFA secret (but don't enable yet)
    await databaseCircuitBreaker.execute(async () => {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          mfaSecret: mfaSecret.base32,
          mfaBackupCodes: JSON.stringify(backupCodes.codes),
          // Don't set mfaEnabled to true yet - wait for verification
        }
      });
    });

    await auditLog('MFA_SETUP_INITIATED', user.id, user.tenantId, 
      { email: user.email }, clientIp, userAgent);

    return c.json({
      secret: mfaSecret.base32,
      qrCode: mfaSecret.qr_code_url,
      backupCodes: backupCodes.codes,
      message: 'Please scan the QR code with your authenticator app and verify with a token'
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('MFA setup error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /mfa/verify - Verify MFA setup
app.post('/mfa/verify', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  const userPayload = c.get('user') as AccessTokenPayload;
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');
  
  try {
    const body = await c.req.json();
    const { token } = body;

    if (!token) {
      return c.json({ 
        error: { 
          code: 'MISSING_TOKEN',
          message: 'MFA token is required',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Get user with MFA secret
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findUnique({
        where: { id: userPayload.sub }
      });
    });

    if (!user || !user.mfaSecret) {
      return c.json({ 
        error: { 
          code: 'MFA_NOT_SETUP',
          message: 'MFA has not been set up',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Verify the token
    const verificationResult = await mfaService.verifyToken(user.mfaSecret, token);

    if (!verificationResult.verified) {
      await auditLog('MFA_VERIFICATION_FAILED', user.id, user.tenantId, 
        { reason: verificationResult.error }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'INVALID_TOKEN',
          message: verificationResult.error || 'Invalid MFA token',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Enable MFA
    await databaseCircuitBreaker.execute(async () => {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          mfaEnabled: true,
          mfaVerifiedAt: new Date()
        }
      });
    });

    await auditLog('MFA_ENABLED', user.id, user.tenantId, 
      { email: user.email }, clientIp, userAgent);

    return c.json({
      success: true,
      message: 'MFA has been successfully enabled'
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('MFA verification error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /mfa/disable - Disable MFA
app.post('/mfa/disable', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  const userPayload = c.get('user') as AccessTokenPayload;
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');
  
  try {
    const body = await c.req.json();
    const { password, token } = body;

    if (!password || !token) {
      return c.json({ 
        error: { 
          code: 'MISSING_CREDENTIALS',
          message: 'Password and MFA token are required',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Get user with password hash
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findUnique({
        where: { id: userPayload.sub }
      });
    });

    if (!user || !user.mfaEnabled) {
      return c.json({ 
        error: { 
          code: 'MFA_NOT_ENABLED',
          message: 'MFA is not enabled',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, user.passwordHash);
    if (!isValidPassword) {
      await auditLog('MFA_DISABLE_FAILED', user.id, user.tenantId, 
        { reason: 'Invalid password' }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'INVALID_PASSWORD',
          message: 'Invalid password',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Verify MFA token
    const verificationResult = await mfaService.verifyToken(user.mfaSecret!, token);
    if (!verificationResult.verified) {
      await auditLog('MFA_DISABLE_FAILED', user.id, user.tenantId, 
        { reason: 'Invalid MFA token' }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'INVALID_TOKEN',
          message: 'Invalid MFA token',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Disable MFA
    await databaseCircuitBreaker.execute(async () => {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          mfaEnabled: false,
          mfaSecret: null,
          mfaBackupCodes: null,
          mfaVerifiedAt: null
        }
      });
    });

    await auditLog('MFA_DISABLED', user.id, user.tenantId, 
      { email: user.email }, clientIp, userAgent);

    return c.json({
      success: true,
      message: 'MFA has been disabled'
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('MFA disable error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /mfa/backup-codes/regenerate - Regenerate backup codes
app.post('/mfa/backup-codes/regenerate', requireAuth, async (c: Context) => {
  const requestId = c.get('requestId');
  const userPayload = c.get('user') as AccessTokenPayload;
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');
  
  try {
    const body = await c.req.json();
    const { token } = body;

    if (!token) {
      return c.json({ 
        error: { 
          code: 'MISSING_TOKEN',
          message: 'MFA token is required',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Get user
    const user = await databaseCircuitBreaker.execute(async () => {
      return await prisma.user.findUnique({
        where: { id: userPayload.sub }
      });
    });

    if (!user || !user.mfaEnabled) {
      return c.json({ 
        error: { 
          code: 'MFA_NOT_ENABLED',
          message: 'MFA is not enabled',
          timestamp: new Date().toISOString(),
        } 
      }, 400);
    }

    // Verify MFA token
    const verificationResult = await mfaService.verifyToken(user.mfaSecret!, token);
    if (!verificationResult.verified) {
      await auditLog('BACKUP_CODES_REGENERATION_FAILED', user.id, user.tenantId, 
        { reason: 'Invalid MFA token' }, clientIp, userAgent);
      return c.json({ 
        error: { 
          code: 'INVALID_TOKEN',
          message: 'Invalid MFA token',
          timestamp: new Date().toISOString(),
        } 
      }, 401);
    }

    // Generate new backup codes
    const backupCodes = await mfaService.generateBackupCodes();

    // Store new backup codes
    await databaseCircuitBreaker.execute(async () => {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          mfaBackupCodes: JSON.stringify(backupCodes.codes)
        }
      });
    });

    await auditLog('BACKUP_CODES_REGENERATED', user.id, user.tenantId, 
      { email: user.email }, clientIp, userAgent);

    return c.json({
      backupCodes: backupCodes.codes,
      message: 'New backup codes generated. Please store them securely.'
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Backup codes regeneration error', { error: errorMessage, requestId });
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// POST /admin/rotate-jwt-secrets - Admin endpoint to rotate JWT secrets
app.post('/admin/rotate-jwt-secrets', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');
  const clientIp = c.get('clientIp');
  const userAgent = c.get('userAgent');
  
  try {
    const adminUser = c.get('user') as AccessTokenPayload;
    
    // Check if user has admin privileges
    if (adminUser.role !== 'SUPER_ADMIN') {
      return c.json({ 
        error: { 
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'Super admin privileges required for JWT secret rotation',
          timestamp: new Date().toISOString(),
        } 
      }, 403);
    }
    
    // Log the rotation attempt
    await auditLog('JWT_ROTATION_INITIATED', adminUser.sub, adminUser.tenantId, 
      { adminEmail: adminUser.email }, clientIp, userAgent);
    
    // Rotate the JWT secrets
    await jwtService.rotateSecrets();
    
    // Get rotation status
    const rotationStatus = jwtService.getRotationStatus();
    
    // Log successful rotation
    await auditLog('JWT_ROTATION_COMPLETED', adminUser.sub, adminUser.tenantId, 
      { 
        adminEmail: adminUser.email,
        gracePeriodEnds: rotationStatus.gracePeriodEnds
      }, clientIp, userAgent);
    
    // Log security event
    await logSecurityEvent({
      eventType: SecurityEventType.JWT_SECRET_ROTATED,
      userId: adminUser.sub,
      organizationId: adminUser.tenantId,
      severity: SecuritySeverity.HIGH,
      details: {
        rotatedBy: adminUser.email,
        gracePeriodEnds: rotationStatus.gracePeriodEnds
      },
      request: {
        ip: clientIp,
        userAgent
      }
    });
    
    return c.json({
      message: 'JWT secrets rotated successfully',
      status: rotationStatus
    });
    
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('JWT secret rotation failed', { error: errorMessage, requestId });
    
    await auditLog('JWT_ROTATION_FAILED', c.get('user').sub, c.get('user').tenantId, 
      { error: errorMessage }, clientIp, userAgent);
    
    return c.json({ 
      error: { 
        code: 'ROTATION_FAILED',
        message: 'Failed to rotate JWT secrets',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// GET /admin/jwt-rotation-status - Get current JWT rotation status
app.get('/admin/jwt-rotation-status', authMiddleware, async (c: Context) => {
  const requestId = c.get('requestId');
  
  try {
    const adminUser = c.get('user') as AccessTokenPayload;
    
    // Check if user has admin privileges
    if (adminUser.role !== 'SUPER_ADMIN' && adminUser.role !== 'ADMIN') {
      return c.json({ 
        error: { 
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'Admin privileges required',
          timestamp: new Date().toISOString(),
        } 
      }, 403);
    }
    
    const rotationStatus = jwtService.getRotationStatus();
    
    return c.json({
      status: rotationStatus
    });
    
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Failed to get JWT rotation status', { error: errorMessage, requestId });
    
    return c.json({ 
      error: { 
        code: 'INTERNAL_ERROR',
        message: 'Failed to get rotation status',
        timestamp: new Date().toISOString(),
      } 
    }, 500);
  }
});

// Graceful shutdown handling
const gracefulShutdown = async () => {
  appLogger.info('Shutting down auth routes...');
  
  try {
    await prisma.$disconnect();
    await redis.quit();
    appLogger.info('Auth routes shutdown completed');
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    appLogger.error('Error during auth routes shutdown', { error: errorMessage });
  }
};

// Export graceful shutdown for use by main application
export { gracefulShutdown };

export default app;
