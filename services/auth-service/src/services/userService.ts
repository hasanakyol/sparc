import { PrismaClient, User, Credential } from '@prisma/client';
import { 
  hashPassword, 
  verifyPassword, 
  generateUUID, 
  createError, 
  ErrorCodes, 
  validateInput,
  validateTenantAccess,
  addTenantFilter,
  logWithContext,
  logAudit,
  logError,
  getCurrentTimestamp,
  SPARCError,
  JWTPayload,
  TenantContext,
  LogContext
} from '@sparc/shared';
import { 
  UserSchema, 
  CreateUserDTO, 
  UpdateUserDTO,
  User as UserType,
  CreateAuditLogDTO
} from '@sparc/shared/types';
import winston from 'winston';
import Redis from 'ioredis';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

// ============================================================================
// INTERFACES AND TYPES
// ============================================================================

export interface UserServiceConfig {
  prisma: PrismaClient;
  redis: Redis;
  logger: winston.Logger;
  jwtConfig: {
    accessTokenSecret: string;
    refreshTokenSecret: string;
    accessTokenExpiry: string;
    refreshTokenExpiry: string;
    issuer: string;
  };
  passwordOptions?: {
    saltRounds?: number;
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecialChars?: boolean;
  };
  bruteForceProtection?: {
    maxAttempts?: number;
    windowMs?: number;
    blockDurationMs?: number;
  };
  sessionConfig?: {
    maxSessions?: number;
    sessionTimeoutMs?: number;
    extendOnActivity?: boolean;
  };
  circuitBreaker?: {
    enabled?: boolean;
    failureThreshold?: number;
    resetTimeoutMs?: number;
  };
}

export interface CreateUserRequest extends CreateUserDTO {
  password: string;
}

export interface UpdateUserRequest extends Partial<UpdateUserDTO> {
  password?: string;
}

export interface UserWithCredentials extends User {
  credentials: Credential[];
}

export interface AuthenticationResult {
  user: User;
  isValid: boolean;
  reason?: string;
}

export interface SessionInfo {
  userId: string;
  tenantId: string;
  sessionId: string;
  expiresAt: Date;
  lastActivity: Date;
  ipAddress?: string;
  userAgent?: string;
  deviceFingerprint?: string;
  isActive: boolean;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface RefreshTokenData {
  userId: string;
  tenantId: string;
  sessionId: string;
  deviceFingerprint?: string;
  issuedAt: number;
  expiresAt: number;
}

export interface PasswordResetRequest {
  email: string;
  tenantId: string;
}

export interface PasswordResetConfirm {
  token: string;
  newPassword: string;
}

export interface BruteForceAttempt {
  attempts: number;
  lastAttempt: number;
  blockedUntil?: number;
}

export interface CircuitBreakerState {
  failures: number;
  lastFailureTime: number;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
}

export interface UserPermissions {
  roles: string[];
  permissions: string[];
  accessGroups: string[];
}

export interface UserListOptions {
  page?: number;
  limit?: number;
  search?: string;
  roles?: string[];
  active?: boolean;
  sortBy?: 'username' | 'email' | 'createdAt' | 'lastLogin';
  sortOrder?: 'asc' | 'desc';
}

export interface UserStats {
  totalUsers: number;
  activeUsers: number;
  inactiveUsers: number;
  usersByRole: Record<string, number>;
  recentLogins: number;
}

// ============================================================================
// USER SERVICE CLASS
// ============================================================================

export class UserService {
  private prisma: PrismaClient;
  private redis: Redis;
  private logger: winston.Logger;
  private jwtConfig: UserServiceConfig['jwtConfig'];
  private passwordOptions: Required<NonNullable<UserServiceConfig['passwordOptions']>>;
  private bruteForceConfig: Required<NonNullable<UserServiceConfig['bruteForceProtection']>>;
  private sessionConfig: Required<NonNullable<UserServiceConfig['sessionConfig']>>;
  private circuitBreakerConfig: Required<NonNullable<UserServiceConfig['circuitBreaker']>>;
  private circuitBreakerState: CircuitBreakerState;

  constructor(config: UserServiceConfig) {
    this.prisma = config.prisma;
    this.redis = config.redis;
    this.logger = config.logger;
    this.jwtConfig = config.jwtConfig;
    
    this.passwordOptions = {
      saltRounds: 12,
      minLength: 8,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      ...config.passwordOptions
    };

    this.bruteForceConfig = {
      maxAttempts: 5,
      windowMs: 15 * 60 * 1000, // 15 minutes
      blockDurationMs: 30 * 60 * 1000, // 30 minutes
      ...config.bruteForceProtection
    };

    this.sessionConfig = {
      maxSessions: 5,
      sessionTimeoutMs: 24 * 60 * 60 * 1000, // 24 hours
      extendOnActivity: true,
      ...config.sessionConfig
    };

    this.circuitBreakerConfig = {
      enabled: true,
      failureThreshold: 5,
      resetTimeoutMs: 60 * 1000, // 1 minute
      ...config.circuitBreaker
    };

    this.circuitBreakerState = {
      failures: 0,
      lastFailureTime: 0,
      state: 'CLOSED'
    };
  }

  // ============================================================================
  // USER CRUD OPERATIONS
  // ============================================================================

  async createUser(
    userData: CreateUserRequest,
    context: TenantContext,
    logContext: LogContext
  ): Promise<User> {
    try {
      // Validate input
      const validatedData = validateInput(
        UserSchema.omit({ 
          id: true, 
          createdAt: true, 
          updatedAt: true, 
          lastLogin: true 
        }).extend({ password: UserSchema.shape.email }),
        userData,
        logContext.requestId
      );

      // Check if user already exists
      const existingUser = await this.findUserByEmail(
        validatedData.email,
        context.tenantId,
        logContext
      );

      if (existingUser) {
        throw createError(
          ErrorCodes.DUPLICATE_RESOURCE,
          'User with this email already exists',
          409,
          { email: validatedData.email },
          logContext.requestId,
          context.tenantId
        );
      }

      // Check username uniqueness within tenant
      const existingUsername = await this.findUserByUsername(
        validatedData.username,
        context.tenantId,
        logContext
      );

      if (existingUsername) {
        throw createError(
          ErrorCodes.DUPLICATE_RESOURCE,
          'User with this username already exists',
          409,
          { username: validatedData.username },
          logContext.requestId,
          context.tenantId
        );
      }

      // Hash password
      const passwordHash = await hashPassword(userData.password, this.passwordOptions);

      // Create user
      const user = await this.prisma.user.create({
        data: {
          id: generateUUID(),
          tenantId: context.tenantId,
          username: validatedData.username,
          email: validatedData.email,
          passwordHash,
          roles: validatedData.roles || [],
          permissions: validatedData.permissions || {},
          active: validatedData.active ?? true,
          createdAt: new Date(),
          updatedAt: new Date()
        }
      });

      // Log audit event
      await this.createAuditLog({
        tenantId: context.tenantId,
        userId: logContext.userId,
        action: 'CREATE_USER',
        resourceType: 'user',
        resourceId: user.id,
        details: {
          username: user.username,
          email: user.email,
          roles: user.roles
        },
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'CREATE_USER',
        'user',
        logContext,
        'success',
        { userId: user.id, username: user.username }
      );

      return user;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'CREATE_USER' });
      throw error;
    }
  }

  async getUserById(
    userId: string,
    tenantId: string,
    logContext: LogContext,
    includeCredentials: boolean = false
  ): Promise<User | UserWithCredentials | null> {
    try {
      const user = await this.prisma.user.findFirst({
        where: { id: userId, tenantId },
        include: {
          credentials: includeCredentials
        }
      });

      if (!user) {
        return null;
      }

      validateTenantAccess(tenantId, user.tenantId, logContext.requestId);

      return user;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'GET_USER', userId });
      throw error;
    }
  }

  async updateUser(
    userId: string,
    updateData: UpdateUserRequest,
    context: TenantContext,
    logContext: LogContext
  ): Promise<User> {
    try {
      // Get existing user
      const existingUser = await this.getUserById(userId, context.tenantId, logContext);
      
      if (!existingUser) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          context.tenantId
        );
      }

      // Validate update data
      const validatedData = validateInput(
        UserSchema.partial().omit({ 
          id: true, 
          tenantId: true, 
          createdAt: true, 
          lastLogin: true 
        }),
        updateData,
        logContext.requestId
      );

      // Check for email/username conflicts if being updated
      if (validatedData.email && validatedData.email !== existingUser.email) {
        const emailConflict = await this.findUserByEmail(
          validatedData.email,
          context.tenantId,
          logContext
        );
        
        if (emailConflict && emailConflict.id !== userId) {
          throw createError(
            ErrorCodes.DUPLICATE_RESOURCE,
            'Email already in use by another user',
            409,
            { email: validatedData.email },
            logContext.requestId,
            context.tenantId
          );
        }
      }

      if (validatedData.username && validatedData.username !== existingUser.username) {
        const usernameConflict = await this.findUserByUsername(
          validatedData.username,
          context.tenantId,
          logContext
        );
        
        if (usernameConflict && usernameConflict.id !== userId) {
          throw createError(
            ErrorCodes.DUPLICATE_RESOURCE,
            'Username already in use by another user',
            409,
            { username: validatedData.username },
            logContext.requestId,
            context.tenantId
          );
        }
      }

      // Prepare update data
      const updatePayload: any = {
        ...validatedData,
        updatedAt: new Date()
      };

      // Hash new password if provided
      if (updateData.password) {
        updatePayload.passwordHash = await hashPassword(updateData.password, this.passwordOptions);
        delete updatePayload.password;
      }

      // Update user
      const updatedUser = await this.prisma.user.update({
        where: { id: userId, tenantId: context.tenantId },
        data: updatePayload
      });

      // Log audit event
      await this.createAuditLog({
        tenantId: context.tenantId,
        userId: logContext.userId,
        action: 'UPDATE_USER',
        resourceType: 'user',
        resourceId: userId,
        details: {
          changes: validatedData,
          passwordChanged: !!updateData.password
        },
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'UPDATE_USER',
        'user',
        logContext,
        'success',
        { userId, changes: Object.keys(validatedData) }
      );

      return updatedUser;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'UPDATE_USER', userId });
      throw error;
    }
  }

  async deleteUser(
    userId: string,
    tenantId: string,
    logContext: LogContext,
    softDelete: boolean = true
  ): Promise<void> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          tenantId
        );
      }

      if (softDelete) {
        // Soft delete - deactivate user
        await this.prisma.user.update({
          where: { id: userId, tenantId },
          data: { 
            active: false, 
            updatedAt: new Date() 
          }
        });
      } else {
        // Hard delete - remove user and related data
        await this.prisma.$transaction(async (tx) => {
          // Delete user credentials
          await tx.credential.deleteMany({
            where: { userId, tenantId }
          });

          // Delete mobile credentials
          await tx.mobileCredential.deleteMany({
            where: { userId, tenantId }
          });

          // Delete user
          await tx.user.delete({
            where: { id: userId, tenantId }
          });
        });
      }

      // Log audit event
      await this.createAuditLog({
        tenantId,
        userId: logContext.userId,
        action: softDelete ? 'DEACTIVATE_USER' : 'DELETE_USER',
        resourceType: 'user',
        resourceId: userId,
        details: {
          username: user.username,
          email: user.email,
          softDelete
        },
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        softDelete ? 'DEACTIVATE_USER' : 'DELETE_USER',
        'user',
        logContext,
        'success',
        { userId, username: user.username }
      );

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'DELETE_USER', userId });
      throw error;
    }
  }

  async listUsers(
    tenantId: string,
    options: UserListOptions,
    logContext: LogContext
  ): Promise<{ users: User[]; total: number; page: number; limit: number }> {
    try {
      const {
        page = 1,
        limit = 20,
        search,
        roles,
        active,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = options;

      const skip = (page - 1) * limit;

      // Build where clause
      const where: any = { tenantId };

      if (search) {
        where.OR = [
          { username: { contains: search, mode: 'insensitive' } },
          { email: { contains: search, mode: 'insensitive' } }
        ];
      }

      if (roles && roles.length > 0) {
        where.roles = { hasSome: roles };
      }

      if (active !== undefined) {
        where.active = active;
      }

      // Get total count
      const total = await this.prisma.user.count({ where });

      // Get users
      const users = await this.prisma.user.findMany({
        where,
        skip,
        take: limit,
        orderBy: { [sortBy]: sortOrder },
        select: {
          id: true,
          username: true,
          email: true,
          roles: true,
          active: true,
          createdAt: true,
          updatedAt: true,
          // Exclude sensitive fields
          tenantId: false,
          passwordHash: false,
          permissions: false
        }
      });

      return { users: users as User[], total, page, limit };

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'LIST_USERS' });
      throw error;
    }
  }

  // ============================================================================
  // AUTHENTICATION METHODS
  // ============================================================================

  async authenticateUser(
    username: string,
    password: string,
    tenantId: string,
    logContext: LogContext,
    deviceFingerprint?: string
  ): Promise<AuthenticationResult & { tokens?: TokenPair; sessionId?: string }> {
    const identifier = `${tenantId}:${username}`;
    
    try {
      // Check brute force protection
      const bruteForceCheck = await this.checkBruteForceProtection(identifier, logContext);
      if (!bruteForceCheck.allowed) {
        return {
          user: null as any,
          isValid: false,
          reason: `Account temporarily locked. Try again in ${Math.ceil(bruteForceCheck.retryAfter! / 60)} minutes.`
        };
      }

      // Execute with circuit breaker protection
      const result = await this.executeWithCircuitBreaker(async () => {
        // Find user by username or email
        const user = await this.prisma.user.findFirst({
          where: {
            tenantId,
            OR: [
              { username },
              { email: username }
            ]
          },
          include: {
            tenant: true
          }
        });

        if (!user) {
          await this.recordFailedAttempt(identifier, logContext);
          await this.createAuditLog({
            tenantId,
            action: 'LOGIN_FAILED',
            resourceType: 'user',
            resourceId: username,
            details: { reason: 'user_not_found' },
            ipAddress: logContext.ip || '',
            userAgent: logContext.userAgent || '',
            timestamp: getCurrentTimestamp()
          });

          // Add timing attack protection
          await this.addTimingDelay();

          return {
            user: null as any,
            isValid: false,
            reason: 'Invalid credentials'
          };
        }

        if (!user.active || !user.tenant?.isActive) {
          await this.recordFailedAttempt(identifier, logContext);
          await this.createAuditLog({
            tenantId,
            userId: user.id,
            action: 'LOGIN_FAILED',
            resourceType: 'user',
            resourceId: user.id,
            details: { reason: 'user_inactive' },
            ipAddress: logContext.ip || '',
            userAgent: logContext.userAgent || '',
            timestamp: getCurrentTimestamp()
          });

          return {
            user,
            isValid: false,
            reason: 'Account is inactive'
          };
        }

        // Verify password with timing attack protection
        const isPasswordValid = await this.verifyPasswordSecure(password, user.passwordHash);

        if (!isPasswordValid) {
          await this.recordFailedAttempt(identifier, logContext);
          await this.createAuditLog({
            tenantId,
            userId: user.id,
            action: 'LOGIN_FAILED',
            resourceType: 'user',
            resourceId: user.id,
            details: { reason: 'invalid_password' },
            ipAddress: logContext.ip || '',
            userAgent: logContext.userAgent || '',
            timestamp: getCurrentTimestamp()
          });

          return {
            user,
            isValid: false,
            reason: 'Invalid credentials'
          };
        }

        // Clear failed attempts on successful authentication
        await this.clearFailedAttempts(identifier);

        // Create session and generate tokens
        const sessionId = await this.createUserSession(user, logContext, deviceFingerprint);
        const tokens = await this.generateTokenPair(user, sessionId, deviceFingerprint);

        // Update last login
        await this.prisma.user.update({
          where: { id: user.id },
          data: { updatedAt: new Date() }
        });

        // Log successful authentication
        await this.createAuditLog({
          tenantId,
          userId: user.id,
          action: 'LOGIN_SUCCESS',
          resourceType: 'user',
          resourceId: user.id,
          details: { sessionId, deviceFingerprint },
          ipAddress: logContext.ip || '',
          userAgent: logContext.userAgent || '',
          timestamp: getCurrentTimestamp()
        });

        logAudit(
          this.logger,
          'LOGIN_SUCCESS',
          'user',
          logContext,
          'success',
          { userId: user.id, username: user.username, sessionId }
        );

        return {
          user,
          isValid: true,
          tokens,
          sessionId
        };
      });

      return result;

    } catch (error) {
      await this.recordCircuitBreakerFailure();
      logError(this.logger, error as Error, logContext, { action: 'AUTHENTICATE_USER' });
      throw error;
    }
  }

  async validateUserSession(
    sessionId: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<{ user: User; session: SessionInfo } | null> {
    try {
      return await this.executeWithCircuitBreaker(async () => {
        // Get session from Redis
        const sessionKey = `session:${sessionId}`;
        const sessionData = await this.redis.get(sessionKey);

        if (!sessionData) {
          return null;
        }

        const session: SessionInfo = JSON.parse(sessionData);

        // Validate session
        if (session.tenantId !== tenantId || !session.isActive || new Date() > session.expiresAt) {
          await this.redis.del(sessionKey);
          return null;
        }

        // Get user
        const user = await this.prisma.user.findFirst({
          where: {
            id: session.userId,
            tenantId,
            active: true
          }
        });

        if (!user) {
          await this.redis.del(sessionKey);
          return null;
        }

        // Extend session if configured
        if (this.sessionConfig.extendOnActivity) {
          await this.extendSession(sessionId, logContext);
        }

        return { user, session };
      });

    } catch (error) {
      await this.recordCircuitBreakerFailure();
      logError(this.logger, error as Error, logContext, { action: 'VALIDATE_SESSION', sessionId });
      throw error;
    }
  }

  async validateAccessToken(
    token: string,
    logContext: LogContext
  ): Promise<JWTPayload | null> {
    try {
      const decoded = jwt.verify(token, this.jwtConfig.accessTokenSecret) as JWTPayload;
      
      // Check if token is blacklisted
      const blacklistKey = `blacklist:${token}`;
      const isBlacklisted = await this.redis.exists(blacklistKey);
      
      if (isBlacklisted) {
        return null;
      }

      // Validate session exists
      const sessionValidation = await this.validateUserSession(decoded.sessionId, decoded.tenantId, logContext);
      
      if (!sessionValidation) {
        return null;
      }

      return decoded;

    } catch (error) {
      if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
        return null;
      }
      logError(this.logger, error as Error, logContext, { action: 'VALIDATE_ACCESS_TOKEN' });
      throw error;
    }
  }

  async refreshTokens(
    refreshToken: string,
    logContext: LogContext,
    deviceFingerprint?: string
  ): Promise<TokenPair | null> {
    try {
      return await this.executeWithCircuitBreaker(async () => {
        // Verify refresh token
        const decoded = jwt.verify(refreshToken, this.jwtConfig.refreshTokenSecret) as RefreshTokenData;
        
        // Check if refresh token exists in Redis
        const refreshKey = `refresh:${decoded.sessionId}`;
        const storedToken = await this.redis.get(refreshKey);
        
        if (!storedToken || storedToken !== refreshToken) {
          return null;
        }

        // Validate device fingerprint if provided
        if (deviceFingerprint && decoded.deviceFingerprint !== deviceFingerprint) {
          // Potential token theft - invalidate session
          await this.invalidateSession(decoded.sessionId, logContext);
          await this.createAuditLog({
            tenantId: decoded.tenantId,
            userId: decoded.userId,
            action: 'SUSPICIOUS_TOKEN_REFRESH',
            resourceType: 'session',
            resourceId: decoded.sessionId,
            details: { 
              expectedFingerprint: decoded.deviceFingerprint,
              actualFingerprint: deviceFingerprint
            },
            ipAddress: logContext.ip || '',
            userAgent: logContext.userAgent || '',
            timestamp: getCurrentTimestamp()
          });
          return null;
        }

        // Get user
        const user = await this.prisma.user.findFirst({
          where: {
            id: decoded.userId,
            tenantId: decoded.tenantId,
            active: true
          }
        });

        if (!user) {
          await this.invalidateSession(decoded.sessionId, logContext);
          return null;
        }

        // Generate new token pair
        const newTokens = await this.generateTokenPair(user, decoded.sessionId, deviceFingerprint);

        // Log token refresh
        await this.createAuditLog({
          tenantId: decoded.tenantId,
          userId: decoded.userId,
          action: 'TOKEN_REFRESH',
          resourceType: 'session',
          resourceId: decoded.sessionId,
          details: {},
          ipAddress: logContext.ip || '',
          userAgent: logContext.userAgent || '',
          timestamp: getCurrentTimestamp()
        });

        return newTokens;
      });

    } catch (error) {
      if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
        return null;
      }
      await this.recordCircuitBreakerFailure();
      logError(this.logger, error as Error, logContext, { action: 'REFRESH_TOKENS' });
      throw error;
    }
  }

  // ============================================================================
  // PASSWORD MANAGEMENT
  // ============================================================================

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<void> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          tenantId
        );
      }

      // Verify current password
      const isCurrentPasswordValid = await verifyPassword(currentPassword, user.passwordHash);
      
      if (!isCurrentPasswordValid) {
        throw createError(
          ErrorCodes.INVALID_CREDENTIALS,
          'Current password is incorrect',
          401,
          {},
          logContext.requestId,
          tenantId
        );
      }

      // Hash new password
      const newPasswordHash = await hashPassword(newPassword, this.passwordOptions);

      // Update password
      await this.prisma.user.update({
        where: { id: userId, tenantId },
        data: { 
          passwordHash: newPasswordHash,
          updatedAt: new Date()
        }
      });

      // Log audit event
      await this.createAuditLog({
        tenantId,
        userId: logContext.userId,
        action: 'CHANGE_PASSWORD',
        resourceType: 'user',
        resourceId: userId,
        details: {},
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'CHANGE_PASSWORD',
        'user',
        logContext,
        'success',
        { userId }
      );

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'CHANGE_PASSWORD', userId });
      throw error;
    }
  }

  async resetPassword(
    userId: string,
    newPassword: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<void> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          tenantId
        );
      }

      // Hash new password
      const newPasswordHash = await hashPassword(newPassword, this.passwordOptions);

      // Update password
      await this.prisma.user.update({
        where: { id: userId, tenantId },
        data: { 
          passwordHash: newPasswordHash,
          updatedAt: new Date()
        }
      });

      // Log audit event
      await this.createAuditLog({
        tenantId,
        userId: logContext.userId,
        action: 'RESET_PASSWORD',
        resourceType: 'user',
        resourceId: userId,
        details: { resetBy: logContext.userId },
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'RESET_PASSWORD',
        'user',
        logContext,
        'success',
        { userId, resetBy: logContext.userId }
      );

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'RESET_PASSWORD', userId });
      throw error;
    }
  }

  // ============================================================================
  // ROLE AND PERMISSION MANAGEMENT
  // ============================================================================

  async assignRoles(
    userId: string,
    roles: string[],
    tenantId: string,
    logContext: LogContext
  ): Promise<User> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          tenantId
        );
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId, tenantId },
        data: { 
          roles,
          updatedAt: new Date()
        }
      });

      // Log audit event
      await this.createAuditLog({
        tenantId,
        userId: logContext.userId,
        action: 'ASSIGN_ROLES',
        resourceType: 'user',
        resourceId: userId,
        details: { 
          previousRoles: user.roles,
          newRoles: roles
        },
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'ASSIGN_ROLES',
        'user',
        logContext,
        'success',
        { userId, roles }
      );

      return updatedUser;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'ASSIGN_ROLES', userId });
      throw error;
    }
  }

  async updatePermissions(
    userId: string,
    permissions: Record<string, any>,
    tenantId: string,
    logContext: LogContext
  ): Promise<User> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          tenantId
        );
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId, tenantId },
        data: { 
          permissions,
          updatedAt: new Date()
        }
      });

      // Log audit event
      await this.createAuditLog({
        tenantId,
        userId: logContext.userId,
        action: 'UPDATE_PERMISSIONS',
        resourceType: 'user',
        resourceId: userId,
        details: { 
          previousPermissions: user.permissions,
          newPermissions: permissions
        },
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'UPDATE_PERMISSIONS',
        'user',
        logContext,
        'success',
        { userId }
      );

      return updatedUser;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'UPDATE_PERMISSIONS', userId });
      throw error;
    }
  }

  async checkPermission(
    userId: string,
    permission: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<boolean> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user || !user.active) {
        return false;
      }

      // Check if user has the specific permission
      if (user.permissions && user.permissions[permission]) {
        return true;
      }

      // Check role-based permissions (simplified - in real implementation, 
      // you'd have a role-permission mapping)
      const adminRoles = ['super_admin', 'tenant_admin', 'site_admin'];
      if (adminRoles.some(role => user.roles.includes(role))) {
        return true;
      }

      return false;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'CHECK_PERMISSION', userId });
      return false;
    }
  }

  // ============================================================================
  // ACCOUNT LIFECYCLE OPERATIONS
  // ============================================================================

  async activateUser(
    userId: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<User> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          tenantId
        );
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId, tenantId },
        data: { 
          active: true,
          updatedAt: new Date()
        }
      });

      // Log audit event
      await this.createAuditLog({
        tenantId,
        userId: logContext.userId,
        action: 'ACTIVATE_USER',
        resourceType: 'user',
        resourceId: userId,
        details: {},
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'ACTIVATE_USER',
        'user',
        logContext,
        'success',
        { userId }
      );

      return updatedUser;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'ACTIVATE_USER', userId });
      throw error;
    }
  }

  async deactivateUser(
    userId: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<User> {
    try {
      const user = await this.getUserById(userId, tenantId, logContext);
      
      if (!user) {
        throw createError(
          ErrorCodes.RESOURCE_NOT_FOUND,
          'User not found',
          404,
          { userId },
          logContext.requestId,
          tenantId
        );
      }

      const updatedUser = await this.prisma.user.update({
        where: { id: userId, tenantId },
        data: { 
          active: false,
          updatedAt: new Date()
        }
      });

      // Log audit event
      await this.createAuditLog({
        tenantId,
        userId: logContext.userId,
        action: 'DEACTIVATE_USER',
        resourceType: 'user',
        resourceId: userId,
        details: {},
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });

      logAudit(
        this.logger,
        'DEACTIVATE_USER',
        'user',
        logContext,
        'success',
        { userId }
      );

      return updatedUser;

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'DEACTIVATE_USER', userId });
      throw error;
    }
  }

  // ============================================================================
  // UTILITY METHODS
  // ============================================================================

  private async findUserByEmail(
    email: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<User | null> {
    return this.prisma.user.findFirst({
      where: { email, tenantId }
    });
  }

  private async findUserByUsername(
    username: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<User | null> {
    return this.prisma.user.findFirst({
      where: { username, tenantId }
    });
  }

  // ============================================================================
  // SESSION MANAGEMENT
  // ============================================================================

  async createUserSession(
    user: User,
    logContext: LogContext,
    deviceFingerprint?: string
  ): Promise<string> {
    const sessionId = generateUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.sessionConfig.sessionTimeoutMs);

    const session: SessionInfo = {
      userId: user.id,
      tenantId: user.tenantId,
      sessionId,
      expiresAt,
      lastActivity: now,
      ipAddress: logContext.ip,
      userAgent: logContext.userAgent,
      deviceFingerprint,
      isActive: true
    };

    // Store session in Redis
    const sessionKey = `session:${sessionId}`;
    await this.redis.setex(
      sessionKey,
      Math.floor(this.sessionConfig.sessionTimeoutMs / 1000),
      JSON.stringify(session)
    );

    // Manage session limits
    await this.enforceSessionLimits(user.id, user.tenantId, sessionId);

    return sessionId;
  }

  async extendSession(sessionId: string, logContext: LogContext): Promise<void> {
    const sessionKey = `session:${sessionId}`;
    const sessionData = await this.redis.get(sessionKey);

    if (sessionData) {
      const session: SessionInfo = JSON.parse(sessionData);
      session.lastActivity = new Date();
      session.expiresAt = new Date(Date.now() + this.sessionConfig.sessionTimeoutMs);

      await this.redis.setex(
        sessionKey,
        Math.floor(this.sessionConfig.sessionTimeoutMs / 1000),
        JSON.stringify(session)
      );
    }
  }

  async invalidateSession(sessionId: string, logContext: LogContext): Promise<void> {
    const sessionKey = `session:${sessionId}`;
    const refreshKey = `refresh:${sessionId}`;

    // Get session data for audit log
    const sessionData = await this.redis.get(sessionKey);
    
    // Remove session and refresh token
    await Promise.all([
      this.redis.del(sessionKey),
      this.redis.del(refreshKey)
    ]);

    if (sessionData) {
      const session: SessionInfo = JSON.parse(sessionData);
      await this.createAuditLog({
        tenantId: session.tenantId,
        userId: session.userId,
        action: 'SESSION_INVALIDATED',
        resourceType: 'session',
        resourceId: sessionId,
        details: { reason: 'manual_logout' },
        ipAddress: logContext.ip || '',
        userAgent: logContext.userAgent || '',
        timestamp: getCurrentTimestamp()
      });
    }
  }

  async invalidateAllUserSessions(
    userId: string,
    tenantId: string,
    logContext: LogContext,
    excludeSessionId?: string
  ): Promise<void> {
    // Get all user sessions
    const pattern = `session:*`;
    const sessionKeys = await this.redis.keys(pattern);

    const userSessions: string[] = [];
    
    for (const key of sessionKeys) {
      const sessionData = await this.redis.get(key);
      if (sessionData) {
        const session: SessionInfo = JSON.parse(sessionData);
        if (session.userId === userId && session.tenantId === tenantId) {
          if (!excludeSessionId || session.sessionId !== excludeSessionId) {
            userSessions.push(session.sessionId);
          }
        }
      }
    }

    // Invalidate sessions
    for (const sessionId of userSessions) {
      await this.invalidateSession(sessionId, logContext);
    }

    await this.createAuditLog({
      tenantId,
      userId: logContext.userId,
      action: 'ALL_SESSIONS_INVALIDATED',
      resourceType: 'user',
      resourceId: userId,
      details: { 
        invalidatedSessions: userSessions.length,
        excludedSession: excludeSessionId
      },
      ipAddress: logContext.ip || '',
      userAgent: logContext.userAgent || '',
      timestamp: getCurrentTimestamp()
    });
  }

  private async enforceSessionLimits(
    userId: string,
    tenantId: string,
    newSessionId: string
  ): Promise<void> {
    const pattern = `session:*`;
    const sessionKeys = await this.redis.keys(pattern);

    const userSessions: { sessionId: string; lastActivity: Date }[] = [];
    
    for (const key of sessionKeys) {
      const sessionData = await this.redis.get(key);
      if (sessionData) {
        const session: SessionInfo = JSON.parse(sessionData);
        if (session.userId === userId && session.tenantId === tenantId && session.sessionId !== newSessionId) {
          userSessions.push({
            sessionId: session.sessionId,
            lastActivity: new Date(session.lastActivity)
          });
        }
      }
    }

    // Remove oldest sessions if limit exceeded
    if (userSessions.length >= this.sessionConfig.maxSessions) {
      userSessions.sort((a, b) => a.lastActivity.getTime() - b.lastActivity.getTime());
      const sessionsToRemove = userSessions.slice(0, userSessions.length - this.sessionConfig.maxSessions + 1);
      
      for (const session of sessionsToRemove) {
        await this.redis.del(`session:${session.sessionId}`);
        await this.redis.del(`refresh:${session.sessionId}`);
      }
    }
  }

  // ============================================================================
  // TOKEN MANAGEMENT
  // ============================================================================

  async generateTokenPair(
    user: User,
    sessionId: string,
    deviceFingerprint?: string
  ): Promise<TokenPair> {
    const now = Math.floor(Date.now() / 1000);
    const accessTokenExpiry = now + this.parseExpiry(this.jwtConfig.accessTokenExpiry);
    const refreshTokenExpiry = now + this.parseExpiry(this.jwtConfig.refreshTokenExpiry);

    // Access token payload
    const accessPayload: JWTPayload = {
      sub: user.id,
      tenantId: user.tenantId,
      sessionId,
      roles: user.roles as string[],
      permissions: user.permissions as Record<string, any>,
      type: 'access',
      iat: now,
      exp: accessTokenExpiry,
      iss: this.jwtConfig.issuer
    };

    // Refresh token payload
    const refreshPayload: RefreshTokenData = {
      userId: user.id,
      tenantId: user.tenantId,
      sessionId,
      deviceFingerprint,
      issuedAt: now,
      expiresAt: refreshTokenExpiry
    };

    // Generate tokens
    const accessToken = jwt.sign(accessPayload, this.jwtConfig.accessTokenSecret);
    const refreshToken = jwt.sign(refreshPayload, this.jwtConfig.refreshTokenSecret);

    // Store refresh token in Redis
    const refreshKey = `refresh:${sessionId}`;
    await this.redis.setex(
      refreshKey,
      this.parseExpiry(this.jwtConfig.refreshTokenExpiry),
      refreshToken
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: this.parseExpiry(this.jwtConfig.accessTokenExpiry),
      tokenType: 'Bearer'
    };
  }

  async blacklistToken(token: string, logContext: LogContext): Promise<void> {
    try {
      const decoded = jwt.decode(token) as any;
      if (decoded && decoded.exp) {
        const ttl = decoded.exp - Math.floor(Date.now() / 1000);
        if (ttl > 0) {
          const blacklistKey = `blacklist:${token}`;
          await this.redis.setex(blacklistKey, ttl, '1');
        }
      }
    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'BLACKLIST_TOKEN' });
    }
  }

  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) return 3600; // Default 1 hour

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: return 3600;
    }
  }

  // ============================================================================
  // BRUTE FORCE PROTECTION
  // ============================================================================

  async checkBruteForceProtection(
    identifier: string,
    logContext: LogContext
  ): Promise<{ allowed: boolean; retryAfter?: number }> {
    const key = `brute_force:${identifier}`;
    const data = await this.redis.get(key);

    if (!data) {
      return { allowed: true };
    }

    const attempt: BruteForceAttempt = JSON.parse(data);
    const now = Date.now();

    // Check if still blocked
    if (attempt.blockedUntil && now < attempt.blockedUntil) {
      return {
        allowed: false,
        retryAfter: Math.ceil((attempt.blockedUntil - now) / 1000)
      };
    }

    // Check if window has expired
    if (now - attempt.lastAttempt > this.bruteForceConfig.windowMs) {
      await this.redis.del(key);
      return { allowed: true };
    }

    // Check attempt count
    if (attempt.attempts >= this.bruteForceConfig.maxAttempts) {
      const blockedUntil = now + this.bruteForceConfig.blockDurationMs;
      attempt.blockedUntil = blockedUntil;
      
      await this.redis.setex(
        key,
        Math.ceil(this.bruteForceConfig.blockDurationMs / 1000),
        JSON.stringify(attempt)
      );

      return {
        allowed: false,
        retryAfter: Math.ceil(this.bruteForceConfig.blockDurationMs / 1000)
      };
    }

    return { allowed: true };
  }

  async recordFailedAttempt(identifier: string, logContext: LogContext): Promise<void> {
    const key = `brute_force:${identifier}`;
    const data = await this.redis.get(key);
    const now = Date.now();

    let attempt: BruteForceAttempt;

    if (data) {
      attempt = JSON.parse(data);
      // Reset if window expired
      if (now - attempt.lastAttempt > this.bruteForceConfig.windowMs) {
        attempt = { attempts: 1, lastAttempt: now };
      } else {
        attempt.attempts++;
        attempt.lastAttempt = now;
      }
    } else {
      attempt = { attempts: 1, lastAttempt: now };
    }

    await this.redis.setex(
      key,
      Math.ceil(this.bruteForceConfig.windowMs / 1000),
      JSON.stringify(attempt)
    );
  }

  async clearFailedAttempts(identifier: string): Promise<void> {
    const key = `brute_force:${identifier}`;
    await this.redis.del(key);
  }

  // ============================================================================
  // CIRCUIT BREAKER PATTERN
  // ============================================================================

  async executeWithCircuitBreaker<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.circuitBreakerConfig.enabled) {
      return operation();
    }

    const now = Date.now();

    // Check circuit breaker state
    if (this.circuitBreakerState.state === 'OPEN') {
      if (now - this.circuitBreakerState.lastFailureTime > this.circuitBreakerConfig.resetTimeoutMs) {
        this.circuitBreakerState.state = 'HALF_OPEN';
      } else {
        throw createError(
          ErrorCodes.SERVICE_UNAVAILABLE,
          'Service temporarily unavailable',
          503,
          { circuitBreakerState: this.circuitBreakerState.state }
        );
      }
    }

    try {
      const result = await operation();
      
      // Reset on success
      if (this.circuitBreakerState.state === 'HALF_OPEN') {
        this.circuitBreakerState.state = 'CLOSED';
        this.circuitBreakerState.failures = 0;
      }

      return result;
    } catch (error) {
      await this.recordCircuitBreakerFailure();
      throw error;
    }
  }

  async recordCircuitBreakerFailure(): Promise<void> {
    if (!this.circuitBreakerConfig.enabled) return;

    this.circuitBreakerState.failures++;
    this.circuitBreakerState.lastFailureTime = Date.now();

    if (this.circuitBreakerState.failures >= this.circuitBreakerConfig.failureThreshold) {
      this.circuitBreakerState.state = 'OPEN';
      this.logger.warn('Circuit breaker opened', {
        failures: this.circuitBreakerState.failures,
        threshold: this.circuitBreakerConfig.failureThreshold
      });
    }
  }

  // ============================================================================
  // SECURITY UTILITIES
  // ============================================================================

  private async verifyPasswordSecure(password: string, hash: string): Promise<boolean> {
    // Add consistent timing to prevent timing attacks
    const startTime = Date.now();
    
    try {
      const result = await bcrypt.compare(password, hash);
      await this.addTimingDelay(startTime);
      return result;
    } catch (error) {
      await this.addTimingDelay(startTime);
      return false;
    }
  }

  private async addTimingDelay(startTime?: number): Promise<void> {
    const elapsed = startTime ? Date.now() - startTime : 0;
    const minDelay = 100; // Minimum 100ms delay
    const delay = Math.max(minDelay - elapsed, 0);
    
    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  private async createAuditLog(data: CreateAuditLogDTO): Promise<void> {
    try {
      await this.executeWithCircuitBreaker(async () => {
        await this.prisma.auditLog.create({
          data: {
            id: generateUUID(),
            ...data
          }
        });
      });
    } catch (error) {
      // Log audit creation failure but don't throw to avoid breaking main operations
      this.logger.error('Failed to create audit log', { error, data });
    }
  }

  async getUserStats(
    tenantId: string,
    logContext: LogContext
  ): Promise<UserStats> {
    try {
      return await this.executeWithCircuitBreaker(async () => {
        const [
          totalUsers,
          activeUsers,
          inactiveUsers,
          usersByRole
        ] = await Promise.all([
          this.prisma.user.count({ where: { tenantId } }),
          this.prisma.user.count({ where: { tenantId, active: true } }),
          this.prisma.user.count({ where: { tenantId, active: false } }),
          this.prisma.user.groupBy({
            by: ['roles'],
            where: { tenantId },
            _count: true
          })
        ]);

        // Process role statistics
        const roleStats: Record<string, number> = {};
        usersByRole.forEach(group => {
          const roles = group.roles as string[];
          roles.forEach(role => {
            roleStats[role] = (roleStats[role] || 0) + group._count;
          });
        });

        // Get recent logins (last 24 hours)
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        
        const recentLogins = await this.prisma.auditLog.count({
          where: {
            tenantId,
            action: 'LOGIN_SUCCESS',
            timestamp: { gte: yesterday }
          }
        });

        return {
          totalUsers,
          activeUsers,
          inactiveUsers,
          usersByRole: roleStats,
          recentLogins
        };
      });

    } catch (error) {
      await this.recordCircuitBreakerFailure();
      logError(this.logger, error as Error, logContext, { action: 'GET_USER_STATS' });
      throw error;
    }
  }

  // ============================================================================
  // LOGOUT AND CLEANUP
  // ============================================================================

  async logoutUser(
    sessionId: string,
    accessToken: string,
    logContext: LogContext
  ): Promise<void> {
    try {
      // Invalidate session
      await this.invalidateSession(sessionId, logContext);
      
      // Blacklist access token
      await this.blacklistToken(accessToken, logContext);

      logAudit(
        this.logger,
        'LOGOUT',
        'session',
        logContext,
        'success',
        { sessionId }
      );

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'LOGOUT_USER', sessionId });
      throw error;
    }
  }

  async logoutAllDevices(
    userId: string,
    tenantId: string,
    logContext: LogContext
  ): Promise<void> {
    try {
      await this.invalidateAllUserSessions(userId, tenantId, logContext);

      logAudit(
        this.logger,
        'LOGOUT_ALL_DEVICES',
        'user',
        logContext,
        'success',
        { userId }
      );

    } catch (error) {
      logError(this.logger, error as Error, logContext, { action: 'LOGOUT_ALL_DEVICES', userId });
      throw error;
    }
  }

  // ============================================================================
  // MONITORING AND HEALTH
  // ============================================================================

  async getServiceHealth(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    checks: Record<string, 'healthy' | 'unhealthy'>;
    circuitBreaker: CircuitBreakerState;
  }> {
    const checks: Record<string, 'healthy' | 'unhealthy'> = {};

    // Check database
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      checks.database = 'healthy';
    } catch {
      checks.database = 'unhealthy';
    }

    // Check Redis
    try {
      await this.redis.ping();
      checks.redis = 'healthy';
    } catch {
      checks.redis = 'unhealthy';
    }

    const unhealthyCount = Object.values(checks).filter(status => status === 'unhealthy').length;
    let status: 'healthy' | 'degraded' | 'unhealthy';

    if (unhealthyCount === 0) {
      status = 'healthy';
    } else if (unhealthyCount === Object.keys(checks).length) {
      status = 'unhealthy';
    } else {
      status = 'degraded';
    }

    return {
      status,
      checks,
      circuitBreaker: this.circuitBreakerState
    };
  }

  async cleanupExpiredSessions(): Promise<{ cleaned: number }> {
    try {
      const pattern = `session:*`;
      const sessionKeys = await this.redis.keys(pattern);
      let cleaned = 0;

      for (const key of sessionKeys) {
        const sessionData = await this.redis.get(key);
        if (sessionData) {
          const session: SessionInfo = JSON.parse(sessionData);
          if (new Date() > session.expiresAt) {
            await this.redis.del(key);
            await this.redis.del(`refresh:${session.sessionId}`);
            cleaned++;
          }
        }
      }

      this.logger.info('Cleaned up expired sessions', { cleaned });
      return { cleaned };

    } catch (error) {
      this.logger.error('Failed to cleanup expired sessions', { error });
      return { cleaned: 0 };
    }
  }
}

// ============================================================================
// FACTORY FUNCTION
// ============================================================================

export function createUserService(config: UserServiceConfig): UserService {
  return new UserService(config);
}

// ============================================================================
// EXPORTS
// ============================================================================

export default UserService;
