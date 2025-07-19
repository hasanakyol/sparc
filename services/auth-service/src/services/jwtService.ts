import { sign, verify, decode } from 'hono/jwt';
import { getSecretsManager, SecretValue } from './secretsManager';
import { logger } from '@sparc/shared/logging';
import { AccessTokenPayload, RefreshTokenPayload } from '@sparc/shared/types';
import crypto from 'crypto';

export interface JWTConfig {
  accessTokenExpiry: string;
  refreshTokenExpiry: string;
  issuer: string;
  audience: string;
  algorithm: 'HS256';
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}

export class JWTService {
  private static instance: JWTService;
  private secretsManager = getSecretsManager();
  private config: JWTConfig;
  
  // Cache for secrets during rotation grace period
  private currentAccessSecret?: string;
  private previousAccessSecret?: string;
  private currentRefreshSecret?: string;
  private previousRefreshSecret?: string;
  private rotationGracePeriod = 3600000; // 1 hour
  private rotationTimestamp?: Date;
  
  private constructor(config: JWTConfig) {
    this.config = config;
    this.initializeSecrets();
  }
  
  static getInstance(config: JWTConfig): JWTService {
    if (!JWTService.instance) {
      JWTService.instance = new JWTService(config);
    }
    return JWTService.instance;
  }
  
  private async initializeSecrets(): Promise<void> {
    try {
      // Load initial secrets
      this.currentAccessSecret = await this.secretsManager.getSecret('JWT_ACCESS_SECRET');
      this.currentRefreshSecret = await this.secretsManager.getSecret('JWT_REFRESH_SECRET');
      
      logger.info('JWT secrets initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize JWT secrets:', error);
      // Fall back to environment variables
      this.currentAccessSecret = process.env.JWT_ACCESS_SECRET || process.env.JWT_SECRET;
      this.currentRefreshSecret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
      
      if (!this.currentAccessSecret || !this.currentRefreshSecret) {
        throw new Error('JWT secrets not configured');
      }
    }
  }
  
  async generateTokens(
    userId: string,
    organizationId: string,
    email: string,
    role: string,
    permissions: string[],
    sessionId?: string
  ): Promise<TokenPair> {
    // Ensure secrets are loaded
    if (!this.currentAccessSecret || !this.currentRefreshSecret) {
      await this.initializeSecrets();
    }
    
    const now = Math.floor(Date.now() / 1000);
    sessionId = sessionId || crypto.randomUUID();
    
    const accessTokenPayload: AccessTokenPayload = {
      sub: userId,
      email,
      username: email, // Using email as username for backward compatibility
      organizationId,
      tenantId: organizationId, // Include both for backward compatibility
      role,
      permissions,
      type: 'access',
      iat: now,
      exp: now + (15 * 60), // 15 minutes
      iss: this.config.issuer,
      aud: this.config.audience,
      jti: crypto.randomUUID(),
      sessionId,
    };
    
    const refreshTokenPayload: RefreshTokenPayload = {
      sub: userId,
      tenantId: organizationId, // Use organizationId as tenantId for backward compatibility
      type: 'refresh',
      iat: now,
      exp: now + (7 * 24 * 60 * 60), // 7 days
      jti: crypto.randomUUID(),
      sessionId,
    };
    
    const accessToken = await sign(accessTokenPayload, this.currentAccessSecret!, this.config.algorithm);
    const refreshToken = await sign(refreshTokenPayload, this.currentRefreshSecret!, this.config.algorithm);
    
    return { accessToken, refreshToken, sessionId };
  }
  
  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    // Try with current secret first
    try {
      const payload = await verify(token, this.currentAccessSecret!) as AccessTokenPayload;
      
      if (payload.type !== 'access') {
        throw new Error('Invalid token type');
      }
      
      return payload;
    } catch (error) {
      // If we're in rotation grace period, try with previous secret
      if (this.isInRotationGracePeriod() && this.previousAccessSecret) {
        try {
          const payload = await verify(token, this.previousAccessSecret) as AccessTokenPayload;
          
          if (payload.type !== 'access') {
            throw new Error('Invalid token type');
          }
          
          logger.info('Token verified with previous secret during rotation grace period');
          return payload;
        } catch {
          // If both verifications fail, throw the original error
          throw error;
        }
      }
      
      throw error;
    }
  }
  
  async verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    // Try with current secret first
    try {
      const payload = await verify(token, this.currentRefreshSecret!) as RefreshTokenPayload;
      
      if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
      }
      
      return payload;
    } catch (error) {
      // If we're in rotation grace period, try with previous secret
      if (this.isInRotationGracePeriod() && this.previousRefreshSecret) {
        try {
          const payload = await verify(token, this.previousRefreshSecret) as RefreshTokenPayload;
          
          if (payload.type !== 'refresh') {
            throw new Error('Invalid token type');
          }
          
          logger.info('Refresh token verified with previous secret during rotation grace period');
          return payload;
        } catch {
          // If both verifications fail, throw the original error
          throw error;
        }
      }
      
      throw error;
    }
  }
  
  /**
   * Rotate JWT secrets with grace period for backward compatibility
   */
  async rotateSecrets(): Promise<void> {
    try {
      logger.info('Starting JWT secret rotation');
      
      // Store current secrets as previous
      this.previousAccessSecret = this.currentAccessSecret;
      this.previousRefreshSecret = this.currentRefreshSecret;
      
      // Generate new secrets
      const newAccessSecret = this.generateSecret();
      const newRefreshSecret = this.generateSecret();
      
      // Update secrets in AWS Secrets Manager
      await Promise.all([
        this.secretsManager.rotateSecret('JWT_ACCESS_SECRET', newAccessSecret),
        this.secretsManager.rotateSecret('JWT_REFRESH_SECRET', newRefreshSecret)
      ]);
      
      // Update current secrets
      this.currentAccessSecret = newAccessSecret;
      this.currentRefreshSecret = newRefreshSecret;
      
      // Set rotation timestamp
      this.rotationTimestamp = new Date();
      
      // Schedule cleanup of previous secrets after grace period
      setTimeout(() => {
        this.previousAccessSecret = undefined;
        this.previousRefreshSecret = undefined;
        this.rotationTimestamp = undefined;
        logger.info('JWT secret rotation grace period ended');
      }, this.rotationGracePeriod);
      
      logger.info('JWT secrets rotated successfully');
    } catch (error) {
      logger.error('Failed to rotate JWT secrets:', error);
      throw new Error('Failed to rotate JWT secrets');
    }
  }
  
  /**
   * Get rotation status
   */
  getRotationStatus(): {
    inRotation: boolean;
    rotationTimestamp?: Date;
    gracePeriodEnds?: Date;
  } {
    const inRotation = this.isInRotationGracePeriod();
    
    return {
      inRotation,
      rotationTimestamp: this.rotationTimestamp,
      gracePeriodEnds: this.rotationTimestamp 
        ? new Date(this.rotationTimestamp.getTime() + this.rotationGracePeriod)
        : undefined
    };
  }
  
  /**
   * Force reload secrets from AWS Secrets Manager
   */
  async reloadSecrets(): Promise<void> {
    this.secretsManager.clearCache('JWT_ACCESS_SECRET');
    this.secretsManager.clearCache('JWT_REFRESH_SECRET');
    await this.initializeSecrets();
  }
  
  private isInRotationGracePeriod(): boolean {
    if (!this.rotationTimestamp) {
      return false;
    }
    
    const elapsed = Date.now() - this.rotationTimestamp.getTime();
    return elapsed < this.rotationGracePeriod;
  }
  
  private generateSecret(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}