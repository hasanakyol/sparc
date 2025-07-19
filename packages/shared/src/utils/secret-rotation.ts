/**
 * Secret Rotation Utilities
 * 
 * This module provides utilities for rotating secrets in production
 * with zero downtime.
 */

import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { Redis } from 'ioredis';
import { PrismaClient } from '@prisma/client';
import { logger } from '../logger';

export interface SecretRotationOptions {
  redis: Redis;
  prisma: PrismaClient;
  logger?: any;
}

export interface RotationResult {
  success: boolean;
  rotatedAt: Date;
  errors?: string[];
  warnings?: string[];
}

/**
 * JWT Secret Rotation
 * 
 * Supports multiple valid secrets during rotation period
 */
export class JWTSecretRotation {
  private redis: Redis;
  private logger: any;
  private readonly SECRET_KEY = 'jwt:secrets';
  private readonly ROTATION_OVERLAP_HOURS = 24; // Keep old secret valid for 24 hours

  constructor(options: SecretRotationOptions) {
    this.redis = options.redis;
    this.logger = options.logger || console;
  }

  /**
   * Rotate JWT secret
   */
  async rotateSecret(newSecret: string): Promise<RotationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Validate new secret
      if (!newSecret || newSecret.length < 32) {
        errors.push('New JWT secret must be at least 32 characters');
        return { success: false, rotatedAt: new Date(), errors };
      }

      // Get current secrets
      const currentSecrets = await this.getCurrentSecrets();
      
      // Check if new secret is already in use
      if (currentSecrets.some(s => s.secret === newSecret)) {
        errors.push('New secret is already in rotation');
        return { success: false, rotatedAt: new Date(), errors };
      }

      // Add new secret with expiration
      const expirationTime = Date.now() + (this.ROTATION_OVERLAP_HOURS * 60 * 60 * 1000);
      const newSecretEntry = {
        secret: newSecret,
        createdAt: Date.now(),
        expiresAt: expirationTime,
        primary: true
      };

      // Mark existing secrets as non-primary
      const updatedSecrets = currentSecrets.map(s => ({ ...s, primary: false }));
      updatedSecrets.push(newSecretEntry);

      // Remove expired secrets
      const validSecrets = updatedSecrets.filter(s => 
        !s.expiresAt || s.expiresAt > Date.now()
      );

      // Store updated secrets
      await this.redis.set(this.SECRET_KEY, JSON.stringify(validSecrets));

      // Log rotation
      this.logger.info('JWT secret rotated successfully', {
        previousCount: currentSecrets.length,
        currentCount: validSecrets.length,
        rotatedAt: new Date().toISOString()
      });

      // Schedule cleanup of old secrets
      this.scheduleSecretCleanup();

      return {
        success: true,
        rotatedAt: new Date(),
        warnings: validSecrets.length > 2 ? ['Multiple secrets in rotation'] : []
      };

    } catch (error) {
      errors.push(`Rotation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { success: false, rotatedAt: new Date(), errors };
    }
  }

  /**
   * Get current valid secrets
   */
  async getCurrentSecrets(): Promise<any[]> {
    try {
      const data = await this.redis.get(this.SECRET_KEY);
      if (!data) return [];
      
      const secrets = JSON.parse(data);
      // Filter out expired secrets
      return secrets.filter((s: any) => !s.expiresAt || s.expiresAt > Date.now());
    } catch {
      return [];
    }
  }

  /**
   * Get primary secret for signing new tokens
   */
  async getPrimarySecret(): Promise<string | null> {
    const secrets = await this.getCurrentSecrets();
    const primary = secrets.find(s => s.primary);
    return primary ? primary.secret : null;
  }

  /**
   * Verify token with multiple secrets
   */
  async verifyToken(token: string): Promise<any> {
    const secrets = await this.getCurrentSecrets();
    
    for (const secretEntry of secrets) {
      try {
        return jwt.verify(token, secretEntry.secret);
      } catch (err) {
        // Try next secret
        continue;
      }
    }
    
    throw new Error('Token verification failed with all secrets');
  }

  /**
   * Schedule cleanup of expired secrets
   */
  private scheduleSecretCleanup(): void {
    setTimeout(async () => {
      try {
        const secrets = await this.getCurrentSecrets();
        const validSecrets = secrets.filter(s => 
          !s.expiresAt || s.expiresAt > Date.now()
        );
        
        if (validSecrets.length < secrets.length) {
          await this.redis.set(this.SECRET_KEY, JSON.stringify(validSecrets));
          this.logger.info('Cleaned up expired JWT secrets', {
            removed: secrets.length - validSecrets.length
          });
        }
      } catch (error) {
        this.logger.error('Failed to cleanup secrets', { error });
      }
    }, this.ROTATION_OVERLAP_HOURS * 60 * 60 * 1000);
  }
}

/**
 * Database Password Rotation
 */
export class DatabasePasswordRotation {
  private prisma: PrismaClient;
  private logger: any;

  constructor(options: SecretRotationOptions) {
    this.prisma = options.prisma;
    this.logger = options.logger || console;
  }

  /**
   * Rotate database password
   * Note: This requires coordination with database administrator
   */
  async prepareRotation(newPassword: string): Promise<RotationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Validate new password
      if (!newPassword || newPassword.length < 8) {
        errors.push('New password must be at least 8 characters');
        return { success: false, rotatedAt: new Date(), errors };
      }

      // Test current connection
      await this.prisma.$queryRaw`SELECT 1`;

      // Generate rotation script
      const rotationScript = this.generateRotationScript(newPassword);
      
      // Save rotation plan
      await this.saveRotationPlan(rotationScript);

      warnings.push('Database password rotation prepared. Execute the rotation script with DBA.');

      return {
        success: true,
        rotatedAt: new Date(),
        warnings
      };

    } catch (error) {
      errors.push(`Rotation preparation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { success: false, rotatedAt: new Date(), errors };
    }
  }

  private generateRotationScript(newPassword: string): string {
    return `
-- Database Password Rotation Script
-- Generated: ${new Date().toISOString()}
-- EXECUTE WITH DBA PRIVILEGES

-- Step 1: Create new user with new password
CREATE USER sparc_user_new WITH PASSWORD '${newPassword}';

-- Step 2: Grant all privileges from old user
GRANT ALL PRIVILEGES ON DATABASE sparc_db TO sparc_user_new;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sparc_user_new;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sparc_user_new;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO sparc_user_new;

-- Step 3: Test connection with new credentials
-- psql -U sparc_user_new -d sparc_db -c "SELECT 1;"

-- Step 4: Update application configuration
-- Update DATABASE_URL and DATABASE_PASSWORD environment variables

-- Step 5: After confirming application works with new user
-- DROP USER sparc_user_old;

-- Rollback if needed:
-- DROP USER sparc_user_new;
    `;
  }

  private async saveRotationPlan(script: string): Promise<void> {
    // In production, this would save to a secure location
    // For now, just log it
    this.logger.info('Database rotation script generated', {
      scriptLength: script.length,
      timestamp: new Date().toISOString()
    });
  }
}

/**
 * Encryption Key Rotation
 */
export class EncryptionKeyRotation {
  private prisma: PrismaClient;
  private redis: Redis;
  private logger: any;

  constructor(options: SecretRotationOptions) {
    this.prisma = options.prisma;
    this.redis = options.redis;
    this.logger = options.logger || console;
  }

  /**
   * Rotate encryption key with data re-encryption
   */
  async rotateKey(
    oldKey: string,
    newKey: string,
    batchSize: number = 100
  ): Promise<RotationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Validate keys
      if (!this.validateKey(oldKey) || !this.validateKey(newKey)) {
        errors.push('Invalid encryption key format');
        return { success: false, rotatedAt: new Date(), errors };
      }

      // Start rotation transaction
      const rotationId = crypto.randomUUID();
      await this.startRotation(rotationId, oldKey, newKey);

      // Re-encrypt data in batches
      let processed = 0;
      let hasMore = true;

      while (hasMore) {
        const batch = await this.getNextBatch(batchSize);
        if (batch.length === 0) {
          hasMore = false;
          break;
        }

        await this.reencryptBatch(batch, oldKey, newKey);
        processed += batch.length;

        // Update progress
        await this.updateRotationProgress(rotationId, processed);
      }

      // Complete rotation
      await this.completeRotation(rotationId);

      this.logger.info('Encryption key rotation completed', {
        rotationId,
        recordsProcessed: processed,
        completedAt: new Date().toISOString()
      });

      return {
        success: true,
        rotatedAt: new Date(),
        warnings: processed === 0 ? ['No encrypted data found'] : []
      };

    } catch (error) {
      errors.push(`Key rotation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { success: false, rotatedAt: new Date(), errors };
    }
  }

  private validateKey(key: string): boolean {
    try {
      const decoded = Buffer.from(key, 'base64');
      return decoded.length === 32; // AES-256 requires 32 bytes
    } catch {
      return false;
    }
  }

  private async startRotation(rotationId: string, oldKey: string, newKey: string): Promise<void> {
    await this.redis.setex(`rotation:${rotationId}`, 86400, JSON.stringify({
      status: 'in_progress',
      startedAt: new Date().toISOString(),
      oldKeyHash: crypto.createHash('sha256').update(oldKey).digest('hex'),
      newKeyHash: crypto.createHash('sha256').update(newKey).digest('hex')
    }));
  }

  private async getNextBatch(batchSize: number): Promise<any[]> {
    // Get credentials that need re-encryption
    return await this.prisma.credential.findMany({
      where: {
        encryptionVersion: { lt: 2 } // Assuming version 2 uses new key
      },
      take: batchSize
    });
  }

  private async reencryptBatch(batch: any[], oldKey: string, newKey: string): Promise<void> {
    // Import encryption utilities
    const { decrypt, encrypt } = require('./encryption');

    for (const record of batch) {
      try {
        // Decrypt with old key
        const decryptedPin = record.pinCode ? decrypt(record.pinCode, oldKey) : null;
        const decryptedBiometric = record.biometricTemplate ? 
          decrypt(record.biometricTemplate, oldKey) : null;

        // Re-encrypt with new key
        const updates: any = {
          encryptionVersion: 2
        };

        if (decryptedPin) {
          updates.pinCode = encrypt(decryptedPin, newKey);
        }
        if (decryptedBiometric) {
          updates.biometricTemplate = encrypt(decryptedBiometric, newKey);
        }

        // Update record
        await this.prisma.credential.update({
          where: { id: record.id },
          data: updates
        });

      } catch (error) {
        this.logger.error('Failed to re-encrypt record', {
          recordId: record.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  }

  private async updateRotationProgress(rotationId: string, processed: number): Promise<void> {
    const key = `rotation:${rotationId}`;
    const data = await this.redis.get(key);
    if (data) {
      const rotation = JSON.parse(data);
      rotation.processed = processed;
      rotation.lastUpdated = new Date().toISOString();
      await this.redis.setex(key, 86400, JSON.stringify(rotation));
    }
  }

  private async completeRotation(rotationId: string): Promise<void> {
    const key = `rotation:${rotationId}`;
    const data = await this.redis.get(key);
    if (data) {
      const rotation = JSON.parse(data);
      rotation.status = 'completed';
      rotation.completedAt = new Date().toISOString();
      await this.redis.setex(key, 86400, JSON.stringify(rotation));
    }
  }
}

/**
 * API Key Rotation
 */
export class APIKeyRotation {
  private redis: Redis;
  private prisma: PrismaClient;
  private logger: any;

  constructor(options: SecretRotationOptions) {
    this.redis = options.redis;
    this.prisma = options.prisma;
    this.logger = options.logger || console;
  }

  /**
   * Generate new API key
   */
  generateApiKey(): string {
    const prefix = 'sk_live_';
    const randomBytes = crypto.randomBytes(32);
    return prefix + randomBytes.toString('base64url');
  }

  /**
   * Rotate API key for a tenant
   */
  async rotateApiKey(
    tenantId: string,
    gracePeriodHours: number = 24
  ): Promise<RotationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Generate new API key
      const newApiKey = this.generateApiKey();
      const hashedKey = crypto.createHash('sha256').update(newApiKey).digest('hex');

      // Store new key with grace period
      const expirationTime = Date.now() + (gracePeriodHours * 60 * 60 * 1000);
      
      await this.redis.setex(
        `apikey:${tenantId}:${hashedKey}`,
        gracePeriodHours * 3600,
        JSON.stringify({
          tenantId,
          createdAt: Date.now(),
          expiresAt: expirationTime,
          rotated: true
        })
      );

      // Update tenant record
      await this.prisma.tenant.update({
        where: { id: tenantId },
        data: {
          apiKeyRotatedAt: new Date(),
          settings: {
            update: {
              apiKeyGracePeriod: expirationTime
            }
          }
        }
      });

      // Send notification to tenant
      await this.notifyTenantOfRotation(tenantId, newApiKey, gracePeriodHours);

      return {
        success: true,
        rotatedAt: new Date(),
        warnings: [`Old API key valid for ${gracePeriodHours} hours`]
      };

    } catch (error) {
      errors.push(`API key rotation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { success: false, rotatedAt: new Date(), errors };
    }
  }

  private async notifyTenantOfRotation(
    tenantId: string,
    newApiKey: string,
    gracePeriodHours: number
  ): Promise<void> {
    // In production, this would send email/webhook notification
    this.logger.info('API key rotation notification', {
      tenantId,
      gracePeriodHours,
      notifiedAt: new Date().toISOString()
    });
  }
}

/**
 * Webhook Secret Rotation
 */
export class WebhookSecretRotation {
  private redis: Redis;
  private prisma: PrismaClient;
  private logger: any;

  constructor(options: SecretRotationOptions) {
    this.redis = options.redis;
    this.prisma = options.prisma;
    this.logger = options.logger || console;
  }

  /**
   * Rotate webhook signing secret
   */
  async rotateWebhookSecret(
    tenantId: string,
    newSecret: string
  ): Promise<RotationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      // Validate new secret
      if (!newSecret || newSecret.length < 16) {
        errors.push('Webhook secret must be at least 16 characters');
        return { success: false, rotatedAt: new Date(), errors };
      }

      // Store both old and new secrets temporarily
      const transitionPeriod = 7 * 24 * 60 * 60 * 1000; // 7 days
      
      // Get current webhook configuration
      const tenant = await this.prisma.tenant.findUnique({
        where: { id: tenantId }
      });

      if (!tenant) {
        errors.push('Tenant not found');
        return { success: false, rotatedAt: new Date(), errors };
      }

      // Store rotation information
      await this.redis.setex(
        `webhook:rotation:${tenantId}`,
        transitionPeriod / 1000,
        JSON.stringify({
          oldSecret: tenant.settings?.webhookSecret,
          newSecret,
          rotatedAt: Date.now(),
          transitionEndsAt: Date.now() + transitionPeriod
        })
      );

      // Update tenant with new secret
      await this.prisma.tenant.update({
        where: { id: tenantId },
        data: {
          settings: {
            update: {
              webhookSecret: newSecret,
              webhookSecretRotatedAt: new Date()
            }
          }
        }
      });

      warnings.push('Both old and new webhook secrets valid for 7 days');

      return {
        success: true,
        rotatedAt: new Date(),
        warnings
      };

    } catch (error) {
      errors.push(`Webhook secret rotation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return { success: false, rotatedAt: new Date(), errors };
    }
  }

  /**
   * Verify webhook signature with rotation support
   */
  async verifyWebhookSignature(
    tenantId: string,
    payload: string,
    signature: string
  ): Promise<boolean> {
    try {
      // Get current secret
      const tenant = await this.prisma.tenant.findUnique({
        where: { id: tenantId }
      });

      if (!tenant?.settings?.webhookSecret) {
        return false;
      }

      // Try current secret
      const currentSignature = crypto
        .createHmac('sha256', tenant.settings.webhookSecret)
        .update(payload)
        .digest('hex');

      if (currentSignature === signature) {
        return true;
      }

      // Check if in rotation period
      const rotationData = await this.redis.get(`webhook:rotation:${tenantId}`);
      if (rotationData) {
        const rotation = JSON.parse(rotationData);
        
        // Try old secret
        if (rotation.oldSecret) {
          const oldSignature = crypto
            .createHmac('sha256', rotation.oldSecret)
            .update(payload)
            .digest('hex');
          
          if (oldSignature === signature) {
            this.logger.warn('Webhook verified with old secret', {
              tenantId,
              rotationEndsAt: new Date(rotation.transitionEndsAt).toISOString()
            });
            return true;
          }
        }
      }

      return false;

    } catch (error) {
      this.logger.error('Webhook verification error', { error, tenantId });
      return false;
    }
  }
}

/**
 * Unified secret rotation manager
 */
export class SecretRotationManager {
  private jwtRotation: JWTSecretRotation;
  private dbRotation: DatabasePasswordRotation;
  private encryptionRotation: EncryptionKeyRotation;
  private apiKeyRotation: APIKeyRotation;
  private webhookRotation: WebhookSecretRotation;

  constructor(options: SecretRotationOptions) {
    this.jwtRotation = new JWTSecretRotation(options);
    this.dbRotation = new DatabasePasswordRotation(options);
    this.encryptionRotation = new EncryptionKeyRotation(options);
    this.apiKeyRotation = new APIKeyRotation(options);
    this.webhookRotation = new WebhookSecretRotation(options);
  }

  /**
   * Perform scheduled rotation check
   */
  async performRotationCheck(): Promise<void> {
    const rotations = await this.getScheduledRotations();
    
    for (const rotation of rotations) {
      try {
        switch (rotation.type) {
          case 'jwt':
            await this.jwtRotation.rotateSecret(rotation.newValue);
            break;
          case 'database':
            await this.dbRotation.prepareRotation(rotation.newValue);
            break;
          case 'encryption':
            await this.encryptionRotation.rotateKey(rotation.oldValue, rotation.newValue);
            break;
          case 'apikey':
            await this.apiKeyRotation.rotateApiKey(rotation.tenantId);
            break;
          case 'webhook':
            await this.webhookRotation.rotateWebhookSecret(rotation.tenantId, rotation.newValue);
            break;
        }
      } catch (error) {
        logger.error('Rotation failed', {
          type: rotation.type,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  }

  private async getScheduledRotations(): Promise<any[]> {
    // In production, this would fetch from a rotation schedule database
    return [];
  }
}