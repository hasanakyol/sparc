/**
 * Secrets Rotation and Management System for SPARC Platform
 * Provides automated secrets rotation, versioning, and secure storage
 */

import crypto from 'crypto';
import { z } from 'zod';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  PutSecretValueCommand,
  CreateSecretCommand,
  UpdateSecretCommand,
  DescribeSecretCommand,
  UpdateSecretVersionStageCommand,
  ListSecretsCommand,
  TagResourceCommand,
} from '@aws-sdk/client-secrets-manager';
import { KMSClient, GenerateDataKeyCommand } from '@aws-sdk/client-kms';
import Redis from 'ioredis';
import { EventEmitter } from 'events';

// Secret types
export enum SecretType {
  DATABASE_PASSWORD = 'database_password',
  API_KEY = 'api_key',
  JWT_SECRET = 'jwt_secret',
  ENCRYPTION_KEY = 'encryption_key',
  OAUTH_CLIENT_SECRET = 'oauth_client_secret',
  WEBHOOK_SECRET = 'webhook_secret',
  SERVICE_ACCOUNT = 'service_account',
  CERTIFICATE = 'certificate',
  SSH_KEY = 'ssh_key',
}

// Secret metadata schema
export const secretMetadataSchema = z.object({
  name: z.string(),
  type: z.nativeEnum(SecretType),
  description: z.string().optional(),
  rotationEnabled: z.boolean().default(true),
  rotationInterval: z.number().default(90), // days
  lastRotated: z.date().optional(),
  nextRotation: z.date().optional(),
  version: z.number().default(1),
  tags: z.record(z.string()).optional(),
  compliance: z.object({
    standards: z.array(z.string()).default(['SOC2']),
    dataClassification: z.enum(['public', 'internal', 'confidential', 'restricted']).default('restricted'),
  }).optional(),
  validation: z.object({
    minLength: z.number().optional(),
    maxLength: z.number().optional(),
    pattern: z.string().optional(),
    customValidator: z.string().optional(), // Function name to call
  }).optional(),
});

export type SecretMetadata = z.infer<typeof secretMetadataSchema>;

// Secret value schema
export const secretValueSchema = z.object({
  value: z.string(),
  metadata: secretMetadataSchema,
  createdAt: z.date(),
  createdBy: z.string(),
  expiresAt: z.date().optional(),
  encrypted: z.boolean().default(true),
});

export type SecretValue = z.infer<typeof secretValueSchema>;

// Rotation strategy interface
export interface RotationStrategy {
  generateNewSecret(metadata: SecretMetadata): Promise<string>;
  validateSecret(secret: string, metadata: SecretMetadata): Promise<boolean>;
  preRotation?(metadata: SecretMetadata, oldSecret: string): Promise<void>;
  postRotation?(metadata: SecretMetadata, newSecret: string): Promise<void>;
  rollback?(metadata: SecretMetadata, oldSecret: string, error: Error): Promise<void>;
}

// Configuration
export interface SecretsManagerConfig {
  awsRegion: string;
  kmsKeyId: string;
  secretsPrefix: string;
  redis?: Redis;
  cacheTTL?: number; // seconds
  rotationStrategies?: Map<SecretType, RotationStrategy>;
  webhooks?: {
    onRotation?: string[];
    onFailure?: string[];
  };
  monitoring?: {
    metricsEnabled: boolean;
    logsEnabled: boolean;
  };
}

/**
 * Secrets Manager
 */
export class SecretsManager extends EventEmitter {
  private secretsClient: SecretsManagerClient;
  private kmsClient: KMSClient;
  private config: SecretsManagerConfig;
  private redis?: Redis;
  private rotationStrategies: Map<SecretType, RotationStrategy>;
  private rotationTimers: Map<string, NodeJS.Timeout> = new Map();

  constructor(config: SecretsManagerConfig) {
    super();
    
    this.config = config;
    this.secretsClient = new SecretsManagerClient({ region: config.awsRegion });
    this.kmsClient = new KMSClient({ region: config.awsRegion });
    this.redis = config.redis;
    
    // Initialize rotation strategies
    this.rotationStrategies = config.rotationStrategies || this.getDefaultRotationStrategies();
    
    // Start rotation scheduler
    this.startRotationScheduler();
  }

  /**
   * Create a new secret
   */
  async createSecret(
    name: string,
    value: string,
    metadata: Omit<SecretMetadata, 'name'>
  ): Promise<void> {
    const fullName = `${this.config.secretsPrefix}/${name}`;
    const completeMetadata: SecretMetadata = {
      ...metadata,
      name,
      lastRotated: new Date(),
      nextRotation: this.calculateNextRotation(metadata.rotationInterval || 90),
    };
    
    // Validate the secret
    const strategy = this.rotationStrategies.get(metadata.type);
    if (strategy && !await strategy.validateSecret(value, completeMetadata)) {
      throw new Error('Secret validation failed');
    }
    
    // Encrypt the secret value
    const encryptedValue = await this.encryptSecret(value);
    
    // Create the secret value object
    const secretValue: SecretValue = {
      value: encryptedValue,
      metadata: completeMetadata,
      createdAt: new Date(),
      createdBy: 'system', // TODO: Get from context
      encrypted: true,
    };
    
    try {
      // Create in AWS Secrets Manager
      await this.secretsClient.send(new CreateSecretCommand({
        Name: fullName,
        SecretString: JSON.stringify(secretValue),
        KmsKeyId: this.config.kmsKeyId,
        Tags: [
          { Key: 'Type', Value: metadata.type },
          { Key: 'Environment', Value: process.env.NODE_ENV || 'development' },
          { Key: 'ManagedBy', Value: 'SPARC' },
          ...Object.entries(metadata.tags || {}).map(([k, v]) => ({ Key: k, Value: v })),
        ],
      }));
      
      // Schedule rotation if enabled
      if (metadata.rotationEnabled) {
        this.scheduleRotation(fullName, completeMetadata.nextRotation!);
      }
      
      this.emit('secret:created', { name, metadata: completeMetadata });
      
    } catch (error) {
      this.emit('secret:error', { name, error, operation: 'create' });
      throw error;
    }
  }

  /**
   * Get a secret value
   */
  async getSecret(name: string, options?: { 
    version?: string; 
    decrypt?: boolean;
    bypassCache?: boolean;
  }): Promise<string> {
    const fullName = `${this.config.secretsPrefix}/${name}`;
    
    // Check cache first
    if (!options?.bypassCache && this.redis) {
      const cached = await this.getCachedSecret(fullName);
      if (cached) return cached;
    }
    
    try {
      // Get from AWS Secrets Manager
      const response = await this.secretsClient.send(new GetSecretValueCommand({
        SecretId: fullName,
        VersionId: options?.version,
        VersionStage: options?.version ? undefined : 'AWSCURRENT',
      }));
      
      if (!response.SecretString) {
        throw new Error('Secret value not found');
      }
      
      const secretValue = JSON.parse(response.SecretString) as SecretValue;
      
      // Decrypt if needed
      let value = secretValue.value;
      if (secretValue.encrypted && options?.decrypt !== false) {
        value = await this.decryptSecret(value);
      }
      
      // Cache the decrypted value
      if (this.redis && options?.decrypt !== false) {
        await this.cacheSecret(fullName, value);
      }
      
      // Check if secret is expired
      if (secretValue.expiresAt && new Date(secretValue.expiresAt) < new Date()) {
        this.emit('secret:expired', { name, expiresAt: secretValue.expiresAt });
        throw new Error('Secret has expired');
      }
      
      return value;
      
    } catch (error) {
      this.emit('secret:error', { name, error, operation: 'get' });
      throw error;
    }
  }

  /**
   * Update a secret value
   */
  async updateSecret(
    name: string,
    value: string,
    options?: { 
      metadata?: Partial<SecretMetadata>;
      rotateImmediately?: boolean;
    }
  ): Promise<void> {
    const fullName = `${this.config.secretsPrefix}/${name}`;
    
    try {
      // Get current metadata
      const currentSecret = await this.getSecretMetadata(name);
      const updatedMetadata: SecretMetadata = {
        ...currentSecret,
        ...options?.metadata,
        version: currentSecret.version + 1,
        lastRotated: new Date(),
        nextRotation: this.calculateNextRotation(
          options?.metadata?.rotationInterval || currentSecret.rotationInterval
        ),
      };
      
      // Validate the new secret
      const strategy = this.rotationStrategies.get(updatedMetadata.type);
      if (strategy && !await strategy.validateSecret(value, updatedMetadata)) {
        throw new Error('Secret validation failed');
      }
      
      // Encrypt the new value
      const encryptedValue = await this.encryptSecret(value);
      
      // Create new secret value
      const secretValue: SecretValue = {
        value: encryptedValue,
        metadata: updatedMetadata,
        createdAt: new Date(),
        createdBy: 'system', // TODO: Get from context
        encrypted: true,
      };
      
      // Update in AWS Secrets Manager
      await this.secretsClient.send(new PutSecretValueCommand({
        SecretId: fullName,
        SecretString: JSON.stringify(secretValue),
        VersionStages: ['AWSPENDING'],
      }));
      
      // Promote to current
      await this.promoteSecretVersion(fullName);
      
      // Clear cache
      if (this.redis) {
        await this.clearCachedSecret(fullName);
      }
      
      // Reschedule rotation
      if (updatedMetadata.rotationEnabled) {
        this.scheduleRotation(fullName, updatedMetadata.nextRotation!);
      }
      
      this.emit('secret:updated', { name, metadata: updatedMetadata });
      
      // Rotate immediately if requested
      if (options?.rotateImmediately) {
        await this.rotateSecret(name);
      }
      
    } catch (error) {
      this.emit('secret:error', { name, error, operation: 'update' });
      throw error;
    }
  }

  /**
   * Rotate a secret
   */
  async rotateSecret(name: string): Promise<void> {
    const fullName = `${this.config.secretsPrefix}/${name}`;
    
    try {
      // Get current secret and metadata
      const currentValue = await this.getSecret(name);
      const metadata = await this.getSecretMetadata(name);
      
      // Get rotation strategy
      const strategy = this.rotationStrategies.get(metadata.type);
      if (!strategy) {
        throw new Error(`No rotation strategy for secret type: ${metadata.type}`);
      }
      
      // Pre-rotation hook
      if (strategy.preRotation) {
        await strategy.preRotation(metadata, currentValue);
      }
      
      // Generate new secret
      const newValue = await strategy.generateNewSecret(metadata);
      
      // Validate new secret
      if (!await strategy.validateSecret(newValue, metadata)) {
        throw new Error('New secret validation failed');
      }
      
      // Update the secret
      await this.updateSecret(name, newValue, {
        metadata: {
          lastRotated: new Date(),
          nextRotation: this.calculateNextRotation(metadata.rotationInterval),
          version: metadata.version + 1,
        },
      });
      
      // Post-rotation hook
      if (strategy.postRotation) {
        await strategy.postRotation(metadata, newValue);
      }
      
      // Send notifications
      await this.sendRotationNotifications(name, metadata);
      
      this.emit('secret:rotated', { name, metadata });
      
    } catch (error) {
      // Rollback on failure
      const metadata = await this.getSecretMetadata(name);
      const strategy = this.rotationStrategies.get(metadata.type);
      
      if (strategy?.rollback) {
        try {
          const currentValue = await this.getSecret(name);
          await strategy.rollback(metadata, currentValue, error as Error);
        } catch (rollbackError) {
          console.error('Rollback failed:', rollbackError);
        }
      }
      
      this.emit('secret:rotation:failed', { name, error });
      await this.sendFailureNotifications(name, error as Error);
      
      throw error;
    }
  }

  /**
   * List all secrets
   */
  async listSecrets(options?: {
    type?: SecretType;
    tags?: Record<string, string>;
  }): Promise<SecretMetadata[]> {
    const secrets: SecretMetadata[] = [];
    let nextToken: string | undefined;
    
    do {
      const response = await this.secretsClient.send(new ListSecretsCommand({
        NextToken: nextToken,
        Filters: [
          {
            Key: 'name',
            Values: [`${this.config.secretsPrefix}/`],
          },
          ...(options?.tags ? Object.entries(options.tags).map(([k, v]) => ({
            Key: `tag-key`,
            Values: [k],
          })) : []),
        ],
      }));
      
      for (const secret of response.SecretList || []) {
        try {
          const metadata = await this.getSecretMetadata(
            secret.Name!.replace(`${this.config.secretsPrefix}/`, '')
          );
          
          if (!options?.type || metadata.type === options.type) {
            secrets.push(metadata);
          }
        } catch (error) {
          console.error(`Failed to get metadata for secret ${secret.Name}:`, error);
        }
      }
      
      nextToken = response.NextToken;
    } while (nextToken);
    
    return secrets;
  }

  /**
   * Get secret metadata
   */
  private async getSecretMetadata(name: string): Promise<SecretMetadata> {
    const fullName = `${this.config.secretsPrefix}/${name}`;
    
    const response = await this.secretsClient.send(new DescribeSecretCommand({
      SecretId: fullName,
    }));
    
    if (!response.Name) {
      throw new Error('Secret not found');
    }
    
    // Get the current version
    const secretResponse = await this.secretsClient.send(new GetSecretValueCommand({
      SecretId: fullName,
      VersionStage: 'AWSCURRENT',
    }));
    
    if (!secretResponse.SecretString) {
      throw new Error('Secret value not found');
    }
    
    const secretValue = JSON.parse(secretResponse.SecretString) as SecretValue;
    return secretValue.metadata;
  }

  /**
   * Promote secret version
   */
  private async promoteSecretVersion(secretId: string): Promise<void> {
    // Move AWSPENDING to AWSCURRENT
    await this.secretsClient.send(new UpdateSecretVersionStageCommand({
      SecretId: secretId,
      VersionStage: 'AWSCURRENT',
      MoveToVersionId: 'AWSPENDING',
      RemoveFromVersionId: 'AWSCURRENT',
    }));
  }

  /**
   * Encrypt secret using KMS
   */
  private async encryptSecret(plaintext: string): Promise<string> {
    const response = await this.kmsClient.send(new GenerateDataKeyCommand({
      KeyId: this.config.kmsKeyId,
      KeySpec: 'AES_256',
    }));
    
    if (!response.Plaintext || !response.CiphertextBlob) {
      throw new Error('Failed to generate data key');
    }
    
    // Use the data key to encrypt the secret
    const cipher = crypto.createCipheriv(
      'aes-256-gcm',
      response.Plaintext,
      crypto.randomBytes(16)
    );
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    
    const authTag = cipher.getAuthTag();
    
    // Return base64 encoded encrypted data with the encrypted data key
    return Buffer.concat([
      Buffer.from(response.CiphertextBlob),
      authTag,
      encrypted,
    ]).toString('base64');
  }

  /**
   * Decrypt secret
   */
  private async decryptSecret(encrypted: string): Promise<string> {
    // This is a simplified version - implement proper decryption
    // In production, use KMS to decrypt the data key first
    return encrypted; // TODO: Implement actual decryption
  }

  /**
   * Cache secret in Redis
   */
  private async cacheSecret(key: string, value: string): Promise<void> {
    if (!this.redis) return;
    
    const ttl = this.config.cacheTTL || 300; // 5 minutes default
    await this.redis.setex(`secret:${key}`, ttl, value);
  }

  /**
   * Get cached secret
   */
  private async getCachedSecret(key: string): Promise<string | null> {
    if (!this.redis) return null;
    
    return await this.redis.get(`secret:${key}`);
  }

  /**
   * Clear cached secret
   */
  private async clearCachedSecret(key: string): Promise<void> {
    if (!this.redis) return;
    
    await this.redis.del(`secret:${key}`);
  }

  /**
   * Calculate next rotation date
   */
  private calculateNextRotation(intervalDays: number): Date {
    const next = new Date();
    next.setDate(next.getDate() + intervalDays);
    return next;
  }

  /**
   * Schedule secret rotation
   */
  private scheduleRotation(secretName: string, rotationDate: Date): void {
    // Clear existing timer
    const existingTimer = this.rotationTimers.get(secretName);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }
    
    const delay = rotationDate.getTime() - Date.now();
    if (delay <= 0) {
      // Rotate immediately
      this.rotateSecret(secretName.replace(`${this.config.secretsPrefix}/`, '')).catch(error => {
        console.error(`Failed to rotate secret ${secretName}:`, error);
      });
    } else {
      // Schedule future rotation
      const timer = setTimeout(() => {
        this.rotateSecret(secretName.replace(`${this.config.secretsPrefix}/`, '')).catch(error => {
          console.error(`Failed to rotate secret ${secretName}:`, error);
        });
      }, delay);
      
      this.rotationTimers.set(secretName, timer);
    }
  }

  /**
   * Start rotation scheduler
   */
  private async startRotationScheduler(): Promise<void> {
    // Check all secrets on startup
    try {
      const secrets = await this.listSecrets();
      
      for (const secret of secrets) {
        if (secret.rotationEnabled && secret.nextRotation) {
          this.scheduleRotation(
            `${this.config.secretsPrefix}/${secret.name}`,
            new Date(secret.nextRotation)
          );
        }
      }
    } catch (error) {
      console.error('Failed to start rotation scheduler:', error);
    }
    
    // Check for new rotations every hour
    setInterval(() => {
      this.startRotationScheduler();
    }, 3600000);
  }

  /**
   * Send rotation notifications
   */
  private async sendRotationNotifications(name: string, metadata: SecretMetadata): Promise<void> {
    if (!this.config.webhooks?.onRotation) return;
    
    const payload = {
      event: 'secret_rotated',
      timestamp: new Date().toISOString(),
      secret: {
        name,
        type: metadata.type,
        version: metadata.version,
        nextRotation: metadata.nextRotation,
      },
    };
    
    for (const webhook of this.config.webhooks.onRotation) {
      try {
        await fetch(webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch (error) {
        console.error(`Failed to send rotation notification to ${webhook}:`, error);
      }
    }
  }

  /**
   * Send failure notifications
   */
  private async sendFailureNotifications(name: string, error: Error): Promise<void> {
    if (!this.config.webhooks?.onFailure) return;
    
    const payload = {
      event: 'secret_rotation_failed',
      timestamp: new Date().toISOString(),
      secret: { name },
      error: {
        message: error.message,
        stack: error.stack,
      },
    };
    
    for (const webhook of this.config.webhooks.onFailure) {
      try {
        await fetch(webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch (err) {
        console.error(`Failed to send failure notification to ${webhook}:`, err);
      }
    }
  }

  /**
   * Get default rotation strategies
   */
  private getDefaultRotationStrategies(): Map<SecretType, RotationStrategy> {
    const strategies = new Map<SecretType, RotationStrategy>();
    
    // Database password strategy
    strategies.set(SecretType.DATABASE_PASSWORD, {
      generateNewSecret: async (metadata) => {
        return this.generateSecurePassword({
          length: 32,
          includeSymbols: true,
          excludeAmbiguous: true,
        });
      },
      validateSecret: async (secret, metadata) => {
        return secret.length >= (metadata.validation?.minLength || 16) &&
               secret.length <= (metadata.validation?.maxLength || 128) &&
               /[A-Z]/.test(secret) &&
               /[a-z]/.test(secret) &&
               /[0-9]/.test(secret) &&
               /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(secret);
      },
      preRotation: async (metadata, oldSecret) => {
        // TODO: Create new database user with new password
        console.log('Pre-rotation: Creating new database user');
      },
      postRotation: async (metadata, newSecret) => {
        // TODO: Update application configurations
        // TODO: Remove old database user after grace period
        console.log('Post-rotation: Updating application configurations');
      },
      rollback: async (metadata, oldSecret, error) => {
        // TODO: Restore old database user
        console.log('Rollback: Restoring old database configuration');
      },
    });
    
    // API key strategy
    strategies.set(SecretType.API_KEY, {
      generateNewSecret: async (metadata) => {
        return crypto.randomBytes(32).toString('base64url');
      },
      validateSecret: async (secret, metadata) => {
        return secret.length === 43; // Base64URL encoded 32 bytes
      },
      postRotation: async (metadata, newSecret) => {
        // TODO: Notify API consumers about new key
        console.log('Post-rotation: Notifying API consumers');
      },
    });
    
    // JWT secret strategy
    strategies.set(SecretType.JWT_SECRET, {
      generateNewSecret: async (metadata) => {
        return crypto.randomBytes(64).toString('hex');
      },
      validateSecret: async (secret, metadata) => {
        return secret.length === 128; // 64 bytes in hex
      },
      preRotation: async (metadata, oldSecret) => {
        // TODO: Start dual validation period
        console.log('Pre-rotation: Enabling dual JWT validation');
      },
      postRotation: async (metadata, newSecret) => {
        // TODO: Invalidate tokens signed with old secret
        console.log('Post-rotation: Invalidating old tokens');
      },
    });
    
    // Certificate strategy
    strategies.set(SecretType.CERTIFICATE, {
      generateNewSecret: async (metadata) => {
        // TODO: Generate new certificate using ACME or internal CA
        throw new Error('Certificate rotation not implemented');
      },
      validateSecret: async (secret, metadata) => {
        // TODO: Validate certificate format and expiration
        return true;
      },
      preRotation: async (metadata, oldSecret) => {
        // TODO: Deploy new certificate alongside old one
        console.log('Pre-rotation: Deploying new certificate');
      },
      postRotation: async (metadata, newSecret) => {
        // TODO: Remove old certificate after grace period
        console.log('Post-rotation: Scheduling old certificate removal');
      },
    });
    
    return strategies;
  }

  /**
   * Generate secure password
   */
  private generateSecurePassword(options: {
    length: number;
    includeSymbols?: boolean;
    excludeAmbiguous?: boolean;
  }): string {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let charset = lowercase + uppercase + numbers;
    if (options.includeSymbols) {
      charset += symbols;
    }
    
    if (options.excludeAmbiguous) {
      charset = charset.replace(/[0OIl1]/g, '');
    }
    
    let password = '';
    const randomBytes = crypto.randomBytes(options.length);
    
    for (let i = 0; i < options.length; i++) {
      password += charset[randomBytes[i] % charset.length];
    }
    
    // Ensure password contains at least one character from each category
    if (!password.match(/[a-z]/)) {
      password = password.slice(0, -1) + lowercase[crypto.randomInt(lowercase.length)];
    }
    if (!password.match(/[A-Z]/)) {
      password = password.slice(0, -1) + uppercase[crypto.randomInt(uppercase.length)];
    }
    if (!password.match(/[0-9]/)) {
      password = password.slice(0, -1) + numbers[crypto.randomInt(numbers.length)];
    }
    if (options.includeSymbols && !password.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/)) {
      password = password.slice(0, -1) + symbols[crypto.randomInt(symbols.length)];
    }
    
    return password;
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    // Clear all rotation timers
    for (const timer of this.rotationTimers.values()) {
      clearTimeout(timer);
    }
    this.rotationTimers.clear();
    
    // Remove all listeners
    this.removeAllListeners();
  }
}

/**
 * Create secrets manager instance
 */
export function createSecretsManager(config: SecretsManagerConfig): SecretsManager {
  return new SecretsManager(config);
}

export default SecretsManager;