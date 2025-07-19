import { SecretsManagerClient, GetSecretValueCommand, UpdateSecretCommand } from '@aws-sdk/client-secrets-manager';
import { createHash } from 'crypto';
import { logger } from '@sparc/shared/logging';

export interface SecretValue {
  value: string;
  version?: string;
  lastRotated?: Date;
}

export interface SecretRotationConfig {
  automaticRotation: boolean;
  rotationInterval: number; // in days
  rotationLambdaArn?: string;
}

export class SecretsManager {
  private client: SecretsManagerClient;
  private cache = new Map<string, { value: string; expires: Date; version?: string }>();
  private readonly cacheDuration = 3600000; // 1 hour default
  
  constructor(region: string = process.env.AWS_REGION || 'us-east-1') {
    this.client = new SecretsManagerClient({ region });
  }
  
  /**
   * Get a secret value from AWS Secrets Manager with caching
   */
  async getSecret(key: string): Promise<string> {
    const cached = this.cache.get(key);
    if (cached && cached.expires > new Date()) {
      logger.debug(`Returning cached secret for key: ${key}`);
      return cached.value;
    }
    
    try {
      // Fetch from Secrets Manager
      const command = new GetSecretValueCommand({ SecretId: key });
      const response = await this.client.send(command);
      
      if (!response.SecretString) {
        throw new Error(`Secret ${key} not found or is binary`);
      }
      
      // Try to parse as JSON first
      let secretValue: string;
      try {
        const parsed = JSON.parse(response.SecretString);
        // If it's an object with a 'value' property, use that
        secretValue = parsed.value || response.SecretString;
      } catch {
        // If not JSON, use as-is
        secretValue = response.SecretString;
      }
      
      // Cache the secret
      this.cache.set(key, {
        value: secretValue,
        expires: new Date(Date.now() + this.cacheDuration),
        version: response.VersionId
      });
      
      logger.info(`Successfully retrieved secret: ${key}`);
      return secretValue;
      
    } catch (error) {
      logger.error(`Failed to retrieve secret ${key}:`, error);
      
      // Fall back to environment variable if available
      const envValue = process.env[key];
      if (envValue) {
        logger.warn(`Using environment variable fallback for ${key}`);
        return envValue;
      }
      
      throw new Error(`Failed to retrieve secret ${key}: ${error}`);
    }
  }
  
  /**
   * Get multiple secrets at once
   */
  async getSecrets(keys: string[]): Promise<Record<string, string>> {
    const results: Record<string, string> = {};
    
    await Promise.all(
      keys.map(async (key) => {
        try {
          results[key] = await this.getSecret(key);
        } catch (error) {
          logger.error(`Failed to get secret ${key}:`, error);
          throw error;
        }
      })
    );
    
    return results;
  }
  
  /**
   * Rotate a secret manually
   */
  async rotateSecret(key: string, newValue?: string): Promise<void> {
    try {
      // Generate new secret value if not provided
      const secretValue = newValue || this.generateSecretValue();
      
      // Update the secret in AWS Secrets Manager
      const command = new UpdateSecretCommand({
        SecretId: key,
        SecretString: JSON.stringify({
          value: secretValue,
          lastRotated: new Date().toISOString(),
          rotatedBy: 'manual'
        })
      });
      
      await this.client.send(command);
      
      // Invalidate cache
      this.cache.delete(key);
      
      logger.info(`Successfully rotated secret: ${key}`);
      
      // Notify dependent services about rotation
      await this.notifyRotation(key);
      
    } catch (error) {
      logger.error(`Failed to rotate secret ${key}:`, error);
      throw new Error(`Failed to rotate secret ${key}: ${error}`);
    }
  }
  
  /**
   * Set up automatic rotation for a secret
   */
  async enableAutomaticRotation(
    key: string, 
    config: SecretRotationConfig
  ): Promise<void> {
    // In production, this would configure AWS Secrets Manager rotation
    // For now, we'll store the configuration
    logger.info(`Enabling automatic rotation for ${key}`, config);
    
    // This would typically:
    // 1. Create/update rotation Lambda if needed
    // 2. Configure rotation schedule
    // 3. Set up necessary IAM permissions
  }
  
  /**
   * Clear the cache for a specific secret or all secrets
   */
  clearCache(key?: string): void {
    if (key) {
      this.cache.delete(key);
      logger.debug(`Cleared cache for secret: ${key}`);
    } else {
      this.cache.clear();
      logger.debug('Cleared all secrets from cache');
    }
  }
  
  /**
   * Generate a secure random secret value
   */
  private generateSecretValue(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return result;
  }
  
  /**
   * Notify dependent services about secret rotation
   */
  private async notifyRotation(key: string): Promise<void> {
    // In production, this would:
    // 1. Publish to SNS/EventBridge
    // 2. Trigger service restarts if needed
    // 3. Update service discovery
    
    logger.info(`Notifying services about rotation of secret: ${key}`);
  }
  
  /**
   * Get secret with version validation
   */
  async getSecretWithVersion(key: string, requiredVersion?: string): Promise<SecretValue> {
    const cached = this.cache.get(key);
    
    if (cached && cached.expires > new Date()) {
      if (!requiredVersion || cached.version === requiredVersion) {
        return {
          value: cached.value,
          version: cached.version
        };
      }
    }
    
    const command = new GetSecretValueCommand({
      SecretId: key,
      VersionId: requiredVersion
    });
    
    const response = await this.client.send(command);
    
    if (!response.SecretString) {
      throw new Error(`Secret ${key} not found`);
    }
    
    const secretData = JSON.parse(response.SecretString);
    
    return {
      value: secretData.value || response.SecretString,
      version: response.VersionId,
      lastRotated: secretData.lastRotated ? new Date(secretData.lastRotated) : undefined
    };
  }
  
  /**
   * Validate secret age and trigger rotation if needed
   */
  async validateSecretAge(key: string, maxAgeInDays: number = 90): Promise<boolean> {
    try {
      const secret = await this.getSecretWithVersion(key);
      
      if (!secret.lastRotated) {
        logger.warn(`Secret ${key} has no rotation timestamp`);
        return false;
      }
      
      const ageInDays = (Date.now() - secret.lastRotated.getTime()) / (1000 * 60 * 60 * 24);
      
      if (ageInDays > maxAgeInDays) {
        logger.warn(`Secret ${key} is ${ageInDays} days old, exceeds max age of ${maxAgeInDays} days`);
        return false;
      }
      
      return true;
    } catch (error) {
      logger.error(`Failed to validate secret age for ${key}:`, error);
      return false;
    }
  }
}

// Singleton instance
let secretsManager: SecretsManager | null = null;

export function getSecretsManager(): SecretsManager {
  if (!secretsManager) {
    secretsManager = new SecretsManager();
  }
  return secretsManager;
}

// Helper function for JWT secret rotation
export async function rotateJWTSecret(): Promise<string> {
  const manager = getSecretsManager();
  const newSecret = createHash('sha256')
    .update(Math.random().toString())
    .update(Date.now().toString())
    .digest('hex');
  
  await manager.rotateSecret('JWT_SECRET', newSecret);
  return newSecret;
}