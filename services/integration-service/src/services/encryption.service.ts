import crypto from 'crypto';
import { logger } from '@sparc/shared';

export class EncryptionService {
  private algorithm = 'aes-256-gcm';
  private key: Buffer;

  constructor() {
    // In production, this should come from a secure key management service
    const encryptionKey = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    this.key = Buffer.from(encryptionKey, 'hex');
  }

  async encrypt(data: string): Promise<string> {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
      
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      const authTag = cipher.getAuthTag();
      
      // Combine iv:authTag:encrypted
      return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (error) {
      logger.error('Encryption failed', { error });
      throw new Error('Failed to encrypt data');
    }
  }

  async decrypt(encryptedData: string): Promise<string> {
    try {
      const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
      
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      logger.error('Decryption failed', { error });
      throw new Error('Failed to decrypt data');
    }
  }

  generateHash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  generateRandomToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  compareHash(data: string, hash: string): boolean {
    const dataHash = this.generateHash(data);
    return crypto.timingSafeEqual(Buffer.from(dataHash), Buffer.from(hash));
  }
}