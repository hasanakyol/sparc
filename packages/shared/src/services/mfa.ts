import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { logger } from '../utils/logger';

export interface MFASecret {
  base32: string;
  otpauth_url: string;
  qr_code_url?: string;
}

export interface MFAVerificationResult {
  verified: boolean;
  error?: string;
}

export interface MFABackupCodes {
  codes: string[];
  createdAt: Date;
}

class MFAService {
  private readonly appName: string = 'SPARC Security Platform';
  private readonly backupCodeLength: number = 8;
  private readonly backupCodeCount: number = 10;

  /**
   * Generate a new MFA secret for a user
   */
  async generateSecret(userEmail: string, tenantName?: string): Promise<MFASecret> {
    try {
      const secret = speakeasy.generateSecret({
        name: `${this.appName}${tenantName ? ` - ${tenantName}` : ''} (${userEmail})`,
        length: 32,
      });

      // Generate QR code
      const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

      return {
        base32: secret.base32,
        otpauth_url: secret.otpauth_url,
        qr_code_url: qrCodeDataUrl,
      };
    } catch (error) {
      logger.error('Failed to generate MFA secret', { error, userEmail });
      throw new Error('Failed to generate MFA secret');
    }
  }

  /**
   * Verify a TOTP token
   */
  verifyToken(token: string, secret: string): MFAVerificationResult {
    try {
      // Remove any spaces from the token
      const cleanToken = token.replace(/\s/g, '');

      // Verify with a window of 1 to account for time drift
      const verified = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: cleanToken,
        window: 1,
      });

      return { verified };
    } catch (error) {
      logger.error('Failed to verify MFA token', { error });
      return { 
        verified: false, 
        error: 'Invalid token format' 
      };
    }
  }

  /**
   * Generate backup codes
   */
  generateBackupCodes(): MFABackupCodes {
    const codes: string[] = [];
    
    for (let i = 0; i < this.backupCodeCount; i++) {
      // Generate a random alphanumeric code
      const code = this.generateRandomCode(this.backupCodeLength);
      codes.push(code);
    }

    return {
      codes,
      createdAt: new Date(),
    };
  }

  /**
   * Hash backup codes for storage
   */
  async hashBackupCodes(codes: string[]): Promise<string[]> {
    const bcrypt = await import('bcrypt');
    const hashedCodes: string[] = [];

    for (const code of codes) {
      const hashed = await bcrypt.hash(code, 10);
      hashedCodes.push(hashed);
    }

    return hashedCodes;
  }

  /**
   * Verify a backup code
   */
  async verifyBackupCode(inputCode: string, hashedCodes: string[]): Promise<{ verified: boolean; index?: number }> {
    const bcrypt = await import('bcrypt');
    const cleanCode = inputCode.replace(/\s/g, '').toUpperCase();

    for (let i = 0; i < hashedCodes.length; i++) {
      const isValid = await bcrypt.compare(cleanCode, hashedCodes[i]);
      if (isValid) {
        return { verified: true, index: i };
      }
    }

    return { verified: false };
  }

  /**
   * Generate a recovery token for account recovery
   */
  generateRecoveryToken(): string {
    return this.generateRandomCode(16);
  }

  /**
   * Validate MFA setup
   */
  validateSetup(token: string, secret: string): { valid: boolean; message?: string } {
    // Verify the token to ensure the user has set up their authenticator correctly
    const verification = this.verifyToken(token, secret);
    
    if (!verification.verified) {
      return {
        valid: false,
        message: verification.error || 'Invalid verification code. Please check your authenticator app.',
      };
    }

    return { valid: true };
  }

  /**
   * Generate time-based token for testing
   */
  generateCurrentToken(secret: string): string {
    return speakeasy.totp({
      secret,
      encoding: 'base32',
    });
  }

  /**
   * Get remaining seconds until token expires
   */
  getTokenTimeRemaining(): number {
    const epoch = Math.floor(Date.now() / 1000);
    return 30 - (epoch % 30);
  }

  /**
   * Format backup codes for display
   */
  formatBackupCodes(codes: string[]): string[] {
    return codes.map(code => {
      // Format as XXXX-XXXX for 8 character codes
      if (code.length === 8) {
        return `${code.slice(0, 4)}-${code.slice(4)}`;
      }
      return code;
    });
  }

  /**
   * Generate random alphanumeric code
   */
  private generateRandomCode(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    
    for (let i = 0; i < length; i++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    return code;
  }
}

// Export singleton instance
export const mfaService = new MFAService();

// Export types
export type {
  MFASecret,
  MFAVerificationResult,
  MFABackupCodes,
};