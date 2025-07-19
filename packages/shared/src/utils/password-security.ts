import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';

/**
 * Enhanced password security implementation
 * - Minimum 12 characters
 * - Complexity requirements
 * - Password history tracking
 * - Breach database checking
 */

// Password validation schema
export const PasswordSchema = z.string()
  .min(12, 'Password must be at least 12 characters long')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character')
  .refine((password) => {
    // Check for common patterns
    const commonPatterns = [
      /^(.)\1+$/, // All same character
      /^(01|12|23|34|45|56|67|78|89|98|87|76|65|54|43|32|21|10)+$/, // Sequential numbers
      /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i, // Sequential letters
      /^(qwerty|asdf|zxcv|qazwsx|zaqwsx|password|admin|letmein|welcome|monkey|dragon)/i // Common passwords
    ];
    
    return !commonPatterns.some(pattern => pattern.test(password));
  }, 'Password contains common patterns or sequences');

// Password history model
interface PasswordHistory {
  id: string;
  userId: string;
  passwordHash: string;
  createdAt: Date;
}

export class PasswordSecurityService {
  private prisma: PrismaClient;
  private breachCheckEndpoint: string;
  private passwordHistoryLimit: number;

  constructor(
    prisma: PrismaClient,
    options: {
      breachCheckEndpoint?: string;
      passwordHistoryLimit?: number;
    } = {}
  ) {
    this.prisma = prisma;
    this.breachCheckEndpoint = options.breachCheckEndpoint || 'https://api.pwnedpasswords.com/range/';
    this.passwordHistoryLimit = options.passwordHistoryLimit || 5;
  }

  /**
   * Validate password against all security requirements
   */
  async validatePassword(password: string, userId?: string): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    // 1. Check complexity requirements
    try {
      PasswordSchema.parse(password);
    } catch (error) {
      if (error instanceof z.ZodError) {
        errors.push(...error.errors.map(e => e.message));
      }
    }

    // 2. Check against breach database
    const isBreached = await this.checkPasswordBreach(password);
    if (isBreached) {
      errors.push('This password has been found in a data breach and cannot be used');
    }

    // 3. Check password history if userId provided
    if (userId) {
      const isReused = await this.checkPasswordHistory(userId, password);
      if (isReused) {
        errors.push(`Password has been used recently. Please choose a different password`);
      }
    }

    // 4. Check for user-specific patterns
    if (userId) {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { username: true, email: true }
      });

      if (user) {
        const lowerPassword = password.toLowerCase();
        const patterns = [
          user.username.toLowerCase(),
          user.email.split('@')[0].toLowerCase(),
          user.email.split('@')[1].split('.')[0].toLowerCase()
        ];

        if (patterns.some(pattern => lowerPassword.includes(pattern) && pattern.length > 3)) {
          errors.push('Password should not contain your username or email');
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Hash password with bcrypt
   */
  async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }

  /**
   * Verify password against hash
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  /**
   * Check if password has been breached using Have I Been Pwned API
   */
  async checkPasswordBreach(password: string): Promise<boolean> {
    try {
      // Create SHA-1 hash of password
      const hash = crypto
        .createHash('sha1')
        .update(password)
        .digest('hex')
        .toUpperCase();

      // Take first 5 characters for k-anonymity
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);

      // Query the API
      const response = await fetch(`${this.breachCheckEndpoint}${prefix}`, {
        headers: {
          'User-Agent': 'SPARC-Security-Platform'
        }
      });

      if (!response.ok) {
        console.error('Failed to check password breach:', response.statusText);
        return false; // Fail open on API errors
      }

      const text = await response.text();
      const hashes = text.split('\n');

      // Check if our hash suffix appears in the results
      for (const line of hashes) {
        const [hashSuffix, count] = line.split(':');
        if (hashSuffix === suffix) {
          const breachCount = parseInt(count, 10);
          return breachCount > 0;
        }
      }

      return false;
    } catch (error) {
      console.error('Error checking password breach:', error);
      return false; // Fail open on errors
    }
  }

  /**
   * Check password against user's password history
   */
  async checkPasswordHistory(userId: string, password: string): Promise<boolean> {
    // Get user's password history
    const history = await this.prisma.$queryRaw<PasswordHistory[]>`
      SELECT * FROM password_history
      WHERE user_id = ${userId}
      ORDER BY created_at DESC
      LIMIT ${this.passwordHistoryLimit}
    `;

    // Check if password matches any in history
    for (const entry of history) {
      const matches = await this.verifyPassword(password, entry.passwordHash);
      if (matches) {
        return true;
      }
    }

    return false;
  }

  /**
   * Add password to user's history
   */
  async addToPasswordHistory(userId: string, passwordHash: string): Promise<void> {
    // Add new password to history
    await this.prisma.$executeRaw`
      INSERT INTO password_history (id, user_id, password_hash, created_at)
      VALUES (${crypto.randomUUID()}, ${userId}, ${passwordHash}, NOW())
    `;

    // Remove old entries beyond the limit
    await this.prisma.$executeRaw`
      DELETE FROM password_history
      WHERE user_id = ${userId}
      AND id NOT IN (
        SELECT id FROM password_history
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
        LIMIT ${this.passwordHistoryLimit}
      )
    `;
  }

  /**
   * Generate a secure random password
   */
  generateSecurePassword(length: number = 16): string {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    const all = uppercase + lowercase + numbers + special;

    let password = '';
    
    // Ensure at least one character from each category
    password += uppercase[crypto.randomInt(uppercase.length)];
    password += lowercase[crypto.randomInt(lowercase.length)];
    password += numbers[crypto.randomInt(numbers.length)];
    password += special[crypto.randomInt(special.length)];

    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
      password += all[crypto.randomInt(all.length)];
    }

    // Shuffle the password
    return password
      .split('')
      .sort(() => crypto.randomInt(3) - 1)
      .join('');
  }

  /**
   * Calculate password strength score
   */
  calculatePasswordStrength(password: string): {
    score: number; // 0-100
    strength: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
    feedback: string[];
  } {
    let score = 0;
    const feedback: string[] = [];

    // Length scoring
    if (password.length >= 12) score += 20;
    if (password.length >= 16) score += 10;
    if (password.length >= 20) score += 10;

    // Character variety
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/[0-9]/.test(password)) score += 10;
    if (/[^A-Za-z0-9]/.test(password)) score += 10;

    // Pattern checks
    if (!/(.)\1{2,}/.test(password)) score += 10; // No repeated characters
    if (!/password|admin|letmein|welcome/i.test(password)) score += 10; // No common words

    // Entropy estimation
    const charsets = [
      { regex: /[a-z]/, size: 26 },
      { regex: /[A-Z]/, size: 26 },
      { regex: /[0-9]/, size: 10 },
      { regex: /[^A-Za-z0-9]/, size: 32 }
    ];
    
    const activeCharsets = charsets.filter(cs => cs.regex.test(password));
    const possibleChars = activeCharsets.reduce((sum, cs) => sum + cs.size, 0);
    const entropy = password.length * Math.log2(possibleChars);
    
    if (entropy >= 60) score += 10;

    // Determine strength
    let strength: 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';
    if (score < 40) {
      strength = 'weak';
      feedback.push('Consider using a longer password with more character variety');
    } else if (score < 60) {
      strength = 'fair';
      feedback.push('Add more unique characters or increase length');
    } else if (score < 80) {
      strength = 'good';
      feedback.push('Good password, consider adding more complexity for sensitive accounts');
    } else if (score < 95) {
      strength = 'strong';
    } else {
      strength = 'very-strong';
    }

    return { score, strength, feedback };
  }
}

/**
 * Password policy configuration
 */
export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  preventReuse: number; // Number of previous passwords to check
  maxAge: number; // Days before password expires
  minAge: number; // Minimum days before password can be changed
  checkBreaches: boolean;
}

export const defaultPasswordPolicy: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventReuse: 5,
  maxAge: 90,
  minAge: 1,
  checkBreaches: true
};