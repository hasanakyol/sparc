import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';
import { BiometricEnrollment } from '../types/schemas';
import { BiometricConfig } from '../types';

export class BiometricService {
  private prisma: PrismaClient;
  private config: any;

  constructor(prisma: PrismaClient, config: any) {
    this.prisma = prisma;
    this.config = config;
  }

  async enrollBiometric(credentialId: string, biometricData: BiometricEnrollment, tenantId: string): Promise<any> {
    // Validate credential exists
    const credential = await this.prisma.mobileCredential.findFirst({
      where: { id: credentialId, tenantId }
    });

    if (!credential) {
      throw new Error('Credential not found');
    }

    // Validate biometric quality
    if (biometricData.quality < 0.7) {
      throw new Error('Biometric quality too low. Please try again.');
    }

    // Hash the biometric template
    const hashedTemplate = this.hashBiometricTemplate(biometricData.template);
    
    // Create biometric enrollment record
    const enrollment = await this.prisma.biometricEnrollment.create({
      data: {
        credentialId,
        type: biometricData.biometricType,
        templateHash: hashedTemplate,
        quality: biometricData.quality,
        liveness: biometricData.liveness,
        enrolledAt: new Date(),
        metadata: biometricData.metadata || {}
      }
    });

    // Update credential biometric settings
    await this.prisma.mobileCredential.update({
      where: { id: credentialId },
      data: {
        biometricSettings: {
          enabled: true,
          types: [biometricData.biometricType],
          fallbackToPin: true
        }
      }
    });

    // Log enrollment event
    await this.logBiometricEvent('biometric_enrolled', {
      credentialId,
      biometricType: biometricData.biometricType,
      quality: biometricData.quality,
      liveness: biometricData.liveness
    });

    return {
      enrollmentId: enrollment.id,
      biometricType: biometricData.biometricType,
      enrolled: true,
      quality: biometricData.quality,
      livenessCheck: biometricData.liveness
    };
  }

  async verifyBiometric(credentialId: string, biometricType: string, template: string): Promise<boolean> {
    // Get enrolled biometric
    const enrollment = await this.prisma.biometricEnrollment.findFirst({
      where: {
        credentialId,
        type: biometricType,
        status: 'active'
      }
    });

    if (!enrollment) {
      return false;
    }

    // Verify template hash
    const hashedTemplate = this.hashBiometricTemplate(template);
    const isMatch = enrollment.templateHash === hashedTemplate;

    // Log verification attempt
    await this.logBiometricEvent('biometric_verification', {
      credentialId,
      biometricType,
      success: isMatch
    });

    // Update last used timestamp
    if (isMatch) {
      await this.prisma.biometricEnrollment.update({
        where: { id: enrollment.id },
        data: { lastUsedAt: new Date() }
      });
    }

    return isMatch;
  }

  async deleteBiometric(credentialId: string, biometricType: string): Promise<void> {
    await this.prisma.biometricEnrollment.updateMany({
      where: {
        credentialId,
        type: biometricType
      },
      data: {
        status: 'deleted',
        deletedAt: new Date()
      }
    });

    await this.logBiometricEvent('biometric_deleted', {
      credentialId,
      biometricType
    });
  }

  async listBiometrics(credentialId: string): Promise<any[]> {
    const enrollments = await this.prisma.biometricEnrollment.findMany({
      where: {
        credentialId,
        status: 'active'
      },
      select: {
        id: true,
        type: true,
        quality: true,
        enrolledAt: true,
        lastUsedAt: true
      }
    });

    return enrollments;
  }

  async updateBiometricSettings(credentialId: string, settings: BiometricConfig): Promise<void> {
    await this.prisma.mobileCredential.update({
      where: { id: credentialId },
      data: {
        biometricSettings: settings
      }
    });
  }

  async handleFailedAttempt(credentialId: string, biometricType: string): Promise<{ locked: boolean; remainingAttempts: number }> {
    // Increment failed attempts
    const key = `biometric_attempts:${credentialId}:${biometricType}`;
    const attempts = await this.incrementAttempts(key);
    
    const maxAttempts = this.config.biometric?.maxAttempts || 5;
    const locked = attempts >= maxAttempts;
    
    if (locked) {
      // Lock biometric for specified duration
      await this.lockBiometric(credentialId, biometricType);
    }

    return {
      locked,
      remainingAttempts: Math.max(0, maxAttempts - attempts)
    };
  }

  private hashBiometricTemplate(template: string): string {
    return crypto.createHash('sha256')
      .update(template)
      .update(this.config.biometricSalt || 'sparc-biometric-salt')
      .digest('hex');
  }

  private async incrementAttempts(key: string): Promise<number> {
    // Implementation would use Redis for atomic increment
    // Simplified for this example
    return 1;
  }

  private async lockBiometric(credentialId: string, biometricType: string): Promise<void> {
    const lockDuration = this.config.biometric?.lockoutDuration || 300; // 5 minutes
    
    await this.prisma.biometricEnrollment.updateMany({
      where: {
        credentialId,
        type: biometricType
      },
      data: {
        lockedUntil: new Date(Date.now() + lockDuration * 1000)
      }
    });

    await this.logBiometricEvent('biometric_locked', {
      credentialId,
      biometricType,
      lockDuration
    });
  }

  private async logBiometricEvent(eventType: string, data: any): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        eventType,
        entityType: 'biometric',
        entityId: data.credentialId,
        metadata: data,
        ipAddress: data.ipAddress || null,
        userAgent: data.userAgent || null
      }
    });
  }
}