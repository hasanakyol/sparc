import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { CredentialService } from '../services/credential-service';
import { 
  MobileCredentialSchema, 
  RevocationRequestSchema,
  EnrollmentRequestSchema,
  AuthenticationRequestSchema
} from '../types/schemas';
import { authMiddleware } from '@shared/middleware/auth';

export function createCredentialsRoutes(prisma: PrismaClient, redis: Redis, config: any) {
  const app = new Hono();
  const credentialService = new CredentialService(prisma, redis, config);

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Enroll new mobile credential
  app.post('/enroll', zValidator('json', EnrollmentRequestSchema), async (c) => {
    try {
      const enrollmentData = c.req.valid('json');
      const user = c.get('user');
      const tenantId = c.get('tenantId');

      const result = await credentialService.enrollCredential(enrollmentData, user.id, tenantId);

      return c.json(result, 201);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Authenticate with mobile credential
  app.post('/authenticate', zValidator('json', AuthenticationRequestSchema), async (c) => {
    try {
      const authData = c.req.valid('json');
      
      const result = await credentialService.authenticateCredential(authData);

      if (result.valid) {
        return c.json({
          authenticated: true,
          details: result.details
        });
      } else {
        return c.json({
          authenticated: false,
          error: result.details.error
        }, 401);
      }
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Revoke credentials
  app.post('/revoke', zValidator('json', RevocationRequestSchema), async (c) => {
    try {
      const revocationData = c.req.valid('json');
      const user = c.get('user');
      const tenantId = c.get('tenantId');

      // Verify user has permission to revoke
      if (!user.permissions?.includes('credential.revoke')) {
        return c.json({ error: 'Insufficient permissions' }, 403);
      }

      await credentialService.revokeCredentials(
        revocationData.credentialIds,
        revocationData.reason,
        {
          immediate: revocationData.immediate,
          meshPropagation: revocationData.meshPropagation,
          remoteWipe: revocationData.remoteWipe,
          notifyUser: revocationData.notifyUser
        }
      );

      return c.json({ 
        success: true,
        revokedCount: revocationData.credentialIds.length
      });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // List user's credentials
  app.get('/', async (c) => {
    try {
      const user = c.get('user');
      const tenantId = c.get('tenantId');
      const { userId } = c.req.query();

      // Admin can query any user's credentials
      const targetUserId = (user.role === 'admin' && userId) ? userId : user.id;

      const credentials = await prisma.mobileCredential.findMany({
        where: {
          userId: targetUserId,
          tenantId,
          status: { not: 'revoked' }
        },
        select: {
          id: true,
          deviceInfo: true,
          credentialType: true,
          status: true,
          issuedAt: true,
          expiresAt: true,
          lastUsedAt: true,
          protocolSettings: true
        },
        orderBy: { issuedAt: 'desc' }
      });

      return c.json(credentials);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Get credential details
  app.get('/:credentialId', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const tenantId = c.get('tenantId');

      const credential = await prisma.mobileCredential.findFirst({
        where: { id: credentialId, tenantId },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              name: true
            }
          },
          accessGroups: true,
          auditLogs: {
            take: 10,
            orderBy: { createdAt: 'desc' }
          }
        }
      });

      if (!credential) {
        return c.json({ error: 'Credential not found' }, 404);
      }

      return c.json(credential);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Update credential status
  app.patch('/:credentialId/status', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const { status } = await c.req.json();
      const user = c.get('user');
      const tenantId = c.get('tenantId');

      if (!['active', 'suspended'].includes(status)) {
        return c.json({ error: 'Invalid status' }, 400);
      }

      // Verify user has permission
      if (!user.permissions?.includes('credential.manage')) {
        return c.json({ error: 'Insufficient permissions' }, 403);
      }

      const credential = await prisma.mobileCredential.findFirst({
        where: { id: credentialId, tenantId }
      });

      if (!credential) {
        return c.json({ error: 'Credential not found' }, 404);
      }

      await prisma.mobileCredential.update({
        where: { id: credentialId },
        data: {
          status,
          suspendedAt: status === 'suspended' ? new Date() : null,
          suspendedReason: status === 'suspended' ? 'Admin action' : null
        }
      });

      // Log status change
      await prisma.auditLog.create({
        data: {
          eventType: 'credential_status_changed',
          entityType: 'mobile_credential',
          entityId: credentialId,
          userId: user.id,
          tenantId,
          metadata: { oldStatus: credential.status, newStatus: status }
        }
      });

      return c.json({ success: true, status });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Generate authentication challenge
  app.post('/:credentialId/challenge', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const { readerId } = await c.req.json();

      if (!readerId) {
        return c.json({ error: 'Reader ID required' }, 400);
      }

      // Generate challenge
      const challenge = Buffer.from(Math.random().toString(36).substring(2) + Date.now()).toString('base64');
      
      // Store challenge with TTL
      await redis.setex(
        `challenge:${credentialId}:${readerId}`,
        300, // 5 minutes
        challenge
      );

      return c.json({
        challenge,
        expiresIn: 300,
        credentialId,
        readerId
      });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  return app;
}

// Validation schemas
const EnrollmentRequestSchema = z.object({
  deviceInfo: z.object({
    deviceId: z.string(),
    model: z.string(),
    os: z.string(),
    osVersion: z.string(),
    appVersion: z.string(),
    hardwareId: z.string().optional(),
    securityLevel: z.enum(['basic', 'enhanced', 'maximum']),
    jailbroken: z.boolean().optional()
  }),
  credentialData: z.object({
    type: z.enum(['pin', 'biometric', 'cryptographic', 'hybrid']),
    format: z.enum(['iso18013', 'iso14443', 'proprietary']),
    issuer: z.string(),
    expiresAt: z.string().optional()
  }),
  protocolSettings: z.object({
    ble: z.object({
      enabled: z.boolean(),
      config: z.any()
    }).optional(),
    nfc: z.object({
      enabled: z.boolean(),
      config: z.any()
    }).optional()
  }).optional(),
  biometricSettings: z.object({
    enabled: z.boolean(),
    types: z.array(z.enum(['fingerprint', 'face', 'voice', 'iris'])),
    fallbackToPin: z.boolean()
  }).optional(),
  meshNetworkEnabled: z.boolean().optional()
});

const AuthenticationRequestSchema = z.object({
  credentialId: z.string().uuid(),
  challenge: z.string().optional(),
  signature: z.string().optional(),
  timestamp: z.string(),
  protocol: z.enum(['standard', 'ble', 'nfc']).optional(),
  protocolSpecific: z.object({
    bleData: z.object({
      rssi: z.number(),
      txPower: z.number(),
      connectionId: z.string(),
      serviceData: z.string()
    }).optional(),
    nfcData: z.object({
      technology: z.string(),
      uid: z.string(),
      atqa: z.string().optional(),
      sak: z.string().optional(),
      applicationData: z.string()
    }).optional()
  }).optional(),
  offlineValidation: z.object({
    enabled: z.boolean(),
    cryptographicProof: z.string(),
    localTimestamp: z.number(),
    sequenceNumber: z.number()
  }).optional()
});