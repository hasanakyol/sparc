import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import { BiometricService } from '../services/biometric-service';
import { BiometricEnrollmentSchema } from '../types/schemas';
import { authMiddleware } from '@shared/middleware/auth';

export function createBiometricRoutes(prisma: PrismaClient, config: any) {
  const app = new Hono();
  const biometricService = new BiometricService(prisma, config);

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Enroll biometric
  app.post('/:credentialId/biometric', zValidator('json', BiometricEnrollmentSchema), async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const biometricData = c.req.valid('json');
      const tenantId = c.get('tenantId');

      const result = await biometricService.enrollBiometric(
        credentialId,
        biometricData,
        tenantId
      );

      return c.json(result, 201);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Verify biometric
  app.post('/:credentialId/biometric/verify', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const { biometricType, template } = await c.req.json();

      if (!biometricType || !template) {
        return c.json({ error: 'Missing biometric data' }, 400);
      }

      const isValid = await biometricService.verifyBiometric(
        credentialId,
        biometricType,
        template
      );

      if (isValid) {
        return c.json({ verified: true });
      } else {
        const failResult = await biometricService.handleFailedAttempt(credentialId, biometricType);
        return c.json({ 
          verified: false,
          locked: failResult.locked,
          remainingAttempts: failResult.remainingAttempts
        }, 401);
      }
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // List enrolled biometrics
  app.get('/:credentialId/biometric', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      
      const biometrics = await biometricService.listBiometrics(credentialId);

      return c.json(biometrics);
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Delete biometric
  app.delete('/:credentialId/biometric/:type', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const biometricType = c.req.param('type');

      await biometricService.deleteBiometric(credentialId, biometricType);

      return c.json({ success: true });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Update biometric settings
  app.patch('/:credentialId/biometric/settings', async (c) => {
    try {
      const credentialId = c.req.param('credentialId');
      const settings = await c.req.json();

      await biometricService.updateBiometricSettings(credentialId, settings);

      return c.json({ success: true });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  return app;
}