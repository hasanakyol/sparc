import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { OfflineSyncSchema } from '../types/schemas';
import { authMiddleware } from '@shared/middleware/auth';

export function createOfflineSyncRoutes(prisma: PrismaClient, redis: Redis, config: any) {
  const app = new Hono();

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Sync offline events
  app.post('/offline-events', zValidator('json', OfflineSyncSchema), async (c) => {
    try {
      const syncData = c.req.valid('json');
      const tenantId = c.get('tenantId');

      const results = {
        eventsProcessed: 0,
        credentialUpdatesProcessed: 0,
        meshMessagesProcessed: 0,
        errors: []
      };

      // Process offline events
      for (const event of syncData.events) {
        try {
          await processOfflineEvent(event, tenantId, prisma);
          results.eventsProcessed++;
        } catch (error: any) {
          results.errors.push({
            eventId: event.id,
            error: error.message
          });
        }
      }

      // Process credential updates
      if (syncData.credentialUpdates) {
        for (const update of syncData.credentialUpdates) {
          try {
            await processCredentialUpdate(update, tenantId, prisma, redis);
            results.credentialUpdatesProcessed++;
          } catch (error: any) {
            results.errors.push({
              credentialId: update.credentialId,
              error: error.message
            });
          }
        }
      }

      // Process mesh messages
      if (syncData.meshMessages && config.meshNetworkEnabled) {
        for (const message of syncData.meshMessages) {
          try {
            // Queue mesh messages for processing
            await redis.lpush('mesh_sync_queue', JSON.stringify(message));
            results.meshMessagesProcessed++;
          } catch (error: any) {
            results.errors.push({
              messageId: message.id,
              error: error.message
            });
          }
        }
      }

      // Update device sync timestamp
      await redis.set(
        `device_last_sync:${syncData.deviceId}`,
        new Date().toISOString(),
        'EX',
        86400 // 24 hours
      );

      return c.json({
        success: true,
        results,
        nextSyncToken: generateSyncToken(),
        syncTimestamp: new Date().toISOString()
      });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Get sync status
  app.get('/sync-status/:deviceId', async (c) => {
    try {
      const deviceId = c.req.param('deviceId');
      
      const lastSync = await redis.get(`device_last_sync:${deviceId}`);
      const pendingMessages = await redis.llen('mesh_sync_queue');
      
      return c.json({
        deviceId,
        lastSyncTime: lastSync,
        pendingMessages,
        syncRequired: !lastSync || (Date.now() - new Date(lastSync).getTime() > 3600000) // 1 hour
      });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Get pending updates for device
  app.get('/pending-updates/:deviceId', async (c) => {
    try {
      const deviceId = c.req.param('deviceId');
      const tenantId = c.get('tenantId');
      const lastSync = c.req.query('since');

      // Get credentials that need sync
      const credentials = await prisma.mobileCredential.findMany({
        where: {
          deviceInfo: {
            path: '$.deviceId',
            equals: deviceId
          },
          tenantId,
          updatedAt: lastSync ? { gt: new Date(lastSync) } : undefined
        },
        select: {
          id: true,
          status: true,
          updatedAt: true
        }
      });

      // Get pending revocations
      const revocations = await redis.smembers(`pending_revocations:${deviceId}`);

      return c.json({
        credentials,
        revocations,
        syncRequired: credentials.length > 0 || revocations.length > 0
      });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  return app;
}

async function processOfflineEvent(event: any, tenantId: string, prisma: PrismaClient): Promise<void> {
  // Verify event signature
  if (!verifyEventSignature(event)) {
    throw new Error('Invalid event signature');
  }

  // Log the offline event
  await prisma.auditLog.create({
    data: {
      eventType: `offline_${event.type}`,
      entityType: 'offline_event',
      entityId: event.id,
      tenantId,
      metadata: {
        ...event.data,
        offlineTimestamp: event.timestamp,
        syncedAt: new Date()
      }
    }
  });
}

async function processCredentialUpdate(update: any, tenantId: string, prisma: PrismaClient, redis: Redis): Promise<void> {
  const { credentialId, action, data } = update;

  switch (action) {
    case 'create':
      // Handle offline credential creation
      // This would typically be rejected as credentials should be created online
      throw new Error('Credential creation not allowed offline');
      
    case 'update':
      // Update credential with offline changes
      await prisma.mobileCredential.update({
        where: { id: credentialId },
        data: {
          metadata: {
            ...data,
            lastOfflineUpdate: update.timestamp
          }
        }
      });
      break;
      
    case 'revoke':
      // Process offline revocation
      await prisma.mobileCredential.update({
        where: { id: credentialId },
        data: {
          status: 'revoked',
          revokedAt: new Date(update.timestamp),
          revokedReason: data.reason || 'Offline revocation'
        }
      });
      
      // Remove from cache
      await redis.del(`credential:${credentialId}`);
      break;
  }
}

function verifyEventSignature(event: any): boolean {
  // In a real implementation, this would verify the cryptographic signature
  // of the offline event to ensure it hasn't been tampered with
  return true;
}

function generateSyncToken(): string {
  // Generate a unique sync token for the next sync operation
  return Buffer.from(Date.now().toString()).toString('base64');
}