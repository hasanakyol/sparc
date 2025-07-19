import { Hono } from 'hono';
import { authMiddleware } from '@shared/middleware/auth';

export function createMeshNetworkRoutes(config: any, meshNetwork: any) {
  const app = new Hono();

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Get mesh network status
  app.get('/status', async (c) => {
    try {
      if (!config.meshNetworkEnabled) {
        return c.json({
          enabled: false,
          message: 'Mesh networking is not enabled'
        });
      }

      const meshStatus = {
        enabled: true,
        nodeId: config.deviceId,
        connectedPeers: meshNetwork.meshPeers.size,
        messagesSent: await c.env.redis.get('mesh_messages_sent') || 0,
        messagesReceived: await c.env.redis.get('mesh_messages_received') || 0,
        lastHeartbeat: await c.env.redis.get('mesh_last_heartbeat'),
        networkHealth: 'healthy'
      };

      return c.json(meshStatus);
    } catch (error: any) {
      return c.json({ error: error.message }, 500);
    }
  });

  // Get mesh network peers
  app.get('/peers', async (c) => {
    try {
      if (!config.meshNetworkEnabled) {
        return c.json({ error: 'Mesh networking is not enabled' }, 400);
      }

      const peers = Array.from(meshNetwork.meshPeers.entries()).map(([id, peer]) => ({
        id,
        address: peer.address,
        port: peer.port,
        lastSeen: peer.lastSeen,
        status: peer.status
      }));

      return c.json(peers);
    } catch (error: any) {
      return c.json({ error: error.message }, 500);
    }
  });

  // Send mesh message
  app.post('/message', async (c) => {
    try {
      if (!config.meshNetworkEnabled) {
        return c.json({ error: 'Mesh networking is not enabled' }, 400);
      }

      const { type, targetDeviceId, payload } = await c.req.json();
      const tenantId = c.get('tenantId');

      if (!type || !payload) {
        return c.json({ error: 'Type and payload required' }, 400);
      }

      // Create and broadcast message
      const message = {
        id: crypto.randomUUID(),
        type,
        sourceDeviceId: config.deviceId,
        targetDeviceId,
        tenantId,
        payload,
        timestamp: new Date(),
        ttl: 30,
        signature: meshNetwork.signMessage(payload)
      };

      await meshNetwork.broadcastMessage(message);

      return c.json({
        success: true,
        messageId: message.id
      });
    } catch (error: any) {
      return c.json({ error: error.message }, 400);
    }
  });

  // Get message history
  app.get('/messages', async (c) => {
    try {
      const { limit = '50' } = c.req.query();
      
      // Get recent messages from cache
      const messages = [];
      for (const [messageId, timestamp] of meshNetwork.messageCache.entries()) {
        messages.push({
          messageId,
          receivedAt: timestamp
        });
      }

      // Sort by timestamp and limit
      messages.sort((a, b) => b.receivedAt.getTime() - a.receivedAt.getTime());
      
      return c.json(messages.slice(0, parseInt(limit)));
    } catch (error: any) {
      return c.json({ error: error.message }, 500);
    }
  });

  return app;
}