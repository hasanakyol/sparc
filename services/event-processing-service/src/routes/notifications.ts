import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { NotificationService } from '../services/notification-service';

// Notification schemas
const NotificationPreferencesSchema = z.object({
  email: z.object({
    enabled: z.boolean(),
    minSeverity: z.enum(['low', 'medium', 'high', 'critical']),
    recipients: z.array(z.string().email())
  }),
  sms: z.object({
    enabled: z.boolean(),
    minSeverity: z.enum(['low', 'medium', 'high', 'critical']),
    recipients: z.array(z.string())
  }),
  push: z.object({
    enabled: z.boolean(),
    minSeverity: z.enum(['low', 'medium', 'high', 'critical'])
  })
});

const TestNotificationSchema = z.object({
  channel: z.enum(['email', 'sms', 'push']),
  recipient: z.string(),
  message: z.string()
});

const PushSubscriptionSchema = z.object({
  endpoint: z.string().url(),
  keys: z.object({
    p256dh: z.string(),
    auth: z.string()
  })
});

export function createNotificationRoutes(notificationService: NotificationService): Hono {
  const app = new Hono();

  // Get notification preferences
  app.get('/preferences', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      
      const preferences = await notificationService.getPreferences(tenantId);
      
      return c.json({ preferences });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch notification preferences' });
    }
  });

  // Update notification preferences
  app.put('/preferences', zValidator('json', NotificationPreferencesSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const preferences = c.req.valid('json');
      
      await notificationService.updatePreferences(tenantId, preferences);
      
      return c.json({ 
        message: 'Notification preferences updated',
        preferences
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to update notification preferences' });
    }
  });

  // Test notification
  app.post('/test', zValidator('json', TestNotificationSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { channel, recipient, message } = c.req.valid('json');
      
      const result = await notificationService.sendTestNotification(
        tenantId,
        channel,
        recipient,
        message
      );
      
      if (!result.success) {
        throw new HTTPException(400, { message: result.error || 'Failed to send test notification' });
      }
      
      return c.json({ 
        message: 'Test notification sent',
        channel,
        recipient
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to send test notification' });
    }
  });

  // Subscribe to push notifications
  app.post('/push/subscribe', zValidator('json', PushSubscriptionSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const userId = c.get('userId');
      const subscription = c.req.valid('json');
      
      await notificationService.subscribePush(tenantId, userId, subscription);
      
      return c.json({ 
        message: 'Push notification subscription added'
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to subscribe to push notifications' });
    }
  });

  // Unsubscribe from push notifications
  app.post('/push/unsubscribe', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const userId = c.get('userId');
      const { endpoint } = await c.req.json();
      
      await notificationService.unsubscribePush(tenantId, userId, endpoint);
      
      return c.json({ 
        message: 'Push notification subscription removed'
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to unsubscribe from push notifications' });
    }
  });

  // Get notification history
  app.get('/history', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { limit = '100', offset = '0' } = c.req.query();
      
      const history = await notificationService.getNotificationHistory(tenantId, {
        limit: parseInt(limit),
        offset: parseInt(offset)
      });
      
      return c.json({ 
        notifications: history,
        count: history.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch notification history' });
    }
  });

  // Get notification statistics
  app.get('/stats', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const { period = '24h' } = c.req.query();
      
      const stats = await notificationService.getStatistics(tenantId, period);
      
      return c.json({ 
        statistics: stats,
        period
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to fetch notification statistics' });
    }
  });

  // Retry failed notifications
  app.post('/retry', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      
      const result = await notificationService.retryFailedNotifications(tenantId);
      
      return c.json({ 
        message: 'Failed notifications retry initiated',
        retried: result.retried,
        successful: result.successful,
        failed: result.failed
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to retry notifications' });
    }
  });

  // Get VAPID public key for push notifications
  app.get('/push/vapid-key', (c) => {
    try {
      const publicKey = notificationService.getVapidPublicKey();
      
      if (!publicKey) {
        throw new HTTPException(503, { message: 'Push notifications not configured' });
      }
      
      return c.json({ 
        publicKey
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'Failed to get VAPID public key' });
    }
  });

  return app;
}