import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { NotificationService } from '../services/notification.service';
import { notificationPreferencesSchema } from '@sparc/shared/types/alerts';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import Redis from 'ioredis';
import { z } from 'zod';

const notificationsRouter = new Hono();

// Initialize services
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const notificationService = new NotificationService(redis);

// Apply auth middleware to all routes
notificationsRouter.use('*', authMiddleware);

// Get notification preferences
notificationsRouter.get('/preferences', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string | undefined;

    const preferences = await notificationService.getNotificationPreferences(tenantId, userId);

    if (!preferences) {
      // Return default preferences if none exist
      return c.json({
        preferences: {
          email: true,
          sms: false,
          push: true,
          criticalOnly: false
        }
      });
    }

    return c.json({ preferences });
  } catch (error) {
    logger.error('Failed to fetch notification preferences', { error });
    throw new HTTPException(500, { message: 'Failed to fetch preferences' });
  }
});

// Update notification preferences
notificationsRouter.put('/preferences', zValidator('json', notificationPreferencesSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string | undefined;
    const updates = c.req.valid('json');

    const preferences = await notificationService.updateNotificationPreferences(
      tenantId,
      userId,
      {
        email: updates.email !== undefined 
          ? { enabled: updates.email, addresses: [] }
          : undefined,
        sms: updates.sms !== undefined 
          ? { enabled: updates.sms, numbers: [] }
          : undefined,
        push: updates.push !== undefined 
          ? { enabled: updates.push, subscriptions: [] }
          : undefined,
        criticalOnly: updates.criticalOnly
      }
    );

    logger.info('Notification preferences updated', { 
      tenantId, 
      userId,
      updates 
    });

    return c.json({ preferences });
  } catch (error) {
    logger.error('Failed to update notification preferences', { error });
    throw new HTTPException(500, { message: 'Failed to update preferences' });
  }
});

// Add email addresses to preferences
const emailAddressesSchema = z.object({
  addresses: z.array(z.string().email())
});

notificationsRouter.post('/preferences/email', zValidator('json', emailAddressesSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string | undefined;
    const { addresses } = c.req.valid('json');

    const currentPrefs = await notificationService.getNotificationPreferences(tenantId, userId);
    
    if (!currentPrefs) {
      throw new HTTPException(404, { message: 'Preferences not found' });
    }

    const updatedPrefs = await notificationService.updateNotificationPreferences(
      tenantId,
      userId,
      {
        email: {
          enabled: currentPrefs.email.enabled,
          addresses: [...new Set([...currentPrefs.email.addresses, ...addresses])]
        }
      }
    );

    logger.info('Email addresses added', { 
      tenantId, 
      userId,
      addedCount: addresses.length 
    });

    return c.json({ preferences: updatedPrefs });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to add email addresses', { error });
    throw new HTTPException(500, { message: 'Failed to add email addresses' });
  }
});

// Remove email addresses from preferences
notificationsRouter.delete('/preferences/email', zValidator('json', emailAddressesSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string | undefined;
    const { addresses } = c.req.valid('json');

    const currentPrefs = await notificationService.getNotificationPreferences(tenantId, userId);
    
    if (!currentPrefs) {
      throw new HTTPException(404, { message: 'Preferences not found' });
    }

    const updatedPrefs = await notificationService.updateNotificationPreferences(
      tenantId,
      userId,
      {
        email: {
          enabled: currentPrefs.email.enabled,
          addresses: currentPrefs.email.addresses.filter(addr => !addresses.includes(addr))
        }
      }
    );

    logger.info('Email addresses removed', { 
      tenantId, 
      userId,
      removedCount: addresses.length 
    });

    return c.json({ preferences: updatedPrefs });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to remove email addresses', { error });
    throw new HTTPException(500, { message: 'Failed to remove email addresses' });
  }
});

// Add SMS numbers to preferences
const smsNumbersSchema = z.object({
  numbers: z.array(z.string().regex(/^\+?[1-9]\d{1,14}$/))
});

notificationsRouter.post('/preferences/sms', zValidator('json', smsNumbersSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string | undefined;
    const { numbers } = c.req.valid('json');

    const currentPrefs = await notificationService.getNotificationPreferences(tenantId, userId);
    
    if (!currentPrefs) {
      throw new HTTPException(404, { message: 'Preferences not found' });
    }

    const updatedPrefs = await notificationService.updateNotificationPreferences(
      tenantId,
      userId,
      {
        sms: {
          enabled: currentPrefs.sms.enabled,
          numbers: [...new Set([...currentPrefs.sms.numbers, ...numbers])]
        }
      }
    );

    logger.info('SMS numbers added', { 
      tenantId, 
      userId,
      addedCount: numbers.length 
    });

    return c.json({ preferences: updatedPrefs });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to add SMS numbers', { error });
    throw new HTTPException(500, { message: 'Failed to add SMS numbers' });
  }
});

// Web Push subscription management
const pushSubscriptionSchema = z.object({
  endpoint: z.string().url(),
  keys: z.object({
    p256dh: z.string(),
    auth: z.string()
  })
});

notificationsRouter.post('/preferences/push/subscribe', zValidator('json', pushSubscriptionSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string | undefined;
    const subscription = c.req.valid('json');

    const currentPrefs = await notificationService.getNotificationPreferences(tenantId, userId);
    
    if (!currentPrefs) {
      throw new HTTPException(404, { message: 'Preferences not found' });
    }

    // Check if subscription already exists
    const existingIndex = currentPrefs.push.subscriptions.findIndex(
      sub => sub.endpoint === subscription.endpoint
    );

    let updatedSubscriptions;
    if (existingIndex >= 0) {
      // Update existing subscription
      updatedSubscriptions = [...currentPrefs.push.subscriptions];
      updatedSubscriptions[existingIndex] = subscription;
    } else {
      // Add new subscription
      updatedSubscriptions = [...currentPrefs.push.subscriptions, subscription];
    }

    const updatedPrefs = await notificationService.updateNotificationPreferences(
      tenantId,
      userId,
      {
        push: {
          enabled: currentPrefs.push.enabled,
          subscriptions: updatedSubscriptions
        }
      }
    );

    // Store subscription in Redis for quick access
    await redis.sadd(
      `push_subscriptions:${tenantId}`,
      JSON.stringify(subscription)
    );

    logger.info('Push subscription added', { 
      tenantId, 
      userId,
      endpoint: subscription.endpoint 
    });

    return c.json({ 
      message: 'Push subscription registered successfully',
      preferences: updatedPrefs 
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to register push subscription', { error });
    throw new HTTPException(500, { message: 'Failed to register push subscription' });
  }
});

// Webhook URL management
const webhookUrlsSchema = z.object({
  urls: z.array(z.string().url())
});

notificationsRouter.post('/preferences/webhook', zValidator('json', webhookUrlsSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string | undefined;
    const { urls } = c.req.valid('json');

    const currentPrefs = await notificationService.getNotificationPreferences(tenantId, userId);
    
    if (!currentPrefs) {
      throw new HTTPException(404, { message: 'Preferences not found' });
    }

    const updatedPrefs = await notificationService.updateNotificationPreferences(
      tenantId,
      userId,
      {
        webhook: {
          enabled: currentPrefs.webhook.enabled,
          urls: [...new Set([...currentPrefs.webhook.urls, ...urls])]
        }
      }
    );

    logger.info('Webhook URLs added', { 
      tenantId, 
      userId,
      addedCount: urls.length 
    });

    return c.json({ preferences: updatedPrefs });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to add webhook URLs', { error });
    throw new HTTPException(500, { message: 'Failed to add webhook URLs' });
  }
});

// Test notification endpoint
const testNotificationSchema = z.object({
  type: z.enum(['email', 'sms', 'push', 'webhook']),
  recipient: z.string().optional()
});

notificationsRouter.post('/test', zValidator('json', testNotificationSchema), async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const { type, recipient } = c.req.valid('json');

    // Create a test alert
    const testAlert = {
      id: 'test-' + Date.now(),
      tenantId,
      alertType: 'maintenance_required' as const,
      priority: 'low' as const,
      sourceId: 'test-source',
      sourceType: 'system' as const,
      message: 'This is a test notification',
      details: { test: true, requestedBy: userId },
      status: 'open' as const,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Send test notification based on type
    const preferences = await notificationService.getNotificationPreferences(tenantId, userId);
    
    if (!preferences) {
      throw new HTTPException(404, { message: 'Notification preferences not found' });
    }

    // Temporarily override preferences to send only the requested type
    const testPrefs = {
      ...preferences,
      email: { ...preferences.email, enabled: type === 'email' },
      sms: { ...preferences.sms, enabled: type === 'sms' },
      push: { ...preferences.push, enabled: type === 'push' },
      webhook: { ...preferences.webhook, enabled: type === 'webhook' },
      criticalOnly: false
    };

    // If recipient is provided, use it for the test
    if (recipient) {
      switch (type) {
        case 'email':
          testPrefs.email.addresses = [recipient];
          break;
        case 'sms':
          testPrefs.sms.numbers = [recipient];
          break;
        case 'webhook':
          testPrefs.webhook.urls = [recipient];
          break;
      }
    }

    // Send the test notification
    await notificationService.sendNotifications(testAlert);

    logger.info('Test notification sent', { 
      tenantId, 
      userId,
      type,
      recipient 
    });

    return c.json({ 
      message: `Test ${type} notification sent successfully`,
      testAlertId: testAlert.id
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to send test notification', { error });
    throw new HTTPException(500, { message: 'Failed to send test notification' });
  }
});

export default notificationsRouter;