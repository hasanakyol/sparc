import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import { NotificationService } from '../notification.service';
import Redis from 'ioredis';
import nodemailer from 'nodemailer';
import twilio from 'twilio';
import webpush from 'web-push';
import { db } from '../../db';
import type { Alert, NotificationPreferences } from '@sparc/shared/types/alerts';

// Mock dependencies
jest.mock('../../db');
jest.mock('ioredis');
jest.mock('nodemailer');
jest.mock('twilio');
jest.mock('web-push');
jest.mock('../alert.service');

const mockRedis = {
  get: jest.fn(),
  setex: jest.fn(),
  del: jest.fn(),
  sadd: jest.fn(),
};

const mockEmailTransporter = {
  sendMail: jest.fn(),
  verify: jest.fn(),
};

const mockTwilioClient = {
  messages: {
    create: jest.fn(),
  },
};

const mockDb = {
  select: jest.fn(),
  insert: jest.fn(),
  update: jest.fn(),
};

describe('NotificationService', () => {
  let notificationService: NotificationService;
  let redisInstance: any;

  const mockAlert: Alert = {
    id: 'test-alert-id',
    tenantId: 'test-tenant',
    alertType: 'system_offline',
    priority: 'critical',
    sourceId: 'test-source',
    sourceType: 'system',
    message: 'Critical system failure',
    details: { severity: 'high' },
    status: 'open',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockPreferences: NotificationPreferences = {
    id: 'pref-id',
    tenantId: 'test-tenant',
    email: {
      enabled: true,
      addresses: ['test@example.com', 'admin@example.com'],
    },
    sms: {
      enabled: true,
      numbers: ['+1234567890'],
    },
    push: {
      enabled: true,
      subscriptions: [{
        endpoint: 'https://fcm.googleapis.com/push/abc',
        keys: {
          p256dh: 'test-key',
          auth: 'test-auth',
        },
      }],
    },
    webhook: {
      enabled: true,
      urls: ['https://webhook.example.com/alerts'],
    },
    criticalOnly: false,
    preferences: {},
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    redisInstance = mockRedis as any;
    
    // Mock nodemailer
    (nodemailer.createTransport as jest.Mock).mockReturnValue(mockEmailTransporter);
    
    // Mock Twilio
    (twilio as unknown as jest.Mock).mockReturnValue(mockTwilioClient);
    
    // Mock webpush
    (webpush.setVapidDetails as jest.Mock).mockImplementation(() => {});
    (webpush.sendNotification as jest.Mock).mockResolvedValue({});
    
    // Mock database
    (db.select as jest.Mock).mockReturnValue({
      from: jest.fn().mockReturnValue({
        where: jest.fn().mockReturnValue({
          limit: jest.fn().mockResolvedValue([mockPreferences]),
        }),
      }),
    });

    // Mock fetch for webhook notifications
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
    }) as jest.Mock;

    notificationService = new NotificationService(redisInstance);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('sendNotifications', () => {
    it('should send all enabled notification types for critical alerts', async () => {
      mockRedis.get.mockResolvedValue(null);

      await notificationService.sendNotifications(mockAlert);

      // Verify email was sent
      expect(mockEmailTransporter.sendMail).toHaveBeenCalledWith({
        from: expect.any(String),
        to: 'test@example.com,admin@example.com',
        subject: '[CRITICAL] system offline - Critical system failure',
        html: expect.stringContaining('Critical system failure'),
      });

      // Verify SMS was sent
      expect(mockTwilioClient.messages.create).toHaveBeenCalledWith({
        body: '[CRITICAL] system offline: Critical system failure',
        from: expect.any(String),
        to: '+1234567890',
      });

      // Verify push notification was sent
      expect(webpush.sendNotification).toHaveBeenCalledWith(
        mockPreferences.push.subscriptions[0],
        expect.stringContaining('CRITICAL Alert'),
      );

      // Verify webhook was called
      expect(global.fetch).toHaveBeenCalledWith(
        'https://webhook.example.com/alerts',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-SPARC-Alert-ID': 'test-alert-id',
            'X-SPARC-Tenant-ID': 'test-tenant',
          }),
          body: expect.stringContaining('test-alert-id'),
        }),
      );
    });

    it('should respect criticalOnly preference', async () => {
      const lowPriorityAlert: Alert = {
        ...mockAlert,
        priority: 'low',
      };

      const criticalOnlyPrefs = {
        ...mockPreferences,
        criticalOnly: true,
      };

      (db.select as jest.Mock).mockReturnValue({
        from: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue([criticalOnlyPrefs]),
          }),
        }),
      });

      await notificationService.sendNotifications(lowPriorityAlert);

      expect(mockEmailTransporter.sendMail).not.toHaveBeenCalled();
      expect(mockTwilioClient.messages.create).not.toHaveBeenCalled();
      expect(webpush.sendNotification).not.toHaveBeenCalled();
      expect(global.fetch).not.toHaveBeenCalled();
    });

    it('should skip SMS for low priority alerts', async () => {
      const lowPriorityAlert: Alert = {
        ...mockAlert,
        priority: 'low',
      };

      await notificationService.sendNotifications(lowPriorityAlert);

      expect(mockEmailTransporter.sendMail).toHaveBeenCalled();
      expect(mockTwilioClient.messages.create).not.toHaveBeenCalled();
      expect(webpush.sendNotification).toHaveBeenCalled();
    });

    it('should handle notification failures gracefully', async () => {
      mockEmailTransporter.sendMail.mockRejectedValue(new Error('Email failed'));
      mockTwilioClient.messages.create.mockRejectedValue(new Error('SMS failed'));
      webpush.sendNotification.mockRejectedValue(new Error('Push failed'));
      (global.fetch as jest.Mock).mockRejectedValue(new Error('Webhook failed'));

      // Should not throw
      await expect(notificationService.sendNotifications(mockAlert)).resolves.not.toThrow();
    });

    it('should use default preferences when none exist', async () => {
      (db.select as jest.Mock).mockReturnValue({
        from: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue([]),
          }),
        }),
      });

      await notificationService.sendNotifications(mockAlert);

      // Should not send any notifications with default (empty) preferences
      expect(mockEmailTransporter.sendMail).not.toHaveBeenCalled();
      expect(mockTwilioClient.messages.create).not.toHaveBeenCalled();
      expect(webpush.sendNotification).not.toHaveBeenCalled();
    });
  });

  describe('getNotificationPreferences', () => {
    it('should return cached preferences if available', async () => {
      const cachedPrefs = JSON.stringify(mockPreferences);
      mockRedis.get.mockResolvedValue(cachedPrefs);

      const prefs = await notificationService.getNotificationPreferences('test-tenant', 'user-123');

      expect(prefs).toEqual(mockPreferences);
      expect(mockRedis.get).toHaveBeenCalledWith('notification_prefs:test-tenant:user-123');
      expect(db.select).not.toHaveBeenCalled();
    });

    it('should fetch from database if not cached', async () => {
      mockRedis.get.mockResolvedValue(null);

      const prefs = await notificationService.getNotificationPreferences('test-tenant');

      expect(prefs).toBeDefined();
      expect(db.select).toHaveBeenCalled();
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'notification_prefs:test-tenant',
        3600,
        expect.any(String),
      );
    });

    it('should return default preferences if none exist', async () => {
      mockRedis.get.mockResolvedValue(null);
      (db.select as jest.Mock).mockReturnValue({
        from: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue([]),
          }),
        }),
      });

      const prefs = await notificationService.getNotificationPreferences('test-tenant');

      expect(prefs).toBeDefined();
      expect(prefs?.email.enabled).toBe(true);
      expect(prefs?.email.addresses).toEqual([]);
      expect(prefs?.sms.enabled).toBe(false);
      expect(prefs?.push.enabled).toBe(true);
      expect(prefs?.criticalOnly).toBe(false);
    });
  });

  describe('updateNotificationPreferences', () => {
    it('should update existing preferences', async () => {
      const updates = {
        email: { enabled: false, addresses: [] },
        criticalOnly: true,
      };

      (db.select as jest.Mock).mockReturnValue({
        from: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue([mockPreferences]),
          }),
        }),
      });

      (db.update as jest.Mock).mockReturnValue({
        set: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            returning: jest.fn().mockResolvedValue([{
              ...mockPreferences,
              email: updates.email,
              criticalOnly: 'true',
            }]),
          }),
        }),
      });

      const updatedPrefs = await notificationService.updateNotificationPreferences(
        'test-tenant',
        'user-123',
        updates,
      );

      expect(updatedPrefs.email.enabled).toBe(false);
      expect(updatedPrefs.criticalOnly).toBe(true);
      expect(db.update).toHaveBeenCalled();
      expect(mockRedis.del).toHaveBeenCalledWith('notification_prefs:test-tenant:user-123');
    });

    it('should create new preferences if none exist', async () => {
      (db.select as jest.Mock).mockReturnValue({
        from: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue([]),
          }),
        }),
      });

      (db.insert as jest.Mock).mockReturnValue({
        values: jest.fn().mockReturnValue({
          returning: jest.fn().mockResolvedValue([mockPreferences]),
        }),
      });

      const updates = {
        email: { enabled: true, addresses: ['new@example.com'] },
      };

      const newPrefs = await notificationService.updateNotificationPreferences(
        'test-tenant',
        undefined,
        updates,
      );

      expect(newPrefs).toBeDefined();
      expect(db.insert).toHaveBeenCalled();
    });
  });

  describe('Email notifications', () => {
    it('should format email HTML correctly', async () => {
      await notificationService.sendNotifications(mockAlert);

      const emailCall = mockEmailTransporter.sendMail.mock.calls[0][0];
      expect(emailCall.html).toContain('Alert Notification');
      expect(emailCall.html).toContain('CRITICAL');
      expect(emailCall.html).toContain('Critical system failure');
      expect(emailCall.html).toContain('system offline');
      expect(emailCall.html).toContain('test-alert-id');
    });

    it('should handle multiple email addresses', async () => {
      await notificationService.sendNotifications(mockAlert);

      expect(mockEmailTransporter.sendMail).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'test@example.com,admin@example.com',
        }),
      );
    });
  });

  describe('Push notifications', () => {
    it('should remove invalid subscriptions on 410 error', async () => {
      const error410 = new Error('Received unexpected response code: 410');
      webpush.sendNotification.mockRejectedValue(error410);

      (db.update as jest.Mock).mockReturnValue({
        set: jest.fn().mockReturnValue({
          where: jest.fn().mockReturnValue({
            returning: jest.fn().mockResolvedValue([{
              ...mockPreferences,
              push: { enabled: true, subscriptions: [] },
            }]),
          }),
        }),
      });

      await notificationService.sendNotifications(mockAlert);

      expect(db.update).toHaveBeenCalled();
    });

    it('should format push notification payload correctly', async () => {
      await notificationService.sendNotifications(mockAlert);

      const pushCall = webpush.sendNotification.mock.calls[0];
      const payload = JSON.parse(pushCall[1]);

      expect(payload.title).toBe('CRITICAL Alert');
      expect(payload.body).toBe('Critical system failure');
      expect(payload.data.alertId).toBe('test-alert-id');
      expect(payload.data.alertType).toBe('system_offline');
      expect(payload.data.priority).toBe('critical');
    });
  });

  describe('Webhook notifications', () => {
    it('should include proper headers in webhook request', async () => {
      await notificationService.sendNotifications(mockAlert);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://webhook.example.com/alerts',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-SPARC-Alert-ID': 'test-alert-id',
            'X-SPARC-Tenant-ID': 'test-tenant',
          }),
        }),
      );
    });

    it('should handle webhook failures', async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      // Should not throw
      await expect(notificationService.sendNotifications(mockAlert)).resolves.not.toThrow();
    });
  });
});