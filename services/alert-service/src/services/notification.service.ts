import { Redis } from 'ioredis';
import nodemailer from 'nodemailer';
import twilio from 'twilio';
import webpush from 'web-push';
import { db } from '../db';
import { notificationPreferences } from '@sparc/database/schemas/alerts';
import { eq, and } from 'drizzle-orm';
import type { Alert, AlertPriority, NotificationPreferences } from '@sparc/shared/types/alerts';
import { config, logger } from '@sparc/shared';
import { AlertService } from './alert.service';

export class NotificationService {
  private emailTransporter: nodemailer.Transporter;
  private twilioClient: twilio.Twilio;
  private alertService: AlertService;

  constructor(private redis: Redis) {
    this.alertService = new AlertService(redis);

    // Initialize email transporter
    this.emailTransporter = nodemailer.createTransport({
      host: config.notifications?.smtp?.host || process.env.SMTP_HOST,
      port: config.notifications?.smtp?.port || 587,
      secure: config.notifications?.smtp?.secure || false,
      auth: {
        user: config.notifications?.smtp?.user || process.env.SMTP_USER,
        pass: config.notifications?.smtp?.password || process.env.SMTP_PASSWORD
      }
    });

    // Initialize Twilio client
    this.twilioClient = twilio(
      config.notifications?.twilio?.accountSid || process.env.TWILIO_ACCOUNT_SID,
      config.notifications?.twilio?.authToken || process.env.TWILIO_AUTH_TOKEN
    );

    // Configure web push
    webpush.setVapidDetails(
      config.notifications?.webpush?.subject || process.env.WEBPUSH_SUBJECT || 'mailto:alerts@sparc.io',
      config.notifications?.webpush?.publicKey || process.env.WEBPUSH_PUBLIC_KEY!,
      config.notifications?.webpush?.privateKey || process.env.WEBPUSH_PRIVATE_KEY!
    );
  }

  async sendNotifications(alert: Alert): Promise<void> {
    try {
      const preferences = await this.getNotificationPreferences(alert.tenantId);
      
      if (!preferences) {
        logger.warn('No notification preferences found', { tenantId: alert.tenantId });
        return;
      }

      // Check if only critical alerts should be sent
      if (preferences.criticalOnly && alert.priority !== 'critical') {
        return;
      }

      // Send notifications based on preferences
      const promises: Promise<void>[] = [];

      if (preferences.email.enabled) {
        promises.push(this.sendEmailNotification(alert, preferences));
      }

      if (preferences.sms.enabled && ['high', 'critical'].includes(alert.priority)) {
        promises.push(this.sendSMSNotification(alert, preferences));
      }

      if (preferences.push.enabled) {
        promises.push(this.sendPushNotification(alert, preferences));
      }

      if (preferences.webhook.enabled) {
        promises.push(this.sendWebhookNotification(alert, preferences));
      }

      await Promise.allSettled(promises);
    } catch (error) {
      logger.error('Failed to send notifications', { error, alertId: alert.id });
    }
  }

  async getNotificationPreferences(
    tenantId: string,
    userId?: string
  ): Promise<NotificationPreferences | null> {
    // Check cache first
    const cacheKey = userId 
      ? `notification_prefs:${tenantId}:${userId}`
      : `notification_prefs:${tenantId}`;
    
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Query database
    const conditions = [eq(notificationPreferences.tenantId, tenantId)];
    if (userId) {
      conditions.push(eq(notificationPreferences.userId, userId));
    }

    const [prefs] = await db.select()
      .from(notificationPreferences)
      .where(and(...conditions))
      .limit(1);

    if (!prefs) {
      // Return default preferences
      const defaultPrefs: NotificationPreferences = {
        id: '',
        tenantId,
        userId,
        email: { enabled: true, addresses: [] },
        sms: { enabled: false, numbers: [] },
        push: { enabled: true, subscriptions: [] },
        webhook: { enabled: false, urls: [] },
        criticalOnly: false,
        preferences: {},
        createdAt: new Date(),
        updatedAt: new Date()
      };
      return defaultPrefs;
    }

    const mapped = this.mapToNotificationPreferences(prefs);
    
    // Cache for 1 hour
    await this.redis.setex(cacheKey, 3600, JSON.stringify(mapped));
    
    return mapped;
  }

  async updateNotificationPreferences(
    tenantId: string,
    userId: string | undefined,
    updates: Partial<NotificationPreferences>
  ): Promise<NotificationPreferences> {
    const conditions = [eq(notificationPreferences.tenantId, tenantId)];
    if (userId) {
      conditions.push(eq(notificationPreferences.userId, userId));
    }

    // Check if preferences exist
    const [existing] = await db.select()
      .from(notificationPreferences)
      .where(and(...conditions))
      .limit(1);

    let result;
    if (existing) {
      // Update existing
      [result] = await db.update(notificationPreferences)
        .set({
          email: updates.email || existing.email,
          sms: updates.sms || existing.sms,
          push: updates.push || existing.push,
          webhook: updates.webhook || existing.webhook,
          criticalOnly: updates.criticalOnly?.toString() || existing.criticalOnly,
          preferences: updates.preferences || existing.preferences,
          updatedAt: new Date()
        })
        .where(and(...conditions))
        .returning();
    } else {
      // Create new
      [result] = await db.insert(notificationPreferences)
        .values({
          tenantId,
          userId,
          email: updates.email || { enabled: true, addresses: [] },
          sms: updates.sms || { enabled: false, numbers: [] },
          push: updates.push || { enabled: true, subscriptions: [] },
          webhook: updates.webhook || { enabled: false, urls: [] },
          criticalOnly: (updates.criticalOnly || false).toString(),
          preferences: updates.preferences || {},
          createdAt: new Date(),
          updatedAt: new Date()
        })
        .returning();
    }

    // Clear cache
    const cacheKey = userId 
      ? `notification_prefs:${tenantId}:${userId}`
      : `notification_prefs:${tenantId}`;
    await this.redis.del(cacheKey);

    return this.mapToNotificationPreferences(result);
  }

  private async sendEmailNotification(
    alert: Alert,
    preferences: NotificationPreferences
  ): Promise<void> {
    if (!preferences.email.addresses || preferences.email.addresses.length === 0) {
      return;
    }

    const notificationId = await this.alertService.trackNotification(
      alert.id,
      'email',
      undefined,
      preferences.email.addresses.join(',')
    );

    try {
      const subject = `[${alert.priority.toUpperCase()}] ${alert.alertType.replace(/_/g, ' ')} - ${alert.message}`;
      const html = this.generateEmailHTML(alert);

      await this.emailTransporter.sendMail({
        from: config.notifications?.smtp?.from || process.env.SMTP_FROM || 'alerts@sparc.io',
        to: preferences.email.addresses.join(','),
        subject,
        html
      });

      await this.alertService.updateNotificationStatus(notificationId, 'delivered');
      
      logger.info('Email notification sent', {
        alertId: alert.id,
        recipients: preferences.email.addresses.length
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await this.alertService.updateNotificationStatus(notificationId, 'failed', errorMessage);
      logger.error('Failed to send email notification', { error: errorMessage, alertId: alert.id });
    }
  }

  private async sendSMSNotification(
    alert: Alert,
    preferences: NotificationPreferences
  ): Promise<void> {
    if (!preferences.sms.numbers || preferences.sms.numbers.length === 0) {
      return;
    }

    const message = `[${alert.priority.toUpperCase()}] ${alert.alertType.replace(/_/g, ' ')}: ${alert.message}`;

    for (const phoneNumber of preferences.sms.numbers) {
      const notificationId = await this.alertService.trackNotification(
        alert.id,
        'sms',
        undefined,
        phoneNumber
      );

      try {
        await this.twilioClient.messages.create({
          body: message,
          from: config.notifications?.twilio?.fromNumber || process.env.TWILIO_FROM_NUMBER,
          to: phoneNumber
        });

        await this.alertService.updateNotificationStatus(notificationId, 'delivered');
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        await this.alertService.updateNotificationStatus(notificationId, 'failed', errorMessage);
        logger.error('Failed to send SMS notification', { error: errorMessage, alertId: alert.id });
      }
    }

    logger.info('SMS notifications sent', {
      alertId: alert.id,
      recipients: preferences.sms.numbers.length
    });
  }

  private async sendPushNotification(
    alert: Alert,
    preferences: NotificationPreferences
  ): Promise<void> {
    if (!preferences.push.subscriptions || preferences.push.subscriptions.length === 0) {
      return;
    }

    const payload = JSON.stringify({
      title: `${alert.priority.toUpperCase()} Alert`,
      body: alert.message,
      icon: '/icons/alert.png',
      badge: '/icons/badge.png',
      data: {
        alertId: alert.id,
        alertType: alert.alertType,
        priority: alert.priority
      }
    });

    for (const subscription of preferences.push.subscriptions) {
      const notificationId = await this.alertService.trackNotification(
        alert.id,
        'push',
        undefined,
        subscription.endpoint
      );

      try {
        await webpush.sendNotification(subscription, payload);
        await this.alertService.updateNotificationStatus(notificationId, 'delivered');
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        await this.alertService.updateNotificationStatus(notificationId, 'failed', errorMessage);
        
        // Remove invalid subscription
        if (error instanceof Error && error.message.includes('410')) {
          preferences.push.subscriptions = preferences.push.subscriptions.filter(
            sub => sub.endpoint !== subscription.endpoint
          );
          await this.updateNotificationPreferences(alert.tenantId, undefined, {
            push: preferences.push
          });
        }
      }
    }

    logger.info('Push notifications sent', {
      alertId: alert.id,
      recipients: preferences.push.subscriptions.length
    });
  }

  private async sendWebhookNotification(
    alert: Alert,
    preferences: NotificationPreferences
  ): Promise<void> {
    if (!preferences.webhook.urls || preferences.webhook.urls.length === 0) {
      return;
    }

    const payload = {
      alert,
      timestamp: new Date().toISOString(),
      source: 'sparc-alert-service'
    };

    for (const url of preferences.webhook.urls) {
      const notificationId = await this.alertService.trackNotification(
        alert.id,
        'webhook',
        undefined,
        url
      );

      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-SPARC-Alert-ID': alert.id,
            'X-SPARC-Tenant-ID': alert.tenantId
          },
          body: JSON.stringify(payload)
        });

        if (response.ok) {
          await this.alertService.updateNotificationStatus(notificationId, 'delivered');
        } else {
          await this.alertService.updateNotificationStatus(
            notificationId, 
            'failed', 
            `HTTP ${response.status}: ${response.statusText}`
          );
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        await this.alertService.updateNotificationStatus(notificationId, 'failed', errorMessage);
        logger.error('Failed to send webhook notification', { error: errorMessage, alertId: alert.id });
      }
    }

    logger.info('Webhook notifications sent', {
      alertId: alert.id,
      recipients: preferences.webhook.urls.length
    });
  }

  private generateEmailHTML(alert: Alert): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
          .priority-${alert.priority} { 
            color: ${this.getPriorityColor(alert.priority)}; 
            font-weight: bold; 
          }
          .details { background-color: #f8f9fa; padding: 15px; margin-top: 20px; border-radius: 5px; }
          .footer { margin-top: 30px; font-size: 12px; color: #6c757d; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2>Alert Notification</h2>
            <p class="priority-${alert.priority}">Priority: ${alert.priority.toUpperCase()}</p>
          </div>
          
          <div class="content">
            <p><strong>Type:</strong> ${alert.alertType.replace(/_/g, ' ')}</p>
            <p><strong>Message:</strong> ${alert.message}</p>
            <p><strong>Source:</strong> ${alert.sourceType} (${alert.sourceId})</p>
            <p><strong>Time:</strong> ${new Date(alert.createdAt).toLocaleString()}</p>
            
            ${Object.keys(alert.details).length > 0 ? `
              <div class="details">
                <h3>Additional Details</h3>
                <pre>${JSON.stringify(alert.details, null, 2)}</pre>
              </div>
            ` : ''}
          </div>
          
          <div class="footer">
            <p>This is an automated notification from SPARC Alert System.</p>
            <p>Alert ID: ${alert.id}</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  private getPriorityColor(priority: AlertPriority): string {
    switch (priority) {
      case 'critical': return '#dc3545';
      case 'high': return '#fd7e14';
      case 'medium': return '#ffc107';
      case 'low': return '#28a745';
      default: return '#6c757d';
    }
  }

  private mapToNotificationPreferences(dbPrefs: any): NotificationPreferences {
    return {
      id: dbPrefs.id,
      tenantId: dbPrefs.tenantId,
      userId: dbPrefs.userId,
      email: dbPrefs.email || { enabled: true, addresses: [] },
      sms: dbPrefs.sms || { enabled: false, numbers: [] },
      push: dbPrefs.push || { enabled: true, subscriptions: [] },
      webhook: dbPrefs.webhook || { enabled: false, urls: [] },
      criticalOnly: dbPrefs.criticalOnly === 'true',
      preferences: dbPrefs.preferences || {},
      createdAt: dbPrefs.createdAt,
      updatedAt: dbPrefs.updatedAt
    };
  }
}