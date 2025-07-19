import Redis from 'ioredis';
import nodemailer from 'nodemailer';
import twilio from 'twilio';
import webpush from 'web-push';

interface NotificationConfig {
  smtp?: {
    host?: string;
    port?: number;
    user?: string;
    password?: string;
  };
  twilio?: {
    accountSid?: string;
    authToken?: string;
    fromNumber?: string;
  };
  webPush?: {
    publicKey?: string;
    privateKey?: string;
    subject?: string;
  };
}

interface NotificationPreferences {
  email: {
    enabled: boolean;
    minSeverity: 'low' | 'medium' | 'high' | 'critical';
    recipients: string[];
  };
  sms: {
    enabled: boolean;
    minSeverity: 'low' | 'medium' | 'high' | 'critical';
    recipients: string[];
  };
  push: {
    enabled: boolean;
    minSeverity: 'low' | 'medium' | 'high' | 'critical';
  };
}

interface PushSubscription {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

export class NotificationService {
  private emailTransporter?: nodemailer.Transporter;
  private twilioClient?: twilio.Twilio;
  private vapidPublicKey?: string;

  constructor(
    private redis: Redis,
    private config: NotificationConfig
  ) {
    this.initializeServices();
  }

  private initializeServices(): void {
    // Initialize email
    if (this.config.smtp?.host) {
      this.emailTransporter = nodemailer.createTransporter({
        host: this.config.smtp.host,
        port: this.config.smtp.port || 587,
        secure: this.config.smtp.port === 465,
        auth: {
          user: this.config.smtp.user,
          pass: this.config.smtp.password,
        },
      });
    }

    // Initialize SMS
    if (this.config.twilio?.accountSid && this.config.twilio?.authToken) {
      this.twilioClient = twilio(
        this.config.twilio.accountSid,
        this.config.twilio.authToken
      );
    }

    // Initialize web push
    if (this.config.webPush?.publicKey && this.config.webPush?.privateKey) {
      this.vapidPublicKey = this.config.webPush.publicKey;
      webpush.setVapidDetails(
        this.config.webPush.subject || 'mailto:admin@sparc.com',
        this.config.webPush.publicKey,
        this.config.webPush.privateKey
      );
    }
  }

  async getPreferences(tenantId: string): Promise<NotificationPreferences> {
    const cached = await this.redis.get(`notification_prefs:${tenantId}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // Default preferences
    const defaults: NotificationPreferences = {
      email: {
        enabled: true,
        minSeverity: 'medium',
        recipients: []
      },
      sms: {
        enabled: !!this.twilioClient,
        minSeverity: 'high',
        recipients: []
      },
      push: {
        enabled: !!this.vapidPublicKey,
        minSeverity: 'low'
      }
    };

    await this.redis.setex(
      `notification_prefs:${tenantId}`,
      3600,
      JSON.stringify(defaults)
    );

    return defaults;
  }

  async updatePreferences(tenantId: string, preferences: NotificationPreferences): Promise<void> {
    await this.redis.setex(
      `notification_prefs:${tenantId}`,
      3600,
      JSON.stringify(preferences)
    );
  }

  async sendEmail(to: string, subject: string, html: string): Promise<boolean> {
    if (!this.emailTransporter) {
      console.warn('Email service not configured');
      return false;
    }

    try {
      await this.emailTransporter.sendMail({
        from: this.config.smtp?.user || 'noreply@sparc.com',
        to,
        subject,
        html
      });

      console.log(`Email sent to ${to}: ${subject}`);
      return true;
    } catch (error) {
      console.error('Failed to send email:', error);
      return false;
    }
  }

  async sendSMS(to: string, message: string): Promise<boolean> {
    if (!this.twilioClient || !this.config.twilio?.fromNumber) {
      console.warn('SMS service not configured');
      return false;
    }

    try {
      await this.twilioClient.messages.create({
        body: message,
        from: this.config.twilio.fromNumber,
        to
      });

      console.log(`SMS sent to ${to}`);
      return true;
    } catch (error) {
      console.error('Failed to send SMS:', error);
      return false;
    }
  }

  async sendPush(subscription: PushSubscription, payload: any): Promise<boolean> {
    if (!this.vapidPublicKey) {
      console.warn('Push notification service not configured');
      return false;
    }

    try {
      await webpush.sendNotification(subscription, JSON.stringify(payload));
      console.log('Push notification sent');
      return true;
    } catch (error) {
      console.error('Failed to send push notification:', error);
      return false;
    }
  }

  async sendPushToTenant(tenantId: string, payload: any): Promise<void> {
    const subscriptions = await this.getSubscriptions(tenantId);
    
    await Promise.all(
      subscriptions.map(sub => this.sendPush(sub, payload))
    );
  }

  async subscribePush(tenantId: string, userId: string, subscription: PushSubscription): Promise<void> {
    const key = `push_sub:${tenantId}:${userId}`;
    await this.redis.hset(key, subscription.endpoint, JSON.stringify(subscription));
    
    // Add to tenant's subscription list
    await this.redis.sadd(`push_subs:${tenantId}`, `${userId}:${subscription.endpoint}`);
  }

  async unsubscribePush(tenantId: string, userId: string, endpoint: string): Promise<void> {
    const key = `push_sub:${tenantId}:${userId}`;
    await this.redis.hdel(key, endpoint);
    
    // Remove from tenant's subscription list
    await this.redis.srem(`push_subs:${tenantId}`, `${userId}:${endpoint}`);
  }

  async sendTestNotification(
    tenantId: string,
    channel: 'email' | 'sms' | 'push',
    recipient: string,
    message: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      switch (channel) {
        case 'email':
          const emailSuccess = await this.sendEmail(
            recipient,
            'SPARC Test Notification',
            `<p>${message}</p>`
          );
          return { success: emailSuccess, error: emailSuccess ? undefined : 'Email service not configured' };
          
        case 'sms':
          const smsSuccess = await this.sendSMS(recipient, message);
          return { success: smsSuccess, error: smsSuccess ? undefined : 'SMS service not configured' };
          
        case 'push':
          // For push test, send to all user's subscriptions
          const userId = recipient; // Assuming recipient is userId for push
          const subs = await this.getUserSubscriptions(tenantId, userId);
          if (subs.length === 0) {
            return { success: false, error: 'No push subscriptions found' };
          }
          
          await Promise.all(
            subs.map(sub => this.sendPush(sub, {
              title: 'Test Notification',
              body: message
            }))
          );
          return { success: true };
          
        default:
          return { success: false, error: 'Invalid channel' };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async getNotificationHistory(tenantId: string, options: any): Promise<any[]> {
    // In production, this would query from a notifications table
    return [];
  }

  async getStatistics(tenantId: string, period: string): Promise<any> {
    // In production, this would calculate actual statistics
    return {
      sent: {
        email: 0,
        sms: 0,
        push: 0
      },
      failed: {
        email: 0,
        sms: 0,
        push: 0
      },
      period
    };
  }

  async retryFailedNotifications(tenantId: string): Promise<any> {
    // In production, this would retry failed notifications from a queue
    return {
      retried: 0,
      successful: 0,
      failed: 0
    };
  }

  getVapidPublicKey(): string | null {
    return this.vapidPublicKey || null;
  }

  private async getSubscriptions(tenantId: string): Promise<PushSubscription[]> {
    const subIds = await this.redis.smembers(`push_subs:${tenantId}`);
    const subscriptions: PushSubscription[] = [];

    for (const subId of subIds) {
      const [userId, endpoint] = subId.split(':');
      const sub = await this.redis.hget(`push_sub:${tenantId}:${userId}`, endpoint);
      if (sub) {
        subscriptions.push(JSON.parse(sub));
      }
    }

    return subscriptions;
  }

  private async getUserSubscriptions(tenantId: string, userId: string): Promise<PushSubscription[]> {
    const key = `push_sub:${tenantId}:${userId}`;
    const subs = await this.redis.hgetall(key);
    
    return Object.values(subs).map(sub => JSON.parse(sub));
  }
}