import { eq, and } from 'drizzle-orm';
import nodemailer from 'nodemailer';
import twilio from 'twilio';
import QRCode from 'qrcode';
import { getDb } from '../db';
import { visitors } from '@sparc/database/schemas/visitor-management';
import { users } from '@sparc/database/schemas/user-management';
import { config } from '@sparc/shared';
import { logger } from '@sparc/shared';
import type { ServiceResponse } from '../types';

export interface NotificationData {
  type: 'pre-registration' | 'check-in' | 'check-out' | 'approval-required' | 'approved' | 'denied' | 'overstay';
  recipient: {
    email?: string;
    phone?: string;
    name: string;
  };
  visitor: {
    id: string;
    name: string;
    company?: string;
    purpose: string;
    expectedArrival?: Date;
    expectedDeparture?: Date;
    actualArrival?: Date;
    actualDeparture?: Date;
  };
  host?: {
    name: string;
    email?: string;
  };
  additionalData?: any;
}

export class NotificationService {
  private db = getDb();
  private emailTransporter: nodemailer.Transporter | null = null;
  private twilioClient: twilio.Twilio | null = null;

  constructor() {
    this.initializeServices();
  }

  private initializeServices() {
    // Initialize email transporter
    if (config.notifications?.smtp?.host) {
      this.emailTransporter = nodemailer.createTransporter({
        host: config.notifications.smtp.host,
        port: config.notifications.smtp.port || 587,
        secure: config.notifications.smtp.secure || false,
        auth: {
          user: config.notifications.smtp.user,
          pass: config.notifications.smtp.pass,
        },
      });
    }

    // Initialize Twilio client
    if (config.notifications?.twilio?.accountSid && config.notifications?.twilio?.authToken) {
      this.twilioClient = twilio(
        config.notifications.twilio.accountSid,
        config.notifications.twilio.authToken
      );
    }
  }

  async sendVisitorNotification(
    visitorId: string,
    type: NotificationData['type'],
    organizationId: string
  ): Promise<ServiceResponse> {
    try {
      // Get visitor and host information
      const result = await this.db
        .select({
          visitor: visitors,
          host: {
            id: users.id,
            firstName: users.firstName,
            lastName: users.lastName,
            email: users.email,
            phone: users.phone,
          },
        })
        .from(visitors)
        .leftJoin(users, eq(visitors.hostUserId, users.id))
        .where(and(
          eq(visitors.id, visitorId),
          eq(visitors.organizationId, organizationId)
        ))
        .limit(1);

      if (!result.length) {
        return {
          success: false,
          error: {
            code: 'VISITOR_NOT_FOUND',
            message: 'Visitor not found',
          },
        };
      }

      const visitor = result[0].visitor;
      const host = result[0].host;

      const notificationData: NotificationData = {
        type,
        recipient: {
          email: visitor.email || undefined,
          phone: visitor.phone || undefined,
          name: `${visitor.firstName} ${visitor.lastName}`,
        },
        visitor: {
          id: visitor.id,
          name: `${visitor.firstName} ${visitor.lastName}`,
          company: visitor.company || undefined,
          purpose: visitor.purpose,
          expectedArrival: visitor.expectedArrival ? new Date(visitor.expectedArrival) : undefined,
          expectedDeparture: visitor.expectedDeparture ? new Date(visitor.expectedDeparture) : undefined,
          actualArrival: visitor.actualArrival ? new Date(visitor.actualArrival) : undefined,
          actualDeparture: visitor.actualDeparture ? new Date(visitor.actualDeparture) : undefined,
        },
        host: host ? {
          name: `${host.firstName} ${host.lastName}`,
          email: host.email || undefined,
        } : undefined,
      };

      // Send appropriate notification based on type
      let emailSent = false;
      let smsSent = false;

      switch (type) {
        case 'pre-registration':
          if (visitor.email && visitor.invitationCode) {
            emailSent = await this.sendPreRegistrationEmail(notificationData, visitor.invitationCode);
          }
          break;

        case 'check-in':
        case 'check-out':
          // Notify host
          if (host?.email) {
            emailSent = await this.sendHostNotificationEmail(
              { ...notificationData, recipient: { email: host.email, name: `${host.firstName} ${host.lastName}` } },
              type
            );
          }
          break;

        case 'approval-required':
          // Notify host for approval
          if (host?.email) {
            emailSent = await this.sendApprovalRequestEmail(
              { ...notificationData, recipient: { email: host.email, name: `${host.firstName} ${host.lastName}` } }
            );
          }
          break;

        case 'approved':
        case 'denied':
          // Notify visitor
          if (visitor.email) {
            emailSent = await this.sendApprovalResultEmail(notificationData, type === 'approved');
          }
          break;

        case 'overstay':
          // Notify host and security
          if (host?.email) {
            emailSent = await this.sendOverstayNotification(
              { ...notificationData, recipient: { email: host.email, name: `${host.firstName} ${host.lastName}` } }
            );
          }
          break;
      }

      logger.info('Notification sent', {
        visitorId,
        type,
        emailSent,
        smsSent,
      });

      return {
        success: true,
        data: {
          emailSent,
          smsSent,
        },
      };
    } catch (error) {
      logger.error('Failed to send notification', { error, visitorId, type });
      return {
        success: false,
        error: {
          code: 'NOTIFICATION_FAILED',
          message: 'Failed to send notification',
        },
      };
    }
  }

  private async sendPreRegistrationEmail(
    data: NotificationData,
    invitationCode: string
  ): Promise<boolean> {
    if (!this.emailTransporter || !data.recipient.email) {
      return false;
    }

    try {
      // Generate QR code
      const qrData = JSON.stringify({
        invitationCode,
        visitorId: data.visitor.id,
      });
      const qrCode = await QRCode.toDataURL(qrData);

      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f4f4f4; }
            .info-box { background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
            .qr-code { text-align: center; margin: 20px 0; }
            .footer { text-align: center; padding: 10px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Visitor Pre-Registration Confirmation</h1>
            </div>
            <div class="content">
              <p>Dear ${data.recipient.name},</p>
              <p>Your visit has been pre-registered. Please find your visit details below:</p>
              
              <div class="info-box">
                <h3>Visit Details</h3>
                <p><strong>Purpose:</strong> ${data.visitor.purpose}</p>
                <p><strong>Host:</strong> ${data.host?.name || 'Not specified'}</p>
                <p><strong>Expected Arrival:</strong> ${data.visitor.expectedArrival?.toLocaleString() || 'Not specified'}</p>
                <p><strong>Expected Departure:</strong> ${data.visitor.expectedDeparture?.toLocaleString() || 'Not specified'}</p>
                <p><strong>Invitation Code:</strong> ${invitationCode}</p>
              </div>
              
              <div class="qr-code">
                <h3>Quick Check-in QR Code</h3>
                <p>Present this QR code at reception for quick check-in:</p>
                <img src="${qrCode}" alt="Check-in QR Code" style="max-width: 200px;" />
              </div>
              
              <div class="info-box">
                <h3>Important Information</h3>
                <ul>
                  <li>Please bring a valid photo ID</li>
                  <li>Arrive at the designated time</li>
                  <li>Check in at the main reception</li>
                  <li>Your host will be notified upon your arrival</li>
                </ul>
              </div>
            </div>
            <div class="footer">
              <p>This is an automated message. Please do not reply to this email.</p>
              <p>If you need to cancel or modify your visit, please contact your host.</p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.emailTransporter.sendMail({
        from: config.notifications?.smtp?.from || 'noreply@sparc.security',
        to: data.recipient.email,
        subject: 'Visitor Pre-Registration Confirmation',
        html,
      });

      return true;
    } catch (error) {
      logger.error('Failed to send pre-registration email', { error });
      return false;
    }
  }

  private async sendHostNotificationEmail(
    data: NotificationData,
    action: 'check-in' | 'check-out'
  ): Promise<boolean> {
    if (!this.emailTransporter || !data.recipient.email) {
      return false;
    }

    try {
      const actionText = action === 'check-in' ? 'has arrived' : 'has departed';
      const timeText = action === 'check-in' 
        ? `Arrival time: ${data.visitor.actualArrival?.toLocaleString()}`
        : `Departure time: ${data.visitor.actualDeparture?.toLocaleString()}`;

      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #3498db; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .visitor-info { background-color: #f4f4f4; padding: 15px; margin: 10px 0; border-radius: 5px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Visitor ${action === 'check-in' ? 'Arrival' : 'Departure'} Notification</h1>
            </div>
            <div class="content">
              <p>Dear ${data.recipient.name},</p>
              <p>Your visitor <strong>${data.visitor.name}</strong> ${actionText}.</p>
              
              <div class="visitor-info">
                <h3>Visitor Details</h3>
                <p><strong>Name:</strong> ${data.visitor.name}</p>
                ${data.visitor.company ? `<p><strong>Company:</strong> ${data.visitor.company}</p>` : ''}
                <p><strong>Purpose:</strong> ${data.visitor.purpose}</p>
                <p><strong>${timeText}</strong></p>
              </div>
              
              ${action === 'check-in' ? `
              <p>Please ensure you are available to meet your visitor or have made appropriate arrangements.</p>
              ` : ''}
            </div>
          </div>
        </body>
        </html>
      `;

      await this.emailTransporter.sendMail({
        from: config.notifications?.smtp?.from || 'noreply@sparc.security',
        to: data.recipient.email,
        subject: `Visitor ${action === 'check-in' ? 'Arrived' : 'Departed'}: ${data.visitor.name}`,
        html,
      });

      return true;
    } catch (error) {
      logger.error('Failed to send host notification email', { error });
      return false;
    }
  }

  private async sendApprovalRequestEmail(data: NotificationData): Promise<boolean> {
    if (!this.emailTransporter || !data.recipient.email) {
      return false;
    }

    try {
      const approvalUrl = `${config.app?.baseUrl || 'https://sparc.security'}/visitors/approve/${data.visitor.id}`;

      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #f39c12; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .visitor-info { background-color: #f4f4f4; padding: 15px; margin: 10px 0; border-radius: 5px; }
            .action-buttons { text-align: center; margin: 20px 0; }
            .button { display: inline-block; padding: 10px 20px; margin: 0 10px; text-decoration: none; border-radius: 5px; }
            .approve { background-color: #27ae60; color: white; }
            .deny { background-color: #e74c3c; color: white; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Visitor Approval Required</h1>
            </div>
            <div class="content">
              <p>Dear ${data.recipient.name},</p>
              <p>A visitor requires your approval for entry:</p>
              
              <div class="visitor-info">
                <h3>Visitor Details</h3>
                <p><strong>Name:</strong> ${data.visitor.name}</p>
                ${data.visitor.company ? `<p><strong>Company:</strong> ${data.visitor.company}</p>` : ''}
                <p><strong>Purpose:</strong> ${data.visitor.purpose}</p>
                <p><strong>Expected Arrival:</strong> ${data.visitor.expectedArrival?.toLocaleString() || 'Not specified'}</p>
              </div>
              
              <div class="action-buttons">
                <a href="${approvalUrl}?action=approve" class="button approve">Approve Visit</a>
                <a href="${approvalUrl}?action=deny" class="button deny">Deny Visit</a>
              </div>
              
              <p>You can also manage visitor approvals through the SPARC security portal.</p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.emailTransporter.sendMail({
        from: config.notifications?.smtp?.from || 'noreply@sparc.security',
        to: data.recipient.email,
        subject: `Visitor Approval Required: ${data.visitor.name}`,
        html,
      });

      return true;
    } catch (error) {
      logger.error('Failed to send approval request email', { error });
      return false;
    }
  }

  private async sendApprovalResultEmail(
    data: NotificationData,
    approved: boolean
  ): Promise<boolean> {
    if (!this.emailTransporter || !data.recipient.email) {
      return false;
    }

    try {
      const html = approved ? `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #27ae60; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Visit Approved</h1>
            </div>
            <div class="content">
              <p>Dear ${data.recipient.name},</p>
              <p>Your visit has been approved. You may proceed with check-in at the scheduled time.</p>
              <p><strong>Expected Arrival:</strong> ${data.visitor.expectedArrival?.toLocaleString() || 'Not specified'}</p>
              <p>Please bring a valid photo ID for check-in.</p>
            </div>
          </div>
        </body>
        </html>
      ` : `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #e74c3c; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Visit Denied</h1>
            </div>
            <div class="content">
              <p>Dear ${data.recipient.name},</p>
              <p>We regret to inform you that your visit request has been denied.</p>
              <p>If you believe this is an error, please contact your host directly.</p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.emailTransporter.sendMail({
        from: config.notifications?.smtp?.from || 'noreply@sparc.security',
        to: data.recipient.email,
        subject: `Visit ${approved ? 'Approved' : 'Denied'}`,
        html,
      });

      return true;
    } catch (error) {
      logger.error('Failed to send approval result email', { error });
      return false;
    }
  }

  private async sendOverstayNotification(data: NotificationData): Promise<boolean> {
    if (!this.emailTransporter || !data.recipient.email) {
      return false;
    }

    try {
      const overstayMinutes = data.visitor.expectedDeparture 
        ? Math.floor((Date.now() - data.visitor.expectedDeparture.getTime()) / 60000)
        : 0;

      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #e74c3c; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .alert { background-color: #ffe4e4; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid #e74c3c; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Visitor Overstay Alert</h1>
            </div>
            <div class="content">
              <p>Dear ${data.recipient.name},</p>
              
              <div class="alert">
                <h3>⚠️ Overstay Detected</h3>
                <p>Your visitor has exceeded their expected departure time.</p>
              </div>
              
              <h3>Visitor Details</h3>
              <p><strong>Name:</strong> ${data.visitor.name}</p>
              ${data.visitor.company ? `<p><strong>Company:</strong> ${data.visitor.company}</p>` : ''}
              <p><strong>Expected Departure:</strong> ${data.visitor.expectedDeparture?.toLocaleString()}</p>
              <p><strong>Overstay Duration:</strong> ${overstayMinutes} minutes</p>
              
              <p>Please contact your visitor or security if assistance is needed.</p>
            </div>
          </div>
        </body>
        </html>
      `;

      await this.emailTransporter.sendMail({
        from: config.notifications?.smtp?.from || 'noreply@sparc.security',
        to: data.recipient.email,
        subject: `⚠️ Visitor Overstay Alert: ${data.visitor.name}`,
        html,
      });

      return true;
    } catch (error) {
      logger.error('Failed to send overstay notification', { error });
      return false;
    }
  }

  async sendSMS(phone: string, message: string): Promise<boolean> {
    if (!this.twilioClient || !config.notifications?.twilio?.from) {
      return false;
    }

    try {
      await this.twilioClient.messages.create({
        body: message,
        from: config.notifications.twilio.from,
        to: phone,
      });
      return true;
    } catch (error) {
      logger.error('Failed to send SMS', { error });
      return false;
    }
  }

  async testEmailConfiguration(): Promise<ServiceResponse> {
    if (!this.emailTransporter) {
      return {
        success: false,
        error: {
          code: 'EMAIL_NOT_CONFIGURED',
          message: 'Email service is not configured',
        },
      };
    }

    try {
      await this.emailTransporter.verify();
      return {
        success: true,
        data: { message: 'Email configuration is valid' },
      };
    } catch (error) {
      logger.error('Email configuration test failed', { error });
      return {
        success: false,
        error: {
          code: 'EMAIL_CONFIG_INVALID',
          message: 'Email configuration is invalid',
        },
      };
    }
  }
}