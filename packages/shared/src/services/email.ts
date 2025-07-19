import nodemailer from 'nodemailer';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { config } from '../config';
import { logger } from '../utils/logger';

export interface EmailOptions {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
  from?: string;
  replyTo?: string;
  attachments?: Array<{
    filename: string;
    content: Buffer | string;
    contentType?: string;
  }>;
}

export interface EmailTemplate {
  subject: string;
  html: string;
  text?: string;
}

class EmailService {
  private transporter: nodemailer.Transporter | null = null;
  private sesClient: SESClient | null = null;
  private useAWSSES: boolean = false;

  constructor() {
    this.initialize();
  }

  private initialize() {
    const emailConfig = config.email || {
      provider: 'smtp',
      smtp: {
        host: process.env.SMTP_HOST || 'localhost',
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER || '',
          pass: process.env.SMTP_PASS || '',
        },
      },
      from: {
        name: process.env.EMAIL_FROM_NAME || 'SPARC Security Platform',
        address: process.env.EMAIL_FROM_ADDRESS || 'noreply@sparc.security',
      },
    };

    if (emailConfig.provider === 'ses' && process.env.AWS_REGION) {
      // Use AWS SES
      this.useAWSSES = true;
      this.sesClient = new SESClient({
        region: process.env.AWS_REGION,
        credentials: process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY ? {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        } : undefined,
      });
      logger.info('Email service initialized with AWS SES');
    } else {
      // Use SMTP
      this.transporter = nodemailer.createTransport({
        host: emailConfig.smtp.host,
        port: emailConfig.smtp.port,
        secure: emailConfig.smtp.secure,
        auth: emailConfig.smtp.auth.user ? {
          user: emailConfig.smtp.auth.user,
          pass: emailConfig.smtp.auth.pass,
        } : undefined,
      });
      logger.info('Email service initialized with SMTP');
    }
  }

  async sendEmail(options: EmailOptions): Promise<void> {
    try {
      const from = options.from || `${config.email.from.name} <${config.email.from.address}>`;
      
      if (this.useAWSSES && this.sesClient) {
        // Send via AWS SES
        const command = new SendEmailCommand({
          Source: from,
          Destination: {
            ToAddresses: Array.isArray(options.to) ? options.to : [options.to],
          },
          Message: {
            Subject: {
              Data: options.subject,
              Charset: 'UTF-8',
            },
            Body: {
              Html: {
                Data: options.html,
                Charset: 'UTF-8',
              },
              Text: options.text ? {
                Data: options.text,
                Charset: 'UTF-8',
              } : undefined,
            },
          },
          ReplyToAddresses: options.replyTo ? [options.replyTo] : undefined,
        });

        await this.sesClient.send(command);
        logger.info('Email sent via AWS SES', {
          to: options.to,
          subject: options.subject,
        });
      } else if (this.transporter) {
        // Send via SMTP
        await this.transporter.sendMail({
          from,
          to: Array.isArray(options.to) ? options.to.join(', ') : options.to,
          subject: options.subject,
          html: options.html,
          text: options.text,
          replyTo: options.replyTo,
          attachments: options.attachments,
        });
        logger.info('Email sent via SMTP', {
          to: options.to,
          subject: options.subject,
        });
      } else {
        throw new Error('Email service not properly configured');
      }
    } catch (error) {
      logger.error('Failed to send email', {
        error,
        to: options.to,
        subject: options.subject,
      });
      throw error;
    }
  }

  // Email template methods
  getVerificationEmailTemplate(token: string, tenantName: string): EmailTemplate {
    const verificationUrl = `${config.app.url}/auth/verify-email?token=${token}`;
    
    return {
      subject: 'Verify your email address',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Email Verification</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #4A90E2; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background-color: #4A90E2; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>SPARC Security Platform</h1>
            </div>
            <div class="content">
              <h2>Welcome to ${tenantName}!</h2>
              <p>Thank you for signing up. Please verify your email address by clicking the button below:</p>
              <p style="text-align: center;">
                <a href="${verificationUrl}" class="button">Verify Email Address</a>
              </p>
              <p>Or copy and paste this link into your browser:</p>
              <p style="word-break: break-all;">${verificationUrl}</p>
              <p>This link will expire in 24 hours.</p>
              <p>If you didn't create an account, you can safely ignore this email.</p>
            </div>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
Welcome to ${tenantName}!

Please verify your email address by visiting the following link:
${verificationUrl}

This link will expire in 24 hours.

If you didn't create an account, you can safely ignore this email.

© ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.
      `.trim(),
    };
  }

  getPasswordResetEmailTemplate(token: string, email: string): EmailTemplate {
    const resetUrl = `${config.app.url}/auth/reset-password?token=${token}`;
    
    return {
      subject: 'Reset your password',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Password Reset</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #4A90E2; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .button { display: inline-block; padding: 12px 24px; background-color: #4A90E2; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>SPARC Security Platform</h1>
            </div>
            <div class="content">
              <h2>Password Reset Request</h2>
              <p>We received a request to reset the password for the account associated with ${email}.</p>
              <p style="text-align: center;">
                <a href="${resetUrl}" class="button">Reset Password</a>
              </p>
              <p>Or copy and paste this link into your browser:</p>
              <p style="word-break: break-all;">${resetUrl}</p>
              <div class="warning">
                <p><strong>Security Notice:</strong></p>
                <ul>
                  <li>This link will expire in 1 hour</li>
                  <li>If you didn't request this, please ignore this email</li>
                  <li>Your password won't change until you create a new one</li>
                </ul>
              </div>
            </div>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.</p>
              <p>This is an automated message, please do not reply.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
Password Reset Request

We received a request to reset the password for the account associated with ${email}.

Reset your password by visiting:
${resetUrl}

Security Notice:
- This link will expire in 1 hour
- If you didn't request this, please ignore this email
- Your password won't change until you create a new one

© ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.
      `.trim(),
    };
  }

  getMFASetupEmailTemplate(secret: string, qrCodeUrl: string, email: string): EmailTemplate {
    return {
      subject: 'Two-Factor Authentication Setup',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>2FA Setup</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #4A90E2; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .code-box { background-color: #e9ecef; padding: 15px; font-family: monospace; font-size: 18px; text-align: center; margin: 20px 0; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            .steps { background-color: white; padding: 20px; margin: 20px 0; border: 1px solid #ddd; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>SPARC Security Platform</h1>
            </div>
            <div class="content">
              <h2>Two-Factor Authentication Setup</h2>
              <p>You've enabled two-factor authentication for your account (${email}). Follow these steps to complete the setup:</p>
              
              <div class="steps">
                <h3>Step 1: Install an Authenticator App</h3>
                <p>If you haven't already, install one of these apps:</p>
                <ul>
                  <li>Google Authenticator</li>
                  <li>Microsoft Authenticator</li>
                  <li>Authy</li>
                </ul>
                
                <h3>Step 2: Scan QR Code or Enter Secret</h3>
                <p>Open your authenticator app and scan the QR code from the setup page, or manually enter this secret:</p>
                <div class="code-box">${secret}</div>
                
                <h3>Step 3: Enter Verification Code</h3>
                <p>Enter the 6-digit code from your authenticator app to complete setup.</p>
              </div>
              
              <p><strong>Important:</strong> Keep your secret key safe. You'll need it if you lose access to your authenticator app.</p>
            </div>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
Two-Factor Authentication Setup

You've enabled two-factor authentication for your account (${email}).

Setup Instructions:

1. Install an Authenticator App:
   - Google Authenticator
   - Microsoft Authenticator
   - Authy

2. Add your account using this secret:
   ${secret}

3. Enter the 6-digit code from your app to complete setup.

Important: Keep your secret key safe. You'll need it if you lose access to your authenticator app.

© ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.
      `.trim(),
    };
  }

  getLoginAlertEmailTemplate(email: string, ipAddress: string, userAgent: string, timestamp: Date): EmailTemplate {
    return {
      subject: 'New login to your SPARC account',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Login Alert</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background-color: #4A90E2; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .alert-box { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; }
            .details { background-color: white; padding: 15px; margin: 20px 0; border: 1px solid #ddd; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>SPARC Security Platform</h1>
            </div>
            <div class="content">
              <h2>New Login Detected</h2>
              <div class="alert-box">
                <p>A new login to your account (${email}) was detected.</p>
              </div>
              
              <div class="details">
                <h3>Login Details:</h3>
                <ul>
                  <li><strong>Time:</strong> ${timestamp.toLocaleString()}</li>
                  <li><strong>IP Address:</strong> ${ipAddress}</li>
                  <li><strong>Device/Browser:</strong> ${userAgent}</li>
                </ul>
              </div>
              
              <p><strong>Was this you?</strong></p>
              <p>If you recognize this login, no action is needed.</p>
              <p>If you don't recognize this login, please:</p>
              <ol>
                <li>Change your password immediately</li>
                <li>Enable two-factor authentication</li>
                <li>Review your recent account activity</li>
              </ol>
            </div>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
New Login Detected

A new login to your account (${email}) was detected.

Login Details:
- Time: ${timestamp.toLocaleString()}
- IP Address: ${ipAddress}
- Device/Browser: ${userAgent}

Was this you?

If you recognize this login, no action is needed.

If you don't recognize this login, please:
1. Change your password immediately
2. Enable two-factor authentication
3. Review your recent account activity

© ${new Date().getFullYear()} SPARC Security Platform. All rights reserved.
      `.trim(),
    };
  }
}

// Export singleton instance
export const emailService = new EmailService();

// Export convenience functions
export async function sendVerificationEmail(email: string, token: string, tenantName: string): Promise<void> {
  const template = emailService.getVerificationEmailTemplate(token, tenantName);
  await emailService.sendEmail({
    to: email,
    ...template,
  });
}

export async function sendPasswordResetEmail(email: string, token: string): Promise<void> {
  const template = emailService.getPasswordResetEmailTemplate(token, email);
  await emailService.sendEmail({
    to: email,
    ...template,
  });
}

export async function sendMFASetupEmail(email: string, secret: string, qrCodeUrl: string): Promise<void> {
  const template = emailService.getMFASetupEmailTemplate(secret, qrCodeUrl, email);
  await emailService.sendEmail({
    to: email,
    ...template,
  });
}

export async function sendLoginAlertEmail(email: string, ipAddress: string, userAgent: string): Promise<void> {
  const template = emailService.getLoginAlertEmailTemplate(email, ipAddress, userAgent, new Date());
  await emailService.sendEmail({
    to: email,
    ...template,
  });
}