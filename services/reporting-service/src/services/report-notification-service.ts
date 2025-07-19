import nodemailer from 'nodemailer';
import { ReportingServiceConfig } from '../config';
import { ReportNotification } from '../types';
import { logger } from '../utils/logger';
import { createTracer } from '../utils/telemetry';

const tracer = createTracer('report-notification-service');

export class ReportNotificationService {
  constructor(
    private emailTransporter: nodemailer.Transporter,
    private config: ReportingServiceConfig
  ) {}

  async sendReportCompletionNotification(
    userId: string,
    reportId: string,
    filename: string
  ): Promise<void> {
    return tracer.startActiveSpan('send-completion-notification', async (span) => {
      try {
        span.setAttributes({
          'notification.type': 'report_completion',
          'notification.user_id': userId,
          'notification.report_id': reportId
        });

        // Get user email (in a real implementation, this would fetch from database)
        const userEmail = await this.getUserEmail(userId);
        if (!userEmail) {
          logger.warn('User email not found', { userId });
          return;
        }

        const subject = 'Your Report is Ready';
        const html = `
          <h2>Report Generation Complete</h2>
          <p>Your requested report has been successfully generated and is ready for download.</p>
          <p><strong>Report ID:</strong> ${reportId}</p>
          <p><strong>Filename:</strong> ${filename}</p>
          <p>You can download your report from the SPARC platform or by clicking the link below:</p>
          <p><a href="${this.config.corsOrigins[0]}/reports/${reportId}/download" style="background-color: #4472C4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Download Report</a></p>
          <p>This report will be available for download for the next 7 days.</p>
          <br>
          <p>Best regards,<br>SPARC Reporting System</p>
        `;

        await this.sendEmail(userEmail, subject, html);
        
        logger.info('Report completion notification sent', { userId, reportId });
      } catch (error) {
        logger.error('Failed to send completion notification', {
          userId,
          reportId,
          error: (error as Error).message
        });
        throw error;
      } finally {
        span.end();
      }
    });
  }

  async sendReportFailureNotification(
    userId: string,
    reportId: string,
    errorMessage: string
  ): Promise<void> {
    return tracer.startActiveSpan('send-failure-notification', async (span) => {
      try {
        span.setAttributes({
          'notification.type': 'report_failure',
          'notification.user_id': userId,
          'notification.report_id': reportId
        });

        const userEmail = await this.getUserEmail(userId);
        if (!userEmail) {
          return;
        }

        const subject = 'Report Generation Failed';
        const html = `
          <h2>Report Generation Failed</h2>
          <p>We encountered an error while generating your requested report.</p>
          <p><strong>Report ID:</strong> ${reportId}</p>
          <p><strong>Error:</strong> ${this.sanitizeErrorMessage(errorMessage)}</p>
          <p>Please try again or contact support if the issue persists.</p>
          <br>
          <p>Best regards,<br>SPARC Reporting System</p>
        `;

        await this.sendEmail(userEmail, subject, html);
        
        logger.info('Report failure notification sent', { userId, reportId });
      } catch (error) {
        logger.error('Failed to send failure notification', {
          userId,
          reportId,
          error: (error as Error).message
        });
      } finally {
        span.end();
      }
    });
  }

  async sendScheduledReportNotification(
    recipients: string[],
    reportId: string,
    reportName: string,
    filename: string,
    attachment?: Buffer
  ): Promise<void> {
    return tracer.startActiveSpan('send-scheduled-notification', async (span) => {
      try {
        span.setAttributes({
          'notification.type': 'scheduled_report',
          'notification.report_id': reportId,
          'notification.recipient_count': recipients.length
        });

        const subject = `Scheduled Report: ${reportName}`;
        const html = `
          <h2>Scheduled Report Delivery</h2>
          <p>Your scheduled report "${reportName}" has been generated and is attached to this email.</p>
          <p><strong>Report ID:</strong> ${reportId}</p>
          <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
          <p>You can also access this report from the SPARC platform.</p>
          <br>
          <p>This is an automated report delivery. To modify or unsubscribe from this report, please log in to the SPARC platform.</p>
          <br>
          <p>Best regards,<br>SPARC Reporting System</p>
        `;

        const mailOptions: nodemailer.SendMailOptions = {
          from: this.config.smtp.from,
          to: recipients,
          subject,
          html,
          attachments: attachment ? [{
            filename,
            content: attachment
          }] : undefined
        };

        await this.emailTransporter.sendMail(mailOptions);
        
        logger.info('Scheduled report notification sent', {
          reportId,
          recipientCount: recipients.length
        });
      } catch (error) {
        logger.error('Failed to send scheduled report notification', {
          reportId,
          error: (error as Error).message
        });
        throw error;
      } finally {
        span.end();
      }
    });
  }

  async sendComplianceReportNotification(
    recipients: string[],
    framework: string,
    score: number,
    reportId: string,
    attachment?: Buffer
  ): Promise<void> {
    return tracer.startActiveSpan('send-compliance-notification', async (span) => {
      try {
        span.setAttributes({
          'notification.type': 'compliance_report',
          'notification.framework': framework,
          'notification.score': score,
          'notification.report_id': reportId
        });

        const subject = `Compliance Report: ${framework.toUpperCase()} - Score: ${score}%`;
        const scoreColor = score >= 90 ? '#28a745' : score >= 70 ? '#ffc107' : '#dc3545';
        
        const html = `
          <h2>Compliance Report Generated</h2>
          <p>A new compliance report has been generated for ${framework.toUpperCase()}.</p>
          <div style="margin: 20px 0;">
            <p><strong>Overall Compliance Score:</strong></p>
            <div style="background-color: #f0f0f0; border-radius: 10px; overflow: hidden; height: 30px;">
              <div style="background-color: ${scoreColor}; width: ${score}%; height: 100%; text-align: center; line-height: 30px; color: white; font-weight: bold;">
                ${score}%
              </div>
            </div>
          </div>
          <p><strong>Report ID:</strong> ${reportId}</p>
          <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
          <p>Please review the attached report for detailed findings and recommendations.</p>
          <br>
          <p>Best regards,<br>SPARC Compliance Team</p>
        `;

        const mailOptions: nodemailer.SendMailOptions = {
          from: this.config.smtp.from,
          to: recipients,
          subject,
          html,
          attachments: attachment ? [{
            filename: `${framework}_compliance_report.pdf`,
            content: attachment
          }] : undefined
        };

        await this.emailTransporter.sendMail(mailOptions);
        
        logger.info('Compliance report notification sent', {
          reportId,
          framework,
          score,
          recipientCount: recipients.length
        });
      } catch (error) {
        logger.error('Failed to send compliance notification', {
          reportId,
          error: (error as Error).message
        });
        throw error;
      } finally {
        span.end();
      }
    });
  }

  async sendReportExpirationWarning(
    userId: string,
    reportId: string,
    expirationDate: Date
  ): Promise<void> {
    return tracer.startActiveSpan('send-expiration-warning', async (span) => {
      try {
        span.setAttributes({
          'notification.type': 'expiration_warning',
          'notification.user_id': userId,
          'notification.report_id': reportId
        });

        const userEmail = await this.getUserEmail(userId);
        if (!userEmail) {
          return;
        }

        const daysUntilExpiration = Math.ceil((expirationDate.getTime() - Date.now()) / (24 * 60 * 60 * 1000));
        
        const subject = 'Report Expiration Warning';
        const html = `
          <h2>Report Expiration Warning</h2>
          <p>Your report will expire in ${daysUntilExpiration} days.</p>
          <p><strong>Report ID:</strong> ${reportId}</p>
          <p><strong>Expiration Date:</strong> ${expirationDate.toLocaleString()}</p>
          <p>Please download your report before it expires:</p>
          <p><a href="${this.config.corsOrigins[0]}/reports/${reportId}/download" style="background-color: #4472C4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Download Report</a></p>
          <br>
          <p>Best regards,<br>SPARC Reporting System</p>
        `;

        await this.sendEmail(userEmail, subject, html);
        
        logger.info('Report expiration warning sent', { userId, reportId, daysUntilExpiration });
      } catch (error) {
        logger.error('Failed to send expiration warning', {
          userId,
          reportId,
          error: (error as Error).message
        });
      } finally {
        span.end();
      }
    });
  }

  async sendBulkReportNotification(
    userId: string,
    reportCount: number,
    completedCount: number,
    failedCount: number
  ): Promise<void> {
    return tracer.startActiveSpan('send-bulk-notification', async (span) => {
      try {
        span.setAttributes({
          'notification.type': 'bulk_report',
          'notification.user_id': userId,
          'notification.total_count': reportCount,
          'notification.completed_count': completedCount,
          'notification.failed_count': failedCount
        });

        const userEmail = await this.getUserEmail(userId);
        if (!userEmail) {
          return;
        }

        const subject = 'Bulk Report Generation Complete';
        const html = `
          <h2>Bulk Report Generation Complete</h2>
          <p>Your bulk report request has been processed.</p>
          <div style="margin: 20px 0;">
            <p><strong>Summary:</strong></p>
            <ul>
              <li>Total Reports Requested: ${reportCount}</li>
              <li>Successfully Generated: ${completedCount}</li>
              <li>Failed: ${failedCount}</li>
            </ul>
          </div>
          <p>You can access your completed reports from the SPARC platform.</p>
          <br>
          <p>Best regards,<br>SPARC Reporting System</p>
        `;

        await this.sendEmail(userEmail, subject, html);
        
        logger.info('Bulk report notification sent', {
          userId,
          reportCount,
          completedCount,
          failedCount
        });
      } catch (error) {
        logger.error('Failed to send bulk notification', {
          userId,
          error: (error as Error).message
        });
      } finally {
        span.end();
      }
    });
  }

  private async sendEmail(to: string | string[], subject: string, html: string): Promise<void> {
    try {
      const mailOptions: nodemailer.SendMailOptions = {
        from: this.config.smtp.from,
        to,
        subject,
        html,
        text: this.htmlToText(html)
      };

      const info = await this.emailTransporter.sendMail(mailOptions);
      
      logger.debug('Email sent', {
        messageId: info.messageId,
        to: Array.isArray(to) ? to.join(', ') : to
      });
    } catch (error) {
      logger.error('Failed to send email', {
        to: Array.isArray(to) ? to.join(', ') : to,
        subject,
        error: (error as Error).message
      });
      throw error;
    }
  }

  private async getUserEmail(userId: string): Promise<string | null> {
    // In a real implementation, this would fetch from the database
    // For now, returning a mock email
    return `user-${userId}@sparc.com`;
  }

  private sanitizeErrorMessage(error: string): string {
    // Remove sensitive information from error messages
    return error
      .replace(/postgresql:\/\/[^@]+@[^/]+/gi, 'postgresql://***@***')
      .replace(/redis:\/\/[^@]+@[^/]+/gi, 'redis://***@***')
      .replace(/Bearer\s+[^\s]+/gi, 'Bearer ***')
      .substring(0, 200);
  }

  private htmlToText(html: string): string {
    // Simple HTML to text conversion
    return html
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/p>/gi, '\n\n')
      .replace(/<[^>]+>/g, '')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&amp;/gi, '&')
      .trim();
  }

  async testEmailConfiguration(): Promise<boolean> {
    try {
      await this.emailTransporter.verify();
      logger.info('Email configuration verified');
      return true;
    } catch (error) {
      logger.error('Email configuration test failed', {
        error: (error as Error).message
      });
      return false;
    }
  }
}