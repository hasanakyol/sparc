import Redis from 'ioredis';
import { logger } from '@sparc/shared';
import { db, schema } from '../db';
import { eq, and, or, inArray } from 'drizzle-orm';

interface NotificationChannel {
  type: 'email' | 'sms' | 'push' | 'webhook';
  config: Record<string, any>;
}

interface NotificationRecipient {
  userId?: string;
  email?: string;
  phone?: string;
  role?: string;
  teamId?: string;
}

export class NotificationService {
  private channels: Map<string, NotificationChannel> = new Map();

  constructor(private redis: Redis) {
    this.initializeChannels();
  }

  private initializeChannels(): void {
    // Initialize notification channels based on environment config
    if (process.env.SMTP_HOST) {
      this.channels.set('email', {
        type: 'email',
        config: {
          host: process.env.SMTP_HOST,
          port: process.env.SMTP_PORT || 587,
          secure: process.env.SMTP_SECURE === 'true',
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS
          }
        }
      });
    }

    if (process.env.SMS_API_KEY) {
      this.channels.set('sms', {
        type: 'sms',
        config: {
          apiKey: process.env.SMS_API_KEY,
          apiUrl: process.env.SMS_API_URL
        }
      });
    }

    if (process.env.PUSH_SERVICE_URL) {
      this.channels.set('push', {
        type: 'push',
        config: {
          serviceUrl: process.env.PUSH_SERVICE_URL,
          apiKey: process.env.PUSH_API_KEY
        }
      });
    }

    // Webhook channel is always available
    this.channels.set('webhook', {
      type: 'webhook',
      config: {}
    });
  }

  async sendWorkOrderNotification(
    workOrder: any,
    event: 'created' | 'assigned' | 'completed' | 'cancelled' | 'overdue',
    additionalData?: any
  ): Promise<void> {
    try {
      const recipients = await this.getWorkOrderRecipients(workOrder, event);
      
      const notification = {
        type: 'work_order',
        event,
        workOrderId: workOrder.id,
        title: this.getWorkOrderNotificationTitle(workOrder, event),
        message: this.getWorkOrderNotificationMessage(workOrder, event, additionalData),
        priority: workOrder.priority,
        data: {
          workOrder: {
            id: workOrder.id,
            title: workOrder.title,
            type: workOrder.workOrderType,
            priority: workOrder.priority,
            status: workOrder.status,
            deviceId: workOrder.deviceId,
            deviceType: workOrder.deviceType,
            scheduledDate: workOrder.scheduledDate,
            dueDate: workOrder.dueDate
          },
          ...additionalData
        }
      };

      await this.sendToRecipients(recipients, notification);

      // Log notification
      await db.insert(schema.maintenanceHistory)
        .values({
          tenantId: workOrder.tenantId,
          deviceId: workOrder.deviceId,
          workOrderId: workOrder.id,
          activityType: 'notification',
          description: `Notification sent: ${event} - ${notification.title}`,
          performedBy: null, // System
          createdAt: new Date()
        });

    } catch (error) {
      logger.error('Failed to send work order notification', {
        workOrderId: workOrder.id,
        event,
        error
      });
    }
  }

  async sendPreventiveMaintenanceAlert(
    schedule: any,
    workOrders: any[]
  ): Promise<void> {
    try {
      const recipients = await this.getScheduleRecipients(schedule);
      
      const notification = {
        type: 'preventive_maintenance',
        event: 'scheduled',
        scheduleId: schedule.id,
        title: `Preventive Maintenance Scheduled - ${schedule.name}`,
        message: `${workOrders.length} work orders have been created for scheduled maintenance "${schedule.name}"`,
        priority: 'medium',
        data: {
          schedule: {
            id: schedule.id,
            name: schedule.name,
            frequency: schedule.frequency,
            scope: schedule.scope
          },
          workOrderCount: workOrders.length,
          workOrderIds: workOrders.map(wo => wo.id)
        }
      };

      await this.sendToRecipients(recipients, notification);

    } catch (error) {
      logger.error('Failed to send preventive maintenance alert', {
        scheduleId: schedule.id,
        error
      });
    }
  }

  async sendSLAViolationAlert(
    workOrder: any,
    slaConfig: any,
    violation: {
      type: 'response' | 'resolution';
      expectedTime: Date;
      actualTime: Date;
      severity: 'warning' | 'violation' | 'critical';
    }
  ): Promise<void> {
    try {
      const recipients = await this.getSLARecipients(workOrder, violation.severity);
      
      const notification = {
        type: 'sla_violation',
        event: violation.type,
        workOrderId: workOrder.id,
        title: `SLA ${violation.severity === 'warning' ? 'Warning' : 'Violation'} - ${workOrder.title}`,
        message: this.getSLAViolationMessage(workOrder, slaConfig, violation),
        priority: violation.severity === 'critical' ? 'critical' : 'high',
        data: {
          workOrder: {
            id: workOrder.id,
            title: workOrder.title,
            priority: workOrder.priority,
            status: workOrder.status
          },
          sla: {
            name: slaConfig.name,
            responseTime: slaConfig.responseTimeHours,
            resolutionTime: slaConfig.resolutionTimeHours
          },
          violation
        }
      };

      await this.sendToRecipients(recipients, notification);

      // Create escalation if critical
      if (violation.severity === 'critical') {
        await this.createEscalation(workOrder, slaConfig, violation);
      }

    } catch (error) {
      logger.error('Failed to send SLA violation alert', {
        workOrderId: workOrder.id,
        error
      });
    }
  }

  async sendPredictiveMaintenanceAlert(
    device: any,
    healthScore: any,
    workOrder: any
  ): Promise<void> {
    try {
      const recipients = await this.getPredictiveMaintenanceRecipients(device, healthScore.riskLevel);
      
      const notification = {
        type: 'predictive_maintenance',
        event: 'alert',
        deviceId: device.id,
        title: `Predictive Maintenance Alert - ${device.name}`,
        message: `Device health score: ${healthScore.healthScore}/100. Risk level: ${healthScore.riskLevel}. ${healthScore.recommendations.join('. ')}`,
        priority: healthScore.riskLevel === 'critical' ? 'critical' : 'high',
        data: {
          device: {
            id: device.id,
            name: device.name,
            type: device.type
          },
          healthScore,
          workOrder: {
            id: workOrder.id,
            scheduledDate: workOrder.scheduledDate
          }
        }
      };

      await this.sendToRecipients(recipients, notification);

    } catch (error) {
      logger.error('Failed to send predictive maintenance alert', {
        deviceId: device.id,
        error
      });
    }
  }

  async sendInventoryAlert(
    part: any,
    alertType: 'low_stock' | 'out_of_stock' | 'reorder_required',
    currentQuantity: number,
    threshold: number
  ): Promise<void> {
    try {
      const recipients = await this.getInventoryRecipients(part.tenantId);
      
      const notification = {
        type: 'inventory',
        event: alertType,
        partId: part.id,
        title: `Inventory Alert - ${part.name}`,
        message: this.getInventoryAlertMessage(part, alertType, currentQuantity, threshold),
        priority: alertType === 'out_of_stock' ? 'high' : 'medium',
        data: {
          part: {
            id: part.id,
            partNumber: part.partNumber,
            name: part.name,
            category: part.category
          },
          currentQuantity,
          threshold,
          reorderPoint: part.reorderPoint,
          reorderQuantity: part.reorderQuantity
        }
      };

      await this.sendToRecipients(recipients, notification);

    } catch (error) {
      logger.error('Failed to send inventory alert', {
        partId: part.id,
        alertType,
        error
      });
    }
  }

  private async sendToRecipients(
    recipients: NotificationRecipient[],
    notification: any
  ): Promise<void> {
    const promises: Promise<void>[] = [];

    // Group recipients by channel preference
    for (const recipient of recipients) {
      // Send via email if available
      if (recipient.email && this.channels.has('email')) {
        promises.push(this.sendEmail(recipient.email, notification));
      }

      // Send via SMS for critical notifications
      if (recipient.phone && this.channels.has('sms') && notification.priority === 'critical') {
        promises.push(this.sendSMS(recipient.phone, notification));
      }

      // Send push notification if user ID available
      if (recipient.userId && this.channels.has('push')) {
        promises.push(this.sendPushNotification(recipient.userId, notification));
      }
    }

    // Always send to webhook for integration
    promises.push(this.sendWebhook(notification));

    // Publish to Redis for real-time updates
    promises.push(this.publishNotification(notification));

    await Promise.allSettled(promises);
  }

  private async sendEmail(email: string, notification: any): Promise<void> {
    // In production, integrate with email service
    logger.info('Sending email notification', {
      to: email,
      subject: notification.title,
      type: notification.type
    });

    // Queue email job
    await this.redis.lpush('queue:emails', JSON.stringify({
      to: email,
      subject: notification.title,
      template: `maintenance_${notification.type}`,
      data: notification
    }));
  }

  private async sendSMS(phone: string, notification: any): Promise<void> {
    // In production, integrate with SMS service
    logger.info('Sending SMS notification', {
      to: phone,
      message: `${notification.title}: ${notification.message}`.substring(0, 160)
    });

    // Queue SMS job
    await this.redis.lpush('queue:sms', JSON.stringify({
      to: phone,
      message: `${notification.title}: ${notification.message}`.substring(0, 160)
    }));
  }

  private async sendPushNotification(userId: string, notification: any): Promise<void> {
    // In production, integrate with push notification service
    logger.info('Sending push notification', {
      userId,
      title: notification.title
    });

    // Queue push notification job
    await this.redis.lpush('queue:push', JSON.stringify({
      userId,
      title: notification.title,
      body: notification.message,
      data: notification.data
    }));
  }

  private async sendWebhook(notification: any): Promise<void> {
    // Publish to webhook service
    await this.redis.publish('webhooks:maintenance', JSON.stringify({
      event: `maintenance.${notification.type}.${notification.event}`,
      data: notification
    }));
  }

  private async publishNotification(notification: any): Promise<void> {
    // Publish for real-time updates
    await this.redis.publish('maintenance:notifications', JSON.stringify(notification));
  }

  private async getWorkOrderRecipients(
    workOrder: any,
    event: string
  ): Promise<NotificationRecipient[]> {
    const recipients: NotificationRecipient[] = [];

    // Always notify assigned technician
    if (workOrder.assignedTo) {
      const [user] = await db.select({
        id: schema.users.id,
        email: schema.users.email,
        phone: schema.users.phone
      })
      .from(schema.users)
      .where(eq(schema.users.id, workOrder.assignedTo))
      .limit(1);

      if (user) {
        recipients.push({
          userId: user.id,
          email: user.email,
          phone: user.phone
        });
      }
    }

    // Notify managers for critical work orders
    if (workOrder.priority === 'critical' || event === 'overdue') {
      // In production, fetch managers from role/team configuration
      recipients.push({
        role: 'maintenance_manager',
        teamId: workOrder.teamId
      });
    }

    // Notify requester for status changes
    if (workOrder.requestedBy && ['completed', 'cancelled'].includes(event)) {
      const [requester] = await db.select({
        id: schema.users.id,
        email: schema.users.email
      })
      .from(schema.users)
      .where(eq(schema.users.id, workOrder.requestedBy))
      .limit(1);

      if (requester) {
        recipients.push({
          userId: requester.id,
          email: requester.email
        });
      }
    }

    return recipients;
  }

  private async getScheduleRecipients(schedule: any): Promise<NotificationRecipient[]> {
    // In production, fetch from notification preferences
    return [{
      role: 'maintenance_supervisor',
      teamId: schedule.teamId
    }];
  }

  private async getSLARecipients(
    workOrder: any,
    severity: string
  ): Promise<NotificationRecipient[]> {
    const recipients = await this.getWorkOrderRecipients(workOrder, 'sla_violation');

    // Add escalation recipients for critical violations
    if (severity === 'critical') {
      recipients.push({
        role: 'operations_manager'
      });
    }

    return recipients;
  }

  private async getPredictiveMaintenanceRecipients(
    device: any,
    riskLevel: string
  ): Promise<NotificationRecipient[]> {
    const recipients: NotificationRecipient[] = [{
      role: 'maintenance_planner'
    }];

    if (riskLevel === 'critical') {
      recipients.push({
        role: 'maintenance_manager'
      });
    }

    return recipients;
  }

  private async getInventoryRecipients(tenantId: string): Promise<NotificationRecipient[]> {
    return [{
      role: 'inventory_manager'
    }, {
      role: 'maintenance_supervisor'
    }];
  }

  private getWorkOrderNotificationTitle(workOrder: any, event: string): string {
    const titles: Record<string, string> = {
      created: `New Work Order: ${workOrder.title}`,
      assigned: `Work Order Assigned: ${workOrder.title}`,
      completed: `Work Order Completed: ${workOrder.title}`,
      cancelled: `Work Order Cancelled: ${workOrder.title}`,
      overdue: `Work Order Overdue: ${workOrder.title}`
    };
    return titles[event] || `Work Order Update: ${workOrder.title}`;
  }

  private getWorkOrderNotificationMessage(
    workOrder: any,
    event: string,
    additionalData?: any
  ): string {
    const messages: Record<string, string> = {
      created: `A new ${workOrder.priority} priority work order has been created for ${workOrder.deviceType} maintenance.`,
      assigned: `You have been assigned to work order #${workOrder.id} for ${workOrder.deviceType} maintenance.`,
      completed: `Work order #${workOrder.id} has been completed. Total time: ${additionalData?.totalHours || 'N/A'} hours.`,
      cancelled: `Work order #${workOrder.id} has been cancelled. Reason: ${additionalData?.reason || 'Not specified'}.`,
      overdue: `Work order #${workOrder.id} is overdue. It was due on ${workOrder.dueDate?.toLocaleDateString() || 'N/A'}.`
    };
    return messages[event] || `Work order #${workOrder.id} has been updated.`;
  }

  private getSLAViolationMessage(
    workOrder: any,
    slaConfig: any,
    violation: any
  ): string {
    const timeDiff = Math.abs(violation.actualTime.getTime() - violation.expectedTime.getTime());
    const hours = Math.floor(timeDiff / (1000 * 60 * 60));
    
    if (violation.severity === 'warning') {
      return `Work order #${workOrder.id} is approaching SLA ${violation.type} time limit. ${hours} hours until violation.`;
    } else {
      return `Work order #${workOrder.id} has violated SLA ${violation.type} time by ${hours} hours.`;
    }
  }

  private getInventoryAlertMessage(
    part: any,
    alertType: string,
    currentQuantity: number,
    threshold: number
  ): string {
    const messages: Record<string, string> = {
      low_stock: `Part ${part.partNumber} is running low. Current quantity: ${currentQuantity}, Reorder point: ${threshold}.`,
      out_of_stock: `Part ${part.partNumber} is out of stock! This may impact maintenance operations.`,
      reorder_required: `Part ${part.partNumber} needs to be reordered. Current: ${currentQuantity}, Recommended order: ${part.reorderQuantity}.`
    };
    return messages[alertType] || `Inventory alert for part ${part.partNumber}.`;
  }

  private async createEscalation(
    workOrder: any,
    slaConfig: any,
    violation: any
  ): Promise<void> {
    // Create escalation record
    await db.insert(schema.maintenanceHistory)
      .values({
        tenantId: workOrder.tenantId,
        deviceId: workOrder.deviceId,
        workOrderId: workOrder.id,
        activityType: 'escalation',
        description: `SLA violation escalated: ${violation.type} time exceeded by ${Math.abs(violation.actualTime.getTime() - violation.expectedTime.getTime()) / (1000 * 60 * 60)} hours`,
        performedBy: null, // System
        createdAt: new Date()
      });

    // Queue escalation workflow
    await this.redis.lpush('queue:escalations', JSON.stringify({
      type: 'sla_violation',
      workOrderId: workOrder.id,
      slaConfigId: slaConfig.id,
      violation,
      escalationLevel: 1
    }));
  }
}