import { Redis } from 'ioredis';
import { CronJob } from 'cron';
import { AlertService } from './alert.service';
import { NotificationService } from './notification.service';
import type { Alert, AlertPriority, PRIORITY_CONFIG } from '@sparc/shared/types/alerts';
import { logger } from '@sparc/shared';

interface EscalationData {
  alertId: string;
  tenantId: string;
  escalationLevel: number;
}

export class EscalationService {
  private alertService: AlertService;
  private notificationService: NotificationService;
  private escalationJob: CronJob;

  constructor(private redis: Redis) {
    this.alertService = new AlertService(redis);
    this.notificationService = new NotificationService(redis);

    // Process escalations every 30 seconds
    this.escalationJob = new CronJob('*/30 * * * * *', () => {
      this.processEscalations().catch(error => {
        logger.error('Failed to process escalations', { error });
      });
    });
  }

  start(): void {
    this.escalationJob.start();
    logger.info('Escalation service started');
  }

  stop(): void {
    this.escalationJob.stop();
    logger.info('Escalation service stopped');
  }

  async scheduleEscalation(alert: Alert): Promise<void> {
    try {
      const priorityConfig = PRIORITY_CONFIG[alert.priority as keyof typeof PRIORITY_CONFIG];
      const escalationTime = Date.now() + priorityConfig.timeout * 60 * 1000;

      const escalationData: EscalationData = {
        alertId: alert.id,
        tenantId: alert.tenantId,
        escalationLevel: priorityConfig.escalationLevel
      };

      await this.redis.zadd(
        'alert_escalations',
        escalationTime,
        JSON.stringify(escalationData)
      );

      logger.info('Escalation scheduled', {
        alertId: alert.id,
        escalationTime: new Date(escalationTime).toISOString(),
        escalationLevel: priorityConfig.escalationLevel
      });
    } catch (error) {
      logger.error('Failed to schedule escalation', { error, alertId: alert.id });
    }
  }

  async cancelEscalation(alertId: string): Promise<void> {
    try {
      const escalations = await this.redis.zrange('alert_escalations', 0, -1);
      
      for (const escalation of escalations) {
        const data: EscalationData = JSON.parse(escalation);
        if (data.alertId === alertId) {
          await this.redis.zrem('alert_escalations', escalation);
          logger.info('Escalation cancelled', { alertId });
          break;
        }
      }
    } catch (error) {
      logger.error('Failed to cancel escalation', { error, alertId });
    }
  }

  private async processEscalations(): Promise<void> {
    const now = Date.now();
    
    try {
      // Get all escalations due for processing
      const dueEscalations = await this.redis.zrangebyscore(
        'alert_escalations',
        0,
        now
      );

      for (const escalationStr of dueEscalations) {
        try {
          const escalationData: EscalationData = JSON.parse(escalationStr);
          
          // Get the alert
          const alert = await this.alertService.getAlert(
            escalationData.tenantId,
            escalationData.alertId
          );

          if (alert && alert.status === 'open') {
            await this.escalateAlert(alert, escalationData.escalationLevel);
          }

          // Remove processed escalation
          await this.redis.zrem('alert_escalations', escalationStr);
        } catch (error) {
          logger.error('Failed to process individual escalation', { 
            error, 
            escalation: escalationStr 
          });
        }
      }
    } catch (error) {
      logger.error('Failed to process escalations batch', { error });
    }
  }

  private async escalateAlert(alert: Alert, escalationLevel: number): Promise<void> {
    try {
      // Determine new priority based on escalation level
      let newPriority = alert.priority;
      
      if (escalationLevel > 3 && alert.priority !== 'critical') {
        newPriority = 'critical';
      } else if (escalationLevel > 2 && alert.priority === 'low') {
        newPriority = 'high';
      } else if (escalationLevel > 1 && alert.priority === 'low') {
        newPriority = 'medium';
      }

      // Update alert priority if needed
      if (newPriority !== alert.priority) {
        const updated = await this.alertService.updateAlert(
          alert.tenantId,
          alert.id,
          { details: { ...alert.details, escalated: true, originalPriority: alert.priority } }
        );
        
        if (updated) {
          alert = updated;
          alert.priority = newPriority as AlertPriority;
        }
      }

      // Add escalation record
      await this.alertService.addEscalation(
        alert.id,
        `Level ${escalationLevel}`,
        undefined,
        `Alert escalated due to no response within ${PRIORITY_CONFIG[alert.priority as keyof typeof PRIORITY_CONFIG].timeout} minutes`
      );

      // Send escalation notifications
      await this.notificationService.sendNotifications(alert);

      // Broadcast escalation event via Redis pub/sub
      await this.redis.publish(
        `alert:escalated:${alert.tenantId}`,
        JSON.stringify({
          alertId: alert.id,
          escalationLevel,
          newPriority,
          timestamp: new Date().toISOString()
        })
      );

      logger.info('Alert escalated', {
        alertId: alert.id,
        escalationLevel,
        newPriority,
        originalPriority: alert.priority
      });

      // Schedule next escalation if not at max level
      if (escalationLevel < 5 && alert.status === 'open') {
        const nextEscalationTime = Date.now() + PRIORITY_CONFIG[newPriority as keyof typeof PRIORITY_CONFIG].timeout * 60 * 1000;
        
        await this.redis.zadd(
          'alert_escalations',
          nextEscalationTime,
          JSON.stringify({
            alertId: alert.id,
            tenantId: alert.tenantId,
            escalationLevel: escalationLevel + 1
          })
        );
      }
    } catch (error) {
      logger.error('Failed to escalate alert', { error, alertId: alert.id });
    }
  }

  async getScheduledEscalations(tenantId?: string): Promise<Array<{
    alertId: string;
    tenantId: string;
    escalationLevel: number;
    scheduledFor: Date;
  }>> {
    try {
      const escalations = await this.redis.zrange('alert_escalations', 0, -1, 'WITHSCORES');
      const result = [];

      for (let i = 0; i < escalations.length; i += 2) {
        const data: EscalationData = JSON.parse(escalations[i]);
        const timestamp = parseInt(escalations[i + 1]);

        if (!tenantId || data.tenantId === tenantId) {
          result.push({
            ...data,
            scheduledFor: new Date(timestamp)
          });
        }
      }

      return result;
    } catch (error) {
      logger.error('Failed to get scheduled escalations', { error });
      return [];
    }
  }
}