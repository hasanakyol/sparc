import * as cron from 'node-cron';
import Redis from 'ioredis';
import { db, schema } from '../db';
import { eq, and, isNull, lte, inArray } from 'drizzle-orm';
import { logger } from '@sparc/shared';
import { NotificationService } from './notification.service';

export class SlaMonitoringService {
  private scheduledTask: cron.ScheduledTask | null = null;
  private running = false;

  constructor(
    private redis: Redis,
    private notificationService: NotificationService
  ) {}

  async start(): Promise<void> {
    // Run every 15 minutes
    this.scheduledTask = cron.schedule('*/15 * * * *', async () => {
      await this.checkSlaStatuses();
    });

    this.running = true;
    logger.info('SLA monitoring service started');
  }

  async stop(): Promise<void> {
    if (this.scheduledTask) {
      this.scheduledTask.stop();
      this.scheduledTask = null;
    }
    this.running = false;
    logger.info('SLA monitoring service stopped');
  }

  isRunning(): boolean {
    return this.running;
  }

  private async checkSlaStatuses(): Promise<void> {
    const startTime = Date.now();
    logger.info('Starting SLA status check');

    try {
      // Get all open work orders with SLA deadlines
      const openWorkOrders = await db.select({
        workOrder: schema.workOrders,
        assignedUser: {
          id: schema.users.id,
          username: schema.users.username,
          email: schema.users.email
        }
      })
      .from(schema.workOrders)
      .leftJoin(schema.users, eq(schema.workOrders.assignedTo, schema.users.id))
      .where(and(
        inArray(schema.workOrders.status, ['open', 'assigned', 'in_progress']),
        isNull(schema.workOrders.slaMet)
      ));

      logger.info(`Checking ${openWorkOrders.length} work orders for SLA status`);

      const now = new Date();
      let violationsDetected = 0;
      let warningsIssued = 0;
      let escalationsTriggered = 0;

      for (const { workOrder, assignedUser } of openWorkOrders) {
        try {
          // Get applicable SLA configuration
          const slaConfig = await this.getApplicableSlaConfig(workOrder);
          
          if (!slaConfig) {
            continue; // No SLA applies
          }

          // Calculate SLA deadline if not set
          const deadline = workOrder.slaDeadline || 
            new Date(workOrder.createdAt.getTime() + slaConfig.resolutionTime * 60 * 1000);

          // Check SLA status
          const timeRemaining = deadline.getTime() - now.getTime();
          const responseTime = (now.getTime() - workOrder.createdAt.getTime()) / (1000 * 60); // minutes

          if (timeRemaining <= 0 && !workOrder.slaDeadline) {
            // SLA breached
            await this.handleSlaViolation(workOrder, slaConfig, assignedUser);
            violationsDetected++;
          } else if (timeRemaining > 0 && timeRemaining <= slaConfig.resolutionTime * 0.25 * 60 * 1000) {
            // Less than 25% time remaining - issue warning
            await this.handleSlaWarning(workOrder, slaConfig, assignedUser, timeRemaining);
            warningsIssued++;
          }

          // Check for escalation needs
          if (slaConfig.escalationLevels && Array.isArray(slaConfig.escalationLevels)) {
            for (const level of slaConfig.escalationLevels) {
              if (responseTime >= level.delayMinutes && !await this.isEscalated(workOrder.id, level.level)) {
                await this.handleEscalation(workOrder, slaConfig, level, assignedUser);
                escalationsTriggered++;
              }
            }
          }

          // Update SLA deadline if not set
          if (!workOrder.slaDeadline) {
            await db.update(schema.workOrders)
              .set({ slaDeadline: deadline })
              .where(eq(schema.workOrders.id, workOrder.id));
          }

        } catch (error) {
          logger.error('Failed to check SLA for work order', {
            workOrderId: workOrder.id,
            error
          });
        }
      }

      // Update metrics
      if (violationsDetected > 0) {
        await this.redis.incr('metrics:sla:violations', violationsDetected);
      }

      const duration = Date.now() - startTime;
      logger.info('SLA status check completed', {
        workOrdersChecked: openWorkOrders.length,
        violationsDetected,
        warningsIssued,
        escalationsTriggered,
        durationMs: duration
      });

    } catch (error) {
      logger.error('Failed to check SLA statuses', { error });
    }
  }

  private async getApplicableSlaConfig(workOrder: any): Promise<any | null> {
    const configs = await db.select()
      .from(schema.maintenanceSlaConfig)
      .where(and(
        eq(schema.maintenanceSlaConfig.tenantId, workOrder.tenantId),
        eq(schema.maintenanceSlaConfig.active, 1)
      ));

    // Find the most specific matching config
    const applicableConfig = configs.find(config => {
      const matchesType = !config.workOrderType || config.workOrderType === workOrder.workOrderType;
      const matchesPriority = !config.priority || config.priority === workOrder.priority;
      const matchesDeviceType = !config.deviceType || config.deviceType === workOrder.deviceType;
      return matchesType && matchesPriority && matchesDeviceType;
    });

    return applicableConfig || null;
  }

  private async handleSlaViolation(workOrder: any, slaConfig: any, assignedUser: any): Promise<void> {
    // Update work order
    await db.update(schema.workOrders)
      .set({
        slaMet: 0,
        updatedAt: new Date()
      })
      .where(eq(schema.workOrders.id, workOrder.id));

    // Create history entry
    await db.insert(schema.maintenanceHistory)
      .values({
        tenantId: workOrder.tenantId,
        deviceId: workOrder.deviceId,
        workOrderId: workOrder.id,
        activityType: 'maintenance',
        description: `SLA violated - ${slaConfig.name}`,
        performedBy: null // System generated
      });

    // Publish violation event
    await this.redis.publish('maintenance:sla:violation', JSON.stringify({
      tenantId: workOrder.tenantId,
      workOrderId: workOrder.id,
      violation: {
        type: 'resolution',
        slaConfigId: slaConfig.id,
        slaConfigName: slaConfig.name,
        deadline: workOrder.slaDeadline,
        breachedAt: new Date()
      }
    }));

    // Send notifications
    await this.notificationService.sendSlaViolationNotification(workOrder, slaConfig, assignedUser);

    logger.warn('SLA violation detected', {
      workOrderId: workOrder.id,
      slaConfigId: slaConfig.id
    });
  }

  private async handleSlaWarning(
    workOrder: any, 
    slaConfig: any, 
    assignedUser: any, 
    timeRemaining: number
  ): Promise<void> {
    const hoursRemaining = Math.floor(timeRemaining / (1000 * 60 * 60));
    
    // Check if we've already sent a warning recently
    const warningKey = `sla:warning:${workOrder.id}`;
    const recentWarning = await this.redis.get(warningKey);
    
    if (recentWarning) {
      return; // Already warned
    }

    // Send warning notification
    await this.notificationService.sendSlaWarningNotification(
      workOrder, 
      slaConfig, 
      assignedUser, 
      hoursRemaining
    );

    // Mark as warned (expires in 4 hours)
    await this.redis.setex(warningKey, 4 * 60 * 60, '1');

    logger.info('SLA warning issued', {
      workOrderId: workOrder.id,
      hoursRemaining
    });
  }

  private async handleEscalation(
    workOrder: any,
    slaConfig: any,
    escalationLevel: any,
    assignedUser: any
  ): Promise<void> {
    // Mark as escalated
    const escalationKey = `sla:escalation:${workOrder.id}:${escalationLevel.level}`;
    await this.redis.setex(escalationKey, 24 * 60 * 60, '1'); // Expires in 24 hours

    // Get users to notify
    const notifyUsers = [];
    
    // Add users by role
    if (escalationLevel.notifyRoles && Array.isArray(escalationLevel.notifyRoles)) {
      const roleUsers = await db.select()
        .from(schema.users)
        .where(and(
          eq(schema.users.tenantId, workOrder.tenantId),
          eq(schema.users.active, true),
          // This would need proper role checking
          inArray(schema.users.roles, escalationLevel.notifyRoles)
        ));
      
      notifyUsers.push(...roleUsers);
    }

    // Add specific users
    if (escalationLevel.notifyUsers && Array.isArray(escalationLevel.notifyUsers)) {
      const specificUsers = await db.select()
        .from(schema.users)
        .where(and(
          eq(schema.users.tenantId, workOrder.tenantId),
          inArray(schema.users.id, escalationLevel.notifyUsers)
        ));
      
      notifyUsers.push(...specificUsers);
    }

    // Send escalation notifications
    await this.notificationService.sendEscalationNotification(
      workOrder,
      slaConfig,
      escalationLevel,
      assignedUser,
      notifyUsers
    );

    // Create history entry
    await db.insert(schema.maintenanceHistory)
      .values({
        tenantId: workOrder.tenantId,
        deviceId: workOrder.deviceId,
        workOrderId: workOrder.id,
        activityType: 'maintenance',
        description: `SLA escalation level ${escalationLevel.level} triggered - ${slaConfig.name}`,
        performedBy: null // System generated
      });

    logger.info('SLA escalation triggered', {
      workOrderId: workOrder.id,
      escalationLevel: escalationLevel.level
    });
  }

  private async isEscalated(workOrderId: string, level: number): Promise<boolean> {
    const escalationKey = `sla:escalation:${workOrderId}:${level}`;
    const exists = await this.redis.exists(escalationKey);
    return exists === 1;
  }
}