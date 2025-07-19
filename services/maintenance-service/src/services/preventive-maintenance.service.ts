import * as cron from 'node-cron';
import Redis from 'ioredis';
import { db, schema } from '../db';
import { eq, and, lte, inArray } from 'drizzle-orm';
import { logger } from '@sparc/shared';
import { NotificationService } from './notification.service';

export class PreventiveMaintenanceService {
  private scheduledTask: cron.ScheduledTask | null = null;
  private running = false;

  constructor(
    private redis: Redis,
    private notificationService: NotificationService
  ) {}

  async start(): Promise<void> {
    // Run every hour at minute 0
    this.scheduledTask = cron.schedule('0 * * * *', async () => {
      await this.generateScheduledWorkOrders();
    });

    this.running = true;
    logger.info('Preventive maintenance service started');
  }

  async stop(): Promise<void> {
    if (this.scheduledTask) {
      this.scheduledTask.stop();
      this.scheduledTask = null;
    }
    this.running = false;
    logger.info('Preventive maintenance service stopped');
  }

  isRunning(): boolean {
    return this.running;
  }

  private async generateScheduledWorkOrders(): Promise<void> {
    const startTime = Date.now();
    logger.info('Starting preventive maintenance generation');

    try {
      // Get all active schedules that are due
      const dueSchedules = await db.select()
        .from(schema.preventiveMaintenanceSchedules)
        .where(and(
          eq(schema.preventiveMaintenanceSchedules.active, 1),
          lte(schema.preventiveMaintenanceSchedules.nextGeneration, new Date())
        ));

      logger.info(`Found ${dueSchedules.length} due schedules`);

      let totalGenerated = 0;

      for (const schedule of dueSchedules) {
        try {
          const generated = await this.processSchedule(schedule);
          totalGenerated += generated;
        } catch (error) {
          logger.error('Failed to process schedule', { 
            scheduleId: schedule.id, 
            error 
          });
        }
      }

      // Update metrics
      if (totalGenerated > 0) {
        await this.redis.incr('metrics:pm:generated', totalGenerated);
      }

      const duration = Date.now() - startTime;
      logger.info('Preventive maintenance generation completed', {
        schedulesProcessed: dueSchedules.length,
        workOrdersGenerated: totalGenerated,
        durationMs: duration
      });

    } catch (error) {
      logger.error('Failed to generate preventive maintenance work orders', { error });
    }
  }

  private async processSchedule(schedule: any): Promise<number> {
    const tenantId = schedule.tenantId;
    let generated = 0;

    // Get applicable devices
    let deviceQuery = db.select()
      .from(schema.devices)
      .where(and(
        eq(schema.devices.tenantId, tenantId),
        eq(schema.devices.type, schedule.deviceType),
        eq(schema.devices.status, 'active')
      ));

    // Filter by specific device IDs if specified
    if (schedule.deviceIds && (schedule.deviceIds as string[]).length > 0) {
      deviceQuery = deviceQuery.where(
        inArray(schema.devices.id, schedule.deviceIds as string[])
      );
    }

    const devices = await deviceQuery;

    logger.info(`Processing ${devices.length} devices for schedule ${schedule.id}`);

    // Generate work order for each device
    for (const device of devices) {
      try {
        // Check if there's already an open preventive maintenance work order
        const [existingWorkOrder] = await db.select()
          .from(schema.workOrders)
          .where(and(
            eq(schema.workOrders.tenantId, tenantId),
            eq(schema.workOrders.deviceId, device.id),
            eq(schema.workOrders.workOrderType, 'preventive'),
            inArray(schema.workOrders.status, ['open', 'assigned', 'in_progress'])
          ))
          .limit(1);

        if (!existingWorkOrder) {
          const template = schedule.workOrderTemplate as any;
          
          // Calculate scheduled date
          const scheduledDate = this.calculateScheduledDate(schedule.interval);

          // Create work order
          const [workOrder] = await db.insert(schema.workOrders)
            .values({
              tenantId,
              deviceId: device.id,
              deviceType: device.type,
              workOrderType: 'preventive',
              priority: template.priority || 'medium',
              title: template.title.replace('{device}', device.name),
              description: template.description.replace('{device}', device.name),
              scheduledDate,
              estimatedCost: (template.estimatedHours * 75).toString(), // Default hourly rate
              status: 'open',
              diagnosticData: {
                scheduleId: schedule.id,
                scheduleName: schedule.name
              }
            })
            .returning();

          // Create history entry
          await db.insert(schema.maintenanceHistory)
            .values({
              tenantId,
              deviceId: device.id,
              workOrderId: workOrder.id,
              activityType: 'maintenance',
              description: `Preventive maintenance work order generated from schedule: ${schedule.name}`,
              performedBy: null, // System generated
              nextActionDate: scheduledDate
            });

          // Publish work order created event
          await this.redis.publish('maintenance:work-order:update', JSON.stringify({
            action: 'created',
            tenantId,
            workOrder
          }));

          generated++;

          // Send notification
          await this.notificationService.sendWorkOrderNotification(workOrder, 'created');
        }
      } catch (error) {
        logger.error('Failed to generate work order for device', {
          deviceId: device.id,
          scheduleId: schedule.id,
          error
        });
      }
    }

    // Update schedule's last generated and next generation dates
    const nextGeneration = this.calculateNextGeneration(schedule.interval, schedule.intervalValue);
    
    await db.update(schema.preventiveMaintenanceSchedules)
      .set({
        lastGenerated: new Date(),
        nextGeneration,
        updatedAt: new Date()
      })
      .where(eq(schema.preventiveMaintenanceSchedules.id, schedule.id));

    logger.info(`Generated ${generated} work orders for schedule ${schedule.id}`);

    return generated;
  }

  private calculateScheduledDate(interval: string): Date {
    const now = new Date();
    
    // Schedule work orders 7 days from now by default
    const scheduledDate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    
    // Adjust to next business day if falls on weekend
    const dayOfWeek = scheduledDate.getDay();
    if (dayOfWeek === 0) { // Sunday
      scheduledDate.setDate(scheduledDate.getDate() + 1);
    } else if (dayOfWeek === 6) { // Saturday
      scheduledDate.setDate(scheduledDate.getDate() + 2);
    }
    
    return scheduledDate;
  }

  private calculateNextGeneration(interval: string, intervalValue: number): Date {
    const now = new Date();
    
    switch (interval) {
      case 'daily':
        return new Date(now.getTime() + intervalValue * 24 * 60 * 60 * 1000);
      case 'weekly':
        return new Date(now.getTime() + intervalValue * 7 * 24 * 60 * 60 * 1000);
      case 'monthly':
        const nextMonth = new Date(now);
        nextMonth.setMonth(nextMonth.getMonth() + intervalValue);
        return nextMonth;
      case 'quarterly':
        const nextQuarter = new Date(now);
        nextQuarter.setMonth(nextQuarter.getMonth() + intervalValue * 3);
        return nextQuarter;
      case 'annually':
        const nextYear = new Date(now);
        nextYear.setFullYear(nextYear.getFullYear() + intervalValue);
        return nextYear;
      default:
        return new Date(now.getTime() + 24 * 60 * 60 * 1000); // Default to 1 day
    }
  }
}