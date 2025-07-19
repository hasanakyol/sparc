import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { AlertServiceIntegration } from '../services/alert-service-integration';
import { Logger } from '../utils/logger';

const webhookEventSchema = z.object({
  elevatorId: z.string(),
  eventType: z.string(),
  eventData: z.any(),
  timestamp: z.string(),
});

export function createWebhookRoutes(
  prisma: PrismaClient,
  redis: Redis,
  logger: Logger,
  alertService: AlertServiceIntegration
) {
  const app = new Hono();

  // Webhook endpoint for external elevator system events
  app.post('/elevator-events', zValidator('json', webhookEventSchema), async (c) => {
    try {
      const { elevatorId, eventType, eventData, timestamp } = c.req.valid('json');
      const signature = c.req.header('x-elevator-signature');

      // TODO: Implement signature verification based on manufacturer
      // For now, we'll skip signature verification

      // Find elevator in database
      const elevator = await prisma.elevatorControl.findUnique({
        where: { id: elevatorId },
      });

      if (!elevator) {
        logger.warn('Webhook received for unknown elevator', { elevatorId });
        return c.json({ error: 'Elevator not found' }, 404);
      }

      // Process different event types
      switch (eventType) {
        case 'STATUS_CHANGE':
          await redis.setex(`elevator:status:${elevatorId}`, 300, JSON.stringify(eventData));
          break;

        case 'EMERGENCY_ACTIVATED':
          await prisma.elevatorControl.update({
            where: { id: elevatorId },
            data: { emergencyOverride: true, status: 'emergency' },
          });
          
          await alertService.sendElevatorAlert(
            elevatorId,
            'EMERGENCY_ACTIVATED',
            `Emergency mode activated on elevator ${elevator.name}: ${eventData.reason || 'Unknown reason'}`,
            'CRITICAL'
          );
          break;

        case 'MAINTENANCE_REQUIRED':
          await alertService.sendElevatorAlert(
            elevatorId,
            'MAINTENANCE_REQUIRED',
            `Maintenance required for elevator ${elevator.name}: ${eventData.description || 'Scheduled maintenance'}`,
            'MEDIUM'
          );
          break;

        case 'FAULT_DETECTED':
          await alertService.sendElevatorAlert(
            elevatorId,
            'FAULT_DETECTED',
            `Fault detected on elevator ${elevator.name}: ${eventData.faultCode || 'Unknown fault'}`,
            'HIGH'
          );
          break;

        case 'DOOR_OBSTRUCTION':
          await alertService.sendElevatorAlert(
            elevatorId,
            'DOOR_OBSTRUCTION',
            `Door obstruction detected on elevator ${elevator.name} at floor ${eventData.floor || 'unknown'}`,
            'MEDIUM'
          );
          break;

        case 'OVERLOAD':
          await alertService.sendElevatorAlert(
            elevatorId,
            'OVERLOAD',
            `Overload detected on elevator ${elevator.name}. Current load: ${eventData.loadPercentage || 'unknown'}%`,
            'HIGH'
          );
          break;

        case 'POWER_FAILURE':
          await alertService.sendElevatorAlert(
            elevatorId,
            'POWER_FAILURE',
            `Power failure detected on elevator ${elevator.name}`,
            'CRITICAL'
          );
          break;

        case 'COMMUNICATION_LOST':
          await alertService.sendElevatorAlert(
            elevatorId,
            'COMMUNICATION_LOST',
            `Communication lost with elevator ${elevator.name}`,
            'HIGH'
          );
          break;

        case 'MAINTENANCE_COMPLETED':
          await prisma.elevatorControl.update({
            where: { id: elevatorId },
            data: { status: 'normal' },
          });
          
          await alertService.sendElevatorAlert(
            elevatorId,
            'MAINTENANCE_COMPLETED',
            `Maintenance completed for elevator ${elevator.name}`,
            'LOW'
          );
          break;

        default:
          logger.warn('Unknown elevator event type', { elevatorId, eventType });
      }

      // Log webhook event
      await prisma.auditLog.create({
        data: {
          tenantId: elevator.tenantId,
          userId: null,
          action: `ELEVATOR_WEBHOOK_${eventType}`,
          resourceType: 'ELEVATOR',
          resourceId: elevatorId,
          details: { eventType, eventData, webhookTimestamp: timestamp },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'webhook',
        },
      });

      logger.info('Elevator webhook processed', { elevatorId, eventType });

      return c.json({ message: 'Webhook processed successfully' });
    } catch (error) {
      if (error.name === 'ZodError') {
        return c.json({ error: 'Invalid webhook payload', details: error.errors }, 400);
      }
      logger.error('Failed to process elevator webhook', { error: error.message });
      return c.json({ error: 'Failed to process webhook' }, 500);
    }
  });

  // Health check webhook endpoint
  app.post('/health-check', async (c) => {
    try {
      const body = await c.req.json();
      logger.debug('Health check webhook received', body);
      
      return c.json({ 
        message: 'Health check received',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Failed to process health check webhook', { error: error.message });
      return c.json({ error: 'Failed to process health check' }, 500);
    }
  });

  return app;
}