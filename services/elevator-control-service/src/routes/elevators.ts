import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { ElevatorService } from '../services/elevator-service';
import { AccessControlIntegration } from '../services/access-control-integration';
import { AlertServiceIntegration } from '../services/alert-service-integration';
import { DestinationDispatchService } from '../services/destination-dispatch-service';
import { 
  elevatorControlSchema, 
  floorAccessRequestSchema, 
  emergencyOverrideSchema,
  destinationDispatchSchema 
} from '../types';
import { Logger } from '../utils/logger';

export function createElevatorRoutes(
  prisma: PrismaClient,
  redis: Redis,
  logger: Logger,
  elevatorService: ElevatorService,
  accessControl: AccessControlIntegration,
  alertService: AlertServiceIntegration,
  dispatchService: DestinationDispatchService
) {
  const app = new Hono();

  // List elevators
  app.get('/', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const buildingId = c.req.query('buildingId');

      const elevators = await elevatorService.getAllElevatorsWithStatus(tenantId, buildingId);

      return c.json({
        elevators,
        total: elevators.length,
      });
    } catch (error) {
      logger.error('Failed to fetch elevators', { error: error.message });
      return c.json({ error: 'Failed to fetch elevators' }, 500);
    }
  });

  // Get elevator by ID
  app.get('/:id', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const elevatorId = c.req.param('id');

      const elevator = await elevatorService.getElevatorWithStatus(elevatorId, tenantId);

      if (!elevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      return c.json({ elevator });
    } catch (error) {
      logger.error('Failed to fetch elevator', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to fetch elevator' }, 500);
    }
  });

  // Create elevator
  app.post('/', zValidator('json', elevatorControlSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');
      const validatedData = c.req.valid('json');

      // Verify building exists and belongs to tenant
      const building = await prisma.building.findFirst({
        where: { id: validatedData.buildingId, site: { tenantId } },
      });

      if (!building) {
        return c.json({ error: 'Building not found' }, 404);
      }

      const elevator = await prisma.elevatorControl.create({
        data: {
          ...validatedData,
          tenantId,
        },
        include: {
          building: {
            select: {
              id: true,
              name: true,
              floors: true,
            },
          },
        },
      });

      // Log audit event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: user.id,
          action: 'ELEVATOR_CREATED',
          resourceType: 'ELEVATOR',
          resourceId: elevator.id,
          details: { elevatorData: validatedData },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      logger.info('Elevator created', { 
        elevatorId: elevator.id, 
        tenantId, 
        userId: user.id 
      });

      return c.json({ elevator }, 201);
    } catch (error) {
      if (error.name === 'ZodError') {
        return c.json({ error: 'Validation failed', details: error.errors }, 400);
      }
      logger.error('Failed to create elevator', { error: error.message });
      return c.json({ error: 'Failed to create elevator' }, 500);
    }
  });

  // Update elevator
  app.put('/:id', zValidator('json', elevatorControlSchema.partial()), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');
      const elevatorId = c.req.param('id');
      const validatedData = c.req.valid('json');

      const existingElevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
      });

      if (!existingElevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      const elevator = await prisma.elevatorControl.update({
        where: { id: elevatorId },
        data: validatedData,
        include: {
          building: {
            select: {
              id: true,
              name: true,
              floors: true,
            },
          },
        },
      });

      // Log audit event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: user.id,
          action: 'ELEVATOR_UPDATED',
          resourceType: 'ELEVATOR',
          resourceId: elevator.id,
          details: { changes: validatedData },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      logger.info('Elevator updated', { 
        elevatorId, 
        tenantId, 
        userId: user.id 
      });

      return c.json({ elevator });
    } catch (error) {
      if (error.name === 'ZodError') {
        return c.json({ error: 'Validation failed', details: error.errors }, 400);
      }
      logger.error('Failed to update elevator', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to update elevator' }, 500);
    }
  });

  // Delete elevator
  app.delete('/:id', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');
      const elevatorId = c.req.param('id');

      const existingElevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
      });

      if (!existingElevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      await prisma.elevatorControl.delete({
        where: { id: elevatorId },
      });

      // Log audit event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: user.id,
          action: 'ELEVATOR_DELETED',
          resourceType: 'ELEVATOR',
          resourceId: elevatorId,
          details: { elevatorName: existingElevator.name },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      logger.info('Elevator deleted', { 
        elevatorId, 
        tenantId, 
        userId: user.id 
      });

      return c.json({ message: 'Elevator deleted successfully' });
    } catch (error) {
      logger.error('Failed to delete elevator', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to delete elevator' }, 500);
    }
  });

  // Floor access request
  app.post('/:id/access', zValidator('json', floorAccessRequestSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const elevatorId = c.req.param('id');
      const validatedData = c.req.valid('json');

      const elevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
        include: { building: true },
      });

      if (!elevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      // Check if target floor is served by this elevator
      const floorsServed = elevator.floorsServed as number[];
      if (!floorsServed.includes(validatedData.targetFloor)) {
        return c.json({ error: 'Floor not served by this elevator' }, 400);
      }

      // Check user access permissions
      const hasAccess = await accessControl.checkUserAccess(
        validatedData.userId,
        elevator.buildingId,
        validatedData.targetFloor
      );

      if (!hasAccess) {
        // Log access denied event
        await prisma.auditLog.create({
          data: {
            tenantId,
            userId: validatedData.userId,
            action: 'ELEVATOR_ACCESS_DENIED',
            resourceType: 'ELEVATOR',
            resourceId: elevatorId,
            details: { 
              targetFloor: validatedData.targetFloor,
              reason: 'Insufficient permissions',
            },
            ipAddress: c.req.header('x-forwarded-for') || 'unknown',
            userAgent: c.req.header('user-agent') || 'unknown',
          },
        });

        return c.json({ error: 'Access denied to target floor' }, 403);
      }

      // Send floor request to elevator
      const success = await elevatorService.sendFloorRequest(
        elevatorId, 
        validatedData.targetFloor, 
        validatedData.userId
      );

      if (!success) {
        await alertService.sendElevatorAlert(
          elevatorId,
          'COMMUNICATION_ERROR',
          `Failed to send floor request to elevator ${elevator.name}`,
          'HIGH'
        );
        return c.json({ error: 'Failed to communicate with elevator' }, 500);
      }

      // Log successful access event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: validatedData.userId,
          action: 'ELEVATOR_ACCESS_GRANTED',
          resourceType: 'ELEVATOR',
          resourceId: elevatorId,
          details: { 
            targetFloor: validatedData.targetFloor,
            credentialId: validatedData.credentialId,
            reason: validatedData.reason,
          },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      logger.info('Elevator access granted', { 
        elevatorId, 
        userId: validatedData.userId, 
        targetFloor: validatedData.targetFloor 
      });

      return c.json({
        message: 'Floor access granted',
        elevatorId,
        targetFloor: validatedData.targetFloor,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      if (error.name === 'ZodError') {
        return c.json({ error: 'Validation failed', details: error.errors }, 400);
      }
      logger.error('Failed to process floor access request', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to process access request' }, 500);
    }
  });

  // Emergency override
  app.post('/:id/emergency', zValidator('json', emergencyOverrideSchema), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');
      const elevatorId = c.req.param('id');
      const validatedData = c.req.valid('json');

      const elevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
      });

      if (!elevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      // Check if user has emergency override permissions
      const userRoles = user.roles || [];
      if (!userRoles.includes('SECURITY_ADMIN') && !userRoles.includes('EMERGENCY_RESPONDER')) {
        return c.json({ error: 'Insufficient permissions for emergency override' }, 403);
      }

      const success = await elevatorService.setEmergencyOverride(
        elevatorId,
        validatedData.action,
        validatedData.reason
      );

      if (!success) {
        await alertService.sendElevatorAlert(
          elevatorId,
          'EMERGENCY_OVERRIDE_FAILED',
          `Failed to ${validatedData.action.toLowerCase()} emergency override for elevator ${elevator.name}`,
          'CRITICAL'
        );
        return c.json({ error: 'Failed to execute emergency override' }, 500);
      }

      const emergencyEnabled = validatedData.action !== 'DISABLE';

      // Update elevator status in database
      await prisma.elevatorControl.update({
        where: { id: elevatorId },
        data: { 
          emergencyOverride: emergencyEnabled,
          status: emergencyEnabled ? 'emergency' : 'normal',
        },
      });

      // Log emergency override event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: user.id,
          action: `ELEVATOR_EMERGENCY_${validatedData.action}`,
          resourceType: 'ELEVATOR',
          resourceId: elevatorId,
          details: { 
            action: validatedData.action,
            reason: validatedData.reason,
            duration: validatedData.duration,
          },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      // Send alert for emergency override
      await alertService.sendElevatorAlert(
        elevatorId,
        'EMERGENCY_OVERRIDE',
        `Emergency override ${validatedData.action.toLowerCase()} activated for elevator ${elevator.name}: ${validatedData.reason}`,
        'CRITICAL'
      );

      logger.info('Emergency override executed', { 
        elevatorId, 
        action: validatedData.action, 
        userId: user.id 
      });

      // Schedule automatic disable if duration is specified
      if (validatedData.duration && emergencyEnabled) {
        setTimeout(async () => {
          try {
            await elevatorService.setEmergencyOverride(elevatorId, 'DISABLE', 'Automatic timeout');
            await prisma.elevatorControl.update({
              where: { id: elevatorId },
              data: { 
                emergencyOverride: false,
                status: 'normal',
              },
            });
            
            await alertService.sendElevatorAlert(
              elevatorId,
              'EMERGENCY_OVERRIDE_TIMEOUT',
              `Emergency override automatically disabled for elevator ${elevator.name} after ${validatedData.duration} seconds`,
              'MEDIUM'
            );
          } catch (error) {
            logger.error('Failed to automatically disable emergency override', { 
              elevatorId, 
              error: error.message 
            });
          }
        }, validatedData.duration * 1000);
      }

      return c.json({
        message: `Emergency override ${validatedData.action.toLowerCase()} executed successfully`,
        elevatorId,
        action: validatedData.action,
        emergencyEnabled,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      if (error.name === 'ZodError') {
        return c.json({ error: 'Validation failed', details: error.errors }, 400);
      }
      logger.error('Failed to execute emergency override', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to execute emergency override' }, 500);
    }
  });

  // Get elevator status
  app.get('/:id/status', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const elevatorId = c.req.param('id');

      const elevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
      });

      if (!elevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      const status = await elevatorService.getElevatorStatus(elevatorId);

      if (!status) {
        await alertService.sendElevatorAlert(
          elevatorId,
          'STATUS_UNAVAILABLE',
          `Unable to retrieve status for elevator ${elevator.name}`,
          'MEDIUM'
        );
        return c.json({ error: 'Unable to retrieve elevator status' }, 503);
      }

      return c.json({
        elevatorId,
        elevatorName: elevator.name,
        status,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to get elevator status', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to get elevator status' }, 500);
    }
  });

  // Get elevator diagnostics
  app.get('/:id/diagnostics', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');
      const elevatorId = c.req.param('id');

      // Check if user has maintenance permissions
      const userRoles = user.roles || [];
      if (!userRoles.includes('MAINTENANCE') && !userRoles.includes('ADMIN')) {
        return c.json({ error: 'Insufficient permissions for diagnostics' }, 403);
      }

      const elevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
      });

      if (!elevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      const diagnostics = await elevatorService.getDiagnostics(elevatorId);

      return c.json({
        elevatorId,
        elevatorName: elevator.name,
        diagnostics,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to get elevator diagnostics', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to get elevator diagnostics' }, 500);
    }
  });

  // Set maintenance mode
  app.post('/:id/maintenance', zValidator('json', z.object({
    enabled: z.boolean(),
    reason: z.string().min(1)
  })), async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');
      const elevatorId = c.req.param('id');
      const { enabled, reason } = c.req.valid('json');

      // Check if user has maintenance permissions
      const userRoles = user.roles || [];
      if (!userRoles.includes('MAINTENANCE') && !userRoles.includes('ADMIN')) {
        return c.json({ error: 'Insufficient permissions for maintenance mode' }, 403);
      }

      const elevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
      });

      if (!elevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      const success = await elevatorService.setMaintenanceMode(elevatorId, enabled, reason);

      if (!success) {
        return c.json({ error: 'Failed to set maintenance mode' }, 500);
      }

      // Log maintenance mode change
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: user.id,
          action: enabled ? 'ELEVATOR_MAINTENANCE_ENABLED' : 'ELEVATOR_MAINTENANCE_DISABLED',
          resourceType: 'ELEVATOR',
          resourceId: elevatorId,
          details: { reason },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      await alertService.sendElevatorAlert(
        elevatorId,
        'MAINTENANCE_MODE',
        `Maintenance mode ${enabled ? 'enabled' : 'disabled'} for elevator ${elevator.name}: ${reason}`,
        'MEDIUM'
      );

      return c.json({
        message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'} successfully`,
        elevatorId,
        maintenanceMode: enabled,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      if (error.name === 'ZodError') {
        return c.json({ error: 'Validation failed', details: error.errors }, 400);
      }
      logger.error('Failed to set maintenance mode', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to set maintenance mode' }, 500);
    }
  });

  // Reset elevator
  app.post('/:id/reset', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');
      const elevatorId = c.req.param('id');

      // Check if user has maintenance permissions
      const userRoles = user.roles || [];
      if (!userRoles.includes('MAINTENANCE') && !userRoles.includes('ADMIN')) {
        return c.json({ error: 'Insufficient permissions for elevator reset' }, 403);
      }

      const elevator = await prisma.elevatorControl.findFirst({
        where: { id: elevatorId, tenantId },
      });

      if (!elevator) {
        return c.json({ error: 'Elevator not found' }, 404);
      }

      const success = await elevatorService.resetElevator(elevatorId);

      if (!success) {
        return c.json({ error: 'Failed to reset elevator' }, 500);
      }

      // Log reset event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: user.id,
          action: 'ELEVATOR_RESET',
          resourceType: 'ELEVATOR',
          resourceId: elevatorId,
          details: {},
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      return c.json({
        message: 'Elevator reset successfully',
        elevatorId,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to reset elevator', { 
        elevatorId: c.req.param('id'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to reset elevator' }, 500);
    }
  });

  return app;
}