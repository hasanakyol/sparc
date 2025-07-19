import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import { ElevatorService } from '../services/elevator-service';
import { AccessControlIntegration } from '../services/access-control-integration';
import { DestinationDispatchService } from '../services/destination-dispatch-service';
import { destinationDispatchSchema } from '../types';
import { Logger } from '../utils/logger';

export function createDispatchRoutes(
  prisma: PrismaClient,
  logger: Logger,
  elevatorService: ElevatorService,
  accessControl: AccessControlIntegration,
  dispatchService: DestinationDispatchService
) {
  const app = new Hono();

  // Destination dispatch for a building
  app.post('/:buildingId/dispatch', 
    zValidator('json', z.object({
      requests: z.array(destinationDispatchSchema)
    })), 
    async (c) => {
      try {
        const tenantId = c.get('tenantId');
        const buildingId = c.req.param('buildingId');
        const { requests } = c.req.valid('json');

        // Verify building exists and belongs to tenant
        const building = await prisma.building.findFirst({
          where: { id: buildingId, site: { tenantId } },
        });

        if (!building) {
          return c.json({ error: 'Building not found' }, 404);
        }

        // Validate all users have access to their target floors
        for (const request of requests) {
          const hasAccess = await accessControl.checkUserAccess(
            request.userId,
            buildingId,
            request.targetFloor
          );

          if (!hasAccess) {
            return c.json({ 
              error: `User ${request.userId} does not have access to floor ${request.targetFloor}` 
            }, 403);
          }
        }

        // Optimize elevator assignments
        const assignments = await dispatchService.optimizeElevatorAssignment(buildingId, requests);

        // Execute assignments
        const results = [];
        for (const assignment of assignments) {
          const elevator = await prisma.elevatorControl.findUnique({
            where: { id: assignment.elevatorId },
          });

          if (elevator) {
            const success = await elevatorService.sendFloorRequest(
              assignment.elevatorId,
              assignment.targetFloor,
              assignment.userId
            );

            results.push({
              ...assignment,
              success,
              elevatorName: elevator.name,
            });

            // Log assignment
            await prisma.auditLog.create({
              data: {
                tenantId,
                userId: assignment.userId,
                action: 'DESTINATION_DISPATCH',
                resourceType: 'ELEVATOR',
                resourceId: assignment.elevatorId,
                details: { 
                  targetFloor: assignment.targetFloor,
                  priority: assignment.priority,
                  estimatedArrival: assignment.estimatedArrival,
                },
                ipAddress: c.req.header('x-forwarded-for') || 'unknown',
                userAgent: c.req.header('user-agent') || 'unknown',
              },
            });
          }
        }

        logger.info('Destination dispatch executed', { 
          buildingId, 
          requestCount: requests.length, 
          assignmentCount: assignments.length 
        });

        return c.json({
          message: 'Destination dispatch completed',
          buildingId,
          assignments: results,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        if (error.name === 'ZodError') {
          return c.json({ error: 'Validation failed', details: error.errors }, 400);
        }
        logger.error('Failed to execute destination dispatch', { 
          buildingId: c.req.param('buildingId'), 
          error: error.message 
        });
        return c.json({ error: 'Failed to execute destination dispatch' }, 500);
      }
    }
  );

  // Get building elevator status
  app.get('/:buildingId/elevators/status', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const buildingId = c.req.param('buildingId');

      const elevators = await prisma.elevatorControl.findMany({
        where: { buildingId, tenantId },
      });

      const statusResults = await Promise.all(
        elevators.map(async (elevator) => {
          try {
            const status = await elevatorService.getElevatorStatus(elevator.id);
            
            return {
              elevatorId: elevator.id,
              elevatorName: elevator.name,
              manufacturer: elevator.manufacturer,
              floorsServed: elevator.floorsServed,
              emergencyOverride: elevator.emergencyOverride,
              status,
            };
          } catch (error) {
            logger.error('Failed to get elevator status', { 
              elevatorId: elevator.id, 
              error: error.message 
            });
            
            return {
              elevatorId: elevator.id,
              elevatorName: elevator.name,
              manufacturer: elevator.manufacturer,
              floorsServed: elevator.floorsServed,
              emergencyOverride: elevator.emergencyOverride,
              status: null,
            };
          }
        })
      );

      return c.json({
        buildingId,
        elevators: statusResults,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to get building elevator status', { 
        buildingId: c.req.param('buildingId'), 
        error: error.message 
      });
      return c.json({ error: 'Failed to get elevator status' }, 500);
    }
  });

  return app;
}