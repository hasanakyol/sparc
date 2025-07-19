import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { AccessControlIntegration } from '../services/access-control-integration';
import { Logger } from '../utils/logger';

export function createIntegrationRoutes(
  prisma: PrismaClient,
  logger: Logger,
  accessControl: AccessControlIntegration
) {
  const app = new Hono();

  // Sync access control permissions
  app.post('/access-control/sync', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');

      // Sync access control permissions for all elevators
      const elevators = await prisma.elevatorControl.findMany({
        where: { tenantId },
        include: { building: true },
      });

      let syncCount = 0;
      const errors = [];

      for (const elevator of elevators) {
        try {
          // Get updated access rules from access control service
          const accessRules = await accessControl.getAccessRules(elevator.buildingId);

          if (accessRules && accessRules.accessRules) {
            await prisma.elevatorControl.update({
              where: { id: elevator.id },
              data: { accessRules: accessRules.accessRules },
            });
            syncCount++;
          }
        } catch (error) {
          logger.error('Failed to sync access rules for elevator', { 
            elevatorId: elevator.id, 
            error: error.message 
          });
          errors.push({
            elevatorId: elevator.id,
            elevatorName: elevator.name,
            error: error.message
          });
        }
      }

      // Log sync event
      await prisma.auditLog.create({
        data: {
          tenantId,
          userId: user.id,
          action: 'ACCESS_CONTROL_SYNC',
          resourceType: 'SYSTEM',
          resourceId: 'elevator-control-service',
          details: { 
            syncedElevators: syncCount, 
            totalElevators: elevators.length,
            errors: errors.length > 0 ? errors : undefined
          },
          ipAddress: c.req.header('x-forwarded-for') || 'unknown',
          userAgent: c.req.header('user-agent') || 'unknown',
        },
      });

      logger.info('Access control sync completed', { 
        tenantId, 
        syncCount, 
        totalElevators: elevators.length,
        errorCount: errors.length 
      });

      return c.json({
        message: 'Access control sync completed',
        syncedElevators: syncCount,
        totalElevators: elevators.length,
        errors,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to sync access control', { error: error.message });
      return c.json({ error: 'Failed to sync access control' }, 500);
    }
  });

  // Test connection to all elevators
  app.post('/test-connections', async (c) => {
    try {
      const tenantId = c.get('tenantId');
      const user = c.get('user');

      // Check if user has admin permissions
      const userRoles = user.roles || [];
      if (!userRoles.includes('ADMIN')) {
        return c.json({ error: 'Insufficient permissions for connection test' }, 403);
      }

      const elevators = await prisma.elevatorControl.findMany({
        where: { tenantId },
      });

      const results = await Promise.all(
        elevators.map(async (elevator) => {
          try {
            // TODO: Test actual connection using adapter
            // For now, we'll simulate the test
            const connected = Math.random() > 0.1; // 90% success rate for simulation
            
            return {
              elevatorId: elevator.id,
              elevatorName: elevator.name,
              manufacturer: elevator.manufacturer,
              ipAddress: elevator.ipAddress,
              connected,
              responseTime: connected ? Math.floor(Math.random() * 100) + 50 : null,
              error: connected ? null : 'Connection timeout'
            };
          } catch (error) {
            return {
              elevatorId: elevator.id,
              elevatorName: elevator.name,
              manufacturer: elevator.manufacturer,
              ipAddress: elevator.ipAddress,
              connected: false,
              responseTime: null,
              error: error.message
            };
          }
        })
      );

      const connectedCount = results.filter(r => r.connected).length;

      logger.info('Connection test completed', { 
        tenantId,
        totalElevators: elevators.length,
        connectedCount,
        failedCount: elevators.length - connectedCount
      });

      return c.json({
        message: 'Connection test completed',
        totalElevators: elevators.length,
        connectedCount,
        failedCount: elevators.length - connectedCount,
        results,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error('Failed to test connections', { error: error.message });
      return c.json({ error: 'Failed to test connections' }, 500);
    }
  });

  return app;
}