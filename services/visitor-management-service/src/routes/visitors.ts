import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { VisitorService } from '../services/visitor.service';
import { NotificationService } from '../services/notification.service';
import { 
  VisitorPreRegistrationSchema,
  VisitorCheckInSchema,
  VisitorUpdateSchema,
  VisitorSearchSchema,
  VisitorApprovalSchema,
} from '../types';
import { logger } from '@sparc/shared';
import { Redis } from 'ioredis';

const visitorsRouter = new Hono();
const visitorService = new VisitorService();
const notificationService = new NotificationService();

// Pre-register a visitor
visitorsRouter.post(
  '/pre-register',
  zValidator('json', VisitorPreRegistrationSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const data = c.req.valid('json');

    const result = await visitorService.preRegisterVisitor(data, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Pre-registration failed' });
    }

    // Send notification
    await notificationService.sendVisitorNotification(
      result.data.visitor.id,
      'pre-registration',
      organizationId
    );

    return c.json(result);
  }
);

// Check in a visitor
visitorsRouter.post(
  '/check-in',
  zValidator('json', VisitorCheckInSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const data = c.req.valid('json');

    const result = await visitorService.checkInVisitor(data, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Check-in failed' });
    }

    // Send notification to host
    await notificationService.sendVisitorNotification(
      result.data.visitor.id,
      'check-in',
      organizationId
    );

    // Broadcast real-time update
    const redis = c.get('redis') as Redis;
    await redis.publish('visitor:events', JSON.stringify({
      type: 'visitor:checked-in',
      organizationId,
      data: {
        visitorId: result.data.visitor.id,
        visitor: result.data.visitor,
        timestamp: new Date().toISOString(),
        performedBy: userId,
      },
    }));

    return c.json(result);
  }
);

// Check out a visitor
visitorsRouter.post(
  '/:id/check-out',
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const visitorId = c.req.param('id');

    const result = await visitorService.checkOutVisitor(visitorId, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Check-out failed' });
    }

    // Send notification to host
    await notificationService.sendVisitorNotification(
      visitorId,
      'check-out',
      organizationId
    );

    // Broadcast real-time update
    const redis = c.get('redis') as Redis;
    await redis.publish('visitor:events', JSON.stringify({
      type: 'visitor:checked-out',
      organizationId,
      data: {
        visitorId,
        visitor: result.data.visitor,
        timestamp: new Date().toISOString(),
        performedBy: userId,
      },
    }));

    return c.json(result);
  }
);

// Search visitors
visitorsRouter.get(
  '/',
  zValidator('query', VisitorSearchSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const params = c.req.valid('query');

    const result = await visitorService.searchVisitors(params, organizationId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Search failed' });
    }

    return c.json(result);
  }
);

// Get visitor by ID
visitorsRouter.get('/:id', async (c) => {
  const organizationId = c.get('tenantId');
  const visitorId = c.req.param('id');

  const result = await visitorService.getVisitorById(visitorId, organizationId);
  
  if (!result.success) {
    throw new HTTPException(404, { message: result.error?.message || 'Visitor not found' });
  }

  return c.json(result);
});

// Update visitor
visitorsRouter.put(
  '/:id',
  zValidator('json', VisitorUpdateSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const visitorId = c.req.param('id');
    const data = c.req.valid('json');

    const result = await visitorService.updateVisitor(visitorId, data, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Update failed' });
    }

    // Broadcast real-time update
    const redis = c.get('redis') as Redis;
    await redis.publish('visitor:events', JSON.stringify({
      type: 'visitor:updated',
      organizationId,
      data: {
        visitorId,
        visitor: result.data.visitor,
        timestamp: new Date().toISOString(),
        performedBy: userId,
      },
    }));

    return c.json(result);
  }
);

// Approve or deny visitor
visitorsRouter.post(
  '/:id/approval',
  zValidator('json', VisitorApprovalSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const visitorId = c.req.param('id');
    const { approved, reason, accessAreas, validUntil } = c.req.valid('json');

    const updateData: any = {
      status: approved ? 'APPROVED' : 'DENIED',
    };

    if (approved) {
      updateData.approvedBy = userId;
      updateData.approvedAt = new Date();
      if (accessAreas) updateData.accessAreas = accessAreas;
      if (validUntil) updateData.expectedDeparture = new Date(validUntil);
    } else {
      updateData.deniedBy = userId;
      updateData.deniedAt = new Date();
      if (reason) updateData.denialReason = reason;
    }

    const result = await visitorService.updateVisitor(visitorId, updateData, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Approval update failed' });
    }

    // Send notification to visitor
    await notificationService.sendVisitorNotification(
      visitorId,
      approved ? 'approved' : 'denied',
      organizationId
    );

    // Broadcast real-time update
    const redis = c.get('redis') as Redis;
    await redis.publish('visitor:events', JSON.stringify({
      type: approved ? 'visitor:approved' : 'visitor:denied',
      organizationId,
      data: {
        visitorId,
        visitor: result.data.visitor,
        timestamp: new Date().toISOString(),
        performedBy: userId,
      },
    }));

    return c.json(result);
  }
);

// Get active visitors (currently on-site)
visitorsRouter.get('/active/all', async (c) => {
  const organizationId = c.get('tenantId');

  const result = await visitorService.getActiveVisitors(organizationId);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Failed to get active visitors' });
  }

  return c.json(result);
});

// Get overstay visitors
visitorsRouter.get('/overstay/all', async (c) => {
  const organizationId = c.get('tenantId');

  const result = await visitorService.getOverstayVisitors(organizationId);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Failed to get overstay visitors' });
  }

  // Send overstay notifications if needed
  for (const visitor of result.data) {
    // Check if notification was already sent (simple implementation)
    const redis = c.get('redis') as Redis;
    const notificationKey = `overstay:notified:${visitor.id}`;
    const alreadyNotified = await redis.get(notificationKey);
    
    if (!alreadyNotified) {
      await notificationService.sendVisitorNotification(
        visitor.id,
        'overstay',
        organizationId
      );
      // Mark as notified for 24 hours
      await redis.setex(notificationKey, 86400, '1');
    }
  }

  return c.json(result);
});

// Get visitor analytics
visitorsRouter.get('/analytics/summary', async (c) => {
  const organizationId = c.get('tenantId');
  const fromDate = c.req.query('fromDate') ? new Date(c.req.query('fromDate')!) : undefined;
  const toDate = c.req.query('toDate') ? new Date(c.req.query('toDate')!) : undefined;

  const result = await visitorService.getVisitorAnalytics(organizationId, fromDate, toDate);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Failed to get analytics' });
  }

  return c.json(result);
});

// Emergency evacuation list
visitorsRouter.get('/emergency/evacuation', async (c) => {
  const organizationId = c.get('tenantId');
  const userId = c.get('userId');

  const result = await visitorService.getActiveVisitors(organizationId);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Failed to get evacuation list' });
  }

  // Log emergency access
  logger.warn('Emergency evacuation list accessed', {
    organizationId,
    userId,
    visitorCount: result.data.length,
    timestamp: new Date().toISOString(),
  });

  return c.json({
    ...result,
    emergency: true,
    generatedAt: new Date().toISOString(),
    totalOnSite: result.data.length,
  });
});

export default visitorsRouter;