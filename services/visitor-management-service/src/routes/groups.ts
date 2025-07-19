import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { and, eq } from 'drizzle-orm';
import { getDb } from '../db';
import { 
  visitorGroups,
  visitorGroupMembers,
  visitors,
  users
} from '@sparc/database/schemas/visitor-management';
import { users as userTable } from '@sparc/database/schemas/user-management';
import { VisitorGroupSchema } from '../types';
import { VisitorService } from '../services/visitor.service';
import { NotificationService } from '../services/notification.service';
import { logger } from '@sparc/shared';

const groupsRouter = new Hono();
const db = getDb();
const visitorService = new VisitorService();
const notificationService = new NotificationService();

// Create visitor group
groupsRouter.post(
  '/',
  zValidator('json', VisitorGroupSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const data = c.req.valid('json');

    try {
      // Check if host exists
      const [host] = await db
        .select()
        .from(userTable)
        .where(and(
          eq(userTable.id, data.hostUserId),
          eq(userTable.organizationId, organizationId)
        ))
        .limit(1);

      if (!host) {
        throw new HTTPException(404, { message: 'Host not found' });
      }

      // Create group
      const [group] = await db
        .insert(visitorGroups)
        .values({
          organizationId,
          name: data.name,
          description: data.description,
          groupSize: data.groupSize,
          purpose: data.purpose,
          hostUserId: data.hostUserId,
          expectedArrival: new Date(data.expectedArrival),
          expectedDeparture: new Date(data.expectedDeparture),
          accessAreas: data.accessAreas || [],
          requiresEscort: data.requiresEscort,
          createdBy: userId,
        })
        .returning();

      // Create visitors and group members
      const createdVisitors = [];
      let primaryContactId = null;

      for (const member of data.members) {
        // Create visitor
        const result = await visitorService.preRegisterVisitor(
          {
            ...member,
            purpose: data.purpose,
            hostUserId: data.hostUserId,
            expectedArrival: data.expectedArrival,
            expectedDeparture: data.expectedDeparture,
            accessAreas: data.accessAreas,
            requiresEscort: data.requiresEscort,
          },
          organizationId,
          userId
        );

        if (result.success) {
          const visitor = result.data.visitor;
          createdVisitors.push(visitor);

          // Add to group
          await db.insert(visitorGroupMembers).values({
            groupId: group.id,
            visitorId: visitor.id,
            isPrimaryContact: member.isPrimaryContact || false,
          });

          if (member.isPrimaryContact) {
            primaryContactId = visitor.id;
          }

          // Send notification
          await notificationService.sendVisitorNotification(
            visitor.id,
            'pre-registration',
            organizationId
          );
        }
      }

      // Update group with primary contact
      if (primaryContactId) {
        await db
          .update(visitorGroups)
          .set({ primaryContactId })
          .where(eq(visitorGroups.id, group.id));
      }

      logger.info('Visitor group created', {
        groupId: group.id,
        organizationId,
        memberCount: createdVisitors.length,
        createdBy: userId,
      });

      return c.json({
        success: true,
        data: {
          group,
          members: createdVisitors,
        },
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to create visitor group', { error });
      throw new HTTPException(500, { message: 'Failed to create group' });
    }
  }
);

// Get visitor group
groupsRouter.get('/:id', async (c) => {
  const organizationId = c.get('tenantId');
  const groupId = c.req.param('id');

  try {
    const result = await db
      .select({
        group: visitorGroups,
        host: {
          id: userTable.id,
          firstName: userTable.firstName,
          lastName: userTable.lastName,
          email: userTable.email,
        },
      })
      .from(visitorGroups)
      .leftJoin(userTable, eq(visitorGroups.hostUserId, userTable.id))
      .where(and(
        eq(visitorGroups.id, groupId),
        eq(visitorGroups.organizationId, organizationId)
      ))
      .limit(1);

    if (!result.length) {
      throw new HTTPException(404, { message: 'Group not found' });
    }

    // Get group members
    const members = await db
      .select({
        member: visitorGroupMembers,
        visitor: visitors,
      })
      .from(visitorGroupMembers)
      .leftJoin(visitors, eq(visitorGroupMembers.visitorId, visitors.id))
      .where(eq(visitorGroupMembers.groupId, groupId));

    return c.json({
      success: true,
      data: {
        ...result[0].group,
        host: result[0].host,
        members: members.map(m => ({
          ...m.visitor,
          isPrimaryContact: m.member.isPrimaryContact,
        })),
      },
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get visitor group', { error });
    throw new HTTPException(500, { message: 'Failed to get group' });
  }
});

// List visitor groups
groupsRouter.get('/', async (c) => {
  const organizationId = c.get('tenantId');
  const hostId = c.req.query('hostId');
  const fromDate = c.req.query('fromDate');
  const toDate = c.req.query('toDate');

  try {
    const conditions = [eq(visitorGroups.organizationId, organizationId)];

    if (hostId) {
      conditions.push(eq(visitorGroups.hostUserId, hostId));
    }

    if (fromDate) {
      conditions.push(eq(visitorGroups.expectedArrival, new Date(fromDate)));
    }

    if (toDate) {
      conditions.push(eq(visitorGroups.expectedArrival, new Date(toDate)));
    }

    const groups = await db
      .select({
        group: visitorGroups,
        host: {
          id: userTable.id,
          firstName: userTable.firstName,
          lastName: userTable.lastName,
        },
      })
      .from(visitorGroups)
      .leftJoin(userTable, eq(visitorGroups.hostUserId, userTable.id))
      .where(and(...conditions))
      .orderBy(visitorGroups.expectedArrival);

    // Get member counts
    const groupsWithCounts = await Promise.all(
      groups.map(async (g) => {
        const members = await db
          .select({ count: visitorGroupMembers.id })
          .from(visitorGroupMembers)
          .where(eq(visitorGroupMembers.groupId, g.group.id));

        return {
          ...g.group,
          host: g.host,
          memberCount: members.length,
        };
      })
    );

    return c.json({
      success: true,
      data: groupsWithCounts,
    });
  } catch (error) {
    logger.error('Failed to list visitor groups', { error });
    throw new HTTPException(500, { message: 'Failed to list groups' });
  }
});

// Check in entire group
groupsRouter.post('/:id/check-in', async (c) => {
  const organizationId = c.get('tenantId');
  const userId = c.get('userId');
  const groupId = c.req.param('id');

  try {
    // Get group and members
    const [group] = await db
      .select()
      .from(visitorGroups)
      .where(and(
        eq(visitorGroups.id, groupId),
        eq(visitorGroups.organizationId, organizationId)
      ))
      .limit(1);

    if (!group) {
      throw new HTTPException(404, { message: 'Group not found' });
    }

    // Get all group members
    const members = await db
      .select({
        visitor: visitors,
      })
      .from(visitorGroupMembers)
      .leftJoin(visitors, eq(visitorGroupMembers.visitorId, visitors.id))
      .where(eq(visitorGroupMembers.groupId, groupId));

    const checkedInMembers = [];
    const errors = [];

    // Check in each member
    for (const member of members) {
      if (member.visitor) {
        const result = await visitorService.checkInVisitor(
          { visitorId: member.visitor.id },
          organizationId,
          userId
        );

        if (result.success) {
          checkedInMembers.push(result.data.visitor);
          // Send notification
          await notificationService.sendVisitorNotification(
            member.visitor.id,
            'check-in',
            organizationId
          );
        } else {
          errors.push({
            visitorId: member.visitor.id,
            name: `${member.visitor.firstName} ${member.visitor.lastName}`,
            error: result.error,
          });
        }
      }
    }

    logger.info('Group check-in completed', {
      groupId,
      organizationId,
      checkedInCount: checkedInMembers.length,
      errorCount: errors.length,
    });

    return c.json({
      success: errors.length === 0,
      data: {
        group,
        checkedIn: checkedInMembers,
        failed: errors,
      },
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to check in group', { error });
    throw new HTTPException(500, { message: 'Failed to check in group' });
  }
});

// Check out entire group
groupsRouter.post('/:id/check-out', async (c) => {
  const organizationId = c.get('tenantId');
  const userId = c.get('userId');
  const groupId = c.req.param('id');

  try {
    // Get group and members
    const members = await db
      .select({
        visitor: visitors,
      })
      .from(visitorGroupMembers)
      .leftJoin(visitors, eq(visitorGroupMembers.visitorId, visitors.id))
      .where(eq(visitorGroupMembers.groupId, groupId));

    const checkedOutMembers = [];
    const errors = [];

    // Check out each member
    for (const member of members) {
      if (member.visitor && member.visitor.status === 'CHECKED_IN') {
        const result = await visitorService.checkOutVisitor(
          member.visitor.id,
          organizationId,
          userId
        );

        if (result.success) {
          checkedOutMembers.push(result.data.visitor);
          // Send notification
          await notificationService.sendVisitorNotification(
            member.visitor.id,
            'check-out',
            organizationId
          );
        } else {
          errors.push({
            visitorId: member.visitor.id,
            name: `${member.visitor.firstName} ${member.visitor.lastName}`,
            error: result.error,
          });
        }
      }
    }

    logger.info('Group check-out completed', {
      groupId,
      organizationId,
      checkedOutCount: checkedOutMembers.length,
      errorCount: errors.length,
    });

    return c.json({
      success: errors.length === 0,
      data: {
        checkedOut: checkedOutMembers,
        failed: errors,
      },
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to check out group', { error });
    throw new HTTPException(500, { message: 'Failed to check out group' });
  }
});

// Add member to existing group
groupsRouter.post('/:id/members', async (c) => {
  const organizationId = c.get('tenantId');
  const userId = c.get('userId');
  const groupId = c.req.param('id');
  const memberData = await c.req.json();

  try {
    // Check if group exists
    const [group] = await db
      .select()
      .from(visitorGroups)
      .where(and(
        eq(visitorGroups.id, groupId),
        eq(visitorGroups.organizationId, organizationId)
      ))
      .limit(1);

    if (!group) {
      throw new HTTPException(404, { message: 'Group not found' });
    }

    // Create visitor
    const result = await visitorService.preRegisterVisitor(
      {
        ...memberData,
        purpose: group.purpose,
        hostUserId: group.hostUserId,
        expectedArrival: group.expectedArrival.toISOString(),
        expectedDeparture: group.expectedDeparture.toISOString(),
        accessAreas: group.accessAreas || [],
        requiresEscort: group.requiresEscort,
      },
      organizationId,
      userId
    );

    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Failed to add member' });
    }

    // Add to group
    await db.insert(visitorGroupMembers).values({
      groupId,
      visitorId: result.data.visitor.id,
      isPrimaryContact: false,
    });

    // Send notification
    await notificationService.sendVisitorNotification(
      result.data.visitor.id,
      'pre-registration',
      organizationId
    );

    logger.info('Member added to group', {
      groupId,
      visitorId: result.data.visitor.id,
      organizationId,
    });

    return c.json({
      success: true,
      data: result.data.visitor,
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to add member to group', { error });
    throw new HTTPException(500, { message: 'Failed to add member' });
  }
});

// Remove member from group
groupsRouter.delete('/:groupId/members/:visitorId', async (c) => {
  const organizationId = c.get('tenantId');
  const groupId = c.req.param('groupId');
  const visitorId = c.req.param('visitorId');

  try {
    // Check if member exists in group
    const [member] = await db
      .select()
      .from(visitorGroupMembers)
      .where(and(
        eq(visitorGroupMembers.groupId, groupId),
        eq(visitorGroupMembers.visitorId, visitorId)
      ))
      .limit(1);

    if (!member) {
      throw new HTTPException(404, { message: 'Member not found in group' });
    }

    // Remove from group
    await db
      .delete(visitorGroupMembers)
      .where(and(
        eq(visitorGroupMembers.groupId, groupId),
        eq(visitorGroupMembers.visitorId, visitorId)
      ));

    logger.info('Member removed from group', {
      groupId,
      visitorId,
      organizationId,
    });

    return c.json({
      success: true,
      message: 'Member removed from group',
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to remove member from group', { error });
    throw new HTTPException(500, { message: 'Failed to remove member' });
  }
});

export default groupsRouter;