import { Hono } from 'hono';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';
import { eq, and, desc, asc, gte, lte, inArray, isNull } from 'drizzle-orm';
import { db, schema } from '../db';
import { 
  createWorkOrderSchema, 
  updateWorkOrderSchema, 
  workOrderFilterSchema,
  CreateWorkOrderInput,
  UpdateWorkOrderInput,
  WorkOrderFilter
} from '../types';
import { logger } from '@sparc/shared';
import { trace } from '@opentelemetry/api';
import Redis from 'ioredis';

const tracer = trace.getTracer('maintenance-service');
const app = new Hono<{ Variables: { tenantId: string; userId: string; redis: Redis } }>();

// List work orders with filtering
app.get('/', async (c) => {
  const span = tracer.startSpan('listWorkOrders');
  
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    // Validate and parse filters
    const filters = workOrderFilterSchema.parse(query);
    
    // Build where conditions
    const conditions = [eq(schema.workOrders.tenantId, tenantId)];
    
    if (filters.status) {
      conditions.push(eq(schema.workOrders.status, filters.status));
    }
    
    if (filters.priority) {
      conditions.push(eq(schema.workOrders.priority, filters.priority));
    }
    
    if (filters.workOrderType) {
      conditions.push(eq(schema.workOrders.workOrderType, filters.workOrderType));
    }
    
    if (filters.assignedTo) {
      conditions.push(eq(schema.workOrders.assignedTo, filters.assignedTo));
    }
    
    if (filters.deviceId) {
      conditions.push(eq(schema.workOrders.deviceId, filters.deviceId));
    }
    
    if (filters.deviceType) {
      conditions.push(eq(schema.workOrders.deviceType, filters.deviceType));
    }
    
    if (filters.startDate) {
      conditions.push(gte(schema.workOrders.createdAt, new Date(filters.startDate)));
    }
    
    if (filters.endDate) {
      conditions.push(lte(schema.workOrders.createdAt, new Date(filters.endDate)));
    }
    
    if (filters.slaStatus) {
      if (filters.slaStatus === 'pending') {
        conditions.push(isNull(schema.workOrders.slaMet));
      } else if (filters.slaStatus === 'met') {
        conditions.push(eq(schema.workOrders.slaMet, 1));
      } else if (filters.slaStatus === 'missed') {
        conditions.push(eq(schema.workOrders.slaMet, 0));
      }
    }
    
    // Build order by
    const orderColumn = filters.sortBy === 'createdAt' ? schema.workOrders.createdAt :
                       filters.sortBy === 'scheduledDate' ? schema.workOrders.scheduledDate :
                       filters.sortBy === 'priority' ? schema.workOrders.priority :
                       schema.workOrders.status;
    
    const orderDirection = filters.sortOrder === 'asc' ? asc : desc;
    
    // Execute query with pagination
    const offset = (filters.page - 1) * filters.limit;
    
    const [workOrders, totalCount] = await Promise.all([
      db.select({
        workOrder: schema.workOrders,
        assignedUser: {
          id: schema.users.id,
          username: schema.users.username,
          email: schema.users.email
        },
        createdByUser: {
          id: schema.users.id,
          username: schema.users.username,
          email: schema.users.email
        }
      })
      .from(schema.workOrders)
      .leftJoin(schema.users, eq(schema.workOrders.assignedTo, schema.users.id))
      .leftJoin(schema.users, eq(schema.workOrders.createdBy, schema.users.id))
      .where(and(...conditions))
      .orderBy(orderDirection(orderColumn))
      .limit(filters.limit)
      .offset(offset),
      
      db.select({ count: schema.workOrders.id })
        .from(schema.workOrders)
        .where(and(...conditions))
    ]);
    
    span.setAttributes({
      'workOrders.count': workOrders.length,
      'workOrders.total': totalCount.length,
      'workOrders.filters': JSON.stringify(filters)
    });
    
    return c.json({
      workOrders: workOrders.map(row => ({
        ...row.workOrder,
        assignedUser: row.assignedUser?.id ? row.assignedUser : null,
        createdByUser: row.createdByUser?.id ? row.createdByUser : null
      })),
      pagination: {
        page: filters.page,
        limit: filters.limit,
        total: totalCount.length,
        totalPages: Math.ceil(totalCount.length / filters.limit)
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to list work orders', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid filter parameters', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to list work orders' });
  } finally {
    span.end();
  }
});

// Get single work order
app.get('/:id', async (c) => {
  const span = tracer.startSpan('getWorkOrder');
  
  try {
    const tenantId = c.get('tenantId');
    const workOrderId = c.req.param('id');
    
    span.setAttributes({ 'workOrder.id': workOrderId });
    
    const result = await db.select({
      workOrder: schema.workOrders,
      assignedUser: {
        id: schema.users.id,
        username: schema.users.username,
        email: schema.users.email
      },
      createdByUser: {
        id: schema.users.id,
        username: schema.users.username,
        email: schema.users.email
      }
    })
    .from(schema.workOrders)
    .leftJoin(schema.users, eq(schema.workOrders.assignedTo, schema.users.id))
    .leftJoin(schema.users, eq(schema.workOrders.createdBy, schema.users.id))
    .where(and(
      eq(schema.workOrders.id, workOrderId),
      eq(schema.workOrders.tenantId, tenantId)
    ))
    .limit(1);
    
    if (result.length === 0) {
      throw new HTTPException(404, { message: 'Work order not found' });
    }
    
    const workOrder = {
      ...result[0].workOrder,
      assignedUser: result[0].assignedUser?.id ? result[0].assignedUser : null,
      createdByUser: result[0].createdByUser?.id ? result[0].createdByUser : null
    };
    
    // Get maintenance history for this work order
    const history = await db.select()
      .from(schema.maintenanceHistory)
      .where(eq(schema.maintenanceHistory.workOrderId, workOrderId))
      .orderBy(desc(schema.maintenanceHistory.createdAt));
    
    // Get costs for this work order
    const costs = await db.select()
      .from(schema.maintenanceCosts)
      .where(eq(schema.maintenanceCosts.workOrderId, workOrderId))
      .orderBy(desc(schema.maintenanceCosts.createdAt));
    
    return c.json({
      workOrder,
      history,
      costs,
      totalCost: costs.reduce((sum, cost) => sum + Number(cost.amount), 0)
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get work order', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to get work order' });
  } finally {
    span.end();
  }
});

// Create work order
app.post('/', async (c) => {
  const span = tracer.startSpan('createWorkOrder');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const redis = c.get('redis');
    const body = await c.req.json();
    
    // Validate input
    const input = createWorkOrderSchema.parse(body) as CreateWorkOrderInput;
    
    span.setAttributes({
      'workOrder.type': input.workOrderType,
      'workOrder.priority': input.priority,
      'workOrder.deviceId': input.deviceId
    });
    
    // Verify device exists (would normally check device service)
    // For now, we'll assume device validation is handled externally
    
    // Calculate SLA deadline if configured
    let slaDeadline = input.slaDeadline ? new Date(input.slaDeadline) : null;
    
    if (!slaDeadline) {
      // Get applicable SLA configuration
      const slaConfigs = await db.select()
        .from(schema.maintenanceSlaConfig)
        .where(and(
          eq(schema.maintenanceSlaConfig.tenantId, tenantId),
          eq(schema.maintenanceSlaConfig.active, 1)
        ));
      
      // Find matching SLA config
      const applicableConfig = slaConfigs.find(config => {
        const matchesType = !config.workOrderType || config.workOrderType === input.workOrderType;
        const matchesPriority = !config.priority || config.priority === input.priority;
        const matchesDeviceType = !config.deviceType || config.deviceType === input.deviceType;
        return matchesType && matchesPriority && matchesDeviceType;
      });
      
      if (applicableConfig) {
        slaDeadline = new Date(Date.now() + applicableConfig.resolutionTime * 60 * 1000);
      }
    }
    
    // Create work order
    const [workOrder] = await db.insert(schema.workOrders)
      .values({
        tenantId,
        deviceId: input.deviceId,
        deviceType: input.deviceType,
        workOrderType: input.workOrderType,
        priority: input.priority,
        title: input.title,
        description: input.description,
        assignedTo: input.assignedTo,
        scheduledDate: input.scheduledDate ? new Date(input.scheduledDate) : null,
        estimatedCost: input.estimatedCost?.toString(),
        slaDeadline,
        createdBy: userId,
        status: 'open'
      })
      .returning();
    
    // Create initial history entry
    await db.insert(schema.maintenanceHistory)
      .values({
        tenantId,
        deviceId: input.deviceId,
        workOrderId: workOrder.id,
        activityType: 'maintenance',
        description: `Work order created: ${input.title}`,
        performedBy: userId
      });
    
    // Publish work order created event
    await redis.publish('maintenance:work-order:update', JSON.stringify({
      action: 'created',
      tenantId,
      workOrder
    }));
    
    // Update metrics
    await redis.incr('metrics:work_orders:total');
    
    logger.info('Work order created', { workOrderId: workOrder.id, tenantId });
    
    return c.json({ workOrder }, 201);
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to create work order', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid work order data', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to create work order' });
  } finally {
    span.end();
  }
});

// Update work order
app.put('/:id', async (c) => {
  const span = tracer.startSpan('updateWorkOrder');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const redis = c.get('redis');
    const workOrderId = c.req.param('id');
    const body = await c.req.json();
    
    // Validate input
    const input = updateWorkOrderSchema.parse(body) as UpdateWorkOrderInput;
    
    span.setAttributes({ 'workOrder.id': workOrderId });
    
    // Get existing work order
    const [existing] = await db.select()
      .from(schema.workOrders)
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!existing) {
      throw new HTTPException(404, { message: 'Work order not found' });
    }
    
    // Build update data
    const updateData: any = {
      updatedAt: new Date()
    };
    
    if (input.status !== undefined) {
      updateData.status = input.status;
      
      // Handle status-specific updates
      if (input.status === 'completed') {
        updateData.completedDate = new Date();
        
        // Check if SLA was met
        if (existing.slaDeadline) {
          updateData.slaMet = new Date() <= existing.slaDeadline ? 1 : 0;
          
          if (updateData.slaMet === 0) {
            // Publish SLA violation event
            await redis.publish('maintenance:sla:violation', JSON.stringify({
              tenantId,
              workOrderId,
              violation: {
                type: 'resolution',
                deadline: existing.slaDeadline,
                completedAt: new Date()
              }
            }));
          }
        }
      }
    }
    
    if (input.assignedTo !== undefined) updateData.assignedTo = input.assignedTo;
    if (input.scheduledDate !== undefined) updateData.scheduledDate = input.scheduledDate ? new Date(input.scheduledDate) : null;
    if (input.priority !== undefined) updateData.priority = input.priority;
    if (input.laborHours !== undefined) updateData.laborHours = input.laborHours.toString();
    if (input.actualCost !== undefined) updateData.actualCost = input.actualCost.toString();
    if (input.completionNotes !== undefined) updateData.completionNotes = input.completionNotes;
    if (input.diagnosticData !== undefined) updateData.diagnosticData = input.diagnosticData;
    
    // Handle parts usage
    if (input.partsUsed && input.partsUsed.length > 0) {
      updateData.partsUsed = input.partsUsed;
      
      // Record parts usage
      for (const part of input.partsUsed) {
        await db.insert(schema.partsUsageHistory)
          .values({
            tenantId,
            partId: part.partId,
            workOrderId,
            quantity: part.quantity,
            unitCost: part.unitCost.toString(),
            totalCost: (part.quantity * part.unitCost).toString(),
            usedBy: userId
          });
        
        // Update inventory
        await db.update(schema.partsInventory)
          .set({ 
            quantity: db.raw(`quantity - ${part.quantity}`),
            updatedAt: new Date()
          })
          .where(and(
            eq(schema.partsInventory.id, part.partId),
            eq(schema.partsInventory.tenantId, tenantId)
          ));
      }
      
      // Update metrics
      await redis.incr('metrics:parts:usage', input.partsUsed.length);
    }
    
    // Update work order
    const [updated] = await db.update(schema.workOrders)
      .set(updateData)
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId)
      ))
      .returning();
    
    // Create history entry
    const changes = Object.keys(updateData).filter(key => key !== 'updatedAt');
    if (changes.length > 0) {
      await db.insert(schema.maintenanceHistory)
        .values({
          tenantId,
          deviceId: updated.deviceId,
          workOrderId,
          activityType: 'maintenance',
          description: `Work order updated: ${changes.join(', ')}`,
          performedBy: userId,
          duration: input.laborHours ? Math.round(input.laborHours * 60) : null
        });
    }
    
    // Publish work order updated event
    await redis.publish('maintenance:work-order:update', JSON.stringify({
      action: 'updated',
      tenantId,
      workOrder: updated
    }));
    
    logger.info('Work order updated', { workOrderId, changes });
    
    return c.json({ workOrder: updated });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to update work order', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid update data', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to update work order' });
  } finally {
    span.end();
  }
});

// Delete work order
app.delete('/:id', async (c) => {
  const span = tracer.startSpan('deleteWorkOrder');
  
  try {
    const tenantId = c.get('tenantId');
    const workOrderId = c.req.param('id');
    const redis = c.get('redis');
    
    span.setAttributes({ 'workOrder.id': workOrderId });
    
    // Get existing work order
    const [existing] = await db.select()
      .from(schema.workOrders)
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!existing) {
      throw new HTTPException(404, { message: 'Work order not found' });
    }
    
    // Don't allow deletion of in-progress work orders
    if (existing.status === 'in_progress') {
      throw new HTTPException(400, { message: 'Cannot delete work order in progress' });
    }
    
    // Delete work order (cascade will handle related records)
    await db.delete(schema.workOrders)
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId)
      ));
    
    // Publish work order deleted event
    await redis.publish('maintenance:work-order:update', JSON.stringify({
      action: 'deleted',
      tenantId,
      workOrderId
    }));
    
    logger.info('Work order deleted', { workOrderId });
    
    return c.json({ success: true });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to delete work order', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to delete work order' });
  } finally {
    span.end();
  }
});

// Assign work order
app.post('/:id/assign', async (c) => {
  const span = tracer.startSpan('assignWorkOrder');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const redis = c.get('redis');
    const workOrderId = c.req.param('id');
    const body = await c.req.json();
    
    const { technicianId } = z.object({
      technicianId: z.string().uuid()
    }).parse(body);
    
    span.setAttributes({
      'workOrder.id': workOrderId,
      'technician.id': technicianId
    });
    
    // Update work order
    const [updated] = await db.update(schema.workOrders)
      .set({
        assignedTo: technicianId,
        status: 'assigned',
        updatedAt: new Date()
      })
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId),
        inArray(schema.workOrders.status, ['open', 'assigned'])
      ))
      .returning();
    
    if (!updated) {
      throw new HTTPException(404, { message: 'Work order not found or cannot be assigned' });
    }
    
    // Create history entry
    await db.insert(schema.maintenanceHistory)
      .values({
        tenantId,
        deviceId: updated.deviceId,
        workOrderId,
        activityType: 'maintenance',
        description: `Work order assigned to technician`,
        performedBy: userId
      });
    
    // TODO: Send notification to assigned technician
    
    logger.info('Work order assigned', { workOrderId, technicianId });
    
    return c.json({ workOrder: updated });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to assign work order', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid assignment data', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to assign work order' });
  } finally {
    span.end();
  }
});

// Complete work order
app.post('/:id/complete', async (c) => {
  const span = tracer.startSpan('completeWorkOrder');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const redis = c.get('redis');
    const workOrderId = c.req.param('id');
    const body = await c.req.json();
    
    const completionData = z.object({
      laborHours: z.number().positive(),
      actualCost: z.number().positive().optional(),
      partsUsed: z.array(z.object({
        partId: z.string().uuid(),
        quantity: z.number().positive(),
        unitCost: z.number().positive()
      })).optional(),
      completionNotes: z.string(),
      diagnosticData: z.record(z.any()).optional()
    }).parse(body);
    
    span.setAttributes({ 'workOrder.id': workOrderId });
    
    // Get existing work order
    const [existing] = await db.select()
      .from(schema.workOrders)
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!existing) {
      throw new HTTPException(404, { message: 'Work order not found' });
    }
    
    if (existing.status === 'completed') {
      throw new HTTPException(400, { message: 'Work order already completed' });
    }
    
    // Calculate actual cost if not provided
    let actualCost = completionData.actualCost;
    if (!actualCost && completionData.partsUsed) {
      const partsCost = completionData.partsUsed.reduce((sum, part) => 
        sum + (part.quantity * part.unitCost), 0
      );
      const laborCost = completionData.laborHours * 75; // Default hourly rate
      actualCost = partsCost + laborCost;
    }
    
    // Update work order
    const completedDate = new Date();
    const slaMet = existing.slaDeadline ? completedDate <= existing.slaDeadline ? 1 : 0 : null;
    
    const [updated] = await db.update(schema.workOrders)
      .set({
        status: 'completed',
        completedDate,
        laborHours: completionData.laborHours.toString(),
        actualCost: actualCost?.toString(),
        partsUsed: completionData.partsUsed || [],
        completionNotes: completionData.completionNotes,
        diagnosticData: completionData.diagnosticData || existing.diagnosticData,
        slaMet,
        updatedAt: new Date()
      })
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId)
      ))
      .returning();
    
    // Handle parts usage
    if (completionData.partsUsed && completionData.partsUsed.length > 0) {
      for (const part of completionData.partsUsed) {
        // Record usage
        await db.insert(schema.partsUsageHistory)
          .values({
            tenantId,
            partId: part.partId,
            workOrderId,
            quantity: part.quantity,
            unitCost: part.unitCost.toString(),
            totalCost: (part.quantity * part.unitCost).toString(),
            usedBy: userId,
            notes: `Used for work order: ${existing.title}`
          });
        
        // Update inventory
        const [partInfo] = await db.update(schema.partsInventory)
          .set({ 
            quantity: db.raw(`quantity - ${part.quantity}`),
            updatedAt: new Date()
          })
          .where(and(
            eq(schema.partsInventory.id, part.partId),
            eq(schema.partsInventory.tenantId, tenantId)
          ))
          .returning();
        
        // Check if reorder needed
        if (partInfo && partInfo.quantity <= partInfo.minQuantity) {
          await redis.publish('maintenance:inventory:low', JSON.stringify({
            tenantId,
            part: partInfo,
            alert: {
              type: 'low_stock',
              currentQuantity: partInfo.quantity,
              minQuantity: partInfo.minQuantity
            }
          }));
        }
      }
    }
    
    // Record cost
    if (actualCost) {
      await db.insert(schema.maintenanceCosts)
        .values({
          tenantId,
          workOrderId,
          costCategory: 'labor',
          description: `Labor: ${completionData.laborHours} hours`,
          amount: (completionData.laborHours * 75).toString(), // Default hourly rate
          approvedBy: userId
        });
      
      if (completionData.partsUsed) {
        const partsCost = completionData.partsUsed.reduce((sum, part) => 
          sum + (part.quantity * part.unitCost), 0
        );
        
        await db.insert(schema.maintenanceCosts)
          .values({
            tenantId,
            workOrderId,
            costCategory: 'parts',
            description: `Parts used: ${completionData.partsUsed.length} items`,
            amount: partsCost.toString(),
            approvedBy: userId
          });
      }
      
      // Update metrics
      await redis.incrby('metrics:costs:total', Math.round(actualCost));
    }
    
    // Create history entry
    await db.insert(schema.maintenanceHistory)
      .values({
        tenantId,
        deviceId: updated.deviceId,
        workOrderId,
        activityType: 'maintenance',
        description: `Work order completed`,
        performedBy: userId,
        duration: Math.round(completionData.laborHours * 60),
        outcome: completionData.completionNotes
      });
    
    // Check SLA violation
    if (slaMet === 0) {
      await redis.publish('maintenance:sla:violation', JSON.stringify({
        tenantId,
        workOrderId,
        violation: {
          type: 'resolution',
          deadline: existing.slaDeadline,
          completedAt: completedDate
        }
      }));
    }
    
    // Publish work order completed event
    await redis.publish('maintenance:work-order:update', JSON.stringify({
      action: 'completed',
      tenantId,
      workOrder: updated
    }));
    
    logger.info('Work order completed', { workOrderId });
    
    return c.json({ workOrder: updated });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to complete work order', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid completion data', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to complete work order' });
  } finally {
    span.end();
  }
});

export default app;