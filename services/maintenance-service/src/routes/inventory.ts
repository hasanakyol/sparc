import { Hono } from 'hono';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';
import { eq, and, desc, lte, like, or } from 'drizzle-orm';
import { db, schema } from '../db';
import { 
  createPartSchema,
  updatePartSchema,
  recordPartUsageSchema,
  CreatePartInput,
  UpdatePartInput,
  RecordPartUsageInput
} from '../types';
import { logger } from '@sparc/shared';
import { trace } from '@opentelemetry/api';
import Redis from 'ioredis';

const tracer = trace.getTracer('maintenance-service');
const app = new Hono<{ Variables: { tenantId: string; userId: string; redis: Redis } }>();

// List parts with search and filtering
app.get('/parts', async (c) => {
  const span = tracer.startSpan('listParts');
  
  try {
    const tenantId = c.get('tenantId');
    const search = c.req.query('search');
    const category = c.req.query('category');
    const lowStock = c.req.query('lowStock');
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '20');
    
    const conditions = [eq(schema.partsInventory.tenantId, tenantId)];
    
    // Search by part number, name, or description
    if (search) {
      conditions.push(or(
        like(schema.partsInventory.partNumber, `%${search}%`),
        like(schema.partsInventory.name, `%${search}%`),
        like(schema.partsInventory.description, `%${search}%`)
      ));
    }
    
    // Filter by category
    if (category) {
      conditions.push(eq(schema.partsInventory.category, category));
    }
    
    // Filter by low stock
    if (lowStock === 'true') {
      conditions.push(lte(schema.partsInventory.quantity, schema.partsInventory.minQuantity));
    }
    
    const offset = (page - 1) * limit;
    
    const [parts, totalCount] = await Promise.all([
      db.select()
        .from(schema.partsInventory)
        .where(and(...conditions))
        .orderBy(desc(schema.partsInventory.updatedAt))
        .limit(limit)
        .offset(offset),
      
      db.select({ count: schema.partsInventory.id })
        .from(schema.partsInventory)
        .where(and(...conditions))
    ]);
    
    // Calculate total value
    const totalValue = parts.reduce((sum, part) => 
      sum + (part.quantity * (part.unitCost ? parseFloat(part.unitCost) : 0)), 0
    );
    
    // Get categories for filtering
    const categories = await db.selectDistinct({ category: schema.partsInventory.category })
      .from(schema.partsInventory)
      .where(eq(schema.partsInventory.tenantId, tenantId));
    
    span.setAttributes({
      'parts.count': parts.length,
      'parts.total': totalCount.length,
      'parts.totalValue': totalValue
    });
    
    return c.json({
      parts,
      pagination: {
        page,
        limit,
        total: totalCount.length,
        totalPages: Math.ceil(totalCount.length / limit)
      },
      summary: {
        totalValue,
        lowStockCount: parts.filter(p => p.quantity <= p.minQuantity).length,
        categories: categories.map(c => c.category)
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to list parts', { error });
    throw new HTTPException(500, { message: 'Failed to list parts' });
  } finally {
    span.end();
  }
});

// Get single part with usage history
app.get('/parts/:id', async (c) => {
  const span = tracer.startSpan('getPart');
  
  try {
    const tenantId = c.get('tenantId');
    const partId = c.req.param('id');
    
    span.setAttributes({ 'part.id': partId });
    
    const [part] = await db.select()
      .from(schema.partsInventory)
      .where(and(
        eq(schema.partsInventory.id, partId),
        eq(schema.partsInventory.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!part) {
      throw new HTTPException(404, { message: 'Part not found' });
    }
    
    // Get usage history
    const usageHistory = await db.select({
      usage: schema.partsUsageHistory,
      workOrder: {
        id: schema.workOrders.id,
        title: schema.workOrders.title,
        status: schema.workOrders.status
      },
      user: {
        id: schema.users.id,
        username: schema.users.username
      }
    })
    .from(schema.partsUsageHistory)
    .leftJoin(schema.workOrders, eq(schema.partsUsageHistory.workOrderId, schema.workOrders.id))
    .leftJoin(schema.users, eq(schema.partsUsageHistory.usedBy, schema.users.id))
    .where(eq(schema.partsUsageHistory.partId, partId))
    .orderBy(desc(schema.partsUsageHistory.usedAt))
    .limit(50);
    
    // Calculate usage statistics
    const last30Days = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentUsage = usageHistory.filter(h => h.usage.usedAt >= last30Days);
    
    const stats = {
      totalUsed: usageHistory.reduce((sum, h) => sum + h.usage.quantity, 0),
      last30DaysUsed: recentUsage.reduce((sum, h) => sum + h.usage.quantity, 0),
      averageMonthlyUsage: recentUsage.length > 0 
        ? recentUsage.reduce((sum, h) => sum + h.usage.quantity, 0) 
        : 0,
      estimatedRunoutDays: part.quantity > 0 && recentUsage.length > 0
        ? Math.floor(part.quantity / (recentUsage.reduce((sum, h) => sum + h.usage.quantity, 0) / 30))
        : null
    };
    
    return c.json({
      part,
      usageHistory: usageHistory.map(h => ({
        ...h.usage,
        workOrder: h.workOrder,
        user: h.user
      })),
      stats
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get part', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to get part' });
  } finally {
    span.end();
  }
});

// Create new part
app.post('/parts', async (c) => {
  const span = tracer.startSpan('createPart');
  
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    
    // Validate input
    const input = createPartSchema.parse(body) as CreatePartInput;
    
    span.setAttributes({
      'part.partNumber': input.partNumber,
      'part.name': input.name,
      'part.category': input.category
    });
    
    // Check if part number already exists
    const [existing] = await db.select()
      .from(schema.partsInventory)
      .where(and(
        eq(schema.partsInventory.tenantId, tenantId),
        eq(schema.partsInventory.partNumber, input.partNumber)
      ))
      .limit(1);
    
    if (existing) {
      throw new HTTPException(400, { message: 'Part number already exists' });
    }
    
    // Create part
    const [part] = await db.insert(schema.partsInventory)
      .values({
        tenantId,
        ...input,
        unitCost: input.unitCost?.toString()
      })
      .returning();
    
    logger.info('Part created', { partId: part.id, partNumber: part.partNumber });
    
    return c.json({ part }, 201);
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to create part', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid part data', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to create part' });
  } finally {
    span.end();
  }
});

// Update part
app.put('/parts/:id', async (c) => {
  const span = tracer.startSpan('updatePart');
  
  try {
    const tenantId = c.get('tenantId');
    const partId = c.req.param('id');
    const body = await c.req.json();
    
    // Validate input
    const input = updatePartSchema.parse(body) as UpdatePartInput;
    
    span.setAttributes({ 'part.id': partId });
    
    // Get existing part
    const [existing] = await db.select()
      .from(schema.partsInventory)
      .where(and(
        eq(schema.partsInventory.id, partId),
        eq(schema.partsInventory.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!existing) {
      throw new HTTPException(404, { message: 'Part not found' });
    }
    
    // Build update data
    const updateData: any = {
      updatedAt: new Date()
    };
    
    Object.keys(input).forEach(key => {
      if (input[key] !== undefined) {
        if (key === 'unitCost') {
          updateData[key] = input[key].toString();
        } else {
          updateData[key] = input[key];
        }
      }
    });
    
    // Update part
    const [updated] = await db.update(schema.partsInventory)
      .set(updateData)
      .where(and(
        eq(schema.partsInventory.id, partId),
        eq(schema.partsInventory.tenantId, tenantId)
      ))
      .returning();
    
    // Check if low stock alert needed
    if (updated.quantity <= updated.minQuantity) {
      const redis = c.get('redis');
      await redis.publish('maintenance:inventory:low', JSON.stringify({
        tenantId,
        part: updated,
        alert: {
          type: 'low_stock',
          currentQuantity: updated.quantity,
          minQuantity: updated.minQuantity
        }
      }));
    }
    
    logger.info('Part updated', { partId });
    
    return c.json({ part: updated });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to update part', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid update data', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to update part' });
  } finally {
    span.end();
  }
});

// Delete part
app.delete('/parts/:id', async (c) => {
  const span = tracer.startSpan('deletePart');
  
  try {
    const tenantId = c.get('tenantId');
    const partId = c.req.param('id');
    
    span.setAttributes({ 'part.id': partId });
    
    // Check if part has usage history
    const [usage] = await db.select()
      .from(schema.partsUsageHistory)
      .where(eq(schema.partsUsageHistory.partId, partId))
      .limit(1);
    
    if (usage) {
      throw new HTTPException(400, { message: 'Cannot delete part with usage history' });
    }
    
    // Delete part
    const result = await db.delete(schema.partsInventory)
      .where(and(
        eq(schema.partsInventory.id, partId),
        eq(schema.partsInventory.tenantId, tenantId)
      ));
    
    if (result.rowCount === 0) {
      throw new HTTPException(404, { message: 'Part not found' });
    }
    
    logger.info('Part deleted', { partId });
    
    return c.json({ success: true });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to delete part', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to delete part' });
  } finally {
    span.end();
  }
});

// Record part usage
app.post('/parts/:id/usage', async (c) => {
  const span = tracer.startSpan('recordPartUsage');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const redis = c.get('redis');
    const partId = c.req.param('id');
    const body = await c.req.json();
    
    // Validate input
    const input = recordPartUsageSchema.parse(body) as RecordPartUsageInput;
    
    span.setAttributes({
      'part.id': partId,
      'usage.quantity': input.quantity,
      'usage.workOrderId': input.workOrderId || 'manual'
    });
    
    // Get part details
    const [part] = await db.select()
      .from(schema.partsInventory)
      .where(and(
        eq(schema.partsInventory.id, partId),
        eq(schema.partsInventory.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!part) {
      throw new HTTPException(404, { message: 'Part not found' });
    }
    
    // Check available quantity
    if (part.quantity < input.quantity) {
      throw new HTTPException(400, { 
        message: `Insufficient stock. Available: ${part.quantity}, Requested: ${input.quantity}` 
      });
    }
    
    // Validate work order if provided
    if (input.workOrderId) {
      const [workOrder] = await db.select()
        .from(schema.workOrders)
        .where(and(
          eq(schema.workOrders.id, input.workOrderId),
          eq(schema.workOrders.tenantId, tenantId)
        ))
        .limit(1);
      
      if (!workOrder) {
        throw new HTTPException(400, { message: 'Work order not found' });
      }
    }
    
    const unitCost = part.unitCost ? parseFloat(part.unitCost) : 0;
    const totalCost = input.quantity * unitCost;
    
    // Record usage
    const [usage] = await db.insert(schema.partsUsageHistory)
      .values({
        tenantId,
        partId,
        workOrderId: input.workOrderId,
        quantity: input.quantity,
        unitCost: unitCost.toString(),
        totalCost: totalCost.toString(),
        usedBy: userId,
        notes: input.notes
      })
      .returning();
    
    // Update inventory
    const newQuantity = part.quantity - input.quantity;
    const [updated] = await db.update(schema.partsInventory)
      .set({ 
        quantity: newQuantity,
        updatedAt: new Date()
      })
      .where(eq(schema.partsInventory.id, partId))
      .returning();
    
    // Check if reorder needed
    if (newQuantity <= part.minQuantity) {
      await redis.publish('maintenance:inventory:low', JSON.stringify({
        tenantId,
        part: updated,
        alert: {
          type: 'low_stock',
          currentQuantity: newQuantity,
          minQuantity: part.minQuantity,
          lastUsage: {
            quantity: input.quantity,
            by: userId,
            workOrderId: input.workOrderId
          }
        }
      }));
    }
    
    // Update metrics
    await redis.incr('metrics:parts:usage');
    
    logger.info('Part usage recorded', { 
      partId, 
      quantity: input.quantity,
      remainingQuantity: newQuantity 
    });
    
    return c.json({
      usage,
      part: updated,
      alert: newQuantity <= part.minQuantity ? 'Low stock alert triggered' : null
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to record part usage', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid usage data', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to record part usage' });
  } finally {
    span.end();
  }
});

// Bulk update inventory (for stocktaking)
app.post('/parts/bulk-update', async (c) => {
  const span = tracer.startSpan('bulkUpdateInventory');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const body = await c.req.json();
    
    const { updates } = z.object({
      updates: z.array(z.object({
        partId: z.string().uuid(),
        quantity: z.number().int().min(0),
        notes: z.string().optional()
      })).min(1).max(100)
    }).parse(body);
    
    span.setAttributes({ 'updates.count': updates.length });
    
    const results = [];
    const alerts = [];
    
    for (const update of updates) {
      // Get current part
      const [part] = await db.select()
        .from(schema.partsInventory)
        .where(and(
          eq(schema.partsInventory.id, update.partId),
          eq(schema.partsInventory.tenantId, tenantId)
        ))
        .limit(1);
      
      if (!part) {
        results.push({ partId: update.partId, error: 'Part not found' });
        continue;
      }
      
      const quantityDiff = update.quantity - part.quantity;
      
      // Update part quantity
      const [updated] = await db.update(schema.partsInventory)
        .set({
          quantity: update.quantity,
          updatedAt: new Date()
        })
        .where(eq(schema.partsInventory.id, update.partId))
        .returning();
      
      // Record adjustment in usage history
      if (quantityDiff !== 0) {
        await db.insert(schema.partsUsageHistory)
          .values({
            tenantId,
            partId: update.partId,
            quantity: Math.abs(quantityDiff),
            unitCost: '0',
            totalCost: '0',
            usedBy: userId,
            notes: `Inventory adjustment: ${quantityDiff > 0 ? 'added' : 'removed'} ${Math.abs(quantityDiff)} units. ${update.notes || ''}`
          });
      }
      
      // Check for low stock
      if (update.quantity <= part.minQuantity) {
        alerts.push({
          partId: update.partId,
          partNumber: part.partNumber,
          name: part.name,
          currentQuantity: update.quantity,
          minQuantity: part.minQuantity
        });
      }
      
      results.push({
        partId: update.partId,
        previousQuantity: part.quantity,
        newQuantity: update.quantity,
        difference: quantityDiff
      });
    }
    
    // Send low stock alerts
    if (alerts.length > 0) {
      const redis = c.get('redis');
      for (const alert of alerts) {
        await redis.publish('maintenance:inventory:low', JSON.stringify({
          tenantId,
          part: alert,
          alert: {
            type: 'low_stock_bulk_update',
            alerts: alerts.length
          }
        }));
      }
    }
    
    logger.info('Bulk inventory update completed', { 
      updateCount: updates.length,
      alertCount: alerts.length 
    });
    
    return c.json({
      results,
      alerts,
      summary: {
        total: updates.length,
        successful: results.filter(r => !r.error).length,
        failed: results.filter(r => r.error).length,
        lowStockAlerts: alerts.length
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to bulk update inventory', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid bulk update data', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to bulk update inventory' });
  } finally {
    span.end();
  }
});

// Get low stock report
app.get('/low-stock-report', async (c) => {
  const span = tracer.startSpan('getLowStockReport');
  
  try {
    const tenantId = c.get('tenantId');
    
    // Get all parts that are at or below minimum quantity
    const lowStockParts = await db.select()
      .from(schema.partsInventory)
      .where(and(
        eq(schema.partsInventory.tenantId, tenantId),
        lte(schema.partsInventory.quantity, schema.partsInventory.minQuantity)
      ))
      .orderBy(
        desc(db.raw(`${schema.partsInventory.minQuantity} - ${schema.partsInventory.quantity}`))
      );
    
    // Calculate reorder suggestions
    const reorderSuggestions = await Promise.all(lowStockParts.map(async (part) => {
      // Get usage history for the last 90 days
      const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      const usageHistory = await db.select()
        .from(schema.partsUsageHistory)
        .where(and(
          eq(schema.partsUsageHistory.partId, part.id),
          gte(schema.partsUsageHistory.usedAt, ninetyDaysAgo)
        ));
      
      const totalUsed = usageHistory.reduce((sum, h) => sum + h.quantity, 0);
      const averageDailyUsage = totalUsed / 90;
      const daysUntilStockout = part.quantity > 0 ? Math.floor(part.quantity / averageDailyUsage) : 0;
      
      // Calculate suggested reorder quantity
      const leadTimeDays = 14; // Assumed lead time
      const safetyStockDays = 30; // Safety stock for 30 days
      const suggestedQuantity = Math.ceil(averageDailyUsage * (leadTimeDays + safetyStockDays));
      
      return {
        ...part,
        currentStockLevel: part.quantity,
        minimumStockLevel: part.minQuantity,
        stockShortage: part.minQuantity - part.quantity,
        averageDailyUsage: Math.round(averageDailyUsage * 100) / 100,
        daysUntilStockout,
        suggestedReorderQuantity: Math.max(suggestedQuantity, part.maxQuantity || suggestedQuantity),
        estimatedCost: part.unitCost 
          ? suggestedQuantity * parseFloat(part.unitCost)
          : null,
        urgency: daysUntilStockout <= 7 ? 'critical' :
                daysUntilStockout <= 14 ? 'high' :
                daysUntilStockout <= 30 ? 'medium' : 'low'
      };
    }));
    
    // Group by category
    const byCategory = reorderSuggestions.reduce((acc, part) => {
      if (!acc[part.category]) {
        acc[part.category] = [];
      }
      acc[part.category].push(part);
      return acc;
    }, {} as Record<string, typeof reorderSuggestions>);
    
    // Calculate totals
    const totalEstimatedCost = reorderSuggestions.reduce((sum, part) => 
      sum + (part.estimatedCost || 0), 0
    );
    
    span.setAttributes({
      'lowStock.count': lowStockParts.length,
      'lowStock.totalCost': totalEstimatedCost
    });
    
    return c.json({
      summary: {
        totalParts: lowStockParts.length,
        criticalParts: reorderSuggestions.filter(p => p.urgency === 'critical').length,
        totalEstimatedReorderCost: totalEstimatedCost,
        byCategory: Object.keys(byCategory).map(category => ({
          category,
          count: byCategory[category].length,
          estimatedCost: byCategory[category].reduce((sum, p) => sum + (p.estimatedCost || 0), 0)
        }))
      },
      parts: reorderSuggestions,
      byCategory
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get low stock report', { error });
    throw new HTTPException(500, { message: 'Failed to get low stock report' });
  } finally {
    span.end();
  }
});

export default app;