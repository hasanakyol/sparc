import { Hono } from 'hono';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';
import { eq, and, desc, gte, lte, isNull } from 'drizzle-orm';
import { db, schema } from '../db';
import { 
  createSlaConfigSchema,
  CreateSlaConfigInput
} from '../types';
import { logger } from '@sparc/shared';
import { trace } from '@opentelemetry/api';
import Redis from 'ioredis';

const tracer = trace.getTracer('maintenance-service');
const app = new Hono<{ Variables: { tenantId: string; userId: string; redis: Redis } }>();

// List SLA configurations
app.get('/configs', async (c) => {
  const span = tracer.startSpan('listSlaConfigs');
  
  try {
    const tenantId = c.get('tenantId');
    const active = c.req.query('active');
    
    const conditions = [eq(schema.maintenanceSlaConfig.tenantId, tenantId)];
    
    if (active !== undefined) {
      conditions.push(eq(schema.maintenanceSlaConfig.active, active === 'true' ? 1 : 0));
    }
    
    const configs = await db.select()
      .from(schema.maintenanceSlaConfig)
      .where(and(...conditions))
      .orderBy(desc(schema.maintenanceSlaConfig.createdAt));
    
    span.setAttributes({ 'sla.configs.count': configs.length });
    
    return c.json({ configs });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to list SLA configs', { error });
    throw new HTTPException(500, { message: 'Failed to list SLA configurations' });
  } finally {
    span.end();
  }
});

// Get single SLA configuration
app.get('/configs/:id', async (c) => {
  const span = tracer.startSpan('getSlaConfig');
  
  try {
    const tenantId = c.get('tenantId');
    const configId = c.req.param('id');
    
    span.setAttributes({ 'sla.config.id': configId });
    
    const [config] = await db.select()
      .from(schema.maintenanceSlaConfig)
      .where(and(
        eq(schema.maintenanceSlaConfig.id, configId),
        eq(schema.maintenanceSlaConfig.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!config) {
      throw new HTTPException(404, { message: 'SLA configuration not found' });
    }
    
    // Get recent violations for this config
    const violations = await getRecentViolations(tenantId, config);
    
    return c.json({
      config,
      recentViolations: violations
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get SLA config', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to get SLA configuration' });
  } finally {
    span.end();
  }
});

// Create SLA configuration
app.post('/configs', async (c) => {
  const span = tracer.startSpan('createSlaConfig');
  
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    
    // Validate input
    const input = createSlaConfigSchema.parse(body) as CreateSlaConfigInput;
    
    span.setAttributes({
      'sla.name': input.name,
      'sla.responseTime': input.responseTime,
      'sla.resolutionTime': input.resolutionTime
    });
    
    // Check for overlapping configurations
    const existing = await db.select()
      .from(schema.maintenanceSlaConfig)
      .where(and(
        eq(schema.maintenanceSlaConfig.tenantId, tenantId),
        eq(schema.maintenanceSlaConfig.active, 1)
      ));
    
    const hasOverlap = existing.some(config => {
      const matchesType = (!input.workOrderType && !config.workOrderType) ||
                         (input.workOrderType === config.workOrderType);
      const matchesPriority = (!input.priority && !config.priority) ||
                             (input.priority === config.priority);
      const matchesDevice = (!input.deviceType && !config.deviceType) ||
                           (input.deviceType === config.deviceType);
      
      return matchesType && matchesPriority && matchesDevice;
    });
    
    if (hasOverlap) {
      throw new HTTPException(400, { 
        message: 'An active SLA configuration already exists for these criteria' 
      });
    }
    
    // Create SLA configuration
    const [config] = await db.insert(schema.maintenanceSlaConfig)
      .values({
        tenantId,
        name: input.name,
        deviceType: input.deviceType,
        workOrderType: input.workOrderType,
        priority: input.priority,
        responseTime: input.responseTime,
        resolutionTime: input.resolutionTime,
        escalationLevels: input.escalationLevels || [],
        active: input.active ? 1 : 0
      })
      .returning();
    
    logger.info('SLA configuration created', { configId: config.id, name: config.name });
    
    return c.json({ config }, 201);
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to create SLA config', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid SLA configuration', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to create SLA configuration' });
  } finally {
    span.end();
  }
});

// Update SLA configuration
app.put('/configs/:id', async (c) => {
  const span = tracer.startSpan('updateSlaConfig');
  
  try {
    const tenantId = c.get('tenantId');
    const configId = c.req.param('id');
    const body = await c.req.json();
    
    span.setAttributes({ 'sla.config.id': configId });
    
    // Get existing config
    const [existing] = await db.select()
      .from(schema.maintenanceSlaConfig)
      .where(and(
        eq(schema.maintenanceSlaConfig.id, configId),
        eq(schema.maintenanceSlaConfig.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!existing) {
      throw new HTTPException(404, { message: 'SLA configuration not found' });
    }
    
    // Update config
    const [updated] = await db.update(schema.maintenanceSlaConfig)
      .set({
        ...body,
        updatedAt: new Date()
      })
      .where(and(
        eq(schema.maintenanceSlaConfig.id, configId),
        eq(schema.maintenanceSlaConfig.tenantId, tenantId)
      ))
      .returning();
    
    logger.info('SLA configuration updated', { configId });
    
    return c.json({ config: updated });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to update SLA config', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to update SLA configuration' });
  } finally {
    span.end();
  }
});

// Delete SLA configuration
app.delete('/configs/:id', async (c) => {
  const span = tracer.startSpan('deleteSlaConfig');
  
  try {
    const tenantId = c.get('tenantId');
    const configId = c.req.param('id');
    
    span.setAttributes({ 'sla.config.id': configId });
    
    const result = await db.delete(schema.maintenanceSlaConfig)
      .where(and(
        eq(schema.maintenanceSlaConfig.id, configId),
        eq(schema.maintenanceSlaConfig.tenantId, tenantId)
      ));
    
    if (result.rowCount === 0) {
      throw new HTTPException(404, { message: 'SLA configuration not found' });
    }
    
    logger.info('SLA configuration deleted', { configId });
    
    return c.json({ success: true });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to delete SLA config', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to delete SLA configuration' });
  } finally {
    span.end();
  }
});

// Get SLA violations
app.get('/violations', async (c) => {
  const span = tracer.startSpan('getSlaViolations');
  
  try {
    const tenantId = c.get('tenantId');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const workOrderType = c.req.query('workOrderType');
    const priority = c.req.query('priority');
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '20');
    
    const conditions = [
      eq(schema.workOrders.tenantId, tenantId),
      eq(schema.workOrders.slaMet, 0) // Only violations
    ];
    
    if (startDate) {
      conditions.push(gte(schema.workOrders.createdAt, new Date(startDate)));
    }
    
    if (endDate) {
      conditions.push(lte(schema.workOrders.createdAt, new Date(endDate)));
    }
    
    if (workOrderType) {
      conditions.push(eq(schema.workOrders.workOrderType, workOrderType));
    }
    
    if (priority) {
      conditions.push(eq(schema.workOrders.priority, priority));
    }
    
    const offset = (page - 1) * limit;
    
    const [violations, totalCount] = await Promise.all([
      db.select({
        workOrder: schema.workOrders,
        assignedUser: {
          id: schema.users.id,
          username: schema.users.username,
          email: schema.users.email
        }
      })
      .from(schema.workOrders)
      .leftJoin(schema.users, eq(schema.workOrders.assignedTo, schema.users.id))
      .where(and(...conditions))
      .orderBy(desc(schema.workOrders.createdAt))
      .limit(limit)
      .offset(offset),
      
      db.select({ count: schema.workOrders.id })
        .from(schema.workOrders)
        .where(and(...conditions))
    ]);
    
    // Calculate violation details
    const violationDetails = violations.map(v => {
      const workOrder = v.workOrder;
      const deadline = workOrder.slaDeadline;
      const completed = workOrder.completedDate;
      
      let violationType = 'resolution';
      let violationHours = 0;
      
      if (deadline && completed) {
        violationHours = (completed.getTime() - deadline.getTime()) / (1000 * 60 * 60);
      }
      
      return {
        workOrder: {
          ...workOrder,
          assignedUser: v.assignedUser?.id ? v.assignedUser : null
        },
        violation: {
          type: violationType,
          deadline,
          actualCompletion: completed,
          violationHours: Math.round(violationHours * 100) / 100,
          violationDays: Math.round(violationHours / 24 * 100) / 100
        }
      };
    });
    
    span.setAttributes({
      'violations.count': violations.length,
      'violations.total': totalCount.length
    });
    
    return c.json({
      violations: violationDetails,
      pagination: {
        page,
        limit,
        total: totalCount.length,
        totalPages: Math.ceil(totalCount.length / limit)
      },
      summary: {
        totalViolations: totalCount.length,
        avgViolationHours: violationDetails.length > 0
          ? violationDetails.reduce((sum, v) => sum + v.violation.violationHours, 0) / violationDetails.length
          : 0
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get SLA violations', { error });
    throw new HTTPException(500, { message: 'Failed to get SLA violations' });
  } finally {
    span.end();
  }
});

// Get SLA performance metrics
app.get('/performance', async (c) => {
  const span = tracer.startSpan('getSlaPerformance');
  
  try {
    const tenantId = c.get('tenantId');
    const startDate = c.req.query('startDate') 
      ? new Date(c.req.query('startDate')) 
      : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = c.req.query('endDate') 
      ? new Date(c.req.query('endDate')) 
      : new Date();
    
    // Overall SLA performance
    const overallPerformance = await db.select({
      total: sql`COUNT(*)`,
      met: sql`COUNT(*) FILTER (WHERE sla_met = 1)`,
      missed: sql`COUNT(*) FILTER (WHERE sla_met = 0)`,
      pending: sql`COUNT(*) FILTER (WHERE sla_met IS NULL)`,
      metRate: sql`
        (COUNT(*) FILTER (WHERE sla_met = 1) * 100.0 / 
         NULLIF(COUNT(*) FILTER (WHERE sla_met IS NOT NULL), 0))
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ));
    
    // SLA performance by priority
    const byPriority = await db.select({
      priority: schema.workOrders.priority,
      total: sql`COUNT(*)`,
      met: sql`COUNT(*) FILTER (WHERE sla_met = 1)`,
      metRate: sql`
        (COUNT(*) FILTER (WHERE sla_met = 1) * 100.0 / 
         NULLIF(COUNT(*) FILTER (WHERE sla_met IS NOT NULL), 0))
      `,
      avgResponseTime: sql`
        AVG(EXTRACT(EPOCH FROM (
          COALESCE(
            (SELECT MIN(created_at) FROM ${schema.maintenanceHistory} 
             WHERE work_order_id = ${schema.workOrders.id}),
            updated_at
          ) - created_at
        )) / 3600)
      `,
      avgResolutionTime: sql`
        AVG(EXTRACT(EPOCH FROM (completed_date - created_at)) / 3600)
        FILTER (WHERE completed_date IS NOT NULL)
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ))
    .groupBy(schema.workOrders.priority);
    
    // SLA performance by work order type
    const byType = await db.select({
      workOrderType: schema.workOrders.workOrderType,
      total: sql`COUNT(*)`,
      met: sql`COUNT(*) FILTER (WHERE sla_met = 1)`,
      metRate: sql`
        (COUNT(*) FILTER (WHERE sla_met = 1) * 100.0 / 
         NULLIF(COUNT(*) FILTER (WHERE sla_met IS NOT NULL), 0))
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ))
    .groupBy(schema.workOrders.workOrderType);
    
    // SLA trends over time
    const groupBy = c.req.query('groupBy') || 'week';
    const dateFormat = groupBy === 'day' ? '%Y-%m-%d' :
                      groupBy === 'week' ? '%Y-W%V' :
                      groupBy === 'month' ? '%Y-%m' :
                      '%Y-Q%q';
    
    const trends = await db.select({
      period: sql`TO_CHAR(created_at, ${dateFormat})`,
      total: sql`COUNT(*)`,
      met: sql`COUNT(*) FILTER (WHERE sla_met = 1)`,
      missed: sql`COUNT(*) FILTER (WHERE sla_met = 0)`,
      metRate: sql`
        (COUNT(*) FILTER (WHERE sla_met = 1) * 100.0 / 
         NULLIF(COUNT(*) FILTER (WHERE sla_met IS NOT NULL), 0))
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ))
    .groupBy(sql`TO_CHAR(created_at, ${dateFormat})`)
    .orderBy(sql`TO_CHAR(created_at, ${dateFormat})`);
    
    // Get active SLA configurations
    const activeConfigs = await db.select()
      .from(schema.maintenanceSlaConfig)
      .where(and(
        eq(schema.maintenanceSlaConfig.tenantId, tenantId),
        eq(schema.maintenanceSlaConfig.active, 1)
      ));
    
    return c.json({
      summary: {
        dateRange: { start: startDate, end: endDate },
        overall: {
          total: Number(overallPerformance[0].total),
          met: Number(overallPerformance[0].met),
          missed: Number(overallPerformance[0].missed),
          pending: Number(overallPerformance[0].pending),
          metRate: Number(overallPerformance[0].metRate) || 0
        },
        activeConfigurations: activeConfigs.length
      },
      byPriority: byPriority.map(p => ({
        priority: p.priority,
        total: Number(p.total),
        met: Number(p.met),
        metRate: Number(p.metRate) || 0,
        avgResponseTimeHours: Number(p.avgResponseTime) || 0,
        avgResolutionTimeHours: Number(p.avgResolutionTime) || 0
      })),
      byType: byType.map(t => ({
        workOrderType: t.workOrderType,
        total: Number(t.total),
        met: Number(t.met),
        metRate: Number(t.metRate) || 0
      })),
      trends: trends.map(t => ({
        period: t.period,
        total: Number(t.total),
        met: Number(t.met),
        missed: Number(t.missed),
        metRate: Number(t.metRate) || 0
      }))
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get SLA performance', { error });
    throw new HTTPException(500, { message: 'Failed to get SLA performance' });
  } finally {
    span.end();
  }
});

// Check SLA status for a work order
app.get('/check/:workOrderId', async (c) => {
  const span = tracer.startSpan('checkSlaStatus');
  
  try {
    const tenantId = c.get('tenantId');
    const workOrderId = c.req.param('workOrderId');
    
    span.setAttributes({ 'workOrder.id': workOrderId });
    
    // Get work order
    const [workOrder] = await db.select()
      .from(schema.workOrders)
      .where(and(
        eq(schema.workOrders.id, workOrderId),
        eq(schema.workOrders.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!workOrder) {
      throw new HTTPException(404, { message: 'Work order not found' });
    }
    
    // Get applicable SLA config
    const configs = await db.select()
      .from(schema.maintenanceSlaConfig)
      .where(and(
        eq(schema.maintenanceSlaConfig.tenantId, tenantId),
        eq(schema.maintenanceSlaConfig.active, 1)
      ));
    
    const applicableConfig = configs.find(config => {
      const matchesType = !config.workOrderType || config.workOrderType === workOrder.workOrderType;
      const matchesPriority = !config.priority || config.priority === workOrder.priority;
      const matchesDeviceType = !config.deviceType || config.deviceType === workOrder.deviceType;
      return matchesType && matchesPriority && matchesDeviceType;
    });
    
    if (!applicableConfig) {
      return c.json({
        workOrderId,
        slaApplicable: false,
        message: 'No SLA configuration found for this work order'
      });
    }
    
    // Calculate SLA status
    const now = new Date();
    const createdAt = workOrder.createdAt;
    const responseTime = Math.floor((now.getTime() - createdAt.getTime()) / (1000 * 60)); // minutes
    const deadline = workOrder.slaDeadline || new Date(createdAt.getTime() + applicableConfig.resolutionTime * 60 * 1000);
    
    let status = 'on_track';
    let riskLevel = 'low';
    const timeRemaining = Math.floor((deadline.getTime() - now.getTime()) / (1000 * 60)); // minutes
    
    if (workOrder.status === 'completed') {
      status = workOrder.slaMet === 1 ? 'met' : 'missed';
    } else if (timeRemaining < 0) {
      status = 'breached';
      riskLevel = 'critical';
    } else if (timeRemaining < applicableConfig.resolutionTime * 0.1) { // Less than 10% time remaining
      status = 'at_risk';
      riskLevel = 'high';
    } else if (timeRemaining < applicableConfig.resolutionTime * 0.25) { // Less than 25% time remaining
      status = 'warning';
      riskLevel = 'medium';
    }
    
    // Check for escalation needs
    const escalationNeeded = applicableConfig.escalationLevels && 
      applicableConfig.escalationLevels.some((level: any) => responseTime >= level.delayMinutes);
    
    return c.json({
      workOrderId,
      slaApplicable: true,
      config: {
        id: applicableConfig.id,
        name: applicableConfig.name,
        responseTime: applicableConfig.responseTime,
        resolutionTime: applicableConfig.resolutionTime
      },
      status: {
        current: status,
        riskLevel,
        responseTimeMinutes: responseTime,
        timeRemainingMinutes: timeRemaining,
        deadline,
        escalationNeeded,
        percentComplete: workOrder.status === 'completed' 
          ? 100 
          : Math.max(0, Math.min(100, ((applicableConfig.resolutionTime - timeRemaining) / applicableConfig.resolutionTime) * 100))
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to check SLA status', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to check SLA status' });
  } finally {
    span.end();
  }
});

// Helper function to get recent violations
async function getRecentViolations(tenantId: string, config: any) {
  const conditions = [
    eq(schema.workOrders.tenantId, tenantId),
    eq(schema.workOrders.slaMet, 0),
    gte(schema.workOrders.createdAt, new Date(Date.now() - 30 * 24 * 60 * 60 * 1000))
  ];
  
  if (config.workOrderType) {
    conditions.push(eq(schema.workOrders.workOrderType, config.workOrderType));
  }
  
  if (config.priority) {
    conditions.push(eq(schema.workOrders.priority, config.priority));
  }
  
  if (config.deviceType) {
    conditions.push(eq(schema.workOrders.deviceType, config.deviceType));
  }
  
  return db.select()
    .from(schema.workOrders)
    .where(and(...conditions))
    .orderBy(desc(schema.workOrders.createdAt))
    .limit(10);
}

export default app;