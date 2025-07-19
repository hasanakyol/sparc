import { Hono } from 'hono';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';
import { eq, and, gte, lte, sql, desc } from 'drizzle-orm';
import { db, schema } from '../db';
import { analyticsFilterSchema, AnalyticsFilter } from '../types';
import { logger } from '@sparc/shared';
import { trace } from '@opentelemetry/api';

const tracer = trace.getTracer('maintenance-service');
const app = new Hono<{ Variables: { tenantId: string; userId: string } }>();

// Get maintenance analytics overview
app.get('/overview', async (c) => {
  const span = tracer.startSpan('getMaintenanceOverview');
  
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    // Parse date range
    const startDate = query.startDate ? new Date(query.startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = query.endDate ? new Date(query.endDate) : new Date();
    
    span.setAttributes({
      'analytics.startDate': startDate.toISOString(),
      'analytics.endDate': endDate.toISOString()
    });
    
    // Get work order statistics
    const workOrderStats = await db.select({
      total: sql`count(*)`,
      byStatus: sql`
        json_object_agg(status, count) FILTER (WHERE status IS NOT NULL) 
        FROM (
          SELECT status, count(*) as count 
          FROM ${schema.workOrders} 
          WHERE tenant_id = ${tenantId}
            AND created_at >= ${startDate}
            AND created_at <= ${endDate}
          GROUP BY status
        ) as status_counts
      `,
      byPriority: sql`
        json_object_agg(priority, count) FILTER (WHERE priority IS NOT NULL)
        FROM (
          SELECT priority, count(*) as count
          FROM ${schema.workOrders}
          WHERE tenant_id = ${tenantId}
            AND created_at >= ${startDate}
            AND created_at <= ${endDate}
          GROUP BY priority
        ) as priority_counts
      `,
      byType: sql`
        json_object_agg(work_order_type, count) FILTER (WHERE work_order_type IS NOT NULL)
        FROM (
          SELECT work_order_type, count(*) as count
          FROM ${schema.workOrders}
          WHERE tenant_id = ${tenantId}
            AND created_at >= ${startDate}
            AND created_at <= ${endDate}
          GROUP BY work_order_type
        ) as type_counts
      `,
      avgCompletionTime: sql`
        AVG(EXTRACT(EPOCH FROM (completed_date - created_at)) / 3600)
        FROM ${schema.workOrders}
        WHERE tenant_id = ${tenantId}
          AND status = 'completed'
          AND completed_date IS NOT NULL
          AND created_at >= ${startDate}
          AND created_at <= ${endDate}
      `,
      slaMetRate: sql`
        (COUNT(*) FILTER (WHERE sla_met = 1) * 100.0 / 
         NULLIF(COUNT(*) FILTER (WHERE sla_met IS NOT NULL), 0))
        FROM ${schema.workOrders}
        WHERE tenant_id = ${tenantId}
          AND created_at >= ${startDate}
          AND created_at <= ${endDate}
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ));
    
    // Get maintenance costs
    const costStats = await db.select({
      totalCost: sql`SUM(amount)`,
      byCategory: sql`
        json_object_agg(cost_category, total) FILTER (WHERE cost_category IS NOT NULL)
        FROM (
          SELECT cost_category, SUM(amount) as total
          FROM ${schema.maintenanceCosts}
          WHERE tenant_id = ${tenantId}
            AND incurred_at >= ${startDate}
            AND incurred_at <= ${endDate}
          GROUP BY cost_category
        ) as cost_categories
      `
    })
    .from(schema.maintenanceCosts)
    .where(and(
      eq(schema.maintenanceCosts.tenantId, tenantId),
      gte(schema.maintenanceCosts.incurredAt, startDate),
      lte(schema.maintenanceCosts.incurredAt, endDate)
    ));
    
    // Get preventive vs corrective ratio
    const maintenanceTypes = await db.select({
      preventive: sql`COUNT(*) FILTER (WHERE work_order_type = 'preventive')`,
      corrective: sql`COUNT(*) FILTER (WHERE work_order_type = 'corrective')`,
      emergency: sql`COUNT(*) FILTER (WHERE work_order_type = 'emergency')`
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ));
    
    // Get parts usage statistics
    const partsStats = await db.select({
      totalPartsUsed: sql`COUNT(DISTINCT part_id)`,
      totalQuantity: sql`SUM(quantity)`,
      totalValue: sql`SUM(total_cost)`
    })
    .from(schema.partsUsageHistory)
    .where(and(
      eq(schema.partsUsageHistory.tenantId, tenantId),
      gte(schema.partsUsageHistory.usedAt, startDate),
      lte(schema.partsUsageHistory.usedAt, endDate)
    ));
    
    // Get device health overview
    const deviceHealth = await db.select({
      totalDevices: sql`COUNT(DISTINCT device_id)`,
      withIssues: sql`
        COUNT(DISTINCT device_id) FILTER (
          WHERE overall_status IN ('fail', 'warning')
        )
      `
    })
    .from(schema.deviceDiagnostics)
    .where(and(
      eq(schema.deviceDiagnostics.tenantId, tenantId),
      gte(schema.deviceDiagnostics.createdAt, startDate)
    ));
    
    const overview = {
      dateRange: {
        start: startDate,
        end: endDate,
        days: Math.ceil((endDate.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24))
      },
      workOrders: {
        total: Number(workOrderStats[0].total),
        byStatus: workOrderStats[0].byStatus || {},
        byPriority: workOrderStats[0].byPriority || {},
        byType: workOrderStats[0].byType || {},
        avgCompletionTimeHours: Number(workOrderStats[0].avgCompletionTime) || 0,
        slaMetRate: Number(workOrderStats[0].slaMetRate) || 0
      },
      costs: {
        total: Number(costStats[0].totalCost) || 0,
        byCategory: costStats[0].byCategory || {}
      },
      maintenance: {
        preventive: Number(maintenanceTypes[0].preventive),
        corrective: Number(maintenanceTypes[0].corrective),
        emergency: Number(maintenanceTypes[0].emergency),
        preventiveRatio: maintenanceTypes[0].preventive && maintenanceTypes[0].corrective
          ? (Number(maintenanceTypes[0].preventive) / (Number(maintenanceTypes[0].preventive) + Number(maintenanceTypes[0].corrective))) * 100
          : 0
      },
      parts: {
        uniquePartsUsed: Number(partsStats[0].totalPartsUsed),
        totalQuantity: Number(partsStats[0].totalQuantity),
        totalValue: Number(partsStats[0].totalValue) || 0
      },
      devices: {
        total: Number(deviceHealth[0].totalDevices),
        withIssues: Number(deviceHealth[0].withIssues),
        healthRate: deviceHealth[0].totalDevices > 0
          ? ((Number(deviceHealth[0].totalDevices) - Number(deviceHealth[0].withIssues)) / Number(deviceHealth[0].totalDevices)) * 100
          : 100
      }
    };
    
    return c.json({ overview });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get maintenance overview', { error });
    throw new HTTPException(500, { message: 'Failed to get maintenance overview' });
  } finally {
    span.end();
  }
});

// Get maintenance costs analysis
app.get('/costs', async (c) => {
  const span = tracer.startSpan('getMaintenanceCosts');
  
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const filters = analyticsFilterSchema.parse(query) as AnalyticsFilter;
    
    span.setAttributes({
      'costs.startDate': filters.startDate,
      'costs.endDate': filters.endDate,
      'costs.groupBy': filters.groupBy || 'month'
    });
    
    const startDate = new Date(filters.startDate);
    const endDate = new Date(filters.endDate);
    
    // Get costs by time period
    const groupBy = filters.groupBy || 'month';
    const dateFormat = groupBy === 'day' ? '%Y-%m-%d' :
                      groupBy === 'week' ? '%Y-W%V' :
                      groupBy === 'month' ? '%Y-%m' :
                      '%Y-Q%q';
    
    const costsByPeriod = await db.select({
      period: sql`TO_CHAR(incurred_at, ${dateFormat})`,
      totalCost: sql`SUM(amount)`,
      laborCost: sql`SUM(amount) FILTER (WHERE cost_category = 'labor')`,
      partsCost: sql`SUM(amount) FILTER (WHERE cost_category = 'parts')`,
      contractorCost: sql`SUM(amount) FILTER (WHERE cost_category = 'contractor')`,
      otherCost: sql`SUM(amount) FILTER (WHERE cost_category = 'other')`,
      workOrderCount: sql`COUNT(DISTINCT work_order_id)`
    })
    .from(schema.maintenanceCosts)
    .where(and(
      eq(schema.maintenanceCosts.tenantId, tenantId),
      gte(schema.maintenanceCosts.incurredAt, startDate),
      lte(schema.maintenanceCosts.incurredAt, endDate)
    ))
    .groupBy(sql`TO_CHAR(incurred_at, ${dateFormat})`)
    .orderBy(sql`TO_CHAR(incurred_at, ${dateFormat})`);
    
    // Get costs by device type
    const costsByDeviceType = await db.select({
      deviceType: schema.workOrders.deviceType,
      totalCost: sql`SUM(${schema.maintenanceCosts.amount})`,
      avgCostPerWorkOrder: sql`AVG(${schema.maintenanceCosts.amount})`,
      workOrderCount: sql`COUNT(DISTINCT ${schema.workOrders.id})`
    })
    .from(schema.maintenanceCosts)
    .innerJoin(schema.workOrders, eq(schema.maintenanceCosts.workOrderId, schema.workOrders.id))
    .where(and(
      eq(schema.maintenanceCosts.tenantId, tenantId),
      gte(schema.maintenanceCosts.incurredAt, startDate),
      lte(schema.maintenanceCosts.incurredAt, endDate)
    ))
    .groupBy(schema.workOrders.deviceType)
    .orderBy(desc(sql`SUM(${schema.maintenanceCosts.amount})`));
    
    // Get costs by work order type
    const costsByWorkOrderType = await db.select({
      workOrderType: schema.workOrders.workOrderType,
      totalCost: sql`SUM(${schema.maintenanceCosts.amount})`,
      avgCostPerWorkOrder: sql`AVG(${schema.maintenanceCosts.amount})`,
      workOrderCount: sql`COUNT(DISTINCT ${schema.workOrders.id})`
    })
    .from(schema.maintenanceCosts)
    .innerJoin(schema.workOrders, eq(schema.maintenanceCosts.workOrderId, schema.workOrders.id))
    .where(and(
      eq(schema.maintenanceCosts.tenantId, tenantId),
      gte(schema.maintenanceCosts.incurredAt, startDate),
      lte(schema.maintenanceCosts.incurredAt, endDate)
    ))
    .groupBy(schema.workOrders.workOrderType)
    .orderBy(desc(sql`SUM(${schema.maintenanceCosts.amount})`));
    
    // Get top cost drivers (work orders)
    const topCostWorkOrders = await db.select({
      workOrder: {
        id: schema.workOrders.id,
        title: schema.workOrders.title,
        deviceType: schema.workOrders.deviceType,
        workOrderType: schema.workOrders.workOrderType,
        status: schema.workOrders.status
      },
      totalCost: sql`SUM(${schema.maintenanceCosts.amount})`,
      costBreakdown: sql`
        json_object_agg(cost_category, category_total)
        FROM (
          SELECT cost_category, SUM(amount) as category_total
          FROM ${schema.maintenanceCosts}
          WHERE work_order_id = ${schema.workOrders.id}
          GROUP BY cost_category
        ) as categories
      `
    })
    .from(schema.maintenanceCosts)
    .innerJoin(schema.workOrders, eq(schema.maintenanceCosts.workOrderId, schema.workOrders.id))
    .where(and(
      eq(schema.maintenanceCosts.tenantId, tenantId),
      gte(schema.maintenanceCosts.incurredAt, startDate),
      lte(schema.maintenanceCosts.incurredAt, endDate)
    ))
    .groupBy(schema.workOrders.id)
    .orderBy(desc(sql`SUM(${schema.maintenanceCosts.amount})`))
    .limit(10);
    
    // Calculate cost trends
    const totalCost = costsByPeriod.reduce((sum, period) => sum + Number(period.totalCost), 0);
    const avgCostPerPeriod = costsByPeriod.length > 0 ? totalCost / costsByPeriod.length : 0;
    
    // Budget analysis (would need budget data)
    const budgetAnalysis = {
      totalBudget: 100000, // Placeholder
      spent: totalCost,
      remaining: 100000 - totalCost,
      percentUsed: (totalCost / 100000) * 100,
      projectedYearEnd: avgCostPerPeriod * 12 // Simplified projection
    };
    
    return c.json({
      summary: {
        totalCost,
        avgCostPerPeriod,
        periodCount: costsByPeriod.length,
        costByCategory: {
          labor: costsByPeriod.reduce((sum, p) => sum + Number(p.laborCost || 0), 0),
          parts: costsByPeriod.reduce((sum, p) => sum + Number(p.partsCost || 0), 0),
          contractor: costsByPeriod.reduce((sum, p) => sum + Number(p.contractorCost || 0), 0),
          other: costsByPeriod.reduce((sum, p) => sum + Number(p.otherCost || 0), 0)
        }
      },
      costsByPeriod: costsByPeriod.map(p => ({
        ...p,
        totalCost: Number(p.totalCost),
        laborCost: Number(p.laborCost || 0),
        partsCost: Number(p.partsCost || 0),
        contractorCost: Number(p.contractorCost || 0),
        otherCost: Number(p.otherCost || 0),
        workOrderCount: Number(p.workOrderCount)
      })),
      costsByDeviceType: costsByDeviceType.map(c => ({
        ...c,
        totalCost: Number(c.totalCost),
        avgCostPerWorkOrder: Number(c.avgCostPerWorkOrder),
        workOrderCount: Number(c.workOrderCount)
      })),
      costsByWorkOrderType: costsByWorkOrderType.map(c => ({
        ...c,
        totalCost: Number(c.totalCost),
        avgCostPerWorkOrder: Number(c.avgCostPerWorkOrder),
        workOrderCount: Number(c.workOrderCount)
      })),
      topCostWorkOrders: topCostWorkOrders.map(w => ({
        workOrder: w.workOrder,
        totalCost: Number(w.totalCost),
        costBreakdown: w.costBreakdown || {}
      })),
      budgetAnalysis
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get maintenance costs', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid filter parameters', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to get maintenance costs' });
  } finally {
    span.end();
  }
});

// Get maintenance performance metrics
app.get('/performance', async (c) => {
  const span = tracer.startSpan('getMaintenancePerformance');
  
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const filters = analyticsFilterSchema.parse(query) as AnalyticsFilter;
    
    span.setAttributes({
      'performance.startDate': filters.startDate,
      'performance.endDate': filters.endDate
    });
    
    const startDate = new Date(filters.startDate);
    const endDate = new Date(filters.endDate);
    
    // Mean Time To Repair (MTTR)
    const mttr = await db.select({
      avgHours: sql`
        AVG(EXTRACT(EPOCH FROM (completed_date - created_at)) / 3600)
      `,
      byPriority: sql`
        json_object_agg(priority, avg_hours)
        FROM (
          SELECT priority, 
                 AVG(EXTRACT(EPOCH FROM (completed_date - created_at)) / 3600) as avg_hours
          FROM ${schema.workOrders}
          WHERE tenant_id = ${tenantId}
            AND status = 'completed'
            AND completed_date IS NOT NULL
            AND created_at >= ${startDate}
            AND created_at <= ${endDate}
          GROUP BY priority
        ) as priority_mttr
      `,
      byType: sql`
        json_object_agg(work_order_type, avg_hours)
        FROM (
          SELECT work_order_type,
                 AVG(EXTRACT(EPOCH FROM (completed_date - created_at)) / 3600) as avg_hours
          FROM ${schema.workOrders}
          WHERE tenant_id = ${tenantId}
            AND status = 'completed'
            AND completed_date IS NOT NULL
            AND created_at >= ${startDate}
            AND created_at <= ${endDate}
          GROUP BY work_order_type
        ) as type_mttr
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      eq(schema.workOrders.status, 'completed'),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ));
    
    // First Time Fix Rate
    const firstTimeFixRate = await db.select({
      total: sql`COUNT(*)`,
      firstTimeFix: sql`
        COUNT(*) FILTER (
          WHERE id NOT IN (
            SELECT DISTINCT work_order_id 
            FROM ${schema.maintenanceHistory}
            WHERE activity_type = 'repair'
              AND work_order_id IS NOT NULL
            GROUP BY work_order_id
            HAVING COUNT(*) > 1
          )
        )
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      eq(schema.workOrders.status, 'completed'),
      eq(schema.workOrders.workOrderType, 'corrective'),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ));
    
    // Technician performance
    const technicianPerformance = await db.select({
      technician: {
        id: schema.users.id,
        username: schema.users.username,
        email: schema.users.email
      },
      completedCount: sql`COUNT(*) FILTER (WHERE ${schema.workOrders.status} = 'completed')`,
      avgCompletionTime: sql`
        AVG(EXTRACT(EPOCH FROM (completed_date - created_at)) / 3600) 
        FILTER (WHERE status = 'completed' AND completed_date IS NOT NULL)
      `,
      totalLaborHours: sql`SUM(labor_hours::numeric)`,
      slaMetRate: sql`
        (COUNT(*) FILTER (WHERE sla_met = 1) * 100.0 / 
         NULLIF(COUNT(*) FILTER (WHERE sla_met IS NOT NULL), 0))
      `
    })
    .from(schema.workOrders)
    .innerJoin(schema.users, eq(schema.workOrders.assignedTo, schema.users.id))
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ))
    .groupBy(schema.users.id)
    .orderBy(desc(sql`COUNT(*) FILTER (WHERE ${schema.workOrders.status} = 'completed')`));
    
    // Preventive maintenance effectiveness
    const pmEffectiveness = await db.select({
      preventiveCount: sql`
        COUNT(*) FILTER (WHERE work_order_type = 'preventive')
      `,
      correctiveCount: sql`
        COUNT(*) FILTER (WHERE work_order_type = 'corrective')
      `,
      emergencyCount: sql`
        COUNT(*) FILTER (WHERE work_order_type = 'emergency')
      `,
      pmComplianceRate: sql`
        (COUNT(*) FILTER (
          WHERE work_order_type = 'preventive' 
            AND status = 'completed'
            AND completed_date <= scheduled_date + INTERVAL '7 days'
        ) * 100.0 / 
        NULLIF(COUNT(*) FILTER (WHERE work_order_type = 'preventive'), 0))
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ));
    
    // Asset reliability (devices with most issues)
    const assetReliability = await db.select({
      deviceId: schema.workOrders.deviceId,
      deviceType: schema.workOrders.deviceType,
      failureCount: sql`COUNT(*) FILTER (WHERE work_order_type = 'corrective')`,
      totalDowntime: sql`
        SUM(EXTRACT(EPOCH FROM (completed_date - created_at)) / 3600) 
        FILTER (WHERE work_order_type IN ('corrective', 'emergency'))
      `,
      avgTimeBetweenFailures: sql`
        AVG(days_between) FROM (
          SELECT EXTRACT(DAY FROM (created_at - LAG(created_at) OVER (PARTITION BY device_id ORDER BY created_at)))
            as days_between
          FROM ${schema.workOrders}
          WHERE tenant_id = ${tenantId}
            AND device_id = ${schema.workOrders.deviceId}
            AND work_order_type = 'corrective'
        ) as mtbf
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, startDate),
      lte(schema.workOrders.createdAt, endDate)
    ))
    .groupBy(schema.workOrders.deviceId, schema.workOrders.deviceType)
    .orderBy(desc(sql`COUNT(*) FILTER (WHERE work_order_type = 'corrective')`))
    .limit(20);
    
    const performance = {
      mttr: {
        overall: Number(mttr[0].avgHours) || 0,
        byPriority: mttr[0].byPriority || {},
        byType: mttr[0].byType || {}
      },
      firstTimeFixRate: {
        rate: firstTimeFixRate[0].total > 0
          ? (Number(firstTimeFixRate[0].firstTimeFix) / Number(firstTimeFixRate[0].total)) * 100
          : 0,
        total: Number(firstTimeFixRate[0].total),
        firstTimeFix: Number(firstTimeFixRate[0].firstTimeFix)
      },
      technicianPerformance: technicianPerformance.map(t => ({
        technician: t.technician,
        completedCount: Number(t.completedCount),
        avgCompletionTimeHours: Number(t.avgCompletionTime) || 0,
        totalLaborHours: Number(t.totalLaborHours) || 0,
        slaMetRate: Number(t.slaMetRate) || 0,
        productivity: t.totalLaborHours && t.completedCount
          ? Number(t.completedCount) / Number(t.totalLaborHours)
          : 0
      })),
      preventiveMaintenance: {
        effectiveness: {
          preventiveCount: Number(pmEffectiveness[0].preventiveCount),
          correctiveCount: Number(pmEffectiveness[0].correctiveCount),
          emergencyCount: Number(pmEffectiveness[0].emergencyCount),
          preventiveRatio: pmEffectiveness[0].preventiveCount && pmEffectiveness[0].correctiveCount
            ? Number(pmEffectiveness[0].preventiveCount) / 
              (Number(pmEffectiveness[0].preventiveCount) + Number(pmEffectiveness[0].correctiveCount)) * 100
            : 0,
          complianceRate: Number(pmEffectiveness[0].pmComplianceRate) || 0
        }
      },
      assetReliability: assetReliability.map(a => ({
        deviceId: a.deviceId,
        deviceType: a.deviceType,
        failureCount: Number(a.failureCount),
        totalDowntimeHours: Number(a.totalDowntime) || 0,
        avgTimeBetweenFailuresDays: Number(a.avgTimeBetweenFailures) || 0,
        reliabilityScore: a.avgTimeBetweenFailures
          ? Math.min(100, (Number(a.avgTimeBetweenFailures) / 30) * 100) // Simple scoring
          : 0
      }))
    };
    
    return c.json({ performance });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get maintenance performance', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid filter parameters', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to get maintenance performance' });
  } finally {
    span.end();
  }
});

// Get predictive maintenance insights
app.get('/predictive', async (c) => {
  const span = tracer.startSpan('getPredictiveInsights');
  
  try {
    const tenantId = c.get('tenantId');
    
    // Get devices with increasing failure rates
    const failureTrends = await db.select({
      deviceId: schema.workOrders.deviceId,
      deviceType: schema.workOrders.deviceType,
      recentFailures: sql`
        COUNT(*) FILTER (
          WHERE work_order_type = 'corrective' 
            AND created_at >= CURRENT_DATE - INTERVAL '30 days'
        )
      `,
      previousFailures: sql`
        COUNT(*) FILTER (
          WHERE work_order_type = 'corrective'
            AND created_at >= CURRENT_DATE - INTERVAL '60 days'
            AND created_at < CURRENT_DATE - INTERVAL '30 days'
        )
      `,
      avgRepairCost: sql`
        AVG(amount) FROM ${schema.maintenanceCosts}
        WHERE work_order_id IN (
          SELECT id FROM ${schema.workOrders}
          WHERE device_id = ${schema.workOrders.deviceId}
            AND work_order_type = 'corrective'
        )
      `
    })
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      gte(schema.workOrders.createdAt, new Date(Date.now() - 60 * 24 * 60 * 60 * 1000))
    ))
    .groupBy(schema.workOrders.deviceId, schema.workOrders.deviceType)
    .having(sql`COUNT(*) FILTER (WHERE work_order_type = 'corrective') > 2`);
    
    // Analyze IoT metrics for anomalies
    const iotAnomalies = await db.select({
      deviceId: schema.iotDeviceMetrics.deviceId,
      metricType: schema.iotDeviceMetrics.metricType,
      anomalyCount: sql`COUNT(*) FILTER (WHERE anomaly_detected = 1)`,
      avgValue: sql`AVG(value)`,
      stdDev: sql`STDDEV(value)`,
      maxValue: sql`MAX(value)`,
      latestValue: sql`
        FIRST_VALUE(value) OVER (
          PARTITION BY device_id, metric_type 
          ORDER BY recorded_at DESC
        )
      `
    })
    .from(schema.iotDeviceMetrics)
    .where(and(
      eq(schema.iotDeviceMetrics.tenantId, tenantId),
      gte(schema.iotDeviceMetrics.recordedAt, new Date(Date.now() - 7 * 24 * 60 * 60 * 1000))
    ))
    .groupBy(
      schema.iotDeviceMetrics.deviceId,
      schema.iotDeviceMetrics.metricType,
      schema.iotDeviceMetrics.value,
      schema.iotDeviceMetrics.recordedAt
    );
    
    // Generate predictions
    const predictions = failureTrends.map(trend => {
      const failureIncrease = Number(trend.recentFailures) - Number(trend.previousFailures);
      const failureRate = failureIncrease / Number(trend.previousFailures || 1);
      
      return {
        deviceId: trend.deviceId,
        deviceType: trend.deviceType,
        riskLevel: failureRate > 0.5 ? 'high' :
                  failureRate > 0.2 ? 'medium' : 'low',
        predictedFailureWindow: failureRate > 0.5 ? '7-14 days' :
                               failureRate > 0.2 ? '14-30 days' : '30+ days',
        estimatedCost: Number(trend.avgRepairCost) || 0,
        recommendation: failureRate > 0.5 
          ? 'Schedule immediate preventive maintenance'
          : 'Monitor closely and schedule maintenance within 30 days',
        metrics: {
          recentFailures: Number(trend.recentFailures),
          previousFailures: Number(trend.previousFailures),
          failureRateIncrease: failureRate * 100
        }
      };
    });
    
    // High-risk devices needing attention
    const highRiskDevices = predictions.filter(p => p.riskLevel === 'high');
    
    return c.json({
      summary: {
        totalDevicesAnalyzed: failureTrends.length,
        highRiskDevices: highRiskDevices.length,
        estimatedPreventableCosts: highRiskDevices.reduce((sum, d) => sum + d.estimatedCost, 0),
        anomaliesDetected: iotAnomalies.filter(a => Number(a.anomalyCount) > 0).length
      },
      predictions,
      iotAnomalies: iotAnomalies
        .filter(a => Number(a.anomalyCount) > 0)
        .map(a => ({
          deviceId: a.deviceId,
          metricType: a.metricType,
          anomalyCount: Number(a.anomalyCount),
          avgValue: Number(a.avgValue),
          stdDev: Number(a.stdDev),
          maxValue: Number(a.maxValue),
          latestValue: Number(a.latestValue),
          status: Number(a.latestValue) > Number(a.avgValue) + 2 * Number(a.stdDev)
            ? 'critical' : 'warning'
        })),
      recommendations: {
        immediate: highRiskDevices.map(d => ({
          deviceId: d.deviceId,
          action: 'Schedule preventive maintenance',
          estimatedSavings: d.estimatedCost * 0.7 // Assuming 70% cost savings
        })),
        monitoring: predictions
          .filter(p => p.riskLevel === 'medium')
          .map(p => ({
            deviceId: p.deviceId,
            action: 'Increase monitoring frequency',
            checkInterval: '48 hours'
          }))
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get predictive insights', { error });
    throw new HTTPException(500, { message: 'Failed to get predictive insights' });
  } finally {
    span.end();
  }
});

export default app;