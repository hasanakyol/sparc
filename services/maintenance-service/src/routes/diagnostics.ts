import { Hono } from 'hono';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';
import { eq, and, desc, gte } from 'drizzle-orm';
import { db, schema } from '../db';
import { 
  runDiagnosticsSchema,
  diagnosticResultSchema,
  RunDiagnosticsInput,
  DiagnosticResult
} from '../types';
import { logger } from '@sparc/shared';
import { trace } from '@opentelemetry/api';
import Redis from 'ioredis';

const tracer = trace.getTracer('maintenance-service');
const app = new Hono<{ Variables: { tenantId: string; userId: string; redis: Redis } }>();

// Run diagnostics on a device
app.post('/:deviceId/run', async (c) => {
  const span = tracer.startSpan('runDeviceDiagnostics');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const redis = c.get('redis');
    const deviceId = c.req.param('deviceId');
    const body = await c.req.json();
    
    // Validate input
    const input = runDiagnosticsSchema.parse(body) as RunDiagnosticsInput;
    
    span.setAttributes({
      'device.id': deviceId,
      'diagnostics.type': input.diagnosticType,
      'diagnostics.automated': input.automated
    });
    
    // Verify device exists (would normally check device service)
    const [device] = await db.select()
      .from(schema.devices)
      .where(and(
        eq(schema.devices.id, deviceId),
        eq(schema.devices.tenantId, tenantId)
      ))
      .limit(1);
    
    if (!device) {
      throw new HTTPException(404, { message: 'Device not found' });
    }
    
    // Perform diagnostics based on device type
    const diagnosticResults = await performDiagnostics(device, input.diagnosticType);
    
    // Determine overall status
    const overallStatus = determineOverallStatus(diagnosticResults);
    
    // Generate recommendations
    const recommendations = generateRecommendations(diagnosticResults, device);
    
    // Save diagnostic results
    const [diagnostic] = await db.insert(schema.deviceDiagnostics)
      .values({
        tenantId,
        deviceId,
        diagnosticType: input.diagnosticType,
        results: diagnosticResults,
        overallStatus,
        recommendations,
        performedBy: input.automated ? null : userId,
        automated: input.automated ? 1 : 0
      })
      .returning();
    
    // Create maintenance history entry
    await db.insert(schema.maintenanceHistory)
      .values({
        tenantId,
        deviceId,
        activityType: 'diagnostic',
        description: `${input.diagnosticType} diagnostics performed`,
        performedBy: input.automated ? null : userId,
        outcome: `Overall status: ${overallStatus}`,
        recommendations
      });
    
    // If critical issues found, create work order
    if (overallStatus === 'fail' && !input.automated) {
      const criticalIssues = Object.entries(diagnosticResults)
        .filter(([_, status]) => status === 'fail')
        .map(([test, _]) => test);
      
      const [workOrder] = await db.insert(schema.workOrders)
        .values({
          tenantId,
          deviceId,
          deviceType: device.type,
          workOrderType: 'corrective',
          priority: 'high',
          title: `Diagnostic Issues Detected - ${device.name}`,
          description: `Critical issues found during diagnostics: ${criticalIssues.join(', ')}`,
          diagnosticData: diagnosticResults,
          createdBy: userId,
          status: 'open'
        })
        .returning();
      
      // Publish work order created event
      await redis.publish('maintenance:work-order:update', JSON.stringify({
        action: 'created',
        tenantId,
        workOrder
      }));
      
      diagnostic.workOrderId = workOrder.id;
    }
    
    // Check for predictive maintenance indicators
    if (recommendations.some(r => r.includes('preventive') || r.includes('scheduled'))) {
      await redis.publish('maintenance:predictive:alert', JSON.stringify({
        tenantId,
        deviceId,
        alert: {
          type: 'predictive_maintenance',
          diagnosticId: diagnostic.id,
          recommendations,
          severity: overallStatus === 'warning' ? 'medium' : 'low'
        }
      }));
    }
    
    logger.info('Device diagnostics completed', {
      deviceId,
      diagnosticType: input.diagnosticType,
      overallStatus
    });
    
    return c.json({
      diagnostic,
      device: {
        id: device.id,
        name: device.name,
        type: device.type,
        status: device.status
      },
      workOrderCreated: diagnostic.workOrderId ? true : false
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to run device diagnostics', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid diagnostic request', cause: error.errors });
    }
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to run diagnostics' });
  } finally {
    span.end();
  }
});

// Get diagnostic history for a device
app.get('/:deviceId/history', async (c) => {
  const span = tracer.startSpan('getDeviceDiagnosticHistory');
  
  try {
    const tenantId = c.get('tenantId');
    const deviceId = c.req.param('deviceId');
    const limit = parseInt(c.req.query('limit') || '50');
    const days = parseInt(c.req.query('days') || '90');
    
    span.setAttributes({
      'device.id': deviceId,
      'history.limit': limit,
      'history.days': days
    });
    
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    
    // Get diagnostic history
    const diagnostics = await db.select({
      diagnostic: schema.deviceDiagnostics,
      performedByUser: {
        id: schema.users.id,
        username: schema.users.username
      }
    })
    .from(schema.deviceDiagnostics)
    .leftJoin(schema.users, eq(schema.deviceDiagnostics.performedBy, schema.users.id))
    .where(and(
      eq(schema.deviceDiagnostics.deviceId, deviceId),
      eq(schema.deviceDiagnostics.tenantId, tenantId),
      gte(schema.deviceDiagnostics.createdAt, startDate)
    ))
    .orderBy(desc(schema.deviceDiagnostics.createdAt))
    .limit(limit);
    
    // Get related work orders
    const workOrderIds = diagnostics
      .map(d => d.diagnostic.workOrderId)
      .filter(id => id !== null);
    
    const workOrders = workOrderIds.length > 0
      ? await db.select()
          .from(schema.workOrders)
          .where(inArray(schema.workOrders.id, workOrderIds))
      : [];
    
    // Calculate trends
    const trends = analyzeDiagnosticTrends(diagnostics.map(d => d.diagnostic));
    
    return c.json({
      diagnostics: diagnostics.map(d => ({
        ...d.diagnostic,
        performedByUser: d.performedByUser?.id ? d.performedByUser : null,
        workOrder: workOrders.find(wo => wo.id === d.diagnostic.workOrderId) || null
      })),
      trends,
      summary: {
        totalDiagnostics: diagnostics.length,
        automated: diagnostics.filter(d => d.diagnostic.automated).length,
        manual: diagnostics.filter(d => !d.diagnostic.automated).length,
        failureRate: diagnostics.length > 0
          ? (diagnostics.filter(d => d.diagnostic.overallStatus === 'fail').length / diagnostics.length) * 100
          : 0
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get device diagnostic history', { error });
    throw new HTTPException(500, { message: 'Failed to get diagnostic history' });
  } finally {
    span.end();
  }
});

// Get latest diagnostic for a device
app.get('/:deviceId/latest', async (c) => {
  const span = tracer.startSpan('getLatestDiagnostic');
  
  try {
    const tenantId = c.get('tenantId');
    const deviceId = c.req.param('deviceId');
    
    span.setAttributes({ 'device.id': deviceId });
    
    const [latest] = await db.select()
      .from(schema.deviceDiagnostics)
      .where(and(
        eq(schema.deviceDiagnostics.deviceId, deviceId),
        eq(schema.deviceDiagnostics.tenantId, tenantId)
      ))
      .orderBy(desc(schema.deviceDiagnostics.createdAt))
      .limit(1);
    
    if (!latest) {
      throw new HTTPException(404, { message: 'No diagnostic history found for device' });
    }
    
    return c.json({ diagnostic: latest });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get latest diagnostic', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to get latest diagnostic' });
  } finally {
    span.end();
  }
});

// Compare diagnostics over time
app.get('/:deviceId/compare', async (c) => {
  const span = tracer.startSpan('compareDiagnostics');
  
  try {
    const tenantId = c.get('tenantId');
    const deviceId = c.req.param('deviceId');
    const count = parseInt(c.req.query('count') || '5');
    
    span.setAttributes({
      'device.id': deviceId,
      'compare.count': count
    });
    
    // Get recent diagnostics
    const diagnostics = await db.select()
      .from(schema.deviceDiagnostics)
      .where(and(
        eq(schema.deviceDiagnostics.deviceId, deviceId),
        eq(schema.deviceDiagnostics.tenantId, tenantId)
      ))
      .orderBy(desc(schema.deviceDiagnostics.createdAt))
      .limit(count);
    
    if (diagnostics.length < 2) {
      throw new HTTPException(400, { 
        message: 'Not enough diagnostic history for comparison' 
      });
    }
    
    // Compare results
    const comparison = diagnostics.map((diag, index) => {
      const previous = index < diagnostics.length - 1 ? diagnostics[index + 1] : null;
      const results = diag.results as DiagnosticResult;
      const previousResults = previous?.results as DiagnosticResult | null;
      
      const changes: Record<string, string> = {};
      
      if (previousResults) {
        Object.keys(results).forEach(key => {
          if (results[key] !== previousResults[key]) {
            changes[key] = `${previousResults[key]} → ${results[key]}`;
          }
        });
      }
      
      return {
        diagnosticId: diag.id,
        createdAt: diag.createdAt,
        overallStatus: diag.overallStatus,
        changes: Object.keys(changes).length > 0 ? changes : null,
        improvementCount: Object.values(changes).filter(c => 
          c.includes('fail → pass') || c.includes('warning → pass')
        ).length,
        degradationCount: Object.values(changes).filter(c => 
          c.includes('pass → fail') || c.includes('pass → warning')
        ).length
      };
    });
    
    // Calculate overall trend
    const trend = comparison.reduce((acc, comp) => {
      acc.improvements += comp.improvementCount;
      acc.degradations += comp.degradationCount;
      return acc;
    }, { improvements: 0, degradations: 0 });
    
    return c.json({
      comparison,
      trend: {
        ...trend,
        overall: trend.improvements > trend.degradations ? 'improving' :
                trend.degradations > trend.improvements ? 'degrading' : 'stable'
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to compare diagnostics', { error });
    
    if (error instanceof HTTPException) throw error;
    throw new HTTPException(500, { message: 'Failed to compare diagnostics' });
  } finally {
    span.end();
  }
});

// Schedule automated diagnostics
app.post('/:deviceId/schedule', async (c) => {
  const span = tracer.startSpan('scheduleAutomatedDiagnostics');
  
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    const deviceId = c.req.param('deviceId');
    const body = await c.req.json();
    
    const { interval, diagnosticTypes } = z.object({
      interval: z.enum(['daily', 'weekly', 'monthly']),
      diagnosticTypes: z.array(z.string()).min(1)
    }).parse(body);
    
    span.setAttributes({
      'device.id': deviceId,
      'schedule.interval': interval,
      'schedule.types': diagnosticTypes.join(',')
    });
    
    // This would typically integrate with the preventive maintenance scheduler
    // For now, we'll create a placeholder schedule
    const schedule = {
      deviceId,
      interval,
      diagnosticTypes,
      nextRun: calculateNextRun(interval),
      createdBy: userId
    };
    
    logger.info('Automated diagnostics scheduled', {
      deviceId,
      interval,
      diagnosticTypes
    });
    
    return c.json({ 
      schedule,
      message: 'Automated diagnostics scheduled successfully' 
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to schedule automated diagnostics', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid schedule data', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to schedule diagnostics' });
  } finally {
    span.end();
  }
});

// Helper functions

async function performDiagnostics(device: any, diagnosticType: string): Promise<DiagnosticResult> {
  // Simulate diagnostics based on device type and diagnostic type
  const results: DiagnosticResult = {
    connectivity: 'pass',
    hardware: 'pass',
    firmware: 'pass',
    configuration: 'pass'
  };
  
  // Check device connectivity
  if (device.status === 'offline') {
    results.connectivity = 'fail';
  } else if (device.lastSeen && new Date(device.lastSeen) < new Date(Date.now() - 5 * 60 * 1000)) {
    results.connectivity = 'warning';
  }
  
  // Check hardware based on metrics
  if (device.healthMetrics) {
    const metrics = device.healthMetrics as any;
    
    if (metrics.temperature && metrics.temperature > 70) {
      results.hardware = 'warning';
    }
    if (metrics.temperature && metrics.temperature > 85) {
      results.hardware = 'fail';
    }
    
    if (metrics.powerStatus && metrics.powerStatus !== 'normal') {
      results.hardware = results.hardware === 'fail' ? 'fail' : 'warning';
    }
  }
  
  // Check firmware
  if (device.firmwareVersion) {
    // This would check against a firmware database
    const latestVersion = '2.1.0';
    if (device.firmwareVersion < latestVersion) {
      results.firmware = 'warning';
    }
  }
  
  // Additional checks based on diagnostic type
  if (diagnosticType === 'comprehensive') {
    results.performance = 'pass';
    results.security = 'pass';
    
    // Simulate performance check
    if (device.healthMetrics?.responseTime && device.healthMetrics.responseTime > 1000) {
      results.performance = 'warning';
    }
    
    // Simulate security check
    if (!device.lastSecurityUpdate || 
        new Date(device.lastSecurityUpdate) < new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)) {
      results.security = 'warning';
    }
  }
  
  return results;
}

function determineOverallStatus(results: DiagnosticResult): 'pass' | 'fail' | 'warning' {
  const statuses = Object.values(results);
  
  if (statuses.includes('fail')) {
    return 'fail';
  }
  if (statuses.includes('warning')) {
    return 'warning';
  }
  return 'pass';
}

function generateRecommendations(results: DiagnosticResult, device: any): string[] {
  const recommendations: string[] = [];
  
  if (results.connectivity === 'fail') {
    recommendations.push('Check network connectivity and power supply');
    recommendations.push('Verify network configuration and firewall rules');
  } else if (results.connectivity === 'warning') {
    recommendations.push('Monitor device connectivity - intermittent issues detected');
  }
  
  if (results.hardware === 'fail') {
    recommendations.push('Immediate hardware inspection required');
    recommendations.push('Check temperature and cooling systems');
  } else if (results.hardware === 'warning') {
    recommendations.push('Schedule preventive maintenance for hardware components');
  }
  
  if (results.firmware === 'warning') {
    recommendations.push('Firmware update available - schedule update during maintenance window');
  }
  
  if (results.configuration === 'warning') {
    recommendations.push('Review and update device configuration');
  }
  
  if (results.performance === 'warning') {
    recommendations.push('Performance degradation detected - investigate resource usage');
  }
  
  if (results.security === 'warning') {
    recommendations.push('Security updates required - apply latest patches');
  }
  
  // General recommendations
  if (results.connectivity === 'pass' && results.hardware === 'pass' && results.firmware === 'pass') {
    recommendations.push('Device operating normally - continue regular monitoring');
  }
  
  return recommendations;
}

function analyzeDiagnosticTrends(diagnostics: any[]): any {
  if (diagnostics.length < 2) {
    return { trend: 'insufficient_data' };
  }
  
  // Count status occurrences
  const statusCounts = diagnostics.reduce((acc, diag) => {
    acc[diag.overallStatus] = (acc[diag.overallStatus] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  // Analyze failure patterns
  const recentDiagnostics = diagnostics.slice(0, 5);
  const olderDiagnostics = diagnostics.slice(5, 10);
  
  const recentFailureRate = recentDiagnostics.filter(d => d.overallStatus === 'fail').length / recentDiagnostics.length;
  const olderFailureRate = olderDiagnostics.length > 0
    ? olderDiagnostics.filter(d => d.overallStatus === 'fail').length / olderDiagnostics.length
    : 0;
  
  // Common failure points
  const failurePoints: Record<string, number> = {};
  diagnostics.forEach(diag => {
    if (diag.overallStatus === 'fail') {
      const results = diag.results as DiagnosticResult;
      Object.entries(results).forEach(([key, value]) => {
        if (value === 'fail') {
          failurePoints[key] = (failurePoints[key] || 0) + 1;
        }
      });
    }
  });
  
  return {
    statusDistribution: statusCounts,
    trend: recentFailureRate > olderFailureRate ? 'degrading' :
           recentFailureRate < olderFailureRate ? 'improving' : 'stable',
    recentFailureRate: Math.round(recentFailureRate * 100),
    commonFailurePoints: Object.entries(failurePoints)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 3)
      .map(([point, count]) => ({ point, count }))
  };
}

function calculateNextRun(interval: string): Date {
  const now = new Date();
  
  switch (interval) {
    case 'daily':
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case 'weekly':
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case 'monthly':
      const nextMonth = new Date(now);
      nextMonth.setMonth(nextMonth.getMonth() + 1);
      return nextMonth;
    default:
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
  }
}

export default app;