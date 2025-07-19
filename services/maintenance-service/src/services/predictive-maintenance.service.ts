import * as cron from 'node-cron';
import Redis from 'ioredis';
import { db, schema } from '../db';
import { eq, and, gte, sql, desc, inArray } from 'drizzle-orm';
import { logger } from '@sparc/shared';
import { NotificationService } from './notification.service';

interface DeviceHealthScore {
  deviceId: string;
  deviceType: string;
  healthScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  predictedFailureWindow?: string;
  recommendations: string[];
  metrics: {
    failureRate: number;
    mtbf: number; // Mean Time Between Failures
    avgRepairTime: number;
    recentAnomalies: number;
    utilizationRate: number;
  };
}

export class PredictiveMaintenanceService {
  private scheduledTask: cron.ScheduledTask | null = null;
  private running = false;

  constructor(
    private redis: Redis,
    private notificationService: NotificationService
  ) {}

  async start(): Promise<void> {
    // Run analysis every 6 hours
    this.scheduledTask = cron.schedule('0 */6 * * *', async () => {
      await this.analyzePredictiveMaintenance();
    });

    // Also run once on startup after a delay
    setTimeout(() => this.analyzePredictiveMaintenance(), 60000); // 1 minute delay

    this.running = true;
    logger.info('Predictive maintenance service started');
  }

  async stop(): Promise<void> {
    if (this.scheduledTask) {
      this.scheduledTask.stop();
      this.scheduledTask = null;
    }
    this.running = false;
    logger.info('Predictive maintenance service stopped');
  }

  isRunning(): boolean {
    return this.running;
  }

  private async analyzePredictiveMaintenance(): Promise<void> {
    const startTime = Date.now();
    logger.info('Starting predictive maintenance analysis');

    try {
      // Get all active devices
      const devices = await db.select()
        .from(schema.devices)
        .where(eq(schema.devices.status, 'active'));

      logger.info(`Analyzing ${devices.length} devices`);

      const highRiskDevices: DeviceHealthScore[] = [];
      let alertsGenerated = 0;

      for (const device of devices) {
        try {
          const healthScore = await this.calculateDeviceHealthScore(device);
          
          if (healthScore.riskLevel === 'high' || healthScore.riskLevel === 'critical') {
            highRiskDevices.push(healthScore);
            
            // Create predictive alert
            await this.createPredictiveAlert(device, healthScore);
            alertsGenerated++;
          }

          // Store health score in cache
          await this.redis.setex(
            `device:health:${device.id}`,
            86400, // 24 hours
            JSON.stringify(healthScore)
          );

        } catch (error) {
          logger.error('Failed to analyze device', {
            deviceId: device.id,
            error
          });
        }
      }

      // Update global insights
      await this.updateGlobalInsights(devices.length, highRiskDevices);

      // Update metrics
      if (alertsGenerated > 0) {
        await this.redis.incr('metrics:predictive:alerts', alertsGenerated);
      }

      const duration = Date.now() - startTime;
      logger.info('Predictive maintenance analysis completed', {
        devicesAnalyzed: devices.length,
        highRiskDevices: highRiskDevices.length,
        alertsGenerated,
        durationMs: duration
      });

    } catch (error) {
      logger.error('Failed to run predictive maintenance analysis', { error });
    }
  }

  private async calculateDeviceHealthScore(device: any): Promise<DeviceHealthScore> {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

    // Get maintenance history
    const [maintenanceHistory, iotMetrics, diagnosticResults] = await Promise.all([
      // Maintenance history
      db.select({
        workOrderType: schema.workOrders.workOrderType,
        createdAt: schema.workOrders.createdAt,
        completedDate: schema.workOrders.completedDate,
        laborHours: schema.workOrders.laborHours,
        actualCost: schema.workOrders.actualCost
      })
      .from(schema.workOrders)
      .where(and(
        eq(schema.workOrders.deviceId, device.id),
        gte(schema.workOrders.createdAt, ninetyDaysAgo)
      ))
      .orderBy(desc(schema.workOrders.createdAt)),

      // IoT metrics with anomalies
      db.select({
        metricType: schema.iotDeviceMetrics.metricType,
        anomalyCount: sql`COUNT(*) FILTER (WHERE anomaly_detected = 1)`,
        totalCount: sql`COUNT(*)`,
        avgValue: sql`AVG(value::numeric)`,
        maxValue: sql`MAX(value::numeric)`,
        lastAnomaly: sql`MAX(recorded_at) FILTER (WHERE anomaly_detected = 1)`
      })
      .from(schema.iotDeviceMetrics)
      .where(and(
        eq(schema.iotDeviceMetrics.deviceId, device.id),
        gte(schema.iotDeviceMetrics.recordedAt, thirtyDaysAgo)
      ))
      .groupBy(schema.iotDeviceMetrics.metricType),

      // Recent diagnostic results
      db.select()
      .from(schema.deviceDiagnostics)
      .where(and(
        eq(schema.deviceDiagnostics.deviceId, device.id),
        gte(schema.deviceDiagnostics.createdAt, thirtyDaysAgo)
      ))
      .orderBy(desc(schema.deviceDiagnostics.createdAt))
      .limit(10)
    ]);

    // Calculate metrics
    const correctiveWorkOrders = maintenanceHistory.filter(wo => wo.workOrderType === 'corrective');
    const recentCorrectiveWorkOrders = correctiveWorkOrders.filter(wo => 
      wo.createdAt >= thirtyDaysAgo
    );

    // Failure rate (failures per month)
    const failureRate = recentCorrectiveWorkOrders.length;

    // Mean Time Between Failures (MTBF) in days
    let mtbf = 0;
    if (correctiveWorkOrders.length > 1) {
      const sortedFailures = correctiveWorkOrders.sort((a, b) => 
        a.createdAt.getTime() - b.createdAt.getTime()
      );
      
      let totalDays = 0;
      for (let i = 1; i < sortedFailures.length; i++) {
        const daysBetween = (sortedFailures[i].createdAt.getTime() - 
                            sortedFailures[i-1].createdAt.getTime()) / (1000 * 60 * 60 * 24);
        totalDays += daysBetween;
      }
      mtbf = totalDays / (sortedFailures.length - 1);
    }

    // Average repair time
    const completedWorkOrders = maintenanceHistory.filter(wo => wo.completedDate);
    const avgRepairTime = completedWorkOrders.length > 0
      ? completedWorkOrders.reduce((sum, wo) => {
          const hours = wo.laborHours ? parseFloat(wo.laborHours) : 
                       (wo.completedDate!.getTime() - wo.createdAt.getTime()) / (1000 * 60 * 60);
          return sum + hours;
        }, 0) / completedWorkOrders.length
      : 0;

    // IoT anomalies
    const recentAnomalies = iotMetrics.reduce((sum, metric) => 
      sum + Number(metric.anomalyCount), 0
    );
    
    // Diagnostic failures
    const failedDiagnostics = diagnosticResults.filter(d => d.overallStatus === 'fail').length;
    const warningDiagnostics = diagnosticResults.filter(d => d.overallStatus === 'warning').length;

    // Device utilization (simplified - would need actual runtime data)
    const utilizationRate = device.status === 'active' ? 85 : 0;

    // Calculate health score (0-100)
    let healthScore = 100;

    // Deduct for failures
    healthScore -= Math.min(failureRate * 10, 30); // Max 30 points for failures
    
    // Deduct for short MTBF
    if (mtbf > 0 && mtbf < 30) {
      healthScore -= Math.min((30 - mtbf), 20); // Max 20 points for short MTBF
    }

    // Deduct for IoT anomalies
    healthScore -= Math.min(recentAnomalies * 2, 20); // Max 20 points for anomalies

    // Deduct for diagnostic issues
    healthScore -= failedDiagnostics * 10 + warningDiagnostics * 5; // Max based on diagnostics

    // Ensure score is between 0 and 100
    healthScore = Math.max(0, Math.min(100, healthScore));

    // Determine risk level
    let riskLevel: 'low' | 'medium' | 'high' | 'critical';
    if (healthScore >= 80) {
      riskLevel = 'low';
    } else if (healthScore >= 60) {
      riskLevel = 'medium';
    } else if (healthScore >= 40) {
      riskLevel = 'high';
    } else {
      riskLevel = 'critical';
    }

    // Predict failure window
    let predictedFailureWindow: string | undefined;
    if (riskLevel === 'critical') {
      predictedFailureWindow = '0-7 days';
    } else if (riskLevel === 'high') {
      if (mtbf > 0 && mtbf < 30) {
        predictedFailureWindow = `${Math.floor(mtbf / 2)}-${Math.floor(mtbf)} days`;
      } else {
        predictedFailureWindow = '7-30 days';
      }
    }

    // Generate recommendations
    const recommendations: string[] = [];
    
    if (failureRate > 2) {
      recommendations.push('High failure rate detected - schedule immediate inspection');
    }
    
    if (mtbf > 0 && mtbf < 30) {
      recommendations.push('Frequent failures occurring - consider component replacement');
    }
    
    if (recentAnomalies > 5) {
      recommendations.push('Multiple IoT anomalies detected - check sensor calibration');
    }
    
    if (failedDiagnostics > 0) {
      recommendations.push('Recent diagnostic failures - perform comprehensive maintenance');
    }
    
    if (avgRepairTime > 4) {
      recommendations.push('Long repair times - ensure spare parts availability');
    }

    if (riskLevel === 'low' && recommendations.length === 0) {
      recommendations.push('Device operating normally - continue regular monitoring');
    }

    return {
      deviceId: device.id,
      deviceType: device.type,
      healthScore,
      riskLevel,
      predictedFailureWindow,
      recommendations,
      metrics: {
        failureRate,
        mtbf,
        avgRepairTime,
        recentAnomalies,
        utilizationRate
      }
    };
  }

  private async createPredictiveAlert(device: any, healthScore: DeviceHealthScore): Promise<void> {
    // Check if we've already created an alert recently
    const alertKey = `predictive:alert:${device.id}`;
    const recentAlert = await this.redis.get(alertKey);
    
    if (recentAlert) {
      return; // Already alerted
    }

    // Check for existing open predictive work orders
    const [existingWorkOrder] = await db.select()
      .from(schema.workOrders)
      .where(and(
        eq(schema.workOrders.deviceId, device.id),
        eq(schema.workOrders.workOrderType, 'preventive'),
        inArray(schema.workOrders.status, ['open', 'assigned', 'in_progress']),
        gte(schema.workOrders.createdAt, new Date(Date.now() - 7 * 24 * 60 * 60 * 1000))
      ))
      .limit(1);

    if (!existingWorkOrder) {
      // Create predictive maintenance work order
      const [workOrder] = await db.insert(schema.workOrders)
        .values({
          tenantId: device.tenantId,
          deviceId: device.id,
          deviceType: device.type,
          workOrderType: 'preventive',
          priority: healthScore.riskLevel === 'critical' ? 'critical' : 'high',
          title: `Predictive Maintenance Required - ${device.name}`,
          description: `Health score: ${healthScore.healthScore}/100. ${healthScore.recommendations.join('. ')}`,
          scheduledDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), // 3 days from now
          status: 'open',
          diagnosticData: {
            healthScore: healthScore.healthScore,
            riskLevel: healthScore.riskLevel,
            predictedFailureWindow: healthScore.predictedFailureWindow,
            metrics: healthScore.metrics
          }
        })
        .returning();

      // Create history entry
      await db.insert(schema.maintenanceHistory)
        .values({
          tenantId: device.tenantId,
          deviceId: device.id,
          workOrderId: workOrder.id,
          activityType: 'maintenance',
          description: `Predictive maintenance alert - Risk level: ${healthScore.riskLevel}`,
          performedBy: null, // System generated
          recommendations: healthScore.recommendations,
          nextActionDate: workOrder.scheduledDate
        });

      // Send notifications
      await this.notificationService.sendPredictiveMaintenanceAlert(device, healthScore, workOrder);
    }

    // Publish predictive alert event
    await this.redis.publish('maintenance:predictive:alert', JSON.stringify({
      tenantId: device.tenantId,
      deviceId: device.id,
      alert: {
        type: 'predictive_maintenance',
        healthScore: healthScore.healthScore,
        riskLevel: healthScore.riskLevel,
        predictedFailureWindow: healthScore.predictedFailureWindow,
        recommendations: healthScore.recommendations,
        device: {
          id: device.id,
          name: device.name,
          type: device.type
        }
      }
    }));

    // Mark as alerted (expires based on risk level)
    const ttl = healthScore.riskLevel === 'critical' ? 24 * 60 * 60 : 7 * 24 * 60 * 60;
    await this.redis.setex(alertKey, ttl, JSON.stringify({
      alertedAt: new Date(),
      healthScore: healthScore.healthScore,
      riskLevel: healthScore.riskLevel
    }));

    logger.info('Predictive maintenance alert created', {
      deviceId: device.id,
      healthScore: healthScore.healthScore,
      riskLevel: healthScore.riskLevel
    });
  }

  private async updateGlobalInsights(totalDevices: number, highRiskDevices: DeviceHealthScore[]): Promise<void> {
    const insights = {
      timestamp: new Date(),
      totalDevices,
      healthyDevices: totalDevices - highRiskDevices.length,
      highRiskDevices: highRiskDevices.length,
      riskDistribution: {
        critical: highRiskDevices.filter(d => d.riskLevel === 'critical').length,
        high: highRiskDevices.filter(d => d.riskLevel === 'high').length
      },
      topRiskFactors: this.identifyTopRiskFactors(highRiskDevices),
      estimatedCostSavings: this.estimateCostSavings(highRiskDevices)
    };

    // Store insights
    await this.redis.setex(
      'predictive:insights:latest',
      86400, // 24 hours
      JSON.stringify(insights)
    );

    // Store historical data
    await this.redis.lpush(
      'predictive:insights:history',
      JSON.stringify(insights)
    );
    
    // Keep only last 30 days of history
    await this.redis.ltrim('predictive:insights:history', 0, 29);
  }

  private identifyTopRiskFactors(highRiskDevices: DeviceHealthScore[]): string[] {
    const factors: Record<string, number> = {};

    highRiskDevices.forEach(device => {
      if (device.metrics.failureRate > 2) {
        factors['High failure rate'] = (factors['High failure rate'] || 0) + 1;
      }
      if (device.metrics.mtbf < 30 && device.metrics.mtbf > 0) {
        factors['Frequent failures'] = (factors['Frequent failures'] || 0) + 1;
      }
      if (device.metrics.recentAnomalies > 5) {
        factors['IoT anomalies'] = (factors['IoT anomalies'] || 0) + 1;
      }
      if (device.metrics.avgRepairTime > 4) {
        factors['Long repair times'] = (factors['Long repair times'] || 0) + 1;
      }
    });

    return Object.entries(factors)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([factor]) => factor);
  }

  private estimateCostSavings(highRiskDevices: DeviceHealthScore[]): number {
    // Estimate based on preventing emergency repairs
    const avgEmergencyRepairCost = 1500; // Base cost
    const avgPreventiveMaintenanceCost = 500; // Base cost
    
    return highRiskDevices.reduce((total, device) => {
      const multiplier = device.riskLevel === 'critical' ? 0.8 : 0.5; // Probability of failure
      return total + (avgEmergencyRepairCost - avgPreventiveMaintenanceCost) * multiplier;
    }, 0);
  }
}