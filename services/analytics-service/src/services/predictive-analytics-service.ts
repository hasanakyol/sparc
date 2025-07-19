import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';
import { PredictiveAlert, IncidentPrediction, AccessPattern } from '../types';

export class PredictiveAnalyticsService extends BaseAnalyticsService {
  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
  }

  async generatePredictiveAlerts(
    tenantId: string,
    entityType?: string,
    entityId?: string
  ): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    try {
      // Analyze different patterns for predictions
      const [
        securityBreaches,
        equipmentFailures,
        safetyViolations
      ] = await Promise.all([
        this.predictSecurityBreaches(tenantId, entityType, entityId),
        this.predictEquipmentFailures(tenantId, entityType, entityId),
        this.predictSafetyViolations(tenantId, entityType, entityId)
      ]);

      alerts.push(...securityBreaches, ...equipmentFailures, ...safetyViolations);

      // Store predictive alerts
      await this.storePredictiveAlerts(tenantId, alerts);

      // Sort by probability and severity
      return alerts.sort((a, b) => {
        if (a.severity !== b.severity) {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          return severityOrder[b.severity] - severityOrder[a.severity];
        }
        return b.probability - a.probability;
      });
    } catch (error) {
      this.logger.error('Predictive alert generation failed', { error, tenantId });
      throw error;
    }
  }

  async generateIncidentPredictions(
    tenantId: string,
    buildingId?: string
  ): Promise<IncidentPrediction[]> {
    const predictions: IncidentPrediction[] = [];

    try {
      // Generate predictions for different incident types
      const [
        securityIncidents,
        crowdIncidents,
        equipmentIncidents,
        safetyIncidents
      ] = await Promise.all([
        this.predictSecurityIncidents(tenantId, buildingId),
        this.predictCrowdIncidents(tenantId, buildingId),
        this.predictEquipmentIncidents(tenantId, buildingId),
        this.predictSafetyIncidents(tenantId, buildingId)
      ]);

      predictions.push(
        ...securityIncidents,
        ...crowdIncidents,
        ...equipmentIncidents,
        ...safetyIncidents
      );

      // Filter by confidence threshold
      return predictions.filter(p => p.confidence > 0.6);
    } catch (error) {
      this.logger.error('Incident prediction failed', { error, tenantId, buildingId });
      throw error;
    }
  }

  async analyzeAccessPatterns(
    tenantId: string,
    userId: string,
    startDate: Date,
    endDate: Date
  ): Promise<any> {
    try {
      // Get user's access events
      const accessEvents = await this.prisma.accessControlEvent.findMany({
        where: {
          tenantId,
          userId,
          timestamp: {
            gte: startDate,
            lte: endDate
          }
        },
        include: {
          door: {
            include: {
              zone: true,
              floor: true,
              building: true
            }
          }
        },
        orderBy: { timestamp: 'asc' }
      });

      // Analyze patterns
      const patterns = this.extractAccessPatterns(accessEvents);
      const anomalies = await this.detectAccessAnomalies(userId, accessEvents, patterns);
      const riskScore = this.calculateAccessRiskScore(patterns, anomalies);

      return {
        userId,
        period: { startDate, endDate },
        totalAccesses: accessEvents.length,
        patterns,
        anomalies,
        riskScore,
        recommendations: this.generateAccessRecommendations(patterns, anomalies, riskScore)
      };
    } catch (error) {
      this.logger.error('Access pattern analysis failed', { error, tenantId, userId });
      throw error;
    }
  }

  async analyzeBehaviorPatterns(
    tenantId: string,
    entityType: string,
    entityId: string,
    startDate: Date,
    endDate: Date
  ): Promise<any> {
    try {
      // Get behavior data from OpenSearch
      const behaviorData = await this.queryOpenSearch(
        `${this.config.opensearchIndex}-behavior`,
        {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { term: { entityType } },
                { term: { entityId } },
                {
                  range: {
                    timestamp: {
                      gte: startDate.toISOString(),
                      lte: endDate.toISOString()
                    }
                  }
                }
              ]
            }
          },
          size: 10000,
          sort: [{ timestamp: { order: 'asc' } }]
        }
      );

      // Analyze behavior patterns
      const patterns = this.extractBehaviorPatterns(behaviorData);
      const predictions = this.generateBehaviorPredictions(patterns);

      return {
        entityType,
        entityId,
        period: { startDate, endDate },
        dataPoints: behaviorData.length,
        patterns,
        predictions,
        riskIndicators: this.identifyRiskIndicators(patterns)
      };
    } catch (error) {
      this.logger.error('Behavior pattern analysis failed', { error, tenantId, entityType, entityId });
      throw error;
    }
  }

  async analyzeDeviceHealth(
    tenantId: string,
    deviceType?: string,
    deviceId?: string
  ): Promise<any> {
    try {
      const whereClause: any = { tenantId };
      if (deviceType) whereClause.type = deviceType;
      if (deviceId) whereClause.id = deviceId;

      // Get device data
      const devices = await this.prisma.device.findMany({
        where: whereClause,
        include: {
          events: {
            where: {
              timestamp: {
                gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
              }
            },
            orderBy: { timestamp: 'desc' }
          }
        }
      });

      // Analyze health for each device
      const healthAnalysis = devices.map(device => {
        const health = this.calculateDeviceHealth(device);
        const prediction = this.predictDeviceFailure(device, health);
        
        return {
          deviceId: device.id,
          deviceType: device.type,
          name: device.name,
          health,
          prediction,
          lastSeen: device.lastSeen,
          recommendations: this.generateDeviceRecommendations(health, prediction)
        };
      });

      return {
        summary: {
          totalDevices: devices.length,
          healthyDevices: healthAnalysis.filter(d => d.health.status === 'healthy').length,
          warningDevices: healthAnalysis.filter(d => d.health.status === 'warning').length,
          criticalDevices: healthAnalysis.filter(d => d.health.status === 'critical').length
        },
        devices: healthAnalysis
      };
    } catch (error) {
      this.logger.error('Device health analysis failed', { error, tenantId });
      throw error;
    }
  }

  private async predictSecurityBreaches(
    tenantId: string,
    entityType?: string,
    entityId?: string
  ): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    // Analyze failed access attempts
    const failedAttempts = await this.analyzeFailedAccessAttempts(tenantId, entityType, entityId);
    if (failedAttempts.riskScore > 0.7) {
      alerts.push({
        id: this.generateId(),
        type: 'security_breach_risk',
        severity: failedAttempts.riskScore > 0.9 ? 'critical' : 'high',
        message: `High risk of security breach detected. ${failedAttempts.count} failed attempts in the last hour.`,
        entityId: entityId || 'system',
        entityType: entityType || 'system',
        probability: failedAttempts.riskScore,
        factors: failedAttempts.factors,
        recommendedActions: [
          'Review access logs immediately',
          'Verify user credentials',
          'Consider temporary access restrictions'
        ],
        timestamp: new Date()
      });
    }

    // Analyze unusual access patterns
    const unusualPatterns = await this.analyzeUnusualAccessPatterns(tenantId, entityType, entityId);
    alerts.push(...unusualPatterns);

    return alerts;
  }

  private async predictEquipmentFailures(
    tenantId: string,
    entityType?: string,
    entityId?: string
  ): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    // Analyze device health metrics
    const devices = await this.getDevicesWithHealthIssues(tenantId, entityType, entityId);
    
    for (const device of devices) {
      if (device.failureProbability > 0.6) {
        alerts.push({
          id: this.generateId(),
          type: 'equipment_failure_risk',
          severity: device.failureProbability > 0.8 ? 'high' : 'medium',
          message: `${device.name} showing signs of potential failure. Estimated time to failure: ${device.timeToFailure} hours.`,
          entityId: device.id,
          entityType: device.type,
          probability: device.failureProbability,
          factors: device.factors,
          recommendedActions: device.recommendations,
          timestamp: new Date()
        });
      }
    }

    return alerts;
  }

  private async predictSafetyViolations(
    tenantId: string,
    entityType?: string,
    entityId?: string
  ): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    // Analyze occupancy and capacity violations
    const capacityRisks = await this.analyzeCapacityRisks(tenantId);
    
    for (const risk of capacityRisks) {
      if (risk.violationProbability > 0.7) {
        alerts.push({
          id: this.generateId(),
          type: 'safety_violation_risk',
          severity: risk.violationProbability > 0.9 ? 'critical' : 'high',
          message: `${risk.location} approaching capacity limit. Current: ${risk.currentOccupancy}, Limit: ${risk.maxCapacity}`,
          entityId: risk.locationId,
          entityType: 'zone',
          probability: risk.violationProbability,
          factors: ['High occupancy trend', 'Peak hour approaching'],
          recommendedActions: [
            'Monitor occupancy closely',
            'Prepare crowd control measures',
            'Alert security personnel'
          ],
          timestamp: new Date()
        });
      }
    }

    return alerts;
  }

  private extractAccessPatterns(accessEvents: any[]): any {
    const patterns = {
      timePatterns: new Map<number, number>(),
      locationPatterns: new Map<string, number>(),
      sequencePatterns: [],
      frequency: {
        daily: 0,
        weekly: 0,
        monthly: 0
      }
    };

    // Analyze time patterns
    accessEvents.forEach(event => {
      const hour = new Date(event.timestamp).getHours();
      patterns.timePatterns.set(hour, (patterns.timePatterns.get(hour) || 0) + 1);
      
      const location = `${event.door.building.name}-${event.door.floor?.name || 'Ground'}-${event.door.zone?.name || 'Common'}`;
      patterns.locationPatterns.set(location, (patterns.locationPatterns.get(location) || 0) + 1);
    });

    // Calculate frequencies
    const days = Math.ceil((new Date(accessEvents[accessEvents.length - 1]?.timestamp).getTime() - 
                           new Date(accessEvents[0]?.timestamp).getTime()) / (1000 * 60 * 60 * 24));
    patterns.frequency.daily = accessEvents.length / Math.max(days, 1);
    patterns.frequency.weekly = patterns.frequency.daily * 7;
    patterns.frequency.monthly = patterns.frequency.daily * 30;

    return patterns;
  }

  private async detectAccessAnomalies(userId: string, accessEvents: any[], patterns: any): Promise<any[]> {
    const anomalies: any[] = [];

    // Detect time-based anomalies
    accessEvents.forEach(event => {
      const hour = new Date(event.timestamp).getHours();
      const expectedCount = patterns.timePatterns.get(hour) || 0;
      const avgCount = Array.from(patterns.timePatterns.values()).reduce((a, b) => a + b, 0) / patterns.timePatterns.size;
      
      if (hour < 6 || hour > 22) {
        anomalies.push({
          type: 'after_hours_access',
          timestamp: event.timestamp,
          location: event.door.name,
          severity: 'medium'
        });
      }
    });

    return anomalies;
  }

  private calculateAccessRiskScore(patterns: any, anomalies: any[]): number {
    let score = 0;

    // Factor in anomaly count
    score += Math.min(anomalies.length * 0.1, 0.3);

    // Factor in unusual time patterns
    const afterHoursAccess = anomalies.filter(a => a.type === 'after_hours_access').length;
    score += Math.min(afterHoursAccess * 0.15, 0.3);

    // Factor in frequency
    if (patterns.frequency.daily > 20) {
      score += 0.2; // Unusually high frequency
    }

    return Math.min(score, 1.0);
  }

  private generateAccessRecommendations(patterns: any, anomalies: any[], riskScore: number): string[] {
    const recommendations: string[] = [];

    if (riskScore > 0.7) {
      recommendations.push('Review user access privileges');
      recommendations.push('Consider implementing time-based access restrictions');
    }

    if (anomalies.filter(a => a.type === 'after_hours_access').length > 5) {
      recommendations.push('Investigate reason for frequent after-hours access');
    }

    if (patterns.frequency.daily > 15) {
      recommendations.push('Verify if high access frequency is justified by role');
    }

    return recommendations;
  }

  private async storePredictiveAlerts(tenantId: string, alerts: PredictiveAlert[]): Promise<void> {
    for (const alert of alerts) {
      await this.storeInOpenSearch(`${this.config.opensearchIndex}-predictive-alerts`, {
        ...alert,
        tenantId,
        timestamp: alert.timestamp.toISOString()
      });
    }

    // Broadcast high-severity alerts
    const criticalAlerts = alerts.filter(a => a.severity === 'critical');
    if (criticalAlerts.length > 0) {
      await this.broadcastUpdate('predictive-alerts', {
        tenantId,
        alerts: criticalAlerts
      });
    }
  }

  // Helper methods for predictions (simplified implementations)
  private async analyzeFailedAccessAttempts(tenantId: string, entityType?: string, entityId?: string): Promise<any> {
    // Implementation would analyze failed access attempts
    return { count: 0, riskScore: 0, factors: [] };
  }

  private async analyzeUnusualAccessPatterns(tenantId: string, entityType?: string, entityId?: string): Promise<PredictiveAlert[]> {
    // Implementation would analyze unusual patterns
    return [];
  }

  private async getDevicesWithHealthIssues(tenantId: string, deviceType?: string, deviceId?: string): Promise<any[]> {
    // Implementation would get devices with health issues
    return [];
  }

  private async analyzeCapacityRisks(tenantId: string): Promise<any[]> {
    // Implementation would analyze capacity risks
    return [];
  }

  private extractBehaviorPatterns(behaviorData: any[]): any {
    // Implementation would extract behavior patterns
    return {};
  }

  private generateBehaviorPredictions(patterns: any): any[] {
    // Implementation would generate predictions
    return [];
  }

  private identifyRiskIndicators(patterns: any): any[] {
    // Implementation would identify risk indicators
    return [];
  }

  private calculateDeviceHealth(device: any): any {
    // Implementation would calculate device health
    return { status: 'healthy', score: 1.0 };
  }

  private predictDeviceFailure(device: any, health: any): any {
    // Implementation would predict device failure
    return { probability: 0, timeToFailure: null };
  }

  private generateDeviceRecommendations(health: any, prediction: any): string[] {
    // Implementation would generate recommendations
    return [];
  }

  private async predictSecurityIncidents(tenantId: string, buildingId?: string): Promise<IncidentPrediction[]> {
    // Implementation would predict security incidents
    return [];
  }

  private async predictCrowdIncidents(tenantId: string, buildingId?: string): Promise<IncidentPrediction[]> {
    // Implementation would predict crowd incidents
    return [];
  }

  private async predictEquipmentIncidents(tenantId: string, buildingId?: string): Promise<IncidentPrediction[]> {
    // Implementation would predict equipment incidents
    return [];
  }

  private async predictSafetyIncidents(tenantId: string, buildingId?: string): Promise<IncidentPrediction[]> {
    // Implementation would predict safety incidents
    return [];
  }
}