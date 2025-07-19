import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';
import { BehaviorEvent, CrowdAnalysis } from '../types';

export class BehaviorAnalyticsService extends BaseAnalyticsService {
  private behaviorProfiles: Map<string, any> = new Map();

  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
  }

  async processBehaviorEvent(
    tenantId: string,
    event: any
  ): Promise<BehaviorEvent> {
    const processedEvent: BehaviorEvent = {
      id: this.generateId(),
      cameraId: event.cameraId,
      tenantId,
      timestamp: new Date(event.timestamp),
      eventType: event.eventType,
      severity: event.severity,
      confidence: event.confidence,
      location: event.location,
      duration: event.duration,
      objectCount: event.objectCount,
      metadata: event.metadata
    };

    // Store event
    await this.storeInOpenSearch(`${this.config.opensearchIndex}-behavior`, {
      ...processedEvent,
      timestamp: processedEvent.timestamp.toISOString()
    });

    // Update behavior patterns
    await this.updateBehaviorPatterns(tenantId, event.cameraId, processedEvent);

    // Generate alerts based on severity
    if (processedEvent.severity === 'high' || processedEvent.severity === 'critical') {
      await this.generateBehaviorAlert(tenantId, processedEvent);
    }

    // Broadcast real-time update
    await this.broadcastUpdate('behavior-event', {
      tenantId,
      event: processedEvent
    });

    return processedEvent;
  }

  async performCrowdAnalysis(
    tenantId: string,
    cameraId: string,
    imageData: string
  ): Promise<CrowdAnalysis> {
    try {
      // In production, this would call ML API for crowd analysis
      const analysis = await this.analyzeCrowdMetrics(imageData);
      
      const crowdAnalysis: CrowdAnalysis = {
        cameraId,
        timestamp: new Date(),
        totalCount: analysis.count,
        density: analysis.density,
        averageSpeed: analysis.averageSpeed,
        flowDirection: analysis.flowDirection,
        hotspots: analysis.hotspots,
        riskLevel: this.calculateCrowdRiskLevel(analysis)
      };

      // Store analysis
      await this.storeInOpenSearch(`${this.config.opensearchIndex}-crowd`, {
        ...crowdAnalysis,
        tenantId,
        timestamp: crowdAnalysis.timestamp.toISOString()
      });

      // Generate alert if high risk
      if (crowdAnalysis.riskLevel === 'high' || crowdAnalysis.riskLevel === 'critical') {
        await this.generateCrowdAlert(tenantId, crowdAnalysis);
      }

      // Update real-time metrics
      await this.redis.hset(
        `crowd:realtime:${tenantId}`,
        cameraId,
        JSON.stringify({
          count: crowdAnalysis.totalCount,
          density: crowdAnalysis.density,
          riskLevel: crowdAnalysis.riskLevel,
          timestamp: crowdAnalysis.timestamp.toISOString()
        })
      );

      return crowdAnalysis;
    } catch (error) {
      this.logger.error('Crowd analysis failed', { error, tenantId, cameraId });
      throw error;
    }
  }

  private async updateBehaviorPatterns(
    tenantId: string,
    cameraId: string,
    event: BehaviorEvent
  ): Promise<void> {
    const profileKey = `${cameraId}:${event.eventType}`;
    const profile = this.behaviorProfiles.get(profileKey) || {
      totalEvents: 0,
      severityCounts: { low: 0, medium: 0, high: 0, critical: 0 },
      hourlyDistribution: new Array(24).fill(0),
      locations: new Map()
    };

    // Update profile
    profile.totalEvents++;
    profile.severityCounts[event.severity]++;
    profile.hourlyDistribution[new Date(event.timestamp).getHours()]++;
    
    const locationKey = `${event.location.x},${event.location.y}`;
    profile.locations.set(locationKey, (profile.locations.get(locationKey) || 0) + 1);

    this.behaviorProfiles.set(profileKey, profile);

    // Store profile periodically
    if (profile.totalEvents % 100 === 0) {
      await this.storeInOpenSearch(`${this.config.opensearchIndex}-behavior-profiles`, {
        tenantId,
        cameraId,
        eventType: event.eventType,
        profile: {
          ...profile,
          locations: Array.from(profile.locations.entries())
        },
        updatedAt: new Date().toISOString()
      });
    }
  }

  private async analyzeCrowdMetrics(imageData: string): Promise<any> {
    // Mock implementation - in production would call ML API
    return {
      count: Math.floor(Math.random() * 50) + 10,
      density: Math.random() * 0.8 + 0.1,
      averageSpeed: Math.random() * 2 + 0.5,
      flowDirection: {
        angle: Math.random() * 360,
        magnitude: Math.random()
      },
      hotspots: [
        {
          x: Math.random(),
          y: Math.random(),
          intensity: Math.random()
        }
      ]
    };
  }

  private calculateCrowdRiskLevel(analysis: any): 'low' | 'medium' | 'high' | 'critical' {
    const { count, density } = analysis;
    
    if (density > 0.9 || count > 100) return 'critical';
    if (density > 0.7 || count > 75) return 'high';
    if (density > 0.5 || count > 50) return 'medium';
    return 'low';
  }

  private async generateBehaviorAlert(
    tenantId: string,
    event: BehaviorEvent
  ): Promise<void> {
    const alertTitles: Record<string, string> = {
      loitering: 'Loitering Detected',
      crowd_formation: 'Crowd Formation Detected',
      unusual_direction: 'Unusual Movement Pattern',
      speed_violation: 'Speed Violation Detected',
      object_left: 'Unattended Object Detected',
      object_removed: 'Object Removal Detected'
    };

    const alert = {
      id: this.generateId(),
      type: 'behavior_analysis',
      severity: event.severity,
      title: alertTitles[event.eventType] || 'Behavior Alert',
      message: `${event.eventType.replace(/_/g, ' ')} detected at camera ${event.cameraId}`,
      tenantId,
      entityId: event.cameraId,
      entityType: 'camera',
      data: event,
      timestamp: new Date()
    };

    await this.storeInOpenSearch(`${this.config.opensearchIndex}-alerts`, {
      ...alert,
      timestamp: alert.timestamp.toISOString()
    });

    await this.broadcastUpdate('behavior-alert', alert);
  }

  private async generateCrowdAlert(
    tenantId: string,
    analysis: CrowdAnalysis
  ): Promise<void> {
    const alert = {
      id: this.generateId(),
      type: 'crowd_analysis',
      severity: analysis.riskLevel,
      title: 'High Crowd Density Detected',
      message: `Camera ${analysis.cameraId} detecting ${analysis.totalCount} people with ${(analysis.density * 100).toFixed(0)}% density`,
      tenantId,
      entityId: analysis.cameraId,
      entityType: 'camera',
      data: analysis,
      timestamp: new Date(),
      recommendedActions: [
        'Monitor situation closely',
        'Consider crowd control measures',
        'Alert security personnel',
        'Prepare evacuation routes if needed'
      ]
    };

    await this.storeInOpenSearch(`${this.config.opensearchIndex}-alerts`, {
      ...alert,
      timestamp: alert.timestamp.toISOString()
    });

    await this.broadcastUpdate('crowd-alert', alert);
  }
}