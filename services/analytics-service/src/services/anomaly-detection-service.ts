import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';
import { AnomalyScore } from '../types';

export class AnomalyDetectionService extends BaseAnalyticsService {
  private anomalyModels: Map<string, any> = new Map();

  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
    this.initializeModels();
  }

  private async initializeModels(): Promise<void> {
    // Initialize anomaly detection models
    // In production, these would be loaded from ML model storage
    this.anomalyModels.set('access_pattern', {
      type: 'statistical',
      threshold: 0.8
    });
    this.anomalyModels.set('behavior_pattern', {
      type: 'ml_based',
      threshold: 0.75
    });
  }

  async detectAnomalies(
    tenantId: string,
    entityType: 'user' | 'door' | 'camera' | 'zone',
    entityId: string,
    threshold: number = 0.8,
    timeWindow: number = 24
  ): Promise<AnomalyScore[]> {
    const cacheKey = `anomaly:${tenantId}:${entityType}:${entityId}:${timeWindow}`;
    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    try {
      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - timeWindow * 60 * 60 * 1000);

      // Get historical data
      const historicalData = await this.getHistoricalData(
        tenantId,
        entityType,
        entityId,
        startTime,
        endTime
      );

      // Calculate baseline behavior
      const baseline = await this.calculateBaseline(historicalData);

      // Detect anomalies
      const anomalies: AnomalyScore[] = [];
      for (const dataPoint of historicalData) {
        const score = await this.calculateAnomalyScore(dataPoint, baseline);
        
        if (score.score >= threshold) {
          const factors = await this.identifyAnomalyFactors(dataPoint, baseline);
          
          anomalies.push({
            entityId,
            entityType,
            score: score.score,
            factors,
            timestamp: dataPoint.timestamp,
            severity: this.calculateSeverity(score.score)
          });

          // Store anomaly for future analysis
          await this.storeAnomaly(tenantId, {
            ...score,
            entityId,
            entityType,
            factors,
            timestamp: dataPoint.timestamp
          });
        }
      }

      // Cache results
      await this.cache.set(cacheKey, anomalies, 300); // 5 minutes

      return anomalies;
    } catch (error) {
      this.logger.error('Anomaly detection failed', { error, entityType, entityId });
      throw error;
    }
  }

  private async getHistoricalData(
    tenantId: string,
    entityType: string,
    entityId: string,
    startTime: Date,
    endTime: Date
  ): Promise<any[]> {
    const query = {
      query: {
        bool: {
          must: [
            { term: { tenantId } },
            { term: { entityType } },
            { term: { entityId } },
            {
              range: {
                timestamp: {
                  gte: startTime.toISOString(),
                  lte: endTime.toISOString()
                }
              }
            }
          ]
        }
      },
      size: 10000,
      sort: [{ timestamp: { order: 'asc' } }]
    };

    return await this.queryOpenSearch(this.config.opensearchIndex, query);
  }

  private async calculateBaseline(historicalData: any[]): Promise<any> {
    if (historicalData.length === 0) {
      return {
        mean: 0,
        stdDev: 0,
        patterns: {}
      };
    }

    // Calculate statistical baseline
    const values = historicalData.map(d => d.value || 0);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    // Identify patterns (time of day, day of week, etc.)
    const patterns = this.identifyPatterns(historicalData);

    return {
      mean,
      stdDev,
      patterns,
      sampleSize: historicalData.length
    };
  }

  private identifyPatterns(data: any[]): any {
    const hourlyPatterns: { [key: number]: number[] } = {};
    const dailyPatterns: { [key: number]: number[] } = {};

    data.forEach(point => {
      const date = new Date(point.timestamp);
      const hour = date.getHours();
      const day = date.getDay();

      if (!hourlyPatterns[hour]) hourlyPatterns[hour] = [];
      if (!dailyPatterns[day]) dailyPatterns[day] = [];

      hourlyPatterns[hour].push(point.value || 0);
      dailyPatterns[day].push(point.value || 0);
    });

    return {
      hourly: Object.entries(hourlyPatterns).reduce((acc, [hour, values]) => {
        acc[hour] = values.reduce((a, b) => a + b, 0) / values.length;
        return acc;
      }, {} as any),
      daily: Object.entries(dailyPatterns).reduce((acc, [day, values]) => {
        acc[day] = values.reduce((a, b) => a + b, 0) / values.length;
        return acc;
      }, {} as any)
    };
  }

  private async calculateAnomalyScore(dataPoint: any, baseline: any): Promise<{ score: number }> {
    const value = dataPoint.value || 0;
    const { mean, stdDev } = baseline;

    if (stdDev === 0) {
      return { score: value !== mean ? 1 : 0 };
    }

    // Z-score calculation
    const zScore = Math.abs((value - mean) / stdDev);

    // Convert to 0-1 score
    const score = Math.min(1, zScore / 3); // 3 standard deviations = 1.0 score

    return { score };
  }

  private async identifyAnomalyFactors(dataPoint: any, baseline: any): Promise<string[]> {
    const factors: string[] = [];
    const value = dataPoint.value || 0;

    // Check if value is significantly different from mean
    if (Math.abs(value - baseline.mean) > 2 * baseline.stdDev) {
      factors.push('Significant deviation from average');
    }

    // Check time-based patterns
    const date = new Date(dataPoint.timestamp);
    const hour = date.getHours();
    const day = date.getDay();

    if (baseline.patterns.hourly[hour]) {
      const hourlyAvg = baseline.patterns.hourly[hour];
      if (Math.abs(value - hourlyAvg) > hourlyAvg * 0.5) {
        factors.push(`Unusual for this time of day (${hour}:00)`);
      }
    }

    if (baseline.patterns.daily[day]) {
      const dailyAvg = baseline.patterns.daily[day];
      if (Math.abs(value - dailyAvg) > dailyAvg * 0.5) {
        factors.push(`Unusual for ${['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][day]}`);
      }
    }

    // Add entity-specific factors
    if (dataPoint.metadata) {
      if (dataPoint.metadata.failedAttempts > 3) {
        factors.push('Multiple failed attempts');
      }
      if (dataPoint.metadata.unusualLocation) {
        factors.push('Access from unusual location');
      }
    }

    return factors;
  }

  private calculateSeverity(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 0.95) return 'critical';
    if (score >= 0.85) return 'high';
    if (score >= 0.7) return 'medium';
    return 'low';
  }

  private async storeAnomaly(tenantId: string, anomaly: any): Promise<void> {
    await this.storeInOpenSearch(`${this.config.opensearchIndex}-anomalies`, {
      ...anomaly,
      tenantId,
      detectedAt: new Date().toISOString()
    });

    // Broadcast anomaly detection
    await this.broadcastUpdate('anomaly-detected', {
      tenantId,
      anomaly
    });
  }
}