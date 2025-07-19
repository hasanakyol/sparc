import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { Client } from '@opensearch-project/opensearch';
import Redis from 'ioredis';
import { PrismaClient } from '@sparc/shared/prisma';
import { z } from 'zod';
import { createLogger, format, transports } from 'winston';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { createHealthCheckHandler } from '@sparc/shared/utils/health-check';
import { CacheService } from '@sparc/shared/utils/cache';
import { cacheMiddleware, cacheInvalidationMiddleware } from '@sparc/shared/middleware/cache';

// Types and schemas
const AnalyticsQuerySchema = z.object({
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  tenantId: z.string().uuid(),
  siteId: z.string().uuid().optional(),
  buildingId: z.string().uuid().optional(),
  floorId: z.string().uuid().optional(),
  eventTypes: z.array(z.string()).optional(),
  limit: z.number().min(1).max(1000).default(100),
  offset: z.number().min(0).default(0)
});

const AnomalyDetectionSchema = z.object({
  tenantId: z.string().uuid(),
  entityType: z.enum(['user', 'door', 'camera', 'zone']),
  entityId: z.string().uuid(),
  threshold: z.number().min(0).max(1).default(0.8),
  timeWindow: z.number().min(1).max(168).default(24) // hours
});

const OccupancyQuerySchema = z.object({
  tenantId: z.string().uuid(),
  buildingId: z.string().uuid().optional(),
  floorId: z.string().uuid().optional(),
  zoneId: z.string().uuid().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  granularity: z.enum(['minute', 'hour', 'day']).default('hour')
});

// Advanced Video Analytics Schemas
const VideoAnalyticsConfigSchema = z.object({
  cameraId: z.string().uuid(),
  faceRecognition: z.object({
    enabled: z.boolean().default(false),
    confidence: z.number().min(0).max(1).default(0.8),
    enrollmentMode: z.boolean().default(false),
    watchlistEnabled: z.boolean().default(false)
  }).default({}),
  licensePlateRecognition: z.object({
    enabled: z.boolean().default(false),
    confidence: z.number().min(0).max(1).default(0.85),
    regions: z.array(z.string()).default(['US', 'EU']),
    watchlistEnabled: z.boolean().default(false)
  }).default({}),
  behaviorAnalysis: z.object({
    loiteringDetection: z.boolean().default(false),
    loiteringThreshold: z.number().min(30).max(3600).default(300), // seconds
    crowdAnalysis: z.boolean().default(false),
    crowdThreshold: z.number().min(5).max(100).default(10),
    directionAnalysis: z.boolean().default(false),
    speedAnalysis: z.boolean().default(false)
  }).default({}),
  zones: z.array(z.object({
    id: z.string().uuid(),
    name: z.string(),
    coordinates: z.array(z.object({
      x: z.number().min(0).max(1),
      y: z.number().min(0).max(1)
    })),
    type: z.enum(['detection', 'exclusion', 'counting']),
    analytics: z.array(z.string()).default([])
  })).default([])
});

const FaceRecognitionEventSchema = z.object({
  cameraId: z.string().uuid(),
  timestamp: z.string().datetime(),
  personId: z.string().uuid().optional(),
  confidence: z.number().min(0).max(1),
  boundingBox: z.object({
    x: z.number(),
    y: z.number(),
    width: z.number(),
    height: z.number()
  }),
  features: z.array(z.number()).optional(),
  isWatchlisted: z.boolean().default(false),
  metadata: z.record(z.any()).optional()
});

const LicensePlateEventSchema = z.object({
  cameraId: z.string().uuid(),
  timestamp: z.string().datetime(),
  plateNumber: z.string(),
  confidence: z.number().min(0).max(1),
  region: z.string(),
  boundingBox: z.object({
    x: z.number(),
    y: z.number(),
    width: z.number(),
    height: z.number()
  }),
  vehicleType: z.string().optional(),
  isWatchlisted: z.boolean().default(false),
  metadata: z.record(z.any()).optional()
});

const BehaviorEventSchema = z.object({
  cameraId: z.string().uuid(),
  timestamp: z.string().datetime(),
  eventType: z.enum(['loitering', 'crowd_formation', 'unusual_direction', 'speed_violation', 'object_left', 'object_removed']),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  confidence: z.number().min(0).max(1),
  location: z.object({
    x: z.number(),
    y: z.number()
  }),
  duration: z.number().optional(),
  objectCount: z.number().optional(),
  metadata: z.record(z.any()).optional()
});

interface AccessPattern {
  userId: string;
  doorId: string;
  timestamp: Date;
  granted: boolean;
  location: {
    building: string;
    floor: string;
    zone: string;
  };
}

interface AnomalyScore {
  entityId: string;
  entityType: string;
  score: number;
  factors: string[];
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface OccupancyData {
  location: {
    buildingId: string;
    floorId?: string;
    zoneId?: string;
  };
  timestamp: Date;
  count: number;
  capacity: number;
  utilizationRate: number;
}

interface PredictiveAlert {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  entityId: string;
  entityType: string;
  probability: number;
  factors: string[];
  recommendedActions: string[];
  timestamp: Date;
}

// Advanced Video Analytics Interfaces
interface FaceRecognitionEvent {
  id: string;
  cameraId: string;
  tenantId: string;
  timestamp: Date;
  personId?: string;
  confidence: number;
  boundingBox: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  features?: number[];
  isWatchlisted: boolean;
  metadata?: Record<string, any>;
}

interface LicensePlateEvent {
  id: string;
  cameraId: string;
  tenantId: string;
  timestamp: Date;
  plateNumber: string;
  confidence: number;
  region: string;
  boundingBox: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  vehicleType?: string;
  isWatchlisted: boolean;
  metadata?: Record<string, any>;
}

interface BehaviorEvent {
  id: string;
  cameraId: string;
  tenantId: string;
  timestamp: Date;
  eventType: 'loitering' | 'crowd_formation' | 'unusual_direction' | 'speed_violation' | 'object_left' | 'object_removed';
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  location: {
    x: number;
    y: number;
  };
  duration?: number;
  objectCount?: number;
  metadata?: Record<string, any>;
}

interface VideoAnalyticsConfig {
  cameraId: string;
  faceRecognition: {
    enabled: boolean;
    confidence: number;
    enrollmentMode: boolean;
    watchlistEnabled: boolean;
  };
  licensePlateRecognition: {
    enabled: boolean;
    confidence: number;
    regions: string[];
    watchlistEnabled: boolean;
  };
  behaviorAnalysis: {
    loiteringDetection: boolean;
    loiteringThreshold: number;
    crowdAnalysis: boolean;
    crowdThreshold: number;
    directionAnalysis: boolean;
    speedAnalysis: boolean;
  };
  zones: Array<{
    id: string;
    name: string;
    coordinates: Array<{ x: number; y: number }>;
    type: 'detection' | 'exclusion' | 'counting';
    analytics: string[];
  }>;
}

interface MLModelConfig {
  modelId: string;
  modelType: 'face_recognition' | 'license_plate' | 'behavior_analysis' | 'object_detection';
  version: string;
  endpoint: string;
  apiKey?: string;
  confidence: number;
  enabled: boolean;
}

interface CrowdAnalysis {
  cameraId: string;
  timestamp: Date;
  totalCount: number;
  density: number;
  averageSpeed: number;
  flowDirection: {
    angle: number;
    magnitude: number;
  };
  hotspots: Array<{
    x: number;
    y: number;
    intensity: number;
  }>;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

interface IncidentPrediction {
  id: string;
  type: 'security_breach' | 'crowd_incident' | 'equipment_failure' | 'safety_violation';
  probability: number;
  timeToIncident: number; // minutes
  location: {
    buildingId: string;
    floorId?: string;
    zoneId?: string;
    cameraId?: string;
  };
  factors: string[];
  recommendedActions: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
}

// Initialize services
const app = new Hono();
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const cache = new CacheService(redis, {
  prefix: 'analytics',
  ttl: 300 // 5 minutes default
});

const opensearch = new Client({
  node: process.env.OPENSEARCH_URL || 'https://localhost:9200',
  auth: {
    username: process.env.OPENSEARCH_USERNAME || 'admin',
    password: process.env.OPENSEARCH_PASSWORD || 'admin'
  },
  ssl: {
    rejectUnauthorized: false
  }
});

const analyticsLogger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'analytics-error.log', level: 'error' }),
    new transports.File({ filename: 'analytics-combined.log' })
  ]
});

// Machine Learning and Analytics Engine
class AnalyticsEngine {
  private anomalyModels: Map<string, any> = new Map();
  private behaviorProfiles: Map<string, any> = new Map();
  private mlModels: Map<string, MLModelConfig> = new Map();
  private videoAnalyticsConfigs: Map<string, VideoAnalyticsConfig> = new Map();
  private faceDatabase: Map<string, { personId: string; features: number[]; metadata: any }> = new Map();
  private licensePlateWatchlist: Set<string> = new Set();
  private faceWatchlist: Set<string> = new Set();

  async detectAnomalies(tenantId: string, entityType: string, entityId: string, threshold: number = 0.8): Promise<AnomalyScore> {
    try {
      // Get historical data for the entity
      const historicalData = await this.getHistoricalData(tenantId, entityType, entityId);
      
      // Calculate baseline behavior patterns
      const baseline = await this.calculateBaseline(historicalData);
      
      // Get recent activity
      const recentActivity = await this.getRecentActivity(tenantId, entityType, entityId);
      
      // Calculate anomaly score using statistical analysis
      const score = await this.calculateAnomalyScore(baseline, recentActivity);
      
      // Determine severity based on score and threshold
      const severity = this.determineSeverity(score, threshold);
      
      // Identify contributing factors
      const factors = await this.identifyAnomalyFactors(baseline, recentActivity);

      const anomaly: AnomalyScore = {
        entityId,
        entityType,
        score,
        factors,
        timestamp: new Date(),
        severity
      };

      // Store anomaly in OpenSearch for further analysis
      await this.storeAnomaly(tenantId, anomaly);

      return anomaly;
    } catch (error) {
      analyticsLogger.error('Anomaly detection failed', { error, tenantId, entityType, entityId });
      throw error;
    }
  }

  async trackOccupancy(tenantId: string, buildingId?: string, floorId?: string, zoneId?: string): Promise<OccupancyData[]> {
    try {
      const query = {
        index: `access-events-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { term: { granted: true } },
                { range: { timestamp: { gte: 'now-24h' } } }
              ],
              ...(buildingId && { filter: [{ term: { buildingId } }] }),
              ...(floorId && { filter: [{ term: { floorId } }] }),
              ...(zoneId && { filter: [{ term: { zoneId } }] })
            }
          },
          aggs: {
            occupancy_over_time: {
              date_histogram: {
                field: 'timestamp',
                interval: '1h'
              },
              aggs: {
                entries: {
                  filter: { term: { eventType: 'entry' } }
                },
                exits: {
                  filter: { term: { eventType: 'exit' } }
                },
                net_occupancy: {
                  bucket_script: {
                    buckets_path: {
                      entries: 'entries>_count',
                      exits: 'exits>_count'
                    },
                    script: 'params.entries - params.exits'
                  }
                }
              }
            }
          }
        }
      };

      const response = await opensearch.search(query);
      
      // Process aggregation results into occupancy data
      const occupancyData = await this.processOccupancyResults(response.body.aggregations, tenantId, buildingId, floorId, zoneId);
      
      return occupancyData;
    } catch (error) {
      analyticsLogger.error('Occupancy tracking failed', { error, tenantId, buildingId, floorId, zoneId });
      throw error;
    }
  }

  async generatePredictiveAlerts(tenantId: string): Promise<PredictiveAlert[]> {
    try {
      const alerts: PredictiveAlert[] = [];

      // Analyze access patterns for potential security risks
      const accessAnomalies = await this.analyzeAccessPatterns(tenantId);
      alerts.push(...accessAnomalies);

      // Analyze occupancy trends for capacity planning
      const occupancyAlerts = await this.analyzeOccupancyTrends(tenantId);
      alerts.push(...occupancyAlerts);

      // Analyze device health for maintenance predictions
      const deviceAlerts = await this.analyzeDeviceHealth(tenantId);
      alerts.push(...deviceAlerts);

      // Analyze behavioral patterns for security threats
      const behaviorAlerts = await this.analyzeBehaviorPatterns(tenantId);
      alerts.push(...behaviorAlerts);

      // Store alerts in Redis for real-time access
      await this.storePredictiveAlerts(tenantId, alerts);

      return alerts;
    } catch (error) {
      analyticsLogger.error('Predictive alert generation failed', { error, tenantId });
      throw error;
    }
  }

  private async getHistoricalData(tenantId: string, entityType: string, entityId: string): Promise<any[]> {
    const query = {
      index: `access-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              { term: { [`${entityType}Id`]: entityId } },
              { range: { timestamp: { gte: 'now-30d' } } }
            ]
          }
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: 10000
      }
    };

    const response = await opensearch.search(query);
    return response.body.hits.hits.map((hit: any) => hit._source);
  }

  private async calculateBaseline(historicalData: any[]): Promise<any> {
    // Calculate statistical baseline from historical data
    const hourlyPatterns = new Map<number, number[]>();
    const dailyPatterns = new Map<number, number[]>();
    const locationPatterns = new Map<string, number>();

    historicalData.forEach(event => {
      const date = new Date(event.timestamp);
      const hour = date.getHours();
      const day = date.getDay();
      const location = `${event.buildingId}-${event.floorId}-${event.zoneId}`;

      if (!hourlyPatterns.has(hour)) hourlyPatterns.set(hour, []);
      if (!dailyPatterns.has(day)) dailyPatterns.set(day, []);

      hourlyPatterns.get(hour)!.push(1);
      dailyPatterns.get(day)!.push(1);
      locationPatterns.set(location, (locationPatterns.get(location) || 0) + 1);
    });

    return {
      hourlyPatterns: this.calculateStatistics(hourlyPatterns),
      dailyPatterns: this.calculateStatistics(dailyPatterns),
      locationPatterns,
      totalEvents: historicalData.length,
      avgEventsPerDay: historicalData.length / 30
    };
  }

  private calculateStatistics(patterns: Map<number, number[]>): Map<number, { mean: number; std: number; count: number }> {
    const stats = new Map();
    
    patterns.forEach((values, key) => {
      const mean = values.reduce((sum, val) => sum + val, 0) / values.length;
      const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
      const std = Math.sqrt(variance);
      
      stats.set(key, { mean, std, count: values.length });
    });

    return stats;
  }

  private async getRecentActivity(tenantId: string, entityType: string, entityId: string): Promise<any[]> {
    const query = {
      index: `access-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              { term: { [`${entityType}Id`]: entityId } },
              { range: { timestamp: { gte: 'now-24h' } } }
            ]
          }
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: 1000
      }
    };

    const response = await opensearch.search(query);
    return response.body.hits.hits.map((hit: any) => hit._source);
  }

  private async calculateAnomalyScore(baseline: any, recentActivity: any[]): Promise<number> {
    let anomalyScore = 0;
    let factors = 0;

    // Check hourly pattern deviation
    const currentHour = new Date().getHours();
    const recentHourlyActivity = recentActivity.filter(event => 
      new Date(event.timestamp).getHours() === currentHour
    ).length;

    const expectedHourly = baseline.hourlyPatterns.get(currentHour)?.mean || 0;
    const hourlyDeviation = Math.abs(recentHourlyActivity - expectedHourly) / (expectedHourly + 1);
    anomalyScore += hourlyDeviation * 0.3;
    factors++;

    // Check location pattern deviation
    const recentLocations = new Map<string, number>();
    recentActivity.forEach(event => {
      const location = `${event.buildingId}-${event.floorId}-${event.zoneId}`;
      recentLocations.set(location, (recentLocations.get(location) || 0) + 1);
    });

    let locationAnomalyScore = 0;
    recentLocations.forEach((count, location) => {
      const expected = baseline.locationPatterns.get(location) || 0;
      const deviation = Math.abs(count - expected) / (expected + 1);
      locationAnomalyScore += deviation;
    });
    anomalyScore += (locationAnomalyScore / recentLocations.size) * 0.4;
    factors++;

    // Check frequency deviation
    const recentFrequency = recentActivity.length;
    const expectedFrequency = baseline.avgEventsPerDay / 24;
    const frequencyDeviation = Math.abs(recentFrequency - expectedFrequency) / (expectedFrequency + 1);
    anomalyScore += frequencyDeviation * 0.3;
    factors++;

    return Math.min(anomalyScore / factors, 1.0);
  }

  private determineSeverity(score: number, threshold: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score < threshold * 0.5) return 'low';
    if (score < threshold) return 'medium';
    if (score < threshold * 1.5) return 'high';
    return 'critical';
  }

  private async identifyAnomalyFactors(baseline: any, recentActivity: any[]): Promise<string[]> {
    const factors: string[] = [];

    // Check for unusual time patterns
    const currentHour = new Date().getHours();
    const recentHourlyActivity = recentActivity.filter(event => 
      new Date(event.timestamp).getHours() === currentHour
    ).length;
    const expectedHourly = baseline.hourlyPatterns.get(currentHour)?.mean || 0;
    
    if (recentHourlyActivity > expectedHourly * 2) {
      factors.push('Unusual high activity for current time');
    } else if (recentHourlyActivity < expectedHourly * 0.5 && expectedHourly > 0) {
      factors.push('Unusual low activity for current time');
    }

    // Check for new locations
    const recentLocations = new Set(recentActivity.map(event => 
      `${event.buildingId}-${event.floorId}-${event.zoneId}`
    ));
    const baselineLocations = new Set(baseline.locationPatterns.keys());
    
    recentLocations.forEach(location => {
      if (!baselineLocations.has(location)) {
        factors.push('Access to new/unusual location');
      }
    });

    // Check for rapid successive access attempts
    const sortedActivity = recentActivity.sort((a, b) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
    
    for (let i = 1; i < sortedActivity.length; i++) {
      const timeDiff = new Date(sortedActivity[i].timestamp).getTime() - 
                      new Date(sortedActivity[i-1].timestamp).getTime();
      if (timeDiff < 30000) { // Less than 30 seconds
        factors.push('Rapid successive access attempts');
        break;
      }
    }

    return factors;
  }

  private async storeAnomaly(tenantId: string, anomaly: AnomalyScore): Promise<void> {
    await opensearch.index({
      index: `anomalies-${tenantId}`,
      body: {
        ...anomaly,
        tenantId,
        '@timestamp': new Date().toISOString()
      }
    });
  }

  private async processOccupancyResults(aggregations: any, tenantId: string, buildingId?: string, floorId?: string, zoneId?: string): Promise<OccupancyData[]> {
    const buckets = aggregations.occupancy_over_time.buckets;
    const occupancyData: OccupancyData[] = [];

    // Get capacity information from database
    const capacity = await this.getLocationCapacity(tenantId, buildingId, floorId, zoneId);

    let runningOccupancy = 0;

    buckets.forEach((bucket: any) => {
      runningOccupancy += bucket.net_occupancy.value || 0;
      runningOccupancy = Math.max(0, runningOccupancy); // Ensure non-negative

      occupancyData.push({
        location: {
          buildingId: buildingId || 'all',
          floorId,
          zoneId
        },
        timestamp: new Date(bucket.key),
        count: runningOccupancy,
        capacity,
        utilizationRate: capacity > 0 ? runningOccupancy / capacity : 0
      });
    });

    return occupancyData;
  }

  private async getLocationCapacity(tenantId: string, buildingId?: string, floorId?: string, zoneId?: string): Promise<number> {
    try {
      if (zoneId) {
        const zone = await prisma.zone.findFirst({
          where: { id: zoneId, tenantId }
        });
        return zone?.capacity || 50; // Default zone capacity
      }

      if (floorId) {
        const floor = await prisma.floor.findFirst({
          where: { id: floorId, tenantId },
          include: { zones: true }
        });
        return floor?.zones.reduce((sum, zone) => sum + (zone.capacity || 50), 0) || 200;
      }

      if (buildingId) {
        const building = await prisma.building.findFirst({
          where: { id: buildingId, tenantId },
          include: { floors: { include: { zones: true } } }
        });
        return building?.floors.reduce((sum, floor) => 
          sum + floor.zones.reduce((zoneSum, zone) => zoneSum + (zone.capacity || 50), 0), 0
        ) || 1000;
      }

      // Default tenant capacity
      return 5000;
    } catch (error) {
      analyticsLogger.error('Failed to get location capacity', { error, tenantId, buildingId, floorId, zoneId });
      return 100; // Fallback capacity
    }
  }

  private async analyzeAccessPatterns(tenantId: string): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    // Analyze for potential tailgating
    const tailgatingQuery = {
      index: `access-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              { range: { timestamp: { gte: 'now-1h' } } }
            ]
          }
        },
        aggs: {
          doors: {
            terms: { field: 'doorId' },
            aggs: {
              rapid_access: {
                filter: {
                  range: { timestamp: { gte: 'now-5m' } }
                }
              }
            }
          }
        }
      }
    };

    const response = await opensearch.search(tailgatingQuery);
    
    response.body.aggregations.doors.buckets.forEach((bucket: any) => {
      if (bucket.rapid_access.doc_count > 5) {
        alerts.push({
          id: `tailgating-${bucket.key}-${Date.now()}`,
          type: 'potential_tailgating',
          severity: 'medium',
          message: `Potential tailgating detected at door ${bucket.key}`,
          entityId: bucket.key,
          entityType: 'door',
          probability: 0.7,
          factors: ['Multiple rapid access attempts', 'Short time window'],
          recommendedActions: ['Review video footage', 'Increase security presence'],
          timestamp: new Date()
        });
      }
    });

    return alerts;
  }

  private async analyzeOccupancyTrends(tenantId: string): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    // Get current occupancy levels
    const occupancyData = await this.trackOccupancy(tenantId);
    
    occupancyData.forEach(data => {
      if (data.utilizationRate > 0.9) {
        alerts.push({
          id: `capacity-${data.location.buildingId}-${Date.now()}`,
          type: 'capacity_warning',
          severity: 'high',
          message: `Building approaching capacity limit`,
          entityId: data.location.buildingId,
          entityType: 'building',
          probability: 0.9,
          factors: ['High utilization rate', 'Limited remaining capacity'],
          recommendedActions: ['Monitor entry points', 'Prepare overflow procedures'],
          timestamp: new Date()
        });
      }
    });

    return alerts;
  }

  private async analyzeDeviceHealth(tenantId: string): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    // Analyze device failure patterns
    const devices = await prisma.accessPanel.findMany({
      where: { tenantId },
      include: { doors: true }
    });

    for (const device of devices) {
      // Check for increasing error rates
      const errorQuery = {
        index: `device-events-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { deviceId: device.id } },
                { term: { eventType: 'error' } },
                { range: { timestamp: { gte: 'now-24h' } } }
              ]
            }
          }
        }
      };

      const errorResponse = await opensearch.search(errorQuery);
      const errorCount = errorResponse.body.hits.total.value;

      if (errorCount > 10) {
        alerts.push({
          id: `device-health-${device.id}-${Date.now()}`,
          type: 'device_degradation',
          severity: 'medium',
          message: `Device showing signs of degradation`,
          entityId: device.id,
          entityType: 'device',
          probability: 0.6,
          factors: ['Increasing error rate', 'Performance degradation'],
          recommendedActions: ['Schedule maintenance', 'Monitor closely'],
          timestamp: new Date()
        });
      }
    }

    return alerts;
  }

  private async analyzeBehaviorPatterns(tenantId: string): Promise<PredictiveAlert[]> {
    const alerts: PredictiveAlert[] = [];

    // Analyze for unusual user behavior
    const users = await prisma.user.findMany({
      where: { tenantId },
      take: 100 // Limit for performance
    });

    for (const user of users) {
      const anomaly = await this.detectAnomalies(tenantId, 'user', user.id, 0.7);
      
      if (anomaly.severity === 'high' || anomaly.severity === 'critical') {
        alerts.push({
          id: `behavior-${user.id}-${Date.now()}`,
          type: 'unusual_behavior',
          severity: anomaly.severity,
          message: `Unusual behavior pattern detected for user ${user.email}`,
          entityId: user.id,
          entityType: 'user',
          probability: anomaly.score,
          factors: anomaly.factors,
          recommendedActions: ['Review user activity', 'Contact user for verification'],
          timestamp: new Date()
        });
      }
    }

    return alerts;
  }

  private async storePredictiveAlerts(tenantId: string, alerts: PredictiveAlert[]): Promise<void> {
    const pipeline = redis.pipeline();
    
    alerts.forEach(alert => {
      pipeline.setex(`alert:${tenantId}:${alert.id}`, 3600, JSON.stringify(alert));
    });
    
    await pipeline.exec();
  }

  // Advanced Video Analytics Methods
  async configureVideoAnalytics(tenantId: string, config: VideoAnalyticsConfig): Promise<void> {
    try {
      // Validate camera exists and belongs to tenant
      const camera = await prisma.camera.findFirst({
        where: { id: config.cameraId, tenantId }
      });

      if (!camera) {
        throw new Error('Camera not found or access denied');
      }

      // Store configuration
      this.videoAnalyticsConfigs.set(config.cameraId, config);

      // Store in database
      await prisma.videoAnalyticsConfig.upsert({
        where: { cameraId: config.cameraId },
        update: {
          faceRecognition: config.faceRecognition,
          licensePlateRecognition: config.licensePlateRecognition,
          behaviorAnalysis: config.behaviorAnalysis,
          zones: config.zones
        },
        create: {
          cameraId: config.cameraId,
          tenantId,
          faceRecognition: config.faceRecognition,
          licensePlateRecognition: config.licensePlateRecognition,
          behaviorAnalysis: config.behaviorAnalysis,
          zones: config.zones
        }
      });

      // Initialize ML models if needed
      await this.initializeMLModels(config);

      analyticsLogger.info('Video analytics configured', { cameraId: config.cameraId, tenantId });
    } catch (error) {
      analyticsLogger.error('Failed to configure video analytics', { error, tenantId, cameraId: config.cameraId });
      throw error;
    }
  }

  async processFaceRecognitionEvent(tenantId: string, event: FaceRecognitionEvent): Promise<void> {
    try {
      // Check if face recognition is enabled for this camera
      const config = this.videoAnalyticsConfigs.get(event.cameraId);
      if (!config?.faceRecognition.enabled) {
        return;
      }

      // Perform face matching if features are provided
      if (event.features) {
        const matchResult = await this.matchFace(event.features, config.faceRecognition.confidence);
        if (matchResult) {
          event.personId = matchResult.personId;
          event.isWatchlisted = this.faceWatchlist.has(matchResult.personId);
        }
      }

      // Store event in OpenSearch
      await opensearch.index({
        index: `face-recognition-${tenantId}`,
        body: {
          ...event,
          tenantId,
          '@timestamp': event.timestamp
        }
      });

      // Generate alerts for watchlisted individuals
      if (event.isWatchlisted) {
        await this.generateFaceRecognitionAlert(tenantId, event);
      }

      // Update person tracking
      if (event.personId) {
        await this.updatePersonTracking(tenantId, event);
      }

      analyticsLogger.info('Face recognition event processed', { 
        cameraId: event.cameraId, 
        personId: event.personId,
        isWatchlisted: event.isWatchlisted 
      });
    } catch (error) {
      analyticsLogger.error('Failed to process face recognition event', { error, event });
      throw error;
    }
  }

  async processLicensePlateEvent(tenantId: string, event: LicensePlateEvent): Promise<void> {
    try {
      // Check if license plate recognition is enabled for this camera
      const config = this.videoAnalyticsConfigs.get(event.cameraId);
      if (!config?.licensePlateRecognition.enabled) {
        return;
      }

      // Check against watchlist
      event.isWatchlisted = this.licensePlateWatchlist.has(event.plateNumber);

      // Store event in OpenSearch
      await opensearch.index({
        index: `license-plate-${tenantId}`,
        body: {
          ...event,
          tenantId,
          '@timestamp': event.timestamp
        }
      });

      // Generate alerts for watchlisted plates
      if (event.isWatchlisted) {
        await this.generateLicensePlateAlert(tenantId, event);
      }

      // Correlate with access control events
      await this.correlateLicensePlateWithAccess(tenantId, event);

      analyticsLogger.info('License plate event processed', { 
        cameraId: event.cameraId, 
        plateNumber: event.plateNumber,
        isWatchlisted: event.isWatchlisted 
      });
    } catch (error) {
      analyticsLogger.error('Failed to process license plate event', { error, event });
      throw error;
    }
  }

  async processBehaviorEvent(tenantId: string, event: BehaviorEvent): Promise<void> {
    try {
      // Check if behavior analysis is enabled for this camera
      const config = this.videoAnalyticsConfigs.get(event.cameraId);
      if (!config?.behaviorAnalysis) {
        return;
      }

      // Validate event type is enabled
      const isEnabled = this.isBehaviorAnalysisEnabled(config, event.eventType);
      if (!isEnabled) {
        return;
      }

      // Store event in OpenSearch
      await opensearch.index({
        index: `behavior-events-${tenantId}`,
        body: {
          ...event,
          tenantId,
          '@timestamp': event.timestamp
        }
      });

      // Generate alerts based on severity
      if (event.severity === 'high' || event.severity === 'critical') {
        await this.generateBehaviorAlert(tenantId, event);
      }

      // Update behavior patterns
      await this.updateBehaviorPatterns(tenantId, event);

      analyticsLogger.info('Behavior event processed', { 
        cameraId: event.cameraId, 
        eventType: event.eventType,
        severity: event.severity 
      });
    } catch (error) {
      analyticsLogger.error('Failed to process behavior event', { error, event });
      throw error;
    }
  }

  async performCrowdAnalysis(tenantId: string, cameraId: string): Promise<CrowdAnalysis> {
    try {
      const config = this.videoAnalyticsConfigs.get(cameraId);
      if (!config?.behaviorAnalysis.crowdAnalysis) {
        throw new Error('Crowd analysis not enabled for this camera');
      }

      // Get recent person detection events
      const recentEvents = await this.getRecentPersonDetections(tenantId, cameraId, 300); // Last 5 minutes

      // Analyze crowd density and movement
      const analysis = await this.analyzeCrowdMetrics(recentEvents, config);

      // Store analysis results
      await opensearch.index({
        index: `crowd-analysis-${tenantId}`,
        body: {
          ...analysis,
          tenantId,
          '@timestamp': new Date().toISOString()
        }
      });

      // Generate alerts if risk level is high
      if (analysis.riskLevel === 'high' || analysis.riskLevel === 'critical') {
        await this.generateCrowdAlert(tenantId, analysis);
      }

      return analysis;
    } catch (error) {
      analyticsLogger.error('Crowd analysis failed', { error, tenantId, cameraId });
      throw error;
    }
  }

  async generateIncidentPredictions(tenantId: string): Promise<IncidentPrediction[]> {
    try {
      const predictions: IncidentPrediction[] = [];

      // Analyze patterns for security breach prediction
      const securityPredictions = await this.predictSecurityBreaches(tenantId);
      predictions.push(...securityPredictions);

      // Analyze crowd patterns for incident prediction
      const crowdPredictions = await this.predictCrowdIncidents(tenantId);
      predictions.push(...crowdPredictions);

      // Analyze equipment patterns for failure prediction
      const equipmentPredictions = await this.predictEquipmentFailures(tenantId);
      predictions.push(...equipmentPredictions);

      // Analyze safety patterns for violation prediction
      const safetyPredictions = await this.predictSafetyViolations(tenantId);
      predictions.push(...safetyPredictions);

      // Store predictions
      for (const prediction of predictions) {
        await opensearch.index({
          index: `incident-predictions-${tenantId}`,
          body: {
            ...prediction,
            tenantId,
            '@timestamp': prediction.timestamp.toISOString()
          }
        });
      }

      return predictions;
    } catch (error) {
      analyticsLogger.error('Incident prediction failed', { error, tenantId });
      throw error;
    }
  }

  async enrollFace(tenantId: string, personId: string, features: number[], metadata: any = {}): Promise<void> {
    try {
      // Store face features in database
      await prisma.faceEnrollment.create({
        data: {
          personId,
          tenantId,
          features,
          metadata,
          enrolledAt: new Date()
        }
      });

      // Update in-memory database
      this.faceDatabase.set(`${tenantId}:${personId}`, {
        personId,
        features,
        metadata
      });

      analyticsLogger.info('Face enrolled', { tenantId, personId });
    } catch (error) {
      analyticsLogger.error('Face enrollment failed', { error, tenantId, personId });
      throw error;
    }
  }

  async updateWatchlists(tenantId: string, type: 'face' | 'license_plate', items: string[]): Promise<void> {
    try {
      if (type === 'face') {
        // Update face watchlist
        this.faceWatchlist.clear();
        items.forEach(personId => this.faceWatchlist.add(personId));
        
        await prisma.faceWatchlist.deleteMany({ where: { tenantId } });
        await prisma.faceWatchlist.createMany({
          data: items.map(personId => ({ tenantId, personId }))
        });
      } else {
        // Update license plate watchlist
        this.licensePlateWatchlist.clear();
        items.forEach(plate => this.licensePlateWatchlist.add(plate));
        
        await prisma.licensePlateWatchlist.deleteMany({ where: { tenantId } });
        await prisma.licensePlateWatchlist.createMany({
          data: items.map(plateNumber => ({ tenantId, plateNumber }))
        });
      }

      analyticsLogger.info('Watchlist updated', { tenantId, type, count: items.length });
    } catch (error) {
      analyticsLogger.error('Watchlist update failed', { error, tenantId, type });
      throw error;
    }
  }

  // Private helper methods for advanced video analytics
  private async initializeMLModels(config: VideoAnalyticsConfig): Promise<void> {
    try {
      // Initialize face recognition model
      if (config.faceRecognition.enabled) {
        const faceModel: MLModelConfig = {
          modelId: `face-recognition-${config.cameraId}`,
          modelType: 'face_recognition',
          version: '1.0',
          endpoint: process.env.FACE_RECOGNITION_ENDPOINT || 'http://localhost:8001/face-recognition',
          confidence: config.faceRecognition.confidence,
          enabled: true
        };
        this.mlModels.set(faceModel.modelId, faceModel);
      }

      // Initialize license plate recognition model
      if (config.licensePlateRecognition.enabled) {
        const lprModel: MLModelConfig = {
          modelId: `lpr-${config.cameraId}`,
          modelType: 'license_plate',
          version: '1.0',
          endpoint: process.env.LPR_ENDPOINT || 'http://localhost:8002/license-plate',
          confidence: config.licensePlateRecognition.confidence,
          enabled: true
        };
        this.mlModels.set(lprModel.modelId, lprModel);
      }

      // Initialize behavior analysis model
      if (config.behaviorAnalysis.loiteringDetection || config.behaviorAnalysis.crowdAnalysis) {
        const behaviorModel: MLModelConfig = {
          modelId: `behavior-${config.cameraId}`,
          modelType: 'behavior_analysis',
          version: '1.0',
          endpoint: process.env.BEHAVIOR_ANALYSIS_ENDPOINT || 'http://localhost:8003/behavior',
          confidence: 0.7,
          enabled: true
        };
        this.mlModels.set(behaviorModel.modelId, behaviorModel);
      }
    } catch (error) {
      analyticsLogger.error('ML model initialization failed', { error, cameraId: config.cameraId });
      throw error;
    }
  }

  private async matchFace(features: number[], confidence: number): Promise<{ personId: string; similarity: number } | null> {
    try {
      let bestMatch: { personId: string; similarity: number } | null = null;

      // Compare with enrolled faces
      for (const [key, enrollment] of this.faceDatabase) {
        const similarity = this.calculateCosineSimilarity(features, enrollment.features);
        
        if (similarity >= confidence && (!bestMatch || similarity > bestMatch.similarity)) {
          bestMatch = {
            personId: enrollment.personId,
            similarity
          };
        }
      }

      return bestMatch;
    } catch (error) {
      analyticsLogger.error('Face matching failed', { error });
      return null;
    }
  }

  private calculateCosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length) return 0;

    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }

    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  private async generateFaceRecognitionAlert(tenantId: string, event: FaceRecognitionEvent): Promise<void> {
    const alert: PredictiveAlert = {
      id: `face-alert-${event.id}-${Date.now()}`,
      type: 'watchlist_face_detected',
      severity: 'high',
      message: `Watchlisted individual detected on camera ${event.cameraId}`,
      entityId: event.cameraId,
      entityType: 'camera',
      probability: event.confidence,
      factors: ['Face recognition match', 'Watchlist entry'],
      recommendedActions: ['Verify identity', 'Dispatch security', 'Review access logs'],
      timestamp: new Date()
    };

    await this.storeAlert(tenantId, alert);
  }

  private async generateLicensePlateAlert(tenantId: string, event: LicensePlateEvent): Promise<void> {
    const alert: PredictiveAlert = {
      id: `lpr-alert-${event.id}-${Date.now()}`,
      type: 'watchlist_plate_detected',
      severity: 'high',
      message: `Watchlisted license plate ${event.plateNumber} detected on camera ${event.cameraId}`,
      entityId: event.cameraId,
      entityType: 'camera',
      probability: event.confidence,
      factors: ['License plate recognition match', 'Watchlist entry'],
      recommendedActions: ['Verify vehicle', 'Check access authorization', 'Monitor vehicle movement'],
      timestamp: new Date()
    };

    await this.storeAlert(tenantId, alert);
  }

  private async generateBehaviorAlert(tenantId: string, event: BehaviorEvent): Promise<void> {
    const alert: PredictiveAlert = {
      id: `behavior-alert-${event.id}-${Date.now()}`,
      type: `behavior_${event.eventType}`,
      severity: event.severity,
      message: `${event.eventType.replace('_', ' ')} detected on camera ${event.cameraId}`,
      entityId: event.cameraId,
      entityType: 'camera',
      probability: event.confidence,
      factors: ['Behavior analysis detection', `Event type: ${event.eventType}`],
      recommendedActions: this.getBehaviorRecommendations(event.eventType),
      timestamp: new Date()
    };

    await this.storeAlert(tenantId, alert);
  }

  private async generateCrowdAlert(tenantId: string, analysis: CrowdAnalysis): Promise<void> {
    const alert: PredictiveAlert = {
      id: `crowd-alert-${analysis.cameraId}-${Date.now()}`,
      type: 'crowd_risk',
      severity: analysis.riskLevel,
      message: `High crowd density detected on camera ${analysis.cameraId}`,
      entityId: analysis.cameraId,
      entityType: 'camera',
      probability: 0.9,
      factors: [`Crowd count: ${analysis.totalCount}`, `Density: ${analysis.density}`, `Risk level: ${analysis.riskLevel}`],
      recommendedActions: ['Monitor crowd movement', 'Prepare crowd control measures', 'Alert security personnel'],
      timestamp: new Date()
    };

    await this.storeAlert(tenantId, alert);
  }

  private getBehaviorRecommendations(eventType: string): string[] {
    const recommendations: Record<string, string[]> = {
      loitering: ['Investigate area', 'Approach individual', 'Review access authorization'],
      crowd_formation: ['Monitor crowd behavior', 'Prepare crowd control', 'Alert security'],
      unusual_direction: ['Verify access route', 'Check for unauthorized access', 'Monitor individual'],
      speed_violation: ['Check for emergency', 'Verify safety protocols', 'Monitor area'],
      object_left: ['Investigate object', 'Check for security threat', 'Secure area'],
      object_removed: ['Verify authorization', 'Check inventory', 'Review access logs']
    };

    return recommendations[eventType] || ['Monitor situation', 'Alert security'];
  }

  private async storeAlert(tenantId: string, alert: PredictiveAlert): Promise<void> {
    await redis.setex(`alert:${tenantId}:${alert.id}`, 3600, JSON.stringify(alert));
    
    // Also store in OpenSearch for historical analysis
    await opensearch.index({
      index: `alerts-${tenantId}`,
      body: {
        ...alert,
        tenantId,
        '@timestamp': alert.timestamp.toISOString()
      }
    });
  }

  private isBehaviorAnalysisEnabled(config: VideoAnalyticsConfig, eventType: string): boolean {
    switch (eventType) {
      case 'loitering':
        return config.behaviorAnalysis.loiteringDetection;
      case 'crowd_formation':
        return config.behaviorAnalysis.crowdAnalysis;
      case 'unusual_direction':
        return config.behaviorAnalysis.directionAnalysis;
      case 'speed_violation':
        return config.behaviorAnalysis.speedAnalysis;
      default:
        return true; // Enable other event types by default
    }
  }

  private async updatePersonTracking(tenantId: string, event: FaceRecognitionEvent): Promise<void> {
    try {
      // Update person location tracking
      await redis.setex(
        `person:${tenantId}:${event.personId}:location`,
        3600,
        JSON.stringify({
          cameraId: event.cameraId,
          timestamp: event.timestamp,
          confidence: event.confidence
        })
      );

      // Store in person tracking index
      await opensearch.index({
        index: `person-tracking-${tenantId}`,
        body: {
          personId: event.personId,
          cameraId: event.cameraId,
          timestamp: event.timestamp,
          confidence: event.confidence,
          tenantId,
          '@timestamp': event.timestamp
        }
      });
    } catch (error) {
      analyticsLogger.error('Person tracking update failed', { error, event });
    }
  }

  private async correlateLicensePlateWithAccess(tenantId: string, event: LicensePlateEvent): Promise<void> {
    try {
      // Look for recent access events near this camera
      const camera = await prisma.camera.findFirst({
        where: { id: event.cameraId, tenantId },
        include: { building: true, floor: true, zone: true }
      });

      if (!camera) return;

      // Search for access events in the same area within the last 10 minutes
      const recentAccessEvents = await opensearch.search({
        index: `access-events-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { range: { timestamp: { gte: 'now-10m' } } },
                {
                  bool: {
                    should: [
                      { term: { buildingId: camera.buildingId } },
                      { term: { floorId: camera.floorId } },
                      { term: { zoneId: camera.zoneId } }
                    ]
                  }
                }
              ]
            }
          },
          sort: [{ timestamp: { order: 'desc' } }],
          size: 10
        }
      });

      // Create correlation records
      for (const hit of recentAccessEvents.body.hits.hits) {
        await opensearch.index({
          index: `vehicle-access-correlation-${tenantId}`,
          body: {
            plateNumber: event.plateNumber,
            accessEventId: hit._source.id,
            cameraId: event.cameraId,
            userId: hit._source.userId,
            timestamp: event.timestamp,
            confidence: event.confidence,
            tenantId,
            '@timestamp': event.timestamp
          }
        });
      }
    } catch (error) {
      analyticsLogger.error('License plate correlation failed', { error, event });
    }
  }

  private async updateBehaviorPatterns(tenantId: string, event: BehaviorEvent): Promise<void> {
    try {
      const patternKey = `behavior:${tenantId}:${event.cameraId}:${event.eventType}`;
      
      // Get existing pattern data
      const existingPattern = await redis.get(patternKey);
      let pattern = existingPattern ? JSON.parse(existingPattern) : {
        eventType: event.eventType,
        cameraId: event.cameraId,
        count: 0,
        averageConfidence: 0,
        lastOccurrence: null,
        frequency: 0
      };

      // Update pattern
      pattern.count++;
      pattern.averageConfidence = (pattern.averageConfidence * (pattern.count - 1) + event.confidence) / pattern.count;
      pattern.lastOccurrence = event.timestamp;
      pattern.frequency = pattern.count / Math.max(1, (Date.now() - new Date(pattern.lastOccurrence).getTime()) / (24 * 60 * 60 * 1000));

      // Store updated pattern
      await redis.setex(patternKey, 86400, JSON.stringify(pattern)); // 24 hour expiry
    } catch (error) {
      analyticsLogger.error('Behavior pattern update failed', { error, event });
    }
  }

  private async getRecentPersonDetections(tenantId: string, cameraId: string, seconds: number): Promise<any[]> {
    try {
      const response = await opensearch.search({
        index: `face-recognition-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { term: { cameraId } },
                { range: { timestamp: { gte: `now-${seconds}s` } } }
              ]
            }
          },
          sort: [{ timestamp: { order: 'desc' } }],
          size: 1000
        }
      });

      return response.body.hits.hits.map((hit: any) => hit._source);
    } catch (error) {
      analyticsLogger.error('Failed to get recent person detections', { error, tenantId, cameraId });
      return [];
    }
  }

  private async analyzeCrowdMetrics(events: any[], config: VideoAnalyticsConfig): Promise<CrowdAnalysis> {
    try {
      const totalCount = events.length;
      const timestamp = new Date();

      // Calculate density (simplified - would use actual area in production)
      const density = totalCount / 100; // Assuming 100 sq meter area

      // Calculate average speed (simplified)
      const averageSpeed = this.calculateAverageSpeed(events);

      // Calculate flow direction
      const flowDirection = this.calculateFlowDirection(events);

      // Identify hotspots
      const hotspots = this.identifyHotspots(events);

      // Determine risk level
      const riskLevel = this.determineRiskLevel(totalCount, density, config);

      return {
        cameraId: config.cameraId,
        timestamp,
        totalCount,
        density,
        averageSpeed,
        flowDirection,
        hotspots,
        riskLevel
      };
    } catch (error) {
      analyticsLogger.error('Crowd metrics analysis failed', { error });
      throw error;
    }
  }

  private calculateAverageSpeed(events: any[]): number {
    // Simplified speed calculation - would track movement between frames in production
    return events.length > 0 ? Math.random() * 2 + 1 : 0; // 1-3 m/s
  }

  private calculateFlowDirection(events: any[]): { angle: number; magnitude: number } {
    // Simplified flow direction calculation
    return {
      angle: Math.random() * 360,
      magnitude: Math.random()
    };
  }

  private identifyHotspots(events: any[]): Array<{ x: number; y: number; intensity: number }> {
    // Simplified hotspot identification
    const hotspots: Array<{ x: number; y: number; intensity: number }> = [];
    
    // Group events by location and calculate intensity
    const locationMap = new Map<string, number>();
    
    events.forEach(event => {
      if (event.boundingBox) {
        const x = Math.floor(event.boundingBox.x / 0.1) * 0.1;
        const y = Math.floor(event.boundingBox.y / 0.1) * 0.1;
        const key = `${x},${y}`;
        locationMap.set(key, (locationMap.get(key) || 0) + 1);
      }
    });

    // Convert to hotspots
    locationMap.forEach((count, key) => {
      const [x, y] = key.split(',').map(Number);
      if (count > 2) { // Threshold for hotspot
        hotspots.push({ x, y, intensity: count / events.length });
      }
    });

    return hotspots;
  }

  private determineRiskLevel(count: number, density: number, config: VideoAnalyticsConfig): 'low' | 'medium' | 'high' | 'critical' {
    const threshold = config.behaviorAnalysis.crowdThreshold;
    
    if (count > threshold * 2 || density > 0.8) return 'critical';
    if (count > threshold * 1.5 || density > 0.6) return 'high';
    if (count > threshold || density > 0.4) return 'medium';
    return 'low';
  }

  private async predictSecurityBreaches(tenantId: string): Promise<IncidentPrediction[]> {
    const predictions: IncidentPrediction[] = [];

    try {
      // Analyze failed access attempts
      const failedAttempts = await opensearch.search({
        index: `access-events-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { term: { granted: false } },
                { range: { timestamp: { gte: 'now-1h' } } }
              ]
            }
          },
          aggs: {
            by_door: {
              terms: { field: 'doorId', size: 10 }
            },
            by_user: {
              terms: { field: 'userId', size: 10 }
            }
          }
        }
      });

      // Check for suspicious patterns
      failedAttempts.body.aggregations.by_door.buckets.forEach((bucket: any) => {
        if (bucket.doc_count > 5) {
          predictions.push({
            id: `security-breach-${bucket.key}-${Date.now()}`,
            type: 'security_breach',
            probability: Math.min(bucket.doc_count / 10, 0.9),
            timeToIncident: 30,
            location: {
              buildingId: 'unknown',
              doorId: bucket.key
            },
            factors: [`${bucket.doc_count} failed access attempts`, 'Potential brute force attack'],
            recommendedActions: ['Increase security presence', 'Review access logs', 'Check door status'],
            severity: bucket.doc_count > 10 ? 'critical' : 'high',
            timestamp: new Date()
          });
        }
      });
    } catch (error) {
      analyticsLogger.error('Security breach prediction failed', { error, tenantId });
    }

    return predictions;
  }

  private async predictCrowdIncidents(tenantId: string): Promise<IncidentPrediction[]> {
    const predictions: IncidentPrediction[] = [];

    try {
      // Analyze crowd analysis data
      const crowdData = await opensearch.search({
        index: `crowd-analysis-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { range: { timestamp: { gte: 'now-30m' } } }
              ]
            }
          },
          sort: [{ timestamp: { order: 'desc' } }],
          size: 100
        }
      });

      // Analyze trends
      const analyses = crowdData.body.hits.hits.map((hit: any) => hit._source);
      const highRiskCameras = analyses.filter((analysis: any) => 
        analysis.riskLevel === 'high' || analysis.riskLevel === 'critical'
      );

      highRiskCameras.forEach((analysis: any) => {
        predictions.push({
          id: `crowd-incident-${analysis.cameraId}-${Date.now()}`,
          type: 'crowd_incident',
          probability: analysis.riskLevel === 'critical' ? 0.8 : 0.6,
          timeToIncident: 15,
          location: {
            buildingId: 'unknown',
            cameraId: analysis.cameraId
          },
          factors: [`High crowd density: ${analysis.density}`, `Total count: ${analysis.totalCount}`],
          recommendedActions: ['Deploy crowd control', 'Monitor exits', 'Prepare emergency procedures'],
          severity: analysis.riskLevel === 'critical' ? 'critical' : 'high',
          timestamp: new Date()
        });
      });
    } catch (error) {
      analyticsLogger.error('Crowd incident prediction failed', { error, tenantId });
    }

    return predictions;
  }

  private async predictEquipmentFailures(tenantId: string): Promise<IncidentPrediction[]> {
    const predictions: IncidentPrediction[] = [];

    try {
      // Analyze device error patterns
      const deviceErrors = await opensearch.search({
        index: `device-events-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { term: { eventType: 'error' } },
                { range: { timestamp: { gte: 'now-24h' } } }
              ]
            }
          },
          aggs: {
            by_device: {
              terms: { field: 'deviceId', size: 20 }
            }
          }
        }
      });

      deviceErrors.body.aggregations.by_device.buckets.forEach((bucket: any) => {
        if (bucket.doc_count > 5) {
          predictions.push({
            id: `equipment-failure-${bucket.key}-${Date.now()}`,
            type: 'equipment_failure',
            probability: Math.min(bucket.doc_count / 20, 0.8),
            timeToIncident: 120,
            location: {
              buildingId: 'unknown'
            },
            factors: [`${bucket.doc_count} error events`, 'Increasing failure rate'],
            recommendedActions: ['Schedule maintenance', 'Check device status', 'Prepare replacement'],
            severity: bucket.doc_count > 15 ? 'high' : 'medium',
            timestamp: new Date()
          });
        }
      });
    } catch (error) {
      analyticsLogger.error('Equipment failure prediction failed', { error, tenantId });
    }

    return predictions;
  }

  private async predictSafetyViolations(tenantId: string): Promise<IncidentPrediction[]> {
    const predictions: IncidentPrediction[] = [];

    try {
      // Analyze behavior events for safety patterns
      const behaviorEvents = await opensearch.search({
        index: `behavior-events-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { terms: { eventType: ['speed_violation', 'object_left', 'unusual_direction'] } },
                { range: { timestamp: { gte: 'now-2h' } } }
              ]
            }
          },
          aggs: {
            by_camera: {
              terms: { field: 'cameraId', size: 10 }
            }
          }
        }
      });

      behaviorEvents.body.aggregations.by_camera.buckets.forEach((bucket: any) => {
        if (bucket.doc_count > 3) {
          predictions.push({
            id: `safety-violation-${bucket.key}-${Date.now()}`,
            type: 'safety_violation',
            probability: Math.min(bucket.doc_count / 10, 0.7),
            timeToIncident: 60,
            location: {
              buildingId: 'unknown',
              cameraId: bucket.key
            },
            factors: [`${bucket.doc_count} safety-related events`, 'Pattern of violations'],
            recommendedActions: ['Review safety protocols', 'Increase monitoring', 'Safety briefing'],
            severity: bucket.doc_count > 6 ? 'high' : 'medium',
            timestamp: new Date()
          });
        }
      });
    } catch (error) {
      analyticsLogger.error('Safety violation prediction failed', { error, tenantId });
    }

    return predictions;
  }
}

// Initialize analytics engine
const analyticsEngine = new AnalyticsEngine();

// Middleware
app.use('*', cors({
  origin: process.env.CORS_ORIGIN || '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID']
}));

app.use('*', logger());
app.use('*', prettyJSON());

// Authentication middleware
app.use('*', async (c, next) => {
  if (c.req.path === '/health') {
    return next();
  }

  const authorization = c.req.header('Authorization');
  if (!authorization?.startsWith('Bearer ')) {
    throw new HTTPException(401, { message: 'Missing or invalid authorization header' });
  }

  const token = authorization.substring(7);
  try {
    // Verify JWT token (implementation would use actual JWT verification)
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    c.set('user', payload);
    c.set('tenantId', payload.tenantId);
  } catch (error) {
    throw new HTTPException(401, { message: 'Invalid token' });
  }

  await next();
});

// Apply caching middleware to analytics endpoints
app.use('/analytics/*', cacheMiddleware(cache, {
  ttl: 300, // 5 minutes
  namespace: 'analytics',
  excludePaths: ['/health', '/ready'],
  keyGenerator: (c) => {
    const url = new URL(c.req.url);
    const tenantId = c.get('tenantId');
    return `${tenantId}:${url.pathname}:${url.search}`;
  }
}));

// Apply cache invalidation for data updates
app.use('*', cacheInvalidationMiddleware(cache, {
  triggers: {
    method: ['POST', 'PUT', 'DELETE'],
    paths: ['/api/video-analytics', '/api/alerts', '/api/behavior-profiles']
  },
  invalidate: {
    namespace: 'analytics'
  }
}));

// Health check endpoint
app.get('/health', createHealthCheckHandler({
  serviceName: 'analytics-service',
  prismaClient: prisma,
  redisClient: redis,
  customChecks: {
    opensearch: async () => {
      try {
        const health = await opensearchClient.cluster.health();
        return health.body.status !== 'red';
      } catch {
        return false;
      }
    }
  }
}));

// Analytics endpoints

// Get security analytics
app.get('/analytics/security', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = AnalyticsQuerySchema.parse(c.req.query());

    const securityMetrics = await opensearch.search({
      index: `access-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [])
            ]
          }
        },
        aggs: {
          access_attempts: {
            terms: { field: 'granted' }
          },
          hourly_distribution: {
            date_histogram: {
              field: 'timestamp',
              interval: '1h'
            }
          },
          top_doors: {
            terms: { field: 'doorId', size: 10 }
          },
          failed_attempts: {
            filter: { term: { granted: false } },
            aggs: {
              by_user: {
                terms: { field: 'userId', size: 10 }
              }
            }
          }
        }
      }
    });

    return c.json({
      success: true,
      data: {
        totalEvents: securityMetrics.body.hits.total.value,
        accessAttempts: securityMetrics.body.aggregations.access_attempts.buckets,
        hourlyDistribution: securityMetrics.body.aggregations.hourly_distribution.buckets,
        topDoors: securityMetrics.body.aggregations.top_doors.buckets,
        failedAttempts: securityMetrics.body.aggregations.failed_attempts
      }
    });
  } catch (error) {
    analyticsLogger.error('Security analytics failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve security analytics' });
  }
});

// Get occupancy analytics
app.get('/analytics/occupancy', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = OccupancyQuerySchema.parse(c.req.query());

    const occupancyData = await analyticsEngine.trackOccupancy(
      tenantId,
      query.buildingId,
      query.floorId,
      query.zoneId
    );

    return c.json({
      success: true,
      data: occupancyData
    });
  } catch (error) {
    analyticsLogger.error('Occupancy analytics failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve occupancy analytics' });
  }
});

// Detect anomalies
app.post('/analytics/anomalies', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const body = AnomalyDetectionSchema.parse(await c.req.json());

    const anomaly = await analyticsEngine.detectAnomalies(
      tenantId,
      body.entityType,
      body.entityId,
      body.threshold
    );

    return c.json({
      success: true,
      data: anomaly
    });
  } catch (error) {
    analyticsLogger.error('Anomaly detection failed', { error });
    throw new HTTPException(500, { message: 'Failed to detect anomalies' });
  }
});

// Get predictive alerts
app.get('/analytics/alerts/predictive', async (c) => {
  try {
    const tenantId = c.get('tenantId');

    const alerts = await analyticsEngine.generatePredictiveAlerts(tenantId);

    return c.json({
      success: true,
      data: alerts
    });
  } catch (error) {
    analyticsLogger.error('Predictive alerts failed', { error });
    throw new HTTPException(500, { message: 'Failed to generate predictive alerts' });
  }
});

// Get behavioral analysis
app.get('/analytics/behavior/:entityType/:entityId', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const entityType = c.req.param('entityType');
    const entityId = c.req.param('entityId');

    const behaviorAnalysis = await opensearch.search({
      index: `access-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              { term: { [`${entityType}Id`]: entityId } },
              { range: { timestamp: { gte: 'now-30d' } } }
            ]
          }
        },
        aggs: {
          daily_pattern: {
            date_histogram: {
              field: 'timestamp',
              interval: 'day'
            }
          },
          hourly_pattern: {
            date_histogram: {
              field: 'timestamp',
              interval: 'hour'
            }
          },
          location_pattern: {
            terms: { field: 'doorId', size: 20 }
          },
          access_success_rate: {
            terms: { field: 'granted' }
          }
        }
      }
    });

    return c.json({
      success: true,
      data: {
        totalEvents: behaviorAnalysis.body.hits.total.value,
        dailyPattern: behaviorAnalysis.body.aggregations.daily_pattern.buckets,
        hourlyPattern: behaviorAnalysis.body.aggregations.hourly_pattern.buckets,
        locationPattern: behaviorAnalysis.body.aggregations.location_pattern.buckets,
        successRate: behaviorAnalysis.body.aggregations.access_success_rate.buckets
      }
    });
  } catch (error) {
    analyticsLogger.error('Behavioral analysis failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve behavioral analysis' });
  }
});

// Get trend analysis
app.get('/analytics/trends', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = AnalyticsQuerySchema.parse(c.req.query());

    const trends = await opensearch.search({
      index: `access-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [{ range: { timestamp: { gte: 'now-30d' } } }])
            ]
          }
        },
        aggs: {
          daily_trends: {
            date_histogram: {
              field: 'timestamp',
              interval: 'day'
            },
            aggs: {
              access_granted: {
                filter: { term: { granted: true } }
              },
              access_denied: {
                filter: { term: { granted: false } }
              },
              unique_users: {
                cardinality: { field: 'userId' }
              }
            }
          },
          weekly_comparison: {
            date_histogram: {
              field: 'timestamp',
              interval: 'week'
            }
          }
        }
      }
    });

    return c.json({
      success: true,
      data: {
        dailyTrends: trends.body.aggregations.daily_trends.buckets,
        weeklyComparison: trends.body.aggregations.weekly_comparison.buckets
      }
    });
  } catch (error) {
    analyticsLogger.error('Trend analysis failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve trend analysis' });
  }
});

// Real-time analytics dashboard data
app.get('/analytics/dashboard', async (c) => {
  try {
    const tenantId = c.get('tenantId');

    // Get real-time metrics from Redis cache
    const cachedMetrics = await redis.get(`dashboard:${tenantId}`);
    if (cachedMetrics) {
      return c.json({
        success: true,
        data: JSON.parse(cachedMetrics),
        cached: true
      });
    }

    // Generate fresh dashboard data
    const [securityMetrics, occupancyData, recentAlerts] = await Promise.all([
      opensearch.search({
        index: `access-events-${tenantId}`,
        body: {
          query: {
            bool: {
              must: [
                { term: { tenantId } },
                { range: { timestamp: { gte: 'now-24h' } } }
              ]
            }
          },
          aggs: {
            total_events: { value_count: { field: 'timestamp' } },
            success_rate: {
              terms: { field: 'granted' }
            },
            active_doors: {
              cardinality: { field: 'doorId' }
            },
            unique_users: {
              cardinality: { field: 'userId' }
            }
          }
        }
      }),
      analyticsEngine.trackOccupancy(tenantId),
      redis.keys(`alert:${tenantId}:*`).then(keys => 
        keys.length > 0 ? redis.mget(keys) : []
      )
    ]);

    const dashboardData = {
      timestamp: new Date().toISOString(),
      security: {
        totalEvents: securityMetrics.body.aggregations.total_events.value,
        successRate: securityMetrics.body.aggregations.success_rate.buckets,
        activeDoors: securityMetrics.body.aggregations.active_doors.value,
        uniqueUsers: securityMetrics.body.aggregations.unique_users.value
      },
      occupancy: occupancyData.slice(-24), // Last 24 hours
      alerts: recentAlerts.filter(alert => alert).map(alert => JSON.parse(alert)).slice(0, 10)
    };

    // Cache for 1 minute
    await redis.setex(`dashboard:${tenantId}`, 60, JSON.stringify(dashboardData));

    return c.json({
      success: true,
      data: dashboardData,
      cached: false
    });
  } catch (error) {
    analyticsLogger.error('Dashboard data failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve dashboard data' });
  }
});

// Advanced Video Analytics Endpoints

// Configure video analytics for a camera
app.post('/analytics/video/configure', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const config = VideoAnalyticsConfigSchema.parse(body);

    await analyticsEngine.configureVideoAnalytics(tenantId, config);

    return c.json({
      success: true,
      message: 'Video analytics configured successfully'
    });
  } catch (error) {
    analyticsLogger.error('Video analytics configuration failed', { error });
    throw new HTTPException(500, { message: 'Failed to configure video analytics' });
  }
});

// Process face recognition event
app.post('/analytics/video/face-recognition', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const event = FaceRecognitionEventSchema.parse(body);

    const faceEvent: FaceRecognitionEvent = {
      id: `face-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      tenantId,
      ...event,
      timestamp: new Date(event.timestamp)
    };

    await analyticsEngine.processFaceRecognitionEvent(tenantId, faceEvent);

    return c.json({
      success: true,
      eventId: faceEvent.id,
      message: 'Face recognition event processed'
    });
  } catch (error) {
    analyticsLogger.error('Face recognition processing failed', { error });
    throw new HTTPException(500, { message: 'Failed to process face recognition event' });
  }
});

// Process license plate recognition event
app.post('/analytics/video/license-plate', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const event = LicensePlateEventSchema.parse(body);

    const lprEvent: LicensePlateEvent = {
      id: `lpr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      tenantId,
      ...event,
      timestamp: new Date(event.timestamp)
    };

    await analyticsEngine.processLicensePlateEvent(tenantId, lprEvent);

    return c.json({
      success: true,
      eventId: lprEvent.id,
      message: 'License plate event processed'
    });
  } catch (error) {
    analyticsLogger.error('License plate processing failed', { error });
    throw new HTTPException(500, { message: 'Failed to process license plate event' });
  }
});

// Process behavior analysis event
app.post('/analytics/video/behavior', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const event = BehaviorEventSchema.parse(body);

    const behaviorEvent: BehaviorEvent = {
      id: `behavior-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      tenantId,
      ...event,
      timestamp: new Date(event.timestamp)
    };

    await analyticsEngine.processBehaviorEvent(tenantId, behaviorEvent);

    return c.json({
      success: true,
      eventId: behaviorEvent.id,
      message: 'Behavior event processed'
    });
  } catch (error) {
    analyticsLogger.error('Behavior event processing failed', { error });
    throw new HTTPException(500, { message: 'Failed to process behavior event' });
  }
});

// Get face recognition events
app.get('/analytics/video/face-recognition', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const searchQuery = {
      index: `face-recognition-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              ...(query.cameraId ? [{ term: { cameraId: query.cameraId } }] : []),
              ...(query.personId ? [{ term: { personId: query.personId } }] : []),
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [{ range: { timestamp: { gte: 'now-24h' } } }])
            ]
          }
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: parseInt(query.limit as string) || 100
      }
    };

    const response = await opensearch.search(searchQuery);
    const events = response.body.hits.hits.map((hit: any) => hit._source);

    return c.json({
      success: true,
      data: events,
      total: response.body.hits.total.value
    });
  } catch (error) {
    analyticsLogger.error('Face recognition query failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve face recognition events' });
  }
});

// Get license plate events
app.get('/analytics/video/license-plate', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const searchQuery = {
      index: `license-plate-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              ...(query.cameraId ? [{ term: { cameraId: query.cameraId } }] : []),
              ...(query.plateNumber ? [{ term: { plateNumber: query.plateNumber } }] : []),
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [{ range: { timestamp: { gte: 'now-24h' } } }])
            ]
          }
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: parseInt(query.limit as string) || 100
      }
    };

    const response = await opensearch.search(searchQuery);
    const events = response.body.hits.hits.map((hit: any) => hit._source);

    return c.json({
      success: true,
      data: events,
      total: response.body.hits.total.value
    });
  } catch (error) {
    analyticsLogger.error('License plate query failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve license plate events' });
  }
});

// Get behavior events
app.get('/analytics/video/behavior', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const searchQuery = {
      index: `behavior-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              ...(query.cameraId ? [{ term: { cameraId: query.cameraId } }] : []),
              ...(query.eventType ? [{ term: { eventType: query.eventType } }] : []),
              ...(query.severity ? [{ term: { severity: query.severity } }] : []),
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [{ range: { timestamp: { gte: 'now-24h' } } }])
            ]
          }
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: parseInt(query.limit as string) || 100
      }
    };

    const response = await opensearch.search(searchQuery);
    const events = response.body.hits.hits.map((hit: any) => hit._source);

    return c.json({
      success: true,
      data: events,
      total: response.body.hits.total.value
    });
  } catch (error) {
    analyticsLogger.error('Behavior events query failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve behavior events' });
  }
});

// Perform crowd analysis
app.post('/analytics/video/crowd-analysis', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const { cameraId } = await c.req.json();

    if (!cameraId) {
      throw new HTTPException(400, { message: 'Camera ID is required' });
    }

    const analysis = await analyticsEngine.performCrowdAnalysis(tenantId, cameraId);

    return c.json({
      success: true,
      data: analysis
    });
  } catch (error) {
    analyticsLogger.error('Crowd analysis failed', { error });
    throw new HTTPException(500, { message: 'Failed to perform crowd analysis' });
  }
});

// Enroll face
app.post('/analytics/video/face-enrollment', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const { personId, features, metadata } = await c.req.json();

    if (!personId || !features || !Array.isArray(features)) {
      throw new HTTPException(400, { message: 'Person ID and features array are required' });
    }

    await analyticsEngine.enrollFace(tenantId, personId, features, metadata);

    return c.json({
      success: true,
      message: 'Face enrolled successfully'
    });
  } catch (error) {
    analyticsLogger.error('Face enrollment failed', { error });
    throw new HTTPException(500, { message: 'Failed to enroll face' });
  }
});

// Update watchlists
app.post('/analytics/video/watchlist', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const { type, items } = await c.req.json();

    if (!type || !items || !Array.isArray(items)) {
      throw new HTTPException(400, { message: 'Type and items array are required' });
    }

    if (!['face', 'license_plate'].includes(type)) {
      throw new HTTPException(400, { message: 'Type must be "face" or "license_plate"' });
    }

    await analyticsEngine.updateWatchlists(tenantId, type, items);

    return c.json({
      success: true,
      message: `${type} watchlist updated successfully`
    });
  } catch (error) {
    analyticsLogger.error('Watchlist update failed', { error });
    throw new HTTPException(500, { message: 'Failed to update watchlist' });
  }
});

// Get incident predictions
app.get('/analytics/predictions', async (c) => {
  try {
    const tenantId = c.get('tenantId');

    const predictions = await analyticsEngine.generateIncidentPredictions(tenantId);

    return c.json({
      success: true,
      data: predictions
    });
  } catch (error) {
    analyticsLogger.error('Incident predictions failed', { error });
    throw new HTTPException(500, { message: 'Failed to generate incident predictions' });
  }
});

// Get person tracking data
app.get('/analytics/video/person-tracking/:personId', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const personId = c.req.param('personId');
    const query = c.req.query();

    const searchQuery = {
      index: `person-tracking-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              { term: { personId } },
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [{ range: { timestamp: { gte: 'now-24h' } } }])
            ]
          }
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: parseInt(query.limit as string) || 100
      }
    };

    const response = await opensearch.search(searchQuery);
    const tracking = response.body.hits.hits.map((hit: any) => hit._source);

    return c.json({
      success: true,
      data: tracking,
      total: response.body.hits.total.value
    });
  } catch (error) {
    analyticsLogger.error('Person tracking query failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve person tracking data' });
  }
});

// Get vehicle-access correlations
app.get('/analytics/video/vehicle-correlations', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();

    const searchQuery = {
      index: `vehicle-access-correlation-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              ...(query.plateNumber ? [{ term: { plateNumber: query.plateNumber } }] : []),
              ...(query.userId ? [{ term: { userId: query.userId } }] : []),
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [{ range: { timestamp: { gte: 'now-24h' } } }])
            ]
          }
        },
        sort: [{ timestamp: { order: 'desc' } }],
        size: parseInt(query.limit as string) || 100
      }
    };

    const response = await opensearch.search(searchQuery);
    const correlations = response.body.hits.hits.map((hit: any) => hit._source);

    return c.json({
      success: true,
      data: correlations,
      total: response.body.hits.total.value
    });
  } catch (error) {
    analyticsLogger.error('Vehicle correlation query failed', { error });
    throw new HTTPException(500, { message: 'Failed to retrieve vehicle correlations' });
  }
});

// Export analytics data
app.post('/analytics/export', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const body = await c.req.json();
    const { format = 'json', ...query } = body;

    const exportData = await opensearch.search({
      index: `access-events-${tenantId}`,
      body: {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              ...(query.startDate && query.endDate ? [{
                range: {
                  timestamp: {
                    gte: query.startDate,
                    lte: query.endDate
                  }
                }
              }] : [])
            ]
          }
        },
        size: query.limit || 10000,
        sort: [{ timestamp: { order: 'desc' } }]
      }
    });

    const data = exportData.body.hits.hits.map((hit: any) => hit._source);

    if (format === 'csv') {
      // Convert to CSV format
      const csv = this.convertToCSV(data);
      c.header('Content-Type', 'text/csv');
      c.header('Content-Disposition', 'attachment; filename=analytics-export.csv');
      return c.text(csv);
    }

    return c.json({
      success: true,
      data,
      total: exportData.body.hits.total.value,
      exported: data.length
    });
  } catch (error) {
    analyticsLogger.error('Analytics export failed', { error });
    throw new HTTPException(500, { message: 'Failed to export analytics data' });
  }
});

// Error handling
app.onError((err, c) => {
  analyticsLogger.error('Unhandled error', { error: err });
  
  if (err instanceof HTTPException) {
    return c.json({
      success: false,
      error: err.message
    }, err.status);
  }

  return c.json({
    success: false,
    error: 'Internal server error'
  }, 500);
});

// Background tasks
async function startBackgroundTasks() {
  // Generate predictive alerts every 15 minutes
  setInterval(async () => {
    try {
      const tenants = await prisma.tenant.findMany({ select: { id: true } });
      
      for (const tenant of tenants) {
        await analyticsEngine.generatePredictiveAlerts(tenant.id);
      }
      
      analyticsLogger.info('Predictive alerts generated for all tenants');
    } catch (error) {
      analyticsLogger.error('Background predictive alerts failed', { error });
    }
  }, 15 * 60 * 1000);

  // Update occupancy data every 5 minutes
  setInterval(async () => {
    try {
      const tenants = await prisma.tenant.findMany({ select: { id: true } });
      
      for (const tenant of tenants) {
        const occupancyData = await analyticsEngine.trackOccupancy(tenant.id);
        await redis.setex(`occupancy:${tenant.id}`, 300, JSON.stringify(occupancyData));
      }
      
      analyticsLogger.info('Occupancy data updated for all tenants');
    } catch (error) {
      analyticsLogger.error('Background occupancy update failed', { error });
    }
  }, 5 * 60 * 1000);

  // Generate incident predictions every 10 minutes
  setInterval(async () => {
    try {
      const tenants = await prisma.tenant.findMany({ select: { id: true } });
      
      for (const tenant of tenants) {
        await analyticsEngine.generateIncidentPredictions(tenant.id);
      }
      
      analyticsLogger.info('Incident predictions generated for all tenants');
    } catch (error) {
      analyticsLogger.error('Background incident predictions failed', { error });
    }
  }, 10 * 60 * 1000);

  // Perform crowd analysis every 2 minutes for active cameras
  setInterval(async () => {
    try {
      const tenants = await prisma.tenant.findMany({ select: { id: true } });
      
      for (const tenant of tenants) {
        // Get cameras with crowd analysis enabled
        const cameras = await prisma.camera.findMany({
          where: { 
            tenantId: tenant.id,
            status: 'online'
          },
          include: {
            videoAnalyticsConfig: true
          }
        });

        for (const camera of cameras) {
          if (camera.videoAnalyticsConfig?.behaviorAnalysis?.crowdAnalysis) {
            try {
              await analyticsEngine.performCrowdAnalysis(tenant.id, camera.id);
            } catch (error) {
              analyticsLogger.error('Crowd analysis failed for camera', { 
                error, 
                tenantId: tenant.id, 
                cameraId: camera.id 
              });
            }
          }
        }
      }
      
      analyticsLogger.info('Crowd analysis completed for all active cameras');
    } catch (error) {
      analyticsLogger.error('Background crowd analysis failed', { error });
    }
  }, 2 * 60 * 1000);

  // Clean up old analytics data every hour
  setInterval(async () => {
    try {
      const tenants = await prisma.tenant.findMany({ select: { id: true } });
      
      for (const tenant of tenants) {
        // Clean up old face recognition events (older than 90 days)
        await opensearch.deleteByQuery({
          index: `face-recognition-${tenant.id}`,
          body: {
            query: {
              range: {
                timestamp: {
                  lt: 'now-90d'
                }
              }
            }
          }
        });

        // Clean up old behavior events (older than 30 days)
        await opensearch.deleteByQuery({
          index: `behavior-events-${tenant.id}`,
          body: {
            query: {
              range: {
                timestamp: {
                  lt: 'now-30d'
                }
              }
            }
          }
        });

        // Clean up old predictions (older than 7 days)
        await opensearch.deleteByQuery({
          index: `incident-predictions-${tenant.id}`,
          body: {
            query: {
              range: {
                timestamp: {
                  lt: 'now-7d'
                }
              }
            }
          }
        });
      }
      
      analyticsLogger.info('Analytics data cleanup completed');
    } catch (error) {
      analyticsLogger.error('Background cleanup failed', { error });
    }
  }, 60 * 60 * 1000);
}

// WebSocket server for real-time analytics
const server = createServer();
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  analyticsLogger.info('WebSocket connection established');
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message.toString());
      
      if (data.type === 'subscribe' && data.tenantId) {
        // Subscribe to real-time analytics updates
        ws.tenantId = data.tenantId;
        ws.send(JSON.stringify({
          type: 'subscribed',
          tenantId: data.tenantId
        }));
      }
    } catch (error) {
      analyticsLogger.error('WebSocket message error', { error });
    }
  });

  ws.on('close', () => {
    analyticsLogger.info('WebSocket connection closed');
  });
});

// Start server
const port = parseInt(process.env.PORT || '3007');

server.on('request', app.fetch);

server.listen(port, () => {
  analyticsLogger.info(`Analytics service started on port ${port}`);
  startBackgroundTasks();
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  analyticsLogger.info('SIGTERM received, shutting down gracefully');
  
  await prisma.$disconnect();
  await redis.quit();
  
  server.close(() => {
    analyticsLogger.info('Analytics service stopped');
    process.exit(0);
  });
});

export default app;

// Test Suite - Only included in test environment
