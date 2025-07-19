import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';
import { OccupancyData } from '../types';

export class OccupancyService extends BaseAnalyticsService {
  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
  }

  async trackOccupancy(
    tenantId: string,
    location: {
      buildingId: string;
      floorId?: string;
      zoneId?: string;
    }
  ): Promise<OccupancyData> {
    const cacheKey = `occupancy:${tenantId}:${location.buildingId}:${location.floorId || 'all'}:${location.zoneId || 'all'}`;
    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    try {
      // Get current occupancy count
      const currentCount = await this.getCurrentOccupancyCount(tenantId, location);
      
      // Get location capacity
      const capacity = await this.getLocationCapacity(tenantId, location);
      
      // Calculate utilization rate
      const utilizationRate = capacity > 0 ? (currentCount / capacity) : 0;

      const occupancyData: OccupancyData = {
        location,
        timestamp: new Date(),
        count: currentCount,
        capacity,
        utilizationRate
      };

      // Store in Redis for real-time tracking
      await this.redis.hset(
        `occupancy:realtime:${tenantId}`,
        `${location.buildingId}:${location.floorId || 'all'}:${location.zoneId || 'all'}`,
        JSON.stringify(occupancyData)
      );

      // Store historical data in OpenSearch
      await this.storeInOpenSearch(`${this.config.opensearchIndex}-occupancy`, {
        ...occupancyData,
        tenantId,
        timestamp: occupancyData.timestamp.toISOString()
      });

      // Broadcast real-time update
      await this.broadcastUpdate('occupancy-update', {
        tenantId,
        occupancyData
      });

      // Cache for 30 seconds
      await this.cache.set(cacheKey, occupancyData, 30);

      return occupancyData;
    } catch (error) {
      this.logger.error('Occupancy tracking failed', { error, tenantId, location });
      throw error;
    }
  }

  async analyzeOccupancyTrends(
    tenantId: string,
    buildingId: string,
    startDate: Date,
    endDate: Date,
    granularity: 'minute' | 'hour' | 'day' = 'hour'
  ): Promise<any> {
    const cacheKey = `occupancy:trends:${tenantId}:${buildingId}:${startDate.getTime()}:${endDate.getTime()}:${granularity}`;
    const cached = await this.cache.get(cacheKey);
    if (cached) return cached;

    try {
      const query = {
        query: {
          bool: {
            must: [
              { term: { tenantId } },
              { term: { 'location.buildingId': buildingId } },
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
        aggs: {
          trends: {
            date_histogram: {
              field: 'timestamp',
              calendar_interval: granularity,
              min_doc_count: 0,
              extended_bounds: {
                min: startDate.toISOString(),
                max: endDate.toISOString()
              }
            },
            aggs: {
              avg_occupancy: { avg: { field: 'count' } },
              max_occupancy: { max: { field: 'count' } },
              min_occupancy: { min: { field: 'count' } },
              avg_utilization: { avg: { field: 'utilizationRate' } }
            }
          },
          peak_hours: {
            terms: {
              field: 'timestamp',
              size: 24,
              script: {
                source: "doc['timestamp'].value.hourOfDay"
              }
            },
            aggs: {
              avg_occupancy: { avg: { field: 'count' } }
            }
          }
        },
        size: 0
      };

      const response = await this.opensearch.search({
        index: `${this.config.opensearchIndex}-occupancy`,
        body: query
      });

      const trends = response.body.aggregations.trends.buckets.map((bucket: any) => ({
        timestamp: bucket.key_as_string,
        averageOccupancy: Math.round(bucket.avg_occupancy.value || 0),
        maxOccupancy: bucket.max_occupancy.value || 0,
        minOccupancy: bucket.min_occupancy.value || 0,
        averageUtilization: bucket.avg_utilization.value || 0
      }));

      const peakHours = response.body.aggregations.peak_hours.buckets
        .sort((a: any, b: any) => b.avg_occupancy.value - a.avg_occupancy.value)
        .slice(0, 5)
        .map((bucket: any) => ({
          hour: bucket.key,
          averageOccupancy: Math.round(bucket.avg_occupancy.value || 0)
        }));

      const result = {
        trends,
        peakHours,
        summary: {
          totalDataPoints: trends.length,
          overallAverage: Math.round(
            trends.reduce((sum, t) => sum + t.averageOccupancy, 0) / trends.length
          ),
          peakOccupancy: Math.max(...trends.map(t => t.maxOccupancy)),
          averageUtilization: (
            trends.reduce((sum, t) => sum + t.averageUtilization, 0) / trends.length
          ).toFixed(2)
        }
      };

      // Cache for 5 minutes
      await this.cache.set(cacheKey, result, 300);

      return result;
    } catch (error) {
      this.logger.error('Occupancy trend analysis failed', { error, tenantId, buildingId });
      throw error;
    }
  }

  private async getCurrentOccupancyCount(
    tenantId: string,
    location: { buildingId: string; floorId?: string; zoneId?: string }
  ): Promise<number> {
    // In a real implementation, this would aggregate data from:
    // - Access control events (entries/exits)
    // - Camera people counting
    // - Sensor data
    // For now, we'll simulate with recent access events

    const recentEvents = await this.prisma.accessControlEvent.count({
      where: {
        tenantId,
        doorId: {
          in: await this.getLocationDoors(tenantId, location)
        },
        timestamp: {
          gte: new Date(Date.now() - 8 * 60 * 60 * 1000) // Last 8 hours
        },
        granted: true
      }
    });

    // Simple simulation: assume 70% are still in the building
    return Math.round(recentEvents * 0.7);
  }

  private async getLocationCapacity(
    tenantId: string,
    location: { buildingId: string; floorId?: string; zoneId?: string }
  ): Promise<number> {
    if (location.zoneId) {
      const zone = await this.prisma.zone.findFirst({
        where: { id: location.zoneId, tenantId }
      });
      return zone?.metadata?.capacity || 50;
    }

    if (location.floorId) {
      const floor = await this.prisma.floor.findFirst({
        where: { id: location.floorId, tenantId }
      });
      return floor?.metadata?.capacity || 200;
    }

    const building = await this.prisma.building.findFirst({
      where: { id: location.buildingId, tenantId }
    });
    return building?.metadata?.capacity || 1000;
  }

  private async getLocationDoors(
    tenantId: string,
    location: { buildingId: string; floorId?: string; zoneId?: string }
  ): Promise<string[]> {
    const whereClause: any = {
      tenantId,
      buildingId: location.buildingId
    };

    if (location.floorId) {
      whereClause.floorId = location.floorId;
    }

    if (location.zoneId) {
      whereClause.zoneId = location.zoneId;
    }

    const doors = await this.prisma.door.findMany({
      where: whereClause,
      select: { id: true }
    });

    return doors.map(d => d.id);
  }
}