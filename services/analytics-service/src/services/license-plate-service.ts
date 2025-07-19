import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';
import { LicensePlateEvent } from '../types';

export class LicensePlateService extends BaseAnalyticsService {
  private licensePlateWatchlist: Set<string> = new Set();

  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
  }

  async processLicensePlateEvent(
    tenantId: string,
    event: any
  ): Promise<LicensePlateEvent> {
    const processedEvent: LicensePlateEvent = {
      id: this.generateId(),
      cameraId: event.cameraId,
      tenantId,
      timestamp: new Date(event.timestamp),
      plateNumber: event.plateNumber.toUpperCase(),
      confidence: event.confidence,
      region: event.region,
      boundingBox: event.boundingBox,
      vehicleType: event.vehicleType,
      isWatchlisted: this.licensePlateWatchlist.has(event.plateNumber.toUpperCase()),
      metadata: event.metadata
    };

    // Store event
    await this.storeInOpenSearch(`${this.config.opensearchIndex}-video`, {
      ...processedEvent,
      type: 'license_plate',
      timestamp: processedEvent.timestamp.toISOString()
    });

    // Correlate with access control events
    const correlation = await this.correlateLicensePlateWithAccess(
      tenantId,
      processedEvent.plateNumber,
      processedEvent.timestamp
    );

    if (correlation) {
      processedEvent.metadata = {
        ...processedEvent.metadata,
        accessCorrelation: correlation
      };
    }

    // Generate alert if on watchlist
    if (processedEvent.isWatchlisted) {
      await this.generateLicensePlateAlert(tenantId, processedEvent);
    }

    // Broadcast real-time update
    await this.broadcastUpdate('license-plate', {
      tenantId,
      event: processedEvent
    });

    return processedEvent;
  }

  private async correlateLicensePlateWithAccess(
    tenantId: string,
    plateNumber: string,
    timestamp: Date
  ): Promise<any> {
    // Look for access events within 5 minutes
    const timeWindow = 5 * 60 * 1000; // 5 minutes
    const startTime = new Date(timestamp.getTime() - timeWindow);
    const endTime = new Date(timestamp.getTime() + timeWindow);

    const accessEvents = await this.prisma.accessControlEvent.findMany({
      where: {
        tenantId,
        timestamp: {
          gte: startTime,
          lte: endTime
        },
        metadata: {
          path: ['vehicleInfo', 'plateNumber'],
          equals: plateNumber
        }
      },
      include: {
        user: true,
        door: true
      }
    });

    if (accessEvents.length > 0) {
      return {
        matchedEvents: accessEvents.length,
        users: [...new Set(accessEvents.map(e => e.user?.name).filter(Boolean))],
        doors: [...new Set(accessEvents.map(e => e.door?.name).filter(Boolean))],
        timeCorrelation: accessEvents.map(e => ({
          eventTime: e.timestamp,
          timeDifference: Math.abs(e.timestamp.getTime() - timestamp.getTime()) / 1000
        }))
      };
    }

    return null;
  }

  private async generateLicensePlateAlert(
    tenantId: string,
    event: LicensePlateEvent
  ): Promise<void> {
    const alert = {
      id: this.generateId(),
      type: 'license_plate_watchlist',
      severity: 'high',
      title: 'Watchlisted Vehicle Detected',
      message: `Vehicle with plate ${event.plateNumber} on watchlist detected at camera ${event.cameraId}`,
      tenantId,
      entityId: event.plateNumber,
      entityType: 'vehicle',
      data: event,
      timestamp: new Date()
    };

    // Store alert
    await this.storeInOpenSearch(`${this.config.opensearchIndex}-alerts`, {
      ...alert,
      timestamp: alert.timestamp.toISOString()
    });

    // Broadcast critical alert
    await this.broadcastUpdate('watchlist-alert', alert);
  }

  updateWatchlist(plateNumbers: string[], action: 'add' | 'remove'): void {
    const normalizedPlates = plateNumbers.map(p => p.toUpperCase());
    
    if (action === 'add') {
      normalizedPlates.forEach(plate => this.licensePlateWatchlist.add(plate));
    } else {
      normalizedPlates.forEach(plate => this.licensePlateWatchlist.delete(plate));
    }
  }
}