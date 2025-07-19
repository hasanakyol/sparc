import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';
import { FaceRecognitionEvent } from '../types';

export class FaceRecognitionService extends BaseAnalyticsService {
  private faceDatabase: Map<string, { personId: string; features: number[]; metadata: any }> = new Map();
  private faceWatchlist: Set<string> = new Set();

  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
  }

  async processFaceRecognitionEvent(
    tenantId: string,
    event: any
  ): Promise<FaceRecognitionEvent> {
    const processedEvent: FaceRecognitionEvent = {
      id: this.generateId(),
      cameraId: event.cameraId,
      tenantId,
      timestamp: new Date(event.timestamp),
      confidence: event.confidence,
      boundingBox: event.boundingBox,
      features: event.features,
      isWatchlisted: false,
      metadata: event.metadata
    };

    // Process face recognition
    if (event.features) {
      const match = await this.matchFace(event.features);
      if (match) {
        processedEvent.personId = match.personId;
        processedEvent.isWatchlisted = this.faceWatchlist.has(match.personId);
        
        // Update person tracking
        await this.updatePersonTracking(tenantId, match.personId, event.cameraId);
      }
    }

    // Store event
    await this.storeInOpenSearch(`${this.config.opensearchIndex}-video`, {
      ...processedEvent,
      type: 'face_recognition',
      timestamp: processedEvent.timestamp.toISOString()
    });

    // Generate alert if on watchlist
    if (processedEvent.isWatchlisted) {
      await this.generateFaceRecognitionAlert(tenantId, processedEvent);
    }

    // Broadcast real-time update
    await this.broadcastUpdate('face-recognition', {
      tenantId,
      event: processedEvent
    });

    return processedEvent;
  }

  async enrollFace(
    tenantId: string,
    personId: string,
    imageData: string,
    metadata?: any
  ): Promise<{ success: boolean; personId: string }> {
    try {
      // Extract features from image (would call ML API)
      const features = await this.extractFaceFeatures(imageData);
      
      // Store in face database
      this.faceDatabase.set(personId, {
        personId,
        features,
        metadata: {
          ...metadata,
          enrolledAt: new Date(),
          tenantId
        }
      });

      // Store in database
      await this.prisma.person.update({
        where: { id: personId },
        data: {
          biometricData: {
            face: {
              enrolled: true,
              features,
              enrolledAt: new Date()
            }
          }
        }
      });

      this.logger.info('Face enrolled successfully', { tenantId, personId });

      return { success: true, personId };
    } catch (error) {
      this.logger.error('Face enrollment failed', { error, tenantId, personId });
      throw error;
    }
  }

  private async matchFace(features: number[]): Promise<{ personId: string; similarity: number } | null> {
    let bestMatch: { personId: string; similarity: number } | null = null;
    let highestSimilarity = 0;

    for (const [personId, data] of this.faceDatabase.entries()) {
      const similarity = this.calculateCosineSimilarity(features, data.features);
      
      if (similarity > 0.8 && similarity > highestSimilarity) {
        highestSimilarity = similarity;
        bestMatch = { personId, similarity };
      }
    }

    return bestMatch;
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

  private async extractFaceFeatures(imageData: string): Promise<number[]> {
    // In production, this would call the ML API
    // For now, return mock features
    return Array.from({ length: 128 }, () => Math.random());
  }

  private async updatePersonTracking(
    tenantId: string,
    personId: string,
    cameraId: string
  ): Promise<void> {
    const trackingKey = `person:tracking:${tenantId}:${personId}`;
    const trackingData = {
      cameraId,
      timestamp: new Date().toISOString(),
      location: await this.getCameraLocation(cameraId)
    };

    // Store in Redis with expiry
    await this.redis.lpush(trackingKey, JSON.stringify(trackingData));
    await this.redis.ltrim(trackingKey, 0, 99); // Keep last 100 sightings
    await this.redis.expire(trackingKey, 86400); // 24 hours
  }

  private async generateFaceRecognitionAlert(
    tenantId: string,
    event: FaceRecognitionEvent
  ): Promise<void> {
    const alert = {
      id: this.generateId(),
      type: 'face_recognition_watchlist',
      severity: 'high',
      title: 'Watchlisted Person Detected',
      message: `Person ${event.personId} on watchlist detected at camera ${event.cameraId}`,
      tenantId,
      entityId: event.personId,
      entityType: 'person',
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

  private async getCameraLocation(cameraId: string): Promise<any> {
    const camera = await this.prisma.camera.findUnique({
      where: { id: cameraId },
      include: {
        zone: {
          include: {
            floor: {
              include: {
                building: true
              }
            }
          }
        }
      }
    });

    if (!camera) return null;

    return {
      building: camera.zone?.floor?.building?.name,
      floor: camera.zone?.floor?.name,
      zone: camera.zone?.name,
      camera: camera.name
    };
  }

  updateWatchlist(personIds: string[], action: 'add' | 'remove'): void {
    if (action === 'add') {
      personIds.forEach(id => this.faceWatchlist.add(id));
    } else {
      personIds.forEach(id => this.faceWatchlist.delete(id));
    }
  }
}