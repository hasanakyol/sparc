import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';
import { VideoAnalyticsConfig, MLModelConfig } from '../types';

export class VideoAnalyticsService extends BaseAnalyticsService {
  private videoAnalyticsConfigs: Map<string, VideoAnalyticsConfig> = new Map();
  private mlModels: Map<string, MLModelConfig> = new Map();

  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
    this.initializeMLModels();
  }

  private async initializeMLModels(): Promise<void> {
    // Initialize ML models for video analytics
    if (this.config.mlApiUrl) {
      this.mlModels.set('face_recognition', {
        modelId: 'face_recognition_v1',
        modelType: 'face_recognition',
        version: '1.0.0',
        endpoint: `${this.config.mlApiUrl}/face`,
        apiKey: this.config.mlApiKey,
        confidence: 0.8,
        enabled: true
      });

      this.mlModels.set('license_plate', {
        modelId: 'license_plate_v1',
        modelType: 'license_plate',
        version: '1.0.0',
        endpoint: `${this.config.mlApiUrl}/license-plate`,
        apiKey: this.config.mlApiKey,
        confidence: 0.85,
        enabled: true
      });

      this.mlModels.set('behavior_analysis', {
        modelId: 'behavior_analysis_v1',
        modelType: 'behavior_analysis',
        version: '1.0.0',
        endpoint: `${this.config.mlApiUrl}/behavior`,
        apiKey: this.config.mlApiKey,
        confidence: 0.75,
        enabled: true
      });
    }
  }

  async configureVideoAnalytics(
    tenantId: string,
    config: VideoAnalyticsConfig
  ): Promise<VideoAnalyticsConfig> {
    const cacheKey = `video-config:${tenantId}:${config.cameraId}`;

    // Validate configuration
    this.validateVideoConfig(config);

    // Store configuration
    this.videoAnalyticsConfigs.set(config.cameraId, config);

    // Store in database
    await this.prisma.camera.update({
      where: { id: config.cameraId },
      data: {
        analyticsConfig: config as any
      }
    });

    // Store in Redis for quick access
    await this.redis.set(cacheKey, JSON.stringify(config), 'EX', 3600);

    // Broadcast configuration update
    await this.broadcastUpdate('video-config-updated', {
      tenantId,
      cameraId: config.cameraId,
      config
    });

    this.logger.info('Video analytics configured', { 
      tenantId, 
      cameraId: config.cameraId,
      features: {
        faceRecognition: config.faceRecognition.enabled,
        licensePlate: config.licensePlateRecognition.enabled,
        behavior: Object.values(config.behaviorAnalysis).some(v => v === true)
      }
    });

    return config;
  }

  async getVideoAnalyticsConfig(
    tenantId: string,
    cameraId: string
  ): Promise<VideoAnalyticsConfig | null> {
    const cacheKey = `video-config:${tenantId}:${cameraId}`;

    // Check cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Check in-memory map
    if (this.videoAnalyticsConfigs.has(cameraId)) {
      return this.videoAnalyticsConfigs.get(cameraId)!;
    }

    // Load from database
    const camera = await this.prisma.camera.findFirst({
      where: { id: cameraId, tenantId }
    });

    if (camera?.analyticsConfig) {
      const config = camera.analyticsConfig as VideoAnalyticsConfig;
      this.videoAnalyticsConfigs.set(cameraId, config);
      await this.redis.set(cacheKey, JSON.stringify(config), 'EX', 3600);
      return config;
    }

    return null;
  }

  isBehaviorAnalysisEnabled(config: VideoAnalyticsConfig): boolean {
    return Object.values(config.behaviorAnalysis).some(v => v === true);
  }

  getMLModel(modelType: string): MLModelConfig | undefined {
    return this.mlModels.get(modelType);
  }

  private validateVideoConfig(config: VideoAnalyticsConfig): void {
    // Validate confidence thresholds
    if (config.faceRecognition.confidence < 0 || config.faceRecognition.confidence > 1) {
      throw new Error('Face recognition confidence must be between 0 and 1');
    }

    if (config.licensePlateRecognition.confidence < 0 || config.licensePlateRecognition.confidence > 1) {
      throw new Error('License plate confidence must be between 0 and 1');
    }

    // Validate zones
    if (config.zones.length > 0) {
      for (const zone of config.zones) {
        if (zone.coordinates.length < 3) {
          throw new Error(`Zone ${zone.name} must have at least 3 coordinates`);
        }

        // Validate coordinates are within 0-1 range
        for (const coord of zone.coordinates) {
          if (coord.x < 0 || coord.x > 1 || coord.y < 0 || coord.y > 1) {
            throw new Error(`Zone ${zone.name} coordinates must be between 0 and 1`);
          }
        }
      }
    }

    // Validate behavior thresholds
    if (config.behaviorAnalysis.loiteringThreshold < 30 || config.behaviorAnalysis.loiteringThreshold > 3600) {
      throw new Error('Loitering threshold must be between 30 and 3600 seconds');
    }

    if (config.behaviorAnalysis.crowdThreshold < 5 || config.behaviorAnalysis.crowdThreshold > 100) {
      throw new Error('Crowd threshold must be between 5 and 100 people');
    }
  }
}