import { CacheService } from './cacheService';
import { Camera, VideoRecording, VideoStream, PrivacyMask } from '../types';
import { logger } from '../logger';

export interface VideoCacheConfig {
  ttl?: {
    camera?: number;
    recording?: number;
    stream?: number;
    thumbnail?: number;
    metadata?: number;
    privacyMask?: number;
  };
}

export class VideoCache {
  private cache: CacheService;
  private config: VideoCacheConfig;
  private namespace = 'video';

  constructor(cache: CacheService, config: VideoCacheConfig = {}) {
    this.cache = cache;
    this.config = {
      ttl: {
        camera: config.ttl?.camera || 3600, // 1 hour
        recording: config.ttl?.recording || 1800, // 30 minutes
        stream: config.ttl?.stream || 300, // 5 minutes
        thumbnail: config.ttl?.thumbnail || 3600, // 1 hour
        metadata: config.ttl?.metadata || 1800, // 30 minutes
        privacyMask: config.ttl?.privacyMask || 3600, // 1 hour
      },
    };
  }

  /**
   * Get camera by ID
   */
  async getCamera(cameraId: string): Promise<Camera | null> {
    const key = `camera:${cameraId}`;
    return this.cache.get<Camera>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.camera,
      tags: [`camera:${cameraId}`],
    });
  }

  /**
   * Set camera
   */
  async setCamera(camera: Camera): Promise<boolean> {
    const key = `camera:${camera.id}`;
    return this.cache.set(key, camera, {
      prefix: this.namespace,
      ttl: this.config.ttl?.camera,
      tags: [`camera:${camera.id}`, `floor:${camera.floor_id}`],
    });
  }

  /**
   * Get cameras by floor
   */
  async getCamerasByFloor(floorId: string): Promise<Camera[] | null> {
    const key = `floor:${floorId}:cameras`;
    return this.cache.get<Camera[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.camera,
      tags: [`floor:${floorId}`],
    });
  }

  /**
   * Set cameras for a floor
   */
  async setCamerasByFloor(floorId: string, cameras: Camera[]): Promise<boolean> {
    const key = `floor:${floorId}:cameras`;
    return this.cache.set(key, cameras, {
      prefix: this.namespace,
      ttl: this.config.ttl?.camera,
      tags: [`floor:${floorId}`],
    });
  }

  /**
   * Get video recording metadata
   */
  async getRecording(recordingId: string): Promise<VideoRecording | null> {
    const key = `recording:${recordingId}`;
    return this.cache.get<VideoRecording>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.recording,
      tags: [`recording:${recordingId}`],
    });
  }

  /**
   * Set video recording metadata
   */
  async setRecording(recording: VideoRecording): Promise<boolean> {
    const key = `recording:${recording.id}`;
    return this.cache.set(key, recording, {
      prefix: this.namespace,
      ttl: this.config.ttl?.recording,
      tags: [
        `recording:${recording.id}`,
        `camera:${recording.camera_id}`,
        `tenant:${recording.tenant_id}`,
      ],
    });
  }

  /**
   * Get recordings by camera and time range
   */
  async getRecordingsByTimeRange(
    cameraId: string,
    startTime: Date,
    endTime: Date
  ): Promise<VideoRecording[] | null> {
    const key = `camera:${cameraId}:recordings:${startTime.getTime()}-${endTime.getTime()}`;
    return this.cache.get<VideoRecording[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.recording,
      tags: [`camera:${cameraId}`],
    });
  }

  /**
   * Set recordings for a time range
   */
  async setRecordingsByTimeRange(
    cameraId: string,
    startTime: Date,
    endTime: Date,
    recordings: VideoRecording[]
  ): Promise<boolean> {
    const key = `camera:${cameraId}:recordings:${startTime.getTime()}-${endTime.getTime()}`;
    return this.cache.set(key, recordings, {
      prefix: this.namespace,
      ttl: this.config.ttl?.recording,
      tags: [`camera:${cameraId}`],
    });
  }

  /**
   * Get video stream URL
   */
  async getStreamUrl(cameraId: string, resolution: 'high' | 'medium' | 'low'): Promise<string | null> {
    const key = `stream:${cameraId}:${resolution}`;
    return this.cache.get<string>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.stream,
      tags: [`camera:${cameraId}`, 'stream'],
    });
  }

  /**
   * Set video stream URL
   */
  async setStreamUrl(
    cameraId: string,
    resolution: 'high' | 'medium' | 'low',
    url: string
  ): Promise<boolean> {
    const key = `stream:${cameraId}:${resolution}`;
    return this.cache.set(key, url, {
      prefix: this.namespace,
      ttl: this.config.ttl?.stream,
      tags: [`camera:${cameraId}`, 'stream'],
    });
  }

  /**
   * Get video stream metadata
   */
  async getStreamMetadata(cameraId: string): Promise<VideoStream | null> {
    const key = `stream:${cameraId}:metadata`;
    return this.cache.get<VideoStream>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metadata,
      tags: [`camera:${cameraId}`, 'stream'],
    });
  }

  /**
   * Set video stream metadata
   */
  async setStreamMetadata(stream: VideoStream): Promise<boolean> {
    const key = `stream:${stream.camera_id}:metadata`;
    return this.cache.set(key, stream, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metadata,
      tags: [`camera:${stream.camera_id}`, 'stream'],
    });
  }

  /**
   * Get video thumbnail
   */
  async getThumbnail(cameraId: string, timestamp?: Date): Promise<Buffer | null> {
    const time = timestamp ? timestamp.getTime() : 'latest';
    const key = `thumbnail:${cameraId}:${time}`;
    
    const data = await this.cache.get<string>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.thumbnail,
      tags: [`camera:${cameraId}`, 'thumbnail'],
    });

    return data ? Buffer.from(data, 'base64') : null;
  }

  /**
   * Set video thumbnail
   */
  async setThumbnail(
    cameraId: string,
    thumbnail: Buffer,
    timestamp?: Date
  ): Promise<boolean> {
    const time = timestamp ? timestamp.getTime() : 'latest';
    const key = `thumbnail:${cameraId}:${time}`;
    
    return this.cache.set(key, thumbnail.toString('base64'), {
      prefix: this.namespace,
      ttl: this.config.ttl?.thumbnail,
      tags: [`camera:${cameraId}`, 'thumbnail'],
      compress: false, // Already compressed as image
    });
  }

  /**
   * Get privacy masks for camera
   */
  async getPrivacyMasks(cameraId: string): Promise<PrivacyMask[] | null> {
    const key = `camera:${cameraId}:privacy-masks`;
    return this.cache.get<PrivacyMask[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.privacyMask,
      tags: [`camera:${cameraId}`, 'privacy-mask'],
    });
  }

  /**
   * Set privacy masks for camera
   */
  async setPrivacyMasks(cameraId: string, masks: PrivacyMask[]): Promise<boolean> {
    const key = `camera:${cameraId}:privacy-masks`;
    return this.cache.set(key, masks, {
      prefix: this.namespace,
      ttl: this.config.ttl?.privacyMask,
      tags: [`camera:${cameraId}`, 'privacy-mask'],
    });
  }

  /**
   * Get video analytics metadata
   */
  async getAnalyticsMetadata(
    cameraId: string,
    analyticsType: string
  ): Promise<any | null> {
    const key = `analytics:${cameraId}:${analyticsType}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metadata,
      tags: [`camera:${cameraId}`, 'analytics', `analytics:${analyticsType}`],
    });
  }

  /**
   * Set video analytics metadata
   */
  async setAnalyticsMetadata(
    cameraId: string,
    analyticsType: string,
    metadata: any
  ): Promise<boolean> {
    const key = `analytics:${cameraId}:${analyticsType}`;
    return this.cache.set(key, metadata, {
      prefix: this.namespace,
      ttl: this.config.ttl?.metadata,
      tags: [`camera:${cameraId}`, 'analytics', `analytics:${analyticsType}`],
    });
  }

  /**
   * Get HLS manifest
   */
  async getHLSManifest(cameraId: string): Promise<string | null> {
    const key = `hls:${cameraId}:manifest`;
    return this.cache.get<string>(key, {
      prefix: this.namespace,
      ttl: 60, // 1 minute - HLS manifests update frequently
      tags: [`camera:${cameraId}`, 'hls'],
    });
  }

  /**
   * Set HLS manifest
   */
  async setHLSManifest(cameraId: string, manifest: string): Promise<boolean> {
    const key = `hls:${cameraId}:manifest`;
    return this.cache.set(key, manifest, {
      prefix: this.namespace,
      ttl: 60, // 1 minute
      tags: [`camera:${cameraId}`, 'hls'],
      compress: false, // Manifests are small text files
    });
  }

  /**
   * Get video segment info
   */
  async getVideoSegment(segmentId: string): Promise<{
    url: string;
    duration: number;
    size: number;
  } | null> {
    const key = `segment:${segmentId}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: 300, // 5 minutes
      tags: ['segment'],
    });
  }

  /**
   * Set video segment info
   */
  async setVideoSegment(
    segmentId: string,
    segment: { url: string; duration: number; size: number }
  ): Promise<boolean> {
    const key = `segment:${segmentId}`;
    return this.cache.set(key, segment, {
      prefix: this.namespace,
      ttl: 300, // 5 minutes
      tags: ['segment'],
    });
  }

  /**
   * Invalidate camera cache
   */
  async invalidateCamera(cameraId: string): Promise<void> {
    await this.cache.invalidateByTags([`camera:${cameraId}`]);
    logger.info('Invalidated camera cache', { cameraId });
  }

  /**
   * Invalidate all stream URLs
   */
  async invalidateStreams(): Promise<void> {
    await this.cache.invalidateByTags(['stream']);
    logger.info('Invalidated all stream caches');
  }

  /**
   * Invalidate thumbnails for camera
   */
  async invalidateThumbnails(cameraId: string): Promise<void> {
    await this.cache.invalidateByTags([`camera:${cameraId}`, 'thumbnail']);
    logger.info('Invalidated thumbnail cache', { cameraId });
  }

  /**
   * Get camera status summary
   */
  async getCameraStatusSummary(tenantId: string): Promise<{
    online: number;
    offline: number;
    error: number;
    maintenance: number;
  } | null> {
    const key = `tenant:${tenantId}:camera-status`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: 60, // 1 minute
      tags: [`tenant:${tenantId}`, 'status'],
    });
  }

  /**
   * Set camera status summary
   */
  async setCameraStatusSummary(
    tenantId: string,
    status: {
      online: number;
      offline: number;
      error: number;
      maintenance: number;
    }
  ): Promise<boolean> {
    const key = `tenant:${tenantId}:camera-status`;
    return this.cache.set(key, status, {
      prefix: this.namespace,
      ttl: 60, // 1 minute
      tags: [`tenant:${tenantId}`, 'status'],
    });
  }

  /**
   * Warm up video cache
   */
  async warmup(data: {
    cameras?: Camera[];
    recordings?: VideoRecording[];
    privacyMasks?: Array<{ cameraId: string; masks: PrivacyMask[] }>;
  }): Promise<void> {
    const operations = [];

    if (data.cameras) {
      for (const camera of data.cameras) {
        operations.push(this.setCamera(camera));
      }
    }

    if (data.recordings) {
      for (const recording of data.recordings) {
        operations.push(this.setRecording(recording));
      }
    }

    if (data.privacyMasks) {
      for (const item of data.privacyMasks) {
        operations.push(this.setPrivacyMasks(item.cameraId, item.masks));
      }
    }

    await Promise.all(operations);
    logger.info('Video cache warmed up', {
      cameras: data.cameras?.length || 0,
      recordings: data.recordings?.length || 0,
      privacyMasks: data.privacyMasks?.length || 0,
    });
  }
}