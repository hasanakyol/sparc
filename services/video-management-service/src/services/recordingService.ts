import { S3Client, PutObjectCommand, DeleteObjectCommand, HeadObjectCommand } from '@aws-sdk/client-s3';
import { PrismaClient } from '@prisma/client';
import { EventEmitter } from 'events';
import { createWriteStream, createReadStream, existsSync, mkdirSync, readdirSync, statSync, unlinkSync } from 'fs';
import { join, dirname } from 'path';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';

// Types for video recording
interface Camera {
  id: string;
  tenantId: string;
  name: string;
  streamUrl: string;
  buildingId: string;
  floorId?: string;
  zoneId?: string;
  isActive: boolean;
  recordingEnabled: boolean;
  motionDetectionEnabled: boolean;
  recordingQuality: 'low' | 'medium' | 'high';
  retentionDays: number;
}

interface VideoRecording {
  id: string;
  tenantId: string;
  cameraId: string;
  filename: string;
  s3Key: string;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  fileSize?: number;
  recordingType: 'scheduled' | 'motion' | 'manual' | 'event_triggered';
  triggerEventId?: string;
  status: 'recording' | 'completed' | 'failed' | 'archived' | 'offline_pending';
  metadata: Record<string, any>;
  checksum?: string;
  isOffline: boolean;
  syncedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

interface RecordingTrigger {
  id: string;
  tenantId: string;
  cameraId: string;
  triggerType: 'motion' | 'access_event' | 'schedule' | 'manual';
  triggerData: Record<string, any>;
  preRecordSeconds: number;
  postRecordSeconds: number;
  isActive: boolean;
}

interface TenantStorageQuota {
  tenantId: string;
  maxStorageGB: number;
  currentStorageGB: number;
  retentionDays: number;
  autoArchiveEnabled: boolean;
  archiveAfterDays: number;
}

interface OfflineRecording {
  id: string;
  cameraId: string;
  localPath: string;
  startTime: Date;
  endTime?: Date;
  metadata: Record<string, any>;
  syncStatus: 'pending' | 'syncing' | 'completed' | 'failed';
}

interface RecordingConfig {
  s3Bucket: string;
  s3Region: string;
  localStoragePath: string;
  maxOfflineStorageGB: number;
  defaultRetentionDays: number;
  motionDetectionSensitivity: number;
  recordingChunkDurationMinutes: number;
  maxConcurrentRecordings: number;
}

class RecordingService extends EventEmitter {
  private prisma: PrismaClient;
  private s3Client: S3Client;
  private config: RecordingConfig;
  private activeRecordings: Map<string, NodeJS.Timeout> = new Map();
  private offlineRecordings: Map<string, OfflineRecording> = new Map();
  private isOnline: boolean = true;
  private syncQueue: OfflineRecording[] = [];
  private storageQuotas: Map<string, TenantStorageQuota> = new Map();

  constructor(config: RecordingConfig) {
    super();
    this.config = config;
    this.prisma = new PrismaClient();
    this.s3Client = new S3Client({ region: config.s3Region });
    
    // Ensure local storage directory exists
    if (!existsSync(config.localStoragePath)) {
      mkdirSync(config.localStoragePath, { recursive: true });
    }

    // Initialize offline recording recovery
    this.initializeOfflineRecovery();
    
    // Start background tasks
    this.startBackgroundTasks();
  }

  /**
   * Start a new recording for a camera
   */
  async startRecording(
    cameraId: string,
    tenantId: string,
    recordingType: VideoRecording['recordingType'],
    triggerEventId?: string,
    duration?: number
  ): Promise<string> {
    try {
      // Check if camera exists and is active
      const camera = await this.getCamera(cameraId, tenantId);
      if (!camera || !camera.isActive || !camera.recordingEnabled) {
        throw new Error(`Camera ${cameraId} is not available for recording`);
      }

      // Check storage quota
      await this.checkStorageQuota(tenantId);

      // Generate recording ID and metadata
      const recordingId = uuidv4();
      const startTime = new Date();
      const filename = this.generateFilename(camera, startTime, recordingType);
      const s3Key = this.generateS3Key(tenantId, camera.id, filename);

      // Create recording record
      const recording: Omit<VideoRecording, 'createdAt' | 'updatedAt'> = {
        id: recordingId,
        tenantId,
        cameraId,
        filename,
        s3Key,
        startTime,
        recordingType,
        triggerEventId,
        status: 'recording',
        metadata: {
          quality: camera.recordingQuality,
          streamUrl: camera.streamUrl,
          buildingId: camera.buildingId,
          floorId: camera.floorId,
          zoneId: camera.zoneId
        },
        isOffline: !this.isOnline,
        createdAt: startTime,
        updatedAt: startTime
      };

      // Save to database
      await this.saveRecording(recording);

      // Start actual recording process
      if (this.isOnline) {
        await this.startOnlineRecording(recording, camera, duration);
      } else {
        await this.startOfflineRecording(recording, camera, duration);
      }

      this.emit('recordingStarted', { recordingId, cameraId, tenantId });
      return recordingId;

    } catch (error) {
      console.error(`Failed to start recording for camera ${cameraId}:`, error);
      throw error;
    }
  }

  /**
   * Stop an active recording
   */
  async stopRecording(recordingId: string, tenantId: string): Promise<void> {
    try {
      const recording = await this.getRecording(recordingId, tenantId);
      if (!recording) {
        throw new Error(`Recording ${recordingId} not found`);
      }

      if (recording.status !== 'recording') {
        throw new Error(`Recording ${recordingId} is not active`);
      }

      // Stop the recording process
      const timeout = this.activeRecordings.get(recordingId);
      if (timeout) {
        clearTimeout(timeout);
        this.activeRecordings.delete(recordingId);
      }

      // Finalize recording
      await this.finalizeRecording(recordingId, tenantId);
      
      this.emit('recordingStopped', { recordingId, tenantId });

    } catch (error) {
      console.error(`Failed to stop recording ${recordingId}:`, error);
      throw error;
    }
  }

  /**
   * Handle motion detection trigger
   */
  async handleMotionDetection(cameraId: string, tenantId: string, motionData: any): Promise<void> {
    try {
      const camera = await this.getCamera(cameraId, tenantId);
      if (!camera?.motionDetectionEnabled) {
        return;
      }

      // Check if already recording due to motion
      const existingRecording = await this.getActiveRecordingForCamera(cameraId, tenantId);
      if (existingRecording && existingRecording.recordingType === 'motion') {
        // Extend existing recording
        await this.extendRecording(existingRecording.id, tenantId, 300); // 5 minutes
        return;
      }

      // Start new motion-triggered recording
      const recordingId = await this.startRecording(
        cameraId,
        tenantId,
        'motion',
        undefined,
        600 // 10 minutes default for motion
      );

      this.emit('motionRecordingStarted', { recordingId, cameraId, tenantId, motionData });

    } catch (error) {
      console.error(`Failed to handle motion detection for camera ${cameraId}:`, error);
    }
  }

  /**
   * Handle access control event trigger
   */
  async handleAccessEvent(eventId: string, cameraIds: string[], tenantId: string): Promise<void> {
    try {
      const recordingPromises = cameraIds.map(async (cameraId) => {
        const camera = await this.getCamera(cameraId, tenantId);
        if (!camera?.recordingEnabled) {
          return null;
        }

        // Start event-triggered recording with pre/post buffer
        return this.startRecording(
          cameraId,
          tenantId,
          'event_triggered',
          eventId,
          120 // 2 minutes for access events
        );
      });

      const recordingIds = await Promise.all(recordingPromises);
      const validRecordingIds = recordingIds.filter(id => id !== null);

      this.emit('accessEventRecordingStarted', { 
        eventId, 
        recordingIds: validRecordingIds, 
        tenantId 
      });

    } catch (error) {
      console.error(`Failed to handle access event ${eventId}:`, error);
    }
  }

  /**
   * Get recordings with filtering and pagination
   */
  async getRecordings(
    tenantId: string,
    filters: {
      cameraId?: string;
      buildingId?: string;
      floorId?: string;
      startDate?: Date;
      endDate?: Date;
      recordingType?: VideoRecording['recordingType'];
      status?: VideoRecording['status'];
    },
    pagination: { page: number; limit: number }
  ): Promise<{ recordings: VideoRecording[]; total: number }> {
    try {
      // Build query conditions
      const where: any = { tenantId };
      
      if (filters.cameraId) where.cameraId = filters.cameraId;
      if (filters.recordingType) where.recordingType = filters.recordingType;
      if (filters.status) where.status = filters.status;
      if (filters.startDate || filters.endDate) {
        where.startTime = {};
        if (filters.startDate) where.startTime.gte = filters.startDate;
        if (filters.endDate) where.startTime.lte = filters.endDate;
      }

      // Handle building/floor filters through camera relationship
      if (filters.buildingId || filters.floorId) {
        where.camera = {};
        if (filters.buildingId) where.camera.buildingId = filters.buildingId;
        if (filters.floorId) where.camera.floorId = filters.floorId;
      }

      const [recordings, total] = await Promise.all([
        this.prisma.videoRecording.findMany({
          where,
          include: {
            camera: {
              select: {
                name: true,
                buildingId: true,
                floorId: true,
                zoneId: true
              }
            }
          },
          orderBy: { startTime: 'desc' },
          skip: (pagination.page - 1) * pagination.limit,
          take: pagination.limit
        }),
        this.prisma.videoRecording.count({ where })
      ]);

      return { recordings: recordings as VideoRecording[], total };

    } catch (error) {
      console.error(`Failed to get recordings for tenant ${tenantId}:`, error);
      throw error;
    }
  }

  /**
   * Export recording with watermark and chain of custody
   */
  async exportRecording(
    recordingId: string,
    tenantId: string,
    exportOptions: {
      format: 'mp4' | 'avi';
      quality: 'original' | 'high' | 'medium' | 'low';
      watermark?: string;
      startTime?: Date;
      endTime?: Date;
    }
  ): Promise<{ exportId: string; downloadUrl: string }> {
    try {
      const recording = await this.getRecording(recordingId, tenantId);
      if (!recording) {
        throw new Error(`Recording ${recordingId} not found`);
      }

      const exportId = uuidv4();
      const exportFilename = `export_${exportId}.${exportOptions.format}`;
      const exportS3Key = `exports/${tenantId}/${exportFilename}`;

      // Create export log entry
      await this.createExportLog(exportId, recordingId, tenantId, exportOptions);

      // Process video export (this would integrate with video processing service)
      const downloadUrl = await this.processVideoExport(
        recording,
        exportS3Key,
        exportOptions
      );

      this.emit('recordingExported', { exportId, recordingId, tenantId });

      return { exportId, downloadUrl };

    } catch (error) {
      console.error(`Failed to export recording ${recordingId}:`, error);
      throw error;
    }
  }

  /**
   * Archive old recordings based on retention policies
   */
  async archiveOldRecordings(): Promise<void> {
    try {
      const tenants = await this.getAllTenants();

      for (const tenant of tenants) {
        const quota = await this.getStorageQuota(tenant.id);
        if (!quota.autoArchiveEnabled) continue;

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - quota.archiveAfterDays);

        const oldRecordings = await this.prisma.videoRecording.findMany({
          where: {
            tenantId: tenant.id,
            status: 'completed',
            startTime: { lt: cutoffDate }
          }
        });

        for (const recording of oldRecordings) {
          await this.archiveRecording(recording.id, tenant.id);
        }
      }

    } catch (error) {
      console.error('Failed to archive old recordings:', error);
    }
  }

  /**
   * Delete recordings based on retention policies
   */
  async deleteExpiredRecordings(): Promise<void> {
    try {
      const tenants = await this.getAllTenants();

      for (const tenant of tenants) {
        const quota = await this.getStorageQuota(tenant.id);
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - quota.retentionDays);

        const expiredRecordings = await this.prisma.videoRecording.findMany({
          where: {
            tenantId: tenant.id,
            startTime: { lt: cutoffDate },
            status: { in: ['completed', 'archived'] }
          }
        });

        for (const recording of expiredRecordings) {
          await this.deleteRecording(recording.id, tenant.id);
        }
      }

    } catch (error) {
      console.error('Failed to delete expired recordings:', error);
    }
  }

  /**
   * Sync offline recordings when connectivity is restored
   */
  async syncOfflineRecordings(): Promise<void> {
    if (!this.isOnline) return;

    try {
      const pendingRecordings = await this.prisma.videoRecording.findMany({
        where: {
          status: 'offline_pending',
          isOffline: true
        }
      });

      for (const recording of pendingRecordings) {
        await this.syncSingleOfflineRecording(recording);
      }

      // Sync local offline recordings
      for (const [recordingId, offlineRecording] of this.offlineRecordings) {
        if (offlineRecording.syncStatus === 'pending') {
          await this.syncLocalOfflineRecording(offlineRecording);
        }
      }

    } catch (error) {
      console.error('Failed to sync offline recordings:', error);
    }
  }

  /**
   * Set online/offline status
   */
  setOnlineStatus(isOnline: boolean): void {
    const wasOffline = !this.isOnline;
    this.isOnline = isOnline;

    if (isOnline && wasOffline) {
      // Connectivity restored, start syncing
      this.syncOfflineRecordings();
      this.emit('connectivityRestored');
    } else if (!isOnline) {
      this.emit('connectivityLost');
    }
  }

  /**
   * Get storage usage for a tenant
   */
  async getStorageUsage(tenantId: string): Promise<{
    currentStorageGB: number;
    maxStorageGB: number;
    recordingCount: number;
    oldestRecording?: Date;
    newestRecording?: Date;
  }> {
    try {
      const [recordings, quota] = await Promise.all([
        this.prisma.videoRecording.findMany({
          where: { tenantId },
          select: {
            fileSize: true,
            startTime: true
          }
        }),
        this.getStorageQuota(tenantId)
      ]);

      const totalBytes = recordings.reduce((sum, r) => sum + (r.fileSize || 0), 0);
      const currentStorageGB = totalBytes / (1024 * 1024 * 1024);

      const dates = recordings.map(r => r.startTime).sort();
      
      return {
        currentStorageGB,
        maxStorageGB: quota.maxStorageGB,
        recordingCount: recordings.length,
        oldestRecording: dates[0],
        newestRecording: dates[dates.length - 1]
      };

    } catch (error) {
      console.error(`Failed to get storage usage for tenant ${tenantId}:`, error);
      throw error;
    }
  }

  // Private helper methods

  private async startOnlineRecording(
    recording: Omit<VideoRecording, 'createdAt' | 'updatedAt'>,
    camera: Camera,
    duration?: number
  ): Promise<void> {
    // This would integrate with actual video capture/streaming service
    // For now, simulate the recording process
    
    if (duration) {
      const timeout = setTimeout(async () => {
        await this.finalizeRecording(recording.id, recording.tenantId);
        this.activeRecordings.delete(recording.id);
      }, duration * 1000);
      
      this.activeRecordings.set(recording.id, timeout);
    }
  }

  private async startOfflineRecording(
    recording: Omit<VideoRecording, 'createdAt' | 'updatedAt'>,
    camera: Camera,
    duration?: number
  ): Promise<void> {
    const localPath = join(
      this.config.localStoragePath,
      recording.tenantId,
      recording.filename
    );

    // Ensure directory exists
    mkdirSync(dirname(localPath), { recursive: true });

    const offlineRecording: OfflineRecording = {
      id: recording.id,
      cameraId: camera.id,
      localPath,
      startTime: recording.startTime,
      metadata: recording.metadata,
      syncStatus: 'pending'
    };

    this.offlineRecordings.set(recording.id, offlineRecording);

    // Start local recording process
    if (duration) {
      const timeout = setTimeout(async () => {
        offlineRecording.endTime = new Date();
        await this.finalizeOfflineRecording(recording.id);
        this.activeRecordings.delete(recording.id);
      }, duration * 1000);
      
      this.activeRecordings.set(recording.id, timeout);
    }
  }

  private async finalizeRecording(recordingId: string, tenantId: string): Promise<void> {
    const endTime = new Date();
    const recording = await this.getRecording(recordingId, tenantId);
    
    if (!recording) return;

    const duration = Math.floor((endTime.getTime() - recording.startTime.getTime()) / 1000);
    
    // Calculate file size and checksum (would be actual values in real implementation)
    const fileSize = Math.floor(Math.random() * 1000000000); // Simulated
    const checksum = createHash('sha256').update(recordingId).digest('hex');

    await this.prisma.videoRecording.update({
      where: { id: recordingId },
      data: {
        endTime,
        duration,
        fileSize,
        checksum,
        status: 'completed',
        updatedAt: endTime
      }
    });

    // Update storage quota
    await this.updateStorageUsage(tenantId, fileSize);
  }

  private async finalizeOfflineRecording(recordingId: string): Promise<void> {
    const offlineRecording = this.offlineRecordings.get(recordingId);
    if (!offlineRecording) return;

    offlineRecording.endTime = new Date();
    
    // Update database record
    await this.prisma.videoRecording.update({
      where: { id: recordingId },
      data: {
        endTime: offlineRecording.endTime,
        status: 'offline_pending',
        updatedAt: new Date()
      }
    });
  }

  private async syncSingleOfflineRecording(recording: VideoRecording): Promise<void> {
    try {
      const offlineRecording = this.offlineRecordings.get(recording.id);
      if (!offlineRecording || !existsSync(offlineRecording.localPath)) {
        return;
      }

      // Upload to S3
      const fileStream = createReadStream(offlineRecording.localPath);
      const uploadCommand = new PutObjectCommand({
        Bucket: this.config.s3Bucket,
        Key: recording.s3Key,
        Body: fileStream,
        Metadata: {
          recordingId: recording.id,
          tenantId: recording.tenantId,
          cameraId: recording.cameraId
        }
      });

      await this.s3Client.send(uploadCommand);

      // Update database
      await this.prisma.videoRecording.update({
        where: { id: recording.id },
        data: {
          status: 'completed',
          isOffline: false,
          syncedAt: new Date(),
          updatedAt: new Date()
        }
      });

      // Clean up local file
      unlinkSync(offlineRecording.localPath);
      this.offlineRecordings.delete(recording.id);

      this.emit('offlineRecordingSynced', { recordingId: recording.id });

    } catch (error) {
      console.error(`Failed to sync offline recording ${recording.id}:`, error);
      
      // Mark as failed
      await this.prisma.videoRecording.update({
        where: { id: recording.id },
        data: {
          status: 'failed',
          updatedAt: new Date()
        }
      });
    }
  }

  private async syncLocalOfflineRecording(offlineRecording: OfflineRecording): Promise<void> {
    offlineRecording.syncStatus = 'syncing';
    
    try {
      // Find corresponding database record
      const recording = await this.prisma.videoRecording.findUnique({
        where: { id: offlineRecording.id }
      });

      if (recording) {
        await this.syncSingleOfflineRecording(recording as VideoRecording);
      }

      offlineRecording.syncStatus = 'completed';

    } catch (error) {
      console.error(`Failed to sync local offline recording ${offlineRecording.id}:`, error);
      offlineRecording.syncStatus = 'failed';
    }
  }

  private async archiveRecording(recordingId: string, tenantId: string): Promise<void> {
    try {
      // Move to archive storage (could be Glacier, etc.)
      await this.prisma.videoRecording.update({
        where: { id: recordingId },
        data: {
          status: 'archived',
          updatedAt: new Date()
        }
      });

      this.emit('recordingArchived', { recordingId, tenantId });

    } catch (error) {
      console.error(`Failed to archive recording ${recordingId}:`, error);
    }
  }

  private async deleteRecording(recordingId: string, tenantId: string): Promise<void> {
    try {
      const recording = await this.getRecording(recordingId, tenantId);
      if (!recording) return;

      // Delete from S3
      if (recording.s3Key) {
        const deleteCommand = new DeleteObjectCommand({
          Bucket: this.config.s3Bucket,
          Key: recording.s3Key
        });
        await this.s3Client.send(deleteCommand);
      }

      // Delete from database
      await this.prisma.videoRecording.delete({
        where: { id: recordingId }
      });

      // Update storage usage
      if (recording.fileSize) {
        await this.updateStorageUsage(tenantId, -recording.fileSize);
      }

      this.emit('recordingDeleted', { recordingId, tenantId });

    } catch (error) {
      console.error(`Failed to delete recording ${recordingId}:`, error);
    }
  }

  private async getCamera(cameraId: string, tenantId: string): Promise<Camera | null> {
    try {
      const camera = await this.prisma.camera.findFirst({
        where: { id: cameraId, tenantId }
      });
      return camera as Camera | null;
    } catch (error) {
      console.error(`Failed to get camera ${cameraId}:`, error);
      return null;
    }
  }

  private async getRecording(recordingId: string, tenantId: string): Promise<VideoRecording | null> {
    try {
      const recording = await this.prisma.videoRecording.findFirst({
        where: { id: recordingId, tenantId }
      });
      return recording as VideoRecording | null;
    } catch (error) {
      console.error(`Failed to get recording ${recordingId}:`, error);
      return null;
    }
  }

  private async saveRecording(recording: Omit<VideoRecording, 'createdAt' | 'updatedAt'>): Promise<void> {
    await this.prisma.videoRecording.create({
      data: {
        ...recording,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    });
  }

  private async getActiveRecordingForCamera(cameraId: string, tenantId: string): Promise<VideoRecording | null> {
    try {
      const recording = await this.prisma.videoRecording.findFirst({
        where: {
          cameraId,
          tenantId,
          status: 'recording'
        }
      });
      return recording as VideoRecording | null;
    } catch (error) {
      console.error(`Failed to get active recording for camera ${cameraId}:`, error);
      return null;
    }
  }

  private async extendRecording(recordingId: string, tenantId: string, additionalSeconds: number): Promise<void> {
    const timeout = this.activeRecordings.get(recordingId);
    if (timeout) {
      clearTimeout(timeout);
      
      const newTimeout = setTimeout(async () => {
        await this.finalizeRecording(recordingId, tenantId);
        this.activeRecordings.delete(recordingId);
      }, additionalSeconds * 1000);
      
      this.activeRecordings.set(recordingId, newTimeout);
    }
  }

  private async checkStorageQuota(tenantId: string): Promise<void> {
    const quota = await this.getStorageQuota(tenantId);
    if (quota.currentStorageGB >= quota.maxStorageGB) {
      throw new Error(`Storage quota exceeded for tenant ${tenantId}`);
    }
  }

  private async getStorageQuota(tenantId: string): Promise<TenantStorageQuota> {
    let quota = this.storageQuotas.get(tenantId);
    
    if (!quota) {
      // Load from database or use defaults
      quota = {
        tenantId,
        maxStorageGB: 1000, // Default 1TB
        currentStorageGB: 0,
        retentionDays: this.config.defaultRetentionDays,
        autoArchiveEnabled: true,
        archiveAfterDays: 90
      };
      
      // Calculate current usage
      const usage = await this.calculateCurrentStorageUsage(tenantId);
      quota.currentStorageGB = usage;
      
      this.storageQuotas.set(tenantId, quota);
    }
    
    return quota;
  }

  private async calculateCurrentStorageUsage(tenantId: string): Promise<number> {
    const result = await this.prisma.videoRecording.aggregate({
      where: { tenantId },
      _sum: { fileSize: true }
    });
    
    const totalBytes = result._sum.fileSize || 0;
    return totalBytes / (1024 * 1024 * 1024); // Convert to GB
  }

  private async updateStorageUsage(tenantId: string, fileSizeBytes: number): Promise<void> {
    const quota = await this.getStorageQuota(tenantId);
    quota.currentStorageGB += fileSizeBytes / (1024 * 1024 * 1024);
    this.storageQuotas.set(tenantId, quota);
  }

  private async getAllTenants(): Promise<{ id: string }[]> {
    return this.prisma.tenant.findMany({
      select: { id: true }
    });
  }

  private generateFilename(camera: Camera, startTime: Date, recordingType: string): string {
    const timestamp = startTime.toISOString().replace(/[:.]/g, '-');
    return `${camera.name}_${timestamp}_${recordingType}.mp4`;
  }

  private generateS3Key(tenantId: string, cameraId: string, filename: string): string {
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    
    return `recordings/${tenantId}/${year}/${month}/${day}/${cameraId}/${filename}`;
  }

  private async createExportLog(
    exportId: string,
    recordingId: string,
    tenantId: string,
    options: any
  ): Promise<void> {
    await this.prisma.videoExportLog.create({
      data: {
        id: exportId,
        recordingId,
        tenantId,
        exportedBy: 'system', // Would be actual user ID
        exportOptions: options,
        status: 'processing',
        createdAt: new Date()
      }
    });
  }

  private async processVideoExport(
    recording: VideoRecording,
    exportS3Key: string,
    options: any
  ): Promise<string> {
    // This would integrate with actual video processing service
    // For now, return a simulated download URL
    return `https://${this.config.s3Bucket}.s3.${this.config.s3Region}.amazonaws.com/${exportS3Key}`;
  }

  private initializeOfflineRecovery(): void {
    // Scan local storage for unsynced recordings
    try {
      if (existsSync(this.config.localStoragePath)) {
        this.scanLocalRecordings(this.config.localStoragePath);
      }
    } catch (error) {
      console.error('Failed to initialize offline recovery:', error);
    }
  }

  private scanLocalRecordings(directory: string): void {
    try {
      const entries = readdirSync(directory);
      
      for (const entry of entries) {
        const fullPath = join(directory, entry);
        const stat = statSync(fullPath);
        
        if (stat.isDirectory()) {
          this.scanLocalRecordings(fullPath);
        } else if (entry.endsWith('.mp4')) {
          // Parse filename to extract recording info
          const recordingId = this.extractRecordingIdFromFilename(entry);
          if (recordingId) {
            const offlineRecording: OfflineRecording = {
              id: recordingId,
              cameraId: 'unknown',
              localPath: fullPath,
              startTime: new Date(stat.birthtime),
              endTime: new Date(stat.mtime),
              metadata: {},
              syncStatus: 'pending'
            };
            
            this.offlineRecordings.set(recordingId, offlineRecording);
          }
        }
      }
    } catch (error) {
      console.error(`Failed to scan directory ${directory}:`, error);
    }
  }

  private extractRecordingIdFromFilename(filename: string): string | null {
    // Extract recording ID from filename pattern
    // This would depend on the actual filename format used
    const match = filename.match(/([a-f0-9-]{36})/);
    return match ? match[1] : null;
  }

  private startBackgroundTasks(): void {
    // Archive old recordings every hour
    setInterval(() => {
      this.archiveOldRecordings();
    }, 60 * 60 * 1000);

    // Delete expired recordings every 6 hours
    setInterval(() => {
      this.deleteExpiredRecordings();
    }, 6 * 60 * 60 * 1000);

    // Sync offline recordings every 5 minutes when online
    setInterval(() => {
      if (this.isOnline) {
        this.syncOfflineRecordings();
      }
    }, 5 * 60 * 1000);

    // Clean up completed active recordings every minute
    setInterval(() => {
      this.cleanupCompletedRecordings();
    }, 60 * 1000);
  }

  private async cleanupCompletedRecordings(): Promise<void> {
    for (const [recordingId, timeout] of this.activeRecordings) {
      try {
        const recording = await this.prisma.videoRecording.findUnique({
          where: { id: recordingId }
        });
        
        if (!recording || recording.status !== 'recording') {
          clearTimeout(timeout);
          this.activeRecordings.delete(recordingId);
        }
      } catch (error) {
        console.error(`Failed to check recording status for ${recordingId}:`, error);
      }
    }
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    // Stop all active recordings
    for (const [recordingId, timeout] of this.activeRecordings) {
      clearTimeout(timeout);
    }
    this.activeRecordings.clear();

    // Disconnect from database
    await this.prisma.$disconnect();
  }
}

export default RecordingService;
export {
  RecordingService,
  Camera,
  VideoRecording,
  RecordingTrigger,
  TenantStorageQuota,
  OfflineRecording,
  RecordingConfig
};