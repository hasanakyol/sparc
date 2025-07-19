import { z } from 'zod';

export const CameraSchema = z.object({
  id: z.string().uuid().optional(),
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  ipAddress: z.string().ip(),
  port: z.number().int().min(1).max(65535).default(80),
  username: z.string().min(1),
  password: z.string().min(1),
  protocol: z.enum(['ONVIF', 'RTSP', 'HTTP', 'HTTPS']).default('ONVIF'),
  manufacturer: z.string().optional(),
  model: z.string().optional(),
  firmwareVersion: z.string().optional(),
  buildingId: z.string().uuid(),
  floorId: z.string().uuid().optional(),
  zoneId: z.string().uuid().optional(),
  position: z.object({
    x: z.number(),
    y: z.number(),
    rotation: z.number().default(0)
  }).optional(),
  capabilities: z.object({
    ptz: z.boolean().default(false),
    audio: z.boolean().default(false),
    nightVision: z.boolean().default(false),
    motionDetection: z.boolean().default(false),
    analytics: z.boolean().default(false)
  }).default({}),
  streamUrls: z.object({
    main: z.string().url().optional(),
    sub: z.string().url().optional(),
    mobile: z.string().url().optional()
  }).default({}),
  recordingSettings: z.object({
    enabled: z.boolean().default(true),
    quality: z.enum(['high', 'medium', 'low']).default('medium'),
    fps: z.number().int().min(1).max(60).default(15),
    resolution: z.string().default('1920x1080'),
    retentionDays: z.number().int().min(1).max(365).default(30),
    motionRecording: z.boolean().default(true),
    continuousRecording: z.boolean().default(false)
  }).default({}),
  privacyMasks: z.array(z.object({
    id: z.string().uuid(),
    name: z.string(),
    coordinates: z.array(z.object({
      x: z.number(),
      y: z.number()
    })),
    enabled: z.boolean().default(true)
  })).default([]),
  status: z.enum(['online', 'offline', 'error', 'maintenance']).default('offline'),
  tenantId: z.string().uuid()
});

export const StreamRequestSchema = z.object({
  cameraId: z.string().uuid(),
  quality: z.enum(['high', 'medium', 'low']).default('medium'),
  format: z.enum(['hls', 'webrtc', 'mjpeg']).default('hls')
});

export const RecordingSearchSchema = z.object({
  cameraIds: z.array(z.string().uuid()).optional(),
  startTime: z.string().datetime(),
  endTime: z.string().datetime(),
  eventTypes: z.array(z.string()).optional(),
  buildingId: z.string().uuid().optional(),
  floorId: z.string().uuid().optional(),
  page: z.number().int().min(1).default(1),
  limit: z.number().int().min(1).max(100).default(20)
});

export const VideoExportSchema = z.object({
  recordingIds: z.array(z.string().uuid()),
  format: z.enum(['mp4', 'avi', 'mov']).default('mp4'),
  quality: z.enum(['original', 'high', 'medium', 'low']).default('high'),
  includeAudio: z.boolean().default(true),
  watermark: z.boolean().default(true),
  reason: z.string().min(1).max(500),
  requestedBy: z.string().uuid()
});

export type Camera = z.infer<typeof CameraSchema>;
export type StreamRequest = z.infer<typeof StreamRequestSchema>;
export type RecordingSearch = z.infer<typeof RecordingSearchSchema>;
export type VideoExport = z.infer<typeof VideoExportSchema>;