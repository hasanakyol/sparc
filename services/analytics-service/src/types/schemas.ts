import { z } from 'zod';

// Core Analytics Schemas
export const AnalyticsQuerySchema = z.object({
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

export const AnomalyDetectionSchema = z.object({
  tenantId: z.string().uuid(),
  entityType: z.enum(['user', 'door', 'camera', 'zone']),
  entityId: z.string().uuid(),
  threshold: z.number().min(0).max(1).default(0.8),
  timeWindow: z.number().min(1).max(168).default(24) // hours
});

export const OccupancyQuerySchema = z.object({
  tenantId: z.string().uuid(),
  buildingId: z.string().uuid().optional(),
  floorId: z.string().uuid().optional(),
  zoneId: z.string().uuid().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  granularity: z.enum(['minute', 'hour', 'day']).default('hour')
});

// Video Analytics Schemas
export const VideoAnalyticsConfigSchema = z.object({
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

export const FaceRecognitionEventSchema = z.object({
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

export const LicensePlateEventSchema = z.object({
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

export const BehaviorEventSchema = z.object({
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

// Type exports for convenience
export type AnalyticsQuery = z.infer<typeof AnalyticsQuerySchema>;
export type AnomalyDetection = z.infer<typeof AnomalyDetectionSchema>;
export type OccupancyQuery = z.infer<typeof OccupancyQuerySchema>;
export type VideoAnalyticsConfig = z.infer<typeof VideoAnalyticsConfigSchema>;
export type FaceRecognitionEvent = z.infer<typeof FaceRecognitionEventSchema>;
export type LicensePlateEvent = z.infer<typeof LicensePlateEventSchema>;
export type BehaviorEvent = z.infer<typeof BehaviorEventSchema>;