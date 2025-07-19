// Core Analytics Interfaces
export interface AccessPattern {
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

export interface AnomalyScore {
  entityId: string;
  entityType: string;
  score: number;
  factors: string[];
  timestamp: Date;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface OccupancyData {
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

export interface PredictiveAlert {
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

// Video Analytics Interfaces
export interface FaceRecognitionEvent {
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

export interface LicensePlateEvent {
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

export interface BehaviorEvent {
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

export interface VideoAnalyticsConfig {
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

export interface MLModelConfig {
  modelId: string;
  modelType: 'face_recognition' | 'license_plate' | 'behavior_analysis' | 'object_detection';
  version: string;
  endpoint: string;
  apiKey?: string;
  confidence: number;
  enabled: boolean;
}

export interface CrowdAnalysis {
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

export interface IncidentPrediction {
  id: string;
  type: 'security_breach' | 'crowd_incident' | 'equipment_failure' | 'safety_violation';
  probability: number;
  timeToIncident: number; // minutes
  location: {
    buildingId: string;
    floorId?: string;
    zoneId?: string;
  };
  factors: string[];
  recommendedActions: string[];
  confidence: number;
}

// Service Configuration
export interface AnalyticsServiceConfig {
  port: number;
  redisUrl: string;
  jwtSecret: string;
  opensearchUrl: string;
  mlApiUrl?: string;
  mlApiKey?: string;
  videoProcessingUrl?: string;
  enableRealtimeAnalytics: boolean;
  enablePredictiveAnalytics: boolean;
  retentionDays: number;
}