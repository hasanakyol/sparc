/**
 * Domain Events for SPARC Security Platform
 * 
 * Event naming convention: <entity>.<action>
 * All events are versioned to support schema evolution
 */

// Security Events
export interface SecurityIncidentCreated {
  incidentId: string;
  type: 'intrusion' | 'unauthorized_access' | 'alarm' | 'suspicious_activity' | 'other';
  severity: 'critical' | 'high' | 'medium' | 'low';
  siteId: string;
  zoneId?: string;
  description: string;
  detectedBy: {
    type: 'camera' | 'sensor' | 'user' | 'analytics' | 'system';
    id: string;
    name?: string;
  };
  evidence?: {
    videoClips?: string[];
    images?: string[];
    sensorData?: any;
  };
}

export interface SecurityIncidentUpdated {
  incidentId: string;
  previousStatus: string;
  newStatus: string;
  updatedBy: string;
  updates: {
    severity?: string;
    assignee?: string;
    description?: string;
    notes?: string;
  };
}

export interface SecurityIncidentResolved {
  incidentId: string;
  resolvedBy: string;
  resolution: string;
  actionsTaken: string[];
  preventiveMeasures?: string[];
}

export interface SecurityAlertTriggered {
  alertId: string;
  ruleId: string;
  ruleName: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: {
    type: string;
    id: string;
  };
  data: any;
  thresholdValue?: number;
  actualValue?: number;
}

export interface AccessGranted {
  accessId: string;
  userId: string;
  credentialType: 'badge' | 'pin' | 'biometric' | 'mobile';
  grantedTo: {
    zoneId: string;
    zoneName: string;
    accessPointId?: string;
  };
  timestamp: Date;
}

export interface AccessDenied {
  attemptId: string;
  userId?: string;
  credentialType: 'badge' | 'pin' | 'biometric' | 'mobile';
  deniedAt: {
    zoneId: string;
    zoneName: string;
    accessPointId?: string;
  };
  reason: 'invalid_credential' | 'no_permission' | 'expired' | 'blacklisted' | 'time_restriction';
  timestamp: Date;
}

// Video Events
export interface VideoRecordingStarted {
  recordingId: string;
  cameraId: string;
  cameraName: string;
  siteId: string;
  zoneId: string;
  triggerType: 'manual' | 'scheduled' | 'motion' | 'alert' | 'continuous';
  quality: 'high' | 'medium' | 'low';
  expectedDuration?: number;
}

export interface VideoRecordingStopped {
  recordingId: string;
  cameraId: string;
  duration: number;
  fileSize: number;
  storageLocation: string;
  reason: 'manual' | 'scheduled' | 'error' | 'storage_full' | 'camera_offline';
}

export interface MotionDetected {
  detectionId: string;
  cameraId: string;
  cameraName: string;
  siteId: string;
  zoneId: string;
  motionArea: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  confidence: number;
  timestamp: Date;
  snapshotUrl?: string;
}

export interface VideoAnalyticsEvent {
  eventId: string;
  cameraId: string;
  type: 'person_detected' | 'vehicle_detected' | 'object_left' | 'line_crossed' | 'crowd_detected' | 'face_detected';
  confidence: number;
  boundingBox?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  attributes?: Record<string, any>;
  timestamp: Date;
}

export interface VideoStreamStarted {
  streamId: string;
  cameraId: string;
  viewerId: string;
  streamType: 'live' | 'playback';
  quality: 'high' | 'medium' | 'low' | 'auto';
  protocol: 'rtsp' | 'hls' | 'webrtc';
}

export interface VideoStreamStopped {
  streamId: string;
  cameraId: string;
  viewerId: string;
  duration: number;
  reason: 'user_action' | 'timeout' | 'error' | 'camera_offline';
}

// System Events
export interface DeviceOnline {
  deviceId: string;
  deviceType: 'camera' | 'sensor' | 'access_controller' | 'alarm_panel';
  deviceName: string;
  siteId: string;
  zoneId?: string;
  ipAddress?: string;
  firmwareVersion?: string;
  previousStatus?: string;
}

export interface DeviceOffline {
  deviceId: string;
  deviceType: 'camera' | 'sensor' | 'access_controller' | 'alarm_panel';
  deviceName: string;
  siteId: string;
  zoneId?: string;
  lastSeen: Date;
  possibleReasons?: string[];
}

export interface DeviceHealthIssue {
  deviceId: string;
  deviceType: string;
  issueType: 'high_cpu' | 'high_memory' | 'disk_full' | 'network_issue' | 'hardware_failure';
  severity: 'critical' | 'warning' | 'info';
  metrics?: Record<string, number>;
  recommendations?: string[];
}

export interface ConfigurationChanged {
  entityType: 'site' | 'zone' | 'camera' | 'sensor' | 'system';
  entityId: string;
  changedBy: string;
  changes: Array<{
    field: string;
    oldValue: any;
    newValue: any;
  }>;
  reason?: string;
}

export interface SystemMaintenanceScheduled {
  maintenanceId: string;
  type: 'update' | 'backup' | 'cleanup' | 'restart';
  scheduledFor: Date;
  estimatedDuration: number;
  affectedServices: string[];
  notificationsSent: boolean;
}

// Analytics Events
export interface ThresholdExceeded {
  thresholdId: string;
  metricName: string;
  metricType: 'count' | 'rate' | 'duration' | 'percentage';
  configuredThreshold: number;
  actualValue: number;
  period: string;
  entityType: string;
  entityId: string;
}

export interface AnomalyDetected {
  anomalyId: string;
  type: 'behavior' | 'traffic' | 'access_pattern' | 'system_metric';
  description: string;
  confidence: number;
  baseline: any;
  observed: any;
  recommendations?: string[];
}

export interface ReportGenerated {
  reportId: string;
  reportType: string;
  reportName: string;
  generatedBy: string;
  format: 'pdf' | 'csv' | 'json' | 'xlsx';
  parameters: Record<string, any>;
  fileUrl: string;
  fileSize: number;
}

export interface PredictionGenerated {
  predictionId: string;
  modelName: string;
  predictionType: string;
  entityType: string;
  entityId: string;
  prediction: any;
  confidence: number;
  timeHorizon?: string;
}

// User Events
export interface UserLoggedIn {
  userId: string;
  username: string;
  authMethod: 'password' | 'sso' | 'mfa' | 'biometric';
  ipAddress: string;
  userAgent: string;
  sessionId: string;
  organizationId: string;
}

export interface UserLoggedOut {
  userId: string;
  username: string;
  sessionDuration: number;
  logoutType: 'manual' | 'timeout' | 'forced' | 'error';
}

export interface UserPermissionChanged {
  userId: string;
  changedBy: string;
  changes: {
    added?: string[];
    removed?: string[];
    modified?: Array<{
      permission: string;
      oldValue: any;
      newValue: any;
    }>;
  };
  reason?: string;
}

export interface UserPasswordChanged {
  userId: string;
  changedBy: string;
  changeType: 'user_initiated' | 'admin_reset' | 'expired' | 'compromised';
  requireMfaReset?: boolean;
}

export interface UserAccountLocked {
  userId: string;
  reason: 'failed_attempts' | 'suspicious_activity' | 'admin_action' | 'compliance';
  lockDuration?: number;
  unlockMethod?: 'automatic' | 'admin_only' | 'user_verification';
}

// Aggregated Event Types
export interface SparcDomainEvents {
  // Security Events
  'security.incident.created': SecurityIncidentCreated;
  'security.incident.updated': SecurityIncidentUpdated;
  'security.incident.resolved': SecurityIncidentResolved;
  'security.alert.triggered': SecurityAlertTriggered;
  'security.access.granted': AccessGranted;
  'security.access.denied': AccessDenied;

  // Video Events
  'video.recording.started': VideoRecordingStarted;
  'video.recording.stopped': VideoRecordingStopped;
  'video.motion.detected': MotionDetected;
  'video.analytics.event': VideoAnalyticsEvent;
  'video.stream.started': VideoStreamStarted;
  'video.stream.stopped': VideoStreamStopped;

  // System Events
  'system.device.online': DeviceOnline;
  'system.device.offline': DeviceOffline;
  'system.device.health_issue': DeviceHealthIssue;
  'system.configuration.changed': ConfigurationChanged;
  'system.maintenance.scheduled': SystemMaintenanceScheduled;

  // Analytics Events
  'analytics.threshold.exceeded': ThresholdExceeded;
  'analytics.anomaly.detected': AnomalyDetected;
  'analytics.report.generated': ReportGenerated;
  'analytics.prediction.generated': PredictionGenerated;

  // User Events
  'user.logged_in': UserLoggedIn;
  'user.logged_out': UserLoggedOut;
  'user.permission.changed': UserPermissionChanged;
  'user.password.changed': UserPasswordChanged;
  'user.account.locked': UserAccountLocked;
}

// Event version mapping for schema evolution
export const EVENT_VERSIONS: Record<keyof SparcDomainEvents, number> = {
  'security.incident.created': 1,
  'security.incident.updated': 1,
  'security.incident.resolved': 1,
  'security.alert.triggered': 1,
  'security.access.granted': 1,
  'security.access.denied': 1,
  'video.recording.started': 1,
  'video.recording.stopped': 1,
  'video.motion.detected': 1,
  'video.analytics.event': 1,
  'video.stream.started': 1,
  'video.stream.stopped': 1,
  'system.device.online': 1,
  'system.device.offline': 1,
  'system.device.health_issue': 1,
  'system.configuration.changed': 1,
  'system.maintenance.scheduled': 1,
  'analytics.threshold.exceeded': 1,
  'analytics.anomaly.detected': 1,
  'analytics.report.generated': 1,
  'analytics.prediction.generated': 1,
  'user.logged_in': 1,
  'user.logged_out': 1,
  'user.permission.changed': 1,
  'user.password.changed': 1,
  'user.account.locked': 1,
};