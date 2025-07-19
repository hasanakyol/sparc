// WebSocket Event Type Definitions

// Base event interface
export interface BaseWebSocketEvent {
  timestamp: string;
  tenantId?: string;
  userId?: string;
  correlationId?: string;
}

// Video Events
export namespace VideoEvents {
  export interface StreamStarted extends BaseWebSocketEvent {
    cameraId: string;
    quality: 'low' | 'medium' | 'high' | 'ultra';
    streamUrl: string;
    sessionId: string;
  }

  export interface StreamStopped extends BaseWebSocketEvent {
    cameraId: string;
    sessionId: string;
    reason?: string;
  }

  export interface StreamError extends BaseWebSocketEvent {
    cameraId: string;
    sessionId: string;
    error: {
      code: string;
      message: string;
      details?: any;
    };
  }

  export interface RecordingStarted extends BaseWebSocketEvent {
    cameraId: string;
    recordingId: string;
    duration?: number;
    format: string;
  }

  export interface RecordingStopped extends BaseWebSocketEvent {
    cameraId: string;
    recordingId: string;
    fileUrl?: string;
    fileSize?: number;
    duration?: number;
  }

  export interface RecordingProgress extends BaseWebSocketEvent {
    cameraId: string;
    recordingId: string;
    progress: number; // 0-100
    timeElapsed: number;
    timeRemaining?: number;
  }

  export interface MotionDetected extends BaseWebSocketEvent {
    cameraId: string;
    zones: string[];
    confidence: number;
    snapshot?: string;
  }

  export interface VideoAnalytics extends BaseWebSocketEvent {
    cameraId: string;
    analytics: {
      peopleCount?: number;
      vehicleCount?: number;
      objects?: Array<{
        type: string;
        confidence: number;
        boundingBox: {
          x: number;
          y: number;
          width: number;
          height: number;
        };
      }>;
    };
  }
}

// Alert Events
export namespace AlertEvents {
  export interface AlertCreated extends BaseWebSocketEvent {
    alert: {
      id: string;
      type: string;
      priority: 'low' | 'medium' | 'high' | 'critical';
      title: string;
      message: string;
      source: {
        type: string;
        id: string;
        name?: string;
      };
      details?: Record<string, any>;
    };
  }

  export interface AlertUpdated extends BaseWebSocketEvent {
    alertId: string;
    updates: {
      status?: 'active' | 'acknowledged' | 'resolved' | 'expired';
      priority?: 'low' | 'medium' | 'high' | 'critical';
      assignee?: {
        userId: string;
        name: string;
      };
      notes?: string;
    };
  }

  export interface AlertAcknowledged extends BaseWebSocketEvent {
    alertId: string;
    acknowledgedBy: {
      userId: string;
      name: string;
    };
    notes?: string;
  }

  export interface AlertResolved extends BaseWebSocketEvent {
    alertId: string;
    resolvedBy: {
      userId: string;
      name: string;
    };
    resolution: string;
    rootCause?: string;
  }

  export interface AlertEscalated extends BaseWebSocketEvent {
    alertId: string;
    escalationLevel: number;
    escalatedTo: {
      userId?: string;
      groupId?: string;
      name: string;
    };
    reason: string;
  }

  export interface BatchAlertsUpdate extends BaseWebSocketEvent {
    alertIds: string[];
    action: 'acknowledge' | 'resolve' | 'escalate';
    updates: Record<string, any>;
  }
}

// Monitoring Events
export namespace MonitoringEvents {
  export interface MetricsUpdate extends BaseWebSocketEvent {
    metrics: {
      system?: {
        cpu: number;
        memory: number;
        disk: number;
        network: {
          in: number;
          out: number;
        };
      };
      services?: Record<string, {
        status: 'healthy' | 'degraded' | 'down';
        responseTime: number;
        errorRate: number;
        throughput: number;
      }>;
      security?: {
        activeAlerts: number;
        threatsDetected: number;
        accessDenied: number;
        suspiciousActivities: number;
      };
    };
  }

  export interface ServiceStatusChanged extends BaseWebSocketEvent {
    serviceName: string;
    previousStatus: 'healthy' | 'degraded' | 'down';
    currentStatus: 'healthy' | 'degraded' | 'down';
    reason?: string;
    affectedFeatures?: string[];
  }

  export interface ThresholdBreached extends BaseWebSocketEvent {
    metric: string;
    threshold: {
      name: string;
      value: number;
      condition: 'above' | 'below';
    };
    currentValue: number;
    severity: 'warning' | 'critical';
  }

  export interface SecurityEvent extends BaseWebSocketEvent {
    eventType: 'intrusion' | 'unauthorized_access' | 'anomaly' | 'policy_violation';
    severity: 'low' | 'medium' | 'high' | 'critical';
    source: {
      type: string;
      id: string;
      location?: string;
    };
    details: Record<string, any>;
    recommendations?: string[];
  }

  export interface SystemEvent extends BaseWebSocketEvent {
    eventType: 'startup' | 'shutdown' | 'restart' | 'backup' | 'update' | 'error';
    component: string;
    status: 'started' | 'completed' | 'failed';
    details?: Record<string, any>;
  }
}

// Access Control Events
export namespace AccessEvents {
  export interface AccessGranted extends BaseWebSocketEvent {
    doorId: string;
    doorName: string;
    credential: {
      type: 'card' | 'pin' | 'biometric' | 'mobile';
      id: string;
    };
    person: {
      id: string;
      name: string;
      type: 'employee' | 'visitor' | 'contractor';
    };
  }

  export interface AccessDenied extends BaseWebSocketEvent {
    doorId: string;
    doorName: string;
    credential?: {
      type: 'card' | 'pin' | 'biometric' | 'mobile';
      id: string;
    };
    reason: 'invalid_credential' | 'expired' | 'no_permission' | 'schedule' | 'lockdown';
    person?: {
      id: string;
      name: string;
    };
  }

  export interface DoorForced extends BaseWebSocketEvent {
    doorId: string;
    doorName: string;
    location?: string;
  }

  export interface DoorHeldOpen extends BaseWebSocketEvent {
    doorId: string;
    doorName: string;
    duration: number;
    location?: string;
  }

  export interface EmergencyUnlock extends BaseWebSocketEvent {
    doors: string[];
    reason: 'fire' | 'evacuation' | 'medical' | 'manual';
    initiatedBy?: {
      userId: string;
      name: string;
    };
  }
}

// Environmental Events
export namespace EnvironmentalEvents {
  export interface SensorReading extends BaseWebSocketEvent {
    sensorId: string;
    sensorType: 'temperature' | 'humidity' | 'air_quality' | 'water' | 'smoke' | 'motion';
    value: number;
    unit: string;
    location: string;
    status: 'normal' | 'warning' | 'critical';
  }

  export interface EnvironmentalAlert extends BaseWebSocketEvent {
    type: 'temperature' | 'humidity' | 'air_quality' | 'water_leak' | 'smoke' | 'fire';
    severity: 'warning' | 'critical';
    location: string;
    sensors: Array<{
      id: string;
      value: number;
      threshold: number;
    }>;
    recommendations?: string[];
  }

  export interface HVACStatusChanged extends BaseWebSocketEvent {
    zoneId: string;
    zoneName: string;
    previousState: 'heating' | 'cooling' | 'idle' | 'off';
    currentState: 'heating' | 'cooling' | 'idle' | 'off';
    setpoint?: {
      temperature: number;
      humidity?: number;
    };
  }
}

// Incident Events
export namespace IncidentEvents {
  export interface IncidentCreated extends BaseWebSocketEvent {
    incident: {
      id: string;
      type: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      title: string;
      description: string;
      location?: string;
      affectedAssets?: string[];
    };
  }

  export interface IncidentUpdated extends BaseWebSocketEvent {
    incidentId: string;
    updates: {
      status?: 'open' | 'investigating' | 'resolved' | 'closed';
      severity?: 'low' | 'medium' | 'high' | 'critical';
      assignee?: {
        userId: string;
        name: string;
      };
      timeline?: Array<{
        timestamp: string;
        action: string;
        user: string;
        details?: string;
      }>;
    };
  }

  export interface IncidentEscalated extends BaseWebSocketEvent {
    incidentId: string;
    escalationLevel: number;
    escalatedTo: {
      userId?: string;
      teamId?: string;
      name: string;
    };
    reason: string;
  }

  export interface IncidentResolved extends BaseWebSocketEvent {
    incidentId: string;
    resolvedBy: {
      userId: string;
      name: string;
    };
    resolution: string;
    rootCause?: string;
    preventiveMeasures?: string[];
  }
}

// System Events
export namespace SystemEvents {
  export interface MaintenanceScheduled extends BaseWebSocketEvent {
    maintenanceId: string;
    type: 'planned' | 'emergency';
    startTime: string;
    endTime: string;
    affectedServices: string[];
    description: string;
  }

  export interface BackupCompleted extends BaseWebSocketEvent {
    backupId: string;
    type: 'full' | 'incremental' | 'differential';
    size: number;
    duration: number;
    status: 'success' | 'partial' | 'failed';
    details?: Record<string, any>;
  }

  export interface ConfigurationChanged extends BaseWebSocketEvent {
    component: string;
    changes: Array<{
      setting: string;
      previousValue: any;
      newValue: any;
    }>;
    changedBy: {
      userId: string;
      name: string;
    };
  }

  export interface LicenseAlert extends BaseWebSocketEvent {
    type: 'expiring' | 'expired' | 'limit_reached';
    component: string;
    details: {
      expiryDate?: string;
      currentUsage?: number;
      limit?: number;
    };
  }
}

// Aggregated event map for type safety
export type WebSocketEventMap = {
  // Video events
  'video:stream:started': VideoEvents.StreamStarted;
  'video:stream:stopped': VideoEvents.StreamStopped;
  'video:stream:error': VideoEvents.StreamError;
  'video:recording:started': VideoEvents.RecordingStarted;
  'video:recording:stopped': VideoEvents.RecordingStopped;
  'video:recording:progress': VideoEvents.RecordingProgress;
  'video:motion:detected': VideoEvents.MotionDetected;
  'video:analytics': VideoEvents.VideoAnalytics;

  // Alert events
  'alert:created': AlertEvents.AlertCreated;
  'alert:updated': AlertEvents.AlertUpdated;
  'alert:acknowledged': AlertEvents.AlertAcknowledged;
  'alert:resolved': AlertEvents.AlertResolved;
  'alert:escalated': AlertEvents.AlertEscalated;
  'alert:batch:update': AlertEvents.BatchAlertsUpdate;

  // Monitoring events
  'monitoring:metrics:update': MonitoringEvents.MetricsUpdate;
  'monitoring:service:status': MonitoringEvents.ServiceStatusChanged;
  'monitoring:threshold:breached': MonitoringEvents.ThresholdBreached;
  'monitoring:security:event': MonitoringEvents.SecurityEvent;
  'monitoring:system:event': MonitoringEvents.SystemEvent;

  // Access events
  'access:granted': AccessEvents.AccessGranted;
  'access:denied': AccessEvents.AccessDenied;
  'access:door:forced': AccessEvents.DoorForced;
  'access:door:held': AccessEvents.DoorHeldOpen;
  'access:emergency:unlock': AccessEvents.EmergencyUnlock;

  // Environmental events
  'environmental:sensor:reading': EnvironmentalEvents.SensorReading;
  'environmental:alert': EnvironmentalEvents.EnvironmentalAlert;
  'environmental:hvac:status': EnvironmentalEvents.HVACStatusChanged;

  // Incident events
  'incident:created': IncidentEvents.IncidentCreated;
  'incident:updated': IncidentEvents.IncidentUpdated;
  'incident:escalated': IncidentEvents.IncidentEscalated;
  'incident:resolved': IncidentEvents.IncidentResolved;

  // System events
  'system:maintenance:scheduled': SystemEvents.MaintenanceScheduled;
  'system:backup:completed': SystemEvents.BackupCompleted;
  'system:config:changed': SystemEvents.ConfigurationChanged;
  'system:license:alert': SystemEvents.LicenseAlert;
};

// Type helper for event listeners
export type WebSocketEventHandler<K extends keyof WebSocketEventMap> = (
  event: WebSocketEventMap[K]
) => void | Promise<void>;