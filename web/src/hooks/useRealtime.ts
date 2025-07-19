'use client';

import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { io, Socket } from 'socket.io-client';
import { toast } from 'react-hot-toast';
import apiClient from '@/lib/api';

// Types for real-time events - Updated to match backend schemas
export interface AccessEvent {
  id: string;
  tenantId: string;
  userId?: string;
  doorId: string;
  credentialId?: string;
  cardNumber?: string;
  eventType: 'access_granted' | 'access_denied' | 'door_forced' | 'door_held_open' | 'door_propped' | 'tailgating_detected' | 'anti_passback_violation';
  timestamp: string;
  buildingId: string;
  floorId: string;
  zoneId?: string;
  deviceId?: string;
  readerId?: string;
  direction?: 'entry' | 'exit';
  reason?: string;
  metadata?: Record<string, any>;
}

export interface VideoEvent {
  id: string;
  tenantId: string;
  cameraId: string;
  eventType: 'motion_detected' | 'camera_offline' | 'camera_online' | 'camera_tampered' | 'line_crossing' | 'loitering_detected' | 'object_detection' | 'face_detection';
  timestamp: string;
  buildingId: string;
  floorId: string;
  zoneId?: string;
  confidence?: number;
  boundingBox?: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  objectType?: string;
  metadata?: Record<string, any>;
}

export interface EnvironmentalEvent {
  id: string;
  tenantId: string;
  sensorId: string;
  sensorType: 'temperature' | 'humidity' | 'air_quality' | 'water_leak' | 'smoke' | 'co2' | 'motion';
  eventType: 'threshold_exceeded' | 'threshold_below' | 'sensor_offline' | 'sensor_online' | 'sensor_error' | 'calibration_required';
  value: number;
  unit: string;
  threshold?: number;
  timestamp: string;
  buildingId: string;
  floorId: string;
  zoneId?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  metadata?: Record<string, any>;
}

export interface Alert {
  id: string;
  tenantId: string;
  type: 'security' | 'environmental' | 'system' | 'maintenance' | 'safety';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  sourceEvents: string[];
  buildingId: string;
  floorId: string;
  zoneId?: string;
  timestamp: string;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: string;
  resolved: boolean;
  resolvedBy?: string;
  resolvedAt?: string;
  escalated: boolean;
  escalatedAt?: string;
  priority: number;
  tags?: string[];
  metadata?: Record<string, any>;
}

export interface SystemStatus {
  id: string;
  tenantId: string;
  component: string;
  service: string;
  status: 'online' | 'offline' | 'degraded' | 'maintenance' | 'error';
  message?: string;
  timestamp: string;
  buildingId?: string;
  floorId?: string;
  healthScore?: number;
  lastSeen?: string;
  metadata?: Record<string, any>;
}

export interface DeviceStatus {
  id: string;
  tenantId: string;
  deviceId: string;
  deviceType: 'door_controller' | 'card_reader' | 'camera' | 'sensor' | 'panel';
  status: 'online' | 'offline' | 'error' | 'maintenance';
  buildingId: string;
  floorId: string;
  zoneId?: string;
  timestamp: string;
  batteryLevel?: number;
  signalStrength?: number;
  lastSeen?: string;
  firmwareVersion?: string;
  metadata?: Record<string, any>;
}

export interface VideoFeed {
  cameraId: string;
  streamUrl: string;
  status: 'active' | 'inactive' | 'error' | 'buffering';
  quality: 'low' | 'medium' | 'high' | 'ultra';
  resolution: string;
  fps: number;
  timestamp: string;
  buildingId: string;
  floorId: string;
  zoneId?: string;
}

// Connection status
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error' | 'reconnecting';

// Event handlers
export interface RealtimeEventHandlers {
  onAccessEvent?: (event: AccessEvent) => void;
  onVideoEvent?: (event: VideoEvent) => void;
  onEnvironmentalEvent?: (event: EnvironmentalEvent) => void;
  onAlert?: (alert: Alert) => void;
  onAlertAcknowledged?: (data: { alertId: string; userId: string; timestamp: string }) => void;
  onAlertResolved?: (data: { alertId: string; userId: string; timestamp: string }) => void;
  onAlertEscalated?: (data: { alertId: string; escalatedBy: string; timestamp: string }) => void;
  onSystemStatus?: (status: SystemStatus) => void;
  onDeviceStatus?: (status: DeviceStatus) => void;
  onVideoFeed?: (feed: VideoFeed) => void;
  onConnectionStatusChange?: (status: ConnectionStatus) => void;
  onError?: (error: Error) => void;
  onSubscriptionConfirmed?: (data: { type: string; target: string }) => void;
  onSubscriptionError?: (data: { type: string; target: string; error: string }) => void;
}

// Subscription options
export interface SubscriptionOptions {
  buildings?: string[];
  floors?: Array<{ buildingId: string; floorId: string }>;
  zones?: Array<{ buildingId: string; floorId: string; zoneId: string }>;
  cameras?: string[];
  doors?: string[];
  sensors?: string[];
  devices?: string[];
  alertTypes?: Alert['type'][];
  alertSeverities?: Alert['severity'][];
  eventTypes?: {
    access?: AccessEvent['eventType'][];
    video?: VideoEvent['eventType'][];
    environmental?: EnvironmentalEvent['eventType'][];
  };
  permissions?: string[];
}

// Hook configuration
export interface UseRealtimeConfig {
  url?: string;
  tenantId: string;
  token: string;
  autoConnect?: boolean;
  reconnectAttempts?: number;
  reconnectDelay?: number;
  heartbeatInterval?: number;
  subscriptions?: SubscriptionOptions;
  handlers?: RealtimeEventHandlers;
  enableToasts?: boolean;
  toastConfig?: {
    showAccessEvents?: boolean;
    showVideoEvents?: boolean;
    showEnvironmentalEvents?: boolean;
    showAlerts?: boolean;
    showSystemStatus?: boolean;
    alertSeverityThreshold?: Alert['severity'];
  };
}

// Hook return type
export interface UseRealtimeReturn {
  socket: Socket | null;
  connectionStatus: ConnectionStatus;
  isConnected: boolean;
  lastEvent: AccessEvent | VideoEvent | EnvironmentalEvent | Alert | SystemStatus | null;
  eventCounts: {
    accessEvents: number;
    videoEvents: number;
    environmentalEvents: number;
    alerts: number;
    systemStatus: number;
    deviceStatus: number;
  };
  connect: () => void;
  disconnect: () => void;
  reconnect: () => void;
  subscribeToBuilding: (buildingId: string) => void;
  unsubscribeFromBuilding: (buildingId: string) => void;
  subscribeToFloor: (buildingId: string, floorId: string) => void;
  unsubscribeFromFloor: (buildingId: string, floorId: string) => void;
  subscribeToZone: (buildingId: string, floorId: string, zoneId: string) => void;
  unsubscribeFromZone: (buildingId: string, floorId: string, zoneId: string) => void;
  subscribeToDevice: (deviceId: string) => void;
  unsubscribeFromDevice: (deviceId: string) => void;
  updateSubscriptions: (subscriptions: SubscriptionOptions) => void;
  clearEventCounts: () => void;
  getConnectionInfo: () => {
    id: string | undefined;
    connected: boolean;
    transport: string | undefined;
    ping: number | undefined;
    tenantId: string | null;
    userId: string | null;
    subscriptions: SubscriptionOptions;
  };
  enableDebugMode: () => void;
  disableDebugMode: () => void;
}

// Default configuration
const DEFAULT_CONFIG: Partial<UseRealtimeConfig> = {
  url: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
  autoConnect: true,
  reconnectAttempts: 5,
  reconnectDelay: 1000,
  heartbeatInterval: 30000,
  enableToasts: true,
  toastConfig: {
    showAccessEvents: false,
    showVideoEvents: false,
    showEnvironmentalEvents: false,
    showAlerts: true,
    showSystemStatus: true,
    alertSeverityThreshold: 'medium',
  },
};

// Severity levels for comparison
const SEVERITY_LEVELS = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function useRealtime(config: UseRealtimeConfig): UseRealtimeReturn {
  const mergedConfig = useMemo(() => ({ ...DEFAULT_CONFIG, ...config }), [config]);
  
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('disconnected');
  const [lastEvent, setLastEvent] = useState<AccessEvent | VideoEvent | EnvironmentalEvent | Alert | SystemStatus | null>(null);
  const [eventCounts, setEventCounts] = useState({
    accessEvents: 0,
    videoEvents: 0,
    environmentalEvents: 0,
    alerts: 0,
    systemStatus: 0,
    deviceStatus: 0,
  });

  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();
  const heartbeatIntervalRef = useRef<NodeJS.Timeout>();
  const reconnectAttemptsRef = useRef(0);
  const subscriptionsRef = useRef<SubscriptionOptions>({});
  const debugModeRef = useRef(false);
  const eventLogRef = useRef<Array<{ timestamp: string; type: string; data: any }>>([]);

  // Memoized derived state
  const isConnected = useMemo(() => connectionStatus === 'connected', [connectionStatus]);

  // Debug logging helper
  const debugLog = useCallback((message: string, data?: any) => {
    if (debugModeRef.current) {
      console.log(`[useRealtime] ${message}`, data);
      eventLogRef.current.push({
        timestamp: new Date().toISOString(),
        type: 'debug',
        data: { message, data }
      });
      // Keep only last 100 debug entries
      if (eventLogRef.current.length > 100) {
        eventLogRef.current = eventLogRef.current.slice(-100);
      }
    }
  }, []);

  // Event logging helper
  const logEvent = useCallback((type: string, event: any) => {
    if (debugModeRef.current) {
      eventLogRef.current.push({
        timestamp: new Date().toISOString(),
        type,
        data: event
      });
      // Keep only last 100 events
      if (eventLogRef.current.length > 100) {
        eventLogRef.current = eventLogRef.current.slice(-100);
      }
    }
  }, []);

  // Toast notification helper
  const showToast = useCallback((type: string, message: string, severity?: Alert['severity']) => {
    if (!mergedConfig.enableToasts) return;

    const toastConfig = mergedConfig.toastConfig!;
    
    if (severity && toastConfig.alertSeverityThreshold) {
      const currentLevel = SEVERITY_LEVELS[severity];
      const thresholdLevel = SEVERITY_LEVELS[toastConfig.alertSeverityThreshold];
      if (currentLevel < thresholdLevel) return;
    }

    switch (type) {
      case 'access_event':
        if (toastConfig.showAccessEvents) {
          toast(message, { icon: '🚪' });
        }
        break;
      case 'video_event':
        if (toastConfig.showVideoEvents) {
          toast(message, { icon: '📹' });
        }
        break;
      case 'environmental_event':
        if (toastConfig.showEnvironmentalEvents) {
          toast(message, { icon: '🌡️' });
        }
        break;
      case 'alert':
        if (toastConfig.showAlerts) {
          const icon = severity === 'critical' ? '🚨' : severity === 'high' ? '⚠️' : '📢';
          toast.error(message, { icon, duration: severity === 'critical' ? 0 : 5000 });
        }
        break;
      case 'system_status':
        if (toastConfig.showSystemStatus) {
          toast(message, { icon: '⚙️' });
        }
        break;
      default:
        toast(message);
    }
  }, [mergedConfig.enableToasts, mergedConfig.toastConfig]);

  // Event handlers with backend data transformation
  const handleAccessEvent = useCallback((rawEvent: any) => {
    debugLog('Received access event', rawEvent);
    
    // Transform backend event to frontend format
    const event: AccessEvent = {
      id: rawEvent.id || rawEvent.eventId,
      tenantId: rawEvent.tenantId,
      userId: rawEvent.userId,
      doorId: rawEvent.doorId,
      credentialId: rawEvent.credentialId,
      cardNumber: rawEvent.cardNumber,
      eventType: rawEvent.eventType || rawEvent.type,
      timestamp: rawEvent.timestamp || rawEvent.createdAt,
      buildingId: rawEvent.buildingId || rawEvent.location?.buildingId,
      floorId: rawEvent.floorId || rawEvent.location?.floorId,
      zoneId: rawEvent.zoneId || rawEvent.location?.zoneId,
      deviceId: rawEvent.deviceId,
      readerId: rawEvent.readerId,
      direction: rawEvent.direction,
      reason: rawEvent.reason || rawEvent.denialReason,
      metadata: rawEvent.metadata || rawEvent.additionalData,
    };
    
    logEvent('access_event', event);
    setLastEvent(event);
    setEventCounts(prev => ({ ...prev, accessEvents: prev.accessEvents + 1 }));
    
    mergedConfig.handlers?.onAccessEvent?.(event);
    
    if (event.eventType === 'access_denied' || event.eventType === 'tailgating_detected') {
      showToast('access_event', `Security event: ${event.eventType} at door ${event.doorId}`);
    }
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleVideoEvent = useCallback((rawEvent: any) => {
    debugLog('Received video event', rawEvent);
    
    // Transform backend event to frontend format
    const event: VideoEvent = {
      id: rawEvent.id || rawEvent.eventId,
      tenantId: rawEvent.tenantId,
      cameraId: rawEvent.cameraId,
      eventType: rawEvent.eventType || rawEvent.type,
      timestamp: rawEvent.timestamp || rawEvent.createdAt,
      buildingId: rawEvent.buildingId || rawEvent.location?.buildingId,
      floorId: rawEvent.floorId || rawEvent.location?.floorId,
      zoneId: rawEvent.zoneId || rawEvent.location?.zoneId,
      confidence: rawEvent.confidence,
      boundingBox: rawEvent.boundingBox,
      objectType: rawEvent.objectType,
      metadata: rawEvent.metadata || rawEvent.additionalData,
    };
    
    logEvent('video_event', event);
    setLastEvent(event);
    setEventCounts(prev => ({ ...prev, videoEvents: prev.videoEvents + 1 }));
    
    mergedConfig.handlers?.onVideoEvent?.(event);
    
    if (event.eventType === 'camera_offline' || event.eventType === 'camera_tampered') {
      showToast('video_event', `Camera alert: ${event.eventType} for camera ${event.cameraId}`);
    }
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleEnvironmentalEvent = useCallback((rawEvent: any) => {
    debugLog('Received environmental event', rawEvent);
    
    // Transform backend event to frontend format
    const event: EnvironmentalEvent = {
      id: rawEvent.id || rawEvent.eventId,
      tenantId: rawEvent.tenantId,
      sensorId: rawEvent.sensorId,
      sensorType: rawEvent.sensorType,
      eventType: rawEvent.eventType || rawEvent.type,
      value: rawEvent.value || rawEvent.reading,
      unit: rawEvent.unit,
      threshold: rawEvent.threshold,
      timestamp: rawEvent.timestamp || rawEvent.createdAt,
      buildingId: rawEvent.buildingId || rawEvent.location?.buildingId,
      floorId: rawEvent.floorId || rawEvent.location?.floorId,
      zoneId: rawEvent.zoneId || rawEvent.location?.zoneId,
      severity: rawEvent.severity || 'medium',
      metadata: rawEvent.metadata || rawEvent.additionalData,
    };
    
    logEvent('environmental_event', event);
    setLastEvent(event);
    setEventCounts(prev => ({ ...prev, environmentalEvents: prev.environmentalEvents + 1 }));
    
    mergedConfig.handlers?.onEnvironmentalEvent?.(event);
    
    if (event.severity === 'high' || event.severity === 'critical') {
      showToast('environmental_event', `Environmental alert: ${event.eventType} (${event.value} ${event.unit})`, event.severity);
    }
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleAlert = useCallback((rawAlert: any) => {
    debugLog('Received alert', rawAlert);
    
    // Transform backend alert to frontend format
    const alert: Alert = {
      id: rawAlert.id || rawAlert.alertId,
      tenantId: rawAlert.tenantId,
      type: rawAlert.type || rawAlert.alertType,
      severity: rawAlert.severity,
      title: rawAlert.title || rawAlert.message,
      description: rawAlert.description || rawAlert.details,
      sourceEvents: rawAlert.sourceEvents || rawAlert.relatedEvents || [],
      buildingId: rawAlert.buildingId || rawAlert.location?.buildingId,
      floorId: rawAlert.floorId || rawAlert.location?.floorId,
      zoneId: rawAlert.zoneId || rawAlert.location?.zoneId,
      timestamp: rawAlert.timestamp || rawAlert.createdAt,
      acknowledged: rawAlert.acknowledged || false,
      acknowledgedBy: rawAlert.acknowledgedBy,
      acknowledgedAt: rawAlert.acknowledgedAt,
      resolved: rawAlert.resolved || false,
      resolvedBy: rawAlert.resolvedBy,
      resolvedAt: rawAlert.resolvedAt,
      escalated: rawAlert.escalated || false,
      escalatedAt: rawAlert.escalatedAt,
      priority: rawAlert.priority || 1,
      tags: rawAlert.tags || [],
      metadata: rawAlert.metadata || rawAlert.additionalData,
    };
    
    logEvent('alert', alert);
    setLastEvent(alert);
    setEventCounts(prev => ({ ...prev, alerts: prev.alerts + 1 }));
    
    mergedConfig.handlers?.onAlert?.(alert);
    
    showToast('alert', `${alert.severity.toUpperCase()}: ${alert.title}`, alert.severity);
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleAlertAcknowledged = useCallback((data: any) => {
    debugLog('Alert acknowledged', data);
    const transformedData = {
      alertId: data.alertId || data.id,
      userId: data.userId || data.acknowledgedBy,
      timestamp: data.timestamp || data.acknowledgedAt || new Date().toISOString(),
    };
    
    logEvent('alert_acknowledged', transformedData);
    mergedConfig.handlers?.onAlertAcknowledged?.(transformedData);
    showToast('alert', `Alert ${transformedData.alertId} acknowledged`);
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleAlertResolved = useCallback((data: any) => {
    debugLog('Alert resolved', data);
    const transformedData = {
      alertId: data.alertId || data.id,
      userId: data.userId || data.resolvedBy,
      timestamp: data.timestamp || data.resolvedAt || new Date().toISOString(),
    };
    
    logEvent('alert_resolved', transformedData);
    mergedConfig.handlers?.onAlertResolved?.(transformedData);
    showToast('alert', `Alert ${transformedData.alertId} resolved`);
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleAlertEscalated = useCallback((data: any) => {
    debugLog('Alert escalated', data);
    const transformedData = {
      alertId: data.alertId || data.id,
      escalatedBy: data.escalatedBy || data.userId,
      timestamp: data.timestamp || data.escalatedAt || new Date().toISOString(),
    };
    
    logEvent('alert_escalated', transformedData);
    mergedConfig.handlers?.onAlertEscalated?.(transformedData);
    showToast('alert', `Alert ${transformedData.alertId} escalated`, 'high');
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleSystemStatus = useCallback((rawStatus: any) => {
    debugLog('Received system status', rawStatus);
    
    // Transform backend status to frontend format
    const status: SystemStatus = {
      id: rawStatus.id || rawStatus.statusId,
      tenantId: rawStatus.tenantId,
      component: rawStatus.component || rawStatus.componentName,
      service: rawStatus.service || rawStatus.serviceName,
      status: rawStatus.status,
      message: rawStatus.message || rawStatus.description,
      timestamp: rawStatus.timestamp || rawStatus.updatedAt,
      buildingId: rawStatus.buildingId,
      floorId: rawStatus.floorId,
      healthScore: rawStatus.healthScore,
      lastSeen: rawStatus.lastSeen,
      metadata: rawStatus.metadata || rawStatus.additionalData,
    };
    
    logEvent('system_status', status);
    setLastEvent(status);
    setEventCounts(prev => ({ ...prev, systemStatus: prev.systemStatus + 1 }));
    
    mergedConfig.handlers?.onSystemStatus?.(status);
    
    if (status.status === 'offline' || status.status === 'error') {
      showToast('system_status', `System alert: ${status.component} is ${status.status}`);
    }
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleDeviceStatus = useCallback((rawStatus: any) => {
    debugLog('Received device status', rawStatus);
    
    // Transform backend device status to frontend format
    const status: DeviceStatus = {
      id: rawStatus.id || rawStatus.statusId,
      tenantId: rawStatus.tenantId,
      deviceId: rawStatus.deviceId,
      deviceType: rawStatus.deviceType || rawStatus.type,
      status: rawStatus.status,
      buildingId: rawStatus.buildingId || rawStatus.location?.buildingId,
      floorId: rawStatus.floorId || rawStatus.location?.floorId,
      zoneId: rawStatus.zoneId || rawStatus.location?.zoneId,
      timestamp: rawStatus.timestamp || rawStatus.updatedAt,
      batteryLevel: rawStatus.batteryLevel,
      signalStrength: rawStatus.signalStrength,
      lastSeen: rawStatus.lastSeen,
      firmwareVersion: rawStatus.firmwareVersion,
      metadata: rawStatus.metadata || rawStatus.additionalData,
    };
    
    logEvent('device_status', status);
    setEventCounts(prev => ({ ...prev, deviceStatus: prev.deviceStatus + 1 }));
    
    mergedConfig.handlers?.onDeviceStatus?.(status);
    
    if (status.status === 'offline' || status.status === 'error') {
      showToast('system_status', `Device alert: ${status.deviceType} ${status.deviceId} is ${status.status}`);
    }
  }, [mergedConfig.handlers, showToast, debugLog, logEvent]);

  const handleVideoFeed = useCallback((rawFeed: any) => {
    debugLog('Received video feed update', rawFeed);
    
    // Transform backend feed to frontend format
    const feed: VideoFeed = {
      cameraId: rawFeed.cameraId,
      streamUrl: rawFeed.streamUrl || rawFeed.url,
      status: rawFeed.status,
      quality: rawFeed.quality || 'medium',
      resolution: rawFeed.resolution || '1920x1080',
      fps: rawFeed.fps || 30,
      timestamp: rawFeed.timestamp || new Date().toISOString(),
      buildingId: rawFeed.buildingId || rawFeed.location?.buildingId,
      floorId: rawFeed.floorId || rawFeed.location?.floorId,
      zoneId: rawFeed.zoneId || rawFeed.location?.zoneId,
    };
    
    logEvent('video_feed', feed);
    mergedConfig.handlers?.onVideoFeed?.(feed);
  }, [mergedConfig.handlers, debugLog, logEvent]);

  const handleConnectionStatusChange = useCallback((status: ConnectionStatus) => {
    debugLog(`Connection status changed to: ${status}`);
    setConnectionStatus(status);
    mergedConfig.handlers?.onConnectionStatusChange?.(status);
    
    switch (status) {
      case 'connected':
        toast.success('Connected to real-time service');
        reconnectAttemptsRef.current = 0;
        break;
      case 'disconnected':
        toast.error('Disconnected from real-time service');
        break;
      case 'reconnecting':
        toast.loading('Reconnecting to real-time service...');
        break;
      case 'error':
        toast.error('Connection error occurred');
        break;
    }
  }, [mergedConfig.handlers, debugLog]);

  const handleError = useCallback((error: Error) => {
    debugLog('Socket error occurred', error);
    console.error('Socket.IO error:', error);
    mergedConfig.handlers?.onError?.(error);
    toast.error(`Real-time connection error: ${error.message}`);
  }, [mergedConfig.handlers, debugLog]);

  const handleSubscriptionConfirmed = useCallback((data: any) => {
    debugLog('Subscription confirmed', data);
    mergedConfig.handlers?.onSubscriptionConfirmed?.(data);
  }, [mergedConfig.handlers, debugLog]);

  const handleSubscriptionError = useCallback((data: any) => {
    debugLog('Subscription error', data);
    mergedConfig.handlers?.onSubscriptionError?.(data);
    toast.error(`Subscription error: ${data.error}`);
  }, [mergedConfig.handlers, debugLog]);

  // Connection management
  const connect = useCallback(() => {
    if (socket?.connected) return;

    debugLog('Attempting to connect to real-time service', {
      url: mergedConfig.url,
      tenantId: mergedConfig.tenantId,
      hasToken: !!mergedConfig.token,
    });

    setConnectionStatus('connecting');

    // Convert HTTP URL to WebSocket URL for Socket.IO
    const socketUrl = mergedConfig.url!.replace(/^http/, 'ws');
    
    const newSocket = io(socketUrl, {
      auth: {
        token: mergedConfig.token,
        tenantId: mergedConfig.tenantId,
      },
      extraHeaders: {
        'X-Tenant-ID': mergedConfig.tenantId,
        'Authorization': `Bearer ${mergedConfig.token}`,
      },
      transports: ['websocket', 'polling'],
      timeout: 20000,
      forceNew: true,
      reconnection: false, // We handle reconnection manually
    });

    // Connection event handlers
    newSocket.on('connect', () => {
      debugLog('Socket.IO connected', { socketId: newSocket.id });
      console.log('Socket.IO connected:', newSocket.id);
      handleConnectionStatusChange('connected');
      
      // Apply initial subscriptions with permission checks
      if (mergedConfig.subscriptions?.buildings) {
        mergedConfig.subscriptions.buildings.forEach(buildingId => {
          debugLog('Subscribing to building', buildingId);
          newSocket.emit('subscribe_building', { 
            buildingId,
            permissions: mergedConfig.subscriptions?.permissions || []
          });
        });
      }
      
      if (mergedConfig.subscriptions?.floors) {
        mergedConfig.subscriptions.floors.forEach(({ buildingId, floorId }) => {
          debugLog('Subscribing to floor', { buildingId, floorId });
          newSocket.emit('subscribe_floor', { 
            buildingId, 
            floorId,
            permissions: mergedConfig.subscriptions?.permissions || []
          });
        });
      }

      if (mergedConfig.subscriptions?.zones) {
        mergedConfig.subscriptions.zones.forEach(({ buildingId, floorId, zoneId }) => {
          debugLog('Subscribing to zone', { buildingId, floorId, zoneId });
          newSocket.emit('subscribe_zone', { 
            buildingId, 
            floorId, 
            zoneId,
            permissions: mergedConfig.subscriptions?.permissions || []
          });
        });
      }

      if (mergedConfig.subscriptions?.devices) {
        mergedConfig.subscriptions.devices.forEach(deviceId => {
          debugLog('Subscribing to device', deviceId);
          newSocket.emit('subscribe_device', { 
            deviceId,
            permissions: mergedConfig.subscriptions?.permissions || []
          });
        });
      }
    });

    newSocket.on('disconnect', (reason) => {
      debugLog('Socket.IO disconnected', { reason });
      console.log('Socket.IO disconnected:', reason);
      handleConnectionStatusChange('disconnected');
      
      // Attempt reconnection if not manually disconnected
      if (reason !== 'io client disconnect' && reconnectAttemptsRef.current < mergedConfig.reconnectAttempts!) {
        scheduleReconnect();
      }
    });

    newSocket.on('connect_error', (error) => {
      debugLog('Socket.IO connection error', error);
      console.error('Socket.IO connection error:', error);
      handleConnectionStatusChange('error');
      handleError(error);
      
      if (reconnectAttemptsRef.current < mergedConfig.reconnectAttempts!) {
        scheduleReconnect();
      }
    });

    // Authentication error handling
    newSocket.on('auth_error', (error) => {
      debugLog('Authentication error', error);
      console.error('Socket.IO authentication error:', error);
      handleError(new Error(`Authentication failed: ${error.message}`));
      // Don't attempt reconnection on auth errors
    });

    // Tenant context error handling
    newSocket.on('tenant_error', (error) => {
      debugLog('Tenant context error', error);
      console.error('Socket.IO tenant error:', error);
      handleError(new Error(`Tenant access denied: ${error.message}`));
    });

    // Event handlers - Updated to match backend event names
    newSocket.on('access_event', handleAccessEvent);
    newSocket.on('video_event', handleVideoEvent);
    newSocket.on('environmental_event', handleEnvironmentalEvent);
    newSocket.on('alert', handleAlert);
    newSocket.on('alert_acknowledged', handleAlertAcknowledged);
    newSocket.on('alert_resolved', handleAlertResolved);
    newSocket.on('alert_escalated', handleAlertEscalated);
    newSocket.on('system_status', handleSystemStatus);
    newSocket.on('device_status', handleDeviceStatus);
    newSocket.on('video_feed', handleVideoFeed);
    newSocket.on('subscription_confirmed', handleSubscriptionConfirmed);
    newSocket.on('subscription_error', handleSubscriptionError);

    // Pong handler for heartbeat
    newSocket.on('pong', () => {
      debugLog('Received pong from server');
    });

    // Heartbeat with enhanced monitoring
    if (mergedConfig.heartbeatInterval) {
      heartbeatIntervalRef.current = setInterval(() => {
        if (newSocket.connected) {
          debugLog('Sending ping to server');
          newSocket.emit('ping', { timestamp: Date.now() });
        }
      }, mergedConfig.heartbeatInterval);
    }

    setSocket(newSocket);
  }, [
    mergedConfig.url,
    mergedConfig.token,
    mergedConfig.tenantId,
    mergedConfig.subscriptions,
    mergedConfig.reconnectAttempts,
    mergedConfig.heartbeatInterval,
    handleConnectionStatusChange,
    handleError,
    handleAccessEvent,
    handleVideoEvent,
    handleEnvironmentalEvent,
    handleAlert,
    handleAlertAcknowledged,
    handleAlertResolved,
    handleAlertEscalated,
    handleSystemStatus,
    handleDeviceStatus,
    handleVideoFeed,
    handleSubscriptionConfirmed,
    handleSubscriptionError,
    debugLog,
  ]);

  const scheduleReconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }

    reconnectAttemptsRef.current++;
    setConnectionStatus('reconnecting');

    // Exponential backoff with jitter
    const baseDelay = mergedConfig.reconnectDelay! * Math.pow(2, reconnectAttemptsRef.current - 1);
    const jitter = Math.random() * 1000; // Add up to 1 second of jitter
    const delay = Math.min(baseDelay + jitter, 30000); // Cap at 30 seconds
    
    debugLog(`Scheduling reconnection attempt ${reconnectAttemptsRef.current}/${mergedConfig.reconnectAttempts}`, {
      delay,
      baseDelay,
      jitter,
    });
    
    reconnectTimeoutRef.current = setTimeout(() => {
      console.log(`Reconnection attempt ${reconnectAttemptsRef.current}/${mergedConfig.reconnectAttempts}`);
      connect();
    }, delay);
  }, [mergedConfig.reconnectDelay, mergedConfig.reconnectAttempts, connect, debugLog]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
    }

    if (socket) {
      socket.disconnect();
      setSocket(null);
    }
    
    setConnectionStatus('disconnected');
    reconnectAttemptsRef.current = 0;
  }, [socket]);

  const reconnect = useCallback(() => {
    disconnect();
    setTimeout(connect, 100);
  }, [disconnect, connect]);

  // Enhanced subscription management with permission checks
  const subscribeToBuilding = useCallback((buildingId: string) => {
    if (socket?.connected) {
      debugLog('Subscribing to building', buildingId);
      socket.emit('subscribe_building', { 
        buildingId,
        permissions: mergedConfig.subscriptions?.permissions || []
      });
      subscriptionsRef.current.buildings = [
        ...(subscriptionsRef.current.buildings || []),
        buildingId,
      ].filter((id, index, arr) => arr.indexOf(id) === index);
    }
  }, [socket, mergedConfig.subscriptions?.permissions, debugLog]);

  const unsubscribeFromBuilding = useCallback((buildingId: string) => {
    if (socket?.connected) {
      debugLog('Unsubscribing from building', buildingId);
      socket.emit('unsubscribe_building', { buildingId });
      subscriptionsRef.current.buildings = subscriptionsRef.current.buildings?.filter(
        id => id !== buildingId
      );
    }
  }, [socket, debugLog]);

  const subscribeToFloor = useCallback((buildingId: string, floorId: string) => {
    if (socket?.connected) {
      debugLog('Subscribing to floor', { buildingId, floorId });
      socket.emit('subscribe_floor', { 
        buildingId, 
        floorId,
        permissions: mergedConfig.subscriptions?.permissions || []
      });
      subscriptionsRef.current.floors = [
        ...(subscriptionsRef.current.floors || []),
        { buildingId, floorId },
      ].filter((floor, index, arr) => 
        arr.findIndex(f => f.buildingId === floor.buildingId && f.floorId === floor.floorId) === index
      );
    }
  }, [socket, mergedConfig.subscriptions?.permissions, debugLog]);

  const unsubscribeFromFloor = useCallback((buildingId: string, floorId: string) => {
    if (socket?.connected) {
      debugLog('Unsubscribing from floor', { buildingId, floorId });
      socket.emit('unsubscribe_floor', { buildingId, floorId });
      subscriptionsRef.current.floors = subscriptionsRef.current.floors?.filter(
        floor => !(floor.buildingId === buildingId && floor.floorId === floorId)
      );
    }
  }, [socket, debugLog]);

  const subscribeToZone = useCallback((buildingId: string, floorId: string, zoneId: string) => {
    if (socket?.connected) {
      debugLog('Subscribing to zone', { buildingId, floorId, zoneId });
      socket.emit('subscribe_zone', { 
        buildingId, 
        floorId, 
        zoneId,
        permissions: mergedConfig.subscriptions?.permissions || []
      });
      subscriptionsRef.current.zones = [
        ...(subscriptionsRef.current.zones || []),
        { buildingId, floorId, zoneId },
      ].filter((zone, index, arr) => 
        arr.findIndex(z => z.buildingId === zone.buildingId && z.floorId === zone.floorId && z.zoneId === zone.zoneId) === index
      );
    }
  }, [socket, mergedConfig.subscriptions?.permissions, debugLog]);

  const unsubscribeFromZone = useCallback((buildingId: string, floorId: string, zoneId: string) => {
    if (socket?.connected) {
      debugLog('Unsubscribing from zone', { buildingId, floorId, zoneId });
      socket.emit('unsubscribe_zone', { buildingId, floorId, zoneId });
      subscriptionsRef.current.zones = subscriptionsRef.current.zones?.filter(
        zone => !(zone.buildingId === buildingId && zone.floorId === floorId && zone.zoneId === zoneId)
      );
    }
  }, [socket, debugLog]);

  const subscribeToDevice = useCallback((deviceId: string) => {
    if (socket?.connected) {
      debugLog('Subscribing to device', deviceId);
      socket.emit('subscribe_device', { 
        deviceId,
        permissions: mergedConfig.subscriptions?.permissions || []
      });
      subscriptionsRef.current.devices = [
        ...(subscriptionsRef.current.devices || []),
        deviceId,
      ].filter((id, index, arr) => arr.indexOf(id) === index);
    }
  }, [socket, mergedConfig.subscriptions?.permissions, debugLog]);

  const unsubscribeFromDevice = useCallback((deviceId: string) => {
    if (socket?.connected) {
      debugLog('Unsubscribing from device', deviceId);
      socket.emit('unsubscribe_device', { deviceId });
      subscriptionsRef.current.devices = subscriptionsRef.current.devices?.filter(
        id => id !== deviceId
      );
    }
  }, [socket, debugLog]);

  const updateSubscriptions = useCallback((subscriptions: SubscriptionOptions) => {
    debugLog('Updating subscriptions', subscriptions);
    
    // Unsubscribe from current subscriptions
    subscriptionsRef.current.buildings?.forEach(buildingId => {
      if (!subscriptions.buildings?.includes(buildingId)) {
        unsubscribeFromBuilding(buildingId);
      }
    });

    subscriptionsRef.current.floors?.forEach(({ buildingId, floorId }) => {
      if (!subscriptions.floors?.find(f => f.buildingId === buildingId && f.floorId === floorId)) {
        unsubscribeFromFloor(buildingId, floorId);
      }
    });

    subscriptionsRef.current.zones?.forEach(({ buildingId, floorId, zoneId }) => {
      if (!subscriptions.zones?.find(z => z.buildingId === buildingId && z.floorId === floorId && z.zoneId === zoneId)) {
        unsubscribeFromZone(buildingId, floorId, zoneId);
      }
    });

    subscriptionsRef.current.devices?.forEach(deviceId => {
      if (!subscriptions.devices?.includes(deviceId)) {
        unsubscribeFromDevice(deviceId);
      }
    });

    // Subscribe to new subscriptions
    subscriptions.buildings?.forEach(buildingId => {
      if (!subscriptionsRef.current.buildings?.includes(buildingId)) {
        subscribeToBuilding(buildingId);
      }
    });

    subscriptions.floors?.forEach(({ buildingId, floorId }) => {
      if (!subscriptionsRef.current.floors?.find(f => f.buildingId === buildingId && f.floorId === floorId)) {
        subscribeToFloor(buildingId, floorId);
      }
    });

    subscriptions.zones?.forEach(({ buildingId, floorId, zoneId }) => {
      if (!subscriptionsRef.current.zones?.find(z => z.buildingId === buildingId && z.floorId === floorId && z.zoneId === zoneId)) {
        subscribeToZone(buildingId, floorId, zoneId);
      }
    });

    subscriptions.devices?.forEach(deviceId => {
      if (!subscriptionsRef.current.devices?.includes(deviceId)) {
        subscribeToDevice(deviceId);
      }
    });

    subscriptionsRef.current = subscriptions;
  }, [
    subscribeToBuilding, 
    unsubscribeFromBuilding, 
    subscribeToFloor, 
    unsubscribeFromFloor,
    subscribeToZone,
    unsubscribeFromZone,
    subscribeToDevice,
    unsubscribeFromDevice,
    debugLog
  ]);

  // Utility functions
  const clearEventCounts = useCallback(() => {
    debugLog('Clearing event counts');
    setEventCounts({
      accessEvents: 0,
      videoEvents: 0,
      environmentalEvents: 0,
      alerts: 0,
      systemStatus: 0,
      deviceStatus: 0,
    });
  }, [debugLog]);

  const getConnectionInfo = useCallback(() => ({
    id: socket?.id,
    connected: socket?.connected || false,
    transport: socket?.io.engine?.transport?.name,
    ping: socket?.ping,
    tenantId: mergedConfig.tenantId,
    userId: apiClient.getUser()?.id || null,
    subscriptions: subscriptionsRef.current,
  }), [socket, mergedConfig.tenantId]);

  const enableDebugMode = useCallback(() => {
    debugModeRef.current = true;
    console.log('[useRealtime] Debug mode enabled');
  }, []);

  const disableDebugMode = useCallback(() => {
    debugModeRef.current = false;
    eventLogRef.current = [];
    console.log('[useRealtime] Debug mode disabled');
  }, []);

  // Auto-connect on mount with enhanced validation
  useEffect(() => {
    if (mergedConfig.autoConnect && mergedConfig.tenantId && mergedConfig.token) {
      // Validate token is not expired
      const user = apiClient.getUser();
      const isAuthenticated = apiClient.isAuthenticated();
      
      if (isAuthenticated && user) {
        debugLog('Auto-connecting with valid authentication', {
          tenantId: mergedConfig.tenantId,
          userId: user.id,
        });
        connect();
      } else {
        debugLog('Skipping auto-connect due to invalid authentication');
      }
    }

    return () => {
      debugLog('Component unmounting, disconnecting');
      disconnect();
    };
  }, [mergedConfig.autoConnect, mergedConfig.tenantId, mergedConfig.token, connect, disconnect, debugLog]);

  // Update subscriptions when config changes
  useEffect(() => {
    if (mergedConfig.subscriptions && socket?.connected) {
      updateSubscriptions(mergedConfig.subscriptions);
    }
  }, [mergedConfig.subscriptions, socket?.connected, updateSubscriptions]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (heartbeatIntervalRef.current) {
        clearInterval(heartbeatIntervalRef.current);
      }
    };
  }, []);

  return {
    socket,
    connectionStatus,
    isConnected,
    lastEvent,
    eventCounts,
    connect,
    disconnect,
    reconnect,
    subscribeToBuilding,
    unsubscribeFromBuilding,
    subscribeToFloor,
    unsubscribeFromFloor,
    subscribeToZone,
    unsubscribeFromZone,
    subscribeToDevice,
    unsubscribeFromDevice,
    updateSubscriptions,
    clearEventCounts,
    getConnectionInfo,
    enableDebugMode,
    disableDebugMode,
  };
}

// Convenience hooks for specific event types
export function useAccessEvents(config: Omit<UseRealtimeConfig, 'handlers'> & {
  onAccessEvent?: (event: AccessEvent) => void;
}) {
  return useRealtime({
    ...config,
    handlers: {
      onAccessEvent: config.onAccessEvent,
    },
  });
}

export function useVideoEvents(config: Omit<UseRealtimeConfig, 'handlers'> & {
  onVideoEvent?: (event: VideoEvent) => void;
}) {
  return useRealtime({
    ...config,
    handlers: {
      onVideoEvent: config.onVideoEvent,
    },
  });
}

export function useAlerts(config: Omit<UseRealtimeConfig, 'handlers'> & {
  onAlert?: (alert: Alert) => void;
  onAlertAcknowledged?: (data: { alertId: string; userId: string }) => void;
  onAlertResolved?: (data: { alertId: string; userId: string }) => void;
}) {
  return useRealtime({
    ...config,
    handlers: {
      onAlert: config.onAlert,
      onAlertAcknowledged: config.onAlertAcknowledged,
      onAlertResolved: config.onAlertResolved,
    },
  });
}

export function useSystemStatus(config: Omit<UseRealtimeConfig, 'handlers'> & {
  onSystemStatus?: (status: SystemStatus) => void;
}) {
  return useRealtime({
    ...config,
    handlers: {
      onSystemStatus: config.onSystemStatus,
    },
  });
}
