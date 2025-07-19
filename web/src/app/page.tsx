'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Responsive, WidthProvider, Layout } from 'react-grid-layout';
import apiClient from '@/lib/api';
import { useRealtime } from '@/hooks/useRealtime';
import {
  Shield,
  Camera,
  AlertTriangle,
  Users,
  Activity,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Settings,
  Plus,
  MoreVertical,
  RefreshCw,
  Bell,
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
  TrendingDown,
  MapPin,
  Thermometer,
  Droplets,
  Zap,
  Building,
  DoorOpen,
  DoorClosed,
  Video,
  VideoOff,
  Wifi,
  WifiOff,
  Calendar,
  BarChart3,
  PieChart,
  LineChart,
  Grid3X3,
  Maximize2,
  Minimize2,
  Download,
  Filter,
  Search,
  ChevronDown,
  ChevronUp,
  Info,
  Warning,
  AlertCircle,
  Loader2
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import type {
  Door,
  Camera as CameraType,
  Alert as AlertType,
  AccessEvent,
  EnvironmentalReading as EnvironmentalReadingType,
  Building,
  Floor,
  PaginatedResponse,
  ListQueryParams
} from '@sparc/shared';

const ResponsiveGridLayout = WidthProvider(Responsive);

// Transform backend types to frontend display types
interface AccessPoint {
  id: string;
  name: string;
  location: string;
  building: string;
  floor: string;
  status: 'online' | 'offline' | 'error';
  isLocked: boolean;
  lastActivity: string;
  accessCount: number;
  batteryLevel?: number;
  signalStrength: number;
}

interface Camera {
  id: string;
  name: string;
  location: string;
  building: string;
  floor: string;
  status: 'online' | 'offline' | 'recording' | 'error';
  isRecording: boolean;
  lastMotion: string;
  streamUrl?: string;
  resolution: string;
  fps: number;
}

interface Alert {
  id: string;
  type: 'unauthorized_access' | 'door_ajar' | 'camera_offline' | 'environmental' | 'system_error';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  location: string;
  timestamp: string;
  acknowledged: boolean;
  assignedTo?: string;
}

interface EnvironmentalReading {
  id: string;
  sensorType: 'temperature' | 'humidity' | 'water' | 'smoke';
  location: string;
  value: number;
  unit: string;
  status: 'normal' | 'warning' | 'critical';
  timestamp: string;
}

interface DashboardStats {
  totalAccessPoints: number;
  onlineAccessPoints: number;
  totalCameras: number;
  onlineCameras: number;
  activeAlerts: number;
  criticalAlerts: number;
  todayEvents: number;
  currentOccupancy: number;
  maxOccupancy: number;
}

interface RealtimeEvent {
  id: string;
  type: 'access_granted' | 'access_denied' | 'door_opened' | 'motion_detected' | 'alert_triggered';
  location: string;
  user?: string;
  timestamp: string;
  details: string;
}

// Widget types for customizable dashboard
type WidgetType = 
  | 'system_overview'
  | 'access_points_status'
  | 'cameras_status'
  | 'active_alerts'
  | 'recent_events'
  | 'environmental_monitoring'
  | 'occupancy_tracking'
  | 'security_metrics'
  | 'building_overview'
  | 'quick_actions';

interface DashboardWidget {
  id: string;
  type: WidgetType;
  title: string;
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  minH?: number;
  maxW?: number;
  maxH?: number;
}

// Default dashboard layout
const defaultLayout: DashboardWidget[] = [
  { id: 'system_overview', type: 'system_overview', title: 'System Overview', x: 0, y: 0, w: 6, h: 2, minW: 4, minH: 2 },
  { id: 'quick_actions', type: 'quick_actions', title: 'Quick Actions', x: 6, y: 0, w: 6, h: 2, minW: 3, minH: 2 },
  { id: 'active_alerts', type: 'active_alerts', title: 'Active Alerts', x: 0, y: 2, w: 4, h: 3, minW: 3, minH: 3 },
  { id: 'recent_events', type: 'recent_events', title: 'Recent Events', x: 4, y: 2, w: 4, h: 3, minW: 3, minH: 3 },
  { id: 'building_overview', type: 'building_overview', title: 'Building Overview', x: 8, y: 2, w: 4, h: 3, minW: 3, minH: 3 },
  { id: 'access_points_status', type: 'access_points_status', title: 'Access Points', x: 0, y: 5, w: 6, h: 3, minW: 4, minH: 3 },
  { id: 'cameras_status', type: 'cameras_status', title: 'Cameras', x: 6, y: 5, w: 6, h: 3, minW: 4, minH: 3 },
  { id: 'environmental_monitoring', type: 'environmental_monitoring', title: 'Environmental', x: 0, y: 8, w: 4, h: 2, minW: 3, minH: 2 },
  { id: 'occupancy_tracking', type: 'occupancy_tracking', title: 'Occupancy', x: 4, y: 8, w: 4, h: 2, minW: 3, minH: 2 },
  { id: 'security_metrics', type: 'security_metrics', title: 'Security Metrics', x: 8, y: 8, w: 4, h: 2, minW: 3, minH: 2 }
];

export default function DashboardPage() {
  // State management
  const [dashboardStats, setDashboardStats] = useState<DashboardStats>({
    totalAccessPoints: 0,
    onlineAccessPoints: 0,
    totalCameras: 0,
    onlineCameras: 0,
    activeAlerts: 0,
    criticalAlerts: 0,
    todayEvents: 0,
    currentOccupancy: 0,
    maxOccupancy: 100
  });
  const [accessPoints, setAccessPoints] = useState<AccessPoint[]>([]);
  const [cameras, setCameras] = useState<Camera[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [recentEvents, setRecentEvents] = useState<RealtimeEvent[]>([]);
  const [environmentalReadings, setEnvironmentalReadings] = useState<EnvironmentalReading[]>([]);
  const [widgets, setWidgets] = useState<DashboardWidget[]>(defaultLayout);
  const [isEditMode, setIsEditMode] = useState(false);
  const [selectedBuilding, setSelectedBuilding] = useState<string>('all');
  const [selectedFloor, setSelectedFloor] = useState<string>('all');
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [buildings, setBuildings] = useState<Building[]>([]);
  const [floors, setFloors] = useState<Floor[]>([]);

  const { toast } = useToast();

  // Real-time connection using the updated useRealtime hook
  const {
    isConnected,
    lastEvent,
    eventCounts,
    connect: connectRealtime,
    disconnect: disconnectRealtime,
    subscribeToBuilding,
    unsubscribeFromBuilding,
    updateSubscriptions
  } = useRealtime({
    tenantId: apiClient.getCurrentTenantId() || '',
    token: apiClient.getUser() ? 'authenticated' : '',
    autoConnect: true,
    handlers: {
      onAccessEvent: (event) => {
        // Transform access event to realtime event format
        const realtimeEvent: RealtimeEvent = {
          id: event.id,
          type: event.eventType === 'access_granted' ? 'access_granted' : 'access_denied',
          location: `${event.buildingId} - ${event.floorId}`,
          user: event.userId,
          timestamp: new Date(event.timestamp).toLocaleTimeString(),
          details: `${event.eventType} at door ${event.doorId}`
        };
        setRecentEvents(prev => [realtimeEvent, ...prev.slice(0, 49)]);
        
        // Show toast for critical events
        if (event.eventType === 'access_denied' || event.eventType === 'tailgating_detected') {
          toast({
            title: "Security Event",
            description: `${event.eventType} at ${realtimeEvent.location}`,
            variant: "destructive",
          });
        }
      },
      onAlert: (alert) => {
        // Transform backend alert to frontend format
        const frontendAlert: Alert = {
          id: alert.id,
          type: alert.type === 'security' ? 'unauthorized_access' : 
                alert.type === 'environmental' ? 'environmental' : 'system_error',
          severity: alert.severity,
          message: alert.title,
          location: `${alert.buildingId} - ${alert.floorId}`,
          timestamp: new Date(alert.timestamp).toLocaleTimeString(),
          acknowledged: alert.acknowledged,
          assignedTo: alert.acknowledgedBy
        };
        
        setAlerts(prev => {
          const existing = prev.find(a => a.id === alert.id);
          if (existing) {
            return prev.map(a => a.id === alert.id ? frontendAlert : a);
          }
          return [frontendAlert, ...prev];
        });

        // Show toast for new alerts
        if (!alert.acknowledged) {
          toast({
            title: "New Alert",
            description: `${alert.severity.toUpperCase()}: ${alert.title}`,
            variant: alert.severity === 'critical' || alert.severity === 'high' ? "destructive" : "default",
          });
        }
      },
      onDeviceStatus: (status) => {
        // Update device status in real-time
        if (status.deviceType === 'door_controller') {
          setAccessPoints(prev => prev.map(ap => 
            ap.id === status.deviceId 
              ? { ...ap, status: status.status as any, lastActivity: 'Just now' }
              : ap
          ));
        } else if (status.deviceType === 'camera') {
          setCameras(prev => prev.map(cam => 
            cam.id === status.deviceId 
              ? { ...cam, status: status.status as any, lastMotion: 'Just now' }
              : cam
          ));
        }
      },
      onConnectionStatusChange: (status) => {
        if (status === 'connected') {
          toast({
            title: "Connected",
            description: "Real-time updates are now active",
            duration: 3000,
          });
        } else if (status === 'disconnected') {
          toast({
            title: "Disconnected",
            description: "Real-time updates are unavailable",
            variant: "destructive",
            duration: 5000,
          });
        }
      },
      onError: (error) => {
        console.error('Real-time connection error:', error);
        toast({
          title: "Connection Error",
          description: "Real-time updates may be interrupted",
          variant: "destructive",
        });
      }
    }
  });

  // Data transformation helpers
  const transformDoorToAccessPoint = (door: Door, building?: Building, floor?: Floor): AccessPoint => {
    return {
      id: door.id,
      name: door.name,
      location: `${building?.name || 'Unknown Building'} - ${floor?.name || 'Unknown Floor'}`,
      building: building?.name || 'Unknown Building',
      floor: floor?.name || 'Unknown Floor',
      status: door.status === 'online' ? 'online' : door.status === 'offline' ? 'offline' : 'error',
      isLocked: door.isLocked,
      lastActivity: door.lastActivity ? new Date(door.lastActivity).toLocaleString() : 'Never',
      accessCount: door.accessCount || 0,
      batteryLevel: door.batteryLevel,
      signalStrength: door.signalStrength || 0
    };
  };

  const transformCameraToCamera = (camera: CameraType, building?: Building, floor?: Floor): Camera => {
    return {
      id: camera.id,
      name: camera.name,
      location: `${building?.name || 'Unknown Building'} - ${floor?.name || 'Unknown Floor'}`,
      building: building?.name || 'Unknown Building',
      floor: floor?.name || 'Unknown Floor',
      status: camera.status === 'online' ? 'online' : 
              camera.status === 'offline' ? 'offline' : 
              camera.isRecording ? 'recording' : 'error',
      isRecording: camera.isRecording,
      lastMotion: camera.lastMotion ? new Date(camera.lastMotion).toLocaleString() : 'Never',
      streamUrl: camera.streamUrl,
      resolution: camera.resolution || '1080p',
      fps: camera.fps || 30
    };
  };

  const transformAlertToAlert = (alert: AlertType, building?: Building, floor?: Floor): Alert => {
    return {
      id: alert.id,
      type: alert.type === 'security' ? 'unauthorized_access' : 
            alert.type === 'environmental' ? 'environmental' : 'system_error',
      severity: alert.severity,
      message: alert.title,
      location: `${building?.name || 'Unknown Building'} - ${floor?.name || 'Unknown Floor'}`,
      timestamp: new Date(alert.timestamp).toLocaleString(),
      acknowledged: alert.acknowledged,
      assignedTo: alert.acknowledgedBy
    };
  };

  const transformEnvironmentalReading = (reading: EnvironmentalReadingType): EnvironmentalReading => {
    return {
      id: reading.id,
      sensorType: reading.sensorType as any,
      location: reading.location || 'Unknown Location',
      value: reading.value,
      unit: reading.unit,
      status: reading.status === 'normal' ? 'normal' : 
              reading.status === 'warning' ? 'warning' : 'critical',
      timestamp: new Date(reading.timestamp).toLocaleString()
    };
  };

  // Load initial data using ApiClient
  useEffect(() => {
    loadDashboardData();
  }, [selectedBuilding, selectedFloor]);

  const loadDashboardData = async () => {
    if (!apiClient.isAuthenticated()) {
      setError('Not authenticated');
      setLoading(false);
      return;
    }

    setRefreshing(true);
    setError(null);
    
    try {
      // Build query parameters for filtering
      const queryParams: ListQueryParams = {
        limit: 100,
        offset: 0
      };

      if (selectedBuilding !== 'all') {
        queryParams.buildingId = selectedBuilding;
      }
      if (selectedFloor !== 'all') {
        queryParams.floorId = selectedFloor;
      }

      // Load all data in parallel with proper error handling
      const [
        buildingsResponse,
        floorsResponse,
        doorsResponse,
        camerasResponse,
        alertsResponse,
        accessEventsResponse,
        environmentalResponse
      ] = await Promise.allSettled([
        apiClient.getBuildings({ limit: 50 }),
        apiClient.getFloors({ limit: 200 }),
        apiClient.getDoors(queryParams),
        apiClient.getCameras(queryParams),
        apiClient.getAlerts({ ...queryParams, acknowledged: false }),
        apiClient.getAccessEvents({ ...queryParams, limit: 50 }),
        // Note: Environmental readings endpoint may not exist yet, handle gracefully
        apiClient.get<PaginatedResponse<EnvironmentalReadingType>>('/api/v1/environmental/readings', { 
          ...queryParams 
        }).catch(() => ({ data: [], total: 0, page: 1, limit: 100 }))
      ]);

      // Process buildings
      const buildingsData = buildingsResponse.status === 'fulfilled' ? buildingsResponse.value.data : [];
      setBuildings(buildingsData);

      // Process floors
      const floorsData = floorsResponse.status === 'fulfilled' ? floorsResponse.value.data : [];
      setFloors(floorsData);

      // Process doors (access points)
      if (doorsResponse.status === 'fulfilled') {
        const doorsData = doorsResponse.value.data;
        const transformedAccessPoints = doorsData.map(door => {
          const building = buildingsData.find(b => b.id === door.buildingId);
          const floor = floorsData.find(f => f.id === door.floorId);
          return transformDoorToAccessPoint(door, building, floor);
        });
        setAccessPoints(transformedAccessPoints);
      } else {
        console.error('Failed to load doors:', doorsResponse.reason);
        setAccessPoints([]);
      }

      // Process cameras
      if (camerasResponse.status === 'fulfilled') {
        const camerasData = camerasResponse.value.data;
        const transformedCameras = camerasData.map(camera => {
          const building = buildingsData.find(b => b.id === camera.buildingId);
          const floor = floorsData.find(f => f.id === camera.floorId);
          return transformCameraToCamera(camera, building, floor);
        });
        setCameras(transformedCameras);
      } else {
        console.error('Failed to load cameras:', camerasResponse.reason);
        setCameras([]);
      }

      // Process alerts
      if (alertsResponse.status === 'fulfilled') {
        const alertsData = alertsResponse.value.data;
        const transformedAlerts = alertsData.map(alert => {
          const building = buildingsData.find(b => b.id === alert.buildingId);
          const floor = floorsData.find(f => f.id === alert.floorId);
          return transformAlertToAlert(alert, building, floor);
        });
        setAlerts(transformedAlerts);
      } else {
        console.error('Failed to load alerts:', alertsResponse.reason);
        setAlerts([]);
      }

      // Process access events for recent events
      if (accessEventsResponse.status === 'fulfilled') {
        const eventsData = accessEventsResponse.value.data;
        const transformedEvents: RealtimeEvent[] = eventsData.map(event => ({
          id: event.id,
          type: event.eventType === 'access_granted' ? 'access_granted' : 'access_denied',
          location: `${event.buildingId} - ${event.floorId}`,
          user: event.userId,
          timestamp: new Date(event.timestamp).toLocaleTimeString(),
          details: `${event.eventType} at door ${event.doorId}`
        }));
        setRecentEvents(transformedEvents);
      } else {
        console.error('Failed to load access events:', accessEventsResponse.reason);
        setRecentEvents([]);
      }

      // Process environmental readings
      if (environmentalResponse.status === 'fulfilled') {
        const envData = environmentalResponse.value.data;
        const transformedReadings = envData.map(transformEnvironmentalReading);
        setEnvironmentalReadings(transformedReadings);
      } else {
        console.warn('Environmental readings not available');
        setEnvironmentalReadings([]);
      }

      // Calculate dashboard stats from loaded data
      const totalDoors = doorsResponse.status === 'fulfilled' ? doorsResponse.value.total : 0;
      const onlineDoors = doorsResponse.status === 'fulfilled' ? 
        doorsResponse.value.data.filter(d => d.status === 'online').length : 0;
      
      const totalCameras = camerasResponse.status === 'fulfilled' ? camerasResponse.value.total : 0;
      const onlineCameras = camerasResponse.status === 'fulfilled' ? 
        camerasResponse.value.data.filter(c => c.status === 'online').length : 0;
      
      const totalAlerts = alertsResponse.status === 'fulfilled' ? alertsResponse.value.total : 0;
      const criticalAlerts = alertsResponse.status === 'fulfilled' ? 
        alertsResponse.value.data.filter(a => a.severity === 'critical').length : 0;
      
      const todayEvents = accessEventsResponse.status === 'fulfilled' ? accessEventsResponse.value.total : 0;

      setDashboardStats({
        totalAccessPoints: totalDoors,
        onlineAccessPoints: onlineDoors,
        totalCameras: totalCameras,
        onlineCameras: onlineCameras,
        activeAlerts: totalAlerts,
        criticalAlerts: criticalAlerts,
        todayEvents: todayEvents,
        // Get real-time occupancy data from analytics service
        currentOccupancy: (await apiClient.get('/analytics/occupancy/current', { buildingId: selectedBuilding !== 'all' ? selectedBuilding : undefined })).data.count,
        maxOccupancy: 500
      });

      setLastUpdate(new Date());
      setLoading(false);

      // Update real-time subscriptions based on selected filters
      if (selectedBuilding !== 'all') {
        subscribeToBuilding(selectedBuilding);
      }

    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      setError(error instanceof Error ? error.message : 'Failed to load dashboard data');
      toast({
        title: "Error",
        description: "Failed to load dashboard data. Please try again.",
        variant: "destructive",
      });
    } finally {
      setRefreshing(false);
      setLoading(false);
    }
  };

  // Layout change handler
  const handleLayoutChange = useCallback((layout: Layout[]) => {
    if (isEditMode) {
      const updatedWidgets = widgets.map(widget => {
        const layoutItem = layout.find(item => item.i === widget.id);
        if (layoutItem) {
          return {
            ...widget,
            x: layoutItem.x,
            y: layoutItem.y,
            w: layoutItem.w,
            h: layoutItem.h
          };
        }
        return widget;
      });
      setWidgets(updatedWidgets);
    }
  }, [isEditMode, widgets]);

  // Widget action handlers using ApiClient
  const handleDoorControl = async (accessPointId: string, action: 'lock' | 'unlock') => {
    try {
      if (action === 'lock') {
        await apiClient.lockDoor(accessPointId);
      } else {
        await apiClient.unlockDoor(accessPointId);
      }
      
      // Update local state optimistically
      setAccessPoints(prev => prev.map(ap => 
        ap.id === accessPointId 
          ? { ...ap, isLocked: action === 'lock', lastActivity: 'Just now' }
          : ap
      ));

      toast({
        title: "Success",
        description: `Door ${action}ed successfully`,
      });
    } catch (error) {
      console.error(`Failed to ${action} door:`, error);
      toast({
        title: "Error",
        description: `Failed to ${action} door. Please try again.`,
        variant: "destructive",
      });
    }
  };

  const handleAlertAcknowledge = async (alertId: string) => {
    try {
      await apiClient.acknowledgeAlert(alertId);
      
      // Update local state optimistically
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? { ...alert, acknowledged: true } : alert
      ));

      toast({
        title: "Alert Acknowledged",
        description: "Alert has been marked as acknowledged",
      });
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
      toast({
        title: "Error",
        description: "Failed to acknowledge alert. Please try again.",
        variant: "destructive",
      });
    }
  };

  // Bulk actions for quick actions widget
  const handleLockAllDoors = async () => {
    try {
      const onlineAccessPoints = accessPoints.filter(ap => ap.status === 'online');
      const lockPromises = onlineAccessPoints.map(ap => 
        ap.isLocked ? Promise.resolve() : apiClient.lockDoor(ap.id)
      );
      
      await Promise.allSettled(lockPromises);
      
      // Refresh data to get updated states
      await loadDashboardData();
      
      toast({
        title: "Success",
        description: `Attempted to lock ${onlineAccessPoints.length} doors`,
      });
    } catch (error) {
      console.error('Failed to lock all doors:', error);
      toast({
        title: "Error",
        description: "Failed to lock all doors. Some may have been locked successfully.",
        variant: "destructive",
      });
    }
  };

  const handleUnlockAllDoors = async () => {
    try {
      const onlineAccessPoints = accessPoints.filter(ap => ap.status === 'online');
      const unlockPromises = onlineAccessPoints.map(ap => 
        !ap.isLocked ? Promise.resolve() : apiClient.unlockDoor(ap.id)
      );
      
      await Promise.allSettled(unlockPromises);
      
      // Refresh data to get updated states
      await loadDashboardData();
      
      toast({
        title: "Success",
        description: `Attempted to unlock ${onlineAccessPoints.length} doors`,
      });
    } catch (error) {
      console.error('Failed to unlock all doors:', error);
      toast({
        title: "Error",
        description: "Failed to unlock all doors. Some may have been unlocked successfully.",
        variant: "destructive",
      });
    }
  };

  const handleEmergencyLockdown = async () => {
    try {
      // This would typically call a dedicated emergency endpoint
      // For now, we'll lock all doors
      await handleLockAllDoors();
      
      toast({
        title: "Emergency Lockdown Activated",
        description: "All doors have been locked for security",
        variant: "destructive",
      });
    } catch (error) {
      console.error('Failed to activate emergency lockdown:', error);
      toast({
        title: "Error",
        description: "Failed to activate emergency lockdown",
        variant: "destructive",
      });
    }
  };

  // Widget components
  const SystemOverviewWidget = () => (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">System Overview</CardTitle>
        <div className="flex items-center space-x-2">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-xs text-muted-foreground">
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <Shield className="h-4 w-4 text-blue-500" />
              <span className="text-sm font-medium">Access Points</span>
            </div>
            <div className="text-2xl font-bold">
              {dashboardStats.onlineAccessPoints}/{dashboardStats.totalAccessPoints}
            </div>
            <Progress 
              value={(dashboardStats.onlineAccessPoints / dashboardStats.totalAccessPoints) * 100} 
              className="h-2"
            />
          </div>
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <Camera className="h-4 w-4 text-green-500" />
              <span className="text-sm font-medium">Cameras</span>
            </div>
            <div className="text-2xl font-bold">
              {dashboardStats.onlineCameras}/{dashboardStats.totalCameras}
            </div>
            <Progress 
              value={(dashboardStats.onlineCameras / dashboardStats.totalCameras) * 100} 
              className="h-2"
            />
          </div>
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <span className="text-sm font-medium">Active Alerts</span>
            </div>
            <div className="text-2xl font-bold text-red-600">
              {dashboardStats.activeAlerts}
            </div>
            <div className="text-xs text-muted-foreground">
              {dashboardStats.criticalAlerts} critical
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <Users className="h-4 w-4 text-purple-500" />
              <span className="text-sm font-medium">Occupancy</span>
            </div>
            <div className="text-2xl font-bold">
              {dashboardStats.currentOccupancy}
            </div>
            <Progress 
              value={(dashboardStats.currentOccupancy / dashboardStats.maxOccupancy) * 100} 
              className="h-2"
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );

  const QuickActionsWidget = () => (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Quick Actions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            className="h-auto flex-col space-y-1 p-3"
            onClick={handleLockAllDoors}
            disabled={refreshing || loading}
          >
            <Lock className="h-4 w-4" />
            <span className="text-xs">Lock All</span>
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            className="h-auto flex-col space-y-1 p-3"
            onClick={handleUnlockAllDoors}
            disabled={refreshing || loading}
          >
            <Unlock className="h-4 w-4" />
            <span className="text-xs">Unlock All</span>
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            className="h-auto flex-col space-y-1 p-3"
            onClick={handleEmergencyLockdown}
            disabled={refreshing || loading}
          >
            <AlertTriangle className="h-4 w-4" />
            <span className="text-xs">Emergency</span>
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            className="h-auto flex-col space-y-1 p-3"
            onClick={loadDashboardData}
            disabled={refreshing || loading}
          >
            {refreshing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            <span className="text-xs">Refresh</span>
          </Button>
        </div>
        <Separator className="my-3" />
        <div className="text-xs text-muted-foreground">
          Last updated: {lastUpdate.toLocaleTimeString()}
          {error && (
            <div className="text-red-500 mt-1">
              Error: {error}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );

  const ActiveAlertsWidget = () => (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
        <Badge variant="destructive">{alerts.filter(a => !a.acknowledged).length}</Badge>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px]">
          <div className="space-y-2">
            {alerts.filter(alert => !alert.acknowledged).map((alert) => (
              <Alert key={alert.id} className={`
                ${alert.severity === 'critical' ? 'border-red-500' : ''}
                ${alert.severity === 'high' ? 'border-orange-500' : ''}
                ${alert.severity === 'medium' ? 'border-yellow-500' : ''}
                ${alert.severity === 'low' ? 'border-blue-500' : ''}
              `}>
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-2">
                    {alert.severity === 'critical' && <AlertCircle className="h-4 w-4 text-red-500 mt-0.5" />}
                    {alert.severity === 'high' && <Warning className="h-4 w-4 text-orange-500 mt-0.5" />}
                    {alert.severity === 'medium' && <Info className="h-4 w-4 text-yellow-500 mt-0.5" />}
                    {alert.severity === 'low' && <Info className="h-4 w-4 text-blue-500 mt-0.5" />}
                    <div className="flex-1">
                      <AlertTitle className="text-sm">{alert.message}</AlertTitle>
                      <AlertDescription className="text-xs">
                        {alert.location} • {alert.timestamp}
                      </AlertDescription>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleAlertAcknowledge(alert.id)}
                  >
                    <CheckCircle className="h-4 w-4" />
                  </Button>
                </div>
              </Alert>
            ))}
            {alerts.filter(alert => !alert.acknowledged).length === 0 && (
              <div className="text-center text-muted-foreground py-8">
                <CheckCircle className="h-8 w-8 mx-auto mb-2 text-green-500" />
                <p className="text-sm">No active alerts</p>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );

  const RecentEventsWidget = () => (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Recent Events</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px]">
          <div className="space-y-2">
            {loading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin" />
                <span className="ml-2 text-sm text-muted-foreground">Loading events...</span>
              </div>
            ) : recentEvents.length === 0 ? (
              <div className="text-center text-muted-foreground py-8">
                <Activity className="h-8 w-8 mx-auto mb-2" />
                <p className="text-sm">No recent events</p>
              </div>
            ) : (
              recentEvents.slice(0, 10).map((event) => (
                <div key={event.id} className="flex items-center space-x-3 p-2 rounded-lg border">
                  <div className={`w-2 h-2 rounded-full ${
                    event.type === 'access_granted' ? 'bg-green-500' :
                    event.type === 'access_denied' ? 'bg-red-500' :
                    event.type === 'motion_detected' ? 'bg-blue-500' :
                    'bg-yellow-500'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{event.details}</p>
                    <p className="text-xs text-muted-foreground">{event.location}</p>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {event.timestamp}
                  </div>
                </div>
              ))
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );

  const AccessPointsStatusWidget = () => (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">Access Points Status</CardTitle>
        <div className="flex items-center space-x-2">
          <Badge variant="outline">{accessPoints.length} total</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px]">
          <div className="space-y-2">
            {loading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin" />
                <span className="ml-2 text-sm text-muted-foreground">Loading access points...</span>
              </div>
            ) : accessPoints.length === 0 ? (
              <div className="text-center text-muted-foreground py-8">
                <Shield className="h-8 w-8 mx-auto mb-2" />
                <p className="text-sm">No access points found</p>
              </div>
            ) : (
              accessPoints.map((point) => (
                <div key={point.id} className="flex items-center justify-between p-3 rounded-lg border">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${
                      point.status === 'online' ? 'bg-green-500' :
                      point.status === 'offline' ? 'bg-gray-500' :
                      'bg-red-500'
                    }`} />
                    <div>
                      <p className="text-sm font-medium">{point.name}</p>
                      <p className="text-xs text-muted-foreground">{point.location}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger>
                          <Badge variant={point.isLocked ? "default" : "destructive"}>
                            {point.isLocked ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{point.isLocked ? 'Locked' : 'Unlocked'}</p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm" disabled={point.status !== 'online'}>
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent>
                        <DropdownMenuItem 
                          onClick={() => handleDoorControl(point.id, point.isLocked ? 'unlock' : 'lock')}
                          disabled={point.status !== 'online'}
                        >
                          {point.isLocked ? 'Unlock' : 'Lock'} Door
                        </DropdownMenuItem>
                        <DropdownMenuItem>View Details</DropdownMenuItem>
                        <DropdownMenuItem>View Events</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              ))
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );

  const CamerasStatusWidget = () => (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">Cameras Status</CardTitle>
        <div className="flex items-center space-x-2">
          <Badge variant="outline">{cameras.length} total</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[200px]">
          <div className="space-y-2">
            {loading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-6 w-6 animate-spin" />
                <span className="ml-2 text-sm text-muted-foreground">Loading cameras...</span>
              </div>
            ) : cameras.length === 0 ? (
              <div className="text-center text-muted-foreground py-8">
                <Camera className="h-8 w-8 mx-auto mb-2" />
                <p className="text-sm">No cameras found</p>
              </div>
            ) : (
              cameras.map((camera) => (
                <div key={camera.id} className="flex items-center justify-between p-3 rounded-lg border">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${
                      camera.status === 'online' || camera.status === 'recording' ? 'bg-green-500' :
                      camera.status === 'offline' ? 'bg-gray-500' :
                      'bg-red-500'
                    }`} />
                    <div>
                      <p className="text-sm font-medium">{camera.name}</p>
                      <p className="text-xs text-muted-foreground">{camera.location}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger>
                          <Badge variant={camera.isRecording ? "default" : "secondary"}>
                            {camera.isRecording ? <Video className="h-3 w-3" /> : <VideoOff className="h-3 w-3" />}
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>{camera.isRecording ? 'Recording' : 'Not Recording'}</p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm" disabled={camera.status === 'offline'}>
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent>
                        <DropdownMenuItem disabled={camera.status === 'offline'}>
                          View Live Feed
                        </DropdownMenuItem>
                        <DropdownMenuItem>View Recordings</DropdownMenuItem>
                        <DropdownMenuItem disabled={camera.status === 'offline'}>
                          Camera Settings
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              ))
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );

  const EnvironmentalMonitoringWidget = () => (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Environmental Monitoring</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {environmentalReadings.map((reading) => (
            <div key={reading.id} className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                {reading.sensorType === 'temperature' && <Thermometer className="h-4 w-4 text-red-500" />}
                {reading.sensorType === 'humidity' && <Droplets className="h-4 w-4 text-blue-500" />}
                {reading.sensorType === 'water' && <Droplets className="h-4 w-4 text-cyan-500" />}
                {reading.sensorType === 'smoke' && <Zap className="h-4 w-4 text-orange-500" />}
                <div>
                  <p className="text-sm font-medium capitalize">{reading.sensorType}</p>
                  <p className="text-xs text-muted-foreground">{reading.location}</p>
                </div>
              </div>
              <div className="text-right">
                <p className={`text-sm font-bold ${
                  reading.status === 'normal' ? 'text-green-600' :
                  reading.status === 'warning' ? 'text-yellow-600' :
                  'text-red-600'
                }`}>
                  {reading.value}{reading.unit}
                </p>
                <p className="text-xs text-muted-foreground">{reading.timestamp}</p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );

  const OccupancyTrackingWidget = () => (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Occupancy Tracking</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="text-center">
            <div className="text-3xl font-bold">{dashboardStats.currentOccupancy}</div>
            <div className="text-sm text-muted-foreground">Current Occupancy</div>
          </div>
          <Progress 
            value={(dashboardStats.currentOccupancy / dashboardStats.maxOccupancy) * 100} 
            className="h-3"
          />
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>0</span>
            <span>Max: {dashboardStats.maxOccupancy}</span>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="text-center p-2 bg-muted rounded">
              <div className="font-semibold">68%</div>
              <div>Capacity</div>
            </div>
            <div className="text-center p-2 bg-muted rounded">
              <div className="font-semibold">+12</div>
              <div>vs Yesterday</div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  const BuildingOverviewWidget = () => (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Building Overview</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin" />
              <span className="ml-2 text-sm text-muted-foreground">Loading buildings...</span>
            </div>
          ) : buildings.length === 0 ? (
            <div className="text-center text-muted-foreground py-8">
              <Building className="h-8 w-8 mx-auto mb-2" />
              <p className="text-sm">No buildings found</p>
            </div>
          ) : (
            <>
              {buildings.slice(0, 3).map((building) => {
                const buildingFloors = floors.filter(f => f.buildingId === building.id);
                const buildingDoors = accessPoints.filter(ap => ap.building === building.name);
                const buildingCameras = cameras.filter(cam => cam.building === building.name);
                
                return (
                  <div key={building.id} className="flex items-center justify-between p-2 rounded border">
                    <div className="flex items-center space-x-2">
                      <Building className="h-4 w-4" />
                      <span className="text-sm">{building.name}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge variant="outline" className="text-xs">
                        {buildingFloors.length} floors
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {buildingDoors.length} doors
                      </Badge>
                    </div>
                  </div>
                );
              })}
              <div className="grid grid-cols-2 gap-2 mt-4">
                <div className="text-center p-2 bg-muted rounded">
                  <div className="text-lg font-bold">{dashboardStats.totalAccessPoints}</div>
                  <div className="text-xs text-muted-foreground">Total Doors</div>
                </div>
                <div className="text-center p-2 bg-muted rounded">
                  <div className="text-lg font-bold">{dashboardStats.totalCameras}</div>
                  <div className="text-xs text-muted-foreground">Cameras</div>
                </div>
              </div>
            </>
          )}
        </div>
      </CardContent>
    </Card>
  );

  const SecurityMetricsWidget = () => (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Security Metrics</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm">Today's Events</span>
            <span className="text-lg font-bold">{dashboardStats.todayEvents}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Access Success Rate</span>
            <span className="text-lg font-bold text-green-600">98.2%</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm">Avg Response Time</span>
            <span className="text-lg font-bold">1.2s</span>
          </div>
          <Separator />
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="text-center p-2 bg-green-50 rounded">
              <div className="font-semibold text-green-700">1,203</div>
              <div className="text-green-600">Granted</div>
            </div>
            <div className="text-center p-2 bg-red-50 rounded">
              <div className="font-semibold text-red-700">44</div>
              <div className="text-red-600">Denied</div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );

  // Widget renderer
  const renderWidget = (widget: DashboardWidget) => {
    switch (widget.type) {
      case 'system_overview':
        return <SystemOverviewWidget />;
      case 'quick_actions':
        return <QuickActionsWidget />;
      case 'active_alerts':
        return <ActiveAlertsWidget />;
      case 'recent_events':
        return <RecentEventsWidget />;
      case 'access_points_status':
        return <AccessPointsStatusWidget />;
      case 'cameras_status':
        return <CamerasStatusWidget />;
      case 'environmental_monitoring':
        return <EnvironmentalMonitoringWidget />;
      case 'occupancy_tracking':
        return <OccupancyTrackingWidget />;
      case 'building_overview':
        return <BuildingOverviewWidget />;
      case 'security_metrics':
        return <SecurityMetricsWidget />;
      default:
        return <div>Unknown widget type</div>;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold">Security Dashboard</h1>
              <p className="text-muted-foreground">
                Real-time monitoring and control center
              </p>
            </div>
            <div className="flex items-center space-x-4">
              {/* Filters */}
              <div className="flex items-center space-x-2">
                <Select value={selectedBuilding} onValueChange={setSelectedBuilding}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Building" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Buildings</SelectItem>
                    {buildings.map((building) => (
                      <SelectItem key={building.id} value={building.id}>
                        {building.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={selectedFloor} onValueChange={setSelectedFloor}>
                  <SelectTrigger className="w-[120px]">
                    <SelectValue placeholder="Floor" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Floors</SelectItem>
                    {floors
                      .filter(floor => selectedBuilding === 'all' || floor.buildingId === selectedBuilding)
                      .map((floor) => (
                        <SelectItem key={floor.id} value={floor.id}>
                          {floor.name}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Dashboard Controls */}
              <div className="flex items-center space-x-2">
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant={isEditMode ? "default" : "outline"}
                        size="sm"
                        onClick={() => setIsEditMode(!isEditMode)}
                      >
                        <Settings className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>{isEditMode ? 'Exit Edit Mode' : 'Edit Dashboard'}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>

                <Button variant="outline" size="sm" onClick={loadDashboardData} disabled={refreshing || loading}>
                  {refreshing || loading ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Dashboard Content */}
      <div className="container mx-auto px-4 py-6">
        {/* Authentication check */}
        {!apiClient.isAuthenticated() ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <Alert className="max-w-md">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Authentication Required</AlertTitle>
              <AlertDescription>
                Please log in to access the dashboard.
              </AlertDescription>
            </Alert>
          </div>
        ) : loading ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <div className="text-center">
              <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
              <p className="text-muted-foreground">Loading dashboard...</p>
            </div>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <Alert className="max-w-md" variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error Loading Dashboard</AlertTitle>
              <AlertDescription>
                {error}
                <Button 
                  variant="outline" 
                  size="sm" 
                  className="mt-2 w-full"
                  onClick={loadDashboardData}
                >
                  Try Again
                </Button>
              </AlertDescription>
            </Alert>
          </div>
        ) : (
          <>
            {isEditMode && (
              <Alert className="mb-6">
                <Settings className="h-4 w-4" />
                <AlertTitle>Edit Mode Active</AlertTitle>
                <AlertDescription>
                  Drag and resize widgets to customize your dashboard layout. Click "Exit Edit Mode" when finished.
                </AlertDescription>
              </Alert>
            )}

            <ResponsiveGridLayout
          className="layout"
          layouts={{
            lg: widgets.map(w => ({ i: w.id, x: w.x, y: w.y, w: w.w, h: w.h, minW: w.minW, minH: w.minH, maxW: w.maxW, maxH: w.maxH })),
            md: widgets.map(w => ({ i: w.id, x: w.x, y: w.y, w: w.w, h: w.h, minW: w.minW, minH: w.minH, maxW: w.maxW, maxH: w.maxH })),
            sm: widgets.map(w => ({ i: w.id, x: 0, y: w.y, w: 12, h: w.h, minW: w.minW, minH: w.minH, maxW: w.maxW, maxH: w.maxH }))
          }}
          breakpoints={{ lg: 1200, md: 996, sm: 768, xs: 480, xxs: 0 }}
          cols={{ lg: 12, md: 10, sm: 6, xs: 4, xxs: 2 }}
          rowHeight={60}
          onLayoutChange={handleLayoutChange}
          isDraggable={isEditMode}
          isResizable={isEditMode}
          margin={[16, 16]}
          containerPadding={[0, 0]}
        >
            {widgets.map((widget) => (
              <div key={widget.id} className="widget-container">
                {renderWidget(widget)}
              </div>
            ))}
          </ResponsiveGridLayout>
        </>
      )}
    </div>

      {/* Connection Status Toast */}
      <AnimatePresence>
        {!isConnected && (
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 50 }}
            className="fixed bottom-4 right-4 z-50"
          >
            <Alert className="border-red-500 bg-red-50">
              <WifiOff className="h-4 w-4" />
              <AlertTitle>Connection Lost</AlertTitle>
              <AlertDescription>
                Real-time updates are unavailable. Attempting to reconnect...
              </AlertDescription>
            </Alert>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
