'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { 
  Search, 
  Filter, 
  RefreshCw, 
  Settings, 
  Wifi, 
  WifiOff, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Download, 
  Upload, 
  Play, 
  Pause, 
  RotateCcw,
  Network,
  Monitor,
  Camera,
  Shield,
  Thermometer,
  Activity,
  Clock,
  MapPin,
  Zap,
  HardDrive,
  Cpu,
  MemoryStick,
  Eye,
  EyeOff,
  MoreVertical,
  Edit,
  Trash2,
  Copy,
  Power,
  PowerOff
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useRealtime } from '@/hooks/useRealtime';
import { apiClient } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';

// Types
interface Device {
  id: string;
  name: string;
  type: 'camera' | 'access_panel' | 'sensor' | 'controller' | 'gateway';
  manufacturer: string;
  model: string;
  firmwareVersion: string;
  ipAddress: string;
  macAddress: string;
  status: 'online' | 'offline' | 'error' | 'maintenance';
  health: 'healthy' | 'warning' | 'critical';
  lastSeen: string;
  location: string;
  zone: string;
  capabilities: string[];
  configuration: Record<string, any>;
  metrics: {
    uptime: number;
    cpuUsage: number;
    memoryUsage: number;
    temperature: number;
    networkLatency: number;
  };
  alerts: DeviceAlert[];
  maintenanceSchedule?: MaintenanceSchedule;
}

interface DeviceAlert {
  id: string;
  type: 'warning' | 'error' | 'info';
  message: string;
  timestamp: string;
  acknowledged: boolean;
}

interface MaintenanceSchedule {
  nextMaintenance: string;
  lastMaintenance: string;
  interval: number;
  type: 'preventive' | 'corrective';
}

interface FirmwareUpdate {
  id: string;
  version: string;
  releaseDate: string;
  description: string;
  size: number;
  critical: boolean;
  compatible: boolean;
}

interface NetworkTopologyNode {
  id: string;
  name: string;
  type: string;
  x: number;
  y: number;
  connections: string[];
}

const DevicesPage: React.FC = () => {
  const { user, hasPermission } = useAuth();
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevices, setSelectedDevices] = useState<string[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [filterZone, setFilterZone] = useState<string>('all');
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [discoveryProgress, setDiscoveryProgress] = useState(0);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [firmwareDialogOpen, setFirmwareDialogOpen] = useState(false);
  const [diagnosticsDialogOpen, setDiagnosticsDialogOpen] = useState(false);
  const [topologyDialogOpen, setTopologyDialogOpen] = useState(false);
  const [availableUpdates, setAvailableUpdates] = useState<FirmwareUpdate[]>([]);
  const [diagnosticsResults, setDiagnosticsResults] = useState<any>(null);
  const [networkTopology, setNetworkTopology] = useState<NetworkTopologyNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [bulkOperationDialogOpen, setBulkOperationDialogOpen] = useState(false);
  const [bulkOperation, setBulkOperation] = useState<string>('');

  // Real-time updates for device status
  const realtimeData = useRealtime('device_events', {
    onDeviceStatusUpdate: (data: any) => {
      setDevices(prev => prev.map(device => 
        device.id === data.deviceId 
          ? { ...device, status: data.status, lastSeen: data.timestamp, metrics: { ...device.metrics, ...data.metrics } }
          : device
      ));
    },
    onDeviceAlert: (data: any) => {
      setDevices(prev => prev.map(device => 
        device.id === data.deviceId 
          ? { ...device, alerts: [...device.alerts, data.alert] }
          : device
      ));
      toast({
        title: "Device Alert",
        description: `${data.deviceName}: ${data.alert.message}`,
        variant: data.alert.type === 'error' ? 'destructive' : 'default'
      });
    },
    onDeviceDiscovered: (data: any) => {
      setDevices(prev => [...prev, data.device]);
      toast({
        title: "New Device Discovered",
        description: `${data.device.name} (${data.device.type}) has been discovered`,
      });
    }
  });

  // Load devices on mount
  useEffect(() => {
    loadDevices();
  }, []);

  const loadDevices = async () => {
    try {
      setLoading(true);
      const response = await apiClient.get('/devices');
      setDevices(response.data);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load devices",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  // Device discovery
  const startDeviceDiscovery = async () => {
    if (!hasPermission('device:discover')) {
      toast({
        title: "Permission Denied",
        description: "You don't have permission to discover devices",
        variant: "destructive"
      });
      return;
    }

    try {
      setIsDiscovering(true);
      setDiscoveryProgress(0);
      
      const response = await apiClient.post('/devices/discover', {
        protocols: ['onvif', 'mdns', 'dhcp', 'snmp'],
        networkRanges: ['auto']
      });

      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setDiscoveryProgress(prev => {
          if (prev >= 100) {
            clearInterval(progressInterval);
            setIsDiscovering(false);
            return 100;
          }
          return prev + 10;
        });
      }, 1000);

      toast({
        title: "Device Discovery Started",
        description: "Scanning network for devices...",
      });
    } catch (error) {
      setIsDiscovering(false);
      toast({
        title: "Discovery Failed",
        description: "Failed to start device discovery",
        variant: "destructive"
      });
    }
  };

  // Device configuration
  const updateDeviceConfiguration = async (deviceId: string, config: Record<string, any>) => {
    if (!hasPermission('device:configure')) {
      toast({
        title: "Permission Denied",
        description: "You don't have permission to configure devices",
        variant: "destructive"
      });
      return;
    }

    try {
      await apiClient.put(`/devices/${deviceId}/configuration`, config);
      setDevices(prev => prev.map(device => 
        device.id === deviceId 
          ? { ...device, configuration: { ...device.configuration, ...config } }
          : device
      ));
      toast({
        title: "Configuration Updated",
        description: "Device configuration has been updated successfully",
      });
      setConfigDialogOpen(false);
    } catch (error) {
      toast({
        title: "Configuration Failed",
        description: "Failed to update device configuration",
        variant: "destructive"
      });
    }
  };

  // Firmware management
  const checkFirmwareUpdates = async (deviceId: string) => {
    try {
      const response = await apiClient.get(`/devices/${deviceId}/firmware/updates`);
      setAvailableUpdates(response.data);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to check firmware updates",
        variant: "destructive"
      });
    }
  };

  const updateFirmware = async (deviceId: string, updateId: string) => {
    if (!hasPermission('device:firmware')) {
      toast({
        title: "Permission Denied",
        description: "You don't have permission to update firmware",
        variant: "destructive"
      });
      return;
    }

    try {
      await apiClient.post(`/devices/${deviceId}/firmware/update`, { updateId });
      toast({
        title: "Firmware Update Started",
        description: "Firmware update has been initiated",
      });
    } catch (error) {
      toast({
        title: "Update Failed",
        description: "Failed to start firmware update",
        variant: "destructive"
      });
    }
  };

  // Device diagnostics
  const runDiagnostics = async (deviceId: string) => {
    try {
      const response = await apiClient.post(`/devices/${deviceId}/diagnostics`);
      setDiagnosticsResults(response.data);
    } catch (error) {
      toast({
        title: "Diagnostics Failed",
        description: "Failed to run device diagnostics",
        variant: "destructive"
      });
    }
  };

  // Network topology
  const loadNetworkTopology = async () => {
    try {
      const response = await apiClient.get('/devices/topology');
      setNetworkTopology(response.data);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load network topology",
        variant: "destructive"
      });
    }
  };

  // Bulk operations
  const executeBulkOperation = async () => {
    if (selectedDevices.length === 0) {
      toast({
        title: "No Devices Selected",
        description: "Please select devices to perform bulk operations",
        variant: "destructive"
      });
      return;
    }

    try {
      await apiClient.post('/devices/bulk', {
        deviceIds: selectedDevices,
        operation: bulkOperation
      });
      toast({
        title: "Bulk Operation Started",
        description: `${bulkOperation} operation initiated for ${selectedDevices.length} devices`,
      });
      setBulkOperationDialogOpen(false);
      setSelectedDevices([]);
    } catch (error) {
      toast({
        title: "Bulk Operation Failed",
        description: "Failed to execute bulk operation",
        variant: "destructive"
      });
    }
  };

  // Filtered devices
  const filteredDevices = useMemo(() => {
    return devices.filter(device => {
      const matchesSearch = device.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           device.ipAddress.includes(searchTerm) ||
                           device.location.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesType = filterType === 'all' || device.type === filterType;
      const matchesStatus = filterStatus === 'all' || device.status === filterStatus;
      const matchesZone = filterZone === 'all' || device.zone === filterZone;
      
      return matchesSearch && matchesType && matchesStatus && matchesZone;
    });
  }, [devices, searchTerm, filterType, filterStatus, filterZone]);

  // Get unique zones for filter
  const zones = useMemo(() => {
    return Array.from(new Set(devices.map(device => device.zone))).filter(Boolean);
  }, [devices]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'offline': return <XCircle className="h-4 w-4 text-red-500" />;
      case 'error': return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'maintenance': return <Clock className="h-4 w-4 text-yellow-500" />;
      default: return <XCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy': return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'warning': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'critical': return <XCircle className="h-4 w-4 text-red-500" />;
      default: return <XCircle className="h-4 w-4 text-gray-500" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'camera': return <Camera className="h-4 w-4" />;
      case 'access_panel': return <Shield className="h-4 w-4" />;
      case 'sensor': return <Thermometer className="h-4 w-4" />;
      case 'controller': return <Cpu className="h-4 w-4" />;
      case 'gateway': return <Network className="h-4 w-4" />;
      default: return <Monitor className="h-4 w-4" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin" />
        <span className="ml-2">Loading devices...</span>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Device Management</h1>
          <p className="text-muted-foreground">
            Discover, configure, and monitor all hardware devices
          </p>
        </div>
        <div className="flex gap-2">
          {hasPermission('device:discover') && (
            <Button 
              onClick={startDeviceDiscovery} 
              disabled={isDiscovering}
              className="flex items-center gap-2"
            >
              {isDiscovering ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              {isDiscovering ? 'Discovering...' : 'Discover Devices'}
            </Button>
          )}
          <Button variant="outline" onClick={loadDevices}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Discovery Progress */}
      {isDiscovering && (
        <Card>
          <CardContent className="pt-6">
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>Discovering devices...</span>
                <span>{discoveryProgress}%</span>
              </div>
              <Progress value={discoveryProgress} />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters and Search */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex-1 min-w-64">
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search devices by name, IP, or location..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Device Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="camera">Cameras</SelectItem>
                <SelectItem value="access_panel">Access Panels</SelectItem>
                <SelectItem value="sensor">Sensors</SelectItem>
                <SelectItem value="controller">Controllers</SelectItem>
                <SelectItem value="gateway">Gateways</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="online">Online</SelectItem>
                <SelectItem value="offline">Offline</SelectItem>
                <SelectItem value="error">Error</SelectItem>
                <SelectItem value="maintenance">Maintenance</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterZone} onValueChange={setFilterZone}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="Zone" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Zones</SelectItem>
                {zones.map(zone => (
                  <SelectItem key={zone} value={zone}>{zone}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            {selectedDevices.length > 0 && (
              <Button 
                variant="outline" 
                onClick={() => setBulkOperationDialogOpen(true)}
                className="flex items-center gap-2"
              >
                <Settings className="h-4 w-4" />
                Bulk Actions ({selectedDevices.length})
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Device Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filteredDevices.map((device) => (
          <Card key={device.id} className="hover:shadow-lg transition-shadow">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Checkbox
                    checked={selectedDevices.includes(device.id)}
                    onCheckedChange={(checked) => {
                      if (checked) {
                        setSelectedDevices(prev => [...prev, device.id]);
                      } else {
                        setSelectedDevices(prev => prev.filter(id => id !== device.id));
                      }
                    }}
                  />
                  {getTypeIcon(device.type)}
                  <CardTitle className="text-sm truncate">{device.name}</CardTitle>
                </div>
                <div className="flex items-center gap-1">
                  {getStatusIcon(device.status)}
                  {getHealthIcon(device.health)}
                </div>
              </div>
              <CardDescription className="text-xs">
                {device.manufacturer} {device.model}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">IP Address:</span>
                  <span className="font-mono">{device.ipAddress}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Location:</span>
                  <span className="truncate">{device.location}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Firmware:</span>
                  <span>{device.firmwareVersion}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Uptime:</span>
                  <span>{Math.floor(device.metrics.uptime / 3600)}h</span>
                </div>
              </div>

              {/* Metrics */}
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span>CPU</span>
                  <span>{device.metrics.cpuUsage}%</span>
                </div>
                <Progress value={device.metrics.cpuUsage} className="h-1" />
                <div className="flex justify-between text-xs">
                  <span>Memory</span>
                  <span>{device.metrics.memoryUsage}%</span>
                </div>
                <Progress value={device.metrics.memoryUsage} className="h-1" />
              </div>

              {/* Alerts */}
              {device.alerts.length > 0 && (
                <div className="space-y-1">
                  {device.alerts.slice(0, 2).map((alert) => (
                    <Alert key={alert.id} className="py-2">
                      <AlertTriangle className="h-3 w-3" />
                      <AlertDescription className="text-xs">
                        {alert.message}
                      </AlertDescription>
                    </Alert>
                  ))}
                  {device.alerts.length > 2 && (
                    <p className="text-xs text-muted-foreground">
                      +{device.alerts.length - 2} more alerts
                    </p>
                  )}
                </div>
              )}

              {/* Actions */}
              <div className="flex gap-1 pt-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setSelectedDevice(device);
                    setConfigDialogOpen(true);
                  }}
                  className="flex-1 text-xs"
                >
                  <Settings className="h-3 w-3 mr-1" />
                  Config
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setSelectedDevice(device);
                    checkFirmwareUpdates(device.id);
                    setFirmwareDialogOpen(true);
                  }}
                  className="flex-1 text-xs"
                >
                  <Download className="h-3 w-3 mr-1" />
                  Update
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setSelectedDevice(device);
                    runDiagnostics(device.id);
                    setDiagnosticsDialogOpen(true);
                  }}
                  className="flex-1 text-xs"
                >
                  <Activity className="h-3 w-3 mr-1" />
                  Test
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Network Topology Button */}
      <div className="flex justify-center">
        <Button
          variant="outline"
          onClick={() => {
            loadNetworkTopology();
            setTopologyDialogOpen(true);
          }}
          className="flex items-center gap-2"
        >
          <Network className="h-4 w-4" />
          View Network Topology
        </Button>
      </div>

      {/* Device Configuration Dialog */}
      <Dialog open={configDialogOpen} onOpenChange={setConfigDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Device Configuration</DialogTitle>
            <DialogDescription>
              Configure settings for {selectedDevice?.name}
            </DialogDescription>
          </DialogHeader>
          {selectedDevice && (
            <div className="space-y-4">
              <Tabs defaultValue="general">
                <TabsList>
                  <TabsTrigger value="general">General</TabsTrigger>
                  <TabsTrigger value="network">Network</TabsTrigger>
                  <TabsTrigger value="security">Security</TabsTrigger>
                  <TabsTrigger value="advanced">Advanced</TabsTrigger>
                </TabsList>
                <TabsContent value="general" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="device-name">Device Name</Label>
                      <Input id="device-name" defaultValue={selectedDevice.name} />
                    </div>
                    <div>
                      <Label htmlFor="device-location">Location</Label>
                      <Input id="device-location" defaultValue={selectedDevice.location} />
                    </div>
                  </div>
                  <div>
                    <Label htmlFor="device-description">Description</Label>
                    <Textarea id="device-description" placeholder="Device description..." />
                  </div>
                </TabsContent>
                <TabsContent value="network" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="ip-address">IP Address</Label>
                      <Input id="ip-address" defaultValue={selectedDevice.ipAddress} />
                    </div>
                    <div>
                      <Label htmlFor="subnet-mask">Subnet Mask</Label>
                      <Input id="subnet-mask" defaultValue="255.255.255.0" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="gateway">Gateway</Label>
                      <Input id="gateway" placeholder="192.168.1.1" />
                    </div>
                    <div>
                      <Label htmlFor="dns">DNS Server</Label>
                      <Input id="dns" placeholder="8.8.8.8" />
                    </div>
                  </div>
                </TabsContent>
                <TabsContent value="security" className="space-y-4">
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2">
                      <Switch id="encryption" />
                      <Label htmlFor="encryption">Enable Encryption</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Switch id="authentication" />
                      <Label htmlFor="authentication">Require Authentication</Label>
                    </div>
                    <div>
                      <Label htmlFor="certificate">Security Certificate</Label>
                      <Input id="certificate" type="file" accept=".pem,.crt" />
                    </div>
                  </div>
                </TabsContent>
                <TabsContent value="advanced" className="space-y-4">
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="polling-interval">Polling Interval (seconds)</Label>
                      <Input id="polling-interval" type="number" defaultValue="30" />
                    </div>
                    <div>
                      <Label htmlFor="timeout">Connection Timeout (seconds)</Label>
                      <Input id="timeout" type="number" defaultValue="10" />
                    </div>
                    <div>
                      <Label htmlFor="custom-config">Custom Configuration (JSON)</Label>
                      <Textarea 
                        id="custom-config" 
                        placeholder='{"key": "value"}'
                        className="font-mono text-sm"
                      />
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setConfigDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={() => updateDeviceConfiguration(selectedDevice.id, {})}>
                  Save Configuration
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Firmware Management Dialog */}
      <Dialog open={firmwareDialogOpen} onOpenChange={setFirmwareDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Firmware Management</DialogTitle>
            <DialogDescription>
              Manage firmware updates for {selectedDevice?.name}
            </DialogDescription>
          </DialogHeader>
          {selectedDevice && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Current Version</Label>
                  <div className="p-2 bg-muted rounded">{selectedDevice.firmwareVersion}</div>
                </div>
                <div>
                  <Label>Device Model</Label>
                  <div className="p-2 bg-muted rounded">{selectedDevice.model}</div>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label>Available Updates</Label>
                {availableUpdates.length > 0 ? (
                  <div className="space-y-2">
                    {availableUpdates.map((update) => (
                      <Card key={update.id}>
                        <CardContent className="p-4">
                          <div className="flex justify-between items-start">
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className="font-medium">Version {update.version}</span>
                                {update.critical && (
                                  <Badge variant="destructive">Critical</Badge>
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground">
                                {update.description}
                              </p>
                              <div className="text-xs text-muted-foreground">
                                Released: {new Date(update.releaseDate).toLocaleDateString()} • 
                                Size: {(update.size / 1024 / 1024).toFixed(1)} MB
                              </div>
                            </div>
                            <Button
                              size="sm"
                              onClick={() => updateFirmware(selectedDevice.id, update.id)}
                              disabled={!update.compatible}
                            >
                              {update.compatible ? 'Install' : 'Incompatible'}
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    No firmware updates available
                  </div>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Diagnostics Dialog */}
      <Dialog open={diagnosticsDialogOpen} onOpenChange={setDiagnosticsDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Device Diagnostics</DialogTitle>
            <DialogDescription>
              Diagnostic results for {selectedDevice?.name}
            </DialogDescription>
          </DialogHeader>
          {diagnosticsResults ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <Wifi className="h-4 w-4" />
                      <span className="font-medium">Connectivity</span>
                    </div>
                    <div className="mt-2">
                      <Badge variant={diagnosticsResults.connectivity.status === 'pass' ? 'default' : 'destructive'}>
                        {diagnosticsResults.connectivity.status}
                      </Badge>
                      <p className="text-sm text-muted-foreground mt-1">
                        Latency: {diagnosticsResults.connectivity.latency}ms
                      </p>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2">
                      <HardDrive className="h-4 w-4" />
                      <span className="font-medium">Storage</span>
                    </div>
                    <div className="mt-2">
                      <Badge variant={diagnosticsResults.storage.status === 'pass' ? 'default' : 'destructive'}>
                        {diagnosticsResults.storage.status}
                      </Badge>
                      <p className="text-sm text-muted-foreground mt-1">
                        Free: {diagnosticsResults.storage.freeSpace}GB
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </div>
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4" />
                    <span className="font-medium">Performance</span>
                  </div>
                  <div className="mt-2 space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>CPU Usage</span>
                      <span>{diagnosticsResults.performance.cpu}%</span>
                    </div>
                    <Progress value={diagnosticsResults.performance.cpu} />
                    <div className="flex justify-between text-sm">
                      <span>Memory Usage</span>
                      <span>{diagnosticsResults.performance.memory}%</span>
                    </div>
                    <Progress value={diagnosticsResults.performance.memory} />
                  </div>
                </CardContent>
              </Card>
            </div>
          ) : (
            <div className="text-center py-8">
              <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4" />
              <p className="text-muted-foreground">Running diagnostics...</p>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Network Topology Dialog */}
      <Dialog open={topologyDialogOpen} onOpenChange={setTopologyDialogOpen}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>Network Topology</DialogTitle>
            <DialogDescription>
              Visual representation of device network connections
            </DialogDescription>
          </DialogHeader>
          <div className="h-96 bg-muted rounded-lg flex items-center justify-center">
            <div className="text-center">
              <Network className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">Network topology visualization</p>
              <p className="text-sm text-muted-foreground">
                Interactive network map showing device connections and relationships
              </p>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Bulk Operations Dialog */}
      <Dialog open={bulkOperationDialogOpen} onOpenChange={setBulkOperationDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Bulk Operations</DialogTitle>
            <DialogDescription>
              Perform operations on {selectedDevices.length} selected devices
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="bulk-operation">Select Operation</Label>
              <Select value={bulkOperation} onValueChange={setBulkOperation}>
                <SelectTrigger>
                  <SelectValue placeholder="Choose operation..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="reboot">Reboot Devices</SelectItem>
                  <SelectItem value="update_firmware">Update Firmware</SelectItem>
                  <SelectItem value="backup_config">Backup Configuration</SelectItem>
                  <SelectItem value="restore_config">Restore Configuration</SelectItem>
                  <SelectItem value="enable_maintenance">Enable Maintenance Mode</SelectItem>
                  <SelectItem value="disable_maintenance">Disable Maintenance Mode</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setBulkOperationDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={executeBulkOperation} disabled={!bulkOperation}>
                Execute Operation
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default DevicesPage;