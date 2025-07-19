'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { 
  Thermometer, 
  Droplets, 
  Wind, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Settings, 
  TrendingUp, 
  MapPin,
  Zap,
  WifiOff,
  Activity,
  Calendar,
  Download,
  RefreshCw
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { useAuth } from '@/hooks/useAuth';
import { useRealtime } from '@/hooks/useRealtime';
import { apiClient } from '@/lib/api-client';

// Types
interface Sensor {
  id: string;
  name: string;
  type: 'temperature' | 'humidity' | 'air_quality' | 'water_leak' | 'hvac';
  location: string;
  floor: string;
  coordinates: { x: number; y: number };
  status: 'online' | 'offline' | 'warning' | 'error';
  lastReading: number;
  lastReadingTime: string;
  thresholds: {
    min: number;
    max: number;
    critical_min: number;
    critical_max: number;
  };
  unit: string;
  batteryLevel?: number;
  firmware?: string;
}

interface EnvironmentalReading {
  id: string;
  sensorId: string;
  value: number;
  timestamp: string;
  quality: 'good' | 'warning' | 'critical';
}

interface EnvironmentalAlert {
  id: string;
  sensorId: string;
  sensorName: string;
  type: 'threshold_exceeded' | 'sensor_offline' | 'battery_low' | 'maintenance_required';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: string;
  acknowledged: boolean;
  resolvedAt?: string;
}

interface HVACSystem {
  id: string;
  name: string;
  zone: string;
  status: 'running' | 'idle' | 'maintenance' | 'error';
  temperature: number;
  targetTemperature: number;
  humidity: number;
  targetHumidity: number;
  airflow: number;
  energyConsumption: number;
}

export default function EnvironmentalPage() {
  const { user, hasPermission } = useAuth();
  const [sensors, setSensors] = useState<Sensor[]>([]);
  const [readings, setReadings] = useState<EnvironmentalReading[]>([]);
  const [alerts, setAlerts] = useState<EnvironmentalAlert[]>([]);
  const [hvacSystems, setHVACSystems] = useState<HVACSystem[]>([]);
  const [selectedSensor, setSelectedSensor] = useState<Sensor | null>(null);
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [selectedFloor, setSelectedFloor] = useState('all');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Real-time updates
  useRealtime('environmental_reading', (data: EnvironmentalReading) => {
    setReadings(prev => [data, ...prev.slice(0, 999)]);
    // Update sensor last reading
    setSensors(prev => prev.map(sensor => 
      sensor.id === data.sensorId 
        ? { ...sensor, lastReading: data.value, lastReadingTime: data.timestamp }
        : sensor
    ));
  });

  useRealtime('environmental_alert', (data: EnvironmentalAlert) => {
    setAlerts(prev => [data, ...prev]);
  });

  useRealtime('sensor_status', (data: { sensorId: string; status: Sensor['status'] }) => {
    setSensors(prev => prev.map(sensor => 
      sensor.id === data.sensorId 
        ? { ...sensor, status: data.status }
        : sensor
    ));
  });

  // Load initial data
  useEffect(() => {
    loadEnvironmentalData();
  }, []);

  const loadEnvironmentalData = async () => {
    try {
      setLoading(true);
      const [sensorsData, readingsData, alertsData, hvacData] = await Promise.all([
        apiClient.get('/environmental/sensors'),
        apiClient.get(`/environmental/readings?timeRange=${selectedTimeRange}`),
        apiClient.get('/environmental/alerts?status=active'),
        apiClient.get('/environmental/hvac-systems')
      ]);

      setSensors(sensorsData.data);
      setReadings(readingsData.data);
      setAlerts(alertsData.data);
      setHVACSystems(hvacData.data);
    } catch (error) {
      console.error('Failed to load environmental data:', error);
    } finally {
      setLoading(false);
    }
  };

  const refreshData = async () => {
    setRefreshing(true);
    await loadEnvironmentalData();
    setRefreshing(false);
  };

  // Filter sensors by floor
  const filteredSensors = useMemo(() => {
    return selectedFloor === 'all' 
      ? sensors 
      : sensors.filter(sensor => sensor.floor === selectedFloor);
  }, [sensors, selectedFloor]);

  // Get unique floors
  const floors = useMemo(() => {
    const uniqueFloors = [...new Set(sensors.map(sensor => sensor.floor))];
    return uniqueFloors.sort();
  }, [sensors]);

  // Calculate summary statistics
  const summaryStats = useMemo(() => {
    const activeSensors = filteredSensors.filter(s => s.status === 'online').length;
    const totalSensors = filteredSensors.length;
    const activeAlerts = alerts.filter(a => !a.acknowledged).length;
    const criticalAlerts = alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length;

    const avgTemperature = filteredSensors
      .filter(s => s.type === 'temperature' && s.status === 'online')
      .reduce((sum, s) => sum + s.lastReading, 0) / 
      filteredSensors.filter(s => s.type === 'temperature' && s.status === 'online').length || 0;

    const avgHumidity = filteredSensors
      .filter(s => s.type === 'humidity' && s.status === 'online')
      .reduce((sum, s) => sum + s.lastReading, 0) / 
      filteredSensors.filter(s => s.type === 'humidity' && s.status === 'online').length || 0;

    return {
      activeSensors,
      totalSensors,
      activeAlerts,
      criticalAlerts,
      avgTemperature: Math.round(avgTemperature * 10) / 10,
      avgHumidity: Math.round(avgHumidity * 10) / 10
    };
  }, [filteredSensors, alerts]);

  // Prepare chart data
  const chartData = useMemo(() => {
    const timeRangeHours = selectedTimeRange === '1h' ? 1 : selectedTimeRange === '24h' ? 24 : 168;
    const now = new Date();
    const startTime = new Date(now.getTime() - timeRangeHours * 60 * 60 * 1000);

    const filteredReadings = readings.filter(r => 
      new Date(r.timestamp) >= startTime &&
      filteredSensors.some(s => s.id === r.sensorId)
    );

    // Group by time intervals
    const intervalMinutes = timeRangeHours <= 1 ? 5 : timeRangeHours <= 24 ? 60 : 360;
    const intervals = Math.ceil(timeRangeHours * 60 / intervalMinutes);

    const chartPoints = [];
    for (let i = 0; i < intervals; i++) {
      const intervalStart = new Date(startTime.getTime() + i * intervalMinutes * 60 * 1000);
      const intervalEnd = new Date(intervalStart.getTime() + intervalMinutes * 60 * 1000);

      const intervalReadings = filteredReadings.filter(r => {
        const readingTime = new Date(r.timestamp);
        return readingTime >= intervalStart && readingTime < intervalEnd;
      });

      const tempReadings = intervalReadings.filter(r => {
        const sensor = sensors.find(s => s.id === r.sensorId);
        return sensor?.type === 'temperature';
      });

      const humidityReadings = intervalReadings.filter(r => {
        const sensor = sensors.find(s => s.id === r.sensorId);
        return sensor?.type === 'humidity';
      });

      const avgTemp = tempReadings.length > 0 
        ? tempReadings.reduce((sum, r) => sum + r.value, 0) / tempReadings.length 
        : null;

      const avgHumidity = humidityReadings.length > 0 
        ? humidityReadings.reduce((sum, r) => sum + r.value, 0) / humidityReadings.length 
        : null;

      chartPoints.push({
        time: intervalStart.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        temperature: avgTemp ? Math.round(avgTemp * 10) / 10 : null,
        humidity: avgHumidity ? Math.round(avgHumidity * 10) / 10 : null
      });
    }

    return chartPoints;
  }, [readings, filteredSensors, selectedTimeRange, sensors]);

  const acknowledgeAlert = async (alertId: string) => {
    try {
      await apiClient.patch(`/environmental/alerts/${alertId}/acknowledge`);
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? { ...alert, acknowledged: true } : alert
      ));
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
    }
  };

  const updateSensorThresholds = async (sensorId: string, thresholds: Sensor['thresholds']) => {
    try {
      await apiClient.patch(`/environmental/sensors/${sensorId}/thresholds`, { thresholds });
      setSensors(prev => prev.map(sensor => 
        sensor.id === sensorId ? { ...sensor, thresholds } : sensor
      ));
    } catch (error) {
      console.error('Failed to update sensor thresholds:', error);
    }
  };

  const controlHVAC = async (systemId: string, settings: { targetTemperature?: number; targetHumidity?: number }) => {
    try {
      await apiClient.patch(`/environmental/hvac/${systemId}/control`, settings);
      setHVACSystems(prev => prev.map(system => 
        system.id === systemId ? { ...system, ...settings } : system
      ));
    } catch (error) {
      console.error('Failed to control HVAC system:', error);
    }
  };

  const getSensorStatusColor = (status: Sensor['status']) => {
    switch (status) {
      case 'online': return 'text-green-600';
      case 'warning': return 'text-yellow-600';
      case 'error': return 'text-red-600';
      case 'offline': return 'text-gray-600';
      default: return 'text-gray-600';
    }
  };

  const getSensorStatusIcon = (status: Sensor['status']) => {
    switch (status) {
      case 'online': return <CheckCircle className="h-4 w-4" />;
      case 'warning': return <AlertTriangle className="h-4 w-4" />;
      case 'error': return <XCircle className="h-4 w-4" />;
      case 'offline': return <WifiOff className="h-4 w-4" />;
      default: return <WifiOff className="h-4 w-4" />;
    }
  };

  const getAlertSeverityColor = (severity: EnvironmentalAlert['severity']) => {
    switch (severity) {
      case 'low': return 'border-blue-200 bg-blue-50';
      case 'medium': return 'border-yellow-200 bg-yellow-50';
      case 'high': return 'border-orange-200 bg-orange-50';
      case 'critical': return 'border-red-200 bg-red-50';
      default: return 'border-gray-200 bg-gray-50';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Environmental Monitoring</h1>
          <p className="text-muted-foreground">
            Real-time sensor data and environmental control systems
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <Select value={selectedFloor} onValueChange={setSelectedFloor}>
            <SelectTrigger className="w-32">
              <SelectValue placeholder="Floor" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Floors</SelectItem>
              {floors.map(floor => (
                <SelectItem key={floor} value={floor}>Floor {floor}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={refreshData}
            disabled={refreshing}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Sensors</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {summaryStats.activeSensors}/{summaryStats.totalSensors}
            </div>
            <p className="text-xs text-muted-foreground">
              {Math.round((summaryStats.activeSensors / summaryStats.totalSensors) * 100)}% online
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Temperature</CardTitle>
            <Thermometer className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summaryStats.avgTemperature}°C</div>
            <p className="text-xs text-muted-foreground">Across all zones</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Humidity</CardTitle>
            <Droplets className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{summaryStats.avgHumidity}%</div>
            <p className="text-xs text-muted-foreground">Relative humidity</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {summaryStats.criticalAlerts}
            </div>
            <p className="text-xs text-muted-foreground">
              {summaryStats.activeAlerts} total alerts
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="sensors">Sensors</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
          <TabsTrigger value="hvac">HVAC Systems</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Real-time Chart */}
            <Card className="col-span-1 lg:col-span-2">
              <CardHeader>
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle>Environmental Trends</CardTitle>
                    <CardDescription>Real-time temperature and humidity data</CardDescription>
                  </div>
                  <Select value={selectedTimeRange} onValueChange={setSelectedTimeRange}>
                    <SelectTrigger className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1h">Last Hour</SelectItem>
                      <SelectItem value="24h">Last 24 Hours</SelectItem>
                      <SelectItem value="7d">Last 7 Days</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis yAxisId="temp" orientation="left" />
                    <YAxis yAxisId="humidity" orientation="right" />
                    <Tooltip />
                    <Legend />
                    <Line 
                      yAxisId="temp"
                      type="monotone" 
                      dataKey="temperature" 
                      stroke="#ef4444" 
                      strokeWidth={2}
                      name="Temperature (°C)"
                    />
                    <Line 
                      yAxisId="humidity"
                      type="monotone" 
                      dataKey="humidity" 
                      stroke="#3b82f6" 
                      strokeWidth={2}
                      name="Humidity (%)"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Floor Plan */}
            <Card>
              <CardHeader>
                <CardTitle>Sensor Locations</CardTitle>
                <CardDescription>Interactive floor plan with sensor status</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="relative bg-gray-100 rounded-lg h-64 overflow-hidden">
                  {/* Simplified floor plan representation */}
                  <svg className="w-full h-full" viewBox="0 0 400 200">
                    {/* Room outlines */}
                    <rect x="10" y="10" width="180" height="80" fill="none" stroke="#ccc" strokeWidth="2" />
                    <rect x="210" y="10" width="180" height="80" fill="none" stroke="#ccc" strokeWidth="2" />
                    <rect x="10" y="110" width="180" height="80" fill="none" stroke="#ccc" strokeWidth="2" />
                    <rect x="210" y="110" width="180" height="80" fill="none" stroke="#ccc" strokeWidth="2" />
                    
                    {/* Sensor positions */}
                    {filteredSensors.map(sensor => (
                      <g key={sensor.id}>
                        <circle
                          cx={sensor.coordinates.x}
                          cy={sensor.coordinates.y}
                          r="8"
                          fill={sensor.status === 'online' ? '#10b981' : 
                                sensor.status === 'warning' ? '#f59e0b' : '#ef4444'}
                          className="cursor-pointer"
                          onClick={() => setSelectedSensor(sensor)}
                        />
                        <text
                          x={sensor.coordinates.x}
                          y={sensor.coordinates.y - 12}
                          textAnchor="middle"
                          className="text-xs fill-gray-600"
                        >
                          {sensor.name}
                        </text>
                      </g>
                    ))}
                  </svg>
                </div>
                <div className="mt-4 flex items-center space-x-4 text-sm">
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                    <span>Online</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
                    <span>Warning</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                    <span>Error/Offline</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Recent Alerts */}
            <Card>
              <CardHeader>
                <CardTitle>Recent Alerts</CardTitle>
                <CardDescription>Latest environmental alerts and warnings</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {alerts.slice(0, 5).map(alert => (
                    <div 
                      key={alert.id}
                      className={`p-3 rounded-lg border ${getAlertSeverityColor(alert.severity)}`}
                    >
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <Badge variant={alert.severity === 'critical' ? 'destructive' : 'secondary'}>
                              {alert.severity}
                            </Badge>
                            <span className="text-sm font-medium">{alert.sensorName}</span>
                          </div>
                          <p className="text-sm text-gray-600 mt-1">{alert.message}</p>
                          <p className="text-xs text-gray-500 mt-1">
                            {new Date(alert.timestamp).toLocaleString()}
                          </p>
                        </div>
                        {!alert.acknowledged && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => acknowledgeAlert(alert.id)}
                          >
                            Acknowledge
                          </Button>
                        )}
                      </div>
                    </div>
                  ))}
                  {alerts.length === 0 && (
                    <p className="text-center text-gray-500 py-4">No active alerts</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Sensors Tab */}
        <TabsContent value="sensors" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredSensors.map(sensor => (
              <Card key={sensor.id} className="relative">
                <CardHeader className="pb-3">
                  <div className="flex justify-between items-start">
                    <div>
                      <CardTitle className="text-lg">{sensor.name}</CardTitle>
                      <CardDescription>{sensor.location}</CardDescription>
                    </div>
                    <div className={`flex items-center space-x-1 ${getSensorStatusColor(sensor.status)}`}>
                      {getSensorStatusIcon(sensor.status)}
                      <span className="text-sm capitalize">{sensor.status}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {/* Current Reading */}
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Current Reading:</span>
                      <span className="text-lg font-semibold">
                        {sensor.lastReading} {sensor.unit}
                      </span>
                    </div>

                    {/* Thresholds */}
                    <div className="text-xs text-gray-500">
                      <div>Normal: {sensor.thresholds.min} - {sensor.thresholds.max} {sensor.unit}</div>
                      <div>Critical: {sensor.thresholds.critical_min} - {sensor.thresholds.critical_max} {sensor.unit}</div>
                    </div>

                    {/* Last Update */}
                    <div className="text-xs text-gray-500">
                      Last update: {new Date(sensor.lastReadingTime).toLocaleString()}
                    </div>

                    {/* Battery Level (if applicable) */}
                    {sensor.batteryLevel !== undefined && (
                      <div className="flex items-center justify-between text-sm">
                        <span>Battery:</span>
                        <span className={sensor.batteryLevel < 20 ? 'text-red-600' : 'text-green-600'}>
                          {sensor.batteryLevel}%
                        </span>
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex space-x-2 pt-2">
                      <Dialog>
                        <DialogTrigger asChild>
                          <Button size="sm" variant="outline" className="flex-1">
                            <Settings className="h-4 w-4 mr-1" />
                            Configure
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Configure {sensor.name}</DialogTitle>
                            <DialogDescription>
                              Adjust thresholds and alert settings for this sensor.
                            </DialogDescription>
                          </DialogHeader>
                          <SensorConfigurationForm 
                            sensor={sensor} 
                            onSave={(thresholds) => updateSensorThresholds(sensor.id, thresholds)}
                          />
                        </DialogContent>
                      </Dialog>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        onClick={() => setSelectedSensor(sensor)}
                      >
                        <TrendingUp className="h-4 w-4 mr-1" />
                        Trends
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Trends Tab */}
        <TabsContent value="trends" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Historical Trends Analysis</CardTitle>
              <CardDescription>Detailed environmental data analysis over time</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {/* Time Range Selector */}
                <div className="flex space-x-4">
                  <Select value={selectedTimeRange} onValueChange={setSelectedTimeRange}>
                    <SelectTrigger className="w-40">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1h">Last Hour</SelectItem>
                      <SelectItem value="24h">Last 24 Hours</SelectItem>
                      <SelectItem value="7d">Last 7 Days</SelectItem>
                      <SelectItem value="30d">Last 30 Days</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button variant="outline">
                    <Download className="h-4 w-4 mr-2" />
                    Export Data
                  </Button>
                </div>

                {/* Detailed Chart */}
                <ResponsiveContainer width="100%" height={400}>
                  <AreaChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <YAxis yAxisId="temp" orientation="left" />
                    <YAxis yAxisId="humidity" orientation="right" />
                    <Tooltip />
                    <Legend />
                    <Area
                      yAxisId="temp"
                      type="monotone"
                      dataKey="temperature"
                      stackId="1"
                      stroke="#ef4444"
                      fill="#ef4444"
                      fillOpacity={0.3}
                      name="Temperature (°C)"
                    />
                    <Area
                      yAxisId="humidity"
                      type="monotone"
                      dataKey="humidity"
                      stackId="2"
                      stroke="#3b82f6"
                      fill="#3b82f6"
                      fillOpacity={0.3}
                      name="Humidity (%)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* HVAC Systems Tab */}
        <TabsContent value="hvac" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {hvacSystems.map(system => (
              <Card key={system.id}>
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <div>
                      <CardTitle>{system.name}</CardTitle>
                      <CardDescription>Zone: {system.zone}</CardDescription>
                    </div>
                    <Badge 
                      variant={system.status === 'running' ? 'default' : 
                              system.status === 'error' ? 'destructive' : 'secondary'}
                    >
                      {system.status}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Temperature Control */}
                    <div className="space-y-2">
                      <Label>Temperature Control</Label>
                      <div className="flex items-center space-x-4">
                        <div className="flex-1">
                          <div className="flex justify-between text-sm">
                            <span>Current: {system.temperature}°C</span>
                            <span>Target: {system.targetTemperature}°C</span>
                          </div>
                          <Input
                            type="range"
                            min="16"
                            max="30"
                            value={system.targetTemperature}
                            onChange={(e) => controlHVAC(system.id, { 
                              targetTemperature: parseInt(e.target.value) 
                            })}
                            className="mt-2"
                          />
                        </div>
                      </div>
                    </div>

                    {/* Humidity Control */}
                    <div className="space-y-2">
                      <Label>Humidity Control</Label>
                      <div className="flex items-center space-x-4">
                        <div className="flex-1">
                          <div className="flex justify-between text-sm">
                            <span>Current: {system.humidity}%</span>
                            <span>Target: {system.targetHumidity}%</span>
                          </div>
                          <Input
                            type="range"
                            min="30"
                            max="70"
                            value={system.targetHumidity}
                            onChange={(e) => controlHVAC(system.id, { 
                              targetHumidity: parseInt(e.target.value) 
                            })}
                            className="mt-2"
                          />
                        </div>
                      </div>
                    </div>

                    {/* System Metrics */}
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-600">Airflow:</span>
                        <div className="font-semibold">{system.airflow} CFM</div>
                      </div>
                      <div>
                        <span className="text-gray-600">Energy:</span>
                        <div className="font-semibold">{system.energyConsumption} kW</div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Alerts Tab */}
        <TabsContent value="alerts" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Environmental Alerts</CardTitle>
              <CardDescription>Manage and respond to environmental alerts</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {alerts.map(alert => (
                  <div 
                    key={alert.id}
                    className={`p-4 rounded-lg border ${getAlertSeverityColor(alert.severity)}`}
                  >
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <Badge 
                            variant={alert.severity === 'critical' ? 'destructive' : 'secondary'}
                          >
                            {alert.severity.toUpperCase()}
                          </Badge>
                          <span className="font-medium">{alert.sensorName}</span>
                          <span className="text-sm text-gray-500">
                            {new Date(alert.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-gray-700 mb-2">{alert.message}</p>
                        <div className="flex items-center space-x-4 text-sm text-gray-600">
                          <span>Type: {alert.type.replace('_', ' ')}</span>
                          {alert.acknowledged && (
                            <span className="text-green-600">✓ Acknowledged</span>
                          )}
                          {alert.resolvedAt && (
                            <span className="text-blue-600">
                              Resolved: {new Date(alert.resolvedAt).toLocaleString()}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex space-x-2">
                        {!alert.acknowledged && (
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => acknowledgeAlert(alert.id)}
                          >
                            Acknowledge
                          </Button>
                        )}
                        <Button size="sm" variant="outline">
                          View Details
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
                {alerts.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    No environmental alerts at this time
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// Sensor Configuration Form Component
function SensorConfigurationForm({ 
  sensor, 
  onSave 
}: { 
  sensor: Sensor; 
  onSave: (thresholds: Sensor['thresholds']) => void;
}) {
  const [thresholds, setThresholds] = useState(sensor.thresholds);

  const handleSave = () => {
    onSave(thresholds);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label htmlFor="min">Minimum Normal</Label>
          <Input
            id="min"
            type="number"
            value={thresholds.min}
            onChange={(e) => setThresholds(prev => ({ 
              ...prev, 
              min: parseFloat(e.target.value) 
            }))}
          />
        </div>
        <div>
          <Label htmlFor="max">Maximum Normal</Label>
          <Input
            id="max"
            type="number"
            value={thresholds.max}
            onChange={(e) => setThresholds(prev => ({ 
              ...prev, 
              max: parseFloat(e.target.value) 
            }))}
          />
        </div>
        <div>
          <Label htmlFor="critical_min">Critical Minimum</Label>
          <Input
            id="critical_min"
            type="number"
            value={thresholds.critical_min}
            onChange={(e) => setThresholds(prev => ({ 
              ...prev, 
              critical_min: parseFloat(e.target.value) 
            }))}
          />
        </div>
        <div>
          <Label htmlFor="critical_max">Critical Maximum</Label>
          <Input
            id="critical_max"
            type="number"
            value={thresholds.critical_max}
            onChange={(e) => setThresholds(prev => ({ 
              ...prev, 
              critical_max: parseFloat(e.target.value) 
            }))}
          />
        </div>
      </div>
      <div className="flex justify-end space-x-2">
        <Button variant="outline">Cancel</Button>
        <Button onClick={handleSave}>Save Changes</Button>
      </div>
    </div>
  );
}