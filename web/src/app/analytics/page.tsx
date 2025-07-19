'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { DatePickerWithRange } from '@/components/ui/date-picker';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  PieChart, 
  Pie, 
  Cell, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  ScatterChart,
  Scatter
} from 'recharts';
import { 
  Activity, 
  AlertTriangle, 
  Shield, 
  Users, 
  Eye, 
  TrendingUp, 
  TrendingDown, 
  Clock, 
  MapPin, 
  Camera, 
  Zap, 
  Download, 
  Filter, 
  RefreshCw, 
  Settings, 
  BarChart3, 
  PieChart as PieChartIcon, 
  LineChart as LineChartIcon,
  Calendar,
  Search,
  Bell,
  AlertCircle,
  CheckCircle,
  XCircle,
  Info
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useRealtime } from '@/hooks/useRealtime';
import { apiClient } from '@/lib/api-client';
import { cn } from '@/lib/utils';
import { format, subDays, subHours, subMinutes } from 'date-fns';

// Types
interface SecurityMetric {
  id: string;
  name: string;
  value: number;
  change: number;
  trend: 'up' | 'down' | 'stable';
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface OccupancyData {
  timestamp: string;
  zone: string;
  occupancy: number;
  capacity: number;
  utilization: number;
}

interface SecurityEvent {
  id: string;
  timestamp: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  location: string;
  userId?: string;
  deviceId?: string;
  resolved: boolean;
}

interface BehavioralPattern {
  id: string;
  pattern: string;
  confidence: number;
  anomalyScore: number;
  frequency: number;
  lastSeen: string;
  riskLevel: 'low' | 'medium' | 'high';
}

interface PredictiveAlert {
  id: string;
  type: string;
  probability: number;
  timeframe: string;
  description: string;
  recommendedActions: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface ThreatAssessment {
  overallRisk: number;
  categories: {
    physical: number;
    cyber: number;
    operational: number;
    environmental: number;
  };
  trends: {
    daily: number;
    weekly: number;
    monthly: number;
  };
}

interface VideoAnalytics {
  personCount: number;
  faceDetections: number;
  behaviorAlerts: number;
  crowdDensity: number;
  suspiciousActivity: number;
  cameras: {
    id: string;
    name: string;
    status: 'online' | 'offline' | 'error';
    personCount: number;
    alerts: number;
  }[];
}

const COLORS = {
  primary: '#3b82f6',
  secondary: '#8b5cf6',
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',
  info: '#06b6d4'
};

const CHART_COLORS = ['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#06b6d4'];

export default function AnalyticsPage() {
  const { user, hasPermission } = useAuth();
  const [timeRange, setTimeRange] = useState({ from: subDays(new Date(), 7), to: new Date() });
  const [refreshInterval, setRefreshInterval] = useState(30000); // 30 seconds
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedMetrics, setSelectedMetrics] = useState<string[]>(['all']);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Data states
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetric[]>([]);
  const [occupancyData, setOccupancyData] = useState<OccupancyData[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [behavioralPatterns, setBehavioralPatterns] = useState<BehavioralPattern[]>([]);
  const [predictiveAlerts, setPredictiveAlerts] = useState<PredictiveAlert[]>([]);
  const [threatAssessment, setThreatAssessment] = useState<ThreatAssessment | null>(null);
  const [videoAnalytics, setVideoAnalytics] = useState<VideoAnalytics | null>(null);
  const [trendData, setTrendData] = useState<any[]>([]);
  const [anomalyData, setAnomalyData] = useState<any[]>([]);

  // Real-time updates
  useRealtime('analytics', (data) => {
    if (data.type === 'security_event') {
      setSecurityEvents(prev => [data.payload, ...prev.slice(0, 99)]);
    } else if (data.type === 'occupancy_update') {
      setOccupancyData(prev => [...prev.slice(-99), data.payload]);
    } else if (data.type === 'behavioral_anomaly') {
      setBehavioralPatterns(prev => [data.payload, ...prev.slice(0, 49)]);
    } else if (data.type === 'predictive_alert') {
      setPredictiveAlerts(prev => [data.payload, ...prev.slice(0, 19)]);
    } else if (data.type === 'video_analytics') {
      setVideoAnalytics(data.payload);
    }
  });

  // Data fetching
  const fetchAnalyticsData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [
        metricsRes,
        occupancyRes,
        eventsRes,
        patternsRes,
        alertsRes,
        threatRes,
        videoRes,
        trendsRes,
        anomaliesRes
      ] = await Promise.all([
        apiClient.get('/analytics/security-metrics', {
          params: { 
            from: timeRange.from.toISOString(), 
            to: timeRange.to.toISOString() 
          }
        }),
        apiClient.get('/analytics/occupancy', {
          params: { 
            from: timeRange.from.toISOString(), 
            to: timeRange.to.toISOString() 
          }
        }),
        apiClient.get('/analytics/security-events', {
          params: { 
            from: timeRange.from.toISOString(), 
            to: timeRange.to.toISOString(),
            severity: filterSeverity !== 'all' ? filterSeverity : undefined,
            search: searchQuery || undefined
          }
        }),
        apiClient.get('/analytics/behavioral-patterns', {
          params: { 
            from: timeRange.from.toISOString(), 
            to: timeRange.to.toISOString() 
          }
        }),
        apiClient.get('/analytics/predictive-alerts'),
        apiClient.get('/analytics/threat-assessment'),
        apiClient.get('/analytics/video-analytics'),
        apiClient.get('/analytics/trends', {
          params: { 
            from: timeRange.from.toISOString(), 
            to: timeRange.to.toISOString() 
          }
        }),
        apiClient.get('/analytics/anomalies', {
          params: { 
            from: timeRange.from.toISOString(), 
            to: timeRange.to.toISOString() 
          }
        })
      ]);

      setSecurityMetrics(metricsRes.data);
      setOccupancyData(occupancyRes.data);
      setSecurityEvents(eventsRes.data);
      setBehavioralPatterns(patternsRes.data);
      setPredictiveAlerts(alertsRes.data);
      setThreatAssessment(threatRes.data);
      setVideoAnalytics(videoRes.data);
      setTrendData(trendsRes.data);
      setAnomalyData(anomaliesRes.data);
    } catch (err) {
      setError('Failed to fetch analytics data');
      console.error('Analytics data fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  // Auto-refresh effect
  useEffect(() => {
    fetchAnalyticsData();
  }, [timeRange, filterSeverity, searchQuery]);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(fetchAnalyticsData, refreshInterval);
    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval, timeRange, filterSeverity, searchQuery]);

  // Export functionality
  const exportData = async (format: 'csv' | 'pdf' | 'json') => {
    try {
      const response = await apiClient.post('/analytics/export', {
        format,
        timeRange,
        metrics: selectedMetrics,
        filters: { severity: filterSeverity, search: searchQuery }
      }, { responseType: 'blob' });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `analytics-report-${format}.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
    }
  };

  // Computed values
  const filteredEvents = useMemo(() => {
    return securityEvents.filter(event => {
      const matchesSeverity = filterSeverity === 'all' || event.severity === filterSeverity;
      const matchesSearch = !searchQuery || 
        event.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        event.location.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesSeverity && matchesSearch;
    });
  }, [securityEvents, filterSeverity, searchQuery]);

  const criticalAlerts = useMemo(() => {
    return predictiveAlerts.filter(alert => alert.severity === 'critical').length;
  }, [predictiveAlerts]);

  const averageOccupancy = useMemo(() => {
    if (occupancyData.length === 0) return 0;
    return occupancyData.reduce((sum, data) => sum + data.utilization, 0) / occupancyData.length;
  }, [occupancyData]);

  if (!hasPermission('analytics:read')) {
    return (
      <div className="flex items-center justify-center h-96">
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Access Denied</AlertTitle>
          <AlertDescription>
            You don't have permission to view analytics data.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Analytics</h1>
          <p className="text-muted-foreground">
            Advanced analytics, anomaly detection, and predictive insights
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => fetchAnalyticsData()}
            disabled={loading}
          >
            <RefreshCw className={cn("h-4 w-4 mr-2", loading && "animate-spin")} />
            Refresh
          </Button>
          
          <Select value={refreshInterval.toString()} onValueChange={(value) => setRefreshInterval(Number(value))}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="10000">10s</SelectItem>
              <SelectItem value="30000">30s</SelectItem>
              <SelectItem value="60000">1m</SelectItem>
              <SelectItem value="300000">5m</SelectItem>
            </SelectContent>
          </Select>
          
          <div className="flex items-center space-x-2">
            <Switch
              id="auto-refresh"
              checked={autoRefresh}
              onCheckedChange={setAutoRefresh}
            />
            <Label htmlFor="auto-refresh">Auto-refresh</Label>
          </div>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Filters & Controls</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="space-y-2">
              <Label>Time Range</Label>
              <DatePickerWithRange
                date={timeRange}
                onDateChange={setTimeRange}
              />
            </div>
            
            <div className="space-y-2">
              <Label>Severity Filter</Label>
              <Select value={filterSeverity} onValueChange={setFilterSeverity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label>Search Events</Label>
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search events..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
            
            <div className="space-y-2">
              <Label>Export Data</Label>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => exportData('csv')}>
                  <Download className="h-4 w-4 mr-1" />
                  CSV
                </Button>
                <Button variant="outline" size="sm" onClick={() => exportData('pdf')}>
                  <Download className="h-4 w-4 mr-1" />
                  PDF
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
            <AlertTriangle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">{criticalAlerts}</div>
            <p className="text-xs text-muted-foreground">
              Critical alerts requiring attention
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Events</CardTitle>
            <Shield className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{filteredEvents.length}</div>
            <p className="text-xs text-muted-foreground">
              Events in selected timeframe
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Average Occupancy</CardTitle>
            <Users className="h-4 w-4 text-blue-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{averageOccupancy.toFixed(1)}%</div>
            <p className="text-xs text-muted-foreground">
              Space utilization rate
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Risk Score</CardTitle>
            <TrendingUp className="h-4 w-4 text-orange-600" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {threatAssessment?.overallRisk.toFixed(1) || '0.0'}
            </div>
            <p className="text-xs text-muted-foreground">
              Overall security risk level
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Analytics Tabs */}
      <Tabs defaultValue="dashboard" className="space-y-4">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="occupancy">Occupancy</TabsTrigger>
          <TabsTrigger value="behavioral">Behavioral</TabsTrigger>
          <TabsTrigger value="predictive">Predictive</TabsTrigger>
          <TabsTrigger value="video">Video Analytics</TabsTrigger>
          <TabsTrigger value="trends">Trends</TabsTrigger>
        </TabsList>

        {/* Dashboard Tab */}
        <TabsContent value="dashboard" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Security Events Timeline */}
            <Card>
              <CardHeader>
                <CardTitle>Security Events Timeline</CardTitle>
                <CardDescription>Recent security events and alerts</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={trendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="events" stroke={COLORS.primary} />
                    <Line type="monotone" dataKey="alerts" stroke={COLORS.danger} />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Threat Assessment */}
            <Card>
              <CardHeader>
                <CardTitle>Threat Assessment</CardTitle>
                <CardDescription>Risk levels by category</CardDescription>
              </CardHeader>
              <CardContent>
                {threatAssessment && (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-sm">Physical Security</span>
                        <span className="text-sm font-medium">{threatAssessment.categories.physical}%</span>
                      </div>
                      <Progress value={threatAssessment.categories.physical} className="h-2" />
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-sm">Cyber Security</span>
                        <span className="text-sm font-medium">{threatAssessment.categories.cyber}%</span>
                      </div>
                      <Progress value={threatAssessment.categories.cyber} className="h-2" />
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-sm">Operational</span>
                        <span className="text-sm font-medium">{threatAssessment.categories.operational}%</span>
                      </div>
                      <Progress value={threatAssessment.categories.operational} className="h-2" />
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-sm">Environmental</span>
                        <span className="text-sm font-medium">{threatAssessment.categories.environmental}%</span>
                      </div>
                      <Progress value={threatAssessment.categories.environmental} className="h-2" />
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Recent Events */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Security Events</CardTitle>
              <CardDescription>Latest security events and incidents</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {filteredEvents.slice(0, 20).map((event) => (
                  <div key={event.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <Badge variant={
                        event.severity === 'critical' ? 'destructive' :
                        event.severity === 'high' ? 'destructive' :
                        event.severity === 'medium' ? 'default' : 'secondary'
                      }>
                        {event.severity}
                      </Badge>
                      <div>
                        <p className="text-sm font-medium">{event.description}</p>
                        <p className="text-xs text-muted-foreground">
                          {event.location} • {format(new Date(event.timestamp), 'MMM dd, HH:mm')}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {event.resolved ? (
                        <CheckCircle className="h-4 w-4 text-green-600" />
                      ) : (
                        <AlertCircle className="h-4 w-4 text-orange-600" />
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Occupancy Tab */}
        <TabsContent value="occupancy" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Occupancy Trends</CardTitle>
                <CardDescription>Space utilization over time</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={occupancyData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Area type="monotone" dataKey="utilization" stroke={COLORS.primary} fill={COLORS.primary} fillOpacity={0.3} />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Zone Utilization</CardTitle>
                <CardDescription>Current occupancy by zone</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={occupancyData.slice(-10)}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="zone" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="utilization" fill={COLORS.primary} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Behavioral Tab */}
        <TabsContent value="behavioral" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Behavioral Patterns</CardTitle>
                <CardDescription>Detected behavioral anomalies</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {behavioralPatterns.slice(0, 10).map((pattern) => (
                    <div key={pattern.id} className="flex items-center justify-between p-3 border rounded-lg">
                      <div>
                        <p className="text-sm font-medium">{pattern.pattern}</p>
                        <p className="text-xs text-muted-foreground">
                          Confidence: {(pattern.confidence * 100).toFixed(1)}% • 
                          Risk: {pattern.riskLevel}
                        </p>
                      </div>
                      <Badge variant={
                        pattern.riskLevel === 'high' ? 'destructive' :
                        pattern.riskLevel === 'medium' ? 'default' : 'secondary'
                      }>
                        {pattern.anomalyScore.toFixed(2)}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Anomaly Detection</CardTitle>
                <CardDescription>Real-time anomaly scoring</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <ScatterChart data={anomalyData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" />
                    <YAxis dataKey="score" />
                    <Tooltip />
                    <Scatter dataKey="score" fill={COLORS.warning} />
                  </ScatterChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Predictive Tab */}
        <TabsContent value="predictive" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Predictive Alerts</CardTitle>
              <CardDescription>AI-powered threat predictions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {predictiveAlerts.map((alert) => (
                  <Alert key={alert.id} className={cn(
                    alert.severity === 'critical' && 'border-destructive',
                    alert.severity === 'high' && 'border-orange-500'
                  )}>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle className="flex items-center justify-between">
                      <span>{alert.type}</span>
                      <Badge variant={
                        alert.severity === 'critical' ? 'destructive' :
                        alert.severity === 'high' ? 'destructive' :
                        alert.severity === 'medium' ? 'default' : 'secondary'
                      }>
                        {(alert.probability * 100).toFixed(1)}%
                      </Badge>
                    </AlertTitle>
                    <AlertDescription>
                      <p className="mb-2">{alert.description}</p>
                      <p className="text-xs text-muted-foreground mb-2">
                        Expected timeframe: {alert.timeframe}
                      </p>
                      <div className="space-y-1">
                        <p className="text-xs font-medium">Recommended Actions:</p>
                        <ul className="text-xs space-y-1">
                          {alert.recommendedActions.map((action, index) => (
                            <li key={index} className="flex items-center space-x-2">
                              <div className="w-1 h-1 bg-current rounded-full" />
                              <span>{action}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </AlertDescription>
                  </Alert>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Video Analytics Tab */}
        <TabsContent value="video" className="space-y-4">
          {videoAnalytics && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Video Analytics Overview</CardTitle>
                  <CardDescription>Real-time video intelligence</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-600">{videoAnalytics.personCount}</div>
                      <p className="text-xs text-muted-foreground">People Detected</p>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-600">{videoAnalytics.faceDetections}</div>
                      <p className="text-xs text-muted-foreground">Face Detections</p>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-orange-600">{videoAnalytics.behaviorAlerts}</div>
                      <p className="text-xs text-muted-foreground">Behavior Alerts</p>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-red-600">{videoAnalytics.suspiciousActivity}</div>
                      <p className="text-xs text-muted-foreground">Suspicious Activity</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Camera Status</CardTitle>
                  <CardDescription>Live camera feed status</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {videoAnalytics.cameras.map((camera) => (
                      <div key={camera.id} className="flex items-center justify-between p-2 border rounded">
                        <div className="flex items-center space-x-2">
                          <Camera className="h-4 w-4" />
                          <span className="text-sm font-medium">{camera.name}</span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant={
                            camera.status === 'online' ? 'default' :
                            camera.status === 'offline' ? 'secondary' : 'destructive'
                          }>
                            {camera.status}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {camera.personCount} people
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* Trends Tab */}
        <TabsContent value="trends" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Trends Analysis</CardTitle>
              <CardDescription>Historical patterns and forecasting</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="events" stroke={COLORS.primary} name="Security Events" />
                  <Line type="monotone" dataKey="alerts" stroke={COLORS.danger} name="Critical Alerts" />
                  <Line type="monotone" dataKey="occupancy" stroke={COLORS.success} name="Occupancy %" />
                  <Line type="monotone" dataKey="riskScore" stroke={COLORS.warning} name="Risk Score" />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Error Display */}
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}