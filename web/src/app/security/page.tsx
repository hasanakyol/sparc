'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Eye, 
  FileText, 
  Users, 
  Settings, 
  TrendingUp, 
  Download,
  Search,
  Filter,
  RefreshCw,
  Bell,
  Lock,
  Globe,
  Activity,
  BarChart3,
  Calendar,
  Clock,
  MapPin,
  User,
  Building,
  Wifi,
  Server,
  Database,
  Network
} from 'lucide-react';

// Real implementations
import { useAuth } from '@/hooks/useAuth';
import { useRealtime } from '@/hooks/useRealtime';
import { apiClient } from '@/lib/api';

interface SecurityMetrics {
  threatLevel: string;
  activeIncidents: number;
  complianceScore: number;
  vulnerabilities: number;
  securityEvents: number;
  lastScan: string;
}

interface ComplianceFramework {
  status: 'compliant' | 'non-compliant' | 'pending';
  score: number;
  lastAudit: string;
}

interface ComplianceStatus {
  sox: ComplianceFramework;
  hipaa: ComplianceFramework;
  pciDss: ComplianceFramework;
  gdpr: ComplianceFramework;
}

interface AuditEvent {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  ip: string;
  details: string;
}

interface SecurityAlert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  message: string;
  timestamp: string;
  status: 'open' | 'investigating' | 'resolved';
  location: string;
}

interface SecurityIncident {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  assignee: string;
  createdAt: string;
  description: string;
}

const SecurityDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadMetrics = async () => {
      try {
        const data = await apiClient.get('/api/security/dashboard/metrics');
        setMetrics(data);
      } catch (error) {
        console.error('Failed to load security metrics:', error);
      } finally {
        setLoading(false);
      }
    };

    loadMetrics();
  }, []);

  if (loading || !metrics) {
    return <div className="flex items-center justify-center h-64">Loading...</div>;
  }

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'low': return 'text-green-600';
      case 'medium': return 'text-yellow-600';
      case 'high': return 'text-red-600';
      case 'critical': return 'text-red-800';
      default: return 'text-gray-600';
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Threat Level</CardTitle>
          <Shield className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className={`text-2xl font-bold ${getThreatLevelColor(metrics.threatLevel)}`}>
            {metrics.threatLevel.toUpperCase()}
          </div>
          <p className="text-xs text-muted-foreground">
            Last scan: {new Date(metrics.lastScan).toLocaleString()}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Active Incidents</CardTitle>
          <AlertTriangle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{metrics.activeIncidents}</div>
          <p className="text-xs text-muted-foreground">
            Requiring immediate attention
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Compliance Score</CardTitle>
          <CheckCircle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{metrics.complianceScore}%</div>
          <Progress value={metrics.complianceScore} className="mt-2" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
          <XCircle className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-red-600">{metrics.vulnerabilities}</div>
          <p className="text-xs text-muted-foreground">
            {metrics.securityEvents} events today
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

const ThreatIndicator: React.FC<{ level: string }> = ({ level }) => {
  const getIndicatorColor = (threatLevel: string) => {
    switch (threatLevel) {
      case 'low': return 'bg-green-500';
      case 'medium': return 'bg-yellow-500';
      case 'high': return 'bg-red-500';
      case 'critical': return 'bg-red-700';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="flex items-center space-x-2">
      <div className={`w-3 h-3 rounded-full ${getIndicatorColor(level)}`} />
      <span className="text-sm font-medium">{level.toUpperCase()}</span>
    </div>
  );
};

const ComplianceStatus: React.FC = () => {
  const [compliance, setCompliance] = useState<ComplianceStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadCompliance = async () => {
      try {
        const data = await apiClient.get('/api/security/compliance/status');
        setCompliance(data);
      } catch (error) {
        console.error('Failed to load compliance status:', error);
      } finally {
        setLoading(false);
      }
    };

    loadCompliance();
  }, []);

  if (loading || !compliance) {
    return <div>Loading compliance status...</div>;
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'compliant':
        return <Badge variant="default" className="bg-green-500">Compliant</Badge>;
      case 'non-compliant':
        return <Badge variant="destructive">Non-Compliant</Badge>;
      case 'pending':
        return <Badge variant="secondary">Pending</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <div className="space-y-4">
      {Object.entries(compliance).map(([framework, data]) => (
        <Card key={framework}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">{framework.toUpperCase()}</CardTitle>
              {getStatusBadge(data.status)}
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between mb-2">
              <span>Compliance Score</span>
              <span className="font-bold">{data.score}%</span>
            </div>
            <Progress value={data.score} className="mb-2" />
            <p className="text-sm text-muted-foreground">
              Last audit: {new Date(data.lastAudit).toLocaleDateString()}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};

const AuditTrail: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState('all');

  useEffect(() => {
    const loadAuditTrail = async () => {
      try {
        const params = new URLSearchParams();
        if (searchTerm) params.append('search', searchTerm);
        if (filterAction !== 'all') params.append('action', filterAction);
        
        const data = await apiClient.get(`/api/security/audit/trail?${params.toString()}`);
        setEvents(data);
      } catch (error) {
        console.error('Failed to load audit trail:', error);
      } finally {
        setLoading(false);
      }
    };

    loadAuditTrail();
  }, [searchTerm, filterAction]);

  const filteredEvents = useMemo(() => {
    return events.filter(event => {
      const matchesSearch = searchTerm === '' || 
        event.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
        event.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
        event.resource.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesFilter = filterAction === 'all' || event.action === filterAction;
      
      return matchesSearch && matchesFilter;
    });
  }, [events, searchTerm, filterAction]);

  return (
    <div className="space-y-4">
      <div className="flex space-x-4">
        <div className="flex-1">
          <Input
            placeholder="Search audit events..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full"
          />
        </div>
        <Select value={filterAction} onValueChange={setFilterAction}>
          <SelectTrigger className="w-48">
            <SelectValue placeholder="Filter by action" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Actions</SelectItem>
            <SelectItem value="ACCESS_GRANTED">Access Granted</SelectItem>
            <SelectItem value="ACCESS_DENIED">Access Denied</SelectItem>
            <SelectItem value="LOGIN">Login</SelectItem>
            <SelectItem value="LOGOUT">Logout</SelectItem>
            <SelectItem value="CONFIG_CHANGE">Config Change</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {loading ? (
        <div>Loading audit trail...</div>
      ) : (
        <div className="space-y-2">
          {filteredEvents.map((event) => (
            <Card key={event.id}>
              <CardContent className="pt-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div>
                      <p className="font-medium">{event.action}</p>
                      <p className="text-sm text-muted-foreground">{event.user}</p>
                    </div>
                    <Separator orientation="vertical" className="h-8" />
                    <div>
                      <p className="text-sm">{event.resource}</p>
                      <p className="text-xs text-muted-foreground">{event.ip}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm">{new Date(event.timestamp).toLocaleString()}</p>
                    <p className="text-xs text-muted-foreground">{event.details}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

const SecurityAlerts: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadAlerts = async () => {
      try {
        const data = await apiClient.get('/api/security/alerts');
        setAlerts(data);
      } catch (error) {
        console.error('Failed to load security alerts:', error);
      } finally {
        setLoading(false);
      }
    };

    loadAlerts();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'border-green-500 bg-green-50';
      case 'medium': return 'border-yellow-500 bg-yellow-50';
      case 'high': return 'border-red-500 bg-red-50';
      case 'critical': return 'border-red-700 bg-red-100';
      default: return 'border-gray-500 bg-gray-50';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'low': return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'medium': return <AlertTriangle className="h-4 w-4 text-yellow-600" />;
      case 'high': return <XCircle className="h-4 w-4 text-red-600" />;
      case 'critical': return <Shield className="h-4 w-4 text-red-700" />;
      default: return <Eye className="h-4 w-4 text-gray-600" />;
    }
  };

  return (
    <div className="space-y-4">
      {loading ? (
        <div>Loading security alerts...</div>
      ) : (
        alerts.map((alert) => (
          <Alert key={alert.id} className={getSeverityColor(alert.severity)}>
            <div className="flex items-start space-x-3">
              {getSeverityIcon(alert.severity)}
              <div className="flex-1">
                <AlertTitle className="flex items-center justify-between">
                  <span>{alert.type.replace(/_/g, ' ')}</span>
                  <Badge variant={alert.status === 'open' ? 'destructive' : 'secondary'}>
                    {alert.status}
                  </Badge>
                </AlertTitle>
                <AlertDescription className="mt-2">
                  <p>{alert.message}</p>
                  <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
                    <span>{alert.location}</span>
                    <span>{new Date(alert.timestamp).toLocaleString()}</span>
                  </div>
                </AlertDescription>
              </div>
            </div>
          </Alert>
        ))
      )}
    </div>
  );
};

const IncidentReporting: React.FC = () => {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadIncidents = async () => {
      try {
        const data = await apiClient.get('/api/security/incidents');
        setIncidents(data);
      } catch (error) {
        console.error('Failed to load incidents:', error);
      } finally {
        setLoading(false);
      }
    };

    loadIncidents();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-red-600';
      case 'investigating': return 'text-yellow-600';
      case 'resolved': return 'text-green-600';
      case 'closed': return 'text-gray-600';
      default: return 'text-gray-600';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold">Security Incidents</h3>
        <Button>
          <FileText className="h-4 w-4 mr-2" />
          Create Incident
        </Button>
      </div>

      {loading ? (
        <div>Loading incidents...</div>
      ) : (
        <div className="space-y-4">
          {incidents.map((incident) => (
            <Card key={incident.id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">{incident.title}</CardTitle>
                  <div className="flex items-center space-x-2">
                    <Badge variant={incident.severity === 'high' ? 'destructive' : 'secondary'}>
                      {incident.severity}
                    </Badge>
                    <span className={`text-sm font-medium ${getStatusColor(incident.status)}`}>
                      {incident.status.toUpperCase()}
                    </span>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-2">{incident.description}</p>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Assigned to: {incident.assignee}</span>
                  <span>Created: {new Date(incident.createdAt).toLocaleString()}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

const CybersecurityMonitor: React.FC = () => {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadCybersecurityStatus = async () => {
      try {
        const data = await apiClient.get('/api/security/cybersecurity/status');
        setStatus(data);
      } catch (error) {
        console.error('Failed to load cybersecurity status:', error);
      } finally {
        setLoading(false);
      }
    };

    loadCybersecurityStatus();
  }, []);

  if (loading || !status) {
    return <div>Loading cybersecurity status...</div>;
  }

  const getStatusIcon = (statusValue: string) => {
    return statusValue === 'active' || statusValue === 'secure' ? 
      <CheckCircle className="h-5 w-5 text-green-600" /> : 
      <XCircle className="h-5 w-5 text-red-600" />;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5" />
            <span>Firewall Status</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            {getStatusIcon(status.firewallStatus)}
            <span className="capitalize">{status.firewallStatus}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Eye className="h-5 w-5" />
            <span>Intrusion Detection</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            {getStatusIcon(status.intrusionDetection)}
            <span className="capitalize">{status.intrusionDetection}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5" />
            <span>Antivirus Status</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            {getStatusIcon(status.antivirusStatus)}
            <span className="capitalize">{status.antivirusStatus}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Network className="h-5 w-5" />
            <span>Network Security</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            {getStatusIcon(status.networkSecurity)}
            <span className="capitalize">{status.networkSecurity}</span>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Last updated: {new Date(status.lastUpdate).toLocaleString()}
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

export default function SecurityPage() {
  const { user, hasPermission } = useAuth();
  const realtimeData = useRealtime('security-events');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [refreshing, setRefreshing] = useState(false);
  
  // Listen for real-time security events
  useEffect(() => {
    if (realtimeData?.data) {
      // Handle real-time security events
      console.log('Real-time security event:', realtimeData.data);
      // You can trigger component refreshes or show notifications here
    }
  }, [realtimeData]);

  // Check permissions
  if (!hasPermission('security:read')) {
    return (
      <div className="flex items-center justify-center h-64">
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Access Denied</AlertTitle>
          <AlertDescription>
            You don't have permission to view security information.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      // Trigger refresh of all components by forcing re-renders
      window.location.reload();
    } catch (error) {
      console.error('Failed to refresh data:', error);
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security & Compliance</h1>
          <p className="text-muted-foreground">
            Monitor security threats, manage compliance, and track incidents
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={`h-4 w-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button>
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="audit">Audit Trail</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="incidents">Incidents</TabsTrigger>
          <TabsTrigger value="cybersecurity">Cybersecurity</TabsTrigger>
          <TabsTrigger value="training">Training</TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="space-y-6">
          <SecurityDashboard />
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Recent Security Alerts</CardTitle>
                <CardDescription>Latest security events requiring attention</CardDescription>
              </CardHeader>
              <CardContent>
                <SecurityAlerts />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>System Status</CardTitle>
                <CardDescription>Current cybersecurity system status</CardDescription>
              </CardHeader>
              <CardContent>
                <CybersecurityMonitor />
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Compliance Status</CardTitle>
              <CardDescription>
                Monitor compliance with regulatory frameworks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ComplianceStatus />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="audit" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Audit Trail</CardTitle>
              <CardDescription>
                Comprehensive log of all security-related activities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <AuditTrail />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Security Alerts</CardTitle>
              <CardDescription>
                Active security alerts and notifications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <SecurityAlerts />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="incidents" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Incident Management</CardTitle>
              <CardDescription>
                Track and manage security incidents
              </CardDescription>
            </CardHeader>
            <CardContent>
              <IncidentReporting />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="cybersecurity" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Cybersecurity Monitoring</CardTitle>
              <CardDescription>
                Real-time monitoring of cybersecurity systems
              </CardDescription>
            </CardHeader>
            <CardContent>
              <CybersecurityMonitor />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="training" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Security Training</CardTitle>
              <CardDescription>
                Track security awareness training completion
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card>
                    <CardContent className="pt-6">
                      <div className="text-2xl font-bold">78%</div>
                      <p className="text-sm text-muted-foreground">Completion Rate</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-6">
                      <div className="text-2xl font-bold">117</div>
                      <p className="text-sm text-muted-foreground">Completed Users</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="pt-6">
                      <div className="text-2xl font-bold">33</div>
                      <p className="text-sm text-muted-foreground">Pending Users</p>
                    </CardContent>
                  </Card>
                </div>
                <Progress value={78} className="w-full" />
                <p className="text-sm text-muted-foreground">
                  Next training deadline: March 1, 2024
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
