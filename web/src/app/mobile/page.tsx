'use client';

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { 
  Smartphone, 
  Wifi, 
  Bluetooth, 
  QrCode, 
  Shield, 
  Users, 
  Activity, 
  Settings, 
  Download, 
  Upload,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Bell,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Plus,
  Trash2,
  Edit,
  Search,
  Filter,
  BarChart3,
  Zap,
  Clock,
  MapPin,
  Signal
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useRealtime } from '@/hooks/useRealtime';
import { apiClient } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';

interface MobileCredential {
  id: string;
  userId: string;
  deviceId: string;
  deviceName: string;
  platform: 'ios' | 'android';
  status: 'active' | 'inactive' | 'revoked' | 'expired';
  enrolledAt: string;
  lastUsed: string;
  accessLevel: string;
  nfcEnabled: boolean;
  bluetoothEnabled: boolean;
  offlineCapable: boolean;
  pushNotifications: boolean;
  encryptionLevel: string;
  batteryLevel?: number;
  location?: string;
  usageCount: number;
}

interface MobileDevice {
  id: string;
  name: string;
  platform: 'ios' | 'android';
  osVersion: string;
  appVersion: string;
  isCompatible: boolean;
  capabilities: {
    nfc: boolean;
    bluetooth: boolean;
    biometric: boolean;
    camera: boolean;
  };
  registeredAt: string;
  lastSeen: string;
  status: 'online' | 'offline' | 'unknown';
}

interface EnrollmentSession {
  id: string;
  qrCode: string;
  expiresAt: string;
  status: 'pending' | 'completed' | 'expired';
  deviceInfo?: Partial<MobileDevice>;
}

export default function MobilePage() {
  const { user, hasPermission } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [credentials, setCredentials] = useState<MobileCredential[]>([]);
  const [devices, setDevices] = useState<MobileDevice[]>([]);
  const [enrollmentSessions, setEnrollmentSessions] = useState<EnrollmentSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedCredentials, setSelectedCredentials] = useState<string[]>([]);
  const [showEnrollmentDialog, setShowEnrollmentDialog] = useState(false);
  const [showBulkDialog, setShowBulkDialog] = useState(false);
  const [enrollmentData, setEnrollmentData] = useState({
    userId: '',
    accessLevel: '',
    nfcEnabled: true,
    bluetoothEnabled: true,
    offlineCapable: true,
    pushNotifications: true,
    expiryDays: 365
  });

  // Real-time updates for mobile credential events
  useRealtime('mobile-credentials', (event) => {
    switch (event.type) {
      case 'credential-enrolled':
        setCredentials(prev => [...prev, event.data]);
        toast({
          title: 'Mobile Credential Enrolled',
          description: `New credential enrolled for ${event.data.deviceName}`,
        });
        break;
      case 'credential-used':
        setCredentials(prev => prev.map(cred => 
          cred.id === event.data.id 
            ? { ...cred, lastUsed: event.data.lastUsed, usageCount: cred.usageCount + 1 }
            : cred
        ));
        break;
      case 'credential-revoked':
        setCredentials(prev => prev.map(cred => 
          cred.id === event.data.id 
            ? { ...cred, status: 'revoked' }
            : cred
        ));
        break;
      case 'device-status-changed':
        setDevices(prev => prev.map(device => 
          device.id === event.data.id 
            ? { ...device, status: event.data.status, lastSeen: event.data.lastSeen }
            : device
        ));
        break;
    }
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [credentialsRes, devicesRes, sessionsRes] = await Promise.all([
        apiClient.get('/mobile-credentials'),
        apiClient.get('/mobile-devices'),
        apiClient.get('/mobile-enrollment-sessions')
      ]);
      
      setCredentials(credentialsRes.data);
      setDevices(devicesRes.data);
      setEnrollmentSessions(sessionsRes.data);
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load mobile credential data',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const generateEnrollmentQR = async () => {
    try {
      const response = await apiClient.post('/mobile-credentials/enroll', enrollmentData);
      const session = response.data;
      setEnrollmentSessions(prev => [...prev, session]);
      setShowEnrollmentDialog(false);
      toast({
        title: 'Enrollment QR Generated',
        description: 'QR code is ready for mobile device enrollment',
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to generate enrollment QR code',
        variant: 'destructive',
      });
    }
  };

  const revokeCredential = async (credentialId: string) => {
    try {
      await apiClient.post(`/mobile-credentials/${credentialId}/revoke`);
      setCredentials(prev => prev.map(cred => 
        cred.id === credentialId ? { ...cred, status: 'revoked' } : cred
      ));
      toast({
        title: 'Credential Revoked',
        description: 'Mobile credential has been revoked successfully',
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to revoke mobile credential',
        variant: 'destructive',
      });
    }
  };

  const bulkRevokeCredentials = async () => {
    try {
      await apiClient.post('/mobile-credentials/bulk-revoke', {
        credentialIds: selectedCredentials
      });
      setCredentials(prev => prev.map(cred => 
        selectedCredentials.includes(cred.id) ? { ...cred, status: 'revoked' } : cred
      ));
      setSelectedCredentials([]);
      setShowBulkDialog(false);
      toast({
        title: 'Credentials Revoked',
        description: `${selectedCredentials.length} credentials revoked successfully`,
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to revoke selected credentials',
        variant: 'destructive',
      });
    }
  };

  const updateCredentialSettings = async (credentialId: string, settings: Partial<MobileCredential>) => {
    try {
      await apiClient.patch(`/mobile-credentials/${credentialId}`, settings);
      setCredentials(prev => prev.map(cred => 
        cred.id === credentialId ? { ...cred, ...settings } : cred
      ));
      toast({
        title: 'Settings Updated',
        description: 'Mobile credential settings updated successfully',
      });
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update credential settings',
        variant: 'destructive',
      });
    }
  };

  const checkDeviceCompatibility = async (deviceInfo: any) => {
    try {
      const response = await apiClient.post('/mobile-devices/compatibility-check', deviceInfo);
      return response.data;
    } catch (error) {
      return { isCompatible: false, issues: ['Unknown compatibility error'] };
    }
  };

  const filteredCredentials = credentials.filter(cred => {
    const matchesSearch = cred.deviceName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         cred.userId.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || cred.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-500';
      case 'inactive': return 'bg-yellow-500';
      case 'revoked': return 'bg-red-500';
      case 'expired': return 'bg-gray-500';
      default: return 'bg-gray-500';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircle className="h-4 w-4" />;
      case 'inactive': return <Clock className="h-4 w-4" />;
      case 'revoked': return <XCircle className="h-4 w-4" />;
      case 'expired': return <AlertTriangle className="h-4 w-4" />;
      default: return <Clock className="h-4 w-4" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4" />
          <p>Loading mobile credentials...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Mobile Credentials</h1>
          <p className="text-muted-foreground">Manage mobile access credentials and devices</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => setShowEnrollmentDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Enroll Device
          </Button>
          {selectedCredentials.length > 0 && (
            <Button variant="destructive" onClick={() => setShowBulkDialog(true)}>
              <Trash2 className="h-4 w-4 mr-2" />
              Revoke Selected ({selectedCredentials.length})
            </Button>
          )}
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Credentials</CardTitle>
            <Smartphone className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{credentials.length}</div>
            <p className="text-xs text-muted-foreground">
              {credentials.filter(c => c.status === 'active').length} active
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Registered Devices</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{devices.length}</div>
            <p className="text-xs text-muted-foreground">
              {devices.filter(d => d.status === 'online').length} online
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">NFC Enabled</CardTitle>
            <Wifi className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {credentials.filter(c => c.nfcEnabled).length}
            </div>
            <p className="text-xs text-muted-foreground">
              {Math.round((credentials.filter(c => c.nfcEnabled).length / credentials.length) * 100)}% of credentials
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Bluetooth Enabled</CardTitle>
            <Bluetooth className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {credentials.filter(c => c.bluetoothEnabled).length}
            </div>
            <p className="text-xs text-muted-foreground">
              {Math.round((credentials.filter(c => c.bluetoothEnabled).length / credentials.length) * 100)}% of credentials
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="credentials">Credentials</TabsTrigger>
          <TabsTrigger value="devices">Devices</TabsTrigger>
          <TabsTrigger value="enrollment">Enrollment</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Recent Activity</CardTitle>
                <CardDescription>Latest mobile credential events</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {credentials.slice(0, 5).map((credential) => (
                    <div key={credential.id} className="flex items-center space-x-4">
                      <div className={`w-2 h-2 rounded-full ${getStatusColor(credential.status)}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{credential.deviceName}</p>
                        <p className="text-xs text-muted-foreground">
                          Last used: {new Date(credential.lastUsed).toLocaleDateString()}
                        </p>
                      </div>
                      <Badge variant="outline">{credential.status}</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Device Status</CardTitle>
                <CardDescription>Current status of registered devices</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {devices.slice(0, 5).map((device) => (
                    <div key={device.id} className="flex items-center space-x-4">
                      <div className="flex items-center space-x-2">
                        {device.platform === 'ios' ? (
                          <Smartphone className="h-4 w-4" />
                        ) : (
                          <Smartphone className="h-4 w-4" />
                        )}
                        <Signal className={`h-3 w-3 ${device.status === 'online' ? 'text-green-500' : 'text-gray-400'}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{device.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {device.platform} {device.osVersion}
                        </p>
                      </div>
                      <Badge variant={device.status === 'online' ? 'default' : 'secondary'}>
                        {device.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="credentials" className="space-y-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-2">
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search credentials..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8 w-64"
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="active">Active</SelectItem>
                  <SelectItem value="inactive">Inactive</SelectItem>
                  <SelectItem value="revoked">Revoked</SelectItem>
                  <SelectItem value="expired">Expired</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button variant="outline" onClick={loadData}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-12">
                      <input
                        type="checkbox"
                        checked={selectedCredentials.length === filteredCredentials.length}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedCredentials(filteredCredentials.map(c => c.id));
                          } else {
                            setSelectedCredentials([]);
                          }
                        }}
                      />
                    </TableHead>
                    <TableHead>Device</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Capabilities</TableHead>
                    <TableHead>Last Used</TableHead>
                    <TableHead>Usage Count</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredCredentials.map((credential) => (
                    <TableRow key={credential.id}>
                      <TableCell>
                        <input
                          type="checkbox"
                          checked={selectedCredentials.includes(credential.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedCredentials(prev => [...prev, credential.id]);
                            } else {
                              setSelectedCredentials(prev => prev.filter(id => id !== credential.id));
                            }
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          <Smartphone className="h-4 w-4" />
                          <div>
                            <p className="font-medium">{credential.deviceName}</p>
                            <p className="text-xs text-muted-foreground">{credential.platform}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>{credential.userId}</TableCell>
                      <TableCell>
                        <div className="flex items-center space-x-2">
                          {getStatusIcon(credential.status)}
                          <Badge className={getStatusColor(credential.status)}>
                            {credential.status}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          {credential.nfcEnabled && <Wifi className="h-4 w-4 text-blue-500" />}
                          {credential.bluetoothEnabled && <Bluetooth className="h-4 w-4 text-blue-500" />}
                          {credential.offlineCapable && <Zap className="h-4 w-4 text-green-500" />}
                          {credential.pushNotifications && <Bell className="h-4 w-4 text-orange-500" />}
                        </div>
                      </TableCell>
                      <TableCell>
                        {new Date(credential.lastUsed).toLocaleDateString()}
                      </TableCell>
                      <TableCell>{credential.usageCount}</TableCell>
                      <TableCell>
                        <div className="flex space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              // Open credential settings dialog
                            }}
                          >
                            <Settings className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => revokeCredential(credential.id)}
                            disabled={credential.status === 'revoked'}
                          >
                            <XCircle className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="devices" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Registered Devices</CardTitle>
              <CardDescription>Manage mobile devices and their capabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {devices.map((device) => (
                  <Card key={device.id}>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-lg">{device.name}</CardTitle>
                        <Badge variant={device.status === 'online' ? 'default' : 'secondary'}>
                          {device.status}
                        </Badge>
                      </div>
                      <CardDescription>
                        {device.platform} {device.osVersion}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex items-center justify-between text-sm">
                        <span>App Version:</span>
                        <span>{device.appVersion}</span>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span>Compatible:</span>
                        <Badge variant={device.isCompatible ? 'default' : 'destructive'}>
                          {device.isCompatible ? 'Yes' : 'No'}
                        </Badge>
                      </div>
                      <div className="space-y-2">
                        <p className="text-sm font-medium">Capabilities:</p>
                        <div className="flex flex-wrap gap-1">
                          {device.capabilities.nfc && (
                            <Badge variant="outline" className="text-xs">
                              <Wifi className="h-3 w-3 mr-1" />
                              NFC
                            </Badge>
                          )}
                          {device.capabilities.bluetooth && (
                            <Badge variant="outline" className="text-xs">
                              <Bluetooth className="h-3 w-3 mr-1" />
                              Bluetooth
                            </Badge>
                          )}
                          {device.capabilities.biometric && (
                            <Badge variant="outline" className="text-xs">
                              <Shield className="h-3 w-3 mr-1" />
                              Biometric
                            </Badge>
                          )}
                          {device.capabilities.camera && (
                            <Badge variant="outline" className="text-xs">
                              <Eye className="h-3 w-3 mr-1" />
                              Camera
                            </Badge>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-sm">
                        <span>Last Seen:</span>
                        <span>{new Date(device.lastSeen).toLocaleDateString()}</span>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="enrollment" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Active Enrollment Sessions</CardTitle>
                <CardDescription>QR codes waiting for device enrollment</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {enrollmentSessions.filter(s => s.status === 'pending').map((session) => (
                    <Card key={session.id}>
                      <CardContent className="p-4">
                        <div className="flex items-center space-x-4">
                          <div className="bg-white p-2 rounded border">
                            <QrCode className="h-16 w-16" />
                          </div>
                          <div className="flex-1">
                            <p className="font-medium">Session {session.id.slice(0, 8)}</p>
                            <p className="text-sm text-muted-foreground">
                              Expires: {new Date(session.expiresAt).toLocaleString()}
                            </p>
                            <Badge className="mt-1">{session.status}</Badge>
                          </div>
                          <Button variant="outline" size="sm">
                            <Download className="h-4 w-4 mr-2" />
                            Download QR
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                  {enrollmentSessions.filter(s => s.status === 'pending').length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      No active enrollment sessions
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Enrollment History</CardTitle>
                <CardDescription>Recently completed enrollments</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {enrollmentSessions.filter(s => s.status === 'completed').slice(0, 5).map((session) => (
                    <div key={session.id} className="flex items-center space-x-4">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <div className="flex-1">
                        <p className="text-sm font-medium">
                          {session.deviceInfo?.name || 'Unknown Device'}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Enrolled: {new Date(session.expiresAt).toLocaleDateString()}
                        </p>
                      </div>
                      <Badge variant="outline">Completed</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Usage Analytics</CardTitle>
                <CardDescription>Mobile credential usage patterns</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Daily Active Credentials</span>
                    <span className="font-medium">
                      {credentials.filter(c => {
                        const lastUsed = new Date(c.lastUsed);
                        const today = new Date();
                        return lastUsed.toDateString() === today.toDateString();
                      }).length}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Weekly Active Credentials</span>
                    <span className="font-medium">
                      {credentials.filter(c => {
                        const lastUsed = new Date(c.lastUsed);
                        const weekAgo = new Date();
                        weekAgo.setDate(weekAgo.getDate() - 7);
                        return lastUsed >= weekAgo;
                      }).length}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Average Usage per Credential</span>
                    <span className="font-medium">
                      {Math.round(credentials.reduce((sum, c) => sum + c.usageCount, 0) / credentials.length)}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Platform Distribution</CardTitle>
                <CardDescription>Device platform breakdown</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Smartphone className="h-4 w-4" />
                      <span className="text-sm">iOS Devices</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">
                        {credentials.filter(c => c.platform === 'ios').length}
                      </span>
                      <Progress 
                        value={(credentials.filter(c => c.platform === 'ios').length / credentials.length) * 100} 
                        className="w-20"
                      />
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <Smartphone className="h-4 w-4" />
                      <span className="text-sm">Android Devices</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">
                        {credentials.filter(c => c.platform === 'android').length}
                      </span>
                      <Progress 
                        value={(credentials.filter(c => c.platform === 'android').length / credentials.length) * 100} 
                        className="w-20"
                      />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Default Enrollment Settings</CardTitle>
                <CardDescription>Configure default settings for new mobile credentials</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor="default-nfc">Enable NFC by default</Label>
                  <Switch id="default-nfc" defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="default-bluetooth">Enable Bluetooth by default</Label>
                  <Switch id="default-bluetooth" defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="default-offline">Enable offline capability</Label>
                  <Switch id="default-offline" defaultChecked />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="default-push">Enable push notifications</Label>
                  <Switch id="default-push" defaultChecked />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="default-expiry">Default credential expiry (days)</Label>
                  <Input id="default-expiry" type="number" defaultValue="365" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Security Settings</CardTitle>
                <CardDescription>Configure security policies for mobile credentials</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="encryption-level">Encryption Level</Label>
                  <Select defaultValue="aes256">
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="aes128">AES-128</SelectItem>
                      <SelectItem value="aes256">AES-256</SelectItem>
                      <SelectItem value="rsa2048">RSA-2048</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="require-biometric">Require biometric authentication</Label>
                  <Switch id="require-biometric" />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="auto-revoke">Auto-revoke inactive credentials</Label>
                  <Switch id="auto-revoke" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="inactivity-days">Inactivity threshold (days)</Label>
                  <Input id="inactivity-days" type="number" defaultValue="90" />
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      {/* Enrollment Dialog */}
      <Dialog open={showEnrollmentDialog} onOpenChange={setShowEnrollmentDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Enroll Mobile Device</DialogTitle>
            <DialogDescription>
              Generate a QR code for mobile device enrollment
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="user-id">User ID</Label>
              <Input
                id="user-id"
                value={enrollmentData.userId}
                onChange={(e) => setEnrollmentData(prev => ({ ...prev, userId: e.target.value }))}
                placeholder="Enter user ID"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="access-level">Access Level</Label>
              <Select
                value={enrollmentData.accessLevel}
                onValueChange={(value) => setEnrollmentData(prev => ({ ...prev, accessLevel: value }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select access level" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="basic">Basic Access</SelectItem>
                  <SelectItem value="standard">Standard Access</SelectItem>
                  <SelectItem value="premium">Premium Access</SelectItem>
                  <SelectItem value="admin">Admin Access</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center space-x-2">
                <Switch
                  id="nfc-enabled"
                  checked={enrollmentData.nfcEnabled}
                  onCheckedChange={(checked) => setEnrollmentData(prev => ({ ...prev, nfcEnabled: checked }))}
                />
                <Label htmlFor="nfc-enabled">NFC</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="bluetooth-enabled"
                  checked={enrollmentData.bluetoothEnabled}
                  onCheckedChange={(checked) => setEnrollmentData(prev => ({ ...prev, bluetoothEnabled: checked }))}
                />
                <Label htmlFor="bluetooth-enabled">Bluetooth</Label>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center space-x-2">
                <Switch
                  id="offline-capable"
                  checked={enrollmentData.offlineCapable}
                  onCheckedChange={(checked) => setEnrollmentData(prev => ({ ...prev, offlineCapable: checked }))}
                />
                <Label htmlFor="offline-capable">Offline</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  id="push-notifications"
                  checked={enrollmentData.pushNotifications}
                  onCheckedChange={(checked) => setEnrollmentData(prev => ({ ...prev, pushNotifications: checked }))}
                />
                <Label htmlFor="push-notifications">Push</Label>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="expiry-days">Expiry (days)</Label>
              <Input
                id="expiry-days"
                type="number"
                value={enrollmentData.expiryDays}
                onChange={(e) => setEnrollmentData(prev => ({ ...prev, expiryDays: parseInt(e.target.value) }))}
              />
            </div>
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setShowEnrollmentDialog(false)}>
                Cancel
              </Button>
              <Button onClick={generateEnrollmentQR}>
                <QrCode className="h-4 w-4 mr-2" />
                Generate QR Code
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Bulk Revoke Dialog */}
      <Dialog open={showBulkDialog} onOpenChange={setShowBulkDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke Selected Credentials</DialogTitle>
            <DialogDescription>
              Are you sure you want to revoke {selectedCredentials.length} mobile credentials? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={() => setShowBulkDialog(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={bulkRevokeCredentials}>
              <Trash2 className="h-4 w-4 mr-2" />
              Revoke Credentials
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}