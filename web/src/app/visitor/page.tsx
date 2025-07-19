'use client';

import React, { useState, useEffect, useMemo } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { useRealtime } from '@/hooks/useRealtime';
import { apiClient } from '@/lib/api-client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { 
  Users, 
  UserCheck, 
  UserX, 
  Clock, 
  AlertTriangle, 
  Shield, 
  Printer, 
  Bell, 
  Calendar as CalendarIcon,
  Search,
  Filter,
  Download,
  RefreshCw,
  Camera,
  MapPin,
  Phone,
  Mail,
  Building,
  QrCode,
  CheckCircle,
  XCircle,
  AlertCircle
} from 'lucide-react';
import { format, addDays, isAfter, isBefore } from 'date-fns';
import { toast } from 'sonner';

interface Visitor {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  company: string;
  purpose: string;
  hostId: string;
  hostName: string;
  expectedArrival: string;
  expectedDeparture: string;
  actualArrival?: string;
  actualDeparture?: string;
  status: 'pre-registered' | 'checked-in' | 'checked-out' | 'overstay' | 'evacuated';
  badgeNumber?: string;
  photo?: string;
  accessRestrictions: string[];
  watchlistStatus: 'clear' | 'flagged' | 'pending';
  emergencyContact?: {
    name: string;
    phone: string;
    relationship: string;
  };
  vehicleInfo?: {
    make: string;
    model: string;
    licensePlate: string;
    parkingSpot?: string;
  };
  createdAt: string;
  updatedAt: string;
}

interface Host {
  id: string;
  name: string;
  email: string;
  department: string;
  phone: string;
}

interface VisitorStats {
  total: number;
  checkedIn: number;
  preRegistered: number;
  overstay: number;
  evacuated: number;
}

export default function VisitorManagementPage() {
  const { user, hasPermission } = useAuth();
  const [visitors, setVisitors] = useState<Visitor[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [stats, setStats] = useState<VisitorStats>({
    total: 0,
    checkedIn: 0,
    preRegistered: 0,
    overstay: 0,
    evacuated: 0
  });
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedDate, setSelectedDate] = useState<Date>(new Date());
  const [showPreRegistration, setShowPreRegistration] = useState(false);
  const [showCheckIn, setShowCheckIn] = useState(false);
  const [showBadgePrint, setShowBadgePrint] = useState(false);
  const [selectedVisitor, setSelectedVisitor] = useState<Visitor | null>(null);
  const [isKioskMode, setIsKioskMode] = useState(false);

  // Real-time updates for visitor events
  useRealtime('visitor-events', (event) => {
    switch (event.type) {
      case 'visitor-checked-in':
      case 'visitor-checked-out':
      case 'visitor-pre-registered':
      case 'visitor-overstay':
      case 'visitor-evacuated':
        fetchVisitors();
        break;
      case 'watchlist-alert':
        toast.error(`Watchlist Alert: ${event.data.visitorName} flagged for ${event.data.reason}`);
        break;
      case 'host-notification':
        if (event.data.hostId === user?.id) {
          toast.info(`Your visitor ${event.data.visitorName} has arrived`);
        }
        break;
    }
  });

  // Fetch visitors and related data
  const fetchVisitors = async () => {
    try {
      const [visitorsResponse, hostsResponse, statsResponse] = await Promise.all([
        apiClient.get('/api/visitors', {
          params: {
            date: format(selectedDate, 'yyyy-MM-dd'),
            status: statusFilter !== 'all' ? statusFilter : undefined,
            search: searchTerm || undefined
          }
        }),
        apiClient.get('/api/hosts'),
        apiClient.get('/api/visitors/stats', {
          params: { date: format(selectedDate, 'yyyy-MM-dd') }
        })
      ]);

      setVisitors(visitorsResponse.data);
      setHosts(hostsResponse.data);
      setStats(statsResponse.data);
    } catch (error) {
      console.error('Error fetching visitor data:', error);
      toast.error('Failed to load visitor data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user && hasPermission('visitor:read')) {
      fetchVisitors();
    }
  }, [user, selectedDate, statusFilter, searchTerm]);

  // Filter and sort visitors
  const filteredVisitors = useMemo(() => {
    return visitors
      .filter(visitor => {
        const matchesSearch = searchTerm === '' || 
          `${visitor.firstName} ${visitor.lastName}`.toLowerCase().includes(searchTerm.toLowerCase()) ||
          visitor.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
          visitor.company.toLowerCase().includes(searchTerm.toLowerCase());
        
        const matchesStatus = statusFilter === 'all' || visitor.status === statusFilter;
        
        return matchesSearch && matchesStatus;
      })
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }, [visitors, searchTerm, statusFilter]);

  // Pre-registration form component
  const PreRegistrationForm = () => {
    const [formData, setFormData] = useState({
      firstName: '',
      lastName: '',
      email: '',
      phone: '',
      company: '',
      purpose: '',
      hostId: '',
      expectedArrival: '',
      expectedDeparture: '',
      accessRestrictions: [] as string[],
      emergencyContact: {
        name: '',
        phone: '',
        relationship: ''
      },
      vehicleInfo: {
        make: '',
        model: '',
        licensePlate: ''
      }
    });

    const handleSubmit = async (e: React.FormEvent) => {
      e.preventDefault();
      try {
        await apiClient.post('/api/visitors/pre-register', formData);
        toast.success('Visitor pre-registered successfully');
        setShowPreRegistration(false);
        fetchVisitors();
        
        // Reset form
        setFormData({
          firstName: '',
          lastName: '',
          email: '',
          phone: '',
          company: '',
          purpose: '',
          hostId: '',
          expectedArrival: '',
          expectedDeparture: '',
          accessRestrictions: [],
          emergencyContact: { name: '', phone: '', relationship: '' },
          vehicleInfo: { make: '', model: '', licensePlate: '' }
        });
      } catch (error) {
        console.error('Error pre-registering visitor:', error);
        toast.error('Failed to pre-register visitor');
      }
    };

    return (
      <Dialog open={showPreRegistration} onOpenChange={setShowPreRegistration}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Pre-Register Visitor</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="firstName">First Name *</Label>
                <Input
                  id="firstName"
                  value={formData.firstName}
                  onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
                  required
                />
              </div>
              <div>
                <Label htmlFor="lastName">Last Name *</Label>
                <Input
                  id="lastName"
                  value={formData.lastName}
                  onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="email">Email *</Label>
                <Input
                  id="email"
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                />
              </div>
              <div>
                <Label htmlFor="phone">Phone</Label>
                <Input
                  id="phone"
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                />
              </div>
            </div>

            <div>
              <Label htmlFor="company">Company</Label>
              <Input
                id="company"
                value={formData.company}
                onChange={(e) => setFormData({ ...formData, company: e.target.value })}
              />
            </div>

            <div>
              <Label htmlFor="purpose">Purpose of Visit *</Label>
              <Textarea
                id="purpose"
                value={formData.purpose}
                onChange={(e) => setFormData({ ...formData, purpose: e.target.value })}
                required
              />
            </div>

            <div>
              <Label htmlFor="host">Host *</Label>
              <Select value={formData.hostId} onValueChange={(value) => setFormData({ ...formData, hostId: value })}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a host" />
                </SelectTrigger>
                <SelectContent>
                  {hosts.map((host) => (
                    <SelectItem key={host.id} value={host.id}>
                      {host.name} - {host.department}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="expectedArrival">Expected Arrival *</Label>
                <Input
                  id="expectedArrival"
                  type="datetime-local"
                  value={formData.expectedArrival}
                  onChange={(e) => setFormData({ ...formData, expectedArrival: e.target.value })}
                  required
                />
              </div>
              <div>
                <Label htmlFor="expectedDeparture">Expected Departure *</Label>
                <Input
                  id="expectedDeparture"
                  type="datetime-local"
                  value={formData.expectedDeparture}
                  onChange={(e) => setFormData({ ...formData, expectedDeparture: e.target.value })}
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Emergency Contact</Label>
              <div className="grid grid-cols-3 gap-2">
                <Input
                  placeholder="Name"
                  value={formData.emergencyContact.name}
                  onChange={(e) => setFormData({
                    ...formData,
                    emergencyContact: { ...formData.emergencyContact, name: e.target.value }
                  })}
                />
                <Input
                  placeholder="Phone"
                  value={formData.emergencyContact.phone}
                  onChange={(e) => setFormData({
                    ...formData,
                    emergencyContact: { ...formData.emergencyContact, phone: e.target.value }
                  })}
                />
                <Input
                  placeholder="Relationship"
                  value={formData.emergencyContact.relationship}
                  onChange={(e) => setFormData({
                    ...formData,
                    emergencyContact: { ...formData.emergencyContact, relationship: e.target.value }
                  })}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>Vehicle Information</Label>
              <div className="grid grid-cols-3 gap-2">
                <Input
                  placeholder="Make"
                  value={formData.vehicleInfo.make}
                  onChange={(e) => setFormData({
                    ...formData,
                    vehicleInfo: { ...formData.vehicleInfo, make: e.target.value }
                  })}
                />
                <Input
                  placeholder="Model"
                  value={formData.vehicleInfo.model}
                  onChange={(e) => setFormData({
                    ...formData,
                    vehicleInfo: { ...formData.vehicleInfo, model: e.target.value }
                  })}
                />
                <Input
                  placeholder="License Plate"
                  value={formData.vehicleInfo.licensePlate}
                  onChange={(e) => setFormData({
                    ...formData,
                    vehicleInfo: { ...formData.vehicleInfo, licensePlate: e.target.value }
                  })}
                />
              </div>
            </div>

            <div className="flex justify-end space-x-2">
              <Button type="button" variant="outline" onClick={() => setShowPreRegistration(false)}>
                Cancel
              </Button>
              <Button type="submit">Pre-Register Visitor</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    );
  };

  // Check-in component
  const CheckInForm = () => {
    const [searchEmail, setSearchEmail] = useState('');
    const [foundVisitor, setFoundVisitor] = useState<Visitor | null>(null);
    const [photo, setPhoto] = useState<string>('');
    const [watchlistChecked, setWatchlistChecked] = useState(false);

    const searchVisitor = async () => {
      try {
        const response = await apiClient.get(`/api/visitors/search?email=${searchEmail}`);
        setFoundVisitor(response.data);
        
        // Perform watchlist check
        const watchlistResponse = await apiClient.post('/api/visitors/watchlist-check', {
          firstName: response.data.firstName,
          lastName: response.data.lastName,
          email: response.data.email
        });
        
        setWatchlistChecked(true);
        if (watchlistResponse.data.flagged) {
          toast.warning(`Visitor flagged on watchlist: ${watchlistResponse.data.reason}`);
        }
      } catch (error) {
        console.error('Error searching visitor:', error);
        toast.error('Visitor not found');
        setFoundVisitor(null);
      }
    };

    const handleCheckIn = async () => {
      if (!foundVisitor) return;

      try {
        await apiClient.post(`/api/visitors/${foundVisitor.id}/check-in`, {
          photo,
          actualArrival: new Date().toISOString()
        });
        
        toast.success('Visitor checked in successfully');
        setShowCheckIn(false);
        fetchVisitors();
        
        // Send host notification
        await apiClient.post('/api/notifications/host', {
          hostId: foundVisitor.hostId,
          visitorName: `${foundVisitor.firstName} ${foundVisitor.lastName}`,
          message: 'Your visitor has arrived and checked in'
        });
        
        // Reset form
        setSearchEmail('');
        setFoundVisitor(null);
        setPhoto('');
        setWatchlistChecked(false);
      } catch (error) {
        console.error('Error checking in visitor:', error);
        toast.error('Failed to check in visitor');
      }
    };

    return (
      <Dialog open={showCheckIn} onOpenChange={setShowCheckIn}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Visitor Check-In</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="searchEmail">Search by Email</Label>
              <div className="flex space-x-2">
                <Input
                  id="searchEmail"
                  type="email"
                  value={searchEmail}
                  onChange={(e) => setSearchEmail(e.target.value)}
                  placeholder="visitor@example.com"
                />
                <Button onClick={searchVisitor}>
                  <Search className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {foundVisitor && (
              <Card>
                <CardContent className="pt-4">
                  <div className="space-y-2">
                    <h3 className="font-semibold">
                      {foundVisitor.firstName} {foundVisitor.lastName}
                    </h3>
                    <p className="text-sm text-gray-600">{foundVisitor.company}</p>
                    <p className="text-sm">{foundVisitor.purpose}</p>
                    <p className="text-sm">Host: {foundVisitor.hostName}</p>
                    
                    {foundVisitor.watchlistStatus === 'flagged' && (
                      <Alert className="border-red-200 bg-red-50">
                        <AlertTriangle className="h-4 w-4 text-red-600" />
                        <AlertDescription className="text-red-800">
                          This visitor is flagged on the security watchlist
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}

            {foundVisitor && (
              <div>
                <Label htmlFor="photo">Take Photo</Label>
                <div className="flex items-center space-x-2">
                  <Button type="button" variant="outline" className="flex-1">
                    <Camera className="h-4 w-4 mr-2" />
                    Capture Photo
                  </Button>
                  {photo && <CheckCircle className="h-5 w-5 text-green-600" />}
                </div>
              </div>
            )}

            <div className="flex justify-end space-x-2">
              <Button type="button" variant="outline" onClick={() => setShowCheckIn(false)}>
                Cancel
              </Button>
              <Button 
                onClick={handleCheckIn} 
                disabled={!foundVisitor || !watchlistChecked}
              >
                Check In
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    );
  };

  // Badge printing component
  const BadgePrintDialog = () => {
    const handlePrintBadge = async () => {
      if (!selectedVisitor) return;

      try {
        await apiClient.post(`/api/visitors/${selectedVisitor.id}/print-badge`);
        toast.success('Badge printed successfully');
        setShowBadgePrint(false);
      } catch (error) {
        console.error('Error printing badge:', error);
        toast.error('Failed to print badge');
      }
    };

    return (
      <Dialog open={showBadgePrint} onOpenChange={setShowBadgePrint}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Print Visitor Badge</DialogTitle>
          </DialogHeader>
          {selectedVisitor && (
            <div className="space-y-4">
              <Card>
                <CardContent className="pt-4">
                  <div className="text-center space-y-2">
                    <div className="w-20 h-20 bg-gray-200 rounded-full mx-auto flex items-center justify-center">
                      {selectedVisitor.photo ? (
                        <img 
                          src={selectedVisitor.photo} 
                          alt="Visitor" 
                          className="w-full h-full rounded-full object-cover"
                        />
                      ) : (
                        <Users className="h-8 w-8 text-gray-400" />
                      )}
                    </div>
                    <h3 className="font-semibold">
                      {selectedVisitor.firstName} {selectedVisitor.lastName}
                    </h3>
                    <p className="text-sm text-gray-600">{selectedVisitor.company}</p>
                    <p className="text-sm">Host: {selectedVisitor.hostName}</p>
                    <div className="flex justify-center">
                      <QrCode className="h-16 w-16" />
                    </div>
                    {selectedVisitor.accessRestrictions.length > 0 && (
                      <div className="text-xs text-red-600">
                        Restricted Areas: {selectedVisitor.accessRestrictions.join(', ')}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
              
              <div className="flex justify-end space-x-2">
                <Button type="button" variant="outline" onClick={() => setShowBadgePrint(false)}>
                  Cancel
                </Button>
                <Button onClick={handlePrintBadge}>
                  <Printer className="h-4 w-4 mr-2" />
                  Print Badge
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    );
  };

  // Visitor actions
  const handleCheckOut = async (visitor: Visitor) => {
    try {
      await apiClient.post(`/api/visitors/${visitor.id}/check-out`, {
        actualDeparture: new Date().toISOString()
      });
      toast.success('Visitor checked out successfully');
      fetchVisitors();
    } catch (error) {
      console.error('Error checking out visitor:', error);
      toast.error('Failed to check out visitor');
    }
  };

  const handleEvacuate = async (visitor: Visitor) => {
    try {
      await apiClient.post(`/api/visitors/${visitor.id}/evacuate`);
      toast.success('Visitor marked as evacuated');
      fetchVisitors();
    } catch (error) {
      console.error('Error evacuating visitor:', error);
      toast.error('Failed to evacuate visitor');
    }
  };

  const exportVisitorData = async () => {
    try {
      const response = await apiClient.get('/api/visitors/export', {
        params: {
          date: format(selectedDate, 'yyyy-MM-dd'),
          format: 'csv'
        },
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `visitors-${format(selectedDate, 'yyyy-MM-dd')}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error exporting visitor data:', error);
      toast.error('Failed to export visitor data');
    }
  };

  if (!user || !hasPermission('visitor:read')) {
    return (
      <div className="flex items-center justify-center h-64">
        <Alert>
          <Shield className="h-4 w-4" />
          <AlertDescription>
            You don't have permission to access visitor management.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Visitor Management</h1>
          <p className="text-gray-600">Manage visitor registration, check-in, and tracking</p>
        </div>
        <div className="flex items-center space-x-2">
          <Switch
            checked={isKioskMode}
            onCheckedChange={setIsKioskMode}
          />
          <Label>Kiosk Mode</Label>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Users className="h-5 w-5 text-blue-600" />
              <div>
                <p className="text-sm text-gray-600">Total Visitors</p>
                <p className="text-2xl font-bold">{stats.total}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <UserCheck className="h-5 w-5 text-green-600" />
              <div>
                <p className="text-sm text-gray-600">Checked In</p>
                <p className="text-2xl font-bold">{stats.checkedIn}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <CalendarIcon className="h-5 w-5 text-blue-600" />
              <div>
                <p className="text-sm text-gray-600">Pre-Registered</p>
                <p className="text-2xl font-bold">{stats.preRegistered}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <Clock className="h-5 w-5 text-orange-600" />
              <div>
                <p className="text-sm text-gray-600">Overstay</p>
                <p className="text-2xl font-bold">{stats.overstay}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              <div>
                <p className="text-sm text-gray-600">Evacuated</p>
                <p className="text-2xl font-bold">{stats.evacuated}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Controls */}
      <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="flex items-center space-x-2">
            <Search className="h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search visitors..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-64"
            />
          </div>
          
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              <SelectItem value="pre-registered">Pre-Registered</SelectItem>
              <SelectItem value="checked-in">Checked In</SelectItem>
              <SelectItem value="checked-out">Checked Out</SelectItem>
              <SelectItem value="overstay">Overstay</SelectItem>
              <SelectItem value="evacuated">Evacuated</SelectItem>
            </SelectContent>
          </Select>
          
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="outline">
                <CalendarIcon className="h-4 w-4 mr-2" />
                {format(selectedDate, 'MMM dd, yyyy')}
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-auto p-0">
              <Calendar
                mode="single"
                selected={selectedDate}
                onSelect={(date) => date && setSelectedDate(date)}
                initialFocus
              />
            </PopoverContent>
          </Popover>
        </div>

        <div className="flex space-x-2">
          {hasPermission('visitor:create') && (
            <Button onClick={() => setShowPreRegistration(true)}>
              <Users className="h-4 w-4 mr-2" />
              Pre-Register
            </Button>
          )}
          
          {hasPermission('visitor:checkin') && (
            <Button onClick={() => setShowCheckIn(true)}>
              <UserCheck className="h-4 w-4 mr-2" />
              Check In
            </Button>
          )}
          
          <Button variant="outline" onClick={exportVisitorData}>
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          
          <Button variant="outline" onClick={fetchVisitors}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Visitor List */}
      <Card>
        <CardHeader>
          <CardTitle>Visitors ({filteredVisitors.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {filteredVisitors.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                No visitors found for the selected criteria
              </div>
            ) : (
              filteredVisitors.map((visitor) => (
                <div key={visitor.id} className="border rounded-lg p-4 hover:bg-gray-50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="w-12 h-12 bg-gray-200 rounded-full flex items-center justify-center">
                        {visitor.photo ? (
                          <img 
                            src={visitor.photo} 
                            alt="Visitor" 
                            className="w-full h-full rounded-full object-cover"
                          />
                        ) : (
                          <Users className="h-6 w-6 text-gray-400" />
                        )}
                      </div>
                      
                      <div>
                        <h3 className="font-semibold">
                          {visitor.firstName} {visitor.lastName}
                        </h3>
                        <div className="flex items-center space-x-4 text-sm text-gray-600">
                          <span className="flex items-center">
                            <Building className="h-3 w-3 mr-1" />
                            {visitor.company}
                          </span>
                          <span className="flex items-center">
                            <Mail className="h-3 w-3 mr-1" />
                            {visitor.email}
                          </span>
                          <span className="flex items-center">
                            <Users className="h-3 w-3 mr-1" />
                            Host: {visitor.hostName}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 mt-1">{visitor.purpose}</p>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-4">
                      <div className="text-right text-sm">
                        <p className="text-gray-600">
                          Expected: {format(new Date(visitor.expectedArrival), 'MMM dd, HH:mm')}
                        </p>
                        {visitor.actualArrival && (
                          <p className="text-green-600">
                            Arrived: {format(new Date(visitor.actualArrival), 'MMM dd, HH:mm')}
                          </p>
                        )}
                        {visitor.actualDeparture && (
                          <p className="text-blue-600">
                            Departed: {format(new Date(visitor.actualDeparture), 'MMM dd, HH:mm')}
                          </p>
                        )}
                      </div>
                      
                      <div className="flex flex-col items-end space-y-2">
                        <Badge 
                          variant={
                            visitor.status === 'checked-in' ? 'default' :
                            visitor.status === 'pre-registered' ? 'secondary' :
                            visitor.status === 'checked-out' ? 'outline' :
                            visitor.status === 'overstay' ? 'destructive' :
                            'destructive'
                          }
                        >
                          {visitor.status.replace('-', ' ').toUpperCase()}
                        </Badge>
                        
                        {visitor.watchlistStatus === 'flagged' && (
                          <Badge variant="destructive">
                            <AlertTriangle className="h-3 w-3 mr-1" />
                            Watchlist
                          </Badge>
                        )}
                        
                        <div className="flex space-x-1">
                          {visitor.status === 'checked-in' && hasPermission('visitor:checkout') && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleCheckOut(visitor)}
                            >
                              <UserX className="h-3 w-3 mr-1" />
                              Check Out
                            </Button>
                          )}
                          
                          {(visitor.status === 'checked-in' || visitor.status === 'pre-registered') && hasPermission('visitor:badge') && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => {
                                setSelectedVisitor(visitor);
                                setShowBadgePrint(true);
                              }}
                            >
                              <Printer className="h-3 w-3 mr-1" />
                              Badge
                            </Button>
                          )}
                          
                          {visitor.status === 'checked-in' && hasPermission('visitor:evacuate') && (
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => handleEvacuate(visitor)}
                            >
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              Evacuate
                            </Button>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>

      {/* Dialogs */}
      <PreRegistrationForm />
      <CheckInForm />
      <BadgePrintDialog />
    </div>
  );
}