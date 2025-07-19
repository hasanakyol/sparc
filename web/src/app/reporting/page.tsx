'use client';

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Checkbox } from '@/components/ui/checkbox';
import { Textarea } from '@/components/ui/textarea';
import { 
  FileText, 
  Download, 
  Calendar as CalendarIcon, 
  Clock, 
  Share2, 
  Filter, 
  Search, 
  Plus, 
  Play, 
  Pause, 
  Trash2, 
  Edit, 
  Eye, 
  BarChart3, 
  PieChart, 
  TrendingUp,
  Shield,
  FileCheck,
  AlertTriangle,
  Settings,
  Users,
  Building,
  Activity
} from 'lucide-react';
import { format } from 'date-fns';
import { useAuth } from '@/hooks/useAuth';
import { useRealtime } from '@/hooks/useRealtime';
import { apiClient } from '@/lib/api-client';
import { cn } from '@/lib/utils';

interface Report {
  id: string;
  name: string;
  description: string;
  type: 'compliance' | 'audit' | 'analytics' | 'custom';
  template: string;
  status: 'draft' | 'scheduled' | 'running' | 'completed' | 'failed';
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  schedule?: {
    frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly';
    time: string;
    enabled: boolean;
  };
  parameters: Record<string, any>;
  lastRun?: string;
  nextRun?: string;
  progress?: number;
}

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  category: 'compliance' | 'security' | 'operations' | 'analytics';
  fields: Array<{
    name: string;
    type: 'text' | 'date' | 'select' | 'multiselect' | 'number';
    required: boolean;
    options?: string[];
  }>;
  complianceStandard?: 'SOX' | 'HIPAA' | 'PCI-DSS' | 'GDPR' | 'ISO27001';
}

const ReportingPage: React.FC = () => {
  const { user, hasPermission } = useAuth();
  const [reports, setReports] = useState<Report[]>([]);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showScheduleDialog, setShowScheduleDialog] = useState(false);
  const [reportProgress, setReportProgress] = useState<Record<string, number>>({});

  // Real-time updates for report generation progress
  useRealtime('report-progress', (data) => {
    setReportProgress(prev => ({
      ...prev,
      [data.reportId]: data.progress
    }));
  });

  useRealtime('report-completed', (data) => {
    setReports(prev => prev.map(report => 
      report.id === data.reportId 
        ? { ...report, status: 'completed', updatedAt: new Date().toISOString() }
        : report
    ));
    setReportProgress(prev => {
      const updated = { ...prev };
      delete updated[data.reportId];
      return updated;
    });
  });

  useEffect(() => {
    loadReports();
    loadTemplates();
  }, []);

  const loadReports = async () => {
    try {
      const response = await apiClient.get('/reports');
      setReports(response.data);
    } catch (error) {
      console.error('Failed to load reports:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const loadTemplates = async () => {
    try {
      const response = await apiClient.get('/reports/templates');
      setTemplates(response.data);
    } catch (error) {
      console.error('Failed to load templates:', error);
    }
  };

  const createReport = async (reportData: Partial<Report>) => {
    try {
      const response = await apiClient.post('/reports', reportData);
      setReports(prev => [...prev, response.data]);
      setShowCreateDialog(false);
    } catch (error) {
      console.error('Failed to create report:', error);
    }
  };

  const runReport = async (reportId: string) => {
    try {
      await apiClient.post(`/reports/${reportId}/run`);
      setReports(prev => prev.map(report => 
        report.id === reportId 
          ? { ...report, status: 'running', progress: 0 }
          : report
      ));
    } catch (error) {
      console.error('Failed to run report:', error);
    }
  };

  const scheduleReport = async (reportId: string, schedule: Report['schedule']) => {
    try {
      await apiClient.put(`/reports/${reportId}/schedule`, { schedule });
      setReports(prev => prev.map(report => 
        report.id === reportId 
          ? { ...report, schedule }
          : report
      ));
      setShowScheduleDialog(false);
    } catch (error) {
      console.error('Failed to schedule report:', error);
    }
  };

  const exportReport = async (reportId: string, format: 'pdf' | 'csv' | 'json') => {
    try {
      const response = await apiClient.get(`/reports/${reportId}/export?format=${format}`, {
        responseType: 'blob'
      });
      
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `report-${reportId}.${format}`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export report:', error);
    }
  };

  const deleteReport = async (reportId: string) => {
    try {
      await apiClient.delete(`/reports/${reportId}`);
      setReports(prev => prev.filter(report => report.id !== reportId));
    } catch (error) {
      console.error('Failed to delete report:', error);
    }
  };

  const filteredReports = reports.filter(report => {
    const matchesSearch = report.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         report.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = filterType === 'all' || report.type === filterType;
    const matchesStatus = filterStatus === 'all' || report.status === filterStatus;
    return matchesSearch && matchesType && matchesStatus;
  });

  const complianceTemplates = templates.filter(t => t.category === 'compliance');
  const securityTemplates = templates.filter(t => t.category === 'security');
  const operationsTemplates = templates.filter(t => t.category === 'operations');
  const analyticsTemplates = templates.filter(t => t.category === 'analytics');

  const getStatusColor = (status: Report['status']) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'running': return 'bg-blue-100 text-blue-800';
      case 'failed': return 'bg-red-100 text-red-800';
      case 'scheduled': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getTypeIcon = (type: Report['type']) => {
    switch (type) {
      case 'compliance': return <Shield className="h-4 w-4" />;
      case 'audit': return <FileCheck className="h-4 w-4" />;
      case 'analytics': return <BarChart3 className="h-4 w-4" />;
      default: return <FileText className="h-4 w-4" />;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Reporting & Analytics</h1>
          <p className="text-muted-foreground">
            Generate, schedule, and manage comprehensive reports and analytics
          </p>
        </div>
        {hasPermission('reports:create') && (
          <Button onClick={() => setShowCreateDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            Create Report
          </Button>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="reports">Reports</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
          <TabsTrigger value="audit">Audit Trail</TabsTrigger>
          <TabsTrigger value="scheduled">Scheduled</TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="space-y-6">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Reports</CardTitle>
                <FileText className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{reports.length}</div>
                <p className="text-xs text-muted-foreground">
                  +{reports.filter(r => new Date(r.createdAt) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).length} this week
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Running Reports</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{reports.filter(r => r.status === 'running').length}</div>
                <p className="text-xs text-muted-foreground">
                  Currently processing
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Scheduled Reports</CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{reports.filter(r => r.schedule?.enabled).length}</div>
                <p className="text-xs text-muted-foreground">
                  Automated reports
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Compliance Reports</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{reports.filter(r => r.type === 'compliance').length}</div>
                <p className="text-xs text-muted-foreground">
                  SOX, HIPAA, PCI-DSS
                </p>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Recent Reports</CardTitle>
                <CardDescription>Latest generated reports</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[300px]">
                  <div className="space-y-4">
                    {reports
                      .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
                      .slice(0, 10)
                      .map((report) => (
                        <div key={report.id} className="flex items-center justify-between p-3 border rounded-lg">
                          <div className="flex items-center space-x-3">
                            {getTypeIcon(report.type)}
                            <div>
                              <p className="font-medium">{report.name}</p>
                              <p className="text-sm text-muted-foreground">
                                {format(new Date(report.updatedAt), 'MMM dd, yyyy HH:mm')}
                              </p>
                            </div>
                          </div>
                          <Badge className={getStatusColor(report.status)}>
                            {report.status}
                          </Badge>
                        </div>
                      ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Report Generation Activity</CardTitle>
                <CardDescription>Reports generated over time</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[300px] flex items-center justify-center text-muted-foreground">
                  <div className="text-center">
                    <TrendingUp className="h-12 w-12 mx-auto mb-4" />
                    <p>Chart visualization would be rendered here</p>
                    <p className="text-sm">Using existing chart components</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="reports" className="space-y-6">
          <div className="flex items-center space-x-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search reports..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8"
                />
              </div>
            </div>
            <Select value={filterType} onValueChange={setFilterType}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="compliance">Compliance</SelectItem>
                <SelectItem value="audit">Audit</SelectItem>
                <SelectItem value="analytics">Analytics</SelectItem>
                <SelectItem value="custom">Custom</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="draft">Draft</SelectItem>
                <SelectItem value="scheduled">Scheduled</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-4">
            {filteredReports.map((report) => (
              <Card key={report.id}>
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {getTypeIcon(report.type)}
                      <div>
                        <h3 className="font-semibold">{report.name}</h3>
                        <p className="text-sm text-muted-foreground">{report.description}</p>
                        <div className="flex items-center space-x-4 mt-2">
                          <Badge className={getStatusColor(report.status)}>
                            {report.status}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            Created {format(new Date(report.createdAt), 'MMM dd, yyyy')}
                          </span>
                          {report.schedule?.enabled && (
                            <Badge variant="outline">
                              <Clock className="h-3 w-3 mr-1" />
                              Scheduled
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {report.status === 'running' && reportProgress[report.id] !== undefined && (
                        <div className="flex items-center space-x-2">
                          <Progress value={reportProgress[report.id]} className="w-20" />
                          <span className="text-sm text-muted-foreground">
                            {reportProgress[report.id]}%
                          </span>
                        </div>
                      )}
                      
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <Settings className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => setSelectedReport(report)}>
                            <Eye className="h-4 w-4 mr-2" />
                            View
                          </DropdownMenuItem>
                          {hasPermission('reports:run') && report.status !== 'running' && (
                            <DropdownMenuItem onClick={() => runReport(report.id)}>
                              <Play className="h-4 w-4 mr-2" />
                              Run Now
                            </DropdownMenuItem>
                          )}
                          {hasPermission('reports:schedule') && (
                            <DropdownMenuItem onClick={() => {
                              setSelectedReport(report);
                              setShowScheduleDialog(true);
                            }}>
                              <Clock className="h-4 w-4 mr-2" />
                              Schedule
                            </DropdownMenuItem>
                          )}
                          {report.status === 'completed' && (
                            <>
                              <DropdownMenuItem onClick={() => exportReport(report.id, 'pdf')}>
                                <Download className="h-4 w-4 mr-2" />
                                Export PDF
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => exportReport(report.id, 'csv')}>
                                <Download className="h-4 w-4 mr-2" />
                                Export CSV
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => exportReport(report.id, 'json')}>
                                <Download className="h-4 w-4 mr-2" />
                                Export JSON
                              </DropdownMenuItem>
                            </>
                          )}
                          <DropdownMenuItem>
                            <Share2 className="h-4 w-4 mr-2" />
                            Share
                          </DropdownMenuItem>
                          {hasPermission('reports:delete') && (
                            <DropdownMenuItem 
                              onClick={() => deleteReport(report.id)}
                              className="text-red-600"
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              Delete
                            </DropdownMenuItem>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="templates" className="space-y-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Shield className="h-5 w-5 mr-2" />
                  Compliance Templates
                </CardTitle>
                <CardDescription>
                  Pre-built templates for regulatory compliance reporting
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {complianceTemplates.map((template) => (
                    <Card key={template.id} className="cursor-pointer hover:shadow-md transition-shadow">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-semibold">{template.name}</h4>
                          {template.complianceStandard && (
                            <Badge variant="secondary">{template.complianceStandard}</Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground mb-4">{template.description}</p>
                        <Button size="sm" className="w-full">
                          Use Template
                        </Button>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <BarChart3 className="h-5 w-5 mr-2" />
                  Analytics Templates
                </CardTitle>
                <CardDescription>
                  Data analytics and performance reporting templates
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {analyticsTemplates.map((template) => (
                    <Card key={template.id} className="cursor-pointer hover:shadow-md transition-shadow">
                      <CardContent className="p-4">
                        <h4 className="font-semibold mb-2">{template.name}</h4>
                        <p className="text-sm text-muted-foreground mb-4">{template.description}</p>
                        <Button size="sm" className="w-full">
                          Use Template
                        </Button>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-6">
          <div className="grid gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Compliance Dashboard</CardTitle>
                <CardDescription>
                  Monitor compliance status across all regulatory frameworks
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                  {['SOX', 'HIPAA', 'PCI-DSS', 'GDPR'].map((standard) => (
                    <Card key={standard}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-semibold">{standard}</h4>
                          <Badge className="bg-green-100 text-green-800">Compliant</Badge>
                        </div>
                        <Progress value={95} className="mb-2" />
                        <p className="text-sm text-muted-foreground">95% compliance score</p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Recent Compliance Reports</CardTitle>
                <CardDescription>
                  Latest compliance assessments and reports
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {reports
                    .filter(r => r.type === 'compliance')
                    .slice(0, 5)
                    .map((report) => (
                      <div key={report.id} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          <Shield className="h-4 w-4" />
                          <div>
                            <p className="font-medium">{report.name}</p>
                            <p className="text-sm text-muted-foreground">
                              {format(new Date(report.updatedAt), 'MMM dd, yyyy HH:mm')}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getStatusColor(report.status)}>
                            {report.status}
                          </Badge>
                          {report.status === 'completed' && (
                            <Button size="sm" variant="outline">
                              <Download className="h-4 w-4 mr-2" />
                              Download
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="audit" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Audit Trail</CardTitle>
              <CardDescription>
                Comprehensive audit trail of all system activities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-4 mb-6">
                <div className="flex-1">
                  <div className="relative">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search audit logs..."
                      className="pl-8"
                    />
                  </div>
                </div>
                <Popover>
                  <PopoverTrigger asChild>
                    <Button variant="outline">
                      <CalendarIcon className="h-4 w-4 mr-2" />
                      Date Range
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0" align="start">
                    <Calendar mode="range" />
                  </PopoverContent>
                </Popover>
                <Select>
                  <SelectTrigger className="w-[180px]">
                    <SelectValue placeholder="Filter by action" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Actions</SelectItem>
                    <SelectItem value="create">Create</SelectItem>
                    <SelectItem value="update">Update</SelectItem>
                    <SelectItem value="delete">Delete</SelectItem>
                    <SelectItem value="access">Access</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                {[...Array(10)].map((_, i) => (
                  <div key={i} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center space-x-3">
                      <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                      <div>
                        <p className="font-medium">User accessed compliance report</p>
                        <p className="text-sm text-muted-foreground">
                          john.doe@company.com • {format(new Date(), 'MMM dd, yyyy HH:mm')}
                        </p>
                      </div>
                    </div>
                    <Badge variant="outline">Access</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scheduled" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Scheduled Reports</CardTitle>
              <CardDescription>
                Manage automated report generation schedules
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {reports
                  .filter(r => r.schedule?.enabled)
                  .map((report) => (
                    <Card key={report.id}>
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-4">
                            <Clock className="h-5 w-5 text-muted-foreground" />
                            <div>
                              <h4 className="font-semibold">{report.name}</h4>
                              <p className="text-sm text-muted-foreground">
                                Runs {report.schedule?.frequency} at {report.schedule?.time}
                              </p>
                              {report.nextRun && (
                                <p className="text-sm text-muted-foreground">
                                  Next run: {format(new Date(report.nextRun), 'MMM dd, yyyy HH:mm')}
                                </p>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <Badge className="bg-green-100 text-green-800">Active</Badge>
                            <Button size="sm" variant="outline">
                              <Edit className="h-4 w-4 mr-2" />
                              Edit
                            </Button>
                            <Button size="sm" variant="outline">
                              <Pause className="h-4 w-4 mr-2" />
                              Pause
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Create Report Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create New Report</DialogTitle>
            <DialogDescription>
              Build a custom report or use a pre-built template
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <Label htmlFor="name">Report Name</Label>
                <Input id="name" placeholder="Enter report name" />
              </div>
              <div>
                <Label htmlFor="type">Report Type</Label>
                <Select>
                  <SelectTrigger>
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="compliance">Compliance</SelectItem>
                    <SelectItem value="audit">Audit</SelectItem>
                    <SelectItem value="analytics">Analytics</SelectItem>
                    <SelectItem value="custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <Label htmlFor="description">Description</Label>
              <Textarea id="description" placeholder="Enter report description" />
            </div>
            <div>
              <Label htmlFor="template">Template</Label>
              <Select>
                <SelectTrigger>
                  <SelectValue placeholder="Select template (optional)" />
                </SelectTrigger>
                <SelectContent>
                  {templates.map((template) => (
                    <SelectItem key={template.id} value={template.id}>
                      {template.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
                Cancel
              </Button>
              <Button onClick={() => createReport({
                name: 'New Report',
                description: 'Custom report',
                type: 'custom',
                template: 'default',
                status: 'draft',
                parameters: {}
              })}>
                Create Report
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Schedule Report Dialog */}
      <Dialog open={showScheduleDialog} onOpenChange={setShowScheduleDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Schedule Report</DialogTitle>
            <DialogDescription>
              Configure automated report generation
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="frequency">Frequency</Label>
              <Select>
                <SelectTrigger>
                  <SelectValue placeholder="Select frequency" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                  <SelectItem value="monthly">Monthly</SelectItem>
                  <SelectItem value="quarterly">Quarterly</SelectItem>
                  <SelectItem value="yearly">Yearly</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="time">Time</Label>
              <Input id="time" type="time" />
            </div>
            <div className="flex items-center space-x-2">
              <Checkbox id="enabled" />
              <Label htmlFor="enabled">Enable schedule</Label>
            </div>
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setShowScheduleDialog(false)}>
                Cancel
              </Button>
              <Button onClick={() => {
                if (selectedReport) {
                  scheduleReport(selectedReport.id, {
                    frequency: 'daily',
                    time: '09:00',
                    enabled: true
                  });
                }
              }}>
                Save Schedule
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default ReportingPage;