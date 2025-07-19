'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Calendar } from '@/components/ui/calendar'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import { 
  CalendarIcon, 
  ClockIcon, 
  UserIcon, 
  WrenchIcon, 
  AlertTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  PlayCircleIcon,
  PauseCircleIcon,
  ToolIcon,
  TruckIcon,
  DollarSignIcon,
  BarChart3Icon,
  SearchIcon,
  PlusIcon,
  FilterIcon,
  DownloadIcon,
  BellIcon,
  MapPinIcon,
  ClipboardListIcon,
  SettingsIcon,
  PhoneIcon
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useRealtime } from '@/hooks/useRealtime'
import { apiClient } from '@/lib/api-client'
import { toast } from '@/hooks/use-toast'

interface WorkOrder {
  id: string
  title: string
  description: string
  priority: 'low' | 'medium' | 'high' | 'critical'
  status: 'pending' | 'assigned' | 'in_progress' | 'completed' | 'cancelled'
  type: 'preventive' | 'corrective' | 'emergency' | 'inspection'
  assignedTo?: string
  assignedTechnician?: string
  deviceId?: string
  deviceName?: string
  location: string
  scheduledDate: Date
  completedDate?: Date
  estimatedHours: number
  actualHours?: number
  parts: WorkOrderPart[]
  totalCost: number
  createdAt: Date
  updatedAt: Date
}

interface WorkOrderPart {
  id: string
  partNumber: string
  partName: string
  quantity: number
  unitCost: number
  totalCost: number
  supplier?: string
  warrantyExpiry?: Date
}

interface MaintenanceSchedule {
  id: string
  name: string
  description: string
  deviceId: string
  deviceName: string
  frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly'
  interval: number
  nextDue: Date
  lastCompleted?: Date
  estimatedHours: number
  requiredParts: string[]
  instructions: string
  isActive: boolean
}

interface Technician {
  id: string
  name: string
  email: string
  phone: string
  skills: string[]
  availability: 'available' | 'busy' | 'offline'
  currentWorkOrders: number
  location?: string
}

interface DeviceHealth {
  deviceId: string
  deviceName: string
  healthScore: number
  lastMaintenance: Date
  nextMaintenance: Date
  alerts: string[]
  predictiveIssues: string[]
}

export default function MaintenancePage() {
  const { user, hasPermission } = useAuth()
  const [workOrders, setWorkOrders] = useState<WorkOrder[]>([])
  const [schedules, setSchedules] = useState<MaintenanceSchedule[]>([])
  const [technicians, setTechnicians] = useState<Technician[]>([])
  const [deviceHealth, setDeviceHealth] = useState<DeviceHealth[]>([])
  const [selectedDate, setSelectedDate] = useState<Date>(new Date())
  const [activeTab, setActiveTab] = useState('dashboard')
  const [isCreateWorkOrderOpen, setIsCreateWorkOrderOpen] = useState(false)
  const [isCreateScheduleOpen, setIsCreateScheduleOpen] = useState(false)
  const [selectedWorkOrder, setSelectedWorkOrder] = useState<WorkOrder | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [priorityFilter, setPriorityFilter] = useState('all')
  const [loading, setLoading] = useState(true)

  // Real-time updates for work order status changes
  useRealtime('maintenance_updates', (data) => {
    if (data.type === 'work_order_updated') {
      setWorkOrders(prev => prev.map(wo => 
        wo.id === data.workOrderId ? { ...wo, ...data.updates } : wo
      ))
      toast({
        title: 'Work Order Updated',
        description: `Work order ${data.workOrderId} has been updated`,
      })
    }
  })

  useEffect(() => {
    loadMaintenanceData()
  }, [])

  const loadMaintenanceData = async () => {
    try {
      setLoading(true)
      const [workOrdersRes, schedulesRes, techniciansRes, deviceHealthRes] = await Promise.all([
        apiClient.get('/maintenance/work-orders'),
        apiClient.get('/maintenance/schedules'),
        apiClient.get('/maintenance/technicians'),
        apiClient.get('/devices/health')
      ])

      setWorkOrders(workOrdersRes.data)
      setSchedules(schedulesRes.data)
      setTechnicians(techniciansRes.data)
      setDeviceHealth(deviceHealthRes.data)
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load maintenance data',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  const createWorkOrder = async (workOrderData: Partial<WorkOrder>) => {
    try {
      const response = await apiClient.post('/maintenance/work-orders', workOrderData)
      setWorkOrders(prev => [...prev, response.data])
      setIsCreateWorkOrderOpen(false)
      toast({
        title: 'Success',
        description: 'Work order created successfully'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to create work order',
        variant: 'destructive'
      })
    }
  }

  const updateWorkOrderStatus = async (workOrderId: string, status: WorkOrder['status']) => {
    try {
      await apiClient.patch(`/maintenance/work-orders/${workOrderId}`, { status })
      setWorkOrders(prev => prev.map(wo => 
        wo.id === workOrderId ? { ...wo, status } : wo
      ))
      toast({
        title: 'Success',
        description: 'Work order status updated'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update work order status',
        variant: 'destructive'
      })
    }
  }

  const assignTechnician = async (workOrderId: string, technicianId: string) => {
    try {
      await apiClient.patch(`/maintenance/work-orders/${workOrderId}/assign`, { technicianId })
      const technician = technicians.find(t => t.id === technicianId)
      setWorkOrders(prev => prev.map(wo => 
        wo.id === workOrderId ? { 
          ...wo, 
          assignedTo: technicianId,
          assignedTechnician: technician?.name 
        } : wo
      ))
      toast({
        title: 'Success',
        description: 'Technician assigned successfully'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to assign technician',
        variant: 'destructive'
      })
    }
  }

  const createMaintenanceSchedule = async (scheduleData: Partial<MaintenanceSchedule>) => {
    try {
      const response = await apiClient.post('/maintenance/schedules', scheduleData)
      setSchedules(prev => [...prev, response.data])
      setIsCreateScheduleOpen(false)
      toast({
        title: 'Success',
        description: 'Maintenance schedule created successfully'
      })
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to create maintenance schedule',
        variant: 'destructive'
      })
    }
  }

  const filteredWorkOrders = workOrders.filter(wo => {
    const matchesSearch = wo.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         wo.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         wo.location.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'all' || wo.status === statusFilter
    const matchesPriority = priorityFilter === 'all' || wo.priority === priorityFilter
    return matchesSearch && matchesStatus && matchesPriority
  })

  const getStatusColor = (status: WorkOrder['status']) => {
    switch (status) {
      case 'pending': return 'bg-yellow-100 text-yellow-800'
      case 'assigned': return 'bg-blue-100 text-blue-800'
      case 'in_progress': return 'bg-orange-100 text-orange-800'
      case 'completed': return 'bg-green-100 text-green-800'
      case 'cancelled': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getPriorityColor = (priority: WorkOrder['priority']) => {
    switch (priority) {
      case 'low': return 'bg-green-100 text-green-800'
      case 'medium': return 'bg-yellow-100 text-yellow-800'
      case 'high': return 'bg-orange-100 text-orange-800'
      case 'critical': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getStatusIcon = (status: WorkOrder['status']) => {
    switch (status) {
      case 'pending': return <ClockIcon className="h-4 w-4" />
      case 'assigned': return <UserIcon className="h-4 w-4" />
      case 'in_progress': return <PlayCircleIcon className="h-4 w-4" />
      case 'completed': return <CheckCircleIcon className="h-4 w-4" />
      case 'cancelled': return <XCircleIcon className="h-4 w-4" />
      default: return <ClockIcon className="h-4 w-4" />
    }
  }

  const dashboardStats = {
    totalWorkOrders: workOrders.length,
    pendingWorkOrders: workOrders.filter(wo => wo.status === 'pending').length,
    inProgressWorkOrders: workOrders.filter(wo => wo.status === 'in_progress').length,
    completedThisMonth: workOrders.filter(wo => 
      wo.status === 'completed' && 
      wo.completedDate && 
      new Date(wo.completedDate).getMonth() === new Date().getMonth()
    ).length,
    totalCostThisMonth: workOrders
      .filter(wo => wo.completedDate && new Date(wo.completedDate).getMonth() === new Date().getMonth())
      .reduce((sum, wo) => sum + wo.totalCost, 0),
    averageCompletionTime: workOrders
      .filter(wo => wo.status === 'completed' && wo.actualHours)
      .reduce((sum, wo) => sum + (wo.actualHours || 0), 0) / 
      workOrders.filter(wo => wo.status === 'completed' && wo.actualHours).length || 0,
    availableTechnicians: technicians.filter(t => t.availability === 'available').length,
    criticalDevices: deviceHealth.filter(d => d.healthScore < 30).length
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-gray-900"></div>
      </div>
    )
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Maintenance Management</h1>
          <p className="text-muted-foreground">
            Manage work orders, schedules, and maintenance operations
          </p>
        </div>
        <div className="flex gap-2">
          {hasPermission('maintenance:create') && (
            <>
              <Dialog open={isCreateWorkOrderOpen} onOpenChange={setIsCreateWorkOrderOpen}>
                <DialogTrigger asChild>
                  <Button>
                    <PlusIcon className="h-4 w-4 mr-2" />
                    Create Work Order
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>Create New Work Order</DialogTitle>
                    <DialogDescription>
                      Create a new maintenance work order
                    </DialogDescription>
                  </DialogHeader>
                  <WorkOrderForm onSubmit={createWorkOrder} technicians={technicians} />
                </DialogContent>
              </Dialog>
              
              <Dialog open={isCreateScheduleOpen} onOpenChange={setIsCreateScheduleOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline">
                    <CalendarIcon className="h-4 w-4 mr-2" />
                    Schedule Maintenance
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>Create Maintenance Schedule</DialogTitle>
                    <DialogDescription>
                      Set up recurring maintenance schedule
                    </DialogDescription>
                  </DialogHeader>
                  <MaintenanceScheduleForm onSubmit={createMaintenanceSchedule} />
                </DialogContent>
              </Dialog>
            </>
          )}
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="work-orders">Work Orders</TabsTrigger>
          <TabsTrigger value="scheduling">Scheduling</TabsTrigger>
          <TabsTrigger value="technicians">Technicians</TabsTrigger>
          <TabsTrigger value="inventory">Inventory</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="devices">Device Health</TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Work Orders</CardTitle>
                <ClipboardListIcon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{dashboardStats.totalWorkOrders}</div>
                <p className="text-xs text-muted-foreground">
                  {dashboardStats.pendingWorkOrders} pending
                </p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">In Progress</CardTitle>
                <PlayCircleIcon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{dashboardStats.inProgressWorkOrders}</div>
                <p className="text-xs text-muted-foreground">
                  Active work orders
                </p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Monthly Cost</CardTitle>
                <DollarSignIcon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  ${dashboardStats.totalCostThisMonth.toLocaleString()}
                </div>
                <p className="text-xs text-muted-foreground">
                  {dashboardStats.completedThisMonth} completed this month
                </p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Available Technicians</CardTitle>
                <UserIcon className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{dashboardStats.availableTechnicians}</div>
                <p className="text-xs text-muted-foreground">
                  of {technicians.length} total
                </p>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Recent Work Orders</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {workOrders.slice(0, 5).map((workOrder) => (
                    <div key={workOrder.id} className="flex items-center space-x-4">
                      <div className="flex-shrink-0">
                        {getStatusIcon(workOrder.status)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{workOrder.title}</p>
                        <p className="text-sm text-muted-foreground">{workOrder.location}</p>
                      </div>
                      <Badge className={getPriorityColor(workOrder.priority)}>
                        {workOrder.priority}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Device Health Alerts</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {deviceHealth.filter(d => d.healthScore < 50).slice(0, 5).map((device) => (
                    <div key={device.deviceId} className="flex items-center space-x-4">
                      <AlertTriangleIcon className="h-4 w-4 text-orange-500" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{device.deviceName}</p>
                        <div className="flex items-center space-x-2">
                          <Progress value={device.healthScore} className="w-20" />
                          <span className="text-xs text-muted-foreground">
                            {device.healthScore}%
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="work-orders" className="space-y-4">
          <div className="flex justify-between items-center">
            <div className="flex space-x-2">
              <div className="relative">
                <SearchIcon className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search work orders..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8 w-64"
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="assigned">Assigned</SelectItem>
                  <SelectItem value="in_progress">In Progress</SelectItem>
                  <SelectItem value="completed">Completed</SelectItem>
                  <SelectItem value="cancelled">Cancelled</SelectItem>
                </SelectContent>
              </Select>
              <Select value={priorityFilter} onValueChange={setPriorityFilter}>
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="Priority" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Priority</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button variant="outline">
              <DownloadIcon className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Work Order</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead>Assigned To</TableHead>
                    <TableHead>Location</TableHead>
                    <TableHead>Scheduled</TableHead>
                    <TableHead>Cost</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredWorkOrders.map((workOrder) => (
                    <TableRow key={workOrder.id}>
                      <TableCell>
                        <div>
                          <p className="font-medium">{workOrder.title}</p>
                          <p className="text-sm text-muted-foreground truncate max-w-48">
                            {workOrder.description}
                          </p>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={getStatusColor(workOrder.status)}>
                          {workOrder.status.replace('_', ' ')}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getPriorityColor(workOrder.priority)}>
                          {workOrder.priority}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {workOrder.assignedTechnician || (
                          <Select onValueChange={(value) => assignTechnician(workOrder.id, value)}>
                            <SelectTrigger className="w-32">
                              <SelectValue placeholder="Assign" />
                            </SelectTrigger>
                            <SelectContent>
                              {technicians.filter(t => t.availability === 'available').map((tech) => (
                                <SelectItem key={tech.id} value={tech.id}>
                                  {tech.name}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          <MapPinIcon className="h-4 w-4 mr-1 text-muted-foreground" />
                          {workOrder.location}
                        </div>
                      </TableCell>
                      <TableCell>
                        {new Date(workOrder.scheduledDate).toLocaleDateString()}
                      </TableCell>
                      <TableCell>${workOrder.totalCost.toLocaleString()}</TableCell>
                      <TableCell>
                        <div className="flex space-x-1">
                          {workOrder.status === 'pending' && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => updateWorkOrderStatus(workOrder.id, 'in_progress')}
                            >
                              Start
                            </Button>
                          )}
                          {workOrder.status === 'in_progress' && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => updateWorkOrderStatus(workOrder.id, 'completed')}
                            >
                              Complete
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => setSelectedWorkOrder(workOrder)}
                          >
                            View
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

        <TabsContent value="scheduling" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="md:col-span-1">
              <Card>
                <CardHeader>
                  <CardTitle>Maintenance Calendar</CardTitle>
                </CardHeader>
                <CardContent>
                  <Calendar
                    mode="single"
                    selected={selectedDate}
                    onSelect={(date) => date && setSelectedDate(date)}
                    className="rounded-md border"
                  />
                </CardContent>
              </Card>
            </div>
            
            <div className="md:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle>Scheduled Maintenance</CardTitle>
                  <CardDescription>
                    Preventive maintenance schedules and upcoming tasks
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {schedules.map((schedule) => (
                      <div key={schedule.id} className="border rounded-lg p-4">
                        <div className="flex justify-between items-start">
                          <div>
                            <h4 className="font-medium">{schedule.name}</h4>
                            <p className="text-sm text-muted-foreground">{schedule.description}</p>
                            <div className="flex items-center space-x-4 mt-2">
                              <span className="text-sm">Device: {schedule.deviceName}</span>
                              <span className="text-sm">Frequency: {schedule.frequency}</span>
                              <span className="text-sm">
                                Next Due: {new Date(schedule.nextDue).toLocaleDateString()}
                              </span>
                            </div>
                          </div>
                          <Badge variant={schedule.isActive ? "default" : "secondary"}>
                            {schedule.isActive ? "Active" : "Inactive"}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="technicians" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {technicians.map((technician) => (
              <Card key={technician.id}>
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <div>
                      <CardTitle className="text-lg">{technician.name}</CardTitle>
                      <CardDescription>{technician.email}</CardDescription>
                    </div>
                    <Badge 
                      variant={technician.availability === 'available' ? 'default' : 'secondary'}
                    >
                      {technician.availability}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex items-center">
                      <PhoneIcon className="h-4 w-4 mr-2 text-muted-foreground" />
                      <span className="text-sm">{technician.phone}</span>
                    </div>
                    {technician.location && (
                      <div className="flex items-center">
                        <MapPinIcon className="h-4 w-4 mr-2 text-muted-foreground" />
                        <span className="text-sm">{technician.location}</span>
                      </div>
                    )}
                    <div className="flex items-center">
                      <ClipboardListIcon className="h-4 w-4 mr-2 text-muted-foreground" />
                      <span className="text-sm">{technician.currentWorkOrders} active work orders</span>
                    </div>
                    <div className="mt-3">
                      <p className="text-sm font-medium mb-1">Skills:</p>
                      <div className="flex flex-wrap gap-1">
                        {technician.skills.map((skill) => (
                          <Badge key={skill} variant="outline" className="text-xs">
                            {skill}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="inventory" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Parts Inventory</CardTitle>
              <CardDescription>
                Track parts usage, costs, and warranty information
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8">
                <TruckIcon className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">Parts Inventory Management</h3>
                <p className="text-muted-foreground mb-4">
                  Track parts usage, manage inventory levels, and monitor warranty status
                </p>
                <Button>
                  <PlusIcon className="h-4 w-4 mr-2" />
                  Add Parts
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Maintenance Metrics</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between text-sm">
                      <span>Average Completion Time</span>
                      <span>{dashboardStats.averageCompletionTime.toFixed(1)} hours</span>
                    </div>
                    <Progress value={75} className="mt-1" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm">
                      <span>On-Time Completion Rate</span>
                      <span>87%</span>
                    </div>
                    <Progress value={87} className="mt-1" />
                  </div>
                  <div>
                    <div className="flex justify-between text-sm">
                      <span>First-Time Fix Rate</span>
                      <span>92%</span>
                    </div>
                    <Progress value={92} className="mt-1" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Cost Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  <BarChart3Icon className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="text-lg font-medium mb-2">Cost Analytics</h3>
                  <p className="text-muted-foreground">
                    Detailed cost analysis and trending reports
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="devices" className="space-y-4">
          <div className="grid gap-4">
            {deviceHealth.map((device) => (
              <Card key={device.deviceId}>
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <div>
                      <CardTitle className="text-lg">{device.deviceName}</CardTitle>
                      <CardDescription>Device ID: {device.deviceId}</CardDescription>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold">{device.healthScore}%</div>
                      <p className="text-sm text-muted-foreground">Health Score</p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <Progress value={device.healthScore} className="w-full" />
                    
                    <div className="grid gap-4 md:grid-cols-2">
                      <div>
                        <p className="text-sm font-medium mb-2">Maintenance Schedule</p>
                        <div className="space-y-1">
                          <div className="flex justify-between text-sm">
                            <span>Last Maintenance:</span>
                            <span>{new Date(device.lastMaintenance).toLocaleDateString()}</span>
                          </div>
                          <div className="flex justify-between text-sm">
                            <span>Next Maintenance:</span>
                            <span>{new Date(device.nextMaintenance).toLocaleDateString()}</span>
                          </div>
                        </div>
                      </div>
                      
                      <div>
                        <p className="text-sm font-medium mb-2">Active Alerts</p>
                        <div className="space-y-1">
                          {device.alerts.length > 0 ? (
                            device.alerts.map((alert, index) => (
                              <div key={index} className="flex items-center text-sm">
                                <AlertTriangleIcon className="h-3 w-3 mr-1 text-orange-500" />
                                {alert}
                              </div>
                            ))
                          ) : (
                            <p className="text-sm text-muted-foreground">No active alerts</p>
                          )}
                        </div>
                      </div>
                    </div>

                    {device.predictiveIssues.length > 0 && (
                      <div>
                        <p className="text-sm font-medium mb-2">Predictive Issues</p>
                        <div className="space-y-1">
                          {device.predictiveIssues.map((issue, index) => (
                            <Alert key={index}>
                              <BellIcon className="h-4 w-4" />
                              <AlertTitle>Predictive Alert</AlertTitle>
                              <AlertDescription>{issue}</AlertDescription>
                            </Alert>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {selectedWorkOrder && (
        <WorkOrderDetailDialog
          workOrder={selectedWorkOrder}
          onClose={() => setSelectedWorkOrder(null)}
          onUpdate={loadMaintenanceData}
        />
      )}
    </div>
  )
}

// Work Order Form Component
function WorkOrderForm({ 
  onSubmit, 
  technicians 
}: { 
  onSubmit: (data: Partial<WorkOrder>) => void
  technicians: Technician[]
}) {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    priority: 'medium' as WorkOrder['priority'],
    type: 'corrective' as WorkOrder['type'],
    location: '',
    scheduledDate: new Date(),
    estimatedHours: 1,
    assignedTo: ''
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <Label htmlFor="title">Title</Label>
          <Input
            id="title"
            value={formData.title}
            onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
            required
          />
        </div>
        <div>
          <Label htmlFor="location">Location</Label>
          <Input
            id="location"
            value={formData.location}
            onChange={(e) => setFormData(prev => ({ ...prev, location: e.target.value }))}
            required
          />
        </div>
      </div>

      <div>
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
          required
        />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div>
          <Label htmlFor="priority">Priority</Label>
          <Select value={formData.priority} onValueChange={(value: WorkOrder['priority']) => 
            setFormData(prev => ({ ...prev, priority: value }))
          }>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
            </SelectContent>
          </Select>
        </div>
        
        <div>
          <Label htmlFor="type">Type</Label>
          <Select value={formData.type} onValueChange={(value: WorkOrder['type']) => 
            setFormData(prev => ({ ...prev, type: value }))
          }>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="preventive">Preventive</SelectItem>
              <SelectItem value="corrective">Corrective</SelectItem>
              <SelectItem value="emergency">Emergency</SelectItem>
              <SelectItem value="inspection">Inspection</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <div>
          <Label htmlFor="estimatedHours">Estimated Hours</Label>
          <Input
            id="estimatedHours"
            type="number"
            min="0.5"
            step="0.5"
            value={formData.estimatedHours}
            onChange={(e) => setFormData(prev => ({ ...prev, estimatedHours: parseFloat(e.target.value) }))}
            required
          />
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <Label htmlFor="scheduledDate">Scheduled Date</Label>
          <Input
            id="scheduledDate"
            type="datetime-local"
            value={formData.scheduledDate.toISOString().slice(0, 16)}
            onChange={(e) => setFormData(prev => ({ ...prev, scheduledDate: new Date(e.target.value) }))}
            required
          />
        </div>
        
        <div>
          <Label htmlFor="assignedTo">Assign Technician</Label>
          <Select value={formData.assignedTo} onValueChange={(value) => 
            setFormData(prev => ({ ...prev, assignedTo: value }))
          }>
            <SelectTrigger>
              <SelectValue placeholder="Select technician" />
            </SelectTrigger>
            <SelectContent>
              {technicians.filter(t => t.availability === 'available').map((tech) => (
                <SelectItem key={tech.id} value={tech.id}>
                  {tech.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="flex justify-end space-x-2">
        <Button type="submit">Create Work Order</Button>
      </div>
    </form>
  )
}

// Maintenance Schedule Form Component
function MaintenanceScheduleForm({ 
  onSubmit 
}: { 
  onSubmit: (data: Partial<MaintenanceSchedule>) => void
}) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    deviceId: '',
    frequency: 'monthly' as MaintenanceSchedule['frequency'],
    interval: 1,
    estimatedHours: 2,
    instructions: '',
    isActive: true
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit(formData)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <Label htmlFor="name">Schedule Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
            required
          />
        </div>
        <div>
          <Label htmlFor="deviceId">Device ID</Label>
          <Input
            id="deviceId"
            value={formData.deviceId}
            onChange={(e) => setFormData(prev => ({ ...prev, deviceId: e.target.value }))}
            required
          />
        </div>
      </div>

      <div>
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
          required
        />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div>
          <Label htmlFor="frequency">Frequency</Label>
          <Select value={formData.frequency} onValueChange={(value: MaintenanceSchedule['frequency']) => 
            setFormData(prev => ({ ...prev, frequency: value }))
          }>
            <SelectTrigger>
              <SelectValue />
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
          <Label htmlFor="interval">Interval</Label>
          <Input
            id="interval"
            type="number"
            min="1"
            value={formData.interval}
            onChange={(e) => setFormData(prev => ({ ...prev, interval: parseInt(e.target.value) }))}
            required
          />
        </div>

        <div>
          <Label htmlFor="estimatedHours">Estimated Hours</Label>
          <Input
            id="estimatedHours"
            type="number"
            min="0.5"
            step="0.5"
            value={formData.estimatedHours}
            onChange={(e) => setFormData(prev => ({ ...prev, estimatedHours: parseFloat(e.target.value) }))}
            required
          />
        </div>
      </div>

      <div>
        <Label htmlFor="instructions">Instructions</Label>
        <Textarea
          id="instructions"
          value={formData.instructions}
          onChange={(e) => setFormData(prev => ({ ...prev, instructions: e.target.value }))}
          placeholder="Detailed maintenance instructions..."
        />
      </div>

      <div className="flex items-center space-x-2">
        <Checkbox
          id="isActive"
          checked={formData.isActive}
          onCheckedChange={(checked) => setFormData(prev => ({ ...prev, isActive: !!checked }))}
        />
        <Label htmlFor="isActive">Active Schedule</Label>
      </div>

      <div className="flex justify-end space-x-2">
        <Button type="submit">Create Schedule</Button>
      </div>
    </form>
  )
}

// Work Order Detail Dialog Component
function WorkOrderDetailDialog({ 
  workOrder, 
  onClose, 
  onUpdate 
}: { 
  workOrder: WorkOrder
  onClose: () => void
  onUpdate: () => void
}) {
  return (
    <Dialog open={!!workOrder} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{workOrder.title}</DialogTitle>
          <DialogDescription>Work Order Details</DialogDescription>
        </DialogHeader>
        
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h4 className="font-medium mb-2">Basic Information</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>Status:</span>
                  <Badge className={getStatusColor(workOrder.status)}>
                    {workOrder.status.replace('_', ' ')}
                  </Badge>
                </div>
                <div className="flex justify-between">
                  <span>Priority:</span>
                  <Badge className={getPriorityColor(workOrder.priority)}>
                    {workOrder.priority}
                  </Badge>
                </div>
                <div className="flex justify-between">
                  <span>Type:</span>
                  <span>{workOrder.type}</span>
                </div>
                <div className="flex justify-between">
                  <span>Location:</span>
                  <span>{workOrder.location}</span>
                </div>
              </div>
            </div>
            
            <div>
              <h4 className="font-medium mb-2">Schedule & Assignment</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span>Scheduled:</span>
                  <span>{new Date(workOrder.scheduledDate).toLocaleString()}</span>
                </div>
                {workOrder.completedDate && (
                  <div className="flex justify-between">
                    <span>Completed:</span>
                    <span>{new Date(workOrder.completedDate).toLocaleString()}</span>
                  </div>
                )}
                <div className="flex justify-between">
                  <span>Assigned To:</span>
                  <span>{workOrder.assignedTechnician || 'Unassigned'}</span>
                </div>
                <div className="flex justify-between">
                  <span>Estimated Hours:</span>
                  <span>{workOrder.estimatedHours}h</span>
                </div>
                {workOrder.actualHours && (
                  <div className="flex justify-between">
                    <span>Actual Hours:</span>
                    <span>{workOrder.actualHours}h</span>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div>
            <h4 className="font-medium mb-2">Description</h4>
            <p className="text-sm text-muted-foreground">{workOrder.description}</p>
          </div>

          {workOrder.parts.length > 0 && (
            <div>
              <h4 className="font-medium mb-2">Parts Used</h4>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Part Number</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Quantity</TableHead>
                    <TableHead>Unit Cost</TableHead>
                    <TableHead>Total</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {workOrder.parts.map((part) => (
                    <TableRow key={part.id}>
                      <TableCell>{part.partNumber}</TableCell>
                      <TableCell>{part.partName}</TableCell>
                      <TableCell>{part.quantity}</TableCell>
                      <TableCell>${part.unitCost}</TableCell>
                      <TableCell>${part.totalCost}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          <div className="flex justify-between items-center pt-4 border-t">
            <div>
              <span className="text-lg font-medium">Total Cost: ${workOrder.totalCost.toLocaleString()}</span>
            </div>
            <div className="flex space-x-2">
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
              <Button onClick={onUpdate}>
                Refresh
              </Button>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function getStatusColor(status: WorkOrder['status']) {
  switch (status) {
    case 'pending': return 'bg-yellow-100 text-yellow-800'
    case 'assigned': return 'bg-blue-100 text-blue-800'
    case 'in_progress': return 'bg-orange-100 text-orange-800'
    case 'completed': return 'bg-green-100 text-green-800'
    case 'cancelled': return 'bg-red-100 text-red-800'
    default: return 'bg-gray-100 text-gray-800'
  }
}

function getPriorityColor(priority: WorkOrder['priority']) {
  switch (priority) {
    case 'low': return 'bg-green-100 text-green-800'
    case 'medium': return 'bg-yellow-100 text-yellow-800'
    case 'high': return 'bg-orange-100 text-orange-800'
    case 'critical': return 'bg-red-100 text-red-800'
    default: return 'bg-gray-100 text-gray-800'
  }
}