'use client'

import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Progress } from '@/components/ui/progress'
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Lock, 
  Unlock, 
  DoorOpen, 
  DoorClosed, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Clock, 
  Users, 
  Building, 
  MapPin, 
  Search, 
  Filter, 
  RefreshCw, 
  Settings, 
  Eye, 
  EyeOff, 
  Zap, 
  Activity, 
  Calendar, 
  User, 
  Key, 
  Wifi, 
  WifiOff,
  Camera,
  Bell,
  Download,
  Upload,
  MoreHorizontal,
  ChevronDown,
  ChevronRight,
  Home,
  Layers,
  Navigation,
  Loader2
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { format } from 'date-fns'
import { toast } from 'react-hot-toast'
import apiClient from '@/lib/api'
import { useRealtime } from '@/hooks/useRealtime'
import type { 
  Building as APIBuilding,
  Floor as APIFloor,
  Zone as APIZone,
  Door as APIDoor,
  AccessEvent as APIAccessEvent,
  AccessGroup as APIAccessGroup,
  Schedule as APISchedule,
  PaginatedResponse,
  ListQueryParams
} from '@sparc/shared'

// Enhanced types for UI state management
interface DoorWithCoordinates extends APIDoor {
  x: number // Floor plan coordinates
  y: number
  batteryLevel?: number
  emergencyOverride?: boolean
}

interface FloorWithDoors extends APIFloor {
  doors: DoorWithCoordinates[]
  zones: APIZone[]
}

interface BuildingWithFloors extends APIBuilding {
  floors: FloorWithDoors[]
}

interface AccessEventWithDetails extends APIAccessEvent {
  doorName?: string
  userName?: string
  location?: string
}

// Error handling interface
interface ApiError {
  message: string
  code?: string
  details?: any
}

export default function AccessControlPage() {
  // State management
  const [selectedBuilding, setSelectedBuilding] = useState<string>('')
  const [selectedFloor, setSelectedFloor] = useState<string>('')
  const [selectedZone, setSelectedZone] = useState<string>('')
  const [doors, setDoors] = useState<DoorWithCoordinates[]>([])
  const [accessEvents, setAccessEvents] = useState<AccessEventWithDetails[]>([])
  const [buildings, setBuildings] = useState<BuildingWithFloors[]>([])
  const [zones, setZones] = useState<APIZone[]>([])
  const [accessGroups, setAccessGroups] = useState<APIAccessGroup[]>([])
  const [schedules, setSchedules] = useState<APISchedule[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [emergencyMode, setEmergencyMode] = useState(false)
  const [selectedDoor, setSelectedDoor] = useState<DoorWithCoordinates | null>(null)
  const [showFloorPlan, setShowFloorPlan] = useState(true)
  const [realTimeUpdates, setRealTimeUpdates] = useState(true)
  const [loading, setLoading] = useState(false)
  const [initialLoading, setInitialLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [eventsPage, setEventsPage] = useState(1)
  const [eventsTotal, setEventsTotal] = useState(0)
  const [refreshing, setRefreshing] = useState(false)

  // Get current user and tenant for permissions
  const currentUser = apiClient.getUser()
  const currentTenant = apiClient.getTenant()
  const tenantId = apiClient.getCurrentTenantId()

  // Real-time connection setup
  const realtimeConfig = useMemo(() => ({
    tenantId: tenantId || '',
    token: apiClient.isAuthenticated() ? 'valid' : '', // Token is managed by apiClient
    autoConnect: realTimeUpdates && !!tenantId,
    subscriptions: {
      buildings: selectedBuilding ? [selectedBuilding] : [],
      floors: selectedBuilding && selectedFloor ? [{ buildingId: selectedBuilding, floorId: selectedFloor }] : [],
      zones: selectedZone ? [{ buildingId: selectedBuilding, floorId: selectedFloor, zoneId: selectedZone }] : [],
      permissions: currentUser?.permissions || [],
    },
    handlers: {
      onAccessEvent: handleRealtimeAccessEvent,
      onDeviceStatus: handleRealtimeDeviceStatus,
      onAlert: handleRealtimeAlert,
      onConnectionStatusChange: (status: any) => {
        if (status === 'connected') {
          toast.success('Real-time updates connected')
        } else if (status === 'disconnected') {
          toast.error('Real-time updates disconnected')
        }
      },
      onError: (error: Error) => {
        console.error('Real-time connection error:', error)
        toast.error(`Real-time error: ${error.message}`)
      }
    },
    enableToasts: true,
    toastConfig: {
      showAccessEvents: true,
      showAlerts: true,
      alertSeverityThreshold: 'medium' as const,
    }
  }), [tenantId, realTimeUpdates, selectedBuilding, selectedFloor, selectedZone, currentUser?.permissions])

  const realtime = useRealtime(realtimeConfig)

  // Real-time event handlers
  const handleRealtimeAccessEvent = useCallback((event: any) => {
    const transformedEvent: AccessEventWithDetails = {
      ...event,
      timestamp: new Date(event.timestamp),
      doorName: doors.find(d => d.id === event.doorId)?.name || 'Unknown Door',
      location: doors.find(d => d.id === event.doorId)?.location || 'Unknown Location'
    }
    
    setAccessEvents(prev => [transformedEvent, ...prev.slice(0, 49)])
    
    // Show toast for important events
    if (event.eventType === 'access_denied' || event.eventType === 'door_forced') {
      toast.error(`Security Alert: ${event.eventType} at ${transformedEvent.doorName}`)
    }
  }, [doors])

  const handleRealtimeDeviceStatus = useCallback((status: any) => {
    if (status.deviceType === 'door_controller') {
      setDoors(prev => prev.map(door => 
        door.id === status.deviceId 
          ? { 
              ...door, 
              status: status.status === 'online' ? door.status : 'offline',
              lastActivity: new Date(status.timestamp),
              batteryLevel: status.batteryLevel
            }
          : door
      ))
    }
  }, [])

  const handleRealtimeAlert = useCallback((alert: any) => {
    if (alert.type === 'security' && alert.severity === 'high') {
      toast.error(`Security Alert: ${alert.title}`)
    }
  }, [])

  // Data loading functions
  const loadBuildings = useCallback(async () => {
    try {
      const response = await apiClient.getPaginated<APIBuilding>('/api/v1/buildings', {
        limit: 100,
        include: ['floors', 'zones']
      })
      
      // Transform buildings to include floors and zones
      const buildingsWithFloors: BuildingWithFloors[] = await Promise.all(
        response.data.map(async (building) => {
          const floorsResponse = await apiClient.getPaginated<APIFloor>('/api/v1/floors', {
            buildingId: building.id,
            include: ['zones']
          })
          
          const floors: FloorWithDoors[] = await Promise.all(
            floorsResponse.data.map(async (floor) => {
              const doorsResponse = await apiClient.getPaginated<APIDoor>('/api/v1/doors', {
                floorId: floor.id,
                limit: 100
              })
              
              const zonesResponse = await apiClient.getPaginated<APIZone>('/api/v1/zones', {
                floorId: floor.id
              })
              
              // Add coordinates for floor plan visualization
              const doorsWithCoords: DoorWithCoordinates[] = doorsResponse.data.map((door, index) => ({
                ...door,
                x: 100 + (index % 5) * 80, // Simple grid layout
                y: 100 + Math.floor(index / 5) * 80,
                // TODO: Get from device status
                batteryLevel: deviceStatusMap.get(door.id)?.batteryLevel,
                emergencyOverride: false
              }))
              
              return {
                ...floor,
                doors: doorsWithCoords,
                zones: zonesResponse.data
              }
            })
          )
          
          return {
            ...building,
            floors
          }
        })
      )
      
      setBuildings(buildingsWithFloors)
      
      // Auto-select first building and floor if none selected
      if (!selectedBuilding && buildingsWithFloors.length > 0) {
        setSelectedBuilding(buildingsWithFloors[0].id)
        if (buildingsWithFloors[0].floors.length > 0) {
          setSelectedFloor(buildingsWithFloors[0].floors[0].id)
        }
      }
    } catch (error: any) {
      console.error('Failed to load buildings:', error)
      setError({ message: 'Failed to load buildings', details: error })
      toast.error('Failed to load buildings')
    }
  }, [selectedBuilding])

  const loadDoors = useCallback(async () => {
    if (!selectedFloor) return
    
    try {
      const params: ListQueryParams = {
        floorId: selectedFloor,
        limit: 100,
        include: ['status', 'lastActivity']
      }
      
      if (selectedZone) {
        params.zoneId = selectedZone
      }
      
      const response = await apiClient.getPaginated<APIDoor>('/api/v1/doors', params)
      
      // Transform doors with coordinates
      const doorsWithCoords: DoorWithCoordinates[] = response.data.map((door, index) => ({
        ...door,
        x: 100 + (index % 5) * 80,
        y: 100 + Math.floor(index / 5) * 80,
        batteryLevel: Math.floor(Math.random() * 100), // TODO: Get from device management service
        emergencyOverride: false
      }))
      
      setDoors(doorsWithCoords)
    } catch (error: any) {
      console.error('Failed to load doors:', error)
      toast.error('Failed to load doors')
    }
  }, [selectedFloor, selectedZone])

  const loadAccessEvents = useCallback(async (page = 1) => {
    try {
      const params: ListQueryParams = {
        page,
        limit: 50,
        sortBy: 'timestamp',
        sortOrder: 'desc'
      }
      
      if (selectedBuilding) {
        params.buildingId = selectedBuilding
      }
      
      if (selectedFloor) {
        params.floorId = selectedFloor
      }
      
      const response = await apiClient.getPaginated<APIAccessEvent>('/api/v1/access-events', params)
      
      // Transform events with additional details
      const eventsWithDetails: AccessEventWithDetails[] = response.data.map(event => ({
        ...event,
        timestamp: new Date(event.timestamp),
        doorName: doors.find(d => d.id === event.doorId)?.name || 'Unknown Door',
        location: doors.find(d => d.id === event.doorId)?.location || 'Unknown Location'
      }))
      
      if (page === 1) {
        setAccessEvents(eventsWithDetails)
      } else {
        setAccessEvents(prev => [...prev, ...eventsWithDetails])
      }
      
      setEventsTotal(response.total)
      setEventsPage(page)
    } catch (error: any) {
      console.error('Failed to load access events:', error)
      toast.error('Failed to load access events')
    }
  }, [selectedBuilding, selectedFloor, doors])

  const loadAccessGroups = useCallback(async () => {
    try {
      const response = await apiClient.getPaginated<APIAccessGroup>('/api/v1/access-groups', {
        limit: 100
      })
      setAccessGroups(response.data)
    } catch (error: any) {
      console.error('Failed to load access groups:', error)
      toast.error('Failed to load access groups')
    }
  }, [])

  const loadSchedules = useCallback(async () => {
    try {
      const response = await apiClient.getPaginated<APISchedule>('/api/v1/schedules', {
        limit: 100
      })
      setSchedules(response.data)
    } catch (error: any) {
      console.error('Failed to load schedules:', error)
      toast.error('Failed to load schedules')
    }
  }, [])

  // Initial data loading
  useEffect(() => {
    const loadInitialData = async () => {
      setInitialLoading(true)
      setError(null)
      
      try {
        await Promise.all([
          loadBuildings(),
          loadAccessGroups(),
          loadSchedules()
        ])
      } catch (error: any) {
        console.error('Failed to load initial data:', error)
        setError({ message: 'Failed to load initial data', details: error })
      } finally {
        setInitialLoading(false)
      }
    }
    
    if (tenantId && apiClient.isAuthenticated()) {
      loadInitialData()
    }
  }, [tenantId, loadBuildings, loadAccessGroups, loadSchedules])

  // Load doors when floor changes
  useEffect(() => {
    if (selectedFloor) {
      loadDoors()
    }
  }, [selectedFloor, loadDoors])

  // Load access events when building/floor changes
  useEffect(() => {
    if (selectedBuilding) {
      loadAccessEvents(1)
    }
  }, [selectedBuilding, selectedFloor, loadAccessEvents])

  // Memoized computed values
  const filteredDoors = useMemo(() => {
    return doors.filter(door => {
      const matchesSearch = door.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           (door.location || '').toLowerCase().includes(searchTerm.toLowerCase())
      const matchesStatus = statusFilter === 'all' || door.status === statusFilter
      const matchesZone = !selectedZone || door.zoneId === selectedZone
      return matchesSearch && matchesStatus && matchesZone
    })
  }, [doors, searchTerm, statusFilter, selectedZone])

  const currentFloor = useMemo(() => {
    return buildings
      .find(b => b.id === selectedBuilding)
      ?.floors.find(f => f.id === selectedFloor)
  }, [buildings, selectedBuilding, selectedFloor])

  const currentZones = useMemo(() => {
    return currentFloor?.zones || []
  }, [currentFloor])

  // Door status helpers
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'locked': return 'bg-green-500'
      case 'unlocked': return 'bg-blue-500'
      case 'open': return 'bg-yellow-500'
      case 'forced': return 'bg-red-500'
      case 'held_open': return 'bg-orange-500'
      case 'offline': return 'bg-gray-500'
      default: return 'bg-gray-400'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'locked': return <Lock className="h-4 w-4" />
      case 'unlocked': return <Unlock className="h-4 w-4" />
      case 'open': return <DoorOpen className="h-4 w-4" />
      case 'forced': return <AlertTriangle className="h-4 w-4" />
      case 'held_open': return <Clock className="h-4 w-4" />
      case 'offline': return <WifiOff className="h-4 w-4" />
      default: return <DoorClosed className="h-4 w-4" />
    }
  }

  // Permission checks
  const canControlDoor = useCallback((door: DoorWithCoordinates) => {
    if (!currentUser) return false
    
    // Check if user has door control permissions
    const hasPermission = currentUser.permissions?.includes('door:control') || 
                         currentUser.permissions?.includes('access_control:manage')
    
    // Check if door is online
    const isOnline = door.status !== 'offline'
    
    return hasPermission && isOnline
  }, [currentUser])

  const canEmergencyOverride = useCallback(() => {
    if (!currentUser) return false
    
    return currentUser.permissions?.includes('emergency:override') || 
           currentUser.permissions?.includes('access_control:emergency')
  }, [currentUser])

  // Door control actions with real API calls
  const handleDoorAction = useCallback(async (doorId: string, action: 'lock' | 'unlock' | 'pulse' | 'emergency_unlock') => {
    const door = doors.find(d => d.id === doorId)
    if (!door) return
    
    if (!canControlDoor(door)) {
      toast.error('You do not have permission to control this door')
      return
    }
    
    setLoading(true)
    
    try {
      // Optimistic update
      setDoors(prev => prev.map(d => 
        d.id === doorId 
          ? { 
              ...d, 
              status: action === 'lock' ? 'locked' : action === 'unlock' || action === 'emergency_unlock' ? 'unlocked' : d.status,
              lastActivity: new Date(),
              emergencyOverride: action === 'emergency_unlock' ? true : d.emergencyOverride
            }
          : d
      ))
      
      // Make API call
      switch (action) {
        case 'lock':
          await apiClient.lockDoor(doorId)
          toast.success(`Door ${door.name} locked successfully`)
          break
        case 'unlock':
          await apiClient.unlockDoor(doorId)
          toast.success(`Door ${door.name} unlocked successfully`)
          break
        case 'pulse':
          await apiClient.post(`/api/v1/doors/${doorId}/pulse`)
          toast.success(`Door ${door.name} pulsed successfully`)
          break
        case 'emergency_unlock':
          if (!canEmergencyOverride()) {
            throw new Error('Emergency override permission required')
          }
          await apiClient.post(`/api/v1/doors/${doorId}/emergency-unlock`)
          toast.success(`Emergency unlock activated for ${door.name}`)
          break
      }
      
      // Refresh door status
      await loadDoors()
      
    } catch (error: any) {
      console.error('Door action failed:', error)
      toast.error(`Failed to ${action} door: ${error.message}`)
      
      // Revert optimistic update on error
      await loadDoors()
    } finally {
      setLoading(false)
    }
  }, [doors, canControlDoor, canEmergencyOverride, loadDoors])

  // Emergency lockdown with real API calls
  const handleEmergencyLockdown = useCallback(async () => {
    if (!canEmergencyOverride()) {
      toast.error('You do not have emergency override permissions')
      return
    }
    
    setLoading(true)
    
    try {
      if (emergencyMode) {
        // Exit emergency mode
        await apiClient.post('/api/v1/access-control/emergency-exit')
        setEmergencyMode(false)
        toast.success('Emergency mode deactivated')
      } else {
        // Activate emergency lockdown
        await apiClient.post('/api/v1/access-control/emergency-lockdown', {
          buildingId: selectedBuilding,
          reason: 'Manual emergency activation',
          userId: currentUser?.id
        })
        setEmergencyMode(true)
        toast.success('Emergency lockdown activated')
      }
      
      // Refresh all doors status
      await loadDoors()
      
    } catch (error: any) {
      console.error('Emergency lockdown failed:', error)
      toast.error(`Emergency operation failed: ${error.message}`)
    } finally {
      setLoading(false)
    }
  }, [emergencyMode, canEmergencyOverride, selectedBuilding, currentUser?.id, loadDoors])

  // Refresh data
  const handleRefresh = useCallback(async () => {
    setRefreshing(true)
    try {
      await Promise.all([
        loadBuildings(),
        loadDoors(),
        loadAccessEvents(1),
        loadAccessGroups(),
        loadSchedules()
      ])
      toast.success('Data refreshed successfully')
    } catch (error: any) {
      console.error('Refresh failed:', error)
      toast.error('Failed to refresh data')
    } finally {
      setRefreshing(false)
    }
  }, [loadBuildings, loadDoors, loadAccessEvents, loadAccessGroups, loadSchedules])

  // Export data
  const handleExport = useCallback(async () => {
    try {
      const exportData = {
        doors: filteredDoors,
        accessEvents: accessEvents.slice(0, 100), // Limit export size
        timestamp: new Date().toISOString(),
        building: buildings.find(b => b.id === selectedBuilding)?.name,
        floor: currentFloor?.name
      }
      
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `access-control-export-${format(new Date(), 'yyyy-MM-dd-HH-mm')}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      
      toast.success('Data exported successfully')
    } catch (error: any) {
      console.error('Export failed:', error)
      toast.error('Failed to export data')
    }
  }, [filteredDoors, accessEvents, buildings, selectedBuilding, currentFloor])

  // Handle building/floor selection changes
  const handleBuildingChange = useCallback((buildingId: string) => {
    setSelectedBuilding(buildingId)
    setSelectedFloor('')
    setSelectedZone('')
    setSelectedDoor(null)
    setDoors([])
    
    // Auto-select first floor
    const building = buildings.find(b => b.id === buildingId)
    if (building && building.floors.length > 0) {
      setSelectedFloor(building.floors[0].id)
    }
  }, [buildings])

  const handleFloorChange = useCallback((floorId: string) => {
    setSelectedFloor(floorId)
    setSelectedZone('')
    setSelectedDoor(null)
  }, [])

  const handleZoneChange = useCallback((zoneId: string) => {
    setSelectedZone(zoneId)
    setSelectedDoor(null)
  }, [])

  // Real-time updates toggle
  const handleRealTimeToggle = useCallback((enabled: boolean) => {
    setRealTimeUpdates(enabled)
    if (enabled) {
      realtime.connect()
    } else {
      realtime.disconnect()
    }
  }, [realtime])

  // Show loading state during initial load
  if (initialLoading) {
    return (
      <div className="flex h-screen bg-gray-50 items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
          <p className="text-gray-600">Loading access control system...</p>
        </div>
      </div>
    )
  }

  // Show error state
  if (error && !buildings.length) {
    return (
      <div className="flex h-screen bg-gray-50 items-center justify-center">
        <div className="text-center max-w-md">
          <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Failed to Load</h2>
          <p className="text-gray-600 mb-4">{error.message}</p>
          <Button onClick={() => window.location.reload()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="w-80 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="h-6 w-6 text-blue-600" />
            <h1 className="text-xl font-semibold text-gray-900">Access Control</h1>
          </div>
          
          {/* Building/Floor Selection */}
          <div className="space-y-3">
            <div>
              <Label htmlFor="building">Building</Label>
              <Select value={selectedBuilding} onValueChange={handleBuildingChange}>
                <SelectTrigger>
                  <SelectValue placeholder="Select building" />
                </SelectTrigger>
                <SelectContent>
                  {buildings.map(building => (
                    <SelectItem key={building.id} value={building.id}>
                      <div className="flex items-center gap-2">
                        <Building className="h-4 w-4" />
                        {building.name}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            <div>
              <Label htmlFor="floor">Floor</Label>
              <Select value={selectedFloor} onValueChange={handleFloorChange}>
                <SelectTrigger>
                  <SelectValue placeholder="Select floor" />
                </SelectTrigger>
                <SelectContent>
                  {buildings.find(b => b.id === selectedBuilding)?.floors.map(floor => (
                    <SelectItem key={floor.id} value={floor.id}>
                      <div className="flex items-center gap-2">
                        <Layers className="h-4 w-4" />
                        {floor.name}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="zone">Zone (Optional)</Label>
              <Select value={selectedZone} onValueChange={handleZoneChange}>
                <SelectTrigger>
                  <SelectValue placeholder="All zones" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All zones</SelectItem>
                  {currentZones.map(zone => (
                    <SelectItem key={zone.id} value={zone.id}>
                      <div className="flex items-center gap-2">
                        <MapPin className="h-4 w-4" />
                        {zone.name}
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="p-4 border-b border-gray-200">
          <div className="relative mb-3">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search doors..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
          
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger>
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="locked">Locked</SelectItem>
              <SelectItem value="unlocked">Unlocked</SelectItem>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="forced">Forced</SelectItem>
              <SelectItem value="held_open">Held Open</SelectItem>
              <SelectItem value="offline">Offline</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Emergency Controls */}
        <div className="p-4 border-b border-gray-200">
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button 
                variant={emergencyMode ? "destructive" : "outline"} 
                className="w-full"
                disabled={loading}
              >
                <Zap className="h-4 w-4 mr-2" />
                {emergencyMode ? 'Exit Emergency Mode' : 'Emergency Lockdown'}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>
                  {emergencyMode ? 'Exit Emergency Mode?' : 'Emergency Lockdown?'}
                </AlertDialogTitle>
                <AlertDialogDescription>
                  {emergencyMode 
                    ? 'This will restore normal access control operations.'
                    : 'This will immediately unlock all doors for emergency evacuation. This action will be logged and requires authorization.'
                  }
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={handleEmergencyLockdown}>
                  {emergencyMode ? 'Exit Emergency Mode' : 'Activate Emergency Mode'}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>

        {/* Door List */}
        <ScrollArea className="flex-1">
          <div className="p-4 space-y-2">
            {loading && doors.length === 0 ? (
              <div className="text-center py-8">
                <Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />
                <p className="text-sm text-gray-500">Loading doors...</p>
              </div>
            ) : filteredDoors.length === 0 ? (
              <div className="text-center py-8">
                <DoorClosed className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                <p className="text-sm text-gray-500">No doors found</p>
                {searchTerm && (
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    onClick={() => setSearchTerm('')}
                    className="mt-2"
                  >
                    Clear search
                  </Button>
                )}
              </div>
            ) : (
              filteredDoors.map(door => (
                <Card 
                  key={door.id} 
                  className={cn(
                    "cursor-pointer transition-colors hover:bg-gray-50",
                    selectedDoor?.id === door.id && "ring-2 ring-blue-500"
                  )}
                  onClick={() => setSelectedDoor(door)}
                >
                  <CardContent className="p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div className={cn("w-3 h-3 rounded-full", getStatusColor(door.status))} />
                        <span className="font-medium text-sm">{door.name}</span>
                      </div>
                      {door.status === 'offline' && <WifiOff className="h-4 w-4 text-red-500" />}
                    </div>
                    
                    <div className="text-xs text-gray-500 mb-2">{door.location || 'No location'}</div>
                    
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="text-xs">
                        {door.status.replace('_', ' ')}
                      </Badge>
                      <span className="text-xs text-gray-400">
                        {door.lastActivity ? format(new Date(door.lastActivity), 'HH:mm') : 'No activity'}
                      </span>
                    </div>
                    
                    {door.batteryLevel && (
                      <div className="mt-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-500">Battery:</span>
                          <Progress value={door.batteryLevel} className="h-1 flex-1" />
                          <span className="text-xs text-gray-500">{door.batteryLevel}%</span>
                        </div>
                      </div>
                    )}
                    
                    {door.emergencyOverride && (
                      <div className="mt-2 flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3 text-orange-500" />
                        <span className="text-xs text-orange-600">Emergency Override</span>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </ScrollArea>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <div className="bg-white border-b border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h2 className="text-lg font-semibold text-gray-900">
                {currentFloor ? `${buildings.find(b => b.id === selectedBuilding)?.name} - ${currentFloor.name}` : 'Select a floor'}
              </h2>
              <Badge variant="outline" className="flex items-center gap-1">
                <Activity className="h-3 w-3" />
                {filteredDoors.length} doors
              </Badge>
            </div>
            
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-2">
                <Label htmlFor="realtime" className="text-sm">Real-time updates</Label>
                <Switch
                  id="realtime"
                  checked={realTimeUpdates}
                  onCheckedChange={handleRealTimeToggle}
                />
                {realtime.isConnected && (
                  <div className="flex items-center gap-1">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                    <span className="text-xs text-green-600">Live</span>
                  </div>
                )}
              </div>
              
              <Separator orientation="vertical" className="h-6" />
              
              <Button variant="outline" size="sm" onClick={handleExport}>
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
              
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleRefresh}
                disabled={refreshing}
              >
                <RefreshCw className={cn("h-4 w-4 mr-2", refreshing && "animate-spin")} />
                Refresh
              </Button>
            </div>
          </div>
        </div>

        {/* Content Tabs */}
        <div className="flex-1 p-4">
          <Tabs defaultValue="floorplan" className="h-full flex flex-col">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="floorplan">Floor Plan</TabsTrigger>
              <TabsTrigger value="events">Access Events</TabsTrigger>
              <TabsTrigger value="permissions">Permissions</TabsTrigger>
            </TabsList>
            
            {/* Floor Plan Tab */}
            <TabsContent value="floorplan" className="flex-1 mt-4">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-full">
                {/* Floor Plan Visualization */}
                <div className="lg:col-span-2">
                  <Card className="h-full">
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Navigation className="h-5 w-5" />
                        Interactive Floor Plan
                      </CardTitle>
                      <CardDescription>
                        Click on doors to view details and control access
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="h-full">
                      <div className="relative w-full h-96 bg-gray-100 rounded-lg overflow-hidden">
                        <svg
                          viewBox="0 0 500 400"
                          className="w-full h-full"
                          style={{ background: 'linear-gradient(45deg, #f8f9fa 25%, transparent 25%), linear-gradient(-45deg, #f8f9fa 25%, transparent 25%), linear-gradient(45deg, transparent 75%, #f8f9fa 75%), linear-gradient(-45deg, transparent 75%, #f8f9fa 75%)', backgroundSize: '20px 20px', backgroundPosition: '0 0, 0 10px, 10px -10px, -10px 0px' }}
                        >
                          {/* Floor plan outline */}
                          <rect x="50" y="50" width="400" height="300" fill="white" stroke="#e5e7eb" strokeWidth="2" />
                          
                          {/* Zones */}
                          {currentZones.map((zone, index) => (
                            <g key={zone.id}>
                              <rect 
                                x={60 + (index % 3) * 130} 
                                y={60 + Math.floor(index / 3) * 120} 
                                width={120} 
                                height={110} 
                                fill={zone.type === 'public' ? '#f0f9ff' : zone.type === 'restricted' ? '#fef3c7' : '#fee2e2'} 
                                stroke="#d1d5db" 
                                strokeWidth="1"
                                opacity="0.5"
                              />
                              <text 
                                x={120 + (index % 3) * 130} 
                                y={80 + Math.floor(index / 3) * 120} 
                                fontSize="12" 
                                fill="#6b7280" 
                                textAnchor="middle"
                              >
                                {zone.name}
                              </text>
                            </g>
                          ))}
                          
                          {/* Doors */}
                          {filteredDoors.map(door => (
                            <g key={door.id}>
                              <circle
                                cx={door.x}
                                cy={door.y}
                                r="12"
                                fill={getStatusColor(door.status).replace('bg-', '')}
                                stroke="white"
                                strokeWidth="2"
                                className="cursor-pointer hover:stroke-blue-500 hover:stroke-4 transition-all"
                                onClick={() => setSelectedDoor(door)}
                              />
                              {!door.isOnline && (
                                <circle
                                  cx={door.x + 8}
                                  cy={door.y - 8}
                                  r="4"
                                  fill="#ef4444"
                                  stroke="white"
                                  strokeWidth="1"
                                />
                              )}
                              <text
                                x={door.x}
                                y={door.y + 25}
                                fontSize="10"
                                fill="#374151"
                                textAnchor="middle"
                                className="pointer-events-none"
                              >
                                {door.name}
                              </text>
                            </g>
                          ))}
                        </svg>
                      </div>
                      
                      {/* Legend */}
                      <div className="mt-4 flex flex-wrap gap-4">
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-green-500" />
                          <span className="text-sm text-gray-600">Locked</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-blue-500" />
                          <span className="text-sm text-gray-600">Unlocked</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-yellow-500" />
                          <span className="text-sm text-gray-600">Open</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-red-500" />
                          <span className="text-sm text-gray-600">Forced</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-orange-500" />
                          <span className="text-sm text-gray-600">Held Open</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-gray-500" />
                          <span className="text-sm text-gray-600">Offline</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Door Details Panel */}
                <div className="space-y-4">
                  {selectedDoor ? (
                    <>
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2">
                            {getStatusIcon(selectedDoor.status)}
                            {selectedDoor.name}
                          </CardTitle>
                          <CardDescription>{selectedDoor.location}</CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-600">Status</span>
                            <Badge className={getStatusColor(selectedDoor.status)}>
                              {selectedDoor.status.replace('_', ' ')}
                            </Badge>
                          </div>
                          
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-600">Access Level</span>
                            <Badge variant="outline">
                              {selectedDoor.accessLevel.replace('_', ' ')}
                            </Badge>
                          </div>
                          
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-600">Reader Type</span>
                            <span className="text-sm font-medium">{selectedDoor.readerType}</span>
                          </div>
                          
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-600">Online Status</span>
                            <div className="flex items-center gap-1">
                              {selectedDoor.isOnline ? (
                                <Wifi className="h-4 w-4 text-green-500" />
                              ) : (
                                <WifiOff className="h-4 w-4 text-red-500" />
                              )}
                              <span className="text-sm">
                                {selectedDoor.isOnline ? 'Online' : 'Offline'}
                              </span>
                            </div>
                          </div>
                          
                          <div className="flex items-center justify-between">
                            <span className="text-sm text-gray-600">Last Activity</span>
                            <span className="text-sm">
                              {format(selectedDoor.lastActivity, 'MMM dd, HH:mm')}
                            </span>
                          </div>
                          
                          {selectedDoor.batteryLevel && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-600">Battery Level</span>
                                <span className="text-sm font-medium">{selectedDoor.batteryLevel}%</span>
                              </div>
                              <Progress value={selectedDoor.batteryLevel} className="h-2" />
                            </div>
                          )}
                          
                          {selectedDoor.emergencyOverride && (
                            <div className="flex items-center gap-2 p-2 bg-orange-50 rounded-lg">
                              <AlertTriangle className="h-4 w-4 text-orange-500" />
                              <span className="text-sm text-orange-700">Emergency Override Active</span>
                            </div>
                          )}
                        </CardContent>
                      </Card>

                      {/* Door Controls */}
                      <Card>
                        <CardHeader>
                          <CardTitle>Door Controls</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <Button 
                            className="w-full" 
                            variant="outline"
                            onClick={() => handleDoorAction(selectedDoor.id, 'unlock')}
                            disabled={loading || !canControlDoor(selectedDoor)}
                          >
                            <Unlock className="h-4 w-4 mr-2" />
                            Unlock Door
                          </Button>
                          
                          <Button 
                            className="w-full" 
                            variant="outline"
                            onClick={() => handleDoorAction(selectedDoor.id, 'lock')}
                            disabled={loading || !canControlDoor(selectedDoor)}
                          >
                            <Lock className="h-4 w-4 mr-2" />
                            Lock Door
                          </Button>

                          <Button 
                            className="w-full" 
                            variant="outline"
                            onClick={() => handleDoorAction(selectedDoor.id, 'pulse')}
                            disabled={loading || !canControlDoor(selectedDoor)}
                          >
                            <Zap className="h-4 w-4 mr-2" />
                            Pulse Door
                          </Button>
                          
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button 
                                className="w-full" 
                                variant="destructive"
                                disabled={loading || !canEmergencyOverride()}
                              >
                                <Zap className="h-4 w-4 mr-2" />
                                Emergency Unlock
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>Emergency Unlock</AlertDialogTitle>
                                <AlertDialogDescription>
                                  This will immediately unlock the door and set an emergency override. 
                                  This action will be logged and requires authorization.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                <AlertDialogAction 
                                  onClick={() => handleDoorAction(selectedDoor.id, 'emergency_unlock')}
                                >
                                  Emergency Unlock
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                          
                          <Separator />
                          
                          <Button className="w-full" variant="outline">
                            <Camera className="h-4 w-4 mr-2" />
                            View Camera
                          </Button>
                          
                          <Button className="w-full" variant="outline">
                            <Settings className="h-4 w-4 mr-2" />
                            Configure
                          </Button>
                        </CardContent>
                      </Card>
                    </>
                  ) : (
                    <Card>
                      <CardContent className="p-6 text-center">
                        <DoorClosed className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Door</h3>
                        <p className="text-gray-500">
                          Click on a door in the floor plan or select from the list to view details and controls.
                        </p>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </div>
            </TabsContent>

            {/* Access Events Tab */}
            <TabsContent value="events" className="flex-1 mt-4">
              <Card className="h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-5 w-5" />
                    Recent Access Events
                  </CardTitle>
                  <CardDescription>
                    Real-time access control events and alerts
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-96">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Time</TableHead>
                          <TableHead>Door</TableHead>
                          <TableHead>User</TableHead>
                          <TableHead>Event</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {accessEvents.map(event => (
                          <TableRow key={event.id}>
                            <TableCell className="font-mono text-sm">
                              {format(event.timestamp, 'HH:mm:ss')}
                            </TableCell>
                            <TableCell>
                              <div>
                                <div className="font-medium">{event.doorName || 'Unknown Door'}</div>
                                <div className="text-sm text-gray-500">{event.location || 'Unknown Location'}</div>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div>
                                <div className="font-medium">{event.userName || event.userId || 'Unknown User'}</div>
                                <div className="text-sm text-gray-500">{event.credentialId || 'No credential'}</div>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-2">
                                {event.eventType === 'access_granted' || event.eventType === 'granted' ? (
                                  <CheckCircle className="h-4 w-4 text-green-500" />
                                ) : event.eventType === 'access_denied' || event.eventType === 'denied' ? (
                                  <XCircle className="h-4 w-4 text-red-500" />
                                ) : (
                                  <AlertTriangle className="h-4 w-4 text-orange-500" />
                                )}
                                <span className="capitalize">{event.eventType.replace('_', ' ')}</span>
                              </div>
                              {event.reason && (
                                <div className="text-sm text-gray-500 mt-1">{event.reason}</div>
                              )}
                            </TableCell>
                            <TableCell>
                              <Badge 
                                variant={
                                  event.eventType === 'access_granted' || event.eventType === 'granted' 
                                    ? 'default' 
                                    : 'destructive'
                                }
                              >
                                {event.eventType.replace('_', ' ')}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Button variant="ghost" size="sm">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                        {accessEvents.length === 0 && (
                          <TableRow>
                            <TableCell colSpan={6} className="text-center py-8 text-gray-500">
                              No access events found
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                  
                  {/* Pagination */}
                  {eventsTotal > 50 && (
                    <div className="flex items-center justify-between mt-4">
                      <div className="text-sm text-gray-500">
                        Showing {accessEvents.length} of {eventsTotal} events
                      </div>
                      <Button 
                        variant="outline" 
                        size="sm"
                        onClick={() => loadAccessEvents(eventsPage + 1)}
                        disabled={accessEvents.length >= eventsTotal}
                      >
                        Load More
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Permissions Tab */}
            <TabsContent value="permissions" className="flex-1 mt-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 h-full">
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Users className="h-5 w-5" />
                      Access Groups
                    </CardTitle>
                    <CardDescription>
                      Manage user access groups and permissions
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <Button className="w-full" variant="outline">
                        <Users className="h-4 w-4 mr-2" />
                        Create Access Group
                      </Button>
                      
                      <div className="space-y-2">
                        {accessGroups.map(group => (
                          <div key={group.id} className="flex items-center justify-between p-3 border rounded-lg">
                            <div>
                              <div className="font-medium">{group.name}</div>
                              <div className="text-sm text-gray-500">
                                {group.description}
                              </div>
                              <div className="text-xs text-gray-400 mt-1">
                                {group.permissions?.length || 0} permissions
                              </div>
                            </div>
                            <Button variant="ghost" size="sm">
                              <Settings className="h-4 w-4" />
                            </Button>
                          </div>
                        ))}
                        {accessGroups.length === 0 && (
                          <div className="text-center py-8 text-gray-500">
                            No access groups found
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Calendar className="h-5 w-5" />
                      Access Schedules
                    </CardTitle>
                    <CardDescription>
                      Configure time-based access controls
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <Button className="w-full" variant="outline">
                        <Calendar className="h-4 w-4 mr-2" />
                        Create Schedule
                      </Button>
                      
                      <div className="space-y-2">
                        {schedules.map(schedule => (
                          <div key={schedule.id} className="flex items-center justify-between p-3 border rounded-lg">
                            <div>
                              <div className="font-medium">{schedule.name}</div>
                              <div className="text-sm text-gray-500">
                                {schedule.timeSlots?.length || 0} time slots
                              </div>
                              <div className="text-xs text-gray-400 mt-1">
                                Timezone: {schedule.timezone || 'UTC'}
                              </div>
                            </div>
                            <Button variant="ghost" size="sm">
                              <Settings className="h-4 w-4" />
                            </Button>
                          </div>
                        ))}
                        {schedules.length === 0 && (
                          <div className="text-center py-8 text-gray-500">
                            No schedules found
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  )
}
