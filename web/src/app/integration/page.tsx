'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import { Progress } from '@/components/ui/progress'
import { 
  Activity, 
  AlertCircle, 
  CheckCircle, 
  Clock, 
  Database, 
  Download, 
  ExternalLink, 
  FileText, 
  Globe, 
  Key, 
  Link, 
  Play, 
  Plus, 
  RefreshCw, 
  Settings, 
  Shield, 
  Upload, 
  Webhook, 
  Wifi, 
  X,
  Zap
} from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useRealtime } from '@/hooks/useRealtime'
import { apiClient } from '@/lib/api-client'
import { toast } from '@/hooks/use-toast'

interface Integration {
  id: string
  name: string
  type: 'ldap' | 'active_directory' | 'hvac' | 'fire_safety' | 'api' | 'webhook'
  status: 'connected' | 'disconnected' | 'error' | 'syncing'
  lastSync: string
  health: number
  endpoint?: string
  description: string
  config: Record<string, any>
  credentials?: {
    username?: string
    encrypted: boolean
  }
}

interface SyncStatus {
  integrationId: string
  status: 'idle' | 'syncing' | 'error' | 'completed'
  progress: number
  lastSync: string
  recordsProcessed: number
  errors: string[]
}

interface WebhookConfig {
  id: string
  name: string
  url: string
  events: string[]
  secret: string
  active: boolean
  lastTriggered?: string
  deliveryStatus: 'success' | 'failed' | 'pending'
}

interface ApiEndpoint {
  id: string
  name: string
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  url: string
  headers: Record<string, string>
  body?: string
  expectedStatus: number
  lastTested?: string
  status: 'success' | 'failed' | 'pending'
  responseTime?: number
}

export default function IntegrationPage() {
  const { user, hasPermission } = useAuth()
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [syncStatuses, setSyncStatuses] = useState<SyncStatus[]>([])
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([])
  const [apiEndpoints, setApiEndpoints] = useState<ApiEndpoint[]>([])
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')
  const [testResults, setTestResults] = useState<Record<string, any>>({})

  // Real-time updates for integration status
  useRealtime('integration_status', (data) => {
    setIntegrations(prev => prev.map(integration => 
      integration.id === data.integrationId 
        ? { ...integration, status: data.status, health: data.health }
        : integration
    ))
  })

  // Real-time updates for sync status
  useRealtime('sync_status', (data) => {
    setSyncStatuses(prev => prev.map(status => 
      status.integrationId === data.integrationId 
        ? { ...status, ...data }
        : status
    ))
  })

  useEffect(() => {
    loadIntegrations()
    loadSyncStatuses()
    loadWebhooks()
    loadApiEndpoints()
  }, [])

  const loadIntegrations = async () => {
    try {
      const response = await apiClient.get('/integrations')
      setIntegrations(response.data)
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load integrations',
        variant: 'destructive'
      })
    }
  }

  const loadSyncStatuses = async () => {
    try {
      const response = await apiClient.get('/integrations/sync-status')
      setSyncStatuses(response.data)
    } catch (error) {
      console.error('Failed to load sync statuses:', error)
    }
  }

  const loadWebhooks = async () => {
    try {
      const response = await apiClient.get('/integrations/webhooks')
      setWebhooks(response.data)
    } catch (error) {
      console.error('Failed to load webhooks:', error)
    }
  }

  const loadApiEndpoints = async () => {
    try {
      const response = await apiClient.get('/integrations/api-endpoints')
      setApiEndpoints(response.data)
    } catch (error) {
      console.error('Failed to load API endpoints:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const testIntegration = async (integrationId: string) => {
    try {
      const response = await apiClient.post(`/integrations/${integrationId}/test`)
      setTestResults(prev => ({ ...prev, [integrationId]: response.data }))
      toast({
        title: 'Test Completed',
        description: response.data.success ? 'Integration test passed' : 'Integration test failed'
      })
    } catch (error) {
      toast({
        title: 'Test Failed',
        description: 'Failed to test integration',
        variant: 'destructive'
      })
    }
  }

  const syncIntegration = async (integrationId: string) => {
    try {
      await apiClient.post(`/integrations/${integrationId}/sync`)
      toast({
        title: 'Sync Started',
        description: 'Integration sync has been initiated'
      })
    } catch (error) {
      toast({
        title: 'Sync Failed',
        description: 'Failed to start integration sync',
        variant: 'destructive'
      })
    }
  }

  const testApiEndpoint = async (endpoint: ApiEndpoint) => {
    try {
      const startTime = Date.now()
      const response = await apiClient.post('/integrations/test-endpoint', {
        method: endpoint.method,
        url: endpoint.url,
        headers: endpoint.headers,
        body: endpoint.body
      })
      const responseTime = Date.now() - startTime
      
      setApiEndpoints(prev => prev.map(ep => 
        ep.id === endpoint.id 
          ? { 
              ...ep, 
              status: response.status === endpoint.expectedStatus ? 'success' : 'failed',
              responseTime,
              lastTested: new Date().toISOString()
            }
          : ep
      ))
      
      toast({
        title: 'Endpoint Tested',
        description: `Response: ${response.status} (${responseTime}ms)`
      })
    } catch (error) {
      setApiEndpoints(prev => prev.map(ep => 
        ep.id === endpoint.id 
          ? { ...ep, status: 'failed', lastTested: new Date().toISOString() }
          : ep
      ))
      toast({
        title: 'Test Failed',
        description: 'Failed to test API endpoint',
        variant: 'destructive'
      })
    }
  }

  const triggerWebhook = async (webhookId: string) => {
    try {
      await apiClient.post(`/integrations/webhooks/${webhookId}/trigger`)
      toast({
        title: 'Webhook Triggered',
        description: 'Test webhook has been sent'
      })
    } catch (error) {
      toast({
        title: 'Webhook Failed',
        description: 'Failed to trigger webhook',
        variant: 'destructive'
      })
    }
  }

  const exportData = async (integrationId: string, format: 'csv' | 'json') => {
    try {
      const response = await apiClient.get(`/integrations/${integrationId}/export?format=${format}`, {
        responseType: 'blob'
      })
      
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `integration-data.${format}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      
      toast({
        title: 'Export Complete',
        description: `Data exported as ${format.toUpperCase()}`
      })
    } catch (error) {
      toast({
        title: 'Export Failed',
        description: 'Failed to export integration data',
        variant: 'destructive'
      })
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'disconnected':
        return <X className="h-4 w-4 text-gray-500" />
      case 'error':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      case 'syncing':
        return <RefreshCw className="h-4 w-4 text-blue-500 animate-spin" />
      default:
        return <Clock className="h-4 w-4 text-yellow-500" />
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ldap':
      case 'active_directory':
        return <Shield className="h-4 w-4" />
      case 'hvac':
        return <Zap className="h-4 w-4" />
      case 'fire_safety':
        return <AlertCircle className="h-4 w-4" />
      case 'api':
        return <Globe className="h-4 w-4" />
      case 'webhook':
        return <Webhook className="h-4 w-4" />
      default:
        return <Link className="h-4 w-4" />
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <RefreshCw className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold">Integration Management</h1>
          <p className="text-muted-foreground">
            Configure and monitor third-party system integrations
          </p>
        </div>
        {hasPermission('integrations:create') && (
          <Dialog>
            <DialogTrigger asChild>
              <Button>
                <Plus className="h-4 w-4 mr-2" />
                Add Integration
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Add New Integration</DialogTitle>
                <DialogDescription>
                  Configure a new third-party system integration
                </DialogDescription>
              </DialogHeader>
              <IntegrationForm onSave={loadIntegrations} />
            </DialogContent>
          </Dialog>
        )}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="connections">Connections</TabsTrigger>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="api-testing">API Testing</TabsTrigger>
          <TabsTrigger value="sync-status">Sync Status</TabsTrigger>
          <TabsTrigger value="logs">Logs</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Total Integrations</CardTitle>
                <Link className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{integrations.length}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Connected</CardTitle>
                <CheckCircle className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {integrations.filter(i => i.status === 'connected').length}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Syncing</CardTitle>
                <RefreshCw className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {integrations.filter(i => i.status === 'syncing').length}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Errors</CardTitle>
                <AlertCircle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {integrations.filter(i => i.status === 'error').length}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Integration Status</CardTitle>
              <CardDescription>
                Overview of all configured integrations and their current status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {integrations.map((integration) => (
                  <div key={integration.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-4">
                      {getTypeIcon(integration.type)}
                      <div>
                        <div className="font-medium">{integration.name}</div>
                        <div className="text-sm text-muted-foreground">{integration.description}</div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <div className="flex items-center space-x-2">
                          {getStatusIcon(integration.status)}
                          <Badge variant={integration.status === 'connected' ? 'default' : 'secondary'}>
                            {integration.status}
                          </Badge>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Health: {integration.health}%
                        </div>
                      </div>
                      <div className="flex space-x-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => testIntegration(integration.id)}
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => syncIntegration(integration.id)}
                        >
                          <RefreshCw className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setSelectedIntegration(integration)}
                        >
                          <Settings className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="connections" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {integrations.map((integration) => (
              <Card key={integration.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {getTypeIcon(integration.type)}
                      <CardTitle className="text-lg">{integration.name}</CardTitle>
                    </div>
                    {getStatusIcon(integration.status)}
                  </div>
                  <CardDescription>{integration.description}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <Label className="text-muted-foreground">Type</Label>
                      <div className="capitalize">{integration.type.replace('_', ' ')}</div>
                    </div>
                    <div>
                      <Label className="text-muted-foreground">Last Sync</Label>
                      <div>{new Date(integration.lastSync).toLocaleString()}</div>
                    </div>
                    <div>
                      <Label className="text-muted-foreground">Health</Label>
                      <div className="flex items-center space-x-2">
                        <Progress value={integration.health} className="flex-1" />
                        <span>{integration.health}%</span>
                      </div>
                    </div>
                    <div>
                      <Label className="text-muted-foreground">Endpoint</Label>
                      <div className="truncate">{integration.endpoint || 'N/A'}</div>
                    </div>
                  </div>
                  
                  <Separator />
                  
                  <div className="flex justify-between">
                    <div className="flex space-x-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => testIntegration(integration.id)}
                      >
                        <Play className="h-4 w-4 mr-1" />
                        Test
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => syncIntegration(integration.id)}
                      >
                        <RefreshCw className="h-4 w-4 mr-1" />
                        Sync
                      </Button>
                    </div>
                    <div className="flex space-x-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => exportData(integration.id, 'csv')}
                      >
                        <Download className="h-4 w-4 mr-1" />
                        CSV
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => exportData(integration.id, 'json')}
                      >
                        <Download className="h-4 w-4 mr-1" />
                        JSON
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="webhooks" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <div>
                  <CardTitle>Webhook Management</CardTitle>
                  <CardDescription>
                    Configure and manage webhook endpoints for real-time notifications
                  </CardDescription>
                </div>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Webhook
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {webhooks.map((webhook) => (
                  <div key={webhook.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-4">
                      <Webhook className="h-4 w-4" />
                      <div>
                        <div className="font-medium">{webhook.name}</div>
                        <div className="text-sm text-muted-foreground">{webhook.url}</div>
                        <div className="text-xs text-muted-foreground">
                          Events: {webhook.events.join(', ')}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <Badge variant={webhook.active ? 'default' : 'secondary'}>
                          {webhook.active ? 'Active' : 'Inactive'}
                        </Badge>
                        <div className="text-xs text-muted-foreground">
                          {webhook.lastTriggered && `Last: ${new Date(webhook.lastTriggered).toLocaleString()}`}
                        </div>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => triggerWebhook(webhook.id)}
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="api-testing" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex justify-between items-center">
                <div>
                  <CardTitle>API Endpoint Testing</CardTitle>
                  <CardDescription>
                    Test and validate API endpoints for integration health monitoring
                  </CardDescription>
                </div>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Endpoint
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {apiEndpoints.map((endpoint) => (
                  <div key={endpoint.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex items-center space-x-4">
                      <Globe className="h-4 w-4" />
                      <div>
                        <div className="font-medium">{endpoint.name}</div>
                        <div className="text-sm text-muted-foreground">
                          <Badge variant="outline" className="mr-2">{endpoint.method}</Badge>
                          {endpoint.url}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <div className="flex items-center space-x-2">
                          {endpoint.status === 'success' && <CheckCircle className="h-4 w-4 text-green-500" />}
                          {endpoint.status === 'failed' && <X className="h-4 w-4 text-red-500" />}
                          {endpoint.status === 'pending' && <Clock className="h-4 w-4 text-yellow-500" />}
                          <Badge variant={endpoint.status === 'success' ? 'default' : 'secondary'}>
                            {endpoint.status}
                          </Badge>
                        </div>
                        {endpoint.responseTime && (
                          <div className="text-xs text-muted-foreground">
                            {endpoint.responseTime}ms
                          </div>
                        )}
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => testApiEndpoint(endpoint)}
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sync-status" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Data Synchronization Status</CardTitle>
              <CardDescription>
                Monitor data sync progress and resolve synchronization errors
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {syncStatuses.map((status) => {
                  const integration = integrations.find(i => i.id === status.integrationId)
                  return (
                    <div key={status.integrationId} className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <div className="font-medium">{integration?.name}</div>
                        <Badge variant={status.status === 'completed' ? 'default' : 'secondary'}>
                          {status.status}
                        </Badge>
                      </div>
                      
                      {status.status === 'syncing' && (
                        <div className="space-y-2">
                          <Progress value={status.progress} />
                          <div className="text-sm text-muted-foreground">
                            {status.recordsProcessed} records processed
                          </div>
                        </div>
                      )}
                      
                      <div className="text-sm text-muted-foreground">
                        Last sync: {new Date(status.lastSync).toLocaleString()}
                      </div>
                      
                      {status.errors.length > 0 && (
                        <Alert className="mt-2">
                          <AlertCircle className="h-4 w-4" />
                          <AlertTitle>Sync Errors</AlertTitle>
                          <AlertDescription>
                            <ul className="list-disc list-inside">
                              {status.errors.map((error, index) => (
                                <li key={index}>{error}</li>
                              ))}
                            </ul>
                          </AlertDescription>
                        </Alert>
                      )}
                    </div>
                  )
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="logs" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Integration Logs</CardTitle>
              <CardDescription>
                View integration activity logs and troubleshoot issues
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-2 text-sm font-mono">
                  <div className="flex items-center space-x-2">
                    <span className="text-muted-foreground">2024-01-15 10:30:15</span>
                    <Badge variant="default">INFO</Badge>
                    <span>LDAP sync completed successfully - 150 users processed</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-muted-foreground">2024-01-15 10:25:32</span>
                    <Badge variant="secondary">WARN</Badge>
                    <span>HVAC system connection timeout - retrying in 30s</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-muted-foreground">2024-01-15 10:20:45</span>
                    <Badge variant="destructive">ERROR</Badge>
                    <span>Fire safety system authentication failed</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-muted-foreground">2024-01-15 10:15:12</span>
                    <Badge variant="default">INFO</Badge>
                    <span>Webhook delivered successfully to endpoint: /api/notifications</span>
                  </div>
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {selectedIntegration && (
        <IntegrationConfigDialog
          integration={selectedIntegration}
          onClose={() => setSelectedIntegration(null)}
          onSave={loadIntegrations}
        />
      )}
    </div>
  )
}

function IntegrationForm({ onSave }: { onSave: () => void }) {
  const [formData, setFormData] = useState({
    name: '',
    type: '',
    description: '',
    endpoint: '',
    username: '',
    password: ''
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await apiClient.post('/integrations', formData)
      toast({
        title: 'Integration Added',
        description: 'New integration has been configured successfully'
      })
      onSave()
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to add integration',
        variant: 'destructive'
      })
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label htmlFor="name">Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
            required
          />
        </div>
        <div>
          <Label htmlFor="type">Type</Label>
          <Select value={formData.type} onValueChange={(value) => setFormData(prev => ({ ...prev, type: value }))}>
            <SelectTrigger>
              <SelectValue placeholder="Select integration type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ldap">LDAP</SelectItem>
              <SelectItem value="active_directory">Active Directory</SelectItem>
              <SelectItem value="hvac">HVAC System</SelectItem>
              <SelectItem value="fire_safety">Fire Safety</SelectItem>
              <SelectItem value="api">Generic API</SelectItem>
              <SelectItem value="webhook">Webhook</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      
      <div>
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          value={formData.description}
          onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
        />
      </div>
      
      <div>
        <Label htmlFor="endpoint">Endpoint URL</Label>
        <Input
          id="endpoint"
          type="url"
          value={formData.endpoint}
          onChange={(e) => setFormData(prev => ({ ...prev, endpoint: e.target.value }))}
        />
      </div>
      
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label htmlFor="username">Username</Label>
          <Input
            id="username"
            value={formData.username}
            onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
          />
        </div>
        <div>
          <Label htmlFor="password">Password</Label>
          <Input
            id="password"
            type="password"
            value={formData.password}
            onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
          />
        </div>
      </div>
      
      <div className="flex justify-end space-x-2">
        <Button type="submit">Add Integration</Button>
      </div>
    </form>
  )
}

function IntegrationConfigDialog({ 
  integration, 
  onClose, 
  onSave 
}: { 
  integration: Integration
  onClose: () => void
  onSave: () => void 
}) {
  const [config, setConfig] = useState(integration.config)

  const handleSave = async () => {
    try {
      await apiClient.put(`/integrations/${integration.id}`, { config })
      toast({
        title: 'Configuration Updated',
        description: 'Integration configuration has been saved'
      })
      onSave()
      onClose()
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to update configuration',
        variant: 'destructive'
      })
    }
  }

  return (
    <Dialog open={true} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Configure {integration.name}</DialogTitle>
          <DialogDescription>
            Update integration settings and credentials
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-4">
          <div>
            <Label>Integration Type</Label>
            <div className="capitalize">{integration.type.replace('_', ' ')}</div>
          </div>
          
          <div>
            <Label htmlFor="endpoint">Endpoint URL</Label>
            <Input
              id="endpoint"
              value={config.endpoint || ''}
              onChange={(e) => setConfig(prev => ({ ...prev, endpoint: e.target.value }))}
            />
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="timeout">Timeout (seconds)</Label>
              <Input
                id="timeout"
                type="number"
                value={config.timeout || 30}
                onChange={(e) => setConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) }))}
              />
            </div>
            <div>
              <Label htmlFor="retries">Max Retries</Label>
              <Input
                id="retries"
                type="number"
                value={config.retries || 3}
                onChange={(e) => setConfig(prev => ({ ...prev, retries: parseInt(e.target.value) }))}
              />
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <Switch
              checked={config.enabled || false}
              onCheckedChange={(checked) => setConfig(prev => ({ ...prev, enabled: checked }))}
            />
            <Label>Enable Integration</Label>
          </div>
        </div>
        
        <div className="flex justify-end space-x-2">
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave}>Save Configuration</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}