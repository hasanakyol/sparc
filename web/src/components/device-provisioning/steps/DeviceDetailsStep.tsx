'use client';

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { 
  MapPin,
  Building,
  Home,
  Layers,
  Info,
  AlertCircle
} from 'lucide-react';
import { apiClient } from '@/lib/api-client';

interface DeviceDetailsStepProps {
  data: any;
  updateData: (updates: any) => void;
}

interface Location {
  id: string;
  name: string;
  type: 'site' | 'building' | 'floor';
  parentId?: string;
}

export const DeviceDetailsStep: React.FC<DeviceDetailsStepProps> = ({
  data,
  updateData
}) => {
  const [locations, setLocations] = useState<{
    sites: Location[];
    buildings: Location[];
    floors: Location[];
  }>({
    sites: [],
    buildings: [],
    floors: []
  });
  const [zones, setZones] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  // Load locations on mount
  useEffect(() => {
    loadLocations();
  }, []);

  // Load buildings when site changes
  useEffect(() => {
    if (data.location?.siteId) {
      loadBuildings(data.location.siteId);
    }
  }, [data.location?.siteId]);

  // Load floors when building changes
  useEffect(() => {
    if (data.location?.buildingId) {
      loadFloors(data.location.buildingId);
    }
  }, [data.location?.buildingId]);

  const loadLocations = async () => {
    try {
      setLoading(true);
      // Mock data - in production, fetch from API
      setLocations({
        sites: [
          { id: 'site-1', name: 'Chicago Headquarters', type: 'site' },
          { id: 'site-2', name: 'New York Office', type: 'site' },
          { id: 'site-3', name: 'San Francisco Campus', type: 'site' }
        ],
        buildings: [],
        floors: []
      });
    } catch (error) {
      console.error('Failed to load locations:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadBuildings = async (siteId: string) => {
    try {
      // Mock data - in production, fetch based on siteId
      const buildingsMap: Record<string, Location[]> = {
        'site-1': [
          { id: 'bldg-1', name: 'Main Building', type: 'building', parentId: siteId },
          { id: 'bldg-2', name: 'Research Center', type: 'building', parentId: siteId },
          { id: 'bldg-3', name: 'Data Center', type: 'building', parentId: siteId }
        ],
        'site-2': [
          { id: 'bldg-4', name: 'Tower A', type: 'building', parentId: siteId },
          { id: 'bldg-5', name: 'Tower B', type: 'building', parentId: siteId }
        ],
        'site-3': [
          { id: 'bldg-6', name: 'North Building', type: 'building', parentId: siteId },
          { id: 'bldg-7', name: 'South Building', type: 'building', parentId: siteId }
        ]
      };
      
      setLocations(prev => ({
        ...prev,
        buildings: buildingsMap[siteId] || [],
        floors: [] // Reset floors when building changes
      }));
    } catch (error) {
      console.error('Failed to load buildings:', error);
    }
  };

  const loadFloors = async (buildingId: string) => {
    try {
      // Mock data - in production, fetch based on buildingId
      const floorsMap: Record<string, Location[]> = {
        'bldg-1': [
          { id: 'floor-1', name: 'Ground Floor', type: 'floor', parentId: buildingId },
          { id: 'floor-2', name: 'Floor 1', type: 'floor', parentId: buildingId },
          { id: 'floor-3', name: 'Floor 2', type: 'floor', parentId: buildingId },
          { id: 'floor-4', name: 'Floor 3', type: 'floor', parentId: buildingId }
        ],
        'bldg-2': [
          { id: 'floor-5', name: 'Basement', type: 'floor', parentId: buildingId },
          { id: 'floor-6', name: 'Ground Floor', type: 'floor', parentId: buildingId },
          { id: 'floor-7', name: 'Floor 1', type: 'floor', parentId: buildingId }
        ]
      };

      const zonesMap: Record<string, string[]> = {
        'floor-1': ['Reception', 'Lobby', 'Security Desk', 'Conference Room A'],
        'floor-2': ['Open Office', 'Meeting Room 1', 'Meeting Room 2', 'Break Room'],
        'floor-3': ['Executive Suite', 'Board Room', 'Private Offices'],
        'floor-4': ['IT Department', 'Server Room', 'Network Operations']
      };
      
      setLocations(prev => ({
        ...prev,
        floors: floorsMap[buildingId] || []
      }));

      // Load zones for the selected floor
      if (data.location?.floorId) {
        setZones(zonesMap[data.location.floorId] || []);
      }
    } catch (error) {
      console.error('Failed to load floors:', error);
    }
  };

  const validateField = (field: string, value: string): string | null => {
    switch (field) {
      case 'serialNumber':
        if (!value) return 'Serial number is required';
        if (value.length < 6) return 'Serial number must be at least 6 characters';
        return null;
        
      case 'macAddress':
        if (!value) return 'MAC address is required';
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        if (!macRegex.test(value)) return 'Invalid MAC address format';
        return null;
        
      case 'ipAddress':
        if (value) {
          const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
          if (!ipRegex.test(value)) return 'Invalid IP address format';
          const parts = value.split('.');
          if (parts.some(part => parseInt(part) > 255)) return 'Invalid IP address';
        }
        return null;
        
      default:
        return null;
    }
  };

  const handleFieldChange = (field: string, value: string) => {
    const error = validateField(field, value);
    setValidationErrors(prev => ({
      ...prev,
      [field]: error || ''
    }));

    updateData({
      [field]: value
    });
  };

  const handleLocationChange = (type: 'siteId' | 'buildingId' | 'floorId' | 'zone', value: string) => {
    updateData({
      location: {
        ...data.location,
        [type]: value,
        // Reset child selections when parent changes
        ...(type === 'siteId' && { buildingId: '', floorId: '', zone: '' }),
        ...(type === 'buildingId' && { floorId: '', zone: '' }),
        ...(type === 'floorId' && { zone: '' })
      }
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Device Details</h3>
        <p className="text-sm text-muted-foreground mt-1">
          Provide specific information about the device and its location
        </p>
      </div>

      {/* Device Information */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Device Information</CardTitle>
          <CardDescription>
            Basic device identification and specifications
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="deviceType">Device Type</Label>
              <Select
                value={data.deviceType}
                onValueChange={(v) => updateData({ deviceType: v })}
                disabled={data.discoveryMethod === 'automatic'}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select device type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="camera">IP Camera</SelectItem>
                  <SelectItem value="access_panel">Access Control Panel</SelectItem>
                  <SelectItem value="sensor">Environmental Sensor</SelectItem>
                  <SelectItem value="controller">Controller</SelectItem>
                  <SelectItem value="gateway">Gateway</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="manufacturer">Manufacturer</Label>
              <Input
                id="manufacturer"
                value={data.manufacturer}
                onChange={(e) => updateData({ manufacturer: e.target.value })}
                placeholder="e.g., Axis, HID, Honeywell"
                disabled={data.discoveryMethod === 'automatic'}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="model">Model</Label>
            <Input
              id="model"
              value={data.model}
              onChange={(e) => updateData({ model: e.target.value })}
              placeholder="e.g., P3375-V, VertX V100"
              disabled={data.discoveryMethod === 'automatic'}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="serialNumber">Serial Number *</Label>
              <Input
                id="serialNumber"
                value={data.serialNumber}
                onChange={(e) => handleFieldChange('serialNumber', e.target.value)}
                placeholder="e.g., ACCC8E123456"
                className={validationErrors.serialNumber ? 'border-destructive' : ''}
              />
              {validationErrors.serialNumber && (
                <p className="text-xs text-destructive">{validationErrors.serialNumber}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="macAddress">MAC Address *</Label>
              <Input
                id="macAddress"
                value={data.macAddress}
                onChange={(e) => handleFieldChange('macAddress', e.target.value.toUpperCase())}
                placeholder="00:00:00:00:00:00"
                disabled={data.discoveryMethod === 'automatic'}
                className={validationErrors.macAddress ? 'border-destructive' : ''}
              />
              {validationErrors.macAddress && (
                <p className="text-xs text-destructive">{validationErrors.macAddress}</p>
              )}
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="ipAddress">IP Address (Optional)</Label>
            <Input
              id="ipAddress"
              value={data.ipAddress || ''}
              onChange={(e) => handleFieldChange('ipAddress', e.target.value)}
              placeholder="192.168.1.100"
              disabled={data.discoveryMethod === 'automatic'}
              className={validationErrors.ipAddress ? 'border-destructive' : ''}
            />
            {validationErrors.ipAddress && (
              <p className="text-xs text-destructive">{validationErrors.ipAddress}</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Location Information */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Location Assignment</CardTitle>
          <CardDescription>
            Specify where this device will be installed
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="site">Site *</Label>
            <Select
              value={data.location?.siteId || ''}
              onValueChange={(v) => handleLocationChange('siteId', v)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select a site" />
                <MapPin className="h-4 w-4 ml-2 text-muted-foreground" />
              </SelectTrigger>
              <SelectContent>
                {locations.sites.map(site => (
                  <SelectItem key={site.id} value={site.id}>
                    {site.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="building">Building *</Label>
            <Select
              value={data.location?.buildingId || ''}
              onValueChange={(v) => handleLocationChange('buildingId', v)}
              disabled={!data.location?.siteId}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select a building" />
                <Building className="h-4 w-4 ml-2 text-muted-foreground" />
              </SelectTrigger>
              <SelectContent>
                {locations.buildings.map(building => (
                  <SelectItem key={building.id} value={building.id}>
                    {building.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="floor">Floor *</Label>
              <Select
                value={data.location?.floorId || ''}
                onValueChange={(v) => handleLocationChange('floorId', v)}
                disabled={!data.location?.buildingId}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a floor" />
                  <Layers className="h-4 w-4 ml-2 text-muted-foreground" />
                </SelectTrigger>
                <SelectContent>
                  {locations.floors.map(floor => (
                    <SelectItem key={floor.id} value={floor.id}>
                      {floor.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="zone">Zone (Optional)</Label>
              <Select
                value={data.location?.zone || ''}
                onValueChange={(v) => handleLocationChange('zone', v)}
                disabled={!data.location?.floorId}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a zone" />
                  <Home className="h-4 w-4 ml-2 text-muted-foreground" />
                </SelectTrigger>
                <SelectContent>
                  {zones.map(zone => (
                    <SelectItem key={zone} value={zone}>
                      {zone}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              The device location determines access policies and monitoring zones
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      {/* Additional Information */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Additional Information</CardTitle>
          <CardDescription>
            Optional metadata and notes
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              value={data.metadata?.description || ''}
              onChange={(e) => updateData({ 
                metadata: { ...data.metadata, description: e.target.value }
              })}
              placeholder="Add any additional notes or description about this device..."
              rows={3}
            />
          </div>

          <div className="space-y-2">
            <Label>Tags</Label>
            <Input
              placeholder="Enter tags separated by commas (e.g., critical, outdoor, backup)"
              value={data.metadata?.tags?.join(', ') || ''}
              onChange={(e) => updateData({
                metadata: { 
                  ...data.metadata, 
                  tags: e.target.value.split(',').map(t => t.trim()).filter(t => t)
                }
              })}
            />
            {data.metadata?.tags && data.metadata.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {data.metadata.tags.map((tag: string, index: number) => (
                  <Badge key={index} variant="secondary">
                    {tag}
                  </Badge>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Validation Summary */}
      {Object.values(validationErrors).some(error => error) && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            Please fix the validation errors before proceeding
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};