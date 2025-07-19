'use client';

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  Search, 
  Wifi, 
  QrCode, 
  PencilLine,
  RefreshCw,
  Network,
  Camera,
  Shield,
  Thermometer,
  Cpu,
  AlertCircle,
  CheckCircle,
  Info
} from 'lucide-react';
import { apiClient } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';

interface DeviceDiscoveryStepProps {
  data: any;
  updateData: (updates: any) => void;
}

interface DiscoveredDevice {
  ipAddress: string;
  macAddress: string;
  manufacturer: string;
  model: string;
  deviceType: string;
  firmwareVersion?: string;
  capabilities?: string[];
  protocols?: string[];
  status?: 'online' | 'offline';
}

export const DeviceDiscoveryStep: React.FC<DeviceDiscoveryStepProps> = ({
  data,
  updateData
}) => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [discoveredDevices, setDiscoveredDevices] = useState<DiscoveredDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<DiscoveredDevice | null>(
    data.selectedDevice || null
  );
  const [manualEntry, setManualEntry] = useState({
    ipAddress: data.ipAddress || '',
    macAddress: data.macAddress || '',
    deviceType: data.deviceType || '',
    manufacturer: data.manufacturer || '',
    model: data.model || ''
  });
  const [qrData, setQrData] = useState('');

  const startNetworkScan = async () => {
    try {
      setIsScanning(true);
      setScanProgress(0);
      setDiscoveredDevices([]);

      // Simulate network scanning with progress
      const progressInterval = setInterval(() => {
        setScanProgress(prev => {
          if (prev >= 100) {
            clearInterval(progressInterval);
            return 100;
          }
          return prev + 10;
        });
      }, 500);

      // Mock discovered devices (in production, this would be real network scan)
      setTimeout(() => {
        const mockDevices: DiscoveredDevice[] = [
          {
            ipAddress: '192.168.1.100',
            macAddress: '00:06:8E:12:34:56',
            manufacturer: 'HID Global',
            model: 'VertX V100',
            deviceType: 'access_panel',
            firmwareVersion: '1.0.0',
            capabilities: ['osdp', 'http_api'],
            protocols: ['OSDP', 'HTTP'],
            status: 'online'
          },
          {
            ipAddress: '192.168.1.101',
            macAddress: '00:0C:29:45:67:89',
            manufacturer: 'Axis',
            model: 'P3375-V',
            deviceType: 'camera',
            firmwareVersion: '9.80.1',
            capabilities: ['onvif', 'rtsp', 'motion_detection'],
            protocols: ['ONVIF', 'RTSP', 'HTTP'],
            status: 'online'
          },
          {
            ipAddress: '192.168.1.102',
            macAddress: '00:1B:44:11:22:33',
            manufacturer: 'Honeywell',
            model: 'T7350',
            deviceType: 'sensor',
            firmwareVersion: '2.1.0',
            capabilities: ['temperature', 'humidity'],
            protocols: ['BACnet', 'Modbus'],
            status: 'online'
          }
        ];

        setDiscoveredDevices(mockDevices);
        setIsScanning(false);
        clearInterval(progressInterval);
        setScanProgress(100);
      }, 5000);

    } catch (error) {
      setIsScanning(false);
      toast({
        title: "Scan Failed",
        description: "Failed to scan network for devices",
        variant: "destructive"
      });
    }
  };

  const selectDevice = (device: DiscoveredDevice) => {
    setSelectedDevice(device);
    updateData({
      selectedDevice: device,
      deviceType: device.deviceType,
      manufacturer: device.manufacturer,
      model: device.model,
      ipAddress: device.ipAddress,
      macAddress: device.macAddress
    });
  };

  const handleManualEntry = () => {
    updateData({
      discoveryMethod: 'manual',
      deviceType: manualEntry.deviceType,
      manufacturer: manualEntry.manufacturer,
      model: manualEntry.model,
      ipAddress: manualEntry.ipAddress,
      macAddress: manualEntry.macAddress
    });
  };

  const processQrCode = () => {
    try {
      // Parse QR code data (assuming JSON format)
      const deviceData = JSON.parse(qrData);
      updateData({
        discoveryMethod: 'qrcode',
        ...deviceData
      });
      toast({
        title: "QR Code Processed",
        description: "Device information extracted successfully"
      });
    } catch (error) {
      toast({
        title: "Invalid QR Code",
        description: "Could not parse device information from QR code",
        variant: "destructive"
      });
    }
  };

  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType) {
      case 'camera': return <Camera className="h-5 w-5" />;
      case 'access_panel': return <Shield className="h-5 w-5" />;
      case 'sensor': return <Thermometer className="h-5 w-5" />;
      case 'controller': return <Cpu className="h-5 w-5" />;
      default: return <Network className="h-5 w-5" />;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Device Discovery</h3>
        <p className="text-sm text-muted-foreground mt-1">
          Choose how you want to add the device to the system
        </p>
      </div>

      <Tabs defaultValue={data.discoveryMethod || 'automatic'} onValueChange={(v) => updateData({ discoveryMethod: v })}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="automatic">
            <Wifi className="h-4 w-4 mr-2" />
            Network Scan
          </TabsTrigger>
          <TabsTrigger value="manual">
            <PencilLine className="h-4 w-4 mr-2" />
            Manual Entry
          </TabsTrigger>
          <TabsTrigger value="qrcode">
            <QrCode className="h-4 w-4 mr-2" />
            QR Code
          </TabsTrigger>
        </TabsList>

        <TabsContent value="automatic" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Network Discovery</CardTitle>
              <CardDescription>
                Automatically scan your network to discover compatible devices
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label>Network Range</Label>
                  <p className="text-sm text-muted-foreground">
                    Scanning 192.168.1.0/24
                  </p>
                </div>
                <Button 
                  onClick={startNetworkScan} 
                  disabled={isScanning}
                  variant="outline"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Search className="h-4 w-4 mr-2" />
                      Start Scan
                    </>
                  )}
                </Button>
              </div>

              {isScanning && (
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Scanning network...</span>
                    <span>{scanProgress}%</span>
                  </div>
                  <Progress value={scanProgress} />
                </div>
              )}

              {discoveredDevices.length > 0 && (
                <div className="space-y-2">
                  <Label>Discovered Devices ({discoveredDevices.length})</Label>
                  <div className="grid gap-2">
                    {discoveredDevices.map((device, index) => (
                      <Card 
                        key={index}
                        className={`cursor-pointer transition-colors ${
                          selectedDevice?.macAddress === device.macAddress 
                            ? 'border-primary bg-primary/5' 
                            : 'hover:border-primary/50'
                        }`}
                        onClick={() => selectDevice(device)}
                      >
                        <CardContent className="p-4">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start space-x-3">
                              <div className="p-2 bg-muted rounded-lg">
                                {getDeviceIcon(device.deviceType)}
                              </div>
                              <div className="space-y-1">
                                <div className="flex items-center gap-2">
                                  <span className="font-medium">
                                    {device.manufacturer} {device.model}
                                  </span>
                                  <Badge variant={device.status === 'online' ? 'default' : 'secondary'}>
                                    {device.status}
                                  </Badge>
                                </div>
                                <div className="text-sm text-muted-foreground space-y-0.5">
                                  <div>IP: {device.ipAddress}</div>
                                  <div>MAC: {device.macAddress}</div>
                                  {device.firmwareVersion && (
                                    <div>Firmware: v{device.firmwareVersion}</div>
                                  )}
                                </div>
                                {device.protocols && (
                                  <div className="flex gap-1 mt-2">
                                    {device.protocols.map(protocol => (
                                      <Badge key={protocol} variant="outline" className="text-xs">
                                        {protocol}
                                      </Badge>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                            {selectedDevice?.macAddress === device.macAddress && (
                              <CheckCircle className="h-5 w-5 text-primary" />
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>
              )}

              {!isScanning && discoveredDevices.length === 0 && (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    Click "Start Scan" to discover devices on your network
                  </AlertDescription>
                </Alert>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="manual" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Manual Device Entry</CardTitle>
              <CardDescription>
                Enter device information manually
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="deviceType">Device Type</Label>
                  <Select 
                    value={manualEntry.deviceType} 
                    onValueChange={(v) => setManualEntry({ ...manualEntry, deviceType: v })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select device type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="camera">Camera</SelectItem>
                      <SelectItem value="access_panel">Access Panel</SelectItem>
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
                    value={manualEntry.manufacturer}
                    onChange={(e) => setManualEntry({ ...manualEntry, manufacturer: e.target.value })}
                    placeholder="e.g., Axis, HID, Honeywell"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="model">Model</Label>
                <Input
                  id="model"
                  value={manualEntry.model}
                  onChange={(e) => setManualEntry({ ...manualEntry, model: e.target.value })}
                  placeholder="e.g., P3375-V, VertX V100"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="ipAddress">IP Address</Label>
                  <Input
                    id="ipAddress"
                    value={manualEntry.ipAddress}
                    onChange={(e) => setManualEntry({ ...manualEntry, ipAddress: e.target.value })}
                    placeholder="192.168.1.100"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="macAddress">MAC Address</Label>
                  <Input
                    id="macAddress"
                    value={manualEntry.macAddress}
                    onChange={(e) => setManualEntry({ ...manualEntry, macAddress: e.target.value })}
                    placeholder="00:00:00:00:00:00"
                  />
                </div>
              </div>

              <Button 
                onClick={handleManualEntry}
                disabled={!manualEntry.deviceType || !manualEntry.manufacturer || !manualEntry.model || !manualEntry.macAddress}
              >
                Continue with Manual Entry
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="qrcode" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>QR Code Provisioning</CardTitle>
              <CardDescription>
                Scan or enter the device provisioning QR code
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert>
                <Info className="h-4 w-4" />
                <AlertDescription>
                  QR codes should be generated by the device manufacturer and contain
                  all necessary provisioning information in JSON format.
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <Label htmlFor="qrData">QR Code Data</Label>
                <textarea
                  id="qrData"
                  className="w-full min-h-[100px] p-2 border rounded-md font-mono text-sm"
                  value={qrData}
                  onChange={(e) => setQrData(e.target.value)}
                  placeholder='{"deviceType":"camera","manufacturer":"Axis","model":"P3375-V","serialNumber":"ACCC8E123456","macAddress":"00:0C:29:45:67:89"}'
                />
              </div>

              <div className="flex items-center gap-4">
                <Button 
                  onClick={processQrCode}
                  disabled={!qrData}
                >
                  Process QR Code
                </Button>
                <Button variant="outline">
                  <Camera className="h-4 w-4 mr-2" />
                  Scan with Camera
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {selectedDevice && (
        <Alert>
          <CheckCircle className="h-4 w-4" />
          <AlertDescription>
            Selected device: {selectedDevice.manufacturer} {selectedDevice.model} ({selectedDevice.ipAddress})
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};