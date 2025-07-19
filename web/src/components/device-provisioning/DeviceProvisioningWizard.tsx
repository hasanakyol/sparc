'use client';

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useAuth } from '@/hooks/useAuth';
import { apiClient } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';
import { 
  ChevronRight, 
  ChevronLeft, 
  CheckCircle, 
  XCircle,
  Shield,
  Wifi,
  Settings,
  FileCheck,
  Loader2
} from 'lucide-react';

// Import wizard steps
import { DeviceDiscoveryStep } from './steps/DeviceDiscoveryStep';
import { DeviceDetailsStep } from './steps/DeviceDetailsStep';
import { CertificateGenerationStep } from './steps/CertificateGenerationStep';
import { ConfigurationStep } from './steps/ConfigurationStep';
import { ValidationStep } from './steps/ValidationStep';
import { ActivationStep } from './steps/ActivationStep';

interface DeviceProvisioningData {
  // Discovery
  discoveryMethod: 'automatic' | 'manual' | 'qrcode';
  discoveredDevices?: any[];
  selectedDevice?: any;
  
  // Device Details
  deviceType: string;
  manufacturer: string;
  model: string;
  serialNumber: string;
  macAddress: string;
  ipAddress?: string;
  location: {
    siteId: string;
    buildingId: string;
    floorId: string;
    zone?: string;
  };
  
  // Certificate
  generateCertificate: boolean;
  certificateTemplate?: string;
  certificateOptions?: {
    validityDays: number;
    keySize: number;
  };
  
  // Configuration
  configurationTemplate?: string;
  customConfiguration?: Record<string, any>;
  
  // Validation
  validationResults?: {
    connectivity: boolean;
    authentication: boolean;
    configuration: boolean;
    security: boolean;
  };
  
  // Activation
  autoActivate: boolean;
  activationSchedule?: 'immediate' | 'scheduled';
  scheduledTime?: Date;
}

interface WizardStep {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  component: React.ComponentType<any>;
  validation?: (data: DeviceProvisioningData) => boolean;
}

const wizardSteps: WizardStep[] = [
  {
    id: 'discovery',
    title: 'Device Discovery',
    description: 'Find and identify the device to provision',
    icon: <Wifi className="h-5 w-5" />,
    component: DeviceDiscoveryStep,
    validation: (data) => !!data.selectedDevice || data.discoveryMethod === 'manual'
  },
  {
    id: 'details',
    title: 'Device Details',
    description: 'Specify device information and location',
    icon: <FileCheck className="h-5 w-5" />,
    component: DeviceDetailsStep,
    validation: (data) => !!(data.deviceType && data.manufacturer && data.model && 
                            data.serialNumber && data.macAddress && data.location.siteId)
  },
  {
    id: 'certificate',
    title: 'Security Certificate',
    description: 'Generate and install device certificate',
    icon: <Shield className="h-5 w-5" />,
    component: CertificateGenerationStep
  },
  {
    id: 'configuration',
    title: 'Configuration',
    description: 'Apply device configuration and policies',
    icon: <Settings className="h-5 w-5" />,
    component: ConfigurationStep
  },
  {
    id: 'validation',
    title: 'Validation',
    description: 'Test device connectivity and configuration',
    icon: <CheckCircle className="h-5 w-5" />,
    component: ValidationStep
  },
  {
    id: 'activation',
    title: 'Activation',
    description: 'Activate device in production',
    icon: <CheckCircle className="h-5 w-5" />,
    component: ActivationStep
  }
];

interface DeviceProvisioningWizardProps {
  onComplete: (deviceId: string) => void;
  onCancel: () => void;
  initialData?: Partial<DeviceProvisioningData>;
}

export const DeviceProvisioningWizard: React.FC<DeviceProvisioningWizardProps> = ({
  onComplete,
  onCancel,
  initialData = {}
}) => {
  const { user } = useAuth();
  const [currentStep, setCurrentStep] = useState(0);
  const [provisioningData, setProvisioningData] = useState<DeviceProvisioningData>({
    discoveryMethod: 'automatic',
    deviceType: '',
    manufacturer: '',
    model: '',
    serialNumber: '',
    macAddress: '',
    location: {
      siteId: '',
      buildingId: '',
      floorId: ''
    },
    generateCertificate: true,
    autoActivate: true,
    ...initialData
  });
  const [isProvisioning, setIsProvisioning] = useState(false);
  const [provisioningId, setProvisioningId] = useState<string | null>(null);
  const [provisioningStatus, setProvisioningStatus] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const currentStepConfig = wizardSteps[currentStep];
  const StepComponent = currentStepConfig.component;
  const progress = ((currentStep + 1) / wizardSteps.length) * 100;

  const canProceed = () => {
    if (currentStepConfig.validation) {
      return currentStepConfig.validation(provisioningData);
    }
    return true;
  };

  const handleNext = async () => {
    if (!canProceed()) {
      toast({
        title: "Validation Error",
        description: "Please complete all required fields before proceeding",
        variant: "destructive"
      });
      return;
    }

    // Start provisioning after details step
    if (currentStep === 1 && !provisioningId) {
      await startProvisioning();
    }

    if (currentStep < wizardSteps.length - 1) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handlePrevious = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const updateData = (updates: Partial<DeviceProvisioningData>) => {
    setProvisioningData(prev => ({ ...prev, ...updates }));
  };

  const startProvisioning = async () => {
    try {
      setIsProvisioning(true);
      setError(null);

      const response = await apiClient.post('/provisioning', {
        deviceType: provisioningData.deviceType,
        manufacturer: provisioningData.manufacturer,
        model: provisioningData.model,
        serialNumber: provisioningData.serialNumber,
        macAddress: provisioningData.macAddress,
        ipAddress: provisioningData.ipAddress,
        location: provisioningData.location,
        options: {
          templateId: provisioningData.configurationTemplate,
          generateCertificate: provisioningData.generateCertificate,
          autoActivate: provisioningData.autoActivate,
          customConfig: provisioningData.customConfiguration
        }
      });

      setProvisioningId(response.data.provisioningId);
      
      // Start polling for status
      pollProvisioningStatus(response.data.provisioningId);
    } catch (error: any) {
      setError(error.response?.data?.message || 'Failed to start provisioning');
      setIsProvisioning(false);
    }
  };

  const pollProvisioningStatus = async (id: string) => {
    const checkStatus = async () => {
      try {
        const response = await apiClient.get(`/provisioning/${id}/status`);
        setProvisioningStatus(response.data.provisioning);

        if (response.data.provisioning.status === 'completed') {
          setIsProvisioning(false);
          onComplete(response.data.provisioning.deviceId);
        } else if (response.data.provisioning.status === 'failed') {
          setError(response.data.provisioning.errorMessage || 'Provisioning failed');
          setIsProvisioning(false);
        } else {
          // Continue polling
          setTimeout(checkStatus, 2000);
        }
      } catch (error) {
        console.error('Failed to check provisioning status:', error);
        setTimeout(checkStatus, 5000);
      }
    };

    checkStatus();
  };

  const cancelProvisioning = async () => {
    if (provisioningId) {
      try {
        await apiClient.post(`/provisioning/${provisioningId}/cancel`);
      } catch (error) {
        console.error('Failed to cancel provisioning:', error);
      }
    }
    onCancel();
  };

  // Set up WebSocket connection for real-time updates
  useEffect(() => {
    if (!provisioningId) return;

    const ws = new WebSocket(`${process.env.NEXT_PUBLIC_WS_URL}/provisioning?tenantId=${user?.tenantId}`);

    ws.onopen = () => {
      ws.send(JSON.stringify({
        type: 'subscribe',
        channel: `provisioning:${provisioningId}`
      }));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.type === 'provisioning_progress' && data.provisioningId === provisioningId) {
        // Update UI based on progress
        console.log('Provisioning progress:', data);
      }
    };

    return () => {
      ws.close();
    };
  }, [provisioningId, user?.tenantId]);

  return (
    <div className="max-w-4xl mx-auto p-6">
      <Card>
        <CardHeader>
          <CardTitle>Device Provisioning Wizard</CardTitle>
          <CardDescription>
            Follow the steps to securely provision a new device
          </CardDescription>
          <Progress value={progress} className="mt-4" />
        </CardHeader>
        <CardContent>
          {/* Step Indicators */}
          <div className="flex justify-between mb-8">
            {wizardSteps.map((step, index) => (
              <div
                key={step.id}
                className={`flex flex-col items-center ${
                  index <= currentStep ? 'text-primary' : 'text-muted-foreground'
                }`}
              >
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center border-2 ${
                    index < currentStep
                      ? 'bg-primary text-primary-foreground border-primary'
                      : index === currentStep
                      ? 'border-primary'
                      : 'border-muted-foreground'
                  }`}
                >
                  {index < currentStep ? (
                    <CheckCircle className="h-5 w-5" />
                  ) : (
                    step.icon
                  )}
                </div>
                <span className="text-xs mt-1 text-center max-w-20">{step.title}</span>
              </div>
            ))}
          </div>

          {/* Error Alert */}
          {error && (
            <Alert variant="destructive" className="mb-4">
              <XCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {/* Step Content */}
          <div className="min-h-[400px]">
            <StepComponent
              data={provisioningData}
              updateData={updateData}
              provisioningStatus={provisioningStatus}
              isProvisioning={isProvisioning}
            />
          </div>

          {/* Navigation */}
          <div className="flex justify-between mt-6">
            <Button
              variant="outline"
              onClick={currentStep === 0 ? cancelProvisioning : handlePrevious}
              disabled={isProvisioning}
            >
              <ChevronLeft className="h-4 w-4 mr-2" />
              {currentStep === 0 ? 'Cancel' : 'Previous'}
            </Button>

            {currentStep < wizardSteps.length - 1 ? (
              <Button
                onClick={handleNext}
                disabled={!canProceed() || isProvisioning}
              >
                {isProvisioning && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Next
                <ChevronRight className="h-4 w-4 ml-2" />
              </Button>
            ) : (
              <Button
                onClick={() => onComplete(provisioningStatus?.deviceId)}
                disabled={provisioningStatus?.status !== 'completed'}
              >
                Complete
                <CheckCircle className="h-4 w-4 ml-2" />
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};