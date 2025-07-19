'use client';

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { 
  Shield,
  Key,
  Lock,
  Download,
  Copy,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Info,
  RefreshCw,
  Calendar,
  Fingerprint,
  FileText,
  ShieldCheck
} from 'lucide-react';
import { apiClient } from '@/lib/api-client';
import { toast } from '@/hooks/use-toast';

interface CertificateGenerationStepProps {
  data: any;
  updateData: (updates: any) => void;
  provisioningStatus?: any;
  isProvisioning?: boolean;
}

interface CertificateTemplate {
  id: string;
  name: string;
  description: string;
  validityDays: number;
  keyAlgorithm: string;
  keySize: number;
}

interface GeneratedCertificate {
  id: string;
  serialNumber: string;
  fingerprint: string;
  issuedAt: string;
  expiresAt: string;
  subject: {
    commonName: string;
    organization: string;
    organizationalUnit: string;
  };
}

export const CertificateGenerationStep: React.FC<CertificateGenerationStepProps> = ({
  data,
  updateData,
  provisioningStatus,
  isProvisioning
}) => {
  const [templates, setTemplates] = useState<CertificateTemplate[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<CertificateTemplate | null>(null);
  const [certificateStatus, setCertificateStatus] = useState<'pending' | 'generating' | 'completed' | 'failed'>('pending');
  const [generatedCertificate, setGeneratedCertificate] = useState<GeneratedCertificate | null>(null);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [verificationStatus, setVerificationStatus] = useState<{
    chainValid: boolean;
    signatureValid: boolean;
    notExpired: boolean;
    notRevoked: boolean;
  } | null>(null);

  useEffect(() => {
    loadCertificateTemplates();
  }, []);

  useEffect(() => {
    // Check provisioning status for certificate generation
    if (provisioningStatus?.steps) {
      const certStep = provisioningStatus.steps.find((s: any) => s.stepName === 'generate_certificate');
      if (certStep) {
        setCertificateStatus(
          certStep.status === 'completed' ? 'completed' :
          certStep.status === 'in_progress' ? 'generating' :
          certStep.status === 'failed' ? 'failed' : 'pending'
        );
        
        if (certStep.status === 'completed' && certStep.stepData?.certificateId) {
          // Load certificate details
          loadCertificateDetails(certStep.stepData.certificateId);
        }
      }
    }
  }, [provisioningStatus]);

  const loadCertificateTemplates = async () => {
    try {
      // Mock templates - in production, fetch from API
      const mockTemplates: CertificateTemplate[] = [
        {
          id: 'tpl-1',
          name: 'Standard Device Certificate',
          description: 'Default certificate for IoT devices with 1 year validity',
          validityDays: 365,
          keyAlgorithm: 'RSA',
          keySize: 2048
        },
        {
          id: 'tpl-2',
          name: 'High Security Certificate',
          description: 'Enhanced security certificate with 2 year validity',
          validityDays: 730,
          keyAlgorithm: 'RSA',
          keySize: 4096
        },
        {
          id: 'tpl-3',
          name: 'Short-term Certificate',
          description: 'Temporary certificate for testing (90 days)',
          validityDays: 90,
          keyAlgorithm: 'RSA',
          keySize: 2048
        }
      ];
      
      setTemplates(mockTemplates);
      
      // Select default template
      if (!data.certificateTemplate && mockTemplates.length > 0) {
        setSelectedTemplate(mockTemplates[0]);
        updateData({ certificateTemplate: mockTemplates[0].id });
      }
    } catch (error) {
      console.error('Failed to load certificate templates:', error);
    }
  };

  const loadCertificateDetails = async (certificateId: string) => {
    try {
      // Mock certificate details - in production, fetch from API
      const mockCertificate: GeneratedCertificate = {
        id: certificateId,
        serialNumber: 'AB:CD:EF:12:34:56:78:90',
        fingerprint: 'SHA256:1234567890ABCDEF1234567890ABCDEF12345678',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        subject: {
          commonName: `device-${data.serialNumber}`,
          organization: 'SPARC Security Platform',
          organizationalUnit: data.deviceType
        }
      };
      
      setGeneratedCertificate(mockCertificate);
      
      // Simulate verification
      setTimeout(() => {
        setVerificationStatus({
          chainValid: true,
          signatureValid: true,
          notExpired: true,
          notRevoked: true
        });
      }, 1000);
    } catch (error) {
      console.error('Failed to load certificate details:', error);
    }
  };

  const handleTemplateChange = (templateId: string) => {
    const template = templates.find(t => t.id === templateId);
    if (template) {
      setSelectedTemplate(template);
      updateData({ 
        certificateTemplate: templateId,
        certificateOptions: {
          validityDays: template.validityDays,
          keySize: template.keySize
        }
      });
    }
  };

  const downloadCertificate = async () => {
    try {
      setDownloadProgress(0);
      
      // Simulate download progress
      const interval = setInterval(() => {
        setDownloadProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            return 100;
          }
          return prev + 20;
        });
      }, 200);

      // In production, download actual certificate
      setTimeout(() => {
        const certificateData = {
          certificate: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
          privateKey: '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'
        };
        
        // Create download
        const blob = new Blob([JSON.stringify(certificateData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `device-cert-${data.serialNumber}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        toast({
          title: "Certificate Downloaded",
          description: "Certificate and private key saved securely"
        });
      }, 1500);
    } catch (error) {
      toast({
        title: "Download Failed",
        description: "Failed to download certificate",
        variant: "destructive"
      });
    }
  };

  const copyCertificateInfo = (info: string) => {
    navigator.clipboard.writeText(info);
    toast({
      title: "Copied",
      description: "Certificate information copied to clipboard"
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-medium">Security Certificate</h3>
        <p className="text-sm text-muted-foreground mt-1">
          Generate and install a unique certificate for secure device authentication
        </p>
      </div>

      {/* Certificate Options */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Certificate Configuration</CardTitle>
          <CardDescription>
            Choose certificate template and generation options
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label htmlFor="generate-cert">Generate Certificate</Label>
              <p className="text-sm text-muted-foreground">
                Create a unique X.509 certificate for this device
              </p>
            </div>
            <Switch
              id="generate-cert"
              checked={data.generateCertificate}
              onCheckedChange={(checked) => updateData({ generateCertificate: checked })}
              disabled={isProvisioning}
            />
          </div>

          {data.generateCertificate && (
            <>
              <div className="space-y-2">
                <Label>Certificate Template</Label>
                <RadioGroup
                  value={data.certificateTemplate}
                  onValueChange={handleTemplateChange}
                  disabled={isProvisioning}
                >
                  {templates.map(template => (
                    <div key={template.id} className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-muted/50">
                      <RadioGroupItem value={template.id} id={template.id} className="mt-1" />
                      <div className="flex-1 space-y-1">
                        <Label htmlFor={template.id} className="font-medium cursor-pointer">
                          {template.name}
                        </Label>
                        <p className="text-sm text-muted-foreground">
                          {template.description}
                        </p>
                        <div className="flex gap-4 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Calendar className="h-3 w-3" />
                            {template.validityDays} days
                          </span>
                          <span className="flex items-center gap-1">
                            <Key className="h-3 w-3" />
                            {template.keyAlgorithm} {template.keySize}-bit
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </RadioGroup>
              </div>

              <Alert>
                <Shield className="h-4 w-4" />
                <AlertTitle>Certificate Authority</AlertTitle>
                <AlertDescription>
                  Certificates will be signed by your organization's trusted Certificate Authority
                </AlertDescription>
              </Alert>
            </>
          )}
        </CardContent>
      </Card>

      {/* Certificate Generation Status */}
      {isProvisioning && data.generateCertificate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Generation Status</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {certificateStatus === 'generating' && (
                  <RefreshCw className="h-5 w-5 animate-spin text-primary" />
                )}
                {certificateStatus === 'completed' && (
                  <CheckCircle className="h-5 w-5 text-green-500" />
                )}
                {certificateStatus === 'failed' && (
                  <XCircle className="h-5 w-5 text-destructive" />
                )}
                {certificateStatus === 'pending' && (
                  <Shield className="h-5 w-5 text-muted-foreground" />
                )}
                <span className="font-medium">
                  {certificateStatus === 'generating' && 'Generating certificate...'}
                  {certificateStatus === 'completed' && 'Certificate generated successfully'}
                  {certificateStatus === 'failed' && 'Certificate generation failed'}
                  {certificateStatus === 'pending' && 'Waiting to generate certificate'}
                </span>
              </div>
              <Badge variant={
                certificateStatus === 'completed' ? 'default' :
                certificateStatus === 'failed' ? 'destructive' :
                'secondary'
              }>
                {certificateStatus}
              </Badge>
            </div>

            {certificateStatus === 'generating' && (
              <Progress value={33} className="h-2" />
            )}
          </CardContent>
        </Card>
      )}

      {/* Generated Certificate Details */}
      {generatedCertificate && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Certificate Details</CardTitle>
            <CardDescription>
              Generated certificate information
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Fingerprint className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">Serial Number</span>
                  </div>
                  <p className="text-xs font-mono">{generatedCertificate.serialNumber}</p>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => copyCertificateInfo(generatedCertificate.serialNumber)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>

              <div className="flex items-center justify-between p-3 bg-muted rounded-lg">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Lock className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">Fingerprint</span>
                  </div>
                  <p className="text-xs font-mono break-all">{generatedCertificate.fingerprint}</p>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => copyCertificateInfo(generatedCertificate.fingerprint)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-muted rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Calendar className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">Issued</span>
                  </div>
                  <p className="text-xs">
                    {new Date(generatedCertificate.issuedAt).toLocaleDateString()}
                  </p>
                </div>
                <div className="p-3 bg-muted rounded-lg">
                  <div className="flex items-center gap-2 mb-1">
                    <Calendar className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">Expires</span>
                  </div>
                  <p className="text-xs">
                    {new Date(generatedCertificate.expiresAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
            </div>

            {/* Certificate Verification */}
            {verificationStatus && (
              <div className="space-y-2">
                <Label>Certificate Verification</Label>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    {verificationStatus.chainValid ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-destructive" />
                    )}
                    <span className="text-sm">Certificate chain valid</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {verificationStatus.signatureValid ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-destructive" />
                    )}
                    <span className="text-sm">Digital signature verified</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {verificationStatus.notExpired ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-destructive" />
                    )}
                    <span className="text-sm">Certificate not expired</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {verificationStatus.notRevoked ? (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-destructive" />
                    )}
                    <span className="text-sm">Certificate not revoked</span>
                  </div>
                </div>
              </div>
            )}

            <div className="flex gap-2">
              <Button
                onClick={downloadCertificate}
                disabled={downloadProgress > 0 && downloadProgress < 100}
                className="flex-1"
              >
                {downloadProgress > 0 && downloadProgress < 100 ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Downloading... {downloadProgress}%
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4 mr-2" />
                    Download Certificate
                  </>
                )}
              </Button>
              <Button variant="outline">
                <FileText className="h-4 w-4 mr-2" />
                View Details
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Security Notice */}
      <Alert>
        <ShieldCheck className="h-4 w-4" />
        <AlertTitle>Security Best Practices</AlertTitle>
        <AlertDescription className="space-y-2 mt-2">
          <p>• Store private keys securely and never share them</p>
          <p>• Use certificate pinning to prevent man-in-the-middle attacks</p>
          <p>• Monitor certificate expiration and renew before expiry</p>
          <p>• Implement proper certificate revocation procedures</p>
        </AlertDescription>
      </Alert>
    </div>
  );
};