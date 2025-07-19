#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SparcStack } from '../lib/sparc-stack';
import { SecurityStack } from '../lib/security-stack';
import { MonitoringStack } from '../lib/monitoring-stack';

/**
 * SPARC Platform Infrastructure Application
 * 
 * This CDK application deploys the complete SPARC unified access control and video surveillance platform
 * infrastructure across multiple environments (dev, staging, prod) with proper stack dependencies,
 * environment-specific configurations, and comprehensive resource tagging.
 * 
 * Architecture Overview:
 * - SecurityStack: KMS keys, certificates, WAF, GuardDuty, security policies
 * - SparcStack: Core infrastructure (VPC, EKS, RDS, Redis, S3, CloudFront, etc.)
 * - MonitoringStack: CloudWatch, X-Ray, CloudTrail, SNS, dashboards
 * 
 * Deployment Models Supported:
 * - SSP-managed: Service provider hosting multiple client organizations
 * - Self-managed: Enterprise managing their own infrastructure
 * - Hybrid: Shared responsibility between SSP and enterprise
 */

const app = new cdk.App();

// Get environment configuration from context or environment variables
const environment = app.node.tryGetContext('environment') || process.env.ENVIRONMENT || 'dev';
const region = app.node.tryGetContext('region') || process.env.AWS_REGION || 'us-east-1';
const account = app.node.tryGetContext('account') || process.env.CDK_DEFAULT_ACCOUNT;

// Validate required parameters
if (!account) {
  throw new Error('AWS account ID must be specified via CDK_DEFAULT_ACCOUNT environment variable or --context account=<account-id>');
}

if (!['dev', 'staging', 'prod'].includes(environment)) {
  throw new Error('Environment must be one of: dev, staging, prod');
}

// Environment-specific configuration
interface EnvironmentConfig {
  domainName?: string;
  certificateArn?: string;
  enableDeletionProtection: boolean;
  enableBackup: boolean;
  enableMultiAz: boolean;
  enablePerformanceInsights: boolean;
  logRetentionDays: number;
  backupRetentionDays: number;
  enableGuardDuty: boolean;
  enableWaf: boolean;
  enableCloudTrail: boolean;
  enableVpcFlowLogs: boolean;
  enableConfigRules: boolean;
  enableSecurityHub: boolean;
  minNodeCount: number;
  maxNodeCount: number;
  desiredNodeCount: number;
  instanceType: string;
  videoInstanceType: string;
  databaseInstanceType: string;
  redisInstanceType: string;
  opensearchInstanceType: string;
  enableOpensearchMultiAz: boolean;
  enableOpensearchDedicatedMaster: boolean;
  storageRetentionDays: number;
  videoRetentionDays: number;
  auditLogRetentionDays: number;
}

const environmentConfigs: Record<string, EnvironmentConfig> = {
  dev: {
    enableDeletionProtection: false,
    enableBackup: false,
    enableMultiAz: false,
    enablePerformanceInsights: false,
    logRetentionDays: 7,
    backupRetentionDays: 7,
    enableGuardDuty: false,
    enableWaf: false,
    enableCloudTrail: true,
    enableVpcFlowLogs: true,
    enableConfigRules: false,
    enableSecurityHub: false,
    minNodeCount: 1,
    maxNodeCount: 5,
    desiredNodeCount: 2,
    instanceType: 'm5.large',
    videoInstanceType: 'c5n.large',
    databaseInstanceType: 'r6g.large',
    redisInstanceType: 'cache.r7g.large',
    opensearchInstanceType: 't3.small.search',
    enableOpensearchMultiAz: false,
    enableOpensearchDedicatedMaster: false,
    storageRetentionDays: 30,
    videoRetentionDays: 30,
    auditLogRetentionDays: 90,
  },
  staging: {
    domainName: app.node.tryGetContext('stagingDomain'),
    certificateArn: app.node.tryGetContext('stagingCertificateArn'),
    enableDeletionProtection: false,
    enableBackup: true,
    enableMultiAz: true,
    enablePerformanceInsights: true,
    logRetentionDays: 30,
    backupRetentionDays: 14,
    enableGuardDuty: true,
    enableWaf: true,
    enableCloudTrail: true,
    enableVpcFlowLogs: true,
    enableConfigRules: true,
    enableSecurityHub: true,
    minNodeCount: 2,
    maxNodeCount: 10,
    desiredNodeCount: 4,
    instanceType: 'm5.xlarge',
    videoInstanceType: 'c5n.xlarge',
    databaseInstanceType: 'r6g.xlarge',
    redisInstanceType: 'cache.r7g.xlarge',
    opensearchInstanceType: 'r6g.large.search',
    enableOpensearchMultiAz: true,
    enableOpensearchDedicatedMaster: true,
    storageRetentionDays: 90,
    videoRetentionDays: 90,
    auditLogRetentionDays: 365,
  },
  prod: {
    domainName: app.node.tryGetContext('prodDomain'),
    certificateArn: app.node.tryGetContext('prodCertificateArn'),
    enableDeletionProtection: true,
    enableBackup: true,
    enableMultiAz: true,
    enablePerformanceInsights: true,
    logRetentionDays: 90,
    backupRetentionDays: 30,
    enableGuardDuty: true,
    enableWaf: true,
    enableCloudTrail: true,
    enableVpcFlowLogs: true,
    enableConfigRules: true,
    enableSecurityHub: true,
    minNodeCount: 3,
    maxNodeCount: 20,
    desiredNodeCount: 6,
    instanceType: 'm5.xlarge',
    videoInstanceType: 'c5n.2xlarge',
    databaseInstanceType: 'r6g.2xlarge',
    redisInstanceType: 'cache.r7g.xlarge',
    opensearchInstanceType: 'r6g.large.search',
    enableOpensearchMultiAz: true,
    enableOpensearchDedicatedMaster: true,
    storageRetentionDays: 2555, // 7 years for compliance
    videoRetentionDays: 2555, // 7 years for compliance
    auditLogRetentionDays: 2555, // 7 years for compliance
  },
};

const config = environmentConfigs[environment];

// Common stack properties
const commonProps: cdk.StackProps = {
  env: {
    account,
    region,
  },
  description: `SPARC Platform Infrastructure - ${environment.toUpperCase()}`,
  tags: {
    Project: 'SPARC',
    Environment: environment,
    ManagedBy: 'CDK',
    CostCenter: 'Security',
    Owner: 'SPARC-Platform-Team',
    Backup: config.enableBackup ? 'Required' : 'Optional',
    Compliance: 'SOX-HIPAA-PCI',
    DataClassification: 'Confidential',
    BusinessUnit: 'Security-Operations',
    Application: 'Unified-Access-Control-Video-Surveillance',
    Version: app.node.tryGetContext('version') || '1.0.0',
    DeploymentModel: app.node.tryGetContext('deploymentModel') || 'self-managed',
    TenantType: app.node.tryGetContext('tenantType') || 'enterprise',
    Region: region,
    LastDeployed: new Date().toISOString(),
  },
  terminationProtection: config.enableDeletionProtection,
};

// Create stack naming convention
const stackPrefix = `sparc-${environment}`;

// 1. Security Stack - Must be deployed first
// Contains KMS keys, certificates, security policies, and compliance resources
const securityStack = new SecurityStack(app, `${stackPrefix}-security`, {
  ...commonProps,
  stackName: `${stackPrefix}-security-stack`,
  description: `SPARC Security Infrastructure - ${environment.toUpperCase()} - KMS, WAF, GuardDuty, Security Policies`,
  environment: environment as 'dev' | 'staging' | 'prod',
  enableGuardDuty: config.enableGuardDuty,
  enableWaf: config.enableWaf,
  enableConfigRules: config.enableConfigRules,
  enableSecurityHub: config.enableSecurityHub,
  auditLogRetentionDays: config.auditLogRetentionDays,
});

// 2. Core Infrastructure Stack - Depends on Security Stack
// Contains VPC, EKS, RDS, Redis, S3, CloudFront, and core platform resources
const sparcStack = new SparcStack(app, `${stackPrefix}-core`, {
  ...commonProps,
  stackName: `${stackPrefix}-core-infrastructure-stack`,
  description: `SPARC Core Infrastructure - ${environment.toUpperCase()} - VPC, EKS, RDS, Redis, S3, CloudFront`,
  environment: environment as 'dev' | 'staging' | 'prod',
  domainName: config.domainName,
  certificateArn: config.certificateArn,
  kmsKey: securityStack.kmsKey,
  webAclArn: securityStack.webAclArn,
  minNodeCount: config.minNodeCount,
  maxNodeCount: config.maxNodeCount,
  desiredNodeCount: config.desiredNodeCount,
  instanceType: config.instanceType,
  videoInstanceType: config.videoInstanceType,
  databaseInstanceType: config.databaseInstanceType,
  redisInstanceType: config.redisInstanceType,
  opensearchInstanceType: config.opensearchInstanceType,
  enableMultiAz: config.enableMultiAz,
  enablePerformanceInsights: config.enablePerformanceInsights,
  enableOpensearchMultiAz: config.enableOpensearchMultiAz,
  enableOpensearchDedicatedMaster: config.enableOpensearchDedicatedMaster,
  backupRetentionDays: config.backupRetentionDays,
  storageRetentionDays: config.storageRetentionDays,
  videoRetentionDays: config.videoRetentionDays,
  enableVpcFlowLogs: config.enableVpcFlowLogs,
});

// Add explicit dependency
sparcStack.addDependency(securityStack);

// 3. Monitoring Stack - Depends on Core Infrastructure
// Contains CloudWatch, X-Ray, CloudTrail, SNS, and observability resources
const monitoringStack = new MonitoringStack(app, `${stackPrefix}-monitoring`, {
  ...commonProps,
  stackName: `${stackPrefix}-monitoring-observability-stack`,
  description: `SPARC Monitoring & Observability - ${environment.toUpperCase()} - CloudWatch, X-Ray, CloudTrail, SNS`,
  environment: environment as 'dev' | 'staging' | 'prod',
  vpc: sparcStack.vpc,
  eksCluster: sparcStack.eksCluster,
  database: sparcStack.database,
  redisCluster: sparcStack.redisCluster,
  opensearchDomain: sparcStack.opensearchDomain,
  kmsKey: securityStack.kmsKey,
  enableCloudTrail: config.enableCloudTrail,
  logRetentionDays: config.logRetentionDays,
  auditLogRetentionDays: config.auditLogRetentionDays,
  alertsTopicArn: sparcStack.alertsTopicArn,
  systemTopicArn: sparcStack.systemTopicArn,
  maintenanceTopicArn: sparcStack.maintenanceTopicArn,
});

// Add explicit dependency
monitoringStack.addDependency(sparcStack);

// Output deployment information
new cdk.CfnOutput(sparcStack, 'DeploymentInfo', {
  value: JSON.stringify({
    environment,
    region,
    account,
    timestamp: new Date().toISOString(),
    stacks: [
      `${stackPrefix}-security`,
      `${stackPrefix}-core`,
      `${stackPrefix}-monitoring`,
    ],
    deploymentModel: app.node.tryGetContext('deploymentModel') || 'self-managed',
    version: app.node.tryGetContext('version') || '1.0.0',
  }),
  description: 'SPARC Platform deployment information',
});

// Environment-specific outputs for integration
new cdk.CfnOutput(sparcStack, 'PlatformEndpoints', {
  value: JSON.stringify({
    apiGateway: `https://${sparcStack.applicationLoadBalancer.loadBalancerDnsName}/api`,
    webInterface: config.domainName ? `https://${config.domainName}` : `https://${sparcStack.cloudFrontDistribution.distributionDomainName}`,
    videoStreaming: `https://${sparcStack.cloudFrontDistribution.distributionDomainName}/hls`,
    database: sparcStack.database.clusterEndpoint.hostname,
    redis: sparcStack.redisCluster.attrRedisEndpointAddress,
    opensearch: sparcStack.opensearchDomain.domainEndpoint,
  }),
  description: 'SPARC Platform service endpoints',
});

// Resource limits and quotas for multi-tenant management
new cdk.CfnOutput(sparcStack, 'PlatformLimits', {
  value: JSON.stringify({
    maxDoors: 10000, // Requirement 12: Support up to 10,000 doors
    maxVideoStreams: 1000, // Requirement 12: Support up to 1,000 concurrent video streams
    maxTenants: environment === 'prod' ? 1000 : 100,
    maxUsersPerTenant: 10000,
    maxSitesPerTenant: 100,
    maxBuildingsPerSite: 50,
    maxFloorsPerBuilding: 100,
    maxCamerasPerFloor: 100,
    videoRetentionDays: config.videoRetentionDays,
    auditLogRetentionDays: config.auditLogRetentionDays,
    offlineOperationHours: 72, // Requirement 27: 72-hour offline operation
    apiResponseTimeMs: 200, // Requirement 5: 200ms API response times
  }),
  description: 'SPARC Platform resource limits and quotas',
});

// Security and compliance configuration
new cdk.CfnOutput(securityStack, 'SecurityConfiguration', {
  value: JSON.stringify({
    encryptionAtRest: 'AES-256-KMS',
    encryptionInTransit: 'TLS-1.3',
    auditLogging: 'Enabled',
    complianceFrameworks: ['SOX', 'HIPAA', 'PCI-DSS'],
    dataRetention: `${config.auditLogRetentionDays} days`,
    backupRetention: `${config.backupRetentionDays} days`,
    multiAz: config.enableMultiAz,
    deletionProtection: config.enableDeletionProtection,
    guardDuty: config.enableGuardDuty,
    waf: config.enableWaf,
    securityHub: config.enableSecurityHub,
  }),
  description: 'SPARC Platform security and compliance configuration',
});

// Deployment model configuration
new cdk.CfnOutput(sparcStack, 'DeploymentModel', {
  value: JSON.stringify({
    model: app.node.tryGetContext('deploymentModel') || 'self-managed',
    tenantType: app.node.tryGetContext('tenantType') || 'enterprise',
    supportedModels: ['ssp-managed', 'self-managed', 'hybrid'],
    multiTenant: true,
    offlineResilience: true,
    mobileCredentials: true,
    videoAnalytics: true,
    environmentalMonitoring: true,
    visitorManagement: true,
    advancedAccessControl: true,
  }),
  description: 'SPARC Platform deployment model and capabilities',
});

// Add stack-level tags for cost allocation and management
const stackTags = {
  'sparc:stack-type': 'infrastructure',
  'sparc:deployment-order': '1-security,2-core,3-monitoring',
  'sparc:environment': environment,
  'sparc:region': region,
  'sparc:cost-center': 'security-operations',
  'sparc:data-classification': 'confidential',
  'sparc:backup-required': config.enableBackup.toString(),
  'sparc:compliance-scope': 'sox-hipaa-pci',
  'sparc:monitoring-level': environment === 'prod' ? 'enhanced' : 'standard',
  'sparc:support-tier': environment === 'prod' ? 'premium' : 'standard',
};

// Apply tags to all stacks
Object.entries(stackTags).forEach(([key, value]) => {
  cdk.Tags.of(securityStack).add(key, value);
  cdk.Tags.of(sparcStack).add(key, value);
  cdk.Tags.of(monitoringStack).add(key, value);
});

// Add environment-specific tags
if (environment === 'prod') {
  const prodTags = {
    'sparc:high-availability': 'true',
    'sparc:disaster-recovery': 'enabled',
    'sparc:performance-tier': 'premium',
    'sparc:security-level': 'enhanced',
    'sparc:compliance-audit': 'required',
  };
  
  Object.entries(prodTags).forEach(([key, value]) => {
    cdk.Tags.of(securityStack).add(key, value);
    cdk.Tags.of(sparcStack).add(key, value);
    cdk.Tags.of(monitoringStack).add(key, value);
  });
}

// Add deployment model specific tags
const deploymentModel = app.node.tryGetContext('deploymentModel') || 'self-managed';
const deploymentTags = {
  'sparc:deployment-model': deploymentModel,
  'sparc:tenant-isolation': 'enabled',
  'sparc:multi-site-support': 'enabled',
  'sparc:offline-resilience': 'enabled',
};

Object.entries(deploymentTags).forEach(([key, value]) => {
  cdk.Tags.of(securityStack).add(key, value);
  cdk.Tags.of(sparcStack).add(key, value);
  cdk.Tags.of(monitoringStack).add(key, value);
});

// Synthesize the application
app.synth();