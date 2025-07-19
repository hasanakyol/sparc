import * as cdk from 'aws-cdk-lib';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

export interface KubernetesIntegrationProps extends cdk.StackProps {
  readonly environment: string;
  readonly eksCluster: eks.Cluster;
  readonly vpc: ec2.Vpc;
  readonly kmsKey: kms.Key;
  readonly sparcStackName: string;
  readonly securityStackName: string;
  readonly monitoringStackName: string;
}

export class KubernetesIntegration extends Construct {
  public readonly namespace: eks.KubernetesManifest;
  public readonly resourceQuota: eks.KubernetesManifest;
  public readonly serviceAccounts: { [key: string]: eks.ServiceAccount };
  public readonly irsaRoles: { [key: string]: iam.Role };

  private readonly microservices = [
    'auth-service',
    'api-gateway',
    'tenant-service',
    'access-control-service',
    'video-management-service',
    'device-management-service',
    'event-processing-service',
    'analytics-service',
    'mobile-credential-service',
    'environmental-service',
    'visitor-management-service',
    'reporting-service'
  ];

  constructor(scope: Construct, id: string, props: KubernetesIntegrationProps) {
    super(scope, id);

    const {
      environment,
      eksCluster,
      vpc,
      kmsKey,
      sparcStackName,
      securityStackName,
      monitoringStackName,
    } = props;

    // Create namespace for SPARC platform
    this.namespace = this.createNamespace(eksCluster, environment);

    // Create resource quota for the namespace
    this.resourceQuota = this.createResourceQuota(eksCluster, environment);

    // Store CDK outputs in Parameter Store for Kubernetes consumption
    this.storeInfrastructureParameters(environment, sparcStackName, securityStackName, monitoringStackName);

    // Create IRSA roles and service accounts for each microservice
    this.serviceAccounts = {};
    this.irsaRoles = {};
    this.createIRSAResources(eksCluster, environment, kmsKey);

    // Install EKS add-ons
    this.installEKSAddons(eksCluster, environment);

    // Create cluster-wide resources
    this.createClusterResources(eksCluster, environment);

    // Create monitoring and observability resources
    this.createMonitoringResources(eksCluster, environment);
  }

  private createNamespace(eksCluster: eks.Cluster, environment: string): eks.KubernetesManifest {
    return new eks.KubernetesManifest(this, 'SparcNamespace', {
      cluster: eksCluster,
      manifest: [
        {
          apiVersion: 'v1',
          kind: 'Namespace',
          metadata: {
            name: `sparc-${environment}`,
            labels: {
              'app.kubernetes.io/name': 'sparc',
              'app.kubernetes.io/instance': environment,
              'app.kubernetes.io/version': '1.0.0',
              'app.kubernetes.io/component': 'platform',
              'app.kubernetes.io/part-of': 'sparc-platform',
              'app.kubernetes.io/managed-by': 'aws-cdk',
              environment: environment,
              'istio-injection': 'enabled', // Enable service mesh if using Istio
            },
            annotations: {
              'scheduler.alpha.kubernetes.io/node-selector': 'node-type=general',
            },
          },
        },
      ],
    });
  }

  private createResourceQuota(eksCluster: eks.Cluster, environment: string): eks.KubernetesManifest {
    const quotaLimits = environment === 'prod' 
      ? {
          'requests.cpu': '20',
          'requests.memory': '40Gi',
          'limits.cpu': '40',
          'limits.memory': '80Gi',
          'persistentvolumeclaims': '20',
          'services': '50',
          'secrets': '100',
          'configmaps': '100',
          'pods': '200',
        }
      : {
          'requests.cpu': '10',
          'requests.memory': '20Gi',
          'limits.cpu': '20',
          'limits.memory': '40Gi',
          'persistentvolumeclaims': '10',
          'services': '25',
          'secrets': '50',
          'configmaps': '50',
          'pods': '100',
        };

    return new eks.KubernetesManifest(this, 'SparcResourceQuota', {
      cluster: eksCluster,
      manifest: [
        {
          apiVersion: 'v1',
          kind: 'ResourceQuota',
          metadata: {
            name: `sparc-resource-quota-${environment}`,
            namespace: `sparc-${environment}`,
          },
          spec: {
            hard: quotaLimits,
          },
        },
        {
          apiVersion: 'v1',
          kind: 'LimitRange',
          metadata: {
            name: `sparc-limit-range-${environment}`,
            namespace: `sparc-${environment}`,
          },
          spec: {
            limits: [
              {
                type: 'Container',
                default: {
                  cpu: '500m',
                  memory: '512Mi',
                },
                defaultRequest: {
                  cpu: '100m',
                  memory: '128Mi',
                },
                max: {
                  cpu: '2000m',
                  memory: '4Gi',
                },
                min: {
                  cpu: '50m',
                  memory: '64Mi',
                },
              },
              {
                type: 'Pod',
                max: {
                  cpu: '4000m',
                  memory: '8Gi',
                },
              },
            ],
          },
        },
      ],
    });
  }

  private storeInfrastructureParameters(
    environment: string,
    sparcStackName: string,
    securityStackName: string,
    monitoringStackName: string
  ): void {
    const parameterPrefix = `/sparc/${environment}`;

    // SPARC Stack parameters
    const sparcParameters = [
      { name: 'vpc-id', importName: `${sparcStackName}-VpcId` },
      { name: 'eks-cluster-name', importName: `${sparcStackName}-EksClusterName` },
      { name: 'eks-cluster-endpoint', importName: `${sparcStackName}-EksClusterEndpoint` },
      { name: 'database-endpoint', importName: `${sparcStackName}-DatabaseEndpoint` },
      { name: 'database-port', importName: `${sparcStackName}-DatabasePort` },
      { name: 'redis-endpoint', importName: `${sparcStackName}-RedisEndpoint` },
      { name: 'video-bucket-name', importName: `${sparcStackName}-VideoBucketName` },
      { name: 'backup-bucket-name', importName: `${sparcStackName}-BackupBucketName` },
      { name: 'cloudfront-domain-name', importName: `${sparcStackName}-CloudFrontDomainName` },
      { name: 'load-balancer-dns-name', importName: `${sparcStackName}-LoadBalancerDnsName` },
      { name: 'opensearch-domain-endpoint', importName: `${sparcStackName}-OpensearchDomainEndpoint` },
      { name: 'kms-key-id', importName: `${sparcStackName}-KmsKeyId` },
      { name: 'alerts-topic-arn', importName: `${sparcStackName}-AlertsTopicArn` },
      { name: 'system-topic-arn', importName: `${sparcStackName}-SystemTopicArn` },
      { name: 'maintenance-topic-arn', importName: `${sparcStackName}-MaintenanceTopicArn` },
      { name: 'events-queue-url', importName: `${sparcStackName}-EventsQueueUrl` },
      { name: 'video-queue-url', importName: `${sparcStackName}-VideoQueueUrl` },
    ];

    // Security Stack parameters
    const securityParameters = [
      { name: 'security-kms-key-id', importName: `sparc-kms-key-id-${environment}` },
      { name: 'security-kms-key-arn', importName: `sparc-kms-key-arn-${environment}` },
      { name: 'certificate-arn', importName: `sparc-certificate-arn-${environment}` },
      { name: 'web-acl-arn', importName: `sparc-web-acl-arn-${environment}` },
      { name: 'security-role-arn', importName: `sparc-security-role-arn-${environment}` },
      { name: 'audit-bucket-name', importName: `sparc-audit-bucket-name-${environment}` },
      { name: 'security-topic-arn', importName: `sparc-security-topic-arn-${environment}` },
    ];

    // Monitoring Stack parameters
    const monitoringParameters = [
      { name: 'alert-topic-arn', importName: `${monitoringStackName}-AlertTopicArn` },
      { name: 'critical-alert-topic-arn', importName: `${monitoringStackName}-CriticalAlertTopicArn` },
      { name: 'security-alert-topic-arn', importName: `${monitoringStackName}-SecurityAlertTopicArn` },
      { name: 'cloudtrail-arn', importName: `${monitoringStackName}-CloudTrailArn` },
      { name: 'audit-log-group-name', importName: `${monitoringStackName}-AuditLogGroupName` },
    ];

    // Create SSM parameters for all infrastructure outputs
    [...sparcParameters, ...securityParameters, ...monitoringParameters].forEach(param => {
      new ssm.StringParameter(this, `Param${param.name.replace(/-/g, '')}`, {
        parameterName: `${parameterPrefix}/${param.name}`,
        stringValue: cdk.Fn.importValue(param.importName),
        description: `SPARC ${environment} - ${param.name}`,
        tier: ssm.ParameterTier.STANDARD,
      });
    });
  }

  private createIRSAResources(eksCluster: eks.Cluster, environment: string, kmsKey: kms.Key): void {
    this.microservices.forEach(serviceName => {
      // Create IRSA role for each microservice
      const role = new iam.Role(this, `${serviceName}IrsaRole`, {
        roleName: `sparc-${serviceName}-irsa-${environment}`,
        assumedBy: new iam.WebIdentityPrincipal(
          eksCluster.openIdConnectProvider.openIdConnectProviderArn,
          {
            StringEquals: {
              [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:sub`]: 
                `system:serviceaccount:sparc-${environment}:${serviceName}`,
              [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
            },
          }
        ),
        description: `IRSA role for SPARC ${serviceName} in ${environment}`,
      });

      // Add service-specific permissions
      this.addServiceSpecificPermissions(role, serviceName, environment, kmsKey);

      // Create Kubernetes service account
      const serviceAccount = new eks.ServiceAccount(this, `${serviceName}ServiceAccount`, {
        cluster: eksCluster,
        name: serviceName,
        namespace: `sparc-${environment}`,
        role: role,
        annotations: {
          'eks.amazonaws.com/role-arn': role.roleArn,
        },
        labels: {
          'app.kubernetes.io/name': serviceName,
          'app.kubernetes.io/instance': environment,
          'app.kubernetes.io/component': 'microservice',
          'app.kubernetes.io/part-of': 'sparc-platform',
          'app.kubernetes.io/managed-by': 'aws-cdk',
        },
      });

      this.irsaRoles[serviceName] = role;
      this.serviceAccounts[serviceName] = serviceAccount;
    });
  }

  private addServiceSpecificPermissions(role: iam.Role, serviceName: string, environment: string, kmsKey: kms.Key): void {
    // Common permissions for all services
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'CommonKMSAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'kms:Encrypt',
        'kms:Decrypt',
        'kms:ReEncrypt*',
        'kms:GenerateDataKey*',
        'kms:DescribeKey',
      ],
      resources: [kmsKey.keyArn],
    }));

    role.addToPolicy(new iam.PolicyStatement({
      sid: 'CommonSSMAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'ssm:GetParameter',
        'ssm:GetParameters',
        'ssm:GetParametersByPath',
      ],
      resources: [`arn:aws:ssm:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:parameter/sparc/${environment}/*`],
    }));

    role.addToPolicy(new iam.PolicyStatement({
      sid: 'CommonSecretsManagerAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'secretsmanager:GetSecretValue',
        'secretsmanager:DescribeSecret',
      ],
      resources: [`arn:aws:secretsmanager:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:secret:sparc/${environment}/*`],
    }));

    // Service-specific permissions
    switch (serviceName) {
      case 'video-management-service':
        role.addToPolicy(new iam.PolicyStatement({
          sid: 'S3VideoAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            's3:GetObject',
            's3:PutObject',
            's3:DeleteObject',
            's3:ListBucket',
            's3:GetObjectVersion',
          ],
          resources: [
            `arn:aws:s3:::sparc-video-storage-${environment}-*`,
            `arn:aws:s3:::sparc-video-storage-${environment}-*/*`,
          ],
        }));

        role.addToPolicy(new iam.PolicyStatement({
          sid: 'CloudFrontAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            'cloudfront:CreateInvalidation',
            'cloudfront:GetInvalidation',
            'cloudfront:ListInvalidations',
          ],
          resources: ['*'],
        }));
        break;

      case 'analytics-service':
        role.addToPolicy(new iam.PolicyStatement({
          sid: 'OpenSearchAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            'es:ESHttpPost',
            'es:ESHttpPut',
            'es:ESHttpGet',
            'es:ESHttpDelete',
            'es:ESHttpHead',
          ],
          resources: [`arn:aws:es:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:domain/sparc-*/*`],
        }));
        break;

      case 'event-processing-service':
        role.addToPolicy(new iam.PolicyStatement({
          sid: 'SQSAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            'sqs:ReceiveMessage',
            'sqs:DeleteMessage',
            'sqs:SendMessage',
            'sqs:GetQueueAttributes',
            'sqs:ChangeMessageVisibility',
          ],
          resources: [
            `arn:aws:sqs:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:sparc-events*`,
            `arn:aws:sqs:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:sparc-video*`,
          ],
        }));

        role.addToPolicy(new iam.PolicyStatement({
          sid: 'SNSAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            'sns:Publish',
            'sns:GetTopicAttributes',
          ],
          resources: [
            `arn:aws:sns:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:sparc-*`,
          ],
        }));
        break;

      case 'reporting-service':
        role.addToPolicy(new iam.PolicyStatement({
          sid: 'S3BackupAccess',
          effect: iam.Effect.ALLOW,
          actions: [
            's3:GetObject',
            's3:PutObject',
            's3:ListBucket',
          ],
          resources: [
            `arn:aws:s3:::sparc-backup-storage-${environment}-*`,
            `arn:aws:s3:::sparc-backup-storage-${environment}-*/*`,
          ],
        }));
        break;

      case 'auth-service':
      case 'tenant-service':
        // Database access is handled through connection strings in secrets
        break;

      default:
        // Default permissions already added above
        break;
    }

    // CloudWatch Logs permissions for all services
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'CloudWatchLogsAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:CreateLogGroup',
        'logs:CreateLogStream',
        'logs:PutLogEvents',
        'logs:DescribeLogGroups',
        'logs:DescribeLogStreams',
      ],
      resources: [`arn:aws:logs:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:log-group:/aws/sparc/${environment}/*`],
    }));
  }

  private installEKSAddons(eksCluster: eks.Cluster, environment: string): void {
    // AWS Load Balancer Controller
    const albControllerRole = new iam.Role(this, 'ALBControllerRole', {
      roleName: `sparc-alb-controller-${environment}`,
      assumedBy: new iam.WebIdentityPrincipal(
        eksCluster.openIdConnectProvider.openIdConnectProviderArn,
        {
          StringEquals: {
            [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:sub`]: 
              'system:serviceaccount:kube-system:aws-load-balancer-controller',
            [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
          },
        }
      ),
    });

    albControllerRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('ElasticLoadBalancingFullAccess')
    );

    albControllerRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'iam:CreateServiceLinkedRole',
        'ec2:DescribeAccountAttributes',
        'ec2:DescribeAddresses',
        'ec2:DescribeAvailabilityZones',
        'ec2:DescribeInternetGateways',
        'ec2:DescribeVpcs',
        'ec2:DescribeSubnets',
        'ec2:DescribeSecurityGroups',
        'ec2:DescribeInstances',
        'ec2:DescribeNetworkInterfaces',
        'ec2:DescribeTags',
        'ec2:GetCoipPoolUsage',
        'ec2:DescribeCoipPools',
        'elasticloadbalancing:DescribeLoadBalancers',
        'elasticloadbalancing:DescribeLoadBalancerAttributes',
        'elasticloadbalancing:DescribeListeners',
        'elasticloadbalancing:DescribeListenerCertificates',
        'elasticloadbalancing:DescribeSSLPolicies',
        'elasticloadbalancing:DescribeRules',
        'elasticloadbalancing:DescribeTargetGroups',
        'elasticloadbalancing:DescribeTargetGroupAttributes',
        'elasticloadbalancing:DescribeTargetHealth',
        'elasticloadbalancing:DescribeTags',
      ],
      resources: ['*'],
    }));

    const albServiceAccount = new eks.ServiceAccount(this, 'ALBControllerServiceAccount', {
      cluster: eksCluster,
      name: 'aws-load-balancer-controller',
      namespace: 'kube-system',
      role: albControllerRole,
    });

    eksCluster.addHelmChart('AWSLoadBalancerController', {
      repository: 'https://aws.github.io/eks-charts',
      chart: 'aws-load-balancer-controller',
      release: 'aws-load-balancer-controller',
      namespace: 'kube-system',
      values: {
        clusterName: eksCluster.clusterName,
        serviceAccount: {
          create: false,
          name: 'aws-load-balancer-controller',
        },
        region: cdk.Stack.of(this).region,
        vpcId: eksCluster.vpc.vpcId,
      },
    });

    // External Secrets Operator
    const externalSecretsRole = new iam.Role(this, 'ExternalSecretsRole', {
      roleName: `sparc-external-secrets-${environment}`,
      assumedBy: new iam.WebIdentityPrincipal(
        eksCluster.openIdConnectProvider.openIdConnectProviderArn,
        {
          StringEquals: {
            [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:sub`]: 
              'system:serviceaccount:external-secrets:external-secrets',
            [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
          },
        }
      ),
    });

    externalSecretsRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'secretsmanager:GetSecretValue',
        'secretsmanager:DescribeSecret',
        'ssm:GetParameter',
        'ssm:GetParameters',
        'ssm:GetParametersByPath',
      ],
      resources: [
        `arn:aws:secretsmanager:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:secret:sparc/${environment}/*`,
        `arn:aws:ssm:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:parameter/sparc/${environment}/*`,
      ],
    }));

    const externalSecretsServiceAccount = new eks.ServiceAccount(this, 'ExternalSecretsServiceAccount', {
      cluster: eksCluster,
      name: 'external-secrets',
      namespace: 'external-secrets',
      role: externalSecretsRole,
    });

    eksCluster.addHelmChart('ExternalSecrets', {
      repository: 'https://charts.external-secrets.io',
      chart: 'external-secrets',
      release: 'external-secrets',
      namespace: 'external-secrets',
      createNamespace: true,
      values: {
        serviceAccount: {
          create: false,
          name: 'external-secrets',
        },
        securityContext: {
          fsGroup: 65534,
        },
      },
    });

    // Cluster Autoscaler
    const clusterAutoscalerRole = new iam.Role(this, 'ClusterAutoscalerRole', {
      roleName: `sparc-cluster-autoscaler-${environment}`,
      assumedBy: new iam.WebIdentityPrincipal(
        eksCluster.openIdConnectProvider.openIdConnectProviderArn,
        {
          StringEquals: {
            [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:sub`]: 
              'system:serviceaccount:kube-system:cluster-autoscaler',
            [`${eksCluster.openIdConnectProvider.openIdConnectProviderIssuer}:aud`]: 'sts.amazonaws.com',
          },
        }
      ),
    });

    clusterAutoscalerRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'autoscaling:DescribeAutoScalingGroups',
        'autoscaling:DescribeAutoScalingInstances',
        'autoscaling:DescribeLaunchConfigurations',
        'autoscaling:DescribeTags',
        'autoscaling:SetDesiredCapacity',
        'autoscaling:TerminateInstanceInAutoScalingGroup',
        'ec2:DescribeLaunchTemplateVersions',
        'ec2:DescribeInstanceTypes',
      ],
      resources: ['*'],
    }));

    const clusterAutoscalerServiceAccount = new eks.ServiceAccount(this, 'ClusterAutoscalerServiceAccount', {
      cluster: eksCluster,
      name: 'cluster-autoscaler',
      namespace: 'kube-system',
      role: clusterAutoscalerRole,
    });

    eksCluster.addHelmChart('ClusterAutoscaler', {
      repository: 'https://kubernetes.github.io/autoscaler',
      chart: 'cluster-autoscaler',
      release: 'cluster-autoscaler',
      namespace: 'kube-system',
      values: {
        autoDiscovery: {
          clusterName: eksCluster.clusterName,
        },
        awsRegion: cdk.Stack.of(this).region,
        serviceAccount: {
          create: false,
          name: 'cluster-autoscaler',
        },
        extraArgs: {
          'scale-down-delay-after-add': '10m',
          'scale-down-unneeded-time': '10m',
          'scale-down-utilization-threshold': '0.5',
          'skip-nodes-with-local-storage': false,
          'skip-nodes-with-system-pods': false,
        },
      },
    });

    // Metrics Server (if not already installed)
    eksCluster.addHelmChart('MetricsServer', {
      repository: 'https://kubernetes-sigs.github.io/metrics-server/',
      chart: 'metrics-server',
      release: 'metrics-server',
      namespace: 'kube-system',
      values: {
        args: [
          '--cert-dir=/tmp',
          '--secure-port=4443',
          '--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname',
          '--kubelet-use-node-status-port',
          '--metric-resolution=15s',
        ],
      },
    });
  }

  private createClusterResources(eksCluster: eks.Cluster, environment: string): void {
    // Create cluster-wide RBAC resources
    new eks.KubernetesManifest(this, 'SparcClusterRBAC', {
      cluster: eksCluster,
      manifest: [
        {
          apiVersion: 'rbac.authorization.k8s.io/v1',
          kind: 'ClusterRole',
          metadata: {
            name: `sparc-cluster-reader-${environment}`,
          },
          rules: [
            {
              apiGroups: [''],
              resources: ['nodes', 'namespaces', 'persistentvolumes'],
              verbs: ['get', 'list', 'watch'],
            },
            {
              apiGroups: ['metrics.k8s.io'],
              resources: ['nodes', 'pods'],
              verbs: ['get', 'list'],
            },
          ],
        },
        {
          apiVersion: 'rbac.authorization.k8s.io/v1',
          kind: 'ClusterRoleBinding',
          metadata: {
            name: `sparc-cluster-reader-binding-${environment}`,
          },
          roleRef: {
            apiGroup: 'rbac.authorization.k8s.io',
            kind: 'ClusterRole',
            name: `sparc-cluster-reader-${environment}`,
          },
          subjects: [
            {
              kind: 'ServiceAccount',
              name: 'analytics-service',
              namespace: `sparc-${environment}`,
            },
            {
              kind: 'ServiceAccount',
              name: 'reporting-service',
              namespace: `sparc-${environment}`,
            },
          ],
        },
      ],
    });

    // Create network policies for security
    new eks.KubernetesManifest(this, 'SparcNetworkPolicies', {
      cluster: eksCluster,
      manifest: [
        {
          apiVersion: 'networking.k8s.io/v1',
          kind: 'NetworkPolicy',
          metadata: {
            name: `sparc-default-deny-${environment}`,
            namespace: `sparc-${environment}`,
          },
          spec: {
            podSelector: {},
            policyTypes: ['Ingress', 'Egress'],
          },
        },
        {
          apiVersion: 'networking.k8s.io/v1',
          kind: 'NetworkPolicy',
          metadata: {
            name: `sparc-allow-internal-${environment}`,
            namespace: `sparc-${environment}`,
          },
          spec: {
            podSelector: {
              matchLabels: {
                'app.kubernetes.io/part-of': 'sparc-platform',
              },
            },
            policyTypes: ['Ingress', 'Egress'],
            ingress: [
              {
                from: [
                  {
                    namespaceSelector: {
                      matchLabels: {
                        name: `sparc-${environment}`,
                      },
                    },
                  },
                ],
              },
            ],
            egress: [
              {
                to: [
                  {
                    namespaceSelector: {
                      matchLabels: {
                        name: `sparc-${environment}`,
                      },
                    },
                  },
                ],
              },
              {
                to: [],
                ports: [
                  { protocol: 'TCP', port: 53 },
                  { protocol: 'UDP', port: 53 },
                ],
              },
              {
                to: [],
                ports: [
                  { protocol: 'TCP', port: 443 },
                  { protocol: 'TCP', port: 80 },
                ],
              },
            ],
          },
        },
      ],
    });
  }

  private createMonitoringResources(eksCluster: eks.Cluster, environment: string): void {
    // Create ServiceMonitor for Prometheus scraping
    new eks.KubernetesManifest(this, 'SparcServiceMonitors', {
      cluster: eksCluster,
      manifest: this.microservices.map(serviceName => ({
        apiVersion: 'monitoring.coreos.com/v1',
        kind: 'ServiceMonitor',
        metadata: {
          name: `${serviceName}-monitor`,
          namespace: `sparc-${environment}`,
          labels: {
            'app.kubernetes.io/name': serviceName,
            'app.kubernetes.io/component': 'monitoring',
            'app.kubernetes.io/part-of': 'sparc-platform',
          },
        },
        spec: {
          selector: {
            matchLabels: {
              'app.kubernetes.io/name': serviceName,
            },
          },
          endpoints: [
            {
              port: 'metrics',
              path: '/metrics',
              interval: '30s',
              scrapeTimeout: '10s',
            },
          ],
        },
      })),
    });

    // Create PrometheusRule for alerting
    new eks.KubernetesManifest(this, 'SparcPrometheusRules', {
      cluster: eksCluster,
      manifest: [
        {
          apiVersion: 'monitoring.coreos.com/v1',
          kind: 'PrometheusRule',
          metadata: {
            name: `sparc-platform-rules-${environment}`,
            namespace: `sparc-${environment}`,
            labels: {
              'app.kubernetes.io/name': 'sparc-platform',
              'app.kubernetes.io/component': 'monitoring',
            },
          },
          spec: {
            groups: [
              {
                name: 'sparc.platform.rules',
                rules: [
                  {
                    alert: 'SparcServiceDown',
                    expr: 'up{job=~"sparc-.*"} == 0',
                    for: '5m',
                    labels: {
                      severity: 'critical',
                    },
                    annotations: {
                      summary: 'SPARC service {{ $labels.job }} is down',
                      description: 'SPARC service {{ $labels.job }} has been down for more than 5 minutes.',
                    },
                  },
                  {
                    alert: 'SparcHighErrorRate',
                    expr: 'rate(http_requests_total{job=~"sparc-.*",status=~"5.."}[5m]) > 0.1',
                    for: '5m',
                    labels: {
                      severity: 'warning',
                    },
                    annotations: {
                      summary: 'High error rate in SPARC service {{ $labels.job }}',
                      description: 'SPARC service {{ $labels.job }} has error rate above 10% for more than 5 minutes.',
                    },
                  },
                  {
                    alert: 'SparcHighLatency',
                    expr: 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=~"sparc-.*"}[5m])) > 0.2',
                    for: '5m',
                    labels: {
                      severity: 'warning',
                    },
                    annotations: {
                      summary: 'High latency in SPARC service {{ $labels.job }}',
                      description: 'SPARC service {{ $labels.job }} 95th percentile latency is above 200ms for more than 5 minutes.',
                    },
                  },
                ],
              },
            ],
          },
        },
      ],
    });
  }
}