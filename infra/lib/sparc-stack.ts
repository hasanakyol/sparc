import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import { Construct } from 'constructs';

export interface SparcStackProps extends cdk.StackProps {
  environment: 'dev' | 'staging' | 'prod';
  domainName?: string;
  certificateArn?: string;
}

export class SparcStack extends cdk.Stack {
  public readonly vpc: ec2.Vpc;
  public readonly eksCluster: eks.Cluster;
  public readonly database: rds.DatabaseCluster;
  public readonly redisCluster: elasticache.CfnCacheCluster;
  public readonly videoBucket: s3.Bucket;
  public readonly backupBucket: s3.Bucket;
  public readonly cloudFrontDistribution: cloudfront.Distribution;
  public readonly applicationLoadBalancer: elbv2.ApplicationLoadBalancer;
  public readonly opensearchDomain: opensearch.Domain;
  public readonly kmsKey: kms.Key;

  constructor(scope: Construct, id: string, props: SparcStackProps) {
    super(scope, id, props);

    const { environment } = props;

    // Create KMS key for encryption
    this.kmsKey = new kms.Key(this, 'SparcKmsKey', {
      description: `SPARC platform encryption key for ${environment}`,
      enableKeyRotation: true,
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    this.kmsKey.addAlias(`alias/sparc-${environment}`);

    // Create VPC with public and private subnets across 3 AZs for high availability
    this.vpc = new ec2.Vpc(this, 'SparcVpc', {
      maxAzs: 3,
      natGateways: environment === 'prod' ? 3 : 1, // High availability for prod
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
        },
        {
          cidrMask: 24,
          name: 'Private',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        },
        {
          cidrMask: 28,
          name: 'Database',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        },
      ],
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    // VPC Flow Logs for security monitoring
    new ec2.FlowLog(this, 'SparcVpcFlowLog', {
      resourceType: ec2.FlowLogResourceType.fromVpc(this.vpc),
      destination: ec2.FlowLogDestination.toCloudWatchLogs(),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    // Create security groups
    const eksSecurityGroup = this.createEksSecurityGroup();
    const rdsSecurityGroup = this.createRdsSecurityGroup();
    const redisSecurityGroup = this.createRedisSecurityGroup();
    const albSecurityGroup = this.createAlbSecurityGroup();
    const opensearchSecurityGroup = this.createOpensearchSecurityGroup();

    // Create EKS cluster for microservices
    this.eksCluster = this.createEksCluster(eksSecurityGroup, environment);

    // Create RDS PostgreSQL cluster with Multi-AZ
    this.database = this.createRdsCluster(rdsSecurityGroup, environment);

    // Create ElastiCache Redis cluster
    this.redisCluster = this.createRedisCluster(redisSecurityGroup, environment);

    // Create S3 buckets for video storage and backups
    this.videoBucket = this.createVideoBucket(environment);
    this.backupBucket = this.createBackupBucket(environment);

    // Create OpenSearch domain for analytics
    this.opensearchDomain = this.createOpensearchDomain(opensearchSecurityGroup, environment);

    // Create Application Load Balancer
    this.applicationLoadBalancer = this.createApplicationLoadBalancer(albSecurityGroup);

    // Create CloudFront distribution for video CDN
    this.cloudFrontDistribution = this.createCloudFrontDistribution();

    // Create SNS topics for notifications
    this.createNotificationTopics();

    // Create SQS queues for event processing
    this.createEventQueues();

    // Create backup vault and plans
    this.createBackupResources(environment);

    // Create CloudWatch log groups
    this.createLogGroups();

    // Output important resource information
    this.createOutputs();

    // Tag all resources
    this.tagResources(environment);
  }

  private createEksSecurityGroup(): ec2.SecurityGroup {
    const sg = new ec2.SecurityGroup(this, 'EksSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for EKS cluster',
      allowAllOutbound: true,
    });

    // Allow HTTPS traffic from ALB
    sg.addIngressRule(
      ec2.Peer.securityGroupId(this.createAlbSecurityGroup().securityGroupId),
      ec2.Port.tcp(443),
      'HTTPS from ALB'
    );

    // Allow internal cluster communication
    sg.addIngressRule(sg, ec2.Port.allTraffic(), 'Internal cluster communication');

    return sg;
  }

  private createRdsSecurityGroup(): ec2.SecurityGroup {
    const sg = new ec2.SecurityGroup(this, 'RdsSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for RDS PostgreSQL cluster',
      allowAllOutbound: false,
    });

    // Allow PostgreSQL access from EKS
    sg.addIngressRule(
      ec2.Peer.securityGroupId(this.createEksSecurityGroup().securityGroupId),
      ec2.Port.tcp(5432),
      'PostgreSQL from EKS'
    );

    return sg;
  }

  private createRedisSecurityGroup(): ec2.SecurityGroup {
    const sg = new ec2.SecurityGroup(this, 'RedisSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for Redis cluster',
      allowAllOutbound: false,
    });

    // Allow Redis access from EKS
    sg.addIngressRule(
      ec2.Peer.securityGroupId(this.createEksSecurityGroup().securityGroupId),
      ec2.Port.tcp(6379),
      'Redis from EKS'
    );

    return sg;
  }

  private createAlbSecurityGroup(): ec2.SecurityGroup {
    const sg = new ec2.SecurityGroup(this, 'AlbSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for Application Load Balancer',
      allowAllOutbound: true,
    });

    // Allow HTTP and HTTPS from internet
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'HTTP from internet');
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'HTTPS from internet');

    return sg;
  }

  private createOpensearchSecurityGroup(): ec2.SecurityGroup {
    const sg = new ec2.SecurityGroup(this, 'OpensearchSecurityGroup', {
      vpc: this.vpc,
      description: 'Security group for OpenSearch domain',
      allowAllOutbound: false,
    });

    // Allow HTTPS access from EKS
    sg.addIngressRule(
      ec2.Peer.securityGroupId(this.createEksSecurityGroup().securityGroupId),
      ec2.Port.tcp(443),
      'HTTPS from EKS'
    );

    return sg;
  }

  private createEksCluster(securityGroup: ec2.SecurityGroup, environment: string): eks.Cluster {
    // Create EKS service role
    const eksServiceRole = new iam.Role(this, 'EksServiceRole', {
      assumedBy: new iam.ServicePrincipal('eks.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSClusterPolicy'),
      ],
    });

    // Create node group role
    const nodeGroupRole = new iam.Role(this, 'EksNodeGroupRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKSWorkerNodePolicy'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEKS_CNI_Policy'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonEC2ContainerRegistryReadOnly'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonS3FullAccess'), // For video storage
      ],
    });

    const cluster = new eks.Cluster(this, 'SparcEksCluster', {
      version: eks.KubernetesVersion.V1_28,
      vpc: this.vpc,
      vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
      securityGroup: securityGroup,
      role: eksServiceRole,
      endpointAccess: eks.EndpointAccess.PRIVATE,
      defaultCapacity: 0, // We'll add managed node groups separately
      clusterLogging: [
        eks.ClusterLoggingTypes.API,
        eks.ClusterLoggingTypes.AUDIT,
        eks.ClusterLoggingTypes.AUTHENTICATOR,
        eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
        eks.ClusterLoggingTypes.SCHEDULER,
      ],
    });

    // Add managed node groups for different workload types
    const nodeGroupConfig = {
      instanceTypes: environment === 'prod' 
        ? [ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE)]
        : [ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE)],
      minSize: environment === 'prod' ? 3 : 1,
      maxSize: environment === 'prod' ? 20 : 10,
      desiredSize: environment === 'prod' ? 6 : 2,
      subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      nodeRole: nodeGroupRole,
      amiType: eks.NodegroupAmiType.AL2_X86_64,
      capacityType: eks.CapacityType.ON_DEMAND,
      diskSize: 100,
      forceUpdate: true,
    };

    // General purpose node group
    cluster.addNodegroupCapacity('GeneralNodeGroup', {
      ...nodeGroupConfig,
      nodegroupName: 'sparc-general',
      labels: {
        'node-type': 'general',
      },
      taints: [],
    });

    // Video processing node group with larger instances
    cluster.addNodegroupCapacity('VideoNodeGroup', {
      ...nodeGroupConfig,
      nodegroupName: 'sparc-video',
      instanceTypes: environment === 'prod'
        ? [ec2.InstanceType.of(ec2.InstanceClass.C5N, ec2.InstanceSize.XLARGE2)]
        : [ec2.InstanceType.of(ec2.InstanceClass.C5N, ec2.InstanceSize.LARGE)],
      minSize: environment === 'prod' ? 2 : 1,
      maxSize: environment === 'prod' ? 10 : 5,
      desiredSize: environment === 'prod' ? 3 : 1,
      diskSize: 200,
      labels: {
        'node-type': 'video',
      },
      taints: [
        {
          effect: eks.TaintEffect.NO_SCHEDULE,
          key: 'video-processing',
          value: 'true',
        },
      ],
    });

    return cluster;
  }

  private createRdsCluster(securityGroup: ec2.SecurityGroup, environment: string): rds.DatabaseCluster {
    // Create database credentials secret
    const dbCredentials = new secretsmanager.Secret(this, 'DbCredentials', {
      description: 'SPARC database credentials',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ username: 'sparc_admin' }),
        generateStringKey: 'password',
        excludeCharacters: '"@/\\\'',
        passwordLength: 32,
      },
      encryptionKey: this.kmsKey,
    });

    // Create subnet group for database
    const subnetGroup = new rds.SubnetGroup(this, 'DbSubnetGroup', {
      description: 'Subnet group for SPARC database',
      vpc: this.vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
    });

    // Create parameter group for PostgreSQL optimization
    const parameterGroup = new rds.ParameterGroup(this, 'DbParameterGroup', {
      engine: rds.DatabaseClusterEngine.auroraPostgres({
        version: rds.AuroraPostgresEngineVersion.VER_15_4,
      }),
      description: 'SPARC PostgreSQL parameter group',
      parameters: {
        'shared_preload_libraries': 'pg_stat_statements',
        'log_statement': 'all',
        'log_min_duration_statement': '1000',
        'max_connections': environment === 'prod' ? '1000' : '500',
        'work_mem': '16MB',
        'maintenance_work_mem': '256MB',
        'effective_cache_size': '1GB',
      },
    });

    const cluster = new rds.DatabaseCluster(this, 'SparcDatabase', {
      engine: rds.DatabaseClusterEngine.auroraPostgres({
        version: rds.AuroraPostgresEngineVersion.VER_15_4,
      }),
      credentials: rds.Credentials.fromSecret(dbCredentials),
      instanceProps: {
        instanceType: environment === 'prod'
          ? ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE2)
          : ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.LARGE),
        vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
        vpc: this.vpc,
        securityGroups: [securityGroup],
      },
      instances: environment === 'prod' ? 3 : 2, // Multi-AZ for high availability
      subnetGroup: subnetGroup,
      parameterGroup: parameterGroup,
      defaultDatabaseName: 'sparc',
      backup: {
        retention: environment === 'prod' ? cdk.Duration.days(30) : cdk.Duration.days(7),
        preferredWindow: '03:00-04:00',
      },
      preferredMaintenanceWindow: 'sun:04:00-sun:05:00',
      cloudwatchLogsExports: ['postgresql'],
      cloudwatchLogsRetention: logs.RetentionDays.ONE_MONTH,
      monitoringInterval: cdk.Duration.seconds(60),
      enablePerformanceInsights: true,
      performanceInsightEncryptionKey: this.kmsKey,
      performanceInsightRetention: rds.PerformanceInsightRetention.DEFAULT,
      storageEncrypted: true,
      storageEncryptionKey: this.kmsKey,
      deletionProtection: environment === 'prod',
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    return cluster;
  }

  private createRedisCluster(securityGroup: ec2.SecurityGroup, environment: string): elasticache.CfnCacheCluster {
    // Create subnet group for Redis
    const subnetGroup = new elasticache.CfnSubnetGroup(this, 'RedisSubnetGroup', {
      description: 'Subnet group for SPARC Redis cluster',
      subnetIds: this.vpc.privateSubnets.map(subnet => subnet.subnetId),
    });

    // Create parameter group for Redis optimization
    const parameterGroup = new elasticache.CfnParameterGroup(this, 'RedisParameterGroup', {
      cacheParameterGroupFamily: 'redis7.x',
      description: 'SPARC Redis parameter group',
      properties: {
        'maxmemory-policy': 'allkeys-lru',
        'timeout': '300',
        'tcp-keepalive': '60',
      },
    });

    const cluster = new elasticache.CfnCacheCluster(this, 'SparcRedisCluster', {
      cacheNodeType: environment === 'prod' ? 'cache.r7g.xlarge' : 'cache.r7g.large',
      engine: 'redis',
      engineVersion: '7.0',
      numCacheNodes: 1,
      cacheSubnetGroupName: subnetGroup.ref,
      vpcSecurityGroupIds: [securityGroup.securityGroupId],
      cacheParameterGroupName: parameterGroup.ref,
      port: 6379,
      preferredMaintenanceWindow: 'sun:05:00-sun:06:00',
      snapshotRetentionLimit: environment === 'prod' ? 7 : 1,
      snapshotWindow: '03:00-05:00',
      transitEncryptionEnabled: true,
      atRestEncryptionEnabled: true,
      kmsKeyId: this.kmsKey.keyArn,
      logDeliveryConfigurations: [
        {
          destinationType: 'cloudwatch-logs',
          logFormat: 'json',
          logType: 'slow-log',
          destinationDetails: {
            cloudWatchLogsDetails: {
              logGroup: '/aws/elasticache/redis/slow-log',
            },
          },
        },
      ],
    });

    return cluster;
  }

  private createVideoBucket(environment: string): s3.Bucket {
    const bucket = new s3.Bucket(this, 'SparcVideoBucket', {
      bucketName: `sparc-video-storage-${environment}-${this.account}`,
      versioned: false,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.kmsKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: 'VideoRetentionPolicy',
          enabled: true,
          transitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: cdk.Duration.days(30),
            },
            {
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: cdk.Duration.days(90),
            },
            {
              storageClass: s3.StorageClass.DEEP_ARCHIVE,
              transitionAfter: cdk.Duration.days(365),
            },
          ],
          expiration: cdk.Duration.days(2555), // 7 years for compliance
        },
      ],
      cors: [
        {
          allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.PUT, s3.HttpMethods.POST],
          allowedOrigins: ['*'], // Will be restricted in production
          allowedHeaders: ['*'],
          maxAge: 3000,
        },
      ],
      notificationsHandlerRole: new iam.Role(this, 'S3NotificationRole', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
        ],
      }),
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    // Enable access logging
    const accessLogsBucket = new s3.Bucket(this, 'VideoAccessLogsBucket', {
      bucketName: `sparc-video-access-logs-${environment}-${this.account}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.kmsKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: 'AccessLogsRetention',
          enabled: true,
          expiration: cdk.Duration.days(90),
        },
      ],
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });

    bucket.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('logging.s3.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [`${accessLogsBucket.bucketArn}/*`],
    }));

    return bucket;
  }

  private createBackupBucket(environment: string): s3.Bucket {
    return new s3.Bucket(this, 'SparcBackupBucket', {
      bucketName: `sparc-backup-storage-${environment}-${this.account}`,
      versioned: true,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.kmsKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: 'BackupRetentionPolicy',
          enabled: true,
          transitions: [
            {
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: cdk.Duration.days(30),
            },
            {
              storageClass: s3.StorageClass.DEEP_ARCHIVE,
              transitionAfter: cdk.Duration.days(90),
            },
          ],
          expiration: cdk.Duration.days(2555), // 7 years
        },
      ],
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });
  }

  private createOpensearchDomain(securityGroup: ec2.SecurityGroup, environment: string): opensearch.Domain {
    return new opensearch.Domain(this, 'SparcOpensearchDomain', {
      version: opensearch.EngineVersion.OPENSEARCH_2_3,
      capacity: {
        dataNodes: environment === 'prod' ? 3 : 1,
        dataNodeInstanceType: environment === 'prod' ? 'r6g.large.search' : 't3.small.search',
        masterNodes: environment === 'prod' ? 3 : 0,
        masterNodeInstanceType: environment === 'prod' ? 'r6g.medium.search' : undefined,
      },
      ebs: {
        volumeSize: environment === 'prod' ? 100 : 20,
        volumeType: ec2.EbsDeviceVolumeType.GP3,
      },
      vpc: this.vpc,
      vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }],
      securityGroups: [securityGroup],
      zoneAwareness: {
        enabled: environment === 'prod',
        availabilityZoneCount: environment === 'prod' ? 3 : undefined,
      },
      logging: {
        slowSearchLogEnabled: true,
        appLogEnabled: true,
        slowIndexLogEnabled: true,
      },
      nodeToNodeEncryption: true,
      encryptionAtRest: {
        enabled: true,
        kmsKey: this.kmsKey,
      },
      enforceHttps: true,
      tlsSecurityPolicy: opensearch.TLSSecurityPolicy.TLS_1_2,
      accessPolicies: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          principals: [new iam.AnyPrincipal()],
          actions: ['es:*'],
          resources: ['*'],
          conditions: {
            IpAddress: {
              'aws:SourceIp': this.vpc.vpcCidrBlock,
            },
          },
        }),
      ],
      removalPolicy: environment === 'prod' ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
    });
  }

  private createApplicationLoadBalancer(securityGroup: ec2.SecurityGroup): elbv2.ApplicationLoadBalancer {
    return new elbv2.ApplicationLoadBalancer(this, 'SparcApplicationLoadBalancer', {
      vpc: this.vpc,
      internetFacing: true,
      securityGroup: securityGroup,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      deletionProtection: false, // Set to true for production
      http2Enabled: true,
      idleTimeout: cdk.Duration.seconds(60),
    });
  }

  private createCloudFrontDistribution(): cloudfront.Distribution {
    // Create Origin Access Control for S3
    const oac = new cloudfront.S3OriginAccessControl(this, 'VideoOAC', {
      description: 'OAC for SPARC video bucket',
    });

    const distribution = new cloudfront.Distribution(this, 'SparcCloudFrontDistribution', {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.videoBucket, {
          originAccessControl: oac,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
        compress: true,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.CORS_S3_ORIGIN,
        responseHeadersPolicy: cloudfront.ResponseHeadersPolicy.CORS_ALLOW_ALL_ORIGINS_WITH_PREFLIGHT_AND_SECURITY_HEADERS,
      },
      additionalBehaviors: {
        '/api/*': {
          origin: new origins.LoadBalancerV2Origin(this.applicationLoadBalancer, {
            protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
          }),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        },
        '/hls/*': {
          origin: origins.S3BucketOrigin.withOriginAccessControl(this.videoBucket, {
            originAccessControl: oac,
            originPath: '/hls',
          }),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
          cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
          compress: false, // Don't compress video segments
          cachePolicy: new cloudfront.CachePolicy(this, 'HlsCachePolicy', {
            cachePolicyName: 'sparc-hls-cache-policy',
            defaultTtl: cdk.Duration.seconds(30),
            maxTtl: cdk.Duration.minutes(5),
            minTtl: cdk.Duration.seconds(0),
            headerBehavior: cloudfront.CacheHeaderBehavior.allowList('Range'),
            queryStringBehavior: cloudfront.CacheQueryStringBehavior.all(),
          }),
        },
      },
      priceClass: cloudfront.PriceClass.PRICE_CLASS_ALL,
      enabled: true,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      geoRestriction: cloudfront.GeoRestriction.denylist(), // Configure as needed
      webAclId: undefined, // Add WAF WebACL ARN if needed
      enableLogging: true,
      logBucket: this.backupBucket,
      logFilePrefix: 'cloudfront-logs/',
      logIncludesCookies: false,
    });

    // Grant CloudFront access to S3 bucket
    this.videoBucket.addToResourcePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('cloudfront.amazonaws.com')],
      actions: ['s3:GetObject'],
      resources: [`${this.videoBucket.bucketArn}/*`],
      conditions: {
        StringEquals: {
          'AWS:SourceArn': `arn:aws:cloudfront::${this.account}:distribution/${distribution.distributionId}`,
        },
      },
    }));

    return distribution;
  }

  private createNotificationTopics(): void {
    // Create SNS topics for different types of notifications
    const alertsTopic = new sns.Topic(this, 'AlertsTopic', {
      topicName: 'sparc-alerts',
      displayName: 'SPARC Security Alerts',
      kmsMasterKey: this.kmsKey,
    });

    const systemTopic = new sns.Topic(this, 'SystemTopic', {
      topicName: 'sparc-system',
      displayName: 'SPARC System Notifications',
      kmsMasterKey: this.kmsKey,
    });

    const maintenanceTopic = new sns.Topic(this, 'MaintenanceTopic', {
      topicName: 'sparc-maintenance',
      displayName: 'SPARC Maintenance Notifications',
      kmsMasterKey: this.kmsKey,
    });

    // Store topic ARNs in SSM parameters for services to use
    new cdk.CfnOutput(this, 'AlertsTopicArn', {
      value: alertsTopic.topicArn,
      description: 'ARN of the alerts SNS topic',
    });

    new cdk.CfnOutput(this, 'SystemTopicArn', {
      value: systemTopic.topicArn,
      description: 'ARN of the system notifications SNS topic',
    });

    new cdk.CfnOutput(this, 'MaintenanceTopicArn', {
      value: maintenanceTopic.topicArn,
      description: 'ARN of the maintenance notifications SNS topic',
    });
  }

  private createEventQueues(): void {
    // Create DLQ for failed events
    const dlq = new sqs.Queue(this, 'EventsDlq', {
      queueName: 'sparc-events-dlq',
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.kmsKey,
      retentionPeriod: cdk.Duration.days(14),
    });

    // Create main event processing queue
    const eventsQueue = new sqs.Queue(this, 'EventsQueue', {
      queueName: 'sparc-events',
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.kmsKey,
      visibilityTimeout: cdk.Duration.seconds(300),
      retentionPeriod: cdk.Duration.days(14),
      deadLetterQueue: {
        queue: dlq,
        maxReceiveCount: 3,
      },
    });

    // Create video processing queue
    const videoQueue = new sqs.Queue(this, 'VideoQueue', {
      queueName: 'sparc-video-processing',
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.kmsKey,
      visibilityTimeout: cdk.Duration.minutes(15), // Longer timeout for video processing
      retentionPeriod: cdk.Duration.days(14),
      deadLetterQueue: {
        queue: dlq,
        maxReceiveCount: 2,
      },
    });

    new cdk.CfnOutput(this, 'EventsQueueUrl', {
      value: eventsQueue.queueUrl,
      description: 'URL of the events processing queue',
    });

    new cdk.CfnOutput(this, 'VideoQueueUrl', {
      value: videoQueue.queueUrl,
      description: 'URL of the video processing queue',
    });
  }

  private createBackupResources(environment: string): void {
    // Create backup vault
    const backupVault = new backup.BackupVault(this, 'SparcBackupVault', {
      backupVaultName: `sparc-backup-vault-${environment}`,
      encryptionKey: this.kmsKey,
      accessPolicy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.DENY,
            principals: [new iam.AnyPrincipal()],
            actions: ['backup:DeleteBackupVault', 'backup:DeleteBackupPlan', 'backup:DeleteRecoveryPoint'],
            resources: ['*'],
            conditions: {
              StringNotEquals: {
                'aws:userid': `${this.account}:root`,
              },
            },
          }),
        ],
      }),
    });

    // Create backup plan
    const backupPlan = new backup.BackupPlan(this, 'SparcBackupPlan', {
      backupPlanName: `sparc-backup-plan-${environment}`,
      backupVault: backupVault,
      backupPlanRules: [
        new backup.BackupPlanRule({
          ruleName: 'DailyBackups',
          scheduleExpression: events.Schedule.cron({ hour: '2', minute: '0' }),
          startWindow: cdk.Duration.hours(1),
          completionWindow: cdk.Duration.hours(2),
          deleteAfter: environment === 'prod' ? cdk.Duration.days(30) : cdk.Duration.days(7),
          moveToColdStorageAfter: environment === 'prod' ? cdk.Duration.days(7) : undefined,
        }),
        new backup.BackupPlanRule({
          ruleName: 'WeeklyBackups',
          scheduleExpression: events.Schedule.cron({ weekDay: 'SUN', hour: '3', minute: '0' }),
          startWindow: cdk.Duration.hours(1),
          completionWindow: cdk.Duration.hours(3),
          deleteAfter: cdk.Duration.days(365),
          moveToColdStorageAfter: cdk.Duration.days(30),
        }),
      ],
    });

    // Create backup selection for RDS
    new backup.BackupSelection(this, 'RdsBackupSelection', {
      backupPlan: backupPlan,
      resources: [
        backup.BackupResource.fromRdsDatabaseCluster(this.database),
      ],
      allowRestores: true,
    });
  }

  private createLogGroups(): void {
    // Create log groups for different services
    const logGroups = [
      'sparc-auth-service',
      'sparc-api-gateway',
      'sparc-tenant-service',
      'sparc-access-control-service',
      'sparc-video-management-service',
      'sparc-event-processing-service',
      'sparc-device-management-service',
      'sparc-mobile-credential-service',
      'sparc-analytics-service',
      'sparc-environmental-service',
      'sparc-visitor-management-service',
      'sparc-reporting-service',
    ];

    logGroups.forEach(logGroupName => {
      new logs.LogGroup(this, `${logGroupName}LogGroup`, {
        logGroupName: `/aws/eks/sparc/${logGroupName}`,
        retention: logs.RetentionDays.ONE_MONTH,
        encryptionKey: this.kmsKey,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });
    });

    // Create log group for Redis
    new logs.LogGroup(this, 'RedisLogGroup', {
      logGroupName: '/aws/elasticache/redis/slow-log',
      retention: logs.RetentionDays.ONE_WEEK,
      encryptionKey: this.kmsKey,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
  }

  private createOutputs(): void {
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.vpc.vpcId,
      description: 'VPC ID',
    });

    new cdk.CfnOutput(this, 'EksClusterName', {
      value: this.eksCluster.clusterName,
      description: 'EKS cluster name',
    });

    new cdk.CfnOutput(this, 'EksClusterEndpoint', {
      value: this.eksCluster.clusterEndpoint,
      description: 'EKS cluster endpoint',
    });

    new cdk.CfnOutput(this, 'DatabaseEndpoint', {
      value: this.database.clusterEndpoint.hostname,
      description: 'RDS cluster endpoint',
    });

    new cdk.CfnOutput(this, 'DatabasePort', {
      value: this.database.clusterEndpoint.port.toString(),
      description: 'RDS cluster port',
    });

    new cdk.CfnOutput(this, 'RedisEndpoint', {
      value: this.redisCluster.attrRedisEndpointAddress,
      description: 'Redis cluster endpoint',
    });

    new cdk.CfnOutput(this, 'VideoBucketName', {
      value: this.videoBucket.bucketName,
      description: 'Video storage bucket name',
    });

    new cdk.CfnOutput(this, 'BackupBucketName', {
      value: this.backupBucket.bucketName,
      description: 'Backup storage bucket name',
    });

    new cdk.CfnOutput(this, 'CloudFrontDomainName', {
      value: this.cloudFrontDistribution.distributionDomainName,
      description: 'CloudFront distribution domain name',
    });

    new cdk.CfnOutput(this, 'LoadBalancerDnsName', {
      value: this.applicationLoadBalancer.loadBalancerDnsName,
      description: 'Application Load Balancer DNS name',
    });

    new cdk.CfnOutput(this, 'OpensearchDomainEndpoint', {
      value: this.opensearchDomain.domainEndpoint,
      description: 'OpenSearch domain endpoint',
    });

    new cdk.CfnOutput(this, 'KmsKeyId', {
      value: this.kmsKey.keyId,
      description: 'KMS key ID for encryption',
    });
  }

  private tagResources(environment: string): void {
    const tags = {
      Project: 'SPARC',
      Environment: environment,
      ManagedBy: 'CDK',
      CostCenter: 'Security',
      Backup: 'Required',
      Compliance: 'SOX-HIPAA-PCI',
    };

    Object.entries(tags).forEach(([key, value]) => {
      cdk.Tags.of(this).add(key, value);
    });
  }
}