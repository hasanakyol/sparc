import {
  Stack,
  StackProps,
  Duration,
  RemovalPolicy,
  CfnOutput,
  aws_kms as kms,
  aws_certificatemanager as acm,
  aws_iam as iam,
  aws_wafv2 as wafv2,
  aws_logs as logs,
  aws_s3 as s3,
  aws_cloudwatch as cloudwatch,
  aws_sns as sns,
  aws_sns_subscriptions as subs,
  aws_events as events,
  aws_events_targets as targets,
  aws_ec2 as ec2,
  aws_guardduty as guardduty,
  aws_config as config,
  aws_cloudtrail as cloudtrail,
  aws_secretsmanager as secretsmanager,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cr from 'aws-cdk-lib/custom-resources';

export interface SecurityStackProps extends StackProps {
  readonly environment: string;
  readonly domainName?: string;
  readonly vpc?: ec2.IVpc;
  readonly enableGuardDuty?: boolean;
  readonly enableShieldAdvanced?: boolean;
  readonly enableConfigRules?: boolean;
  readonly notificationEmail?: string;
}

export class SecurityStack extends Stack {
  public readonly kmsKey: kms.Key;
  public readonly certificate?: acm.Certificate;
  public readonly webAcl: wafv2.CfnWebACL;
  public readonly securityRole: iam.Role;
  public readonly auditBucket: s3.Bucket;
  public readonly securityTopic: sns.Topic;

  constructor(scope: Construct, id: string, props: SecurityStackProps) {
    super(scope, id, props);

    const { environment, domainName, vpc, enableGuardDuty = true, enableShieldAdvanced = false, enableConfigRules = true, notificationEmail } = props;

    // Create SNS topic for security notifications
    this.securityTopic = new sns.Topic(this, 'SecurityTopic', {
      topicName: `sparc-security-alerts-${environment}`,
      displayName: 'SPARC Security Alerts',
      fifo: false,
    });

    if (notificationEmail) {
      this.securityTopic.addSubscription(new subs.EmailSubscription(notificationEmail));
    }

    // Create KMS key for encryption with comprehensive key policy
    this.kmsKey = new kms.Key(this, 'SparcMasterKey', {
      alias: `sparc-master-key-${environment}`,
      description: `SPARC platform master encryption key for ${environment}`,
      enableKeyRotation: true,
      rotationPeriod: Duration.days(365),
      removalPolicy: environment === 'prod' ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      policy: new iam.PolicyDocument({
        statements: [
          // Root account access
          new iam.PolicyStatement({
            sid: 'EnableRootAccess',
            effect: iam.Effect.ALLOW,
            principals: [new iam.AccountRootPrincipal()],
            actions: ['kms:*'],
            resources: ['*'],
          }),
          // CloudTrail access for audit logging
          new iam.PolicyStatement({
            sid: 'AllowCloudTrailEncryption',
            effect: iam.Effect.ALLOW,
            principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
            actions: [
              'kms:GenerateDataKey*',
              'kms:DescribeKey',
              'kms:Encrypt',
              'kms:ReEncrypt*',
              'kms:Decrypt',
            ],
            resources: ['*'],
          }),
          // CloudWatch Logs access
          new iam.PolicyStatement({
            sid: 'AllowCloudWatchLogs',
            effect: iam.Effect.ALLOW,
            principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
            actions: [
              'kms:Encrypt',
              'kms:Decrypt',
              'kms:ReEncrypt*',
              'kms:GenerateDataKey*',
              'kms:DescribeKey',
            ],
            resources: ['*'],
          }),
          // S3 service access for encrypted buckets
          new iam.PolicyStatement({
            sid: 'AllowS3Service',
            effect: iam.Effect.ALLOW,
            principals: [new iam.ServicePrincipal('s3.amazonaws.com')],
            actions: [
              'kms:Decrypt',
              'kms:GenerateDataKey',
            ],
            resources: ['*'],
          }),
        ],
      }),
    });

    // Create S3 bucket for audit logs and security data
    this.auditBucket = new s3.Bucket(this, 'SecurityAuditBucket', {
      bucketName: `sparc-security-audit-${environment}-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.kmsKey,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      lifecycleRules: [
        {
          id: 'audit-log-lifecycle',
          enabled: true,
          transitions: [
            {
              storageClass: s3.StorageClass.INFREQUENT_ACCESS,
              transitionAfter: Duration.days(30),
            },
            {
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: Duration.days(90),
            },
            {
              storageClass: s3.StorageClass.DEEP_ARCHIVE,
              transitionAfter: Duration.days(365),
            },
          ],
          expiration: Duration.days(2555), // 7 years retention for compliance
        },
      ],
      removalPolicy: environment === 'prod' ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      serverAccessLogsPrefix: 'access-logs/',
      eventBridgeEnabled: true,
    });

    // Create CloudTrail for comprehensive audit logging
    const cloudTrail = new cloudtrail.Trail(this, 'SecurityAuditTrail', {
      trailName: `sparc-security-trail-${environment}`,
      bucket: this.auditBucket,
      s3KeyPrefix: 'cloudtrail-logs/',
      includeGlobalServiceEvents: true,
      isMultiRegionTrail: true,
      enableFileValidation: true,
      encryptionKey: this.kmsKey,
      sendToCloudWatchLogs: true,
      cloudWatchLogGroup: new logs.LogGroup(this, 'CloudTrailLogGroup', {
        logGroupName: `/aws/cloudtrail/sparc-${environment}`,
        retention: logs.RetentionDays.ONE_YEAR,
        encryptionKey: this.kmsKey,
        removalPolicy: environment === 'prod' ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      }),
      eventRuleTargets: [
        new targets.SnsTopic(this.securityTopic),
      ],
    });

    // Create ACM certificate if domain name is provided
    if (domainName) {
      this.certificate = new acm.Certificate(this, 'SparcCertificate', {
        domainName,
        subjectAlternativeNames: [`*.${domainName}`],
        validation: acm.CertificateValidation.fromDns(),
        certificateName: `sparc-certificate-${environment}`,
      });
    }

    // Create comprehensive WAF Web ACL
    this.webAcl = new wafv2.CfnWebACL(this, 'SparcWebACL', {
      name: `sparc-web-acl-${environment}`,
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      description: 'SPARC platform Web Application Firewall',
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `SparcWebACL${environment}`,
        sampledRequestsEnabled: true,
      },
      rules: [
        // AWS Managed Core Rule Set
        {
          name: 'AWSManagedRulesCommonRuleSet',
          priority: 1,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesCommonRuleSet',
              excludedRules: [],
            },
          },
          overrideAction: { none: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesCommonRuleSet',
          },
        },
        // Known Bad Inputs Rule Set
        {
          name: 'AWSManagedRulesKnownBadInputsRuleSet',
          priority: 2,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesKnownBadInputsRuleSet',
            },
          },
          overrideAction: { none: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesKnownBadInputsRuleSet',
          },
        },
        // SQL Injection Rule Set
        {
          name: 'AWSManagedRulesSQLiRuleSet',
          priority: 3,
          statement: {
            managedRuleGroupStatement: {
              vendorName: 'AWS',
              name: 'AWSManagedRulesSQLiRuleSet',
            },
          },
          overrideAction: { none: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'AWSManagedRulesSQLiRuleSet',
          },
        },
        // Rate limiting rule
        {
          name: 'RateLimitRule',
          priority: 4,
          statement: {
            rateBasedStatement: {
              limit: 2000,
              aggregateKeyType: 'IP',
            },
          },
          action: { block: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'RateLimitRule',
          },
        },
        // Geographic restriction (example: block certain countries)
        {
          name: 'GeoBlockRule',
          priority: 5,
          statement: {
            geoMatchStatement: {
              countryCodes: ['CN', 'RU', 'KP'], // Example blocked countries
            },
          },
          action: { block: {} },
          visibilityConfig: {
            sampledRequestsEnabled: true,
            cloudWatchMetricsEnabled: true,
            metricName: 'GeoBlockRule',
          },
        },
      ],
    });

    // Create security-focused IAM role
    this.securityRole = new iam.Role(this, 'SparcSecurityRole', {
      roleName: `sparc-security-role-${environment}`,
      description: 'Security role for SPARC platform operations',
      assumedBy: new iam.CompositePrincipal(
        new iam.ServicePrincipal('lambda.amazonaws.com'),
        new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
        new iam.ServicePrincipal('eks.amazonaws.com'),
      ),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
      inlinePolicies: {
        SparcSecurityPolicy: new iam.PolicyDocument({
          statements: [
            // KMS permissions
            new iam.PolicyStatement({
              sid: 'KMSAccess',
              effect: iam.Effect.ALLOW,
              actions: [
                'kms:Encrypt',
                'kms:Decrypt',
                'kms:ReEncrypt*',
                'kms:GenerateDataKey*',
                'kms:DescribeKey',
                'kms:GetKeyPolicy',
              ],
              resources: [this.kmsKey.keyArn],
            }),
            // Secrets Manager permissions
            new iam.PolicyStatement({
              sid: 'SecretsManagerAccess',
              effect: iam.Effect.ALLOW,
              actions: [
                'secretsmanager:GetSecretValue',
                'secretsmanager:DescribeSecret',
              ],
              resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:sparc/${environment}/*`],
            }),
            // CloudWatch Logs permissions
            new iam.PolicyStatement({
              sid: 'CloudWatchLogsAccess',
              effect: iam.Effect.ALLOW,
              actions: [
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents',
                'logs:DescribeLogGroups',
                'logs:DescribeLogStreams',
              ],
              resources: [`arn:aws:logs:${this.region}:${this.account}:log-group:/aws/sparc/${environment}/*`],
            }),
            // S3 audit bucket access
            new iam.PolicyStatement({
              sid: 'AuditBucketAccess',
              effect: iam.Effect.ALLOW,
              actions: [
                's3:GetObject',
                's3:PutObject',
                's3:DeleteObject',
                's3:ListBucket',
              ],
              resources: [
                this.auditBucket.bucketArn,
                `${this.auditBucket.bucketArn}/*`,
              ],
            }),
          ],
        }),
      },
    });

    // Enable GuardDuty if requested
    if (enableGuardDuty) {
      const guardDutyDetector = new cr.AwsCustomResource(this, 'GuardDutyDetector', {
        onCreate: {
          service: 'GuardDuty',
          action: 'createDetector',
          parameters: {
            Enable: true,
            FindingPublishingFrequency: 'FIFTEEN_MINUTES',
            DataSources: {
              S3Logs: { Enable: true },
              Kubernetes: { AuditLogs: { Enable: true } },
              MalwareProtection: { ScanEc2InstanceWithFindings: { EbsVolumes: true } },
            },
          },
          physicalResourceId: cr.PhysicalResourceId.of('GuardDutyDetector'),
        },
        onUpdate: {
          service: 'GuardDuty',
          action: 'updateDetector',
          parameters: {
            DetectorId: new cr.PhysicalResourceIdReference(),
            Enable: true,
            FindingPublishingFrequency: 'FIFTEEN_MINUTES',
          },
        },
        onDelete: {
          service: 'GuardDuty',
          action: 'deleteDetector',
          parameters: {
            DetectorId: new cr.PhysicalResourceIdReference(),
          },
        },
        policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
          resources: cr.AwsCustomResourcePolicy.ANY_RESOURCE,
        }),
      });

      // Create EventBridge rule for GuardDuty findings
      const guardDutyRule = new events.Rule(this, 'GuardDutyFindingsRule', {
        ruleName: `sparc-guardduty-findings-${environment}`,
        description: 'Route GuardDuty findings to SNS',
        eventPattern: {
          source: ['aws.guardduty'],
          detailType: ['GuardDuty Finding'],
          detail: {
            severity: [4.0, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 5.0, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 6.0, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 7.0, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 9.0, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 10.0], // Medium to High severity
          },
        },
        targets: [new targets.SnsTopic(this.securityTopic)],
      });
    }

    // Enable Shield Advanced if requested
    if (enableShieldAdvanced) {
      const shieldAdvanced = new cr.AwsCustomResource(this, 'ShieldAdvanced', {
        onCreate: {
          service: 'Shield',
          action: 'createSubscription',
          physicalResourceId: cr.PhysicalResourceId.of('ShieldAdvancedSubscription'),
        },
        policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
          resources: cr.AwsCustomResourcePolicy.ANY_RESOURCE,
        }),
      });
    }

    // Enable AWS Config rules if requested
    if (enableConfigRules) {
      const configRole = new iam.Role(this, 'ConfigRole', {
        assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/ConfigRole'),
        ],
      });

      const configRecorder = new config.CfnConfigurationRecorder(this, 'ConfigRecorder', {
        name: `sparc-config-recorder-${environment}`,
        roleArn: configRole.roleArn,
        recordingGroup: {
          allSupported: true,
          includeGlobalResourceTypes: true,
        },
      });

      const configDeliveryChannel = new config.CfnDeliveryChannel(this, 'ConfigDeliveryChannel', {
        name: `sparc-config-delivery-${environment}`,
        s3BucketName: this.auditBucket.bucketName,
        s3KeyPrefix: 'config/',
      });

      // Security-focused Config rules
      const securityConfigRules = [
        'encrypted-volumes',
        'root-access-key-check',
        'iam-password-policy',
        'cloudtrail-enabled',
        's3-bucket-public-read-prohibited',
        's3-bucket-public-write-prohibited',
        's3-bucket-ssl-requests-only',
        'guardduty-enabled-centralized',
      ];

      securityConfigRules.forEach((ruleName, index) => {
        new config.CfnConfigRule(this, `ConfigRule${index}`, {
          configRuleName: `sparc-${ruleName}-${environment}`,
          source: {
            owner: 'AWS',
            sourceIdentifier: ruleName.toUpperCase().replace(/-/g, '_'),
          },
        });
      });
    }

    // Create CloudWatch alarms for security monitoring
    const kmsKeyUsageAlarm = new cloudwatch.Alarm(this, 'KMSKeyUsageAlarm', {
      alarmName: `sparc-kms-key-usage-${environment}`,
      alarmDescription: 'Monitor KMS key usage for anomalies',
      metric: this.kmsKey.metricNumberOfRequestsSucceeded(),
      threshold: 1000,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    kmsKeyUsageAlarm.addAlarmAction(new cloudwatch.SnsAction(this.securityTopic));

    // WAF monitoring alarm
    const wafBlockedRequestsAlarm = new cloudwatch.Alarm(this, 'WAFBlockedRequestsAlarm', {
      alarmName: `sparc-waf-blocked-requests-${environment}`,
      alarmDescription: 'Monitor WAF blocked requests',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/WAFV2',
        metricName: 'BlockedRequests',
        dimensionsMap: {
          WebACL: this.webAcl.attrName,
          Region: this.region,
        },
        statistic: 'Sum',
        period: Duration.minutes(5),
      }),
      threshold: 100,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    wafBlockedRequestsAlarm.addAlarmAction(new cloudwatch.SnsAction(this.securityTopic));

    // Output important security resources
    new CfnOutput(this, 'KMSKeyId', {
      value: this.kmsKey.keyId,
      description: 'KMS Key ID for SPARC platform encryption',
      exportName: `sparc-kms-key-id-${environment}`,
    });

    new CfnOutput(this, 'KMSKeyArn', {
      value: this.kmsKey.keyArn,
      description: 'KMS Key ARN for SPARC platform encryption',
      exportName: `sparc-kms-key-arn-${environment}`,
    });

    if (this.certificate) {
      new CfnOutput(this, 'CertificateArn', {
        value: this.certificate.certificateArn,
        description: 'ACM Certificate ARN for SPARC platform',
        exportName: `sparc-certificate-arn-${environment}`,
      });
    }

    new CfnOutput(this, 'WebACLArn', {
      value: this.webAcl.attrArn,
      description: 'WAF Web ACL ARN for SPARC platform',
      exportName: `sparc-web-acl-arn-${environment}`,
    });

    new CfnOutput(this, 'SecurityRoleArn', {
      value: this.securityRole.roleArn,
      description: 'Security role ARN for SPARC platform',
      exportName: `sparc-security-role-arn-${environment}`,
    });

    new CfnOutput(this, 'AuditBucketName', {
      value: this.auditBucket.bucketName,
      description: 'S3 bucket for security audit logs',
      exportName: `sparc-audit-bucket-name-${environment}`,
    });

    new CfnOutput(this, 'SecurityTopicArn', {
      value: this.securityTopic.topicArn,
      description: 'SNS topic for security alerts',
      exportName: `sparc-security-topic-arn-${environment}`,
    });
  }
}