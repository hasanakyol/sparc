import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as xray from 'aws-cdk-lib/aws-xray';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

export interface MonitoringStackProps extends cdk.StackProps {
  readonly environment: string;
  readonly projectName: string;
  readonly alertingEmail: string;
  readonly slackWebhookUrl?: string;
  readonly retentionDays?: number;
  readonly enableDetailedMonitoring?: boolean;
  readonly enableXRayTracing?: boolean;
  readonly cloudTrailBucketName?: string;
}

export class MonitoringStack extends cdk.Stack {
  public readonly alertTopic: sns.Topic;
  public readonly criticalAlertTopic: sns.Topic;
  public readonly securityAlertTopic: sns.Topic;
  public readonly cloudTrail: cloudtrail.Trail;
  public readonly xrayEncryptionConfig: xray.CfnEncryptionConfig;
  public readonly mainDashboard: cloudwatch.Dashboard;
  public readonly securityDashboard: cloudwatch.Dashboard;
  public readonly performanceDashboard: cloudwatch.Dashboard;
  public readonly auditLogGroup: logs.LogGroup;
  public readonly applicationLogGroup: logs.LogGroup;
  public readonly accessControlLogGroup: logs.LogGroup;
  public readonly videoManagementLogGroup: logs.LogGroup;
  public readonly apiGatewayLogGroup: logs.LogGroup;

  constructor(scope: Construct, id: string, props: MonitoringStackProps) {
    super(scope, id, props);

    const {
      environment,
      projectName,
      alertingEmail,
      slackWebhookUrl,
      retentionDays = 2555, // 7 years for compliance (Requirement 10)
      enableDetailedMonitoring = true,
      enableXRayTracing = true,
      cloudTrailBucketName,
    } = props;

    // KMS Key for encryption
    const monitoringKey = new kms.Key(this, 'MonitoringKey', {
      description: `${projectName} monitoring encryption key`,
      enableKeyRotation: true,
      alias: `${projectName}-monitoring-${environment}`,
    });

    // Create SNS Topics for different alert severities
    this.alertTopic = this.createAlertTopic('AlertTopic', 'General alerts', monitoringKey);
    this.criticalAlertTopic = this.createAlertTopic('CriticalAlertTopic', 'Critical system alerts', monitoringKey);
    this.securityAlertTopic = this.createAlertTopic('SecurityAlertTopic', 'Security and compliance alerts', monitoringKey);

    // Subscribe email to all alert topics
    this.alertTopic.addSubscription(new snsSubscriptions.EmailSubscription(alertingEmail));
    this.criticalAlertTopic.addSubscription(new snsSubscriptions.EmailSubscription(alertingEmail));
    this.securityAlertTopic.addSubscription(new snsSubscriptions.EmailSubscription(alertingEmail));

    // Add Slack webhook if provided
    if (slackWebhookUrl) {
      this.alertTopic.addSubscription(new snsSubscriptions.UrlSubscription(slackWebhookUrl));
      this.criticalAlertTopic.addSubscription(new snsSubscriptions.UrlSubscription(slackWebhookUrl));
      this.securityAlertTopic.addSubscription(new snsSubscriptions.UrlSubscription(slackWebhookUrl));
    }

    // Create CloudTrail for audit logging (Requirement 10)
    this.cloudTrail = this.createCloudTrail(cloudTrailBucketName, monitoringKey);

    // Create X-Ray encryption configuration
    if (enableXRayTracing) {
      this.xrayEncryptionConfig = new xray.CfnEncryptionConfig(this, 'XRayEncryption', {
        type: 'KMS',
        keyId: monitoringKey.keyArn,
      });
    }

    // Create Log Groups for different services
    this.auditLogGroup = this.createLogGroup('AuditLogs', '/sparc/audit', retentionDays, monitoringKey);
    this.applicationLogGroup = this.createLogGroup('ApplicationLogs', '/sparc/application', retentionDays, monitoringKey);
    this.accessControlLogGroup = this.createLogGroup('AccessControlLogs', '/sparc/access-control', retentionDays, monitoringKey);
    this.videoManagementLogGroup = this.createLogGroup('VideoManagementLogs', '/sparc/video-management', retentionDays, monitoringKey);
    this.apiGatewayLogGroup = this.createLogGroup('ApiGatewayLogs', '/sparc/api-gateway', retentionDays, monitoringKey);

    // Create metric filters and alarms for security events
    this.createSecurityMetricFilters();

    // Create performance metric filters and alarms
    this.createPerformanceMetricFilters();

    // Create system health metric filters and alarms
    this.createSystemHealthMetricFilters();

    // Create dashboards
    this.mainDashboard = this.createMainDashboard();
    this.securityDashboard = this.createSecurityDashboard();
    this.performanceDashboard = this.createPerformanceDashboard();

    // Create custom metrics for SPARC-specific monitoring
    this.createCustomMetrics();

    // Output important ARNs and names
    this.createOutputs();
  }

  private createAlertTopic(id: string, description: string, kmsKey: kms.Key): sns.Topic {
    return new sns.Topic(this, id, {
      displayName: `${this.stackName} ${description}`,
      masterKey: kmsKey,
    });
  }

  private createCloudTrail(bucketName?: string, kmsKey?: kms.Key): cloudtrail.Trail {
    let bucket: s3.Bucket | undefined;

    if (bucketName) {
      bucket = new s3.Bucket(this, 'CloudTrailBucket', {
        bucketName,
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: kmsKey,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        versioned: true,
        lifecycleRules: [
          {
            id: 'CloudTrailLogRetention',
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
            expiration: cdk.Duration.days(2555), // 7 years
          },
        ],
      });
    }

    const trail = new cloudtrail.Trail(this, 'CloudTrail', {
      bucket,
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      enableFileValidation: true,
      kmsKey,
      sendToCloudWatchLogs: true,
      cloudWatchLogGroup: this.auditLogGroup,
      eventRuleTargets: [
        {
          target: this.securityAlertTopic,
        },
      ],
    });

    // Add data events for S3 buckets (video storage)
    trail.addS3EventSelector([
      {
        bucket: s3.Bucket.fromBucketName(this, 'VideoStorageBucket', `sparc-video-storage-${this.account}-${this.region}`),
        objectPrefix: 'recordings/',
      },
    ]);

    return trail;
  }

  private createLogGroup(id: string, logGroupName: string, retentionDays: number, kmsKey: kms.Key): logs.LogGroup {
    return new logs.LogGroup(this, id, {
      logGroupName,
      retention: this.getRetentionDays(retentionDays),
      encryptionKey: kmsKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
  }

  private getRetentionDays(days: number): logs.RetentionDays {
    // Map days to valid RetentionDays enum values
    if (days >= 2555) return logs.RetentionDays.INFINITE;
    if (days >= 1827) return logs.RetentionDays.FIVE_YEARS;
    if (days >= 1095) return logs.RetentionDays.THREE_YEARS;
    if (days >= 731) return logs.RetentionDays.TWO_YEARS;
    if (days >= 365) return logs.RetentionDays.ONE_YEAR;
    if (days >= 180) return logs.RetentionDays.SIX_MONTHS;
    if (days >= 90) return logs.RetentionDays.THREE_MONTHS;
    if (days >= 60) return logs.RetentionDays.TWO_MONTHS;
    if (days >= 30) return logs.RetentionDays.ONE_MONTH;
    if (days >= 14) return logs.RetentionDays.TWO_WEEKS;
    if (days >= 7) return logs.RetentionDays.ONE_WEEK;
    if (days >= 5) return logs.RetentionDays.FIVE_DAYS;
    if (days >= 3) return logs.RetentionDays.THREE_DAYS;
    return logs.RetentionDays.ONE_DAY;
  }

  private createSecurityMetricFilters(): void {
    // Unauthorized access attempts
    const unauthorizedAccessFilter = new logs.MetricFilter(this, 'UnauthorizedAccessFilter', {
      logGroup: this.accessControlLogGroup,
      metricNamespace: 'SPARC/Security',
      metricName: 'UnauthorizedAccessAttempts',
      filterPattern: logs.FilterPattern.stringValue('$.event_type', '=', 'ACCESS_DENIED'),
      metricValue: '1',
      defaultValue: 0,
    });

    const unauthorizedAccessAlarm = new cloudwatch.Alarm(this, 'UnauthorizedAccessAlarm', {
      metric: unauthorizedAccessFilter.metric({
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 5,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Multiple unauthorized access attempts detected',
    });
    unauthorizedAccessAlarm.addAlarmAction(new cwActions.SnsAction(this.securityAlertTopic));

    // Failed authentication attempts
    const failedAuthFilter = new logs.MetricFilter(this, 'FailedAuthFilter', {
      logGroup: this.applicationLogGroup,
      metricNamespace: 'SPARC/Security',
      metricName: 'FailedAuthentications',
      filterPattern: logs.FilterPattern.stringValue('$.event_type', '=', 'AUTH_FAILED'),
      metricValue: '1',
      defaultValue: 0,
    });

    const failedAuthAlarm = new cloudwatch.Alarm(this, 'FailedAuthAlarm', {
      metric: failedAuthFilter.metric({
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 10,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'High number of failed authentication attempts',
    });
    failedAuthAlarm.addAlarmAction(new cwActions.SnsAction(this.securityAlertTopic));

    // Privilege escalation attempts
    const privilegeEscalationFilter = new logs.MetricFilter(this, 'PrivilegeEscalationFilter', {
      logGroup: this.auditLogGroup,
      metricNamespace: 'SPARC/Security',
      metricName: 'PrivilegeEscalationAttempts',
      filterPattern: logs.FilterPattern.stringValue('$.event_type', '=', 'PRIVILEGE_ESCALATION'),
      metricValue: '1',
      defaultValue: 0,
    });

    const privilegeEscalationAlarm = new cloudwatch.Alarm(this, 'PrivilegeEscalationAlarm', {
      metric: privilegeEscalationFilter.metric({
        statistic: 'Sum',
        period: cdk.Duration.minutes(1),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Privilege escalation attempt detected',
    });
    privilegeEscalationAlarm.addAlarmAction(new cwActions.SnsAction(this.criticalAlertTopic));

    // Data export events (for compliance)
    const dataExportFilter = new logs.MetricFilter(this, 'DataExportFilter', {
      logGroup: this.auditLogGroup,
      metricNamespace: 'SPARC/Compliance',
      metricName: 'DataExports',
      filterPattern: logs.FilterPattern.stringValue('$.event_type', '=', 'DATA_EXPORT'),
      metricValue: '1',
      defaultValue: 0,
    });

    // Video access without authorization
    const unauthorizedVideoAccessFilter = new logs.MetricFilter(this, 'UnauthorizedVideoAccessFilter', {
      logGroup: this.videoManagementLogGroup,
      metricNamespace: 'SPARC/Security',
      metricName: 'UnauthorizedVideoAccess',
      filterPattern: logs.FilterPattern.stringValue('$.event_type', '=', 'VIDEO_ACCESS_DENIED'),
      metricValue: '1',
      defaultValue: 0,
    });

    const unauthorizedVideoAccessAlarm = new cloudwatch.Alarm(this, 'UnauthorizedVideoAccessAlarm', {
      metric: unauthorizedVideoAccessFilter.metric({
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 3,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Unauthorized video access attempts detected',
    });
    unauthorizedVideoAccessAlarm.addAlarmAction(new cwActions.SnsAction(this.securityAlertTopic));
  }

  private createPerformanceMetricFilters(): void {
    // API response time monitoring (Requirement 5: 200ms response times)
    const slowApiFilter = new logs.MetricFilter(this, 'SlowApiFilter', {
      logGroup: this.apiGatewayLogGroup,
      metricNamespace: 'SPARC/Performance',
      metricName: 'SlowApiResponses',
      filterPattern: logs.FilterPattern.numberValue('$.response_time', '>', 200),
      metricValue: '$.response_time',
      defaultValue: 0,
    });

    const slowApiAlarm = new cloudwatch.Alarm(this, 'SlowApiAlarm', {
      metric: slowApiFilter.metric({
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 200,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'API response times exceeding 200ms threshold',
    });
    slowApiAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));

    // Database query performance
    const slowDbQueryFilter = new logs.MetricFilter(this, 'SlowDbQueryFilter', {
      logGroup: this.applicationLogGroup,
      metricNamespace: 'SPARC/Performance',
      metricName: 'SlowDatabaseQueries',
      filterPattern: logs.FilterPattern.numberValue('$.query_time', '>', 500),
      metricValue: '$.query_time',
      defaultValue: 0,
    });

    const slowDbQueryAlarm = new cloudwatch.Alarm(this, 'SlowDbQueryAlarm', {
      metric: slowDbQueryFilter.metric({
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 500,
      evaluationPeriods: 3,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Database queries exceeding 500ms threshold',
    });
    slowDbQueryAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));

    // Video streaming latency (Requirement 3: <2 second latency)
    const videoLatencyFilter = new logs.MetricFilter(this, 'VideoLatencyFilter', {
      logGroup: this.videoManagementLogGroup,
      metricNamespace: 'SPARC/Performance',
      metricName: 'VideoStreamingLatency',
      filterPattern: logs.FilterPattern.numberValue('$.streaming_latency', '>', 2000),
      metricValue: '$.streaming_latency',
      defaultValue: 0,
    });

    const videoLatencyAlarm = new cloudwatch.Alarm(this, 'VideoLatencyAlarm', {
      metric: videoLatencyFilter.metric({
        statistic: 'Average',
        period: cdk.Duration.minutes(1),
      }),
      threshold: 2000,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Video streaming latency exceeding 2 second threshold',
    });
    videoLatencyAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));
  }

  private createSystemHealthMetricFilters(): void {
    // Application errors
    const errorFilter = new logs.MetricFilter(this, 'ErrorFilter', {
      logGroup: this.applicationLogGroup,
      metricNamespace: 'SPARC/Health',
      metricName: 'ApplicationErrors',
      filterPattern: logs.FilterPattern.stringValue('$.level', '=', 'ERROR'),
      metricValue: '1',
      defaultValue: 0,
    });

    const errorAlarm = new cloudwatch.Alarm(this, 'ErrorAlarm', {
      metric: errorFilter.metric({
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 10,
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'High number of application errors',
    });
    errorAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));

    // Device offline events
    const deviceOfflineFilter = new logs.MetricFilter(this, 'DeviceOfflineFilter', {
      logGroup: this.accessControlLogGroup,
      metricNamespace: 'SPARC/Health',
      metricName: 'DevicesOffline',
      filterPattern: logs.FilterPattern.stringValue('$.event_type', '=', 'DEVICE_OFFLINE'),
      metricValue: '1',
      defaultValue: 0,
    });

    const deviceOfflineAlarm = new cloudwatch.Alarm(this, 'DeviceOfflineAlarm', {
      metric: deviceOfflineFilter.metric({
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 5,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Multiple devices have gone offline',
    });
    deviceOfflineAlarm.addAlarmAction(new cwActions.SnsAction(this.criticalAlertTopic));

    // Camera offline events
    const cameraOfflineFilter = new logs.MetricFilter(this, 'CameraOfflineFilter', {
      logGroup: this.videoManagementLogGroup,
      metricNamespace: 'SPARC/Health',
      metricName: 'CamerasOffline',
      filterPattern: logs.FilterPattern.stringValue('$.event_type', '=', 'CAMERA_OFFLINE'),
      metricValue: '1',
      defaultValue: 0,
    });

    const cameraOfflineAlarm = new cloudwatch.Alarm(this, 'CameraOfflineAlarm', {
      metric: cameraOfflineFilter.metric({
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 3,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Multiple cameras have gone offline',
    });
    cameraOfflineAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));

    // Memory usage warnings
    const highMemoryFilter = new logs.MetricFilter(this, 'HighMemoryFilter', {
      logGroup: this.applicationLogGroup,
      metricNamespace: 'SPARC/Health',
      metricName: 'HighMemoryUsage',
      filterPattern: logs.FilterPattern.numberValue('$.memory_usage_percent', '>', 80),
      metricValue: '$.memory_usage_percent',
      defaultValue: 0,
    });

    const highMemoryAlarm = new cloudwatch.Alarm(this, 'HighMemoryAlarm', {
      metric: highMemoryFilter.metric({
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 80,
      evaluationPeriods: 3,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'High memory usage detected',
    });
    highMemoryAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));
  }

  private createMainDashboard(): cloudwatch.Dashboard {
    const dashboard = new cloudwatch.Dashboard(this, 'MainDashboard', {
      dashboardName: `SPARC-Main-${this.stackName}`,
    });

    // System Overview Row
    dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# SPARC Platform - System Overview',
        width: 24,
        height: 1,
      })
    );

    // Key Metrics Row
    dashboard.addWidgets(
      new cloudwatch.SingleValueWidget({
        title: 'Active Access Points',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/AccessControl',
            metricName: 'ActiveAccessPoints',
            statistic: 'Average',
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Active Cameras',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Video',
            metricName: 'ActiveCameras',
            statistic: 'Average',
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Current Users',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Users',
            metricName: 'ActiveUsers',
            statistic: 'Average',
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'System Health',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Health',
            metricName: 'SystemHealthScore',
            statistic: 'Average',
          }),
        ],
        width: 6,
      })
    );

    // Performance Metrics Row
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'API Response Times',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Performance',
            metricName: 'ApiResponseTime',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Access Events per Minute',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/AccessControl',
            metricName: 'AccessEvents',
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
          }),
        ],
        width: 12,
        height: 6,
      })
    );

    // Error Rates Row
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Error Rates',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Health',
            metricName: 'ApplicationErrors',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Device Status',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Health',
            metricName: 'DevicesOffline',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
          new cloudwatch.Metric({
            namespace: 'SPARC/Health',
            metricName: 'CamerasOffline',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 12,
        height: 6,
      })
    );

    return dashboard;
  }

  private createSecurityDashboard(): cloudwatch.Dashboard {
    const dashboard = new cloudwatch.Dashboard(this, 'SecurityDashboard', {
      dashboardName: `SPARC-Security-${this.stackName}`,
    });

    // Security Overview
    dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# SPARC Platform - Security Monitoring',
        width: 24,
        height: 1,
      })
    );

    // Security Metrics Row
    dashboard.addWidgets(
      new cloudwatch.SingleValueWidget({
        title: 'Failed Auth Attempts (Last Hour)',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Security',
            metricName: 'FailedAuthentications',
            statistic: 'Sum',
            period: cdk.Duration.hours(1),
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Unauthorized Access Attempts',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Security',
            metricName: 'UnauthorizedAccessAttempts',
            statistic: 'Sum',
            period: cdk.Duration.hours(1),
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Security Alerts (24h)',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Security',
            metricName: 'SecurityAlerts',
            statistic: 'Sum',
            period: cdk.Duration.hours(24),
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Data Exports (24h)',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Compliance',
            metricName: 'DataExports',
            statistic: 'Sum',
            period: cdk.Duration.hours(24),
          }),
        ],
        width: 6,
      })
    );

    // Security Events Timeline
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Security Events Timeline',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Security',
            metricName: 'FailedAuthentications',
            statistic: 'Sum',
            period: cdk.Duration.minutes(15),
          }),
          new cloudwatch.Metric({
            namespace: 'SPARC/Security',
            metricName: 'UnauthorizedAccessAttempts',
            statistic: 'Sum',
            period: cdk.Duration.minutes(15),
          }),
        ],
        width: 24,
        height: 6,
      })
    );

    // Compliance Metrics
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Audit Log Volume',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/Logs',
            metricName: 'IncomingLogEvents',
            dimensionsMap: {
              LogGroupName: this.auditLogGroup.logGroupName,
            },
            statistic: 'Sum',
            period: cdk.Duration.hours(1),
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'CloudTrail Events',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/CloudTrail',
            metricName: 'EventCount',
            statistic: 'Sum',
            period: cdk.Duration.hours(1),
          }),
        ],
        width: 12,
        height: 6,
      })
    );

    return dashboard;
  }

  private createPerformanceDashboard(): cloudwatch.Dashboard {
    const dashboard = new cloudwatch.Dashboard(this, 'PerformanceDashboard', {
      dashboardName: `SPARC-Performance-${this.stackName}`,
    });

    // Performance Overview
    dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: '# SPARC Platform - Performance Monitoring',
        width: 24,
        height: 1,
      })
    );

    // Key Performance Indicators
    dashboard.addWidgets(
      new cloudwatch.SingleValueWidget({
        title: 'Avg API Response Time',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Performance',
            metricName: 'ApiResponseTime',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Video Streaming Latency',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Performance',
            metricName: 'VideoStreamingLatency',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Database Query Time',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Performance',
            metricName: 'DatabaseQueryTime',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 6,
      }),
      new cloudwatch.SingleValueWidget({
        title: 'Throughput (req/min)',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Performance',
            metricName: 'RequestThroughput',
            statistic: 'Sum',
            period: cdk.Duration.minutes(1),
          }),
        ],
        width: 6,
      })
    );

    // Performance Trends
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Response Time Trends',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Performance',
            metricName: 'ApiResponseTime',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
        ],
        right: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Performance',
            metricName: 'SlowApiResponses',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'System Resource Usage',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Health',
            metricName: 'CpuUsage',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
          new cloudwatch.Metric({
            namespace: 'SPARC/Health',
            metricName: 'MemoryUsage',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 12,
        height: 6,
      })
    );

    // Scalability Metrics (Requirement 12)
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Access Points Scale (Target: 10,000)',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Scale',
            metricName: 'TotalAccessPoints',
            statistic: 'Maximum',
            period: cdk.Duration.hours(1),
          }),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: 'Video Streams Scale (Target: 1,000)',
        left: [
          new cloudwatch.Metric({
            namespace: 'SPARC/Scale',
            metricName: 'ConcurrentVideoStreams',
            statistic: 'Maximum',
            period: cdk.Duration.minutes(5),
          }),
        ],
        width: 12,
        height: 6,
      })
    );

    return dashboard;
  }

  private createCustomMetrics(): void {
    // Create custom metrics for SPARC-specific monitoring
    // These would be published by the application services

    // Access Control Metrics
    const accessControlMetrics = [
      'ActiveAccessPoints',
      'AccessEvents',
      'FailedAccessAttempts',
      'DoorAjarAlerts',
      'OfflineDevices',
    ];

    // Video Management Metrics
    const videoMetrics = [
      'ActiveCameras',
      'ConcurrentVideoStreams',
      'VideoStreamingLatency',
      'RecordingStorage',
      'MotionDetectionEvents',
    ];

    // System Health Metrics
    const healthMetrics = [
      'SystemHealthScore',
      'ServiceAvailability',
      'DatabaseConnections',
      'CacheHitRate',
      'QueueDepth',
    ];

    // Compliance Metrics
    const complianceMetrics = [
      'AuditLogVolume',
      'DataRetentionCompliance',
      'PrivacyMaskingEvents',
      'DataExportRequests',
      'ComplianceViolations',
    ];

    // Create alarms for critical thresholds
    this.createScalabilityAlarms();
  }

  private createScalabilityAlarms(): void {
    // Access Points Scale Alarm (Requirement 12: 10,000 doors)
    const accessPointsAlarm = new cloudwatch.Alarm(this, 'AccessPointsScaleAlarm', {
      metric: new cloudwatch.Metric({
        namespace: 'SPARC/Scale',
        metricName: 'TotalAccessPoints',
        statistic: 'Maximum',
        period: cdk.Duration.hours(1),
      }),
      threshold: 9000, // Alert at 90% of capacity
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Approaching maximum access points capacity (10,000)',
    });
    accessPointsAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));

    // Video Streams Scale Alarm (Requirement 12: 1,000 streams)
    const videoStreamsAlarm = new cloudwatch.Alarm(this, 'VideoStreamsScaleAlarm', {
      metric: new cloudwatch.Metric({
        namespace: 'SPARC/Scale',
        metricName: 'ConcurrentVideoStreams',
        statistic: 'Maximum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 900, // Alert at 90% of capacity
      evaluationPeriods: 2,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Approaching maximum concurrent video streams capacity (1,000)',
    });
    videoStreamsAlarm.addAlarmAction(new cwActions.SnsAction(this.alertTopic));
  }

  private createOutputs(): void {
    new cdk.CfnOutput(this, 'AlertTopicArn', {
      value: this.alertTopic.topicArn,
      description: 'SNS Topic ARN for general alerts',
      exportName: `${this.stackName}-AlertTopicArn`,
    });

    new cdk.CfnOutput(this, 'CriticalAlertTopicArn', {
      value: this.criticalAlertTopic.topicArn,
      description: 'SNS Topic ARN for critical alerts',
      exportName: `${this.stackName}-CriticalAlertTopicArn`,
    });

    new cdk.CfnOutput(this, 'SecurityAlertTopicArn', {
      value: this.securityAlertTopic.topicArn,
      description: 'SNS Topic ARN for security alerts',
      exportName: `${this.stackName}-SecurityAlertTopicArn`,
    });

    new cdk.CfnOutput(this, 'CloudTrailArn', {
      value: this.cloudTrail.trailArn,
      description: 'CloudTrail ARN for audit logging',
      exportName: `${this.stackName}-CloudTrailArn`,
    });

    new cdk.CfnOutput(this, 'AuditLogGroupName', {
      value: this.auditLogGroup.logGroupName,
      description: 'CloudWatch Log Group for audit logs',
      exportName: `${this.stackName}-AuditLogGroupName`,
    });

    new cdk.CfnOutput(this, 'MainDashboardUrl', {
      value: `https://${this.region}.console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${this.mainDashboard.dashboardName}`,
      description: 'URL to the main CloudWatch dashboard',
    });

    new cdk.CfnOutput(this, 'SecurityDashboardUrl', {
      value: `https://${this.region}.console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${this.securityDashboard.dashboardName}`,
      description: 'URL to the security CloudWatch dashboard',
    });

    new cdk.CfnOutput(this, 'PerformanceDashboardUrl', {
      value: `https://${this.region}.console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${this.performanceDashboard.dashboardName}`,
      description: 'URL to the performance CloudWatch dashboard',
    });
  }
}