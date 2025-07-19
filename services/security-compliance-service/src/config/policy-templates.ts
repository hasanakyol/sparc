import { PolicyType, PolicyAction } from '../types/enums';

export const POLICY_TEMPLATES = {
  [PolicyType.ACCESS_CONTROL]: [
    {
      name: 'Require MFA for Admin Access',
      description: 'Enforce multi-factor authentication for administrative operations',
      type: PolicyType.ACCESS_CONTROL,
      rules: [
        {
          condition: {
            field: 'user.role',
            operator: 'in',
            value: ['admin', 'super_admin']
          },
          action: PolicyAction.REQUIRE_MFA
        }
      ],
      priority: 100
    },
    {
      name: 'Restrict Access by IP Range',
      description: 'Limit access to specific IP ranges for sensitive operations',
      type: PolicyType.ACCESS_CONTROL,
      rules: [
        {
          condition: {
            field: 'request.ip',
            operator: 'not_in',
            value: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
          },
          action: PolicyAction.DENY
        }
      ],
      priority: 90
    },
    {
      name: 'Time-based Access Control',
      description: 'Restrict access during non-business hours',
      type: PolicyType.ACCESS_CONTROL,
      rules: [
        {
          condition: {
            field: 'request.time.hour',
            operator: 'not_in',
            value: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
          },
          action: PolicyAction.REQUIRE_APPROVAL
        }
      ],
      priority: 80
    }
  ],

  [PolicyType.DATA_RETENTION]: [
    {
      name: 'PII Data Retention',
      description: 'Automatically delete PII data after retention period',
      type: PolicyType.DATA_RETENTION,
      rules: [
        {
          condition: {
            field: 'data.classification',
            operator: 'equals',
            value: 'PII'
          },
          action: PolicyAction.LOG,
          parameters: {
            retentionDays: 2555, // 7 years
            deletionMethod: 'anonymize'
          }
        }
      ],
      priority: 100
    },
    {
      name: 'Log Retention Policy',
      description: 'Retain audit logs for compliance period',
      type: PolicyType.DATA_RETENTION,
      rules: [
        {
          condition: {
            field: 'data.type',
            operator: 'equals',
            value: 'audit_log'
          },
          action: PolicyAction.LOG,
          parameters: {
            retentionDays: 2555, // 7 years
            archiveAfterDays: 365
          }
        }
      ],
      priority: 90
    }
  ],

  [PolicyType.ENCRYPTION]: [
    {
      name: 'Encrypt Sensitive Data at Rest',
      description: 'Enforce encryption for all sensitive data storage',
      type: PolicyType.ENCRYPTION,
      rules: [
        {
          condition: {
            field: 'data.classification',
            operator: 'in',
            value: ['CONFIDENTIAL', 'RESTRICTED', 'TOP_SECRET']
          },
          action: PolicyAction.BLOCK,
          parameters: {
            requireEncryption: true,
            algorithm: 'AES-256-GCM'
          }
        }
      ],
      priority: 100
    },
    {
      name: 'TLS for Data in Transit',
      description: 'Require TLS 1.2+ for all data transmission',
      type: PolicyType.ENCRYPTION,
      rules: [
        {
          condition: {
            field: 'connection.protocol',
            operator: 'not_equals',
            value: 'https'
          },
          action: PolicyAction.DENY
        }
      ],
      priority: 100
    }
  ],

  [PolicyType.PASSWORD]: [
    {
      name: 'Strong Password Requirements',
      description: 'Enforce strong password complexity requirements',
      type: PolicyType.PASSWORD,
      rules: [
        {
          condition: {
            field: 'password.length',
            operator: 'less_than',
            value: 12
          },
          action: PolicyAction.DENY,
          parameters: {
            minLength: 12,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSpecialChars: true
          }
        }
      ],
      priority: 100
    },
    {
      name: 'Password Rotation Policy',
      description: 'Require password changes every 90 days',
      type: PolicyType.PASSWORD,
      rules: [
        {
          condition: {
            field: 'password.age_days',
            operator: 'greater_than',
            value: 90
          },
          action: PolicyAction.REQUIRE_MFA,
          parameters: {
            forceChange: true,
            notificationDays: [80, 85, 89]
          }
        }
      ],
      priority: 90
    }
  ],

  [PolicyType.SESSION]: [
    {
      name: 'Session Timeout Policy',
      description: 'Automatically terminate inactive sessions',
      type: PolicyType.SESSION,
      rules: [
        {
          condition: {
            field: 'session.idle_minutes',
            operator: 'greater_than',
            value: 30
          },
          action: PolicyAction.BLOCK,
          parameters: {
            terminateSession: true,
            requireReauth: true
          }
        }
      ],
      priority: 90
    },
    {
      name: 'Concurrent Session Limit',
      description: 'Limit concurrent sessions per user',
      type: PolicyType.SESSION,
      rules: [
        {
          condition: {
            field: 'user.concurrent_sessions',
            operator: 'greater_than',
            value: 3
          },
          action: PolicyAction.DENY,
          parameters: {
            maxSessions: 3,
            terminateOldest: true
          }
        }
      ],
      priority: 80
    }
  ],

  [PolicyType.AUDIT]: [
    {
      name: 'Log All Admin Actions',
      description: 'Comprehensive logging of administrative activities',
      type: PolicyType.AUDIT,
      rules: [
        {
          condition: {
            field: 'user.role',
            operator: 'in',
            value: ['admin', 'super_admin']
          },
          action: PolicyAction.LOG,
          parameters: {
            logLevel: 'detailed',
            includePayload: true
          }
        }
      ],
      priority: 100
    },
    {
      name: 'Failed Login Tracking',
      description: 'Track and alert on failed login attempts',
      type: PolicyType.AUDIT,
      rules: [
        {
          condition: {
            field: 'event.type',
            operator: 'equals',
            value: 'login_failed'
          },
          action: PolicyAction.ALERT,
          parameters: {
            threshold: 5,
            timeWindow: 300 // 5 minutes
          }
        }
      ],
      priority: 95
    }
  ],

  [PolicyType.EXPORT]: [
    {
      name: 'Data Export Approval',
      description: 'Require approval for large data exports',
      type: PolicyType.EXPORT,
      rules: [
        {
          condition: {
            field: 'export.record_count',
            operator: 'greater_than',
            value: 10000
          },
          action: PolicyAction.REQUIRE_APPROVAL,
          parameters: {
            approvers: ['data_protection_officer', 'security_admin'],
            expiryHours: 24
          }
        }
      ],
      priority: 90
    },
    {
      name: 'Sensitive Data Export Restriction',
      description: 'Block export of highly sensitive data',
      type: PolicyType.EXPORT,
      rules: [
        {
          condition: {
            field: 'data.classification',
            operator: 'equals',
            value: 'TOP_SECRET'
          },
          action: PolicyAction.DENY
        }
      ],
      priority: 100
    }
  ],

  [PolicyType.NOTIFICATION]: [
    {
      name: 'Security Alert Notifications',
      description: 'Send notifications for security events',
      type: PolicyType.NOTIFICATION,
      rules: [
        {
          condition: {
            field: 'event.severity',
            operator: 'in',
            value: ['CRITICAL', 'HIGH']
          },
          action: PolicyAction.ALERT,
          parameters: {
            channels: ['email', 'sms', 'slack'],
            recipients: ['security-team@company.com']
          }
        }
      ],
      priority: 100
    },
    {
      name: 'Compliance Violation Alerts',
      description: 'Alert on compliance policy violations',
      type: PolicyType.NOTIFICATION,
      rules: [
        {
          condition: {
            field: 'event.type',
            operator: 'equals',
            value: 'compliance_violation'
          },
          action: PolicyAction.ALERT,
          parameters: {
            escalation: true,
            includeDetails: true
          }
        }
      ],
      priority: 95
    }
  ],

  [PolicyType.INCIDENT_RESPONSE]: [
    {
      name: 'Automatic Incident Containment',
      description: 'Automatically contain security incidents',
      type: PolicyType.INCIDENT_RESPONSE,
      rules: [
        {
          condition: {
            field: 'incident.type',
            operator: 'in',
            value: ['malware_detected', 'intrusion_detected']
          },
          action: PolicyAction.QUARANTINE,
          parameters: {
            isolateNetwork: true,
            disableAccounts: true,
            notifySOC: true
          }
        }
      ],
      priority: 100
    },
    {
      name: 'Data Breach Response',
      description: 'Immediate response to data breach detection',
      type: PolicyType.INCIDENT_RESPONSE,
      rules: [
        {
          condition: {
            field: 'incident.type',
            operator: 'equals',
            value: 'data_breach'
          },
          action: PolicyAction.BLOCK,
          parameters: {
            lockdownMode: true,
            preserveEvidence: true,
            notifyLegal: true,
            notifyDPO: true
          }
        }
      ],
      priority: 100
    }
  ],

  [PolicyType.BACKUP]: [
    {
      name: 'Daily Backup Policy',
      description: 'Ensure daily backups of critical data',
      type: PolicyType.BACKUP,
      rules: [
        {
          condition: {
            field: 'data.criticality',
            operator: 'equals',
            value: 'critical'
          },
          action: PolicyAction.LOG,
          parameters: {
            frequency: 'daily',
            retention: 30,
            encryption: true,
            verification: true
          }
        }
      ],
      priority: 90
    },
    {
      name: 'Backup Integrity Check',
      description: 'Verify backup integrity regularly',
      type: PolicyType.BACKUP,
      rules: [
        {
          condition: {
            field: 'backup.age_days',
            operator: 'greater_than',
            value: 7
          },
          action: PolicyAction.ALERT,
          parameters: {
            performIntegrityCheck: true,
            alertOnFailure: true
          }
        }
      ],
      priority: 85
    }
  ]
};