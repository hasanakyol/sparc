# Audit Logging System

## Overview

SPARC implements comprehensive audit logging for security, compliance, and operational visibility. The system automatically tracks all data access and modifications with detailed context.

## Features

1. **Automatic Logging**: Prisma middleware captures all database operations
2. **Batch Processing**: Efficient batching reduces performance impact
3. **Compliance Reports**: Pre-built reports for SOC2, GDPR, HIPAA, PCI DSS
4. **Immutable Records**: Audit logs cannot be modified or deleted
5. **Sensitive Data Protection**: Automatic redaction of sensitive fields

## Architecture

### Components

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Application   │────▶│  Audit Logger    │────▶│  PostgreSQL     │
│   Middleware    │     │  (Batch Queue)   │     │  (audit_logs)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │ Compliance       │
                        │ Report Generator │
                        └──────────────────┘
```

### Audit Events

#### Authentication Events
- `LOGIN` - Successful login
- `LOGOUT` - User logout
- `LOGIN_FAILED` - Failed login attempt
- `PASSWORD_RESET` - Password reset initiated
- `PASSWORD_CHANGED` - Password changed
- `MFA_ENABLED` - MFA enabled
- `MFA_DISABLED` - MFA disabled
- `MFA_VERIFIED` - MFA verification successful

#### Resource Operations
- `CREATE` - Resource created
- `READ` - Resource accessed
- `UPDATE` - Resource modified
- `DELETE` - Resource deleted
- `BULK_CREATE` - Multiple resources created
- `BULK_UPDATE` - Multiple resources updated
- `BULK_DELETE` - Multiple resources deleted

#### Access Control
- `ACCESS_GRANTED` - Physical access granted
- `ACCESS_DENIED` - Physical access denied
- `PERMISSION_GRANTED` - Permission granted
- `PERMISSION_REVOKED` - Permission revoked
- `ROLE_ASSIGNED` - Role assigned
- `ROLE_REMOVED` - Role removed

#### Data Operations
- `EXPORT` - Data exported
- `IMPORT` - Data imported
- `DOWNLOAD` - File downloaded
- `SHARE` - Resource shared

#### Security Events
- `SECURITY_ALERT` - Security alert triggered
- `SUSPICIOUS_ACTIVITY` - Suspicious activity detected
- `RATE_LIMIT_EXCEEDED` - Rate limit exceeded
- `INVALID_TOKEN` - Invalid token used

## Implementation

### 1. Express Middleware Setup

```typescript
import { auditContextMiddleware } from '@sparc/shared/services/audit-logger';

// Add after authentication middleware
app.use(auditContextMiddleware);
```

### 2. Manual Audit Logging

```typescript
import { auditLogger, AuditAction, ResourceType } from '@sparc/shared/services/audit-logger';

// Log a successful action
await auditLogger.logSuccess(
  AuditAction.CREATE,
  ResourceType.USER,
  userId,
  { 
    source: 'admin-panel',
    ipAddress: req.ip 
  }
);

// Log a failed action
await auditLogger.logFailure(
  AuditAction.LOGIN_FAILED,
  ResourceType.USER,
  username,
  'Invalid credentials',
  { attempts: failedAttempts }
);

// Log data changes
await auditLogger.logChange(
  AuditAction.UPDATE,
  ResourceType.USER,
  userId,
  oldUserData,
  newUserData
);
```

### 3. Automatic Database Audit

The system automatically logs all Prisma operations:

```typescript
// This is automatic - no code needed!
const user = await prisma.user.create({
  data: { name: 'John', email: 'john@example.com' }
});
// Automatically logs: CREATE action on USER resource

await prisma.user.update({
  where: { id: userId },
  data: { name: 'Jane' }
});
// Automatically logs: UPDATE action with before/after values
```

### 4. Query Audit Logs

```typescript
// Basic query
const logs = await auditLogger.query({
  tenantId: 'tenant-123',
  startDate: new Date('2024-01-01'),
  endDate: new Date('2024-01-31'),
  limit: 100
});

// Advanced query
const securityLogs = await auditLogger.query({
  tenantId: 'tenant-123',
  action: [
    AuditAction.LOGIN_FAILED,
    AuditAction.SUSPICIOUS_ACTIVITY
  ],
  resourceType: ResourceType.USER,
  result: 'failure',
  orderBy: 'timestamp',
  order: 'desc'
});

// User activity
const userActivity = await auditLogger.query({
  tenantId: 'tenant-123',
  userId: 'user-456',
  limit: 50
});
```

## Compliance Reports

### SOC 2 Access Control Report

```typescript
import { complianceReports } from '@sparc/shared/services/compliance-reports';

const soc2Report = await complianceReports.generateSOC2AccessControlReport(
  tenantId,
  startDate,
  endDate,
  requestingUserId
);

// Report includes:
// - User access changes
// - Failed login attempts
// - Privileged actions
// - System configuration changes
// - Access reviews
```

### GDPR Data Access Report

```typescript
const gdprReport = await complianceReports.generateGDPRDataAccessReport(
  tenantId,
  dataSubjectId, // User requesting their data
  requestingUserId
);

// Report includes:
// - All personal data
// - Access history
// - Video recordings
// - Processing purposes
// - Data sharing information
```

### HIPAA Access Log Report

```typescript
const hipaaReport = await complianceReports.generateHIPAAAccessLogReport(
  tenantId,
  startDate,
  endDate,
  requestingUserId
);

// Report includes:
// - All PHI access
// - Unauthorized attempts
// - Data modifications
// - Security incidents
```

### Custom Reports

```typescript
const customReport = await complianceReports.generateCustomReport(
  tenantId,
  startDate,
  endDate,
  requestingUserId,
  {
    includeAccessLogs: true,
    includeSecurityEvents: true,
    customQueries: [
      {
        name: 'admin_actions',
        action: [AuditAction.CREATE, AuditAction.DELETE],
        resourceType: [ResourceType.USER, ResourceType.ACCESS_GROUP]
      }
    ]
  }
);
```

## Performance Optimization

### Batch Processing
- Logs are batched every 5 seconds or 100 entries
- Reduces database writes by 90%+
- Automatic flush on request completion

### Indexing
```sql
-- Optimized indexes for common queries
CREATE INDEX idx_audit_logs_tenant_timestamp ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_logs_user_timestamp ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
```

### Data Retention

```typescript
// Clean up old logs (runs daily)
const deletedCount = await auditLogger.cleanup(365); // Keep 1 year
```

## Security Considerations

### Sensitive Data Redaction
The following fields are automatically redacted:
- `password`, `passwordHash`
- `token`, `secret`, `apiKey`
- `privateKey`, `creditCard`, `ssn`
- `pinCode`, `mfaSecret`
- `encryptionKey`

### Immutability
- No UPDATE operations allowed on audit_logs
- No DELETE operations except through retention policy
- Row-level security prevents tampering

### Access Control
- Only users with `audit:read` permission can view logs
- Super admins can view cross-tenant logs
- Regular users can only see their tenant's logs

## Monitoring & Alerts

### Key Metrics
```typescript
// Get audit statistics
const stats = await auditLogger.generateReport(
  tenantId,
  startDate,
  endDate,
  { groupBy: 'action' }
);

// Monitor for suspicious activity
const suspiciousActivity = await auditLogger.query({
  action: AuditAction.SUSPICIOUS_ACTIVITY,
  startDate: new Date(Date.now() - 3600000), // Last hour
});
```

### Alert Conditions
- Multiple failed login attempts (>5 in 5 minutes)
- Privilege escalation attempts
- Mass data exports
- Configuration changes
- After-hours access

## Troubleshooting

### Common Issues

1. **Missing audit logs**
   - Check audit context middleware is applied
   - Verify tenant context is set
   - Check batch queue hasn't failed

2. **Performance impact**
   - Increase batch size/delay
   - Add more specific indexes
   - Use read replicas for queries

3. **Storage growth**
   - Implement retention policy
   - Archive old logs to cold storage
   - Compress log details

### Debug Mode

```typescript
// Enable verbose logging
process.env.AUDIT_DEBUG = 'true';

// Check pending batch
console.log(auditLogger.batchQueue);

// Force flush
await auditLogger.flush();
```

## Best Practices

1. **Use appropriate audit actions** - Choose specific actions over generic ones
2. **Include context** - Add relevant details to help investigations
3. **Don't over-audit** - Exclude high-frequency, low-value operations
4. **Regular reviews** - Schedule periodic audit log reviews
5. **Automate compliance** - Use pre-built reports for audits
6. **Monitor anomalies** - Set up alerts for unusual patterns
7. **Test retention** - Verify cleanup doesn't break compliance

## Compliance Mapping

| Requirement | Implementation |
|------------|----------------|
| SOC 2 CC6.1 | Logical access logging |
| GDPR Art. 30 | Processing activity records |
| HIPAA §164.312(b) | Audit controls |
| PCI DSS 10.2 | User access logging |
| ISO 27001 A.12.4 | Event logging |

## API Reference

### AuditLogger Methods
- `log(entry)` - Log an audit entry
- `logSuccess(action, resourceType, resourceId, details)` - Log successful action
- `logFailure(action, resourceType, resourceId, error, details)` - Log failed action
- `logChange(action, resourceType, resourceId, oldValues, newValues)` - Log data change
- `query(filters)` - Query audit logs
- `generateReport(tenantId, startDate, endDate, options)` - Generate audit report
- `cleanup(retentionDays)` - Clean up old logs
- `flush()` - Force flush pending logs

### ComplianceReports Methods
- `generateSOC2AccessControlReport()` - SOC 2 report
- `generateGDPRDataAccessReport()` - GDPR data access report
- `generateHIPAAAccessLogReport()` - HIPAA access log
- `generatePCIDSSReport()` - PCI DSS compliance report
- `generateISO27001Report()` - ISO 27001 security events
- `generateCustomReport()` - Custom compliance report