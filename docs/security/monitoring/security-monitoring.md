# Security Monitoring (SIEM) Documentation

## Overview

The SPARC platform includes a comprehensive Security Information and Event Management (SIEM) system that monitors, detects, and responds to security events across all services. This system provides real-time threat detection, automated alerting, and compliance reporting capabilities.

## Architecture

### Components

1. **Security Event Collection**
   - Distributed event collectors in each service
   - Centralized event storage in PostgreSQL
   - Real-time processing via Redis

2. **Correlation Engine**
   - Time-based event correlation
   - User and IP-based correlation
   - Organization-wide threat detection

3. **Alert Rules Engine**
   - Configurable alert conditions
   - Multiple alert actions (email, webhook, Slack, PagerDuty, SMS)
   - Cooldown periods to prevent alert fatigue

4. **Attack Detection**
   - SQL injection detection
   - Cross-site scripting (XSS) detection
   - Path traversal detection
   - Command injection detection
   - Brute force attack detection

## Security Event Types

### Authentication Events
- `LOGIN_SUCCESS` - Successful user login
- `LOGIN_FAILURE` - Failed login attempt
- `LOGOUT` - User logout
- `PASSWORD_RESET` - Password reset initiated
- `MFA_CHALLENGE` - MFA challenge presented
- `MFA_SUCCESS` - MFA verification successful
- `MFA_FAILURE` - MFA verification failed

### Authorization Events
- `ACCESS_GRANTED` - Access granted to resource
- `ACCESS_DENIED` - Access denied to resource
- `PRIVILEGE_ESCALATION` - Privilege escalation attempt
- `ROLE_CHANGE` - User role modification

### Security Violations
- `BRUTE_FORCE_DETECTED` - Multiple failed login attempts
- `RATE_LIMIT_EXCEEDED` - API rate limit exceeded
- `SUSPICIOUS_ACTIVITY` - General suspicious behavior
- `CSRF_VIOLATION` - CSRF token validation failure
- `SQL_INJECTION_ATTEMPT` - SQL injection detected
- `XSS_ATTEMPT` - Cross-site scripting detected

### Data Access Events
- `SENSITIVE_DATA_ACCESS` - Access to sensitive data
- `DATA_EXPORT` - Data export operation
- `BULK_OPERATION` - Bulk data operation

### System Events
- `SERVICE_START` - Service started
- `SERVICE_STOP` - Service stopped
- `CONFIGURATION_CHANGE` - Configuration modified
- `CERTIFICATE_EXPIRY` - Certificate expiring soon

### Compliance Events
- `AUDIT_LOG_ACCESS` - Audit logs accessed
- `COMPLIANCE_VIOLATION` - Compliance rule violated
- `DATA_RETENTION_VIOLATION` - Data retention policy violated

## Implementation

### Recording Security Events

```typescript
import { logSecurityEvent, SecurityEventType, SecuritySeverity } from '@sparc/shared/security/siem';

// Log a security event
await logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, {
  severity: SecuritySeverity.INFO,
  source: 'auth-service',
  userId: user.id,
  organizationId: user.tenantId,
  ipAddress: clientIp,
  userAgent,
  details: {
    email: user.email,
    sessionId,
    mfaUsed: user.mfaEnabled
  }
});
```

### API Gateway Integration

The API Gateway includes automatic detection of common attacks:

```typescript
// SIEM middleware automatically detects:
// - SQL injection attempts
// - XSS attempts
// - Path traversal attacks
// - Command injection attempts

app.use('/api/v1/*', siemMiddleware);
```

### Alert Rules Configuration

Default alert rules include:

1. **Brute Force Detection**
   - Triggers after 5 failed login attempts in 5 minutes
   - Sends email notification
   - 30-minute cooldown period

2. **Privilege Escalation**
   - Immediate alert on any privilege escalation attempt
   - Email and Slack notifications

3. **SQL Injection**
   - Critical alert on SQL injection attempts
   - PagerDuty integration for immediate response

4. **Suspicious Data Access**
   - Monitors bulk operations and data exports
   - Triggers on 10+ sensitive operations in 10 minutes

## Security Metrics

The SIEM system provides comprehensive metrics:

```typescript
const metrics = await securityMonitoring.getSecurityMetrics({
  start: new Date('2024-01-01'),
  end: new Date()
});

// Returns:
// - Total events by type and severity
// - Top users generating events
// - Top sources of events
// - Trends over time
```

## Database Schema

### security_events table
```sql
CREATE TABLE security_events (
  id UUID PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  source VARCHAR(255) NOT NULL,
  user_id UUID REFERENCES users(id),
  organization_id UUID REFERENCES organizations(id),
  ip_address INET,
  user_agent TEXT,
  details JSONB NOT NULL,
  metadata JSONB
);
```

### alert_rules table
```sql
CREATE TABLE alert_rules (
  id UUID PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  conditions JSONB NOT NULL,
  actions JSONB NOT NULL,
  enabled BOOLEAN DEFAULT true,
  cooldown_minutes INTEGER
);
```

## Alert Actions

### Email Alerts
```typescript
{
  type: 'email',
  config: {
    recipients: ['security@company.com']
  }
}
```

### Webhook Alerts
```typescript
{
  type: 'webhook',
  config: {
    url: 'https://security.company.com/webhook',
    headers: { 'Authorization': 'Bearer token' }
  }
}
```

### Slack Alerts
```typescript
{
  type: 'slack',
  config: {
    webhookUrl: 'https://hooks.slack.com/services/...'
  }
}
```

### PagerDuty Alerts
```typescript
{
  type: 'pagerduty',
  config: {
    apiKey: 'your-api-key',
    routingKey: 'your-routing-key'
  }
}
```

## Best Practices

1. **Event Logging**
   - Log all authentication attempts
   - Record authorization failures
   - Track sensitive data access
   - Monitor configuration changes

2. **Alert Configuration**
   - Set appropriate thresholds to reduce false positives
   - Use cooldown periods to prevent alert fatigue
   - Configure multiple notification channels for critical alerts
   - Regularly review and update alert rules

3. **Attack Detection**
   - Keep attack patterns up to date
   - Monitor for new attack vectors
   - Implement rate limiting before attacks occur
   - Use SIEM data for threat hunting

4. **Compliance**
   - Enable audit log monitoring
   - Configure retention policies
   - Generate regular compliance reports
   - Document security incidents

## Integration with Services

### Auth Service
```typescript
// Automatically logs:
// - Login attempts (success/failure)
// - MFA challenges and results
// - Password resets
// - Brute force attacks
```

### API Gateway
```typescript
// Automatically logs:
// - Rate limit violations
// - CSRF token failures
// - SQL injection attempts
// - XSS attempts
// - Suspicious request patterns
```

### Access Control Service
```typescript
// Log door access events
await logSecurityEvent(SecurityEventType.ACCESS_GRANTED, {
  severity: SecuritySeverity.INFO,
  source: 'access-control',
  userId: credential.userId,
  organizationId: door.organizationId,
  details: {
    doorId: door.id,
    credentialType: 'card',
    location: door.location
  }
});
```

## Monitoring Dashboard

The SIEM system integrates with Grafana for visualization:

1. **Security Overview Dashboard**
   - Real-time event stream
   - Event distribution by type and severity
   - Geographic distribution of events
   - Top security risks

2. **Authentication Dashboard**
   - Login success/failure rates
   - MFA adoption metrics
   - Brute force attack trends
   - Account lockout statistics

3. **Threat Detection Dashboard**
   - Active threats by type
   - Attack patterns over time
   - Blocked requests statistics
   - Vulnerability scan results

## Incident Response

When security events are detected:

1. **Immediate Actions**
   - Block suspicious IP addresses
   - Lock compromised accounts
   - Invalidate affected sessions
   - Notify security team

2. **Investigation**
   - Review correlated events
   - Analyze attack patterns
   - Identify affected resources
   - Determine scope of breach

3. **Remediation**
   - Patch vulnerabilities
   - Update security rules
   - Reset affected credentials
   - Document lessons learned

## Environment Variables

```bash
# SIEM Configuration
SIEM_ENABLED=true
SIEM_RETENTION_DAYS=90
SIEM_ALERT_EMAIL=security@company.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_API_KEY=your-api-key
PAGERDUTY_ROUTING_KEY=your-routing-key
```

## Performance Considerations

1. **Event Storage**
   - Events are stored in PostgreSQL with proper indexes
   - Old events are automatically archived after retention period
   - Real-time events use Redis for processing

2. **Alert Processing**
   - Alerts are processed asynchronously
   - Failed alerts are retried with exponential backoff
   - Alert rules are cached in memory

3. **Attack Detection**
   - Pattern matching is optimized for performance
   - Only suspicious requests undergo deep inspection
   - False positives are minimized through tuning

## Future Enhancements

1. **Machine Learning**
   - Anomaly detection for user behavior
   - Predictive threat analysis
   - Automated response recommendations

2. **Integration**
   - SIEM platform integration (Splunk, ELK)
   - Threat intelligence feeds
   - Automated incident response

3. **Compliance**
   - Automated compliance reporting
   - Regulatory framework mapping
   - Evidence collection automation