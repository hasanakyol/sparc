# Security Monitoring Service

Comprehensive Security Information and Event Management (SIEM) integration for the SPARC platform.

## Features

### Core Capabilities
- **Real-time Security Event Collection**: Collects events from all SPARC services
- **SIEM Integration**: Native support for Splunk, ELK Stack, DataDog, and more
- **Threat Detection**: Advanced pattern matching and ML-based anomaly detection
- **Incident Management**: Full incident lifecycle from detection to resolution
- **Compliance Monitoring**: SOC2, PCI-DSS, HIPAA, GDPR, ISO27001 compliance tracking
- **Security Dashboards**: Real-time security metrics and visualizations
- **Alert Management**: Customizable alert rules with multiple notification channels

### Security Event Types
- Authentication events (login success/failure, MFA, password resets)
- Authorization events (access granted/denied, privilege escalation)
- Security violations (brute force, SQL injection, XSS attempts)
- Data access events (sensitive data access, exports, bulk operations)
- System events (configuration changes, service start/stop)

### Threat Detection Capabilities
- **Pattern-Based Detection**:
  - Brute force attacks
  - Credential stuffing
  - Privilege escalation attempts
  - Data exfiltration patterns
  - Lateral movement detection
  
- **Behavioral Analysis**:
  - Unusual access times
  - Geographic anomalies
  - Impossible travel detection
  - User behavior baselines

- **Machine Learning**:
  - Anomaly detection
  - Risk scoring
  - Predictive threat analysis

## API Endpoints

### Security Events
- `GET /api/security-events` - Query security events
- `POST /api/security-events` - Record a security event
- `GET /api/security-events/:id` - Get event by ID
- `GET /api/security-events/stats/summary` - Event statistics
- `POST /api/security-events/export` - Export events

### Alerts
- `GET /api/alerts/rules` - List alert rules
- `POST /api/alerts/rules` - Create alert rule
- `GET /api/alerts/active` - Get active alerts
- `PATCH /api/alerts/:id` - Update alert status
- `POST /api/alerts/rules/:id/test` - Test alert rule

### Incidents
- `GET /api/incidents` - List incidents
- `POST /api/incidents` - Create incident
- `PATCH /api/incidents/:id` - Update incident
- `POST /api/incidents/:id/timeline` - Add timeline entry
- `GET /api/incidents/playbooks` - Get response playbooks

### Threats
- `GET /api/threats/indicators` - List threat indicators
- `POST /api/threats/indicators` - Add threat indicator
- `GET /api/threats/patterns` - List security patterns
- `POST /api/threats/check` - Check if value is a threat

### SIEM Integration
- `GET /api/siem/providers` - List SIEM providers
- `POST /api/siem/providers` - Add SIEM provider
- `POST /api/siem/query` - Query SIEM
- `GET /api/siem/sync/status` - Sync status

### Compliance
- `GET /api/compliance/reports` - List compliance reports
- `POST /api/compliance/reports/generate` - Generate report
- `GET /api/compliance/controls` - List controls
- `PATCH /api/compliance/controls/:id` - Update control status

### Dashboards & Metrics
- `GET /api/dashboards` - List dashboards
- `POST /api/dashboards` - Create dashboard
- `GET /api/metrics` - Get security metrics
- `GET /api/metrics/realtime` - Real-time metrics

## Configuration

### Environment Variables
```bash
# Service Configuration
PORT=3020
NODE_ENV=production

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/sparc

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# SIEM Providers
SPLUNK_URL=https://splunk.example.com:8089
SPLUNK_TOKEN=your-hec-token
SPLUNK_INDEX=main

ELASTICSEARCH_URL=https://elastic.example.com:9200
ELASTICSEARCH_API_KEY=your-api-key

DATADOG_API_KEY=your-dd-api-key
DATADOG_APP_KEY=your-dd-app-key

# Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_API_KEY=your-pd-key
PAGERDUTY_ROUTING_KEY=your-routing-key

# Security
JWT_SECRET=your-jwt-secret
```

## Development

### Setup
```bash
npm install
npm run dev
```

### Testing
```bash
npm test
npm run test:integration
```

### Building
```bash
npm run build
npm run start
```

## WebSocket Real-time Events

Connect to WebSocket endpoint with authentication token:
```javascript
const ws = new WebSocket('ws://localhost:3020?token=JWT_TOKEN');

// Subscribe to channels
ws.send(JSON.stringify({
  type: 'subscribe',
  channels: ['security:events', 'incidents', 'alerts']
}));

// Receive real-time updates
ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log('Security event:', event);
});
```

### Available Channels
- `security:events` - All security events
- `incidents` - Incident updates
- `alerts` - Alert notifications
- `threats` - Threat detections
- `metrics` - System metrics
- `org:{orgId}` - Organization-specific events

## Alert Rule Examples

### Brute Force Detection
```json
{
  "name": "Brute Force Detection",
  "conditions": [{
    "field": "eventType",
    "operator": "equals",
    "value": "LOGIN_FAILURE",
    "aggregation": {
      "window": 5,
      "threshold": 5
    }
  }],
  "actions": [{
    "type": "email",
    "config": {
      "recipients": ["security@example.com"]
    }
  }]
}
```

### Data Exfiltration Detection
```json
{
  "name": "Suspicious Data Export",
  "conditions": [{
    "field": "eventType",
    "operator": "in",
    "value": ["DATA_EXPORT", "BULK_OPERATION"],
    "aggregation": {
      "window": 10,
      "threshold": 10
    }
  }],
  "actions": [{
    "type": "pagerduty",
    "config": {
      "severity": "high"
    }
  }]
}
```

## Compliance Frameworks

### Supported Frameworks
- **SOC 2**: Service Organization Control 2
- **PCI DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **GDPR**: General Data Protection Regulation
- **ISO 27001**: Information Security Management System

### Automated Controls
- Access control monitoring
- Audit log integrity
- Data encryption verification
- Security training compliance
- Incident response metrics

## Architecture

### Components
1. **Event Collector**: Ingests events from all services
2. **Threat Detection Engine**: Real-time threat analysis
3. **Correlation Engine**: Links related events
4. **Alert Manager**: Rule evaluation and notifications
5. **SIEM Forwarder**: Sends events to external SIEM
6. **Compliance Engine**: Continuous compliance monitoring

### Data Flow
```
Services → Event Collector → Threat Detection → Correlation
                ↓                    ↓              ↓
             Database           Alert Rules    SIEM Providers
                ↓                    ↓              ↓
            Dashboards          Notifications   External SIEM
```

## Performance

- Processes 10,000+ events/second
- Sub-second threat detection
- Real-time SIEM forwarding
- Horizontal scaling support
- Event batching for efficiency

## Security

- End-to-end encryption
- JWT authentication
- Role-based access control
- Audit logging
- Data retention policies