# SPARC Security Operations Manual

## Overview
This manual provides comprehensive security operations procedures for the SPARC Security Platform, covering monitoring, incident response, compliance, and security maintenance.

## Security Architecture

### Defense in Depth Strategy

```
┌─────────────────────────────────────────┐
│         External WAF/DDoS               │
├─────────────────────────────────────────┤
│      Load Balancer (TLS 1.3)           │
├─────────────────────────────────────────┤
│    API Gateway (Rate Limiting)          │
├─────────────────────────────────────────┤
│   Service Mesh (mTLS, Policies)        │
├─────────────────────────────────────────┤
│  Application Layer (RBAC, Encryption)   │
├─────────────────────────────────────────┤
│    Data Layer (Encryption at Rest)      │
└─────────────────────────────────────────┘
```

### Security Components

1. **Web Application Firewall (WAF)**
   - OWASP Core Rule Set
   - Custom rules for SPARC
   - Rate limiting
   - Geo-blocking

2. **Identity & Access Management**
   - Multi-factor authentication
   - SSO integration (SAML/OAuth2)
   - Role-based access control
   - Privileged access management

3. **Network Security**
   - Network segmentation
   - Zero-trust architecture
   - Service mesh (Istio)
   - Network policies

4. **Data Security**
   - Encryption at rest (AES-256)
   - Encryption in transit (TLS 1.3)
   - Key management (HSM/KMS)
   - Data loss prevention

## Daily Security Operations

### Morning Security Checklist

```bash
#!/bin/bash
# Daily security check script

echo "🔒 SPARC Daily Security Check - $(date)"
echo "====================================="

# 1. Check security alerts
echo "1. Checking security alerts..."
kubectl logs -n security deployment/security-monitoring --since=24h | grep -i "critical\|high" | wc -l

# 2. Review failed authentication attempts
echo "2. Failed authentication attempts..."
kubectl exec -it deployment/auth-service -- \
  psql -c "SELECT COUNT(*) FROM auth_logs WHERE status='failed' AND timestamp > NOW() - INTERVAL '24 hours'"

# 3. Check WAF blocks
echo "3. WAF blocked requests..."
aws wafv2 get-sampled-requests \
  --web-acl-arn $WAF_ARN \
  --rule-metric-name ALL \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '24 hours ago' +%s),EndTime=$(date +%s) \
  --max-items 100 | jq '.SampledRequests | length'

# 4. Verify security patches
echo "4. Checking for security updates..."
kubectl get nodes -o json | jq '.items[].status.nodeInfo.kubeletVersion'

# 5. Review access logs
echo "5. Unusual access patterns..."
./scripts/security/analyze-access-patterns.sh --duration 24h

echo "====================================="
echo "Security check complete"
```

### Real-time Security Monitoring

#### Security Event Stream
```typescript
// Security monitoring service
class SecurityMonitor {
  private eventStream: EventEmitter;
  private alertThresholds = {
    failedLogins: 5,
    suspiciousActivity: 3,
    privilegeEscalation: 1,
    dataExfiltration: 1
  };

  async processSecurityEvent(event: SecurityEvent) {
    // Enrich event with context
    const enrichedEvent = await this.enrichEvent(event);
    
    // Check against threat intelligence
    const threatLevel = await this.checkThreatIntel(enrichedEvent);
    
    // Analyze for patterns
    const pattern = await this.detectPattern(enrichedEvent);
    
    // Generate alert if needed
    if (this.shouldAlert(enrichedEvent, threatLevel, pattern)) {
      await this.generateAlert(enrichedEvent);
    }
    
    // Store for analysis
    await this.storeEvent(enrichedEvent);
  }

  private async enrichEvent(event: SecurityEvent) {
    return {
      ...event,
      geoLocation: await this.getGeoLocation(event.ipAddress),
      userHistory: await this.getUserHistory(event.userId),
      deviceFingerprint: await this.getDeviceFingerprint(event.sessionId),
      riskScore: await this.calculateRiskScore(event)
    };
  }

  private async detectPattern(event: EnrichedSecurityEvent) {
    const patterns = [
      this.detectBruteForce,
      this.detectAccountTakeover,
      this.detectPrivilegeEscalation,
      this.detectDataExfiltration,
      this.detectInsiderThreat
    ];

    for (const detectFn of patterns) {
      const result = await detectFn.call(this, event);
      if (result) return result;
    }

    return null;
  }
}
```

#### Security Dashboards

**Grafana Dashboard Queries**

```promql
# Authentication Security
sum(rate(auth_failures_total[5m])) by (user_id)
sum(rate(auth_success_total[5m])) by (auth_method)
histogram_quantile(0.99, auth_duration_bucket)

# Access Control
sum(rate(access_denied_total[5m])) by (resource, action)
sum(rate(privilege_escalation_attempts[5m]))
count(count by (user_id)(access_granted_total))

# Threat Detection
sum(rate(security_events_total[5m])) by (severity, type)
sum(increase(blocked_ips_total[1h]))
avg(threat_risk_score) by (category)

# Data Security
sum(rate(encryption_operations_total[5m])) by (operation)
sum(rate(data_access_total[5m])) by (classification)
count(sensitive_data_access_total) by (user_role)
```

## Threat Detection and Response

### Automated Threat Detection

#### Machine Learning Models
```python
# Anomaly detection for user behavior
from sklearn.ensemble import IsolationForest
import numpy as np

class UserBehaviorAnalyzer:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.01,
            random_state=42
        )
        self.feature_names = [
            'login_hour', 'login_location_entropy',
            'resource_access_count', 'data_download_volume',
            'failed_auth_ratio', 'session_duration'
        ]
    
    def train(self, historical_data):
        features = self.extract_features(historical_data)
        self.model.fit(features)
    
    def detect_anomaly(self, user_activity):
        features = self.extract_features([user_activity])
        anomaly_score = self.model.decision_function(features)[0]
        is_anomaly = self.model.predict(features)[0] == -1
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(anomaly_score),
            'risk_level': self.calculate_risk_level(anomaly_score)
        }
    
    def calculate_risk_level(self, score):
        if score < -0.5:
            return 'CRITICAL'
        elif score < -0.3:
            return 'HIGH'
        elif score < -0.1:
            return 'MEDIUM'
        else:
            return 'LOW'
```

#### Threat Intelligence Integration
```typescript
// Threat intelligence service
class ThreatIntelligenceService {
  private feeds = [
    'https://api.abuseipdb.com/api/v2',
    'https://otx.alienvault.com/api/v1',
    'https://api.threatcrowd.org/v2'
  ];

  async checkIP(ip: string): Promise<ThreatInfo> {
    const results = await Promise.all(
      this.feeds.map(feed => this.queryFeed(feed, ip))
    );

    return {
      ip,
      reputation: this.calculateReputation(results),
      threats: this.aggregateThreats(results),
      lastSeen: new Date(),
      confidence: this.calculateConfidence(results)
    };
  }

  async checkDomain(domain: string): Promise<DomainThreatInfo> {
    // Check domain reputation
    const whois = await this.getWhoisInfo(domain);
    const dnsHistory = await this.getDNSHistory(domain);
    const sslInfo = await this.getSSLInfo(domain);

    return {
      domain,
      registrationAge: this.calculateAge(whois.created),
      sslGrade: sslInfo.grade,
      maliciousScore: this.calculateMaliciousScore(domain),
      phishingProbability: this.checkPhishing(domain)
    };
  }
}
```

### Incident Response Automation

#### Automated Response Actions
```typescript
// Automated incident response
class IncidentResponder {
  async respond(incident: SecurityIncident) {
    const responseActions = this.determineActions(incident);
    
    for (const action of responseActions) {
      await this.executeAction(action, incident);
    }
    
    await this.notifyTeam(incident, responseActions);
  }

  private determineActions(incident: SecurityIncident): ResponseAction[] {
    const actions: ResponseAction[] = [];

    switch (incident.type) {
      case 'BRUTE_FORCE':
        actions.push(
          { type: 'BLOCK_IP', duration: 3600 },
          { type: 'FORCE_MFA', userId: incident.userId },
          { type: 'NOTIFY_USER' }
        );
        break;

      case 'ACCOUNT_TAKEOVER':
        actions.push(
          { type: 'SUSPEND_ACCOUNT', userId: incident.userId },
          { type: 'REVOKE_SESSIONS', userId: incident.userId },
          { type: 'FORCE_PASSWORD_RESET' },
          { type: 'NOTIFY_SECURITY_TEAM', priority: 'HIGH' }
        );
        break;

      case 'DATA_EXFILTRATION':
        actions.push(
          { type: 'BLOCK_USER', userId: incident.userId },
          { type: 'SUSPEND_API_KEYS', userId: incident.userId },
          { type: 'SNAPSHOT_ACTIVITY', duration: 7200 },
          { type: 'NOTIFY_LEGAL', priority: 'CRITICAL' }
        );
        break;

      case 'PRIVILEGE_ESCALATION':
        actions.push(
          { type: 'REVOKE_PRIVILEGES', userId: incident.userId },
          { type: 'AUDIT_PERMISSIONS' },
          { type: 'ISOLATE_ACCOUNT' },
          { type: 'FORENSIC_CAPTURE' }
        );
        break;
    }

    return actions;
  }

  private async executeAction(action: ResponseAction, incident: SecurityIncident) {
    console.log(`Executing ${action.type} for incident ${incident.id}`);
    
    switch (action.type) {
      case 'BLOCK_IP':
        await this.waf.blockIP(incident.sourceIP, action.duration);
        break;
        
      case 'SUSPEND_ACCOUNT':
        await this.auth.suspendAccount(action.userId);
        break;
        
      case 'REVOKE_SESSIONS':
        await this.auth.revokeAllSessions(action.userId);
        break;
        
      case 'FORENSIC_CAPTURE':
        await this.forensics.captureUserActivity(action.userId);
        break;
    }
    
    await this.auditLog.record({
      action: action.type,
      incident: incident.id,
      timestamp: new Date(),
      automated: true
    });
  }
}
```

## Compliance and Audit

### Compliance Frameworks

#### SOC2 Controls
```yaml
# SOC2 Type II Controls Implementation

CC1.1 - Control Environment:
  - Security awareness training: Quarterly
  - Background checks: All employees
  - Code of conduct: Annual acknowledgment

CC2.1 - Information and Communication:
  - Security policies: Published and accessible
  - Incident communication: Within 24 hours
  - Security metrics: Monthly reporting

CC3.1 - Risk Assessment:
  - Annual risk assessment: Complete
  - Vulnerability scanning: Weekly
  - Penetration testing: Quarterly

CC4.1 - Monitoring Activities:
  - Continuous monitoring: 24/7 SOC
  - Log aggregation: Centralized SIEM
  - Anomaly detection: ML-based

CC5.1 - Control Activities:
  - Change management: Approved workflows
  - Access reviews: Quarterly
  - Security testing: Each deployment

CC6.1 - Logical and Physical Access:
  - MFA required: All users
  - Privileged access: Time-limited
  - Access logs: 1-year retention

CC7.1 - System Operations:
  - Vulnerability management: 30-day SLA
  - Patch management: Critical within 72h
  - Capacity monitoring: Real-time

CC8.1 - Change Management:
  - Code reviews: Required
  - Security testing: Automated
  - Deployment approval: Multi-stage

CC9.1 - Risk Mitigation:
  - Incident response: Documented
  - Business continuity: Tested annually
  - Insurance coverage: Cyber liability
```

#### GDPR Compliance
```typescript
// GDPR compliance implementation
class GDPRCompliance {
  // Right to access
  async handleDataAccessRequest(userId: string): Promise<UserData> {
    const data = await this.collectUserData(userId);
    const anonymized = this.anonymizeSensitiveData(data);
    
    await this.auditLog.record({
      type: 'GDPR_ACCESS_REQUEST',
      userId,
      timestamp: new Date(),
      dataCategories: Object.keys(data)
    });
    
    return anonymized;
  }

  // Right to erasure
  async handleDeletionRequest(userId: string): Promise<DeletionReport> {
    // Verify identity
    await this.verifyIdentity(userId);
    
    // Check legal obligations
    const obligations = await this.checkLegalObligations(userId);
    if (obligations.mustRetain) {
      throw new Error(`Cannot delete: ${obligations.reason}`);
    }
    
    // Perform deletion
    const report = await this.deleteUserData(userId);
    
    // Notify third parties
    await this.notifyThirdParties(userId);
    
    return report;
  }

  // Data portability
  async exportUserData(userId: string): Promise<Buffer> {
    const data = await this.collectUserData(userId);
    
    // Convert to machine-readable format
    const exported = {
      format: 'JSON',
      version: '1.0',
      exportDate: new Date().toISOString(),
      data: data
    };
    
    // Encrypt the export
    const encrypted = await this.encrypt(JSON.stringify(exported));
    
    return encrypted;
  }

  // Consent management
  async updateConsent(userId: string, consent: ConsentUpdate): Promise<void> {
    await this.db.transaction(async (trx) => {
      // Record consent change
      await trx.insert('consent_history', {
        userId,
        type: consent.type,
        granted: consent.granted,
        timestamp: new Date(),
        ipAddress: consent.ipAddress,
        userAgent: consent.userAgent
      });
      
      // Update current consent
      await trx.upsert('user_consent', {
        userId,
        [consent.type]: consent.granted,
        updatedAt: new Date()
      });
      
      // Apply consent changes
      if (!consent.granted) {
        await this.restrictProcessing(userId, consent.type);
      }
    });
  }
}
```

### Security Auditing

#### Audit Log Analysis
```bash
#!/bin/bash
# Security audit analysis script

# Extract security-relevant events
echo "Extracting security events..."
kubectl logs -l app=audit-aggregator --since=168h > audit_logs.json

# Analyze access patterns
jq -r '.[] | select(.event_type == "ACCESS_GRANTED" or .event_type == "ACCESS_DENIED") | 
  "\(.timestamp)\t\(.user_id)\t\(.resource)\t\(.action)\t\(.result)"' audit_logs.json | 
  sort | uniq -c | sort -rn > access_analysis.txt

# Find privilege escalations
jq -r '.[] | select(.event_type == "PRIVILEGE_CHANGE") |
  "\(.timestamp)\t\(.user_id)\t\(.old_role)\t\(.new_role)\t\(.changed_by)"' audit_logs.json > 
  privilege_changes.txt

# Detect anomalies
python3 << EOF
import json
import pandas as pd
from datetime import datetime, timedelta

with open('audit_logs.json', 'r') as f:
    logs = [json.loads(line) for line in f]

df = pd.DataFrame(logs)
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Unusual access times
night_access = df[(df['timestamp'].dt.hour < 6) | (df['timestamp'].dt.hour > 22)]
if not night_access.empty:
    print("⚠️  Unusual access times detected:")
    print(night_access[['timestamp', 'user_id', 'event_type']].head(10))

# High-frequency access
freq_access = df.groupby(['user_id', df['timestamp'].dt.date]).size()
suspicious = freq_access[freq_access > 1000]
if not suspicious.empty:
    print("\n⚠️  High-frequency access detected:")
    print(suspicious.head(10))

# Failed authentication spikes
failed_auth = df[df['event_type'] == 'AUTH_FAILED']
failed_by_hour = failed_auth.groupby(df['timestamp'].dt.floor('H')).size()
spikes = failed_by_hour[failed_by_hour > failed_by_hour.mean() + 2*failed_by_hour.std()]
if not spikes.empty:
    print("\n⚠️  Authentication failure spikes:")
    print(spikes)
EOF
```

## Security Maintenance

### Vulnerability Management

#### Automated Scanning
```yaml
# Vulnerability scanning pipeline
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-scanning
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: dependency-scan
            image: owasp/dependency-check
            command:
            - sh
            - -c
            - |
              dependency-check --project SPARC \
                --scan /app \
                --format JSON \
                --out /reports/dependency-report.json
              
          - name: container-scan
            image: aquasec/trivy
            command:
            - sh
            - -c
            - |
              for image in $(kubectl get pods -o jsonpath="{..image}" | tr " " "\n" | sort -u); do
                trivy image --format json --output /reports/trivy-${image//\//-}.json $image
              done
              
          - name: k8s-scan
            image: aquasec/kube-bench
            command:
            - kube-bench
            - run
            - --targets
            - master,node,etcd,policies
            - --json
            - --outputfile
            - /reports/kube-bench.json
```

#### Patch Management Process
```typescript
// Automated patch management
class PatchManager {
  async scanForUpdates(): Promise<PatchReport> {
    const vulnerabilities = await this.scanVulnerabilities();
    const updates = await this.checkUpdates();
    
    return {
      critical: this.filterCritical(vulnerabilities),
      high: this.filterHigh(vulnerabilities),
      available: updates,
      recommended: this.prioritizePatches(vulnerabilities, updates)
    };
  }

  async applyPatches(patches: Patch[], environment: string) {
    // Create backup
    const backup = await this.createBackup(environment);
    
    try {
      // Apply patches in order
      for (const patch of patches) {
        await this.validatePatch(patch);
        await this.applyPatch(patch, environment);
        await this.verifyPatch(patch, environment);
      }
      
      // Run security tests
      await this.runSecurityTests(environment);
      
      // Update compliance records
      await this.updateComplianceRecords(patches);
      
    } catch (error) {
      // Rollback on failure
      await this.rollback(backup);
      throw error;
    }
  }

  private prioritizePatches(vulns: Vulnerability[], updates: Update[]): Patch[] {
    return updates
      .map(update => ({
        ...update,
        priority: this.calculatePriority(update, vulns),
        risk: this.assessRisk(update),
        testingRequired: this.determineTestingLevel(update)
      }))
      .sort((a, b) => b.priority - a.priority);
  }
}
```

### Security Key Rotation

#### Automated Key Rotation
```bash
#!/bin/bash
# Security key rotation script

# Rotate JWT signing keys
echo "Rotating JWT signing keys..."
NEW_JWT_KEY=$(openssl rand -base64 64)
kubectl create secret generic jwt-keys-new \
  --from-literal=private-key="$NEW_JWT_KEY" \
  --from-literal=created-at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Update services to use new key
kubectl set env deployment/auth-service JWT_KEY_NAME=jwt-keys-new

# Rotate database encryption keys
echo "Rotating database encryption keys..."
NEW_DB_KEY=$(openssl rand -hex 32)
kubectl exec -it deployment/postgresql -- psql -c "
  SELECT pgp_sym_encrypt('key_rotation', '$NEW_DB_KEY');
  UPDATE encryption_keys SET 
    key_data = pgp_sym_encrypt(key_data, '$NEW_DB_KEY'),
    rotated_at = NOW()
  WHERE key_type = 'DATABASE';
"

# Rotate API keys
echo "Rotating API keys..."
kubectl exec -it deployment/api-gateway -- node -e "
  const crypto = require('crypto');
  const apiKeys = process.env.API_KEYS.split(',');
  const newKeys = apiKeys.map(k => crypto.randomBytes(32).toString('hex'));
  console.log('New API keys:', newKeys.join(','));
"

# Schedule old key removal
echo "Scheduling old key removal in 24 hours..."
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: cleanup-old-keys-$(date +%s)
spec:
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      containers:
      - name: cleanup
        image: sparc/key-cleanup:latest
        command: ["./cleanup-keys.sh", "--older-than", "24h"]
EOF
```

## Security Metrics and KPIs

### Security Dashboard Metrics

```yaml
# Key security metrics to track
metrics:
  - name: Mean Time to Detect (MTTD)
    target: < 5 minutes
    query: avg(security_incident_detection_time)
    
  - name: Mean Time to Respond (MTTR)
    target: < 30 minutes
    query: avg(security_incident_response_time)
    
  - name: Vulnerability Remediation Time
    target: 
      critical: < 24 hours
      high: < 7 days
      medium: < 30 days
    query: avg(vulnerability_patch_time) by (severity)
    
  - name: Failed Authentication Rate
    target: < 5%
    query: rate(auth_failures_total) / rate(auth_attempts_total)
    
  - name: Security Training Completion
    target: 100%
    query: count(users_completed_training) / count(total_users)
    
  - name: Patch Coverage
    target: > 95%
    query: count(patched_systems) / count(total_systems)
    
  - name: Encryption Coverage
    target: 100%
    query: count(encrypted_data_stores) / count(total_data_stores)
    
  - name: MFA Adoption
    target: > 95%
    query: count(users_with_mfa) / count(total_users)
    
  - name: Security Incident Rate
    target: < 0.1%
    query: count(security_incidents) / count(total_transactions)
    
  - name: Compliance Score
    target: > 95%
    query: sum(passed_controls) / sum(total_controls)
```

### Monthly Security Report Template

```markdown
# SPARC Security Report - [Month Year]

## Executive Summary
- Overall Security Posture: [Score/100]
- Critical Incidents: [Count]
- Compliance Status: [Percentage]

## Key Metrics
| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| MTTD | <5 min | X min | ✓/✗ |
| MTTR | <30 min | X min | ✓/✗ |
| Vulnerability Remediation | <24h | Xh | ✓/✗ |
| Failed Auth Rate | <5% | X% | ✓/✗ |

## Incident Summary
- Total Incidents: X
- Critical: X
- High: X
- Medium: X
- Low: X

## Vulnerability Status
- New Vulnerabilities: X
- Remediated: X
- In Progress: X
- Accepted Risk: X

## Compliance Updates
- SOC2: [Status]
- GDPR: [Status]
- PCI-DSS: [Status]
- HIPAA: [Status]

## Action Items
1. [Priority 1 Action]
2. [Priority 2 Action]
3. [Priority 3 Action]

## Next Month Focus
- [Focus Area 1]
- [Focus Area 2]
- [Focus Area 3]
```

## Security Tools and Resources

### Security Scripts Location
```
/scripts/security/
├── daily-security-check.sh
├── incident-response/
│   ├── isolate-account.sh
│   ├── forensic-capture.sh
│   └── emergency-shutdown.sh
├── vulnerability-scanning/
│   ├── dependency-scan.sh
│   ├── container-scan.sh
│   └── infrastructure-scan.sh
├── compliance/
│   ├── sox-audit.sh
│   ├── gdpr-report.sh
│   └── pci-scan.sh
└── key-rotation/
    ├── rotate-all-keys.sh
    ├── rotate-jwt.sh
    └── rotate-database.sh
```

### External Resources
- OWASP Top 10: https://owasp.org/Top10/
- CWE/SANS Top 25: https://cwe.mitre.org/top25/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- MITRE ATT&CK: https://attack.mitre.org/

### Emergency Contacts
- Security Team Lead: +1-XXX-XXX-XXXX
- CISO: +1-XXX-XXX-XXXX
- Legal Counsel: +1-XXX-XXX-XXXX
- Cyber Insurance: +1-XXX-XXX-XXXX
- FBI Cyber Division: +1-XXX-XXX-XXXX