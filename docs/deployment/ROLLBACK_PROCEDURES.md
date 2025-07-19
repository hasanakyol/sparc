# Rollback Procedures

## Overview

This document provides detailed procedures for rolling back SPARC platform deployments. It covers decision criteria, step-by-step rollback procedures, data integrity verification, and communication templates.

## Rollback Decision Criteria

### Severity Levels

| Level | Criteria | Action | Decision Time |
|-------|----------|--------|---------------|
| **Critical** | Complete service outage, data corruption, security breach | Immediate rollback | < 5 minutes |
| **High** | Major functionality broken, >30% error rate, performance degradation >50% | Rollback after quick fix attempt | < 15 minutes |
| **Medium** | Minor features broken, 10-30% error rate, performance degradation 20-50% | Evaluate fix vs rollback | < 30 minutes |
| **Low** | Cosmetic issues, <10% error rate, minor performance impact | Forward fix preferred | < 1 hour |

### Automatic Rollback Triggers

```yaml
# Prometheus alert rules for automatic rollback
groups:
  - name: deployment_rollback
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.3
        for: 5m
        labels:
          severity: critical
          action: rollback
        annotations:
          summary: "High error rate detected"
          
      - alert: ServiceDown
        expr: up{job="api-gateway"} == 0
        for: 2m
        labels:
          severity: critical
          action: rollback
          
      - alert: DatabaseConnectionFailure
        expr: pg_up == 0
        for: 1m
        labels:
          severity: critical
          action: rollback
```

## Rollback Procedures by Component

### 1. Application Service Rollback

```bash
#!/bin/bash
# Service rollback script

SERVICE_NAME=$1
PREVIOUS_VERSION=$2
NAMESPACE="sparc-prod"

rollback_service() {
  local service=$1
  local version=$2
  
  echo "Rolling back $service to version $version..."
  
  # 1. Capture current state
  kubectl get deployment $service -n $NAMESPACE -o yaml > rollback_state_$service.yaml
  
  # 2. Rollback deployment
  kubectl set image deployment/$service $service=registry.sparc.com/$service:$version \
    -n $NAMESPACE --record
  
  # 3. Wait for rollout
  kubectl rollout status deployment/$service -n $NAMESPACE --timeout=300s
  
  # 4. Verify health
  kubectl exec deployment/$service -n $NAMESPACE -- \
    curl -s http://localhost:8080/health || exit 1
  
  echo "Rollback of $service completed"
}

# Main rollback execution
if [ -z "$SERVICE_NAME" ] || [ -z "$PREVIOUS_VERSION" ]; then
  echo "Usage: $0 <service-name> <previous-version>"
  exit 1
fi

rollback_service $SERVICE_NAME $PREVIOUS_VERSION
```

### 2. Database Rollback Procedures

```bash
#!/bin/bash
# Database rollback script

BACKUP_TIMESTAMP=$1
DB_NAME="sparc_prod"

rollback_database() {
  echo "Starting database rollback to $BACKUP_TIMESTAMP..."
  
  # 1. Stop application traffic
  kubectl scale deployment --all --replicas=0 -n sparc-prod
  
  # 2. Create point-in-time backup
  pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > \
    rollback_safety_$(date +%Y%m%d_%H%M%S).sql
  
  # 3. Download backup from S3
  aws s3 cp s3://$S3_BUCKET/backups/backup_$BACKUP_TIMESTAMP.sql ./
  
  # 4. Restore database
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d postgres -c \
    "DROP DATABASE IF EXISTS $DB_NAME;"
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d postgres -c \
    "CREATE DATABASE $DB_NAME;"
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME < \
    backup_$BACKUP_TIMESTAMP.sql
  
  # 5. Verify restoration
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';"
  
  # 6. Resume application traffic
  kubectl scale deployment --all --replicas=10 -n sparc-prod
  
  echo "Database rollback completed"
}

# Execute with confirmation
read -p "Rollback database to $BACKUP_TIMESTAMP? This will cause data loss. (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rollback_database
else
  echo "Rollback cancelled"
  exit 1
fi
```

### 3. Kubernetes Rollback

```bash
#!/bin/bash
# Kubernetes deployment rollback

# Get rollout history
kubectl rollout history deployment/api-gateway -n sparc-prod

# Rollback to previous version
kubectl rollout undo deployment/api-gateway -n sparc-prod

# Rollback to specific revision
kubectl rollout undo deployment/api-gateway -n sparc-prod --to-revision=2

# Rollback all services in namespace
for deployment in $(kubectl get deployments -n sparc-prod -o name); do
  kubectl rollout undo $deployment -n sparc-prod
done
```

### 4. Infrastructure Rollback

```bash
#!/bin/bash
# Terraform infrastructure rollback

cd infra/terraform/environments/production

# Show current state
terraform show

# Plan rollback
terraform plan -var="image_tag=$PREVIOUS_VERSION"

# Apply rollback
terraform apply -var="image_tag=$PREVIOUS_VERSION" -auto-approve

# Verify infrastructure
terraform output
```

## Data Integrity Verification

### 1. Pre-Rollback Verification

```sql
-- Capture current data statistics
CREATE TABLE rollback_stats_$(date +%s) AS
SELECT 
  'organizations' as table_name, COUNT(*) as row_count FROM organizations
UNION ALL
SELECT 'users', COUNT(*) FROM users
UNION ALL
SELECT 'incidents', COUNT(*) FROM incidents
UNION ALL
SELECT 'cameras', COUNT(*) FROM cameras
UNION ALL
SELECT 'audit_logs', COUNT(*) FROM audit_logs;

-- Capture data checksums
SELECT 
  tablename,
  MD5(CAST(array_agg(t.*) AS text)) as checksum
FROM (
  SELECT * FROM organizations ORDER BY id
) t
GROUP BY tablename;
```

### 2. Post-Rollback Verification

```bash
#!/bin/bash
# Data integrity verification script

verify_data_integrity() {
  echo "Verifying data integrity..."
  
  # 1. Check row counts
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d sparc_prod <<EOF
  SELECT 
    r.table_name,
    r.row_count as before_count,
    CASE r.table_name
      WHEN 'organizations' THEN (SELECT COUNT(*) FROM organizations)
      WHEN 'users' THEN (SELECT COUNT(*) FROM users)
      WHEN 'incidents' THEN (SELECT COUNT(*) FROM incidents)
      WHEN 'cameras' THEN (SELECT COUNT(*) FROM cameras)
      WHEN 'audit_logs' THEN (SELECT COUNT(*) FROM audit_logs)
    END as after_count
  FROM rollback_stats r;
EOF

  # 2. Verify critical data
  kubectl exec deployment/api-gateway -n sparc-prod -- \
    npm run verify:data:integrity
  
  # 3. Check data consistency
  kubectl exec deployment/analytics-service -n sparc-prod -- \
    npm run verify:analytics:consistency
}

verify_data_integrity
```

### 3. Transaction Log Analysis

```bash
#!/bin/bash
# Analyze transaction logs for data loss

analyze_transaction_logs() {
  # Extract transaction logs
  kubectl logs -l app=api-gateway -n sparc-prod --since=1h | \
    grep -E "(INSERT|UPDATE|DELETE)" > transaction_log.txt
  
  # Analyze failed transactions
  grep -E "ERROR|ROLLBACK" transaction_log.txt > failed_transactions.txt
  
  # Generate report
  echo "Transaction Analysis Report"
  echo "=========================="
  echo "Total transactions: $(wc -l < transaction_log.txt)"
  echo "Failed transactions: $(wc -l < failed_transactions.txt)"
  echo "Success rate: $(awk 'END{print 100-(NR*100/$(wc -l < transaction_log.txt))}' failed_transactions.txt)%"
}

analyze_transaction_logs
```

## Communication Templates

### 1. Initial Incident Communication

```markdown
Subject: [URGENT] Production Deployment Issue - Initiating Rollback

Team,

We are experiencing issues with the recent production deployment (version X.X.X) deployed at [timestamp].

**Issue Summary:**
- Error rate: XX%
- Affected services: [list]
- User impact: [description]

**Immediate Actions:**
- Initiating rollback to version X.X.X
- Estimated completion: XX minutes
- [Name] is incident commander

**Next Update:** In 15 minutes or upon completion

Incident Channel: #incident-YYYYMMDD-XXX
```

### 2. Rollback Progress Update

```markdown
Subject: [UPDATE] Rollback in Progress - 50% Complete

**Current Status:**
- Database rollback: ✓ Complete
- Service rollbacks: 8/16 complete
- Frontend rollback: In progress

**Metrics:**
- Error rate: Decreasing (was 45%, now 20%)
- Response times: Improving

**ETA:** 10 minutes

**Actions Required:**
- QA team: Prepare smoke test suite
- Support team: Prepare customer communication
```

### 3. Rollback Completion

```markdown
Subject: [RESOLVED] Rollback Complete - Services Restored

**Summary:**
- Rollback completed at [timestamp]
- All services restored to version X.X.X
- Error rates back to normal (<0.1%)

**Verification:**
- Health checks: ✓ All passing
- Smoke tests: ✓ Complete
- Data integrity: ✓ Verified

**Follow-up Actions:**
- Post-mortem scheduled for [date/time]
- Root cause analysis in progress
- Customer communication sent

Thank you for your swift response.
```

### 4. Customer Communication

```markdown
Subject: Service Restoration Complete

Dear Customer,

We experienced a brief service disruption between [start] and [end] today. The issue has been resolved, and all services are now operating normally.

**What Happened:**
A deployment introduced unexpected issues affecting [description].

**Impact:**
- Some users experienced [impact description]
- Duration: XX minutes
- Data integrity: No data loss occurred

**Resolution:**
We immediately rolled back to the previous stable version and verified all services are functioning correctly.

**Prevention:**
We are conducting a thorough review to prevent similar issues.

We apologize for any inconvenience caused.

The SPARC Team
```

## Automated Rollback Script

```bash
#!/bin/bash
# Comprehensive automated rollback script

set -e

ENVIRONMENT="production"
ROLLBACK_REASON=$1

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a rollback.log
}

notify() {
  # Send Slack notification
  curl -X POST $SLACK_WEBHOOK -H 'Content-type: application/json' \
    -d "{\"text\":\"$1\"}"
  
  # Send email
  echo "$1" | mail -s "SPARC Rollback Alert" ops-team@sparc.com
  
  # Create PagerDuty incident
  curl -X POST https://api.pagerduty.com/incidents \
    -H "Authorization: Token token=$PAGERDUTY_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"incident\":{\"type\":\"incident\",\"title\":\"$1\",\"service\":{\"id\":\"$SERVICE_ID\"}}}"
}

perform_rollback() {
  log "Starting automated rollback. Reason: $ROLLBACK_REASON"
  notify "🔴 Initiating production rollback: $ROLLBACK_REASON"
  
  # 1. Capture current state
  log "Capturing current state..."
  kubectl get all -n sparc-prod > state_before_rollback.txt
  
  # 2. Get previous stable version
  PREVIOUS_VERSION=$(kubectl get deployment api-gateway -n sparc-prod \
    -o jsonpath='{.metadata.annotations.previous-version}')
  
  # 3. Initiate database backup
  log "Creating database safety backup..."
  ./scripts/db-backup-emergency.sh &
  
  # 4. Rollback services
  log "Rolling back services to $PREVIOUS_VERSION..."
  for deployment in $(kubectl get deployments -n sparc-prod -o name); do
    kubectl rollout undo $deployment -n sparc-prod &
  done
  wait
  
  # 5. Verify rollback
  log "Verifying rollback..."
  ./scripts/health-check.sh || {
    notify "⚠️ Rollback health check failed!"
    exit 1
  }
  
  # 6. Run data integrity checks
  log "Verifying data integrity..."
  ./scripts/verify-data-integrity.sh
  
  # 7. Clear caches
  log "Clearing caches..."
  kubectl exec deployment/api-gateway -n sparc-prod -- redis-cli FLUSHALL
  
  # 8. Update DNS if needed
  if [ "$ROLLBACK_DNS" = "true" ]; then
    log "Updating DNS records..."
    ./scripts/update-dns-rollback.sh
  fi
  
  log "Rollback completed successfully"
  notify "✅ Rollback completed. Services restored to $PREVIOUS_VERSION"
}

# Main execution
if [ -z "$ROLLBACK_REASON" ]; then
  echo "Usage: $0 <rollback-reason>"
  exit 1
fi

# Confirm rollback
if [ "$AUTO_ROLLBACK" != "true" ]; then
  read -p "Perform production rollback? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "Rollback cancelled by user"
    exit 0
  fi
fi

perform_rollback
```

## Post-Rollback Checklist

- [ ] All services rolled back successfully
- [ ] Health checks passing
- [ ] Data integrity verified
- [ ] Performance metrics normal
- [ ] Error rates below threshold
- [ ] Customer communication sent
- [ ] Incident report created
- [ ] Post-mortem scheduled
- [ ] Root cause analysis started
- [ ] Monitoring alerts cleared
- [ ] Rollback documented
- [ ] Stakeholders notified

## Rollback Testing Procedures

### Monthly Rollback Drills

```bash
#!/bin/bash
# Rollback drill script for staging environment

run_rollback_drill() {
  echo "Starting rollback drill..."
  
  # 1. Deploy new version to staging
  ./deploy.sh staging v2.0.0-drill
  
  # 2. Simulate failure
  kubectl exec deployment/api-gateway -n sparc-staging -- \
    kill -9 1
  
  # 3. Trigger rollback
  ./rollback.sh staging "Rollback drill - simulated failure"
  
  # 4. Verify rollback
  ./verify-rollback.sh staging
  
  echo "Rollback drill completed"
}

run_rollback_drill
```

## Recovery Time Objectives

| Component | RTO | Actual (Last Test) |
|-----------|-----|-------------------|
| API Gateway | 5 min | 3.5 min |
| Database | 15 min | 12 min |
| Video Services | 10 min | 8 min |
| Web Frontend | 5 min | 4 min |
| Full Platform | 20 min | 18 min |