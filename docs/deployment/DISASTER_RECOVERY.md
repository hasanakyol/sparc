# Disaster Recovery Plan

## Overview

This document outlines the comprehensive disaster recovery (DR) plan for the SPARC platform. It defines Recovery Time Objectives (RTO), Recovery Point Objectives (RPO), backup procedures, failover processes, and testing protocols.

## Recovery Objectives

### Service Level Objectives

| Service Category | RTO | RPO | Priority |
|-----------------|-----|-----|----------|
| Authentication & Core APIs | 15 min | 5 min | P0 |
| Live Video Streaming | 30 min | Real-time | P0 |
| Incident Management | 30 min | 15 min | P1 |
| Historical Video Playback | 1 hour | 30 min | P1 |
| Analytics & Reporting | 2 hours | 1 hour | P2 |
| Audit Logs | 4 hours | 1 hour | P2 |

### Infrastructure Recovery Targets

| Component | RTO | RPO | Backup Frequency |
|-----------|-----|-----|------------------|
| PostgreSQL Database | 30 min | 5 min | Continuous replication |
| Redis Cache | 15 min | N/A | Rebuild from source |
| Object Storage (S3) | 1 hour | 15 min | Cross-region replication |
| Kubernetes Cluster | 45 min | 30 min | Daily snapshots |
| Container Registry | 2 hours | 1 hour | Geo-replicated |

## Disaster Scenarios

### 1. Data Center Failure
- **Impact**: Complete loss of primary region
- **Recovery**: Failover to secondary region
- **RTO**: 30 minutes
- **Procedure**: Execute full regional failover

### 2. Database Corruption
- **Impact**: Data integrity issues
- **Recovery**: Point-in-time restore
- **RTO**: 45 minutes
- **Procedure**: Database restoration from backup

### 3. Cyber Attack / Ransomware
- **Impact**: System compromise
- **Recovery**: Isolated restore from clean backups
- **RTO**: 2-4 hours
- **Procedure**: Security incident response + restore

### 4. Multi-Region Failure
- **Impact**: Loss of primary and secondary regions
- **Recovery**: Restore to tertiary location
- **RTO**: 4-6 hours
- **Procedure**: Full platform reconstruction

## Backup Procedures

### 1. Database Backup Strategy

```bash
#!/bin/bash
# PostgreSQL backup automation script

BACKUP_DIR="/mnt/backups"
S3_BUCKET="sparc-backups-prod"
RETENTION_DAYS=30

perform_database_backup() {
  local db_name=$1
  local timestamp=$(date +%Y%m%d_%H%M%S)
  local backup_file="${db_name}_${timestamp}.sql.gz"
  
  echo "Starting backup of $db_name..."
  
  # 1. Create logical backup
  PGPASSWORD=$DB_PASSWORD pg_dump \
    -h $DB_HOST \
    -U $DB_USER \
    -d $db_name \
    --no-owner \
    --no-privileges \
    --verbose | gzip > $BACKUP_DIR/$backup_file
  
  # 2. Create physical backup (for faster recovery)
  pg_basebackup \
    -h $DB_HOST \
    -U replicator \
    -D $BACKUP_DIR/physical_${timestamp} \
    -Ft -z -P
  
  # 3. Upload to S3 with encryption
  aws s3 cp $BACKUP_DIR/$backup_file \
    s3://$S3_BUCKET/logical/$backup_file \
    --sse aws:kms \
    --sse-kms-key-id $KMS_KEY_ID
  
  # 4. Upload to glacier for long-term storage
  aws s3 cp $BACKUP_DIR/$backup_file \
    s3://$S3_BUCKET-glacier/logical/$backup_file \
    --storage-class GLACIER
  
  # 5. Verify backup
  gunzip -c $BACKUP_DIR/$backup_file | head -n 100 > /dev/null || exit 1
  
  # 6. Clean old backups
  find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
  
  echo "Backup of $db_name completed"
}

# Backup all databases
for db in sparc_prod sparc_auth sparc_video sparc_analytics; do
  perform_database_backup $db
done

# Create backup metadata
cat > $BACKUP_DIR/backup_metadata.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "databases": ["sparc_prod", "sparc_auth", "sparc_video", "sparc_analytics"],
  "type": "full",
  "retention_days": $RETENTION_DAYS,
  "encryption": "aws:kms",
  "kms_key_id": "$KMS_KEY_ID"
}
EOF
```

### 2. Continuous Database Replication

```yaml
# PostgreSQL streaming replication configuration
# postgresql.conf on primary
wal_level = replica
max_wal_senders = 10
wal_keep_segments = 64
hot_standby = on
archive_mode = on
archive_command = 'aws s3 cp %p s3://sparc-wal-archive/%f'

# recovery.conf on standby
standby_mode = on
primary_conninfo = 'host=primary.db.sparc.com port=5432 user=replicator'
restore_command = 'aws s3 cp s3://sparc-wal-archive/%f %p'
trigger_file = '/tmp/failover.trigger'
```

### 3. Application Data Backup

```bash
#!/bin/bash
# Application data backup script

backup_application_data() {
  echo "Backing up application data..."
  
  # 1. Backup configuration files
  kubectl get configmap -n sparc-prod -o yaml > configs_backup.yaml
  kubectl get secret -n sparc-prod -o yaml > secrets_backup.yaml
  
  # 2. Backup persistent volumes
  for pvc in $(kubectl get pvc -n sparc-prod -o name); do
    pvc_name=$(echo $pvc | cut -d'/' -f2)
    kubectl exec -n sparc-prod deployment/backup-agent -- \
      tar czf - /data/$pvc_name | \
      aws s3 cp - s3://$S3_BUCKET/volumes/$pvc_name.tar.gz
  done
  
  # 3. Backup video storage metadata
  aws s3 sync s3://sparc-videos-prod s3://sparc-videos-backup \
    --metadata-directive COPY \
    --storage-class GLACIER_IR
  
  # 4. Export Kubernetes resources
  kubectl get all,pv,pvc,ingress,networkpolicy -A -o yaml > \
    k8s_resources_$(date +%Y%m%d).yaml
}

backup_application_data
```

### 4. Backup Verification

```bash
#!/bin/bash
# Backup verification and testing

verify_backups() {
  local backup_date=$1
  local errors=0
  
  echo "Verifying backups from $backup_date..."
  
  # 1. Verify database backups
  for db in sparc_prod sparc_auth sparc_video sparc_analytics; do
    backup_file="${db}_${backup_date}.sql.gz"
    
    # Download and test
    aws s3 cp s3://$S3_BUCKET/logical/$backup_file /tmp/
    gunzip -t /tmp/$backup_file || ((errors++))
    
    # Verify checksum
    stored_checksum=$(aws s3api head-object \
      --bucket $S3_BUCKET \
      --key logical/$backup_file \
      --query 'Metadata.checksum' --output text)
    
    actual_checksum=$(md5sum /tmp/$backup_file | cut -d' ' -f1)
    
    if [ "$stored_checksum" != "$actual_checksum" ]; then
      echo "ERROR: Checksum mismatch for $backup_file"
      ((errors++))
    fi
  done
  
  # 2. Test restore to verification environment
  ./scripts/restore-to-verify-env.sh $backup_date
  
  # 3. Run data integrity checks
  kubectl exec -n sparc-verify deployment/verification-job -- \
    npm run verify:restored:data
  
  echo "Verification complete. Errors: $errors"
  return $errors
}

# Run daily verification
verify_backups $(date +%Y%m%d -d "yesterday")
```

## Failover Procedures

### 1. Regional Failover

```bash
#!/bin/bash
# Regional failover automation script

FAILOVER_REGION="us-west-2"
PRIMARY_REGION="us-east-1"

initiate_regional_failover() {
  echo "Initiating failover from $PRIMARY_REGION to $FAILOVER_REGION..."
  
  # 1. Update DNS to point to failover region
  update_route53_records() {
    aws route53 change-resource-record-sets \
      --hosted-zone-id $HOSTED_ZONE_ID \
      --change-batch '{
        "Changes": [{
          "Action": "UPSERT",
          "ResourceRecordSet": {
            "Name": "api.sparc.com",
            "Type": "A",
            "AliasTarget": {
              "HostedZoneId": "'$FAILOVER_ALB_ZONE_ID'",
              "DNSName": "'$FAILOVER_ALB_DNS'",
              "EvaluateTargetHealth": true
            }
          }
        }]
      }'
  }
  
  # 2. Promote database read replica
  aws rds promote-read-replica \
    --db-instance-identifier sparc-prod-replica-$FAILOVER_REGION \
    --backup-retention-period 7
  
  # 3. Scale up Kubernetes cluster in failover region
  eksctl scale nodegroup \
    --cluster=sparc-prod-$FAILOVER_REGION \
    --name=workers \
    --nodes=50
  
  # 4. Deploy applications to failover region
  kubectl config use-context sparc-prod-$FAILOVER_REGION
  kubectl apply -k k8s/overlays/disaster-recovery/
  
  # 5. Verify services in failover region
  ./scripts/verify-failover-health.sh $FAILOVER_REGION
  
  # 6. Update CDN origin
  aws cloudfront update-distribution \
    --id $CLOUDFRONT_DIST_ID \
    --distribution-config file://cloudfront-failover-config.json
  
  echo "Regional failover completed"
}

# Execute failover
read -p "Initiate failover to $FAILOVER_REGION? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  initiate_regional_failover
fi
```

### 2. Database Failover

```bash
#!/bin/bash
# Database failover procedure

perform_database_failover() {
  local target_replica=$1
  
  echo "Starting database failover to $target_replica..."
  
  # 1. Stop writes to primary
  kubectl scale deployment --all --replicas=0 -n sparc-prod
  
  # 2. Ensure replication is caught up
  PGPASSWORD=$DB_PASSWORD psql -h $target_replica -U postgres -c \
    "SELECT pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() AS synced;"
  
  # 3. Promote replica
  PGPASSWORD=$DB_PASSWORD psql -h $target_replica -U postgres -c \
    "SELECT pg_promote();"
  
  # 4. Update application connection strings
  kubectl set env deployment/api-gateway \
    DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$target_replica:5432/sparc_prod" \
    -n sparc-prod
  
  # 5. Resume application traffic
  kubectl scale deployment --all --replicas=10 -n sparc-prod
  
  # 6. Verify new primary
  PGPASSWORD=$DB_PASSWORD psql -h $target_replica -U postgres -c \
    "SELECT pg_is_in_recovery();"
  
  echo "Database failover completed"
}
```

### 3. Service-Level Failover

```yaml
# Kubernetes service failover configuration
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled: "true"
spec:
  type: LoadBalancer
  selector:
    app: api-gateway
    failover: active
  ports:
    - port: 443
      targetPort: 8443
  sessionAffinity: ClientIP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: failover-traffic
spec:
  podSelector:
    matchLabels:
      failover: active
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              failover: active
```

## Data Recovery Steps

### 1. Point-in-Time Recovery

```bash
#!/bin/bash
# Point-in-time database recovery

recover_to_timestamp() {
  local target_time=$1
  local recovery_db="sparc_recovery"
  
  echo "Recovering database to $target_time..."
  
  # 1. Create recovery database
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U postgres -c \
    "CREATE DATABASE $recovery_db;"
  
  # 2. Find appropriate base backup
  base_backup=$(aws s3 ls s3://$S3_BUCKET/physical/ \
    --recursive | grep -B1 "$target_time" | head -1 | awk '{print $4}')
  
  # 3. Download base backup
  aws s3 cp s3://$S3_BUCKET/$base_backup /tmp/base_backup.tar
  
  # 4. Extract backup
  mkdir -p /var/lib/postgresql/recovery
  tar -xf /tmp/base_backup.tar -C /var/lib/postgresql/recovery
  
  # 5. Configure recovery
  cat > /var/lib/postgresql/recovery/recovery.conf <<EOF
restore_command = 'aws s3 cp s3://sparc-wal-archive/%f %p'
recovery_target_time = '$target_time'
recovery_target_action = 'promote'
EOF

  # 6. Start recovery
  pg_ctl start -D /var/lib/postgresql/recovery
  
  # 7. Verify recovery
  PGPASSWORD=$DB_PASSWORD psql -h localhost -U postgres -d $recovery_db -c \
    "SELECT COUNT(*) FROM audit_logs WHERE created_at <= '$target_time';"
  
  echo "Recovery to $target_time completed"
}
```

### 2. Selective Data Recovery

```sql
-- Selective table recovery script
BEGIN;

-- Create temporary schema for recovery
CREATE SCHEMA recovery_temp;

-- Import specific tables from backup
\i /tmp/backup_20240118_partial.sql

-- Compare and identify missing records
INSERT INTO production.incidents
SELECT r.* FROM recovery_temp.incidents r
LEFT JOIN production.incidents p ON r.id = p.id
WHERE p.id IS NULL
  AND r.created_at >= '2024-01-18 10:00:00'
  AND r.created_at <= '2024-01-18 14:00:00';

-- Verify recovery
SELECT COUNT(*) as recovered_records
FROM production.incidents
WHERE created_at >= '2024-01-18 10:00:00'
  AND created_at <= '2024-01-18 14:00:00';

-- Clean up
DROP SCHEMA recovery_temp CASCADE;

COMMIT;
```

### 3. Application State Recovery

```bash
#!/bin/bash
# Application state recovery procedure

recover_application_state() {
  local backup_timestamp=$1
  
  echo "Recovering application state from $backup_timestamp..."
  
  # 1. Restore ConfigMaps and Secrets
  kubectl apply -f configs_backup_$backup_timestamp.yaml
  kubectl apply -f secrets_backup_$backup_timestamp.yaml
  
  # 2. Restore persistent volumes
  for pvc_backup in $(aws s3 ls s3://$S3_BUCKET/volumes/ | grep $backup_timestamp); do
    pvc_name=$(echo $pvc_backup | cut -d'.' -f1)
    
    # Create restore job
    kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: restore-$pvc_name
spec:
  template:
    spec:
      containers:
      - name: restore
        image: sparc/backup-restore:latest
        command: ["/bin/sh", "-c"]
        args:
          - |
            aws s3 cp s3://$S3_BUCKET/volumes/$pvc_backup - | tar xzf - -C /restore
        volumeMounts:
        - name: data
          mountPath: /restore
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: $pvc_name
      restartPolicy: Never
EOF
  done
  
  # 3. Wait for restore jobs
  kubectl wait --for=condition=complete job -l restore=true --timeout=3600s
  
  # 4. Verify restored data
  kubectl exec deployment/api-gateway -- ls -la /data/
}
```

## Testing Procedures

### 1. Monthly DR Drill

```bash
#!/bin/bash
# Disaster recovery drill automation

run_dr_drill() {
  local drill_id="drill_$(date +%Y%m%d_%H%M%S)"
  
  echo "Starting DR drill: $drill_id"
  
  # 1. Create isolated test environment
  terraform workspace new $drill_id
  terraform apply -var="environment=dr-test" -auto-approve
  
  # 2. Restore from backup
  ./scripts/restore-from-backup.sh --target-env dr-test --backup-date yesterday
  
  # 3. Run smoke tests
  export API_URL="https://dr-test.sparc.com"
  npm run test:smoke
  
  # 4. Run data validation
  kubectl exec -n dr-test deployment/validation-job -- \
    npm run validate:dr:data
  
  # 5. Test failover procedures
  ./scripts/test-failover.sh dr-test
  
  # 6. Generate report
  generate_dr_report $drill_id
  
  # 7. Cleanup
  terraform destroy -auto-approve
  terraform workspace delete $drill_id
  
  echo "DR drill completed: $drill_id"
}

generate_dr_report() {
  local drill_id=$1
  
  cat > reports/dr_drill_$drill_id.md <<EOF
# DR Drill Report - $drill_id

## Test Results
- Environment Creation: $(cat logs/$drill_id/env_creation.log | grep "Time:" | tail -1)
- Data Restoration: $(cat logs/$drill_id/restore.log | grep "Time:" | tail -1)
- Service Recovery: $(cat logs/$drill_id/services.log | grep "Time:" | tail -1)
- Total RTO: $(cat logs/$drill_id/summary.log | grep "Total Time:")

## Data Validation
$(cat logs/$drill_id/data_validation.json | jq .)

## Issues Found
$(cat logs/$drill_id/issues.txt)

## Recommendations
$(cat logs/$drill_id/recommendations.txt)
EOF
}
```

### 2. Backup Restoration Test

```bash
#!/bin/bash
# Automated backup restoration testing

test_backup_restoration() {
  local test_env="backup-test-$(date +%Y%m%d)"
  
  echo "Testing backup restoration..."
  
  # 1. Select random backup from last 7 days
  backup_date=$(aws s3 ls s3://$S3_BUCKET/logical/ \
    | grep -E "sparc_prod_[0-9]{8}" \
    | sort -r | head -7 | shuf -n 1 | awk '{print $4}' | cut -d'_' -f3 | cut -d'.' -f1)
  
  # 2. Create test database
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U postgres -c \
    "CREATE DATABASE $test_env;"
  
  # 3. Restore backup
  aws s3 cp s3://$S3_BUCKET/logical/sparc_prod_$backup_date.sql.gz - | \
    gunzip | PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U postgres -d $test_env
  
  # 4. Run validation queries
  validation_results=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U postgres -d $test_env <<EOF
SELECT 
  (SELECT COUNT(*) FROM organizations) as org_count,
  (SELECT COUNT(*) FROM users) as user_count,
  (SELECT COUNT(*) FROM incidents) as incident_count,
  (SELECT MAX(created_at) FROM audit_logs) as latest_audit;
EOF
)
  
  # 5. Compare with production
  prod_results=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U postgres -d sparc_prod <<EOF
SELECT 
  (SELECT COUNT(*) FROM organizations) as org_count,
  (SELECT COUNT(*) FROM users) as user_count,
  (SELECT COUNT(*) FROM incidents) as incident_count;
EOF
)
  
  # 6. Clean up
  PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U postgres -c \
    "DROP DATABASE $test_env;"
  
  echo "Restoration test completed for backup: $backup_date"
  echo "Validation Results: $validation_results"
}

# Run test
test_backup_restoration
```

### 3. Chaos Engineering Tests

```yaml
# Chaos engineering scenarios for DR testing
apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: dr-pod-failure
spec:
  action: pod-failure
  mode: fixed
  value: "3"
  duration: "60s"
  selector:
    labelSelectors:
      app: api-gateway
---
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: dr-network-partition
spec:
  action: partition
  mode: all
  selector:
    labelSelectors:
      region: us-east-1
  target:
    labelSelectors:
      region: us-west-2
  duration: "5m"
---
apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: dr-resource-stress
spec:
  mode: one
  selector:
    labelSelectors:
      app: video-processor
  stressors:
    memory:
      workers: 4
      size: "2GB"
    cpu:
      workers: 8
      load: 80
  duration: "10m"
```

## DR Communication Plan

### Notification Chain

```yaml
# Incident notification configuration
notification_chain:
  - level: P0
    contacts:
      - role: CTO
        methods: [phone, sms, email]
        escalation_time: immediate
      - role: VP_Engineering
        methods: [phone, sms, email]
        escalation_time: immediate
      - role: SRE_Lead
        methods: [phone, slack, email]
        escalation_time: immediate
        
  - level: P1
    contacts:
      - role: SRE_On_Call
        methods: [pagerduty, slack]
        escalation_time: immediate
      - role: Engineering_Manager
        methods: [slack, email]
        escalation_time: 15min
        
  - level: P2
    contacts:
      - role: SRE_Team
        methods: [slack, email]
        escalation_time: 30min
```

### Communication Templates

```markdown
# Initial DR Activation

Subject: [P0] Disaster Recovery Activated - [REGION/SERVICE]

**Situation**: Catastrophic failure detected in [affected component]
**Impact**: [User impact description]
**Actions**: DR procedures initiated at [timestamp]
**ETA**: Services expected to be restored by [time]
**War Room**: [Link to virtual war room]
**Status Page**: [Link to public status page]

Updates every 30 minutes or as situation changes.
```

## Recovery Validation Checklist

### Technical Validation
- [ ] All services responding to health checks
- [ ] Database connectivity verified
- [ ] Data integrity checks passed
- [ ] Performance within acceptable limits
- [ ] Security controls re-enabled
- [ ] Monitoring and alerting functional
- [ ] Backup jobs resumed

### Business Validation
- [ ] Critical business functions operational
- [ ] Customer access restored
- [ ] Transaction processing working
- [ ] Video streaming functional
- [ ] Historical data accessible
- [ ] Reports generating correctly

### Post-Recovery Actions
- [ ] Document timeline and actions
- [ ] Calculate actual RTO/RPO
- [ ] Identify improvement areas
- [ ] Update runbooks
- [ ] Schedule post-mortem
- [ ] Communicate lessons learned
- [ ] Update DR procedures
- [ ] Plan next DR test

## DR Metrics and Reporting

```bash
#!/bin/bash
# Generate DR metrics report

generate_dr_metrics() {
  local incident_id=$1
  
  cat > reports/dr_metrics_$incident_id.json <<EOF
{
  "incident_id": "$incident_id",
  "incident_start": "$(date -d @$INCIDENT_START +%Y-%m-%dT%H:%M:%SZ)",
  "recovery_initiated": "$(date -d @$RECOVERY_START +%Y-%m-%dT%H:%M:%SZ)",
  "recovery_completed": "$(date -d @$RECOVERY_END +%Y-%m-%dT%H:%M:%SZ)",
  "total_downtime_minutes": $((($RECOVERY_END - $INCIDENT_START) / 60)),
  "rto_achieved": {
    "api_gateway": "$((($API_RECOVERY - $RECOVERY_START) / 60)) min",
    "database": "$((($DB_RECOVERY - $RECOVERY_START) / 60)) min",
    "video_services": "$((($VIDEO_RECOVERY - $RECOVERY_START) / 60)) min",
    "full_platform": "$((($RECOVERY_END - $RECOVERY_START) / 60)) min"
  },
  "rpo_achieved": {
    "database": "$(calculate_data_loss) min",
    "video_storage": "$(calculate_video_loss) min",
    "audit_logs": "$(calculate_audit_loss) min"
  },
  "data_loss": {
    "transactions_lost": $(count_lost_transactions),
    "incidents_affected": $(count_affected_incidents),
    "video_segments_lost": $(count_lost_video_segments)
  },
  "recovery_method": "$RECOVERY_METHOD",
  "root_cause": "$ROOT_CAUSE",
  "improvement_actions": [
    "$(cat improvement_actions.txt | jq -R . | jq -s .)"
  ]
}
EOF
}
```