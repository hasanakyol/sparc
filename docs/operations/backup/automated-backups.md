# Automated Backup System

## Overview

SPARC implements a comprehensive automated backup system with encryption, compression, and intelligent retention policies. The system supports multiple backup strategies and destinations.

## Backup Types

### 1. Full Backups
- Complete database dump
- Scheduled daily (production) or weekly (development)
- Compressed and encrypted
- Stored in S3 with lifecycle policies

### 2. Incremental Backups
- WAL (Write-Ahead Log) archiving
- Continuous or hourly depending on environment
- Enables point-in-time recovery
- Minimal performance impact

### 3. Differential Backups
- Changes since last full backup
- Faster restore than incremental
- Balance between storage and recovery time

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   PostgreSQL    │────▶│  Backup Service  │────▶│   S3 Storage    │
│   Database      │     │  (Encrypted)     │     │   (KMS)         │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                         │
         │                       ▼                         │
         │              ┌──────────────────┐              │
         └─────────────▶│  WAL Archiving   │──────────────┘
                        │  (Continuous)    │
                        └──────────────────┘
```

## Configuration

### Environment Variables
```bash
# Database connection
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# S3 Configuration
BACKUP_BUCKET=sparc-backups-prod
AWS_REGION=us-east-1

# Encryption
KMS_BACKUP_KEY_ID=arn:aws:kms:region:account:key/key-id
ENCRYPTION_KEY=base64-encoded-key

# Notification
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
ALERT_EMAIL=ops@company.com
```

### Backup Schedule Configuration
```yaml
# Production Schedule
production:
  full_backup:
    schedule: "0 3 * * *"  # Daily at 3 AM UTC
    retention:
      daily: 7      # Keep 7 daily backups
      weekly: 4     # Keep 4 weekly backups
      monthly: 12   # Keep 12 monthly backups
      yearly: 5     # Keep 5 yearly backups
  
  incremental_backup:
    schedule: "continuous"  # WAL archiving
    retention: "7 days"
  
  verification:
    schedule: "0 6 * * 0"  # Weekly on Sunday

# Staging Schedule
staging:
  full_backup:
    schedule: "0 4 * * *"  # Daily at 4 AM UTC
    retention:
      daily: 3
      weekly: 2
      monthly: 3
      yearly: 1
```

## Deployment

### Kubernetes Setup
```bash
# Create namespace and secrets
kubectl create namespace backup
kubectl create secret generic database-credentials \
  --from-literal=url=$DATABASE_URL \
  -n backup

kubectl create secret generic backup-encryption \
  --from-literal=kms-key-id=$KMS_BACKUP_KEY_ID \
  --from-literal=encryption-key=$ENCRYPTION_KEY \
  -n backup

# Deploy backup jobs
kubectl apply -f k8s/base/backup/

# Check status
kubectl get cronjobs -n backup
kubectl get jobs -n backup
```

### Docker Compose Setup
```yaml
version: '3.8'
services:
  backup-scheduler:
    image: sparc/backup-service:latest
    command: ["node", "/app/scripts/backup-scheduler.js"]
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - BACKUP_BUCKET=${BACKUP_BUCKET}
      - AWS_REGION=${AWS_REGION}
    volumes:
      - ./backups:/backups
      - ~/.aws:/root/.aws:ro
```

## Backup Process

### 1. Full Backup Process
```typescript
// Automated by CronJob
async function performFullBackup() {
  // 1. Create database dump
  const dump = await pg_dump(DATABASE_URL);
  
  // 2. Compress dump
  const compressed = await gzip(dump);
  
  // 3. Encrypt compressed data
  const encrypted = await encrypt(compressed);
  
  // 4. Upload to S3 with KMS encryption
  await s3.upload({
    Bucket: BACKUP_BUCKET,
    Key: `backups/${tenant}/${date}/full-backup.sql.gz.enc`,
    Body: encrypted,
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: KMS_KEY_ID
  });
  
  // 5. Verify upload
  const checksum = await calculateChecksum(encrypted);
  await verifyBackup(checksum);
  
  // 6. Apply retention policy
  await cleanupOldBackups(retentionPolicy);
}
```

### 2. Incremental Backup (WAL Archiving)
```bash
# PostgreSQL configuration
archive_mode = on
archive_command = 'aws s3 cp %p s3://sparc-backups/wal/%f --sse aws:kms --sse-kms-key-id $KMS_KEY_ID'
archive_timeout = 300  # 5 minutes

# Recovery configuration
restore_command = 'aws s3 cp s3://sparc-backups/wal/%f %p'
recovery_target_time = '2024-01-15 14:30:00'
```

## Restore Procedures

### 1. Full Restore
```bash
# Download latest backup
aws s3 cp s3://sparc-backups/backups/system/2024/01/full-backup.sql.gz.enc /tmp/

# Decrypt
openssl enc -aes-256-cbc -d -in full-backup.sql.gz.enc -out full-backup.sql.gz -pass pass:$ENCRYPTION_KEY

# Decompress
gunzip full-backup.sql.gz

# Restore database
psql $DATABASE_URL < full-backup.sql
```

### 2. Point-in-Time Recovery
```bash
# Stop PostgreSQL
systemctl stop postgresql

# Clear data directory
rm -rf /var/lib/postgresql/14/main/*

# Restore base backup
tar -xf base-backup.tar -C /var/lib/postgresql/14/main/

# Configure recovery
cat > /var/lib/postgresql/14/main/recovery.conf <<EOF
restore_command = 'aws s3 cp s3://sparc-backups/wal/%f %p'
recovery_target_time = '2024-01-15 14:30:00'
recovery_target_action = 'promote'
EOF

# Start PostgreSQL
systemctl start postgresql
```

### 3. Tenant-Specific Restore
```typescript
// Restore single tenant data
async function restoreTenant(tenantId: string, targetDate: Date) {
  // 1. Find appropriate backup
  const backup = await findBackup(tenantId, targetDate);
  
  // 2. Download and decrypt
  const data = await downloadAndDecrypt(backup);
  
  // 3. Extract tenant data
  const tenantData = await extractTenantData(data, tenantId);
  
  // 4. Begin transaction
  await prisma.$transaction(async (tx) => {
    // 5. Delete existing tenant data
    await tx.tenant.delete({ where: { id: tenantId } });
    
    // 6. Restore tenant data
    await restoreTenantData(tx, tenantData);
  });
}
```

## Monitoring

### Health Checks
```typescript
// Backup health monitoring
const health = await backupService.getBackupHealth(tenantId);

if (health.status === 'critical') {
  // No backup in 48 hours
  await sendAlert({
    severity: 'critical',
    message: 'Backup failed for 48 hours',
    tenant: tenantId,
    lastBackup: health.lastBackup
  });
}
```

### Metrics
- Backup success rate
- Backup duration
- Backup size trends
- Storage costs
- Recovery time objectives (RTO)
- Recovery point objectives (RPO)

### Alerts
1. **Critical**
   - No backup for 48 hours
   - Backup verification failed
   - Storage quota exceeded

2. **Warning**
   - No backup for 24 hours
   - Backup took longer than expected
   - High storage growth rate

3. **Info**
   - Successful backup completion
   - Retention policy applied
   - Storage optimization performed

## Retention Policy

### Grandfather-Father-Son (GFS) Strategy
```
Daily Backups   : Keep 7 days
Weekly Backups  : Keep 4 weeks (Sunday)
Monthly Backups : Keep 12 months (1st of month)
Yearly Backups  : Keep 5 years (January 1st)
```

### Implementation
```typescript
function shouldRetainBackup(backupDate: Date, policy: RetentionPolicy): boolean {
  const now = new Date();
  const age = now.getTime() - backupDate.getTime();
  const days = age / (1000 * 60 * 60 * 24);
  
  // Keep all backups newer than daily retention
  if (days <= policy.daily) return true;
  
  // Keep weekly backups (Sundays)
  if (days <= policy.weekly * 7 && backupDate.getDay() === 0) return true;
  
  // Keep monthly backups (1st of month)
  if (days <= policy.monthly * 30 && backupDate.getDate() === 1) return true;
  
  // Keep yearly backups (Jan 1st)
  if (days <= policy.yearly * 365 && 
      backupDate.getMonth() === 0 && 
      backupDate.getDate() === 1) return true;
  
  return false;
}
```

## Security

### Encryption
- Application-level: AES-256-GCM
- Transit: TLS 1.3
- At rest: AWS KMS (S3 SSE-KMS)
- Key rotation: Every 90 days

### Access Control
- IAM roles for backup service
- Separate KMS keys for backups
- Read-only access for verification
- MFA for manual restore operations

### Audit Trail
```typescript
// All backup operations are logged
await auditLogger.logSuccess(
  AuditAction.BACKUP_CREATED,
  ResourceType.BACKUP,
  backupId,
  {
    type: 'full',
    size: backupSize,
    duration: duration,
    checksum: checksum
  }
);
```

## Testing

### Backup Testing
```bash
# Test backup creation
npm run test:backup:create

# Test encryption/decryption
npm run test:backup:encryption

# Test S3 upload
npm run test:backup:upload

# Test retention policy
npm run test:backup:retention
```

### Restore Testing
```bash
# Monthly restore drill
./scripts/backup/restore-drill.sh

# Verify data integrity
./scripts/backup/verify-restore.sh
```

## Disaster Recovery

### RTO/RPO Targets
- **RTO** (Recovery Time Objective): 4 hours
- **RPO** (Recovery Point Objective): 1 hour

### DR Procedures
1. **Identify failure scope**
2. **Select appropriate backup**
3. **Provision new infrastructure**
4. **Restore from backup**
5. **Verify data integrity**
6. **Update DNS/Load balancers**
7. **Monitor restored system**

### Multi-Region Backup
```yaml
# Cross-region replication
aws s3api put-bucket-replication \
  --bucket sparc-backups-prod \
  --replication-configuration file://replication.json

# replication.json
{
  "Role": "arn:aws:iam::account:role/replication-role",
  "Rules": [{
    "ID": "ReplicateAll",
    "Priority": 1,
    "Status": "Enabled",
    "DeleteMarkerReplication": { "Status": "Enabled" },
    "Filter": {},
    "Destination": {
      "Bucket": "arn:aws:s3:::sparc-backups-dr",
      "ReplicationTime": {
        "Status": "Enabled",
        "Time": { "Minutes": 15 }
      },
      "Metrics": { "Status": "Enabled" },
      "StorageClass": "GLACIER_IR"
    }
  }]
}
```

## Cost Optimization

### Storage Tiers
```yaml
# S3 Lifecycle Policy
lifecycle_rules:
  - id: "TransitionOldBackups"
    status: "Enabled"
    transitions:
      - days: 30
        storage_class: "STANDARD_IA"
      - days: 90
        storage_class: "GLACIER"
      - days: 365
        storage_class: "DEEP_ARCHIVE"
```

### Compression Ratios
- SQL dumps: 85-90% compression
- JSON exports: 70-80% compression
- Binary data: 20-30% compression

### Cost Monitoring
```typescript
// Monthly backup storage cost calculation
async function calculateBackupCosts() {
  const usage = await s3.getBucketMetrics();
  
  return {
    storage: usage.totalSize * STORAGE_COST_PER_GB,
    requests: usage.requests * REQUEST_COST,
    transfer: usage.transfer * TRANSFER_COST_PER_GB,
    total: storage + requests + transfer
  };
}
```

## Troubleshooting

### Common Issues

1. **Backup Timeout**
   ```bash
   # Increase statement timeout
   ALTER DATABASE sparc SET statement_timeout = '6h';
   ```

2. **Storage Full**
   ```bash
   # Emergency cleanup
   aws s3 rm s3://sparc-backups/temp/ --recursive
   ```

3. **Encryption Key Issues**
   ```bash
   # Verify KMS key access
   aws kms describe-key --key-id $KMS_KEY_ID
   aws kms encrypt --key-id $KMS_KEY_ID --plaintext "test"
   ```

### Backup Verification
```bash
# Verify backup integrity
pg_dump $DATABASE_URL | sha256sum > original.checksum
# After restore
pg_dump $RESTORED_URL | sha256sum > restored.checksum
diff original.checksum restored.checksum
```

## Best Practices

1. **Test restores regularly** - Monthly restore drills
2. **Monitor backup windows** - Ensure completion before business hours
3. **Verify backups** - Automated checksums and test restores
4. **Document procedures** - Keep runbooks updated
5. **Secure credentials** - Use IAM roles, not keys
6. **Alert on failures** - Immediate notification for failed backups
7. **Cross-region copies** - For disaster recovery
8. **Compliance validation** - Regular audit of backup access