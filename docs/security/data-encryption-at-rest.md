# Data Encryption at Rest

## Overview

SPARC implements comprehensive encryption at rest to protect sensitive data. This includes database encryption, file storage encryption, and backup encryption.

## Encryption Layers

### 1. Database Encryption (PostgreSQL)

#### Transparent Data Encryption (TDE)
PostgreSQL supports encryption at rest through various methods:

##### Option A: Full Disk Encryption (Recommended)
```bash
# AWS RDS - Enable encryption when creating instance
aws rds create-db-instance \
  --db-instance-identifier sparc-prod \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:region:account:key/key-id

# Azure Database for PostgreSQL
az postgres server create \
  --name sparc-prod \
  --infrastructure-encryption Enabled

# GCP Cloud SQL
gcloud sql instances create sparc-prod \
  --database-version=POSTGRES_14 \
  --disk-encryption-key projects/PROJECT_ID/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
```

##### Option B: Tablespace Encryption
```sql
-- Create encrypted tablespace
CREATE TABLESPACE encrypted_space
  LOCATION '/encrypted/tablespace/path'
  WITH (encryption_key_id = 'master-key-id');

-- Move sensitive tables
ALTER TABLE credentials SET TABLESPACE encrypted_space;
ALTER TABLE mobile_credentials SET TABLESPACE encrypted_space;
ALTER TABLE integration_configurations SET TABLESPACE encrypted_space;
```

##### Option C: Column-Level Encryption (Application Managed)
Already implemented for specific fields:
- Credentials: `pinCode`, `biometricTemplate`
- Mobile Credentials: `credentialData`
- Integration Configurations: `authentication`

### 2. File Storage Encryption

#### S3 Bucket Encryption (AWS)
```json
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "arn:aws:kms:region:account:key/key-id"
    },
    "BucketKeyEnabled": true
  }]
}
```

#### Azure Blob Storage
```bash
# Enable encryption with customer-managed keys
az storage account update \
  --name sparcstorageaccount \
  --encryption-key-name sparc-encryption-key \
  --encryption-key-vault https://sparcvault.vault.azure.net
```

#### Google Cloud Storage
```bash
# Set default encryption key
gsutil kms encryption gs://sparc-storage \
  -k projects/PROJECT_ID/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
```

### 3. Backup Encryption

#### Database Backups
```bash
# PostgreSQL encrypted backup
pg_dump dbname | openssl enc -aes-256-cbc -salt -pass pass:$BACKUP_KEY > backup.sql.enc

# Automated encrypted backups with pgBackRest
[global]
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=$PGBACKREST_PASS

[main]
pg1-path=/var/lib/postgresql/14/main
repo1-path=/backups
repo1-retention-full=7
start-fast=y
compress-type=lz4
```

#### Application Backups
```typescript
import { encrypt } from '@sparc/shared/utils/encryption';
import { S3 } from 'aws-sdk';

export async function createEncryptedBackup(data: any): Promise<void> {
  const backupData = JSON.stringify(data);
  const encrypted = encrypt(backupData);
  
  const s3 = new S3();
  await s3.putObject({
    Bucket: 'sparc-backups',
    Key: `backup-${Date.now()}.enc`,
    Body: encrypted,
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: process.env.KMS_KEY_ID,
  }).promise();
}
```

## Key Management

### 1. Key Hierarchy

```
Master Key (HSM/KMS)
├── Database Encryption Key (DEK)
├── Application Encryption Key
├── Backup Encryption Key
└── File Storage Key
```

### 2. Key Storage

#### AWS KMS
```typescript
import { KMS } from 'aws-sdk';

const kms = new KMS();

// Generate data key
export async function generateDataKey(): Promise<{
  plaintext: Buffer;
  ciphertext: Buffer;
}> {
  const result = await kms.generateDataKey({
    KeyId: process.env.KMS_MASTER_KEY_ID!,
    KeySpec: 'AES_256',
  }).promise();
  
  return {
    plaintext: result.Plaintext!,
    ciphertext: result.CiphertextBlob!,
  };
}

// Decrypt data key
export async function decryptDataKey(ciphertext: Buffer): Promise<Buffer> {
  const result = await kms.decrypt({
    CiphertextBlob: ciphertext,
  }).promise();
  
  return result.Plaintext!;
}
```

#### HashiCorp Vault
```typescript
import vault from 'node-vault';

const client = vault({
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN,
});

// Store encryption key
await client.write('secret/data/sparc/encryption', {
  data: {
    database_key: databaseKey,
    application_key: applicationKey,
    backup_key: backupKey,
  },
});

// Retrieve encryption key
const result = await client.read('secret/data/sparc/encryption');
const keys = result.data.data;
```

### 3. Key Rotation

#### Automated Key Rotation Script
```typescript
import { rotateEncryptionKey } from '@sparc/shared/utils/encryption';
import { getPrismaClient } from '@sparc/shared/database/prisma';

export async function rotateAllKeys(): Promise<void> {
  const prisma = getPrismaClient();
  
  // Generate new keys
  const newKeys = {
    database: generateEncryptionKey(),
    application: generateEncryptionKey(),
    backup: generateEncryptionKey(),
  };
  
  // Rotate database encryption key
  await rotateDatabaseKey(newKeys.database);
  
  // Rotate application encryption key
  await rotateApplicationKey(newKeys.application);
  
  // Rotate backup encryption key
  await rotateBackupKey(newKeys.backup);
  
  // Update key version
  await prisma.systemConfiguration.create({
    data: {
      tenantId: 'system',
      category: 'encryption',
      key: 'key_version',
      value: { version: Date.now() },
      updatedBy: 'system',
    },
  });
}
```

## Implementation Guidelines

### 1. Enable Database Encryption

#### AWS RDS
```terraform
resource "aws_db_instance" "sparc" {
  identifier     = "sparc-production"
  engine         = "postgres"
  engine_version = "14.7"
  
  # Enable encryption
  storage_encrypted = true
  kms_key_id       = aws_kms_key.database.arn
  
  # Enable automated backups with encryption
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  
  # Enable performance insights with encryption
  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.database.arn
}
```

#### Kubernetes Persistent Volumes
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: encrypted-storage
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3
  encrypted: "true"
  kmsKeyId: "arn:aws:kms:region:account:key/key-id"
```

### 2. Application-Level Encryption

#### Sensitive Field Encryption
```typescript
import { Prisma } from '@prisma/client';
import { encrypt, decrypt } from '@sparc/shared/utils/encryption';

// Middleware to encrypt/decrypt sensitive fields
export const encryptionMiddleware: Prisma.Middleware = async (params, next) => {
  // Encrypt on create/update
  if (params.model === 'Credential' && ['create', 'update'].includes(params.action)) {
    if (params.args.data.pinCode) {
      params.args.data.pinCode = encrypt(params.args.data.pinCode);
    }
    if (params.args.data.biometricTemplate) {
      params.args.data.biometricTemplate = encrypt(params.args.data.biometricTemplate);
    }
  }
  
  const result = await next(params);
  
  // Decrypt on read
  if (params.model === 'Credential' && result) {
    if (Array.isArray(result)) {
      result.forEach(decryptCredential);
    } else {
      decryptCredential(result);
    }
  }
  
  return result;
};

function decryptCredential(credential: any) {
  if (credential.pinCode) {
    credential.pinCode = decrypt(credential.pinCode);
  }
  if (credential.biometricTemplate) {
    credential.biometricTemplate = decrypt(credential.biometricTemplate);
  }
}
```

### 3. File Encryption

#### Video File Encryption
```typescript
import { createCipheriv, createDecipheriv } from 'crypto';
import { pipeline } from 'stream/promises';

export async function encryptVideoFile(
  inputPath: string,
  outputPath: string,
  key: Buffer
): Promise<void> {
  const iv = crypto.randomBytes(16);
  const cipher = createCipheriv('aes-256-ctr', key, iv);
  
  const input = createReadStream(inputPath);
  const output = createWriteStream(outputPath);
  
  // Write IV as first 16 bytes
  output.write(iv);
  
  await pipeline(input, cipher, output);
}

export async function decryptVideoStream(
  encryptedPath: string,
  key: Buffer
): Promise<ReadableStream> {
  const input = createReadStream(encryptedPath);
  
  // Read IV from first 16 bytes
  const iv = await readFirstBytes(input, 16);
  const decipher = createDecipheriv('aes-256-ctr', key, iv);
  
  return input.pipe(decipher);
}
```

## Monitoring & Compliance

### 1. Encryption Status Monitoring

```typescript
export async function checkEncryptionStatus(): Promise<EncryptionStatus> {
  const checks = await Promise.all([
    checkDatabaseEncryption(),
    checkStorageEncryption(),
    checkBackupEncryption(),
    checkKeyRotation(),
  ]);
  
  return {
    database: checks[0],
    storage: checks[1],
    backups: checks[2],
    keyRotation: checks[3],
    overallCompliant: checks.every(c => c.compliant),
  };
}
```

### 2. Compliance Reporting

```sql
-- Verify encrypted tables
SELECT 
  tablename,
  tablespace,
  (tablespace = 'encrypted_space') as is_encrypted
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN (
    'credentials',
    'mobile_credentials',
    'integration_configurations'
  );

-- Check encryption settings
SELECT name, setting 
FROM pg_settings 
WHERE name LIKE '%encrypt%';
```

### 3. Audit Trail

```typescript
// Log encryption operations
await auditLogger.logSuccess(
  AuditAction.CONFIG_CHANGED,
  ResourceType.SYSTEM_CONFIG,
  'encryption',
  {
    operation: 'key_rotation',
    keyType: 'database',
    timestamp: new Date(),
  }
);
```

## Security Best Practices

1. **Key Segregation**: Use different keys for different data types
2. **Key Rotation**: Rotate keys every 90 days
3. **Access Control**: Limit key access to essential services
4. **Monitoring**: Alert on decryption failures
5. **Testing**: Regular encryption/decryption tests
6. **Documentation**: Maintain key inventory

## Disaster Recovery

### 1. Key Backup
```bash
# Backup KMS keys
aws kms describe-key --key-id $KEY_ID > key-backup.json
aws kms get-key-policy --key-id $KEY_ID --policy-name default > key-policy.json

# Store in secure offline location
```

### 2. Recovery Procedures
1. Restore master keys from secure backup
2. Decrypt data keys using master keys
3. Verify data integrity
4. Resume normal operations

## Performance Impact

| Operation | Without Encryption | With Encryption | Impact |
|-----------|-------------------|-----------------|---------|
| Database Write | 10ms | 11ms | +10% |
| Database Read | 5ms | 5.5ms | +10% |
| File Upload | 100ms | 120ms | +20% |
| File Download | 80ms | 95ms | +19% |
| Backup | 5 min | 6 min | +20% |

## Compliance Checklist

- [ ] Database encryption enabled
- [ ] Backup encryption configured
- [ ] File storage encryption active
- [ ] Key management system deployed
- [ ] Key rotation schedule defined
- [ ] Encryption monitoring active
- [ ] Audit logging for encryption ops
- [ ] Disaster recovery plan tested
- [ ] Performance benchmarks met
- [ ] Compliance reports generated