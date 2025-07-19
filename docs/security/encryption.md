# SPARC Encryption Implementation Guide

## Overview

This document describes the encryption implementation for sensitive data in the SPARC platform. We use AES-256-GCM encryption with authenticated encryption to protect credentials, PIN codes, biometric data, and authentication tokens.

## Encrypted Fields

### Credential Model
- `pinCode` - User PIN codes (encrypted)
- `pinCodeHash` - Hash for PIN validation (SHA-256)
- `biometricTemplate` - Biometric data (encrypted)
- `cardNumberHash` - Hash for card number searching (SHA-256)

### MobileCredential Model
- `credentialData` - Mobile credential payload (encrypted)
- `deviceIdHash` - Hash for device ID searching (SHA-256)

### IntegrationConfiguration Model
- `authentication` - API keys, passwords, tokens (encrypted JSON)

## Encryption Details

### Algorithm
- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2 with SHA-256
- **Iterations**: 100,000
- **Salt Length**: 32 bytes
- **IV Length**: 16 bytes
- **Tag Length**: 16 bytes (for authentication)

### Key Management

#### Environment Variables
```bash
# Primary encryption key (base64 encoded)
ENCRYPTION_KEY=your-base64-encoded-32-byte-key

# Hash salt for searchable fields
HASH_SALT=your-hash-salt
```

#### Generating a New Key
```bash
# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Using OpenSSL
openssl rand -base64 32
```

## Implementation

### 1. Database Migration

First, run the Prisma migration to add encryption fields:

```bash
cd packages/shared
npx prisma migrate dev --name add-encryption-fields
```

### 2. Encrypt Existing Data

Run the encryption migration script:

```bash
cd packages/shared
npx ts-node src/utils/encrypt-migration.ts encrypt
```

### 3. Using Encryption in Code

#### Manual Encryption/Decryption

```typescript
import { encrypt, decrypt, hash } from '@sparc/shared/utils';

// Encrypt sensitive data
const encryptedPin = encrypt('1234');

// Decrypt data
const plainPin = decrypt(encryptedPin);

// Hash for searching
const pinHash = hash('1234');
```

#### Using Credential Service

```typescript
import { CredentialService } from '@sparc/shared/utils';

// Before saving to database
const encryptedCredential = CredentialService.encryptCredential({
  pinCode: '1234',
  cardNumber: '1234567890',
  biometricTemplate: 'base64-encoded-template'
});

// After reading from database
const decryptedCredential = CredentialService.decryptCredential(credential);

// Validate PIN
const isValid = CredentialService.validatePinCode('1234', credential.pinCodeHash);

// Search by card number
const cardHash = CredentialService.getCardNumberSearchHash('1234567890');
const found = await prisma.credential.findFirst({
  where: { cardNumberHash: cardHash }
});
```

#### Using Prisma Middleware

Add the encryption middleware to your Prisma client:

```typescript
import { PrismaClient } from '@prisma/client';
import { createEncryptionMiddleware } from '@sparc/shared/utils';

const prisma = new PrismaClient();

// Add encryption middleware
prisma.$use(createEncryptionMiddleware());

// Now all credential operations are automatically encrypted/decrypted
const credential = await prisma.credential.create({
  data: {
    userId: 'user-id',
    tenantId: 'tenant-id',
    credentialType: 'PIN',
    pinCode: '1234' // Automatically encrypted
  }
});

// Reading automatically decrypts
const found = await prisma.credential.findUnique({
  where: { id: credential.id }
});
console.log(found.pinCode); // '1234' (decrypted)
```

## Key Rotation

### Process

1. Generate a new encryption key
2. Set both old and new keys in environment
3. Run the rotation script
4. Update environment to use only new key
5. Remove old key

### Commands

```bash
# Generate new key
NEW_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")

# Run rotation
cd packages/shared
npx ts-node src/utils/encrypt-migration.ts rotate "$OLD_KEY" "$NEW_KEY"

# Update .env
echo "ENCRYPTION_KEY=$NEW_KEY" >> .env
```

### Automated Rotation

For production environments, implement automated key rotation:

```typescript
import { rotateEncryptionKey } from '@sparc/shared/utils';

// Schedule this to run periodically
async function performKeyRotation() {
  const oldKey = process.env.ENCRYPTION_KEY;
  const newKey = generateNewKey();
  
  await rotateEncryptionKey(oldKey, newKey, async (old, new) => {
    // Custom reencryption logic
    await reencryptAllData(old, new);
  });
  
  // Update key management service
  await updateKeyInVault(newKey);
}
```

## Security Considerations

### 1. Key Storage
- Never commit encryption keys to version control
- Use environment variables or key management services
- Rotate keys regularly (recommended: every 90 days)

### 2. Backup Keys
- Keep secure backups of all encryption keys
- Store key version with encrypted data
- Maintain key history for recovery

### 3. Access Control
- Limit access to encryption keys
- Use different keys for different environments
- Audit all key access

### 4. Performance
- Encryption adds ~1-2ms per operation
- Use hash fields for searching instead of decrypting all records
- Consider caching decrypted data in memory (with TTL)

## Troubleshooting

### Common Issues

1. **"ENCRYPTION_KEY environment variable is not set"**
   - Ensure ENCRYPTION_KEY is set in your environment
   - Check .env file is loaded

2. **"Decryption failed"**
   - Verify the data is actually encrypted
   - Check if using correct encryption key
   - Ensure data wasn't corrupted

3. **Performance Issues**
   - Use hash fields for searching
   - Implement caching for frequently accessed data
   - Consider batch operations

### Debug Mode

Enable encryption debugging:

```typescript
// Set in environment
process.env.ENCRYPTION_DEBUG = 'true';

// Or in code
import { setEncryptionDebug } from '@sparc/shared/utils';
setEncryptionDebug(true);
```

## Compliance

This encryption implementation helps meet:
- PCI DSS requirements for cardholder data
- GDPR requirements for personal data protection
- SOC 2 Type II encryption controls
- NIST 800-53 cryptographic controls