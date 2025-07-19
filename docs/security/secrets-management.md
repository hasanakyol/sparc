# SPARC Platform - Secrets Management Guide

## Overview

This document provides comprehensive guidance on managing secrets, environment variables, and sensitive configuration in the SPARC platform. Following these practices is critical for maintaining security and preventing unauthorized access.

## Table of Contents

1. [Required Environment Variables](#required-environment-variables)
2. [Generating Secure Secrets](#generating-secure-secrets)
3. [Environment Variable Validation](#environment-variable-validation)
4. [Secret Storage Best Practices](#secret-storage-best-practices)
5. [Secret Rotation](#secret-rotation)
6. [Development vs Production](#development-vs-production)
7. [Common Security Mistakes](#common-security-mistakes)
8. [Troubleshooting](#troubleshooting)

## Required Environment Variables

### Critical Secrets (Required for All Environments)

| Variable | Description | Minimum Requirements |
|----------|-------------|---------------------|
| `JWT_SECRET` | JWT signing secret | 32+ characters |
| `JWT_REFRESH_SECRET` | JWT refresh token secret | 32+ characters (different from JWT_SECRET) |
| `DATABASE_PASSWORD` | PostgreSQL password | 8+ characters, complex |
| `ENCRYPTION_KEY` | Data encryption key | 32 bytes, base64 encoded |
| `HASH_SALT` | Salt for hashing | 16+ characters |

### Production-Only Requirements

| Variable | Description | Requirements |
|----------|-------------|--------------|
| `SSL_CERT_PATH` | SSL certificate path | Valid file path |
| `SSL_KEY_PATH` | SSL private key path | Valid file path |
| `AWS_ACCESS_KEY_ID` | AWS access key | Valid AWS credentials |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | Valid AWS credentials |

## Generating Secure Secrets

### JWT Secrets

Generate a secure JWT secret:

```bash
# Generate a 32-byte secret (base64 encoded)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Example output: K8BNUzp4X6D4FXLr6+WZqJxPh7mfK1Kf2ZQdWvXqDqo=
```

**Important**: Generate different secrets for `JWT_SECRET` and `JWT_REFRESH_SECRET`.

### Database Password

Generate a strong database password:

```bash
# Generate a 16-character password with special characters
node -e "const c=require('crypto');const chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';let pwd='';for(let i=0;i<16;i++)pwd+=chars[c.randomInt(chars.length)];console.log(pwd)"

# Or use a password manager to generate one
```

### Encryption Key

Generate an encryption key for AES-256:

```bash
# Generate a 32-byte key (required for AES-256)
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Verify the key is valid (should output 32)
node -e "console.log(Buffer.from('YOUR_KEY_HERE', 'base64').length)"
```

### Hash Salt

Generate a hash salt:

```bash
# Generate a random salt
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

### Webhook Secret

Generate a webhook signing secret:

```bash
# Generate a webhook secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Environment Variable Validation

The SPARC platform includes automatic environment variable validation that runs on startup.

### Using the Validation

```javascript
// In your service startup
import { validateEnvironment, logEnvironmentValidation } from '@sparc/shared/utils';

// Validate environment on startup
try {
  validateEnvironment(process.env.NODE_ENV === 'production');
  logEnvironmentValidation(logger);
} catch (error) {
  console.error('Environment validation failed:', error.message);
  process.exit(1);
}
```

### Manual Validation

Check your environment manually:

```bash
# Run validation script
node -e "
const { validateEnvironment } = require('@sparc/shared/utils');
const result = validateEnvironment(false, false);
console.log('Valid:', result.valid);
console.log('Missing:', result.missing);
console.log('Invalid:', result.invalid);
console.log('Warnings:', result.warnings);
"
```

## Secret Storage Best Practices

### Development Environment

1. **Use `.env` files** (never commit to version control)
   ```bash
   # Copy the example file
   cp .env.example .env
   
   # Edit with your secrets
   nano .env
   ```

2. **Add to `.gitignore`**
   ```gitignore
   # Environment files
   .env
   .env.local
   .env.*.local
   ```

### Production Environment

1. **AWS Secrets Manager** (Recommended)
   ```javascript
   // Example: Retrieve secrets from AWS
   const AWS = require('aws-sdk');
   const client = new AWS.SecretsManager({ region: 'us-east-1' });
   
   async function getSecret(secretName) {
     const data = await client.getSecretValue({ SecretId: secretName }).promise();
     return JSON.parse(data.SecretString);
   }
   ```

2. **Environment Variables via CI/CD**
   - Set secrets in your CI/CD platform (GitHub Actions, Jenkins, etc.)
   - Use deployment tools that support secret injection

3. **Kubernetes Secrets**
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: sparc-secrets
   type: Opaque
   data:
     jwt-secret: <base64-encoded-secret>
     database-password: <base64-encoded-password>
   ```

4. **Docker Secrets**
   ```yaml
   version: '3.8'
   services:
     api:
       environment:
         JWT_SECRET_FILE: /run/secrets/jwt_secret
       secrets:
         - jwt_secret
   
   secrets:
     jwt_secret:
       external: true
   ```

## Secret Rotation

### Implementing Secret Rotation

1. **JWT Secret Rotation**
   ```javascript
   // Support multiple valid secrets during rotation
   const JWT_SECRETS = [
     process.env.JWT_SECRET_CURRENT,
     process.env.JWT_SECRET_PREVIOUS
   ].filter(Boolean);
   
   // Verify with multiple secrets
   function verifyToken(token) {
     for (const secret of JWT_SECRETS) {
       try {
         return jwt.verify(token, secret);
       } catch (err) {
         continue;
       }
     }
     throw new Error('Invalid token');
   }
   ```

2. **Database Password Rotation**
   ```sql
   -- Create new user with new password
   CREATE USER sparc_user_new WITH PASSWORD 'new_secure_password';
   GRANT ALL PRIVILEGES ON DATABASE sparc_db TO sparc_user_new;
   
   -- Update application configuration
   -- Test connectivity
   -- Remove old user
   DROP USER sparc_user_old;
   ```

3. **Encryption Key Rotation**
   ```javascript
   // Use the provided key rotation utility
   import { rotateEncryptionKey } from '@sparc/shared/utils';
   
   await rotateEncryptionKey(oldKey, newKey, async (old, new) => {
     // Custom reencryption logic
     await reencryptAllData(old, new);
   });
   ```

### Rotation Schedule

| Secret Type | Rotation Frequency | Notes |
|-------------|-------------------|-------|
| JWT Secrets | 90 days | Maintain overlap period |
| Database Passwords | 90 days | Coordinate with DBA |
| Encryption Keys | 180 days | Plan data migration |
| API Keys | 60 days | Update all consumers |
| Webhook Secrets | 120 days | Notify webhook consumers |

## Development vs Production

### Development Best Practices

1. **Never use production secrets in development**
2. **Use different secret values for each developer**
3. **Consider using tools like `direnv` for automatic loading**
   ```bash
   # .envrc file
   export JWT_SECRET="dev-secret-$(whoami)"
   export DATABASE_PASSWORD="dev-password-$(whoami)"
   ```

### Production Requirements

1. **No default values in code**
   ```javascript
   // ❌ BAD
   const secret = process.env.JWT_SECRET || 'default-secret';
   
   // ✅ GOOD
   const secret = process.env.JWT_SECRET;
   if (!secret) {
     throw new Error('JWT_SECRET is required');
   }
   ```

2. **Use secret scanning in CI/CD**
   ```yaml
   # GitHub Actions example
   - name: Scan for secrets
     uses: trufflesecurity/trufflehog@main
     with:
       path: ./
   ```

3. **Monitor for exposed secrets**
   - Enable GitHub secret scanning
   - Use tools like GitGuardian
   - Set up alerts for suspicious access patterns

## Common Security Mistakes

### 1. Hardcoded Secrets
```javascript
// ❌ NEVER DO THIS
const JWT_SECRET = 'my-super-secret-key';

// ✅ ALWAYS DO THIS
const JWT_SECRET = process.env.JWT_SECRET;
```

### 2. Committing .env Files
```bash
# ❌ BAD: .env file in repository
git add .env
git commit -m "Add environment config"

# ✅ GOOD: Only commit .env.example
git add .env.example
git commit -m "Add environment template"
```

### 3. Logging Secrets
```javascript
// ❌ NEVER LOG SECRETS
console.log('Config:', process.env);

// ✅ LOG SAFELY
console.log('Config loaded', {
  jwtConfigured: !!process.env.JWT_SECRET,
  dbConfigured: !!process.env.DATABASE_URL
});
```

### 4. Weak Secrets
```bash
# ❌ WEAK SECRETS
JWT_SECRET=secret123
DATABASE_PASSWORD=admin

# ✅ STRONG SECRETS
JWT_SECRET=K8BNUzp4X6D4FXLr6+WZqJxPh7mfK1Kf2ZQdWvXqDqo=
DATABASE_PASSWORD=xR#9Kp$2mN@5qL&8
```

### 5. Reusing Secrets
```bash
# ❌ REUSING SECRETS
JWT_SECRET=same-secret-everywhere
JWT_REFRESH_SECRET=same-secret-everywhere

# ✅ UNIQUE SECRETS
JWT_SECRET=K8BNUzp4X6D4FXLr6+WZqJxPh7mfK1Kf2ZQdWvXqDqo=
JWT_REFRESH_SECRET=mTvP3X8K9N2D5Q7R1W4E6Y0U3I5O7P9S2D4F6H8J0L2=
```

## Troubleshooting

### Common Issues

1. **"Environment validation failed"**
   - Check all required variables are set
   - Verify secret formats (length, encoding)
   - Run validation script to identify specific issues

2. **"JWT_SECRET environment variable is required"**
   - Ensure .env file is loaded
   - Check environment variable names (case-sensitive)
   - Verify no typos in variable names

3. **"Invalid token" errors**
   - Check JWT_SECRET matches between services
   - Verify token hasn't expired
   - Ensure proper secret rotation handling

4. **"Decryption failed"**
   - Verify ENCRYPTION_KEY is correct
   - Check key encoding (base64)
   - Ensure data was encrypted with same key

### Debug Commands

```bash
# Check if environment variables are set
env | grep -E '^(JWT|DATABASE|ENCRYPTION|HASH)'

# Verify JWT secret length
node -e "console.log('JWT_SECRET length:', process.env.JWT_SECRET?.length)"

# Test database connection
node -e "
const { Client } = require('pg');
const client = new Client({ connectionString: process.env.DATABASE_URL });
client.connect()
  .then(() => console.log('✅ Database connected'))
  .catch(err => console.error('❌ Database error:', err.message))
  .finally(() => client.end());
"

# Validate encryption key
node -e "
const key = process.env.ENCRYPTION_KEY;
if (!key) {
  console.error('❌ ENCRYPTION_KEY not set');
} else {
  const bytes = Buffer.from(key, 'base64');
  console.log('✅ Key length:', bytes.length, 'bytes');
  console.log(bytes.length === 32 ? '✅ Valid AES-256 key' : '❌ Invalid key length');
}
"
```

## Security Checklist

Before deploying to production, ensure:

- [ ] All required environment variables are set
- [ ] No hardcoded secrets in code
- [ ] No secrets in version control
- [ ] Different secrets for each environment
- [ ] Secrets meet complexity requirements
- [ ] Secret rotation plan in place
- [ ] Access to secrets is logged and monitored
- [ ] Secrets are encrypted at rest
- [ ] CI/CD pipeline masks secrets in logs
- [ ] Regular security audits scheduled

## Additional Resources

- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [NIST Key Management Guidelines](https://csrc.nist.gov/projects/key-management/key-management-guidelines)
- [AWS Secrets Manager Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [The Twelve-Factor App: Config](https://12factor.net/config)