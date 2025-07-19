/**
 * Environment Variable Validation
 * 
 * This module validates that all required environment variables are set
 * and meet security requirements before the application starts.
 */

interface RequiredEnvVar {
  name: string;
  description: string;
  validation?: (value: string) => boolean;
  sensitive?: boolean;
}

const REQUIRED_ENV_VARS: RequiredEnvVar[] = [
  // Database
  {
    name: 'DATABASE_URL',
    description: 'PostgreSQL database connection URL',
    sensitive: true,
    validation: (value) => value.startsWith('postgresql://') || value.startsWith('postgres://'),
  },
  {
    name: 'DATABASE_PASSWORD',
    description: 'Database password',
    sensitive: true,
    validation: (value) => value.length >= 8,
  },

  // JWT Secrets
  {
    name: 'JWT_SECRET',
    description: 'JWT signing secret (minimum 32 characters)',
    sensitive: true,
    validation: (value) => value.length >= 32,
  },
  {
    name: 'JWT_REFRESH_SECRET',
    description: 'JWT refresh token secret (minimum 32 characters)',
    sensitive: true,
    validation: (value) => value.length >= 32,
  },

  // Encryption
  {
    name: 'ENCRYPTION_KEY',
    description: 'Data encryption key (32 bytes, base64 encoded)',
    sensitive: true,
    validation: (value) => {
      try {
        const decoded = Buffer.from(value, 'base64');
        return decoded.length === 32;
      } catch {
        return false;
      }
    },
  },
  {
    name: 'HASH_SALT',
    description: 'Salt for hashing sensitive data',
    sensitive: true,
    validation: (value) => value.length >= 16,
  },

  // Redis
  {
    name: 'REDIS_URL',
    description: 'Redis connection URL',
    sensitive: true,
    validation: (value) => value.startsWith('redis://') || value.startsWith('rediss://'),
  },
];

const PRODUCTION_REQUIRED_ENV_VARS: RequiredEnvVar[] = [
  // Additional production-only requirements
  {
    name: 'SSL_CERT_PATH',
    description: 'Path to SSL certificate file',
    sensitive: false,
  },
  {
    name: 'SSL_KEY_PATH',
    description: 'Path to SSL private key file',
    sensitive: false,
  },
  
  // AWS (if using S3 for video storage)
  {
    name: 'AWS_ACCESS_KEY_ID',
    description: 'AWS access key ID',
    sensitive: true,
  },
  {
    name: 'AWS_SECRET_ACCESS_KEY',
    description: 'AWS secret access key',
    sensitive: true,
  },
  
  // Mobile Credentials (if mobile support is enabled)
  {
    name: 'MOBILE_CREDENTIAL_ENCRYPTION_KEY',
    description: 'Encryption key for mobile credentials',
    sensitive: true,
    validation: (value) => value.length >= 32,
  },
];

const OPTIONAL_ENV_VARS: RequiredEnvVar[] = [
  // ONVIF (only if video integration is used)
  {
    name: 'ONVIF_USERNAME',
    description: 'Default ONVIF camera username',
    sensitive: false,
  },
  {
    name: 'ONVIF_PASSWORD',
    description: 'Default ONVIF camera password',
    sensitive: true,
  },
  
  // Webhook
  {
    name: 'WEBHOOK_SECRET',
    description: 'Secret for webhook signature validation',
    sensitive: true,
    validation: (value) => value.length >= 16,
  },
  
  // Notifications
  {
    name: 'SMTP_PASSWORD',
    description: 'SMTP server password',
    sensitive: true,
  },
  {
    name: 'TWILIO_AUTH_TOKEN',
    description: 'Twilio authentication token',
    sensitive: true,
  },
];

export class EnvironmentValidationError extends Error {
  constructor(message: string, public missingVars: string[], public invalidVars: string[]) {
    super(message);
    this.name = 'EnvironmentValidationError';
  }
}

/**
 * Validates environment variables
 * @param isProduction Whether running in production mode
 * @param throwOnError Whether to throw an error or just return validation results
 */
export function validateEnvironment(
  isProduction: boolean = process.env.NODE_ENV === 'production',
  throwOnError: boolean = true
): { valid: boolean; missing: string[]; invalid: string[]; warnings: string[] } {
  const missing: string[] = [];
  const invalid: string[] = [];
  const warnings: string[] = [];

  // Check required vars
  const requiredVars = isProduction 
    ? [...REQUIRED_ENV_VARS, ...PRODUCTION_REQUIRED_ENV_VARS]
    : REQUIRED_ENV_VARS;

  for (const envVar of requiredVars) {
    const value = process.env[envVar.name];
    
    if (!value) {
      missing.push(`${envVar.name}: ${envVar.description}`);
    } else if (envVar.validation && !envVar.validation(value)) {
      invalid.push(`${envVar.name}: ${envVar.description}`);
    }
  }

  // Check optional vars if they are provided
  for (const envVar of OPTIONAL_ENV_VARS) {
    const value = process.env[envVar.name];
    
    if (value && envVar.validation && !envVar.validation(value)) {
      warnings.push(`${envVar.name}: ${envVar.description} - validation failed`);
    }
  }

  // Warn about common security issues
  if (process.env.JWT_SECRET === process.env.JWT_REFRESH_SECRET) {
    warnings.push('JWT_SECRET and JWT_REFRESH_SECRET should be different values');
  }

  if (process.env.NODE_ENV === 'production') {
    // Check for weak passwords in production
    const weakPasswords = ['password', 'admin', 'secret', '12345678'];
    const passwordVars = ['DATABASE_PASSWORD', 'REDIS_PASSWORD', 'ONVIF_PASSWORD'];
    
    for (const varName of passwordVars) {
      const value = process.env[varName];
      if (value && weakPasswords.includes(value.toLowerCase())) {
        warnings.push(`${varName} appears to be a weak password`);
      }
    }
  }

  const valid = missing.length === 0 && invalid.length === 0;

  if (!valid && throwOnError) {
    let errorMessage = 'Environment validation failed:\n';
    
    if (missing.length > 0) {
      errorMessage += '\nMissing required environment variables:\n';
      errorMessage += missing.map(m => `  - ${m}`).join('\n');
    }
    
    if (invalid.length > 0) {
      errorMessage += '\n\nInvalid environment variables:\n';
      errorMessage += invalid.map(i => `  - ${i}`).join('\n');
    }
    
    throw new EnvironmentValidationError(errorMessage, missing, invalid);
  }

  return { valid, missing, invalid, warnings };
}

/**
 * Logs environment validation results
 */
export function logEnvironmentValidation(logger?: any): void {
  const results = validateEnvironment(
    process.env.NODE_ENV === 'production',
    false
  );

  const log = logger || console;

  if (results.valid) {
    log.info('✅ Environment validation passed');
  } else {
    log.error('❌ Environment validation failed');
    
    if (results.missing.length > 0) {
      log.error('Missing environment variables:');
      results.missing.forEach(m => log.error(`  - ${m}`));
    }
    
    if (results.invalid.length > 0) {
      log.error('Invalid environment variables:');
      results.invalid.forEach(i => log.error(`  - ${i}`));
    }
  }

  if (results.warnings.length > 0) {
    log.warn('Environment warnings:');
    results.warnings.forEach(w => log.warn(`  - ${w}`));
  }
}

/**
 * Generate a secure random secret
 */
export function generateSecret(length: number = 32): string {
  const crypto = require('crypto');
  return crypto.randomBytes(length).toString('base64');
}

/**
 * Generate example .env file content
 */
export function generateEnvExample(): string {
  let content = `# SPARC Platform Environment Variables
# Copy this file to .env and fill in the values
# DO NOT commit .env to version control

# Environment
NODE_ENV=development
LOG_LEVEL=info
PORT=3000

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/sparc_db
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=sparc_db
DATABASE_USER=sparc_user
DATABASE_PASSWORD=<strong-password>
DATABASE_SSL=false

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=<redis-password-if-required>

# JWT Secrets (generate with: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
JWT_SECRET=<generate-32-byte-secret>
JWT_REFRESH_SECRET=<generate-different-32-byte-secret>
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Encryption (generate with: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
ENCRYPTION_KEY=<generate-32-byte-key>
HASH_SALT=<generate-random-salt>

# Optional: Video Integration
# ONVIF_USERNAME=<camera-username>
# ONVIF_PASSWORD=<camera-password>

# Optional: Webhooks
# WEBHOOK_SECRET=<webhook-signing-secret>

# Optional: AWS (for S3 video storage)
# AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=<aws-access-key>
# AWS_SECRET_ACCESS_KEY=<aws-secret-key>
# AWS_S3_BUCKET=sparc-video-storage

# Optional: Mobile Credentials
# MOBILE_CREDENTIAL_ENCRYPTION_KEY=<mobile-encryption-key>

# Optional: Email Notifications
# SMTP_HOST=smtp.example.com
# SMTP_PORT=587
# SMTP_SECURE=false
# SMTP_USER=<smtp-username>
# SMTP_PASSWORD=<smtp-password>

# Optional: SMS Notifications (Twilio)
# SMS_PROVIDER=twilio
# TWILIO_ACCOUNT_SID=<twilio-account-sid>
# TWILIO_AUTH_TOKEN=<twilio-auth-token>
# TWILIO_PHONE_NUMBER=<twilio-phone-number>
`;

  return content;
}