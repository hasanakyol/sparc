import { ServiceConfig } from '@sparc/shared/patterns/service-base';
import * as dotenv from 'dotenv';

dotenv.config();

export interface ReportingServiceConfig extends ServiceConfig {
  // Email Configuration
  smtp: {
    host: string;
    port: number;
    user: string;
    pass: string;
    from: string;
  };
  
  // Storage Configuration
  storage: {
    path: string;
    retentionDays: number;
    s3?: {
      bucket: string;
      region: string;
      accessKeyId?: string;
      secretAccessKey?: string;
    };
  };
  
  // Report Generation
  reportGeneration: {
    maxConcurrent: number;
    timeoutMs: number;
    queueName: string;
  };
  
  // OpenTelemetry
  otel: {
    enabled: boolean;
    serviceName: string;
    endpoint: string;
    samplerType: string;
    samplerArg: number;
  };
  
  // Rate Limiting
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
}

export const config: ReportingServiceConfig = {
  // Base service config
  serviceName: process.env.SERVICE_NAME || 'reporting-service',
  port: parseInt(process.env.PORT || '3007'),
  version: process.env.SERVICE_VERSION || '1.0.0',
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://localhost:5432/sparc_reports',
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  enableAuth: true,
  enableRateLimit: true,
  enableMetrics: true,
  
  // Email configuration
  smtp: {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || 'SPARC Reports <reports@sparc.com>'
  },
  
  // Storage configuration
  storage: {
    path: process.env.REPORT_STORAGE_PATH || '/tmp/sparc/reports',
    retentionDays: parseInt(process.env.REPORT_RETENTION_DAYS || '30'),
    s3: process.env.S3_BUCKET ? {
      bucket: process.env.S3_BUCKET,
      region: process.env.S3_REGION || 'us-east-1',
      accessKeyId: process.env.S3_ACCESS_KEY_ID,
      secretAccessKey: process.env.S3_SECRET_ACCESS_KEY
    } : undefined
  },
  
  // Report generation
  reportGeneration: {
    maxConcurrent: parseInt(process.env.MAX_CONCURRENT_REPORTS || '5'),
    timeoutMs: parseInt(process.env.REPORT_TIMEOUT_MS || '300000'),
    queueName: process.env.REPORT_QUEUE_NAME || 'report-generation'
  },
  
  // OpenTelemetry configuration
  otel: {
    enabled: process.env.OTEL_ENABLED === 'true',
    serviceName: process.env.OTEL_SERVICE_NAME || 'reporting-service',
    endpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318',
    samplerType: process.env.OTEL_TRACES_SAMPLER || 'always_on',
    samplerArg: parseFloat(process.env.OTEL_TRACES_SAMPLER_ARG || '1.0')
  },
  
  // Rate limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100')
  }
};

// Validate required configuration
export function validateConfig(config: ReportingServiceConfig): void {
  const required = [
    'serviceName',
    'port',
    'jwtSecret',
    'redisUrl',
    'databaseUrl'
  ];
  
  for (const field of required) {
    if (!config[field as keyof ReportingServiceConfig]) {
      throw new Error(`Missing required configuration: ${field}`);
    }
  }
  
  // Validate email configuration if SMTP is configured
  if (config.smtp.host) {
    if (!config.smtp.user || !config.smtp.pass) {
      throw new Error('SMTP configuration incomplete: user and pass required');
    }
  }
  
  // Validate S3 configuration if enabled
  if (config.storage.s3) {
    if (!config.storage.s3.bucket) {
      throw new Error('S3 configuration incomplete: bucket required');
    }
  }
}