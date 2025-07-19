import { DatabasePoolConfig } from '../connection-pool';

/**
 * Database pool configuration for different service types
 * Based on expected load and connection requirements
 */

export const poolConfigs: Record<string, DatabasePoolConfig> = {
  // API Gateway - High traffic, many concurrent requests
  'api-gateway': {
    min: 10,
    max: 50,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    statementTimeout: 5000,
    queryTimeout: 10000,
    pgBouncer: true,
    ssl: { rejectUnauthorized: false }
  },
  
  // Video Management - Long running operations
  'video-management': {
    min: 5,
    max: 20,
    idleTimeoutMillis: 60000,
    connectionTimeoutMillis: 5000,
    statementTimeout: 300000, // 5 minutes for video operations
    queryTimeout: 300000,
    pgBouncer: true,
    ssl: { rejectUnauthorized: false }
  },
  
  // Analytics Service - Heavy read operations
  'analytics': {
    min: 5,
    max: 30,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    statementTimeout: 60000, // 1 minute for analytics queries
    queryTimeout: 60000,
    pgBouncer: true,
    ssl: { rejectUnauthorized: false },
    // Use read replicas for analytics
    readReplicas: process.env.DATABASE_READ_REPLICAS
      ? process.env.DATABASE_READ_REPLICAS.split(',').map(url => ({
          connectionString: url.trim(),
          weight: 1
        }))
      : undefined
  },
  
  // Auth Service - Critical, fast queries
  'auth': {
    min: 10,
    max: 40,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 1000,
    statementTimeout: 2000,
    queryTimeout: 2000,
    pgBouncer: true,
    ssl: { rejectUnauthorized: false }
  },
  
  // Event Processing - Batch operations
  'event-processing': {
    min: 5,
    max: 25,
    idleTimeoutMillis: 45000,
    connectionTimeoutMillis: 3000,
    statementTimeout: 30000,
    queryTimeout: 30000,
    pgBouncer: true,
    ssl: { rejectUnauthorized: false }
  },
  
  // Default configuration for other services
  default: {
    min: 5,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
    statementTimeout: 5000,
    queryTimeout: 10000,
    pgBouncer: true,
    ssl: { rejectUnauthorized: false }
  }
};

/**
 * Get pool configuration for a specific service
 */
export function getPoolConfig(serviceName: string): DatabasePoolConfig {
  const config = poolConfigs[serviceName] || poolConfigs.default;
  
  // Override with environment variables if present
  return {
    ...config,
    connectionString: process.env.DATABASE_URL,
    min: process.env.DB_POOL_MIN ? parseInt(process.env.DB_POOL_MIN) : config.min,
    max: process.env.DB_POOL_MAX ? parseInt(process.env.DB_POOL_MAX) : config.max,
    idleTimeoutMillis: process.env.DB_IDLE_TIMEOUT ? parseInt(process.env.DB_IDLE_TIMEOUT) : config.idleTimeoutMillis,
    connectionTimeoutMillis: process.env.DB_CONNECTION_TIMEOUT ? parseInt(process.env.DB_CONNECTION_TIMEOUT) : config.connectionTimeoutMillis,
    statementTimeout: process.env.DB_STATEMENT_TIMEOUT ? parseInt(process.env.DB_STATEMENT_TIMEOUT) : config.statementTimeout,
    queryTimeout: process.env.DB_QUERY_TIMEOUT ? parseInt(process.env.DB_QUERY_TIMEOUT) : config.queryTimeout
  };
}