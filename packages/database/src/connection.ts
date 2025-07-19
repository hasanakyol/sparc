import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { createDatabasePool, DatabasePoolConfig } from './connection-pool';
import { logger } from '@sparc/shared/utils/logger';
import { metrics } from '@sparc/shared/monitoring/metrics';

// Environment-based configuration
const isDevelopment = process.env.NODE_ENV === 'development';
const isProduction = process.env.NODE_ENV === 'production';

// Database pool configuration based on fix.md specifications
const poolConfig: DatabasePoolConfig = {
  connectionString: process.env.DATABASE_URL,
  
  // Pool settings as specified in fix.md
  max: isProduction ? 20 : 10,
  min: isProduction ? 5 : 2,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  statementTimeout: 5000,
  queryTimeout: 10000,
  
  // Production optimizations
  ...(isProduction && {
    pgBouncer: true,
    ssl: { rejectUnauthorized: false },
    keepAlive: true,
    keepAliveInitialDelayMillis: 10000,
    
    // Read replicas if configured
    readReplicas: process.env.DATABASE_READ_REPLICAS
      ? process.env.DATABASE_READ_REPLICAS.split(',').map((url, index) => ({
          connectionString: url.trim(),
          weight: 1
        }))
      : undefined
  })
};

// Create the enhanced connection pool
const connectionPool = createDatabasePool(poolConfig);

// Create standard pg Pool for compatibility
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: poolConfig.max,
  min: poolConfig.min,
  idleTimeoutMillis: poolConfig.idleTimeoutMillis,
  connectionTimeoutMillis: poolConfig.connectionTimeoutMillis,
  statement_timeout: poolConfig.statementTimeout,
  query_timeout: poolConfig.queryTimeout,
});

// Monitor pool health
pool.on('error', (err) => {
  logger.error('Unexpected database pool error', err);
  metrics.increment('database.pool.errors');
});

pool.on('connect', (client) => {
  metrics.increment('database.pool.connections');
});

pool.on('remove', () => {
  metrics.decrement('database.pool.connections');
});

// Export Drizzle instance
export const db = drizzle(pool);

// Export the enhanced connection pool for advanced usage
export { connectionPool };

// Export the standard pool for compatibility
export { pool };

// Health check function
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const health = await connectionPool.healthCheck();
    
    // Update metrics
    metrics.gauge('database.pool.health', health.overall ? 1 : 0);
    metrics.gauge('database.pool.primary.total', connectionPool.getStats().primary.total);
    metrics.gauge('database.pool.primary.idle', connectionPool.getStats().primary.idle);
    metrics.gauge('database.pool.primary.waiting', connectionPool.getStats().primary.waiting);
    
    return health.overall;
  } catch (error) {
    logger.error('Database health check failed:', error);
    return false;
  }
}

// Pool statistics monitoring
setInterval(() => {
  const stats = connectionPool.getStats();
  
  // Primary pool metrics
  metrics.gauge('database.pool.primary.total', stats.primary.total);
  metrics.gauge('database.pool.primary.idle', stats.primary.idle);
  metrics.gauge('database.pool.primary.waiting', stats.primary.waiting);
  
  // Query metrics
  metrics.gauge('database.queries.total', stats.queries.queries);
  metrics.gauge('database.queries.errors', stats.queries.errors);
  metrics.gauge('database.queries.slow', stats.queries.slowQueries);
  metrics.gauge('database.connection.errors', stats.queries.connectionErrors);
  
  // Replica metrics
  stats.replicas.forEach((replica, index) => {
    metrics.gauge(`database.pool.replica.${index}.total`, replica.total);
    metrics.gauge(`database.pool.replica.${index}.idle`, replica.idle);
    metrics.gauge(`database.pool.replica.${index}.waiting`, replica.waiting);
  });
  
  // Log warning if pool is exhausted
  if (stats.primary.idle === 0 && stats.primary.waiting > 0) {
    logger.warn('Database connection pool exhausted', {
      waiting: stats.primary.waiting,
      total: stats.primary.total
    });
  }
}, 10000); // Every 10 seconds

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('Closing database connections...');
  await connectionPool.close();
  await pool.end();
});

// For Prisma services - provide connection URL with pool settings
export function getPrismaConnectionUrl(): string {
  const url = new URL(process.env.DATABASE_URL || '');
  
  // Add connection pool parameters for Prisma
  url.searchParams.set('connection_limit', String(poolConfig.max));
  url.searchParams.set('connect_timeout', '10');
  url.searchParams.set('pool_timeout', '10');
  url.searchParams.set('socket_timeout', '10');
  
  if (isProduction) {
    url.searchParams.set('pgbouncer', 'true');
    url.searchParams.set('sslmode', 'require');
  }
  
  return url.toString();
}

// Export types
export type { DatabasePoolConfig, QueryOptions } from './connection-pool';