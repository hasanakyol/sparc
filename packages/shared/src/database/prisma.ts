import { PrismaClient } from '@prisma/client';
import { config } from '../config';
import { logger } from '../utils/logger';
import { createTenantMiddleware, createTenantAwarePrismaClient } from '../utils/rls-context';
import { createAuditMiddleware, createSecurityAuditMiddleware } from '../middleware/audit-prisma';

// Global PrismaClient instance with connection pooling
let prisma: PrismaClient | null = null;

/**
 * Create a configured PrismaClient instance with connection pooling
 */
export function createPrismaClient(): PrismaClient {
  const dbConfig = config.database;
  
  // Parse the DATABASE_URL to extract connection parameters
  const databaseUrl = new URL(dbConfig.url);
  
  // Add connection pool parameters to the URL
  const pooledUrl = new URL(databaseUrl.toString());
  pooledUrl.searchParams.set('connection_limit', dbConfig.poolMax.toString());
  pooledUrl.searchParams.set('pool_timeout', (dbConfig.connectionTimeout / 1000).toString());
  
  const prismaClient = new PrismaClient({
    datasources: {
      db: {
        url: pooledUrl.toString(),
      },
    },
    log: [
      {
        emit: 'event',
        level: 'query',
      },
      {
        emit: 'event',
        level: 'error',
      },
      {
        emit: 'event',
        level: 'warn',
      },
    ],
  });

  // Set up logging
  prismaClient.$on('query', (e) => {
    if (config.logging.level === 'debug') {
      logger.debug('Prisma Query', {
        query: e.query,
        params: e.params,
        duration: e.duration,
      });
    }
  });

  prismaClient.$on('error', (e) => {
    logger.error('Prisma Error', { error: e.message, target: e.target });
  });

  prismaClient.$on('warn', (e) => {
    logger.warn('Prisma Warning', { message: e.message });
  });

  // Add tenant middleware for automatic tenant context injection
  prismaClient.$use(createTenantMiddleware());
  
  // Add audit logging middleware
  prismaClient.$use(createAuditMiddleware({
    excludeReads: config.environment === 'production', // Only audit writes in production
  }));
  
  // Add security-specific audit middleware
  prismaClient.$use(createSecurityAuditMiddleware());

  // Add connection pool monitoring
  if (config.environment !== 'production') {
    setInterval(() => {
      prismaClient.$metrics.json().then((metrics) => {
        logger.debug('Database Pool Metrics', metrics);
      }).catch((err) => {
        logger.error('Failed to get database metrics', err);
      });
    }, 60000); // Log metrics every minute
  }

  return prismaClient;
}

/**
 * Get the singleton PrismaClient instance
 */
export function getPrismaClient(): PrismaClient {
  if (!prisma) {
    prisma = createPrismaClient();
    
    // Ensure proper cleanup on application shutdown
    const cleanup = async () => {
      if (prisma) {
        logger.info('Disconnecting from database...');
        await prisma.$disconnect();
        prisma = null;
      }
    };

    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
    process.on('beforeExit', cleanup);
  }

  return prisma;
}

/**
 * Health check for database connectivity
 */
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const client = getPrismaClient();
    await client.$queryRaw`SELECT 1`;
    return true;
  } catch (error) {
    logger.error('Database health check failed', error);
    return false;
  }
}

/**
 * Execute a database transaction with retry logic
 */
export async function withRetry<T>(
  fn: (prisma: PrismaClient) => Promise<T>,
  options: {
    maxRetries?: number;
    delay?: number;
    backoff?: number;
  } = {}
): Promise<T> {
  const { maxRetries = 3, delay = 1000, backoff = 2 } = options;
  const client = getPrismaClient();
  
  let lastError: any;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn(client);
    } catch (error: any) {
      lastError = error;
      
      // Don't retry on certain errors
      if (
        error.code === 'P2002' || // Unique constraint violation
        error.code === 'P2003' || // Foreign key constraint violation
        error.code === 'P2025'    // Record not found
      ) {
        throw error;
      }
      
      if (attempt < maxRetries) {
        const waitTime = delay * Math.pow(backoff, attempt - 1);
        logger.warn(`Database operation failed, retrying in ${waitTime}ms`, {
          attempt,
          maxRetries,
          error: error.message,
        });
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }
  
  throw lastError;
}

/**
 * Database connection pooling configuration
 */
export const poolConfig = {
  min: config.database.poolMin,
  max: config.database.poolMax,
  idleTimeoutMillis: config.database.idleTimeout,
  connectionTimeoutMillis: config.database.connectionTimeout,
  
  // Additional pool settings for production
  ...(config.environment === 'production' && {
    allowExitOnIdle: false,
    max: Math.max(config.database.poolMax, 20), // Ensure at least 20 connections in production
  }),
};

/**
 * Monitor database pool statistics
 */
export async function getPoolStats() {
  const client = getPrismaClient();
  
  try {
    const metrics = await client.$metrics.json();
    
    return {
      counters: metrics.counters,
      gauges: metrics.gauges,
      histograms: metrics.histograms,
    };
  } catch (error) {
    logger.error('Failed to get pool statistics', error);
    return null;
  }
}

// Export the singleton instance for backward compatibility
export const prisma = getPrismaClient();

/**
 * Create a tenant-aware Prisma client that automatically sets RLS context
 */
export function getTenantAwarePrismaClient(): PrismaClient {
  const baseClient = getPrismaClient();
  return createTenantAwarePrismaClient(baseClient) as PrismaClient;
}