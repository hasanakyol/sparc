/**
 * Example usage of the database connection pool in services
 * This file demonstrates how to integrate the connection pool with existing services
 */

import { createDatabasePool, DatabaseConnectionPool } from './connection-pool';
import { getPoolConfig } from './config/pool-config';
import { db, pool, connectionPool, checkDatabaseHealth, getPrismaConnectionUrl } from './connection';

// Example 1: Using in a service with Drizzle ORM
export async function serviceWithDrizzle() {
  // Import the pre-configured db instance
  const users = await db.select().from(usersTable).where(eq(usersTable.tenantId, 'tenant-123'));
  
  // For complex queries with read replicas
  const analyticsData = await connectionPool.query(
    'SELECT COUNT(*) FROM events WHERE created_at > $1',
    [new Date(Date.now() - 86400000)],
    { useReadReplica: true }
  );
}

// Example 2: Using in a service with custom pool configuration
export async function serviceWithCustomPool() {
  const serviceName = 'video-management';
  const poolConfig = getPoolConfig(serviceName);
  const customPool = createDatabasePool(poolConfig);
  
  // Execute a long-running video processing query
  const result = await customPool.query(
    'UPDATE video_recordings SET status = $1 WHERE id = $2',
    ['processing', 'video-123'],
    { timeout: 300000 } // 5 minute timeout for video operations
  );
  
  // Don't forget to close when service shuts down
  process.on('SIGTERM', async () => {
    await customPool.close();
  });
}

// Example 3: Using with Prisma (for services still using Prisma)
export function configurePrisma() {
  // Set DATABASE_URL with pool parameters
  process.env.DATABASE_URL = getPrismaConnectionUrl();
  
  // Now initialize Prisma client
  // const prisma = new PrismaClient();
}

// Example 4: Transaction with retry logic
export async function transactionWithRetry() {
  const result = await connectionPool.transaction(async (client) => {
    // Begin transaction
    await client.query('INSERT INTO audit_logs (action, user_id) VALUES ($1, $2)', ['login', 'user-123']);
    await client.query('UPDATE users SET last_login = NOW() WHERE id = $1', ['user-123']);
    
    return { success: true };
  }, {
    timeout: 10000,
    retries: 3,
    retryDelay: 100
  });
}

// Example 5: Batch operations
export async function batchInsert() {
  const events = [
    { type: 'motion', cameraId: 'cam-1', timestamp: new Date() },
    { type: 'motion', cameraId: 'cam-2', timestamp: new Date() },
    { type: 'motion', cameraId: 'cam-3', timestamp: new Date() }
  ];
  
  const queries = events.map(event => ({
    text: 'INSERT INTO events (type, camera_id, timestamp) VALUES ($1, $2, $3)',
    values: [event.type, event.cameraId, event.timestamp]
  }));
  
  await connectionPool.batch(queries);
}

// Example 6: Health check endpoint
export async function healthCheckEndpoint() {
  const isHealthy = await checkDatabaseHealth();
  
  if (!isHealthy) {
    throw new Error('Database connection unhealthy');
  }
  
  // Get detailed stats
  const stats = connectionPool.getStats();
  
  return {
    status: 'healthy',
    database: {
      primary: stats.primary,
      replicas: stats.replicas,
      queries: stats.queries
    }
  };
}

// Example 7: Monitoring integration
export function setupMonitoring() {
  // Stats are automatically exported to metrics
  // But you can also manually check them
  setInterval(async () => {
    const stats = connectionPool.getStats();
    
    // Log warning if pool is getting exhausted
    if (stats.primary.idle === 0 && stats.primary.waiting > 0) {
      console.warn('Database pool exhausted!', {
        waiting: stats.primary.waiting,
        total: stats.primary.total
      });
    }
    
    // Log if too many errors
    if (stats.queries.errors > 100) {
      console.error('High database error rate', {
        errors: stats.queries.errors,
        total: stats.queries.queries
      });
    }
  }, 30000); // Check every 30 seconds
}

// Example 8: Graceful shutdown
export function setupGracefulShutdown() {
  const signals = ['SIGTERM', 'SIGINT'];
  
  signals.forEach(signal => {
    process.on(signal, async () => {
      console.log(`Received ${signal}, closing database connections...`);
      
      try {
        // Close the enhanced pool
        await connectionPool.close();
        
        // Close the standard pool
        await pool.end();
        
        console.log('Database connections closed successfully');
        process.exit(0);
      } catch (error) {
        console.error('Error closing database connections:', error);
        process.exit(1);
      }
    });
  });
}