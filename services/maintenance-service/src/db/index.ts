import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as maintenanceSchema from '@sparc/database/schemas/maintenance';
import * as tenantSchema from '@sparc/database/schemas/tenant';
import * as userSchema from '@sparc/database/schemas/user-management';
import * as deviceProvisioningSchema from '@sparc/database/schemas/device-provisioning';
import { config } from '@sparc/shared';

// Create a connection pool
const pool = new Pool({
  connectionString: config.database?.url || process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Create drizzle instance with all schemas
export const db = drizzle(pool, {
  schema: {
    ...maintenanceSchema,
    ...tenantSchema,
    ...userSchema,
    ...deviceProvisioningSchema
  }
});

// Export schema for easy access
export const schema = {
  ...maintenanceSchema,
  ...tenantSchema,
  ...userSchema,
  ...deviceProvisioningSchema
};

// Health check function
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const result = await pool.query('SELECT 1');
    return result.rowCount === 1;
  } catch (error) {
    console.error('Database health check failed:', error);
    return false;
  }
}

// Graceful shutdown
export async function closeDatabaseConnection(): Promise<void> {
  await pool.end();
}