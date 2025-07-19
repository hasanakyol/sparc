import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { config } from '@sparc/shared';

// Create postgres connection
const connectionString = config.database?.url || process.env.DATABASE_URL!;
const sql = postgres(connectionString);

// Create drizzle db instance
export const db = drizzle(sql);

// Export the sql instance for cleanup
export const sqlConnection = sql;