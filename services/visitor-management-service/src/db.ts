import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from '@sparc/database/schemas/visitor-management';
import { config } from '@sparc/shared';

let connection: postgres.Sql | null = null;
let db: ReturnType<typeof drizzle> | null = null;

export function getDb() {
  if (!db) {
    const databaseUrl = config.database?.url || process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error('DATABASE_URL is not set');
    }

    connection = postgres(databaseUrl, {
      max: 10,
      idle_timeout: 20,
      connect_timeout: 10,
    });

    db = drizzle(connection, { schema });
  }

  return db;
}

export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const db = getDb();
    await db.execute`SELECT 1`;
    return true;
  } catch (error) {
    console.error('Database health check failed:', error);
    return false;
  }
}

export async function closeDatabaseConnection(): Promise<void> {
  if (connection) {
    await connection.end();
    connection = null;
    db = null;
  }
}