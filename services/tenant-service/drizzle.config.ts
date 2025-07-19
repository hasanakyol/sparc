import type { Config } from 'drizzle-kit';

export default {
  schema: '../../packages/database/schemas/tenant.ts',
  out: './drizzle',
  driver: 'pg',
  dbCredentials: {
    connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/sparc',
  },
} satisfies Config;