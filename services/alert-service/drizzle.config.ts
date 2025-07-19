import type { Config } from 'drizzle-kit';
import { config } from '@sparc/shared';

export default {
  schema: '../../packages/database/schemas/alerts.ts',
  out: './drizzle',
  driver: 'pg',
  dbCredentials: {
    connectionString: config.database?.url || process.env.DATABASE_URL!,
  },
} satisfies Config;