#!/usr/bin/env node
import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { join } from 'path';
import { getPrismaClient } from '../../shared/src/database/prisma';
import { logger } from '../../shared/src/utils/logger';

async function applyRLS() {
  logger.info('Applying Row Level Security to database...');
  
  const prisma = getPrismaClient();
  
  try {
    // Read the RLS migration SQL
    const sqlPath = join(__dirname, '../migrations/20250118_row_level_security.sql');
    const sqlContent = readFileSync(sqlPath, 'utf-8');
    
    // Split by semicolon and execute each statement
    const statements = sqlContent
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    
    logger.info(`Executing ${statements.length} SQL statements...`);
    
    // Execute within a transaction
    await prisma.$transaction(async (tx) => {
      for (let i = 0; i < statements.length; i++) {
        const statement = statements[i];
        
        // Skip comments
        if (statement.startsWith('--')) continue;
        
        try {
          await tx.$executeRawUnsafe(statement);
          
          if (i % 10 === 0) {
            logger.info(`Progress: ${i}/${statements.length} statements executed`);
          }
        } catch (error: any) {
          logger.error(`Failed to execute statement ${i}:`, {
            statement: statement.substring(0, 100) + '...',
            error: error.message
          });
          throw error;
        }
      }
    });
    
    logger.info('Row Level Security applied successfully!');
    
    // Verify RLS is enabled
    const rlsCheck = await prisma.$queryRaw`
      SELECT tablename, rowsecurity 
      FROM pg_tables 
      WHERE schemaname = 'public' 
      AND tablename NOT LIKE '_prisma%'
      ORDER BY tablename
    ` as Array<{ tablename: string; rowsecurity: boolean }>;
    
    const tablesWithRLS = rlsCheck.filter(t => t.rowsecurity);
    const tablesWithoutRLS = rlsCheck.filter(t => !t.rowsecurity);
    
    logger.info(`RLS Status:`, {
      enabled: tablesWithRLS.length,
      disabled: tablesWithoutRLS.length,
      tablesWithoutRLS: tablesWithoutRLS.map(t => t.tablename)
    });
    
    // Check policies
    const policies = await prisma.$queryRaw`
      SELECT tablename, COUNT(*) as policy_count 
      FROM pg_policies 
      WHERE schemaname = 'public'
      GROUP BY tablename
      ORDER BY tablename
    ` as Array<{ tablename: string; policy_count: number }>;
    
    logger.info('Policy Summary:', policies);
    
  } catch (error) {
    logger.error('Failed to apply Row Level Security:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Run if called directly
if (require.main === module) {
  applyRLS()
    .then(() => {
      logger.info('RLS migration completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('RLS migration failed:', error);
      process.exit(1);
    });
}

export { applyRLS };