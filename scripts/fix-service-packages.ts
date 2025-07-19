#!/usr/bin/env tsx

/**
 * SPARC Service Package.json Fix Script
 * Automatically fixes common issues in service package.json files
 */

import { readdir, readFile, writeFile } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';

interface PackageJson {
  name: string;
  version?: string;
  description?: string;
  main?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  engines?: Record<string, string>;
  keywords?: string[];
  author?: string;
  license?: string;
  private?: boolean;
  [key: string]: any;
}

// Required scripts for all services
const REQUIRED_SCRIPTS = {
  'type-check': 'tsc --noEmit',
  'lint:fix': 'eslint src --ext .ts --fix'
};

// Database scripts by ORM type
const DB_SCRIPTS = {
  prisma: {
    'db:generate': 'prisma generate',
    'db:push': 'prisma db push',
    'db:migrate': 'prisma migrate dev',
    'db:studio': 'prisma studio',
    'db:seed': 'tsx src/scripts/seed.ts'
  },
  drizzle: {
    'db:generate': 'drizzle-kit generate:pg',
    'db:push': 'drizzle-kit push:pg',
    'db:studio': 'drizzle-kit studio',
    'db:seed': 'tsx src/scripts/seed.ts'
  }
};

async function getServices(): Promise<string[]> {
  const servicesDir = join(process.cwd(), 'services');
  const entries = await readdir(servicesDir, { withFileTypes: true });
  
  return entries
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .sort();
}

async function fixService(serviceName: string, dryRun: boolean = false): Promise<{ fixed: boolean; changes: string[] }> {
  const servicePath = join(process.cwd(), 'services', serviceName);
  const packageJsonPath = join(servicePath, 'package.json');
  const changes: string[] = [];
  
  if (!existsSync(packageJsonPath)) {
    console.log(`  ⚠️  Skipping ${serviceName}: package.json not found`);
    return { fixed: false, changes };
  }

  try {
    const content = await readFile(packageJsonPath, 'utf-8');
    const packageJson: PackageJson = JSON.parse(content);
    let modified = false;

    // Ensure scripts object exists
    if (!packageJson.scripts) {
      packageJson.scripts = {};
      modified = true;
      changes.push('Added scripts object');
    }

    // Add missing required scripts
    for (const [scriptName, scriptCommand] of Object.entries(REQUIRED_SCRIPTS)) {
      if (!packageJson.scripts[scriptName]) {
        packageJson.scripts[scriptName] = scriptCommand;
        modified = true;
        changes.push(`Added script: ${scriptName}`);
      }
    }

    // Add missing database scripts
    const hasPrisma = packageJson.dependencies?.['@prisma/client'] || packageJson.devDependencies?.['prisma'];
    const hasDrizzle = packageJson.dependencies?.['drizzle-orm'] || packageJson.devDependencies?.['drizzle-kit'];

    if (hasPrisma) {
      for (const [scriptName, scriptCommand] of Object.entries(DB_SCRIPTS.prisma)) {
        if (!packageJson.scripts[scriptName]) {
          packageJson.scripts[scriptName] = scriptCommand;
          modified = true;
          changes.push(`Added Prisma script: ${scriptName}`);
        }
      }
    } else if (hasDrizzle) {
      for (const [scriptName, scriptCommand] of Object.entries(DB_SCRIPTS.drizzle)) {
        if (!packageJson.scripts[scriptName]) {
          packageJson.scripts[scriptName] = scriptCommand;
          modified = true;
          changes.push(`Added Drizzle script: ${scriptName}`);
        }
      }
    }

    // Add missing engines.node
    if (!packageJson.engines) {
      packageJson.engines = { node: '>=18.0.0' };
      modified = true;
      changes.push('Added engines.node requirement');
    } else if (!packageJson.engines.node) {
      packageJson.engines.node = '>=18.0.0';
      modified = true;
      changes.push('Added engines.node requirement');
    }

    // Add missing license
    if (!packageJson.license) {
      packageJson.license = 'UNLICENSED';
      packageJson.private = true;
      modified = true;
      changes.push('Added license: UNLICENSED and private: true');
    } else if (packageJson.license === 'UNLICENSED' && !packageJson.private) {
      packageJson.private = true;
      modified = true;
      changes.push('Added private: true for UNLICENSED package');
    }

    // Fix package name if needed
    if (packageJson.name && !packageJson.name.startsWith('@sparc/')) {
      packageJson.name = `@sparc/${serviceName}`;
      modified = true;
      changes.push('Fixed package name to use @sparc/ prefix');
    }

    // Sort scripts alphabetically
    if (packageJson.scripts && modified) {
      const sortedScripts = Object.keys(packageJson.scripts)
        .sort()
        .reduce((acc, key) => {
          acc[key] = packageJson.scripts![key];
          return acc;
        }, {} as Record<string, string>);
      packageJson.scripts = sortedScripts;
    }

    // Write changes if not dry run
    if (modified && !dryRun) {
      const formattedContent = JSON.stringify(packageJson, null, 2) + '\n';
      await writeFile(packageJsonPath, formattedContent);
    }

    return { fixed: modified, changes };
  } catch (error) {
    console.error(`  ❌ Error processing ${serviceName}:`, error);
    return { fixed: false, changes };
  }
}

async function createMissingSeedFiles(dryRun: boolean = false): Promise<void> {
  console.log('\n=== Creating Missing Seed Files ===\n');
  
  const services = await getServices();
  
  for (const service of services) {
    const seedPath = join(process.cwd(), 'services', service, 'src', 'scripts', 'seed.ts');
    const scriptsDir = join(process.cwd(), 'services', service, 'src', 'scripts');
    
    if (!existsSync(seedPath) && existsSync(join(process.cwd(), 'services', service, 'package.json'))) {
      try {
        const packageJsonPath = join(process.cwd(), 'services', service, 'package.json');
        const content = await readFile(packageJsonPath, 'utf-8');
        const packageJson = JSON.parse(content);
        
        // Check if service has db:seed script
        if (packageJson.scripts?.['db:seed']) {
          console.log(`Creating seed file for ${service}...`);
          
          if (!dryRun) {
            // Create scripts directory if it doesn't exist
            const { mkdir } = await import('fs/promises');
            await mkdir(scriptsDir, { recursive: true });
            
            // Determine ORM type
            const hasPrisma = packageJson.dependencies?.['@prisma/client'];
            const hasDrizzle = packageJson.dependencies?.['drizzle-orm'];
            
            let seedContent = '';
            
            if (hasPrisma) {
              seedContent = `import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seeding for ${service}...');
  
  // TODO: Add your seed data here
  // Example:
  // await prisma.model.createMany({
  //   data: [
  //     { field: 'value1' },
  //     { field: 'value2' },
  //   ],
  // });
  
  console.log('✅ Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
`;
            } else if (hasDrizzle) {
              seedContent = `import { db } from '../db';
// Import your schema tables here
// import { users, organizations } from '@sparc/database/schemas/${service.replace('-service', '')}';

async function main() {
  console.log('🌱 Starting database seeding for ${service}...');
  
  // TODO: Add your seed data here
  // Example:
  // await db.insert(users).values([
  //   { name: 'John Doe', email: 'john@example.com' },
  //   { name: 'Jane Smith', email: 'jane@example.com' },
  // ]);
  
  console.log('✅ Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  });
`;
            } else {
              seedContent = `// Generic seed script for ${service}

async function main() {
  console.log('🌱 Starting database seeding for ${service}...');
  
  // TODO: Add your database seeding logic here
  
  console.log('✅ Database seeding completed!');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  });
`;
            }
            
            await writeFile(seedPath, seedContent);
            console.log(`  ✅ Created seed file for ${service}`);
          }
        }
      } catch (error) {
        console.error(`  ❌ Error creating seed file for ${service}:`, error);
      }
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  
  console.log('🔧 SPARC Service Package.json Fix Script\n');
  if (dryRun) {
    console.log('🔍 Running in DRY RUN mode - no changes will be made\n');
  }
  
  const services = await getServices();
  console.log(`Found ${services.length} services to check\n`);
  
  let totalFixed = 0;
  const allChanges: Array<{ service: string; changes: string[] }> = [];
  
  for (const service of services) {
    process.stdout.write(`Processing ${service}... `);
    const { fixed, changes } = await fixService(service, dryRun);
    
    if (fixed) {
      console.log(`✅ (${changes.length} fixes)`);
      totalFixed++;
      allChanges.push({ service, changes });
    } else if (changes.length === 0) {
      console.log('✓ (no changes needed)');
    }
  }
  
  // Create missing seed files
  await createMissingSeedFiles(dryRun);
  
  // Summary report
  console.log('\n=== Summary ===\n');
  console.log(`Services processed: ${services.length}`);
  console.log(`Services fixed: ${totalFixed}`);
  
  if (allChanges.length > 0) {
    console.log('\n=== Changes Made ===\n');
    for (const { service, changes } of allChanges) {
      console.log(`${service}:`);
      for (const change of changes) {
        console.log(`  - ${change}`);
      }
      console.log();
    }
  }
  
  if (dryRun && totalFixed > 0) {
    console.log('\n💡 Run without --dry-run to apply these fixes');
  }
  
  console.log('\n✨ Done!');
}

// Run the fix script
main().catch(console.error);