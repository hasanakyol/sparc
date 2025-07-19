#!/usr/bin/env tsx

/**
 * SPARC Service Package.json Audit Script
 * Audits all service package.json files for consistency
 */

import { readdir, readFile } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';

interface PackageJson {
  name: string;
  version: string;
  scripts: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  engines?: Record<string, string>;
  [key: string]: any;
}

interface ServiceAudit {
  name: string;
  path: string;
  issues: string[];
  warnings: string[];
  hasDbScripts: boolean;
  dbType?: 'prisma' | 'drizzle' | 'none';
}

// Required scripts for all services
const REQUIRED_SCRIPTS = [
  'dev',
  'build',
  'start',
  'test',
  'lint',
  'lint:fix',
  'type-check'
];

// Common test scripts
const COMMON_TEST_SCRIPTS = [
  'test:unit',
  'test:integration',
  'test:coverage',
  'test:watch'
];

// Database scripts by type
const DB_SCRIPTS = {
  prisma: ['db:generate', 'db:push', 'db:migrate', 'db:studio', 'db:seed'],
  drizzle: ['db:generate', 'db:push', 'db:studio', 'db:seed']
};

async function getServices(): Promise<string[]> {
  const servicesDir = join(process.cwd(), 'services');
  const entries = await readdir(servicesDir, { withFileTypes: true });
  
  return entries
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
    .sort();
}

async function auditService(serviceName: string): Promise<ServiceAudit> {
  const servicePath = join(process.cwd(), 'services', serviceName);
  const packageJsonPath = join(servicePath, 'package.json');
  
  const audit: ServiceAudit = {
    name: serviceName,
    path: servicePath,
    issues: [],
    warnings: [],
    hasDbScripts: false
  };

  if (!existsSync(packageJsonPath)) {
    audit.issues.push('package.json not found');
    return audit;
  }

  try {
    const content = await readFile(packageJsonPath, 'utf-8');
    const packageJson: PackageJson = JSON.parse(content);

    // Check required scripts
    for (const script of REQUIRED_SCRIPTS) {
      if (!packageJson.scripts?.[script]) {
        audit.issues.push(`Missing required script: ${script}`);
      }
    }

    // Check test scripts
    const hasTestScripts = COMMON_TEST_SCRIPTS.some(script => packageJson.scripts?.[script]);
    if (!hasTestScripts && packageJson.scripts?.test === 'jest') {
      audit.warnings.push('Consider adding specific test scripts (test:unit, test:integration, etc.)');
    }

    // Check database scripts
    const hasPrisma = packageJson.dependencies?.['@prisma/client'] || packageJson.devDependencies?.['prisma'];
    const hasDrizzle = packageJson.dependencies?.['drizzle-orm'] || packageJson.devDependencies?.['drizzle-kit'];

    if (hasPrisma) {
      audit.dbType = 'prisma';
      audit.hasDbScripts = true;
      for (const script of DB_SCRIPTS.prisma) {
        if (!packageJson.scripts?.[script]) {
          audit.issues.push(`Missing Prisma script: ${script}`);
        }
      }
    } else if (hasDrizzle) {
      audit.dbType = 'drizzle';
      audit.hasDbScripts = true;
      for (const script of DB_SCRIPTS.drizzle) {
        if (!packageJson.scripts?.[script]) {
          audit.issues.push(`Missing Drizzle script: ${script}`);
        }
      }
    } else {
      // Check if service might need DB scripts
      const mightNeedDb = serviceName.includes('service') && 
        !['api-gateway', 'api-documentation-service', 'testing-infrastructure-service'].includes(serviceName);
      if (mightNeedDb) {
        audit.warnings.push('Service might need database scripts but none found');
      }
    }

    // Check engine requirements
    if (!packageJson.engines?.node) {
      audit.issues.push('Missing engines.node requirement');
    } else if (packageJson.engines.node !== '>=18.0.0') {
      audit.warnings.push(`Non-standard Node version requirement: ${packageJson.engines.node}`);
    }

    // Check consistent naming
    if (!packageJson.name?.startsWith('@sparc/')) {
      audit.issues.push(`Package name should start with @sparc/ (found: ${packageJson.name})`);
    }

    // Check license consistency
    if (!packageJson.license) {
      audit.issues.push('Missing license field');
    } else if (!['MIT', 'UNLICENSED'].includes(packageJson.license)) {
      audit.warnings.push(`Non-standard license: ${packageJson.license}`);
    }

    // Check private flag for services
    if (packageJson.license === 'UNLICENSED' && !packageJson.private) {
      audit.issues.push('UNLICENSED packages should have private: true');
    }

  } catch (error) {
    audit.issues.push(`Failed to parse package.json: ${error}`);
  }

  return audit;
}

async function generateReport(audits: ServiceAudit[]): Promise<void> {
  const totalServices = audits.length;
  const servicesWithIssues = audits.filter(a => a.issues.length > 0);
  const servicesWithWarnings = audits.filter(a => a.warnings.length > 0);
  
  console.log('\n=== SPARC Service Package.json Audit Report ===\n');
  console.log(`Total services audited: ${totalServices}`);
  console.log(`Services with issues: ${servicesWithIssues.length}`);
  console.log(`Services with warnings: ${servicesWithWarnings.length}`);
  console.log(`Services using Prisma: ${audits.filter(a => a.dbType === 'prisma').length}`);
  console.log(`Services using Drizzle: ${audits.filter(a => a.dbType === 'drizzle').length}`);
  
  if (servicesWithIssues.length > 0) {
    console.log('\n=== Services with Issues ===\n');
    for (const audit of servicesWithIssues) {
      console.log(`\n${audit.name}:`);
      for (const issue of audit.issues) {
        console.log(`  ❌ ${issue}`);
      }
    }
  }
  
  if (servicesWithWarnings.length > 0) {
    console.log('\n=== Services with Warnings ===\n');
    for (const audit of servicesWithWarnings) {
      console.log(`\n${audit.name}:`);
      for (const warning of audit.warnings) {
        console.log(`  ⚠️  ${warning}`);
      }
    }
  }
  
  // Generate fix commands
  console.log('\n=== Suggested Fixes ===\n');
  
  // Group services by issue type
  const missingDevScript = audits.filter(a => a.issues.includes('Missing required script: dev'));
  const missingDbScripts = audits.filter(a => a.issues.some(i => i.includes('Missing') && i.includes('script:')));
  
  if (missingDevScript.length > 0) {
    console.log('Add dev script to services:');
    for (const audit of missingDevScript) {
      console.log(`  cd services/${audit.name} && npm pkg set scripts.dev="tsx watch src/index.ts"`);
    }
  }
  
  console.log('\n=== Summary ===\n');
  console.log('✅ All services have been audited');
  console.log(`📊 ${((totalServices - servicesWithIssues.length) / totalServices * 100).toFixed(1)}% of services have no issues`);
}

async function main() {
  try {
    console.log('Starting SPARC service package.json audit...\n');
    
    const services = await getServices();
    console.log(`Found ${services.length} services to audit`);
    
    const audits: ServiceAudit[] = [];
    
    for (const service of services) {
      process.stdout.write(`Auditing ${service}... `);
      const audit = await auditService(service);
      audits.push(audit);
      
      if (audit.issues.length === 0 && audit.warnings.length === 0) {
        console.log('✅');
      } else if (audit.issues.length > 0) {
        console.log(`❌ (${audit.issues.length} issues)`);
      } else {
        console.log(`⚠️  (${audit.warnings.length} warnings)`);
      }
    }
    
    await generateReport(audits);
    
    // Exit with error if there are issues
    const hasIssues = audits.some(a => a.issues.length > 0);
    process.exit(hasIssues ? 1 : 0);
    
  } catch (error) {
    console.error('Audit failed:', error);
    process.exit(1);
  }
}

// Run the audit
main();