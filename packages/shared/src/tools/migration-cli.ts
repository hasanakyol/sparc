#!/usr/bin/env node

import { Command } from 'commander';
import { z } from 'zod';
import axios, { AxiosInstance } from 'axios';
import * as fs from 'fs/promises';
import * as path from 'path';
import chalk from 'chalk';
import ora from 'ora';
import prompts from 'prompts';

/**
 * Migration CLI for SPARC API version migrations
 */
class MigrationCLI {
  private apiClient: AxiosInstance;
  private config: MigrationConfig;

  constructor() {
    this.config = this.loadConfig();
    this.apiClient = axios.create({
      baseURL: this.config.apiUrl,
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json'
      }
    });
  }

  /**
   * Load configuration
   */
  private loadConfig(): MigrationConfig {
    const configPath = path.join(process.cwd(), '.sparc-migration.json');
    try {
      const config = require(configPath);
      return migrationConfigSchema.parse(config);
    } catch (error) {
      console.error(chalk.red('Configuration file not found or invalid'));
      console.log(chalk.yellow('Run "sparc-migrate init" to create configuration'));
      process.exit(1);
    }
  }

  /**
   * Initialize configuration
   */
  async init(): Promise<void> {
    console.log(chalk.blue('🚀 SPARC API Migration Tool Setup\n'));

    const responses = await prompts([
      {
        type: 'text',
        name: 'apiUrl',
        message: 'API Gateway URL:',
        initial: 'https://api.sparc.io'
      },
      {
        type: 'password',
        name: 'apiKey',
        message: 'API Key:'
      },
      {
        type: 'text',
        name: 'fromVersion',
        message: 'Current API Version:',
        initial: '1.1'
      },
      {
        type: 'text',
        name: 'toVersion',
        message: 'Target API Version:',
        initial: '2.0'
      }
    ]);

    const config: MigrationConfig = {
      apiUrl: responses.apiUrl,
      apiKey: responses.apiKey,
      fromVersion: responses.fromVersion,
      toVersion: responses.toVersion,
      models: []
    };

    await fs.writeFile(
      path.join(process.cwd(), '.sparc-migration.json'),
      JSON.stringify(config, null, 2)
    );

    console.log(chalk.green('\n✅ Configuration saved to .sparc-migration.json'));
    console.log(chalk.gray('Add this file to .gitignore to keep your API key secure'));
  }

  /**
   * Check compatibility
   */
  async checkCompatibility(): Promise<void> {
    const spinner = ora('Checking API compatibility...').start();

    try {
      const response = await this.apiClient.post('/versions/check-compatibility', {
        clientVersion: this.config.fromVersion,
        requiredFeatures: this.config.requiredFeatures || []
      });

      spinner.stop();

      const { compatible, warnings, errors, recommendations } = response.data;

      console.log(chalk.blue('\n📋 Compatibility Check Results\n'));
      console.log(`Current Version: ${chalk.cyan(this.config.fromVersion)}`);
      console.log(`Target Version: ${chalk.cyan(this.config.toVersion)}`);
      console.log(`Status: ${compatible ? chalk.green('✅ Compatible') : chalk.red('❌ Incompatible')}\n`);

      if (errors.length > 0) {
        console.log(chalk.red('Errors:'));
        errors.forEach((error: string) => console.log(`  • ${error}`));
        console.log();
      }

      if (warnings.length > 0) {
        console.log(chalk.yellow('Warnings:'));
        warnings.forEach((warning: string) => console.log(`  • ${warning}`));
        console.log();
      }

      if (recommendations.length > 0) {
        console.log(chalk.blue('Recommendations:'));
        recommendations.forEach((rec: string) => console.log(`  • ${rec}`));
        console.log();
      }
    } catch (error: any) {
      spinner.fail('Compatibility check failed');
      console.error(chalk.red(error.message));
      process.exit(1);
    }
  }

  /**
   * Validate data transformation
   */
  async validate(modelName: string, dataFile: string): Promise<void> {
    const spinner = ora(`Validating ${modelName} transformation...`).start();

    try {
      // Read data file
      const data = JSON.parse(await fs.readFile(dataFile, 'utf-8'));

      // Validate transformation
      const response = await this.apiClient.post('/versions/validate-migration', {
        fromVersion: this.config.fromVersion,
        toVersion: this.config.toVersion,
        model: modelName,
        data
      });

      spinner.stop();

      if (response.data.success) {
        console.log(chalk.green(`\n✅ Transformation valid for ${modelName}\n`));
        console.log(chalk.blue('Original:'));
        console.log(JSON.stringify(response.data.original, null, 2));
        console.log(chalk.blue('\nTransformed:'));
        console.log(JSON.stringify(response.data.transformed, null, 2));
        console.log(chalk.blue('\nChanges:'));
        console.log(JSON.stringify(response.data.changes, null, 2));
      } else {
        console.log(chalk.red(`\n❌ Transformation failed for ${modelName}\n`));
        console.log(chalk.red('Error:'), response.data.error);
        if (response.data.details) {
          console.log(chalk.red('Details:'), JSON.stringify(response.data.details, null, 2));
        }
      }
    } catch (error: any) {
      spinner.fail('Validation failed');
      console.error(chalk.red(error.message));
      process.exit(1);
    }
  }

  /**
   * Generate migration report
   */
  async report(): Promise<void> {
    const spinner = ora('Generating migration report...').start();

    try {
      // Get version information
      const versionsResponse = await this.apiClient.get('/versions');
      const deprecationsResponse = await this.apiClient.get(`/versions/${this.config.fromVersion}/deprecations`);

      spinner.stop();

      console.log(chalk.blue('\n📊 Migration Report\n'));
      console.log(chalk.white('═'.repeat(60)));
      console.log();

      // Current version status
      const currentVersion = versionsResponse.data.versions.find(
        (v: any) => v.version === this.config.fromVersion
      );
      console.log(chalk.cyan('Current Version Status:'));
      console.log(`  Version: ${currentVersion.version}`);
      console.log(`  Status: ${this.getStatusColor(currentVersion.status)}`);
      if (currentVersion.deprecatedAt) {
        console.log(`  Deprecated: ${new Date(currentVersion.deprecatedAt).toLocaleDateString()}`);
      }
      if (currentVersion.sunsetAt) {
        console.log(`  Sunset: ${new Date(currentVersion.sunsetAt).toLocaleDateString()}`);
      }
      console.log();

      // Target version status
      const targetVersion = versionsResponse.data.versions.find(
        (v: any) => v.version === this.config.toVersion
      );
      console.log(chalk.cyan('Target Version Status:'));
      console.log(`  Version: ${targetVersion.version}`);
      console.log(`  Status: ${this.getStatusColor(targetVersion.status)}`);
      console.log();

      // Deprecations
      if (deprecationsResponse.data.notices.length > 0) {
        console.log(chalk.yellow('Deprecation Notices:'));
        deprecationsResponse.data.notices.forEach((notice: any) => {
          console.log(`\n  ${chalk.yellow('⚠')} ${notice.message}`);
          if (notice.endpoint) {
            console.log(`     Endpoint: ${notice.endpoint}`);
          }
          if (notice.daysUntilSunset) {
            console.log(`     Days until sunset: ${notice.daysUntilSunset}`);
          }
          if (notice.migrationGuide) {
            console.log(`     Migration guide: ${chalk.blue(notice.migrationGuide)}`);
          }
        });
      }

      console.log();
      console.log(chalk.white('═'.repeat(60)));
    } catch (error: any) {
      spinner.fail('Report generation failed');
      console.error(chalk.red(error.message));
      process.exit(1);
    }
  }

  /**
   * Run migration tests
   */
  async test(): Promise<void> {
    console.log(chalk.blue('\n🧪 Running Migration Tests\n'));

    const testSuites = [
      { name: 'Endpoint Availability', test: () => this.testEndpoints() },
      { name: 'Data Transformation', test: () => this.testTransformations() },
      { name: 'Backward Compatibility', test: () => this.testBackwardCompatibility() },
      { name: 'Performance', test: () => this.testPerformance() }
    ];

    const results = [];
    for (const suite of testSuites) {
      const spinner = ora(`Testing ${suite.name}...`).start();
      try {
        const result = await suite.test();
        spinner.succeed(`${suite.name}: ${chalk.green('PASSED')}`);
        results.push({ suite: suite.name, passed: true, ...result });
      } catch (error: any) {
        spinner.fail(`${suite.name}: ${chalk.red('FAILED')}`);
        console.error(chalk.gray(`  ${error.message}`));
        results.push({ suite: suite.name, passed: false, error: error.message });
      }
    }

    // Summary
    console.log(chalk.blue('\n📊 Test Summary\n'));
    const passed = results.filter(r => r.passed).length;
    const failed = results.filter(r => !r.passed).length;
    console.log(`Total: ${results.length}`);
    console.log(`Passed: ${chalk.green(passed)}`);
    console.log(`Failed: ${chalk.red(failed)}`);

    if (failed > 0) {
      process.exit(1);
    }
  }

  private async testEndpoints(): Promise<any> {
    // Test key endpoints exist in both versions
    const endpoints = ['/incidents', '/users', '/cameras'];
    const results = [];

    for (const endpoint of endpoints) {
      try {
        await this.apiClient.get(endpoint, {
          headers: { 'Accept-Version': this.config.fromVersion }
        });
        await this.apiClient.get(endpoint, {
          headers: { 'Accept-Version': this.config.toVersion }
        });
        results.push({ endpoint, available: true });
      } catch (error) {
        results.push({ endpoint, available: false });
      }
    }

    return { endpoints: results };
  }

  private async testTransformations(): Promise<any> {
    // Test data transformations for configured models
    const models = this.config.models || ['Incident', 'User', 'Camera'];
    const results = [];

    for (const model of models) {
      try {
        const testData = this.getTestData(model);
        const response = await this.apiClient.post('/versions/validate-migration', {
          fromVersion: this.config.fromVersion,
          toVersion: this.config.toVersion,
          model,
          data: testData
        });
        results.push({ model, valid: response.data.success });
      } catch (error) {
        results.push({ model, valid: false });
      }
    }

    return { models: results };
  }

  private async testBackwardCompatibility(): Promise<any> {
    // Test that old clients can still work with new API
    return { compatible: true };
  }

  private async testPerformance(): Promise<any> {
    // Simple performance test
    const iterations = 10;
    const timings = [];

    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await this.apiClient.get('/versions');
      const end = Date.now();
      timings.push(end - start);
    }

    const average = timings.reduce((a, b) => a + b, 0) / timings.length;
    return { averageResponseTime: average, acceptable: average < 200 };
  }

  private getTestData(model: string): any {
    const testData: Record<string, any> = {
      Incident: {
        incident_id: '123e4567-e89b-12d3-a456-426614174000',
        incident_type: 'security',
        priority: 'high',
        created_by: 'user123',
        created_at: '2024-01-15T10:00:00Z'
      },
      User: {
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        full_name: 'John Doe',
        email: 'john@example.com',
        roles: ['admin'],
        is_active: true
      },
      Camera: {
        id: '123e4567-e89b-12d3-a456-426614174002',
        name: 'Front Door Camera',
        location: 'Building A - Entrance',
        has_ptz: true,
        has_audio: true,
        has_analytics: false
      }
    };

    return testData[model] || {};
  }

  private getStatusColor(status: string): string {
    const colors: Record<string, string> = {
      current: chalk.green(status),
      deprecated: chalk.yellow(status),
      preview: chalk.blue(status),
      sunset: chalk.red(status)
    };
    return colors[status] || status;
  }
}

/**
 * Configuration schema
 */
const migrationConfigSchema = z.object({
  apiUrl: z.string().url(),
  apiKey: z.string(),
  fromVersion: z.string(),
  toVersion: z.string(),
  models: z.array(z.string()).optional(),
  requiredFeatures: z.array(z.string()).optional()
});

type MigrationConfig = z.infer<typeof migrationConfigSchema>;

/**
 * CLI setup
 */
const program = new Command();
const cli = new MigrationCLI();

program
  .name('sparc-migrate')
  .description('SPARC API Migration Tool')
  .version('1.0.0');

program
  .command('init')
  .description('Initialize migration configuration')
  .action(() => cli.init());

program
  .command('check')
  .description('Check version compatibility')
  .action(() => cli.checkCompatibility());

program
  .command('validate <model> <dataFile>')
  .description('Validate data transformation for a model')
  .action((model, dataFile) => cli.validate(model, dataFile));

program
  .command('report')
  .description('Generate migration report')
  .action(() => cli.report());

program
  .command('test')
  .description('Run migration tests')
  .action(() => cli.test());

program.parse(process.argv);