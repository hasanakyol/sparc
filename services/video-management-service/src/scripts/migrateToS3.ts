#!/usr/bin/env node

import { CloudStorageService, MigrationProgress } from '../services/storageService';
import { Command } from 'commander';
import { config } from '@sparc/shared';
import chalk from 'chalk';
import ora from 'ora';
import { statSync, existsSync } from 'fs';
import { join } from 'path';
import Table from 'cli-table3';

interface MigrationConfig {
  sourcePath: string;
  bucket: string;
  region: string;
  batchSize: number;
  dryRun: boolean;
  verify: boolean;
  deleteAfterMigration: boolean;
  continueOnError: boolean;
  filter?: string;
}

class S3MigrationTool {
  private storageService: CloudStorageService;
  private spinner: ora.Ora;
  private startTime: number;
  private config: MigrationConfig;

  constructor(config: MigrationConfig) {
    this.config = config;
    this.spinner = ora();
    this.startTime = Date.now();

    // Initialize storage service
    this.storageService = new CloudStorageService({
      bucket: config.bucket,
      region: config.region,
      cloudfrontDomain: process.env.CLOUDFRONT_DOMAIN,
      cloudfrontDistributionId: process.env.CLOUDFRONT_DISTRIBUTION_ID,
    });
  }

  async run(): Promise<void> {
    try {
      console.log(chalk.blue.bold('\n🚀 S3 Migration Tool\n'));
      
      // Validate source path
      if (!existsSync(this.config.sourcePath)) {
        throw new Error(`Source path does not exist: ${this.config.sourcePath}`);
      }

      const stats = statSync(this.config.sourcePath);
      if (!stats.isDirectory()) {
        throw new Error(`Source path is not a directory: ${this.config.sourcePath}`);
      }

      // Display configuration
      this.displayConfig();

      if (this.config.dryRun) {
        console.log(chalk.yellow('\n⚠️  DRY RUN MODE - No files will be uploaded\n'));
      }

      // Confirm before proceeding (unless dry run)
      if (!this.config.dryRun && !this.config.deleteAfterMigration) {
        const readline = require('readline').createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        const answer = await new Promise<string>((resolve) => {
          readline.question(
            chalk.yellow('\n⚠️  Files will be uploaded but NOT deleted. Continue? (y/N): '),
            resolve
          );
        });

        readline.close();

        if (answer.toLowerCase() !== 'y') {
          console.log(chalk.red('\n❌ Migration cancelled\n'));
          process.exit(0);
        }
      }

      // Start migration
      console.log(chalk.green('\n📁 Starting migration...\n'));
      this.spinner.start('Scanning source directory...');

      const progress = await this.storageService.migrateFromLocalStorage({
        sourcePath: this.config.sourcePath,
        batchSize: this.config.batchSize,
        dryRun: this.config.dryRun,
        verify: this.config.verify,
        deleteAfterMigration: this.config.deleteAfterMigration,
        onProgress: (progress) => this.updateProgress(progress),
      });

      this.spinner.stop();

      // Display final results
      this.displayResults(progress);

    } catch (error) {
      this.spinner.stop();
      console.error(chalk.red('\n❌ Migration failed:'), error);
      process.exit(1);
    } finally {
      await this.storageService.shutdown();
    }
  }

  private displayConfig(): void {
    const table = new Table({
      head: [chalk.cyan('Setting'), chalk.cyan('Value')],
      colWidths: [30, 50],
    });

    table.push(
      ['Source Path', this.config.sourcePath],
      ['S3 Bucket', this.config.bucket],
      ['AWS Region', this.config.region],
      ['Batch Size', this.config.batchSize.toString()],
      ['Dry Run', this.config.dryRun ? 'Yes' : 'No'],
      ['Verify Uploads', this.config.verify ? 'Yes' : 'No'],
      ['Delete After Migration', this.config.deleteAfterMigration ? 'Yes' : 'No'],
      ['Continue on Error', this.config.continueOnError ? 'Yes' : 'No']
    );

    console.log(table.toString());
  }

  private updateProgress(progress: MigrationProgress): void {
    const percentage = progress.totalFiles > 0
      ? (progress.processedFiles / progress.totalFiles) * 100
      : 0;

    const sizeInMB = (progress.processedBytes / 1024 / 1024).toFixed(2);
    const totalSizeInMB = (progress.totalBytes / 1024 / 1024).toFixed(2);

    this.spinner.text = chalk.cyan(
      `Processing: ${progress.processedFiles}/${progress.totalFiles} files ` +
      `(${percentage.toFixed(1)}%) - ${sizeInMB}/${totalSizeInMB} MB`
    );

    if (progress.currentFile) {
      this.spinner.text += chalk.gray(`\nCurrent: ${progress.currentFile}`);
    }

    // Log errors as they occur
    if (progress.errorCount > 0 && progress.errors.length > 0) {
      const lastError = progress.errors[progress.errors.length - 1];
      console.log(chalk.red(`\n❌ Error: ${lastError.file} - ${lastError.error}`));
    }
  }

  private displayResults(progress: MigrationProgress): void {
    const duration = Date.now() - this.startTime;
    const durationMin = (duration / 1000 / 60).toFixed(2);

    console.log(chalk.green.bold('\n✅ Migration Complete!\n'));

    const table = new Table({
      head: [chalk.cyan('Metric'), chalk.cyan('Value')],
      colWidths: [30, 50],
    });

    table.push(
      ['Total Files', progress.totalFiles.toString()],
      ['Processed Files', progress.processedFiles.toString()],
      ['Successful', chalk.green(progress.successCount.toString())],
      ['Failed', progress.errorCount > 0 ? chalk.red(progress.errorCount.toString()) : '0'],
      ['Total Size', `${(progress.totalBytes / 1024 / 1024 / 1024).toFixed(2)} GB`],
      ['Processed Size', `${(progress.processedBytes / 1024 / 1024 / 1024).toFixed(2)} GB`],
      ['Duration', `${durationMin} minutes`],
      ['Average Speed', `${((progress.processedBytes / 1024 / 1024) / (duration / 1000)).toFixed(2)} MB/s`]
    );

    console.log(table.toString());

    // Display errors if any
    if (progress.errors.length > 0) {
      console.log(chalk.red.bold('\n❌ Errors:\n'));
      
      const errorTable = new Table({
        head: [chalk.cyan('File'), chalk.cyan('Error')],
        colWidths: [40, 60],
        wordWrap: true,
      });

      progress.errors.forEach((error) => {
        errorTable.push([error.file, error.error]);
      });

      console.log(errorTable.toString());
    }

    // Provide next steps
    console.log(chalk.blue.bold('\n📋 Next Steps:\n'));
    
    if (this.config.dryRun) {
      console.log(chalk.yellow('• This was a dry run. Run without --dry-run to perform actual migration'));
    } else {
      console.log(chalk.green('• ✅ Videos have been uploaded to S3'));
      
      if (!this.config.deleteAfterMigration) {
        console.log(chalk.yellow('• ⚠️  Original files are still on disk. Delete manually after verification'));
      }
      
      console.log(chalk.blue('• 🔍 Verify uploads in AWS S3 console'));
      console.log(chalk.blue('• 🚀 Update application configuration to use S3 storage'));
      console.log(chalk.blue('• 📊 Monitor CloudWatch metrics for performance'));
    }

    console.log('');
  }
}

// Command line interface
const program = new Command();

program
  .name('migrate-to-s3')
  .description('Migrate video files from local storage to AWS S3')
  .version('1.0.0')
  .requiredOption('-s, --source <path>', 'Source directory containing video files')
  .requiredOption('-b, --bucket <bucket>', 'S3 bucket name')
  .option('-r, --region <region>', 'AWS region', 'us-east-1')
  .option('--batch-size <size>', 'Number of files to upload concurrently', '5')
  .option('--dry-run', 'Simulate migration without uploading files')
  .option('--no-verify', 'Skip verification of uploaded files')
  .option('--delete', 'Delete local files after successful upload')
  .option('--continue-on-error', 'Continue migration even if some files fail')
  .option('--filter <pattern>', 'Filter files by pattern (e.g., "*.mp4")')
  .action(async (options) => {
    const config: MigrationConfig = {
      sourcePath: options.source,
      bucket: options.bucket,
      region: options.region,
      batchSize: parseInt(options.batchSize, 10),
      dryRun: options.dryRun || false,
      verify: options.verify !== false,
      deleteAfterMigration: options.delete || false,
      continueOnError: options.continueOnError || false,
      filter: options.filter,
    };

    const tool = new S3MigrationTool(config);
    await tool.run();
  });

// Parse command line arguments
program.parse(process.argv);

// Show help if no arguments provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}