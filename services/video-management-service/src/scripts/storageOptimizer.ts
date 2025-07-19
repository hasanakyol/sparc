#!/usr/bin/env node

import { CloudStorageService, StorageMetrics } from '../services/storageService';
import { Command } from 'commander';
import { config } from '@sparc/shared';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import { S3Client, ListObjectsV2Command, PutObjectCommand, CopyObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { differenceInDays, parseISO } from 'date-fns';
import pLimit from 'p-limit';

interface OptimizationConfig {
  bucket: string;
  region: string;
  dryRun: boolean;
  tenantId?: string;
  archiveAfterDays: number;
  glacierAfterDays: number;
  deepArchiveAfterDays: number;
  deleteAfterDays?: number;
  maxConcurrency: number;
  verbose: boolean;
}

interface OptimizationResult {
  filesProcessed: number;
  filesToStandardIA: number;
  filesToGlacier: number;
  filesToDeepArchive: number;
  filesDeleted: number;
  bytesOptimized: number;
  estimatedMonthlySavings: number;
  errors: Array<{ key: string; error: string }>;
}

interface StorageClassTransition {
  fromClass: string;
  toClass: string;
  daysOld: number;
  count: number;
  totalSize: number;
  files: Array<{ key: string; size: number; lastModified: Date }>;
}

class StorageOptimizer {
  private storageService: CloudStorageService;
  private s3Client: S3Client;
  private spinner: ora.Ora;
  private config: OptimizationConfig;
  private limit: pLimit.Limit;

  constructor(config: OptimizationConfig) {
    this.config = config;
    this.spinner = ora();
    this.limit = pLimit(config.maxConcurrency);

    // Initialize services
    this.storageService = new CloudStorageService({
      bucket: config.bucket,
      region: config.region,
    });

    this.s3Client = new S3Client({
      region: config.region,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
      },
    });
  }

  async run(): Promise<void> {
    try {
      console.log(chalk.blue.bold('\n🚀 Storage Optimization Tool\n'));
      
      // Display configuration
      this.displayConfig();

      if (this.config.dryRun) {
        console.log(chalk.yellow('\n⚠️  DRY RUN MODE - No changes will be made\n'));
      }

      // Get current storage metrics
      console.log(chalk.green('\n📊 Analyzing current storage...\n'));
      this.spinner.start('Fetching storage metrics...');
      
      const metrics = await this.storageService.getStorageMetrics(this.config.tenantId);
      this.spinner.stop();
      
      this.displayMetrics(metrics);

      // Analyze files for optimization
      console.log(chalk.green('\n🔍 Analyzing files for optimization...\n'));
      this.spinner.start('Scanning files...');
      
      const transitions = await this.analyzeStorageOptimization();
      this.spinner.stop();
      
      this.displayTransitions(transitions);

      // Calculate estimated savings
      const savings = this.calculateSavings(transitions);
      this.displaySavings(savings);

      // Confirm optimization
      if (!this.config.dryRun && transitions.length > 0) {
        const readline = require('readline').createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        const answer = await new Promise<string>((resolve) => {
          readline.question(
            chalk.yellow('\n⚠️  Proceed with optimization? (y/N): '),
            resolve
          );
        });

        readline.close();

        if (answer.toLowerCase() !== 'y') {
          console.log(chalk.red('\n❌ Optimization cancelled\n'));
          process.exit(0);
        }
      }

      // Perform optimization
      if (transitions.length > 0) {
        console.log(chalk.green('\n⚙️  Optimizing storage...\n'));
        const result = await this.optimizeStorage(transitions);
        this.displayResults(result);
      } else {
        console.log(chalk.yellow('\n✅ No optimization needed - storage is already optimal!\n'));
      }

      // Clean up temporary files
      console.log(chalk.green('\n🧹 Cleaning up temporary files...\n'));
      const cleanupResult = await this.storageService.cleanupStorage({
        deleteEmptyFolders: true,
        removeOrphaned: true,
      });
      
      console.log(chalk.green(`✅ Cleaned up ${cleanupResult.deletedFiles} temporary files`));
      console.log(chalk.green(`   Freed ${this.formatBytes(cleanupResult.freedSpace)}`));

    } catch (error) {
      this.spinner.stop();
      console.error(chalk.red('\n❌ Optimization failed:'), error);
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
      ['S3 Bucket', this.config.bucket],
      ['AWS Region', this.config.region],
      ['Tenant Filter', this.config.tenantId || 'All tenants'],
      ['Archive After Days', this.config.archiveAfterDays.toString()],
      ['Glacier After Days', this.config.glacierAfterDays.toString()],
      ['Deep Archive After Days', this.config.deepArchiveAfterDays.toString()],
      ['Delete After Days', this.config.deleteAfterDays?.toString() || 'Never'],
      ['Dry Run', this.config.dryRun ? 'Yes' : 'No'],
      ['Max Concurrency', this.config.maxConcurrency.toString()],
    );

    console.log(table.toString());
  }

  private displayMetrics(metrics: StorageMetrics): void {
    const table = new Table({
      head: [chalk.cyan('Metric'), chalk.cyan('Value')],
      colWidths: [30, 50],
    });

    table.push(
      ['Total Files', metrics.fileCount.toLocaleString()],
      ['Total Size', this.formatBytes(metrics.totalSize)],
      ['Oldest File', metrics.oldestFile.toLocaleDateString()],
      ['Newest File', metrics.newestFile.toLocaleDateString()],
    );

    console.log('\n' + chalk.bold('Current Storage Metrics:'));
    console.log(table.toString());

    // Storage class breakdown
    if (Object.keys(metrics.byStorageClass).length > 0) {
      const classTable = new Table({
        head: [chalk.cyan('Storage Class'), chalk.cyan('Files'), chalk.cyan('Size')],
        colWidths: [25, 15, 20],
      });

      for (const [storageClass, data] of Object.entries(metrics.byStorageClass)) {
        classTable.push([
          storageClass,
          data.count.toLocaleString(),
          this.formatBytes(data.size),
        ]);
      }

      console.log('\n' + chalk.bold('By Storage Class:'));
      console.log(classTable.toString());
    }
  }

  private async analyzeStorageOptimization(): Promise<StorageClassTransition[]> {
    const transitions: StorageClassTransition[] = [];
    let continuationToken: string | undefined;
    const now = new Date();

    const prefix = this.config.tenantId 
      ? `video-recordings/${this.config.tenantId}/`
      : 'video-recordings/';

    do {
      const command = new ListObjectsV2Command({
        Bucket: this.config.bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken,
        MaxKeys: 1000,
      });

      const response = await this.s3Client.send(command);

      if (response.Contents) {
        for (const object of response.Contents) {
          if (!object.LastModified || !object.Key) continue;

          const daysOld = differenceInDays(now, object.LastModified);
          const currentClass = object.StorageClass || 'STANDARD';
          let targetClass: string | null = null;

          // Determine target storage class based on age
          if (this.config.deleteAfterDays && daysOld >= this.config.deleteAfterDays) {
            targetClass = 'DELETE';
          } else if (daysOld >= this.config.deepArchiveAfterDays && currentClass !== 'DEEP_ARCHIVE') {
            targetClass = 'DEEP_ARCHIVE';
          } else if (daysOld >= this.config.glacierAfterDays && 
                     currentClass !== 'GLACIER' && 
                     currentClass !== 'DEEP_ARCHIVE') {
            targetClass = 'GLACIER';
          } else if (daysOld >= this.config.archiveAfterDays && 
                     currentClass === 'STANDARD') {
            targetClass = 'STANDARD_IA';
          }

          if (targetClass && targetClass !== currentClass) {
            // Find or create transition group
            let transition = transitions.find(
              t => t.fromClass === currentClass && t.toClass === targetClass
            );

            if (!transition) {
              transition = {
                fromClass: currentClass,
                toClass: targetClass,
                daysOld,
                count: 0,
                totalSize: 0,
                files: [],
              };
              transitions.push(transition);
            }

            transition.count++;
            transition.totalSize += object.Size || 0;
            
            if (this.config.verbose || transition.files.length < 100) {
              transition.files.push({
                key: object.Key,
                size: object.Size || 0,
                lastModified: object.LastModified,
              });
            }
          }
        }
      }

      continuationToken = response.NextContinuationToken;
    } while (continuationToken);

    return transitions;
  }

  private displayTransitions(transitions: StorageClassTransition[]): void {
    if (transitions.length === 0) {
      return;
    }

    const table = new Table({
      head: [
        chalk.cyan('From'),
        chalk.cyan('To'),
        chalk.cyan('Files'),
        chalk.cyan('Total Size'),
        chalk.cyan('Age (days)'),
      ],
      colWidths: [20, 20, 15, 20, 15],
    });

    for (const transition of transitions) {
      table.push([
        transition.fromClass,
        transition.toClass === 'DELETE' ? chalk.red('DELETE') : transition.toClass,
        transition.count.toLocaleString(),
        this.formatBytes(transition.totalSize),
        `≥ ${transition.daysOld}`,
      ]);
    }

    console.log('\n' + chalk.bold('Recommended Transitions:'));
    console.log(table.toString());

    // Show sample files if verbose
    if (this.config.verbose) {
      for (const transition of transitions) {
        if (transition.files.length > 0) {
          console.log(chalk.gray(`\nSample files for ${transition.fromClass} → ${transition.toClass}:`));
          transition.files.slice(0, 5).forEach(file => {
            console.log(chalk.gray(`  - ${file.key} (${this.formatBytes(file.size)})`));
          });
          if (transition.files.length > 5) {
            console.log(chalk.gray(`  ... and ${transition.files.length - 5} more`));
          }
        }
      }
    }
  }

  private calculateSavings(transitions: StorageClassTransition[]): number {
    // AWS S3 pricing per GB per month (approximate)
    const pricing = {
      STANDARD: 0.023,
      STANDARD_IA: 0.0125,
      GLACIER: 0.004,
      DEEP_ARCHIVE: 0.00099,
      DELETE: 0,
    };

    let monthlySavings = 0;

    for (const transition of transitions) {
      const sizeInGB = transition.totalSize / (1024 * 1024 * 1024);
      const currentCost = sizeInGB * (pricing[transition.fromClass as keyof typeof pricing] || pricing.STANDARD);
      const newCost = sizeInGB * (pricing[transition.toClass as keyof typeof pricing] || 0);
      monthlySavings += currentCost - newCost;
    }

    return monthlySavings;
  }

  private displaySavings(monthlySavings: number): void {
    const table = new Table({
      head: [chalk.cyan('Period'), chalk.cyan('Estimated Savings')],
      colWidths: [20, 30],
    });

    table.push(
      ['Monthly', chalk.green(`$${monthlySavings.toFixed(2)}`)],
      ['Yearly', chalk.green(`$${(monthlySavings * 12).toFixed(2)}`)],
    );

    console.log('\n' + chalk.bold('Cost Savings:'));
    console.log(table.toString());
  }

  private async optimizeStorage(transitions: StorageClassTransition[]): Promise<OptimizationResult> {
    const result: OptimizationResult = {
      filesProcessed: 0,
      filesToStandardIA: 0,
      filesToGlacier: 0,
      filesToDeepArchive: 0,
      filesDeleted: 0,
      bytesOptimized: 0,
      estimatedMonthlySavings: 0,
      errors: [],
    };

    const startTime = Date.now();

    for (const transition of transitions) {
      this.spinner.start(
        `Processing ${transition.count} files from ${transition.fromClass} to ${transition.toClass}...`
      );

      const tasks = transition.files.map(file => 
        this.limit(async () => {
          try {
            if (this.config.dryRun) {
              // Simulate processing in dry run mode
              await new Promise(resolve => setTimeout(resolve, 10));
            } else {
              if (transition.toClass === 'DELETE') {
                await this.deleteObject(file.key);
                result.filesDeleted++;
              } else {
                await this.changeStorageClass(file.key, transition.toClass);
                
                switch (transition.toClass) {
                  case 'STANDARD_IA':
                    result.filesToStandardIA++;
                    break;
                  case 'GLACIER':
                    result.filesToGlacier++;
                    break;
                  case 'DEEP_ARCHIVE':
                    result.filesToDeepArchive++;
                    break;
                }
              }
            }

            result.filesProcessed++;
            result.bytesOptimized += file.size;

            // Update progress
            if (result.filesProcessed % 100 === 0) {
              const elapsed = (Date.now() - startTime) / 1000;
              const rate = result.filesProcessed / elapsed;
              const remaining = (transition.count - result.filesProcessed) / rate;
              
              this.spinner.text = 
                `Processing ${transition.fromClass} → ${transition.toClass}: ` +
                `${result.filesProcessed}/${transition.count} files ` +
                `(${this.formatTime(remaining)} remaining)`;
            }

          } catch (error) {
            result.errors.push({
              key: file.key,
              error: error instanceof Error ? error.message : String(error),
            });
          }
        })
      );

      await Promise.all(tasks);
      this.spinner.stop();
    }

    result.estimatedMonthlySavings = this.calculateSavings(transitions);

    return result;
  }

  private async changeStorageClass(key: string, storageClass: string): Promise<void> {
    // Copy object with new storage class
    const copyCommand = new CopyObjectCommand({
      Bucket: this.config.bucket,
      CopySource: `${this.config.bucket}/${key}`,
      Key: key,
      StorageClass: storageClass as any,
      MetadataDirective: 'COPY',
    });

    await this.s3Client.send(copyCommand);
  }

  private async deleteObject(key: string): Promise<void> {
    const deleteCommand = new DeleteObjectCommand({
      Bucket: this.config.bucket,
      Key: key,
    });

    await this.s3Client.send(deleteCommand);
  }

  private displayResults(result: OptimizationResult): void {
    console.log(chalk.green.bold('\n✅ Optimization Complete!\n'));

    const table = new Table({
      head: [chalk.cyan('Metric'), chalk.cyan('Value')],
      colWidths: [35, 35],
    });

    table.push(
      ['Total Files Processed', result.filesProcessed.toLocaleString()],
      ['Moved to Standard-IA', result.filesToStandardIA.toLocaleString()],
      ['Moved to Glacier', result.filesToGlacier.toLocaleString()],
      ['Moved to Deep Archive', result.filesToDeepArchive.toLocaleString()],
      ['Files Deleted', result.filesDeleted.toLocaleString()],
      ['Total Size Optimized', this.formatBytes(result.bytesOptimized)],
      ['Estimated Monthly Savings', chalk.green(`$${result.estimatedMonthlySavings.toFixed(2)}`)],
      ['Errors', result.errors.length > 0 ? chalk.red(result.errors.length.toString()) : '0'],
    );

    console.log(table.toString());

    if (result.errors.length > 0) {
      console.log(chalk.red.bold('\n❌ Errors:\n'));
      const errorTable = new Table({
        head: [chalk.cyan('File'), chalk.cyan('Error')],
        colWidths: [50, 50],
        wordWrap: true,
      });

      result.errors.slice(0, 10).forEach(error => {
        errorTable.push([error.key, error.error]);
      });

      console.log(errorTable.toString());
      
      if (result.errors.length > 10) {
        console.log(chalk.gray(`\n... and ${result.errors.length - 10} more errors`));
      }
    }
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  private formatTime(seconds: number): string {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${Math.round(seconds / 3600)}h`;
  }
}

// Command line interface
const program = new Command();

program
  .name('storage-optimizer')
  .description('Optimize S3 storage costs by managing lifecycle transitions')
  .version('1.0.0')
  .requiredOption('-b, --bucket <bucket>', 'S3 bucket name')
  .option('-r, --region <region>', 'AWS region', 'us-east-1')
  .option('-t, --tenant <id>', 'Filter by tenant ID')
  .option('--archive-after <days>', 'Move to Standard-IA after N days', '30')
  .option('--glacier-after <days>', 'Move to Glacier after N days', '90')
  .option('--deep-archive-after <days>', 'Move to Deep Archive after N days', '365')
  .option('--delete-after <days>', 'Delete files after N days (optional)')
  .option('--concurrency <n>', 'Maximum concurrent operations', '10')
  .option('--dry-run', 'Simulate optimization without making changes')
  .option('-v, --verbose', 'Show detailed output')
  .action(async (options) => {
    const config: OptimizationConfig = {
      bucket: options.bucket,
      region: options.region,
      tenantId: options.tenant,
      archiveAfterDays: parseInt(options.archiveAfter, 10),
      glacierAfterDays: parseInt(options.glacierAfter, 10),
      deepArchiveAfterDays: parseInt(options.deepArchiveAfter, 10),
      deleteAfterDays: options.deleteAfter ? parseInt(options.deleteAfter, 10) : undefined,
      maxConcurrency: parseInt(options.concurrency, 10),
      dryRun: options.dryRun || false,
      verbose: options.verbose || false,
    };

    const optimizer = new StorageOptimizer(config);
    await optimizer.run();
  });

// Parse command line arguments
program.parse(process.argv);

// Show help if no arguments provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}