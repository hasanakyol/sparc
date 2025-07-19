import { chromium, Browser, BrowserContext, Page } from 'playwright';
import { TestExecutionService } from './test-execution.service';
import {
  TestConfig,
  TestStatus,
  LogLevel,
  ArtifactType,
  TestResults,
  VisualTestConfig,
  Viewport,
  IgnoreRegion,
} from '../types';
import * as path from 'path';
import * as fs from 'fs/promises';
import { PNG } from 'pngjs';
import pixelmatch from 'pixelmatch';
import sharp from 'sharp';

interface VisualDiff {
  page: string;
  viewport: string;
  diffPercentage: number;
  pixelsDiff: number;
  totalPixels: number;
  passed: boolean;
  baselinePath: string;
  currentPath: string;
  diffPath: string;
}

export class VisualTestService {
  private percyToken = process.env.PERCY_TOKEN;
  private applitools = process.env.APPLITOOLS_API_KEY;

  constructor(private testExecutionService: TestExecutionService) {}

  async runVisualTests(config: VisualTestConfig & TestConfig, executionId: string): Promise<void> {
    await this.testExecutionService.updateExecution(executionId, {
      status: TestStatus.RUNNING,
    });

    try {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Starting visual regression tests: ${config.description}`
      );

      let results: TestResults;

      // Determine which visual testing platform to use
      if (this.percyToken) {
        results = await this.runPercyTests(config, executionId);
      } else if (this.applitools) {
        results = await this.runApplitoolsTests(config, executionId);
      } else {
        results = await this.runCustomVisualTests(config, executionId);
      }

      await this.testExecutionService.updateExecution(executionId, {
        status: results.passed ? TestStatus.COMPLETED : TestStatus.FAILED,
        endTime: new Date(),
        results,
      });

    } catch (error) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `Visual test failed: ${error.message}`,
        { error: error.stack }
      );

      await this.testExecutionService.updateExecution(executionId, {
        status: TestStatus.FAILED,
        endTime: new Date(),
        error: error.message,
      });
    }
  }

  private async runPercyTests(
    config: VisualTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running visual tests with Percy'
    );

    const { browsers, viewports } = config;
    const results: TestResults = {
      passed: true,
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0,
      },
      details: {
        platform: 'percy',
        snapshots: [],
      },
    };

    const startTime = Date.now();
    const percySnapshot = await import('@percy/playwright');

    for (const browserName of browsers) {
      const browser = await this.launchBrowser(browserName);
      const context = await browser.newContext();
      const page = await context.newPage();

      for (const viewport of viewports) {
        await page.setViewportSize(viewport);
        
        // Navigate to pages and take snapshots
        const pages = await this.getPagesToTest(config);
        
        for (const pageConfig of pages) {
          results.summary.total++;
          
          try {
            await page.goto(pageConfig.url);
            await page.waitForLoadState('networkidle');
            
            // Apply ignore regions if specified
            if (config.ignoreRegions) {
              await this.applyIgnoreRegions(page, config.ignoreRegions);
            }

            // Take Percy snapshot
            await percySnapshot.percySnapshot(page, `${pageConfig.name}-${browserName}-${viewport.width}x${viewport.height}`, {
              widths: [viewport.width],
              minHeight: viewport.height,
            });

            results.summary.passed++;
            results.details.snapshots.push({
              page: pageConfig.name,
              browser: browserName,
              viewport: `${viewport.width}x${viewport.height}`,
              status: 'captured',
            });

            await this.testExecutionService.addLog(
              executionId,
              LogLevel.INFO,
              `✓ Captured ${pageConfig.name} on ${browserName} at ${viewport.width}x${viewport.height}`
            );

          } catch (error) {
            results.summary.failed++;
            results.passed = false;
            
            await this.testExecutionService.addLog(
              executionId,
              LogLevel.ERROR,
              `✗ Failed to capture ${pageConfig.name}: ${error.message}`
            );
          }
        }
      }

      await context.close();
      await browser.close();
    }

    results.summary.duration = Date.now() - startTime;

    // Percy will handle the comparison and provide results via webhook
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Percy snapshots uploaded. Check Percy dashboard for visual diff results.'
    );

    return results;
  }

  private async runApplitoolsTests(
    config: VisualTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running visual tests with Applitools'
    );

    const { Eyes, Target } = await import('@applitools/eyes-playwright');
    const eyes = new Eyes();
    eyes.setApiKey(this.applitools!);

    const results: TestResults = {
      passed: true,
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0,
      },
      details: {
        platform: 'applitools',
        testResults: [],
      },
    };

    const startTime = Date.now();

    for (const browserName of config.browsers) {
      const browser = await this.launchBrowser(browserName);
      const context = await browser.newContext();
      const page = await context.newPage();

      for (const viewport of config.viewports) {
        await page.setViewportSize(viewport);
        
        // Open Eyes session
        await eyes.open(page, config.name, `${browserName}-${viewport.width}x${viewport.height}`, viewport);

        const pages = await this.getPagesToTest(config);
        
        for (const pageConfig of pages) {
          results.summary.total++;
          
          try {
            await page.goto(pageConfig.url);
            await page.waitForLoadState('networkidle');

            // Check window with Applitools
            await eyes.check(pageConfig.name, Target.window().fully());

            results.summary.passed++;
            
            await this.testExecutionService.addLog(
              executionId,
              LogLevel.INFO,
              `✓ Checked ${pageConfig.name} with Applitools`
            );

          } catch (error) {
            results.summary.failed++;
            results.passed = false;
            
            await this.testExecutionService.addLog(
              executionId,
              LogLevel.ERROR,
              `✗ Applitools check failed: ${error.message}`
            );
          }
        }

        // Close Eyes session and get results
        try {
          const testResults = await eyes.close(false);
          results.details.testResults.push({
            name: `${browserName}-${viewport.width}x${viewport.height}`,
            passed: testResults.getStatus() === 'Passed',
            url: testResults.getUrl(),
          });
        } catch (error) {
          await eyes.abort();
          throw error;
        }
      }

      await context.close();
      await browser.close();
    }

    results.summary.duration = Date.now() - startTime;
    return results;
  }

  private async runCustomVisualTests(
    config: VisualTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running custom visual regression tests'
    );

    const results: TestResults = {
      passed: true,
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0,
      },
      details: {
        platform: 'custom',
        diffs: [],
      },
    };

    const startTime = Date.now();
    const baselinePath = path.join('visual-baselines', config.baseline);
    const currentPath = path.join('test-artifacts', executionId, 'screenshots');
    const diffPath = path.join('test-artifacts', executionId, 'diffs');

    await fs.mkdir(currentPath, { recursive: true });
    await fs.mkdir(diffPath, { recursive: true });

    for (const browserName of config.browsers) {
      const browser = await this.launchBrowser(browserName);
      const context = await browser.newContext();
      const page = await context.newPage();

      for (const viewport of config.viewports) {
        await page.setViewportSize(viewport);
        const viewportKey = `${viewport.width}x${viewport.height}`;
        
        const pages = await this.getPagesToTest(config);
        
        for (const pageConfig of pages) {
          results.summary.total++;
          const screenshotName = `${pageConfig.name}-${browserName}-${viewportKey}.png`;
          
          try {
            await page.goto(pageConfig.url);
            await page.waitForLoadState('networkidle');
            
            // Apply ignore regions
            if (config.ignoreRegions) {
              await this.applyIgnoreRegions(page, config.ignoreRegions);
            }

            // Take screenshot
            const screenshotPath = path.join(currentPath, screenshotName);
            await page.screenshot({ 
              path: screenshotPath,
              fullPage: true,
            });

            // Compare with baseline
            const diff = await this.compareImages(
              path.join(baselinePath, screenshotName),
              screenshotPath,
              path.join(diffPath, `diff-${screenshotName}`),
              config.threshold,
              config.ignoreRegions
            );

            results.details.diffs.push(diff);

            if (diff.passed) {
              results.summary.passed++;
              await this.testExecutionService.addLog(
                executionId,
                LogLevel.INFO,
                `✓ ${pageConfig.name} on ${browserName} ${viewportKey} - ${diff.diffPercentage.toFixed(2)}% difference`
              );
            } else {
              results.summary.failed++;
              results.passed = false;
              await this.testExecutionService.addLog(
                executionId,
                LogLevel.ERROR,
                `✗ ${pageConfig.name} on ${browserName} ${viewportKey} - ${diff.diffPercentage.toFixed(2)}% difference exceeds threshold`
              );

              // Save artifacts
              await this.testExecutionService.addArtifact(executionId, {
                type: ArtifactType.SCREENSHOT,
                name: `diff-${screenshotName}`,
                path: diff.diffPath,
                size: (await fs.stat(diff.diffPath)).size,
                mimeType: 'image/png',
              });
            }

          } catch (error) {
            results.summary.failed++;
            results.passed = false;
            
            await this.testExecutionService.addLog(
              executionId,
              LogLevel.ERROR,
              `✗ Failed to test ${pageConfig.name}: ${error.message}`
            );
          }
        }
      }

      await context.close();
      await browser.close();
    }

    results.summary.duration = Date.now() - startTime;

    // Generate visual report
    await this.generateVisualReport(results, executionId);

    return results;
  }

  private async compareImages(
    baselinePath: string,
    currentPath: string,
    diffPath: string,
    threshold: number,
    ignoreRegions?: IgnoreRegion[]
  ): Promise<VisualDiff> {
    try {
      // Read images
      const baselineBuffer = await fs.readFile(baselinePath);
      const currentBuffer = await fs.readFile(currentPath);

      // Parse PNGs
      const baseline = PNG.sync.read(baselineBuffer);
      const current = PNG.sync.read(currentBuffer);

      // Ensure same dimensions
      if (baseline.width !== current.width || baseline.height !== current.height) {
        // Resize current image to match baseline
        const resizedBuffer = await sharp(currentBuffer)
          .resize(baseline.width, baseline.height)
          .toBuffer();
        const resized = PNG.sync.read(resizedBuffer);
        Object.assign(current, resized);
      }

      // Create diff image
      const diff = new PNG({ width: baseline.width, height: baseline.height });

      // Apply ignore regions by making those pixels identical
      if (ignoreRegions) {
        this.applyIgnoreRegionsToDiff(baseline, current, ignoreRegions);
      }

      // Compare pixels
      const pixelsDiff = pixelmatch(
        baseline.data,
        current.data,
        diff.data,
        baseline.width,
        baseline.height,
        { threshold: 0.1 }
      );

      // Calculate diff percentage
      const totalPixels = baseline.width * baseline.height;
      const diffPercentage = (pixelsDiff / totalPixels) * 100;

      // Write diff image
      await fs.writeFile(diffPath, PNG.sync.write(diff));

      return {
        page: path.basename(currentPath, '.png'),
        viewport: 'unknown',
        diffPercentage,
        pixelsDiff,
        totalPixels,
        passed: diffPercentage <= threshold,
        baselinePath,
        currentPath,
        diffPath,
      };

    } catch (error) {
      if (error.code === 'ENOENT' && error.path === baselinePath) {
        // No baseline exists, create it
        await fs.mkdir(path.dirname(baselinePath), { recursive: true });
        await fs.copyFile(currentPath, baselinePath);
        
        return {
          page: path.basename(currentPath, '.png'),
          viewport: 'unknown',
          diffPercentage: 0,
          pixelsDiff: 0,
          totalPixels: 0,
          passed: true,
          baselinePath,
          currentPath,
          diffPath: '',
        };
      }
      throw error;
    }
  }

  private applyIgnoreRegionsToDiff(
    baseline: PNG,
    current: PNG,
    ignoreRegions: IgnoreRegion[]
  ): void {
    for (const region of ignoreRegions) {
      if (!region.x || !region.y || !region.width || !region.height) continue;

      for (let y = region.y; y < region.y + region.height; y++) {
        for (let x = region.x; x < region.x + region.width; x++) {
          const idx = (baseline.width * y + x) << 2;
          
          // Copy baseline pixels to current for ignored regions
          current.data[idx] = baseline.data[idx];
          current.data[idx + 1] = baseline.data[idx + 1];
          current.data[idx + 2] = baseline.data[idx + 2];
          current.data[idx + 3] = baseline.data[idx + 3];
        }
      }
    }
  }

  private async applyIgnoreRegions(page: Page, ignoreRegions: IgnoreRegion[]): Promise<void> {
    for (const region of ignoreRegions) {
      if (region.selector) {
        // Hide elements by selector
        await page.evaluate((selector) => {
          const elements = document.querySelectorAll(selector);
          elements.forEach(el => {
            (el as HTMLElement).style.visibility = 'hidden';
          });
        }, region.selector);
      }
    }
  }

  private async getPagesToTest(config: VisualTestConfig & TestConfig): Promise<any[]> {
    // This would normally read from a configuration file or database
    return [
      { name: 'dashboard', url: '/dashboard' },
      { name: 'login', url: '/login' },
      { name: 'access-control', url: '/access-control' },
      { name: 'video-management', url: '/video' },
      { name: 'reports', url: '/reports' },
      { name: 'settings', url: '/settings' },
    ];
  }

  private async launchBrowser(browserName: string): Promise<Browser> {
    const browserMap = {
      chromium: chromium,
      // Add other browsers as needed
    };

    const browserType = browserMap[browserName] || chromium;
    return await browserType.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
  }

  private async generateVisualReport(results: TestResults, executionId: string): Promise<void> {
    const reportPath = path.join('test-artifacts', executionId, 'visual-report.html');
    
    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Visual Regression Test Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    h1 { color: #333; }
    .summary { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .diff-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
    .diff-card { background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .diff-card.passed { border-left: 4px solid #4caf50; }
    .diff-card.failed { border-left: 4px solid #f44336; }
    .diff-images { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-top: 10px; }
    .diff-images img { width: 100%; border: 1px solid #ddd; border-radius: 4px; }
    .diff-percentage { font-size: 18px; font-weight: bold; margin: 10px 0; }
    .passed .diff-percentage { color: #4caf50; }
    .failed .diff-percentage { color: #f44336; }
  </style>
</head>
<body>
  <h1>Visual Regression Test Report</h1>
  
  <div class="summary">
    <h2>Summary</h2>
    <p>Total Screenshots: ${results.summary.total}</p>
    <p>Passed: ${results.summary.passed}</p>
    <p>Failed: ${results.summary.failed}</p>
    <p>Duration: ${(results.summary.duration / 1000).toFixed(2)}s</p>
  </div>
  
  <h2>Visual Differences</h2>
  <div class="diff-grid">
    ${results.details.diffs?.map(diff => `
      <div class="diff-card ${diff.passed ? 'passed' : 'failed'}">
        <h3>${diff.page}</h3>
        <div class="diff-percentage">${diff.diffPercentage.toFixed(2)}% difference</div>
        <p>${diff.pixelsDiff} of ${diff.totalPixels} pixels changed</p>
        ${!diff.passed ? `
          <div class="diff-images">
            <div>
              <h4>Baseline</h4>
              <img src="${diff.baselinePath}" alt="Baseline">
            </div>
            <div>
              <h4>Current</h4>
              <img src="${diff.currentPath}" alt="Current">
            </div>
            <div>
              <h4>Diff</h4>
              <img src="${diff.diffPath}" alt="Diff">
            </div>
          </div>
        ` : '<p>✓ Within threshold</p>'}
      </div>
    `).join('') || '<p>No visual diffs recorded</p>'}
  </div>
</body>
</html>
    `;

    await fs.writeFile(reportPath, html);

    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.REPORT,
      name: 'visual-report.html',
      path: reportPath,
      size: Buffer.byteLength(html),
      mimeType: 'text/html',
    });
  }

  async cleanup(): Promise<void> {
    // No specific cleanup needed
  }
}