import { chromium, firefox, webkit, Browser, BrowserContext, Page } from 'playwright';
import { TestExecutionService } from './test-execution.service';
import {
  TestConfig,
  TestStatus,
  LogLevel,
  ArtifactType,
  TestResults,
  TestSummary,
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import * as path from 'path';
import * as fs from 'fs/promises';

export interface E2ETestConfig extends TestConfig {
  parameters: {
    testSuite: string;
    browser: 'chromium' | 'firefox' | 'webkit' | 'all';
    baseUrl: string;
    headless?: boolean;
    viewport?: { width: number; height: number };
    recordVideo?: boolean;
    traceEnabled?: boolean;
    testPattern?: string;
    grep?: string;
    workers?: number;
  };
}

export class E2ETestService {
  private browsers: Map<string, Browser> = new Map();

  constructor(private testExecutionService: TestExecutionService) {}

  async runE2ETests(config: E2ETestConfig, executionId: string): Promise<void> {
    await this.testExecutionService.updateExecution(executionId, {
      status: TestStatus.RUNNING,
    });

    try {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Starting E2E tests: ${config.description}`
      );

      const results = await this.executeTests(config, executionId);

      await this.testExecutionService.updateExecution(executionId, {
        status: results.passed ? TestStatus.COMPLETED : TestStatus.FAILED,
        endTime: new Date(),
        duration: Date.now() - new Date().getTime(),
        results,
      });

    } catch (error) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `E2E test failed: ${error.message}`,
        { error: error.stack }
      );

      await this.testExecutionService.updateExecution(executionId, {
        status: TestStatus.FAILED,
        endTime: new Date(),
        error: error.message,
      });
    }
  }

  private async executeTests(
    config: E2ETestConfig,
    executionId: string
  ): Promise<TestResults> {
    const { browser, testSuite, baseUrl, headless = true, viewport, recordVideo, traceEnabled } = config.parameters;
    
    const results: TestResults = {
      passed: true,
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0,
        flaky: 0,
      },
      details: {
        testSuite,
        browser,
        baseUrl,
        tests: [],
      },
    };

    const browsersToTest = browser === 'all' 
      ? ['chromium', 'firefox', 'webkit'] 
      : [browser];

    for (const browserName of browsersToTest) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Running tests on ${browserName}`
      );

      const browserResults = await this.runBrowserTests(
        browserName as any,
        config,
        executionId
      );

      // Merge results
      results.summary.total += browserResults.summary.total;
      results.summary.passed += browserResults.summary.passed;
      results.summary.failed += browserResults.summary.failed;
      results.summary.skipped += browserResults.summary.skipped;
      results.summary.duration += browserResults.summary.duration;
      results.details.tests.push(...browserResults.details.tests);

      if (!browserResults.passed) {
        results.passed = false;
      }
    }

    return results;
  }

  private async runBrowserTests(
    browserName: 'chromium' | 'firefox' | 'webkit',
    config: E2ETestConfig,
    executionId: string
  ): Promise<TestResults> {
    const { baseUrl, headless, viewport, recordVideo, traceEnabled, testSuite } = config.parameters;
    
    const browser = await this.launchBrowser(browserName, headless);
    const artifactsDir = path.join('test-artifacts', executionId, browserName);
    await fs.mkdir(artifactsDir, { recursive: true });

    const contextOptions: any = {
      baseURL: baseUrl,
      viewport: viewport || { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true,
    };

    if (recordVideo) {
      contextOptions.recordVideo = {
        dir: path.join(artifactsDir, 'videos'),
        size: viewport || { width: 1920, height: 1080 },
      };
    }

    const context = await browser.newContext(contextOptions);

    if (traceEnabled) {
      await context.tracing.start({
        screenshots: true,
        snapshots: true,
        sources: true,
      });
    }

    const page = await context.newPage();
    const results = await this.runTestSuite(page, testSuite, config, executionId);

    // Capture final screenshot
    const screenshotPath = path.join(artifactsDir, 'final-screenshot.png');
    await page.screenshot({ path: screenshotPath, fullPage: true });
    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.SCREENSHOT,
      name: `${browserName}-final-screenshot.png`,
      path: screenshotPath,
      size: (await fs.stat(screenshotPath)).size,
      mimeType: 'image/png',
    });

    if (traceEnabled) {
      const tracePath = path.join(artifactsDir, 'trace.zip');
      await context.tracing.stop({ path: tracePath });
      await this.testExecutionService.addArtifact(executionId, {
        type: ArtifactType.TRACE,
        name: `${browserName}-trace.zip`,
        path: tracePath,
        size: (await fs.stat(tracePath)).size,
        mimeType: 'application/zip',
      });
    }

    await context.close();
    await browser.close();

    return results;
  }

  private async runTestSuite(
    page: Page,
    testSuite: string,
    config: E2ETestConfig,
    executionId: string
  ): Promise<TestResults> {
    const startTime = Date.now();
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
        tests: [],
      },
    };

    // Map test suites to actual test implementations
    const testSuiteMap: Record<string, () => Promise<any>> = {
      'auth-workflows': () => this.runAuthWorkflowTests(page, results, executionId),
      'access-control-workflows': () => this.runAccessControlTests(page, results, executionId),
      'video-management-workflows': () => this.runVideoManagementTests(page, results, executionId),
      'dashboard-workflows': () => this.runDashboardTests(page, results, executionId),
      'multi-tenant-workflows': () => this.runMultiTenantTests(page, results, executionId, config.tenantId),
      'mobile-responsive': () => this.runMobileResponsiveTests(page, results, executionId),
      'accessibility': () => this.runAccessibilityTests(page, results, executionId),
      'performance': () => this.runPerformanceTests(page, results, executionId),
    };

    const testRunner = testSuiteMap[testSuite];
    if (!testRunner) {
      throw new Error(`Unknown test suite: ${testSuite}`);
    }

    await testRunner();

    results.summary.duration = Date.now() - startTime;
    results.passed = results.summary.failed === 0;

    return results;
  }

  private async runAuthWorkflowTests(
    page: Page,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    const tests = [
      {
        name: 'Login with valid credentials',
        action: async () => {
          await page.goto('/login');
          await page.fill('[data-testid="email"]', 'test@example.com');
          await page.fill('[data-testid="password"]', 'password123');
          await page.click('[data-testid="login-button"]');
          await page.waitForSelector('[data-testid="dashboard"]', { timeout: 5000 });
        },
      },
      {
        name: 'Login with invalid credentials',
        action: async () => {
          await page.goto('/login');
          await page.fill('[data-testid="email"]', 'invalid@example.com');
          await page.fill('[data-testid="password"]', 'wrongpassword');
          await page.click('[data-testid="login-button"]');
          await page.waitForSelector('[data-testid="error-message"]', { timeout: 5000 });
          const errorText = await page.textContent('[data-testid="error-message"]');
          if (!errorText?.includes('Invalid credentials')) {
            throw new Error('Expected error message not found');
          }
        },
      },
      {
        name: 'Logout functionality',
        action: async () => {
          // Ensure we're logged in first
          await page.goto('/login');
          await page.fill('[data-testid="email"]', 'test@example.com');
          await page.fill('[data-testid="password"]', 'password123');
          await page.click('[data-testid="login-button"]');
          await page.waitForSelector('[data-testid="dashboard"]');
          
          // Now test logout
          await page.click('[data-testid="user-menu"]');
          await page.click('[data-testid="logout-button"]');
          await page.waitForSelector('[data-testid="login-form"]', { timeout: 5000 });
        },
      },
      {
        name: 'Password reset flow',
        action: async () => {
          await page.goto('/login');
          await page.click('[data-testid="forgot-password-link"]');
          await page.fill('[data-testid="reset-email"]', 'test@example.com');
          await page.click('[data-testid="send-reset-button"]');
          await page.waitForSelector('[data-testid="reset-success-message"]', { timeout: 5000 });
        },
      },
    ];

    for (const test of tests) {
      results.summary.total++;
      const testStart = Date.now();
      
      try {
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          `Running test: ${test.name}`
        );
        
        await test.action();
        
        results.summary.passed++;
        results.details.tests.push({
          name: test.name,
          status: 'passed',
          duration: Date.now() - testStart,
        });
        
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          `✓ ${test.name} (${Date.now() - testStart}ms)`
        );
      } catch (error) {
        results.summary.failed++;
        results.details.tests.push({
          name: test.name,
          status: 'failed',
          duration: Date.now() - testStart,
          error: error.message,
        });
        
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.ERROR,
          `✗ ${test.name}: ${error.message}`
        );

        // Take screenshot on failure
        const screenshotPath = path.join(
          'test-artifacts',
          executionId,
          `${test.name.replace(/\s+/g, '-')}-failure.png`
        );
        await page.screenshot({ path: screenshotPath });
        await this.testExecutionService.addArtifact(executionId, {
          type: ArtifactType.SCREENSHOT,
          name: `${test.name}-failure.png`,
          path: screenshotPath,
          size: (await fs.stat(screenshotPath)).size,
          mimeType: 'image/png',
        });
      }
    }
  }

  private async runAccessControlTests(
    page: Page,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    const tests = [
      {
        name: 'Grant door access',
        action: async () => {
          await page.goto('/access-control/doors');
          await page.click('[data-testid="door-1"]');
          await page.click('[data-testid="grant-access-button"]');
          await page.fill('[data-testid="user-search"]', 'John Doe');
          await page.click('[data-testid="user-result-1"]');
          await page.click('[data-testid="confirm-grant-button"]');
          await page.waitForSelector('[data-testid="success-toast"]');
        },
      },
      {
        name: 'Revoke door access',
        action: async () => {
          await page.goto('/access-control/doors/1/users');
          await page.click('[data-testid="user-access-1"]');
          await page.click('[data-testid="revoke-access-button"]');
          await page.click('[data-testid="confirm-revoke-button"]');
          await page.waitForSelector('[data-testid="success-toast"]');
        },
      },
      {
        name: 'Create access schedule',
        action: async () => {
          await page.goto('/access-control/schedules');
          await page.click('[data-testid="create-schedule-button"]');
          await page.fill('[data-testid="schedule-name"]', 'Business Hours');
          await page.selectOption('[data-testid="schedule-type"]', 'weekly');
          await page.click('[data-testid="save-schedule-button"]');
          await page.waitForSelector('[data-testid="success-toast"]');
        },
      },
    ];

    for (const test of tests) {
      await this.runSingleTest(page, test, results, executionId);
    }
  }

  private async runVideoManagementTests(
    page: Page,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    const tests = [
      {
        name: 'View live camera feed',
        action: async () => {
          await page.goto('/video/cameras');
          await page.click('[data-testid="camera-1"]');
          await page.waitForSelector('[data-testid="video-player"]');
          // Wait for video to load
          await page.waitForFunction(
            () => {
              const video = document.querySelector('video');
              return video && video.readyState >= 3;
            },
            { timeout: 10000 }
          );
        },
      },
      {
        name: 'Switch camera views',
        action: async () => {
          await page.goto('/video/cameras');
          await page.click('[data-testid="grid-view-button"]');
          await page.waitForSelector('[data-testid="camera-grid"]');
          await page.click('[data-testid="single-view-button"]');
          await page.waitForSelector('[data-testid="camera-single"]');
        },
      },
      {
        name: 'Export video clip',
        action: async () => {
          await page.goto('/video/recordings');
          await page.click('[data-testid="recording-1"]');
          await page.click('[data-testid="export-button"]');
          await page.fill('[data-testid="export-start-time"]', '00:00:00');
          await page.fill('[data-testid="export-end-time"]', '00:01:00');
          await page.click('[data-testid="confirm-export-button"]');
          await page.waitForSelector('[data-testid="export-success"]');
        },
      },
    ];

    for (const test of tests) {
      await this.runSingleTest(page, test, results, executionId);
    }
  }

  private async runDashboardTests(
    page: Page,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    const tests = [
      {
        name: 'Dashboard loads with all widgets',
        action: async () => {
          await page.goto('/dashboard');
          await page.waitForSelector('[data-testid="alert-widget"]');
          await page.waitForSelector('[data-testid="camera-widget"]');
          await page.waitForSelector('[data-testid="access-widget"]');
          await page.waitForSelector('[data-testid="visitor-widget"]');
        },
      },
      {
        name: 'Real-time updates work',
        action: async () => {
          await page.goto('/dashboard');
          const initialCount = await page.textContent('[data-testid="alert-count"]');
          // Simulate new alert
          await page.evaluate(() => {
            window.postMessage({ type: 'new-alert', data: { id: 1 } }, '*');
          });
          await page.waitForFunction(
            (initial) => {
              const current = document.querySelector('[data-testid="alert-count"]')?.textContent;
              return current !== initial;
            },
            initialCount,
            { timeout: 5000 }
          );
        },
      },
    ];

    for (const test of tests) {
      await this.runSingleTest(page, test, results, executionId);
    }
  }

  private async runMultiTenantTests(
    page: Page,
    results: TestResults,
    executionId: string,
    tenantId?: string
  ): Promise<void> {
    const tests = [
      {
        name: 'Tenant data isolation',
        action: async () => {
          // Login as tenant A
          await page.goto('/login');
          await page.fill('[data-testid="email"]', 'tenanta@example.com');
          await page.fill('[data-testid="password"]', 'password123');
          await page.click('[data-testid="login-button"]');
          await page.waitForSelector('[data-testid="dashboard"]');
          
          // Check tenant A data
          const tenantAData = await page.textContent('[data-testid="tenant-name"]');
          if (tenantAData !== 'Tenant A') {
            throw new Error('Wrong tenant data displayed');
          }
          
          // Logout and login as tenant B
          await page.click('[data-testid="user-menu"]');
          await page.click('[data-testid="logout-button"]');
          await page.waitForSelector('[data-testid="login-form"]');
          
          await page.fill('[data-testid="email"]', 'tenantb@example.com');
          await page.fill('[data-testid="password"]', 'password123');
          await page.click('[data-testid="login-button"]');
          await page.waitForSelector('[data-testid="dashboard"]');
          
          // Check tenant B data
          const tenantBData = await page.textContent('[data-testid="tenant-name"]');
          if (tenantBData !== 'Tenant B') {
            throw new Error('Wrong tenant data displayed');
          }
        },
      },
    ];

    for (const test of tests) {
      await this.runSingleTest(page, test, results, executionId);
    }
  }

  private async runMobileResponsiveTests(
    page: Page,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    const viewports = [
      { width: 375, height: 667, name: 'iPhone SE' },
      { width: 390, height: 844, name: 'iPhone 12' },
      { width: 768, height: 1024, name: 'iPad' },
      { width: 1920, height: 1080, name: 'Desktop' },
    ];

    for (const viewport of viewports) {
      const test = {
        name: `Responsive layout - ${viewport.name}`,
        action: async () => {
          await page.setViewportSize(viewport);
          await page.goto('/dashboard');
          
          // Check if mobile menu is visible on small screens
          if (viewport.width < 768) {
            await page.waitForSelector('[data-testid="mobile-menu-button"]');
            await page.click('[data-testid="mobile-menu-button"]');
            await page.waitForSelector('[data-testid="mobile-menu"]');
          } else {
            // Desktop navigation should be visible
            await page.waitForSelector('[data-testid="desktop-nav"]');
          }
          
          // Take screenshot for visual verification
          const screenshotPath = path.join(
            'test-artifacts',
            executionId,
            `responsive-${viewport.name}.png`
          );
          await page.screenshot({ path: screenshotPath, fullPage: true });
          await this.testExecutionService.addArtifact(executionId, {
            type: ArtifactType.SCREENSHOT,
            name: `responsive-${viewport.name}.png`,
            path: screenshotPath,
            size: (await fs.stat(screenshotPath)).size,
            mimeType: 'image/png',
          });
        },
      };
      
      await this.runSingleTest(page, test, results, executionId);
    }
  }

  private async runAccessibilityTests(
    page: Page,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    const { injectAxe, checkA11y, getViolations } = await import('axe-playwright');
    
    const tests = [
      {
        name: 'Dashboard accessibility',
        action: async () => {
          await page.goto('/dashboard');
          await injectAxe(page);
          const violations = await getViolations(page);
          if (violations.length > 0) {
            throw new Error(`Found ${violations.length} accessibility violations`);
          }
        },
      },
      {
        name: 'Keyboard navigation',
        action: async () => {
          await page.goto('/dashboard');
          // Tab through interactive elements
          for (let i = 0; i < 10; i++) {
            await page.keyboard.press('Tab');
          }
          // Check if focus is visible
          const focusedElement = await page.evaluate(() => {
            const el = document.activeElement;
            return el?.tagName.toLowerCase();
          });
          if (!focusedElement) {
            throw new Error('No element has focus');
          }
        },
      },
    ];

    for (const test of tests) {
      await this.runSingleTest(page, test, results, executionId);
    }
  }

  private async runPerformanceTests(
    page: Page,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    const tests = [
      {
        name: 'Page load performance',
        action: async () => {
          const startTime = Date.now();
          await page.goto('/dashboard', { waitUntil: 'networkidle' });
          const loadTime = Date.now() - startTime;
          
          if (loadTime > 3000) {
            throw new Error(`Page load took ${loadTime}ms (expected < 3000ms)`);
          }
          
          // Collect performance metrics
          const metrics = await page.evaluate(() => {
            const perf = window.performance.getEntriesByType('navigation')[0] as any;
            return {
              domContentLoaded: perf.domContentLoadedEventEnd - perf.domContentLoadedEventStart,
              loadComplete: perf.loadEventEnd - perf.loadEventStart,
              firstPaint: perf.fetchStart,
              firstContentfulPaint: perf.responseEnd - perf.requestStart,
            };
          });
          
          await this.testExecutionService.addLog(
            executionId,
            LogLevel.INFO,
            'Performance metrics',
            metrics
          );
        },
      },
    ];

    for (const test of tests) {
      await this.runSingleTest(page, test, results, executionId);
    }
  }

  private async runSingleTest(
    page: Page,
    test: { name: string; action: () => Promise<void> },
    results: TestResults,
    executionId: string
  ): Promise<void> {
    results.summary.total++;
    const testStart = Date.now();
    
    try {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Running test: ${test.name}`
      );
      
      await test.action();
      
      results.summary.passed++;
      results.details.tests.push({
        name: test.name,
        status: 'passed',
        duration: Date.now() - testStart,
      });
      
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `✓ ${test.name} (${Date.now() - testStart}ms)`
      );
    } catch (error) {
      results.summary.failed++;
      results.details.tests.push({
        name: test.name,
        status: 'failed',
        duration: Date.now() - testStart,
        error: error.message,
      });
      
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `✗ ${test.name}: ${error.message}`,
        { stack: error.stack }
      );

      // Take screenshot on failure
      try {
        const screenshotPath = path.join(
          'test-artifacts',
          executionId,
          `${test.name.replace(/\s+/g, '-')}-failure.png`
        );
        await page.screenshot({ path: screenshotPath });
        await this.testExecutionService.addArtifact(executionId, {
          type: ArtifactType.SCREENSHOT,
          name: `${test.name}-failure.png`,
          path: screenshotPath,
          size: (await fs.stat(screenshotPath)).size,
          mimeType: 'image/png',
        });
      } catch (screenshotError) {
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.WARN,
          `Failed to capture screenshot: ${screenshotError.message}`
        );
      }
    }
  }

  private async launchBrowser(
    browserName: 'chromium' | 'firefox' | 'webkit',
    headless: boolean
  ): Promise<Browser> {
    const browserMap = {
      chromium: chromium,
      firefox: firefox,
      webkit: webkit,
    };

    const browserType = browserMap[browserName];
    return await browserType.launch({
      headless,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
  }

  async cleanup(): Promise<void> {
    for (const [name, browser] of this.browsers) {
      try {
        await browser.close();
      } catch (error) {
        console.error(`Failed to close browser ${name}:`, error);
      }
    }
    this.browsers.clear();
  }
}