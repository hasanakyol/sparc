import { MicroserviceBase } from '@sparc/shared/patterns/service-base';
import { testRoutes } from './routes/tests';
import { executionRoutes } from './routes/executions';
import { metricsRoutes } from './routes/metrics';
import { reportRoutes } from './routes/reports';
import { cicdRoutes } from './routes/cicd';
import { TestExecutionService } from './services/test-execution.service';
import { TestReportService } from './services/test-report.service';
import { TestMetricsService } from './services/test-metrics.service';
import { E2ETestService } from './services/e2e-test.service';
import { LoadTestService } from './services/load-test.service';
import { SecurityTestService } from './services/security-test.service';
import { ChaosTestService } from './services/chaos-test.service';
import { VisualTestService } from './services/visual-test.service';
import { ContractTestService } from './services/contract-test.service';
import { PerformanceTestService } from './services/performance-test.service';

export class TestingInfrastructureService extends MicroserviceBase {
  private testExecutionService: TestExecutionService;
  private testReportService: TestReportService;
  private testMetricsService: TestMetricsService;
  private e2eTestService: E2ETestService;
  private loadTestService: LoadTestService;
  private securityTestService: SecurityTestService;
  private chaosTestService: ChaosTestService;
  private visualTestService: VisualTestService;
  private contractTestService: ContractTestService;
  private performanceTestService: PerformanceTestService;

  constructor(config: any) {
    super(config);
    
    // Initialize services
    this.testExecutionService = new TestExecutionService(this.prisma, this.redis);
    this.testReportService = new TestReportService(this.prisma, this.redis);
    this.testMetricsService = new TestMetricsService(this.prisma, this.redis);
    
    // Initialize test-specific services
    this.e2eTestService = new E2ETestService(this.testExecutionService);
    this.loadTestService = new LoadTestService(this.testExecutionService);
    this.securityTestService = new SecurityTestService(this.testExecutionService);
    this.chaosTestService = new ChaosTestService(this.testExecutionService);
    this.visualTestService = new VisualTestService(this.testExecutionService);
    this.contractTestService = new ContractTestService(this.testExecutionService);
    this.performanceTestService = new PerformanceTestService(this.testExecutionService);
  }

  public setupRoutes(): void {
    // Test execution routes
    this.app.route('/api/tests', testRoutes({
      e2eTestService: this.e2eTestService,
      loadTestService: this.loadTestService,
      securityTestService: this.securityTestService,
      chaosTestService: this.chaosTestService,
      visualTestService: this.visualTestService,
      contractTestService: this.contractTestService,
      performanceTestService: this.performanceTestService,
    }));

    // Execution management routes
    this.app.route('/api/executions', executionRoutes({
      testExecutionService: this.testExecutionService,
    }));

    // Metrics routes
    this.app.route('/api/metrics', metricsRoutes({
      testMetricsService: this.testMetricsService,
    }));

    // Report routes
    this.app.route('/api/reports', reportRoutes({
      testReportService: this.testReportService,
    }));

    // CI/CD integration routes
    this.app.route('/api/cicd', cicdRoutes({
      testExecutionService: this.testExecutionService,
      e2eTestService: this.e2eTestService,
      loadTestService: this.loadTestService,
      securityTestService: this.securityTestService,
    }));
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};

    // Check Playwright installation
    try {
      const { chromium } = await import('playwright');
      await chromium.launch({ headless: true });
      checks.playwright = true;
    } catch {
      checks.playwright = false;
    }

    // Check k6 availability
    try {
      const { exec } = await import('child_process');
      await new Promise((resolve, reject) => {
        exec('k6 version', (error) => {
          if (error) reject(error);
          else resolve(true);
        });
      });
      checks.k6 = true;
    } catch {
      checks.k6 = false;
    }

    // Check test storage
    try {
      const testCount = await this.prisma.testExecution.count();
      checks.testStorage = true;
    } catch {
      checks.testStorage = false;
    }

    return checks;
  }

  protected async getMetrics(): Promise<string> {
    return this.testMetricsService.getPrometheusMetrics();
  }

  protected async cleanup(): Promise<void> {
    // Cancel any running tests
    await this.testExecutionService.cancelAllRunningTests();
    
    // Close test framework connections
    await this.e2eTestService.cleanup();
    await this.loadTestService.cleanup();
    await this.securityTestService.cleanup();
  }
}