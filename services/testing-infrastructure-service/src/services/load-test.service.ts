import { spawn } from 'child_process';
import { TestExecutionService } from './test-execution.service';
import {
  TestConfig,
  TestStatus,
  LogLevel,
  ArtifactType,
  TestResults,
  LoadTestConfig,
  LoadTestStage,
  PerformanceMetrics,
  ResponseTimeMetrics,
  ThroughputMetrics,
  ErrorMetrics,
} from '../types';
import * as path from 'path';
import * as fs from 'fs/promises';
import * as yaml from 'js-yaml';

export class LoadTestService {
  constructor(private testExecutionService: TestExecutionService) {}

  async runLoadTests(config: LoadTestConfig & TestConfig, executionId: string): Promise<void> {
    await this.testExecutionService.updateExecution(executionId, {
      status: TestStatus.RUNNING,
    });

    try {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Starting load tests: ${config.description}`
      );

      // Generate k6 script
      const scriptPath = await this.generateK6Script(config, executionId);
      
      // Run k6 test
      const results = await this.executeK6Test(scriptPath, config, executionId);

      // Check thresholds
      const passed = this.checkThresholds(results, config.thresholds);

      await this.testExecutionService.updateExecution(executionId, {
        status: passed ? TestStatus.COMPLETED : TestStatus.FAILED,
        endTime: new Date(),
        results,
      });

    } catch (error) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `Load test failed: ${error.message}`,
        { error: error.stack }
      );

      await this.testExecutionService.updateExecution(executionId, {
        status: TestStatus.FAILED,
        endTime: new Date(),
        error: error.message,
      });
    }
  }

  private async generateK6Script(
    config: LoadTestConfig & TestConfig,
    executionId: string
  ): Promise<string> {
    const { scenario, vusers, duration, rampUp, rampDown, stages } = config;
    const baseUrl = this.getEnvironmentUrl(config.environment);

    const script = `
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTime = new Trend('response_time');
const successRate = new Rate('success_rate');

export const options = {
  ${stages ? this.generateStages(stages) : this.generateDefaultStages(vusers, duration, rampUp, rampDown)}
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'],
    'http_req_failed': ['rate<0.01'],
    'errors': ['rate<0.05'],
    'success_rate': ['rate>0.95'],
  },
};

const BASE_URL = '${baseUrl}';

// Test scenarios
${this.generateScenarios(scenario)}

export default function() {
  const scenario = scenarios[__VU % scenarios.length];
  scenario();
}

export function handleSummary(data) {
  return {
    'summary.json': JSON.stringify(data),
    'summary.html': htmlReport(data),
  };
}

function htmlReport(data) {
  return \`
    <html>
      <head><title>Load Test Report</title></head>
      <body>
        <h1>Load Test Results</h1>
        <h2>Summary</h2>
        <p>Duration: \${data.state.testRunDurationMs}ms</p>
        <p>VUs: \${data.metrics.vus.values.max}</p>
        <p>Requests: \${data.metrics.http_reqs.values.count}</p>
        <p>Success Rate: \${(data.metrics.success_rate.values.rate * 100).toFixed(2)}%</p>
        <h2>Response Times</h2>
        <ul>
          <li>Min: \${data.metrics.http_req_duration.values.min}ms</li>
          <li>Max: \${data.metrics.http_req_duration.values.max}ms</li>
          <li>Avg: \${data.metrics.http_req_duration.values.avg}ms</li>
          <li>P95: \${data.metrics.http_req_duration.values['p(95)']}ms</li>
          <li>P99: \${data.metrics.http_req_duration.values['p(99)']}ms</li>
        </ul>
      </body>
    </html>
  \`;
}
`;

    const scriptPath = path.join('test-artifacts', executionId, 'k6-script.js');
    await fs.mkdir(path.dirname(scriptPath), { recursive: true });
    await fs.writeFile(scriptPath, script);

    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.LOG,
      name: 'k6-script.js',
      path: scriptPath,
      size: Buffer.byteLength(script),
      mimeType: 'application/javascript',
    });

    return scriptPath;
  }

  private generateStages(stages: LoadTestStage[]): string {
    const stageConfigs = stages.map(stage => 
      `{ duration: '${stage.duration}s', target: ${stage.target} }`
    ).join(',\n    ');

    return `stages: [
    ${stageConfigs}
  ],`;
  }

  private generateDefaultStages(vusers: number, duration: number, rampUp: number, rampDown: number): string {
    return `stages: [
    { duration: '${rampUp}s', target: ${vusers} },
    { duration: '${duration}s', target: ${vusers} },
    { duration: '${rampDown}s', target: 0 }
  ],`;
  }

  private generateScenarios(scenario: string): string {
    const scenarioMap: Record<string, string> = {
      'full-platform': `
const scenarios = [
  // Access Control scenario
  function accessControlTest() {
    const doorId = Math.floor(Math.random() * 1000) + 1;
    const payload = JSON.stringify({
      cardId: \`CARD-\${__VU}-\${__ITER}\`,
      timestamp: new Date().toISOString(),
    });
    
    const res = http.post(\`\${BASE_URL}/api/access-control/doors/\${doorId}/access\`, payload, {
      headers: { 'Content-Type': 'application/json' },
    });
    
    check(res, {
      'access control status is 200': (r) => r.status === 200,
      'access control response time < 200ms': (r) => r.timings.duration < 200,
    });
    
    errorRate.add(res.status !== 200);
    successRate.add(res.status === 200);
    responseTime.add(res.timings.duration);
    
    sleep(Math.random() * 2 + 1);
  },
  
  // Video Streaming scenario
  function videoStreamTest() {
    const cameraId = Math.floor(Math.random() * 100) + 1;
    const res = http.get(\`\${BASE_URL}/api/video/streams/\${cameraId}/live\`, {
      headers: { 'Accept': 'application/json' },
    });
    
    check(res, {
      'video stream status is 200': (r) => r.status === 200,
      'video stream response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    errorRate.add(res.status !== 200);
    successRate.add(res.status === 200);
    responseTime.add(res.timings.duration);
    
    sleep(Math.random() * 5 + 5);
  },
  
  // Dashboard API scenario
  function dashboardTest() {
    const res = http.batch([
      ['GET', \`\${BASE_URL}/api/dashboard/status\`],
      ['GET', \`\${BASE_URL}/api/events/recent?limit=10\`],
      ['GET', \`\${BASE_URL}/api/alerts/active\`],
    ]);
    
    res.forEach((r) => {
      check(r, {
        'dashboard request status is 200': (r) => r.status === 200,
      });
      errorRate.add(r.status !== 200);
      successRate.add(r.status === 200);
      responseTime.add(r.timings.duration);
    });
    
    sleep(Math.random() * 10 + 10);
  },
];`,
      'api-stress': `
const scenarios = [
  function apiStressTest() {
    const endpoints = [
      '/api/users',
      '/api/organizations',
      '/api/sites',
      '/api/zones',
      '/api/devices',
    ];
    
    const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
    const res = http.get(\`\${BASE_URL}\${endpoint}\`, {
      headers: { 'Accept': 'application/json' },
    });
    
    check(res, {
      'API status is 200': (r) => r.status === 200,
      'API response time < 100ms': (r) => r.timings.duration < 100,
    });
    
    errorRate.add(res.status !== 200);
    successRate.add(res.status === 200);
    responseTime.add(res.timings.duration);
    
    sleep(0.1);
  },
];`,
      'database-intensive': `
const scenarios = [
  function databaseIntensiveTest() {
    // Complex query scenario
    const res = http.get(\`\${BASE_URL}/api/reports/analytics?from=2024-01-01&to=2024-12-31&groupBy=day\`, {
      headers: { 'Accept': 'application/json' },
    });
    
    check(res, {
      'Complex query status is 200': (r) => r.status === 200,
      'Complex query response time < 2000ms': (r) => r.timings.duration < 2000,
    });
    
    errorRate.add(res.status !== 200);
    successRate.add(res.status === 200);
    responseTime.add(res.timings.duration);
    
    sleep(Math.random() * 3 + 2);
  },
];`,
    };

    return scenarioMap[scenario] || scenarioMap['full-platform'];
  }

  private async executeK6Test(
    scriptPath: string,
    config: LoadTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    const outputPath = path.join('test-artifacts', executionId, 'k6-output.json');
    
    return new Promise((resolve, reject) => {
      const k6Process = spawn('k6', [
        'run',
        scriptPath,
        '--out', `json=${outputPath}`,
        '--summary-export', path.join('test-artifacts', executionId, 'summary.json'),
      ]);

      let output = '';
      
      k6Process.stdout.on('data', (data) => {
        const message = data.toString();
        output += message;
        this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          message.trim()
        );
      });

      k6Process.stderr.on('data', (data) => {
        const message = data.toString();
        this.testExecutionService.addLog(
          executionId,
          LogLevel.WARN,
          message.trim()
        );
      });

      k6Process.on('close', async (code) => {
        if (code !== 0) {
          reject(new Error(`k6 exited with code ${code}`));
          return;
        }

        try {
          // Read summary data
          const summaryPath = path.join('test-artifacts', executionId, 'summary.json');
          const summaryData = JSON.parse(await fs.readFile(summaryPath, 'utf8'));

          // Process results
          const results = this.processK6Results(summaryData);

          // Save artifacts
          await this.testExecutionService.addArtifact(executionId, {
            type: ArtifactType.REPORT,
            name: 'k6-summary.json',
            path: summaryPath,
            size: (await fs.stat(summaryPath)).size,
            mimeType: 'application/json',
          });

          const htmlPath = path.join('test-artifacts', executionId, 'summary.html');
          if (await this.fileExists(htmlPath)) {
            await this.testExecutionService.addArtifact(executionId, {
              type: ArtifactType.REPORT,
              name: 'k6-report.html',
              path: htmlPath,
              size: (await fs.stat(htmlPath)).size,
              mimeType: 'text/html',
            });
          }

          resolve(results);
        } catch (error) {
          reject(error);
        }
      });
    });
  }

  private processK6Results(summaryData: any): TestResults {
    const metrics = summaryData.metrics;
    
    const responseTimeMetrics: ResponseTimeMetrics = {
      min: metrics.http_req_duration?.values?.min || 0,
      max: metrics.http_req_duration?.values?.max || 0,
      mean: metrics.http_req_duration?.values?.avg || 0,
      median: metrics.http_req_duration?.values?.med || 0,
      p95: metrics.http_req_duration?.values?.['p(95)'] || 0,
      p99: metrics.http_req_duration?.values?.['p(99)'] || 0,
    };

    const throughputMetrics: ThroughputMetrics = {
      requestsPerSecond: metrics.http_reqs?.values?.rate || 0,
      bytesPerSecond: metrics.data_received?.values?.rate || 0,
      successRate: metrics.success_rate?.values?.rate || 0,
    };

    const errorMetrics: ErrorMetrics = {
      total: metrics.http_req_failed?.values?.count || 0,
      byType: {},
      byCode: this.extractErrorsByCode(summaryData),
    };

    const performanceMetrics: PerformanceMetrics = {
      responseTime: responseTimeMetrics,
      throughput: throughputMetrics,
      resources: {
        cpu: { usage: 0, load: [] },
        memory: { used: 0, total: 0, percentage: 0 },
        network: { bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0, errors: 0 },
      },
      errors: errorMetrics,
    };

    const passed = this.evaluateK6Results(summaryData);

    return {
      passed,
      summary: {
        total: metrics.http_reqs?.values?.count || 0,
        passed: metrics.checks?.values?.passes || 0,
        failed: metrics.checks?.values?.fails || 0,
        skipped: 0,
        duration: summaryData.state?.testRunDurationMs || 0,
      },
      details: {
        vusMax: metrics.vus?.values?.max || 0,
        iterations: metrics.iterations?.values?.count || 0,
        dataReceived: metrics.data_received?.values?.count || 0,
        dataSent: metrics.data_sent?.values?.count || 0,
      },
      performance: performanceMetrics,
    };
  }

  private evaluateK6Results(summaryData: any): boolean {
    // Check if all thresholds passed
    const thresholds = summaryData.thresholds || {};
    for (const [metric, result] of Object.entries(thresholds)) {
      if (!(result as any).ok) {
        return false;
      }
    }
    return true;
  }

  private extractErrorsByCode(summaryData: any): Record<string, number> {
    const errorsByCode: Record<string, number> = {};
    
    // k6 doesn't provide detailed error breakdown by default
    // This would need custom metrics in the k6 script
    if (summaryData.metrics.http_req_failed?.values?.count > 0) {
      errorsByCode['unknown'] = summaryData.metrics.http_req_failed.values.count;
    }
    
    return errorsByCode;
  }

  private checkThresholds(
    results: TestResults,
    thresholds?: LoadTestConfig['thresholds']
  ): boolean {
    if (!thresholds || !results.performance) return results.passed;

    let passed = true;

    if (thresholds.responseTime && results.performance.responseTime.p95 > thresholds.responseTime) {
      passed = false;
    }

    if (thresholds.errorRate) {
      const errorRate = results.performance.errors.total / (results.summary.total || 1);
      if (errorRate > thresholds.errorRate / 100) {
        passed = false;
      }
    }

    if (thresholds.throughput && results.performance.throughput.requestsPerSecond < thresholds.throughput) {
      passed = false;
    }

    return passed;
  }

  private getEnvironmentUrl(environment: string): string {
    const urls: Record<string, string> = {
      local: 'http://localhost:3000',
      dev: 'https://dev-api.sparc.com',
      test: 'https://test-api.sparc.com',
      staging: 'https://staging-api.sparc.com',
      production: 'https://api.sparc.com',
    };
    return urls[environment] || urls.test;
  }

  private async fileExists(path: string): Promise<boolean> {
    try {
      await fs.access(path);
      return true;
    } catch {
      return false;
    }
  }

  async runArtilleryTest(config: any, executionId: string): Promise<void> {
    // Alternative implementation using Artillery
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running Artillery load test'
    );

    const configPath = await this.generateArtilleryConfig(config, executionId);
    
    return new Promise((resolve, reject) => {
      const artillery = spawn('artillery', [
        'run',
        configPath,
        '--output',
        path.join('test-artifacts', executionId, 'artillery-report.json'),
      ]);

      artillery.stdout.on('data', (data) => {
        this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          data.toString().trim()
        );
      });

      artillery.stderr.on('data', (data) => {
        this.testExecutionService.addLog(
          executionId,
          LogLevel.ERROR,
          data.toString().trim()
        );
      });

      artillery.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Artillery exited with code ${code}`));
        }
      });
    });
  }

  private async generateArtilleryConfig(config: any, executionId: string): Promise<string> {
    const artilleryConfig = {
      config: {
        target: this.getEnvironmentUrl(config.environment),
        phases: [
          {
            duration: config.rampUp,
            arrivalRate: 1,
            rampTo: Math.ceil(config.vusers / 10),
          },
          {
            duration: config.duration,
            arrivalRate: Math.ceil(config.vusers / 10),
          },
        ],
        defaults: {
          headers: {
            'Content-Type': 'application/json',
          },
        },
      },
      scenarios: this.generateArtilleryScenarios(config.scenario),
    };

    const configPath = path.join('test-artifacts', executionId, 'artillery-config.yml');
    await fs.writeFile(configPath, yaml.dump(artilleryConfig));
    
    return configPath;
  }

  private generateArtilleryScenarios(scenario: string): any[] {
    // Artillery scenario generation logic
    return [
      {
        name: 'API Load Test',
        weight: 100,
        flow: [
          {
            get: {
              url: '/api/health',
            },
          },
          {
            think: 1,
          },
        ],
      },
    ];
  }

  async cleanup(): Promise<void> {
    // Cleanup any running k6 processes
    try {
      await spawn('pkill', ['-f', 'k6']);
    } catch {
      // Ignore errors
    }
  }
}