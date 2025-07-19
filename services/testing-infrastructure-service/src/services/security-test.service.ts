import { spawn } from 'child_process';
import { TestExecutionService } from './test-execution.service';
import {
  TestConfig,
  TestStatus,
  LogLevel,
  ArtifactType,
  TestResults,
  SecurityFindings,
  SecurityVulnerability,
  SecuritySeverity,
} from '../types';
import * as path from 'path';
import * as fs from 'fs/promises';
import axios from 'axios';

export interface SecurityTestConfig extends TestConfig {
  parameters: {
    target: string;
    scanType: 'baseline' | 'full' | 'api' | 'ajax';
    authMethod?: 'none' | 'basic' | 'bearer' | 'oauth';
    authCredentials?: any;
    excludeUrls?: string[];
    includeUrls?: string[];
    maxDepth?: number;
    maxChildren?: number;
    technologies?: string[];
  };
}

export class SecurityTestService {
  private zapApiUrl = 'http://localhost:8080';
  private zapApiKey = process.env.ZAP_API_KEY || '';

  constructor(private testExecutionService: TestExecutionService) {}

  async runSecurityTests(config: SecurityTestConfig, executionId: string): Promise<void> {
    await this.testExecutionService.updateExecution(executionId, {
      status: TestStatus.RUNNING,
    });

    try {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Starting security tests: ${config.description}`
      );

      // Check if ZAP is running
      const zapRunning = await this.checkZapStatus();
      if (!zapRunning) {
        await this.startZapDaemon(executionId);
      }

      // Run security scan
      const results = await this.runSecurityScan(config, executionId);

      await this.testExecutionService.updateExecution(executionId, {
        status: results.passed ? TestStatus.COMPLETED : TestStatus.FAILED,
        endTime: new Date(),
        results,
      });

    } catch (error) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `Security test failed: ${error.message}`,
        { error: error.stack }
      );

      await this.testExecutionService.updateExecution(executionId, {
        status: TestStatus.FAILED,
        endTime: new Date(),
        error: error.message,
      });
    }
  }

  private async checkZapStatus(): Promise<boolean> {
    try {
      const response = await axios.get(`${this.zapApiUrl}/JSON/core/view/version/`);
      return response.status === 200;
    } catch {
      return false;
    }
  }

  private async startZapDaemon(executionId: string): Promise<void> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Starting OWASP ZAP daemon...'
    );

    return new Promise((resolve, reject) => {
      const zap = spawn('zap.sh', [
        '-daemon',
        '-port', '8080',
        '-config', 'api.disablekey=true',
        '-config', 'api.addrs.addr.name=.*',
        '-config', 'api.addrs.addr.regex=true',
      ]);

      let started = false;

      zap.stdout.on('data', (data) => {
        const message = data.toString();
        this.testExecutionService.addLog(executionId, LogLevel.INFO, `ZAP: ${message.trim()}`);
        
        if (message.includes('ZAP is now listening') && !started) {
          started = true;
          setTimeout(resolve, 5000); // Give ZAP time to fully initialize
        }
      });

      zap.stderr.on('data', (data) => {
        this.testExecutionService.addLog(executionId, LogLevel.WARN, `ZAP Error: ${data.toString().trim()}`);
      });

      // Timeout after 60 seconds
      setTimeout(() => {
        if (!started) {
          reject(new Error('ZAP daemon startup timeout'));
        }
      }, 60000);
    });
  }

  private async runSecurityScan(
    config: SecurityTestConfig,
    executionId: string
  ): Promise<TestResults> {
    const { target, scanType, authMethod, authCredentials, excludeUrls, includeUrls } = config.parameters;

    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      `Configuring security scan for ${target}`
    );

    // Configure authentication if needed
    if (authMethod && authMethod !== 'none') {
      await this.configureAuthentication(authMethod, authCredentials, executionId);
    }

    // Configure scan scope
    await this.configureScanScope(target, excludeUrls, includeUrls, executionId);

    // Start spider scan
    const spiderScanId = await this.startSpiderScan(target, executionId);
    await this.waitForSpiderCompletion(spiderScanId, executionId);

    // Start active scan based on type
    let ascanId: string | null = null;
    if (scanType === 'full' || scanType === 'ajax') {
      ascanId = await this.startActiveScan(target, scanType, executionId);
      await this.waitForActiveScanCompletion(ascanId, executionId);
    }

    // Get scan results
    const alerts = await this.getAlerts(target);
    const findings = this.processAlerts(alerts);

    // Generate reports
    await this.generateReports(executionId);

    // Determine if test passed
    const passed = findings.criticalCount === 0 && findings.highCount < 5;

    return {
      passed,
      summary: {
        total: findings.totalFindings,
        passed: passed ? 1 : 0,
        failed: passed ? 0 : 1,
        skipped: 0,
        duration: 0,
      },
      details: {
        scanType,
        target,
        spiderScanId,
        activeScanId: ascanId,
      },
      security: findings,
    };
  }

  private async configureAuthentication(
    method: string,
    credentials: any,
    executionId: string
  ): Promise<void> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      `Configuring ${method} authentication`
    );

    switch (method) {
      case 'basic':
        await axios.get(`${this.zapApiUrl}/JSON/authentication/action/setAuthenticationMethod/`, {
          params: {
            contextId: '1',
            authMethodName: 'httpAuthentication',
            authMethodConfigParams: `username=${credentials.username}&password=${credentials.password}`,
          },
        });
        break;

      case 'bearer':
        await axios.get(`${this.zapApiUrl}/JSON/script/action/load/`, {
          params: {
            scriptName: 'BearerAuth',
            scriptType: 'httpsender',
            scriptEngine: 'ECMAScript : Graal.js',
            fileName: '',
            scriptDescription: 'Add Bearer token to requests',
          },
        });
        break;

      case 'oauth':
        // OAuth configuration would be more complex
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.WARN,
          'OAuth authentication not fully implemented'
        );
        break;
    }
  }

  private async configureScanScope(
    target: string,
    excludeUrls?: string[],
    includeUrls?: string[],
    executionId: string
  ): Promise<void> {
    // Create a new context
    const contextName = `scan-${executionId}`;
    await axios.get(`${this.zapApiUrl}/JSON/context/action/newContext/`, {
      params: { contextName },
    });

    // Include target in scope
    await axios.get(`${this.zapApiUrl}/JSON/context/action/includeInContext/`, {
      params: {
        contextName,
        regex: `${target}.*`,
      },
    });

    // Add include URLs
    if (includeUrls) {
      for (const url of includeUrls) {
        await axios.get(`${this.zapApiUrl}/JSON/context/action/includeInContext/`, {
          params: {
            contextName,
            regex: url,
          },
        });
      }
    }

    // Add exclude URLs
    if (excludeUrls) {
      for (const url of excludeUrls) {
        await axios.get(`${this.zapApiUrl}/JSON/context/action/excludeFromContext/`, {
          params: {
            contextName,
            regex: url,
          },
        });
      }
    }
  }

  private async startSpiderScan(target: string, executionId: string): Promise<string> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Starting spider scan to discover attack surface'
    );

    const response = await axios.get(`${this.zapApiUrl}/JSON/spider/action/scan/`, {
      params: {
        url: target,
        maxChildren: '0',
        recurse: 'true',
        subtreeOnly: 'false',
      },
    });

    return response.data.scan;
  }

  private async waitForSpiderCompletion(scanId: string, executionId: string): Promise<void> {
    let progress = 0;
    
    while (progress < 100) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      const response = await axios.get(`${this.zapApiUrl}/JSON/spider/view/status/`, {
        params: { scanId },
      });
      
      progress = parseInt(response.data.status);
      
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Spider scan progress: ${progress}%`
      );
    }
  }

  private async startActiveScan(
    target: string,
    scanType: string,
    executionId: string
  ): Promise<string> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      `Starting ${scanType} active security scan`
    );

    const params: any = {
      url: target,
      recurse: 'true',
      inScopeOnly: 'true',
    };

    if (scanType === 'ajax') {
      params.scanPolicyName = 'AJAX Spider Policy';
    }

    const response = await axios.get(`${this.zapApiUrl}/JSON/ascan/action/scan/`, { params });
    return response.data.scan;
  }

  private async waitForActiveScanCompletion(scanId: string, executionId: string): Promise<void> {
    let progress = 0;
    
    while (progress < 100) {
      await new Promise(resolve => setTimeout(resolve, 10000));
      
      const response = await axios.get(`${this.zapApiUrl}/JSON/ascan/view/status/`, {
        params: { scanId },
      });
      
      progress = parseInt(response.data.status);
      
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Active scan progress: ${progress}%`
      );
    }
  }

  private async getAlerts(target: string): Promise<any[]> {
    const response = await axios.get(`${this.zapApiUrl}/JSON/core/view/alerts/`, {
      params: {
        baseurl: target,
        start: '0',
        count: '10000',
      },
    });

    return response.data.alerts || [];
  }

  private processAlerts(alerts: any[]): SecurityFindings {
    const vulnerabilities: SecurityVulnerability[] = [];
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;

    for (const alert of alerts) {
      const severity = this.mapZapRiskToSeverity(alert.risk);
      
      switch (severity) {
        case SecuritySeverity.CRITICAL:
          criticalCount++;
          break;
        case SecuritySeverity.HIGH:
          highCount++;
          break;
        case SecuritySeverity.MEDIUM:
          mediumCount++;
          break;
        case SecuritySeverity.LOW:
          lowCount++;
          break;
        case SecuritySeverity.INFO:
          infoCount++;
          break;
      }

      vulnerabilities.push({
        id: alert.alertRef,
        title: alert.name,
        severity,
        type: alert.wascid ? `WASC-${alert.wascid}` : 'Unknown',
        description: alert.description,
        remediation: alert.solution,
        cvss: this.calculateCvss(alert),
        cwe: alert.cweid ? `CWE-${alert.cweid}` : undefined,
        owasp: this.mapToOwasp(alert),
        affectedComponent: alert.url,
        evidence: alert.evidence,
      });
    }

    return {
      vulnerabilities,
      totalFindings: vulnerabilities.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
    };
  }

  private mapZapRiskToSeverity(risk: string): SecuritySeverity {
    switch (risk.toLowerCase()) {
      case 'critical':
        return SecuritySeverity.CRITICAL;
      case 'high':
        return SecuritySeverity.HIGH;
      case 'medium':
        return SecuritySeverity.MEDIUM;
      case 'low':
        return SecuritySeverity.LOW;
      default:
        return SecuritySeverity.INFO;
    }
  }

  private calculateCvss(alert: any): number {
    // Simplified CVSS calculation based on ZAP risk
    const riskMap: Record<string, number> = {
      critical: 9.5,
      high: 7.5,
      medium: 5.0,
      low: 3.0,
      informational: 0.0,
    };
    
    return riskMap[alert.risk.toLowerCase()] || 0.0;
  }

  private mapToOwasp(alert: any): string | undefined {
    // Map common vulnerabilities to OWASP Top 10
    const owaspMap: Record<string, string> = {
      '79': 'A03:2021 - Injection',
      '89': 'A03:2021 - Injection',
      '90': 'A03:2021 - Injection',
      '22': 'A01:2021 - Broken Access Control',
      '352': 'A01:2021 - Broken Access Control',
      '287': 'A07:2021 - Identification and Authentication Failures',
      '798': 'A04:2021 - Insecure Design',
      '311': 'A02:2021 - Cryptographic Failures',
      '327': 'A02:2021 - Cryptographic Failures',
    };

    return alert.cweid ? owaspMap[alert.cweid] : undefined;
  }

  private async generateReports(executionId: string): Promise<void> {
    const artifactsDir = path.join('test-artifacts', executionId);
    await fs.mkdir(artifactsDir, { recursive: true });

    // Generate HTML report
    const htmlReport = await axios.get(`${this.zapApiUrl}/OTHER/core/other/htmlreport/`);
    const htmlPath = path.join(artifactsDir, 'security-report.html');
    await fs.writeFile(htmlPath, htmlReport.data);
    
    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.REPORT,
      name: 'security-report.html',
      path: htmlPath,
      size: Buffer.byteLength(htmlReport.data),
      mimeType: 'text/html',
    });

    // Generate JSON report
    const jsonReport = await axios.get(`${this.zapApiUrl}/JSON/core/view/alerts/`);
    const jsonPath = path.join(artifactsDir, 'security-findings.json');
    await fs.writeFile(jsonPath, JSON.stringify(jsonReport.data, null, 2));
    
    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.REPORT,
      name: 'security-findings.json',
      path: jsonPath,
      size: Buffer.byteLength(JSON.stringify(jsonReport.data)),
      mimeType: 'application/json',
    });

    // Generate XML report
    const xmlReport = await axios.get(`${this.zapApiUrl}/OTHER/core/other/xmlreport/`);
    const xmlPath = path.join(artifactsDir, 'security-report.xml');
    await fs.writeFile(xmlPath, xmlReport.data);
    
    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.REPORT,
      name: 'security-report.xml',
      path: xmlPath,
      size: Buffer.byteLength(xmlReport.data),
      mimeType: 'application/xml',
    });
  }

  async runBurpSuiteScan(config: SecurityTestConfig, executionId: string): Promise<void> {
    // Alternative implementation using Burp Suite Enterprise Edition API
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running Burp Suite security scan'
    );

    // Implementation would depend on Burp Suite Enterprise Edition API
  }

  async runNucleiScan(config: SecurityTestConfig, executionId: string): Promise<void> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running Nuclei template-based security scan'
    );

    const templatePath = path.join(__dirname, '../../nuclei-templates');
    const outputPath = path.join('test-artifacts', executionId, 'nuclei-results.json');

    return new Promise((resolve, reject) => {
      const nuclei = spawn('nuclei', [
        '-u', config.parameters.target,
        '-t', templatePath,
        '-severity', 'critical,high,medium',
        '-json',
        '-o', outputPath,
      ]);

      nuclei.stdout.on('data', (data) => {
        this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          data.toString().trim()
        );
      });

      nuclei.stderr.on('data', (data) => {
        this.testExecutionService.addLog(
          executionId,
          LogLevel.WARN,
          data.toString().trim()
        );
      });

      nuclei.on('close', async (code) => {
        if (code === 0) {
          await this.testExecutionService.addArtifact(executionId, {
            type: ArtifactType.REPORT,
            name: 'nuclei-results.json',
            path: outputPath,
            size: (await fs.stat(outputPath)).size,
            mimeType: 'application/json',
          });
          resolve();
        } else {
          reject(new Error(`Nuclei exited with code ${code}`));
        }
      });
    });
  }

  async cleanup(): Promise<void> {
    // Stop ZAP daemon
    try {
      await axios.get(`${this.zapApiUrl}/JSON/core/action/shutdown/`);
    } catch {
      // Ignore errors
    }
  }
}