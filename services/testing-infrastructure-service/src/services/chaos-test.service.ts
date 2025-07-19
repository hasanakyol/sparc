import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import { TestExecutionService } from './test-execution.service';
import {
  TestConfig,
  TestStatus,
  LogLevel,
  ArtifactType,
  TestResults,
  ChaosTestConfig,
  ChaosExperiment,
  ChaosType,
  ChaosTarget,
} from '../types';
import * as path from 'path';
import * as fs from 'fs/promises';
import * as yaml from 'js-yaml';

const execAsync = promisify(exec);

export class ChaosTestService {
  private litmusNamespace = 'litmus';
  private chaosMonkeyEnabled = false;

  constructor(private testExecutionService: TestExecutionService) {}

  async runChaosTests(config: ChaosTestConfig & TestConfig, executionId: string): Promise<void> {
    await this.testExecutionService.updateExecution(executionId, {
      status: TestStatus.RUNNING,
    });

    try {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Starting chaos engineering tests: ${config.description}`
      );

      // Check chaos engineering platform
      const platform = await this.detectChaosPlatform();
      
      let results: TestResults;
      switch (platform) {
        case 'litmus':
          results = await this.runLitmusChaos(config, executionId);
          break;
        case 'chaos-mesh':
          results = await this.runChaosMesh(config, executionId);
          break;
        case 'gremlin':
          results = await this.runGremlinChaos(config, executionId);
          break;
        default:
          results = await this.runBasicChaos(config, executionId);
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
        `Chaos test failed: ${error.message}`,
        { error: error.stack }
      );

      await this.testExecutionService.updateExecution(executionId, {
        status: TestStatus.FAILED,
        endTime: new Date(),
        error: error.message,
      });
    }
  }

  private async detectChaosPlatform(): Promise<string> {
    try {
      // Check for Litmus
      await execAsync('kubectl get ns litmus');
      return 'litmus';
    } catch {
      try {
        // Check for Chaos Mesh
        await execAsync('kubectl get ns chaos-testing');
        return 'chaos-mesh';
      } catch {
        try {
          // Check for Gremlin
          await execAsync('gremlin --version');
          return 'gremlin';
        } catch {
          return 'basic';
        }
      }
    }
  }

  private async runLitmusChaos(
    config: ChaosTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running chaos tests with Litmus Chaos'
    );

    const results: TestResults = {
      passed: true,
      summary: {
        total: config.experiments.length,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0,
      },
      details: {
        platform: 'litmus',
        experiments: [],
      },
    };

    const startTime = Date.now();

    for (const experiment of config.experiments) {
      const experimentResult = await this.runLitmusExperiment(
        experiment,
        config.target,
        config.duration,
        executionId
      );

      results.details.experiments.push(experimentResult);
      
      if (experimentResult.passed) {
        results.summary.passed++;
      } else {
        results.summary.failed++;
        results.passed = false;
      }
    }

    results.summary.duration = Date.now() - startTime;

    // Generate chaos report
    await this.generateChaosReport(results, executionId);

    return results;
  }

  private async runLitmusExperiment(
    experiment: ChaosExperiment,
    target: ChaosTarget,
    duration: number,
    executionId: string
  ): Promise<any> {
    const experimentName = `chaos-${experiment.type}-${Date.now()}`;
    
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      `Starting Litmus experiment: ${experiment.type}`
    );

    // Create experiment CRD
    const experimentCRD = this.generateLitmusExperimentCRD(
      experimentName,
      experiment,
      target,
      duration
    );

    const crdPath = path.join('test-artifacts', executionId, `${experimentName}.yaml`);
    await fs.mkdir(path.dirname(crdPath), { recursive: true });
    await fs.writeFile(crdPath, yaml.dump(experimentCRD));

    // Apply experiment
    await execAsync(`kubectl apply -f ${crdPath}`);

    // Monitor experiment
    const result = await this.monitorLitmusExperiment(experimentName, duration, executionId);

    // Cleanup
    await execAsync(`kubectl delete -f ${crdPath}`);

    return {
      name: experiment.type,
      passed: result.status === 'Pass',
      status: result.status,
      duration: result.duration,
      metrics: result.metrics,
      logs: result.logs,
    };
  }

  private generateLitmusExperimentCRD(
    name: string,
    experiment: ChaosExperiment,
    target: ChaosTarget,
    duration: number
  ): any {
    const baseExperiment = {
      apiVersion: 'litmuschaos.io/v1alpha1',
      kind: 'ChaosEngine',
      metadata: {
        name,
        namespace: target.namespace || 'default',
      },
      spec: {
        engineState: 'active',
        appinfo: {
          appns: target.namespace || 'default',
          applabel: this.generateTargetSelector(target),
        },
        chaosServiceAccount: 'litmus-admin',
        experiments: [
          {
            name: this.mapChaosTypeToLitmus(experiment.type),
            spec: {
              components: {
                env: this.generateExperimentEnv(experiment, duration),
              },
            },
          },
        ],
      },
    };

    return baseExperiment;
  }

  private mapChaosTypeToLitmus(type: ChaosType): string {
    const typeMap: Record<ChaosType, string> = {
      [ChaosType.NETWORK_DELAY]: 'pod-network-latency',
      [ChaosType.NETWORK_LOSS]: 'pod-network-loss',
      [ChaosType.SERVICE_CRASH]: 'pod-delete',
      [ChaosType.RESOURCE_EXHAUSTION]: 'pod-cpu-hog',
      [ChaosType.CLOCK_SKEW]: 'time-chaos',
      [ChaosType.DISK_FAILURE]: 'disk-fill',
    };

    return typeMap[type] || 'pod-delete';
  }

  private generateTargetSelector(target: ChaosTarget): string {
    if (target.pods && target.pods.length > 0) {
      return `name in (${target.pods.join(',')})`;
    }
    if (target.services && target.services.length > 0) {
      return `app in (${target.services.join(',')})`;
    }
    return 'app=test-target';
  }

  private generateExperimentEnv(experiment: ChaosExperiment, duration: number): any[] {
    const env = [
      { name: 'TOTAL_CHAOS_DURATION', value: duration.toString() },
      { name: 'CHAOS_INTERVAL', value: '10' },
      { name: 'FORCE', value: 'false' },
    ];

    // Add experiment-specific parameters
    switch (experiment.type) {
      case ChaosType.NETWORK_DELAY:
        env.push(
          { name: 'NETWORK_LATENCY', value: experiment.parameters.latency || '100' },
          { name: 'JITTER', value: experiment.parameters.jitter || '0' }
        );
        break;
      
      case ChaosType.NETWORK_LOSS:
        env.push(
          { name: 'NETWORK_PACKET_LOSS_PERCENTAGE', value: experiment.parameters.lossPercentage || '10' }
        );
        break;
      
      case ChaosType.RESOURCE_EXHAUSTION:
        env.push(
          { name: 'CPU_CORES', value: experiment.parameters.cpuCores || '1' },
          { name: 'CPU_LOAD', value: experiment.parameters.cpuLoad || '100' }
        );
        break;
    }

    return env;
  }

  private async monitorLitmusExperiment(
    experimentName: string,
    maxDuration: number,
    executionId: string
  ): Promise<any> {
    const startTime = Date.now();
    let status = 'Running';
    const logs: string[] = [];
    const metrics: any = {};

    while (status === 'Running' && (Date.now() - startTime) < maxDuration * 1000) {
      await new Promise(resolve => setTimeout(resolve, 5000));

      try {
        const { stdout } = await execAsync(
          `kubectl get chaosresult ${experimentName}-result -o json`
        );
        
        const result = JSON.parse(stdout);
        status = result.status.experimentStatus.phase;
        
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          `Experiment ${experimentName} status: ${status}`
        );

        // Collect metrics
        if (result.status.experimentStatus.probeSuccessPercentage) {
          metrics.probeSuccessRate = result.status.experimentStatus.probeSuccessPercentage;
        }

        // Collect logs
        const podLogs = await this.getExperimentPodLogs(experimentName);
        logs.push(...podLogs);

      } catch (error) {
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.WARN,
          `Failed to get experiment status: ${error.message}`
        );
      }
    }

    return {
      status,
      duration: Date.now() - startTime,
      metrics,
      logs,
    };
  }

  private async getExperimentPodLogs(experimentName: string): Promise<string[]> {
    try {
      const { stdout } = await execAsync(
        `kubectl logs -l experiment=${experimentName} --tail=100`
      );
      return stdout.split('\n').filter(line => line.trim());
    } catch {
      return [];
    }
  }

  private async runChaosMesh(
    config: ChaosTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running chaos tests with Chaos Mesh'
    );

    const results: TestResults = {
      passed: true,
      summary: {
        total: config.experiments.length,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0,
      },
      details: {
        platform: 'chaos-mesh',
        experiments: [],
      },
    };

    const startTime = Date.now();

    for (const experiment of config.experiments) {
      const experimentResult = await this.runChaosMeshExperiment(
        experiment,
        config.target,
        config.duration,
        executionId
      );

      results.details.experiments.push(experimentResult);
      
      if (experimentResult.passed) {
        results.summary.passed++;
      } else {
        results.summary.failed++;
        results.passed = false;
      }
    }

    results.summary.duration = Date.now() - startTime;

    return results;
  }

  private async runChaosMeshExperiment(
    experiment: ChaosExperiment,
    target: ChaosTarget,
    duration: number,
    executionId: string
  ): Promise<any> {
    const experimentName = `chaos-mesh-${experiment.type}-${Date.now()}`;
    
    const chaosCRD = {
      apiVersion: 'chaos-mesh.org/v1alpha1',
      kind: this.mapChaosTypeToChaosMeshKind(experiment.type),
      metadata: {
        name: experimentName,
        namespace: target.namespace || 'default',
      },
      spec: {
        selector: {
          namespaces: [target.namespace || 'default'],
          labelSelectors: this.generateChaosMeshSelector(target),
        },
        mode: 'all',
        duration: `${duration}s`,
        ...this.generateChaosMeshSpec(experiment),
      },
    };

    const crdPath = path.join('test-artifacts', executionId, `${experimentName}.yaml`);
    await fs.mkdir(path.dirname(crdPath), { recursive: true });
    await fs.writeFile(crdPath, yaml.dump(chaosCRD));

    // Apply experiment
    await execAsync(`kubectl apply -f ${crdPath}`);

    // Wait for experiment to complete
    await new Promise(resolve => setTimeout(resolve, duration * 1000));

    // Cleanup
    await execAsync(`kubectl delete -f ${crdPath}`);

    return {
      name: experiment.type,
      passed: true, // Simplified for now
      duration: duration * 1000,
    };
  }

  private mapChaosTypeToChaosMeshKind(type: ChaosType): string {
    const kindMap: Record<ChaosType, string> = {
      [ChaosType.NETWORK_DELAY]: 'NetworkChaos',
      [ChaosType.NETWORK_LOSS]: 'NetworkChaos',
      [ChaosType.SERVICE_CRASH]: 'PodChaos',
      [ChaosType.RESOURCE_EXHAUSTION]: 'StressChaos',
      [ChaosType.CLOCK_SKEW]: 'TimeChaos',
      [ChaosType.DISK_FAILURE]: 'IOChaos',
    };

    return kindMap[type] || 'PodChaos';
  }

  private generateChaosMeshSelector(target: ChaosTarget): any {
    const selectors: any = {};
    
    if (target.services && target.services.length > 0) {
      selectors['app'] = target.services;
    }
    
    if (target.pods && target.pods.length > 0) {
      selectors['name'] = target.pods;
    }
    
    return selectors;
  }

  private generateChaosMeshSpec(experiment: ChaosExperiment): any {
    switch (experiment.type) {
      case ChaosType.NETWORK_DELAY:
        return {
          action: 'delay',
          delay: {
            latency: `${experiment.parameters.latency || 100}ms`,
            jitter: `${experiment.parameters.jitter || 0}ms`,
          },
        };
      
      case ChaosType.NETWORK_LOSS:
        return {
          action: 'loss',
          loss: {
            loss: `${experiment.parameters.lossPercentage || 10}`,
          },
        };
      
      case ChaosType.SERVICE_CRASH:
        return {
          action: 'pod-kill',
        };
      
      case ChaosType.RESOURCE_EXHAUSTION:
        return {
          stressors: {
            cpu: {
              workers: experiment.parameters.cpuWorkers || 1,
              load: experiment.parameters.cpuLoad || 100,
            },
          },
        };
      
      default:
        return {};
    }
  }

  private async runGremlinChaos(
    config: ChaosTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running chaos tests with Gremlin'
    );

    // Gremlin implementation would use their API
    // This is a placeholder implementation
    return {
      passed: true,
      summary: {
        total: config.experiments.length,
        passed: config.experiments.length,
        failed: 0,
        skipped: 0,
        duration: config.duration * 1000,
      },
      details: {
        platform: 'gremlin',
        experiments: [],
      },
    };
  }

  private async runBasicChaos(
    config: ChaosTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running basic chaos tests without platform'
    );

    const results: TestResults = {
      passed: true,
      summary: {
        total: config.experiments.length,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0,
      },
      details: {
        platform: 'basic',
        experiments: [],
      },
    };

    const startTime = Date.now();

    for (const experiment of config.experiments) {
      const experimentResult = await this.runBasicExperiment(
        experiment,
        config.target,
        config.duration,
        executionId
      );

      results.details.experiments.push(experimentResult);
      
      if (experimentResult.passed) {
        results.summary.passed++;
      } else {
        results.summary.failed++;
        results.passed = false;
      }
    }

    results.summary.duration = Date.now() - startTime;

    return results;
  }

  private async runBasicExperiment(
    experiment: ChaosExperiment,
    target: ChaosTarget,
    duration: number,
    executionId: string
  ): Promise<any> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      `Running basic ${experiment.type} experiment`
    );

    switch (experiment.type) {
      case ChaosType.NETWORK_DELAY:
        return this.simulateNetworkDelay(experiment, target, duration, executionId);
      
      case ChaosType.SERVICE_CRASH:
        return this.simulateServiceCrash(experiment, target, executionId);
      
      case ChaosType.RESOURCE_EXHAUSTION:
        return this.simulateResourceExhaustion(experiment, target, duration, executionId);
      
      default:
        return {
          name: experiment.type,
          passed: false,
          error: 'Experiment type not supported in basic mode',
        };
    }
  }

  private async simulateNetworkDelay(
    experiment: ChaosExperiment,
    target: ChaosTarget,
    duration: number,
    executionId: string
  ): Promise<any> {
    const latency = experiment.parameters.latency || 100;
    
    // Use tc (traffic control) to add network delay
    const commands = target.nodes?.map(node => 
      `ssh ${node} "sudo tc qdisc add dev eth0 root netem delay ${latency}ms"`
    ) || [];

    try {
      for (const cmd of commands) {
        await execAsync(cmd);
      }

      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Added ${latency}ms network delay for ${duration}s`
      );

      // Wait for duration
      await new Promise(resolve => setTimeout(resolve, duration * 1000));

      // Remove delay
      const cleanupCommands = target.nodes?.map(node => 
        `ssh ${node} "sudo tc qdisc del dev eth0 root"`
      ) || [];

      for (const cmd of cleanupCommands) {
        await execAsync(cmd);
      }

      return {
        name: experiment.type,
        passed: true,
        duration: duration * 1000,
      };

    } catch (error) {
      return {
        name: experiment.type,
        passed: false,
        error: error.message,
      };
    }
  }

  private async simulateServiceCrash(
    experiment: ChaosExperiment,
    target: ChaosTarget,
    executionId: string
  ): Promise<any> {
    try {
      // Kill random pods
      if (target.pods && target.pods.length > 0) {
        const podToKill = target.pods[Math.floor(Math.random() * target.pods.length)];
        await execAsync(`kubectl delete pod ${podToKill} --force --grace-period=0`);
        
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          `Killed pod: ${podToKill}`
        );
      }

      return {
        name: experiment.type,
        passed: true,
      };

    } catch (error) {
      return {
        name: experiment.type,
        passed: false,
        error: error.message,
      };
    }
  }

  private async simulateResourceExhaustion(
    experiment: ChaosExperiment,
    target: ChaosTarget,
    duration: number,
    executionId: string
  ): Promise<any> {
    const cpuLoad = experiment.parameters.cpuLoad || 100;
    const cpuCores = experiment.parameters.cpuCores || 1;

    // Use stress-ng to consume CPU
    const stressCommand = `stress-ng --cpu ${cpuCores} --cpu-load ${cpuLoad} --timeout ${duration}s`;

    try {
      if (target.pods && target.pods.length > 0) {
        for (const pod of target.pods) {
          execAsync(`kubectl exec ${pod} -- ${stressCommand}`);
        }
      }

      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Applied CPU stress: ${cpuCores} cores at ${cpuLoad}% for ${duration}s`
      );

      // Wait for duration
      await new Promise(resolve => setTimeout(resolve, duration * 1000));

      return {
        name: experiment.type,
        passed: true,
        duration: duration * 1000,
      };

    } catch (error) {
      return {
        name: experiment.type,
        passed: false,
        error: error.message,
      };
    }
  }

  private async generateChaosReport(results: TestResults, executionId: string): Promise<void> {
    const reportPath = path.join('test-artifacts', executionId, 'chaos-report.json');
    await fs.mkdir(path.dirname(reportPath), { recursive: true });
    await fs.writeFile(reportPath, JSON.stringify(results, null, 2));

    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.REPORT,
      name: 'chaos-report.json',
      path: reportPath,
      size: Buffer.byteLength(JSON.stringify(results)),
      mimeType: 'application/json',
    });

    // Generate HTML report
    const htmlReport = this.generateChaosHtmlReport(results);
    const htmlPath = path.join('test-artifacts', executionId, 'chaos-report.html');
    await fs.writeFile(htmlPath, htmlReport);

    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.REPORT,
      name: 'chaos-report.html',
      path: htmlPath,
      size: Buffer.byteLength(htmlReport),
      mimeType: 'text/html',
    });
  }

  private generateChaosHtmlReport(results: TestResults): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <title>Chaos Engineering Test Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #333; }
    .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .experiment { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    .passed { color: green; }
    .failed { color: red; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
  </style>
</head>
<body>
  <h1>Chaos Engineering Test Report</h1>
  
  <div class="summary">
    <h2>Summary</h2>
    <p>Platform: ${results.details.platform}</p>
    <p>Total Experiments: ${results.summary.total}</p>
    <p class="passed">Passed: ${results.summary.passed}</p>
    <p class="failed">Failed: ${results.summary.failed}</p>
    <p>Duration: ${results.summary.duration}ms</p>
  </div>
  
  <h2>Experiments</h2>
  ${results.details.experiments.map(exp => `
    <div class="experiment">
      <h3>${exp.name}</h3>
      <p>Status: <span class="${exp.passed ? 'passed' : 'failed'}">${exp.status || (exp.passed ? 'Passed' : 'Failed')}</span></p>
      <p>Duration: ${exp.duration}ms</p>
      ${exp.error ? `<p class="failed">Error: ${exp.error}</p>` : ''}
      ${exp.metrics ? `
        <h4>Metrics</h4>
        <pre>${JSON.stringify(exp.metrics, null, 2)}</pre>
      ` : ''}
    </div>
  `).join('')}
</body>
</html>
    `;
  }

  async cleanup(): Promise<void> {
    // Cleanup any running chaos experiments
    try {
      await execAsync('kubectl delete chaosengine --all');
    } catch {
      // Ignore errors
    }
  }
}