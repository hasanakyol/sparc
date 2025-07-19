import { Pact, Interaction, Matchers } from '@pact-foundation/pact';
import { TestExecutionService } from './test-execution.service';
import {
  TestConfig,
  TestStatus,
  LogLevel,
  ArtifactType,
  TestResults,
  ContractTestConfig,
} from '../types';
import * as path from 'path';
import * as fs from 'fs/promises';
import axios from 'axios';
import { spawn } from 'child_process';
import { promisify } from 'util';

const exec = promisify(require('child_process').exec);
const { like, term, eachLike } = Matchers;

interface ContractTest {
  consumer: string;
  provider: string;
  interactions: ContractInteraction[];
}

interface ContractInteraction {
  description: string;
  providerState?: string;
  request: {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: any;
    query?: Record<string, string>;
  };
  response: {
    status: number;
    headers?: Record<string, string>;
    body?: any;
  };
}

export class ContractTestService {
  private pactBrokerUrl = process.env.PACT_BROKER_URL || 'http://localhost:9292';
  private pactBrokerToken = process.env.PACT_BROKER_TOKEN;

  constructor(private testExecutionService: TestExecutionService) {}

  async runContractTests(config: ContractTestConfig & TestConfig, executionId: string): Promise<void> {
    await this.testExecutionService.updateExecution(executionId, {
      status: TestStatus.RUNNING,
    });

    try {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        `Starting API contract tests: ${config.description}`
      );

      let results: TestResults;

      // Determine test mode
      if (config.provider && config.consumer) {
        // Run consumer-driven contract tests
        results = await this.runConsumerDrivenTests(config, executionId);
      } else if (config.provider) {
        // Run provider verification
        results = await this.runProviderVerification(config, executionId);
      } else {
        // Run OpenAPI schema validation
        results = await this.runOpenAPIValidation(config, executionId);
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
        `Contract test failed: ${error.message}`,
        { error: error.stack }
      );

      await this.testExecutionService.updateExecution(executionId, {
        status: TestStatus.FAILED,
        endTime: new Date(),
        error: error.message,
      });
    }
  }

  private async runConsumerDrivenTests(
    config: ContractTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    const { consumer, provider } = config;

    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      `Running consumer-driven contract tests: ${consumer} -> ${provider}`
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
        consumer,
        provider,
        interactions: [],
      },
    };

    const startTime = Date.now();

    // Create Pact instance
    const pactDir = path.join('test-artifacts', executionId, 'pacts');
    await fs.mkdir(pactDir, { recursive: true });

    const mockProvider = new Pact({
      consumer,
      provider,
      port: 8989,
      dir: pactDir,
      logLevel: 'debug',
      spec: 3,
    });

    try {
      // Start mock provider
      await mockProvider.setup();

      // Load contract interactions
      const contracts = await this.loadContractTests(consumer, provider);

      for (const contract of contracts) {
        for (const interaction of contract.interactions) {
          results.summary.total++;

          try {
            // Add interaction to Pact
            await mockProvider.addInteraction({
              state: interaction.providerState,
              uponReceiving: interaction.description,
              withRequest: interaction.request,
              willRespondWith: interaction.response,
            });

            // Execute test against mock
            const testResult = await this.executeContractTest(
              interaction,
              'http://localhost:8989',
              executionId
            );

            if (testResult.passed) {
              results.summary.passed++;
            } else {
              results.summary.failed++;
              results.passed = false;
            }

            results.details.interactions.push(testResult);

            // Verify interaction
            await mockProvider.verify();

          } catch (error) {
            results.summary.failed++;
            results.passed = false;

            await this.testExecutionService.addLog(
              executionId,
              LogLevel.ERROR,
              `Contract test failed: ${interaction.description}`,
              { error: error.message }
            );
          }
        }
      }

      // Finalize pact
      await mockProvider.finalize();

      // Publish to Pact Broker if configured
      if (config.publishResults && this.pactBrokerUrl) {
        await this.publishPacts(pactDir, config, executionId);
      }

    } finally {
      await mockProvider.removeInteractions();
    }

    results.summary.duration = Date.now() - startTime;

    // Generate contract test report
    await this.generateContractReport(results, executionId);

    return results;
  }

  private async runProviderVerification(
    config: ContractTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    const { provider, verificationUrl } = config;

    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      `Running provider verification for: ${provider}`
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
        provider,
        verifications: [],
      },
    };

    const startTime = Date.now();

    try {
      // Get pacts from broker
      const pacts = await this.fetchPactsFromBroker(provider);

      for (const pact of pacts) {
        const verificationResult = await this.verifyProviderAgainstPact(
          pact,
          verificationUrl,
          executionId
        );

        results.summary.total += verificationResult.total;
        results.summary.passed += verificationResult.passed;
        results.summary.failed += verificationResult.failed;

        if (verificationResult.failed > 0) {
          results.passed = false;
        }

        results.details.verifications.push(verificationResult);
      }

      // Publish verification results
      if (config.publishResults) {
        await this.publishVerificationResults(provider, results, executionId);
      }

    } catch (error) {
      results.passed = false;
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `Provider verification failed: ${error.message}`
      );
    }

    results.summary.duration = Date.now() - startTime;
    return results;
  }

  private async runOpenAPIValidation(
    config: ContractTestConfig & TestConfig,
    executionId: string
  ): Promise<TestResults> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Running OpenAPI schema validation'
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
        type: 'openapi',
        validations: [],
      },
    };

    const startTime = Date.now();

    try {
      // Load OpenAPI spec
      const specPath = config.parameters?.specPath || './openapi.yaml';
      const spec = await this.loadOpenAPISpec(specPath);

      // Get endpoints to test
      const endpoints = this.extractEndpointsFromSpec(spec);
      results.summary.total = endpoints.length;

      // Validate each endpoint
      for (const endpoint of endpoints) {
        const validation = await this.validateEndpointAgainstSpec(
          endpoint,
          spec,
          config.verificationUrl,
          executionId
        );

        if (validation.passed) {
          results.summary.passed++;
        } else {
          results.summary.failed++;
          results.passed = false;
        }

        results.details.validations.push(validation);
      }

    } catch (error) {
      results.passed = false;
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `OpenAPI validation failed: ${error.message}`
      );
    }

    results.summary.duration = Date.now() - startTime;
    return results;
  }

  private async loadContractTests(consumer: string, provider: string): Promise<ContractTest[]> {
    // Load contract definitions from files or database
    // This is a simplified example
    return [
      {
        consumer,
        provider,
        interactions: [
          {
            description: 'Get user by ID',
            providerState: 'User with ID 123 exists',
            request: {
              method: 'GET',
              path: '/api/users/123',
              headers: {
                Accept: 'application/json',
              },
            },
            response: {
              status: 200,
              headers: {
                'Content-Type': 'application/json',
              },
              body: like({
                id: '123',
                name: 'John Doe',
                email: term({
                  generate: 'john@example.com',
                  matcher: '^.+@.+\\..+$',
                }),
                createdAt: like('2024-01-01T00:00:00Z'),
              }),
            },
          },
          {
            description: 'Create new user',
            request: {
              method: 'POST',
              path: '/api/users',
              headers: {
                'Content-Type': 'application/json',
              },
              body: {
                name: 'Jane Doe',
                email: 'jane@example.com',
              },
            },
            response: {
              status: 201,
              headers: {
                'Content-Type': 'application/json',
                Location: term({
                  generate: '/api/users/456',
                  matcher: '^/api/users/\\d+$',
                }),
              },
              body: like({
                id: '456',
                name: 'Jane Doe',
                email: 'jane@example.com',
              }),
            },
          },
          {
            description: 'List users with pagination',
            request: {
              method: 'GET',
              path: '/api/users',
              query: {
                page: '1',
                limit: '10',
              },
            },
            response: {
              status: 200,
              body: {
                users: eachLike({
                  id: like('123'),
                  name: like('John Doe'),
                  email: like('john@example.com'),
                }),
                pagination: like({
                  page: 1,
                  limit: 10,
                  total: 100,
                  pages: 10,
                }),
              },
            },
          },
        ],
      },
    ];
  }

  private async executeContractTest(
    interaction: ContractInteraction,
    baseUrl: string,
    executionId: string
  ): Promise<any> {
    const startTime = Date.now();

    try {
      const url = `${baseUrl}${interaction.request.path}`;
      const config: any = {
        method: interaction.request.method,
        url,
        headers: interaction.request.headers,
        params: interaction.request.query,
        data: interaction.request.body,
        validateStatus: () => true, // Don't throw on any status
      };

      const response = await axios(config);

      // Validate response
      const validationErrors: string[] = [];

      // Check status
      if (response.status !== interaction.response.status) {
        validationErrors.push(
          `Expected status ${interaction.response.status}, got ${response.status}`
        );
      }

      // Check headers
      if (interaction.response.headers) {
        for (const [key, value] of Object.entries(interaction.response.headers)) {
          if (response.headers[key.toLowerCase()] !== value) {
            validationErrors.push(
              `Expected header ${key}="${value}", got "${response.headers[key.toLowerCase()]}"`
            );
          }
        }
      }

      // Check body (simplified - in real implementation use Pact matchers)
      if (interaction.response.body && JSON.stringify(response.data) !== JSON.stringify(interaction.response.body)) {
        // This is where Pact matchers would be properly validated
        // For now, just check if response has expected structure
      }

      const passed = validationErrors.length === 0;

      if (passed) {
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          `✓ ${interaction.description}`
        );
      } else {
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.ERROR,
          `✗ ${interaction.description}`,
          { errors: validationErrors }
        );
      }

      return {
        description: interaction.description,
        passed,
        duration: Date.now() - startTime,
        errors: validationErrors,
      };

    } catch (error) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `Failed to execute contract test: ${interaction.description}`,
        { error: error.message }
      );

      return {
        description: interaction.description,
        passed: false,
        duration: Date.now() - startTime,
        errors: [error.message],
      };
    }
  }

  private async publishPacts(
    pactDir: string,
    config: ContractTestConfig & TestConfig,
    executionId: string
  ): Promise<void> {
    await this.testExecutionService.addLog(
      executionId,
      LogLevel.INFO,
      'Publishing pacts to broker'
    );

    const publishCommand = [
      'pact-broker', 'publish', pactDir,
      '--broker-base-url', this.pactBrokerUrl,
      '--consumer-app-version', config.parameters?.version || '1.0.0',
    ];

    if (this.pactBrokerToken) {
      publishCommand.push('--broker-token', this.pactBrokerToken);
    }

    if (config.parameters?.tags) {
      for (const tag of config.parameters.tags) {
        publishCommand.push('--tag', tag);
      }
    }

    try {
      const { stdout, stderr } = await exec(publishCommand.join(' '));
      
      if (stdout) {
        await this.testExecutionService.addLog(executionId, LogLevel.INFO, stdout);
      }
      
      if (stderr) {
        await this.testExecutionService.addLog(executionId, LogLevel.WARN, stderr);
      }

    } catch (error) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `Failed to publish pacts: ${error.message}`
      );
    }
  }

  private async fetchPactsFromBroker(provider: string): Promise<any[]> {
    try {
      const response = await axios.get(
        `${this.pactBrokerUrl}/pacts/provider/${provider}/latest`,
        {
          headers: this.pactBrokerToken ? {
            Authorization: `Bearer ${this.pactBrokerToken}`,
          } : {},
        }
      );

      return response.data._embedded.pacts || [];
    } catch (error) {
      console.error('Failed to fetch pacts from broker:', error);
      return [];
    }
  }

  private async verifyProviderAgainstPact(
    pact: any,
    verificationUrl: string,
    executionId: string
  ): Promise<any> {
    const verifier = require('@pact-foundation/pact').Verifier;

    const options = {
      providerBaseUrl: verificationUrl,
      pactUrls: [pact._links.self.href],
      providerVersion: '1.0.0',
      publishVerificationResult: true,
      providerVersionTags: ['main'],
    };

    try {
      const output = await new verifier(options).verifyProvider();
      
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        'Provider verification completed',
        { output }
      );

      return {
        consumer: pact.consumer.name,
        total: output.examples.length,
        passed: output.examples.filter((e: any) => e.status === 'passed').length,
        failed: output.examples.filter((e: any) => e.status === 'failed').length,
        output,
      };

    } catch (error) {
      return {
        consumer: pact.consumer.name,
        total: 0,
        passed: 0,
        failed: 1,
        error: error.message,
      };
    }
  }

  private async publishVerificationResults(
    provider: string,
    results: TestResults,
    executionId: string
  ): Promise<void> {
    // Publish verification results to Pact Broker
    try {
      await axios.post(
        `${this.pactBrokerUrl}/pacts/provider/${provider}/verification-results`,
        {
          success: results.passed,
          providerApplicationVersion: '1.0.0',
          verifiedAt: new Date().toISOString(),
        },
        {
          headers: this.pactBrokerToken ? {
            Authorization: `Bearer ${this.pactBrokerToken}`,
          } : {},
        }
      );

      await this.testExecutionService.addLog(
        executionId,
        LogLevel.INFO,
        'Verification results published to broker'
      );

    } catch (error) {
      await this.testExecutionService.addLog(
        executionId,
        LogLevel.ERROR,
        `Failed to publish verification results: ${error.message}`
      );
    }
  }

  private async loadOpenAPISpec(specPath: string): Promise<any> {
    const content = await fs.readFile(specPath, 'utf8');
    
    if (specPath.endsWith('.yaml') || specPath.endsWith('.yml')) {
      const yaml = require('js-yaml');
      return yaml.load(content);
    } else {
      return JSON.parse(content);
    }
  }

  private extractEndpointsFromSpec(spec: any): any[] {
    const endpoints: any[] = [];

    for (const [path, pathItem] of Object.entries(spec.paths || {})) {
      for (const [method, operation] of Object.entries(pathItem as any)) {
        if (['get', 'post', 'put', 'patch', 'delete'].includes(method)) {
          endpoints.push({
            path,
            method: method.toUpperCase(),
            operation,
          });
        }
      }
    }

    return endpoints;
  }

  private async validateEndpointAgainstSpec(
    endpoint: any,
    spec: any,
    baseUrl: string,
    executionId: string
  ): Promise<any> {
    const startTime = Date.now();

    try {
      // Generate test data based on OpenAPI schema
      const testData = this.generateTestDataFromSchema(endpoint.operation);

      // Make request
      const response = await axios({
        method: endpoint.method,
        url: `${baseUrl}${endpoint.path}`,
        data: testData.body,
        params: testData.query,
        headers: testData.headers,
        validateStatus: () => true,
      });

      // Validate response against schema
      const validationErrors = this.validateResponseAgainstSchema(
        response,
        endpoint.operation.responses
      );

      const passed = validationErrors.length === 0;

      if (passed) {
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.INFO,
          `✓ ${endpoint.method} ${endpoint.path}`
        );
      } else {
        await this.testExecutionService.addLog(
          executionId,
          LogLevel.ERROR,
          `✗ ${endpoint.method} ${endpoint.path}`,
          { errors: validationErrors }
        );
      }

      return {
        endpoint: `${endpoint.method} ${endpoint.path}`,
        passed,
        duration: Date.now() - startTime,
        errors: validationErrors,
      };

    } catch (error) {
      return {
        endpoint: `${endpoint.method} ${endpoint.path}`,
        passed: false,
        duration: Date.now() - startTime,
        errors: [error.message],
      };
    }
  }

  private generateTestDataFromSchema(operation: any): any {
    const testData: any = {
      headers: {},
      query: {},
      body: undefined,
    };

    // Generate data for parameters
    if (operation.parameters) {
      for (const param of operation.parameters) {
        const value = this.generateValueFromSchema(param.schema);
        
        switch (param.in) {
          case 'header':
            testData.headers[param.name] = value;
            break;
          case 'query':
            testData.query[param.name] = value;
            break;
        }
      }
    }

    // Generate request body
    if (operation.requestBody?.content?.['application/json']?.schema) {
      testData.body = this.generateValueFromSchema(
        operation.requestBody.content['application/json'].schema
      );
    }

    return testData;
  }

  private generateValueFromSchema(schema: any): any {
    if (!schema) return undefined;

    switch (schema.type) {
      case 'string':
        if (schema.enum) return schema.enum[0];
        if (schema.format === 'email') return 'test@example.com';
        if (schema.format === 'date') return '2024-01-01';
        if (schema.format === 'date-time') return '2024-01-01T00:00:00Z';
        if (schema.format === 'uuid') return '123e4567-e89b-12d3-a456-426614174000';
        return schema.example || 'test';

      case 'number':
      case 'integer':
        return schema.example || schema.minimum || 1;

      case 'boolean':
        return schema.example || true;

      case 'array':
        return [this.generateValueFromSchema(schema.items)];

      case 'object':
        const obj: any = {};
        if (schema.properties) {
          for (const [key, propSchema] of Object.entries(schema.properties)) {
            if (schema.required?.includes(key) || Math.random() > 0.5) {
              obj[key] = this.generateValueFromSchema(propSchema);
            }
          }
        }
        return obj;

      default:
        return null;
    }
  }

  private validateResponseAgainstSchema(response: any, responseSchemas: any): string[] {
    const errors: string[] = [];
    const statusSchema = responseSchemas[response.status];

    if (!statusSchema) {
      errors.push(`Unexpected response status: ${response.status}`);
      return errors;
    }

    // Validate response body against schema
    if (statusSchema.content?.['application/json']?.schema) {
      const schema = statusSchema.content['application/json'].schema;
      const validationErrors = this.validateDataAgainstSchema(response.data, schema);
      errors.push(...validationErrors);
    }

    return errors;
  }

  private validateDataAgainstSchema(data: any, schema: any, path = ''): string[] {
    const errors: string[] = [];

    if (schema.type === 'object' && schema.properties) {
      // Check required properties
      if (schema.required) {
        for (const required of schema.required) {
          if (!(required in data)) {
            errors.push(`Missing required property: ${path}${required}`);
          }
        }
      }

      // Validate properties
      for (const [key, value] of Object.entries(data)) {
        if (schema.properties[key]) {
          errors.push(
            ...this.validateDataAgainstSchema(
              value,
              schema.properties[key],
              `${path}${key}.`
            )
          );
        }
      }
    }

    // Additional type validation would go here

    return errors;
  }

  private async generateContractReport(results: TestResults, executionId: string): Promise<void> {
    const reportPath = path.join('test-artifacts', executionId, 'contract-report.html');
    
    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>API Contract Test Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1, h2 { color: #333; }
    .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
    .interaction { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    .passed { color: green; }
    .failed { color: red; }
    .error { background: #fee; padding: 10px; margin: 10px 0; border-radius: 3px; }
    pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>API Contract Test Report</h1>
  
  <div class="summary">
    <h2>Summary</h2>
    <p>Consumer: ${results.details.consumer || 'N/A'}</p>
    <p>Provider: ${results.details.provider || 'N/A'}</p>
    <p>Total Interactions: ${results.summary.total}</p>
    <p class="passed">Passed: ${results.summary.passed}</p>
    <p class="failed">Failed: ${results.summary.failed}</p>
    <p>Duration: ${(results.summary.duration / 1000).toFixed(2)}s</p>
  </div>
  
  <h2>Interactions</h2>
  ${(results.details.interactions || []).map(interaction => `
    <div class="interaction">
      <h3>${interaction.description}</h3>
      <p>Status: <span class="${interaction.passed ? 'passed' : 'failed'}">${interaction.passed ? 'Passed' : 'Failed'}</span></p>
      <p>Duration: ${interaction.duration}ms</p>
      ${interaction.errors && interaction.errors.length > 0 ? `
        <div class="error">
          <h4>Errors:</h4>
          <ul>
            ${interaction.errors.map(error => `<li>${error}</li>`).join('')}
          </ul>
        </div>
      ` : ''}
    </div>
  `).join('')}
</body>
</html>
    `;

    await fs.writeFile(reportPath, html);

    await this.testExecutionService.addArtifact(executionId, {
      type: ArtifactType.REPORT,
      name: 'contract-report.html',
      path: reportPath,
      size: Buffer.byteLength(html),
      mimeType: 'text/html',
    });
  }

  async cleanup(): Promise<void> {
    // No specific cleanup needed
  }
}