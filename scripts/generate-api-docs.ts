#!/usr/bin/env ts-node

import * as fs from 'fs/promises';
import * as path from 'path';
import { glob } from 'glob';
import fetch from 'node-fetch';
import chalk from 'chalk';
import ora from 'ora';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

interface ServiceInfo {
  name: string;
  path: string;
  port: number;
  hasOpenAPI: boolean;
  spec?: any;
}

interface GenerateDocsOptions {
  output?: string;
  format?: 'json' | 'yaml' | 'html';
  includePostman?: boolean;
  includeSdk?: boolean;
  startServices?: boolean;
}

// Service port mapping (you should extract this from service configs)
const SERVICE_PORTS: Record<string, number> = {
  'api-gateway': 3000,
  'auth-service': 3001,
  'tenant-service': 3002,
  'access-control-service': 3003,
  'video-management-service': 3004,
  'event-processing-service': 3005,
  'device-management-service': 3006,
  'analytics-service': 3007,
  'alert-service': 3008,
  'environmental-service': 3009,
  'visitor-management-service': 3010,
  'reporting-service': 3011,
  'api-documentation-service': 3012,
  'mobile-credential-service': 3013,
  'security-monitoring-service': 3014,
  'user-management-service': 3015
};

async function discoverServices(): Promise<ServiceInfo[]> {
  const spinner = ora('Discovering services...').start();
  
  try {
    const servicePaths = await glob('services/*/package.json');
    const services: ServiceInfo[] = [];

    for (const servicePath of servicePaths) {
      const serviceDir = path.dirname(servicePath);
      const serviceName = path.basename(serviceDir);
      
      // Check if service has OpenAPI endpoint in its routes
      const routeFiles = await glob(`${serviceDir}/src/routes/*.ts`);
      let hasOpenAPI = false;
      
      for (const routeFile of routeFiles) {
        const content = await fs.readFile(routeFile, 'utf-8');
        if (content.includes('openapi') || content.includes('OpenAPI') || content.includes('@hono/zod-openapi')) {
          hasOpenAPI = true;
          break;
        }
      }

      services.push({
        name: serviceName,
        path: serviceDir,
        port: SERVICE_PORTS[serviceName] || 3000,
        hasOpenAPI
      });
    }

    spinner.succeed(`Discovered ${services.length} services`);
    return services;
  } catch (error) {
    spinner.fail('Failed to discover services');
    throw error;
  }
}

async function fetchServiceSpec(service: ServiceInfo): Promise<any | null> {
  const maxRetries = 3;
  const retryDelay = 1000;

  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(`http://localhost:${service.port}/openapi.json`, {
        timeout: 5000
      });

      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
  }

  return null;
}

async function startService(service: ServiceInfo): Promise<void> {
  const spinner = ora(`Starting ${service.name}...`).start();
  
  try {
    // Check if service is already running
    try {
      const response = await fetch(`http://localhost:${service.port}/health`);
      if (response.ok) {
        spinner.info(`${service.name} already running`);
        return;
      }
    } catch {
      // Service not running, start it
    }

    // Start the service in the background
    exec(`cd ${service.path} && npm run dev`, {
      detached: true,
      stdio: 'ignore'
    }).unref();

    // Wait for service to be ready
    let ready = false;
    for (let i = 0; i < 30; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      try {
        const response = await fetch(`http://localhost:${service.port}/health`);
        if (response.ok) {
          ready = true;
          break;
        }
      } catch {
        // Service not ready yet
      }
    }

    if (ready) {
      spinner.succeed(`${service.name} started`);
    } else {
      spinner.fail(`${service.name} failed to start`);
    }
  } catch (error) {
    spinner.fail(`Failed to start ${service.name}`);
    console.error(error);
  }
}

async function generateUnifiedSpec(services: ServiceInfo[]): Promise<any> {
  const unifiedSpec = {
    openapi: '3.0.0',
    info: {
      title: 'SPARC Platform API',
      version: '1.0.0',
      description: 'Unified API specification for the SPARC security platform',
      contact: {
        name: 'SPARC Support',
        email: 'support@sparc.com',
        url: 'https://sparc.com/support'
      },
      license: {
        name: 'Proprietary',
        url: 'https://sparc.com/license'
      }
    },
    servers: [
      {
        url: 'https://api.sparc.com',
        description: 'Production API'
      },
      {
        url: 'https://staging-api.sparc.com',
        description: 'Staging API'
      },
      {
        url: 'http://localhost:3000',
        description: 'Local development'
      }
    ],
    paths: {},
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'JWT authentication token'
        },
        apiKey: {
          type: 'apiKey',
          in: 'header',
          name: 'X-API-Key',
          description: 'API key for service-to-service communication'
        }
      },
      responses: {},
      schemas: {},
      parameters: {}
    },
    tags: [],
    security: [
      { bearerAuth: [] }
    ]
  };

  // Aggregate specs from all services
  for (const service of services) {
    if (!service.spec) continue;

    // Add service tag
    unifiedSpec.tags.push({
      name: service.name,
      description: `${service.name} endpoints`,
      externalDocs: {
        description: `${service.name} documentation`,
        url: `https://docs.sparc.com/api/${service.name}`
      }
    });

    // Merge paths with service prefix
    if (service.spec.paths) {
      const servicePrefix = `/api/v1/${service.name.replace('-service', '')}`;
      
      for (const [path, pathItem] of Object.entries(service.spec.paths)) {
        // Skip health and OpenAPI endpoints
        if (path === '/health' || path === '/openapi.json') continue;
        
        const fullPath = path.startsWith('/') ? `${servicePrefix}${path}` : `${servicePrefix}/${path}`;
        unifiedSpec.paths[fullPath] = pathItem;

        // Update tags for operations
        for (const method of ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']) {
          if (pathItem[method]) {
            if (!pathItem[method].tags) {
              pathItem[method].tags = [];
            }
            if (!pathItem[method].tags.includes(service.name)) {
              pathItem[method].tags.push(service.name);
            }
          }
        }
      }
    }

    // Merge components
    if (service.spec.components) {
      // Merge schemas with service prefix to avoid conflicts
      if (service.spec.components.schemas) {
        for (const [name, schema] of Object.entries(service.spec.components.schemas)) {
          const prefixedName = `${service.name.replace('-service', '')}_${name}`;
          unifiedSpec.components.schemas[prefixedName] = schema;
        }
      }

      // Merge responses
      if (service.spec.components.responses) {
        Object.assign(unifiedSpec.components.responses, service.spec.components.responses);
      }

      // Merge parameters
      if (service.spec.components.parameters) {
        Object.assign(unifiedSpec.components.parameters, service.spec.components.parameters);
      }
    }
  }

  // Sort tags alphabetically
  unifiedSpec.tags.sort((a, b) => a.name.localeCompare(b.name));

  return unifiedSpec;
}

async function generatePostmanCollection(spec: any): Promise<any> {
  const collection = {
    info: {
      name: spec.info.title,
      description: spec.info.description,
      version: spec.info.version,
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
    },
    auth: {
      type: 'bearer',
      bearer: [
        {
          key: 'token',
          value: '{{access_token}}',
          type: 'string'
        }
      ]
    },
    variable: [
      {
        key: 'baseUrl',
        value: spec.servers[0].url,
        type: 'string'
      },
      {
        key: 'access_token',
        value: '',
        type: 'string'
      }
    ],
    item: []
  };

  // Group endpoints by tag
  const folders = new Map<string, any[]>();

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (typeof operation !== 'object' || !operation) continue;

      const tags = operation.tags || ['Other'];
      const tag = tags[0];

      if (!folders.has(tag)) {
        folders.set(tag, []);
      }

      const request = {
        name: operation.summary || `${method.toUpperCase()} ${path}`,
        request: {
          method: method.toUpperCase(),
          header: [],
          url: {
            raw: '{{baseUrl}}' + path,
            host: ['{{baseUrl}}'],
            path: path.split('/').filter(Boolean)
          },
          description: operation.description
        }
      };

      // Add request body if present
      if (operation.requestBody?.content?.['application/json']?.schema) {
        request.request.body = {
          mode: 'raw',
          raw: JSON.stringify(generateExampleFromSchema(operation.requestBody.content['application/json'].schema), null, 2),
          options: {
            raw: {
              language: 'json'
            }
          }
        };
        request.request.header.push({
          key: 'Content-Type',
          value: 'application/json'
        });
      }

      folders.get(tag).push(request);
    }
  }

  // Convert folders to collection items
  for (const [tag, requests] of folders) {
    collection.item.push({
      name: tag,
      item: requests
    });
  }

  return collection;
}

function generateExampleFromSchema(schema: any): any {
  if (!schema) return null;

  switch (schema.type) {
    case 'object':
      const obj: any = {};
      if (schema.properties) {
        for (const [key, prop] of Object.entries(schema.properties)) {
          obj[key] = generateExampleFromSchema(prop);
        }
      }
      return obj;

    case 'array':
      return [generateExampleFromSchema(schema.items)];

    case 'string':
      if (schema.example) return schema.example;
      if (schema.enum) return schema.enum[0];
      if (schema.format === 'date-time') return new Date().toISOString();
      if (schema.format === 'email') return 'user@example.com';
      if (schema.format === 'uuid') return '123e4567-e89b-12d3-a456-426614174000';
      return 'string';

    case 'number':
    case 'integer':
      if (schema.example) return schema.example;
      if (schema.minimum !== undefined) return schema.minimum;
      return 0;

    case 'boolean':
      if (schema.example !== undefined) return schema.example;
      return true;

    default:
      return null;
  }
}

async function registerWithDocumentationService(spec: any): Promise<void> {
  const spinner = ora('Registering with documentation service...').start();
  
  try {
    const response = await fetch('http://localhost:3012/api/v1/discovery/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        serviceName: 'unified-api',
        version: spec.info.version,
        specification: spec,
        healthEndpoint: '/health'
      })
    });

    if (response.ok) {
      spinner.succeed('Registered unified spec with documentation service');
    } else {
      spinner.fail('Failed to register with documentation service');
    }
  } catch (error) {
    spinner.fail('Documentation service not available');
  }
}

async function generateApiDocs(options: GenerateDocsOptions = {}) {
  console.log(chalk.bold.blue('\n🚀 SPARC API Documentation Generator\n'));

  const {
    output = 'docs/api',
    format = 'json',
    includePostman = true,
    includeSdk = false,
    startServices = false
  } = options;

  try {
    // 1. Discover services
    const services = await discoverServices();
    console.log(chalk.green(`Found ${services.length} services`));

    // 2. Start services if requested
    if (startServices) {
      console.log(chalk.yellow('\nStarting services...'));
      for (const service of services) {
        if (service.hasOpenAPI) {
          await startService(service);
        }
      }
      // Wait a bit for all services to stabilize
      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    // 3. Fetch OpenAPI specs
    console.log(chalk.yellow('\nFetching OpenAPI specifications...'));
    let successCount = 0;
    
    for (const service of services) {
      if (!service.hasOpenAPI) {
        console.log(chalk.gray(`  ⏭️  ${service.name} - No OpenAPI support`));
        continue;
      }

      const spec = await fetchServiceSpec(service);
      if (spec) {
        service.spec = spec;
        successCount++;
        console.log(chalk.green(`  ✅ ${service.name} - Retrieved spec`));
      } else {
        console.log(chalk.red(`  ❌ ${service.name} - Failed to retrieve spec`));
      }
    }

    if (successCount === 0) {
      console.log(chalk.red('\n❌ No OpenAPI specifications found. Make sure services are running.'));
      process.exit(1);
    }

    // 4. Generate unified specification
    console.log(chalk.yellow('\nGenerating unified specification...'));
    const unifiedSpec = await generateUnifiedSpec(services);

    // 5. Create output directory
    await fs.mkdir(output, { recursive: true });

    // 6. Save unified spec
    const specFilename = `openapi.${format}`;
    const specPath = path.join(output, specFilename);
    
    if (format === 'yaml') {
      const yaml = require('js-yaml');
      await fs.writeFile(specPath, yaml.dump(unifiedSpec, { noRefs: true }));
    } else {
      await fs.writeFile(specPath, JSON.stringify(unifiedSpec, null, 2));
    }
    
    console.log(chalk.green(`\n✅ Unified OpenAPI spec saved to: ${specPath}`));

    // 7. Generate Postman collection
    if (includePostman) {
      console.log(chalk.yellow('\nGenerating Postman collection...'));
      const postmanCollection = await generatePostmanCollection(unifiedSpec);
      const postmanPath = path.join(output, 'sparc-api.postman_collection.json');
      await fs.writeFile(postmanPath, JSON.stringify(postmanCollection, null, 2));
      console.log(chalk.green(`✅ Postman collection saved to: ${postmanPath}`));
    }

    // 8. Generate service-specific docs
    console.log(chalk.yellow('\nGenerating service-specific documentation...'));
    const servicesDir = path.join(output, 'services');
    await fs.mkdir(servicesDir, { recursive: true });

    for (const service of services) {
      if (!service.spec) continue;

      const serviceSpecPath = path.join(servicesDir, `${service.name}.${format}`);
      if (format === 'yaml') {
        const yaml = require('js-yaml');
        await fs.writeFile(serviceSpecPath, yaml.dump(service.spec, { noRefs: true }));
      } else {
        await fs.writeFile(serviceSpecPath, JSON.stringify(service.spec, null, 2));
      }
    }

    // 9. Generate HTML documentation
    if (format === 'html' || options.format === undefined) {
      console.log(chalk.yellow('\nGenerating HTML documentation...'));
      await generateHtmlDocs(unifiedSpec, output);
    }

    // 10. Register with documentation service
    await registerWithDocumentationService(unifiedSpec);

    // 11. Generate summary
    const summary = {
      generatedAt: new Date().toISOString(),
      totalServices: services.length,
      servicesWithOpenAPI: successCount,
      totalEndpoints: Object.keys(unifiedSpec.paths).length,
      services: services.map(s => ({
        name: s.name,
        hasOpenAPI: s.hasOpenAPI,
        endpoints: s.spec ? Object.keys(s.spec.paths || {}).length : 0
      }))
    };

    await fs.writeFile(
      path.join(output, 'summary.json'),
      JSON.stringify(summary, null, 2)
    );

    console.log(chalk.bold.green('\n✨ Documentation generation complete!\n'));
    console.log(chalk.cyan('Summary:'));
    console.log(chalk.white(`  • Total services: ${summary.totalServices}`));
    console.log(chalk.white(`  • Services with OpenAPI: ${summary.servicesWithOpenAPI}`));
    console.log(chalk.white(`  • Total endpoints: ${summary.totalEndpoints}`));
    console.log(chalk.white(`  • Output directory: ${output}`));

  } catch (error) {
    console.error(chalk.red('\n❌ Error generating documentation:'), error);
    process.exit(1);
  }
}

async function generateHtmlDocs(spec: any, outputDir: string): Promise<void> {
  const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${spec.info.title}</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4/swagger-ui.css" />
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@4/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@4/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: './openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        tryItOutEnabled: true,
        supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
        onComplete: function() {
          console.log('Swagger UI loaded');
        }
      });
    };
  </script>
</body>
</html>`;

  await fs.writeFile(path.join(outputDir, 'index.html'), htmlContent);
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const options: GenerateDocsOptions = {};

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--output':
      case '-o':
        options.output = args[++i];
        break;
      case '--format':
      case '-f':
        options.format = args[++i] as any;
        break;
      case '--postman':
        options.includePostman = true;
        break;
      case '--no-postman':
        options.includePostman = false;
        break;
      case '--sdk':
        options.includeSdk = true;
        break;
      case '--start-services':
        options.startServices = true;
        break;
      case '--help':
      case '-h':
        console.log(`
SPARC API Documentation Generator

Usage: npm run docs:generate [options]

Options:
  -o, --output <dir>     Output directory (default: docs/api)
  -f, --format <format>  Output format: json, yaml, html (default: json)
  --postman              Include Postman collection (default: true)
  --no-postman           Exclude Postman collection
  --sdk                  Generate SDK stubs
  --start-services       Start services before fetching specs
  -h, --help             Show help
`);
        process.exit(0);
    }
  }

  generateApiDocs(options);
}

export { generateApiDocs };