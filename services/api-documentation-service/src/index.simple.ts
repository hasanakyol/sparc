import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { readFile, readdir } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';

const app = new Hono();

// Middleware
app.use('*', cors());
app.use('*', logger());

const port = parseInt(process.env.PORT || '3012', 10);
const servicesDir = join(__dirname, '../../..');

// Health check endpoints
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'api-documentation-service',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.get('/ready', (c) => {
  return c.json({
    status: 'ready',
    service: 'api-documentation-service',
    timestamp: new Date().toISOString()
  });
});

app.get('/metrics', (c) => {
  const metrics = `
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",status="200"} 1

# HELP nodejs_version_info Node.js version info
# TYPE nodejs_version_info gauge
nodejs_version_info{version="${process.version}"} 1
`;
  return c.text(metrics, 200, { 'Content-Type': 'text/plain' });
});

// List all available service documentation
app.get('/api/docs', async (c) => {
  try {
    const services = await readdir(join(servicesDir, 'services'));
    const availableDocs = [];

    for (const service of services) {
      const docsPath = join(servicesDir, 'services', service, 'docs', 'openapi.json');
      if (existsSync(docsPath)) {
        try {
          const spec = JSON.parse(await readFile(docsPath, 'utf-8'));
          availableDocs.push({
            service,
            title: spec.info.title,
            version: spec.info.version,
            description: spec.info.description,
            docsUrl: `/api/docs/${service}`,
            specUrl: `/api/docs/${service}/openapi.json`
          });
        } catch (error) {
          console.error(`Error reading docs for ${service}:`, error);
        }
      }
    }

    return c.json({
      services: availableDocs,
      totalServices: availableDocs.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return c.json({ error: 'Failed to list documentation' }, 500);
  }
});

// Get OpenAPI spec for a specific service
app.get('/api/docs/:service/openapi.json', async (c) => {
  const { service } = c.req.param();
  const specPath = join(servicesDir, 'services', service, 'docs', 'openapi.json');

  try {
    if (!existsSync(specPath)) {
      return c.json({ error: 'Documentation not found for this service' }, 404);
    }

    const spec = await readFile(specPath, 'utf-8');
    return c.json(JSON.parse(spec));
  } catch (error) {
    return c.json({ error: 'Failed to load documentation' }, 500);
  }
});

// Serve Swagger UI for a specific service
app.get('/api/docs/:service', async (c) => {
  const { service } = c.req.param();
  const specPath = join(servicesDir, 'services', service, 'docs', 'openapi.json');

  if (!existsSync(specPath)) {
    return c.html(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Documentation Not Found</title>
      </head>
      <body>
        <h1>Documentation not found for service: ${service}</h1>
        <p><a href="/api/docs">Back to services list</a></p>
      </body>
      </html>
    `, 404);
  }

  const html = `<!DOCTYPE html>
<html>
<head>
  <title>${service} - API Documentation</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: "/api/docs/${service}/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>`;

  return c.html(html);
});

// Root page - list all services
app.get('/', async (c) => {
  try {
    const services = await readdir(join(servicesDir, 'services'));
    const availableDocs = [];

    for (const service of services) {
      const docsPath = join(servicesDir, 'services', service, 'docs', 'openapi.json');
      if (existsSync(docsPath)) {
        try {
          const spec = JSON.parse(await readFile(docsPath, 'utf-8'));
          availableDocs.push({
            service,
            title: spec.info.title,
            version: spec.info.version,
            description: spec.info.description
          });
        } catch (error) {
          console.error(`Error reading docs for ${service}:`, error);
        }
      }
    }

    const html = `<!DOCTYPE html>
<html>
<head>
  <title>SPARC API Documentation</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
      background: #f5f5f5;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    h1 {
      color: #333;
      margin-bottom: 30px;
    }
    .services-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 20px;
    }
    .service-card {
      background: white;
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .service-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0,0,0,0.15);
    }
    .service-title {
      font-size: 18px;
      font-weight: 600;
      color: #2563eb;
      margin: 0 0 10px 0;
    }
    .service-version {
      font-size: 14px;
      color: #666;
      margin-bottom: 10px;
    }
    .service-description {
      font-size: 14px;
      color: #555;
      margin-bottom: 15px;
    }
    .service-link {
      display: inline-block;
      padding: 8px 16px;
      background: #2563eb;
      color: white;
      text-decoration: none;
      border-radius: 4px;
      font-size: 14px;
      transition: background 0.2s;
    }
    .service-link:hover {
      background: #1d4ed8;
    }
    .no-docs {
      text-align: center;
      padding: 40px;
      color: #666;
    }
    .header-actions {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
    }
    .action-button {
      display: inline-block;
      padding: 10px 20px;
      background: #059669;
      color: white;
      text-decoration: none;
      border-radius: 4px;
      font-size: 14px;
      transition: background 0.2s;
    }
    .action-button:hover {
      background: #047857;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>SPARC API Documentation</h1>
    <div class="header-actions">
      <a href="/api/docs" class="action-button">View API Endpoints</a>
    </div>
    ${availableDocs.length > 0 ? `
      <div class="services-grid">
        ${availableDocs.map(doc => `
          <div class="service-card">
            <h2 class="service-title">${doc.title}</h2>
            <div class="service-version">Version: ${doc.version}</div>
            <div class="service-description">${doc.description}</div>
            <a href="/api/docs/${doc.service}" class="service-link">View Documentation</a>
          </div>
        `).join('')}
      </div>
    ` : `
      <div class="no-docs">
        <p>No API documentation available yet.</p>
        <p>Run <code>npm run docs:generate</code> to generate documentation for all services.</p>
      </div>
    `}
  </div>
</body>
</html>`;

    return c.html(html);
  } catch (error) {
    return c.html('<h1>Error loading documentation</h1>', 500);
  }
});

serve({
  fetch: app.fetch,
  port,
});

console.log(`API Documentation service listening on port ${port}`);
console.log(`View documentation at http://localhost:${port}`);