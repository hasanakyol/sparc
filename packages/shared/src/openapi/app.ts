import { OpenAPIHono } from '@hono/zod-openapi';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { config } from '../config';
import { ServiceOpenAPIRegistry } from './registry';
import type { Context, Next } from 'hono';
import crypto from 'crypto';

export interface CreateOpenAPIAppOptions {
  serviceName: string;
  serviceVersion?: string;
  serviceDescription?: string;
  basePath?: string;
  enableCors?: boolean;
  enableLogging?: boolean;
  enablePrettyJSON?: boolean;
}

// Create an OpenAPI-enabled Hono app with standard middleware
export function createOpenAPIApp(options: CreateOpenAPIAppOptions) {
  const {
    serviceName,
    serviceVersion = '1.0.0',
    serviceDescription = '',
    basePath = '',
    enableCors = true,
    enableLogging = true,
    enablePrettyJSON = true
  } = options;

  // Create the app
  const app = new OpenAPIHono({
    defaultHook: (result, c) => {
      if (!result.success) {
        return c.json({
          error: {
            code: 400,
            message: 'Validation failed',
            requestId: c.get('requestId'),
            timestamp: new Date().toISOString(),
            details: result.error.errors.map(err => ({
              field: err.path.join('.'),
              message: err.message
            }))
          }
        }, 400);
      }
    }
  });

  // Apply global middleware
  if (enableLogging) {
    app.use('*', logger());
  }

  if (enablePrettyJSON) {
    app.use('*', prettyJSON());
  }

  if (enableCors) {
    app.use('*', cors({
      origin: config.cors?.allowedOrigins || '*',
      allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
      allowHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID', 'X-Request-ID'],
      credentials: true,
    }));
  }

  // Request ID middleware
  app.use('*', async (c: Context, next: Next) => {
    const requestId = c.req.header('x-request-id') || crypto.randomUUID();
    c.set('requestId', requestId);
    c.header('x-request-id', requestId);
    await next();
  });

  // Create registry
  const registry = new ServiceOpenAPIRegistry(serviceName, serviceVersion, serviceDescription);

  // Add registry to app context
  app.use('*', async (c: Context, next: Next) => {
    c.set('openAPIRegistry', registry);
    await next();
  });

  // Standard health endpoint
  app.openapi({
    method: 'get',
    path: '/health',
    summary: 'Health check',
    description: 'Check if the service is healthy',
    tags: ['Health'],
    responses: {
      200: {
        description: 'Service is healthy',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                status: { type: 'string', example: 'healthy' },
                service: { type: 'string', example: serviceName },
                version: { type: 'string', example: serviceVersion },
                timestamp: { type: 'string', format: 'date-time' },
                uptime: { type: 'number', example: 1234.56 }
              }
            }
          }
        }
      }
    }
  }, (c) => {
    return c.json({
      status: 'healthy',
      service: serviceName,
      version: serviceVersion,
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  });

  // OpenAPI spec endpoint
  app.openapi({
    method: 'get',
    path: '/openapi.json',
    summary: 'Get OpenAPI specification',
    description: 'Returns the OpenAPI 3.0 specification for this service',
    tags: ['Documentation'],
    responses: {
      200: {
        description: 'OpenAPI specification',
        content: {
          'application/json': {
            schema: {
              type: 'object'
            }
          }
        }
      }
    }
  }, (c) => {
    const spec = registry.generateSpec({
      servers: [
        {
          url: `${config.apiGateway?.url || 'http://localhost:3000'}${basePath}`,
          description: 'API Gateway'
        },
        {
          url: `http://${serviceName}:3000`,
          description: 'Direct service access (internal only)'
        }
      ]
    });
    return c.json(spec);
  });

  // Return app with registry attached
  return { app, registry };
}