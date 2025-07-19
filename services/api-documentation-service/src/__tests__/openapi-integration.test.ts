import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { createOpenAPIApp, z } from '@sparc/shared';
import request from 'supertest';

describe('OpenAPI Integration', () => {
  let app: any;
  let registry: any;

  beforeAll(() => {
    // Create test service with OpenAPI
    const result = createOpenAPIApp({
      serviceName: 'test-service',
      serviceVersion: '1.0.0',
      serviceDescription: 'Test service for OpenAPI integration'
    });
    
    app = result.app;
    registry = result.registry;

    // Define test schema
    const TestResourceSchema = z.object({
      id: z.string().uuid(),
      name: z.string(),
      value: z.number(),
      active: z.boolean(),
      createdAt: z.string().datetime()
    });

    // Register schema
    registry.registerComponent('schemas', 'TestResource', TestResourceSchema);

    // Define test routes
    app.openapi({
      method: 'get',
      path: '/resources',
      summary: 'List test resources',
      description: 'Retrieve a list of test resources with pagination',
      tags: ['Resources'],
      security: [{ bearerAuth: [] }],
      request: {
        query: z.object({
          page: z.string().optional().default('1'),
          limit: z.string().optional().default('10')
        })
      },
      responses: {
        200: {
          description: 'List of resources',
          content: {
            'application/json': {
              schema: z.object({
                data: z.array(TestResourceSchema),
                pagination: z.object({
                  page: z.number(),
                  limit: z.number(),
                  total: z.number()
                })
              })
            }
          }
        }
      }
    }, async (c) => {
      return c.json({
        data: [
          {
            id: '123e4567-e89b-12d3-a456-426614174000',
            name: 'Test Resource',
            value: 42,
            active: true,
            createdAt: new Date().toISOString()
          }
        ],
        pagination: {
          page: 1,
          limit: 10,
          total: 1
        }
      });
    });

    app.openapi({
      method: 'post',
      path: '/resources',
      summary: 'Create a resource',
      tags: ['Resources'],
      security: [{ bearerAuth: [] }],
      request: {
        body: {
          content: {
            'application/json': {
              schema: TestResourceSchema.omit({ id: true, createdAt: true })
            }
          }
        }
      },
      responses: {
        201: {
          description: 'Resource created',
          content: {
            'application/json': {
              schema: TestResourceSchema
            }
          }
        },
        400: {
          description: 'Validation error'
        }
      }
    }, async (c) => {
      const data = c.req.valid('json');
      return c.json({
        ...data,
        id: '123e4567-e89b-12d3-a456-426614174000',
        createdAt: new Date().toISOString()
      }, 201);
    });
  });

  describe('OpenAPI Spec Generation', () => {
    it('should generate valid OpenAPI spec', async () => {
      const response = await request(app).get('/openapi.json');
      
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        openapi: '3.0.0',
        info: {
          title: 'test-service API',
          version: '1.0.0',
          description: 'Test service for OpenAPI integration'
        },
        paths: expect.any(Object),
        components: expect.any(Object)
      });
    });

    it('should include all registered paths', async () => {
      const response = await request(app).get('/openapi.json');
      
      expect(response.body.paths).toHaveProperty('/resources');
      expect(response.body.paths['/resources']).toHaveProperty('get');
      expect(response.body.paths['/resources']).toHaveProperty('post');
    });

    it('should include security schemes', async () => {
      const response = await request(app).get('/openapi.json');
      
      expect(response.body.components.securitySchemes).toHaveProperty('bearerAuth');
      expect(response.body.components.securitySchemes.bearerAuth).toEqual({
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT'
      });
    });

    it('should include registered schemas', async () => {
      const response = await request(app).get('/openapi.json');
      
      expect(response.body.components.schemas).toHaveProperty('TestResource');
    });
  });

  describe('Route Validation', () => {
    it('should validate query parameters', async () => {
      const response = await request(app)
        .get('/resources?page=invalid&limit=abc');
      
      expect(response.status).toBe(400);
      expect(response.body.error).toBeDefined();
      expect(response.body.error.message).toContain('Validation failed');
    });

    it('should validate request body', async () => {
      const response = await request(app)
        .post('/resources')
        .send({
          name: 123, // Should be string
          value: 'not a number', // Should be number
          active: 'yes' // Should be boolean
        });
      
      expect(response.status).toBe(400);
      expect(response.body.error.details).toBeDefined();
    });

    it('should accept valid request', async () => {
      const response = await request(app)
        .post('/resources')
        .send({
          name: 'Valid Resource',
          value: 100,
          active: true
        });
      
      expect(response.status).toBe(201);
      expect(response.body).toMatchObject({
        name: 'Valid Resource',
        value: 100,
        active: true
      });
    });
  });

  describe('Standard Endpoints', () => {
    it('should have health endpoint', async () => {
      const response = await request(app).get('/health');
      
      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        status: 'healthy',
        service: 'test-service',
        version: '1.0.0'
      });
    });
  });
});