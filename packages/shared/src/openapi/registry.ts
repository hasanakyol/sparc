import { OpenAPIRegistry } from '@hono/zod-openapi';
import { z } from 'zod';

// Shared error response schemas
export const ErrorResponseSchema = z.object({
  error: z.object({
    code: z.number(),
    message: z.string(),
    requestId: z.string().optional(),
    timestamp: z.string().datetime(),
    details: z.any().optional()
  })
});

export const UnauthorizedResponseSchema = z.object({
  error: z.object({
    code: z.literal(401),
    message: z.string().default('Authentication required'),
    requestId: z.string().optional(),
    timestamp: z.string().datetime()
  })
});

export const ForbiddenResponseSchema = z.object({
  error: z.object({
    code: z.literal(403),  
    message: z.string().default('Access denied'),
    requestId: z.string().optional(),
    timestamp: z.string().datetime()
  })
});

export const NotFoundResponseSchema = z.object({
  error: z.object({
    code: z.literal(404),
    message: z.string().default('Resource not found'),
    requestId: z.string().optional(),
    timestamp: z.string().datetime()
  })
});

export const ValidationErrorResponseSchema = z.object({
  error: z.object({
    code: z.literal(400),
    message: z.string().default('Validation failed'),
    requestId: z.string().optional(),
    timestamp: z.string().datetime(),
    details: z.array(z.object({
      field: z.string(),
      message: z.string()
    })).optional()
  })
});

// Common response schemas
export const SuccessResponseSchema = z.object({
  success: z.boolean().default(true),
  message: z.string().optional(),
  timestamp: z.string().datetime()
});

export const PaginatedResponseSchema = <T extends z.ZodTypeAny>(schema: T) => z.object({
  data: z.array(schema),
  pagination: z.object({
    page: z.number(),
    limit: z.number(),
    total: z.number(),
    totalPages: z.number()
  }),
  timestamp: z.string().datetime()
});

// Common parameter schemas
export const PaginationParamsSchema = z.object({
  page: z.string().optional().default('1').transform(val => parseInt(val)),
  limit: z.string().optional().default('10').transform(val => parseInt(val)),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).optional().default('asc')
});

export const SearchParamsSchema = PaginationParamsSchema.extend({
  search: z.string().optional(),
  filter: z.string().optional()
});

// Common security schemes
export const bearerAuth = {
  type: 'http' as const,
  scheme: 'bearer' as const,
  bearerFormat: 'JWT'
};

// Service-specific registry class
export class ServiceOpenAPIRegistry {
  private registry: OpenAPIRegistry;
  private serviceName: string;
  private serviceVersion: string;
  private serviceDescription: string;

  constructor(
    serviceName: string,
    serviceVersion: string = '1.0.0',
    serviceDescription: string = ''
  ) {
    this.registry = new OpenAPIRegistry();
    this.serviceName = serviceName;
    this.serviceVersion = serviceVersion;
    this.serviceDescription = serviceDescription;

    // Register common schemas
    this.registerCommonSchemas();
  }

  private registerCommonSchemas() {
    // Register error responses
    this.registry.register('ErrorResponse', ErrorResponseSchema);
    this.registry.register('UnauthorizedResponse', UnauthorizedResponseSchema);
    this.registry.register('ForbiddenResponse', ForbiddenResponseSchema);
    this.registry.register('NotFoundResponse', NotFoundResponseSchema);
    this.registry.register('ValidationErrorResponse', ValidationErrorResponseSchema);
    
    // Register common responses
    this.registry.register('SuccessResponse', SuccessResponseSchema);
    
    // Register common parameters
    this.registry.register('PaginationParams', PaginationParamsSchema);
    this.registry.register('SearchParams', SearchParamsSchema);
  }

  // Get the underlying registry for custom registrations
  getRegistry(): OpenAPIRegistry {
    return this.registry;
  }

  // Register a path with automatic tagging
  registerPath(config: any) {
    // Add service tag automatically
    if (!config.tags) {
      config.tags = [];
    }
    if (!config.tags.includes(this.serviceName)) {
      config.tags.push(this.serviceName);
    }

    return this.registry.registerPath(config);
  }

  // Register a component (schema, response, parameter, etc.)
  registerComponent<T extends z.ZodTypeAny>(
    type: 'schemas' | 'responses' | 'parameters' | 'examples' | 'requestBodies' | 'headers' | 'securitySchemes',
    name: string,
    schema: T
  ) {
    return this.registry.registerComponent(type, name, schema);
  }

  // Generate OpenAPI specification
  generateSpec(config?: {
    servers?: Array<{ url: string; description?: string }>;
    security?: Array<Record<string, string[]>>;
  }) {
    const generator = this.registry.getOpenAPI({
      openapi: '3.0.0',
      info: {
        title: `${this.serviceName} API`,
        version: this.serviceVersion,
        description: this.serviceDescription
      },
      servers: config?.servers || [
        {
          url: `http://localhost:3000`,
          description: 'Development server'
        }
      ],
      security: config?.security || [{ bearerAuth: [] }],
      components: {
        securitySchemes: {
          bearerAuth
        }
      }
    });

    return generator;
  }
}

// Helper function to create standard API responses
export const createApiResponses = (options?: {
  successSchema?: z.ZodTypeAny;
  successDescription?: string;
  includeAuth?: boolean;
  includeNotFound?: boolean;
  includeValidation?: boolean;
}) => {
  const responses: Record<string, any> = {
    200: {
      description: options?.successDescription || 'Successful response',
      content: {
        'application/json': {
          schema: options?.successSchema || SuccessResponseSchema
        }
      }
    },
    500: {
      description: 'Internal server error',
      content: {
        'application/json': {
          schema: ErrorResponseSchema
        }
      }
    }
  };

  if (options?.includeAuth !== false) {
    responses[401] = {
      description: 'Authentication required',
      content: {
        'application/json': {
          schema: UnauthorizedResponseSchema
        }
      }
    };
    responses[403] = {
      description: 'Access denied',
      content: {
        'application/json': {
          schema: ForbiddenResponseSchema
        }
      }
    };
  }

  if (options?.includeNotFound) {
    responses[404] = {
      description: 'Resource not found',
      content: {
        'application/json': {
          schema: NotFoundResponseSchema
        }
      }
    };
  }

  if (options?.includeValidation) {
    responses[400] = {
      description: 'Validation error',
      content: {
        'application/json': {
          schema: ValidationErrorResponseSchema
        }
      }
    };
  }

  return responses;
};