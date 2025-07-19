import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { 
  versionRoute, 
  requireVersion,
  transformResponse 
} from '@sparc/shared/middleware/versioning';
import { versionFeatureFlag } from '@sparc/shared/services/feature-flags';

/**
 * Example: Versioned Incidents API
 * Demonstrates how to implement versioning in a service
 */
const app = new Hono();

// Schemas for different versions
const incidentV1Schema = z.object({
  incident_id: z.string().uuid(),
  incident_type: z.enum(['security', 'safety', 'operational']),
  priority: z.enum(['low', 'medium', 'high', 'critical']),
  description: z.string(),
  status: z.enum(['open', 'in_progress', 'resolved', 'closed']),
  created_by: z.string(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime()
});

const incidentV2Schema = z.object({
  id: z.string().uuid(),
  category: z.enum(['security', 'safety', 'operational', 'environmental']),
  priority: z.enum(['P1', 'P2', 'P3', 'P4']),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  title: z.string(),
  description: z.string(),
  status: z.enum(['open', 'investigating', 'mitigating', 'resolved', 'closed']),
  assignee: z.string().optional(),
  tags: z.array(z.string()).optional(),
  metadata: z.record(z.any()).optional(),
  createdBy: z.string(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  resolvedAt: z.string().datetime().optional()
});

/**
 * GET /incidents - List incidents
 * Supports multiple versions
 */
app.get('/incidents', versionRoute({
  '1.0': async (c) => {
    // Version 1.0 implementation
    const incidents = [
      {
        incident_id: '123e4567-e89b-12d3-a456-426614174000',
        incident_type: 'security',
        priority: 'high',
        description: 'Unauthorized access attempt detected',
        status: 'open',
        created_by: 'user123',
        created_at: '2024-01-15T10:00:00Z',
        updated_at: '2024-01-15T10:00:00Z'
      }
    ];
    
    return c.json({
      incidents,
      total: incidents.length
    });
  },
  
  '1.1': async (c) => {
    // Version 1.1 - Minor improvements
    const incidents = [
      {
        incident_id: '123e4567-e89b-12d3-a456-426614174000',
        incident_type: 'security',
        priority: 'high',
        description: 'Unauthorized access attempt detected',
        status: 'open',
        created_by: 'user123',
        created_at: '2024-01-15T10:00:00Z',
        updated_at: '2024-01-15T10:00:00Z',
        // New in v1.1
        location: 'Building A - Floor 2',
        affected_assets: ['camera-001', 'door-002']
      }
    ];
    
    return c.json({
      incidents,
      total: incidents.length,
      // New in v1.1
      page: 1,
      limit: 20
    });
  },
  
  '2.0': async (c) => {
    // Version 2.0 - Major redesign
    const incidents = [
      {
        id: '123e4567-e89b-12d3-a456-426614174000',
        category: 'security',
        priority: 'P2',
        severity: 'high',
        title: 'Unauthorized Access Attempt',
        description: 'Multiple failed login attempts detected from suspicious IP',
        status: 'investigating',
        assignee: 'security-team',
        tags: ['intrusion', 'authentication', 'suspicious'],
        metadata: {
          source_ip: '192.168.1.100',
          attempts: 5,
          first_attempt: '2024-01-15T09:55:00Z'
        },
        createdBy: 'system',
        createdAt: '2024-01-15T10:00:00Z',
        updatedAt: '2024-01-15T10:05:00Z'
      }
    ];
    
    return c.json({
      data: incidents,
      pagination: {
        total: incidents.length,
        page: 1,
        limit: 20,
        hasMore: false
      },
      _links: {
        self: '/v2/incidents?page=1',
        next: null,
        prev: null
      }
    });
  },
  
  default: async (c) => {
    return c.json({ error: 'Version not supported' }, 400);
  }
}));

/**
 * POST /incidents - Create incident
 * Demonstrates request validation per version
 */
app.post('/incidents', async (c) => {
  const version = c.get('version') as any;
  
  if (version.major === 1) {
    // V1 validation and handling
    const validator = zValidator('json', incidentV1Schema.omit({
      incident_id: true,
      created_at: true,
      updated_at: true
    }));
    
    const middleware = await validator(c, async () => {});
    if (middleware instanceof Response) return middleware;
    
    const data = c.req.valid('json' as any);
    const incident = {
      incident_id: crypto.randomUUID(),
      ...data,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    return c.json(incident, 201);
  } else if (version.major === 2) {
    // V2 validation and handling
    const validator = zValidator('json', incidentV2Schema.omit({
      id: true,
      createdAt: true,
      updatedAt: true,
      resolvedAt: true
    }));
    
    const middleware = await validator(c, async () => {});
    if (middleware instanceof Response) return middleware;
    
    const data = c.req.valid('json' as any);
    const incident = {
      id: crypto.randomUUID(),
      ...data,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    return c.json({ data: incident }, 201);
  }
  
  return c.json({ error: 'Version not supported' }, 400);
});

/**
 * GET /incidents/:id - Get incident by ID
 * Demonstrates response transformation
 */
app.get('/incidents/:id', 
  transformResponse({
    '1.0': (data) => {
      // Transform v2 internal format to v1 response
      if (data.id) {
        return {
          incident_id: data.id,
          incident_type: data.category,
          priority: {
            'P1': 'critical',
            'P2': 'high',
            'P3': 'medium',
            'P4': 'low'
          }[data.priority] || data.priority,
          description: data.description,
          status: data.status === 'investigating' ? 'in_progress' : data.status,
          created_by: data.createdBy,
          created_at: data.createdAt,
          updated_at: data.updatedAt
        };
      }
      return data;
    },
    '1.1': (data) => {
      // Transform v2 to v1.1
      const v1Data = {
        incident_id: data.id,
        incident_type: data.category,
        priority: {
          'P1': 'critical',
          'P2': 'high',
          'P3': 'medium',
          'P4': 'low'
        }[data.priority] || data.priority,
        description: data.description,
        status: data.status === 'investigating' ? 'in_progress' : data.status,
        created_by: data.createdBy,
        created_at: data.createdAt,
        updated_at: data.updatedAt,
        // Additional v1.1 fields
        location: data.metadata?.location || 'Unknown',
        affected_assets: data.metadata?.affected_assets || []
      };
      return v1Data;
    }
  }),
  async (c) => {
    const id = c.req.param('id');
    
    // Always store in v2 format internally
    const incident = {
      id,
      category: 'security',
      priority: 'P2',
      severity: 'high',
      title: 'Unauthorized Access Attempt',
      description: 'Multiple failed login attempts detected',
      status: 'investigating',
      assignee: 'security-team',
      tags: ['intrusion', 'authentication'],
      metadata: {
        location: 'Building A - Floor 2',
        affected_assets: ['camera-001', 'door-002']
      },
      createdBy: 'system',
      createdAt: '2024-01-15T10:00:00Z',
      updatedAt: '2024-01-15T10:05:00Z'
    };
    
    return c.json(incident);
  }
);

/**
 * PATCH /incidents/:id - Update incident
 * Demonstrates version-specific business logic
 */
app.patch('/incidents/:id', 
  requireVersion('1.1'), // Minimum version requirement
  async (c) => {
    const id = c.req.param('id');
    const version = c.get('version') as any;
    const updates = await c.req.json();
    
    // Version-specific validation
    if (version.major === 1) {
      // V1 allows status updates only
      if (updates.status && !['open', 'in_progress', 'resolved', 'closed'].includes(updates.status)) {
        return c.json({ error: 'Invalid status value' }, 400);
      }
    } else if (version.major === 2) {
      // V2 has more statuses and allows assignee updates
      if (updates.status && !['open', 'investigating', 'mitigating', 'resolved', 'closed'].includes(updates.status)) {
        return c.json({ error: 'Invalid status value' }, 400);
      }
    }
    
    // Apply updates
    const updated = {
      id,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    
    return c.json(updated);
  }
);

/**
 * POST /incidents/:id/resolve - Resolve incident
 * Demonstrates feature flag usage with versions
 */
app.post('/incidents/:id/resolve',
  versionFeatureFlag('quick-resolve-feature', {
    'enabled': async (c) => {
      // Quick resolve available
      const id = c.req.param('id');
      const { resolution } = await c.req.json();
      
      return c.json({
        id,
        status: 'resolved',
        resolution,
        resolvedAt: new Date().toISOString(),
        resolvedBy: c.get('user')?.userId
      });
    },
    'disabled': async (c) => {
      // Traditional resolve requires more data
      const id = c.req.param('id');
      const body = await c.req.json();
      
      if (!body.resolution || !body.rootCause || !body.preventiveMeasures) {
        return c.json({
          error: 'Full resolution details required',
          required: ['resolution', 'rootCause', 'preventiveMeasures']
        }, 400);
      }
      
      return c.json({
        id,
        status: 'resolved',
        ...body,
        resolvedAt: new Date().toISOString(),
        resolvedBy: c.get('user')?.userId
      });
    },
    default: async (c) => {
      return c.json({ error: 'Feature not available' }, 404);
    }
  })
);

/**
 * DELETE /incidents/:id - Delete incident
 * Only available in v2.0+
 */
app.delete('/incidents/:id',
  requireVersion('2.0'),
  async (c) => {
    const id = c.req.param('id');
    const hasFeature = c.get('hasFeature') as (flag: string) => boolean;
    
    if (!hasFeature('soft-delete')) {
      return c.json({ error: 'Incident deletion not allowed' }, 403);
    }
    
    return c.json({
      id,
      deleted: true,
      deletedAt: new Date().toISOString(),
      deletedBy: c.get('user')?.userId
    });
  }
);

/**
 * GET /incidents/analytics - Analytics endpoint
 * New in v2.0
 */
app.get('/incidents/analytics',
  requireVersion('2.0'),
  async (c) => {
    const { start, end, groupBy } = c.req.query();
    
    return c.json({
      period: { start, end },
      groupBy: groupBy || 'day',
      metrics: {
        total: 156,
        open: 23,
        resolved: 120,
        averageResolutionTime: '4.5 hours',
        byCategory: {
          security: 45,
          safety: 38,
          operational: 52,
          environmental: 21
        },
        byPriority: {
          P1: 5,
          P2: 28,
          P3: 67,
          P4: 56
        }
      },
      trends: [
        { date: '2024-01-01', count: 12 },
        { date: '2024-01-02', count: 15 },
        { date: '2024-01-03', count: 8 }
      ]
    });
  }
);

export { app as versionedIncidentsRouter };