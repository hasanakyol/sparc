import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { zValidator } from '@hono/zod-validator';
import { PrismaClient } from '@prisma/client';
import { ReportTemplateCreateSchema } from '../types/schemas';
import { ReportTemplate } from '../types';
import { logger } from '../utils/logger';

export function templatesRoutes(prisma: PrismaClient): Hono {
  const app = new Hono();

  // Get all report templates
  app.get('/', async (c) => {
    try {
      const category = c.req.query('category');
      const type = c.req.query('type');

      // Built-in templates
      const templates: ReportTemplate[] = [
        {
          id: 'access_daily',
          name: 'Daily Access Report',
          description: 'Comprehensive daily access events summary',
          type: 'access_events',
          category: 'access',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['userId', 'doorId', 'eventType'],
          defaultParameters: {
            includeDetails: true,
            sortBy: 'timestamp',
            sortOrder: 'desc'
          },
          tags: ['daily', 'access', 'security']
        },
        {
          id: 'user_activity_weekly',
          name: 'Weekly User Activity Report',
          description: 'User activity patterns and statistics for the week',
          type: 'user_activity',
          category: 'analytics',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['department', 'role'],
          defaultParameters: {
            includeDetails: true,
            groupBy: ['department']
          },
          tags: ['weekly', 'users', 'analytics']
        },
        {
          id: 'security_monthly',
          name: 'Monthly Security Assessment',
          description: 'Comprehensive security metrics and incidents',
          type: 'security_assessment',
          category: 'security',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['severity', 'location'],
          defaultParameters: {
            includeDetails: true,
            groupBy: ['severity', 'type']
          },
          tags: ['monthly', 'security', 'compliance']
        },
        {
          id: 'visitor_summary',
          name: 'Visitor Summary Report',
          description: 'Visitor access patterns and statistics',
          type: 'visitor_log',
          category: 'visitor',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['visitorType', 'host'],
          defaultParameters: {
            includeDetails: false,
            sortBy: 'checkIn',
            sortOrder: 'desc'
          },
          tags: ['visitors', 'access']
        },
        {
          id: 'system_health_daily',
          name: 'Daily System Health Report',
          description: 'System performance and health metrics',
          type: 'system_health',
          category: 'system',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['serviceType', 'severity'],
          defaultParameters: {
            includeDetails: true,
            groupBy: ['service', 'status']
          },
          tags: ['daily', 'system', 'monitoring']
        },
        {
          id: 'compliance_sox_quarterly',
          name: 'Quarterly SOX Compliance Report',
          description: 'Sarbanes-Oxley compliance assessment',
          type: 'compliance_sox',
          category: 'compliance',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['includeEvidence', 'includeRecommendations'],
          defaultParameters: {
            includeDetails: true,
            includeEvidence: true,
            includeRecommendations: true
          },
          tags: ['quarterly', 'compliance', 'sox']
        },
        {
          id: 'environmental_monthly',
          name: 'Monthly Environmental Report',
          description: 'Environmental monitoring and energy usage',
          type: 'environmental',
          category: 'facilities',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['location', 'sensorType'],
          defaultParameters: {
            includeDetails: true,
            groupBy: ['location', 'metric']
          },
          tags: ['monthly', 'environmental', 'energy']
        },
        {
          id: 'incident_weekly',
          name: 'Weekly Incident Report',
          description: 'Security incidents and response summary',
          type: 'incident_report',
          category: 'security',
          requiredFields: ['startDate', 'endDate'],
          optionalFields: ['severity', 'type', 'status'],
          defaultParameters: {
            includeDetails: true,
            sortBy: 'severity',
            sortOrder: 'desc'
          },
          tags: ['weekly', 'incidents', 'security']
        }
      ];

      // Filter templates
      let filtered = templates;
      if (category) {
        filtered = filtered.filter(t => t.category === category);
      }
      if (type) {
        filtered = filtered.filter(t => t.type === type);
      }

      return c.json({
        success: true,
        templates: filtered
      });
    } catch (error) {
      logger.error('Failed to get report templates', { error });
      throw new HTTPException(500, { message: 'Failed to get report templates' });
    }
  });

  // Get specific template
  app.get('/:templateId', async (c) => {
    try {
      const templateId = c.req.param('templateId');

      // This would fetch from database in real implementation
      const template: ReportTemplate = {
        id: templateId,
        name: 'Sample Template',
        description: 'Sample template description',
        type: 'access_events',
        category: 'access',
        requiredFields: ['startDate', 'endDate'],
        tags: ['sample']
      };

      return c.json({
        success: true,
        template
      });
    } catch (error) {
      logger.error('Failed to get report template', { error });
      throw new HTTPException(500, { message: 'Failed to get report template' });
    }
  });

  // Create custom template
  app.post('/',
    zValidator('json', ReportTemplateCreateSchema),
    async (c) => {
      try {
        const body = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;
        const userId = c.get('userId') as string;

        // This would save to database
        const templateId = `tmpl_${Date.now()}`;

        return c.json({
          success: true,
          templateId,
          message: 'Template created successfully'
        }, 201);
      } catch (error) {
        logger.error('Failed to create report template', { error });
        throw new HTTPException(500, { message: 'Failed to create report template' });
      }
    }
  );

  // Update custom template
  app.put('/:templateId',
    zValidator('json', ReportTemplateCreateSchema.partial()),
    async (c) => {
      try {
        const templateId = c.req.param('templateId');
        const updates = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;

        // This would update in database

        return c.json({
          success: true,
          message: 'Template updated successfully'
        });
      } catch (error) {
        logger.error('Failed to update report template', { error });
        throw new HTTPException(500, { message: 'Failed to update report template' });
      }
    }
  );

  // Delete custom template
  app.delete('/:templateId', async (c) => {
    try {
      const templateId = c.req.param('templateId');
      const tenantId = c.get('tenantId') as string;

      // This would delete from database

      return c.json({
        success: true,
        message: 'Template deleted successfully'
      });
    } catch (error) {
      logger.error('Failed to delete report template', { error });
      throw new HTTPException(500, { message: 'Failed to delete report template' });
    }
  });

  // Get template categories
  app.get('/meta/categories', async (c) => {
    const categories = [
      { id: 'access', name: 'Access Control', icon: 'door' },
      { id: 'security', name: 'Security', icon: 'shield' },
      { id: 'analytics', name: 'Analytics', icon: 'chart' },
      { id: 'compliance', name: 'Compliance', icon: 'check' },
      { id: 'system', name: 'System', icon: 'server' },
      { id: 'visitor', name: 'Visitor Management', icon: 'user' },
      { id: 'facilities', name: 'Facilities', icon: 'building' }
    ];

    return c.json({
      success: true,
      categories
    });
  });

  // Clone template
  app.post('/:templateId/clone',
    zValidator('json', z.object({
      name: z.string(),
      description: z.string().optional()
    })),
    async (c) => {
      try {
        const templateId = c.req.param('templateId');
        const { name, description } = c.req.valid('json');
        const tenantId = c.get('tenantId') as string;

        // This would clone the template
        const newTemplateId = `tmpl_${Date.now()}`;

        return c.json({
          success: true,
          templateId: newTemplateId,
          message: 'Template cloned successfully'
        }, 201);
      } catch (error) {
        logger.error('Failed to clone report template', { error });
        throw new HTTPException(500, { message: 'Failed to clone report template' });
      }
    }
  );

  return app;
}