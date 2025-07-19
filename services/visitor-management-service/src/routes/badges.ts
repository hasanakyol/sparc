import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { BadgeService } from '../services/badge.service';
import { BadgePrintSchema } from '../types';
import { logger } from '@sparc/shared';

const badgesRouter = new Hono();
const badgeService = new BadgeService();

// Generate and print badge
badgesRouter.post(
  '/print',
  zValidator('json', BadgePrintSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const data = c.req.valid('json');

    const result = await badgeService.generateBadge(data, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Badge generation failed' });
    }

    // Log badge printing
    logger.info('Badge printed', {
      visitorId: data.visitorId,
      organizationId,
      printedBy: userId,
      template: data.template,
    });

    // Return badge data and PDF
    return c.json({
      success: true,
      data: {
        badgeData: result.data.badgeData,
        printJobId: `print-${Date.now()}`,
      },
    });
  }
);

// Get badge PDF
badgesRouter.get(
  '/print/:visitorId/pdf',
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const visitorId = c.req.param('visitorId');

    // Generate badge with default template
    const result = await badgeService.generateBadge(
      {
        visitorId,
        template: 'STANDARD',
      },
      organizationId,
      userId
    );
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Badge generation failed' });
    }

    // Return PDF as binary
    c.header('Content-Type', 'application/pdf');
    c.header('Content-Disposition', `attachment; filename="visitor-badge-${visitorId}.pdf"`);
    
    return c.body(result.data.pdf);
  }
);

// Reprint badge
badgesRouter.post(
  '/:visitorId/reprint',
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const visitorId = c.req.param('visitorId');

    const result = await badgeService.reprintBadge(visitorId, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Badge reprint failed' });
    }

    // Log badge reprinting
    logger.info('Badge reprinted', {
      visitorId,
      organizationId,
      reprintedBy: userId,
    });

    return c.json({
      success: true,
      data: {
        badgeData: result.data.badgeData,
        printJobId: `reprint-${Date.now()}`,
      },
    });
  }
);

// Get badge preview (without saving)
badgesRouter.post(
  '/preview',
  zValidator('json', BadgePrintSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const data = c.req.valid('json');

    // Generate badge without updating visitor record
    // This would be a modified version of generateBadge that doesn't persist
    // For now, we'll use the regular service
    const result = await badgeService.generateBadge(data, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Badge preview failed' });
    }

    // Return preview data
    return c.json({
      success: true,
      data: {
        badgeData: result.data.badgeData,
        previewUrl: `data:application/pdf;base64,${result.data.pdf.toString('base64')}`,
      },
    });
  }
);

// Get badge templates
badgesRouter.get('/templates', async (c) => {
  const templates = [
    {
      id: 'STANDARD',
      name: 'Standard Visitor',
      description: 'Default visitor badge',
      color: '#3498db',
      requiresEscort: false,
    },
    {
      id: 'CONTRACTOR',
      name: 'Contractor',
      description: 'For contractors and vendors',
      color: '#f39c12',
      requiresEscort: false,
    },
    {
      id: 'VIP',
      name: 'VIP Guest',
      description: 'For VIP visitors',
      color: '#9b59b6',
      requiresEscort: false,
    },
    {
      id: 'ESCORT_REQUIRED',
      name: 'Escort Required',
      description: 'Visitor must be escorted at all times',
      color: '#e74c3c',
      requiresEscort: true,
    },
    {
      id: 'TEMPORARY',
      name: 'Temporary',
      description: 'Short-term visitor badge',
      color: '#27ae60',
      requiresEscort: false,
    },
    {
      id: 'EVENT',
      name: 'Event Guest',
      description: 'For event attendees',
      color: '#00bcd4',
      requiresEscort: false,
    },
  ];

  return c.json({
    success: true,
    data: templates,
  });
});

// Batch print badges (for groups)
badgesRouter.post(
  '/batch-print',
  zValidator('json', BadgePrintSchema.array()),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const badges = c.req.valid('json');

    const results = [];
    const errors = [];

    for (const badge of badges) {
      const result = await badgeService.generateBadge(badge, organizationId, userId);
      
      if (result.success) {
        results.push({
          visitorId: badge.visitorId,
          badgeData: result.data.badgeData,
        });
      } else {
        errors.push({
          visitorId: badge.visitorId,
          error: result.error,
        });
      }
    }

    logger.info('Batch badge print', {
      organizationId,
      printedBy: userId,
      successCount: results.length,
      errorCount: errors.length,
    });

    return c.json({
      success: errors.length === 0,
      data: {
        printed: results,
        failed: errors,
        printJobId: `batch-${Date.now()}`,
      },
    });
  }
);

export default badgesRouter;