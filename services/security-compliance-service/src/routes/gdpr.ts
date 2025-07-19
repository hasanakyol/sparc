import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { tenantMiddleware } from '@sparc/shared/middleware/tenant';
import { telemetry, SpanStatusCode } from '@sparc/shared/telemetry';
import { gdprRequestSchema, gdprProcessSchema } from '../types/schemas';
import { GDPRService } from '../services/gdpr-service';

export const gdprRouter = (gdprService: GDPRService) => {
  const router = new Hono();

  // Apply middleware
  router.use('*', authMiddleware);
  router.use('*', tenantMiddleware);

  // Create GDPR request
  router.post('/requests', zValidator('json', gdprRequestSchema), async (c) => {
    return telemetry.withSpan('gdpr.createRequest', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const request = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.requestType': request.type
        });

        const gdprRequest = await gdprService.createGDPRRequest(
          tenantId,
          userId,
          request
        );
        
        span.setAttribute('gdpr.requestId', gdprRequest.id);

        return c.json(gdprRequest, 201);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get GDPR requests
  router.get('/requests', async (c) => {
    return telemetry.withSpan('gdpr.getRequests', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const status = c.req.query('status');
        const type = c.req.query('type');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'filter.status': status,
          'filter.type': type
        });

        const requests = await gdprService.getGDPRRequests(tenantId, {
          status,
          type
        });
        
        span.setAttribute('requests.count', requests.length);

        return c.json({ requests });
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Get GDPR request by ID
  router.get('/requests/:requestId', async (c) => {
    return telemetry.withSpan('gdpr.getRequestById', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const requestId = c.req.param('requestId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.requestId': requestId
        });

        const request = await gdprService.getGDPRRequestById(tenantId, requestId);
        
        if (!request) {
          return c.json({ error: 'GDPR request not found' }, 404);
        }

        return c.json(request);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Process GDPR request
  router.post('/requests/:requestId/process', zValidator('json', gdprProcessSchema), async (c) => {
    return telemetry.withSpan('gdpr.processRequest', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.get('user')?.sub;
        const requestId = c.req.param('requestId');
        const processing = c.req.valid('json');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.requestId': requestId,
          'gdpr.action': processing.action
        });

        const result = await gdprService.processGDPRRequest(
          tenantId,
          requestId,
          userId,
          processing
        );

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Data export for GDPR
  router.post('/export/:userId', async (c) => {
    return telemetry.withSpan('gdpr.exportUserData', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const requesterId = c.get('user')?.sub;
        const targetUserId = c.req.param('userId');
        const format = c.req.query('format') || 'json';
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.targetUserId': targetUserId,
          'gdpr.format': format
        });

        // Verify requester has permission or is the data subject
        if (requesterId !== targetUserId) {
          const hasPermission = await gdprService.verifyDataAccessPermission(
            tenantId,
            requesterId,
            targetUserId
          );
          
          if (!hasPermission) {
            return c.json({ error: 'Unauthorized access to user data' }, 403);
          }
        }

        const exportData = await gdprService.exportUserData(
          tenantId,
          targetUserId,
          format as 'json' | 'csv' | 'pdf'
        );
        
        span.setAttribute('export.size', exportData.data.length);

        // Set headers based on format
        if (format === 'csv') {
          c.header('Content-Type', 'text/csv');
          c.header('Content-Disposition', `attachment; filename="user-data-${targetUserId}.csv"`);
        } else if (format === 'pdf') {
          c.header('Content-Type', 'application/pdf');
          c.header('Content-Disposition', `attachment; filename="user-data-${targetUserId}.pdf"`);
        } else {
          c.header('Content-Type', 'application/json');
          c.header('Content-Disposition', `attachment; filename="user-data-${targetUserId}.json"`);
        }

        return c.body(exportData.data);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Data deletion for GDPR
  router.delete('/data/:userId', async (c) => {
    return telemetry.withSpan('gdpr.deleteUserData', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const requesterId = c.get('user')?.sub;
        const targetUserId = c.req.param('userId');
        const confirmation = c.req.header('x-confirmation-token');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.targetUserId': targetUserId
        });

        // Verify confirmation token
        if (!confirmation) {
          return c.json({ 
            error: 'Confirmation token required for data deletion' 
          }, 400);
        }

        // Verify permission
        const hasPermission = await gdprService.verifyDataDeletionPermission(
          tenantId,
          requesterId,
          targetUserId,
          confirmation
        );
        
        if (!hasPermission) {
          return c.json({ error: 'Unauthorized data deletion' }, 403);
        }

        const result = await gdprService.deleteUserData(
          tenantId,
          targetUserId,
          requesterId
        );
        
        span.setAttributes({
          'deletion.recordsDeleted': result.recordsDeleted,
          'deletion.servicesAffected': result.servicesAffected.length
        });

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Data rectification
  router.put('/data/:userId/rectify', async (c) => {
    return telemetry.withSpan('gdpr.rectifyUserData', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const requesterId = c.get('user')?.sub;
        const targetUserId = c.req.param('userId');
        const updates = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.targetUserId': targetUserId,
          'gdpr.fieldsToUpdate': Object.keys(updates).length
        });

        // Verify permission
        if (requesterId !== targetUserId) {
          const hasPermission = await gdprService.verifyDataAccessPermission(
            tenantId,
            requesterId,
            targetUserId
          );
          
          if (!hasPermission) {
            return c.json({ error: 'Unauthorized data modification' }, 403);
          }
        }

        const result = await gdprService.rectifyUserData(
          tenantId,
          targetUserId,
          updates,
          requesterId
        );

        return c.json(result);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Data portability
  router.post('/portability/:userId', async (c) => {
    return telemetry.withSpan('gdpr.generatePortableData', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const requesterId = c.get('user')?.sub;
        const targetUserId = c.req.param('userId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.targetUserId': targetUserId
        });

        // Verify permission
        if (requesterId !== targetUserId) {
          const hasPermission = await gdprService.verifyDataAccessPermission(
            tenantId,
            requesterId,
            targetUserId
          );
          
          if (!hasPermission) {
            return c.json({ error: 'Unauthorized data access' }, 403);
          }
        }

        const portableData = await gdprService.generatePortableData(
          tenantId,
          targetUserId
        );
        
        span.setAttribute('portability.size', JSON.stringify(portableData).length);

        // Return machine-readable format
        c.header('Content-Type', 'application/json');
        c.header('Content-Disposition', `attachment; filename="portable-data-${targetUserId}.json"`);

        return c.json(portableData);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // Consent management
  router.get('/consent/:userId', async (c) => {
    return telemetry.withSpan('gdpr.getConsent', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.req.param('userId');
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.userId': userId
        });

        const consent = await gdprService.getUserConsent(tenantId, userId);

        return c.json(consent);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  router.put('/consent/:userId', async (c) => {
    return telemetry.withSpan('gdpr.updateConsent', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        const userId = c.req.param('userId');
        const requesterId = c.get('user')?.sub;
        const consentUpdates = await c.req.json();
        
        span.setAttributes({
          'tenant.id': tenantId,
          'gdpr.userId': userId
        });

        // Verify user is updating their own consent
        if (requesterId !== userId) {
          return c.json({ error: 'Users can only update their own consent' }, 403);
        }

        const updatedConsent = await gdprService.updateUserConsent(
          tenantId,
          userId,
          consentUpdates
        );

        return c.json(updatedConsent);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  // GDPR compliance dashboard
  router.get('/dashboard', async (c) => {
    return telemetry.withSpan('gdpr.getDashboard', async (span) => {
      try {
        const tenantId = c.get('tenantId');
        
        span.setAttribute('tenant.id', tenantId);

        const dashboard = await gdprService.getGDPRDashboard(tenantId);

        return c.json(dashboard);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        throw error;
      }
    });
  });

  return router;
};