import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { and, eq, gte, lte } from 'drizzle-orm';
import { getDb } from '../db';
import { 
  visitorCredentials, 
  visitors,
  visitorAccessLogs 
} from '@sparc/database/schemas/visitor-management';
import { VisitorCredentialValidationSchema, AccessLogQuerySchema } from '../types';
import { logger } from '@sparc/shared';
import { z } from 'zod';

const credentialsRouter = new Hono();
const db = getDb();

// Validate credential
credentialsRouter.post(
  '/validate',
  zValidator('json', VisitorCredentialValidationSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const { credentialId, credentialData, accessPoint } = c.req.valid('json');

    try {
      let credential;
      let visitor;

      if (credentialId) {
        // Validate by credential ID
        const result = await db
          .select({
            credential: visitorCredentials,
            visitor: visitors,
          })
          .from(visitorCredentials)
          .leftJoin(visitors, eq(visitorCredentials.visitorId, visitors.id))
          .where(and(
            eq(visitorCredentials.id, credentialId),
            eq(visitorCredentials.organizationId, organizationId),
            eq(visitorCredentials.isActive, true)
          ))
          .limit(1);

        if (result.length > 0) {
          credential = result[0].credential;
          visitor = result[0].visitor;
        }
      } else if (credentialData) {
        // Validate by credential data (e.g., QR code scan)
        const result = await db
          .select({
            credential: visitorCredentials,
            visitor: visitors,
          })
          .from(visitorCredentials)
          .leftJoin(visitors, eq(visitorCredentials.visitorId, visitors.id))
          .where(and(
            eq(visitorCredentials.credentialData, credentialData),
            eq(visitorCredentials.organizationId, organizationId),
            eq(visitorCredentials.isActive, true)
          ))
          .limit(1);

        if (result.length > 0) {
          credential = result[0].credential;
          visitor = result[0].visitor;
        }
      }

      const now = new Date();
      let granted = false;
      let denialReason = '';

      if (!credential || !visitor) {
        denialReason = 'Invalid credential';
      } else if (now < new Date(credential.validFrom) || now > new Date(credential.validUntil)) {
        denialReason = 'Credential expired';
      } else if (visitor.status !== 'CHECKED_IN') {
        denialReason = 'Visitor not checked in';
      } else if (credential.accessAreas && !credential.accessAreas.includes(accessPoint)) {
        denialReason = 'Access denied to this area';
      } else {
        granted = true;
      }

      // Log access attempt
      if (credential && visitor) {
        await db.insert(visitorAccessLogs).values({
          visitorId: visitor.id,
          organizationId,
          accessPoint,
          direction: 'IN', // Could be determined by access point type
          granted,
          denialReason: granted ? undefined : denialReason,
          credentialId: credential.id,
          credentialType: credential.credentialType,
        });
      }

      logger.info('Credential validation', {
        organizationId,
        credentialId: credential?.id,
        visitorId: visitor?.id,
        accessPoint,
        granted,
        denialReason,
      });

      return c.json({
        success: true,
        data: {
          valid: granted,
          visitor: granted && visitor ? {
            id: visitor.id,
            name: `${visitor.firstName} ${visitor.lastName}`,
            company: visitor.company,
            photo: visitor.photo,
            requiresEscort: visitor.requiresEscort,
          } : undefined,
          credential: granted && credential ? {
            id: credential.id,
            type: credential.credentialType,
            validUntil: credential.validUntil,
            accessAreas: credential.accessAreas,
          } : undefined,
          denialReason: !granted ? denialReason : undefined,
        },
      });
    } catch (error) {
      logger.error('Credential validation failed', { error });
      throw new HTTPException(500, { message: 'Validation failed' });
    }
  }
);

// Get visitor credentials
credentialsRouter.get('/visitor/:visitorId', async (c) => {
  const organizationId = c.get('tenantId');
  const visitorId = c.req.param('visitorId');

  try {
    const credentials = await db
      .select()
      .from(visitorCredentials)
      .where(and(
        eq(visitorCredentials.visitorId, visitorId),
        eq(visitorCredentials.organizationId, organizationId)
      ))
      .orderBy(visitorCredentials.issuedAt);

    return c.json({
      success: true,
      data: credentials,
    });
  } catch (error) {
    logger.error('Failed to get visitor credentials', { error });
    throw new HTTPException(500, { message: 'Failed to get credentials' });
  }
});

// Revoke credential
credentialsRouter.post('/:id/revoke', async (c) => {
  const organizationId = c.get('tenantId');
  const userId = c.get('userId');
  const credentialId = c.req.param('id');
  const { reason } = await c.req.json();

  try {
    const [credential] = await db
      .select()
      .from(visitorCredentials)
      .where(and(
        eq(visitorCredentials.id, credentialId),
        eq(visitorCredentials.organizationId, organizationId)
      ))
      .limit(1);

    if (!credential) {
      throw new HTTPException(404, { message: 'Credential not found' });
    }

    if (!credential.isActive) {
      throw new HTTPException(400, { message: 'Credential already revoked' });
    }

    const [updated] = await db
      .update(visitorCredentials)
      .set({
        isActive: false,
        revokedAt: new Date(),
        revokedBy: userId,
        revocationReason: reason || 'Manual revocation',
      })
      .where(eq(visitorCredentials.id, credentialId))
      .returning();

    logger.info('Credential revoked', {
      credentialId,
      organizationId,
      revokedBy: userId,
      reason,
    });

    return c.json({
      success: true,
      data: updated,
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to revoke credential', { error });
    throw new HTTPException(500, { message: 'Failed to revoke credential' });
  }
});

// Get access logs
credentialsRouter.get(
  '/access-logs',
  zValidator('query', AccessLogQuerySchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const params = c.req.valid('query');

    try {
      const conditions = [eq(visitorAccessLogs.organizationId, organizationId)];

      if (params.visitorId) {
        conditions.push(eq(visitorAccessLogs.visitorId, params.visitorId));
      }

      if (params.fromDate) {
        conditions.push(gte(visitorAccessLogs.accessTime, new Date(params.fromDate)));
      }

      if (params.toDate) {
        conditions.push(lte(visitorAccessLogs.accessTime, new Date(params.toDate)));
      }

      if (params.accessPoint) {
        conditions.push(eq(visitorAccessLogs.accessPoint, params.accessPoint));
      }

      if (params.granted !== undefined) {
        conditions.push(eq(visitorAccessLogs.granted, params.granted));
      }

      const offset = (params.page - 1) * params.limit;

      const logs = await db
        .select({
          log: visitorAccessLogs,
          visitor: {
            id: visitors.id,
            firstName: visitors.firstName,
            lastName: visitors.lastName,
            company: visitors.company,
          },
        })
        .from(visitorAccessLogs)
        .leftJoin(visitors, eq(visitorAccessLogs.visitorId, visitors.id))
        .where(and(...conditions))
        .orderBy(visitorAccessLogs.accessTime)
        .limit(params.limit)
        .offset(offset);

      return c.json({
        success: true,
        data: logs.map(l => ({
          ...l.log,
          visitor: l.visitor,
        })),
        meta: {
          page: params.page,
          limit: params.limit,
        },
      });
    } catch (error) {
      logger.error('Failed to get access logs', { error });
      throw new HTTPException(500, { message: 'Failed to get access logs' });
    }
  }
);

// Issue mobile credential
const MobileCredentialSchema = z.object({
  visitorId: z.string().uuid(),
  validUntil: z.string().datetime(),
  accessAreas: z.array(z.string()).optional(),
});

credentialsRouter.post(
  '/mobile',
  zValidator('json', MobileCredentialSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const { visitorId, validUntil, accessAreas } = c.req.valid('json');

    try {
      // Check if visitor exists and is checked in
      const [visitor] = await db
        .select()
        .from(visitors)
        .where(and(
          eq(visitors.id, visitorId),
          eq(visitors.organizationId, organizationId)
        ))
        .limit(1);

      if (!visitor) {
        throw new HTTPException(404, { message: 'Visitor not found' });
      }

      if (visitor.status !== 'CHECKED_IN') {
        throw new HTTPException(400, { message: 'Visitor must be checked in' });
      }

      // Generate mobile credential data
      const credentialData = {
        type: 'MOBILE',
        visitorId,
        organizationId,
        issuedAt: new Date().toISOString(),
        nonce: Math.random().toString(36).substring(2),
      };

      const [credential] = await db
        .insert(visitorCredentials)
        .values({
          visitorId,
          organizationId,
          credentialType: 'MOBILE',
          credentialData: JSON.stringify(credentialData),
          validFrom: new Date(),
          validUntil: new Date(validUntil),
          accessAreas: accessAreas || visitor.accessAreas || [],
          issuedBy: userId,
        })
        .returning();

      logger.info('Mobile credential issued', {
        credentialId: credential.id,
        visitorId,
        organizationId,
        issuedBy: userId,
      });

      return c.json({
        success: true,
        data: {
          credential,
          mobileData: {
            credentialId: credential.id,
            qrCode: credential.credentialData, // Could generate QR code here
            validUntil: credential.validUntil,
          },
        },
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to issue mobile credential', { error });
      throw new HTTPException(500, { message: 'Failed to issue mobile credential' });
    }
  }
);

// Get credential statistics
credentialsRouter.get('/stats', async (c) => {
  const organizationId = c.get('tenantId');

  try {
    const now = new Date();
    
    // Get various metrics
    const [
      activeCredentials,
      expiredCredentials,
      revokedCredentials,
      credentialsByType,
    ] = await Promise.all([
      // Active credentials
      db
        .select({ count: visitorCredentials.id })
        .from(visitorCredentials)
        .where(and(
          eq(visitorCredentials.organizationId, organizationId),
          eq(visitorCredentials.isActive, true),
          gte(visitorCredentials.validUntil, now)
        )),
      
      // Expired credentials
      db
        .select({ count: visitorCredentials.id })
        .from(visitorCredentials)
        .where(and(
          eq(visitorCredentials.organizationId, organizationId),
          eq(visitorCredentials.isActive, true),
          lte(visitorCredentials.validUntil, now)
        )),
      
      // Revoked credentials
      db
        .select({ count: visitorCredentials.id })
        .from(visitorCredentials)
        .where(and(
          eq(visitorCredentials.organizationId, organizationId),
          eq(visitorCredentials.isActive, false)
        )),
      
      // By type (simplified - would need GROUP BY)
      db
        .select()
        .from(visitorCredentials)
        .where(eq(visitorCredentials.organizationId, organizationId)),
    ]);

    // Calculate type distribution
    const typeDistribution: Record<string, number> = {};
    for (const cred of credentialsByType) {
      typeDistribution[cred.credentialType] = (typeDistribution[cred.credentialType] || 0) + 1;
    }

    return c.json({
      success: true,
      data: {
        active: activeCredentials.length,
        expired: expiredCredentials.length,
        revoked: revokedCredentials.length,
        total: credentialsByType.length,
        byType: typeDistribution,
      },
    });
  } catch (error) {
    logger.error('Failed to get credential statistics', { error });
    throw new HTTPException(500, { message: 'Failed to get statistics' });
  }
});

export default credentialsRouter;