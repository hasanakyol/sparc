import { and, eq, gte, lte, or, like, desc, asc, isNull, not } from 'drizzle-orm';
import { randomUUID } from 'crypto';
import { getDb } from '../db';
import { 
  visitors, 
  visitorCredentials, 
  visitorAccessLogs,
  visitorWatchlist,
  visitorGroups,
  visitorGroupMembers
} from '@sparc/database/schemas/visitor-management';
import { users } from '@sparc/database/schemas/user-management';
import { logger } from '@sparc/shared';
import type { 
  VisitorPreRegistration, 
  VisitorCheckIn, 
  VisitorUpdate,
  VisitorSearch,
  ServiceResponse,
  VisitorAnalytics
} from '../types';

export class VisitorService {
  private db = getDb();

  async preRegisterVisitor(
    data: VisitorPreRegistration,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse> {
    try {
      // Check if host exists
      const host = await this.db
        .select()
        .from(users)
        .where(and(
          eq(users.id, data.hostUserId),
          eq(users.organizationId, organizationId)
        ))
        .limit(1);

      if (!host.length) {
        return {
          success: false,
          error: {
            code: 'HOST_NOT_FOUND',
            message: 'The specified host user does not exist',
          },
        };
      }

      // Generate invitation code
      const invitationCode = this.generateInvitationCode();

      // Create visitor record
      const [visitor] = await this.db
        .insert(visitors)
        .values({
          ...data,
          organizationId,
          invitationCode,
          status: 'PENDING',
          createdBy: userId,
        })
        .returning();

      logger.info('Visitor pre-registered', {
        visitorId: visitor.id,
        organizationId,
        hostUserId: data.hostUserId,
      });

      return {
        success: true,
        data: {
          visitor,
          invitationCode,
        },
      };
    } catch (error) {
      logger.error('Failed to pre-register visitor', { error, data });
      return {
        success: false,
        error: {
          code: 'REGISTRATION_FAILED',
          message: 'Failed to pre-register visitor',
        },
      };
    }
  }

  async checkInVisitor(
    data: VisitorCheckIn,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse> {
    try {
      let visitor;

      // Find existing visitor or create new one
      if (data.visitorId) {
        const result = await this.db
          .select()
          .from(visitors)
          .where(and(
            eq(visitors.id, data.visitorId),
            eq(visitors.organizationId, organizationId)
          ))
          .limit(1);

        visitor = result[0];
      } else if (data.invitationCode) {
        const result = await this.db
          .select()
          .from(visitors)
          .where(and(
            eq(visitors.invitationCode, data.invitationCode),
            eq(visitors.organizationId, organizationId)
          ))
          .limit(1);

        visitor = result[0];
      } else if (data.qrCode) {
        // Parse QR code data
        try {
          const qrData = JSON.parse(data.qrCode);
          const result = await this.db
            .select()
            .from(visitors)
            .where(and(
              eq(visitors.id, qrData.visitorId),
              eq(visitors.invitationCode, qrData.invitationCode),
              eq(visitors.organizationId, organizationId)
            ))
            .limit(1);

          visitor = result[0];
        } catch {
          return {
            success: false,
            error: {
              code: 'INVALID_QR_CODE',
              message: 'Invalid QR code format',
            },
          };
        }
      }

      if (!visitor) {
        // Walk-in visitor - create new record
        if (!data.firstName || !data.lastName || !data.purpose || !data.hostUserId) {
          return {
            success: false,
            error: {
              code: 'INCOMPLETE_DATA',
              message: 'Walk-in visitors require complete information',
            },
          };
        }

        // Check if host exists
        const host = await this.db
          .select()
          .from(users)
          .where(and(
            eq(users.id, data.hostUserId),
            eq(users.organizationId, organizationId)
          ))
          .limit(1);

        if (!host.length) {
          return {
            success: false,
            error: {
              code: 'HOST_NOT_FOUND',
              message: 'The specified host user does not exist',
            },
          };
        }

        // Create walk-in visitor
        const [newVisitor] = await this.db
          .insert(visitors)
          .values({
            firstName: data.firstName,
            lastName: data.lastName,
            email: data.email,
            phone: data.phone,
            company: data.company,
            purpose: data.purpose,
            hostUserId: data.hostUserId,
            organizationId,
            status: 'APPROVED', // Walk-ins are auto-approved
            expectedArrival: new Date(),
            expectedDeparture: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours default
            createdBy: userId,
            approvedBy: userId,
            approvedAt: new Date(),
          })
          .returning();

        visitor = newVisitor;
      }

      // Check visitor status
      if (visitor.status === 'DENIED') {
        return {
          success: false,
          error: {
            code: 'VISITOR_DENIED',
            message: 'This visitor has been denied access',
          },
        };
      }

      if (visitor.status === 'CHECKED_IN') {
        return {
          success: false,
          error: {
            code: 'ALREADY_CHECKED_IN',
            message: 'Visitor is already checked in',
          },
        };
      }

      // Update visitor with check-in data
      const updateData: any = {
        status: 'CHECKED_IN',
        actualArrival: new Date(),
        checkedInBy: userId,
        updatedBy: userId,
        updatedAt: new Date(),
      };

      // Add optional fields if provided
      if (data.photo) updateData.photo = data.photo;
      if (data.idDocument) updateData.idDocument = data.idDocument;
      if (data.idType) updateData.idType = data.idType;
      if (data.idNumber) updateData.idNumber = data.idNumber;
      if (data.vehicleLicense) updateData.vehicleLicense = data.vehicleLicense;
      if (data.vehicleMake) updateData.vehicleMake = data.vehicleMake;
      if (data.vehicleModel) updateData.vehicleModel = data.vehicleModel;
      if (data.vehicleColor) updateData.vehicleColor = data.vehicleColor;
      if (data.parkingSpot) updateData.parkingSpot = data.parkingSpot;
      if (data.emergencyContactName) updateData.emergencyContactName = data.emergencyContactName;
      if (data.emergencyContactPhone) updateData.emergencyContactPhone = data.emergencyContactPhone;
      if (data.accessAreas) updateData.accessAreas = data.accessAreas;

      const [updatedVisitor] = await this.db
        .update(visitors)
        .set(updateData)
        .where(eq(visitors.id, visitor.id))
        .returning();

      // Create temporary credential
      const credential = await this.createTemporaryCredential(
        visitor.id,
        organizationId,
        data.accessAreas || visitor.accessAreas || [],
        visitor.expectedDeparture,
        userId
      );

      // Log access
      await this.logAccess({
        visitorId: visitor.id,
        organizationId,
        accessPoint: 'Main Reception',
        direction: 'IN',
        granted: true,
        credentialId: credential.id,
        credentialType: 'QR_CODE',
      });

      logger.info('Visitor checked in', {
        visitorId: visitor.id,
        organizationId,
        checkedInBy: userId,
      });

      return {
        success: true,
        data: {
          visitor: updatedVisitor,
          credential,
        },
      };
    } catch (error) {
      logger.error('Failed to check in visitor', { error, data });
      return {
        success: false,
        error: {
          code: 'CHECKIN_FAILED',
          message: 'Failed to check in visitor',
        },
      };
    }
  }

  async checkOutVisitor(
    visitorId: string,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse> {
    try {
      // Get visitor
      const [visitor] = await this.db
        .select()
        .from(visitors)
        .where(and(
          eq(visitors.id, visitorId),
          eq(visitors.organizationId, organizationId)
        ))
        .limit(1);

      if (!visitor) {
        return {
          success: false,
          error: {
            code: 'VISITOR_NOT_FOUND',
            message: 'Visitor not found',
          },
        };
      }

      if (visitor.status !== 'CHECKED_IN') {
        return {
          success: false,
          error: {
            code: 'NOT_CHECKED_IN',
            message: 'Visitor is not checked in',
          },
        };
      }

      // Update visitor status
      const [updatedVisitor] = await this.db
        .update(visitors)
        .set({
          status: 'CHECKED_OUT',
          actualDeparture: new Date(),
          checkedOutBy: userId,
          updatedBy: userId,
          updatedAt: new Date(),
        })
        .where(eq(visitors.id, visitorId))
        .returning();

      // Revoke credentials
      await this.revokeVisitorCredentials(visitorId, userId);

      // Log access
      await this.logAccess({
        visitorId,
        organizationId,
        accessPoint: 'Main Reception',
        direction: 'OUT',
        granted: true,
      });

      logger.info('Visitor checked out', {
        visitorId,
        organizationId,
        checkedOutBy: userId,
      });

      return {
        success: true,
        data: { visitor: updatedVisitor },
      };
    } catch (error) {
      logger.error('Failed to check out visitor', { error, visitorId });
      return {
        success: false,
        error: {
          code: 'CHECKOUT_FAILED',
          message: 'Failed to check out visitor',
        },
      };
    }
  }

  async searchVisitors(
    params: VisitorSearch,
    organizationId: string
  ): Promise<ServiceResponse> {
    try {
      const conditions = [eq(visitors.organizationId, organizationId)];

      // Add search conditions
      if (params.query) {
        conditions.push(
          or(
            like(visitors.firstName, `%${params.query}%`),
            like(visitors.lastName, `%${params.query}%`),
            like(visitors.email, `%${params.query}%`),
            like(visitors.company, `%${params.query}%`)
          )!
        );
      }

      if (params.status) {
        conditions.push(eq(visitors.status, params.status));
      }

      if (params.hostUserId) {
        conditions.push(eq(visitors.hostUserId, params.hostUserId));
      }

      if (params.fromDate) {
        conditions.push(gte(visitors.expectedArrival, new Date(params.fromDate)));
      }

      if (params.toDate) {
        conditions.push(lte(visitors.expectedArrival, new Date(params.toDate)));
      }

      if (!params.includeExpired) {
        conditions.push(
          or(
            not(eq(visitors.status, 'EXPIRED')),
            isNull(visitors.status)
          )!
        );
      }

      // Calculate offset
      const offset = (params.page - 1) * params.limit;

      // Get total count
      const totalResult = await this.db
        .select({ count: visitors.id })
        .from(visitors)
        .where(and(...conditions));

      const total = totalResult.length;

      // Get paginated results
      const orderBy = params.sortOrder === 'asc' 
        ? asc(visitors[params.sortBy])
        : desc(visitors[params.sortBy]);

      const results = await this.db
        .select({
          visitor: visitors,
          host: {
            id: users.id,
            firstName: users.firstName,
            lastName: users.lastName,
            email: users.email,
          },
        })
        .from(visitors)
        .leftJoin(users, eq(visitors.hostUserId, users.id))
        .where(and(...conditions))
        .orderBy(orderBy)
        .limit(params.limit)
        .offset(offset);

      return {
        success: true,
        data: results.map(r => ({
          ...r.visitor,
          host: r.host,
        })),
        meta: {
          page: params.page,
          limit: params.limit,
          total,
          hasMore: offset + params.limit < total,
        },
      };
    } catch (error) {
      logger.error('Failed to search visitors', { error, params });
      return {
        success: false,
        error: {
          code: 'SEARCH_FAILED',
          message: 'Failed to search visitors',
        },
      };
    }
  }

  async getVisitorById(
    visitorId: string,
    organizationId: string
  ): Promise<ServiceResponse> {
    try {
      const result = await this.db
        .select({
          visitor: visitors,
          host: {
            id: users.id,
            firstName: users.firstName,
            lastName: users.lastName,
            email: users.email,
          },
        })
        .from(visitors)
        .leftJoin(users, eq(visitors.hostUserId, users.id))
        .where(and(
          eq(visitors.id, visitorId),
          eq(visitors.organizationId, organizationId)
        ))
        .limit(1);

      if (!result.length) {
        return {
          success: false,
          error: {
            code: 'VISITOR_NOT_FOUND',
            message: 'Visitor not found',
          },
        };
      }

      const visitorData = {
        ...result[0].visitor,
        host: result[0].host,
      };

      // Get active credentials
      const credentials = await this.db
        .select()
        .from(visitorCredentials)
        .where(and(
          eq(visitorCredentials.visitorId, visitorId),
          eq(visitorCredentials.isActive, true)
        ));

      // Get recent access logs
      const accessLogs = await this.db
        .select()
        .from(visitorAccessLogs)
        .where(eq(visitorAccessLogs.visitorId, visitorId))
        .orderBy(desc(visitorAccessLogs.accessTime))
        .limit(10);

      return {
        success: true,
        data: {
          ...visitorData,
          credentials,
          recentAccess: accessLogs,
        },
      };
    } catch (error) {
      logger.error('Failed to get visitor', { error, visitorId });
      return {
        success: false,
        error: {
          code: 'GET_VISITOR_FAILED',
          message: 'Failed to get visitor details',
        },
      };
    }
  }

  async updateVisitor(
    visitorId: string,
    data: VisitorUpdate,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse> {
    try {
      // Check if visitor exists
      const [visitor] = await this.db
        .select()
        .from(visitors)
        .where(and(
          eq(visitors.id, visitorId),
          eq(visitors.organizationId, organizationId)
        ))
        .limit(1);

      if (!visitor) {
        return {
          success: false,
          error: {
            code: 'VISITOR_NOT_FOUND',
            message: 'Visitor not found',
          },
        };
      }

      // Update visitor
      const updateData: any = {
        ...data,
        updatedBy: userId,
        updatedAt: new Date(),
      };

      // Handle status-specific updates
      if (data.status === 'DENIED' && data.denialReason) {
        updateData.deniedBy = userId;
        updateData.deniedAt = new Date();
        updateData.denialReason = data.denialReason;
      }

      const [updatedVisitor] = await this.db
        .update(visitors)
        .set(updateData)
        .where(eq(visitors.id, visitorId))
        .returning();

      logger.info('Visitor updated', {
        visitorId,
        organizationId,
        updatedBy: userId,
        changes: Object.keys(data),
      });

      return {
        success: true,
        data: { visitor: updatedVisitor },
      };
    } catch (error) {
      logger.error('Failed to update visitor', { error, visitorId, data });
      return {
        success: false,
        error: {
          code: 'UPDATE_FAILED',
          message: 'Failed to update visitor',
        },
      };
    }
  }

  async getActiveVisitors(organizationId: string): Promise<ServiceResponse> {
    try {
      const activeVisitors = await this.db
        .select({
          visitor: visitors,
          host: {
            id: users.id,
            firstName: users.firstName,
            lastName: users.lastName,
            email: users.email,
            phone: users.phone,
          },
        })
        .from(visitors)
        .leftJoin(users, eq(visitors.hostUserId, users.id))
        .where(and(
          eq(visitors.organizationId, organizationId),
          eq(visitors.status, 'CHECKED_IN')
        ))
        .orderBy(desc(visitors.actualArrival));

      return {
        success: true,
        data: activeVisitors.map(r => ({
          ...r.visitor,
          host: r.host,
        })),
      };
    } catch (error) {
      logger.error('Failed to get active visitors', { error, organizationId });
      return {
        success: false,
        error: {
          code: 'GET_ACTIVE_FAILED',
          message: 'Failed to get active visitors',
        },
      };
    }
  }

  async getOverstayVisitors(organizationId: string): Promise<ServiceResponse> {
    try {
      const now = new Date();
      const overstayVisitors = await this.db
        .select({
          visitor: visitors,
          host: {
            id: users.id,
            firstName: users.firstName,
            lastName: users.lastName,
            email: users.email,
            phone: users.phone,
          },
        })
        .from(visitors)
        .leftJoin(users, eq(visitors.hostUserId, users.id))
        .where(and(
          eq(visitors.organizationId, organizationId),
          eq(visitors.status, 'CHECKED_IN'),
          lte(visitors.expectedDeparture, now)
        ))
        .orderBy(asc(visitors.expectedDeparture));

      return {
        success: true,
        data: overstayVisitors.map(r => ({
          ...r.visitor,
          host: r.host,
          overstayMinutes: Math.floor((now.getTime() - new Date(r.visitor.expectedDeparture).getTime()) / 60000),
        })),
      };
    } catch (error) {
      logger.error('Failed to get overstay visitors', { error, organizationId });
      return {
        success: false,
        error: {
          code: 'GET_OVERSTAY_FAILED',
          message: 'Failed to get overstay visitors',
        },
      };
    }
  }

  async getVisitorAnalytics(
    organizationId: string,
    fromDate?: Date,
    toDate?: Date
  ): Promise<ServiceResponse<VisitorAnalytics>> {
    try {
      const now = new Date();
      const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const dateRange = {
        from: fromDate || new Date(todayStart.getTime() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
        to: toDate || now,
      };

      // Get various metrics
      const [
        totalVisitorsResult,
        activeVisitorsResult,
        pendingApprovalsResult,
        todayCheckInsResult,
        todayCheckOutsResult,
        overstayResult,
      ] = await Promise.all([
        // Total visitors in range
        this.db
          .select({ count: visitors.id })
          .from(visitors)
          .where(and(
            eq(visitors.organizationId, organizationId),
            gte(visitors.createdAt, dateRange.from),
            lte(visitors.createdAt, dateRange.to)
          )),
        
        // Active visitors
        this.db
          .select({ count: visitors.id })
          .from(visitors)
          .where(and(
            eq(visitors.organizationId, organizationId),
            eq(visitors.status, 'CHECKED_IN')
          )),
        
        // Pending approvals
        this.db
          .select({ count: visitors.id })
          .from(visitors)
          .where(and(
            eq(visitors.organizationId, organizationId),
            eq(visitors.status, 'PENDING')
          )),
        
        // Today check-ins
        this.db
          .select({ count: visitors.id })
          .from(visitors)
          .where(and(
            eq(visitors.organizationId, organizationId),
            gte(visitors.actualArrival!, todayStart)
          )),
        
        // Today check-outs
        this.db
          .select({ count: visitors.id })
          .from(visitors)
          .where(and(
            eq(visitors.organizationId, organizationId),
            gte(visitors.actualDeparture!, todayStart)
          )),
        
        // Overstay visitors
        this.db
          .select({ count: visitors.id })
          .from(visitors)
          .where(and(
            eq(visitors.organizationId, organizationId),
            eq(visitors.status, 'CHECKED_IN'),
            lte(visitors.expectedDeparture, now)
          )),
      ]);

      // TODO: Calculate average visit duration, top hosts, visitors by status/hour
      // These would require more complex queries or aggregations

      const analytics: VisitorAnalytics = {
        totalVisitors: totalVisitorsResult.length,
        activeVisitors: activeVisitorsResult.length,
        pendingApprovals: pendingApprovalsResult.length,
        todayCheckIns: todayCheckInsResult.length,
        todayCheckOuts: todayCheckOutsResult.length,
        averageVisitDuration: 0, // TODO: Calculate
        topHosts: [], // TODO: Calculate
        visitorsByStatus: {}, // TODO: Calculate
        visitorsByHour: [], // TODO: Calculate
        overstayVisitors: overstayResult.length,
      };

      return {
        success: true,
        data: analytics,
      };
    } catch (error) {
      logger.error('Failed to get visitor analytics', { error, organizationId });
      return {
        success: false,
        error: {
          code: 'ANALYTICS_FAILED',
          message: 'Failed to get visitor analytics',
        },
      };
    }
  }

  // Private helper methods
  private generateInvitationCode(): string {
    return randomUUID().substring(0, 8).toUpperCase();
  }

  private async createTemporaryCredential(
    visitorId: string,
    organizationId: string,
    accessAreas: string[],
    validUntil: Date,
    issuedBy: string
  ) {
    const credentialData = {
      visitorId,
      type: 'VISITOR',
      timestamp: new Date().toISOString(),
    };

    const [credential] = await this.db
      .insert(visitorCredentials)
      .values({
        visitorId,
        organizationId,
        credentialType: 'QR_CODE',
        credentialData: JSON.stringify(credentialData),
        validFrom: new Date(),
        validUntil,
        accessAreas,
        issuedBy,
      })
      .returning();

    return credential;
  }

  private async revokeVisitorCredentials(visitorId: string, revokedBy: string) {
    await this.db
      .update(visitorCredentials)
      .set({
        isActive: false,
        revokedAt: new Date(),
        revokedBy,
        revocationReason: 'Visitor checked out',
      })
      .where(and(
        eq(visitorCredentials.visitorId, visitorId),
        eq(visitorCredentials.isActive, true)
      ));
  }

  private async logAccess(data: {
    visitorId: string;
    organizationId: string;
    accessPoint: string;
    direction: string;
    granted: boolean;
    credentialId?: string;
    credentialType?: string;
    denialReason?: string;
  }) {
    await this.db.insert(visitorAccessLogs).values(data);
  }
}