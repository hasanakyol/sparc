import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { telemetry } from '@sparc/shared/telemetry';
import crypto from 'crypto';
import {
  GDPRRequest,
  GDPRRequestType,
  GDPRRequestStatus,
  GDPRResponse
} from '../types';
import {
  GDPRRequestInput,
  GDPRProcessInput
} from '../types/schemas';
import PDFDocument from 'pdfkit';

export class GDPRService {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async createGDPRRequest(
    tenantId: string,
    userId: string,
    request: GDPRRequestInput
  ): Promise<GDPRRequest> {
    return telemetry.withSpan('gdprService.createRequest', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'gdpr.type': request.type
      });

      // Generate verification token for email verification
      const verificationToken = crypto.randomBytes(32).toString('hex');

      const gdprRequest = await this.prisma.gdprRequest.create({
        data: {
          tenantId,
          requesterId: userId,
          type: request.type,
          status: GDPRRequestStatus.PENDING,
          details: request.details,
          requestedAt: new Date(),
          verificationToken
        }
      });

      // Send verification email (in production)
      await this.sendVerificationEmail(userId, verificationToken);

      // Log GDPR request
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'CREATE',
          resourceType: 'DATA_EXPORT',
          resourceId: gdprRequest.id,
          details: {
            gdprType: request.type
          },
          ipAddress: 'system',
          userAgent: 'gdpr-service'
        }
      });

      // Set expiry for request
      await this.redis.setex(
        `gdpr:request:${gdprRequest.id}`,
        30 * 24 * 60 * 60, // 30 days
        JSON.stringify(gdprRequest)
      );

      return gdprRequest;
    });
  }

  async getGDPRRequests(
    tenantId: string,
    filters: { status?: string; type?: string }
  ): Promise<GDPRRequest[]> {
    const where: any = { tenantId };
    
    if (filters.status) where.status = filters.status;
    if (filters.type) where.type = filters.type;

    return this.prisma.gdprRequest.findMany({
      where,
      orderBy: { requestedAt: 'desc' }
    });
  }

  async getGDPRRequestById(
    tenantId: string,
    requestId: string
  ): Promise<GDPRRequest | null> {
    return this.prisma.gdprRequest.findFirst({
      where: {
        id: requestId,
        tenantId
      }
    });
  }

  async processGDPRRequest(
    tenantId: string,
    requestId: string,
    userId: string,
    processing: GDPRProcessInput
  ): Promise<GDPRRequest> {
    return telemetry.withSpan('gdprService.processRequest', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'gdpr.requestId': requestId,
        'gdpr.action': processing.action
      });

      const request = await this.getGDPRRequestById(tenantId, requestId);
      if (!request) {
        throw new Error('GDPR request not found');
      }

      let newStatus: GDPRRequestStatus;
      switch (processing.action) {
        case 'approve':
          newStatus = GDPRRequestStatus.IN_PROGRESS;
          break;
        case 'reject':
          newStatus = GDPRRequestStatus.REJECTED;
          break;
        case 'partial':
          newStatus = GDPRRequestStatus.PARTIALLY_COMPLETED;
          break;
        default:
          throw new Error('Invalid action');
      }

      // Update request status
      const updatedRequest = await this.prisma.gdprRequest.update({
        where: { id: requestId },
        data: {
          status: newStatus,
          processedAt: new Date(),
          processedBy: userId,
          response: processing.response as any
        }
      });

      // Process based on request type
      if (processing.action === 'approve') {
        switch (request.type) {
          case GDPRRequestType.ACCESS:
            await this.processAccessRequest(request);
            break;
          case GDPRRequestType.ERASURE:
            await this.processErasureRequest(request);
            break;
          case GDPRRequestType.PORTABILITY:
            await this.processPortabilityRequest(request);
            break;
          case GDPRRequestType.RECTIFICATION:
            await this.processRectificationRequest(request);
            break;
        }
      }

      // Log processing
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'UPDATE',
          resourceType: 'DATA_EXPORT',
          resourceId: requestId,
          details: {
            action: processing.action,
            previousStatus: request.status,
            newStatus
          },
          ipAddress: 'system',
          userAgent: 'gdpr-service'
        }
      });

      return updatedRequest;
    });
  }

  async exportUserData(
    tenantId: string,
    userId: string,
    format: 'json' | 'csv' | 'pdf'
  ): Promise<{ data: Buffer; format: string }> {
    return telemetry.withSpan('gdprService.exportUserData', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'user.id': userId,
        'export.format': format
      });

      // Collect all user data from various sources
      const userData = await this.collectUserData(tenantId, userId);

      // Generate export based on format
      let exportData: Buffer;
      switch (format) {
        case 'csv':
          exportData = await this.generateCSVExport(userData);
          break;
        case 'pdf':
          exportData = await this.generatePDFExport(userData);
          break;
        default:
          exportData = Buffer.from(JSON.stringify(userData, null, 2));
      }

      // Log data export
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId,
          action: 'EXPORT',
          resourceType: 'USER',
          resourceId: userId,
          details: {
            format,
            dataCategories: Object.keys(userData)
          },
          ipAddress: 'system',
          userAgent: 'gdpr-service'
        }
      });

      return { data: exportData, format };
    });
  }

  async deleteUserData(
    tenantId: string,
    userId: string,
    requesterId: string
  ): Promise<{
    recordsDeleted: number;
    servicesAffected: string[];
  }> {
    return telemetry.withSpan('gdprService.deleteUserData', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'user.id': userId
      });

      const servicesAffected: string[] = [];
      let recordsDeleted = 0;

      // Start transaction
      await this.prisma.$transaction(async (tx) => {
        // Delete from audit logs (anonymize instead of delete)
        const auditLogs = await tx.auditLog.updateMany({
          where: { userId, tenantId },
          data: {
            userId: null,
            details: {
              anonymized: true,
              anonymizedAt: new Date()
            }
          }
        });
        recordsDeleted += auditLogs.count;
        if (auditLogs.count > 0) servicesAffected.push('audit');

        // Delete from access logs
        const accessLogs = await tx.accessLog.deleteMany({
          where: { userId, tenantId }
        });
        recordsDeleted += accessLogs.count;
        if (accessLogs.count > 0) servicesAffected.push('access');

        // Delete from alerts
        const alerts = await tx.alert.deleteMany({
          where: { userId, tenantId }
        });
        recordsDeleted += alerts.count;
        if (alerts.count > 0) servicesAffected.push('alerts');

        // Mark user as deleted
        await tx.user.update({
          where: { id: userId },
          data: {
            deletedAt: new Date(),
            email: `deleted_${userId}@deleted.com`,
            name: 'Deleted User',
            personalData: null
          }
        });
      });

      // Clear from cache
      await this.clearUserFromCache(tenantId, userId);

      // Notify other services
      await this.notifyDataDeletion(tenantId, userId, servicesAffected);

      // Log deletion
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId: requesterId,
          action: 'DELETE',
          resourceType: 'USER',
          resourceId: userId,
          details: {
            recordsDeleted,
            servicesAffected
          },
          ipAddress: 'system',
          userAgent: 'gdpr-service'
        }
      });

      span.setAttributes({
        'deletion.records': recordsDeleted,
        'deletion.services': servicesAffected.length
      });

      return { recordsDeleted, servicesAffected };
    });
  }

  async rectifyUserData(
    tenantId: string,
    userId: string,
    updates: Record<string, any>,
    requesterId: string
  ): Promise<{ updated: boolean; fieldsUpdated: string[] }> {
    return telemetry.withSpan('gdprService.rectifyUserData', async (span) => {
      span.setAttributes({
        'tenant.id': tenantId,
        'user.id': userId,
        'rectification.fields': Object.keys(updates).length
      });

      const fieldsUpdated: string[] = [];

      // Update user data
      const allowedFields = ['name', 'email', 'phone', 'address'];
      const updateData: any = {};

      for (const [field, value] of Object.entries(updates)) {
        if (allowedFields.includes(field)) {
          updateData[field] = value;
          fieldsUpdated.push(field);
        }
      }

      if (Object.keys(updateData).length > 0) {
        await this.prisma.user.update({
          where: { id: userId },
          data: updateData
        });
      }

      // Log rectification
      await this.prisma.auditLog.create({
        data: {
          tenantId,
          userId: requesterId,
          action: 'UPDATE',
          resourceType: 'USER',
          resourceId: userId,
          details: {
            rectifiedFields: fieldsUpdated,
            updates: updateData
          },
          ipAddress: 'system',
          userAgent: 'gdpr-service'
        }
      });

      return {
        updated: fieldsUpdated.length > 0,
        fieldsUpdated
      };
    });
  }

  async generatePortableData(
    tenantId: string,
    userId: string
  ): Promise<any> {
    return telemetry.withSpan('gdprService.generatePortableData', async (span) => {
      span.setAttribute('tenant.id', tenantId);

      const userData = await this.collectUserData(tenantId, userId);

      // Format data for portability (machine-readable)
      const portableData = {
        version: '1.0',
        exportDate: new Date().toISOString(),
        dataSubject: {
          id: userId,
          tenantId
        },
        data: userData,
        metadata: {
          format: 'json',
          encoding: 'utf-8',
          compression: 'none'
        }
      };

      return portableData;
    });
  }

  async getUserConsent(
    tenantId: string,
    userId: string
  ): Promise<any> {
    const consent = await this.prisma.userConsent.findMany({
      where: {
        userId,
        tenantId
      },
      orderBy: { grantedAt: 'desc' }
    });

    return {
      userId,
      consents: consent,
      lastUpdated: consent[0]?.grantedAt || null
    };
  }

  async updateUserConsent(
    tenantId: string,
    userId: string,
    consentUpdates: Record<string, boolean>
  ): Promise<any> {
    const updates = [];

    for (const [purpose, granted] of Object.entries(consentUpdates)) {
      const consent = await this.prisma.userConsent.upsert({
        where: {
          userId_purpose: {
            userId,
            purpose
          }
        },
        update: {
          granted,
          grantedAt: granted ? new Date() : null,
          revokedAt: !granted ? new Date() : null
        },
        create: {
          userId,
          tenantId,
          purpose,
          granted,
          grantedAt: granted ? new Date() : null
        }
      });
      updates.push(consent);
    }

    // Log consent changes
    await this.prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: 'UPDATE',
        resourceType: 'USER',
        resourceId: userId,
        details: {
          consentUpdates
        },
        ipAddress: 'system',
        userAgent: 'gdpr-service'
      }
    });

    return { updated: updates };
  }

  async getGDPRDashboard(tenantId: string) {
    const [
      pendingRequests,
      completedRequests,
      dataExports,
      dataDeletions,
      consentStats
    ] = await Promise.all([
      this.prisma.gdprRequest.count({
        where: {
          tenantId,
          status: GDPRRequestStatus.PENDING
        }
      }),
      this.prisma.gdprRequest.count({
        where: {
          tenantId,
          status: GDPRRequestStatus.COMPLETED
        }
      }),
      this.prisma.gdprRequest.count({
        where: {
          tenantId,
          type: GDPRRequestType.ACCESS
        }
      }),
      this.prisma.gdprRequest.count({
        where: {
          tenantId,
          type: GDPRRequestType.ERASURE
        }
      }),
      this.getConsentStatistics(tenantId)
    ]);

    // Get request trends
    const requestTrends = await this.getGDPRRequestTrends(tenantId, 30);

    // Get average processing time
    const avgProcessingTime = await this.getAverageProcessingTime(tenantId);

    return {
      summary: {
        pendingRequests,
        completedRequests,
        dataExports,
        dataDeletions
      },
      consentStats,
      requestTrends,
      avgProcessingTime
    };
  }

  async verifyDataAccessPermission(
    tenantId: string,
    requesterId: string,
    targetUserId: string
  ): Promise<boolean> {
    // Check if requester has appropriate permissions
    const user = await this.prisma.user.findFirst({
      where: {
        id: requesterId,
        tenantId
      },
      include: {
        roles: {
          include: {
            permissions: true
          }
        }
      }
    });

    if (!user) return false;

    // Check for data protection officer role or admin permissions
    const hasPermission = user.roles.some(role =>
      role.permissions.some(permission =>
        permission.name === 'gdpr.access.all' ||
        permission.name === 'admin.full'
      )
    );

    return hasPermission;
  }

  async verifyDataDeletionPermission(
    tenantId: string,
    requesterId: string,
    targetUserId: string,
    confirmationToken: string
  ): Promise<boolean> {
    // Verify confirmation token
    const validToken = await this.redis.get(`gdpr:deletion:token:${targetUserId}`);
    if (validToken !== confirmationToken) {
      return false;
    }

    // Verify permissions
    return this.verifyDataAccessPermission(tenantId, requesterId, targetUserId);
  }

  private async collectUserData(
    tenantId: string,
    userId: string
  ): Promise<Record<string, any>> {
    const userData: Record<string, any> = {};

    // Collect personal information
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
        lastLoginAt: true,
        profile: true
      }
    });
    userData.personalInfo = user;

    // Collect access logs
    const accessLogs = await this.prisma.accessLog.findMany({
      where: { userId, tenantId },
      orderBy: { timestamp: 'desc' },
      take: 1000
    });
    userData.accessLogs = accessLogs;

    // Collect audit logs
    const auditLogs = await this.prisma.auditLog.findMany({
      where: { userId, tenantId },
      orderBy: { timestamp: 'desc' },
      take: 1000
    });
    userData.auditLogs = auditLogs;

    // Collect consents
    const consents = await this.prisma.userConsent.findMany({
      where: { userId, tenantId }
    });
    userData.consents = consents;

    // Collect from other services via API calls
    const additionalData = await this.collectFromOtherServices(tenantId, userId);
    Object.assign(userData, additionalData);

    return userData;
  }

  private async collectFromOtherServices(
    tenantId: string,
    userId: string
  ): Promise<Record<string, any>> {
    const data: Record<string, any> = {};

    // Call other microservices to collect data
    // This would involve HTTP/gRPC calls to other services
    // For now, returning mock data structure

    return data;
  }

  private async sendVerificationEmail(
    userId: string,
    verificationToken: string
  ): Promise<void> {
    // In production, send actual email
    // For now, log the token
    console.log(`Verification token for user ${userId}: ${verificationToken}`);
  }

  private async generateCSVExport(userData: any): Promise<Buffer> {
    // Convert userData to CSV format
    // This is a simplified implementation
    const csv = Object.entries(userData)
      .map(([key, value]) => `${key},${JSON.stringify(value)}`)
      .join('\n');

    return Buffer.from(csv);
  }

  private async generatePDFExport(userData: any): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument();
      const chunks: Buffer[] = [];

      doc.on('data', chunks.push.bind(chunks));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      // Add content
      doc.fontSize(20).text('Personal Data Export', 50, 50);
      doc.fontSize(12).text(`Export Date: ${new Date().toISOString()}`, 50, 80);
      
      doc.moveDown();

      // Add user data sections
      Object.entries(userData).forEach(([section, data], index) => {
        doc.fontSize(16).text(section, 50, 120 + (index * 100));
        doc.fontSize(10).text(JSON.stringify(data, null, 2), 70, 140 + (index * 100));
      });

      doc.end();
    });
  }

  private async clearUserFromCache(tenantId: string, userId: string): Promise<void> {
    const pattern = `*:${tenantId}:${userId}:*`;
    const keys = await this.redis.keys(pattern);
    
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
  }

  private async notifyDataDeletion(
    tenantId: string,
    userId: string,
    servicesAffected: string[]
  ): Promise<void> {
    // Publish deletion event to message queue
    await this.redis.publish('gdpr:user:deleted', JSON.stringify({
      tenantId,
      userId,
      servicesAffected,
      timestamp: new Date()
    }));
  }

  private async processAccessRequest(request: GDPRRequest): Promise<void> {
    // Generate data export
    const exportData = await this.exportUserData(
      request.tenantId,
      request.requesterId,
      'json'
    );

    // Store export for download
    const downloadKey = `gdpr:export:${request.id}`;
    await this.redis.setex(
      downloadKey,
      7 * 24 * 60 * 60, // 7 days
      exportData.data
    );

    // Update request with download link
    await this.prisma.gdprRequest.update({
      where: { id: request.id },
      data: {
        status: GDPRRequestStatus.COMPLETED,
        response: {
          downloadUrl: `/api/gdpr/download/${request.id}`,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }
      }
    });
  }

  private async processErasureRequest(request: GDPRRequest): Promise<void> {
    // Delete user data
    const result = await this.deleteUserData(
      request.tenantId,
      request.requesterId,
      request.processedBy!
    );

    // Update request with result
    await this.prisma.gdprRequest.update({
      where: { id: request.id },
      data: {
        status: GDPRRequestStatus.COMPLETED,
        response: result
      }
    });
  }

  private async processPortabilityRequest(request: GDPRRequest): Promise<void> {
    // Generate portable data
    const portableData = await this.generatePortableData(
      request.tenantId,
      request.requesterId
    );

    // Store for download
    const downloadKey = `gdpr:portable:${request.id}`;
    await this.redis.setex(
      downloadKey,
      7 * 24 * 60 * 60, // 7 days
      JSON.stringify(portableData)
    );

    // Update request
    await this.prisma.gdprRequest.update({
      where: { id: request.id },
      data: {
        status: GDPRRequestStatus.COMPLETED,
        response: {
          downloadUrl: `/api/gdpr/download/${request.id}`,
          format: 'json',
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }
      }
    });
  }

  private async processRectificationRequest(request: GDPRRequest): Promise<void> {
    // Apply rectifications
    const result = await this.rectifyUserData(
      request.tenantId,
      request.requesterId,
      request.details.updates || {},
      request.processedBy!
    );

    // Update request
    await this.prisma.gdprRequest.update({
      where: { id: request.id },
      data: {
        status: GDPRRequestStatus.COMPLETED,
        response: result
      }
    });
  }

  private async getConsentStatistics(tenantId: string) {
    const totalUsers = await this.prisma.user.count({
      where: { tenantId }
    });

    const consentedUsers = await this.prisma.userConsent.groupBy({
      by: ['userId'],
      where: {
        tenantId,
        granted: true
      },
      _count: true
    });

    return {
      totalUsers,
      consentedUsers: consentedUsers.length,
      consentRate: totalUsers > 0
        ? Math.round((consentedUsers.length / totalUsers) * 100)
        : 0
    };
  }

  private async getGDPRRequestTrends(tenantId: string, days: number) {
    const trends = [];
    const now = new Date();

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      
      const count = await this.prisma.gdprRequest.count({
        where: {
          tenantId,
          requestedAt: {
            gte: new Date(date.setHours(0, 0, 0, 0)),
            lt: new Date(date.setHours(23, 59, 59, 999))
          }
        }
      });

      trends.push({
        date: date.toISOString().split('T')[0],
        requests: count
      });
    }

    return trends;
  }

  private async getAverageProcessingTime(tenantId: string): Promise<number> {
    const completedRequests = await this.prisma.gdprRequest.findMany({
      where: {
        tenantId,
        status: GDPRRequestStatus.COMPLETED,
        processedAt: { not: null }
      }
    });

    if (completedRequests.length === 0) return 0;

    const totalTime = completedRequests.reduce((sum, req) => {
      const time = req.processedAt!.getTime() - req.requestedAt.getTime();
      return sum + time;
    }, 0);

    return Math.round(totalTime / completedRequests.length / (60 * 60 * 1000)); // Hours
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return true;
    } catch {
      return false;
    }
  }
}