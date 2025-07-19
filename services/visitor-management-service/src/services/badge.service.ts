import { eq, and } from 'drizzle-orm';
import QRCode from 'qrcode';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';
import sharp from 'sharp';
import { getDb } from '../db';
import { visitors } from '@sparc/database/schemas/visitor-management';
import { users } from '@sparc/database/schemas/user-management';
import { logger } from '@sparc/shared';
import type { BadgePrint, ServiceResponse } from '../types';

export interface BadgeData {
  visitorName: string;
  company?: string;
  hostName: string;
  validUntil: Date;
  template: string;
  photo?: string;
  accessAreas?: string[];
  requiresEscort: boolean;
  qrCode: string;
  badgeNumber: string;
  emergencyContact?: string;
}

export class BadgeService {
  private db = getDb();

  async generateBadge(
    data: BadgePrint,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse<{ badgeData: BadgeData; pdf: Buffer }>> {
    try {
      // Get visitor with host information
      const result = await this.db
        .select({
          visitor: visitors,
          host: {
            id: users.id,
            firstName: users.firstName,
            lastName: users.lastName,
          },
        })
        .from(visitors)
        .leftJoin(users, eq(visitors.hostUserId, users.id))
        .where(and(
          eq(visitors.id, data.visitorId),
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

      const visitor = result[0].visitor;
      const host = result[0].host;

      if (visitor.status !== 'CHECKED_IN' && visitor.status !== 'APPROVED') {
        return {
          success: false,
          error: {
            code: 'INVALID_STATUS',
            message: 'Visitor must be checked in or approved to print badge',
          },
        };
      }

      // Generate badge number if not exists
      const badgeNumber = visitor.badgeNumber || this.generateBadgeNumber();

      // Generate QR code data
      const qrData = {
        visitorId: visitor.id,
        badgeNumber,
        validUntil: data.validUntil || visitor.expectedDeparture,
        organizationId,
      };

      const qrCodeDataUrl = await this.generateQRCode(JSON.stringify(qrData));

      // Prepare badge data
      const badgeData: BadgeData = {
        visitorName: `${visitor.firstName} ${visitor.lastName}`,
        company: visitor.company || undefined,
        hostName: host ? `${host.firstName} ${host.lastName}` : 'Unknown',
        validUntil: data.validUntil ? new Date(data.validUntil) : new Date(visitor.expectedDeparture),
        template: data.template,
        photo: visitor.photo || undefined,
        accessAreas: visitor.accessAreas || [],
        requiresEscort: visitor.requiresEscort || false,
        qrCode: qrCodeDataUrl,
        badgeNumber,
        emergencyContact: visitor.emergencyContactPhone || undefined,
      };

      // Generate PDF badge
      const pdfBuffer = await this.generateBadgePDF(badgeData);

      // Update visitor record
      await this.db
        .update(visitors)
        .set({
          badgeNumber,
          badgeTemplate: data.template,
          badgePrintedAt: new Date(),
          badgePrintedBy: userId,
          updatedBy: userId,
          updatedAt: new Date(),
        })
        .where(eq(visitors.id, visitor.id));

      logger.info('Badge generated', {
        visitorId: visitor.id,
        organizationId,
        badgeNumber,
        template: data.template,
      });

      return {
        success: true,
        data: {
          badgeData,
          pdf: pdfBuffer,
        },
      };
    } catch (error) {
      logger.error('Failed to generate badge', { error, data });
      return {
        success: false,
        error: {
          code: 'BADGE_GENERATION_FAILED',
          message: 'Failed to generate badge',
        },
      };
    }
  }

  private async generateBadgePDF(data: BadgeData): Promise<Buffer> {
    // Create a new PDF document
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([300, 450]); // Badge size: 3" x 4.5"

    const { width, height } = page.getSize();
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

    // Template-specific styling
    const templateColors = {
      STANDARD: { primary: rgb(0.2, 0.4, 0.8), secondary: rgb(0.8, 0.8, 0.8) },
      CONTRACTOR: { primary: rgb(0.8, 0.4, 0), secondary: rgb(1, 0.8, 0.4) },
      VIP: { primary: rgb(0.5, 0, 0.5), secondary: rgb(0.9, 0.7, 0.9) },
      ESCORT_REQUIRED: { primary: rgb(0.8, 0, 0), secondary: rgb(1, 0.8, 0.8) },
      TEMPORARY: { primary: rgb(0, 0.6, 0), secondary: rgb(0.8, 1, 0.8) },
      EVENT: { primary: rgb(0, 0.6, 0.8), secondary: rgb(0.8, 0.9, 1) },
    };

    const colors = templateColors[data.template as keyof typeof templateColors] || templateColors.STANDARD;

    // Draw header background
    page.drawRectangle({
      x: 0,
      y: height - 80,
      width,
      height: 80,
      color: colors.primary,
    });

    // Add VISITOR text
    page.drawText('VISITOR', {
      x: 20,
      y: height - 40,
      size: 24,
      font: boldFont,
      color: rgb(1, 1, 1),
    });

    // Add template badge
    if (data.template !== 'STANDARD') {
      const templateText = data.template.replace('_', ' ');
      const textWidth = font.widthOfTextAtSize(templateText, 10);
      page.drawRectangle({
        x: width - textWidth - 30,
        y: height - 50,
        width: textWidth + 20,
        height: 25,
        color: colors.secondary,
      });
      page.drawText(templateText, {
        x: width - textWidth - 20,
        y: height - 40,
        size: 10,
        font: boldFont,
        color: colors.primary,
      });
    }

    // Add photo placeholder or actual photo
    const photoY = height - 180;
    if (data.photo) {
      try {
        // Process base64 photo
        const photoBuffer = Buffer.from(data.photo.replace(/^data:image\/\w+;base64,/, ''), 'base64');
        const resizedPhoto = await sharp(photoBuffer)
          .resize(120, 150, { fit: 'cover' })
          .toBuffer();
        
        const pdfImage = await pdfDoc.embedPng(resizedPhoto);
        page.drawImage(pdfImage, {
          x: (width - 120) / 2,
          y: photoY,
          width: 120,
          height: 150,
        });
      } catch (error) {
        // Draw photo placeholder on error
        page.drawRectangle({
          x: (width - 120) / 2,
          y: photoY,
          width: 120,
          height: 150,
          color: rgb(0.9, 0.9, 0.9),
          borderColor: rgb(0.5, 0.5, 0.5),
          borderWidth: 1,
        });
        page.drawText('PHOTO', {
          x: (width - 40) / 2,
          y: photoY + 65,
          size: 14,
          font,
          color: rgb(0.5, 0.5, 0.5),
        });
      }
    } else {
      // Draw photo placeholder
      page.drawRectangle({
        x: (width - 120) / 2,
        y: photoY,
        width: 120,
        height: 150,
        color: rgb(0.9, 0.9, 0.9),
        borderColor: rgb(0.5, 0.5, 0.5),
        borderWidth: 1,
      });
      page.drawText('NO PHOTO', {
        x: (width - 55) / 2,
        y: photoY + 65,
        size: 14,
        font,
        color: rgb(0.5, 0.5, 0.5),
      });
    }

    // Add visitor name
    const nameY = photoY - 30;
    const nameSize = 18;
    const nameWidth = boldFont.widthOfTextAtSize(data.visitorName, nameSize);
    page.drawText(data.visitorName, {
      x: (width - nameWidth) / 2,
      y: nameY,
      size: nameSize,
      font: boldFont,
      color: rgb(0, 0, 0),
    });

    // Add company
    if (data.company) {
      const companyY = nameY - 20;
      const companySize = 14;
      const companyWidth = font.widthOfTextAtSize(data.company, companySize);
      page.drawText(data.company, {
        x: (width - companyWidth) / 2,
        y: companyY,
        size: companySize,
        font,
        color: rgb(0.3, 0.3, 0.3),
      });
    }

    // Add host information
    const hostY = data.company ? nameY - 50 : nameY - 30;
    page.drawText('HOST:', {
      x: 20,
      y: hostY,
      size: 10,
      font,
      color: rgb(0.5, 0.5, 0.5),
    });
    page.drawText(data.hostName, {
      x: 60,
      y: hostY,
      size: 12,
      font: boldFont,
      color: rgb(0, 0, 0),
    });

    // Add QR code
    const qrY = 20;
    try {
      const qrBuffer = Buffer.from(data.qrCode.replace(/^data:image\/png;base64,/, ''), 'base64');
      const qrImage = await pdfDoc.embedPng(qrBuffer);
      page.drawImage(qrImage, {
        x: 20,
        y: qrY,
        width: 80,
        height: 80,
      });
    } catch (error) {
      // Draw QR placeholder on error
      page.drawRectangle({
        x: 20,
        y: qrY,
        width: 80,
        height: 80,
        color: rgb(0.9, 0.9, 0.9),
        borderColor: rgb(0.5, 0.5, 0.5),
        borderWidth: 1,
      });
    }

    // Add badge number and validity
    const infoX = 120;
    page.drawText(`Badge #: ${data.badgeNumber}`, {
      x: infoX,
      y: qrY + 60,
      size: 10,
      font,
      color: rgb(0, 0, 0),
    });

    page.drawText(`Valid Until:`, {
      x: infoX,
      y: qrY + 40,
      size: 10,
      font,
      color: rgb(0, 0, 0),
    });

    page.drawText(data.validUntil.toLocaleDateString(), {
      x: infoX,
      y: qrY + 25,
      size: 10,
      font: boldFont,
      color: rgb(0, 0, 0),
    });

    // Add escort required notice
    if (data.requiresEscort) {
      page.drawRectangle({
        x: infoX,
        y: qrY,
        width: width - infoX - 20,
        height: 20,
        color: rgb(1, 0, 0),
      });
      page.drawText('ESCORT REQUIRED', {
        x: infoX + 5,
        y: qrY + 5,
        size: 10,
        font: boldFont,
        color: rgb(1, 1, 1),
      });
    }

    // Add footer
    page.drawLine({
      start: { x: 10, y: 10 },
      end: { x: width - 10, y: 10 },
      thickness: 0.5,
      color: rgb(0.5, 0.5, 0.5),
    });

    page.drawText('Report suspicious activity to security', {
      x: 20,
      y: 2,
      size: 6,
      font,
      color: rgb(0.5, 0.5, 0.5),
    });

    // Serialize the PDF to bytes
    const pdfBytes = await pdfDoc.save();
    return Buffer.from(pdfBytes);
  }

  private async generateQRCode(data: string): Promise<string> {
    return await QRCode.toDataURL(data, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 200,
      color: {
        dark: '#000000',
        light: '#FFFFFF',
      },
    });
  }

  private generateBadgeNumber(): string {
    const prefix = 'V';
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = Math.random().toString(36).substring(2, 6).toUpperCase();
    return `${prefix}-${timestamp}-${random}`;
  }

  async reprintBadge(
    visitorId: string,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse<{ badgeData: BadgeData; pdf: Buffer }>> {
    try {
      // Get visitor information
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

      if (!visitor.badgeNumber || !visitor.badgeTemplate) {
        return {
          success: false,
          error: {
            code: 'NO_BADGE_HISTORY',
            message: 'No badge has been printed for this visitor',
          },
        };
      }

      // Use existing badge template and generate with same data
      return await this.generateBadge(
        {
          visitorId,
          template: visitor.badgeTemplate,
          validUntil: visitor.expectedDeparture.toISOString(),
        },
        organizationId,
        userId
      );
    } catch (error) {
      logger.error('Failed to reprint badge', { error, visitorId });
      return {
        success: false,
        error: {
          code: 'REPRINT_FAILED',
          message: 'Failed to reprint badge',
        },
      };
    }
  }
}