import { PrismaClient } from '@prisma/client';
import PDFDocument from 'pdfkit';
import { Parser } from 'json2csv';
import * as XLSX from 'xlsx';
import Handlebars from 'handlebars';
import { ChartJSNodeCanvas } from 'chartjs-node-canvas';
import { ReportingServiceConfig } from '../config';
import { ReportType, ExportFormat, ReportParameters } from '../types';
import { logger } from '../utils/logger';
import { createTracer } from '../utils/telemetry';

const tracer = createTracer('report-generator-service');

export interface FormattedReport {
  data: Buffer;
  mimeType: string;
  filename: string;
  pageCount?: number;
}

export class ReportGeneratorService {
  private chartRenderer: ChartJSNodeCanvas;

  constructor(
    private prisma: PrismaClient,
    private config: ReportingServiceConfig
  ) {
    // Initialize chart renderer for reports with charts
    this.chartRenderer = new ChartJSNodeCanvas({
      width: 800,
      height: 600,
      backgroundColour: 'white'
    });
  }

  async generateReport(
    type: ReportType,
    parameters: ReportParameters,
    tenantId: string,
    progressCallback?: (progress: number) => void
  ): Promise<any[]> {
    return tracer.startActiveSpan('generate-report', async (span) => {
      try {
        span.setAttributes({
          'report.type': type,
          'report.tenant_id': tenantId,
          'report.date_range': `${parameters.startDate.toISOString()} - ${parameters.endDate.toISOString()}`
        });

        let data: any[] = [];

        switch (type) {
          case 'access_events':
            data = await this.generateAccessEventsReport(parameters, tenantId, progressCallback);
            break;
          case 'user_activity':
            data = await this.generateUserActivityReport(parameters, tenantId, progressCallback);
            break;
          case 'door_status':
            data = await this.generateDoorStatusReport(parameters, tenantId, progressCallback);
            break;
          case 'video_events':
            data = await this.generateVideoEventsReport(parameters, tenantId, progressCallback);
            break;
          case 'audit_log':
            data = await this.generateAuditLogReport(parameters, tenantId, progressCallback);
            break;
          case 'system_health':
            data = await this.generateSystemHealthReport(parameters, tenantId, progressCallback);
            break;
          case 'environmental':
            data = await this.generateEnvironmentalReport(parameters, tenantId, progressCallback);
            break;
          case 'visitor_log':
            data = await this.generateVisitorLogReport(parameters, tenantId, progressCallback);
            break;
          case 'incident_report':
            data = await this.generateIncidentReport(parameters, tenantId, progressCallback);
            break;
          case 'security_assessment':
            data = await this.generateSecurityAssessmentReport(parameters, tenantId, progressCallback);
            break;
          case 'device_inventory':
            data = await this.generateDeviceInventoryReport(parameters, tenantId, progressCallback);
            break;
          case 'alarm_history':
            data = await this.generateAlarmHistoryReport(parameters, tenantId, progressCallback);
            break;
          case 'badge_audit':
            data = await this.generateBadgeAuditReport(parameters, tenantId, progressCallback);
            break;
          case 'time_attendance':
            data = await this.generateTimeAttendanceReport(parameters, tenantId, progressCallback);
            break;
          case 'occupancy_analytics':
            data = await this.generateOccupancyAnalyticsReport(parameters, tenantId, progressCallback);
            break;
          case 'energy_usage':
            data = await this.generateEnergyUsageReport(parameters, tenantId, progressCallback);
            break;
          case 'maintenance_log':
            data = await this.generateMaintenanceLogReport(parameters, tenantId, progressCallback);
            break;
          default:
            throw new Error(`Unsupported report type: ${type}`);
        }

        span.setAttributes({ 'report.record_count': data.length });
        return data;
      } finally {
        span.end();
      }
    });
  }

  async formatReport(
    data: any[],
    format: ExportFormat,
    type: ReportType,
    parameters: ReportParameters
  ): Promise<FormattedReport> {
    switch (format) {
      case 'json':
        return this.formatJSON(data);
      case 'csv':
        return this.formatCSV(data);
      case 'xlsx':
        return this.formatXLSX(data, type);
      case 'pdf':
        return this.formatPDF(data, type, parameters);
      case 'html':
        return this.formatHTML(data, type, parameters);
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  private formatJSON(data: any[]): FormattedReport {
    const json = JSON.stringify(data, null, 2);
    return {
      data: Buffer.from(json),
      mimeType: 'application/json',
      filename: 'report.json'
    };
  }

  private formatCSV(data: any[]): FormattedReport {
    if (data.length === 0) {
      return {
        data: Buffer.from(''),
        mimeType: 'text/csv',
        filename: 'report.csv'
      };
    }

    const parser = new Parser({
      fields: Object.keys(data[0])
    });
    const csv = parser.parse(data);

    return {
      data: Buffer.from(csv),
      mimeType: 'text/csv',
      filename: 'report.csv'
    };
  }

  private formatXLSX(data: any[], type: ReportType): FormattedReport {
    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.json_to_sheet(data);
    
    // Add formatting
    const range = XLSX.utils.decode_range(worksheet['!ref'] || 'A1');
    for (let C = range.s.c; C <= range.e.c; ++C) {
      const address = XLSX.utils.encode_col(C) + '1';
      if (!worksheet[address]) continue;
      worksheet[address].s = {
        font: { bold: true },
        fill: { fgColor: { rgb: '4472C4' } },
        alignment: { horizontal: 'center' }
      };
    }

    XLSX.utils.book_append_sheet(workbook, worksheet, type.replace(/_/g, ' '));
    
    const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

    return {
      data: buffer,
      mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      filename: 'report.xlsx'
    };
  }

  private async formatPDF(
    data: any[],
    type: ReportType,
    parameters: ReportParameters
  ): Promise<FormattedReport> {
    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({
        size: 'A4',
        margin: 50,
        info: {
          Title: `${type.replace(/_/g, ' ').toUpperCase()} Report`,
          Author: 'SPARC Reporting System',
          Subject: `Report generated on ${new Date().toISOString()}`
        }
      });

      const chunks: Buffer[] = [];
      doc.on('data', chunk => chunks.push(chunk));
      doc.on('end', () => {
        const pdfData = Buffer.concat(chunks);
        resolve({
          data: pdfData,
          mimeType: 'application/pdf',
          filename: 'report.pdf',
          pageCount: doc.bufferedPageRange().count
        });
      });
      doc.on('error', reject);

      // Generate PDF content
      this.generatePDFContent(doc, data, type, parameters);
      
      doc.end();
    });
  }

  private async formatHTML(
    data: any[],
    type: ReportType,
    parameters: ReportParameters
  ): Promise<FormattedReport> {
    const template = this.getHTMLTemplate(type);
    const compiled = Handlebars.compile(template);
    
    const html = compiled({
      title: type.replace(/_/g, ' ').toUpperCase(),
      generatedAt: new Date().toISOString(),
      startDate: parameters.startDate,
      endDate: parameters.endDate,
      recordCount: data.length,
      data: data,
      summary: this.generateReportSummary(data, type)
    });

    return {
      data: Buffer.from(html),
      mimeType: 'text/html',
      filename: 'report.html'
    };
  }

  private generatePDFContent(
    doc: PDFKit.PDFDocument,
    data: any[],
    type: ReportType,
    parameters: ReportParameters
  ): void {
    // Header
    doc.fontSize(20)
       .font('Helvetica-Bold')
       .text(type.replace(/_/g, ' ').toUpperCase() + ' REPORT', { align: 'center' });
    
    doc.fontSize(12)
       .font('Helvetica')
       .text(`Generated: ${new Date().toLocaleDateString()}`, { align: 'center' })
       .moveDown();

    // Report period
    doc.fontSize(10)
       .text(`Period: ${parameters.startDate.toLocaleDateString()} - ${parameters.endDate.toLocaleDateString()}`)
       .text(`Total Records: ${data.length}`)
       .moveDown();

    // Summary section
    const summary = this.generateReportSummary(data, type);
    if (summary) {
      doc.fontSize(14)
         .font('Helvetica-Bold')
         .text('Summary', { underline: true })
         .font('Helvetica')
         .fontSize(10)
         .moveDown(0.5);

      for (const [key, value] of Object.entries(summary)) {
        doc.text(`${key}: ${value}`);
      }
      doc.moveDown();
    }

    // Data table (limited to first 100 records for PDF)
    if (data.length > 0) {
      doc.addPage();
      doc.fontSize(14)
         .font('Helvetica-Bold')
         .text('Detailed Records', { underline: true })
         .font('Helvetica')
         .fontSize(8)
         .moveDown(0.5);

      // Create table
      const recordsToShow = Math.min(data.length, 100);
      const fields = Object.keys(data[0]).slice(0, 5); // Limit columns
      
      // Table header
      let x = doc.x;
      const columnWidth = 100;
      
      fields.forEach(field => {
        doc.text(field, x, doc.y, { width: columnWidth, align: 'left' });
        x += columnWidth;
      });
      doc.moveDown();

      // Table rows
      for (let i = 0; i < recordsToShow; i++) {
        x = 50;
        fields.forEach(field => {
          const value = String(data[i][field] || '');
          doc.text(value.substring(0, 15), x, doc.y, { width: columnWidth, align: 'left' });
          x += columnWidth;
        });
        doc.moveDown(0.5);

        // Check if we need a new page
        if (doc.y > 700) {
          doc.addPage();
        }
      }

      if (data.length > recordsToShow) {
        doc.moveDown()
           .fontSize(10)
           .text(`... and ${data.length - recordsToShow} more records`, { align: 'center' });
      }
    }

    // Footer
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      doc.fontSize(8)
         .text(
           `Page ${i + 1} of ${pages.count}`,
           50,
           doc.page.height - 50,
           { align: 'center' }
         );
    }
  }

  private generateReportSummary(data: any[], type: ReportType): Record<string, any> {
    switch (type) {
      case 'access_events':
        return {
          'Total Events': data.length,
          'Successful': data.filter(d => d.success).length,
          'Failed': data.filter(d => !d.success).length,
          'Unique Users': new Set(data.map(d => d.userId)).size,
          'Unique Doors': new Set(data.map(d => d.doorId)).size
        };
      
      case 'user_activity':
        return {
          'Total Users': data.length,
          'Active Users': data.filter(d => d.lastActivity).length,
          'Average Events per User': Math.round(data.reduce((sum, d) => sum + (d.eventCount || 0), 0) / data.length)
        };
      
      case 'system_health':
        return {
          'Total Systems': data.length,
          'Healthy': data.filter(d => d.status === 'healthy').length,
          'Warning': data.filter(d => d.status === 'warning').length,
          'Critical': data.filter(d => d.status === 'critical').length,
          'Average Uptime': Math.round(data.reduce((sum, d) => sum + (d.uptime || 0), 0) / data.length) + '%'
        };
      
      default:
        return {
          'Total Records': data.length
        };
    }
  }

  private getHTMLTemplate(type: ReportType): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{title}} Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .meta { color: #666; margin-bottom: 20px; }
        .summary { background: #f5f5f5; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4472C4; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .footer { margin-top: 30px; text-align: center; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <h1>{{title}} Report</h1>
    <div class="meta">
        <p>Generated: {{generatedAt}}</p>
        <p>Period: {{startDate}} - {{endDate}}</p>
        <p>Total Records: {{recordCount}}</p>
    </div>
    
    {{#if summary}}
    <div class="summary">
        <h2>Summary</h2>
        {{#each summary}}
        <p><strong>{{@key}}:</strong> {{this}}</p>
        {{/each}}
    </div>
    {{/if}}
    
    <table>
        <thead>
            <tr>
                {{#each data.[0]}}
                <th>{{@key}}</th>
                {{/each}}
            </tr>
        </thead>
        <tbody>
            {{#each data}}
            <tr>
                {{#each this}}
                <td>{{this}}</td>
                {{/each}}
            </tr>
            {{/each}}
        </tbody>
    </table>
    
    <div class="footer">
        <p>Generated by SPARC Reporting System</p>
    </div>
</body>
</html>
    `;
  }

  // Report generation methods
  private async generateAccessEventsReport(
    parameters: ReportParameters,
    tenantId: string,
    progressCallback?: (progress: number) => void
  ): Promise<any[]> {
    progressCallback?.(10);

    const events = await this.prisma.accessEvent.findMany({
      where: {
        tenantId,
        timestamp: {
          gte: parameters.startDate,
          lte: parameters.endDate
        },
        ...parameters.filters
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        door: {
          select: {
            id: true,
            name: true,
            location: true
          }
        }
      },
      orderBy: parameters.sortBy ? {
        [parameters.sortBy]: parameters.sortOrder || 'desc'
      } : { timestamp: 'desc' },
      take: parameters.limit,
      skip: parameters.offset
    });

    progressCallback?.(50);

    // Transform data
    const transformed = events.map(event => ({
      id: event.id,
      timestamp: event.timestamp,
      userName: `${event.user.firstName} ${event.user.lastName}`,
      userEmail: event.user.email,
      doorName: event.door.name,
      doorLocation: event.door.location,
      eventType: event.eventType,
      success: event.success,
      failureReason: event.failureReason,
      ...(parameters.includeDetails && event.metadata ? { details: event.metadata } : {})
    }));

    progressCallback?.(100);
    return transformed;
  }

  private async generateUserActivityReport(
    parameters: ReportParameters,
    tenantId: string,
    progressCallback?: (progress: number) => void
  ): Promise<any[]> {
    progressCallback?.(10);

    const users = await this.prisma.user.findMany({
      where: {
        tenantId,
        ...parameters.filters
      },
      include: {
        accessEvents: {
          where: {
            timestamp: {
              gte: parameters.startDate,
              lte: parameters.endDate
            }
          },
          select: {
            id: true,
            timestamp: true,
            eventType: true,
            success: true
          }
        },
        _count: {
          select: {
            accessEvents: {
              where: {
                timestamp: {
                  gte: parameters.startDate,
                  lte: parameters.endDate
                }
              }
            }
          }
        }
      },
      take: parameters.limit,
      skip: parameters.offset
    });

    progressCallback?.(50);

    const transformed = users.map(user => ({
      id: user.id,
      name: `${user.firstName} ${user.lastName}`,
      email: user.email,
      department: user.department,
      role: user.role,
      status: user.status,
      eventCount: user._count.accessEvents,
      lastActivity: user.accessEvents[0]?.timestamp,
      successfulEvents: user.accessEvents.filter(e => e.success).length,
      failedEvents: user.accessEvents.filter(e => !e.success).length,
      ...(parameters.includeDetails ? {
        recentEvents: user.accessEvents.slice(0, 10)
      } : {})
    }));

    progressCallback?.(100);
    return transformed;
  }

  private async generateDoorStatusReport(
    parameters: ReportParameters,
    tenantId: string,
    progressCallback?: (progress: number) => void
  ): Promise<any[]> {
    progressCallback?.(10);

    const doors = await this.prisma.door.findMany({
      where: {
        tenantId,
        ...parameters.filters
      },
      include: {
        _count: {
          select: {
            accessEvents: {
              where: {
                timestamp: {
                  gte: parameters.startDate,
                  lte: parameters.endDate
                }
              }
            }
          }
        },
        accessEvents: {
          where: {
            timestamp: {
              gte: parameters.startDate,
              lte: parameters.endDate
            }
          },
          orderBy: { timestamp: 'desc' },
          take: 10
        }
      }
    });

    progressCallback?.(50);

    const transformed = doors.map(door => ({
      id: door.id,
      name: door.name,
      location: door.location,
      status: door.status,
      online: door.online,
      locked: door.locked,
      totalEvents: door._count.accessEvents,
      lastAccess: door.accessEvents[0]?.timestamp,
      ...(parameters.includeDetails ? {
        recentEvents: door.accessEvents,
        configuration: door.configuration
      } : {})
    }));

    progressCallback?.(100);
    return transformed;
  }

  private async generateVideoEventsReport(
    parameters: ReportParameters,
    tenantId: string,
    progressCallback?: (progress: number) => void
  ): Promise<any[]> {
    progressCallback?.(10);

    const events = await this.prisma.videoEvent.findMany({
      where: {
        tenantId,
        timestamp: {
          gte: parameters.startDate,
          lte: parameters.endDate
        },
        ...parameters.filters
      },
      include: {
        camera: {
          select: {
            id: true,
            name: true,
            location: true
          }
        }
      },
      orderBy: { timestamp: 'desc' },
      take: parameters.limit,
      skip: parameters.offset
    });

    progressCallback?.(50);

    const transformed = events.map(event => ({
      id: event.id,
      timestamp: event.timestamp,
      cameraName: event.camera.name,
      cameraLocation: event.camera.location,
      eventType: event.eventType,
      severity: event.severity,
      description: event.description,
      hasVideo: event.videoUrl !== null,
      ...(parameters.includeDetails && event.metadata ? {
        metadata: event.metadata,
        videoUrl: event.videoUrl
      } : {})
    }));

    progressCallback?.(100);
    return transformed;
  }

  private async generateAuditLogReport(
    parameters: ReportParameters,
    tenantId: string,
    progressCallback?: (progress: number) => void
  ): Promise<any[]> {
    progressCallback?.(10);

    const logs = await this.prisma.auditLog.findMany({
      where: {
        tenantId,
        timestamp: {
          gte: parameters.startDate,
          lte: parameters.endDate
        },
        ...parameters.filters
      },
      include: {
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        }
      },
      orderBy: { timestamp: 'desc' },
      take: parameters.limit,
      skip: parameters.offset
    });

    progressCallback?.(50);

    const transformed = logs.map(log => ({
      id: log.id,
      timestamp: log.timestamp,
      userName: log.user ? `${log.user.firstName} ${log.user.lastName}` : 'System',
      userEmail: log.user?.email,
      action: log.action,
      resource: log.resource,
      resourceId: log.resourceId,
      success: log.success,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      ...(parameters.includeDetails ? {
        changes: log.changes,
        metadata: log.metadata
      } : {})
    }));

    progressCallback?.(100);
    return transformed;
  }

  // Placeholder methods for other report types
  private async generateSystemHealthReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch system health metrics
    return [];
  }

  private async generateEnvironmentalReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch environmental sensor data
    return [];
  }

  private async generateVisitorLogReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch visitor management data
    return [];
  }

  private async generateIncidentReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch incident data
    return [];
  }

  private async generateSecurityAssessmentReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would generate security assessment
    return [];
  }

  private async generateDeviceInventoryReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch device inventory
    return [];
  }

  private async generateAlarmHistoryReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch alarm history
    return [];
  }

  private async generateBadgeAuditReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch badge audit data
    return [];
  }

  private async generateTimeAttendanceReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would generate time & attendance report
    return [];
  }

  private async generateOccupancyAnalyticsReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would generate occupancy analytics
    return [];
  }

  private async generateEnergyUsageReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch energy usage data
    return [];
  }

  private async generateMaintenanceLogReport(parameters: ReportParameters, tenantId: string, progressCallback?: (progress: number) => void): Promise<any[]> {
    // Implementation would fetch maintenance logs
    return [];
  }
}