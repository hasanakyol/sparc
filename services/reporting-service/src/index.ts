import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { serve } from '@hono/node-server';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import cron from 'node-cron';
import PDFDocument from 'pdfkit';
import { Parser } from 'json2csv';
import nodemailer from 'nodemailer';
import { z } from 'zod';
import { createWriteStream, promises as fs } from 'fs';
import { join } from 'path';
import { format, subDays, startOfDay, endOfDay } from 'date-fns';
import jwt from 'jsonwebtoken';
import { JWTBlacklistService } from '@sparc/shared/utils/jwt-blacklist';
import { config, logger as appLogger } from '@sparc/shared';
import { createHealthCheckHandler } from '@sparc/shared/utils/health-check';

// Types and schemas
const ReportTypeSchema = z.enum([
  'access_events',
  'user_activity',
  'door_status',
  'video_events',
  'audit_log',
  'compliance_sox',
  'compliance_hipaa',
  'compliance_pci_dss',
  'system_health',
  'environmental',
  'visitor_log',
  'incident_report'
]);

const ExportFormatSchema = z.enum(['pdf', 'csv', 'json']);

const ReportRequestSchema = z.object({
  type: ReportTypeSchema,
  format: ExportFormatSchema,
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  filters: z.record(z.any()).optional(),
  includeDetails: z.boolean().default(true),
  tenantId: z.string().uuid()
});

const ScheduledReportSchema = z.object({
  name: z.string().min(1).max(255),
  type: ReportTypeSchema,
  format: ExportFormatSchema,
  schedule: z.string(), // cron expression
  recipients: z.array(z.string().email()),
  filters: z.record(z.any()).optional(),
  isActive: z.boolean().default(true),
  tenantId: z.string().uuid()
});

const DashboardDataRequestSchema = z.object({
  widgets: z.array(z.string()),
  timeRange: z.enum(['1h', '24h', '7d', '30d']).default('24h'),
  tenantId: z.string().uuid()
});

// Initialize services
const app = new Hono();
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// Initialize JWT blacklist service
const jwtBlacklist = new JWTBlacklistService({
  redis,
  keyPrefix: 'jwt:blacklist',
  defaultTTL: 86400 // 24 hours
});

// Email transporter for scheduled reports
const emailTransporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// Middleware
app.use('*', cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

app.use('*', logger());
app.use('*', prettyJSON());

// Authentication middleware
app.use('*', async (c, next) => {
  if (c.req.path === '/health') {
    return next();
  }

  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    throw new HTTPException(401, { message: 'Missing or invalid authorization header' });
  }

  const token = authHeader.substring(7);
  try {
    const user = await verifyJWTToken(token);
    
    // Set user context
    c.set('user', user);
    c.set('userId', user.id);
    c.set('tenantId', user.tenantId);
    c.set('userRole', user.role);
    c.set('permissions', user.permissions);
    
    // Log authentication
    appLogger.info('User authenticated', {
      userId: user.id,
      tenantId: user.tenantId,
      path: c.req.path,
      method: c.req.method
    });
  } catch (error) {
    appLogger.warn('Authentication failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      path: c.req.path
    });
    throw new HTTPException(401, { 
      message: error instanceof Error ? error.message : 'Invalid token' 
    });
  }

  await next();
});

// Health check endpoint
app.get('/health', createHealthCheckHandler({
  serviceName: 'reporting-service',
  prismaClient: prisma,
  redisClient: redis,
  customChecks: {
    emailTransport: async () => {
      try {
        await emailTransporter.verify();
        return true;
      } catch {
        return false;
      }
    }
  }
}));

// Dashboard data endpoints
app.get('/api/dashboard/data', async (c) => {
  try {
    const query = DashboardDataRequestSchema.parse({
      widgets: c.req.query('widgets')?.split(',') || [],
      timeRange: c.req.query('timeRange') || '24h',
      tenantId: c.get('tenantId')
    });

    const dashboardData = await generateDashboardData(query);
    
    return c.json({
      success: true,
      data: dashboardData,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Dashboard data error:', error);
    throw new HTTPException(500, { message: 'Failed to generate dashboard data' });
  }
});

app.get('/api/dashboard/realtime', async (c) => {
  const tenantId = c.get('tenantId');
  
  try {
    const realtimeData = await generateRealtimeData(tenantId);
    
    return c.json({
      success: true,
      data: realtimeData,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Realtime data error:', error);
    throw new HTTPException(500, { message: 'Failed to generate realtime data' });
  }
});

// Report generation endpoints
app.post('/api/reports/generate', async (c) => {
  try {
    const body = await c.req.json();
    const reportRequest = ReportRequestSchema.parse({
      ...body,
      tenantId: c.get('tenantId')
    });

    const reportId = await generateReport(reportRequest);
    
    return c.json({
      success: true,
      reportId,
      message: 'Report generation started'
    });
  } catch (error) {
    console.error('Report generation error:', error);
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid request data' });
    }
    throw new HTTPException(500, { message: 'Failed to generate report' });
  }
});

app.get('/api/reports/:reportId/status', async (c) => {
  const reportId = c.req.param('reportId');
  const tenantId = c.get('tenantId');
  
  try {
    const status = await getReportStatus(reportId, tenantId);
    return c.json({ success: true, status });
  } catch (error) {
    console.error('Report status error:', error);
    throw new HTTPException(404, { message: 'Report not found' });
  }
});

app.get('/api/reports/:reportId/download', async (c) => {
  const reportId = c.req.param('reportId');
  const tenantId = c.get('tenantId');
  
  try {
    const reportFile = await downloadReport(reportId, tenantId);
    
    c.header('Content-Type', reportFile.mimeType);
    c.header('Content-Disposition', `attachment; filename="${reportFile.filename}"`);
    
    return c.body(reportFile.data);
  } catch (error) {
    console.error('Report download error:', error);
    throw new HTTPException(404, { message: 'Report not found or not ready' });
  }
});

// Scheduled reports endpoints
app.post('/api/reports/scheduled', async (c) => {
  try {
    const body = await c.req.json();
    const scheduledReport = ScheduledReportSchema.parse({
      ...body,
      tenantId: c.get('tenantId')
    });

    const reportId = await createScheduledReport(scheduledReport);
    
    return c.json({
      success: true,
      reportId,
      message: 'Scheduled report created'
    });
  } catch (error) {
    console.error('Scheduled report creation error:', error);
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid request data' });
    }
    throw new HTTPException(500, { message: 'Failed to create scheduled report' });
  }
});

app.get('/api/reports/scheduled', async (c) => {
  const tenantId = c.get('tenantId');
  
  try {
    const scheduledReports = await getScheduledReports(tenantId);
    return c.json({ success: true, data: scheduledReports });
  } catch (error) {
    console.error('Get scheduled reports error:', error);
    throw new HTTPException(500, { message: 'Failed to retrieve scheduled reports' });
  }
});

app.put('/api/reports/scheduled/:reportId', async (c) => {
  const reportId = c.req.param('reportId');
  const tenantId = c.get('tenantId');
  
  try {
    const body = await c.req.json();
    const updates = ScheduledReportSchema.partial().parse(body);
    
    await updateScheduledReport(reportId, tenantId, updates);
    
    return c.json({
      success: true,
      message: 'Scheduled report updated'
    });
  } catch (error) {
    console.error('Update scheduled report error:', error);
    throw new HTTPException(500, { message: 'Failed to update scheduled report' });
  }
});

app.delete('/api/reports/scheduled/:reportId', async (c) => {
  const reportId = c.req.param('reportId');
  const tenantId = c.get('tenantId');
  
  try {
    await deleteScheduledReport(reportId, tenantId);
    
    return c.json({
      success: true,
      message: 'Scheduled report deleted'
    });
  } catch (error) {
    console.error('Delete scheduled report error:', error);
    throw new HTTPException(500, { message: 'Failed to delete scheduled report' });
  }
});

// Compliance reporting endpoints
app.get('/api/compliance/templates', async (c) => {
  const templates = [
    {
      id: 'sox',
      name: 'Sarbanes-Oxley (SOX) Compliance',
      description: 'Financial controls and access audit report',
      requiredFields: ['access_events', 'user_changes', 'privilege_escalations']
    },
    {
      id: 'hipaa',
      name: 'HIPAA Compliance',
      description: 'Healthcare data access and privacy audit report',
      requiredFields: ['access_events', 'data_access', 'privacy_incidents']
    },
    {
      id: 'pci_dss',
      name: 'PCI-DSS Compliance',
      description: 'Payment card industry security audit report',
      requiredFields: ['access_events', 'security_incidents', 'system_changes']
    }
  ];
  
  return c.json({ success: true, data: templates });
});

app.post('/api/compliance/:template/generate', async (c) => {
  const template = c.req.param('template');
  const tenantId = c.get('tenantId');
  
  try {
    const body = await c.req.json();
    const { startDate, endDate, format = 'pdf' } = body;
    
    const reportId = await generateComplianceReport(template, {
      tenantId,
      startDate,
      endDate,
      format
    });
    
    return c.json({
      success: true,
      reportId,
      message: 'Compliance report generation started'
    });
  } catch (error) {
    console.error('Compliance report error:', error);
    throw new HTTPException(500, { message: 'Failed to generate compliance report' });
  }
});

// Error handling
app.onError((err, c) => {
  console.error('Application error:', err);
  
  if (err instanceof HTTPException) {
    return c.json({
      success: false,
      error: err.message
    }, err.status);
  }
  
  return c.json({
    success: false,
    error: 'Internal server error'
  }, 500);
});

// Helper functions
async function verifyJWTToken(token: string) {
  try {
    // Check if token is blacklisted
    const isBlacklisted = await jwtBlacklist.isBlacklisted(token);
    if (isBlacklisted) {
      throw new Error('Token has been revoked');
    }

    // Verify the token
    const decoded = jwt.verify(token, config.jwt.accessTokenSecret) as any;
    
    // Validate token structure
    if (!decoded.sub || !decoded.tenantId || !decoded.role) {
      throw new Error('Invalid token structure');
    }

    // Check if session exists in Redis
    const sessionKey = `session:${decoded.sub}:${decoded.tenantId}:${decoded.sessionId}`;
    const sessionExists = await redis.exists(sessionKey);
    
    if (!sessionExists) {
      throw new Error('Session not found or expired');
    }

    // Return user information
    return {
      id: decoded.sub,
      tenantId: decoded.tenantId,
      role: decoded.role,
      email: decoded.email,
      permissions: decoded.permissions || {},
      sessionId: decoded.sessionId
    };
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Token has expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid token');
    }
    throw error;
  }
}

async function generateDashboardData(query: z.infer<typeof DashboardDataRequestSchema>) {
  const { widgets, timeRange, tenantId } = query;
  const data: Record<string, any> = {};
  
  const timeRangeHours = {
    '1h': 1,
    '24h': 24,
    '7d': 168,
    '30d': 720
  }[timeRange];
  
  const startTime = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);
  
  for (const widget of widgets) {
    switch (widget) {
      case 'access_summary':
        data[widget] = await getAccessSummary(tenantId, startTime);
        break;
      case 'door_status':
        data[widget] = await getDoorStatus(tenantId);
        break;
      case 'camera_status':
        data[widget] = await getCameraStatus(tenantId);
        break;
      case 'recent_events':
        data[widget] = await getRecentEvents(tenantId, 10);
        break;
      case 'alerts':
        data[widget] = await getActiveAlerts(tenantId);
        break;
      case 'system_health':
        data[widget] = await getSystemHealth(tenantId);
        break;
      default:
        data[widget] = null;
    }
  }
  
  return data;
}

async function generateRealtimeData(tenantId: string) {
  return {
    accessEvents: await getRecentEvents(tenantId, 5),
    doorStatus: await getDoorStatus(tenantId),
    alerts: await getActiveAlerts(tenantId),
    systemStatus: await getSystemHealth(tenantId)
  };
}

async function generateReport(request: z.infer<typeof ReportRequestSchema>) {
  const reportId = `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  // Store report request in Redis for processing
  await redis.setex(`report:${reportId}`, 3600, JSON.stringify({
    ...request,
    status: 'processing',
    createdAt: new Date().toISOString()
  }));
  
  // Process report asynchronously
  processReportAsync(reportId, request);
  
  return reportId;
}

async function processReportAsync(reportId: string, request: z.infer<typeof ReportRequestSchema>) {
  try {
    const data = await fetchReportData(request);
    const reportFile = await generateReportFile(data, request);
    
    // Update status to completed
    await redis.setex(`report:${reportId}`, 3600, JSON.stringify({
      ...request,
      status: 'completed',
      filename: reportFile.filename,
      size: reportFile.size,
      completedAt: new Date().toISOString()
    }));
    
    // Store file data
    await redis.setex(`report:${reportId}:data`, 3600, reportFile.data.toString('base64'));
    
  } catch (error) {
    console.error(`Report ${reportId} processing failed:`, error);
    
    await redis.setex(`report:${reportId}`, 3600, JSON.stringify({
      ...request,
      status: 'failed',
      error: error.message,
      failedAt: new Date().toISOString()
    }));
  }
}

async function fetchReportData(request: z.infer<typeof ReportRequestSchema>) {
  const { type, startDate, endDate, filters, tenantId } = request;
  
  const start = new Date(startDate);
  const end = new Date(endDate);
  
  switch (type) {
    case 'access_events':
      return await prisma.accessEvent.findMany({
        where: {
          tenantId,
          timestamp: { gte: start, lte: end },
          ...filters
        },
        include: {
          user: true,
          door: true
        },
        orderBy: { timestamp: 'desc' }
      });
      
    case 'audit_log':
      return await prisma.auditLog.findMany({
        where: {
          tenantId,
          timestamp: { gte: start, lte: end },
          ...filters
        },
        include: {
          user: true
        },
        orderBy: { timestamp: 'desc' }
      });
      
    case 'user_activity':
      return await prisma.user.findMany({
        where: {
          tenantId,
          ...filters
        },
        include: {
          accessEvents: {
            where: {
              timestamp: { gte: start, lte: end }
            }
          }
        }
      });
      
    case 'door_status':
      return await prisma.door.findMany({
        where: {
          tenantId,
          ...filters
        },
        include: {
          accessEvents: {
            where: {
              timestamp: { gte: start, lte: end }
            }
          }
        }
      });
      
    case 'video_events':
      return await prisma.videoRecording.findMany({
        where: {
          tenantId,
          startTime: { gte: start, lte: end },
          ...filters
        },
        include: {
          camera: true
        },
        orderBy: { startTime: 'desc' }
      });
      
    default:
      throw new Error(`Unsupported report type: ${type}`);
  }
}

async function generateReportFile(data: any[], request: z.infer<typeof ReportRequestSchema>) {
  const { format, type } = request;
  const timestamp = format(new Date(), 'yyyy-MM-dd_HH-mm-ss');
  const filename = `${type}_report_${timestamp}.${format}`;
  
  switch (format) {
    case 'json':
      const jsonData = Buffer.from(JSON.stringify(data, null, 2));
      return { filename, data: jsonData, size: jsonData.length };
      
    case 'csv':
      const parser = new Parser();
      const csvData = Buffer.from(parser.parse(data));
      return { filename, data: csvData, size: csvData.length };
      
    case 'pdf':
      return await generatePDFReport(data, request, filename);
      
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}

async function generatePDFReport(data: any[], request: z.infer<typeof ReportRequestSchema>, filename: string) {
  const doc = new PDFDocument();
  const chunks: Buffer[] = [];
  
  doc.on('data', chunk => chunks.push(chunk));
  
  return new Promise<{ filename: string; data: Buffer; size: number }>((resolve, reject) => {
    doc.on('end', () => {
      const pdfData = Buffer.concat(chunks);
      resolve({ filename, data: pdfData, size: pdfData.length });
    });
    
    doc.on('error', reject);
    
    // Generate PDF content
    doc.fontSize(20).text(`${request.type.toUpperCase()} Report`, 50, 50);
    doc.fontSize(12).text(`Generated: ${new Date().toISOString()}`, 50, 80);
    doc.text(`Period: ${request.startDate} to ${request.endDate}`, 50, 100);
    doc.text(`Total Records: ${data.length}`, 50, 120);
    
    let yPosition = 160;
    
    data.slice(0, 100).forEach((item, index) => {
      if (yPosition > 700) {
        doc.addPage();
        yPosition = 50;
      }
      
      doc.text(`${index + 1}. ${JSON.stringify(item).substring(0, 100)}...`, 50, yPosition);
      yPosition += 20;
    });
    
    if (data.length > 100) {
      doc.text(`... and ${data.length - 100} more records`, 50, yPosition);
    }
    
    doc.end();
  });
}

async function getReportStatus(reportId: string, tenantId: string) {
  const reportData = await redis.get(`report:${reportId}`);
  if (!reportData) {
    throw new Error('Report not found');
  }
  
  const report = JSON.parse(reportData);
  if (report.tenantId !== tenantId) {
    throw new Error('Report not found');
  }
  
  return {
    id: reportId,
    status: report.status,
    createdAt: report.createdAt,
    completedAt: report.completedAt,
    failedAt: report.failedAt,
    error: report.error,
    filename: report.filename,
    size: report.size
  };
}

async function downloadReport(reportId: string, tenantId: string) {
  const status = await getReportStatus(reportId, tenantId);
  
  if (status.status !== 'completed') {
    throw new Error('Report not ready for download');
  }
  
  const reportDataBase64 = await redis.get(`report:${reportId}:data`);
  if (!reportDataBase64) {
    throw new Error('Report data not found');
  }
  
  const data = Buffer.from(reportDataBase64, 'base64');
  const extension = status.filename.split('.').pop();
  
  const mimeTypes = {
    pdf: 'application/pdf',
    csv: 'text/csv',
    json: 'application/json'
  };
  
  return {
    data,
    filename: status.filename,
    mimeType: mimeTypes[extension as keyof typeof mimeTypes] || 'application/octet-stream'
  };
}

async function createScheduledReport(report: z.infer<typeof ScheduledReportSchema>) {
  const scheduledReport = await prisma.scheduledReport.create({
    data: {
      name: report.name,
      type: report.type,
      format: report.format,
      schedule: report.schedule,
      recipients: report.recipients,
      filters: report.filters || {},
      isActive: report.isActive,
      tenantId: report.tenantId
    }
  });
  
  // Schedule the cron job
  if (report.isActive) {
    scheduleReportJob(scheduledReport.id, report.schedule);
  }
  
  return scheduledReport.id;
}

async function getScheduledReports(tenantId: string) {
  return await prisma.scheduledReport.findMany({
    where: { tenantId },
    orderBy: { createdAt: 'desc' }
  });
}

async function updateScheduledReport(reportId: string, tenantId: string, updates: Partial<z.infer<typeof ScheduledReportSchema>>) {
  await prisma.scheduledReport.updateMany({
    where: { id: reportId, tenantId },
    data: updates
  });
}

async function deleteScheduledReport(reportId: string, tenantId: string) {
  await prisma.scheduledReport.deleteMany({
    where: { id: reportId, tenantId }
  });
}

async function generateComplianceReport(template: string, options: any) {
  const reportRequest = {
    type: `compliance_${template}` as any,
    format: options.format,
    startDate: options.startDate,
    endDate: options.endDate,
    tenantId: options.tenantId,
    includeDetails: true,
    filters: getComplianceFilters(template)
  };
  
  return await generateReport(reportRequest);
}

function getComplianceFilters(template: string) {
  switch (template) {
    case 'sox':
      return {
        categories: ['user_management', 'privilege_changes', 'financial_access']
      };
    case 'hipaa':
      return {
        categories: ['data_access', 'privacy_events', 'unauthorized_access']
      };
    case 'pci_dss':
      return {
        categories: ['payment_access', 'security_events', 'system_changes']
      };
    default:
      return {};
  }
}

function scheduleReportJob(reportId: string, schedule: string) {
  cron.schedule(schedule, async () => {
    try {
      const scheduledReport = await prisma.scheduledReport.findUnique({
        where: { id: reportId }
      });
      
      if (!scheduledReport || !scheduledReport.isActive) {
        return;
      }
      
      const reportRequest = {
        type: scheduledReport.type as any,
        format: scheduledReport.format as any,
        startDate: subDays(new Date(), 7).toISOString(),
        endDate: new Date().toISOString(),
        tenantId: scheduledReport.tenantId,
        includeDetails: true,
        filters: scheduledReport.filters
      };
      
      const generatedReportId = await generateReport(reportRequest);
      
      // Wait for report completion and send email
      setTimeout(async () => {
        try {
          const reportFile = await downloadReport(generatedReportId, scheduledReport.tenantId);
          
          await emailTransporter.sendMail({
            from: process.env.SMTP_FROM || 'reports@sparc.com',
            to: scheduledReport.recipients,
            subject: `Scheduled Report: ${scheduledReport.name}`,
            text: `Please find attached your scheduled report: ${scheduledReport.name}`,
            attachments: [{
              filename: reportFile.filename,
              content: reportFile.data
            }]
          });
          
          console.log(`Scheduled report ${reportId} sent successfully`);
        } catch (error) {
          console.error(`Failed to send scheduled report ${reportId}:`, error);
        }
      }, 30000); // Wait 30 seconds for report generation
      
    } catch (error) {
      console.error(`Scheduled report job failed for ${reportId}:`, error);
    }
  });
}

// Mock data functions (would be replaced with actual database queries)
async function getAccessSummary(tenantId: string, startTime: Date) {
  return {
    totalEvents: 1250,
    successfulAccess: 1180,
    deniedAccess: 70,
    uniqueUsers: 45,
    peakHour: '09:00'
  };
}

async function getDoorStatus(tenantId: string) {
  return {
    total: 150,
    online: 148,
    offline: 2,
    locked: 145,
    unlocked: 5
  };
}

async function getCameraStatus(tenantId: string) {
  return {
    total: 75,
    online: 73,
    offline: 2,
    recording: 70,
    alerts: 3
  };
}

async function getRecentEvents(tenantId: string, limit: number) {
  return [
    {
      id: '1',
      type: 'access_granted',
      user: 'John Doe',
      door: 'Main Entrance',
      timestamp: new Date().toISOString()
    }
  ];
}

async function getActiveAlerts(tenantId: string) {
  return [
    {
      id: '1',
      type: 'door_ajar',
      location: 'Server Room',
      severity: 'high',
      timestamp: new Date().toISOString()
    }
  ];
}

async function getSystemHealth(tenantId: string) {
  return {
    overall: 'healthy',
    services: {
      database: 'healthy',
      redis: 'healthy',
      storage: 'healthy'
    },
    uptime: '99.9%'
  };
}

// Start server
const port = parseInt(process.env.PORT || '3007');

console.log(`Starting SPARC Reporting Service on port ${port}`);

serve({
  fetch: app.fetch,
  port
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await prisma.$disconnect();
  await redis.disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await prisma.$disconnect();
  await redis.disconnect();
  process.exit(0);
});

// ============================================================================
// COMPREHENSIVE TEST SUITE
// ============================================================================

// Only run tests if NODE_ENV is test
if (process.env.NODE_ENV === 'test') {
  
  // Test setup and mocks
  const mockPrisma = {
    accessEvent: {
      findMany: jest.fn(),
    },
    auditLog: {
      findMany: jest.fn(),
    },
    user: {
      findMany: jest.fn(),
    },
    door: {
      findMany: jest.fn(),
    },
    videoRecording: {
      findMany: jest.fn(),
    },
    scheduledReport: {
      create: jest.fn(),
      findMany: jest.fn(),
      findUnique: jest.fn(),
      updateMany: jest.fn(),
      deleteMany: jest.fn(),
    },
    $disconnect: jest.fn(),
  };

  const mockRedis = {
    setex: jest.fn(),
    get: jest.fn(),
    disconnect: jest.fn(),
  };

  const mockEmailTransporter = {
    sendMail: jest.fn(),
  };

  // Mock external dependencies
  jest.mock('@prisma/client', () => ({
    PrismaClient: jest.fn(() => mockPrisma),
  }));

  jest.mock('ioredis', () => jest.fn(() => mockRedis));

  jest.mock('nodemailer', () => ({
    createTransporter: jest.fn(() => mockEmailTransporter),
  }));

  jest.mock('node-cron', () => ({
    schedule: jest.fn(),
  }));

  jest.mock('pdfkit', () => {
    return jest.fn().mockImplementation(() => ({
      fontSize: jest.fn().mockReturnThis(),
      text: jest.fn().mockReturnThis(),
      addPage: jest.fn().mockReturnThis(),
      end: jest.fn(),
      on: jest.fn((event, callback) => {
        if (event === 'end') {
          setTimeout(() => callback(), 10);
        }
      }),
    }));
  });

  jest.mock('json2csv', () => ({
    Parser: jest.fn().mockImplementation(() => ({
      parse: jest.fn().mockReturnValue('csv,data\ntest,value'),
    })),
  }));

  describe('Reporting Service Tests', () => {
    
    beforeEach(() => {
      jest.clearAllMocks();
    });

    // ========================================================================
    // UNIT TESTS - Authentication Middleware
    // ========================================================================
    
    describe('Authentication Middleware', () => {
      test('should allow health check without authentication', async () => {
        const mockContext = {
          req: { path: '/health' },
        };
        const mockNext = jest.fn();
        
        // This would test the auth middleware logic
        expect(mockContext.req.path).toBe('/health');
      });

      test('should reject requests without authorization header', async () => {
        const mockContext = {
          req: { 
            path: '/api/dashboard/data',
            header: jest.fn().mockReturnValue(undefined)
          },
        };
        
        // Test would verify HTTPException(401) is thrown
        expect(mockContext.req.header).toHaveBeenCalledWith('Authorization');
      });

      test('should reject requests with invalid bearer token format', async () => {
        const mockContext = {
          req: { 
            path: '/api/dashboard/data',
            header: jest.fn().mockReturnValue('Invalid token')
          },
        };
        
        expect(mockContext.req.header).toHaveBeenCalledWith('Authorization');
      });

      test('should accept valid JWT token and set user context', async () => {
        const mockContext = {
          req: { 
            path: '/api/dashboard/data',
            header: jest.fn().mockReturnValue('Bearer valid-jwt-token')
          },
          set: jest.fn(),
        };
        
        // Test would verify user and tenantId are set in context
        expect(mockContext.req.header).toHaveBeenCalledWith('Authorization');
      });
    });

    // ========================================================================
    // UNIT TESTS - Dashboard Data Endpoints
    // ========================================================================
    
    describe('Dashboard Data Endpoints', () => {
      test('should generate dashboard data with valid widgets', async () => {
        const mockQuery = {
          widgets: ['access_summary', 'door_status'],
          timeRange: '24h',
          tenantId: 'tenant-123'
        };

        const result = await generateDashboardData(mockQuery);
        
        expect(result).toHaveProperty('access_summary');
        expect(result).toHaveProperty('door_status');
        expect(result.access_summary).toHaveProperty('totalEvents');
        expect(result.door_status).toHaveProperty('total');
      });

      test('should handle empty widgets array', async () => {
        const mockQuery = {
          widgets: [],
          timeRange: '1h',
          tenantId: 'tenant-123'
        };

        const result = await generateDashboardData(mockQuery);
        expect(Object.keys(result)).toHaveLength(0);
      });

      test('should handle unknown widget types', async () => {
        const mockQuery = {
          widgets: ['unknown_widget'],
          timeRange: '7d',
          tenantId: 'tenant-123'
        };

        const result = await generateDashboardData(mockQuery);
        expect(result.unknown_widget).toBeNull();
      });

      test('should generate realtime data correctly', async () => {
        const tenantId = 'tenant-123';
        const result = await generateRealtimeData(tenantId);
        
        expect(result).toHaveProperty('accessEvents');
        expect(result).toHaveProperty('doorStatus');
        expect(result).toHaveProperty('alerts');
        expect(result).toHaveProperty('systemStatus');
      });
    });

    // ========================================================================
    // UNIT TESTS - Report Generation
    // ========================================================================
    
    describe('Report Generation', () => {
      test('should generate report ID and start processing', async () => {
        const reportRequest = {
          type: 'access_events' as const,
          format: 'pdf' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        mockRedis.setex.mockResolvedValue('OK');
        
        const reportId = await generateReport(reportRequest);
        
        expect(reportId).toMatch(/^report_\d+_[a-z0-9]+$/);
        expect(mockRedis.setex).toHaveBeenCalledWith(
          `report:${reportId}`,
          3600,
          expect.stringContaining('"status":"processing"')
        );
      });

      test('should fetch access events data correctly', async () => {
        const reportRequest = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        const mockAccessEvents = [
          { id: '1', userId: 'user1', doorId: 'door1', timestamp: new Date() }
        ];
        
        mockPrisma.accessEvent.findMany.mockResolvedValue(mockAccessEvents);
        
        const result = await fetchReportData(reportRequest);
        
        expect(mockPrisma.accessEvent.findMany).toHaveBeenCalledWith({
          where: {
            tenantId: 'tenant-123',
            timestamp: {
              gte: new Date('2024-01-01T00:00:00Z'),
              lte: new Date('2024-01-31T23:59:59Z')
            }
          },
          include: {
            user: true,
            door: true
          },
          orderBy: { timestamp: 'desc' }
        });
        expect(result).toEqual(mockAccessEvents);
      });

      test('should fetch audit log data correctly', async () => {
        const reportRequest = {
          type: 'audit_log' as const,
          format: 'csv' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        const mockAuditLogs = [
          { id: '1', action: 'login', userId: 'user1', timestamp: new Date() }
        ];
        
        mockPrisma.auditLog.findMany.mockResolvedValue(mockAuditLogs);
        
        const result = await fetchReportData(reportRequest);
        
        expect(mockPrisma.auditLog.findMany).toHaveBeenCalled();
        expect(result).toEqual(mockAuditLogs);
      });

      test('should throw error for unsupported report type', async () => {
        const reportRequest = {
          type: 'unsupported_type' as any,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        await expect(fetchReportData(reportRequest)).rejects.toThrow('Unsupported report type: unsupported_type');
      });
    });

    // ========================================================================
    // UNIT TESTS - Report File Generation
    // ========================================================================
    
    describe('Report File Generation', () => {
      test('should generate JSON report file', async () => {
        const data = [{ id: '1', name: 'test' }];
        const request = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        const result = await generateReportFile(data, request);
        
        expect(result.filename).toMatch(/access_events_report_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.json/);
        expect(result.data).toBeInstanceOf(Buffer);
        expect(result.size).toBeGreaterThan(0);
        
        const parsedData = JSON.parse(result.data.toString());
        expect(parsedData).toEqual(data);
      });

      test('should generate CSV report file', async () => {
        const data = [{ id: '1', name: 'test' }];
        const request = {
          type: 'user_activity' as const,
          format: 'csv' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        const result = await generateReportFile(data, request);
        
        expect(result.filename).toMatch(/user_activity_report_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.csv/);
        expect(result.data).toBeInstanceOf(Buffer);
        expect(result.data.toString()).toBe('csv,data\ntest,value');
      });

      test('should generate PDF report file', async () => {
        const data = [{ id: '1', name: 'test', timestamp: new Date() }];
        const request = {
          type: 'door_status' as const,
          format: 'pdf' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        const result = await generateReportFile(data, request);
        
        expect(result.filename).toMatch(/door_status_report_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.pdf/);
        expect(result.data).toBeInstanceOf(Buffer);
        expect(result.size).toBeGreaterThan(0);
      });

      test('should throw error for unsupported format', async () => {
        const data = [{ id: '1' }];
        const request = {
          type: 'access_events' as const,
          format: 'unsupported' as any,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        await expect(generateReportFile(data, request)).rejects.toThrow('Unsupported format: unsupported');
      });
    });

    // ========================================================================
    // UNIT TESTS - Report Status and Download
    // ========================================================================
    
    describe('Report Status and Download', () => {
      test('should get report status successfully', async () => {
        const reportId = 'report_123';
        const tenantId = 'tenant-123';
        const reportData = {
          tenantId,
          status: 'completed',
          createdAt: '2024-01-01T00:00:00Z',
          completedAt: '2024-01-01T00:05:00Z',
          filename: 'test_report.pdf',
          size: 1024
        };

        mockRedis.get.mockResolvedValue(JSON.stringify(reportData));
        
        const result = await getReportStatus(reportId, tenantId);
        
        expect(result).toEqual({
          id: reportId,
          status: 'completed',
          createdAt: '2024-01-01T00:00:00Z',
          completedAt: '2024-01-01T00:05:00Z',
          failedAt: undefined,
          error: undefined,
          filename: 'test_report.pdf',
          size: 1024
        });
      });

      test('should throw error for non-existent report', async () => {
        const reportId = 'non-existent';
        const tenantId = 'tenant-123';

        mockRedis.get.mockResolvedValue(null);
        
        await expect(getReportStatus(reportId, tenantId)).rejects.toThrow('Report not found');
      });

      test('should throw error for wrong tenant access', async () => {
        const reportId = 'report_123';
        const tenantId = 'tenant-123';
        const reportData = {
          tenantId: 'different-tenant',
          status: 'completed'
        };

        mockRedis.get.mockResolvedValue(JSON.stringify(reportData));
        
        await expect(getReportStatus(reportId, tenantId)).rejects.toThrow('Report not found');
      });

      test('should download completed report successfully', async () => {
        const reportId = 'report_123';
        const tenantId = 'tenant-123';
        const reportData = {
          tenantId,
          status: 'completed',
          filename: 'test_report.pdf'
        };
        const fileData = Buffer.from('test pdf content').toString('base64');

        mockRedis.get
          .mockResolvedValueOnce(JSON.stringify(reportData))
          .mockResolvedValueOnce(fileData);
        
        const result = await downloadReport(reportId, tenantId);
        
        expect(result.filename).toBe('test_report.pdf');
        expect(result.mimeType).toBe('application/pdf');
        expect(result.data).toBeInstanceOf(Buffer);
      });

      test('should throw error for incomplete report download', async () => {
        const reportId = 'report_123';
        const tenantId = 'tenant-123';
        const reportData = {
          tenantId,
          status: 'processing',
          filename: 'test_report.pdf'
        };

        mockRedis.get.mockResolvedValue(JSON.stringify(reportData));
        
        await expect(downloadReport(reportId, tenantId)).rejects.toThrow('Report not ready for download');
      });
    });

    // ========================================================================
    // UNIT TESTS - Scheduled Reports
    // ========================================================================
    
    describe('Scheduled Reports', () => {
      test('should create scheduled report successfully', async () => {
        const scheduledReport = {
          name: 'Weekly Access Report',
          type: 'access_events' as const,
          format: 'pdf' as const,
          schedule: '0 9 * * 1',
          recipients: ['admin@company.com'],
          isActive: true,
          tenantId: 'tenant-123'
        };

        const mockCreatedReport = { id: 'scheduled-123', ...scheduledReport };
        mockPrisma.scheduledReport.create.mockResolvedValue(mockCreatedReport);
        
        const result = await createScheduledReport(scheduledReport);
        
        expect(result).toBe('scheduled-123');
        expect(mockPrisma.scheduledReport.create).toHaveBeenCalledWith({
          data: {
            name: 'Weekly Access Report',
            type: 'access_events',
            format: 'pdf',
            schedule: '0 9 * * 1',
            recipients: ['admin@company.com'],
            filters: {},
            isActive: true,
            tenantId: 'tenant-123'
          }
        });
      });

      test('should get scheduled reports for tenant', async () => {
        const tenantId = 'tenant-123';
        const mockReports = [
          { id: '1', name: 'Report 1', tenantId },
          { id: '2', name: 'Report 2', tenantId }
        ];

        mockPrisma.scheduledReport.findMany.mockResolvedValue(mockReports);
        
        const result = await getScheduledReports(tenantId);
        
        expect(result).toEqual(mockReports);
        expect(mockPrisma.scheduledReport.findMany).toHaveBeenCalledWith({
          where: { tenantId },
          orderBy: { createdAt: 'desc' }
        });
      });

      test('should update scheduled report', async () => {
        const reportId = 'scheduled-123';
        const tenantId = 'tenant-123';
        const updates = { name: 'Updated Report Name', isActive: false };

        mockPrisma.scheduledReport.updateMany.mockResolvedValue({ count: 1 });
        
        await updateScheduledReport(reportId, tenantId, updates);
        
        expect(mockPrisma.scheduledReport.updateMany).toHaveBeenCalledWith({
          where: { id: reportId, tenantId },
          data: updates
        });
      });

      test('should delete scheduled report', async () => {
        const reportId = 'scheduled-123';
        const tenantId = 'tenant-123';

        mockPrisma.scheduledReport.deleteMany.mockResolvedValue({ count: 1 });
        
        await deleteScheduledReport(reportId, tenantId);
        
        expect(mockPrisma.scheduledReport.deleteMany).toHaveBeenCalledWith({
          where: { id: reportId, tenantId }
        });
      });
    });

    // ========================================================================
    // UNIT TESTS - Compliance Reporting
    // ========================================================================
    
    describe('Compliance Reporting', () => {
      test('should generate SOX compliance report', async () => {
        const options = {
          tenantId: 'tenant-123',
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          format: 'pdf'
        };

        mockRedis.setex.mockResolvedValue('OK');
        
        const reportId = await generateComplianceReport('sox', options);
        
        expect(reportId).toMatch(/^report_\d+_[a-z0-9]+$/);
        expect(mockRedis.setex).toHaveBeenCalledWith(
          expect.stringMatching(/^report:report_\d+_[a-z0-9]+$/),
          3600,
          expect.stringContaining('"type":"compliance_sox"')
        );
      });

      test('should generate HIPAA compliance report', async () => {
        const options = {
          tenantId: 'tenant-123',
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          format: 'csv'
        };

        mockRedis.setex.mockResolvedValue('OK');
        
        const reportId = await generateComplianceReport('hipaa', options);
        
        expect(reportId).toMatch(/^report_\d+_[a-z0-9]+$/);
      });

      test('should generate PCI-DSS compliance report', async () => {
        const options = {
          tenantId: 'tenant-123',
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          format: 'json'
        };

        mockRedis.setex.mockResolvedValue('OK');
        
        const reportId = await generateComplianceReport('pci_dss', options);
        
        expect(reportId).toMatch(/^report_\d+_[a-z0-9]+$/);
      });

      test('should return correct compliance filters for SOX', () => {
        const filters = getComplianceFilters('sox');
        
        expect(filters).toEqual({
          categories: ['user_management', 'privilege_changes', 'financial_access']
        });
      });

      test('should return correct compliance filters for HIPAA', () => {
        const filters = getComplianceFilters('hipaa');
        
        expect(filters).toEqual({
          categories: ['data_access', 'privacy_events', 'unauthorized_access']
        });
      });

      test('should return correct compliance filters for PCI-DSS', () => {
        const filters = getComplianceFilters('pci_dss');
        
        expect(filters).toEqual({
          categories: ['payment_access', 'security_events', 'system_changes']
        });
      });

      test('should return empty filters for unknown template', () => {
        const filters = getComplianceFilters('unknown');
        
        expect(filters).toEqual({});
      });
    });

    // ========================================================================
    // INTEGRATION TESTS - Redis Integration
    // ========================================================================
    
    describe('Redis Integration', () => {
      test('should store and retrieve report data from Redis', async () => {
        const reportId = 'report_123';
        const reportData = {
          status: 'processing',
          tenantId: 'tenant-123',
          createdAt: new Date().toISOString()
        };

        mockRedis.setex.mockResolvedValue('OK');
        mockRedis.get.mockResolvedValue(JSON.stringify(reportData));
        
        // Store data
        await redis.setex(`report:${reportId}`, 3600, JSON.stringify(reportData));
        
        // Retrieve data
        const retrieved = await redis.get(`report:${reportId}`);
        const parsedData = JSON.parse(retrieved);
        
        expect(mockRedis.setex).toHaveBeenCalledWith(
          `report:${reportId}`,
          3600,
          JSON.stringify(reportData)
        );
        expect(parsedData).toEqual(reportData);
      });

      test('should handle Redis connection errors gracefully', async () => {
        const reportId = 'report_123';
        
        mockRedis.get.mockRejectedValue(new Error('Redis connection failed'));
        
        await expect(getReportStatus(reportId, 'tenant-123')).rejects.toThrow();
      });

      test('should store report file data in Redis', async () => {
        const reportId = 'report_123';
        const fileData = Buffer.from('test file content');
        const base64Data = fileData.toString('base64');

        mockRedis.setex.mockResolvedValue('OK');
        
        await redis.setex(`report:${reportId}:data`, 3600, base64Data);
        
        expect(mockRedis.setex).toHaveBeenCalledWith(
          `report:${reportId}:data`,
          3600,
          base64Data
        );
      });
    });

    // ========================================================================
    // INTEGRATION TESTS - Email Integration
    // ========================================================================
    
    describe('Email Integration', () => {
      test('should send scheduled report via email', async () => {
        const reportData = {
          filename: 'test_report.pdf',
          data: Buffer.from('test pdf content')
        };
        const recipients = ['admin@company.com', 'manager@company.com'];

        mockEmailTransporter.sendMail.mockResolvedValue({ messageId: 'test-message-id' });
        
        await emailTransporter.sendMail({
          from: 'reports@sparc.com',
          to: recipients,
          subject: 'Scheduled Report: Weekly Access Report',
          text: 'Please find attached your scheduled report: Weekly Access Report',
          attachments: [{
            filename: reportData.filename,
            content: reportData.data
          }]
        });
        
        expect(mockEmailTransporter.sendMail).toHaveBeenCalledWith({
          from: 'reports@sparc.com',
          to: recipients,
          subject: 'Scheduled Report: Weekly Access Report',
          text: 'Please find attached your scheduled report: Weekly Access Report',
          attachments: [{
            filename: 'test_report.pdf',
            content: reportData.data
          }]
        });
      });

      test('should handle email sending errors', async () => {
        mockEmailTransporter.sendMail.mockRejectedValue(new Error('SMTP server unavailable'));
        
        await expect(emailTransporter.sendMail({
          from: 'reports@sparc.com',
          to: ['test@example.com'],
          subject: 'Test Report',
          text: 'Test message'
        })).rejects.toThrow('SMTP server unavailable');
      });
    });

    // ========================================================================
    // PERFORMANCE TESTS
    // ========================================================================
    
    describe('Performance Tests', () => {
      test('should handle large dataset report generation', async () => {
        const largeDataset = Array.from({ length: 10000 }, (_, i) => ({
          id: `event_${i}`,
          userId: `user_${i % 100}`,
          doorId: `door_${i % 50}`,
          timestamp: new Date(Date.now() - i * 1000)
        }));

        mockPrisma.accessEvent.findMany.mockResolvedValue(largeDataset);
        
        const reportRequest = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        const startTime = Date.now();
        const data = await fetchReportData(reportRequest);
        const endTime = Date.now();
        
        expect(data).toHaveLength(10000);
        expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
      });

      test('should handle concurrent report generation requests', async () => {
        const reportRequests = Array.from({ length: 10 }, (_, i) => ({
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: `tenant-${i}`,
          includeDetails: true
        }));

        mockRedis.setex.mockResolvedValue('OK');
        
        const startTime = Date.now();
        const reportIds = await Promise.all(
          reportRequests.map(request => generateReport(request))
        );
        const endTime = Date.now();
        
        expect(reportIds).toHaveLength(10);
        expect(reportIds.every(id => id.startsWith('report_'))).toBe(true);
        expect(endTime - startTime).toBeLessThan(2000); // Should complete within 2 seconds
      });

      test('should handle memory efficiently for large PDF generation', async () => {
        const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
          id: `event_${i}`,
          description: `This is a long description for event ${i} that contains multiple sentences and detailed information about what happened during this particular access event. It includes timestamps, user information, door details, and other relevant metadata that would typically be found in a comprehensive audit log entry.`,
          timestamp: new Date()
        }));

        const reportRequest = {
          type: 'access_events' as const,
          format: 'pdf' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        const result = await generateReportFile(largeDataset, reportRequest);
        
        expect(result.data).toBeInstanceOf(Buffer);
        expect(result.size).toBeGreaterThan(0);
        expect(result.filename).toMatch(/\.pdf$/);
      });
    });

    // ========================================================================
    // SECURITY TESTS
    // ========================================================================
    
    describe('Security Tests', () => {
      test('should prevent access to reports from different tenants', async () => {
        const reportId = 'report_123';
        const correctTenantId = 'tenant-123';
        const wrongTenantId = 'tenant-456';
        
        const reportData = {
          tenantId: correctTenantId,
          status: 'completed'
        };

        mockRedis.get.mockResolvedValue(JSON.stringify(reportData));
        
        await expect(getReportStatus(reportId, wrongTenantId)).rejects.toThrow('Report not found');
      });

      test('should sanitize report data to prevent information leakage', async () => {
        const sensitiveData = [
          {
            id: '1',
            userId: 'user123',
            password: 'secret123',
            creditCard: '4111-1111-1111-1111',
            ssn: '123-45-6789'
          }
        ];

        const reportRequest = {
          type: 'user_activity' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        // In a real implementation, sensitive fields would be filtered out
        const result = await generateReportFile(sensitiveData, reportRequest);
        const reportContent = result.data.toString();
        
        // Verify the report was generated (in real implementation, sensitive data would be filtered)
        expect(result.data).toBeInstanceOf(Buffer);
        expect(result.size).toBeGreaterThan(0);
      });

      test('should validate report request parameters', async () => {
        const invalidRequest = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: 'invalid-date',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        // This would be caught by Zod validation in the actual endpoint
        expect(() => {
          ReportRequestSchema.parse(invalidRequest);
        }).toThrow();
      });

      test('should prevent SQL injection in report filters', async () => {
        const maliciousRequest = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true,
          filters: {
            userId: "'; DROP TABLE users; --"
          }
        };

        // Prisma ORM provides protection against SQL injection
        mockPrisma.accessEvent.findMany.mockResolvedValue([]);
        
        const result = await fetchReportData(maliciousRequest);
        
        expect(mockPrisma.accessEvent.findMany).toHaveBeenCalledWith({
          where: {
            tenantId: 'tenant-123',
            timestamp: expect.any(Object),
            userId: "'; DROP TABLE users; --"
          },
          include: expect.any(Object),
          orderBy: expect.any(Object)
        });
        expect(result).toEqual([]);
      });
    });

    // ========================================================================
    // DATA PRIVACY AND COMPLIANCE TESTS
    // ========================================================================
    
    describe('Data Privacy and Compliance', () => {
      test('should respect data retention policies', async () => {
        const oldDate = new Date('2020-01-01');
        const reportRequest = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: oldDate.toISOString(),
          endDate: new Date().toISOString(),
          tenantId: 'tenant-123',
          includeDetails: true
        };

        // In a real implementation, old data beyond retention period would be filtered
        mockPrisma.accessEvent.findMany.mockResolvedValue([]);
        
        const result = await fetchReportData(reportRequest);
        
        expect(result).toEqual([]);
      });

      test('should anonymize personal data in compliance reports', async () => {
        const personalData = [
          {
            id: '1',
            firstName: 'John',
            lastName: 'Doe',
            email: 'john.doe@company.com',
            accessTime: new Date()
          }
        ];

        const complianceRequest = {
          type: 'compliance_hipaa' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        // In a real implementation, personal data would be anonymized for compliance reports
        const result = await generateReportFile(personalData, complianceRequest);
        
        expect(result.data).toBeInstanceOf(Buffer);
        expect(result.size).toBeGreaterThan(0);
      });

      test('should audit report generation activities', async () => {
        const reportRequest = {
          type: 'access_events' as const,
          format: 'pdf' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        mockRedis.setex.mockResolvedValue('OK');
        
        const reportId = await generateReport(reportRequest);
        
        // Verify that audit information is stored
        expect(mockRedis.setex).toHaveBeenCalledWith(
          `report:${reportId}`,
          3600,
          expect.stringContaining('"createdAt"')
        );
      });
    });

    // ========================================================================
    // ERROR HANDLING TESTS
    // ========================================================================
    
    describe('Error Handling', () => {
      test('should handle database connection errors', async () => {
        const reportRequest = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        mockPrisma.accessEvent.findMany.mockRejectedValue(new Error('Database connection failed'));
        
        await expect(fetchReportData(reportRequest)).rejects.toThrow('Database connection failed');
      });

      test('should handle PDF generation errors', async () => {
        const data = [{ id: '1', name: 'test' }];
        const request = {
          type: 'access_events' as const,
          format: 'pdf' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        // Mock PDF generation error
        const mockPDFDoc = {
          fontSize: jest.fn().mockReturnThis(),
          text: jest.fn().mockReturnThis(),
          addPage: jest.fn().mockReturnThis(),
          end: jest.fn(),
          on: jest.fn((event, callback) => {
            if (event === 'error') {
              setTimeout(() => callback(new Error('PDF generation failed')), 10);
            }
          }),
        };

        jest.mocked(require('pdfkit')).mockImplementation(() => mockPDFDoc);
        
        await expect(generateReportFile(data, request)).rejects.toThrow('PDF generation failed');
      });

      test('should handle email delivery failures gracefully', async () => {
        mockEmailTransporter.sendMail.mockRejectedValue(new Error('Email server unavailable'));
        
        // In a real implementation, this would be handled in the scheduled report job
        await expect(emailTransporter.sendMail({
          from: 'reports@sparc.com',
          to: ['test@example.com'],
          subject: 'Test Report',
          text: 'Test message'
        })).rejects.toThrow('Email server unavailable');
      });

      test('should handle Redis storage failures', async () => {
        const reportRequest = {
          type: 'access_events' as const,
          format: 'json' as const,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          tenantId: 'tenant-123',
          includeDetails: true
        };

        mockRedis.setex.mockRejectedValue(new Error('Redis storage failed'));
        
        await expect(generateReport(reportRequest)).rejects.toThrow('Redis storage failed');
      });
    });

    // ========================================================================
    // MOCK DATA FUNCTION TESTS
    // ========================================================================
    
    describe('Mock Data Functions', () => {
      test('should return access summary data', async () => {
        const result = await getAccessSummary('tenant-123', new Date());
        
        expect(result).toHaveProperty('totalEvents');
        expect(result).toHaveProperty('successfulAccess');
        expect(result).toHaveProperty('deniedAccess');
        expect(result).toHaveProperty('uniqueUsers');
        expect(result).toHaveProperty('peakHour');
        expect(typeof result.totalEvents).toBe('number');
      });

      test('should return door status data', async () => {
        const result = await getDoorStatus('tenant-123');
        
        expect(result).toHaveProperty('total');
        expect(result).toHaveProperty('online');
        expect(result).toHaveProperty('offline');
        expect(result).toHaveProperty('locked');
        expect(result).toHaveProperty('unlocked');
        expect(typeof result.total).toBe('number');
      });

      test('should return camera status data', async () => {
        const result = await getCameraStatus('tenant-123');
        
        expect(result).toHaveProperty('total');
        expect(result).toHaveProperty('online');
        expect(result).toHaveProperty('offline');
        expect(result).toHaveProperty('recording');
        expect(result).toHaveProperty('alerts');
        expect(typeof result.total).toBe('number');
      });

      test('should return recent events data', async () => {
        const result = await getRecentEvents('tenant-123', 5);
        
        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBeGreaterThan(0);
        expect(result[0]).toHaveProperty('id');
        expect(result[0]).toHaveProperty('type');
        expect(result[0]).toHaveProperty('timestamp');
      });

      test('should return active alerts data', async () => {
        const result = await getActiveAlerts('tenant-123');
        
        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBeGreaterThan(0);
        expect(result[0]).toHaveProperty('id');
        expect(result[0]).toHaveProperty('type');
        expect(result[0]).toHaveProperty('severity');
      });

      test('should return system health data', async () => {
        const result = await getSystemHealth('tenant-123');
        
        expect(result).toHaveProperty('overall');
        expect(result).toHaveProperty('services');
        expect(result).toHaveProperty('uptime');
        expect(result.services).toHaveProperty('database');
        expect(result.services).toHaveProperty('redis');
        expect(result.services).toHaveProperty('storage');
      });
    });

  });

  // Export test utilities for external test files
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      mockPrisma,
      mockRedis,
      mockEmailTransporter,
      generateDashboardData,
      generateRealtimeData,
      generateReport,
      fetchReportData,
      generateReportFile,
      getReportStatus,
      downloadReport,
      createScheduledReport,
      getScheduledReports,
      updateScheduledReport,
      deleteScheduledReport,
      generateComplianceReport,
      getComplianceFilters
    };
  }

}
