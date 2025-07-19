import { Hono } from 'hono';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { AnalyticsEngine } from '../services/analytics-engine';
import { PrismaClient } from '@sparc/shared/prisma';
import { Client } from '@opensearch-project/opensearch';

const ExportRequestSchema = z.object({
  dataType: z.enum(['analytics', 'anomalies', 'predictions', 'occupancy', 'video']),
  format: z.enum(['json', 'csv', 'pdf']),
  startDate: z.string().datetime(),
  endDate: z.string().datetime(),
  filters: z.record(z.any()).optional()
});

export function createExportRoutes(
  analyticsEngine: AnalyticsEngine,
  prisma: PrismaClient,
  opensearch: Client
) {
  const app = new Hono();

  // Apply authentication middleware
  app.use('*', authMiddleware);

  // Export analytics data
  app.post(
    '/',
    zValidator('json', ExportRequestSchema),
    async (c) => {
      const request = c.req.valid('json');
      const tenantId = c.get('tenantId');

      // Generate export based on data type
      let data: any;
      
      switch (request.dataType) {
        case 'analytics':
          data = await exportAnalyticsData(opensearch, tenantId, request);
          break;
        case 'anomalies':
          data = await exportAnomaliesData(opensearch, tenantId, request);
          break;
        case 'predictions':
          data = await exportPredictionsData(opensearch, tenantId, request);
          break;
        case 'occupancy':
          data = await exportOccupancyData(opensearch, tenantId, request);
          break;
        case 'video':
          data = await exportVideoData(opensearch, tenantId, request);
          break;
        default:
          return c.json({ error: 'Invalid data type' }, 400);
      }

      // Format data based on requested format
      switch (request.format) {
        case 'json':
          return c.json(data);
        case 'csv':
          const csv = convertToCSV(data);
          return c.text(csv, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': `attachment; filename="${request.dataType}-export.csv"`
          });
        case 'pdf':
          // PDF generation would require additional libraries
          return c.json({ error: 'PDF export not yet implemented' }, 501);
        default:
          return c.json({ error: 'Invalid format' }, 400);
      }
    }
  );

  return app;
}

// Helper functions for data export
async function exportAnalyticsData(
  opensearch: Client,
  tenantId: string,
  request: any
): Promise<any> {
  const query = {
    query: {
      bool: {
        must: [
          { term: { tenantId } },
          {
            range: {
              timestamp: {
                gte: request.startDate,
                lte: request.endDate
              }
            }
          }
        ]
      }
    },
    size: 10000
  };

  if (request.filters) {
    Object.entries(request.filters).forEach(([key, value]) => {
      query.query.bool.must.push({ term: { [key]: value } });
    });
  }

  const response = await opensearch.search({
    index: 'sparc-analytics',
    body: query
  });

  return response.body.hits.hits.map((hit: any) => hit._source);
}

async function exportAnomaliesData(
  opensearch: Client,
  tenantId: string,
  request: any
): Promise<any> {
  // Similar implementation for anomalies
  return [];
}

async function exportPredictionsData(
  opensearch: Client,
  tenantId: string,
  request: any
): Promise<any> {
  // Similar implementation for predictions
  return [];
}

async function exportOccupancyData(
  opensearch: Client,
  tenantId: string,
  request: any
): Promise<any> {
  // Similar implementation for occupancy
  return [];
}

async function exportVideoData(
  opensearch: Client,
  tenantId: string,
  request: any
): Promise<any> {
  // Similar implementation for video analytics
  return [];
}

function convertToCSV(data: any[]): string {
  if (data.length === 0) return '';

  // Get headers from first object
  const headers = Object.keys(data[0]);
  const csvHeaders = headers.join(',');

  // Convert data rows
  const csvRows = data.map(row => {
    return headers.map(header => {
      const value = row[header];
      // Escape quotes and handle special characters
      if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
        return `"${value.replace(/"/g, '""')}"`;
      }
      return value;
    }).join(',');
  });

  return [csvHeaders, ...csvRows].join('\n');
}