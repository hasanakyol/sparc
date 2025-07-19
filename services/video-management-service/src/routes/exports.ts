import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { VideoProcessor } from '../services/videoProcessor';
import { PrismaClient } from '@prisma/client';

const app = new Hono();
const prisma = new PrismaClient();
const videoProcessor = new VideoProcessor();

// Validation schemas
const createExportSchema = z.object({
  videoId: z.string().uuid(),
  operations: z.array(z.object({
    type: z.enum(['transcode', 'thumbnail', 'convert', 'watermark', 'trim', 'compress']),
    options: z.any()
  })).min(1),
  metadata: z.record(z.any()).optional()
});

const exportQuerySchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  status: z.enum(['queued', 'processing', 'completed', 'failed']).optional()
});

// Get all exports with pagination
app.get('/', zValidator('query', exportQuerySchema), async (c) => {
  const { page, limit, status } = c.req.valid('query');
  const tenantId = c.get('tenantId') as string;

  try {
    const offset = (page - 1) * limit;
    
    const where = {
      tenantId,
      ...(status && { status })
    };

    const [exports, total] = await Promise.all([
      prisma.videoExport.findMany({
        where,
        include: {
          video: {
            select: {
              id: true,
              filename: true,
              cameraId: true
            }
          }
        },
        orderBy: { createdAt: 'desc' },
        skip: offset,
        take: limit
      }),
      prisma.videoExport.count({ where })
    ]);

    return c.json({
      exports,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Failed to get exports:', error);
    throw new HTTPException(500, { message: 'Failed to retrieve exports' });
  }
});

// Get export details with job status
app.get('/:id', async (c) => {
  const exportId = c.req.param('id');
  const tenantId = c.get('tenantId') as string;

  try {
    const export_ = await prisma.videoExport.findFirst({
      where: {
        id: exportId,
        tenantId
      },
      include: {
        video: true
      }
    });

    if (!export_) {
      throw new HTTPException(404, { message: 'Export not found' });
    }

    // Get job status if processing
    let jobStatus = null;
    if (export_.jobId && export_.status !== 'completed') {
      jobStatus = await videoProcessor.getJobStatus(export_.jobId);
    }

    return c.json({
      ...export_,
      jobStatus
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    console.error('Failed to get export:', error);
    throw new HTTPException(500, { message: 'Failed to retrieve export' });
  }
});

// Create a new export job
app.post('/', zValidator('json', createExportSchema), async (c) => {
  const { videoId, operations, metadata } = c.req.valid('json');
  const tenantId = c.get('tenantId') as string;
  const userId = c.get('userId') as string;

  try {
    // Verify video exists and belongs to tenant
    const video = await prisma.videoRecording.findFirst({
      where: {
        id: videoId,
        tenantId
      }
    });

    if (!video) {
      throw new HTTPException(404, { message: 'Video not found' });
    }

    // Queue video processing job
    const { jobId, status } = await videoProcessor.queueVideoProcessing({
      videoId,
      tenantId,
      operations,
      metadata: {
        ...metadata,
        exportedBy: userId,
        originalFilename: video.filename
      }
    });

    // Create export record
    const export_ = await prisma.videoExport.create({
      data: {
        id: jobId,
        videoId,
        tenantId,
        jobId,
        status,
        operations: JSON.stringify(operations),
        metadata: metadata || {},
        exportedBy: userId,
        createdAt: new Date()
      }
    });

    return c.json(export_, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    console.error('Failed to create export:', error);
    throw new HTTPException(500, { message: 'Failed to create export' });
  }
});

// Get download URL for completed export
app.get('/:id/download', async (c) => {
  const exportId = c.req.param('id');
  const tenantId = c.get('tenantId') as string;

  try {
    const export_ = await prisma.videoExport.findFirst({
      where: {
        id: exportId,
        tenantId
      }
    });

    if (!export_) {
      throw new HTTPException(404, { message: 'Export not found' });
    }

    if (export_.status !== 'completed') {
      throw new HTTPException(400, { message: `Export is ${export_.status}` });
    }

    if (!export_.outputUrl) {
      throw new HTTPException(500, { message: 'Export output URL not available' });
    }

    // Log download
    await prisma.videoExportDownload.create({
      data: {
        exportId: export_.id,
        downloadedBy: c.get('userId') as string,
        downloadedAt: new Date()
      }
    });

    // Return download URL or redirect
    return c.json({
      downloadUrl: export_.outputUrl,
      filename: export_.metadata?.filename || `export_${exportId}.mp4`,
      expiresAt: new Date(Date.now() + 3600000) // 1 hour
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    console.error('Failed to get download URL:', error);
    throw new HTTPException(500, { message: 'Failed to get download URL' });
  }
});

// Cancel an export job
app.delete('/:id', async (c) => {
  const exportId = c.req.param('id');
  const tenantId = c.get('tenantId') as string;

  try {
    const export_ = await prisma.videoExport.findFirst({
      where: {
        id: exportId,
        tenantId
      }
    });

    if (!export_) {
      throw new HTTPException(404, { message: 'Export not found' });
    }

    if (export_.status === 'completed') {
      throw new HTTPException(400, { message: 'Cannot cancel completed export' });
    }

    // Cancel the job in the queue
    if (export_.jobId) {
      await videoProcessor.cancelJob(export_.jobId);
    }

    // Update export status
    await prisma.videoExport.update({
      where: { id: exportId },
      data: {
        status: 'cancelled',
        updatedAt: new Date()
      }
    });

    return c.json({ message: 'Export cancelled successfully' });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    console.error('Failed to cancel export:', error);
    throw new HTTPException(500, { message: 'Failed to cancel export' });
  }
});

// Get queue statistics (admin endpoint)
app.get('/queue/stats', async (c) => {
  // Check admin permissions
  const userRole = c.get('userRole') as string;
  if (userRole !== 'admin') {
    throw new HTTPException(403, { message: 'Admin access required' });
  }

  try {
    const stats = await videoProcessor.getQueueStats();
    return c.json(stats);
  } catch (error) {
    console.error('Failed to get queue stats:', error);
    throw new HTTPException(500, { message: 'Failed to get queue statistics' });
  }
});

// Setup event listeners for job updates
videoProcessor.on('job:completed', async ({ jobId, result }) => {
  try {
    await prisma.videoExport.update({
      where: { id: jobId },
      data: {
        status: 'completed',
        outputUrl: result.outputUrl,
        metadata: {
          ...result.metadata,
          duration: result.duration,
          format: result.format,
          fileSize: result.fileSize,
          thumbnailUrl: result.thumbnailUrl
        },
        completedAt: new Date(),
        updatedAt: new Date()
      }
    });
  } catch (error) {
    console.error(`Failed to update export ${jobId} on completion:`, error);
  }
});

videoProcessor.on('job:failed', async ({ jobId, error }) => {
  try {
    await prisma.videoExport.update({
      where: { id: jobId },
      data: {
        status: 'failed',
        metadata: {
          error: error.message || error
        },
        updatedAt: new Date()
      }
    });
  } catch (error) {
    console.error(`Failed to update export ${jobId} on failure:`, error);
  }
});

export default app;