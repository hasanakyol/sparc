import { Hono } from 'hono';
import { stream } from 'hono/streaming';
import { jwt } from 'hono/jwt';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { z } from 'zod';
import { CloudStorageService } from '../services/storageService';
import { createHash } from 'crypto';
import Redis from 'ioredis';
import { EventEmitter } from 'events';
import { Readable } from 'stream';
import { GetObjectCommand } from '@aws-sdk/client-s3';

// Types and schemas
const StreamQualitySchema = z.enum(['auto', '1080p', '720p', '480p', '360p']);
const StreamFormatSchema = z.enum(['hls', 'dash', 'mp4']);
const ExportFormatSchema = z.enum(['mp4', 'hls', 'webm']);

interface StreamSession {
  sessionId: string;
  cameraId: string;
  tenantId: string;
  userId: string;
  quality: string;
  format: string;
  startTime: Date;
  lastActivity: Date;
  type: 'live' | 'recorded' | 'cloud';
  cloudUrl?: string;
  bandwidth: number;
}

interface CloudStreamRequest {
  cameraId: string;
  startTime?: string;
  endTime?: string;
  format?: 'hls' | 'dash' | 'mp4';
  quality?: 'auto' | '1080p' | '720p' | '480p' | '360p';
}

interface AdaptiveBitrateConfig {
  qualities: Array<{
    name: string;
    width: number;
    height: number;
    bitrate: number;
    bandwidth: number;
  }>;
}

// Adaptive bitrate configuration
const ABR_CONFIG: AdaptiveBitrateConfig = {
  qualities: [
    { name: '1080p', width: 1920, height: 1080, bitrate: 5000000, bandwidth: 6500000 },
    { name: '720p', width: 1280, height: 720, bitrate: 2800000, bandwidth: 3650000 },
    { name: '480p', width: 854, height: 480, bitrate: 1400000, bandwidth: 1820000 },
    { name: '360p', width: 640, height: 360, bitrate: 800000, bandwidth: 1040000 },
  ]
};

const app = new Hono();

// Initialize services
const storageService = new CloudStorageService({
  bucket: process.env.S3_BUCKET!,
  region: process.env.AWS_REGION || 'us-east-1',
  cloudfrontDomain: process.env.CLOUDFRONT_DOMAIN,
  cloudfrontDistributionId: process.env.CLOUDFRONT_DISTRIBUTION_ID,
});

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const sessionManager = new SessionManager(redis);

// Middleware
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'Range'],
  exposeHeaders: ['Content-Range', 'Accept-Ranges', 'Content-Length'],
}));

app.use('*', logger());

// JWT Authentication
app.use('*', jwt({
  secret: process.env.JWT_SECRET || 'your-secret-key',
}));

// Tenant isolation
app.use('*', async (c, next) => {
  const payload = c.get('jwtPayload');
  if (!payload?.tenantId) {
    return c.json({ error: 'Tenant ID required' }, 401);
  }
  c.set('tenantId', payload.tenantId);
  c.set('userId', payload.userId);
  await next();
});

// Rate limiting for streaming
app.use('/stream/*', async (c, next) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  
  const rateLimitKey = `stream-rate:${tenantId}:${userId}`;
  const current = await redis.incr(rateLimitKey);
  
  if (current === 1) {
    await redis.expire(rateLimitKey, 60); // 1 minute window
  }
  
  if (current > 10) { // 10 streams per minute per user
    return c.json({ error: 'Rate limit exceeded' }, 429);
  }
  
  await next();
});

// Routes

/**
 * Get CloudFront streaming URL with adaptive bitrate support
 */
app.post('/stream/cloud', async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  
  try {
    const body = await c.req.json();
    const request = CloudStreamRequest.parse(body);
    
    // Validate camera access
    if (!await validateCameraAccess(tenantId, userId, request.cameraId)) {
      return c.json({ error: 'Camera access denied' }, 403);
    }
    
    // Generate session
    const session = await sessionManager.createSession({
      tenantId,
      userId,
      cameraId: request.cameraId,
      type: 'cloud',
      quality: request.quality || 'auto',
      format: request.format || 'hls',
    });
    
    // Generate CloudFront URLs for different qualities
    const streamingUrls: Record<string, string> = {};
    
    if (request.format === 'hls' && request.quality === 'auto') {
      // Generate master playlist URL for adaptive streaming
      const masterKey = generateMasterPlaylistKey(tenantId, request.cameraId, request.startTime);
      streamingUrls.master = await storageService.getStreamingUrl(masterKey, {
        format: 'hls',
        quality: 'auto',
      });
      
      // Generate variant playlist URLs
      for (const quality of ABR_CONFIG.qualities) {
        const variantKey = generateVariantPlaylistKey(
          tenantId,
          request.cameraId,
          quality.name,
          request.startTime
        );
        streamingUrls[quality.name] = await storageService.getStreamingUrl(variantKey, {
          format: 'hls',
          quality: quality.name as any,
        });
      }
    } else {
      // Single quality stream
      const videoKey = generateVideoKey(tenantId, request.cameraId, request.startTime);
      streamingUrls.url = await storageService.getStreamingUrl(videoKey, {
        format: request.format,
        quality: request.quality,
        startTime: request.startTime ? parseInt(request.startTime) : undefined,
        endTime: request.endTime ? parseInt(request.endTime) : undefined,
      });
    }
    
    // Generate signed URLs for secure access
    const signedUrls: Record<string, string> = {};
    for (const [key, url] of Object.entries(streamingUrls)) {
      const videoKey = extractKeyFromUrl(url);
      signedUrls[key] = await storageService.generateSignedUrl(videoKey, 3600); // 1 hour
    }
    
    return c.json({
      sessionId: session.sessionId,
      format: request.format,
      quality: request.quality,
      urls: signedUrls,
      adaptiveBitrate: request.quality === 'auto',
      bandwidth: calculateRecommendedBandwidth(request.quality),
      expiresIn: 3600,
    });
    
  } catch (error) {
    console.error('Cloud streaming error:', error);
    return c.json({ error: 'Failed to generate streaming URLs' }, 500);
  }
});

/**
 * Get HLS master playlist for adaptive bitrate streaming
 */
app.get('/stream/hls/:cameraId/master.m3u8', async (c) => {
  const cameraId = c.req.param('cameraId');
  const tenantId = c.get('tenantId');
  const sessionId = c.req.query('session');
  
  // Validate session
  const session = await sessionManager.getSession(sessionId || '');
  if (!session || session.tenantId !== tenantId || session.cameraId !== cameraId) {
    return c.json({ error: 'Invalid session' }, 401);
  }
  
  // Update session activity
  await sessionManager.updateActivity(sessionId!);
  
  // Generate master playlist
  const masterPlaylist = generateMasterPlaylist(cameraId, sessionId!);
  
  return c.body(masterPlaylist, 200, {
    'Content-Type': 'application/vnd.apple.mpegurl',
    'Cache-Control': 'no-cache',
    'Access-Control-Allow-Origin': '*',
  });
});

/**
 * Get quality-specific HLS playlist
 */
app.get('/stream/hls/:cameraId/:quality/playlist.m3u8', async (c) => {
  const cameraId = c.req.param('cameraId');
  const quality = c.req.param('quality');
  const tenantId = c.get('tenantId');
  const sessionId = c.req.query('session');
  
  // Validate session
  const session = await sessionManager.getSession(sessionId || '');
  if (!session || session.tenantId !== tenantId || session.cameraId !== cameraId) {
    return c.json({ error: 'Invalid session' }, 401);
  }
  
  // Get variant playlist from S3
  const playlistKey = generateVariantPlaylistKey(tenantId, cameraId, quality);
  
  try {
    const playlist = await getS3Object(playlistKey);
    
    // Modify playlist to add session and CDN URLs
    const modifiedPlaylist = modifyPlaylistForCDN(playlist, sessionId!);
    
    return c.body(modifiedPlaylist, 200, {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'max-age=1',
    });
  } catch (error) {
    return c.json({ error: 'Playlist not found' }, 404);
  }
});

/**
 * Stream video segments with range request support
 */
app.get('/stream/segment/:cameraId/:segment', async (c) => {
  const cameraId = c.req.param('cameraId');
  const segment = c.req.param('segment');
  const tenantId = c.get('tenantId');
  const sessionId = c.req.query('session');
  
  // Validate session
  const session = await sessionManager.getSession(sessionId || '');
  if (!session || session.tenantId !== tenantId || session.cameraId !== cameraId) {
    return c.json({ error: 'Invalid session' }, 401);
  }
  
  // Handle range requests for video seeking
  const range = c.req.header('range');
  const segmentKey = generateSegmentKey(tenantId, cameraId, segment);
  
  try {
    if (range) {
      // Parse range header
      const [start, end] = parseRangeHeader(range);
      
      // Get partial content from S3
      const { stream, contentLength, contentRange } = await getS3ObjectRange(
        segmentKey,
        start,
        end
      );
      
      return c.body(stream, 206, {
        'Content-Type': 'video/MP2T',
        'Content-Length': contentLength.toString(),
        'Content-Range': contentRange,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'max-age=3600',
      });
    } else {
      // Get full segment
      const url = await storageService.getStreamingUrl(segmentKey);
      
      // Redirect to CloudFront URL for efficient delivery
      return c.redirect(url, 302);
    }
  } catch (error) {
    return c.json({ error: 'Segment not found' }, 404);
  }
});

/**
 * Export video with CloudFront acceleration
 */
app.post('/export/cloud', async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  
  try {
    const body = await c.req.json();
    const exportRequest = ExportFormatSchema.parse(body);
    
    // Generate export job
    const exportId = crypto.randomUUID();
    const exportKey = `exports/${tenantId}/${exportId}/video.${exportRequest}`;
    
    // Queue export job for processing
    await queueExportJob({
      exportId,
      tenantId,
      userId,
      ...body,
      outputKey: exportKey,
    });
    
    // Generate pre-signed URL for download (valid for 24 hours)
    const downloadUrl = await storageService.generateSignedUrl(exportKey, 86400, {
      download: true,
      filename: `export_${exportId}.${exportRequest}`,
    });
    
    return c.json({
      exportId,
      status: 'processing',
      downloadUrl,
      expiresIn: 86400,
      estimatedTime: calculateExportTime(body),
    });
    
  } catch (error) {
    console.error('Export error:', error);
    return c.json({ error: 'Export failed' }, 500);
  }
});

/**
 * Get streaming analytics
 */
app.get('/analytics/streaming', async (c) => {
  const tenantId = c.get('tenantId');
  const period = c.req.query('period') || '24h';
  
  try {
    // Get streaming metrics from CloudWatch
    const metrics = await getStreamingMetrics(tenantId, period);
    
    // Get bandwidth usage
    const bandwidthUsage = await calculateBandwidthUsage(tenantId, period);
    
    // Get popular content
    const popularContent = await getPopularContent(tenantId, period);
    
    return c.json({
      metrics,
      bandwidthUsage,
      popularContent,
      costEstimate: estimateStreamingCost(bandwidthUsage),
    });
    
  } catch (error) {
    console.error('Analytics error:', error);
    return c.json({ error: 'Failed to get analytics' }, 500);
  }
});

// Helper functions

function generateMasterPlaylist(cameraId: string, sessionId: string): string {
  const variants = ABR_CONFIG.qualities.map(quality => {
    return [
      `#EXT-X-STREAM-INF:BANDWIDTH=${quality.bandwidth},RESOLUTION=${quality.width}x${quality.height}`,
      `${quality.name}/playlist.m3u8?session=${sessionId}`
    ].join('\n');
  }).join('\n');
  
  return [
    '#EXTM3U',
    '#EXT-X-VERSION:3',
    variants
  ].join('\n');
}

function modifyPlaylistForCDN(playlist: string, sessionId: string): string {
  // Add session ID to segment URLs
  return playlist.replace(
    /^([^#].*\.ts)$/gm,
    `/stream/segment/${sessionId}/$1?session=${sessionId}`
  );
}

function parseRangeHeader(range: string): [number, number | undefined] {
  const match = range.match(/bytes=(\d+)-(\d*)/);
  if (!match) {
    throw new Error('Invalid range header');
  }
  
  const start = parseInt(match[1], 10);
  const end = match[2] ? parseInt(match[2], 10) : undefined;
  
  return [start, end];
}

async function getS3Object(key: string): Promise<string> {
  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET!,
    Key: key,
  });
  
  const response = await storageService['s3Client'].send(command);
  const stream = response.Body as Readable;
  
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', chunk => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    stream.on('error', reject);
  });
}

async function getS3ObjectRange(
  key: string,
  start: number,
  end?: number
): Promise<{ stream: Readable; contentLength: number; contentRange: string }> {
  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET!,
    Key: key,
    Range: `bytes=${start}-${end || ''}`,
  });
  
  const response = await storageService['s3Client'].send(command);
  
  return {
    stream: response.Body as Readable,
    contentLength: response.ContentLength || 0,
    contentRange: response.ContentRange || '',
  };
}

function generateMasterPlaylistKey(tenantId: string, cameraId: string, timestamp?: string): string {
  const date = timestamp ? new Date(timestamp) : new Date();
  return `streams/${tenantId}/${cameraId}/${date.toISOString().split('T')[0]}/master.m3u8`;
}

function generateVariantPlaylistKey(
  tenantId: string,
  cameraId: string,
  quality: string,
  timestamp?: string
): string {
  const date = timestamp ? new Date(timestamp) : new Date();
  return `streams/${tenantId}/${cameraId}/${date.toISOString().split('T')[0]}/${quality}/playlist.m3u8`;
}

function generateVideoKey(tenantId: string, cameraId: string, timestamp?: string): string {
  const date = timestamp ? new Date(timestamp) : new Date();
  return `recordings/${tenantId}/${cameraId}/${date.toISOString()}.mp4`;
}

function generateSegmentKey(tenantId: string, cameraId: string, segment: string): string {
  const date = new Date();
  return `streams/${tenantId}/${cameraId}/${date.toISOString().split('T')[0]}/segments/${segment}`;
}

function extractKeyFromUrl(url: string): string {
  const urlObj = new URL(url);
  return urlObj.pathname.substring(1); // Remove leading slash
}

function calculateRecommendedBandwidth(quality?: string): number {
  if (!quality || quality === 'auto') {
    return ABR_CONFIG.qualities[0].bandwidth; // Maximum bandwidth
  }
  
  const qualityConfig = ABR_CONFIG.qualities.find(q => q.name === quality);
  return qualityConfig?.bandwidth || ABR_CONFIG.qualities[2].bandwidth; // Default to 480p
}

async function validateCameraAccess(
  tenantId: string,
  userId: string,
  cameraId: string
): Promise<boolean> {
  // Implementation would check database for permissions
  return true;
}

async function queueExportJob(job: any): Promise<void> {
  // Implementation would add job to processing queue
  await redis.lpush('export-queue', JSON.stringify(job));
}

function calculateExportTime(params: any): number {
  // Estimate based on duration and quality
  const duration = params.endTime - params.startTime;
  const qualityMultiplier = params.quality === 'high' ? 2 : 1;
  return Math.ceil(duration * qualityMultiplier / 60); // minutes
}

async function getStreamingMetrics(tenantId: string, period: string): Promise<any> {
  // Implementation would query CloudWatch metrics
  return {
    totalStreams: 0,
    uniqueViewers: 0,
    averageDuration: 0,
    peakConcurrent: 0,
  };
}

async function calculateBandwidthUsage(tenantId: string, period: string): Promise<any> {
  // Implementation would calculate from CloudFront logs
  return {
    total: 0,
    byQuality: {},
    byCamera: {},
  };
}

async function getPopularContent(tenantId: string, period: string): Promise<any> {
  // Implementation would analyze access patterns
  return [];
}

function estimateStreamingCost(bandwidthUsage: any): number {
  // CloudFront pricing calculation
  const gbTransferred = bandwidthUsage.total / (1024 * 1024 * 1024);
  const costPerGb = 0.085; // USD per GB (varies by region)
  return gbTransferred * costPerGb;
}

// Session manager class
class SessionManager {
  constructor(private redis: Redis) {}
  
  async createSession(params: Partial<StreamSession>): Promise<StreamSession> {
    const session: StreamSession = {
      sessionId: crypto.randomUUID(),
      startTime: new Date(),
      lastActivity: new Date(),
      bandwidth: 0,
      ...params,
    } as StreamSession;
    
    await this.redis.setex(
      `session:${session.sessionId}`,
      3600, // 1 hour
      JSON.stringify(session)
    );
    
    return session;
  }
  
  async getSession(sessionId: string): Promise<StreamSession | null> {
    const data = await this.redis.get(`session:${sessionId}`);
    return data ? JSON.parse(data) : null;
  }
  
  async updateActivity(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.lastActivity = new Date();
      await this.redis.setex(
        `session:${sessionId}`,
        3600,
        JSON.stringify(session)
      );
    }
  }
}

export default app;