import { Hono } from 'hono';
import { stream } from 'hono/streaming';
import { jwt } from 'hono/jwt';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { promises as fs } from 'fs';
import { createReadStream, createWriteStream, existsSync } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import crypto from 'crypto';
import { z } from 'zod';

const execAsync = promisify(exec);

// Types and schemas
const StreamQualitySchema = z.enum(['high', 'medium', 'low', 'auto']);
const StreamTypeSchema = z.enum(['live', 'recorded']);
const ExportFormatSchema = z.enum(['mp4', 'hls', 'webm']);

interface StreamSession {
  sessionId: string;
  cameraId: string;
  tenantId: string;
  userId: string;
  quality: string;
  startTime: Date;
  lastActivity: Date;
  type: 'live' | 'recorded';
}

interface VideoExportRequest {
  cameraId: string;
  startTime: string;
  endTime: string;
  format: 'mp4' | 'hls' | 'webm';
  quality: 'high' | 'medium' | 'low';
  includeWatermark: boolean;
  reason: string;
  requestedBy: string;
}

interface ChainOfCustodyLog {
  exportId: string;
  cameraId: string;
  tenantId: string;
  userId: string;
  startTime: string;
  endTime: string;
  format: string;
  quality: string;
  watermarkId?: string;
  fileHash: string;
  timestamp: string;
  reason: string;
  ipAddress: string;
  userAgent: string;
}

// In-memory session store (in production, use Redis)
const activeSessions = new Map<string, StreamSession>();
const maxConcurrentStreams = 1000;

const app = new Hono();

// Middleware
app.use('*', cors());
app.use('*', logger());

// JWT Authentication middleware
app.use('*', jwt({
  secret: process.env.JWT_SECRET || 'your-secret-key',
}));

// Tenant isolation middleware
app.use('*', async (c, next) => {
  const payload = c.get('jwtPayload');
  if (!payload?.tenantId) {
    return c.json({ error: 'Tenant ID required' }, 401);
  }
  c.set('tenantId', payload.tenantId);
  c.set('userId', payload.userId);
  await next();
});

// Rate limiting middleware for streaming
app.use('/stream/*', async (c, next) => {
  const tenantId = c.get('tenantId');
  const activeSessionsForTenant = Array.from(activeSessions.values())
    .filter(session => session.tenantId === tenantId);
  
  if (activeSessionsForTenant.length >= 100) { // Per-tenant limit
    return c.json({ error: 'Maximum concurrent streams reached for tenant' }, 429);
  }
  
  if (activeSessions.size >= maxConcurrentStreams) {
    return c.json({ error: 'Maximum system concurrent streams reached' }, 429);
  }
  
  await next();
});

// Utility functions
function generateSessionId(): string {
  return crypto.randomUUID();
}

function getVideoPath(tenantId: string, cameraId: string, type: 'live' | 'recorded'): string {
  return path.join(process.env.VIDEO_STORAGE_PATH || '/var/video', tenantId, cameraId, type);
}

function getHLSPath(tenantId: string, cameraId: string, quality: string): string {
  return path.join(getVideoPath(tenantId, cameraId, 'live'), 'hls', quality);
}

async function validateCameraAccess(tenantId: string, userId: string, cameraId: string): Promise<boolean> {
  // In production, check database for camera permissions
  // For now, assume access is granted if camera belongs to tenant
  return true;
}

async function generateHLSStream(inputPath: string, outputDir: string): Promise<void> {
  await fs.mkdir(outputDir, { recursive: true });
  
  const ffmpegCommand = `ffmpeg -i "${inputPath}" \
    -filter:v:0 scale=w=1920:h=1080:force_original_aspect_ratio=decrease -b:v:0 5000k \
    -filter:v:1 scale=w=1280:h=720:force_original_aspect_ratio=decrease -b:v:1 2800k \
    -filter:v:2 scale=w=854:h=480:force_original_aspect_ratio=decrease -b:v:2 1400k \
    -map 0:v -map 0:a \
    -c:a aac -ar 48000 -c:v h264 -profile:v main -crf 20 -sc_threshold 0 \
    -g 48 -keyint_min 48 -hls_time 4 -hls_playlist_type vod \
    -hls_segment_filename "${outputDir}/%v_%03d.ts" \
    -master_pl_name master.m3u8 \
    -f hls -var_stream_map "v:0,a:0 v:1,a:0 v:2,a:0" \
    "${outputDir}/%v.m3u8"`;
  
  await execAsync(ffmpegCommand);
}

async function addWatermark(inputPath: string, outputPath: string, watermarkText: string, tenantId: string): Promise<string> {
  const watermarkId = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const watermarkString = `${watermarkText} | ${timestamp} | ${watermarkId}`;
  
  const ffmpegCommand = `ffmpeg -i "${inputPath}" \
    -vf "drawtext=text='${watermarkString}':fontcolor=white:fontsize=24:box=1:boxcolor=black@0.5:boxborderw=5:x=w-tw-10:y=h-th-10" \
    -codec:a copy "${outputPath}"`;
  
  await execAsync(ffmpegCommand);
  return watermarkId;
}

async function logChainOfCustody(log: ChainOfCustodyLog): Promise<void> {
  const logDir = path.join(process.env.AUDIT_LOG_PATH || '/var/logs/audit', log.tenantId);
  await fs.mkdir(logDir, { recursive: true });
  
  const logFile = path.join(logDir, 'video_exports.jsonl');
  await fs.appendFile(logFile, JSON.stringify(log) + '\n');
}

function calculateFileHash(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = createReadStream(filePath);
    
    stream.on('data', data => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// Routes

// Get live stream (HLS master playlist)
app.get('/stream/live/:cameraId', async (c) => {
  const cameraId = c.req.param('cameraId');
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const quality = c.req.query('quality') || 'auto';
  
  // Validate camera access
  if (!await validateCameraAccess(tenantId, userId, cameraId)) {
    return c.json({ error: 'Camera access denied' }, 403);
  }
  
  // Create session
  const sessionId = generateSessionId();
  const session: StreamSession = {
    sessionId,
    cameraId,
    tenantId,
    userId,
    quality,
    startTime: new Date(),
    lastActivity: new Date(),
    type: 'live'
  };
  activeSessions.set(sessionId, session);
  
  // Get HLS master playlist path
  const hlsDir = getHLSPath(tenantId, cameraId, 'master');
  const masterPlaylistPath = path.join(hlsDir, 'master.m3u8');
  
  if (!existsSync(masterPlaylistPath)) {
    return c.json({ error: 'Live stream not available' }, 404);
  }
  
  try {
    const playlist = await fs.readFile(masterPlaylistPath, 'utf-8');
    
    // Add session ID to playlist URLs
    const modifiedPlaylist = playlist.replace(
      /^([^#].*\.m3u8)$/gm,
      `$1?session=${sessionId}`
    );
    
    return c.body(modifiedPlaylist, 200, {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-cache',
      'Access-Control-Allow-Origin': '*'
    });
  } catch (error) {
    return c.json({ error: 'Failed to read playlist' }, 500);
  }
});

// Get quality-specific playlist
app.get('/stream/live/:cameraId/:quality.m3u8', async (c) => {
  const cameraId = c.req.param('cameraId');
  const quality = c.req.param('quality');
  const sessionId = c.req.query('session');
  const tenantId = c.get('tenantId');
  
  // Validate session
  const session = activeSessions.get(sessionId || '');
  if (!session || session.tenantId !== tenantId || session.cameraId !== cameraId) {
    return c.json({ error: 'Invalid session' }, 401);
  }
  
  // Update session activity
  session.lastActivity = new Date();
  
  const playlistPath = path.join(getHLSPath(tenantId, cameraId, quality), `${quality}.m3u8`);
  
  if (!existsSync(playlistPath)) {
    return c.json({ error: 'Playlist not found' }, 404);
  }
  
  try {
    const playlist = await fs.readFile(playlistPath, 'utf-8');
    
    // Add session ID to segment URLs
    const modifiedPlaylist = playlist.replace(
      /^([^#].*\.ts)$/gm,
      `$1?session=${sessionId}`
    );
    
    return c.body(modifiedPlaylist, 200, {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-cache'
    });
  } catch (error) {
    return c.json({ error: 'Failed to read playlist' }, 500);
  }
});

// Get video segments
app.get('/stream/live/:cameraId/:segment', async (c) => {
  const cameraId = c.req.param('cameraId');
  const segment = c.req.param('segment');
  const sessionId = c.req.query('session');
  const tenantId = c.get('tenantId');
  
  // Validate session
  const session = activeSessions.get(sessionId || '');
  if (!session || session.tenantId !== tenantId || session.cameraId !== cameraId) {
    return c.json({ error: 'Invalid session' }, 401);
  }
  
  // Update session activity
  session.lastActivity = new Date();
  
  // Determine quality from segment name
  const quality = segment.includes('_0_') ? 'high' : 
                 segment.includes('_1_') ? 'medium' : 'low';
  
  const segmentPath = path.join(getHLSPath(tenantId, cameraId, quality), segment);
  
  if (!existsSync(segmentPath)) {
    return c.json({ error: 'Segment not found' }, 404);
  }
  
  return stream(c, async (stream) => {
    const fileStream = createReadStream(segmentPath);
    await stream.pipe(fileStream);
  }, {
    'Content-Type': 'video/MP2T',
    'Cache-Control': 'max-age=3600'
  });
});

// Get recorded video stream
app.get('/stream/recorded/:cameraId', async (c) => {
  const cameraId = c.req.param('cameraId');
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const startTime = c.req.query('start');
  const endTime = c.req.query('end');
  const quality = c.req.query('quality') || 'medium';
  
  if (!startTime || !endTime) {
    return c.json({ error: 'Start and end time required' }, 400);
  }
  
  // Validate camera access
  if (!await validateCameraAccess(tenantId, userId, cameraId)) {
    return c.json({ error: 'Camera access denied' }, 403);
  }
  
  // Create session
  const sessionId = generateSessionId();
  const session: StreamSession = {
    sessionId,
    cameraId,
    tenantId,
    userId,
    quality,
    startTime: new Date(),
    lastActivity: new Date(),
    type: 'recorded'
  };
  activeSessions.set(sessionId, session);
  
  // Generate HLS for recorded video segment
  const recordedDir = getVideoPath(tenantId, cameraId, 'recorded');
  const outputDir = path.join(recordedDir, 'hls', sessionId);
  
  try {
    // In production, this would query the database for recorded segments
    // and concatenate them into a single stream
    const inputPath = path.join(recordedDir, `${startTime}_${endTime}.mp4`);
    
    if (!existsSync(inputPath)) {
      return c.json({ error: 'Recorded video not found' }, 404);
    }
    
    await generateHLSStream(inputPath, outputDir);
    
    const masterPlaylistPath = path.join(outputDir, 'master.m3u8');
    const playlist = await fs.readFile(masterPlaylistPath, 'utf-8');
    
    // Add session ID to playlist URLs
    const modifiedPlaylist = playlist.replace(
      /^([^#].*\.m3u8)$/gm,
      `recorded/$1?session=${sessionId}`
    );
    
    return c.body(modifiedPlaylist, 200, {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-cache'
    });
  } catch (error) {
    return c.json({ error: 'Failed to generate recorded stream' }, 500);
  }
});

// Export video with watermark and chain of custody
app.post('/export', async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  
  try {
    const body = await c.req.json();
    const exportRequest = body as VideoExportRequest;
    
    // Validate request
    if (!exportRequest.cameraId || !exportRequest.startTime || !exportRequest.endTime) {
      return c.json({ error: 'Missing required fields' }, 400);
    }
    
    // Validate camera access
    if (!await validateCameraAccess(tenantId, userId, exportRequest.cameraId)) {
      return c.json({ error: 'Camera access denied' }, 403);
    }
    
    const exportId = crypto.randomUUID();
    const recordedDir = getVideoPath(tenantId, exportRequest.cameraId, 'recorded');
    const exportDir = path.join(process.env.EXPORT_PATH || '/var/exports', tenantId, exportId);
    await fs.mkdir(exportDir, { recursive: true });
    
    // In production, query database for video segments and concatenate
    const inputPath = path.join(recordedDir, `${exportRequest.startTime}_${exportRequest.endTime}.mp4`);
    
    if (!existsSync(inputPath)) {
      return c.json({ error: 'Video not found for specified time range' }, 404);
    }
    
    let outputPath = path.join(exportDir, `export.${exportRequest.format}`);
    let watermarkId: string | undefined;
    
    // Add watermark if requested
    if (exportRequest.includeWatermark) {
      const watermarkText = `SPARC Export | Camera: ${exportRequest.cameraId} | User: ${exportRequest.requestedBy}`;
      watermarkId = await addWatermark(inputPath, outputPath, watermarkText, tenantId);
    } else {
      // Copy without watermark
      await fs.copyFile(inputPath, outputPath);
    }
    
    // Calculate file hash for integrity
    const fileHash = await calculateFileHash(outputPath);
    
    // Log chain of custody
    const custodyLog: ChainOfCustodyLog = {
      exportId,
      cameraId: exportRequest.cameraId,
      tenantId,
      userId,
      startTime: exportRequest.startTime,
      endTime: exportRequest.endTime,
      format: exportRequest.format,
      quality: exportRequest.quality,
      watermarkId,
      fileHash,
      timestamp: new Date().toISOString(),
      reason: exportRequest.reason,
      ipAddress: c.req.header('x-forwarded-for') || 'unknown',
      userAgent: c.req.header('user-agent') || 'unknown'
    };
    
    await logChainOfCustody(custodyLog);
    
    return c.json({
      exportId,
      downloadUrl: `/export/download/${exportId}`,
      fileHash,
      watermarkId,
      timestamp: custodyLog.timestamp
    });
    
  } catch (error) {
    console.error('Export error:', error);
    return c.json({ error: 'Export failed' }, 500);
  }
});

// Download exported video
app.get('/export/download/:exportId', async (c) => {
  const exportId = c.req.param('exportId');
  const tenantId = c.get('tenantId');
  
  const exportDir = path.join(process.env.EXPORT_PATH || '/var/exports', tenantId, exportId);
  const files = await fs.readdir(exportDir).catch(() => []);
  const exportFile = files.find(f => f.startsWith('export.'));
  
  if (!exportFile) {
    return c.json({ error: 'Export not found' }, 404);
  }
  
  const filePath = path.join(exportDir, exportFile);
  const stats = await fs.stat(filePath);
  
  return stream(c, async (stream) => {
    const fileStream = createReadStream(filePath);
    await stream.pipe(fileStream);
  }, {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${exportFile}"`,
    'Content-Length': stats.size.toString()
  });
});

// Get export status and chain of custody
app.get('/export/:exportId/custody', async (c) => {
  const exportId = c.req.param('exportId');
  const tenantId = c.get('tenantId');
  
  try {
    const logFile = path.join(process.env.AUDIT_LOG_PATH || '/var/logs/audit', tenantId, 'video_exports.jsonl');
    const logContent = await fs.readFile(logFile, 'utf-8');
    const logs = logContent.split('\n').filter(line => line.trim());
    
    const exportLog = logs
      .map(line => JSON.parse(line))
      .find(log => log.exportId === exportId);
    
    if (!exportLog) {
      return c.json({ error: 'Export not found' }, 404);
    }
    
    return c.json(exportLog);
  } catch (error) {
    return c.json({ error: 'Failed to retrieve chain of custody' }, 500);
  }
});

// Close streaming session
app.delete('/stream/session/:sessionId', async (c) => {
  const sessionId = c.req.param('sessionId');
  const tenantId = c.get('tenantId');
  
  const session = activeSessions.get(sessionId);
  if (!session || session.tenantId !== tenantId) {
    return c.json({ error: 'Session not found' }, 404);
  }
  
  activeSessions.delete(sessionId);
  
  // Clean up temporary HLS files for recorded streams
  if (session.type === 'recorded') {
    const tempDir = path.join(getVideoPath(tenantId, session.cameraId, 'recorded'), 'hls', sessionId);
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
  
  return c.json({ message: 'Session closed' });
});

// Get active sessions (admin only)
app.get('/sessions', async (c) => {
  const tenantId = c.get('tenantId');
  
  const tenantSessions = Array.from(activeSessions.values())
    .filter(session => session.tenantId === tenantId)
    .map(session => ({
      sessionId: session.sessionId,
      cameraId: session.cameraId,
      quality: session.quality,
      startTime: session.startTime,
      lastActivity: session.lastActivity,
      type: session.type
    }));
  
  return c.json({
    sessions: tenantSessions,
    totalSessions: tenantSessions.length,
    maxConcurrentStreams: 100 // Per-tenant limit
  });
});

// Health check
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    activeSessions: activeSessions.size,
    maxConcurrentStreams,
    timestamp: new Date().toISOString()
  });
});

// Cleanup inactive sessions (run periodically)
setInterval(() => {
  const now = new Date();
  const timeout = 5 * 60 * 1000; // 5 minutes
  
  for (const [sessionId, session] of activeSessions.entries()) {
    if (now.getTime() - session.lastActivity.getTime() > timeout) {
      activeSessions.delete(sessionId);
      
      // Clean up temporary files
      if (session.type === 'recorded') {
        const tempDir = path.join(getVideoPath(session.tenantId, session.cameraId, 'recorded'), 'hls', sessionId);
        fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
      }
    }
  }
}, 60000); // Check every minute

export default app;