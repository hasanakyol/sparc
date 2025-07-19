import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import crypto from 'crypto';

// Import protocol handlers
import { MobileCredentialMeshNetwork } from './protocols/mesh-network';

// Import route modules
import { createCredentialsRoutes } from './routes/credentials';
import { createBiometricRoutes } from './routes/biometric';
import { createDeviceManagementRoutes } from './routes/device-management';
import { createMeshNetworkRoutes } from './routes/mesh-network';

// Import offline sync handler
import { createOfflineSyncRoutes } from './routes/offline-sync';

// Configuration
const config = {
  port: parseInt(process.env.PORT || '3016'),
  jwtSecret: process.env.JWT_SECRET || 'default-jwt-secret',
  encryptionKey: process.env.ENCRYPTION_KEY || 'default-encryption-key',
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  meshNetworkEnabled: process.env.MESH_NETWORK_ENABLED !== 'false',
  deviceId: process.env.DEVICE_ID || crypto.randomUUID(),
  biometric: {
    maxAttempts: parseInt(process.env.BIOMETRIC_MAX_ATTEMPTS || '5'),
    lockoutDuration: parseInt(process.env.BIOMETRIC_LOCKOUT_DURATION || '300')
  },
  minAppVersion: process.env.MIN_APP_VERSION || '1.0.0'
};

// Initialize services
const app = new Hono();
const prisma = new PrismaClient();
const redis = new Redis(config.redisUrl);

// Initialize mesh network if enabled
let meshNetwork: MobileCredentialMeshNetwork | null = null;
if (config.meshNetworkEnabled) {
  meshNetwork = new MobileCredentialMeshNetwork(config.deviceId, console);
}

// Middleware
app.use('*', cors());
app.use('*', logger());
app.use('*', prettyJSON());

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    service: 'mobile-credential-service',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    meshNetworkEnabled: config.meshNetworkEnabled
  });
});

// Mount route modules
app.route('/api/credentials', createCredentialsRoutes(prisma, redis, config));
app.route('/api/credentials', createBiometricRoutes(prisma, config));
app.route('/api/device-management', createDeviceManagementRoutes(prisma, redis, config));
app.route('/api/sync', createOfflineSyncRoutes(prisma, redis, config));

if (meshNetwork) {
  app.route('/api/mesh', createMeshNetworkRoutes(config, meshNetwork));
}

// Self-service enrollment endpoint (public)
app.post('/api/self-service/enroll', async (c) => {
  try {
    const body = await c.req.json();
    const { enrollmentToken, ...enrollmentData } = body;

    // Verify enrollment token
    const tokenData = await redis.get(`enrollment_token:${enrollmentToken}`);
    if (!tokenData) {
      return c.json({ error: 'Invalid or expired enrollment token' }, 401);
    }

    const { userId, tenantId } = JSON.parse(tokenData);
    
    // Import credential service to handle enrollment
    const { CredentialService } = await import('./services/credential-service');
    const credentialService = new CredentialService(prisma, redis, config);
    
    const result = await credentialService.enrollCredential(enrollmentData, userId, tenantId);

    // Delete used token
    await redis.del(`enrollment_token:${enrollmentToken}`);

    return c.json(result, 201);
  } catch (error: any) {
    return c.json({ error: error.message }, 400);
  }
});

// Error handling
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  }, 500);
});

// Initialize mesh network on startup
async function startServer() {
  try {
    // Connect to database
    await prisma.$connect();
    console.log('Connected to database');

    // Initialize mesh network
    if (meshNetwork) {
      await meshNetwork.initialize();
      console.log('Mesh network initialized');

      // Set up mesh event handlers
      meshNetwork.on('credentialRevocation', async (data) => {
        console.log('Received credential revocation via mesh:', data);
        // Handle mesh credential revocation
      });

      meshNetwork.on('deviceWipe', async (data) => {
        console.log('Received device wipe via mesh:', data);
        // Handle mesh device wipe
      });
    }

    // Start HTTP server
    const server = Bun.serve({
      port: config.port,
      fetch: app.fetch
    });

    console.log(`Mobile Credential Service running on port ${config.port}`);
    if (config.meshNetworkEnabled) {
      console.log(`Mesh networking enabled with device ID: ${config.deviceId}`);
    }
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  
  if (meshNetwork) {
    await meshNetwork.shutdown();
  }
  
  await prisma.$disconnect();
  await redis.quit();
  
  process.exit(0);
});

// Start the server
startServer();

export default app;