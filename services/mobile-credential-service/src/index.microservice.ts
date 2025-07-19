import { MicroserviceBase, ServiceConfig } from '@shared/patterns/service-base';
import { createCredentialsRoutes } from './routes/credentials';
import { createBiometricRoutes } from './routes/biometric';
import { createDeviceManagementRoutes } from './routes/device-management';
import { createMeshNetworkRoutes } from './routes/mesh-network';
import { createOfflineSyncRoutes } from './routes/offline-sync';
import { MobileCredentialMeshNetwork } from './protocols/mesh-network';

class MobileCredentialService extends MicroserviceBase {
  private meshNetwork: MobileCredentialMeshNetwork | null = null;

  constructor(config: ServiceConfig) {
    super(config);
    
    // Initialize mesh network if enabled
    if (process.env.MESH_NETWORK_ENABLED !== 'false') {
      this.meshNetwork = new MobileCredentialMeshNetwork(
        process.env.DEVICE_ID || crypto.randomUUID(),
        console
      );
    }
  }

  public setupRoutes(): void {
    // Mount route modules with standardized paths
    this.app.route('/api/v1/credentials', createCredentialsRoutes(this.prisma, this.redis, this.config));
    this.app.route('/api/v1/credentials', createBiometricRoutes(this.prisma, this.config));
    this.app.route('/api/v1/device-management', createDeviceManagementRoutes(this.prisma, this.redis, this.config));
    this.app.route('/api/v1/sync', createOfflineSyncRoutes(this.prisma, this.redis, this.config));

    if (this.meshNetwork) {
      this.app.route('/api/v1/mesh', createMeshNetworkRoutes(this.config, this.meshNetwork));
    }

    // Public endpoints (no auth required)
    this.app.post('/api/v1/self-service/enroll', async (c) => {
      try {
        const body = await c.req.json();
        const { enrollmentToken, ...enrollmentData } = body;

        // Verify enrollment token
        const tokenData = await this.redis.get(`enrollment_token:${enrollmentToken}`);
        if (!tokenData) {
          return c.json({ error: 'Invalid or expired enrollment token' }, 401);
        }

        const { userId, tenantId } = JSON.parse(tokenData);
        
        // Import credential service to handle enrollment
        const { CredentialService } = await import('./services/credential-service');
        const credentialService = new CredentialService(this.prisma, this.redis, this.config);
        
        const result = await credentialService.enrollCredential(enrollmentData, userId, tenantId);

        // Delete used token
        await this.redis.del(`enrollment_token:${enrollmentToken}`);

        return c.json(result, 201);
      } catch (error: any) {
        return c.json({ error: error.message }, 400);
      }
    });
  }

  protected async customHealthChecks(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};

    // Check mesh network health
    if (this.meshNetwork) {
      try {
        checks.meshNetwork = true; // Would check actual mesh status
      } catch {
        checks.meshNetwork = false;
      }
    }

    return checks;
  }

  protected async cleanup(): Promise<void> {
    // Shutdown mesh network
    if (this.meshNetwork) {
      await this.meshNetwork.shutdown();
    }
  }

  public async start(): Promise<void> {
    // Initialize mesh network before starting
    if (this.meshNetwork) {
      await this.meshNetwork.initialize();
      console.log('Mesh network initialized');

      // Set up mesh event handlers
      this.meshNetwork.on('credentialRevocation', async (data) => {
        console.log('Received credential revocation via mesh:', data);
        await this.handleMeshRevocation(data);
      });

      this.meshNetwork.on('deviceWipe', async (data) => {
        console.log('Received device wipe via mesh:', data);
        await this.handleMeshDeviceWipe(data);
      });
    }

    // Start the service
    await super.start();
  }

  private async handleMeshRevocation(data: any): Promise<void> {
    // Handle credential revocation received via mesh network
    try {
      const { credentialIds, reason, tenantId } = data;
      
      // Update credential status in database
      await this.prisma.mobileCredential.updateMany({
        where: {
          id: { in: credentialIds },
          tenantId
        },
        data: {
          status: 'revoked',
          revokedAt: new Date(),
          revokedReason: `Mesh revocation: ${reason}`
        }
      });

      // Invalidate cache
      for (const credentialId of credentialIds) {
        await this.redis.del(`credential:${credentialId}`);
      }

      // Publish event for other services
      await this.publishEvent('credential.revoked', {
        credentialIds,
        reason,
        source: 'mesh'
      });
    } catch (error) {
      console.error('Error handling mesh revocation:', error);
    }
  }

  private async handleMeshDeviceWipe(data: any): Promise<void> {
    // Handle device wipe received via mesh network
    try {
      const { deviceIds, tenantId } = data;
      
      // Mark all credentials on devices as wiped
      await this.prisma.mobileCredential.updateMany({
        where: {
          deviceInfo: {
            path: '$.deviceId',
            in: deviceIds
          },
          tenantId
        },
        data: {
          status: 'revoked',
          revokedAt: new Date(),
          revokedReason: 'Device wiped via mesh'
        }
      });

      // Clear device cache
      for (const deviceId of deviceIds) {
        const keys = await this.redis.keys(`device:${deviceId}:*`);
        if (keys.length > 0) {
          await this.redis.del(...keys);
        }
      }

      // Publish event
      await this.publishEvent('device.wiped', {
        deviceIds,
        source: 'mesh'
      });
    } catch (error) {
      console.error('Error handling mesh device wipe:', error);
    }
  }
}

// Create and start the service
const config: ServiceConfig = {
  serviceName: 'mobile-credential-service',
  port: parseInt(process.env.PORT || '3016'),
  version: process.env.npm_package_version || '1.0.0',
  jwtSecret: process.env.JWT_SECRET!,
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
  databaseUrl: process.env.DATABASE_URL!,
  enableAuth: true,
  enableRateLimit: true,
  enableMetrics: true,
  corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000']
};

const service = new MobileCredentialService(config);
service.start().catch(console.error);