/**
 * Example usage of the SPARC caching layer
 */

import { 
  createCacheManager, 
  CacheManager,
  Cacheable,
  CacheInvalidate 
} from '../index';

// Initialize cache manager
const cacheManager = createCacheManager({
  cache: {
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
    },
    defaultTTL: 3600, // 1 hour
    enableCircuitBreaker: true,
    enableMetrics: true,
  },
  tenant: {
    ttl: {
      tenant: 7200, // 2 hours
      organization: 3600, // 1 hour
      site: 3600, // 1 hour
    },
  },
  session: {
    ttl: {
      session: 86400, // 24 hours
      accessToken: 900, // 15 minutes
    },
    maxConcurrentSessions: 5,
  },
  monitoring: {
    interval: 60000, // 1 minute
    alertThresholds: {
      hitRate: 0.5, // Alert if hit rate < 50%
      errorRate: 0.05, // Alert if error rate > 5%
      memoryUsage: 1024 * 1024 * 1024, // 1GB
      responseTime: 100, // 100ms
    },
  },
});

// Start monitoring
cacheManager.startMonitoring();

// Listen for alerts
cacheManager.monitor.on('alert', (alert) => {
  console.error('Cache alert:', alert);
  // Send to monitoring system
});

// Example service using cache decorators
class TenantService {
  constructor(private cache: CacheManager) {}

  @Cacheable({ ttl: 3600, tags: ['tenant'] })
  async getTenant(tenantId: string) {
    // This will be cached automatically
    console.log('Fetching tenant from database...');
    // Simulate database call
    return {
      id: tenantId,
      name: 'Example Tenant',
      settings: {},
    };
  }

  @CacheInvalidate({ tags: ['tenant'] })
  async updateTenant(tenantId: string, data: any) {
    // Update tenant in database
    console.log('Updating tenant...');
    // Cache will be invalidated automatically
    return { id: tenantId, ...data };
  }
}

// Example: Using tenant cache
async function tenantCacheExample() {
  const tenantId = 'tenant-123';
  
  // Get tenant (will hit database)
  const tenant1 = await cacheManager.tenant.getTenant(tenantId);
  console.log('First fetch:', tenant1);

  // Set tenant in cache
  await cacheManager.tenant.setTenant({
    id: tenantId,
    name: 'ACME Corp',
    domain: 'acme.com',
    settings: {
      limits: { doors: 100, cameras: 50, storage_gb: 1000 },
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  // Get tenant again (will hit cache)
  const tenant2 = await cacheManager.tenant.getTenant(tenantId);
  console.log('Second fetch (from cache):', tenant2);

  // Invalidate tenant cache
  await cacheManager.tenant.invalidateTenant(tenantId);
}

// Example: Using session cache
async function sessionCacheExample() {
  const userId = 'user-123';
  const sessionId = 'session-456';
  const tenantId = 'tenant-123';

  // Create session
  await cacheManager.session.setSession({
    id: sessionId,
    userId,
    tenantId,
    accessToken: 'access-token-789',
    refreshToken: 'refresh-token-abc',
    deviceInfo: {
      userAgent: 'Mozilla/5.0...',
      ipAddress: '192.168.1.1',
    },
    createdAt: new Date().toISOString(),
    lastAccessedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86400000).toISOString(), // 24 hours
    active: true,
  });

  // Get session
  const session = await cacheManager.session.getSession(sessionId);
  console.log('Session:', session);

  // Check failed login attempts
  const attempts = await cacheManager.session.getFailedLoginAttempts('user@example.com', tenantId);
  console.log('Failed login attempts:', attempts);

  // Update session activity
  await cacheManager.session.updateSessionActivity(sessionId);
}

// Example: Using permission cache
async function permissionCacheExample() {
  const userId = 'user-123';
  const tenantId = 'tenant-123';

  // Set user permissions
  await cacheManager.permission.setUserPermissions(userId, tenantId, {
    role: 'admin',
    permissions: {
      system: { admin: true, config: true, users: true },
      access: { doors: ['all'], schedules: ['all'] },
      video: { cameras: ['all'], live: true, playback: true },
    },
  });

  // Get user permissions
  const permissions = await cacheManager.permission.getUserPermissions(userId, tenantId);
  console.log('User permissions:', permissions);

  // Check door access
  const doorId = 'door-789';
  let hasAccess = await cacheManager.permission.getUserDoorAccess(userId, doorId, tenantId);
  
  if (hasAccess === null) {
    // Not cached, calculate and cache
    hasAccess = true; // Simulate permission check
    await cacheManager.permission.setUserDoorAccess(userId, doorId, tenantId, hasAccess);
  }
  
  console.log('Door access:', hasAccess);
}

// Example: Using video cache
async function videoCacheExample() {
  const cameraId = 'camera-123';
  
  // Set camera metadata
  await cacheManager.video.setCamera({
    id: cameraId,
    floor_id: 'floor-456',
    name: 'Main Entrance Camera',
    hardware: {
      ip_address: '192.168.1.100',
      manufacturer: 'Axis',
      model: 'P3225',
      streams: [
        { resolution: 'high', url: 'rtsp://...' },
        { resolution: 'medium', url: 'rtsp://...' },
        { resolution: 'low', url: 'rtsp://...' },
      ],
    },
    settings: {
      recording_enabled: true,
      motion_detection: true,
      retention_days: 30,
    },
    status: 'online',
    created_at: new Date().toISOString(),
  });

  // Get camera
  const camera = await cacheManager.video.getCamera(cameraId);
  console.log('Camera:', camera);

  // Set stream URL
  await cacheManager.video.setStreamUrl(cameraId, 'high', 'https://cdn.example.com/stream/high.m3u8');
  
  // Get stream URL
  const streamUrl = await cacheManager.video.getStreamUrl(cameraId, 'high');
  console.log('Stream URL:', streamUrl);
}

// Example: Using analytics cache
async function analyticsCacheExample() {
  const tenantId = 'tenant-123';
  
  // Set real-time metrics
  await cacheManager.analytics.setRealtimeMetrics(tenantId, {
    activeUsers: 42,
    openDoors: 3,
    activeAlerts: 1,
    onlineCameras: 25,
    systemLoad: 0.65,
  });

  // Get real-time metrics
  const metrics = await cacheManager.analytics.getRealtimeMetrics(tenantId);
  console.log('Real-time metrics:', metrics);

  // Set access statistics
  await cacheManager.analytics.setAccessStats(tenantId, 'hour', {
    totalEvents: 156,
    granted: 150,
    denied: 5,
    forced: 0,
    ajar: 1,
    byDoor: { 'door-123': 45, 'door-456': 35 },
    byUser: { 'user-123': 12, 'user-456': 8 },
  });

  // Batch get multiple metrics
  const batchMetrics = await cacheManager.analytics.batchGetMetrics(tenantId, [
    'activeUsers',
    'systemLoad',
    'cameraStatus',
  ]);
  console.log('Batch metrics:', batchMetrics);
}

// Example: Cache warming
async function cacheWarmingExample() {
  await cacheManager.warmup({
    tenants: {
      tenants: [
        {
          id: 'tenant-1',
          name: 'Tenant 1',
          domain: 'tenant1.com',
          settings: { limits: { doors: 100, cameras: 50, storage_gb: 1000 } },
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ],
      organizations: [
        {
          id: 'org-1',
          tenant_id: 'tenant-1',
          name: 'Organization 1',
          active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ],
    },
  });
  
  console.log('Cache warmed up');
}

// Example: Health check
async function healthCheckExample() {
  const health = await cacheManager.getHealth();
  console.log('Cache health:', health);
  
  // Export metrics for Prometheus
  const prometheusMetrics = cacheManager.monitor.exportMetrics('prometheus');
  console.log('Prometheus metrics:\n', prometheusMetrics);
}

// Example: Event-driven invalidation
function setupInvalidation() {
  if (cacheManager.invalidation) {
    // Trigger invalidation on user update
    cacheManager.invalidation.emit('user.updated', {
      userId: 'user-123',
      tenantId: 'tenant-123',
    });

    // Schedule periodic invalidation
    cacheManager.invalidation.scheduleInvalidation(
      'stale-streams',
      300000, // 5 minutes
      ['stream:*'],
      ['stream']
    );

    // Manual invalidation endpoint
    cacheManager.invalidation.manualInvalidate({
      patterns: ['tenant:123:*'],
      tags: ['tenant:123'],
    });
  }
}

// Run examples
async function runExamples() {
  try {
    console.log('=== Tenant Cache Example ===');
    await tenantCacheExample();
    
    console.log('\n=== Session Cache Example ===');
    await sessionCacheExample();
    
    console.log('\n=== Permission Cache Example ===');
    await permissionCacheExample();
    
    console.log('\n=== Video Cache Example ===');
    await videoCacheExample();
    
    console.log('\n=== Analytics Cache Example ===');
    await analyticsCacheExample();
    
    console.log('\n=== Cache Warming Example ===');
    await cacheWarmingExample();
    
    console.log('\n=== Health Check Example ===');
    await healthCheckExample();
    
    console.log('\n=== Setting up Invalidation ===');
    setupInvalidation();
    
    // Get cache statistics
    const stats = cacheManager.core.getStats();
    console.log('\n=== Cache Statistics ===');
    console.log('Hit rate:', (stats.hitRate * 100).toFixed(2) + '%');
    console.log('Total operations:', stats.hits + stats.misses + stats.sets);
    console.log('Errors:', stats.errors);
    console.log('Avg GET time:', stats.avgGetTime.toFixed(2) + 'ms');
    console.log('Avg SET time:', stats.avgSetTime.toFixed(2) + 'ms');
    
  } catch (error) {
    console.error('Example error:', error);
  } finally {
    // Cleanup
    await cacheManager.disconnect();
  }
}

// Run if called directly
if (require.main === module) {
  runExamples();
}