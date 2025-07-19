import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { SecurityMonitoringService } from '../services/main-service';
import { SIEMProvider } from '@sparc/shared/monitoring/types';
import { prisma } from '@sparc/shared/database/prisma';

const siemProviderSchema = z.object({
  name: z.string(),
  type: z.enum(['splunk', 'elk', 'datadog', 'qradar', 'azure-sentinel', 'sumo-logic']),
  config: z.record(z.any()),
  enabled: z.boolean().default(true)
});

const siemQuerySchema = z.object({
  provider: z.string(),
  query: z.object({
    filter: z.string().optional(),
    startTime: z.string().optional(),
    endTime: z.string().optional(),
    size: z.number().optional()
  })
});

export function siemRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Get configured SIEM providers
  app.get('/providers', async (c) => {
    const tenantId = c.get('tenantId');

    const providers = await prisma.$queryRaw`
      SELECT 
        sp.*,
        sps.last_successful_sync,
        sps.last_error,
        sps.is_connected,
        sps.events_sent_today,
        sps.events_failed_today
      FROM siem_providers sp
      LEFT JOIN siem_provider_status sps ON sp.id = sps.provider_id
      WHERE sp.organization_id = ${tenantId}
      ORDER BY sp.name
    `;

    return c.json(providers);
  });

  // Add SIEM provider
  app.post('/providers', zValidator('json', siemProviderSchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');

    const provider: SIEMProvider = {
      name: data.name,
      type: data.type,
      config: data.config,
      enabled: data.enabled
    };

    // Validate configuration based on provider type
    if (!validateProviderConfig(provider)) {
      return c.json({ error: 'Invalid provider configuration' }, 400);
    }

    // Test connection
    try {
      const testResult = await securityService.querySIEM(provider.name, {
        filter: 'test',
        size: 1
      });
    } catch (error) {
      return c.json({ 
        error: 'Failed to connect to SIEM provider',
        details: error instanceof Error ? error.message : 'Unknown error'
      }, 400);
    }

    // Store provider
    const id = crypto.randomUUID();
    await prisma.$executeRawUnsafe(`
      INSERT INTO siem_providers (
        id, name, type, config, enabled, organization_id
      ) VALUES ($1, $2, $3, $4, $5, $6)
    `,
      id,
      provider.name,
      provider.type,
      JSON.stringify(provider.config),
      provider.enabled,
      tenantId
    );

    // Initialize status
    await prisma.$executeRawUnsafe(`
      INSERT INTO siem_provider_status (
        provider_id, is_connected, last_successful_sync
      ) VALUES ($1, $2, $3)
    `,
      id,
      true,
      new Date()
    );

    return c.json({ id, ...provider }, 201);
  });

  // Update SIEM provider
  app.put('/providers/:id', zValidator('json', siemProviderSchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      UPDATE siem_providers
      SET name = $1, type = $2, config = $3, enabled = $4
      WHERE id = $5 AND organization_id = $6
    `,
      data.name,
      data.type,
      JSON.stringify(data.config),
      data.enabled,
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Delete SIEM provider
  app.delete('/providers/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      DELETE FROM siem_providers
      WHERE id = $1 AND organization_id = $2
    `,
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Test SIEM connection
  app.post('/providers/:id/test', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    const provider = await prisma.$queryRaw<any[]>`
      SELECT * FROM siem_providers
      WHERE id = ${id} AND organization_id = ${tenantId}
      LIMIT 1
    `;

    if (!provider || provider.length === 0) {
      return c.json({ error: 'Provider not found' }, 404);
    }

    try {
      const testEvent = {
        id: crypto.randomUUID(),
        timestamp: new Date(),
        eventType: 'TEST_CONNECTION',
        severity: 'INFO',
        source: 'siem-test',
        details: { test: true }
      };

      // Test sending an event
      await securityService.recordSecurityEvent({
        ...testEvent,
        organizationId: tenantId
      });

      return c.json({
        success: true,
        message: 'Connection test successful',
        testEvent
      });
    } catch (error) {
      return c.json({
        success: false,
        error: error instanceof Error ? error.message : 'Connection test failed'
      }, 500);
    }
  });

  // Query SIEM
  app.post('/query', zValidator('json', siemQuerySchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');

    try {
      const results = await securityService.querySIEM(data.provider, data.query);
      
      return c.json({
        provider: data.provider,
        query: data.query,
        results,
        count: results.length,
        timestamp: new Date()
      });
    } catch (error) {
      return c.json({
        error: 'Query failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      }, 500);
    }
  });

  // Get SIEM sync status
  app.get('/sync/status', async (c) => {
    const tenantId = c.get('tenantId');

    const syncStatus = await prisma.$queryRaw`
      SELECT 
        sp.name as provider_name,
        sp.type as provider_type,
        sps.*,
        (
          SELECT COUNT(*) 
          FROM siem_sync_queue 
          WHERE provider_id = sp.id AND status = 'pending'
        ) as pending_events
      FROM siem_providers sp
      JOIN siem_provider_status sps ON sp.id = sps.provider_id
      WHERE sp.organization_id = ${tenantId}
        AND sp.enabled = true
    `;

    return c.json(syncStatus);
  });

  // Manually sync events
  app.post('/sync/manual', async (c) => {
    const { providerId, startDate, endDate } = await c.req.json();
    const tenantId = c.get('tenantId');

    // Queue sync job
    const jobId = crypto.randomUUID();
    await prisma.$executeRawUnsafe(`
      INSERT INTO siem_sync_jobs (
        id, provider_id, organization_id, 
        start_date, end_date, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `,
      jobId,
      providerId,
      tenantId,
      new Date(startDate),
      new Date(endDate),
      'queued',
      new Date()
    );

    return c.json({
      jobId,
      status: 'queued',
      message: 'Sync job queued successfully'
    });
  });

  // Get sync history
  app.get('/sync/history', async (c) => {
    const tenantId = c.get('tenantId');
    const { providerId, days = '7' } = c.req.query();

    const conditions: string[] = [`sj.organization_id = '${tenantId}'`];
    if (providerId) {
      conditions.push(`sj.provider_id = '${providerId}'`);
    }

    const history = await prisma.$queryRawUnsafe(`
      SELECT 
        sj.*,
        sp.name as provider_name,
        sp.type as provider_type
      FROM siem_sync_jobs sj
      JOIN siem_providers sp ON sj.provider_id = sp.id
      WHERE ${conditions.join(' AND ')}
        AND sj.created_at > NOW() - INTERVAL '${parseInt(days)} days'
      ORDER BY sj.created_at DESC
      LIMIT 100
    `);

    return c.json(history);
  });

  // Get SIEM mappings
  app.get('/mappings', async (c) => {
    const mappings = {
      splunk: {
        fields: {
          timestamp: 'time',
          eventType: 'event_type',
          severity: 'severity',
          source: 'host',
          userId: 'user',
          ipAddress: 'src_ip'
        },
        severityMap: {
          CRITICAL: '10',
          HIGH: '8',
          MEDIUM: '5',
          LOW: '3',
          INFO: '1'
        }
      },
      elk: {
        fields: {
          timestamp: '@timestamp',
          eventType: 'event.type',
          severity: 'event.severity',
          source: 'host.name',
          userId: 'user.id',
          ipAddress: 'source.ip'
        },
        index: 'sparc-security-*'
      },
      datadog: {
        fields: {
          timestamp: 'timestamp',
          eventType: 'evt.name',
          severity: 'status',
          source: 'host',
          userId: 'usr.id',
          ipAddress: 'network.client.ip'
        },
        service: 'sparc-security'
      }
    };

    return c.json(mappings);
  });

  // Update field mappings
  app.post('/mappings/:providerId', async (c) => {
    const { providerId } = c.param();
    const { mappings } = await c.req.json();
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      UPDATE siem_providers
      SET config = config || jsonb_build_object('fieldMappings', $1::jsonb)
      WHERE id = $2 AND organization_id = $3
    `,
      JSON.stringify(mappings),
      providerId,
      tenantId
    );

    return c.json({ success: true });
  });

  // Get SIEM statistics
  app.get('/stats', async (c) => {
    const tenantId = c.get('tenantId');

    const stats = await prisma.$queryRaw`
      SELECT 
        COUNT(DISTINCT sp.id) as total_providers,
        COUNT(DISTINCT sp.id) FILTER (WHERE sp.enabled = true) as active_providers,
        COUNT(DISTINCT sp.id) FILTER (WHERE sps.is_connected = true) as connected_providers,
        SUM(sps.events_sent_today) as events_sent_today,
        SUM(sps.events_failed_today) as events_failed_today,
        AVG(sps.avg_latency_ms) as avg_latency_ms
      FROM siem_providers sp
      LEFT JOIN siem_provider_status sps ON sp.id = sps.provider_id
      WHERE sp.organization_id = ${tenantId}
    `;

    const byProvider = await prisma.$queryRaw`
      SELECT 
        sp.name,
        sp.type,
        sps.events_sent_today,
        sps.events_failed_today,
        sps.avg_latency_ms,
        sps.last_error
      FROM siem_providers sp
      JOIN siem_provider_status sps ON sp.id = sps.provider_id
      WHERE sp.organization_id = ${tenantId}
        AND sp.enabled = true
    `;

    return c.json({
      summary: (stats as any[])[0],
      byProvider
    });
  });

  return app;
}

function validateProviderConfig(provider: SIEMProvider): boolean {
  switch (provider.type) {
    case 'splunk':
      return !!(provider.config.url && provider.config.token);
    case 'elk':
      return !!(provider.config.url && provider.config.apiKey);
    case 'datadog':
      return !!(provider.config.apiKey);
    case 'qradar':
      return !!(provider.config.url && provider.config.apiToken);
    case 'azure-sentinel':
      return !!(provider.config.workspaceId && provider.config.primaryKey);
    case 'sumo-logic':
      return !!(provider.config.endpoint);
    default:
      return false;
  }
}