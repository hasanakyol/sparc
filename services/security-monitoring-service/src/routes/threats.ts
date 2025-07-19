import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { SecurityMonitoringService } from '../services/main-service';
import { ThreatIndicator, SecurityPattern } from '@sparc/shared/monitoring/types';
import { prisma } from '@sparc/shared/database/prisma';

const threatIndicatorSchema = z.object({
  type: z.enum(['ip', 'domain', 'hash', 'email', 'url', 'user-agent']),
  value: z.string(),
  confidence: z.number().min(0).max(1),
  source: z.string(),
  tags: z.array(z.string()).optional()
});

const securityPatternSchema = z.object({
  name: z.string(),
  description: z.string(),
  pattern: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  category: z.enum(['authentication', 'authorization', 'data-access', 'network', 'system']),
  enabled: z.boolean().default(true),
  actions: z.array(z.string())
});

export function threatsRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Get threat indicators
  app.get('/indicators', async (c) => {
    const tenantId = c.get('tenantId');
    const { type, minConfidence = '0.5' } = c.req.query();

    const conditions: string[] = [`organization_id = '${tenantId}'`];
    
    if (type) {
      conditions.push(`type = '${type}'`);
    }
    
    conditions.push(`confidence >= ${parseFloat(minConfidence)}`);

    const indicators = await prisma.$queryRawUnsafe(`
      SELECT * FROM threat_indicators
      WHERE ${conditions.join(' AND ')}
      ORDER BY last_seen DESC
      LIMIT 1000
    `);

    return c.json(indicators);
  });

  // Add threat indicator
  app.post('/indicators', zValidator('json', threatIndicatorSchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const indicator: ThreatIndicator = {
      id: crypto.randomUUID(),
      ...data,
      lastSeen: new Date(),
      tags: data.tags || []
    };

    await prisma.$executeRawUnsafe(`
      INSERT INTO threat_indicators (
        id, type, value, confidence, source, 
        last_seen, tags, organization_id, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (type, value, organization_id) 
      DO UPDATE SET 
        confidence = GREATEST(threat_indicators.confidence, $4),
        last_seen = $6,
        tags = array_cat(threat_indicators.tags, $7)
    `,
      indicator.id,
      indicator.type,
      indicator.value,
      indicator.confidence,
      indicator.source,
      indicator.lastSeen,
      indicator.tags,
      tenantId,
      userId
    );

    return c.json(indicator, 201);
  });

  // Bulk import threat indicators
  app.post('/indicators/bulk', async (c) => {
    const { indicators, source } = await c.req.json();
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const results = {
      imported: 0,
      updated: 0,
      failed: 0,
      errors: [] as string[]
    };

    for (const indicator of indicators) {
      try {
        await prisma.$executeRawUnsafe(`
          INSERT INTO threat_indicators (
            id, type, value, confidence, source, 
            last_seen, tags, organization_id, created_by
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
          ON CONFLICT (type, value, organization_id) 
          DO UPDATE SET 
            confidence = GREATEST(threat_indicators.confidence, $4),
            last_seen = $6,
            tags = array_cat(threat_indicators.tags, $7)
        `,
          crypto.randomUUID(),
          indicator.type,
          indicator.value,
          indicator.confidence || 0.7,
          source || indicator.source,
          new Date(),
          indicator.tags || [],
          tenantId,
          userId
        );
        
        results.imported++;
      } catch (error: any) {
        results.failed++;
        results.errors.push(`${indicator.type}:${indicator.value} - ${error.message}`);
      }
    }

    return c.json(results);
  });

  // Delete threat indicator
  app.delete('/indicators/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      DELETE FROM threat_indicators
      WHERE id = $1 AND organization_id = $2
    `,
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Get security patterns
  app.get('/patterns', async (c) => {
    const tenantId = c.get('tenantId');
    const { category, enabled } = c.req.query();

    const conditions: string[] = [`organization_id = '${tenantId}'`];
    
    if (category) {
      conditions.push(`category = '${category}'`);
    }
    
    if (enabled !== undefined) {
      conditions.push(`enabled = ${enabled === 'true'}`);
    }

    const patterns = await prisma.$queryRawUnsafe(`
      SELECT * FROM security_patterns
      WHERE ${conditions.join(' AND ')}
      ORDER BY severity DESC, name
    `);

    return c.json(patterns);
  });

  // Create security pattern
  app.post('/patterns', zValidator('json', securityPatternSchema), async (c) => {
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    const pattern: SecurityPattern = {
      id: crypto.randomUUID(),
      ...data
    };

    await prisma.$executeRawUnsafe(`
      INSERT INTO security_patterns (
        id, name, description, pattern, severity, 
        category, enabled, actions, organization_id, 
        created_by, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `,
      pattern.id,
      pattern.name,
      pattern.description,
      pattern.pattern,
      pattern.severity,
      pattern.category,
      pattern.enabled,
      JSON.stringify(pattern.actions),
      tenantId,
      userId,
      new Date()
    );

    return c.json(pattern, 201);
  });

  // Update security pattern
  app.put('/patterns/:id', zValidator('json', securityPatternSchema), async (c) => {
    const { id } = c.param();
    const data = c.req.valid('json');
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      UPDATE security_patterns
      SET name = $1, description = $2, pattern = $3,
          severity = $4, category = $5, enabled = $6,
          actions = $7, updated_at = $8
      WHERE id = $9 AND organization_id = $10
    `,
      data.name,
      data.description,
      data.pattern,
      data.severity,
      data.category,
      data.enabled,
      JSON.stringify(data.actions),
      new Date(),
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Delete security pattern
  app.delete('/patterns/:id', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    await prisma.$executeRawUnsafe(`
      DELETE FROM security_patterns
      WHERE id = $1 AND organization_id = $2
    `,
      id,
      tenantId
    );

    return c.json({ success: true });
  });

  // Check if value is a known threat
  app.post('/check', async (c) => {
    const { type, value } = await c.req.json();
    const tenantId = c.get('tenantId');

    const result = await prisma.$queryRaw`
      SELECT * FROM threat_indicators
      WHERE type = ${type} 
        AND value = ${value}
        AND organization_id = ${tenantId}
      ORDER BY confidence DESC
      LIMIT 1
    `;

    const indicator = (result as any[])[0];

    if (indicator) {
      // Update last seen
      await prisma.$executeRawUnsafe(`
        UPDATE threat_indicators
        SET last_seen = NOW()
        WHERE id = $1
      `, indicator.id);

      return c.json({
        isThreat: true,
        confidence: indicator.confidence,
        source: indicator.source,
        tags: indicator.tags,
        lastSeen: indicator.last_seen
      });
    }

    return c.json({ isThreat: false });
  });

  // Get threat intelligence feeds
  app.get('/feeds', async (c) => {
    const feeds = [
      {
        id: 'abuse-ch',
        name: 'Abuse.ch',
        description: 'Malware and botnet C&C tracking',
        enabled: true,
        lastSync: new Date(),
        indicators: 15000
      },
      {
        id: 'alienvault-otx',
        name: 'AlienVault OTX',
        description: 'Open threat exchange',
        enabled: true,
        lastSync: new Date(),
        indicators: 50000
      },
      {
        id: 'misp',
        name: 'MISP',
        description: 'Malware Information Sharing Platform',
        enabled: false,
        lastSync: null,
        indicators: 0
      }
    ];

    return c.json(feeds);
  });

  // Sync threat feed
  app.post('/feeds/:id/sync', async (c) => {
    const { id } = c.param();
    const tenantId = c.get('tenantId');

    // In production, this would trigger actual feed synchronization
    // For now, we'll simulate it
    const feedSync = {
      feedId: id,
      status: 'running',
      startedAt: new Date(),
      message: 'Synchronization started'
    };

    // Queue the sync job
    await prisma.$executeRawUnsafe(`
      INSERT INTO threat_feed_sync_jobs (
        id, feed_id, organization_id, status, started_at
      ) VALUES ($1, $2, $3, $4, $5)
    `,
      crypto.randomUUID(),
      id,
      tenantId,
      'running',
      new Date()
    );

    return c.json(feedSync);
  });

  // Get threat statistics
  app.get('/stats', async (c) => {
    const tenantId = c.get('tenantId');

    const stats = await prisma.$queryRaw`
      SELECT 
        COUNT(*) as total_indicators,
        COUNT(DISTINCT type) as indicator_types,
        AVG(confidence) as avg_confidence,
        COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '24 hours') as active_last_24h,
        COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '7 days') as active_last_7d
      FROM threat_indicators
      WHERE organization_id = ${tenantId}
    `;

    const byType = await prisma.$queryRaw`
      SELECT type, COUNT(*) as count
      FROM threat_indicators
      WHERE organization_id = ${tenantId}
      GROUP BY type
    `;

    const topSources = await prisma.$queryRaw`
      SELECT source, COUNT(*) as count
      FROM threat_indicators
      WHERE organization_id = ${tenantId}
      GROUP BY source
      ORDER BY count DESC
      LIMIT 10
    `;

    return c.json({
      summary: (stats as any[])[0],
      byType,
      topSources
    });
  });

  return app;
}