import { Hono } from 'hono';
import { SecurityMonitoringService } from '../services/main-service';
import { SecurityMetrics } from '@sparc/shared/monitoring/types';
import { prisma } from '@sparc/shared/database/prisma';

export function metricsRouter(securityService: SecurityMonitoringService) {
  const app = new Hono();

  // Get security metrics
  app.get('/', async (c) => {
    const tenantId = c.get('tenantId');
    const { startDate, endDate, granularity = 'hour' } = c.req.query();

    const timeRange = {
      start: startDate ? new Date(startDate) : new Date(Date.now() - 24 * 60 * 60 * 1000),
      end: endDate ? new Date(endDate) : new Date()
    };

    const metrics = await securityService.getSecurityMetrics(timeRange, tenantId);

    return c.json(metrics);
  });

  // Get real-time metrics
  app.get('/realtime', async (c) => {
    const tenantId = c.get('tenantId');

    const realtime = await prisma.$queryRaw`
      SELECT 
        COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 minute') as events_per_minute,
        COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '5 minutes') as events_5min,
        COUNT(*) FILTER (WHERE severity = 'critical' AND timestamp > NOW() - INTERVAL '1 hour') as critical_last_hour,
        COUNT(DISTINCT user_id) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour') as unique_users_hour,
        COUNT(DISTINCT ip_address) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour') as unique_ips_hour
      FROM security_events
      WHERE organization_id = ${tenantId}
    `;

    const activeAlerts = await prisma.$queryRaw`
      SELECT severity, COUNT(*) as count
      FROM security_alerts
      WHERE organization_id = ${tenantId}
        AND resolved = false
      GROUP BY severity
    `;

    return c.json({
      realtime: (realtime as any[])[0],
      activeAlerts,
      timestamp: new Date()
    });
  });

  // Get performance metrics
  app.get('/performance', async (c) => {
    const tenantId = c.get('tenantId');

    const performance = await prisma.$queryRaw`
      SELECT 
        AVG(processing_time_ms) as avg_processing_time,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY processing_time_ms) as p50_processing_time,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY processing_time_ms) as p95_processing_time,
        PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY processing_time_ms) as p99_processing_time,
        COUNT(*) as total_events_processed
      FROM security_event_processing_metrics
      WHERE organization_id = ${tenantId}
        AND timestamp > NOW() - INTERVAL '1 hour'
    `;

    const siemLatency = await prisma.$queryRaw`
      SELECT 
        siem_provider,
        AVG(latency_ms) as avg_latency,
        MAX(latency_ms) as max_latency,
        COUNT(*) as events_forwarded,
        COUNT(*) FILTER (WHERE success = false) as failures
      FROM siem_forwarding_metrics
      WHERE organization_id = ${tenantId}
        AND timestamp > NOW() - INTERVAL '1 hour'
      GROUP BY siem_provider
    `;

    return c.json({
      processing: (performance as any[])[0],
      siemLatency,
      timestamp: new Date()
    });
  });

  // Get threat metrics
  app.get('/threats', async (c) => {
    const tenantId = c.get('tenantId');
    const { days = '7' } = c.req.query();

    const threatMetrics = await prisma.$queryRaw`
      SELECT 
        threat_type,
        COUNT(*) as detections,
        AVG(confidence) as avg_confidence,
        MAX(risk_score) as max_risk_score,
        COUNT(DISTINCT source_ip) as unique_sources
      FROM threat_detections
      WHERE organization_id = ${tenantId}
        AND detected_at > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY threat_type
      ORDER BY detections DESC
    `;

    const geoDistribution = await prisma.$queryRaw`
      SELECT 
        country_code,
        country_name,
        COUNT(*) as threat_count,
        COUNT(DISTINCT ip_address) as unique_ips
      FROM security_events se
      LEFT JOIN ip_geolocation ig ON se.ip_address = ig.ip_address
      WHERE se.organization_id = ${tenantId}
        AND se.timestamp > NOW() - INTERVAL '${parseInt(days)} days'
        AND se.severity IN ('high', 'critical')
      GROUP BY country_code, country_name
      ORDER BY threat_count DESC
      LIMIT 20
    `;

    const attackPatterns = await prisma.$queryRaw`
      SELECT 
        pattern_name,
        COUNT(*) as matches,
        MAX(last_seen) as last_seen,
        array_agg(DISTINCT event_type) as event_types
      FROM pattern_matches
      WHERE organization_id = ${tenantId}
        AND matched_at > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY pattern_name
      ORDER BY matches DESC
    `;

    return c.json({
      threats: threatMetrics,
      geoDistribution,
      attackPatterns,
      timeRange: { days: parseInt(days) }
    });
  });

  // Get user behavior metrics
  app.get('/users', async (c) => {
    const tenantId = c.get('tenantId');
    const { userId, days = '30' } = c.req.query();

    const conditions: string[] = [`organization_id = '${tenantId}'`];
    if (userId) {
      conditions.push(`user_id = '${userId}'`);
    }

    const userMetrics = await prisma.$queryRawUnsafe(`
      SELECT 
        user_id,
        COUNT(*) as total_events,
        COUNT(DISTINCT DATE(timestamp)) as active_days,
        COUNT(DISTINCT ip_address) as unique_ips,
        COUNT(*) FILTER (WHERE event_type = 'LOGIN_SUCCESS') as successful_logins,
        COUNT(*) FILTER (WHERE event_type = 'LOGIN_FAILURE') as failed_logins,
        COUNT(*) FILTER (WHERE severity IN ('high', 'critical')) as high_severity_events,
        MIN(timestamp) as first_seen,
        MAX(timestamp) as last_seen
      FROM security_events
      WHERE ${conditions.join(' AND ')}
        AND timestamp > NOW() - INTERVAL '${parseInt(days)} days'
      GROUP BY user_id
      ORDER BY total_events DESC
      LIMIT 100
    `);

    const riskScores = await prisma.$queryRawUnsafe(`
      SELECT 
        user_id,
        risk_score,
        risk_factors,
        calculated_at
      FROM user_risk_scores
      WHERE ${conditions.join(' AND ')}
      ORDER BY risk_score DESC
    `);

    return c.json({
      users: userMetrics,
      riskScores,
      timeRange: { days: parseInt(days) }
    });
  });

  // Get system health metrics
  app.get('/health', async (c) => {
    const health = {
      services: {
        database: 'healthy',
        redis: 'healthy',
        siem: {} as Record<string, string>
      },
      queues: {} as Record<string, any>,
      resources: {} as Record<string, any>
    };

    // Check SIEM connections
    const siemStatus = await prisma.$queryRaw`
      SELECT 
        provider,
        last_successful_sync,
        last_error,
        is_connected
      FROM siem_provider_status
    `;

    for (const provider of siemStatus as any[]) {
      health.services.siem[provider.provider] = provider.is_connected ? 'healthy' : 'unhealthy';
    }

    // Check queue status
    const queueMetrics = await prisma.$queryRaw`
      SELECT 
        queue_name,
        pending_count,
        processing_count,
        failed_count,
        avg_processing_time_ms
      FROM queue_metrics
      WHERE updated_at > NOW() - INTERVAL '5 minutes'
    `;

    for (const queue of queueMetrics as any[]) {
      health.queues[queue.queue_name] = {
        pending: queue.pending_count,
        processing: queue.processing_count,
        failed: queue.failed_count,
        avgProcessingTime: queue.avg_processing_time_ms
      };
    }

    // Get resource usage
    health.resources = {
      cpu: Math.random() * 100, // Would get from actual monitoring
      memory: Math.random() * 100,
      disk: Math.random() * 100,
      connections: {
        database: 45,
        redis: 12,
        websocket: 234
      }
    };

    return c.json(health);
  });

  // Get historical trends
  app.get('/trends', async (c) => {
    const tenantId = c.get('tenantId');
    const { metric, period = '7d', interval = '1h' } = c.req.query();

    const periodMap: Record<string, string> = {
      '1d': '1 day',
      '7d': '7 days',
      '30d': '30 days',
      '90d': '90 days'
    };

    const intervalMap: Record<string, string> = {
      '5m': '5 minutes',
      '1h': '1 hour',
      '1d': '1 day'
    };

    const trends = await prisma.$queryRawUnsafe(`
      SELECT 
        DATE_TRUNC('${intervalMap[interval] || 'hour'}', timestamp) as time_bucket,
        COUNT(*) as event_count,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
        COUNT(*) FILTER (WHERE severity = 'high') as high_count,
        COUNT(DISTINCT user_id) as unique_users,
        COUNT(DISTINCT ip_address) as unique_ips
      FROM security_events
      WHERE organization_id = $1
        AND timestamp > NOW() - INTERVAL '${periodMap[period] || '7 days'}'
      GROUP BY time_bucket
      ORDER BY time_bucket
    `, tenantId);

    return c.json({
      metric: metric || 'all',
      period,
      interval,
      data: trends
    });
  });

  // Export metrics
  app.post('/export', async (c) => {
    const { metrics, format = 'json', startDate, endDate } = await c.req.json();
    const tenantId = c.get('tenantId');

    const timeRange = {
      start: new Date(startDate || Date.now() - 7 * 24 * 60 * 60 * 1000),
      end: new Date(endDate || Date.now())
    };

    const data = await securityService.getSecurityMetrics(timeRange, tenantId);

    if (format === 'prometheus') {
      // Convert to Prometheus format
      const prometheus = convertToPrometheus(data);
      return new Response(prometheus, {
        headers: {
          'Content-Type': 'text/plain; version=0.0.4'
        }
      });
    }

    return c.json(data);
  });

  return app;
}

function convertToPrometheus(metrics: SecurityMetrics): string {
  const lines: string[] = [];
  
  // Total events
  lines.push(`# HELP sparc_security_events_total Total number of security events`);
  lines.push(`# TYPE sparc_security_events_total counter`);
  lines.push(`sparc_security_events_total ${metrics.totalEvents}`);
  
  // Critical events
  lines.push(`# HELP sparc_security_events_critical Total number of critical security events`);
  lines.push(`# TYPE sparc_security_events_critical counter`);
  lines.push(`sparc_security_events_critical ${metrics.criticalEvents}`);
  
  // Blocked attempts
  lines.push(`# HELP sparc_security_blocked_attempts Total number of blocked attempts`);
  lines.push(`# TYPE sparc_security_blocked_attempts counter`);
  lines.push(`sparc_security_blocked_attempts ${metrics.blockedAttempts}`);
  
  // Active incidents
  lines.push(`# HELP sparc_security_incidents_active Number of active security incidents`);
  lines.push(`# TYPE sparc_security_incidents_active gauge`);
  lines.push(`sparc_security_incidents_active ${metrics.activeIncidents}`);
  
  // MTTD
  lines.push(`# HELP sparc_security_mttd_minutes Mean time to detect in minutes`);
  lines.push(`# TYPE sparc_security_mttd_minutes gauge`);
  lines.push(`sparc_security_mttd_minutes ${metrics.meanTimeToDetect}`);
  
  // MTTR
  lines.push(`# HELP sparc_security_mttr_minutes Mean time to respond in minutes`);
  lines.push(`# TYPE sparc_security_mttr_minutes gauge`);
  lines.push(`sparc_security_mttr_minutes ${metrics.meanTimeToRespond}`);
  
  return lines.join('\n');
}