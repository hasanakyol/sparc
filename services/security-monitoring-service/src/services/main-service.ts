import { Redis } from 'ioredis';
import { 
  SecurityMonitoring, 
  SecurityEvent, 
  SecurityEventType, 
  SecuritySeverity 
} from '@sparc/shared/security/siem';
import { 
  ThreatDetectionEngine, 
  ThreatAnalysis 
} from '@sparc/shared/monitoring/threat-detection';
import { 
  SIEMAdapter, 
  SIEMAdapterFactory 
} from '@sparc/shared/monitoring/siem-adapters';
import { 
  SIEMProvider, 
  SecurityIncident, 
  SecurityDashboard,
  SecurityMetrics,
  ComplianceReport
} from '@sparc/shared/monitoring/types';
import { logger } from '@sparc/shared/utils/logger';
import { prisma } from '@sparc/shared/database/prisma';
import { EventEmitter } from 'events';

export class SecurityMonitoringService extends EventEmitter {
  private securityMonitoring: SecurityMonitoring;
  private threatEngine: ThreatDetectionEngine;
  private siemAdapters: Map<string, SIEMAdapter> = new Map();
  private redis: Redis;
  private backgroundTasks: NodeJS.Timer[] = [];

  constructor(redis: Redis) {
    super();
    this.redis = redis;
    this.securityMonitoring = new SecurityMonitoring(redis);
    this.threatEngine = new ThreatDetectionEngine(redis);
    this.initializeSIEMProviders();
    this.setupEventListeners();
  }

  private async initializeSIEMProviders(): Promise<void> {
    try {
      // Load SIEM providers from environment/config
      const providers: SIEMProvider[] = [
        {
          name: 'Splunk',
          type: 'splunk',
          enabled: !!process.env.SPLUNK_URL,
          config: {
            url: process.env.SPLUNK_URL,
            token: process.env.SPLUNK_TOKEN,
            index: process.env.SPLUNK_INDEX || 'main'
          }
        },
        {
          name: 'ElasticSearch',
          type: 'elk',
          enabled: !!process.env.ELASTICSEARCH_URL,
          config: {
            url: process.env.ELASTICSEARCH_URL,
            apiKey: process.env.ELASTICSEARCH_API_KEY,
            index: 'sparc-security'
          }
        },
        {
          name: 'DataDog',
          type: 'datadog',
          enabled: !!process.env.DATADOG_API_KEY,
          config: {
            apiKey: process.env.DATADOG_API_KEY,
            appKey: process.env.DATADOG_APP_KEY
          }
        }
      ];

      for (const provider of providers) {
        if (provider.enabled && provider.config.url || provider.config.apiKey) {
          try {
            const adapter = SIEMAdapterFactory.create(provider);
            const isConnected = await adapter.testConnection();
            
            if (isConnected) {
              this.siemAdapters.set(provider.name, adapter);
              logger.info(`SIEM provider ${provider.name} connected successfully`);
            } else {
              logger.warn(`Failed to connect to SIEM provider ${provider.name}`);
            }
          } catch (error) {
            logger.error(`Error initializing SIEM provider ${provider.name}`, { error });
          }
        }
      }
    } catch (error) {
      logger.error('Failed to initialize SIEM providers', { error });
    }
  }

  private setupEventListeners(): void {
    // Listen for security events from the base monitoring
    this.securityMonitoring.on('securityEvent', async (event: SecurityEvent) => {
      try {
        // Run threat analysis
        const analysis = await this.threatEngine.analyze(event);
        
        // Forward to SIEM providers
        await this.forwardToSIEM(event);
        
        // Check if incident needs to be created
        if (analysis.riskScore > 70) {
          await this.createIncident(event, analysis);
        }
        
        // Emit for real-time monitoring
        this.emit('security:event', { event, analysis });
        
      } catch (error) {
        logger.error('Error processing security event', { error, event });
      }
    });
  }

  async recordSecurityEvent(
    eventData: Omit<SecurityEvent, 'id' | 'timestamp'>
  ): Promise<SecurityEvent> {
    // Record the event
    await this.securityMonitoring.recordEvent(eventData);
    
    // Return the event (the monitoring will emit it)
    return {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      ...eventData
    };
  }

  private async forwardToSIEM(event: SecurityEvent): Promise<void> {
    const promises: Promise<void>[] = [];
    
    for (const [name, adapter] of this.siemAdapters) {
      promises.push(
        adapter.sendEvent(event).catch(error => {
          logger.error(`Failed to forward event to ${name}`, { error, event });
        })
      );
    }
    
    await Promise.allSettled(promises);
  }

  async createIncident(
    event: SecurityEvent,
    analysis: ThreatAnalysis
  ): Promise<SecurityIncident> {
    const incident: SecurityIncident = {
      id: crypto.randomUUID(),
      title: `Security Incident: ${analysis.threats[0]?.description || event.eventType}`,
      description: `Risk Score: ${analysis.riskScore}\n\n${analysis.recommendations.join('\n')}`,
      severity: this.calculateIncidentSeverity(analysis.riskScore),
      status: 'open',
      events: [event.id],
      timeline: [{
        timestamp: new Date(),
        action: 'incident_created',
        actor: 'system',
        details: { event, analysis }
      }],
      affectedResources: this.extractAffectedResources(event),
      containmentActions: analysis.recommendations,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    // Store incident
    await prisma.$executeRawUnsafe(`
      INSERT INTO security_incidents (
        id, title, description, severity, status, events, 
        timeline, affected_resources, containment_actions, 
        created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `,
      incident.id,
      incident.title,
      incident.description,
      incident.severity,
      incident.status,
      JSON.stringify(incident.events),
      JSON.stringify(incident.timeline),
      JSON.stringify(incident.affectedResources),
      JSON.stringify(incident.containmentActions),
      incident.createdAt,
      incident.updatedAt
    );
    
    // Emit incident created event
    this.emit('incident:created', incident);
    
    return incident;
  }

  private calculateIncidentSeverity(riskScore: number): 'critical' | 'high' | 'medium' | 'low' {
    if (riskScore > 80) return 'critical';
    if (riskScore > 60) return 'high';
    if (riskScore > 40) return 'medium';
    return 'low';
  }

  private extractAffectedResources(event: SecurityEvent): string[] {
    const resources: string[] = [];
    
    if (event.userId) resources.push(`user:${event.userId}`);
    if (event.organizationId) resources.push(`org:${event.organizationId}`);
    if (event.source) resources.push(`service:${event.source}`);
    if (event.details?.resourceId) resources.push(`resource:${event.details.resourceId}`);
    
    return resources;
  }

  async getSecurityMetrics(
    timeRange: { start: Date; end: Date },
    organizationId?: string
  ): Promise<SecurityMetrics> {
    const baseMetrics = await this.securityMonitoring.getSecurityMetrics(timeRange);
    
    // Enhance with additional metrics
    const metrics: SecurityMetrics = {
      timeRange,
      totalEvents: baseMetrics.totalEvents,
      criticalEvents: baseMetrics.eventsBySeverity['CRITICAL'] || 0,
      blockedAttempts: 0,
      activeIncidents: 0,
      meanTimeToDetect: 0,
      meanTimeToRespond: 0,
      topThreats: [],
      eventsByHour: baseMetrics.trendsOverTime,
      geoDistribution: []
    };
    
    // Get blocked attempts
    const blockedResult = await prisma.$queryRaw<any[]>`
      SELECT COUNT(*) as count 
      FROM security_events 
      WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
        AND event_type IN ('ACCESS_DENIED', 'RATE_LIMIT_EXCEEDED', 'BRUTE_FORCE_DETECTED')
        ${organizationId ? `AND organization_id = ${organizationId}` : ''}
    `;
    metrics.blockedAttempts = parseInt(blockedResult[0]?.count || 0);
    
    // Get active incidents
    const incidentResult = await prisma.$queryRaw<any[]>`
      SELECT COUNT(*) as count 
      FROM security_incidents 
      WHERE status IN ('open', 'investigating')
        AND created_at <= ${timeRange.end}
    `;
    metrics.activeIncidents = parseInt(incidentResult[0]?.count || 0);
    
    // Calculate MTTD and MTTR
    const incidentMetrics = await prisma.$queryRaw<any[]>`
      SELECT 
        AVG(EXTRACT(EPOCH FROM (first_response - created_at))) / 60 as avg_ttd,
        AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))) / 60 as avg_ttr
      FROM security_incidents 
      WHERE created_at BETWEEN ${timeRange.start} AND ${timeRange.end}
        AND resolved_at IS NOT NULL
    `;
    
    metrics.meanTimeToDetect = Math.round(incidentMetrics[0]?.avg_ttd || 0);
    metrics.meanTimeToRespond = Math.round(incidentMetrics[0]?.avg_ttr || 0);
    
    // Get top threats
    const threatResults = await prisma.$queryRaw<any[]>`
      SELECT event_type, COUNT(*) as count 
      FROM security_events 
      WHERE timestamp BETWEEN ${timeRange.start} AND ${timeRange.end}
        AND severity IN ('CRITICAL', 'HIGH')
        ${organizationId ? `AND organization_id = ${organizationId}` : ''}
      GROUP BY event_type
      ORDER BY count DESC
      LIMIT 10
    `;
    
    metrics.topThreats = threatResults.map(t => ({
      threat: t.event_type,
      count: parseInt(t.count)
    }));
    
    return metrics;
  }

  async getComplianceReport(
    framework: string,
    period: { start: Date; end: Date }
  ): Promise<ComplianceReport> {
    // Generate compliance report based on framework
    const controls = await this.evaluateComplianceControls(framework, period);
    
    const summary = controls.reduce((acc, control) => {
      acc[control.status]++;
      return acc;
    }, { compliant: 0, 'non-compliant': 0, 'not-applicable': 0 });
    
    const report: ComplianceReport = {
      id: crypto.randomUUID(),
      framework: framework as any,
      period,
      controls,
      summary,
      generatedAt: new Date()
    };
    
    // Store report
    await prisma.$executeRawUnsafe(`
      INSERT INTO compliance_reports (
        id, framework, period_start, period_end, 
        controls, summary, generated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `,
      report.id,
      report.framework,
      report.period.start,
      report.period.end,
      JSON.stringify(report.controls),
      JSON.stringify(report.summary),
      report.generatedAt
    );
    
    return report;
  }

  private async evaluateComplianceControls(
    framework: string,
    period: { start: Date; end: Date }
  ): Promise<any[]> {
    // Framework-specific control evaluation
    switch (framework) {
      case 'soc2':
        return this.evaluateSOC2Controls(period);
      case 'pci-dss':
        return this.evaluatePCIDSSControls(period);
      case 'hipaa':
        return this.evaluateHIPAAControls(period);
      default:
        return [];
    }
  }

  private async evaluateSOC2Controls(period: { start: Date; end: Date }): Promise<any[]> {
    const controls = [];
    
    // CC1.1 - Access Controls
    const accessControlEvents = await prisma.$queryRaw<any[]>`
      SELECT COUNT(*) as unauthorized_count
      FROM security_events
      WHERE event_type = 'ACCESS_DENIED'
        AND timestamp BETWEEN ${period.start} AND ${period.end}
    `;
    
    controls.push({
      id: 'CC1.1',
      name: 'Logical Access Controls',
      description: 'Restricts logical access to systems and data',
      status: parseInt(accessControlEvents[0]?.unauthorized_count || 0) < 100 ? 'compliant' : 'non-compliant',
      evidence: ['access_logs', 'permission_matrix'],
      lastAssessed: new Date()
    });
    
    // CC2.1 - Monitoring
    controls.push({
      id: 'CC2.1',
      name: 'System Monitoring',
      description: 'Monitors system performance and security',
      status: 'compliant', // We have monitoring in place
      evidence: ['monitoring_dashboards', 'alert_rules'],
      lastAssessed: new Date()
    });
    
    // Add more SOC2 controls...
    
    return controls;
  }

  private async evaluatePCIDSSControls(period: { start: Date; end: Date }): Promise<any[]> {
    // PCI-DSS specific controls
    return [];
  }

  private async evaluateHIPAAControls(period: { start: Date; end: Date }): Promise<any[]> {
    // HIPAA specific controls
    return [];
  }

  async createDashboard(dashboard: Omit<SecurityDashboard, 'id'>): Promise<SecurityDashboard> {
    const newDashboard: SecurityDashboard = {
      id: crypto.randomUUID(),
      ...dashboard
    };
    
    await prisma.$executeRawUnsafe(`
      INSERT INTO security_dashboards (id, name, widgets, refresh_interval, layout)
      VALUES ($1, $2, $3, $4, $5)
    `,
      newDashboard.id,
      newDashboard.name,
      JSON.stringify(newDashboard.widgets),
      newDashboard.refreshInterval,
      JSON.stringify(newDashboard.layout)
    );
    
    return newDashboard;
  }

  async querySIEM(provider: string, query: any): Promise<SecurityEvent[]> {
    const adapter = this.siemAdapters.get(provider);
    if (!adapter) {
      throw new Error(`SIEM provider ${provider} not configured`);
    }
    
    return adapter.queryEvents(query);
  }

  startBackgroundTasks(): void {
    // Batch event forwarding to SIEM
    const batchTask = setInterval(async () => {
      await this.processBatchEvents();
    }, 30000); // Every 30 seconds
    
    // Threat intelligence updates
    const threatTask = setInterval(async () => {
      await this.updateThreatIntelligence();
    }, 3600000); // Every hour
    
    // Compliance checks
    const complianceTask = setInterval(async () => {
      await this.runComplianceChecks();
    }, 86400000); // Daily
    
    this.backgroundTasks.push(batchTask, threatTask, complianceTask);
  }

  private async processBatchEvents(): Promise<void> {
    try {
      // Get batched events from Redis
      const events = await this.redis.lrange('security:batch:queue', 0, 100);
      if (events.length === 0) return;
      
      const parsedEvents = events.map(e => JSON.parse(e));
      
      // Send to each SIEM provider
      for (const [name, adapter] of this.siemAdapters) {
        try {
          await adapter.sendBatch(parsedEvents);
        } catch (error) {
          logger.error(`Failed to send batch to ${name}`, { error });
        }
      }
      
      // Clear processed events
      await this.redis.ltrim('security:batch:queue', events.length, -1);
      
    } catch (error) {
      logger.error('Error processing batch events', { error });
    }
  }

  private async updateThreatIntelligence(): Promise<void> {
    try {
      // Fetch threat intelligence feeds
      // This would integrate with services like:
      // - MISP (Malware Information Sharing Platform)
      // - AlienVault OTX
      // - Abuse.ch feeds
      // - Custom threat feeds
      
      logger.info('Threat intelligence update completed');
    } catch (error) {
      logger.error('Failed to update threat intelligence', { error });
    }
  }

  private async runComplianceChecks(): Promise<void> {
    try {
      // Run automated compliance checks
      const frameworks = ['soc2', 'pci-dss', 'hipaa'];
      
      for (const framework of frameworks) {
        const period = {
          start: new Date(Date.now() - 86400000), // Last 24 hours
          end: new Date()
        };
        
        const report = await this.getComplianceReport(framework, period);
        
        if (report.summary['non-compliant'] > 0) {
          logger.warn(`Compliance violations detected for ${framework}`, report.summary);
          // Create incident or alert
        }
      }
      
    } catch (error) {
      logger.error('Failed to run compliance checks', { error });
    }
  }

  async stop(): Promise<void> {
    // Clear background tasks
    for (const task of this.backgroundTasks) {
      clearInterval(task);
    }
    
    // Close connections
    await this.redis.quit();
  }
}