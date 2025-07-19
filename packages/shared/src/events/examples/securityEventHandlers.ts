/**
 * Example security event handlers for SPARC platform
 */

import { BaseEventHandler, BatchEventHandler, AggregatorEventHandler } from '../eventHandlers';
import { DomainEvent, TypedEventBus } from '../eventBus';
import { 
  SecurityIncidentCreated, 
  SecurityAlertTriggered,
  AccessDenied,
  SparcDomainEvents 
} from '../domainEvents';
import { logger } from '@/logger';
import { db } from '@/database/prisma';
import { sendEmail } from '@/services/email';
import { createNotification } from '@/services/notifications';

/**
 * Handler for security incidents
 */
export class SecurityIncidentHandler extends BaseEventHandler<SecurityIncidentCreated> {
  constructor() {
    super('SecurityIncidentHandler');
  }

  protected async process(event: DomainEvent<SecurityIncidentCreated>): Promise<void> {
    const { data } = event;

    // 1. Store incident in database
    await db.securityIncident.create({
      data: {
        id: data.incidentId,
        type: data.type,
        severity: data.severity,
        siteId: data.siteId,
        zoneId: data.zoneId,
        description: data.description,
        detectedBy: JSON.stringify(data.detectedBy),
        evidence: data.evidence ? JSON.stringify(data.evidence) : null,
        tenantId: event.tenantId,
        createdAt: event.timestamp
      }
    });

    // 2. Create notifications based on severity
    if (data.severity === 'critical' || data.severity === 'high') {
      await this.notifySecurityTeam(event);
    }

    // 3. Trigger automated responses
    await this.triggerAutomatedResponse(event);

    // 4. Update dashboards
    await this.updateSecurityDashboard(event);
  }

  private async notifySecurityTeam(event: DomainEvent<SecurityIncidentCreated>): Promise<void> {
    const { data } = event;

    // Get security team members
    const securityTeam = await db.user.findMany({
      where: {
        tenantId: event.tenantId,
        role: { in: ['security_admin', 'security_operator'] },
        notificationsEnabled: true
      }
    });

    // Send notifications
    for (const member of securityTeam) {
      await createNotification({
        userId: member.id,
        type: 'security_incident',
        title: `${data.severity.toUpperCase()} Security Incident`,
        message: data.description,
        data: {
          incidentId: data.incidentId,
          siteId: data.siteId,
          severity: data.severity
        },
        priority: data.severity === 'critical' ? 'urgent' : 'high'
      });

      // Send email for critical incidents
      if (data.severity === 'critical' && member.email) {
        await sendEmail({
          to: member.email,
          subject: `CRITICAL Security Incident at ${data.siteId}`,
          template: 'security-incident',
          data: {
            userName: member.name,
            incident: data
          }
        });
      }
    }
  }

  private async triggerAutomatedResponse(event: DomainEvent<SecurityIncidentCreated>): Promise<void> {
    const { data } = event;

    // Get automated response rules
    const rules = await db.automationRule.findMany({
      where: {
        tenantId: event.tenantId,
        eventType: 'security_incident',
        enabled: true,
        conditions: {
          path: ['severity'],
          equals: data.severity
        }
      }
    });

    // Execute actions
    for (const rule of rules) {
      logger.info('Executing automated response', {
        ruleId: rule.id,
        incidentId: data.incidentId
      });

      // Example actions based on rule configuration
      // This would be more sophisticated in production
    }
  }

  private async updateSecurityDashboard(event: DomainEvent<SecurityIncidentCreated>): Promise<void> {
    // Update real-time dashboard metrics
    // This would integrate with WebSocket service to push updates
  }
}

/**
 * Batch handler for security alerts
 */
export class SecurityAlertBatchHandler extends BatchEventHandler<SecurityAlertTriggered> {
  constructor() {
    super(
      'SecurityAlertBatchHandler',
      async (events) => {
        // Process alerts in batches for efficiency
        const alertsByRule = new Map<string, DomainEvent<SecurityAlertTriggered>[]>();

        // Group by rule
        for (const event of events) {
          const ruleId = event.data.ruleId;
          if (!alertsByRule.has(ruleId)) {
            alertsByRule.set(ruleId, []);
          }
          alertsByRule.get(ruleId)!.push(event);
        }

        // Process each rule's alerts
        for (const [ruleId, ruleEvents] of alertsByRule) {
          await this.processRuleAlerts(ruleId, ruleEvents);
        }
      },
      {
        batchSize: 50,
        flushInterval: 5000 // 5 seconds
      }
    );
  }

  private async processRuleAlerts(
    ruleId: string, 
    events: DomainEvent<SecurityAlertTriggered>[]
  ): Promise<void> {
    // Store alerts in database
    const alerts = events.map(event => ({
      id: event.data.alertId,
      ruleId: event.data.ruleId,
      ruleName: event.data.ruleName,
      type: event.data.type,
      severity: event.data.severity,
      source: JSON.stringify(event.data.source),
      data: JSON.stringify(event.data.data),
      tenantId: event.tenantId,
      createdAt: event.timestamp
    }));

    await db.securityAlert.createMany({ data: alerts });

    // Check for alert storms
    if (events.length > 10) {
      logger.warn('Alert storm detected', {
        ruleId,
        count: events.length,
        tenantId: events[0].tenantId
      });

      // Create meta-alert for storm
      await this.createAlertStormIncident(ruleId, events);
    }
  }

  private async createAlertStormIncident(
    ruleId: string,
    events: DomainEvent<SecurityAlertTriggered>[]
  ): Promise<void> {
    // Create a security incident for the alert storm
    // This would publish a new SecurityIncidentCreated event
  }
}

/**
 * Aggregator for failed access attempts
 */
export class FailedAccessAggregator extends AggregatorEventHandler<AccessDenied> {
  constructor(private eventBus: TypedEventBus<SparcDomainEvents>) {
    super(
      'FailedAccessAggregator',
      (event) => `${event.tenantId}:${event.data.userId || 'unknown'}`,
      async (key, events) => {
        const [tenantId, userId] = key.split(':');
        
        // If more than 5 failed attempts in the window, create security incident
        if (events.length >= 5) {
          await this.createBruteForceIncident(tenantId, userId, events);
        }
      },
      {
        windowSize: 300000 // 5 minutes
      }
    );
  }

  private async createBruteForceIncident(
    tenantId: string,
    userId: string,
    events: DomainEvent<AccessDenied>[]
  ): Promise<void> {
    const locations = events.map(e => ({
      zoneId: e.data.deniedAt.zoneId,
      zoneName: e.data.deniedAt.zoneName,
      timestamp: e.timestamp
    }));

    // Publish security incident
    await this.eventBus.publish('security.incident.created', {
      incidentId: `INC-${Date.now()}`,
      type: 'suspicious_activity',
      severity: 'high',
      siteId: events[0].data.deniedAt.zoneId.split('-')[0], // Extract site from zone
      description: `Multiple failed access attempts detected for user ${userId}`,
      detectedBy: {
        type: 'system',
        id: 'access-control-system',
        name: 'Access Control System'
      },
      evidence: {
        sensorData: {
          failedAttempts: events.length,
          locations,
          timeRange: {
            start: events[0].timestamp,
            end: events[events.length - 1].timestamp
          }
        }
      }
    }, {
      tenantId,
      correlationId: `brute-force-${userId}-${Date.now()}`
    });

    // Lock user account if exists
    if (userId !== 'unknown') {
      await db.user.update({
        where: { id: userId },
        data: {
          accountLocked: true,
          accountLockedAt: new Date(),
          accountLockedReason: 'Multiple failed access attempts'
        }
      });

      // Publish account locked event
      await this.eventBus.publish('user.account.locked', {
        userId,
        reason: 'failed_attempts',
        lockDuration: 3600000, // 1 hour
        unlockMethod: 'admin_only'
      }, { tenantId });
    }
  }
}

/**
 * Register all security event handlers
 */
export function registerSecurityEventHandlers(eventBus: TypedEventBus<SparcDomainEvents>): void {
  // Incident handler
  const incidentHandler = new SecurityIncidentHandler();
  eventBus.subscribe('security.incident.created', event => incidentHandler.handle(event));

  // Alert batch handler
  const alertHandler = new SecurityAlertBatchHandler();
  eventBus.subscribe('security.alert.triggered', event => alertHandler.handle(event));

  // Failed access aggregator
  const accessAggregator = new FailedAccessAggregator(eventBus);
  eventBus.subscribe('security.access.denied', event => accessAggregator.handle(event));

  logger.info('Security event handlers registered');
}