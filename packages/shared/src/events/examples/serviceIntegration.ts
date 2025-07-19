/**
 * Example of integrating Event Bus with a SPARC microservice
 */

import { MicroserviceBase, ServiceConfig } from '@/patterns/service-base';
import { createSparcEventBus, TypedEventBus, SparcDomainEvents } from '../index';
import { EventBusMetrics, EventFlowTracer, EventDebugger, EventBusHealthChecker } from '../eventMonitoring';
import { registerSecurityEventHandlers } from './securityEventHandlers';
import { logger } from '@/logger';

/**
 * Enhanced MicroserviceBase with Event Bus integration
 */
export abstract class EventDrivenMicroservice extends MicroserviceBase {
  protected eventBus!: TypedEventBus<SparcDomainEvents>;
  protected eventMetrics!: EventBusMetrics;
  protected eventTracer!: EventFlowTracer;
  protected eventDebugger!: EventDebugger;
  protected eventHealthChecker!: EventBusHealthChecker;

  constructor(config: ServiceConfig) {
    super(config);
  }

  protected async onInitialize(): Promise<void> {
    await super.onInitialize();
    await this.initializeEventBus();
  }

  private async initializeEventBus(): Promise<void> {
    // Create event bus
    this.eventBus = createSparcEventBus({
      redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
      serviceName: this.config.serviceName,
      maxRetries: 3,
      retryDelay: 1000,
      enablePersistence: true,
      enableOrdering: true,
      batchSize: 100,
      flushInterval: 1000
    });

    // Initialize monitoring
    this.eventMetrics = new EventBusMetrics(this.config.serviceName);
    this.eventTracer = new EventFlowTracer({ maxTraces: 1000, ttl: 3600000 });
    this.eventDebugger = new EventDebugger(process.env.NODE_ENV === 'development');
    this.eventHealthChecker = new EventBusHealthChecker(this.eventBus, this.eventMetrics);

    // Add debug filters in development
    if (process.env.NODE_ENV === 'development') {
      this.eventDebugger.addFilter({ 
        tenantId: process.env.DEBUG_TENANT_ID 
      });
    }

    // Register service-specific event handlers
    await this.registerEventHandlers();

    logger.info('Event bus initialized', {
      service: this.config.serviceName
    });
  }

  /**
   * Override in subclasses to register service-specific event handlers
   */
  protected abstract registerEventHandlers(): Promise<void>;

  /**
   * Publish an event with monitoring
   */
  protected async publishEvent<K extends keyof SparcDomainEvents>(
    type: K,
    data: SparcDomainEvents[K],
    metadata?: {
      correlationId?: string;
      causationId?: string;
      userId?: string;
      [key: string]: any;
    }
  ): Promise<void> {
    const tenantId = this.getTenantId();
    
    // Start trace
    const event = {
      id: `evt-${Date.now()}`,
      type: type as string,
      version: 1,
      tenantId,
      timestamp: new Date(),
      data,
      metadata: {
        ...metadata,
        source: this.config.serviceName
      }
    };

    this.eventTracer.startTrace(event);
    this.eventDebugger.logEvent(event, 'Publishing event');

    try {
      await this.eventBus.publish(type, data, {
        ...metadata,
        tenantId
      });

      this.eventMetrics.recordEventPublished(event);
      this.eventTracer.addStep(event.id, {
        name: 'Event published',
        status: 'completed'
      });
    } catch (error) {
      this.eventTracer.addStep(event.id, {
        name: 'Event publish failed',
        status: 'failed',
        metadata: { error: error.message }
      });
      this.eventTracer.completeTrace(event.id, false, error);
      throw error;
    }
  }

  /**
   * Get current tenant ID from context
   */
  protected getTenantId(): string {
    // This would be implemented based on your auth/context system
    return 'default-tenant';
  }

  /**
   * Health check including event bus
   */
  protected async performHealthCheck(): Promise<any> {
    const baseHealth = await super.performHealthCheck();
    const eventHealth = await this.eventHealthChecker.checkHealth();

    return {
      ...baseHealth,
      eventBus: eventHealth
    };
  }

  protected async onShutdown(): Promise<void> {
    await this.eventBus.close();
    await super.onShutdown();
  }
}

/**
 * Example: Security Monitoring Service with Event Bus
 */
export class SecurityMonitoringService extends EventDrivenMicroservice {
  constructor() {
    super({
      serviceName: 'security-monitoring-service',
      port: 3010,
      enableWebSocket: true,
      enableMetrics: true
    });
  }

  protected async registerEventHandlers(): Promise<void> {
    // Register security event handlers
    registerSecurityEventHandlers(this.eventBus);

    // Service-specific handlers
    await this.eventBus.subscribe('video.motion.detected', async (event) => {
      this.eventTracer.addStep(event.id, {
        name: 'Processing motion detection',
        handler: 'SecurityMonitoringService',
        status: 'started'
      });

      try {
        await this.analyzeMotionForSecurity(event);
        
        this.eventTracer.addStep(event.id, {
          name: 'Motion analysis completed',
          handler: 'SecurityMonitoringService',
          status: 'completed'
        });
      } catch (error) {
        this.eventDebugger.logHandler(event, 'SecurityMonitoringService', 'error', error);
        throw error;
      }
    });

    // Subscribe to device events
    await this.eventBus.subscribe('system.device.offline', async (event) => {
      if (event.data.deviceType === 'camera' || event.data.deviceType === 'sensor') {
        await this.handleSecurityDeviceOffline(event);
      }
    });

    // Subscribe to analytics events
    await this.eventBus.subscribe('analytics.anomaly.detected', async (event) => {
      if (event.data.type === 'behavior' || event.data.type === 'access_pattern') {
        await this.investigateSecurityAnomaly(event);
      }
    });
  }

  private async analyzeMotionForSecurity(event: any): Promise<void> {
    const { cameraId, motionArea, confidence } = event.data;

    // Check if motion is in restricted area
    const camera = await this.db.camera.findUnique({
      where: { id: cameraId },
      include: { zone: true }
    });

    if (camera?.zone.securityLevel === 'high' && confidence > 0.8) {
      // Create security alert
      await this.publishEvent('security.alert.triggered', {
        alertId: `ALT-${Date.now()}`,
        ruleId: 'motion-in-restricted-area',
        ruleName: 'Motion in Restricted Area',
        type: 'motion_detection',
        severity: 'high',
        source: {
          type: 'camera',
          id: cameraId
        },
        data: {
          motionArea,
          confidence,
          zone: camera.zone.name
        }
      }, {
        correlationId: event.metadata?.correlationId,
        causationId: event.id
      });
    }
  }

  private async handleSecurityDeviceOffline(event: any): Promise<void> {
    const { deviceId, deviceType, siteId } = event.data;

    // Check if this affects security coverage
    const affectedZones = await this.db.zone.findMany({
      where: {
        siteId,
        devices: {
          some: {
            id: deviceId,
            type: deviceType
          }
        },
        securityLevel: { in: ['high', 'critical'] }
      }
    });

    if (affectedZones.length > 0) {
      // Create security incident for coverage gap
      await this.publishEvent('security.incident.created', {
        incidentId: `INC-${Date.now()}`,
        type: 'other',
        severity: 'medium',
        siteId,
        description: `Security ${deviceType} offline in critical area`,
        detectedBy: {
          type: 'system',
          id: 'monitoring-system'
        }
      }, {
        correlationId: event.metadata?.correlationId
      });
    }
  }

  private async investigateSecurityAnomaly(event: any): Promise<void> {
    const { type, confidence, description } = event.data;

    if (confidence > 0.85) {
      // High confidence anomaly - create incident
      await this.publishEvent('security.incident.created', {
        incidentId: `INC-${Date.now()}`,
        type: 'suspicious_activity',
        severity: confidence > 0.95 ? 'high' : 'medium',
        siteId: event.data.entityId,
        description: `Anomaly detected: ${description}`,
        detectedBy: {
          type: 'analytics',
          id: 'anomaly-detection',
          name: 'AI Anomaly Detection'
        }
      });
    }
  }

  protected setupRoutes(): void {
    // Add event bus status endpoint
    this.app.get('/events/status', async (c) => {
      const traces = this.eventTracer.getRecentTraces(50);
      const failedTraces = this.eventTracer.getFailedTraces(20);
      
      return c.json({
        recentEvents: traces,
        failedEvents: failedTraces,
        metrics: {
          // This would include actual metrics from Prometheus
        }
      });
    });

    // Add event replay endpoint
    this.app.post('/events/replay', async (c) => {
      const { eventType, from, to, tenantId } = await c.req.json();
      
      const events = await this.eventBus.replay({
        type: eventType,
        from: new Date(from),
        to: to ? new Date(to) : undefined,
        tenantId
      });

      return c.json({
        count: events.length,
        events
      });
    });

    // Other service routes...
    super.setupRoutes();
  }
}

/**
 * Example usage in a service
 */
export async function startSecurityMonitoringService(): Promise<void> {
  const service = new SecurityMonitoringService();
  await service.start();
}

/**
 * Example: Publishing events from API routes
 */
export function createEventPublishingRoutes(service: EventDrivenMicroservice) {
  return {
    // Create incident endpoint
    createIncident: async (c: any) => {
      const data = await c.req.json();
      
      // Validate and create incident
      const incident = {
        incidentId: `INC-${Date.now()}`,
        ...data
      };

      // Publish event
      await service.publishEvent('security.incident.created', incident, {
        userId: c.get('userId'),
        correlationId: c.get('correlationId')
      });

      return c.json({ success: true, incidentId: incident.incidentId });
    },

    // Update incident endpoint
    updateIncident: async (c: any) => {
      const { id } = c.req.param();
      const updates = await c.req.json();
      
      // Get current incident
      const incident = await service.db.securityIncident.findUnique({
        where: { id }
      });

      if (!incident) {
        return c.json({ error: 'Incident not found' }, 404);
      }

      // Update in database
      const updated = await service.db.securityIncident.update({
        where: { id },
        data: updates
      });

      // Publish event
      await service.publishEvent('security.incident.updated', {
        incidentId: id,
        previousStatus: incident.status,
        newStatus: updated.status,
        updatedBy: c.get('userId'),
        updates
      }, {
        userId: c.get('userId'),
        correlationId: incident.correlationId
      });

      return c.json(updated);
    }
  };
}