import { Redis } from 'ioredis';
import { AlertService } from './alert.service';
import { NotificationService } from './notification.service';
import { EscalationService } from './escalation.service';
import type { 
  WebhookEventDTO, 
  EnvironmentalWebhookDTO,
  Alert,
  AlertType,
  AlertPriority,
  SourceType,
  ALERT_TYPE_CONFIG
} from '@sparc/shared/types/alerts';
import { logger } from '@sparc/shared';
import { v4 as uuidv4 } from 'uuid';

export class WebhookProcessorService {
  private alertService: AlertService;
  private notificationService: NotificationService;
  private escalationService: EscalationService;

  constructor(private redis: Redis) {
    this.alertService = new AlertService(redis);
    this.notificationService = new NotificationService(redis);
    this.escalationService = new EscalationService(redis);
  }

  async processWebhookEvent(event: WebhookEventDTO): Promise<Alert | null> {
    try {
      const alertData = await this.transformEventToAlert(event);
      
      if (!alertData) {
        logger.info('Event processed, no alert created', { eventType: event.eventType });
        return null;
      }

      // Create the alert
      const alert = await this.alertService.createAlert(alertData.tenantId, {
        alertType: alertData.alertType as AlertType,
        priority: alertData.priority as AlertPriority,
        sourceId: alertData.sourceId,
        sourceType: alertData.sourceType as SourceType,
        message: alertData.message,
        details: alertData.details
      });

      // Schedule escalation
      await this.escalationService.scheduleEscalation(alert);

      // Send notifications
      await this.notificationService.sendNotifications(alert);

      // Broadcast alert via Redis pub/sub
      await this.redis.publish(
        `alert:created:${alert.tenantId}`,
        JSON.stringify(alert)
      );

      logger.info('Alert created from webhook event', {
        alertId: alert.id,
        eventType: event.eventType,
        tenantId: alert.tenantId
      });

      return alert;
    } catch (error) {
      logger.error('Failed to process webhook event', { error, event });
      throw error;
    }
  }

  async processEnvironmentalWebhook(data: EnvironmentalWebhookDTO): Promise<Alert[]> {
    const alerts: Alert[] = [];

    try {
      // Check temperature thresholds
      if (data.readings.temperature !== undefined && data.thresholds.temperature) {
        const temp = data.readings.temperature;
        const { min, max } = data.thresholds.temperature;
        
        if (temp < min || temp > max) {
          const alert = await this.alertService.createAlert(data.tenantId, {
            alertType: AlertType.TEMPERATURE_THRESHOLD,
            priority: AlertPriority.MEDIUM,
            sourceId: data.sensorId,
            sourceType: SourceType.ENVIRONMENTAL,
            message: `Temperature ${temp}°C exceeds threshold (${min}-${max}°C)`,
            details: { 
              readings: data.readings, 
              thresholds: data.thresholds, 
              sensorId: data.sensorId,
              currentValue: temp,
              thresholdMin: min,
              thresholdMax: max
            }
          });

          alerts.push(alert);
          await this.handleAlertCreated(alert);
        }
      }

      // Check humidity thresholds
      if (data.readings.humidity !== undefined && data.thresholds.humidity) {
        const humidity = data.readings.humidity;
        const { min, max } = data.thresholds.humidity;
        
        if (humidity < min || humidity > max) {
          const alert = await this.alertService.createAlert(data.tenantId, {
            alertType: AlertType.HUMIDITY_THRESHOLD,
            priority: AlertPriority.MEDIUM,
            sourceId: data.sensorId,
            sourceType: SourceType.ENVIRONMENTAL,
            message: `Humidity ${humidity}% exceeds threshold (${min}-${max}%)`,
            details: { 
              readings: data.readings, 
              thresholds: data.thresholds, 
              sensorId: data.sensorId,
              currentValue: humidity,
              thresholdMin: min,
              thresholdMax: max
            }
          });

          alerts.push(alert);
          await this.handleAlertCreated(alert);
        }
      }

      // Check for leak detection
      if (data.readings.leakDetected === true) {
        const alert = await this.alertService.createAlert(data.tenantId, {
          alertType: AlertType.LEAK_DETECTED,
          priority: AlertPriority.CRITICAL,
          sourceId: data.sensorId,
          sourceType: SourceType.ENVIRONMENTAL,
          message: 'Water leak detected',
          details: { 
            readings: data.readings, 
            sensorId: data.sensorId,
            detectedAt: new Date().toISOString()
          }
        });

        alerts.push(alert);
        await this.handleAlertCreated(alert);
      }

      logger.info('Environmental webhook processed', {
        tenantId: data.tenantId,
        sensorId: data.sensorId,
        alertsCreated: alerts.length
      });

      return alerts;
    } catch (error) {
      logger.error('Failed to process environmental webhook', { error, data });
      throw error;
    }
  }

  private async transformEventToAlert(event: WebhookEventDTO): Promise<{
    tenantId: string;
    alertType: string;
    priority: string;
    sourceId: string;
    sourceType: string;
    message: string;
    details: Record<string, any>;
  } | null> {
    const alertConfig = ALERT_TYPE_CONFIG[event.eventType as keyof typeof ALERT_TYPE_CONFIG];
    
    // Extract tenant ID from event data
    const tenantId = event.data.tenantId || event.data.tenant_id || 'unknown';

    // Base alert data
    const baseAlert = {
      tenantId,
      sourceId: event.sourceId,
      sourceType: event.sourceType,
      details: event.data
    };

    // Handle specific event types
    switch (event.eventType) {
      case 'access_denied': {
        // Track repeated access denials
        const denialKey = `access_denials:${event.sourceId}`;
        const recentDenials = await this.redis.incr(denialKey);
        await this.redis.expire(denialKey, 300); // 5 minutes

        if (recentDenials >= 3) {
          return {
            ...baseAlert,
            alertType: AlertType.ACCESS_DENIED,
            priority: AlertPriority.HIGH,
            message: `Multiple access denied attempts (${recentDenials}) at ${event.data.doorName || event.sourceId}`,
            details: { 
              ...event.data, 
              attemptCount: recentDenials,
              threshold: 3,
              timeWindow: '5 minutes'
            }
          };
        }
        // Don't create alert for single denial
        return null;
      }

      case 'door_forced':
      case 'emergency_lockdown':
      case 'security_breach': {
        return {
          ...baseAlert,
          alertType: event.eventType as AlertType,
          priority: alertConfig?.priority || event.priority || AlertPriority.HIGH,
          message: `Security event: ${event.eventType.replace(/_/g, ' ')} at ${event.data.location || event.sourceId}`,
          details: {
            ...event.data,
            eventTime: event.timestamp,
            severity: 'high'
          }
        };
      }

      case 'system_offline':
      case 'camera_offline': {
        return {
          ...baseAlert,
          alertType: event.eventType as AlertType,
          priority: alertConfig?.priority || AlertPriority.HIGH,
          message: `${event.eventType.replace(/_/g, ' ')}: ${event.data.name || event.sourceId}`,
          details: {
            ...event.data,
            offlineAt: event.timestamp,
            lastSeen: event.data.lastSeen || 'unknown'
          }
        };
      }

      case 'motion_detected': {
        // Check if motion detection should create alerts
        const motionConfig = await this.redis.hget(`alert_config:${tenantId}`, 'motion_detection');
        if (motionConfig === 'disabled') {
          return null;
        }

        return {
          ...baseAlert,
          alertType: AlertType.MOTION_DETECTED,
          priority: AlertPriority.LOW,
          message: `Motion detected at ${event.data.location || event.sourceId}`,
          details: {
            ...event.data,
            detectedAt: event.timestamp,
            confidence: event.data.confidence || 'unknown'
          }
        };
      }

      default: {
        // Generic alert for unknown event types
        if (alertConfig) {
          return {
            ...baseAlert,
            alertType: event.eventType,
            priority: alertConfig.priority || event.priority || AlertPriority.MEDIUM,
            message: event.data.message || `${event.eventType.replace(/_/g, ' ')} detected`,
            details: event.data
          };
        }

        // Create a generic alert for truly unknown events
        return {
          ...baseAlert,
          alertType: event.eventType,
          priority: event.priority || AlertPriority.MEDIUM,
          message: `Event: ${event.eventType}`,
          details: event.data
        };
      }
    }
  }

  private async handleAlertCreated(alert: Alert): Promise<void> {
    // Schedule escalation
    await this.escalationService.scheduleEscalation(alert);

    // Send notifications
    await this.notificationService.sendNotifications(alert);

    // Broadcast alert
    await this.redis.publish(
      `alert:created:${alert.tenantId}`,
      JSON.stringify(alert)
    );

    // Update real-time stats
    await this.redis.hincrby(`alert_stats:realtime:${alert.tenantId}`, 'total', 1);
    await this.redis.hincrby(`alert_stats:realtime:${alert.tenantId}`, alert.priority, 1);
    await this.redis.hincrby(`alert_stats:realtime:${alert.tenantId}`, alert.alertType, 1);
    
    // Set expiry on realtime stats (24 hours)
    await this.redis.expire(`alert_stats:realtime:${alert.tenantId}`, 86400);
  }

  async getEventProcessingStats(tenantId: string): Promise<{
    eventsProcessed: number;
    alertsCreated: number;
    lastProcessed: string | null;
    processingErrors: number;
  }> {
    const stats = await this.redis.hgetall(`webhook_stats:${tenantId}`);
    
    return {
      eventsProcessed: parseInt(stats.eventsProcessed || '0'),
      alertsCreated: parseInt(stats.alertsCreated || '0'),
      lastProcessed: stats.lastProcessed || null,
      processingErrors: parseInt(stats.processingErrors || '0')
    };
  }
}