/**
 * Runtime Security Monitoring for SPARC Platform
 * Provides real-time threat detection and automated response
 */

import { EventEmitter } from 'events';
import { z } from 'zod';
import Redis from 'ioredis';
import { Context } from 'hono';
import crypto from 'crypto';

// Threat types
export enum ThreatType {
  BRUTE_FORCE = 'brute_force',
  SQL_INJECTION = 'sql_injection',
  XSS_ATTEMPT = 'xss_attempt',
  PATH_TRAVERSAL = 'path_traversal',
  COMMAND_INJECTION = 'command_injection',
  ANOMALOUS_BEHAVIOR = 'anomalous_behavior',
  DATA_EXFILTRATION = 'data_exfiltration',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  MALWARE_DETECTED = 'malware_detected',
  DOS_ATTACK = 'dos_attack',
  ACCOUNT_TAKEOVER = 'account_takeover',
  API_ABUSE = 'api_abuse',
  SUSPICIOUS_FILE_ACCESS = 'suspicious_file_access',
  CONTAINER_ESCAPE = 'container_escape',
}

// Threat severity
export enum ThreatSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

// Security event schema
export const securityEventSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.date(),
  type: z.nativeEnum(ThreatType),
  severity: z.nativeEnum(ThreatSeverity),
  confidence: z.number().min(0).max(100),
  
  source: z.object({
    ip: z.string(),
    port: z.number().optional(),
    userId: z.string().optional(),
    sessionId: z.string().optional(),
    userAgent: z.string().optional(),
    geo: z.object({
      country: z.string().optional(),
      city: z.string().optional(),
      asn: z.string().optional(),
    }).optional(),
  }),
  
  target: z.object({
    service: z.string(),
    endpoint: z.string().optional(),
    resource: z.string().optional(),
    tenantId: z.string().optional(),
  }),
  
  indicators: z.array(z.object({
    type: z.string(),
    value: z.any(),
    description: z.string(),
  })),
  
  context: z.object({
    requestId: z.string(),
    correlationId: z.string(),
    method: z.string().optional(),
    path: z.string().optional(),
    headers: z.record(z.string()).optional(),
    payload: z.any().optional(),
  }),
  
  response: z.object({
    action: z.enum(['monitor', 'alert', 'block', 'throttle', 'isolate']),
    automated: z.boolean(),
    details: z.string().optional(),
  }),
  
  metadata: z.record(z.unknown()).optional(),
});

export type SecurityEvent = z.infer<typeof securityEventSchema>;

// Detection rule interface
export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  type: ThreatType;
  severity: ThreatSeverity;
  enabled: boolean;
  
  conditions: {
    patterns?: RegExp[];
    thresholds?: {
      count: number;
      window: number; // seconds
    };
    indicators?: string[];
    customLogic?: (event: Partial<SecurityEvent>, context: DetectionContext) => boolean;
  };
  
  response: {
    actions: Array<'monitor' | 'alert' | 'block' | 'throttle' | 'isolate'>;
    notification?: {
      channels: string[];
      template: string;
    };
  };
}

// Detection context
export interface DetectionContext {
  redis: Redis;
  history: SecurityEvent[];
  metrics: Map<string, number>;
  cache: Map<string, any>;
}

// Behavioral baseline
export interface BehavioralBaseline {
  userId: string;
  metrics: {
    avgRequestsPerMinute: number;
    commonEndpoints: string[];
    commonIPs: string[];
    commonUserAgents: string[];
    typicalAccessTimes: { start: number; end: number }[];
    geoLocations: string[];
  };
  lastUpdated: Date;
}

// Configuration
export interface RuntimeMonitorConfig {
  redis: Redis;
  rules: DetectionRule[];
  
  thresholds: {
    bruteForce: {
      attempts: number;
      window: number;
    };
    rateLimit: {
      requests: number;
      window: number;
    };
    anomalyScore: number;
  };
  
  ml?: {
    enabled: boolean;
    modelPath: string;
    updateInterval: number;
  };
  
  response: {
    autoBlock: boolean;
    blockDuration: number;
    notificationWebhooks: string[];
  };
  
  baseline: {
    enabled: boolean;
    learningPeriod: number; // days
    updateInterval: number; // hours
  };
}

/**
 * Runtime Security Monitor
 */
export class RuntimeSecurityMonitor extends EventEmitter {
  private config: RuntimeMonitorConfig;
  private redis: Redis;
  private rules: Map<string, DetectionRule>;
  private baselines: Map<string, BehavioralBaseline> = new Map();
  private mlModel: any; // ML model instance

  constructor(config: RuntimeMonitorConfig) {
    super();
    
    this.config = config;
    this.redis = config.redis;
    this.rules = new Map(config.rules.map(rule => [rule.id, rule]));
    
    // Initialize ML model if enabled
    if (config.ml?.enabled) {
      this.initializeMLModel();
    }
    
    // Start baseline learning if enabled
    if (config.baseline?.enabled) {
      this.startBaselineLearning();
    }
    
    // Start monitoring
    this.startMonitoring();
  }

  /**
   * Analyze request for threats
   */
  async analyzeRequest(context: Context): Promise<SecurityEvent[]> {
    const events: SecurityEvent[] = [];
    const requestData = this.extractRequestData(context);
    
    // Check against detection rules
    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;
      
      const threatDetected = await this.checkRule(rule, requestData, context);
      if (threatDetected) {
        const event = await this.createSecurityEvent(
          rule.type,
          rule.severity,
          requestData,
          rule,
          context
        );
        
        events.push(event);
        
        // Apply response actions
        await this.applyResponse(event, rule);
      }
    }
    
    // ML-based anomaly detection
    if (this.config.ml?.enabled && this.mlModel) {
      const anomalyScore = await this.detectAnomalies(requestData);
      if (anomalyScore > this.config.thresholds.anomalyScore) {
        const event = await this.createSecurityEvent(
          ThreatType.ANOMALOUS_BEHAVIOR,
          this.getSeverityFromScore(anomalyScore),
          requestData,
          null,
          context
        );
        
        events.push(event);
        await this.applyResponse(event, null);
      }
    }
    
    // Behavioral analysis
    if (this.config.baseline?.enabled && requestData.source.userId) {
      const deviations = await this.analyzeUserBehavior(
        requestData.source.userId,
        requestData
      );
      
      if (deviations.length > 0) {
        const event = await this.createSecurityEvent(
          ThreatType.ANOMALOUS_BEHAVIOR,
          ThreatSeverity.MEDIUM,
          requestData,
          null,
          context,
          { deviations }
        );
        
        events.push(event);
      }
    }
    
    // Emit events
    for (const event of events) {
      this.emit('threat:detected', event);
      await this.logSecurityEvent(event);
    }
    
    return events;
  }

  /**
   * Check detection rule
   */
  private async checkRule(
    rule: DetectionRule,
    requestData: any,
    context: Context
  ): Promise<boolean> {
    const detectionContext: DetectionContext = {
      redis: this.redis,
      history: await this.getRecentEvents(requestData.source.ip, 300),
      metrics: new Map(),
      cache: new Map(),
    };
    
    // Pattern matching
    if (rule.conditions.patterns) {
      for (const pattern of rule.conditions.patterns) {
        // Check various request components
        const checkTargets = [
          requestData.context.path,
          JSON.stringify(requestData.context.headers),
          JSON.stringify(requestData.context.payload),
        ];
        
        for (const target of checkTargets) {
          if (target && pattern.test(target)) {
            return true;
          }
        }
      }
    }
    
    // Threshold checking
    if (rule.conditions.thresholds) {
      const key = `threat:${rule.type}:${requestData.source.ip}`;
      const count = await this.incrementCounter(
        key,
        rule.conditions.thresholds.window
      );
      
      if (count >= rule.conditions.thresholds.count) {
        return true;
      }
    }
    
    // Custom logic
    if (rule.conditions.customLogic) {
      return rule.conditions.customLogic(requestData, detectionContext);
    }
    
    return false;
  }

  /**
   * Create security event
   */
  private async createSecurityEvent(
    type: ThreatType,
    severity: ThreatSeverity,
    requestData: any,
    rule: DetectionRule | null,
    context: Context,
    additionalData?: any
  ): Promise<SecurityEvent> {
    const event: SecurityEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      type,
      severity,
      confidence: rule ? 90 : 70, // Higher confidence for rule-based detection
      
      source: requestData.source,
      target: requestData.target,
      
      indicators: this.extractIndicators(type, requestData, additionalData),
      
      context: requestData.context,
      
      response: {
        action: this.determineResponseAction(severity, type),
        automated: this.config.response.autoBlock,
        details: rule?.name,
      },
      
      metadata: {
        rule: rule?.id,
        ...additionalData,
      },
    };
    
    return securityEventSchema.parse(event);
  }

  /**
   * Apply response actions
   */
  private async applyResponse(
    event: SecurityEvent,
    rule: DetectionRule | null
  ): Promise<void> {
    const actions = rule?.response.actions || [event.response.action];
    
    for (const action of actions) {
      switch (action) {
        case 'block':
          if (this.config.response.autoBlock) {
            await this.blockSource(event.source.ip, this.config.response.blockDuration);
          }
          break;
          
        case 'throttle':
          await this.throttleSource(event.source.ip);
          break;
          
        case 'isolate':
          if (event.source.userId) {
            await this.isolateUser(event.source.userId);
          }
          break;
          
        case 'alert':
          await this.sendAlert(event);
          break;
          
        case 'monitor':
          // Just log, no active response
          break;
      }
    }
    
    // Send notifications
    if (rule?.response.notification) {
      await this.sendNotifications(event, rule.response.notification);
    }
  }

  /**
   * Block source IP
   */
  private async blockSource(ip: string, duration: number): Promise<void> {
    const key = `blocked:ip:${ip}`;
    await this.redis.setex(key, duration, JSON.stringify({
      reason: 'security_threat',
      timestamp: new Date().toISOString(),
    }));
    
    this.emit('source:blocked', { ip, duration });
  }

  /**
   * Throttle source
   */
  private async throttleSource(ip: string): Promise<void> {
    const key = `throttled:ip:${ip}`;
    await this.redis.setex(key, 3600, JSON.stringify({
      limit: 10, // requests per minute
      timestamp: new Date().toISOString(),
    }));
    
    this.emit('source:throttled', { ip });
  }

  /**
   * Isolate user account
   */
  private async isolateUser(userId: string): Promise<void> {
    const key = `isolated:user:${userId}`;
    await this.redis.setex(key, 86400, JSON.stringify({
      reason: 'security_threat',
      timestamp: new Date().toISOString(),
      requiresMFA: true,
    }));
    
    // Revoke all active sessions
    await this.revokeUserSessions(userId);
    
    this.emit('user:isolated', { userId });
  }

  /**
   * Extract indicators of compromise
   */
  private extractIndicators(
    type: ThreatType,
    requestData: any,
    additionalData?: any
  ): SecurityEvent['indicators'] {
    const indicators: SecurityEvent['indicators'] = [];
    
    switch (type) {
      case ThreatType.SQL_INJECTION:
        indicators.push({
          type: 'sql_pattern',
          value: requestData.context.payload,
          description: 'SQL injection pattern detected',
        });
        break;
        
      case ThreatType.XSS_ATTEMPT:
        indicators.push({
          type: 'xss_pattern',
          value: requestData.context.payload,
          description: 'XSS pattern detected',
        });
        break;
        
      case ThreatType.BRUTE_FORCE:
        indicators.push({
          type: 'failed_attempts',
          value: additionalData?.attempts || 0,
          description: 'Multiple failed authentication attempts',
        });
        break;
        
      case ThreatType.ANOMALOUS_BEHAVIOR:
        if (additionalData?.deviations) {
          for (const deviation of additionalData.deviations) {
            indicators.push({
              type: 'behavioral_deviation',
              value: deviation,
              description: 'Deviation from normal behavior',
            });
          }
        }
        break;
    }
    
    return indicators;
  }

  /**
   * Analyze user behavior
   */
  private async analyzeUserBehavior(
    userId: string,
    requestData: any
  ): Promise<string[]> {
    const deviations: string[] = [];
    const baseline = this.baselines.get(userId);
    
    if (!baseline) {
      // No baseline yet, start learning
      await this.updateUserBaseline(userId, requestData);
      return deviations;
    }
    
    // Check request rate
    const currentRate = await this.getUserRequestRate(userId);
    if (currentRate > baseline.metrics.avgRequestsPerMinute * 3) {
      deviations.push('abnormal_request_rate');
    }
    
    // Check access time
    const currentHour = new Date().getHours();
    const inTypicalTime = baseline.metrics.typicalAccessTimes.some(
      range => currentHour >= range.start && currentHour <= range.end
    );
    if (!inTypicalTime) {
      deviations.push('unusual_access_time');
    }
    
    // Check geo-location
    if (requestData.source.geo?.country && 
        !baseline.metrics.geoLocations.includes(requestData.source.geo.country)) {
      deviations.push('new_geo_location');
    }
    
    // Check endpoint access
    if (requestData.target.endpoint && 
        !baseline.metrics.commonEndpoints.includes(requestData.target.endpoint)) {
      deviations.push('unusual_endpoint_access');
    }
    
    return deviations;
  }

  /**
   * ML-based anomaly detection
   */
  private async detectAnomalies(requestData: any): Promise<number> {
    if (!this.mlModel) return 0;
    
    // Extract features
    const features = this.extractMLFeatures(requestData);
    
    // Get prediction from model
    const anomalyScore = await this.mlModel.predict(features);
    
    return anomalyScore;
  }

  /**
   * Extract ML features from request
   */
  private extractMLFeatures(requestData: any): number[] {
    // Simplified feature extraction
    const features: number[] = [];
    
    // Time-based features
    const now = new Date();
    features.push(now.getHours()); // Hour of day
    features.push(now.getDay()); // Day of week
    
    // Request features
    features.push(requestData.context.path?.length || 0);
    features.push(Object.keys(requestData.context.headers || {}).length);
    features.push(JSON.stringify(requestData.context.payload || {}).length);
    
    // Source features
    features.push(requestData.source.ip.split('.').map(Number)[3] || 0); // Last octet
    
    // Add more sophisticated features in production
    
    return features;
  }

  /**
   * Initialize ML model
   */
  private async initializeMLModel(): Promise<void> {
    // TODO: Load actual ML model
    // This is a placeholder for the ML integration
    this.mlModel = {
      predict: async (features: number[]): Promise<number> => {
        // Simple anomaly scoring based on features
        const sum = features.reduce((a, b) => a + b, 0);
        return Math.min(sum / features.length / 10, 100);
      },
    };
  }

  /**
   * Start baseline learning
   */
  private async startBaselineLearning(): Promise<void> {
    // Update baselines periodically
    setInterval(async () => {
      await this.updateAllBaselines();
    }, this.config.baseline.updateInterval * 3600000);
  }

  /**
   * Update user baseline
   */
  private async updateUserBaseline(
    userId: string,
    requestData: any
  ): Promise<void> {
    const key = `baseline:${userId}`;
    const data = await this.redis.get(key);
    
    let baseline: any = data ? JSON.parse(data) : {
      requests: [],
      endpoints: new Set(),
      ips: new Set(),
      userAgents: new Set(),
      geoLocations: new Set(),
      accessTimes: [],
    };
    
    // Add new data point
    baseline.requests.push(Date.now());
    baseline.endpoints.add(requestData.target.endpoint);
    baseline.ips.add(requestData.source.ip);
    baseline.userAgents.add(requestData.source.userAgent);
    
    if (requestData.source.geo?.country) {
      baseline.geoLocations.add(requestData.source.geo.country);
    }
    
    baseline.accessTimes.push(new Date().getHours());
    
    // Store updated baseline
    await this.redis.setex(key, 86400 * 30, JSON.stringify({
      requests: baseline.requests.slice(-1000), // Keep last 1000
      endpoints: Array.from(baseline.endpoints),
      ips: Array.from(baseline.ips),
      userAgents: Array.from(baseline.userAgents),
      geoLocations: Array.from(baseline.geoLocations),
      accessTimes: baseline.accessTimes.slice(-100),
    }));
  }

  /**
   * Update all baselines
   */
  private async updateAllBaselines(): Promise<void> {
    // TODO: Implement batch baseline updates
    console.log('Updating behavioral baselines...');
  }

  /**
   * Get recent security events
   */
  private async getRecentEvents(
    ip: string,
    seconds: number
  ): Promise<SecurityEvent[]> {
    const key = `events:${ip}`;
    const events = await this.redis.lrange(key, 0, -1);
    
    const now = Date.now();
    const recentEvents = events
      .map(e => JSON.parse(e))
      .filter(e => now - new Date(e.timestamp).getTime() < seconds * 1000);
    
    return recentEvents;
  }

  /**
   * Log security event
   */
  private async logSecurityEvent(event: SecurityEvent): Promise<void> {
    const key = `events:${event.source.ip}`;
    
    await this.redis.lpush(key, JSON.stringify(event));
    await this.redis.ltrim(key, 0, 99); // Keep last 100 events
    await this.redis.expire(key, 3600); // 1 hour TTL
    
    // Also log to persistent storage
    // TODO: Send to SIEM/logging system
  }

  /**
   * Send alert
   */
  private async sendAlert(event: SecurityEvent): Promise<void> {
    const alert = {
      id: event.id,
      timestamp: event.timestamp,
      type: event.type,
      severity: event.severity,
      source: event.source.ip,
      target: event.target.service,
      description: `Security threat detected: ${event.type}`,
      indicators: event.indicators,
    };
    
    // Send to notification webhooks
    for (const webhook of this.config.response.notificationWebhooks) {
      try {
        await fetch(webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(alert),
        });
      } catch (error) {
        console.error(`Failed to send alert to ${webhook}:`, error);
      }
    }
    
    this.emit('alert:sent', alert);
  }

  /**
   * Send notifications
   */
  private async sendNotifications(
    event: SecurityEvent,
    notification: { channels: string[]; template: string }
  ): Promise<void> {
    // TODO: Implement notification system integration
    console.log('Sending notifications:', notification);
  }

  /**
   * Revoke user sessions
   */
  private async revokeUserSessions(userId: string): Promise<void> {
    const pattern = `session:${userId}:*`;
    const keys = await this.redis.keys(pattern);
    
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
    
    this.emit('sessions:revoked', { userId, count: keys.length });
  }

  /**
   * Get user request rate
   */
  private async getUserRequestRate(userId: string): Promise<number> {
    const key = `rate:user:${userId}`;
    const count = await this.redis.zcount(
      key,
      Date.now() - 60000,
      Date.now()
    );
    
    return count;
  }

  /**
   * Increment counter
   */
  private async incrementCounter(key: string, ttl: number): Promise<number> {
    const multi = this.redis.multi();
    multi.incr(key);
    multi.expire(key, ttl);
    
    const results = await multi.exec();
    return results?.[0]?.[1] as number || 0;
  }

  /**
   * Extract request data
   */
  private extractRequestData(context: Context): any {
    const ip = context.req.header('x-forwarded-for')?.split(',')[0] || 
              context.req.header('x-real-ip') || 
              'unknown';
    
    return {
      source: {
        ip,
        userId: context.get('userId'),
        sessionId: context.get('sessionId'),
        userAgent: context.req.header('user-agent'),
        geo: {
          country: context.req.header('cf-ipcountry'),
          // Add more geo data if available
        },
      },
      target: {
        service: process.env.SERVICE_NAME || 'unknown',
        endpoint: context.req.path,
        tenantId: context.get('tenantId'),
      },
      context: {
        requestId: context.get('requestId') || crypto.randomUUID(),
        correlationId: context.get('correlationId') || crypto.randomUUID(),
        method: context.req.method,
        path: context.req.path,
        headers: this.sanitizeHeaders(context.req.header()),
        payload: context.get('requestBody'),
      },
    };
  }

  /**
   * Sanitize headers for logging
   */
  private sanitizeHeaders(headers: Record<string, string | undefined>): Record<string, string> {
    const sanitized: Record<string, string> = {};
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];
    
    for (const [key, value] of Object.entries(headers)) {
      if (value) {
        if (sensitiveHeaders.includes(key.toLowerCase())) {
          sanitized[key] = '[REDACTED]';
        } else {
          sanitized[key] = value;
        }
      }
    }
    
    return sanitized;
  }

  /**
   * Determine response action based on severity
   */
  private determineResponseAction(
    severity: ThreatSeverity,
    type: ThreatType
  ): SecurityEvent['response']['action'] {
    // Critical threats get blocked
    if (severity === ThreatSeverity.CRITICAL) {
      return 'block';
    }
    
    // High severity threats get throttled or blocked based on type
    if (severity === ThreatSeverity.HIGH) {
      if ([ThreatType.SQL_INJECTION, ThreatType.COMMAND_INJECTION].includes(type)) {
        return 'block';
      }
      return 'throttle';
    }
    
    // Medium severity gets alerted
    if (severity === ThreatSeverity.MEDIUM) {
      return 'alert';
    }
    
    // Low severity just gets monitored
    return 'monitor';
  }

  /**
   * Get severity from anomaly score
   */
  private getSeverityFromScore(score: number): ThreatSeverity {
    if (score >= 90) return ThreatSeverity.CRITICAL;
    if (score >= 70) return ThreatSeverity.HIGH;
    if (score >= 50) return ThreatSeverity.MEDIUM;
    return ThreatSeverity.LOW;
  }

  /**
   * Start monitoring
   */
  private startMonitoring(): void {
    // Periodic health check
    setInterval(() => {
      this.emit('monitor:health', {
        rules: this.rules.size,
        baselines: this.baselines.size,
        mlEnabled: !!this.mlModel,
      });
    }, 60000);
  }

  /**
   * Check if source is blocked
   */
  async isBlocked(ip: string): Promise<boolean> {
    const key = `blocked:ip:${ip}`;
    const blocked = await this.redis.get(key);
    return !!blocked;
  }

  /**
   * Check if source is throttled
   */
  async isThrottled(ip: string): Promise<{ throttled: boolean; limit?: number }> {
    const key = `throttled:ip:${ip}`;
    const data = await this.redis.get(key);
    
    if (!data) {
      return { throttled: false };
    }
    
    const throttleInfo = JSON.parse(data);
    return {
      throttled: true,
      limit: throttleInfo.limit,
    };
  }

  /**
   * Check if user is isolated
   */
  async isUserIsolated(userId: string): Promise<{ isolated: boolean; requiresMFA?: boolean }> {
    const key = `isolated:user:${userId}`;
    const data = await this.redis.get(key);
    
    if (!data) {
      return { isolated: false };
    }
    
    const isolationInfo = JSON.parse(data);
    return {
      isolated: true,
      requiresMFA: isolationInfo.requiresMFA,
    };
  }

  /**
   * Get threat statistics
   */
  async getThreatStats(hours: number = 24): Promise<any> {
    const stats = {
      total: 0,
      byType: {} as Record<ThreatType, number>,
      bySeverity: {} as Record<ThreatSeverity, number>,
      topSources: [] as Array<{ ip: string; count: number }>,
      topTargets: [] as Array<{ service: string; count: number }>,
    };
    
    // TODO: Implement statistics aggregation
    
    return stats;
  }
}

/**
 * Create runtime security monitor middleware
 */
export function createSecurityMonitor(monitor: RuntimeSecurityMonitor) {
  return async (c: Context, next: () => Promise<void>) => {
    // Check if source is blocked
    const ip = c.req.header('x-forwarded-for')?.split(',')[0] || 
              c.req.header('x-real-ip') || 
              'unknown';
    
    if (await monitor.isBlocked(ip)) {
      return c.json({ error: 'Access denied' }, 403);
    }
    
    // Check if source is throttled
    const throttleInfo = await monitor.isThrottled(ip);
    if (throttleInfo.throttled) {
      c.header('X-RateLimit-Limit', throttleInfo.limit?.toString() || '10');
      c.header('Retry-After', '60');
      return c.json({ error: 'Too many requests' }, 429);
    }
    
    // Check if user is isolated
    const userId = c.get('userId');
    if (userId) {
      const isolationInfo = await monitor.isUserIsolated(userId);
      if (isolationInfo.isolated) {
        if (isolationInfo.requiresMFA && !c.get('mfaVerified')) {
          return c.json({ error: 'MFA required', code: 'MFA_REQUIRED' }, 403);
        }
      }
    }
    
    // Store request body for analysis
    if (c.req.method !== 'GET' && c.req.header('content-type')?.includes('application/json')) {
      try {
        const body = await c.req.json();
        c.set('requestBody', body);
      } catch {
        // Ignore parse errors
      }
    }
    
    // Analyze request for threats
    const threats = await monitor.analyzeRequest(c);
    
    // Block if critical threat detected
    const criticalThreat = threats.find(t => t.severity === ThreatSeverity.CRITICAL);
    if (criticalThreat && criticalThreat.response.action === 'block') {
      return c.json({ error: 'Security threat detected' }, 403);
    }
    
    // Continue with request
    await next();
  };
}

// Default detection rules
export const defaultDetectionRules: DetectionRule[] = [
  {
    id: 'sql-injection',
    name: 'SQL Injection Detection',
    description: 'Detects SQL injection attempts',
    type: ThreatType.SQL_INJECTION,
    severity: ThreatSeverity.HIGH,
    enabled: true,
    conditions: {
      patterns: [
        /(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/gi,
        /(--|#|\/\*|\*\/)/g,
        /(\bOR\b\s*\d+\s*=\s*\d+|\bAND\b\s*\d+\s*=\s*\d+)/gi,
      ],
    },
    response: {
      actions: ['block', 'alert'],
    },
  },
  {
    id: 'xss-detection',
    name: 'XSS Detection',
    description: 'Detects cross-site scripting attempts',
    type: ThreatType.XSS_ATTEMPT,
    severity: ThreatSeverity.HIGH,
    enabled: true,
    conditions: {
      patterns: [
        /<script[^>]*>[\s\S]*?<\/script>/gi,
        /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
      ],
    },
    response: {
      actions: ['block', 'alert'],
    },
  },
  {
    id: 'brute-force',
    name: 'Brute Force Detection',
    description: 'Detects brute force login attempts',
    type: ThreatType.BRUTE_FORCE,
    severity: ThreatSeverity.HIGH,
    enabled: true,
    conditions: {
      thresholds: {
        count: 5,
        window: 300, // 5 minutes
      },
      customLogic: (event, context) => {
        return event.context?.path?.includes('/auth/login') &&
               event.context?.method === 'POST';
      },
    },
    response: {
      actions: ['throttle', 'alert'],
    },
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal Detection',
    description: 'Detects path traversal attempts',
    type: ThreatType.PATH_TRAVERSAL,
    severity: ThreatSeverity.HIGH,
    enabled: true,
    conditions: {
      patterns: [
        /\.\./g,
        /\.\.\\/, 
        /%2e%2e/gi,
        /%252e%252e/gi,
      ],
    },
    response: {
      actions: ['block', 'alert'],
    },
  },
  {
    id: 'api-abuse',
    name: 'API Abuse Detection',
    description: 'Detects API abuse patterns',
    type: ThreatType.API_ABUSE,
    severity: ThreatSeverity.MEDIUM,
    enabled: true,
    conditions: {
      thresholds: {
        count: 100,
        window: 60, // 1 minute
      },
    },
    response: {
      actions: ['throttle', 'monitor'],
    },
  },
];

export default RuntimeSecurityMonitor;