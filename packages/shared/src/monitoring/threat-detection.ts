import { SecurityEvent, SecurityEventType, SecuritySeverity } from '../security/siem';
import { ThreatIndicator, SecurityPattern } from './types';
import { Redis } from 'ioredis';
import { logger } from '../utils/logger';
import { prisma } from '../database/prisma';

export class ThreatDetectionEngine {
  private redis: Redis;
  private patterns: Map<string, SecurityPattern> = new Map();
  private indicators: Map<string, ThreatIndicator> = new Map();
  private mlModel: MachineLearningModel;

  constructor(redis: Redis) {
    this.redis = redis;
    this.mlModel = new MachineLearningModel();
    this.loadPatterns();
    this.loadThreatIndicators();
  }

  async analyze(event: SecurityEvent): Promise<ThreatAnalysis> {
    const analysis: ThreatAnalysis = {
      event,
      threats: [],
      riskScore: 0,
      recommendations: []
    };

    // Pattern-based detection
    const patternMatches = await this.detectPatterns(event);
    analysis.threats.push(...patternMatches);

    // Indicator-based detection
    const indicatorMatches = await this.checkIndicators(event);
    analysis.threats.push(...indicatorMatches);

    // Behavioral analysis
    const behaviorAnalysis = await this.analyzeBehavior(event);
    analysis.threats.push(...behaviorAnalysis.threats);

    // Machine learning anomaly detection
    const mlAnalysis = await this.mlModel.analyze(event);
    if (mlAnalysis.isAnomaly) {
      analysis.threats.push({
        type: 'ml_anomaly',
        confidence: mlAnalysis.confidence,
        description: mlAnalysis.description,
        severity: this.calculateMLSeverity(mlAnalysis.confidence)
      });
    }

    // Calculate overall risk score
    analysis.riskScore = this.calculateRiskScore(analysis.threats);

    // Generate recommendations
    analysis.recommendations = this.generateRecommendations(analysis);

    return analysis;
  }

  private async detectPatterns(event: SecurityEvent): Promise<ThreatMatch[]> {
    const matches: ThreatMatch[] = [];

    for (const [id, pattern] of this.patterns) {
      if (!pattern.enabled) continue;

      const isMatch = await this.evaluatePattern(pattern, event);
      if (isMatch) {
        matches.push({
          type: 'pattern',
          patternId: pattern.id,
          confidence: 0.9,
          description: pattern.description,
          severity: pattern.severity
        });
      }
    }

    return matches;
  }

  private async evaluatePattern(pattern: SecurityPattern, event: SecurityEvent): boolean {
    switch (pattern.id) {
      case 'brute-force':
        return await this.detectBruteForce(event);
      case 'credential-stuffing':
        return await this.detectCredentialStuffing(event);
      case 'privilege-escalation':
        return await this.detectPrivilegeEscalation(event);
      case 'data-exfiltration':
        return await this.detectDataExfiltration(event);
      case 'lateral-movement':
        return await this.detectLateralMovement(event);
      case 'command-injection':
        return await this.detectCommandInjection(event);
      case 'sql-injection':
        return await this.detectSQLInjection(event);
      case 'xss-attack':
        return await this.detectXSSAttack(event);
      default:
        return false;
    }
  }

  private async detectBruteForce(event: SecurityEvent): Promise<boolean> {
    if (event.eventType !== SecurityEventType.LOGIN_FAILURE) return false;

    const key = `bf:${event.ipAddress || event.userId}`;
    const attempts = await this.redis.incr(key);
    await this.redis.expire(key, 300); // 5 minute window

    return attempts > 5;
  }

  private async detectCredentialStuffing(event: SecurityEvent): Promise<boolean> {
    if (event.eventType !== SecurityEventType.LOGIN_FAILURE) return false;

    // Check if same IP trying multiple different accounts
    const key = `cs:ip:${event.ipAddress}`;
    const users = await this.redis.sadd(key, event.userId || 'anonymous');
    await this.redis.expire(key, 600); // 10 minute window

    const uniqueUsers = await this.redis.scard(key);
    return uniqueUsers > 10;
  }

  private async detectPrivilegeEscalation(event: SecurityEvent): Promise<boolean> {
    if (event.eventType !== SecurityEventType.PRIVILEGE_ESCALATION &&
        event.eventType !== SecurityEventType.ROLE_CHANGE) return false;

    // Check for rapid role changes or unusual privilege requests
    const key = `pe:${event.userId}`;
    const changes = await this.redis.incr(key);
    await this.redis.expire(key, 3600); // 1 hour window

    return changes > 3;
  }

  private async detectDataExfiltration(event: SecurityEvent): Promise<boolean> {
    if (event.eventType !== SecurityEventType.DATA_EXPORT &&
        event.eventType !== SecurityEventType.BULK_OPERATION) return false;

    // Check for unusual data access patterns
    const key = `de:${event.userId}:${event.organizationId}`;
    const exports = await this.redis.incr(key);
    await this.redis.expire(key, 3600); // 1 hour window

    // Also check data volume if available
    const dataVolume = event.details?.dataVolume || 0;
    
    return exports > 10 || dataVolume > 1000000; // 1MB threshold
  }

  private async detectLateralMovement(event: SecurityEvent): Promise<boolean> {
    // Track access to different systems/services
    const key = `lm:${event.userId}`;
    const services = await this.redis.sadd(key, event.source);
    await this.redis.expire(key, 1800); // 30 minute window

    const uniqueServices = await this.redis.scard(key);
    return uniqueServices > 5;
  }

  private async detectCommandInjection(event: SecurityEvent): Promise<boolean> {
    const input = JSON.stringify(event.details);
    const commandPatterns = [
      /;\s*(ls|cat|rm|wget|curl|sh|bash|cmd|powershell)/i,
      /\|\s*(ls|cat|rm|wget|curl|sh|bash|cmd|powershell)/i,
      /`[^`]*`/,
      /\$\([^)]+\)/,
      /&&\s*(ls|cat|rm|wget|curl|sh|bash|cmd|powershell)/i
    ];

    return commandPatterns.some(pattern => pattern.test(input));
  }

  private async detectSQLInjection(event: SecurityEvent): Promise<boolean> {
    const input = JSON.stringify(event.details);
    const sqlPatterns = [
      /('\s*or\s*'1'\s*=\s*'1|"\s*or\s*"1"\s*=\s*"1)/i,
      /union\s+select/i,
      /drop\s+table/i,
      /insert\s+into/i,
      /update\s+\w+\s+set/i,
      /delete\s+from/i,
      /exec\s*\(/i,
      /xp_cmdshell/i,
      /;\s*--/
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  private async detectXSSAttack(event: SecurityEvent): Promise<boolean> {
    const input = JSON.stringify(event.details);
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe/gi,
      /<embed/gi,
      /<object/gi,
      /eval\s*\(/gi,
      /expression\s*\(/gi
    ];

    return xssPatterns.some(pattern => pattern.test(input));
  }

  private async checkIndicators(event: SecurityEvent): Promise<ThreatMatch[]> {
    const matches: ThreatMatch[] = [];

    // Check IP indicators
    if (event.ipAddress) {
      const ipIndicator = this.indicators.get(`ip:${event.ipAddress}`);
      if (ipIndicator) {
        matches.push({
          type: 'indicator',
          indicatorId: ipIndicator.id,
          confidence: ipIndicator.confidence,
          description: `Malicious IP detected: ${event.ipAddress}`,
          severity: 'high'
        });
      }
    }

    // Check user agent indicators
    if (event.userAgent) {
      const uaIndicator = this.indicators.get(`user-agent:${event.userAgent}`);
      if (uaIndicator) {
        matches.push({
          type: 'indicator',
          indicatorId: uaIndicator.id,
          confidence: uaIndicator.confidence,
          description: `Suspicious user agent detected`,
          severity: 'medium'
        });
      }
    }

    return matches;
  }

  private async analyzeBehavior(event: SecurityEvent): Promise<BehaviorAnalysis> {
    const analysis: BehaviorAnalysis = { threats: [] };

    // Time-based anomalies
    const isOddHour = await this.checkOddHourAccess(event);
    if (isOddHour) {
      analysis.threats.push({
        type: 'behavior',
        confidence: 0.7,
        description: 'Access at unusual hour',
        severity: 'medium'
      });
    }

    // Geographic anomalies
    const geoAnomaly = await this.checkGeographicAnomaly(event);
    if (geoAnomaly) {
      analysis.threats.push({
        type: 'behavior',
        confidence: 0.8,
        description: 'Access from unusual location',
        severity: 'high'
      });
    }

    // Velocity anomalies
    const velocityAnomaly = await this.checkVelocityAnomaly(event);
    if (velocityAnomaly) {
      analysis.threats.push({
        type: 'behavior',
        confidence: 0.9,
        description: 'Impossible travel detected',
        severity: 'critical'
      });
    }

    return analysis;
  }

  private async checkOddHourAccess(event: SecurityEvent): Promise<boolean> {
    const hour = event.timestamp.getHours();
    const dayOfWeek = event.timestamp.getDay();

    // Weekend or outside business hours (assuming 8 AM - 6 PM)
    return dayOfWeek === 0 || dayOfWeek === 6 || hour < 8 || hour > 18;
  }

  private async checkGeographicAnomaly(event: SecurityEvent): Promise<boolean> {
    if (!event.userId || !event.ipAddress) return false;

    // Get user's typical locations
    const key = `geo:${event.userId}`;
    const locations = await this.redis.smembers(key);

    // For demo, we'll check country from IP (would use GeoIP service)
    const currentCountry = await this.getCountryFromIP(event.ipAddress);
    
    if (locations.length > 0 && !locations.includes(currentCountry)) {
      return true;
    }

    // Store this location
    await this.redis.sadd(key, currentCountry);
    await this.redis.expire(key, 86400 * 30); // 30 days

    return false;
  }

  private async checkVelocityAnomaly(event: SecurityEvent): Promise<boolean> {
    if (!event.userId || !event.ipAddress) return false;

    const key = `velocity:${event.userId}`;
    const lastAccess = await this.redis.get(key);

    if (lastAccess) {
      const [lastIP, lastTime] = lastAccess.split(':');
      const timeDiff = event.timestamp.getTime() - parseInt(lastTime);
      
      // If different IP within 5 minutes (impossible travel)
      if (lastIP !== event.ipAddress && timeDiff < 300000) {
        return true;
      }
    }

    // Store current access
    await this.redis.set(key, `${event.ipAddress}:${event.timestamp.getTime()}`, 'EX', 3600);

    return false;
  }

  private async getCountryFromIP(ip: string): Promise<string> {
    // Simplified - would use actual GeoIP service
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
      return 'local';
    }
    return 'US'; // Default for demo
  }

  private calculateRiskScore(threats: ThreatMatch[]): number {
    if (threats.length === 0) return 0;

    const severityScores = {
      critical: 100,
      high: 75,
      medium: 50,
      low: 25
    };

    let totalScore = 0;
    let totalWeight = 0;

    for (const threat of threats) {
      const score = severityScores[threat.severity] || 0;
      const weight = threat.confidence;
      totalScore += score * weight;
      totalWeight += weight;
    }

    return Math.min(100, Math.round(totalScore / totalWeight));
  }

  private generateRecommendations(analysis: ThreatAnalysis): string[] {
    const recommendations: string[] = [];

    if (analysis.riskScore > 80) {
      recommendations.push('Immediately isolate affected systems');
      recommendations.push('Initiate incident response protocol');
      recommendations.push('Preserve evidence for forensic analysis');
    } else if (analysis.riskScore > 60) {
      recommendations.push('Monitor user activity closely');
      recommendations.push('Review access logs for anomalies');
      recommendations.push('Consider temporary access restrictions');
    } else if (analysis.riskScore > 40) {
      recommendations.push('Increase monitoring frequency');
      recommendations.push('Verify user identity through additional channels');
    }

    // Specific threat recommendations
    for (const threat of analysis.threats) {
      if (threat.type === 'pattern' && threat.patternId === 'brute-force') {
        recommendations.push('Enable account lockout after failed attempts');
        recommendations.push('Implement CAPTCHA for login forms');
      }
      if (threat.type === 'indicator') {
        recommendations.push('Block identified malicious IPs at firewall');
        recommendations.push('Update threat intelligence feeds');
      }
    }

    return [...new Set(recommendations)]; // Remove duplicates
  }

  private calculateMLSeverity(confidence: number): 'critical' | 'high' | 'medium' | 'low' {
    if (confidence > 0.9) return 'critical';
    if (confidence > 0.7) return 'high';
    if (confidence > 0.5) return 'medium';
    return 'low';
  }

  private async loadPatterns(): Promise<void> {
    const defaultPatterns: SecurityPattern[] = [
      {
        id: 'brute-force',
        name: 'Brute Force Attack',
        description: 'Multiple failed login attempts from same source',
        pattern: 'login_failure_count > 5 within 5m',
        severity: 'high',
        category: 'authentication',
        enabled: true,
        actions: ['block_ip', 'alert_security']
      },
      {
        id: 'credential-stuffing',
        name: 'Credential Stuffing',
        description: 'Same IP trying multiple different accounts',
        pattern: 'unique_users > 10 from same_ip within 10m',
        severity: 'critical',
        category: 'authentication',
        enabled: true,
        actions: ['block_ip', 'alert_security', 'notify_users']
      },
      {
        id: 'privilege-escalation',
        name: 'Privilege Escalation',
        description: 'Rapid role changes or privilege requests',
        pattern: 'role_changes > 3 within 1h',
        severity: 'critical',
        category: 'authorization',
        enabled: true,
        actions: ['suspend_user', 'alert_security']
      },
      {
        id: 'data-exfiltration',
        name: 'Data Exfiltration',
        description: 'Unusual data export patterns',
        pattern: 'exports > 10 or volume > 1MB within 1h',
        severity: 'critical',
        category: 'data-access',
        enabled: true,
        actions: ['block_exports', 'alert_security']
      },
      {
        id: 'lateral-movement',
        name: 'Lateral Movement',
        description: 'Access to multiple systems in short time',
        pattern: 'unique_services > 5 within 30m',
        severity: 'high',
        category: 'network',
        enabled: true,
        actions: ['monitor_closely', 'alert_security']
      }
    ];

    for (const pattern of defaultPatterns) {
      this.patterns.set(pattern.id, pattern);
    }
  }

  private async loadThreatIndicators(): Promise<void> {
    // Load from threat intelligence feeds
    try {
      const indicators = await prisma.$queryRaw<ThreatIndicator[]>`
        SELECT * FROM threat_indicators WHERE confidence > 0.7
      `;
      
      for (const indicator of indicators) {
        this.indicators.set(`${indicator.type}:${indicator.value}`, indicator);
      }
    } catch (error) {
      logger.error('Failed to load threat indicators', { error });
    }
  }
}

// Machine Learning Model for anomaly detection
class MachineLearningModel {
  private threshold = 0.85;

  async analyze(event: SecurityEvent): Promise<MLAnalysis> {
    // Simplified ML model - would use actual TensorFlow.js or similar
    const features = this.extractFeatures(event);
    const anomalyScore = this.calculateAnomalyScore(features);

    return {
      isAnomaly: anomalyScore > this.threshold,
      confidence: anomalyScore,
      description: this.describeAnomaly(features, anomalyScore)
    };
  }

  private extractFeatures(event: SecurityEvent): number[] {
    // Extract numerical features for ML model
    return [
      event.timestamp.getHours(),
      event.timestamp.getDay(),
      this.encodeEventType(event.eventType),
      this.encodeSeverity(event.severity),
      event.ipAddress ? 1 : 0,
      event.userId ? 1 : 0,
      Object.keys(event.details).length
    ];
  }

  private calculateAnomalyScore(features: number[]): number {
    // Simplified anomaly calculation
    const weights = [0.1, 0.1, 0.3, 0.2, 0.1, 0.1, 0.1];
    let score = 0;

    for (let i = 0; i < features.length; i++) {
      score += features[i] * weights[i];
    }

    // Add some randomness for demo
    return Math.min(1, score + Math.random() * 0.2);
  }

  private encodeEventType(type: SecurityEventType): number {
    const typeMap: Record<string, number> = {
      [SecurityEventType.LOGIN_SUCCESS]: 0.1,
      [SecurityEventType.LOGIN_FAILURE]: 0.8,
      [SecurityEventType.PRIVILEGE_ESCALATION]: 0.9,
      [SecurityEventType.SQL_INJECTION_ATTEMPT]: 0.95
    };
    return typeMap[type] || 0.5;
  }

  private encodeSeverity(severity: SecuritySeverity): number {
    const severityMap: Record<string, number> = {
      [SecuritySeverity.CRITICAL]: 1.0,
      [SecuritySeverity.HIGH]: 0.8,
      [SecuritySeverity.MEDIUM]: 0.5,
      [SecuritySeverity.LOW]: 0.3,
      [SecuritySeverity.INFO]: 0.1
    };
    return severityMap[severity] || 0.5;
  }

  private describeAnomaly(features: number[], score: number): string {
    if (score > 0.95) {
      return 'Highly unusual activity pattern detected';
    } else if (score > 0.9) {
      return 'Suspicious activity pattern detected';
    } else if (score > 0.85) {
      return 'Potentially anomalous behavior detected';
    }
    return 'Minor deviation from normal patterns';
  }
}

// Types
interface ThreatAnalysis {
  event: SecurityEvent;
  threats: ThreatMatch[];
  riskScore: number;
  recommendations: string[];
}

interface ThreatMatch {
  type: 'pattern' | 'indicator' | 'behavior' | 'ml_anomaly';
  patternId?: string;
  indicatorId?: string;
  confidence: number;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface BehaviorAnalysis {
  threats: ThreatMatch[];
}

interface MLAnalysis {
  isAnomaly: boolean;
  confidence: number;
  description: string;
}

export { ThreatDetectionEngine, ThreatAnalysis, ThreatMatch };