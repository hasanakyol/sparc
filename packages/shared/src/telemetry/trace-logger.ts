import winston from 'winston';
import { trace } from '@opentelemetry/api';
import { telemetry } from './index';

/**
 * Enhanced logger that automatically includes trace context
 */
export class TraceLogger {
  private logger: winston.Logger;

  constructor(serviceName: string, options?: winston.LoggerOptions) {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.printf((info) => {
          // Add trace context to every log
          const traceId = telemetry.getCurrentTraceId();
          const spanId = telemetry.getCurrentSpanId();
          
          const logEntry = {
            timestamp: info.timestamp,
            level: info.level,
            service: serviceName,
            message: info.message,
            ...info,
            trace: {
              traceId,
              spanId
            }
          };

          // Remove duplicate fields
          delete logEntry.timestamp;
          delete logEntry.level;
          delete logEntry.message;

          return JSON.stringify(logEntry);
        })
      ),
      defaultMeta: { service: serviceName },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        })
      ],
      ...options
    });
  }

  /**
   * Log with automatic trace context
   */
  private logWithContext(level: string, message: string, meta?: any): void {
    const span = trace.getActiveSpan();
    if (span) {
      // Add log event to span
      span.addEvent(`log.${level}`, {
        'log.message': message,
        'log.severity': level,
        ...meta
      });
    }

    this.logger[level](message, meta);
  }

  /**
   * Log methods with trace context
   */
  error(message: string, error?: Error | any): void {
    if (error instanceof Error) {
      telemetry.recordException(error);
      this.logWithContext('error', message, {
        error: {
          message: error.message,
          stack: error.stack,
          name: error.name
        }
      });
    } else {
      this.logWithContext('error', message, error);
    }
  }

  warn(message: string, meta?: any): void {
    this.logWithContext('warn', message, meta);
  }

  info(message: string, meta?: any): void {
    this.logWithContext('info', message, meta);
  }

  debug(message: string, meta?: any): void {
    this.logWithContext('debug', message, meta);
  }

  verbose(message: string, meta?: any): void {
    this.logWithContext('verbose', message, meta);
  }

  /**
   * Create a child logger with additional metadata
   */
  child(meta: any): TraceLogger {
    const childLogger = new TraceLogger(this.logger.defaultMeta.service, {
      defaultMeta: { ...this.logger.defaultMeta, ...meta }
    });
    return childLogger;
  }

  /**
   * Log performance metrics
   */
  logPerformance(operation: string, duration: number, meta?: any): void {
    const span = trace.getActiveSpan();
    if (span) {
      span.setAttribute(`performance.${operation}.duration`, duration);
    }

    this.info(`Performance: ${operation}`, {
      operation,
      duration,
      unit: 'ms',
      ...meta
    });
  }

  /**
   * Log API request
   */
  logRequest(req: any, meta?: any): void {
    this.info('API Request', {
      method: req.method,
      path: req.path || req.url,
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.headers?.['user-agent'],
      ...meta
    });
  }

  /**
   * Log API response
   */
  logResponse(req: any, res: any, duration: number, meta?: any): void {
    const level = res.statusCode >= 400 ? 'warn' : 'info';
    this.logWithContext(level, 'API Response', {
      method: req.method,
      path: req.path || req.url,
      statusCode: res.statusCode,
      duration,
      unit: 'ms',
      ...meta
    });
  }

  /**
   * Log database query
   */
  logQuery(query: string, params?: any[], duration?: number): void {
    this.debug('Database Query', {
      query: query.substring(0, 1000), // Truncate long queries
      params: params?.slice(0, 10), // Limit params for security
      duration,
      unit: duration ? 'ms' : undefined
    });
  }

  /**
   * Log cache operation
   */
  logCache(operation: 'hit' | 'miss' | 'set' | 'delete', key: string, meta?: any): void {
    this.debug(`Cache ${operation}`, {
      operation,
      key,
      ...meta
    });
  }

  /**
   * Log security event
   */
  logSecurity(event: string, severity: 'low' | 'medium' | 'high' | 'critical', meta?: any): void {
    const level = severity === 'critical' || severity === 'high' ? 'error' : 'warn';
    
    const span = trace.getActiveSpan();
    if (span) {
      span.setAttribute('security.event', event);
      span.setAttribute('security.severity', severity);
    }

    this.logWithContext(level, `Security Event: ${event}`, {
      security: true,
      event,
      severity,
      ...meta
    });
  }

  /**
   * Get the underlying Winston logger
   */
  getLogger(): winston.Logger {
    return this.logger;
  }
}

/**
 * Factory function to create a trace-enabled logger
 */
export function createTraceLogger(serviceName: string, options?: winston.LoggerOptions): TraceLogger {
  return new TraceLogger(serviceName, options);
}