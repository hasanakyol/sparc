import winston from 'winston';
import { context, trace } from '@opentelemetry/api';

const { combine, timestamp, printf, colorize, errors } = winston.format;

// Custom format for logs
const logFormat = printf(({ level, message, timestamp, ...metadata }) => {
  // Get trace context if available
  const span = trace.getActiveSpan();
  const traceId = span?.spanContext().traceId;
  const spanId = span?.spanContext().spanId;
  
  let log = `${timestamp} [${level}]: ${message}`;
  
  if (traceId) {
    log += ` [trace_id=${traceId}]`;
  }
  if (spanId) {
    log += ` [span_id=${spanId}]`;
  }
  
  if (Object.keys(metadata).length > 0) {
    log += ` ${JSON.stringify(metadata)}`;
  }
  
  return log;
});

// Create logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    errors({ stack: true }),
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    logFormat
  ),
  defaultMeta: { service: 'reporting-service' },
  transports: [
    // Console transport
    new winston.transports.Console({
      format: combine(
        colorize(),
        logFormat
      )
    })
  ]
});

// Add file transport in production
if (process.env.NODE_ENV === 'production') {
  logger.add(new winston.transports.File({
    filename: 'logs/error.log',
    level: 'error',
    maxsize: 10485760, // 10MB
    maxFiles: 5
  }));
  
  logger.add(new winston.transports.File({
    filename: 'logs/combined.log',
    maxsize: 10485760, // 10MB
    maxFiles: 10
  }));
}

// Create child logger with additional context
export function createLogger(component: string): winston.Logger {
  return logger.child({ component });
}