import { pino } from 'pino';

// Create logger instance
export const logger = pino({
  name: 'sparc-cache',
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'development' ? {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'HH:MM:ss Z',
      ignore: 'pid,hostname',
    },
  } : undefined,
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ['password', 'secret', 'token', 'apiKey', 'authorization'],
    censor: '[REDACTED]',
  },
});

// Export logger methods for convenience
export const logInfo = logger.info.bind(logger);
export const logError = logger.error.bind(logger);
export const logWarn = logger.warn.bind(logger);
export const logDebug = logger.debug.bind(logger);
export const logTrace = logger.trace.bind(logger);
export const logFatal = logger.fatal.bind(logger);

// Create child logger for specific modules
export function createLogger(module: string) {
  return logger.child({ module });
}