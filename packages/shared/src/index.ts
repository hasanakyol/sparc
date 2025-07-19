// Main entry point for the SPARC shared package
// Exports all common utilities, types, and configurations

// Export all types and schemas
export * from './types';

// Export all utility functions
export * from './utils';

// Export configuration management
export * from './config';

// Export middleware
export * from './middleware';

// Export specific config and logger instances for direct import
export { config } from './config';
export { logger } from './utils';

// Export platform constants
export * from './constants';

// Export database utilities
export * from './database/prisma';
export { prisma, getPrismaClient, checkDatabaseHealth, withRetry, getPoolStats } from './database/prisma';

// Export services
export * from './services/email';
export { emailService, sendVerificationEmail, sendPasswordResetEmail, sendMFASetupEmail, sendLoginAlertEmail } from './services/email';

// Export OpenAPI utilities
export * from './openapi';

// Export telemetry utilities
export * from './telemetry';
export { telemetry, telemetryMiddleware, extractTraceContext, injectTraceContext } from './telemetry';

// Export cache utilities
export * from './cache';
export { CacheManager, createCacheManager, getDefaultCacheManager } from './cache';

// Export WebSocket utilities
export * from './websocket';
export { 
  UnifiedWebSocketService,
  WebSocketClient,
  VideoWebSocketClient,
  AlertWebSocketClient,
  MonitoringWebSocketClient,
  ConnectionState
} from './websocket';

// Export Event Bus utilities
export * from './events';
export { 
  EventBus,
  TypedEventBus,
  createSparcEventBus,
  DomainEvent,
  EventHandler,
  SparcDomainEvents,
  BaseEventHandler,
  BatchEventHandler,
  AggregatorEventHandler,
  EventBusMetrics,
  EventFlowTracer,
  EventDebugger
} from './events';

// Re-export commonly used external dependencies for convenience
export { z } from 'zod';
export type { ZodSchema, ZodType } from 'zod';
export { v4 as uuidv4, v1 as uuidv1 } from 'uuid';
export { format as formatDate, parseISO, isValid as isValidDate } from 'date-fns';
export { pick, omit, merge, cloneDeep } from 'lodash';
