import { context, trace } from '@opentelemetry/api';
import { telemetry, injectTraceContext } from './index';

/**
 * Correlation context for distributed tracing
 */
export interface CorrelationContext {
  traceId: string;
  spanId: string;
  traceFlags: string;
  serviceName: string;
  userId?: string;
  tenantId?: string;
  requestId?: string;
  sessionId?: string;
}

/**
 * Get current correlation context
 */
export function getCorrelationContext(): CorrelationContext | null {
  const span = trace.getActiveSpan();
  if (!span) {
    return null;
  }

  const spanContext = span.spanContext();
  const attributes = (span as any).attributes || {};

  return {
    traceId: spanContext.traceId,
    spanId: spanContext.spanId,
    traceFlags: spanContext.traceFlags.toString(16).padStart(2, '0'),
    serviceName: process.env.SERVICE_NAME || 'unknown',
    userId: attributes['user.id'],
    tenantId: attributes['tenant.id'],
    requestId: attributes['request.id'],
    sessionId: attributes['session.id']
  };
}

/**
 * Error with trace context
 */
export class TracedError extends Error {
  public readonly traceId?: string;
  public readonly spanId?: string;
  public readonly correlationContext?: CorrelationContext;
  public readonly timestamp: Date;
  public readonly service: string;

  constructor(message: string, public readonly code?: string, public readonly details?: any) {
    super(message);
    this.name = 'TracedError';
    this.timestamp = new Date();
    this.service = process.env.SERVICE_NAME || 'unknown';

    const context = getCorrelationContext();
    if (context) {
      this.correlationContext = context;
      this.traceId = context.traceId;
      this.spanId = context.spanId;
    }

    // Capture stack trace
    Error.captureStackTrace(this, TracedError);
  }

  /**
   * Convert to JSON for logging
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      details: this.details,
      timestamp: this.timestamp.toISOString(),
      service: this.service,
      trace: {
        traceId: this.traceId,
        spanId: this.spanId
      },
      correlation: this.correlationContext,
      stack: this.stack
    };
  }

  /**
   * Create from a regular error
   */
  static from(error: Error | any, code?: string): TracedError {
    if (error instanceof TracedError) {
      return error;
    }

    const tracedError = new TracedError(
      error.message || 'Unknown error',
      code || error.code,
      error.details || { originalError: error.name }
    );

    // Preserve original stack if available
    if (error.stack) {
      tracedError.stack = error.stack;
    }

    return tracedError;
  }
}

/**
 * Async context storage for correlation data
 */
export class CorrelationContextManager {
  private static contextKey = Symbol('correlation-context');

  /**
   * Set correlation context
   */
  static setContext(correlationData: Partial<CorrelationContext>): void {
    const currentContext = context.active();
    const newContext = currentContext.setValue(
      CorrelationContextManager.contextKey,
      correlationData
    );
    context.setGlobalContextManager(newContext as any);
  }

  /**
   * Get correlation context
   */
  static getContext(): Partial<CorrelationContext> | undefined {
    return context.active().getValue(CorrelationContextManager.contextKey) as any;
  }

  /**
   * Run function with correlation context
   */
  static runWithContext<T>(
    correlationData: Partial<CorrelationContext>,
    fn: () => T
  ): T {
    const currentContext = context.active();
    const newContext = currentContext.setValue(
      CorrelationContextManager.contextKey,
      correlationData
    );
    return context.with(newContext, fn);
  }
}

/**
 * Middleware to extract and propagate correlation IDs
 */
export function correlationMiddleware() {
  return async (c: any, next: any) => {
    // Extract correlation IDs from headers
    const correlationId = c.req.header('x-correlation-id') || 
                         c.req.header('x-request-id') || 
                         `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const sessionId = c.req.header('x-session-id');
    const userId = c.get('userId');
    const tenantId = c.get('tenantId');

    // Set correlation context
    CorrelationContextManager.setContext({
      requestId: correlationId,
      sessionId,
      userId,
      tenantId,
      serviceName: process.env.SERVICE_NAME || 'unknown'
    });

    // Add to span attributes
    telemetry.addSpanAttributes({
      'correlation.id': correlationId,
      'session.id': sessionId
    });

    // Set correlation ID in context for downstream use
    c.set('correlationId', correlationId);
    c.set('sessionId', sessionId);

    await next();

    // Add correlation ID to response headers
    c.header('x-correlation-id', correlationId);
    if (telemetry.getCurrentTraceId()) {
      c.header('x-trace-id', telemetry.getCurrentTraceId());
    }
  };
}

/**
 * Format log entry with correlation context
 */
export function formatLogWithContext(level: string, message: string, data?: any): any {
  const correlation = getCorrelationContext();
  
  return {
    timestamp: new Date().toISOString(),
    level,
    message,
    service: process.env.SERVICE_NAME || 'unknown',
    correlation: correlation ? {
      traceId: correlation.traceId,
      spanId: correlation.spanId,
      requestId: correlation.requestId,
      userId: correlation.userId,
      tenantId: correlation.tenantId,
      sessionId: correlation.sessionId
    } : undefined,
    data
  };
}

/**
 * Create a correlated fetch client
 */
export function createCorrelatedFetch() {
  return async (url: string, options: RequestInit = {}): Promise<Response> => {
    const correlation = getCorrelationContext();
    
    const headers = {
      ...options.headers,
      'x-correlation-id': correlation?.requestId || 'unknown',
      'x-session-id': correlation?.sessionId || '',
      ...injectTraceContext()
    };

    return fetch(url, {
      ...options,
      headers
    });
  };
}

/**
 * Extract trace context from error for reporting
 */
export function extractErrorContext(error: Error | any): any {
  const correlation = getCorrelationContext();
  
  return {
    error: {
      name: error.name || 'Error',
      message: error.message || 'Unknown error',
      code: error.code,
      stack: error.stack
    },
    trace: correlation ? {
      traceId: correlation.traceId,
      spanId: correlation.spanId,
      service: correlation.serviceName
    } : undefined,
    correlation: correlation ? {
      requestId: correlation.requestId,
      userId: correlation.userId,
      tenantId: correlation.tenantId,
      sessionId: correlation.sessionId
    } : undefined,
    timestamp: new Date().toISOString()
  };
}