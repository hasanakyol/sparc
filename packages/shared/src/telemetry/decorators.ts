import { SpanKind, SpanStatusCode } from '@opentelemetry/api';
import { telemetry } from './index';

/**
 * Decorator to automatically create spans for methods
 */
export function Trace(options?: {
  name?: string;
  kind?: SpanKind;
  attributes?: Record<string, any>;
}) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const spanName = options?.name || `${target.constructor.name}.${propertyKey}`;
      
      return telemetry.withSpan(
        spanName,
        async (span) => {
          // Add method metadata
          span.setAttributes({
            'code.function': propertyKey,
            'code.class': target.constructor.name,
            ...options?.attributes
          });

          // Add argument information (be careful with sensitive data)
          args.forEach((arg, index) => {
            if (typeof arg === 'string' || typeof arg === 'number' || typeof arg === 'boolean') {
              span.setAttribute(`argument.${index}`, arg);
            } else if (arg && typeof arg === 'object') {
              span.setAttribute(`argument.${index}.type`, arg.constructor.name);
            }
          });

          const result = await originalMethod.apply(this, args);
          
          // Add result information
          if (result !== undefined) {
            if (typeof result === 'string' || typeof result === 'number' || typeof result === 'boolean') {
              span.setAttribute('result', result);
            } else if (result && typeof result === 'object') {
              span.setAttribute('result.type', result.constructor.name);
              if (Array.isArray(result)) {
                span.setAttribute('result.length', result.length);
              }
            }
          }

          return result;
        },
        {
          kind: options?.kind || SpanKind.INTERNAL
        }
      );
    };

    return descriptor;
  };
}

/**
 * Decorator for database operations
 */
export function TraceDB(operation: string, table?: string) {
  return Trace({
    name: `db.${operation}`,
    kind: SpanKind.CLIENT,
    attributes: {
      'db.operation': operation,
      'db.table': table,
      'db.system': 'postgresql'
    }
  });
}

/**
 * Decorator for API endpoints
 */
export function TraceAPI(method: string, path: string) {
  return Trace({
    name: `${method} ${path}`,
    kind: SpanKind.SERVER,
    attributes: {
      'http.method': method,
      'http.route': path
    }
  });
}

/**
 * Decorator for external service calls
 */
export function TraceService(serviceName: string, operation: string) {
  return Trace({
    name: `${serviceName}.${operation}`,
    kind: SpanKind.CLIENT,
    attributes: {
      'peer.service': serviceName,
      'service.operation': operation
    }
  });
}

/**
 * Decorator for cache operations
 */
export function TraceCache(operation: 'get' | 'set' | 'delete', key?: string) {
  return Trace({
    name: `cache.${operation}`,
    kind: SpanKind.CLIENT,
    attributes: {
      'cache.operation': operation,
      'cache.key': key,
      'cache.system': 'redis'
    }
  });
}

/**
 * Decorator for message queue operations
 */
export function TraceQueue(operation: 'publish' | 'consume', queue: string) {
  return Trace({
    name: `queue.${operation}`,
    kind: operation === 'publish' ? SpanKind.PRODUCER : SpanKind.CONSUMER,
    attributes: {
      'messaging.operation': operation,
      'messaging.destination': queue,
      'messaging.system': 'rabbitmq'
    }
  });
}

/**
 * Decorator for business logic operations
 */
export function TraceBusiness(domain: string, operation: string) {
  return Trace({
    name: `business.${domain}.${operation}`,
    kind: SpanKind.INTERNAL,
    attributes: {
      'business.domain': domain,
      'business.operation': operation
    }
  });
}

/**
 * Decorator for security operations
 */
export function TraceSecurity(operation: string) {
  return Trace({
    name: `security.${operation}`,
    kind: SpanKind.INTERNAL,
    attributes: {
      'security.operation': operation
    }
  });
}

/**
 * Decorator for video processing operations
 */
export function TraceVideo(operation: string, format?: string) {
  return Trace({
    name: `video.${operation}`,
    kind: SpanKind.INTERNAL,
    attributes: {
      'video.operation': operation,
      'video.format': format
    }
  });
}

/**
 * Decorator for analytics operations
 */
export function TraceAnalytics(analysisType: string) {
  return Trace({
    name: `analytics.${analysisType}`,
    kind: SpanKind.INTERNAL,
    attributes: {
      'analytics.type': analysisType
    }
  });
}

/**
 * Decorator for access control operations
 */
export function TraceAccess(operation: string, resourceType?: string) {
  return Trace({
    name: `access.${operation}`,
    kind: SpanKind.INTERNAL,
    attributes: {
      'access.operation': operation,
      'access.resource_type': resourceType
    }
  });
}

/**
 * Method decorator for performance tracking
 */
export function MeasurePerformance(thresholdMs?: number) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const startTime = Date.now();
      
      try {
        const result = await originalMethod.apply(this, args);
        const duration = Date.now() - startTime;

        telemetry.addSpanAttributes({
          [`performance.${propertyKey}.duration`]: duration,
          [`performance.${propertyKey}.threshold_exceeded`]: thresholdMs ? duration > thresholdMs : false
        });

        if (thresholdMs && duration > thresholdMs) {
          telemetry.addSpanAttributes({
            [`performance.${propertyKey}.slow`]: true
          });
        }

        return result;
      } catch (error) {
        const duration = Date.now() - startTime;
        telemetry.addSpanAttributes({
          [`performance.${propertyKey}.duration`]: duration,
          [`performance.${propertyKey}.failed`]: true
        });
        throw error;
      }
    };

    return descriptor;
  };
}