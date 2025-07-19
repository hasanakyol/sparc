import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-grpc';
import { BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor } from '@opentelemetry/sdk-trace-node';
import { CompositePropagator, W3CTraceContextPropagator, W3CBaggagePropagator } from '@opentelemetry/core';
import { JaegerPropagator } from '@opentelemetry/propagator-jaeger';
import { B3Propagator, B3InjectEncoding } from '@opentelemetry/propagator-b3';
import { registerInstrumentations } from '@opentelemetry/instrumentation';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { ExpressInstrumentation } from '@opentelemetry/instrumentation-express';
import { HonoInstrumentation } from '@opentelemetry/instrumentation-hono';
import { GrpcInstrumentation } from '@opentelemetry/instrumentation-grpc';
import { RedisInstrumentation } from '@opentelemetry/instrumentation-redis-4';
import { IORedisInstrumentation } from '@opentelemetry/instrumentation-ioredis';
import { PrismaInstrumentation } from '@opentelemetry/instrumentation-prisma';
import { Span, SpanStatusCode, trace, context, SpanKind } from '@opentelemetry/api';
import { AsyncHooksContextManager } from '@opentelemetry/context-async-hooks';
import { AlwaysOnSampler, ParentBasedSampler, TraceIdRatioBasedSampler } from '@opentelemetry/sdk-trace-base';

export interface TelemetryConfig {
  serviceName: string;
  serviceVersion?: string;
  environment?: string;
  jaegerEndpoint?: string;
  samplingRatio?: number;
  enableConsoleExporter?: boolean;
  enableAutoInstrumentation?: boolean;
  customAttributes?: Record<string, string>;
}

class TelemetryService {
  private sdk: NodeSDK | null = null;
  private isInitialized = false;

  /**
   * Initialize OpenTelemetry with the given configuration
   */
  async initialize(config: TelemetryConfig): Promise<void> {
    if (this.isInitialized) {
      console.warn('Telemetry already initialized');
      return;
    }

    const {
      serviceName,
      serviceVersion = '1.0.0',
      environment = process.env.NODE_ENV || 'development',
      jaegerEndpoint = process.env.OTEL_EXPORTER_JAEGER_ENDPOINT || 'http://jaeger-collector:4317',
      samplingRatio = environment === 'production' ? 0.1 : 1.0,
      enableConsoleExporter = environment !== 'production',
      enableAutoInstrumentation = true,
      customAttributes = {}
    } = config;

    // Create resource with service information
    const resource = new Resource({
      [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
      [SemanticResourceAttributes.SERVICE_VERSION]: serviceVersion,
      [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: environment,
      [SemanticResourceAttributes.SERVICE_NAMESPACE]: 'sparc',
      ...customAttributes
    });

    // Configure trace exporter
    const traceExporter = new OTLPTraceExporter({
      url: jaegerEndpoint,
      headers: {
        'x-service-name': serviceName
      }
    });

    // Configure span processors
    const spanProcessors = [
      new BatchSpanProcessor(traceExporter, {
        maxQueueSize: 2048,
        maxExportBatchSize: 512,
        scheduledDelayMillis: 5000,
        exportTimeoutMillis: 30000
      })
    ];

    if (enableConsoleExporter) {
      spanProcessors.push(new SimpleSpanProcessor(new ConsoleSpanExporter()));
    }

    // Configure sampler
    const sampler = new ParentBasedSampler({
      root: new TraceIdRatioBasedSampler(samplingRatio),
      remoteParentSampled: new AlwaysOnSampler(),
      remoteParentNotSampled: new AlwaysOnSampler()
    });

    // Configure propagators for distributed tracing
    const propagator = new CompositePropagator({
      propagators: [
        new W3CTraceContextPropagator(),
        new W3CBaggagePropagator(),
        new JaegerPropagator(),
        new B3Propagator({ injectEncoding: B3InjectEncoding.MULTI_HEADER })
      ]
    });

    // Configure instrumentations
    const instrumentations = [];

    if (enableAutoInstrumentation) {
      instrumentations.push(...getNodeAutoInstrumentations({
        '@opentelemetry/instrumentation-fs': {
          enabled: false // Disable fs instrumentation to reduce noise
        }
      }));
    } else {
      // Manual instrumentation configuration
      instrumentations.push(
        new HttpInstrumentation({
          requestHook: (span, request) => {
            span.setAttribute('http.request.body.size', request.headers['content-length'] || 0);
          },
          responseHook: (span, response) => {
            span.setAttribute('http.response.body.size', response.headers['content-length'] || 0);
          }
        }),
        new ExpressInstrumentation({
          requestHook: (span, info) => {
            span.setAttribute('express.route', info.route);
          }
        }),
        new HonoInstrumentation(),
        new GrpcInstrumentation(),
        new RedisInstrumentation(),
        new IORedisInstrumentation(),
        new PrismaInstrumentation()
      );
    }

    // Create and configure SDK
    this.sdk = new NodeSDK({
      resource,
      traceExporter,
      spanProcessors,
      sampler,
      instrumentations,
      textMapPropagator: propagator,
      contextManager: new AsyncHooksContextManager()
    });

    // Initialize the SDK
    await this.sdk.start();
    this.isInitialized = true;

    console.log(`OpenTelemetry initialized for service: ${serviceName}`);
  }

  /**
   * Shutdown telemetry gracefully
   */
  async shutdown(): Promise<void> {
    if (this.sdk) {
      await this.sdk.shutdown();
      this.isInitialized = false;
      console.log('OpenTelemetry shutdown complete');
    }
  }

  /**
   * Get the active tracer
   */
  getTracer(name?: string): any {
    return trace.getTracer(name || 'sparc-tracer');
  }

  /**
   * Create a custom span for business operations
   */
  startSpan(
    name: string,
    options?: {
      kind?: SpanKind;
      attributes?: Record<string, any>;
      parent?: Span;
    }
  ): Span {
    const tracer = this.getTracer();
    const span = tracer.startSpan(name, {
      kind: options?.kind || SpanKind.INTERNAL,
      attributes: options?.attributes
    });

    if (options?.parent) {
      const ctx = trace.setSpan(context.active(), options.parent);
      return trace.setSpan(ctx, span) as unknown as Span;
    }

    return span;
  }

  /**
   * Wrap an async function with a span
   */
  async withSpan<T>(
    name: string,
    fn: (span: Span) => Promise<T>,
    options?: {
      kind?: SpanKind;
      attributes?: Record<string, any>;
    }
  ): Promise<T> {
    const span = this.startSpan(name, options);
    
    try {
      const result = await fn(span);
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : 'Unknown error'
      });
      span.recordException(error as Error);
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Add custom attributes to the current span
   */
  addSpanAttributes(attributes: Record<string, any>): void {
    const span = trace.getActiveSpan();
    if (span) {
      Object.entries(attributes).forEach(([key, value]) => {
        span.setAttribute(key, value);
      });
    }
  }

  /**
   * Record an exception in the current span
   */
  recordException(error: Error, attributes?: Record<string, any>): void {
    const span = trace.getActiveSpan();
    if (span) {
      span.recordException(error, attributes);
    }
  }

  /**
   * Set the status of the current span
   */
  setSpanStatus(code: SpanStatusCode, message?: string): void {
    const span = trace.getActiveSpan();
    if (span) {
      span.setStatus({ code, message });
    }
  }

  /**
   * Get the current trace ID
   */
  getCurrentTraceId(): string | undefined {
    const span = trace.getActiveSpan();
    return span?.spanContext().traceId;
  }

  /**
   * Get the current span ID
   */
  getCurrentSpanId(): string | undefined {
    const span = trace.getActiveSpan();
    return span?.spanContext().spanId;
  }
}

// Export singleton instance
export const telemetry = new TelemetryService();

// Export types and utilities
export {
  Span,
  SpanKind,
  SpanStatusCode,
  trace,
  context
};

// Helper middleware for Hono applications
export const telemetryMiddleware = () => {
  return async (c: any, next: any) => {
    const method = c.req.method;
    const path = c.req.path;
    const spanName = `${method} ${path}`;

    await telemetry.withSpan(
      spanName,
      async (span) => {
        // Add request attributes
        span.setAttributes({
          'http.method': method,
          'http.target': path,
          'http.host': c.req.header('host'),
          'http.scheme': c.req.url.split('://')[0],
          'http.user_agent': c.req.header('user-agent'),
          'tenant.id': c.get('tenantId'),
          'user.id': c.get('userId')
        });

        // Continue with the request
        await next();

        // Add response attributes
        span.setAttributes({
          'http.status_code': c.res.status,
          'http.response.content_length': c.res.headers.get('content-length') || 0
        });

        // Set span status based on HTTP status
        if (c.res.status >= 400) {
          span.setStatus({
            code: SpanStatusCode.ERROR,
            message: `HTTP ${c.res.status}`
          });
        }
      },
      {
        kind: SpanKind.SERVER,
        attributes: {
          'component': 'hono',
          'service.name': process.env.SERVICE_NAME || 'unknown'
        }
      }
    );
  };
};

// Utility function to extract trace context from headers
export function extractTraceContext(headers: Record<string, string>): any {
  const propagator = new CompositePropagator({
    propagators: [
      new W3CTraceContextPropagator(),
      new JaegerPropagator(),
      new B3Propagator()
    ]
  });

  return propagator.extract(context.active(), headers, {
    get(carrier, key) {
      return carrier[key.toLowerCase()];
    },
    keys(carrier) {
      return Object.keys(carrier);
    }
  });
}

// Utility function to inject trace context into headers
export function injectTraceContext(headers: Record<string, string> = {}): Record<string, string> {
  const propagator = new CompositePropagator({
    propagators: [
      new W3CTraceContextPropagator(),
      new JaegerPropagator(),
      new B3Propagator()
    ]
  });

  propagator.inject(context.active(), headers, {
    set(carrier, key, value) {
      carrier[key] = value;
    }
  });

  return headers;
}