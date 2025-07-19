import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { trace, Tracer } from '@opentelemetry/api';
import { ReportingServiceConfig } from '../config';

let sdk: NodeSDK | null = null;

export function setupOpenTelemetry(config: ReportingServiceConfig): void {
  if (!config.otel.enabled) {
    return;
  }

  const resource = new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: config.otel.serviceName,
    [SemanticResourceAttributes.SERVICE_VERSION]: config.version,
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: process.env.NODE_ENV || 'development'
  });

  // Create trace exporter
  const traceExporter = new OTLPTraceExporter({
    url: `${config.otel.endpoint}/v1/traces`,
    headers: {}
  });

  // Create metric exporter
  const metricExporter = new OTLPMetricExporter({
    url: `${config.otel.endpoint}/v1/metrics`,
    headers: {}
  });

  // Create SDK
  sdk = new NodeSDK({
    resource,
    traceExporter,
    metricReader: new PeriodicExportingMetricReader({
      exporter: metricExporter,
      exportIntervalMillis: 10000 // Export metrics every 10 seconds
    }),
    instrumentations: [
      getNodeAutoInstrumentations({
        '@opentelemetry/instrumentation-fs': {
          enabled: false // Disable fs instrumentation to reduce noise
        }
      })
    ]
  });

  // Initialize the SDK
  sdk.start()
    .then(() => {
      console.log('OpenTelemetry initialized successfully');
    })
    .catch((error) => {
      console.error('Error initializing OpenTelemetry:', error);
    });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    sdk?.shutdown()
      .then(() => console.log('OpenTelemetry terminated successfully'))
      .catch((error) => console.error('Error terminating OpenTelemetry:', error))
      .finally(() => process.exit(0));
  });
}

export function createTracer(name: string): Tracer {
  return trace.getTracer(name);
}

// Helper function to record exceptions
export function recordException(error: Error, span?: any): void {
  const activeSpan = span || trace.getActiveSpan();
  if (activeSpan) {
    activeSpan.recordException(error);
    activeSpan.setStatus({ code: 2, message: error.message });
  }
}

// Helper function to add attributes to current span
export function addSpanAttributes(attributes: Record<string, any>): void {
  const span = trace.getActiveSpan();
  if (span) {
    span.setAttributes(attributes);
  }
}

// Helper function to create a child span
export async function withSpan<T>(
  tracer: Tracer,
  name: string,
  fn: () => Promise<T>,
  attributes?: Record<string, any>
): Promise<T> {
  return tracer.startActiveSpan(name, async (span) => {
    try {
      if (attributes) {
        span.setAttributes(attributes);
      }
      const result = await fn();
      span.setStatus({ code: 1 }); // OK
      return result;
    } catch (error) {
      span.recordException(error as Error);
      span.setStatus({ code: 2, message: (error as Error).message }); // ERROR
      throw error;
    } finally {
      span.end();
    }
  });
}