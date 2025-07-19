import { Context, Next } from 'hono';
import { Registry, Counter, Histogram, Gauge } from 'prom-client';

// Create a Registry
const register = new Registry();

// Define default metrics
const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

const httpRequestTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register]
});

const httpRequestsInFlight = new Gauge({
  name: 'http_requests_in_flight',
  help: 'Number of HTTP requests currently being processed',
  labelNames: ['method', 'route'],
  registers: [register]
});

export async function metricsMiddleware(c: Context, next: Next) {
  const start = Date.now();
  const method = c.req.method;
  const route = c.req.routePath || c.req.path;

  // Increment in-flight requests
  httpRequestsInFlight.inc({ method, route });

  try {
    await next();
  } finally {
    // Decrement in-flight requests
    httpRequestsInFlight.dec({ method, route });

    // Record request duration and count
    const duration = (Date.now() - start) / 1000;
    const statusCode = c.res.status.toString();

    httpRequestDuration.observe({ method, route, status_code: statusCode }, duration);
    httpRequestTotal.inc({ method, route, status_code: statusCode });
  }
}

export function getMetricsRegistry(): Registry {
  return register;
}