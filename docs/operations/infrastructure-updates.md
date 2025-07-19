# Infrastructure Updates for SPARC Platform

## Overview

This document describes the infrastructure updates made to support the newly refactored microservices pattern in the SPARC security platform.

## 1. Standardized Health Check Endpoints

All Kubernetes deployments have been updated to use standardized health check endpoints:

- **Liveness Probe**: `/health` - Checks if the service is running
- **Readiness Probe**: `/ready` - Checks if the service is ready to accept traffic
- **Metrics Endpoint**: `/metrics` - Prometheus metrics endpoint

### Updated Services

All 24 services in the platform now use these standardized endpoints:
- api-gateway
- auth-service
- video-management-service
- analytics-service
- device-management-service
- event-processing-service
- access-control-service
- mobile-credential-service
- api-documentation-service
- And all other services...

## 2. Prometheus Monitoring Configuration

### Prometheus Deployment

A comprehensive Prometheus configuration has been created at `k8s/monitoring/prometheus-deployment.yaml` that includes:

- **Service Discovery**: Automatic discovery of all SPARC services using Kubernetes SD
- **Scrape Configurations**: Configured to scrape metrics from all services with `prometheus.io/scrape: "true"` annotation
- **Alert Rules**: Basic alerting rules for service health, performance, and resource usage
- **Storage**: 50GB persistent volume for metrics retention (30 days)

### Key Features

1. **Automatic Service Discovery**
   ```yaml
   - job_name: 'sparc-services'
     kubernetes_sd_configs:
       - role: pod
         namespaces:
           names: ['sparc']
   ```

2. **Common Metrics Collection**
   - HTTP request rates and latencies
   - Error rates
   - Resource usage (CPU, memory)
   - Service-specific metrics

3. **Alert Rules**
   - Service down alerts
   - High error rate alerts (>5%)
   - High latency alerts (p95 > 500ms)
   - Resource usage alerts

## 3. API Documentation Service

### Automated Documentation Generation

1. **Generation Script**: `scripts/generate-api-docs.js`
   - Automatically generates OpenAPI documentation for all services
   - Creates Swagger UI for each service
   - Supports YAML and JSON formats

2. **Centralized Documentation Portal**: `services/api-documentation-service`
   - Aggregates documentation from all services
   - Provides unified Swagger UI
   - Available at http://localhost:3012

3. **Features**
   - Service discovery and listing
   - Interactive API testing with Swagger UI
   - OpenAPI 3.0 specification generation
   - Health check endpoints documentation

### Usage

```bash
# Generate documentation for all services
npm run docs:generate

# Serve documentation portal
npm run docs:serve

# Access documentation
open http://localhost:3012
```

## 4. Kubernetes Configurations

### Deployment Updates

All Kubernetes deployments have been updated with:

1. **Standardized Labels**
   ```yaml
   labels:
     app.kubernetes.io/name: service-name
     app.kubernetes.io/component: backend
     app.kubernetes.io/part-of: sparc
   ```

2. **Prometheus Annotations**
   ```yaml
   annotations:
     prometheus.io/scrape: "true"
     prometheus.io/port: "3000"
     prometheus.io/path: "/metrics"
   ```

3. **Health Probes**
   ```yaml
   livenessProbe:
     httpGet:
       path: /health
       port: http
   readinessProbe:
     httpGet:
       path: /ready
       port: http
   ```

### ServiceMonitor Resources

Each service includes a ServiceMonitor for Prometheus Operator integration:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: service-name-metrics
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: service-name
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

## 5. Infrastructure Scripts

### Health Endpoint Update Script

`scripts/update-health-endpoints.sh` - Updates all Kubernetes deployments to use standardized endpoints

### Documentation Scripts

- `scripts/generate-api-docs.js` - Generates OpenAPI documentation
- `scripts/add-docs-script.js` - Adds documentation generation to service package.json files

## 6. Monitoring Dashboard

The monitoring setup includes:

1. **Prometheus**: Metrics collection and storage
2. **Grafana**: Visualization dashboards (configured in `monitoring/grafana/`)
3. **AlertManager**: Alert routing and notification

### Key Dashboards

- Service Overview Dashboard
- API Performance Dashboard  
- Resource Usage Dashboard
- Error Monitoring Dashboard

## 7. Next Steps

1. **Deploy Monitoring Stack**
   ```bash
   kubectl apply -f k8s/monitoring/prometheus-deployment.yaml
   kubectl apply -f k8s/api-documentation-service.yaml
   ```

2. **Configure Ingress**
   - Set up ingress for Prometheus UI
   - Configure SSL certificates
   - Set up authentication

3. **Set Up Alerts**
   - Configure AlertManager receivers
   - Set up notification channels (email, Slack, PagerDuty)
   - Define escalation policies

4. **Create Custom Dashboards**
   - Import Grafana dashboards
   - Create service-specific dashboards
   - Set up SLO tracking

## 8. Benefits

1. **Standardization**: All services follow the same patterns for health checks and metrics
2. **Observability**: Complete visibility into service health and performance
3. **Documentation**: Automated, always up-to-date API documentation
4. **Scalability**: Infrastructure ready to handle 10,000+ concurrent users
5. **Maintainability**: Consistent configuration across all services