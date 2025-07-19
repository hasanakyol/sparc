#!/bin/bash

# Setup Jaeger for distributed tracing in SPARC

set -e

echo "🚀 Setting up Jaeger for SPARC distributed tracing..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}kubectl is not installed. Please install kubectl first.${NC}"
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}Cannot connect to Kubernetes cluster. Please check your kubeconfig.${NC}"
    exit 1
fi

# Create observability namespace
echo "Creating observability namespace..."
kubectl create namespace observability --dry-run=client -o yaml | kubectl apply -f -

# Apply Jaeger deployment
echo "Deploying Jaeger..."
kubectl apply -f k8s/monitoring/jaeger-deployment.yaml

# Wait for Jaeger to be ready
echo "Waiting for Jaeger to be ready..."
kubectl wait --for=condition=ready pod -l app=jaeger -n observability --timeout=300s

# Create service monitor for Prometheus (if Prometheus operator is installed)
if kubectl get crd servicemonitors.monitoring.coreos.com &> /dev/null; then
    echo "Creating ServiceMonitor for Jaeger metrics..."
    cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: jaeger-metrics
  namespace: observability
  labels:
    app: jaeger
spec:
  selector:
    matchLabels:
      app: jaeger
  endpoints:
  - port: admin
    interval: 30s
    path: /metrics
EOF
fi

# Update Grafana datasources
echo "Configuring Grafana datasources..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource-jaeger
  namespace: observability
data:
  jaeger.yaml: |
    apiVersion: 1
    datasources:
    - name: Jaeger
      type: jaeger
      access: proxy
      url: http://jaeger-query:16686
      jsonData:
        tracesToMetrics:
          datasourceUid: prometheus
          tags: [{ key: 'service.name', value: 'service_name' }]
          queries:
            - name: 'Request rate'
              query: 'sum(rate(traces_spanmetrics_calls_total{$$__tags}[5m]))'
            - name: 'Error rate'
              query: 'sum(rate(traces_spanmetrics_calls_total{status_code="STATUS_CODE_ERROR",$$__tags}[5m]))'
            - name: '95th percentile latency'
              query: 'histogram_quantile(0.95, sum(rate(traces_spanmetrics_duration_milliseconds_bucket{$$__tags}[5m])) by (le))'
EOF

# Import Grafana dashboards
echo "Importing Grafana dashboards..."
kubectl create configmap grafana-dashboard-tracing \
    --from-file=monitoring/grafana/dashboards/distributed-tracing.json \
    --from-file=monitoring/grafana/dashboards/trace-analysis.json \
    -n observability \
    --dry-run=client -o yaml | kubectl apply -f -

# Label the ConfigMap for Grafana to pick it up
kubectl label configmap grafana-dashboard-tracing grafana_dashboard=1 -n observability

# Update Prometheus configuration
echo "Updating Prometheus configuration to scrape Jaeger metrics..."
kubectl apply -f monitoring/prometheus-config.yaml

# Create example trace generation job (optional)
if [ "$1" == "--with-examples" ]; then
    echo "Creating example trace generation job..."
    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: trace-example-generator
  namespace: sparc
spec:
  template:
    metadata:
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8888"
        prometheus.io/otel.scrape: "true"
    spec:
      containers:
      - name: trace-generator
        image: node:18-alpine
        command:
        - sh
        - -c
        - |
          npm install @opentelemetry/api @opentelemetry/sdk-node @opentelemetry/auto-instrumentations-node @opentelemetry/exporter-trace-otlp-grpc
          cat > trace-example.js << 'EOJS'
          const { NodeSDK } = require('@opentelemetry/sdk-node');
          const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-grpc');
          const { Resource } = require('@opentelemetry/resources');
          const { SemanticResourceAttributes } = require('@opentelemetry/semantic-conventions');
          const { trace } = require('@opentelemetry/api');
          
          const exporter = new OTLPTraceExporter({
            url: 'http://jaeger-collector.observability.svc.cluster.local:4317',
          });
          
          const sdk = new NodeSDK({
            resource: new Resource({
              [SemanticResourceAttributes.SERVICE_NAME]: 'trace-example',
              [SemanticResourceAttributes.SERVICE_VERSION]: '1.0.0',
            }),
            traceExporter: exporter,
          });
          
          sdk.start().then(() => {
            const tracer = trace.getTracer('example-tracer');
            
            // Generate example traces
            setInterval(() => {
              const span = tracer.startSpan('example-operation');
              span.setAttribute('example.value', Math.random() * 100);
              
              setTimeout(() => {
                if (Math.random() > 0.9) {
                  span.setStatus({ code: 2, message: 'Random error' });
                }
                span.end();
              }, Math.random() * 1000);
            }, 5000);
            
            console.log('Generating example traces...');
          });
          EOJS
          node trace-example.js
      restartPolicy: Never
  backoffLimit: 1
EOF
fi

# Port forwarding commands
echo -e "${GREEN}✅ Jaeger setup complete!${NC}"
echo ""
echo "To access Jaeger UI locally, run:"
echo -e "${YELLOW}kubectl port-forward -n observability svc/jaeger-query 16686:16686${NC}"
echo ""
echo "Then open: http://localhost:16686"
echo ""
echo "To access Jaeger through the ingress:"
echo -e "${YELLOW}http://monitoring.sparc.local/jaeger${NC}"
echo ""
echo "Environment variables for services:"
echo -e "${YELLOW}JAEGER_ENDPOINT=http://jaeger-collector.observability.svc.cluster.local:4317${NC}"
echo -e "${YELLOW}OTEL_EXPORTER_JAEGER_ENDPOINT=http://jaeger-collector.observability.svc.cluster.local:4317${NC}"
echo ""
echo "To view Jaeger metrics in Prometheus:"
echo -e "${YELLOW}kubectl port-forward -n observability svc/prometheus 9090:9090${NC}"
echo "Then query for metrics starting with 'jaeger_'"