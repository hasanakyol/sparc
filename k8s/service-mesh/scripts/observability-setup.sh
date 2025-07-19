#!/bin/bash
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVICE_MESH=${SERVICE_MESH:-"istio"}
MONITORING_NAMESPACE="monitoring"
PROMETHEUS_RETENTION="30d"
GRAFANA_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD:-"admin"}

echo -e "${GREEN}=== SPARC Service Mesh Observability Setup ===${NC}"

# Function to check if namespace exists
namespace_exists() {
    kubectl get namespace "$1" &>/dev/null
}

# Create monitoring namespace if it doesn't exist
if ! namespace_exists "$MONITORING_NAMESPACE"; then
    echo -e "${YELLOW}Creating monitoring namespace...${NC}"
    kubectl create namespace $MONITORING_NAMESPACE
    kubectl label namespace $MONITORING_NAMESPACE istio-injection=disabled --overwrite
fi

# Install Prometheus Operator
install_prometheus_operator() {
    echo -e "${YELLOW}Installing Prometheus Operator...${NC}"
    
    # Add prometheus-community helm repo
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    
    # Install kube-prometheus-stack
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace $MONITORING_NAMESPACE \
        --set prometheus.prometheusSpec.retention=$PROMETHEUS_RETENTION \
        --set prometheus.prometheusSpec.scrapeInterval=15s \
        --set prometheus.prometheusSpec.evaluationInterval=15s \
        --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false \
        --set grafana.adminPassword=$GRAFANA_ADMIN_PASSWORD \
        --wait
}

# Configure Istio metrics scraping
configure_istio_metrics() {
    echo -e "${YELLOW}Configuring Istio metrics scraping...${NC}"
    
    # Create ServiceMonitor for Istio control plane
    cat > /tmp/istio-control-plane-monitor.yaml << EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: istio-control-plane
  namespace: $MONITORING_NAMESPACE
spec:
  jobLabel: istio-control-plane
  selector:
    matchExpressions:
    - key: app
      operator: In
      values:
      - istiod
      - istio-ingressgateway
      - istio-egressgateway
  namespaceSelector:
    matchNames:
    - istio-system
    - istio-ingress
  endpoints:
  - port: http-monitoring
    interval: 15s
    path: /stats/prometheus
EOF

    # Create ServiceMonitor for Istio data plane (Envoy sidecars)
    cat > /tmp/istio-data-plane-monitor.yaml << EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: istio-data-plane
  namespace: $MONITORING_NAMESPACE
spec:
  jobLabel: istio-mesh
  selector:
    matchExpressions:
    - key: security.istio.io/tlsMode
      operator: Exists
  namespaceSelector:
    any: true
  endpoints:
  - port: http-monitoring
    interval: 15s
    path: /stats/prometheus
    targetPort: 15090
EOF

    # Create PodMonitor for all pods with Envoy sidecars
    cat > /tmp/envoy-stats-monitor.yaml << EOF
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: envoy-stats
  namespace: $MONITORING_NAMESPACE
spec:
  selector:
    matchExpressions:
    - key: security.istio.io/tlsMode
      operator: Exists
  namespaceSelector:
    any: true
  podMetricsEndpoints:
  - port: http-envoy-prom
    path: /stats/prometheus
    interval: 15s
    relabelings:
    - sourceLabels: [__meta_kubernetes_pod_name]
      targetLabel: pod_name
    - sourceLabels: [__meta_kubernetes_pod_container_name]
      targetLabel: container_name
    - sourceLabels: [__meta_kubernetes_namespace]
      targetLabel: namespace
EOF

    kubectl apply -f /tmp/istio-control-plane-monitor.yaml
    kubectl apply -f /tmp/istio-data-plane-monitor.yaml
    kubectl apply -f /tmp/envoy-stats-monitor.yaml
}

# Configure Linkerd metrics scraping
configure_linkerd_metrics() {
    echo -e "${YELLOW}Configuring Linkerd metrics scraping...${NC}"
    
    # Create ServiceMonitor for Linkerd
    cat > /tmp/linkerd-monitor.yaml << EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: linkerd-control-plane
  namespace: $MONITORING_NAMESPACE
spec:
  selector:
    matchLabels:
      linkerd.io/control-plane-component: controller
  namespaceSelector:
    matchNames:
    - linkerd
    - linkerd-viz
  endpoints:
  - port: admin-http
    interval: 15s
    path: /metrics
EOF

    kubectl apply -f /tmp/linkerd-monitor.yaml
}

# Install custom Grafana dashboards
install_grafana_dashboards() {
    echo -e "${YELLOW}Installing custom Grafana dashboards...${NC}"
    
    # SPARC Service Mesh Dashboard
    cat > /tmp/sparc-service-mesh-dashboard.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: sparc-service-mesh-dashboard
  namespace: $MONITORING_NAMESPACE
  labels:
    grafana_dashboard: "1"
data:
  sparc-service-mesh.json: |
    {
      "dashboard": {
        "title": "SPARC Service Mesh Overview",
        "uid": "sparc-mesh-overview",
        "tags": ["sparc", "service-mesh"],
        "timezone": "browser",
        "panels": [
          {
            "title": "Request Rate by Service",
            "targets": [
              {
                "expr": "sum(rate(istio_request_total[5m])) by (destination_service_name, destination_service_namespace)"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
          },
          {
            "title": "Success Rate by Service",
            "targets": [
              {
                "expr": "sum(rate(istio_request_total{response_code!~\"5..\"}[5m])) by (destination_service_name) / sum(rate(istio_request_total[5m])) by (destination_service_name)"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
          },
          {
            "title": "P95 Latency by Service",
            "targets": [
              {
                "expr": "histogram_quantile(0.95, sum(rate(istio_request_duration_milliseconds_bucket[5m])) by (destination_service_name, le))"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
          },
          {
            "title": "Circuit Breaker Status",
            "targets": [
              {
                "expr": "sum(envoy_cluster_circuit_breakers_open) by (cluster_name)"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
          }
        ]
      }
    }
EOF

    # SPARC Video Service Dashboard
    cat > /tmp/sparc-video-dashboard.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: sparc-video-service-dashboard
  namespace: $MONITORING_NAMESPACE
  labels:
    grafana_dashboard: "1"
data:
  sparc-video-service.json: |
    {
      "dashboard": {
        "title": "SPARC Video Service Metrics",
        "uid": "sparc-video-metrics",
        "tags": ["sparc", "video"],
        "timezone": "browser",
        "panels": [
          {
            "title": "Active Video Streams",
            "targets": [
              {
                "expr": "sum(video_active_streams) by (stream_type)"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
          },
          {
            "title": "Video Processing Latency",
            "targets": [
              {
                "expr": "histogram_quantile(0.95, sum(rate(video_processing_duration_seconds_bucket[5m])) by (operation, le))"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
          },
          {
            "title": "Bandwidth Usage",
            "targets": [
              {
                "expr": "sum(rate(video_bandwidth_bytes[5m])) by (direction)"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
          },
          {
            "title": "Stream Errors",
            "targets": [
              {
                "expr": "sum(rate(video_stream_errors_total[5m])) by (error_type)"
              }
            ],
            "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
          }
        ]
      }
    }
EOF

    kubectl apply -f /tmp/sparc-service-mesh-dashboard.yaml
    kubectl apply -f /tmp/sparc-video-dashboard.yaml
}

# Configure distributed tracing
configure_tracing() {
    echo -e "${YELLOW}Configuring distributed tracing...${NC}"
    
    # Deploy Jaeger if not already present
    if ! kubectl get deployment -n $MONITORING_NAMESPACE jaeger &>/dev/null; then
        cat > /tmp/jaeger-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger
  namespace: $MONITORING_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jaeger
  template:
    metadata:
      labels:
        app: jaeger
    spec:
      containers:
      - name: jaeger
        image: jaegertracing/all-in-one:1.50
        ports:
        - containerPort: 5775
          protocol: UDP
        - containerPort: 6831
          protocol: UDP
        - containerPort: 6832
          protocol: UDP
        - containerPort: 5778
          protocol: TCP
        - containerPort: 16686
          protocol: TCP
        - containerPort: 14268
          protocol: TCP
        - containerPort: 14250
          protocol: TCP
        - containerPort: 9411
          protocol: TCP
        env:
        - name: COLLECTOR_ZIPKIN_HTTP_PORT
          value: "9411"
        - name: COLLECTOR_OTLP_ENABLED
          value: "true"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: jaeger-collector
  namespace: $MONITORING_NAMESPACE
spec:
  selector:
    app: jaeger
  ports:
  - name: jaeger-collector-tchannel
    port: 14267
    protocol: TCP
  - name: jaeger-collector-http
    port: 14268
    protocol: TCP
  - name: jaeger-collector-zipkin
    port: 9411
    protocol: TCP
  - name: jaeger-collector-grpc
    port: 14250
    protocol: TCP
  - name: jaeger-collector-otlp-grpc
    port: 4317
    protocol: TCP
  - name: jaeger-collector-otlp-http
    port: 4318
    protocol: TCP
---
apiVersion: v1
kind: Service
metadata:
  name: jaeger-query
  namespace: $MONITORING_NAMESPACE
spec:
  selector:
    app: jaeger
  ports:
  - name: jaeger-query
    port: 16686
    protocol: TCP
  type: LoadBalancer
EOF

        kubectl apply -f /tmp/jaeger-deployment.yaml
    fi
}

# Configure OpenTelemetry Collector
configure_otel_collector() {
    echo -e "${YELLOW}Configuring OpenTelemetry Collector...${NC}"
    
    cat > /tmp/otel-collector-config.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-config
  namespace: $MONITORING_NAMESPACE
data:
  otel-collector-config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318
      prometheus:
        config:
          scrape_configs:
          - job_name: 'otel-collector'
            scrape_interval: 10s
            static_configs:
            - targets: ['localhost:8888']
    
    processors:
      batch:
        timeout: 1s
        send_batch_size: 1024
      memory_limiter:
        check_interval: 1s
        limit_mib: 512
      attributes:
        actions:
        - key: environment
          value: production
          action: insert
        - key: service_mesh
          value: ${SERVICE_MESH}
          action: insert
    
    exporters:
      prometheus:
        endpoint: "0.0.0.0:8889"
      jaeger:
        endpoint: jaeger-collector:14250
        tls:
          insecure: true
      logging:
        loglevel: info
    
    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [memory_limiter, batch, attributes]
          exporters: [jaeger, logging]
        metrics:
          receivers: [otlp, prometheus]
          processors: [memory_limiter, batch, attributes]
          exporters: [prometheus, logging]
EOF

    cat > /tmp/otel-collector-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opentelemetry-collector
  namespace: $MONITORING_NAMESPACE
spec:
  replicas: 2
  selector:
    matchLabels:
      app: opentelemetry-collector
  template:
    metadata:
      labels:
        app: opentelemetry-collector
    spec:
      containers:
      - name: otel-collector
        image: otel/opentelemetry-collector-contrib:0.88.0
        command: ["/otelcol-contrib", "--config=/conf/otel-collector-config.yaml"]
        ports:
        - containerPort: 4317  # OTLP gRPC
        - containerPort: 4318  # OTLP HTTP
        - containerPort: 8888  # Prometheus metrics
        - containerPort: 8889  # Prometheus exporter
        volumeMounts:
        - name: config
          mountPath: /conf
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: otel-collector-config
---
apiVersion: v1
kind: Service
metadata:
  name: opentelemetry-collector
  namespace: $MONITORING_NAMESPACE
spec:
  selector:
    app: opentelemetry-collector
  ports:
  - name: otlp-grpc
    port: 4317
    protocol: TCP
  - name: otlp-http
    port: 4318
    protocol: TCP
  - name: prometheus-metrics
    port: 8889
    protocol: TCP
EOF

    kubectl apply -f /tmp/otel-collector-config.yaml
    kubectl apply -f /tmp/otel-collector-deployment.yaml
}

# Create PrometheusRule for alerting
create_alerting_rules() {
    echo -e "${YELLOW}Creating alerting rules...${NC}"
    
    cat > /tmp/sparc-alerting-rules.yaml << EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: sparc-service-mesh-alerts
  namespace: $MONITORING_NAMESPACE
spec:
  groups:
  - name: service_mesh_alerts
    interval: 30s
    rules:
    # High error rate alert
    - alert: HighErrorRate
      expr: |
        sum(rate(istio_request_total{response_code=~"5.."}[5m])) by (destination_service_name, destination_service_namespace)
        /
        sum(rate(istio_request_total[5m])) by (destination_service_name, destination_service_namespace)
        > 0.05
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High error rate for service {{ \$labels.destination_service_name }}"
        description: "Service {{ \$labels.destination_service_name }} has error rate above 5% (current: {{ \$value | humanizePercentage }})"
    
    # Circuit breaker open alert
    - alert: CircuitBreakerOpen
      expr: sum(envoy_cluster_circuit_breakers_open) by (cluster_name) > 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Circuit breaker open for {{ \$labels.cluster_name }}"
        description: "Circuit breaker is open for cluster {{ \$labels.cluster_name }}"
    
    # High latency alert
    - alert: HighLatency
      expr: |
        histogram_quantile(0.95,
          sum(rate(istio_request_duration_milliseconds_bucket[5m])) by (destination_service_name, le)
        ) > 1000
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High latency for service {{ \$labels.destination_service_name }}"
        description: "P95 latency for {{ \$labels.destination_service_name }} is above 1 second"
    
    # Pod without sidecar alert
    - alert: PodWithoutSidecar
      expr: |
        kube_pod_container_info{namespace="sparc"} 
        unless on(pod, namespace) kube_pod_container_info{container="istio-proxy"}
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "Pod without service mesh sidecar"
        description: "Pod {{ \$labels.pod }} in namespace {{ \$labels.namespace }} does not have a service mesh sidecar"
EOF

    kubectl apply -f /tmp/sparc-alerting-rules.yaml
}

# Main execution
echo -e "${BLUE}Setting up observability for ${SERVICE_MESH} service mesh...${NC}"

# Install Prometheus Operator
install_prometheus_operator

# Configure metrics based on service mesh
case $SERVICE_MESH in
    istio)
        configure_istio_metrics
        ;;
    linkerd)
        configure_linkerd_metrics
        ;;
esac

# Install Grafana dashboards
install_grafana_dashboards

# Configure distributed tracing
configure_tracing

# Configure OpenTelemetry Collector
configure_otel_collector

# Create alerting rules
create_alerting_rules

# Wait for all deployments to be ready
echo -e "${YELLOW}Waiting for all components to be ready...${NC}"
kubectl wait --for=condition=available --timeout=300s deployment --all -n $MONITORING_NAMESPACE

# Display access information
echo -e "\n${GREEN}=== Observability Setup Complete ===${NC}"
echo -e "${BLUE}Access information:${NC}"

# Get Grafana URL
GRAFANA_URL=$(kubectl get svc -n $MONITORING_NAMESPACE prometheus-grafana -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
if [ -z "$GRAFANA_URL" ]; then
    GRAFANA_URL="localhost"
    echo -e "${YELLOW}Grafana:${NC} kubectl port-forward -n $MONITORING_NAMESPACE svc/prometheus-grafana 3000:80"
else
    echo -e "${YELLOW}Grafana:${NC} http://$GRAFANA_URL"
fi
echo -e "  Username: admin"
echo -e "  Password: $GRAFANA_ADMIN_PASSWORD"

# Get Prometheus URL
echo -e "\n${YELLOW}Prometheus:${NC} kubectl port-forward -n $MONITORING_NAMESPACE svc/prometheus-kube-prometheus-prometheus 9090:9090"

# Get Jaeger URL
JAEGER_URL=$(kubectl get svc -n $MONITORING_NAMESPACE jaeger-query -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
if [ -z "$JAEGER_URL" ]; then
    echo -e "\n${YELLOW}Jaeger:${NC} kubectl port-forward -n $MONITORING_NAMESPACE svc/jaeger-query 16686:16686"
else
    echo -e "\n${YELLOW}Jaeger:${NC} http://$JAEGER_URL:16686"
fi

# Service mesh specific dashboards
if [ "$SERVICE_MESH" == "istio" ]; then
    echo -e "\n${YELLOW}Kiali:${NC} istioctl dashboard kiali"
fi

if [ "$SERVICE_MESH" == "linkerd" ]; then
    echo -e "\n${YELLOW}Linkerd Dashboard:${NC} linkerd viz dashboard"
fi

# Clean up temporary files
rm -f /tmp/*.yaml

echo -e "\n${GREEN}Observability stack is ready!${NC}"