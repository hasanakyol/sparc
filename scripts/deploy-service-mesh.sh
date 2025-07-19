#!/bin/bash

# SPARC Service Mesh Deployment Script
# Implements Istio service mesh with mTLS, circuit breakers, and canary deployments

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ISTIO_VERSION="1.20.0"
FLAGGER_VERSION="1.36.0"
NAMESPACE="sparc"
MONITORING_NAMESPACE="monitoring"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed. Please install kubectl first."
    fi
    
    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
    fi
    
    # Check helm
    if ! command -v helm &> /dev/null; then
        log_error "Helm is not installed. Please install Helm 3.x first."
    fi
    
    log_success "Prerequisites check passed"
}

# Install Istio
install_istio() {
    log_info "Installing Istio ${ISTIO_VERSION}..."
    
    # Download Istio
    if [ ! -d "istio-${ISTIO_VERSION}" ]; then
        curl -L https://istio.io/downloadIstio | ISTIO_VERSION=${ISTIO_VERSION} sh -
    fi
    
    cd istio-${ISTIO_VERSION}
    export PATH=$PWD/bin:$PATH
    
    # Install Istio with custom configuration
    log_info "Installing Istio control plane..."
    istioctl install -f ../k8s/service-mesh/istio/istio-config.yaml -y
    
    # Verify installation
    log_info "Verifying Istio installation..."
    kubectl -n istio-system wait --for=condition=ready pod -l app=istiod --timeout=600s
    
    cd ..
    log_success "Istio installed successfully"
}

# Create namespaces
create_namespaces() {
    log_info "Creating namespaces..."
    kubectl apply -f k8s/service-mesh/istio/namespace.yaml
    log_success "Namespaces created"
}

# Apply Istio configurations
apply_istio_configs() {
    log_info "Applying Istio configurations..."
    
    # Apply in order
    log_info "Applying Istio Gateway..."
    kubectl apply -f k8s/service-mesh/istio/gateway.yaml
    
    log_info "Applying PeerAuthentication for mTLS..."
    kubectl apply -f k8s/service-mesh/istio/peer-authentication.yaml
    
    log_info "Applying DestinationRules with circuit breakers..."
    kubectl apply -f k8s/service-mesh/istio/destination-rules.yaml
    
    log_info "Applying VirtualServices..."
    kubectl apply -f k8s/service-mesh/istio/virtual-services.yaml
    
    log_info "Applying AuthorizationPolicies..."
    kubectl apply -f k8s/service-mesh/istio/authorization-policies.yaml
    
    log_info "Applying telemetry configuration..."
    kubectl apply -f k8s/service-mesh/istio/telemetry.yaml
    
    log_info "Applying ServiceEntries for external services..."
    kubectl apply -f k8s/service-mesh/istio/service-entries.yaml
    
    log_success "Istio configurations applied"
}

# Install Flagger for canary deployments
install_flagger() {
    log_info "Installing Flagger ${FLAGGER_VERSION}..."
    
    # Add Flagger Helm repository
    helm repo add flagger https://flagger.app
    helm repo update
    
    # Install Flagger for Istio
    helm upgrade -i flagger flagger/flagger \
        --namespace=istio-system \
        --set crd.create=true \
        --set meshProvider=istio \
        --set metricsServer=http://prometheus.${MONITORING_NAMESPACE}:9090 \
        --version=${FLAGGER_VERSION}
    
    # Install Flagger load tester
    helm upgrade -i flagger-loadtester flagger/loadtester \
        --namespace=test \
        --create-namespace
    
    log_success "Flagger installed successfully"
}

# Apply canary deployment configurations
apply_canary_configs() {
    log_info "Applying canary deployment configurations..."
    kubectl apply -f k8s/service-mesh/policies/canary-deployment.yaml
    log_success "Canary configurations applied"
}

# Update service deployments for Istio
update_deployments() {
    log_info "Updating deployments for Istio sidecar injection..."
    
    # Get all deployments in SPARC namespace
    deployments=$(kubectl get deployments -n ${NAMESPACE} -o jsonpath='{.items[*].metadata.name}')
    
    for deployment in $deployments; do
        log_info "Updating deployment: ${deployment}"
        # Add version label if not exists
        kubectl patch deployment ${deployment} -n ${NAMESPACE} --type='json' \
            -p='[{"op": "add", "path": "/spec/template/metadata/labels/version", "value": "v1"}]' 2>/dev/null || true
        
        # Restart deployment to inject sidecar
        kubectl rollout restart deployment/${deployment} -n ${NAMESPACE}
    done
    
    log_info "Waiting for deployments to be ready..."
    kubectl wait --for=condition=available --timeout=600s deployment --all -n ${NAMESPACE}
    
    log_success "Deployments updated"
}

# Configure monitoring
configure_monitoring() {
    log_info "Configuring monitoring integration..."
    
    # Create ServiceMonitor for Istio metrics
    cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: istio-mesh-metrics
  namespace: istio-system
spec:
  selector:
    matchExpressions:
    - key: app
      operator: In
      values:
      - istiod
      - istio-proxy
  endpoints:
  - port: http-monitoring
    interval: 30s
    path: /stats/prometheus
EOF
    
    # Configure Grafana dashboards
    log_info "Importing Istio dashboards to Grafana..."
    kubectl apply -f istio-${ISTIO_VERSION}/samples/addons/grafana.yaml -n ${MONITORING_NAMESPACE} || true
    
    log_success "Monitoring configured"
}

# Verify service mesh
verify_service_mesh() {
    log_info "Verifying service mesh configuration..."
    
    # Check mTLS
    log_info "Checking mTLS status..."
    istioctl proxy-config listeners deployment/api-gateway -n ${NAMESPACE} | grep -i tls || true
    
    # Check circuit breakers
    log_info "Checking circuit breaker configuration..."
    istioctl proxy-config cluster deployment/api-gateway -n ${NAMESPACE} --fqdn api-gateway.${NAMESPACE}.svc.cluster.local
    
    # Check authorization policies
    log_info "Checking authorization policies..."
    kubectl get authorizationpolicies -A
    
    log_success "Service mesh verification complete"
}

# Create example canary deployment
create_canary_example() {
    log_info "Creating example canary deployment..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: example-app
  namespace: ${NAMESPACE}
spec:
  ports:
  - port: 80
    targetPort: 8080
    name: http
  selector:
    app: example-app
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: example-app
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: example-app
  template:
    metadata:
      labels:
        app: example-app
        version: v1
    spec:
      containers:
      - name: app
        image: nginx:alpine
        ports:
        - containerPort: 8080
          name: http
EOF
    
    log_success "Example canary deployment created"
}

# Main execution
main() {
    log_info "Starting SPARC Service Mesh Deployment"
    
    check_prerequisites
    create_namespaces
    install_istio
    apply_istio_configs
    install_flagger
    apply_canary_configs
    update_deployments
    configure_monitoring
    verify_service_mesh
    
    log_success "Service mesh deployment completed successfully!"
    log_info "Access Kiali dashboard: kubectl port-forward svc/kiali -n istio-system 20001:20001"
    log_info "Access Grafana dashboards: kubectl port-forward svc/grafana -n ${MONITORING_NAMESPACE} 3000:3000"
    log_info "View canary deployments: kubectl get canaries -n ${NAMESPACE}"
}

# Run main function
main "$@"