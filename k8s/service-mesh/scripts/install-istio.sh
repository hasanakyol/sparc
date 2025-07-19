#!/bin/bash
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ISTIO_VERSION=${ISTIO_VERSION:-"1.20.0"}
NAMESPACE="istio-system"
ISTIO_MANIFEST="../istio/istio-config.yaml"

echo -e "${GREEN}=== SPARC Platform - Istio Service Mesh Installation ===${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"
if ! command_exists kubectl; then
    echo -e "${RED}Error: kubectl not found. Please install kubectl first.${NC}"
    exit 1
fi

if ! command_exists helm; then
    echo -e "${RED}Error: helm not found. Please install helm first.${NC}"
    exit 1
fi

# Check cluster connection
if ! kubectl cluster-info &>/dev/null; then
    echo -e "${RED}Error: Cannot connect to Kubernetes cluster.${NC}"
    exit 1
fi

# Download and install Istio CLI
echo -e "${YELLOW}Installing Istio CLI version ${ISTIO_VERSION}...${NC}"
if ! command_exists istioctl; then
    curl -L https://istio.io/downloadIstio | ISTIO_VERSION=${ISTIO_VERSION} sh -
    sudo mv istio-${ISTIO_VERSION}/bin/istioctl /usr/local/bin/
    rm -rf istio-${ISTIO_VERSION}
fi

# Verify Istio CLI installation
istioctl version --remote=false

# Pre-check for Istio installation
echo -e "${YELLOW}Running Istio pre-installation checks...${NC}"
istioctl x precheck

# Create namespaces
echo -e "${YELLOW}Creating Istio namespaces...${NC}"
kubectl apply -f ../istio/namespace.yaml

# Label namespaces for injection
echo -e "${YELLOW}Labeling namespaces for automatic sidecar injection...${NC}"
kubectl label namespace sparc istio-injection=enabled --overwrite
kubectl label namespace database istio-injection=enabled --overwrite
kubectl label namespace monitoring istio-injection=disabled --overwrite

# Install Istio using the operator
echo -e "${YELLOW}Installing Istio control plane...${NC}"
istioctl install -f ${ISTIO_MANIFEST} --skip-confirmation

# Wait for Istio to be ready
echo -e "${YELLOW}Waiting for Istio components to be ready...${NC}"
kubectl -n istio-system wait --for=condition=ready pod -l app=istiod --timeout=600s
kubectl -n istio-ingress wait --for=condition=ready pod -l app=istio-ingressgateway --timeout=600s

# Install Istio addons
echo -e "${YELLOW}Installing Istio addons...${NC}"

# Prometheus
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION%.*}/samples/addons/prometheus.yaml || true

# Grafana
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION%.*}/samples/addons/grafana.yaml || true

# Jaeger
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION%.*}/samples/addons/jaeger.yaml || true

# Kiali
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-${ISTIO_VERSION%.*}/samples/addons/kiali.yaml || true

# Apply security policies
echo -e "${YELLOW}Applying security policies...${NC}"
kubectl apply -f ../istio/peer-authentication.yaml
kubectl apply -f ../istio/authorization-policies.yaml

# Apply traffic management rules
echo -e "${YELLOW}Applying traffic management rules...${NC}"
kubectl apply -f ../istio/gateway.yaml
kubectl apply -f ../istio/destination-rules.yaml
kubectl apply -f ../istio/virtual-services.yaml

# Apply telemetry configuration
echo -e "${YELLOW}Applying telemetry configuration...${NC}"
kubectl apply -f ../istio/telemetry.yaml

# Apply service entries for external services
echo -e "${YELLOW}Applying service entries...${NC}"
kubectl apply -f ../istio/service-entries.yaml

# Apply network policies
echo -e "${YELLOW}Applying zero-trust network policies...${NC}"
kubectl apply -f ../policies/zero-trust-network-policies.yaml

# Verify installation
echo -e "${YELLOW}Verifying Istio installation...${NC}"
istioctl verify-install -f ${ISTIO_MANIFEST}

# Check proxy status
echo -e "${YELLOW}Checking proxy configuration...${NC}"
istioctl proxy-status

# Display ingress gateway information
echo -e "${GREEN}=== Istio Installation Complete ===${NC}"
echo -e "${YELLOW}Ingress Gateway Information:${NC}"
kubectl get svc istio-ingressgateway -n istio-ingress

# Get external IP
INGRESS_HOST=$(kubectl -n istio-ingress get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
INGRESS_PORT=$(kubectl -n istio-ingress get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
SECURE_INGRESS_PORT=$(kubectl -n istio-ingress get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="https")].port}')

echo -e "${GREEN}Ingress Gateway URLs:${NC}"
echo "HTTP:  http://${INGRESS_HOST}:${INGRESS_PORT}"
echo "HTTPS: https://${INGRESS_HOST}:${SECURE_INGRESS_PORT}"

# Display dashboard URLs
echo -e "${GREEN}Dashboard URLs (use 'istioctl dashboard' to access):${NC}"
echo "Kiali:      istioctl dashboard kiali"
echo "Grafana:    istioctl dashboard grafana"
echo "Prometheus: istioctl dashboard prometheus"
echo "Jaeger:     istioctl dashboard jaeger"

# Create a validation script
cat > validate-istio.sh << 'EOF'
#!/bin/bash
echo "=== Validating Istio Installation ==="

# Check control plane
echo "Control Plane Status:"
kubectl get pods -n istio-system

# Check injection
echo -e "\nSidecar Injection Status:"
kubectl get namespace -L istio-injection

# Check policies
echo -e "\nAuthorization Policies:"
kubectl get authorizationpolicy -A

# Check telemetry
echo -e "\nTelemetry Configuration:"
kubectl get telemetry -A

# Check gateways
echo -e "\nGateways:"
kubectl get gateway -A

# Check virtual services
echo -e "\nVirtual Services:"
kubectl get virtualservice -A

# Check destination rules
echo -e "\nDestination Rules:"
kubectl get destinationrule -A
EOF

chmod +x validate-istio.sh

echo -e "${GREEN}Installation complete! Run ./validate-istio.sh to validate the installation.${NC}"