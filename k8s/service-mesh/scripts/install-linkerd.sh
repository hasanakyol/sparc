#!/bin/bash
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
LINKERD_VERSION=${LINKERD_VERSION:-"stable-2.14.1"}
NAMESPACE="linkerd"

echo -e "${GREEN}=== SPARC Platform - Linkerd Service Mesh Installation ===${NC}"

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

# Check cluster connection
if ! kubectl cluster-info &>/dev/null; then
    echo -e "${RED}Error: Cannot connect to Kubernetes cluster.${NC}"
    exit 1
fi

# Install Linkerd CLI
echo -e "${YELLOW}Installing Linkerd CLI...${NC}"
if ! command_exists linkerd; then
    curl -sL https://run.linkerd.io/install | sh
    export PATH=$PATH:$HOME/.linkerd2/bin
    sudo mv $HOME/.linkerd2/bin/linkerd /usr/local/bin/
fi

# Verify Linkerd CLI installation
linkerd version --client

# Pre-check for Linkerd installation
echo -e "${YELLOW}Running Linkerd pre-installation checks...${NC}"
linkerd check --pre

# Install Linkerd CRDs
echo -e "${YELLOW}Installing Linkerd CRDs...${NC}"
linkerd install --crds | kubectl apply -f -

# Install Linkerd control plane
echo -e "${YELLOW}Installing Linkerd control plane...${NC}"
linkerd install \
  --ha \
  --controller-replicas=3 \
  --proxy-cpu-request=100m \
  --proxy-memory-request=50Mi \
  --proxy-cpu-limit=1000m \
  --proxy-memory-limit=250Mi \
  | kubectl apply -f -

# Wait for Linkerd to be ready
echo -e "${YELLOW}Waiting for Linkerd components to be ready...${NC}"
linkerd check

# Install Linkerd Viz extension
echo -e "${YELLOW}Installing Linkerd Viz extension...${NC}"
linkerd viz install | kubectl apply -f -

# Wait for Viz to be ready
kubectl -n linkerd-viz wait --for=condition=ready pod -l component=web --timeout=300s

# Install Linkerd Jaeger extension
echo -e "${YELLOW}Installing Linkerd Jaeger extension...${NC}"
linkerd jaeger install | kubectl apply -f - || true

# Install Linkerd Multicluster extension (optional)
echo -e "${YELLOW}Installing Linkerd Multicluster extension...${NC}"
linkerd multicluster install | kubectl apply -f - || true

# Apply custom configuration
echo -e "${YELLOW}Applying custom Linkerd configuration...${NC}"
kubectl apply -f ../linkerd/linkerd-config.yaml || true

# Label namespaces for injection
echo -e "${YELLOW}Labeling namespaces for automatic proxy injection...${NC}"
kubectl label namespace sparc linkerd.io/inject=enabled --overwrite
kubectl label namespace database linkerd.io/inject=enabled --overwrite
kubectl label namespace monitoring linkerd.io/inject=disabled --overwrite

# Apply traffic policies
echo -e "${YELLOW}Applying traffic policies...${NC}"
kubectl apply -f ../linkerd/traffic-policies.yaml

# Apply network policies
echo -e "${YELLOW}Applying zero-trust network policies...${NC}"
kubectl apply -f ../policies/zero-trust-network-policies.yaml

# Restart deployments to inject proxies
echo -e "${YELLOW}Restarting deployments to inject Linkerd proxies...${NC}"
kubectl -n sparc rollout restart deployment
kubectl -n database rollout restart statefulset

# Wait for rollout to complete
echo -e "${YELLOW}Waiting for rollout to complete...${NC}"
kubectl -n sparc rollout status deployment --timeout=600s || true

# Verify installation
echo -e "${YELLOW}Verifying Linkerd installation...${NC}"
linkerd check

# Check proxy injection
echo -e "${YELLOW}Checking proxy injection status...${NC}"
linkerd -n sparc check --proxy

# Display dashboard information
echo -e "${GREEN}=== Linkerd Installation Complete ===${NC}"

# Get dashboard URL
echo -e "${YELLOW}Accessing Linkerd dashboard:${NC}"
echo "Run: linkerd viz dashboard"

# Display service mesh stats
echo -e "${YELLOW}Service mesh statistics:${NC}"
linkerd -n sparc viz stat deploy

# Create validation script
cat > validate-linkerd.sh << 'EOF'
#!/bin/bash
echo "=== Validating Linkerd Installation ==="

# Check control plane
echo "Control Plane Status:"
linkerd check

# Check data plane
echo -e "\nData Plane Status:"
linkerd -n sparc check --proxy

# Check injection
echo -e "\nNamespace Injection Status:"
kubectl get namespace -L linkerd.io/inject

# Check traffic splits
echo -e "\nTraffic Splits:"
kubectl get trafficsplit -A

# Check service profiles
echo -e "\nService Profiles:"
kubectl get serviceprofile -A

# Check server authorizations
echo -e "\nServer Authorizations:"
kubectl get serverauthorization -A

# Display mesh stats
echo -e "\nMesh Statistics:"
linkerd -n sparc viz stat deploy
linkerd -n sparc viz edges deploy
EOF

chmod +x validate-linkerd.sh

# Create uninstall script
cat > uninstall-linkerd.sh << 'EOF'
#!/bin/bash
echo "=== Uninstalling Linkerd ==="

# Remove viz extension
linkerd viz uninstall | kubectl delete -f -

# Remove multicluster extension
linkerd multicluster uninstall | kubectl delete -f -

# Remove jaeger extension
linkerd jaeger uninstall | kubectl delete -f -

# Remove control plane
linkerd uninstall | kubectl delete -f -

# Remove CRDs
kubectl delete crd -l linkerd.io/control-plane-ns=linkerd

echo "Linkerd uninstalled successfully."
EOF

chmod +x uninstall-linkerd.sh

echo -e "${GREEN}Installation complete!${NC}"
echo -e "${YELLOW}Run ./validate-linkerd.sh to validate the installation.${NC}"
echo -e "${YELLOW}Run ./uninstall-linkerd.sh to uninstall Linkerd.${NC}"