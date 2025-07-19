#!/bin/bash
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
SERVICE_MESH="istio"
NAMESPACE="sparc"
ENABLE_MTLS="true"
ENABLE_TRACING="true"
ENABLE_METRICS="true"

# Function to display usage
usage() {
    echo "Usage: $0 -s <service-name> [-n <namespace>] [-m <mesh-type>] [options]"
    echo ""
    echo "Required:"
    echo "  -s, --service         Service name to onboard"
    echo ""
    echo "Optional:"
    echo "  -n, --namespace       Namespace (default: sparc)"
    echo "  -m, --mesh           Service mesh type: istio|linkerd (default: istio)"
    echo "  -p, --port           Service port (default: auto-detect)"
    echo "  --no-mtls            Disable mTLS"
    echo "  --no-tracing         Disable tracing"
    echo "  --no-metrics         Disable metrics"
    echo "  --canary             Enable canary deployment configuration"
    echo "  --retry              Configure retry policy"
    echo "  --timeout <seconds>  Set request timeout (default: 30s)"
    echo "  -h, --help           Display this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--service)
            SERVICE_NAME="$2"
            shift 2
            ;;
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -m|--mesh)
            SERVICE_MESH="$2"
            shift 2
            ;;
        -p|--port)
            SERVICE_PORT="$2"
            shift 2
            ;;
        --no-mtls)
            ENABLE_MTLS="false"
            shift
            ;;
        --no-tracing)
            ENABLE_TRACING="false"
            shift
            ;;
        --no-metrics)
            ENABLE_METRICS="false"
            shift
            ;;
        --canary)
            ENABLE_CANARY="true"
            shift
            ;;
        --retry)
            ENABLE_RETRY="true"
            shift
            ;;
        --timeout)
            REQUEST_TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Validate required parameters
if [ -z "${SERVICE_NAME:-}" ]; then
    echo -e "${RED}Error: Service name is required${NC}"
    usage
fi

echo -e "${GREEN}=== Onboarding Service: ${SERVICE_NAME} ===${NC}"
echo -e "${BLUE}Namespace: ${NAMESPACE}${NC}"
echo -e "${BLUE}Service Mesh: ${SERVICE_MESH}${NC}"

# Check if service exists
if ! kubectl get service ${SERVICE_NAME} -n ${NAMESPACE} &>/dev/null; then
    echo -e "${RED}Error: Service ${SERVICE_NAME} not found in namespace ${NAMESPACE}${NC}"
    exit 1
fi

# Auto-detect service port if not provided
if [ -z "${SERVICE_PORT:-}" ]; then
    SERVICE_PORT=$(kubectl get service ${SERVICE_NAME} -n ${NAMESPACE} -o jsonpath='{.spec.ports[0].port}')
    echo -e "${YELLOW}Auto-detected service port: ${SERVICE_PORT}${NC}"
fi

# Function to create Istio configuration
create_istio_config() {
    echo -e "${YELLOW}Creating Istio configuration...${NC}"
    
    # Create destination rule
    cat > /tmp/${SERVICE_NAME}-destination-rule.yaml << EOF
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  host: ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http2MaxRequests: 100
        maxRequestsPerConnection: 2
    loadBalancer:
      simple: ROUND_ROBIN
    outlierDetection:
      consecutiveErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
      minHealthPercent: 30
EOF

    # Add retry policy if enabled
    if [ "${ENABLE_RETRY:-false}" == "true" ]; then
        cat >> /tmp/${SERVICE_NAME}-destination-rule.yaml << EOF
    retry:
      attempts: 3
      perTryTimeout: 10s
      retryOn: 5xx,reset,connect-failure,refused-stream
EOF
    fi

    # Create virtual service
    cat > /tmp/${SERVICE_NAME}-virtual-service.yaml << EOF
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  hosts:
  - ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
  http:
  - route:
    - destination:
        host: ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
    timeout: ${REQUEST_TIMEOUT:-30s}
EOF

    # Create PeerAuthentication if mTLS is enabled
    if [ "${ENABLE_MTLS}" == "true" ]; then
        cat > /tmp/${SERVICE_NAME}-peer-auth.yaml << EOF
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  selector:
    matchLabels:
      app: ${SERVICE_NAME}
  mtls:
    mode: STRICT
EOF
    fi

    # Create AuthorizationPolicy
    cat > /tmp/${SERVICE_NAME}-authz-policy.yaml << EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  selector:
    matchLabels:
      app: ${SERVICE_NAME}
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/${NAMESPACE}/sa/api-gateway"]
  - to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
EOF

    # Create telemetry configuration
    if [ "${ENABLE_METRICS}" == "true" ] || [ "${ENABLE_TRACING}" == "true" ]; then
        cat > /tmp/${SERVICE_NAME}-telemetry.yaml << EOF
apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  selector:
    matchLabels:
      app: ${SERVICE_NAME}
EOF
        
        if [ "${ENABLE_METRICS}" == "true" ]; then
            cat >> /tmp/${SERVICE_NAME}-telemetry.yaml << EOF
  metrics:
  - providers:
    - name: prometheus
EOF
        fi
        
        if [ "${ENABLE_TRACING}" == "true" ]; then
            cat >> /tmp/${SERVICE_NAME}-telemetry.yaml << EOF
  tracing:
  - providers:
    - name: jaeger
    randomSamplingPercentage: 100.0
EOF
        fi
    fi

    # Apply configurations
    kubectl apply -f /tmp/${SERVICE_NAME}-destination-rule.yaml
    kubectl apply -f /tmp/${SERVICE_NAME}-virtual-service.yaml
    [ -f /tmp/${SERVICE_NAME}-peer-auth.yaml ] && kubectl apply -f /tmp/${SERVICE_NAME}-peer-auth.yaml
    kubectl apply -f /tmp/${SERVICE_NAME}-authz-policy.yaml
    [ -f /tmp/${SERVICE_NAME}-telemetry.yaml ] && kubectl apply -f /tmp/${SERVICE_NAME}-telemetry.yaml
}

# Function to create Linkerd configuration
create_linkerd_config() {
    echo -e "${YELLOW}Creating Linkerd configuration...${NC}"
    
    # Create service profile
    cat > /tmp/${SERVICE_NAME}-service-profile.yaml << EOF
apiVersion: linkerd.io/v1alpha2
kind: ServiceProfile
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  retryBudget:
    retryRatio: 0.2
    minRetriesPerSecond: 10
    ttl: 10s
  routes:
  - name: default-route
    timeout: ${REQUEST_TIMEOUT:-30s}
EOF

    if [ "${ENABLE_RETRY:-false}" == "true" ]; then
        cat >> /tmp/${SERVICE_NAME}-service-profile.yaml << EOF
    retries:
      limit: 3
      backoff:
        minMs: 25
        maxMs: 250
        jitterRatio: 0.25
EOF
    fi

    # Create server authorization
    if [ "${ENABLE_MTLS}" == "true" ]; then
        cat > /tmp/${SERVICE_NAME}-server-authz.yaml << EOF
apiVersion: policy.linkerd.io/v1beta1
kind: ServerAuthorization
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  server:
    name: ${SERVICE_NAME}
  client:
    meshTLS:
      serviceAccounts:
      - name: api-gateway
        namespace: ${NAMESPACE}
EOF
    fi

    # Apply configurations
    kubectl apply -f /tmp/${SERVICE_NAME}-service-profile.yaml
    [ -f /tmp/${SERVICE_NAME}-server-authz.yaml ] && kubectl apply -f /tmp/${SERVICE_NAME}-server-authz.yaml
}

# Function to create canary configuration
create_canary_config() {
    echo -e "${YELLOW}Creating canary deployment configuration...${NC}"
    
    cat > /tmp/${SERVICE_NAME}-canary.yaml << EOF
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ${SERVICE_NAME}
  progressDeadlineSeconds: 600
  provider: ${SERVICE_MESH}
  service:
    port: ${SERVICE_PORT}
    targetPort: ${SERVICE_PORT}
  analysis:
    interval: 1m
    threshold: 10
    maxWeight: 50
    stepWeight: 10
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99
      interval: 1m
    - name: request-duration
      thresholdRange:
        max: 500
      interval: 1m
EOF
    
    kubectl apply -f /tmp/${SERVICE_NAME}-canary.yaml
}

# Function to create network policy
create_network_policy() {
    echo -e "${YELLOW}Creating network policy...${NC}"
    
    cat > /tmp/${SERVICE_NAME}-network-policy.yaml << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${SERVICE_NAME}
  namespace: ${NAMESPACE}
spec:
  podSelector:
    matchLabels:
      app: ${SERVICE_NAME}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
    - namespaceSelector:
        matchLabels:
          name: istio-system
    - namespaceSelector:
        matchLabels:
          name: linkerd
    ports:
    - protocol: TCP
      port: ${SERVICE_PORT}
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 6379
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
EOF
    
    kubectl apply -f /tmp/${SERVICE_NAME}-network-policy.yaml
}

# Main execution
case ${SERVICE_MESH} in
    istio)
        create_istio_config
        ;;
    linkerd)
        create_linkerd_config
        ;;
    *)
        echo -e "${RED}Error: Unknown service mesh type: ${SERVICE_MESH}${NC}"
        exit 1
        ;;
esac

# Create canary configuration if enabled
if [ "${ENABLE_CANARY:-false}" == "true" ]; then
    create_canary_config
fi

# Create network policy
create_network_policy

# Label the deployment for injection
echo -e "${YELLOW}Labeling deployment for sidecar injection...${NC}"
if [ "${SERVICE_MESH}" == "istio" ]; then
    kubectl label deployment ${SERVICE_NAME} -n ${NAMESPACE} istio-injection=enabled --overwrite
else
    kubectl label deployment ${SERVICE_NAME} -n ${NAMESPACE} linkerd.io/inject=enabled --overwrite
fi

# Restart deployment to inject sidecar
echo -e "${YELLOW}Restarting deployment to inject sidecar...${NC}"
kubectl rollout restart deployment/${SERVICE_NAME} -n ${NAMESPACE}

# Wait for rollout to complete
echo -e "${YELLOW}Waiting for rollout to complete...${NC}"
kubectl rollout status deployment/${SERVICE_NAME} -n ${NAMESPACE} --timeout=300s

# Verify onboarding
echo -e "${GREEN}=== Service Onboarding Complete ===${NC}"
echo -e "${YELLOW}Verifying service mesh integration...${NC}"

if [ "${SERVICE_MESH}" == "istio" ]; then
    # Check Istio proxy status
    istioctl proxy-config cluster deploy/${SERVICE_NAME} -n ${NAMESPACE}
    
    # Check applied configurations
    echo -e "${BLUE}Applied configurations:${NC}"
    kubectl get destinationrule,virtualservice,peerauthentication,authorizationpolicy -n ${NAMESPACE} | grep ${SERVICE_NAME}
else
    # Check Linkerd proxy status
    linkerd -n ${NAMESPACE} check --proxy deployment/${SERVICE_NAME}
    
    # Check applied configurations
    echo -e "${BLUE}Applied configurations:${NC}"
    kubectl get serviceprofile,serverauthorization -n ${NAMESPACE} | grep ${SERVICE_NAME}
fi

# Clean up temporary files
rm -f /tmp/${SERVICE_NAME}-*.yaml

echo -e "${GREEN}Service ${SERVICE_NAME} successfully onboarded to ${SERVICE_MESH} service mesh!${NC}"