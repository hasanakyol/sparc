#!/bin/bash
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE=${NAMESPACE:-"sparc"}
SERVICE_MESH=${SERVICE_MESH:-"istio"}
VERBOSE=${VERBOSE:-"false"}

echo -e "${GREEN}=== SPARC Service Mesh Policy Validator ===${NC}"

# Arrays to store validation results
declare -a PASSED_CHECKS=()
declare -a FAILED_CHECKS=()
declare -a WARNINGS=()

# Function to add passed check
pass_check() {
    PASSED_CHECKS+=("$1")
    [ "$VERBOSE" == "true" ] && echo -e "${GREEN}✓ $1${NC}"
}

# Function to add failed check
fail_check() {
    FAILED_CHECKS+=("$1")
    echo -e "${RED}✗ $1${NC}"
}

# Function to add warning
add_warning() {
    WARNINGS+=("$1")
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl not found${NC}"
    exit 1
fi

# Detect service mesh
detect_service_mesh() {
    if kubectl get namespace istio-system &>/dev/null; then
        SERVICE_MESH="istio"
    elif kubectl get namespace linkerd &>/dev/null; then
        SERVICE_MESH="linkerd"
    else
        fail_check "No service mesh detected"
        exit 1
    fi
    echo -e "${BLUE}Detected service mesh: ${SERVICE_MESH}${NC}"
}

# Validate Istio policies
validate_istio_policies() {
    echo -e "${YELLOW}Validating Istio policies...${NC}"
    
    # Check mTLS configuration
    echo -e "\n${BLUE}Checking mTLS configuration...${NC}"
    MTLS_POLICIES=$(kubectl get peerauthentication -A -o json)
    
    # Check for strict mTLS in production namespaces
    for ns in sparc database; do
        if kubectl get namespace $ns &>/dev/null; then
            MTLS_MODE=$(echo "$MTLS_POLICIES" | jq -r ".items[] | select(.metadata.namespace==\"$ns\") | .spec.mtls.mode" 2>/dev/null || echo "")
            if [ "$MTLS_MODE" == "STRICT" ]; then
                pass_check "Namespace $ns has STRICT mTLS enabled"
            else
                fail_check "Namespace $ns does not have STRICT mTLS enabled"
            fi
        fi
    done
    
    # Check authorization policies
    echo -e "\n${BLUE}Checking authorization policies...${NC}"
    
    # Check for deny-all policy
    if kubectl get authorizationpolicy -n istio-system deny-all &>/dev/null; then
        pass_check "Default deny-all authorization policy exists"
    else
        fail_check "Default deny-all authorization policy missing"
    fi
    
    # Check service-specific authorization policies
    SERVICES=("api-gateway" "auth-service" "video-processor" "analytics-service" "incident-service")
    for service in "${SERVICES[@]}"; do
        if kubectl get authorizationpolicy -n $NAMESPACE allow-$service &>/dev/null; then
            pass_check "Authorization policy for $service exists"
        else
            add_warning "Authorization policy for $service not found"
        fi
    done
    
    # Check destination rules
    echo -e "\n${BLUE}Checking destination rules...${NC}"
    DEST_RULES=$(kubectl get destinationrule -n $NAMESPACE -o json)
    
    # Check for circuit breaker configuration
    CB_COUNT=$(echo "$DEST_RULES" | jq '[.items[] | select(.spec.trafficPolicy.outlierDetection != null)] | length')
    if [ "$CB_COUNT" -gt 0 ]; then
        pass_check "Found $CB_COUNT destination rules with circuit breakers"
    else
        fail_check "No destination rules with circuit breakers found"
    fi
    
    # Check virtual services
    echo -e "\n${BLUE}Checking virtual services...${NC}"
    VS_COUNT=$(kubectl get virtualservice -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
    if [ "$VS_COUNT" -gt 0 ]; then
        pass_check "Found $VS_COUNT virtual services"
    else
        add_warning "No virtual services found in namespace $NAMESPACE"
    fi
    
    # Check telemetry configuration
    echo -e "\n${BLUE}Checking telemetry configuration...${NC}"
    if kubectl get telemetry -n istio-system &>/dev/null; then
        pass_check "Telemetry configuration exists"
    else
        add_warning "No telemetry configuration found"
    fi
}

# Validate Linkerd policies
validate_linkerd_policies() {
    echo -e "${YELLOW}Validating Linkerd policies...${NC}"
    
    # Check service profiles
    echo -e "\n${BLUE}Checking service profiles...${NC}"
    SP_COUNT=$(kubectl get serviceprofile -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
    if [ "$SP_COUNT" -gt 0 ]; then
        pass_check "Found $SP_COUNT service profiles"
    else
        fail_check "No service profiles found in namespace $NAMESPACE"
    fi
    
    # Check server authorizations
    echo -e "\n${BLUE}Checking server authorizations...${NC}"
    SA_COUNT=$(kubectl get serverauthorization -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
    if [ "$SA_COUNT" -gt 0 ]; then
        pass_check "Found $SA_COUNT server authorizations"
    else
        fail_check "No server authorizations found"
    fi
    
    # Check traffic splits
    echo -e "\n${BLUE}Checking traffic splits...${NC}"
    TS_COUNT=$(kubectl get trafficsplit -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
    if [ "$TS_COUNT" -gt 0 ]; then
        pass_check "Found $TS_COUNT traffic splits"
    else
        add_warning "No traffic splits found (may not be using canary deployments)"
    fi
}

# Validate network policies
validate_network_policies() {
    echo -e "\n${YELLOW}Validating network policies...${NC}"
    
    # Check for default deny policy
    if kubectl get networkpolicy -n $NAMESPACE default-deny-all &>/dev/null; then
        pass_check "Default deny-all network policy exists"
    else
        fail_check "Default deny-all network policy missing - zero trust not enforced"
    fi
    
    # Check for DNS allow policy
    if kubectl get networkpolicy -n $NAMESPACE allow-dns &>/dev/null; then
        pass_check "DNS allow policy exists"
    else
        fail_check "DNS allow policy missing - pods cannot resolve DNS"
    fi
    
    # Count total network policies
    NP_COUNT=$(kubectl get networkpolicy -n $NAMESPACE --no-headers 2>/dev/null | wc -l)
    if [ "$NP_COUNT" -gt 2 ]; then
        pass_check "Found $NP_COUNT network policies in namespace $NAMESPACE"
    else
        add_warning "Only $NP_COUNT network policies found - may have incomplete coverage"
    fi
}

# Test service connectivity
test_service_connectivity() {
    echo -e "\n${YELLOW}Testing service connectivity...${NC}"
    
    # Create test pod if it doesn't exist
    kubectl run mesh-test --image=curlimages/curl:latest --restart=Never -n $NAMESPACE -- sleep 3600 &>/dev/null || true
    
    # Wait for pod to be ready
    kubectl wait --for=condition=ready pod/mesh-test -n $NAMESPACE --timeout=30s &>/dev/null || {
        add_warning "Could not create test pod for connectivity testing"
        return
    }
    
    # Test internal service connectivity
    SERVICES=("api-gateway:3000" "auth-service:3001")
    for service_port in "${SERVICES[@]}"; do
        SERVICE=$(echo $service_port | cut -d: -f1)
        PORT=$(echo $service_port | cut -d: -f2)
        
        if kubectl exec mesh-test -n $NAMESPACE -- curl -s -o /dev/null -w "%{http_code}" http://$SERVICE:$PORT/health 2>/dev/null | grep -q "200\|404"; then
            pass_check "Connectivity to $SERVICE successful"
        else
            add_warning "Could not connect to $SERVICE (may require authentication)"
        fi
    done
    
    # Clean up test pod
    kubectl delete pod mesh-test -n $NAMESPACE --force --grace-period=0 &>/dev/null || true
}

# Check policy violations
check_policy_violations() {
    echo -e "\n${YELLOW}Checking for policy violations...${NC}"
    
    # Check for pods without sidecars
    if [ "$SERVICE_MESH" == "istio" ]; then
        PODS_WITHOUT_SIDECAR=$(kubectl get pods -n $NAMESPACE -o json | jq -r '.items[] | select(.spec.containers | length == 1) | .metadata.name' | wc -l)
        if [ "$PODS_WITHOUT_SIDECAR" -eq 0 ]; then
            pass_check "All pods have Istio sidecars injected"
        else
            fail_check "Found $PODS_WITHOUT_SIDECAR pods without Istio sidecars"
        fi
    fi
    
    # Check for services without policies
    SERVICES=$(kubectl get service -n $NAMESPACE -o json | jq -r '.items[] | select(.metadata.name != "kubernetes") | .metadata.name')
    for service in $SERVICES; do
        if [ "$SERVICE_MESH" == "istio" ]; then
            if ! kubectl get virtualservice,destinationrule -n $NAMESPACE 2>/dev/null | grep -q $service; then
                add_warning "Service $service has no traffic management policies"
            fi
        fi
    done
}

# Generate policy report
generate_report() {
    echo -e "\n${GREEN}=== Policy Validation Report ===${NC}"
    echo -e "${BLUE}Service Mesh: ${SERVICE_MESH}${NC}"
    echo -e "${BLUE}Namespace: ${NAMESPACE}${NC}"
    echo -e "${BLUE}Timestamp: $(date)${NC}"
    
    echo -e "\n${GREEN}Passed Checks (${#PASSED_CHECKS[@]}):${NC}"
    for check in "${PASSED_CHECKS[@]}"; do
        echo -e "  ✓ $check"
    done
    
    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Warnings (${#WARNINGS[@]}):${NC}"
        for warning in "${WARNINGS[@]}"; do
            echo -e "  ⚠ $warning"
        done
    fi
    
    if [ ${#FAILED_CHECKS[@]} -gt 0 ]; then
        echo -e "\n${RED}Failed Checks (${#FAILED_CHECKS[@]}):${NC}"
        for check in "${FAILED_CHECKS[@]}"; do
            echo -e "  ✗ $check"
        done
    fi
    
    # Calculate score
    TOTAL_CHECKS=$((${#PASSED_CHECKS[@]} + ${#FAILED_CHECKS[@]}))
    if [ $TOTAL_CHECKS -gt 0 ]; then
        SCORE=$(( (${#PASSED_CHECKS[@]} * 100) / $TOTAL_CHECKS ))
        echo -e "\n${BLUE}Policy Compliance Score: ${SCORE}%${NC}"
        
        if [ $SCORE -eq 100 ]; then
            echo -e "${GREEN}Excellent! All policies are properly configured.${NC}"
        elif [ $SCORE -ge 80 ]; then
            echo -e "${GREEN}Good! Most policies are properly configured.${NC}"
        elif [ $SCORE -ge 60 ]; then
            echo -e "${YELLOW}Fair. Several policies need attention.${NC}"
        else
            echo -e "${RED}Poor. Many policies are missing or misconfigured.${NC}"
        fi
    fi
}

# Export report to file
export_report() {
    REPORT_FILE="policy-validation-report-$(date +%Y%m%d-%H%M%S).txt"
    {
        echo "SPARC Service Mesh Policy Validation Report"
        echo "=========================================="
        echo "Service Mesh: $SERVICE_MESH"
        echo "Namespace: $NAMESPACE"
        echo "Timestamp: $(date)"
        echo ""
        echo "Passed Checks (${#PASSED_CHECKS[@]}):"
        for check in "${PASSED_CHECKS[@]}"; do
            echo "  ✓ $check"
        done
        echo ""
        if [ ${#WARNINGS[@]} -gt 0 ]; then
            echo "Warnings (${#WARNINGS[@]}):"
            for warning in "${WARNINGS[@]}"; do
                echo "  ⚠ $warning"
            done
            echo ""
        fi
        if [ ${#FAILED_CHECKS[@]} -gt 0 ]; then
            echo "Failed Checks (${#FAILED_CHECKS[@]}):"
            for check in "${FAILED_CHECKS[@]}"; do
                echo "  ✗ $check"
            done
        fi
    } > $REPORT_FILE
    
    echo -e "\n${GREEN}Report exported to: $REPORT_FILE${NC}"
}

# Main execution
detect_service_mesh

case $SERVICE_MESH in
    istio)
        validate_istio_policies
        ;;
    linkerd)
        validate_linkerd_policies
        ;;
esac

validate_network_policies
test_service_connectivity
check_policy_violations
generate_report
export_report

# Exit with error if there are failed checks
if [ ${#FAILED_CHECKS[@]} -gt 0 ]; then
    exit 1
fi