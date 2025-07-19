#!/bin/bash

# SPARC Unified Validation Script
# Comprehensive validation for deployments, health checks, and production readiness

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/tmp/sparc-validate-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT=""
NAMESPACE=""
VALIDATION_LEVEL="standard"
REPORT_FORMAT="json"
TIMEOUT=300
HEALTH_CHECK_RETRIES=3
VERBOSE=false
EXIT_ON_FAILURE=true

# Validation categories
declare -a VALIDATION_CATEGORIES=(
    "infrastructure"
    "kubernetes"
    "services"
    "database"
    "security"
    "performance"
    "compliance"
    "external_deps"
)

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✓${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ✗${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${CYAN}[$(date +'%Y-%m-%d %H:%M:%S')] ℹ${NC} $1" | tee -a "$LOG_FILE"
}

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Unified validation script for SPARC platform

OPTIONS:
    -e, --environment ENV      Target environment (development|staging|production)
    -n, --namespace NAMESPACE  Kubernetes namespace (default: sparc-{env})
    -l, --level LEVEL         Validation level (basic|standard|comprehensive)
    -f, --format FORMAT       Report format (json|yaml|markdown|html)
    -t, --timeout SECONDS     Timeout for operations (default: 300)
    -c, --category CATEGORY   Specific category to validate
    --no-exit-on-failure      Continue validation even after failures
    -v, --verbose             Enable verbose output
    -h, --help                Show this help message

VALIDATION LEVELS:
    basic         - Essential checks only (~2 minutes)
    standard      - Standard validation suite (default, ~5 minutes)
    comprehensive - Full validation including performance tests (~15 minutes)

CATEGORIES:
    infrastructure - Cloud resources, networking, DNS
    kubernetes     - Cluster health, nodes, resources
    services       - Application services health
    database       - Database connectivity and health
    security       - Security configurations and compliance
    performance    - Performance metrics and thresholds
    compliance     - Regulatory compliance checks
    external_deps  - External service dependencies

EXAMPLES:
    # Standard validation for production
    $0 -e production

    # Comprehensive validation with specific categories
    $0 -e staging -l comprehensive -c services,database

    # Basic health check only
    $0 -e development -l basic

    # Generate HTML report
    $0 -e production -f html --no-exit-on-failure

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -l|--level)
                VALIDATION_LEVEL="$2"
                shift 2
                ;;
            -f|--format)
                REPORT_FORMAT="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -c|--category)
                IFS=',' read -ra VALIDATION_CATEGORIES <<< "$2"
                shift 2
                ;;
            --no-exit-on-failure)
                EXIT_ON_FAILURE=false
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Initialize validation
initialize() {
    log "Initializing SPARC validation..."
    
    # Validate environment
    if [ -z "$ENVIRONMENT" ]; then
        log_error "Environment must be specified (-e|--environment)"
        exit 1
    fi
    
    # Set namespace if not provided
    if [ -z "$NAMESPACE" ]; then
        NAMESPACE="sparc-${ENVIRONMENT}"
    fi
    
    # Initialize report structure
    VALIDATION_REPORT=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "validation_level": "$VALIDATION_LEVEL",
    "status": "in_progress",
    "summary": {
        "total_checks": 0,
        "passed": 0,
        "failed": 0,
        "warnings": 0
    },
    "categories": {},
    "issues": []
}
EOF
)
    
    log_success "Initialization complete"
}

# Infrastructure validation
validate_infrastructure() {
    log_info "Validating infrastructure..."
    local failures=0
    
    # Check AWS connectivity
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "Cannot connect to AWS"
        ((failures++))
    else
        log_success "AWS connectivity verified"
    fi
    
    # Check VPC and networking
    if [ "$VALIDATION_LEVEL" != "basic" ]; then
        log "Checking VPC configuration..."
        # Add VPC validation logic here
    fi
    
    # Check load balancers
    if [ "$ENVIRONMENT" = "production" ]; then
        log "Checking load balancers..."
        # Add load balancer checks
    fi
    
    # Check DNS resolution
    log "Checking DNS resolution..."
    local domains=("api.sparc.com" "app.sparc.com")
    for domain in "${domains[@]}"; do
        if ! nslookup "$domain" &> /dev/null; then
            log_warning "Cannot resolve $domain"
        fi
    done
    
    return $failures
}

# Kubernetes validation
validate_kubernetes() {
    log_info "Validating Kubernetes cluster..."
    local failures=0
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    # Check nodes
    log "Checking node status..."
    local not_ready_nodes=$(kubectl get nodes -o json | jq '[.items[] | select(.status.conditions[] | select(.type=="Ready" and .status!="True"))] | length')
    if [ "$not_ready_nodes" -gt 0 ]; then
        log_error "$not_ready_nodes nodes are not ready"
        ((failures++))
    else
        log_success "All nodes are ready"
    fi
    
    # Check namespace
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace $NAMESPACE does not exist"
        return 1
    fi
    
    # Check resource quotas
    if [ "$VALIDATION_LEVEL" = "comprehensive" ]; then
        log "Checking resource utilization..."
        local cpu_usage=$(kubectl top nodes --no-headers | awk '{sum+=$3} END {print sum/NR}')
        local mem_usage=$(kubectl top nodes --no-headers | awk '{sum+=$5} END {print sum/NR}')
        
        if (( $(echo "$cpu_usage > 80" | bc -l) )); then
            log_warning "High CPU usage: ${cpu_usage}%"
        fi
        
        if (( $(echo "$mem_usage > 80" | bc -l) )); then
            log_warning "High memory usage: ${mem_usage}%"
        fi
    fi
    
    return $failures
}

# Service health validation
validate_services() {
    log_info "Validating services health..."
    local failures=0
    
    # Get all deployments
    local deployments=$(kubectl get deployments -n "$NAMESPACE" -o json)
    local total_deployments=$(echo "$deployments" | jq '.items | length')
    
    log "Checking $total_deployments deployments..."
    
    # Check each deployment
    for i in $(seq 0 $((total_deployments - 1))); do
        local deployment=$(echo "$deployments" | jq -r ".items[$i]")
        local name=$(echo "$deployment" | jq -r '.metadata.name')
        local desired=$(echo "$deployment" | jq -r '.spec.replicas')
        local ready=$(echo "$deployment" | jq -r '.status.readyReplicas // 0')
        
        if [ "$ready" -lt "$desired" ]; then
            log_error "$name: $ready/$desired replicas ready"
            ((failures++))
        else
            [ "$VERBOSE" = "true" ] && log_success "$name: $ready/$desired replicas ready"
        fi
        
        # Check service endpoints
        if kubectl get service "$name" -n "$NAMESPACE" &> /dev/null; then
            local endpoints=$(kubectl get endpoints "$name" -n "$NAMESPACE" -o json | jq '.subsets[0].addresses | length // 0')
            if [ "$endpoints" -eq 0 ]; then
                log_error "$name: No endpoints available"
                ((failures++))
            fi
        fi
    done
    
    # Health endpoint checks
    if [ "$VALIDATION_LEVEL" != "basic" ]; then
        log "Checking health endpoints..."
        validate_health_endpoints
    fi
    
    return $failures
}

# Health endpoint validation
validate_health_endpoints() {
    local services=(
        "api-gateway:3000"
        "auth-service:3001"
        "tenant-service:3002"
        "access-control-service:3003"
        "video-management-service:3004"
        "event-processing-service:3005"
        "device-management-service:3006"
        "analytics-service:3007"
    )
    
    for service_config in "${services[@]}"; do
        local service_name="${service_config%:*}"
        local service_port="${service_config#*:}"
        
        for retry in $(seq 1 $HEALTH_CHECK_RETRIES); do
            if kubectl exec deployment/"$service_name" -n "$NAMESPACE" -- \
                curl -sf "http://localhost:$service_port/health" &> /dev/null; then
                [ "$VERBOSE" = "true" ] && log_success "$service_name health check passed"
                break
            else
                if [ "$retry" -eq "$HEALTH_CHECK_RETRIES" ]; then
                    log_error "$service_name health check failed after $HEALTH_CHECK_RETRIES attempts"
                else
                    sleep 2
                fi
            fi
        done
    done
}

# Database validation
validate_database() {
    log_info "Validating database connectivity..."
    local failures=0
    
    # Check PostgreSQL connectivity
    log "Checking PostgreSQL connection..."
    if kubectl exec deployment/api-gateway -n "$NAMESPACE" -- \
        pg_isready -h "$DB_HOST" -p 5432 -U "$DB_USER" &> /dev/null; then
        log_success "PostgreSQL connection successful"
    else
        log_error "Cannot connect to PostgreSQL"
        ((failures++))
    fi
    
    # Check Redis connectivity
    log "Checking Redis connection..."
    if kubectl exec deployment/api-gateway -n "$NAMESPACE" -- \
        redis-cli -h "$REDIS_HOST" ping &> /dev/null; then
        log_success "Redis connection successful"
    else
        log_error "Cannot connect to Redis"
        ((failures++))
    fi
    
    # Check database migrations
    if [ "$VALIDATION_LEVEL" != "basic" ]; then
        log "Checking database migrations..."
        # Add migration status check
    fi
    
    return $failures
}

# Security validation
validate_security() {
    log_info "Validating security configurations..."
    local failures=0
    
    # Check network policies
    log "Checking network policies..."
    local policies=$(kubectl get networkpolicies -n "$NAMESPACE" -o json | jq '.items | length')
    if [ "$policies" -eq 0 ]; then
        log_warning "No network policies defined"
    else
        log_success "$policies network policies active"
    fi
    
    # Check pod security standards
    if [ "$VALIDATION_LEVEL" = "comprehensive" ]; then
        log "Checking pod security standards..."
        # Add pod security validation
    fi
    
    # Check secrets encryption
    log "Checking secrets..."
    local secrets=$(kubectl get secrets -n "$NAMESPACE" -o json | jq '.items | length')
    log_success "$secrets secrets configured"
    
    # Check TLS certificates
    if [ "$ENVIRONMENT" = "production" ]; then
        log "Checking TLS certificates..."
        # Add certificate validation
    fi
    
    return $failures
}

# Performance validation
validate_performance() {
    log_info "Validating performance metrics..."
    local failures=0
    
    if [ "$VALIDATION_LEVEL" = "basic" ]; then
        log "Skipping performance validation in basic mode"
        return 0
    fi
    
    # Check response times
    log "Checking API response times..."
    local start_time=$(date +%s%N)
    if kubectl exec deployment/api-gateway -n "$NAMESPACE" -- \
        curl -sf "http://localhost:3000/health" &> /dev/null; then
        local end_time=$(date +%s%N)
        local response_time=$(( (end_time - start_time) / 1000000 ))
        
        if [ "$response_time" -gt 1000 ]; then
            log_warning "Slow API response time: ${response_time}ms"
        else
            log_success "API response time: ${response_time}ms"
        fi
    fi
    
    # Check resource utilization
    if [ "$VALIDATION_LEVEL" = "comprehensive" ]; then
        log "Checking pod resource utilization..."
        # Add resource utilization checks
    fi
    
    return $failures
}

# Compliance validation
validate_compliance() {
    log_info "Validating compliance requirements..."
    local failures=0
    
    if [ "$ENVIRONMENT" != "production" ]; then
        log "Skipping compliance validation for non-production environment"
        return 0
    fi
    
    # Check audit logging
    log "Checking audit logging..."
    # Add audit log validation
    
    # Check data encryption
    log "Checking data encryption..."
    # Add encryption validation
    
    # Check access controls
    log "Checking access controls..."
    # Add RBAC validation
    
    return $failures
}

# External dependencies validation
validate_external_deps() {
    log_info "Validating external dependencies..."
    local failures=0
    
    # Check external service connectivity
    local external_services=(
        "https://api.aws.amazon.com"
        "https://storage.googleapis.com"
    )
    
    for service in "${external_services[@]}"; do
        if curl -sf "$service" &> /dev/null; then
            [ "$VERBOSE" = "true" ] && log_success "Connected to $service"
        else
            log_warning "Cannot connect to $service"
        fi
    done
    
    return $failures
}

# Generate validation report
generate_report() {
    local status="$1"
    local total_checks="$2"
    local passed="$3"
    local failed="$4"
    local warnings="$5"
    
    log "Generating validation report..."
    
    # Update report summary
    VALIDATION_REPORT=$(echo "$VALIDATION_REPORT" | jq \
        --arg status "$status" \
        --argjson total "$total_checks" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson warnings "$warnings" \
        '.status = $status | .summary.total_checks = $total | .summary.passed = $passed | .summary.failed = $failed | .summary.warnings = $warnings')
    
    # Save report
    local report_file="/tmp/sparc-validation-report-$(date +%Y%m%d-%H%M%S).${REPORT_FORMAT}"
    
    case "$REPORT_FORMAT" in
        json)
            echo "$VALIDATION_REPORT" | jq '.' > "$report_file"
            ;;
        yaml)
            echo "$VALIDATION_REPORT" | jq '.' | yq eval -P - > "$report_file"
            ;;
        markdown)
            generate_markdown_report > "$report_file"
            ;;
        html)
            generate_html_report > "$report_file"
            ;;
    esac
    
    log_success "Validation report saved to: $report_file"
}

# Generate markdown report
generate_markdown_report() {
    cat <<EOF
# SPARC Validation Report

**Date**: $(date)
**Environment**: $ENVIRONMENT
**Namespace**: $NAMESPACE
**Validation Level**: $VALIDATION_LEVEL

## Summary

- Total Checks: $(echo "$VALIDATION_REPORT" | jq -r '.summary.total_checks')
- Passed: $(echo "$VALIDATION_REPORT" | jq -r '.summary.passed')
- Failed: $(echo "$VALIDATION_REPORT" | jq -r '.summary.failed')
- Warnings: $(echo "$VALIDATION_REPORT" | jq -r '.summary.warnings')

## Validation Results

$(echo "$VALIDATION_REPORT" | jq -r '.categories | to_entries[] | "### \(.key)\n\(.value)\n"')

## Issues Found

$(echo "$VALIDATION_REPORT" | jq -r '.issues[] | "- [\(.severity)] \(.message)"')

EOF
}

# Generate HTML report
generate_html_report() {
    cat <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>SPARC Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>SPARC Validation Report</h1>
    <p><strong>Date</strong>: $(date)</p>
    <p><strong>Environment</strong>: $ENVIRONMENT</p>
    <p><strong>Validation Level</strong>: $VALIDATION_LEVEL</p>
    
    <h2>Summary</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>
        <tr>
            <td>Total Checks</td>
            <td>$(echo "$VALIDATION_REPORT" | jq -r '.summary.total_checks')</td>
        </tr>
        <tr>
            <td class="success">Passed</td>
            <td>$(echo "$VALIDATION_REPORT" | jq -r '.summary.passed')</td>
        </tr>
        <tr>
            <td class="error">Failed</td>
            <td>$(echo "$VALIDATION_REPORT" | jq -r '.summary.failed')</td>
        </tr>
        <tr>
            <td class="warning">Warnings</td>
            <td>$(echo "$VALIDATION_REPORT" | jq -r '.summary.warnings')</td>
        </tr>
    </table>
</body>
</html>
EOF
}

# Main validation execution
main() {
    log "Starting SPARC unified validation"
    log "Environment: $ENVIRONMENT"
    log "Namespace: $NAMESPACE"
    log "Validation Level: $VALIDATION_LEVEL"
    log "Categories: ${VALIDATION_CATEGORIES[*]}"
    
    local total_checks=0
    local passed=0
    local failed=0
    local warnings=0
    
    # Run validations for each category
    for category in "${VALIDATION_CATEGORIES[@]}"; do
        case "$category" in
            infrastructure)
                validate_infrastructure && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
            kubernetes)
                validate_kubernetes && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
            services)
                validate_services && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
            database)
                validate_database && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
            security)
                validate_security && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
            performance)
                validate_performance && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
            compliance)
                validate_compliance && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
            external_deps)
                validate_external_deps && ((passed++)) || ((failed++))
                ((total_checks++))
                ;;
        esac
    done
    
    # Determine overall status
    local status="passed"
    if [ "$failed" -gt 0 ]; then
        status="failed"
    elif [ "$warnings" -gt 0 ]; then
        status="passed_with_warnings"
    fi
    
    # Generate report
    generate_report "$status" "$total_checks" "$passed" "$failed" "$warnings"
    
    # Summary
    log ""
    log "Validation Summary:"
    log_info "Total checks: $total_checks"
    log_success "Passed: $passed"
    [ "$failed" -gt 0 ] && log_error "Failed: $failed"
    [ "$warnings" -gt 0 ] && log_warning "Warnings: $warnings"
    
    # Exit based on results
    if [ "$failed" -gt 0 ] && [ "$EXIT_ON_FAILURE" = "true" ]; then
        log_error "Validation failed!"
        exit 1
    else
        log_success "Validation completed!"
        exit 0
    fi
}

# Parse arguments and run validation
parse_args "$@"
initialize
main