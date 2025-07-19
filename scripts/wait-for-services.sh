#!/bin/bash

# SPARC Wait for Services Script
# Purpose: Wait for all services to be ready before running tests

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAX_WAIT_TIME="${MAX_WAIT_TIME:-300}" # 5 minutes default
CHECK_INTERVAL="${CHECK_INTERVAL:-5}"  # 5 seconds between checks
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-/health}"

# Services to check (can be overridden by environment)
if [[ -z "${SERVICES_TO_CHECK:-}" ]]; then
    SERVICES_TO_CHECK=(
        "api-gateway:8000"
        "auth-service:3001"
        "tenant-service:3002"
        "access-control-service:3003"
        "video-management-service:3004"
        "analytics-service:3005"
        "alert-service:3006"
        "device-management-service:3007"
        "event-processing-service:3008"
        "reporting-service:3009"
        "visitor-management-service:3010"
    )
else
    IFS=',' read -ra SERVICES_TO_CHECK <<< "$SERVICES_TO_CHECK"
fi

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check if a service is healthy
check_service_health() {
    local service_name="$1"
    local service_url="$2"
    
    # Try health endpoint first
    if curl -sf "${service_url}${HEALTH_ENDPOINT}" >/dev/null 2>&1; then
        return 0
    fi
    
    # Try basic connectivity
    if curl -sf "$service_url" >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

# Wait for a single service
wait_for_service() {
    local service_spec="$1"
    local service_name="${service_spec%%:*}"
    local service_port="${service_spec##*:}"
    local service_url="http://localhost:${service_port}"
    
    local elapsed=0
    local start_time=$(date +%s)
    
    log "Waiting for $service_name on port $service_port..."
    
    while [[ $elapsed -lt $MAX_WAIT_TIME ]]; do
        if check_service_health "$service_name" "$service_url"; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            success "$service_name is ready (took ${duration}s)"
            return 0
        fi
        
        sleep "$CHECK_INTERVAL"
        elapsed=$((elapsed + CHECK_INTERVAL))
        
        # Show progress every 30 seconds
        if [[ $((elapsed % 30)) -eq 0 ]]; then
            warning "Still waiting for $service_name... (${elapsed}s elapsed)"
        fi
    done
    
    error "$service_name failed to start within ${MAX_WAIT_TIME}s"
    return 1
}

# Check database connectivity
check_database() {
    log "Checking database connectivity..."
    
    if [[ -n "${DATABASE_URL:-}" ]]; then
        if psql "$DATABASE_URL" -c "SELECT 1" >/dev/null 2>&1; then
            success "Database is ready"
            return 0
        else
            error "Database is not accessible"
            return 1
        fi
    else
        warning "DATABASE_URL not set, skipping database check"
        return 0
    fi
}

# Check Redis connectivity
check_redis() {
    log "Checking Redis connectivity..."
    
    if [[ -n "${REDIS_URL:-}" ]]; then
        # Extract host and port from Redis URL
        local redis_host=$(echo "$REDIS_URL" | sed -E 's|redis://([^:]+):.*|\1|')
        local redis_port=$(echo "$REDIS_URL" | sed -E 's|redis://[^:]+:([0-9]+).*|\1|')
        
        if redis-cli -h "$redis_host" -p "$redis_port" ping >/dev/null 2>&1; then
            success "Redis is ready"
            return 0
        else
            error "Redis is not accessible"
            return 1
        fi
    else
        warning "REDIS_URL not set, skipping Redis check"
        return 0
    fi
}

# Main execution
main() {
    log "Waiting for SPARC services to be ready"
    log "Maximum wait time: ${MAX_WAIT_TIME}s"
    log "Services to check: ${#SERVICES_TO_CHECK[@]}"
    
    local failed_services=()
    local start_time=$(date +%s)
    
    # Check infrastructure services first
    check_database || failed_services+=("database")
    check_redis || failed_services+=("redis")
    
    # Check application services
    for service in "${SERVICES_TO_CHECK[@]}"; do
        if ! wait_for_service "$service"; then
            failed_services+=("$service")
        fi
    done
    
    # Summary
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    echo
    log "Service readiness check completed in ${total_duration}s"
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        success "All services are ready!"
        exit 0
    else
        error "The following services failed to start:"
        for service in "${failed_services[@]}"; do
            echo "  - $service"
        done
        exit 1
    fi
}

# Handle interrupts gracefully
trap 'echo -e "\n${YELLOW}Interrupted!${NC}"; exit 130' INT TERM

# Run main function
main