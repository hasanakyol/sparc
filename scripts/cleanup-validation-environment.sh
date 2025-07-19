#!/bin/bash

# SPARC Validation Environment Cleanup Script
# Purpose: Clean up test environment after validation runs

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Get validation ID from argument
VALIDATION_ID="${1:-}"

if [[ -z "$VALIDATION_ID" ]]; then
    echo -e "${RED}Error: Validation ID required${NC}"
    echo "Usage: $0 <validation-id>"
    exit 1
fi

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Stop and remove containers
cleanup_containers() {
    log "Cleaning up Docker containers"
    
    local containers=(
        "postgres-validation-$VALIDATION_ID"
        "redis-validation-$VALIDATION_ID"
        "minio-validation-$VALIDATION_ID"
    )
    
    for container in "${containers[@]}"; do
        if docker ps -a | grep -q "$container"; then
            log "Stopping container: $container"
            docker stop "$container" >/dev/null 2>&1 || true
            docker rm "$container" >/dev/null 2>&1 || true
            success "Removed container: $container"
        else
            warning "Container not found: $container"
        fi
    done
}

# Clean up temporary files
cleanup_files() {
    log "Cleaning up temporary files"
    
    local validation_dir="/tmp/sparc-validation-$VALIDATION_ID"
    
    if [[ -d "$validation_dir" ]]; then
        # Archive logs before deletion if requested
        if [[ "${ARCHIVE_LOGS:-false}" == "true" ]]; then
            local archive_name="sparc-validation-logs-$VALIDATION_ID.tar.gz"
            tar -czf "/tmp/$archive_name" -C "$validation_dir" logs/
            success "Logs archived to: /tmp/$archive_name"
        fi
        
        # Remove validation directory
        rm -rf "$validation_dir"
        success "Removed validation directory: $validation_dir"
    else
        warning "Validation directory not found: $validation_dir"
    fi
}

# Clean up any lingering processes
cleanup_processes() {
    log "Checking for lingering processes"
    
    # Kill any processes that might be using test ports
    local ports=(5432 6379 9000 9001)
    
    for port in "${ports[@]}"; do
        if lsof -i :"$port" >/dev/null 2>&1; then
            warning "Port $port is still in use"
            # Don't kill processes automatically, just warn
        fi
    done
}

# Generate cleanup report
generate_report() {
    log "Generating cleanup report"
    
    local report_file="/tmp/sparc-cleanup-report-$VALIDATION_ID.json"
    
    cat > "$report_file" << EOF
{
  "validation_id": "$VALIDATION_ID",
  "cleanup_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "completed",
  "cleaned_items": {
    "containers": ["postgres", "redis", "minio"],
    "directories": ["/tmp/sparc-validation-$VALIDATION_ID"],
    "logs_archived": ${ARCHIVE_LOGS:-false}
  }
}
EOF
    
    success "Cleanup report saved to: $report_file"
}

# Main execution
main() {
    log "SPARC Validation Environment Cleanup"
    log "Validation ID: $VALIDATION_ID"
    
    # Cleanup steps
    cleanup_containers
    cleanup_files
    cleanup_processes
    generate_report
    
    success "Cleanup completed for validation: $VALIDATION_ID"
}

# Run main function
main