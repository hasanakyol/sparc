#!/bin/bash

# SPARC Validation Environment Setup Script
# Purpose: Set up isolated test environment for validation suite

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

# Default values
ENVIRONMENT="${1:-test}"
VALIDATION_ID="${2:-$(date +%Y%m%d-%H%M%S)}"

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

# Create validation environment
setup_environment() {
    log "Setting up validation environment: $ENVIRONMENT"
    
    # Create temporary directories
    export VALIDATION_DIR="/tmp/sparc-validation-$VALIDATION_ID"
    mkdir -p "$VALIDATION_DIR"/{logs,data,config}
    
    # Copy test configuration
    cp "$ROOT_DIR/.env.example" "$VALIDATION_DIR/config/.env"
    
    # Set test-specific environment variables
    export NODE_ENV="test"
    export DATABASE_URL="postgresql://test:test@localhost:5432/sparc_validation_$VALIDATION_ID"
    export REDIS_URL="redis://localhost:6379/1"
    export JWT_SECRET="test-jwt-secret-for-validation-$VALIDATION_ID"
    export LOG_LEVEL="debug"
    export VALIDATION_MODE="true"
    
    # Export validation metadata
    export VALIDATION_ID="$VALIDATION_ID"
    export VALIDATION_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    success "Validation environment created: $VALIDATION_DIR"
}

# Setup test database
setup_database() {
    log "Setting up test database"
    
    # Start PostgreSQL container for testing
    docker run -d \
        --name "postgres-validation-$VALIDATION_ID" \
        -e POSTGRES_USER=test \
        -e POSTGRES_PASSWORD=test \
        -e POSTGRES_DB="sparc_validation_$VALIDATION_ID" \
        -p 5432:5432 \
        postgres:15-alpine
    
    # Wait for database to be ready
    local max_attempts=30
    local attempt=0
    while ! docker exec "postgres-validation-$VALIDATION_ID" pg_isready -U test >/dev/null 2>&1; do
        ((attempt++))
        if [[ $attempt -gt $max_attempts ]]; then
            error "Database failed to start after $max_attempts attempts"
        fi
        log "Waiting for database... (attempt $attempt/$max_attempts)"
        sleep 2
    done
    
    success "Test database ready"
}

# Setup Redis
setup_redis() {
    log "Setting up Redis cache"
    
    docker run -d \
        --name "redis-validation-$VALIDATION_ID" \
        -p 6379:6379 \
        redis:7-alpine \
        redis-server --databases 16
    
    # Wait for Redis to be ready
    local max_attempts=10
    local attempt=0
    while ! docker exec "redis-validation-$VALIDATION_ID" redis-cli ping >/dev/null 2>&1; do
        ((attempt++))
        if [[ $attempt -gt $max_attempts ]]; then
            error "Redis failed to start after $max_attempts attempts"
        fi
        log "Waiting for Redis... (attempt $attempt/$max_attempts)"
        sleep 1
    done
    
    success "Redis cache ready"
}

# Setup MinIO for S3 testing
setup_storage() {
    log "Setting up MinIO for S3 testing"
    
    docker run -d \
        --name "minio-validation-$VALIDATION_ID" \
        -p 9000:9000 \
        -p 9001:9001 \
        -e MINIO_ROOT_USER=minioadmin \
        -e MINIO_ROOT_PASSWORD=minioadmin \
        minio/minio server /data --console-address ":9001"
    
    sleep 5
    
    # Create test bucket
    docker exec "minio-validation-$VALIDATION_ID" \
        mc alias set local http://localhost:9000 minioadmin minioadmin
    docker exec "minio-validation-$VALIDATION_ID" \
        mc mb local/sparc-validation-$VALIDATION_ID || true
    
    export S3_ENDPOINT="http://localhost:9000"
    export S3_ACCESS_KEY="minioadmin"
    export S3_SECRET_KEY="minioadmin"
    export S3_BUCKET="sparc-validation-$VALIDATION_ID"
    
    success "Storage service ready"
}

# Generate test data
generate_test_data() {
    log "Generating test data"
    
    # Create test organizations
    cat > "$VALIDATION_DIR/data/test-organizations.json" << EOF
{
  "organizations": [
    {
      "id": "test-org-1",
      "name": "Test Organization 1",
      "type": "enterprise"
    },
    {
      "id": "test-org-2",
      "name": "Test Organization 2",
      "type": "ssp"
    }
  ]
}
EOF
    
    # Create test users
    cat > "$VALIDATION_DIR/data/test-users.json" << EOF
{
  "users": [
    {
      "id": "test-user-1",
      "email": "admin@test.com",
      "role": "admin"
    },
    {
      "id": "test-user-2",
      "email": "operator@test.com",
      "role": "operator"
    }
  ]
}
EOF
    
    success "Test data generated"
}

# Main execution
main() {
    log "SPARC Validation Environment Setup"
    log "Validation ID: $VALIDATION_ID"
    
    # Setup steps
    setup_environment
    setup_database
    setup_redis
    setup_storage
    generate_test_data
    
    # Output environment info
    cat > "$VALIDATION_DIR/environment.json" << EOF
{
  "validation_id": "$VALIDATION_ID",
  "environment": "$ENVIRONMENT",
  "timestamp": "$VALIDATION_TIMESTAMP",
  "services": {
    "database": "$DATABASE_URL",
    "redis": "$REDIS_URL",
    "storage": "$S3_ENDPOINT"
  },
  "containers": [
    "postgres-validation-$VALIDATION_ID",
    "redis-validation-$VALIDATION_ID",
    "minio-validation-$VALIDATION_ID"
  ]
}
EOF
    
    success "Validation environment ready!"
    echo
    echo "Environment ID: $VALIDATION_ID"
    echo "Config directory: $VALIDATION_DIR"
    echo
    echo "To clean up after testing, run:"
    echo "./scripts/cleanup-validation-environment.sh $VALIDATION_ID"
}

# Run main function
main