#!/bin/bash

# SPARC Development Environment Setup Script
# This script automates the initial setup process for SPARC development environment
# as described in CONTRIBUTING.md and README.md

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_deps=()
    
    # Check Node.js version
    if command_exists node; then
        NODE_VERSION=$(node --version | cut -d'v' -f2)
        REQUIRED_NODE_VERSION="18.0.0"
        if [ "$(printf '%s\n' "$REQUIRED_NODE_VERSION" "$NODE_VERSION" | sort -V | head -n1)" != "$REQUIRED_NODE_VERSION" ]; then
            log_error "Node.js version $NODE_VERSION found, but version 18+ is required"
            missing_deps+=("node")
        else
            log_success "Node.js version $NODE_VERSION found"
        fi
    else
        log_error "Node.js not found"
        missing_deps+=("node")
    fi
    
    # Check npm/yarn
    if command_exists yarn; then
        log_success "Yarn found"
        PACKAGE_MANAGER="yarn"
    elif command_exists npm; then
        log_success "npm found"
        PACKAGE_MANAGER="npm"
    else
        log_error "Neither npm nor yarn found"
        missing_deps+=("npm/yarn")
    fi
    
    # Check Docker
    if command_exists docker; then
        if docker info >/dev/null 2>&1; then
            log_success "Docker found and running"
        else
            log_error "Docker found but not running"
            missing_deps+=("docker-running")
        fi
    else
        log_error "Docker not found"
        missing_deps+=("docker")
    fi
    
    # Check Docker Compose
    if command_exists docker-compose || docker compose version >/dev/null 2>&1; then
        log_success "Docker Compose found"
    else
        log_error "Docker Compose not found"
        missing_deps+=("docker-compose")
    fi
    
    # Check PostgreSQL (optional for local development)
    if command_exists psql; then
        log_success "PostgreSQL client found"
    else
        log_warning "PostgreSQL client not found (optional - will use Docker container)"
    fi
    
    # Check AWS CLI (optional)
    if command_exists aws; then
        log_success "AWS CLI found"
    else
        log_warning "AWS CLI not found (optional - needed for deployment)"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Please install the missing dependencies and run this script again"
        log_info "Installation guides:"
        log_info "  Node.js 18+: https://nodejs.org/en/download/"
        log_info "  Docker: https://docs.docker.com/get-docker/"
        log_info "  Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    log_success "All prerequisites met"
}

# Create environment file
setup_environment() {
    log_info "Setting up environment variables..."
    
    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            cp .env.example .env
            log_success "Created .env file from .env.example"
        else
            log_info "Creating default .env file..."
            cat > .env << 'EOF'
# SPARC Development Environment Configuration

# Database Configuration
DATABASE_URL="postgresql://sparc_user:sparc_password@localhost:5432/sparc_dev"
DATABASE_HOST="localhost"
DATABASE_PORT="5432"
DATABASE_NAME="sparc_dev"
DATABASE_USER="sparc_user"
DATABASE_PASSWORD="sparc_password"

# Redis Configuration
REDIS_URL="redis://localhost:6379"
REDIS_HOST="localhost"
REDIS_PORT="6379"

# JWT Configuration
JWT_SECRET="your-super-secret-jwt-key-change-this-in-production"
JWT_EXPIRES_IN="24h"
JWT_REFRESH_EXPIRES_IN="7d"

# API Configuration
API_PORT="3000"
API_HOST="localhost"
API_BASE_URL="http://localhost:3000"

# Frontend Configuration
NEXT_PUBLIC_API_URL="http://localhost:3000"
NEXT_PUBLIC_WS_URL="ws://localhost:3000"

# AWS Configuration (for deployment)
AWS_REGION="us-east-1"
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""

# S3 Configuration (MinIO for local development)
S3_ENDPOINT="http://localhost:9000"
S3_ACCESS_KEY="minioadmin"
S3_SECRET_KEY="minioadmin"
S3_BUCKET_NAME="sparc-dev"
S3_REGION="us-east-1"

# Video Storage Configuration
VIDEO_STORAGE_PATH="/tmp/sparc/videos"
VIDEO_RETENTION_DAYS="30"

# Logging Configuration
LOG_LEVEL="debug"
LOG_FORMAT="json"

# Development Configuration
NODE_ENV="development"
DEBUG="sparc:*"

# Multi-tenant Configuration
DEFAULT_TENANT_ID="default"
ENABLE_MULTI_TENANT="true"

# Offline Resilience Configuration
OFFLINE_MODE_ENABLED="true"
OFFLINE_CACHE_TTL="259200" # 72 hours in seconds

# Security Configuration
BCRYPT_ROUNDS="12"
RATE_LIMIT_WINDOW_MS="900000" # 15 minutes
RATE_LIMIT_MAX_REQUESTS="100"

# Email Configuration (for notifications)
SMTP_HOST=""
SMTP_PORT="587"
SMTP_USER=""
SMTP_PASSWORD=""
SMTP_FROM="noreply@sparc-platform.com"

# Mobile Credential Configuration
MOBILE_CREDENTIAL_ENABLED="true"
NFC_ENABLED="true"
BLE_ENABLED="true"

# Analytics Configuration
ANALYTICS_ENABLED="true"
FACE_RECOGNITION_ENABLED="false"
LICENSE_PLATE_RECOGNITION_ENABLED="false"

# Hardware Integration Configuration
OSDP_ENABLED="true"
ONVIF_ENABLED="true"
DEVICE_DISCOVERY_ENABLED="true"

# Monitoring Configuration
METRICS_ENABLED="true"
HEALTH_CHECK_INTERVAL="30000" # 30 seconds
EOF
            log_success "Created default .env file"
        fi
    else
        log_warning ".env file already exists, skipping creation"
    fi
    
    log_info "Please review and update the .env file with your specific configuration"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    if [ "$PACKAGE_MANAGER" = "yarn" ]; then
        yarn install
    else
        npm install
    fi
    
    log_success "Dependencies installed successfully"
}

# Start local services with Docker Compose
start_local_services() {
    log_info "Starting local services with Docker Compose..."
    
    if [ ! -f docker-compose.yml ]; then
        log_error "docker-compose.yml not found"
        log_info "Creating basic docker-compose.yml for development..."
        cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: sparc-postgres
    environment:
      POSTGRES_DB: sparc_dev
      POSTGRES_USER: sparc_user
      POSTGRES_PASSWORD: sparc_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sparc_user -d sparc_dev"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: sparc-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    container_name: sparc-minio
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 20s
      retries: 3

volumes:
  postgres_data:
  redis_data:
  minio_data:

networks:
  default:
    name: sparc-network
EOF
        log_success "Created docker-compose.yml"
    fi
    
    # Start services
    docker-compose up -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose ps | grep -q "Up (healthy)"; then
            log_success "Services are ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "Services failed to start within expected time"
            docker-compose logs
            exit 1
        fi
        
        log_info "Waiting for services... (attempt $attempt/$max_attempts)"
        sleep 5
        ((attempt++))
    done
}

# Setup database
setup_database() {
    log_info "Setting up database..."
    
    # Create init script if it doesn't exist
    if [ ! -f scripts/init-db.sql ]; then
        mkdir -p scripts
        cat > scripts/init-db.sql << 'EOF'
-- SPARC Database Initialization Script

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas for multi-tenant architecture
CREATE SCHEMA IF NOT EXISTS public;
CREATE SCHEMA IF NOT EXISTS tenant_shared;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set default search path
ALTER DATABASE sparc_dev SET search_path TO public, tenant_shared, audit;

-- Create basic tables for development
-- These will be replaced by proper Prisma migrations

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default tenant for development
INSERT INTO tenants (id, name, slug) 
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Tenant', 'default')
ON CONFLICT (slug) DO NOTHING;

-- Create audit log function
CREATE OR REPLACE FUNCTION audit.log_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit.audit_log (table_name, operation, new_values, tenant_id, created_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(NEW), NEW.tenant_id, NOW());
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit.audit_log (table_name, operation, old_values, new_values, tenant_id, created_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD), row_to_json(NEW), NEW.tenant_id, NOW());
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit.audit_log (table_name, operation, old_values, tenant_id, created_at)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD), OLD.tenant_id, NOW());
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name VARCHAR(255) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    old_values JSONB,
    new_values JSONB,
    tenant_id UUID,
    user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit.audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit.audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit.audit_log(created_at);

COMMENT ON DATABASE sparc_dev IS 'SPARC Development Database';
EOF
        log_success "Created database initialization script"
    fi
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose exec -T postgres pg_isready -U sparc_user -d sparc_dev >/dev/null 2>&1; then
            log_success "PostgreSQL is ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "PostgreSQL failed to start within expected time"
            exit 1
        fi
        
        log_info "Waiting for PostgreSQL... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    log_success "Database setup completed"
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations..."
    
    # Check if Prisma is available
    if [ "$PACKAGE_MANAGER" = "yarn" ]; then
        if yarn list --pattern prisma >/dev/null 2>&1; then
            yarn prisma generate
            yarn prisma db push
            log_success "Prisma migrations completed"
        else
            log_warning "Prisma not found, skipping migrations"
        fi
    else
        if npm list prisma >/dev/null 2>&1; then
            npx prisma generate
            npx prisma db push
            log_success "Prisma migrations completed"
        else
            log_warning "Prisma not found, skipping migrations"
        fi
    fi
}

# Setup MinIO buckets
setup_minio() {
    log_info "Setting up MinIO buckets..."
    
    # Wait for MinIO to be ready
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:9000/minio/health/live >/dev/null 2>&1; then
            log_success "MinIO is ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "MinIO failed to start within expected time"
            exit 1
        fi
        
        log_info "Waiting for MinIO... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    # Create buckets using MinIO client if available
    if command_exists mc; then
        mc alias set local http://localhost:9000 minioadmin minioadmin
        mc mb local/sparc-dev --ignore-existing
        mc mb local/sparc-videos --ignore-existing
        mc mb local/sparc-backups --ignore-existing
        log_success "MinIO buckets created"
    else
        log_warning "MinIO client (mc) not found, buckets will be created automatically by the application"
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    local directories=(
        "logs"
        "tmp/videos"
        "tmp/uploads"
        "tmp/exports"
        "data/backups"
        "data/certificates"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log_success "Created directory: $dir"
    done
}

# Setup Git hooks
setup_git_hooks() {
    log_info "Setting up Git hooks..."
    
    if [ -d .git ]; then
        if [ "$PACKAGE_MANAGER" = "yarn" ]; then
            yarn husky install
        else
            npx husky install
        fi
        log_success "Git hooks setup completed"
    else
        log_warning "Not a Git repository, skipping Git hooks setup"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    local errors=()
    
    # Check if services are running
    if ! docker-compose ps | grep -q "Up"; then
        errors+=("Docker services not running")
    fi
    
    # Check database connection
    if ! docker-compose exec -T postgres pg_isready -U sparc_user -d sparc_dev >/dev/null 2>&1; then
        errors+=("Cannot connect to PostgreSQL")
    fi
    
    # Check Redis connection
    if ! docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; then
        errors+=("Cannot connect to Redis")
    fi
    
    # Check MinIO connection
    if ! curl -f http://localhost:9000/minio/health/live >/dev/null 2>&1; then
        errors+=("Cannot connect to MinIO")
    fi
    
    if [ ${#errors[@]} -ne 0 ]; then
        log_error "Verification failed with errors:"
        for error in "${errors[@]}"; do
            log_error "  - $error"
        done
        exit 1
    fi
    
    log_success "Installation verification completed successfully"
}

# Print next steps
print_next_steps() {
    log_success "SPARC development environment setup completed!"
    echo
    log_info "Next steps:"
    echo "  1. Review and update the .env file with your specific configuration"
    echo "  2. Start the development server:"
    if [ "$PACKAGE_MANAGER" = "yarn" ]; then
        echo "     yarn dev"
    else
        echo "     npm run dev"
    fi
    echo "  3. Access the application:"
    echo "     - Web UI: http://localhost:3000"
    echo "     - API: http://localhost:3000/api"
    echo "     - MinIO Console: http://localhost:9001 (minioadmin/minioadmin)"
    echo "  4. View logs:"
    echo "     docker-compose logs -f"
    echo "  5. Stop services when done:"
    echo "     docker-compose down"
    echo
    log_info "For more information, see:"
    echo "  - CONTRIBUTING.md for development guidelines"
    echo "  - README.md for project overview"
    echo "  - docs/ directory for detailed documentation"
    echo
    log_success "Happy coding! 🚀"
}

# Main execution
main() {
    echo "=============================================="
    echo "  SPARC Development Environment Setup"
    echo "=============================================="
    echo
    
    # Change to script directory
    cd "$(dirname "$0")/.."
    
    check_prerequisites
    setup_environment
    install_dependencies
    create_directories
    start_local_services
    setup_database
    run_migrations
    setup_minio
    setup_git_hooks
    verify_installation
    print_next_steps
}

# Handle script interruption
trap 'log_error "Setup interrupted"; exit 1' INT TERM

# Run main function
main "$@"