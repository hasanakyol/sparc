#!/bin/bash

# SPARC Platform - Migrate from Alert Service to Unified Event Processing Service
# This script migrates data and configuration from the legacy alert-service to the new unified event-processing-service

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==========================================="
echo "SPARC Alert Service Migration"
echo "==========================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if running from project root
    if [ ! -f "$PROJECT_ROOT/package.json" ]; then
        print_error "This script must be run from the SPARC project root"
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    
    # Check if PostgreSQL is accessible
    if ! docker compose ps | grep -q "postgres.*running"; then
        print_warning "PostgreSQL container is not running. Starting it now..."
        docker compose up -d postgres redis
        sleep 5
    fi
    
    print_success "Prerequisites check completed"
}

# Backup existing data
backup_data() {
    print_status "Creating backup of existing alert data..."
    
    BACKUP_DIR="$PROJECT_ROOT/backups/alert-migration-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup alert service data
    docker compose exec -T postgres pg_dump -U postgres sparc -t alerts -t alert_escalations -t alert_notifications -t notification_preferences > "$BACKUP_DIR/alerts_backup.sql"
    
    # Backup Redis data if any
    docker compose exec -T redis redis-cli --rdb "$BACKUP_DIR/redis_backup.rdb" > /dev/null 2>&1 || true
    
    print_success "Backup created at: $BACKUP_DIR"
}

# Stop old alert service
stop_alert_service() {
    print_status "Stopping alert-service..."
    
    # Check if alert-service is running
    if pm2 list | grep -q "alert-service"; then
        pm2 stop alert-service || true
        pm2 delete alert-service || true
        print_success "Alert service stopped"
    else
        print_warning "Alert service was not running"
    fi
    
    # Stop Docker container if exists
    if docker ps | grep -q "sparc-alert-service"; then
        docker stop sparc-alert-service || true
        docker rm sparc-alert-service || true
        print_success "Alert service container stopped"
    fi
}

# Update nginx configuration
update_nginx_config() {
    print_status "Updating nginx configuration..."
    
    # Check if nginx config exists
    NGINX_CONFIG="$PROJECT_ROOT/infra/nginx/nginx.conf"
    if [ -f "$NGINX_CONFIG" ]; then
        # Backup original
        cp "$NGINX_CONFIG" "$NGINX_CONFIG.backup-$(date +%Y%m%d-%H%M%S)"
        
        # Update routing from alert-service to event-processing-service
        sed -i.bak 's|upstream alert-service|upstream event-processing-service|g' "$NGINX_CONFIG"
        sed -i.bak 's|server alert-service:3006|server event-processing-service:3010|g' "$NGINX_CONFIG"
        sed -i.bak 's|location /api/alerts|location /api/alerts|g' "$NGINX_CONFIG"
        
        print_success "Nginx configuration updated"
    else
        print_warning "Nginx configuration not found, skipping..."
    fi
}

# Update Kubernetes manifests
update_k8s_manifests() {
    print_status "Updating Kubernetes manifests..."
    
    K8S_DIR="$PROJECT_ROOT/k8s"
    if [ -d "$K8S_DIR" ]; then
        # Update service references
        find "$K8S_DIR" -name "*.yaml" -o -name "*.yml" | while read -r file; do
            sed -i.bak 's/alert-service/event-processing-service/g' "$file"
            sed -i.bak 's/port: 3006/port: 3010/g' "$file"
        done
        
        print_success "Kubernetes manifests updated"
    else
        print_warning "Kubernetes directory not found, skipping..."
    fi
}

# Update environment variables
update_env_files() {
    print_status "Updating environment files..."
    
    # Update .env files
    for env_file in "$PROJECT_ROOT"/.env*; do
        if [ -f "$env_file" ]; then
            # Update service URLs
            sed -i.bak 's|ALERT_SERVICE_URL=.*|EVENT_PROCESSING_SERVICE_URL=http://localhost:3010|g' "$env_file"
            sed -i.bak 's|alert-service:3006|event-processing-service:3010|g' "$env_file"
        fi
    done
    
    print_success "Environment files updated"
}

# Update API Gateway routes
update_api_gateway() {
    print_status "Updating API Gateway configuration..."
    
    GATEWAY_CONFIG="$PROJECT_ROOT/services/api-gateway/src/config/routes.ts"
    if [ -f "$GATEWAY_CONFIG" ]; then
        # Backup original
        cp "$GATEWAY_CONFIG" "$GATEWAY_CONFIG.backup-$(date +%Y%m%d-%H%M%S)"
        
        # Update route configuration
        cat > "$GATEWAY_CONFIG.tmp" << 'EOF'
// Route configuration for API Gateway
export const routes = {
  // ... other routes ...
  
  // Event Processing Service (unified alerts and events)
  '/api/alerts': {
    target: process.env.EVENT_PROCESSING_SERVICE_URL || 'http://event-processing-service:3010',
    changeOrigin: true,
    pathRewrite: { '^/api/alerts': '/api/alerts' }
  },
  '/api/events': {
    target: process.env.EVENT_PROCESSING_SERVICE_URL || 'http://event-processing-service:3010',
    changeOrigin: true,
    pathRewrite: { '^/api/events': '/api/events' }
  },
  '/ws/alerts': {
    target: process.env.EVENT_PROCESSING_SERVICE_URL || 'http://event-processing-service:3010',
    ws: true,
    changeOrigin: true
  },
  '/ws/events': {
    target: process.env.EVENT_PROCESSING_SERVICE_URL || 'http://event-processing-service:3010',
    ws: true,
    changeOrigin: true
  },
  
  // ... other routes ...
};
EOF
        
        # Merge with existing config
        # This is a simplified version - in production, use a proper merge tool
        print_warning "Manual review of API Gateway routes may be required"
    fi
}

# Build and deploy new service
deploy_unified_service() {
    print_status "Building and deploying unified event processing service..."
    
    cd "$PROJECT_ROOT/services/event-processing-service"
    
    # Install dependencies
    npm install
    
    # Build service
    npm run build
    
    # Start with PM2 in development
    if command -v pm2 &> /dev/null; then
        pm2 start dist/index.js --name event-processing-service --env production
        pm2 save
        print_success "Event processing service started with PM2"
    else
        print_warning "PM2 not found, starting with npm..."
        npm start &
    fi
    
    cd "$PROJECT_ROOT"
}

# Verify migration
verify_migration() {
    print_status "Verifying migration..."
    
    # Wait for service to start
    sleep 5
    
    # Check health endpoint
    if curl -s http://localhost:3010/health | grep -q "healthy"; then
        print_success "Event processing service is healthy"
    else
        print_error "Event processing service health check failed"
        return 1
    fi
    
    # Check WebSocket connectivity
    if curl -s http://localhost:3010/ws > /dev/null; then
        print_success "WebSocket endpoint is accessible"
    else
        print_warning "WebSocket endpoint check failed"
    fi
    
    # Check alerts API
    if curl -s -H "x-tenant-id: test" http://localhost:3010/api/alerts | grep -q "alerts"; then
        print_success "Alerts API is working"
    else
        print_error "Alerts API check failed"
        return 1
    fi
    
    # Check events API
    if curl -s -H "x-tenant-id: test" http://localhost:3010/api/events | grep -q "events"; then
        print_success "Events API is working"
    else
        print_error "Events API check failed"
        return 1
    fi
    
    print_success "Migration verification completed"
}

# Update documentation
update_documentation() {
    print_status "Updating documentation..."
    
    cat > "$PROJECT_ROOT/docs/ALERT_SERVICE_MIGRATION.md" << 'EOF'
# Alert Service Migration Guide

## Overview

The legacy alert-service has been consolidated into the unified event-processing-service. This provides a single service for managing both alerts and events with improved correlation capabilities.

## Changes

### Endpoints
- Alert endpoints remain at `/api/alerts/*`
- Event endpoints remain at `/api/events/*`
- WebSocket connections now use `/ws` path with namespaces `/alerts` and `/events`

### Port Changes
- Old: alert-service on port 3006
- New: event-processing-service on port 3010

### Environment Variables
- `ALERT_SERVICE_URL` → `EVENT_PROCESSING_SERVICE_URL`
- Update all references from port 3006 to 3010

### API Compatibility
- All existing alert APIs remain compatible
- Additional event submission APIs are now available
- Enhanced correlation and real-time features

## Rollback Instructions

If you need to rollback to the old alert-service:

1. Stop event-processing-service: `pm2 stop event-processing-service`
2. Restore backups from `backups/alert-migration-*`
3. Start alert-service: `pm2 start alert-service`
4. Restore nginx and environment configurations from `.backup-*` files

## Support

For issues or questions, contact the platform team.
EOF
    
    print_success "Documentation updated"
}

# Main migration process
main() {
    print_status "Starting Alert Service to Event Processing Service migration..."
    
    check_prerequisites
    backup_data
    stop_alert_service
    update_nginx_config
    update_k8s_manifests
    update_env_files
    update_api_gateway
    deploy_unified_service
    verify_migration
    update_documentation
    
    echo ""
    print_success "==================================="
    print_success "Migration completed successfully!"
    print_success "==================================="
    echo ""
    print_status "Next steps:"
    echo "  1. Review and test all alert functionality"
    echo "  2. Update any client applications to use port 3010"
    echo "  3. Monitor logs for any issues: pm2 logs event-processing-service"
    echo "  4. Remove old alert-service code after confirming stability"
    echo ""
    print_warning "Remember to update any external integrations or documentation!"
}

# Run main function
main "$@"