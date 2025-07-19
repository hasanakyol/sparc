#!/bin/bash

# SPARC Performance Optimization Script
# This script applies all performance optimizations across the platform

set -euo pipefail

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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for required tools
    local required_tools=("node" "npm" "docker" "kubectl" "terraform" "rust" "wasm-pack")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is not installed. Please install it first."
            exit 1
        fi
    done
    
    # Check Node.js version
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        log_error "Node.js version 18 or higher is required"
        exit 1
    fi
    
    log_success "All prerequisites are met"
}

# Install dependencies
install_dependencies() {
    log_info "Installing performance optimization dependencies..."
    
    # Install global packages
    npm install -g @next/bundle-analyzer compression-webpack-plugin
    
    # Install project dependencies
    npm install --save \
        ioredis \
        lru-cache \
        compression \
        @hono/node-server \
        pg-pool \
        postgres
    
    # Install dev dependencies
    npm install --save-dev \
        webpack-bundle-analyzer \
        compression-webpack-plugin \
        @types/compression
    
    log_success "Dependencies installed"
}

# Build WebAssembly modules
build_wasm_modules() {
    log_info "Building WebAssembly modules..."
    
    cd packages/wasm/video-processor
    
    # Install Rust dependencies
    cargo update
    
    # Build with optimization
    wasm-pack build --target web --out-dir ../../../web/public/wasm -- --features wee_alloc
    
    # Optimize WASM file
    if command -v wasm-opt &> /dev/null; then
        wasm-opt -O4 --enable-simd \
            ../../../web/public/wasm/sparc_video_processor_bg.wasm \
            -o ../../../web/public/wasm/sparc_video_processor_bg.wasm
    fi
    
    cd ../../..
    log_success "WebAssembly modules built"
}

# Update Kubernetes configurations
update_kubernetes_configs() {
    log_info "Updating Kubernetes configurations..."
    
    # Apply HPA configurations
    kubectl apply -f k8s/performance/hpa-configs.yaml
    
    # Update resource limits for all deployments
    for deployment in $(kubectl get deployments -n sparc -o jsonpath='{.items[*].metadata.name}'); do
        kubectl patch deployment "$deployment" -n sparc --patch '
        {
          "spec": {
            "template": {
              "spec": {
                "containers": [{
                  "name": "'$deployment'",
                  "resources": {
                    "requests": {
                      "memory": "512Mi",
                      "cpu": "500m"
                    },
                    "limits": {
                      "memory": "2Gi",
                      "cpu": "2000m"
                    }
                  }
                }]
              }
            }
          }
        }'
    done
    
    log_success "Kubernetes configurations updated"
}

# Configure Redis cluster
configure_redis_cluster() {
    log_info "Configuring Redis cluster..."
    
    # Deploy Redis cluster if not exists
    if ! kubectl get statefulset redis-cluster -n sparc &> /dev/null; then
        cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
  namespace: sparc
spec:
  serviceName: redis-cluster
  replicas: 6
  selector:
    matchLabels:
      app: redis-cluster
  template:
    metadata:
      labels:
        app: redis-cluster
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command: ["redis-server"]
        args:
          - "--cluster-enabled yes"
          - "--cluster-config-file nodes.conf"
          - "--cluster-node-timeout 5000"
          - "--appendonly yes"
          - "--maxmemory 2gb"
          - "--maxmemory-policy allkeys-lru"
        ports:
        - containerPort: 6379
          name: client
        - containerPort: 16379
          name: gossip
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        volumeMounts:
        - name: data
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
EOF
    fi
    
    log_success "Redis cluster configured"
}

# Setup database optimizations
setup_database_optimizations() {
    log_info "Setting up database optimizations..."
    
    # Create indexes for common queries
    cat <<EOF > scripts/db-optimizations.sql
-- Performance indexes for common queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sites_organization_id ON sites(organization_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_zones_site_id ON zones(site_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cameras_zone_id ON cameras(zone_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_created_at ON events(created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_tenant_id_created_at ON events(tenant_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_status_created_at ON alerts(status, created_at DESC);

-- Partial indexes for active records
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_active ON users(id) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cameras_active ON cameras(id) WHERE status = 'active';

-- Composite indexes for complex queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_analytics_composite ON analytics(tenant_id, metric_type, timestamp DESC);

-- Enable query parallelization
ALTER DATABASE sparc SET max_parallel_workers_per_gather = 4;
ALTER DATABASE sparc SET max_parallel_workers = 8;
ALTER DATABASE sparc SET parallel_tuple_cost = 0.1;
ALTER DATABASE sparc SET parallel_setup_cost = 1000;

-- Update table statistics
ANALYZE;
EOF
    
    # Apply optimizations
    # Note: In production, run this against your actual database
    log_warning "Database optimization script created at scripts/db-optimizations.sql"
    log_warning "Please run this script against your database manually"
    
    log_success "Database optimization setup complete"
}

# Configure CDN
configure_cdn() {
    log_info "Configuring CDN..."
    
    # Apply Terraform CDN module
    cd infra/terraform
    terraform init -upgrade
    terraform plan -target=module.cdn -out=cdn.tfplan
    
    log_warning "CDN configuration planned. Review the plan and apply with:"
    log_warning "cd infra/terraform && terraform apply cdn.tfplan"
    
    cd ../..
    log_success "CDN configuration prepared"
}

# Update Next.js configuration
update_nextjs_config() {
    log_info "Updating Next.js configuration..."
    
    # Backup existing config
    cp web/next.config.js web/next.config.js.backup
    
    # Copy optimized config
    cp web/next.config.performance.js web/next.config.js
    
    log_success "Next.js configuration updated"
}

# Setup monitoring dashboards
setup_monitoring() {
    log_info "Setting up performance monitoring..."
    
    # Create ConfigMap for Grafana dashboard
    kubectl create configmap grafana-performance-dashboard \
        --from-file=monitoring/grafana/dashboards/performance-dashboard.json \
        -n monitoring \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Restart Grafana to load new dashboard
    kubectl rollout restart deployment/grafana -n monitoring
    
    log_success "Monitoring dashboards configured"
}

# Build and deploy optimized services
build_and_deploy() {
    log_info "Building optimized services..."
    
    # Build all services with production optimizations
    npm run build
    
    # Build Docker images with multi-stage builds
    docker-compose build --parallel
    
    # Tag and push images (update with your registry)
    # docker tag sparc/api-gateway:latest your-registry/sparc/api-gateway:optimized
    # docker push your-registry/sparc/api-gateway:optimized
    
    log_success "Services built with optimizations"
}

# Run performance tests
run_performance_tests() {
    log_info "Running performance tests..."
    
    # Install Artillery if not present
    if ! command -v artillery &> /dev/null; then
        npm install -g artillery
    fi
    
    # Run load tests
    artillery run tests/performance/load-test.yml
    
    log_success "Performance tests completed"
}

# Main execution
main() {
    log_info "Starting SPARC performance optimization..."
    
    check_prerequisites
    install_dependencies
    build_wasm_modules
    update_kubernetes_configs
    configure_redis_cluster
    setup_database_optimizations
    configure_cdn
    update_nextjs_config
    setup_monitoring
    build_and_deploy
    
    log_success "Performance optimizations applied successfully!"
    log_info "Next steps:"
    log_info "1. Review and apply database optimizations: psql -f scripts/db-optimizations.sql"
    log_info "2. Apply CDN configuration: cd infra/terraform && terraform apply cdn.tfplan"
    log_info "3. Deploy optimized services to your cluster"
    log_info "4. Run performance tests: artillery run tests/performance/load-test.yml"
    log_info "5. Monitor performance in Grafana dashboard"
}

# Run main function
main "$@"