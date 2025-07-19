#!/bin/bash

# SPARC Performance Testing Environment Setup Script
# Creates an isolated environment for performance testing with realistic data volumes

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT_NAME="sparc-perf-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="/tmp/${ENVIRONMENT_NAME}-setup-${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DOCKER_COMPOSE_FILE="docker-compose.perf.yml"
POSTGRES_VERSION="15"
REDIS_VERSION="7"
ELASTICSEARCH_VERSION="8.11.0"
RABBITMQ_VERSION="3.12"
CLEANUP_ON_ERROR=true
SKIP_DATA_GENERATION=false
DATA_VOLUME="large" # small, medium, large
CONCURRENT_USERS=1000
VIDEO_STREAMS=100

# Performance test configuration
PERF_CONFIG_FILE="$PROJECT_ROOT/performance-config.yaml"

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

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

SPARC Performance Testing Environment Setup

Options:
    -n, --name NAME              Environment name (default: sparc-perf-test)
    -v, --volume SIZE            Data volume: small, medium, large (default: large)
    -u, --users COUNT            Concurrent users to simulate (default: 1000)
    -s, --streams COUNT          Video streams to simulate (default: 100)
    --skip-data                  Skip test data generation
    --no-cleanup                 Don't cleanup on error
    -h, --help                   Show this help message

Examples:
    # Setup large performance environment
    $0 --volume large --users 5000 --streams 500

    # Quick setup with minimal data
    $0 --volume small --skip-data

    # Custom environment name
    $0 --name my-perf-test --users 10000

EOF
    exit 0
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--name)
                ENVIRONMENT_NAME="$2"
                shift 2
                ;;
            -v|--volume)
                DATA_VOLUME="$2"
                shift 2
                ;;
            -u|--users)
                CONCURRENT_USERS="$2"
                shift 2
                ;;
            -s|--streams)
                VIDEO_STREAMS="$2"
                shift 2
                ;;
            --skip-data)
                SKIP_DATA_GENERATION=true
                shift
                ;;
            --no-cleanup)
                CLEANUP_ON_ERROR=false
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Cleanup function
cleanup() {
    if [ "$CLEANUP_ON_ERROR" = "true" ]; then
        log_warning "Cleaning up performance environment..."
        docker-compose -f "$PROJECT_ROOT/$DOCKER_COMPOSE_FILE" -p "$ENVIRONMENT_NAME" down -v || true
        rm -f "$PERF_CONFIG_FILE" || true
    fi
}

# Error handler
handle_error() {
    log_error "Setup failed!"
    cleanup
    exit 1
}

trap handle_error ERR

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    for tool in docker docker-compose jq curl psql redis-cli; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check available resources
    local available_memory=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
    local required_memory=$((8 * 1024 * 1024 * 1024)) # 8GB minimum
    
    if [ "$available_memory" -lt "$required_memory" ]; then
        log_warning "Docker has less than 8GB memory available. Performance tests may be limited."
    fi
    
    log_success "Prerequisites check passed"
}

# Create performance test configuration
create_perf_config() {
    log "Creating performance test configuration..."
    
    # Determine data volumes based on size
    case $DATA_VOLUME in
        small)
            local num_orgs=10
            local num_sites=50
            local num_zones=200
            local num_devices=1000
            local num_users=5000
            local num_events=100000
            ;;
        medium)
            local num_orgs=50
            local num_sites=500
            local num_zones=2000
            local num_devices=10000
            local num_users=50000
            local num_events=1000000
            ;;
        large)
            local num_orgs=100
            local num_sites=1000
            local num_zones=5000
            local num_devices=50000
            local num_users=100000
            local num_events=10000000
            ;;
        *)
            log_error "Invalid data volume: $DATA_VOLUME"
            exit 1
            ;;
    esac
    
    cat > "$PERF_CONFIG_FILE" << EOF
# SPARC Performance Test Configuration
# Generated: $(date)

environment:
  name: $ENVIRONMENT_NAME
  type: performance
  data_volume: $DATA_VOLUME

test_data:
  organizations: $num_orgs
  sites: $num_sites
  zones: $num_zones
  devices: $num_devices
  users: $num_users
  events: $num_events

performance_targets:
  concurrent_users: $CONCURRENT_USERS
  video_streams: $VIDEO_STREAMS
  api_requests_per_second: 10000
  event_ingestion_rate: 50000
  
  response_times:
    api_p50: 50ms
    api_p95: 200ms
    api_p99: 500ms
    video_latency: 500ms
    
  resource_limits:
    cpu_per_service: 2
    memory_per_service: 4Gi
    total_cpu: 32
    total_memory: 128Gi

infrastructure:
  postgres:
    version: $POSTGRES_VERSION
    resources:
      cpu: 4
      memory: 16Gi
    config:
      max_connections: 1000
      shared_buffers: 4GB
      work_mem: 16MB
      maintenance_work_mem: 512MB
      effective_cache_size: 12GB
      
  redis:
    version: $REDIS_VERSION
    resources:
      cpu: 2
      memory: 8Gi
    config:
      maxmemory: 6gb
      maxmemory-policy: allkeys-lru
      
  elasticsearch:
    version: $ELASTICSEARCH_VERSION
    resources:
      cpu: 4
      memory: 16Gi
    config:
      heap_size: 8g
      indices.memory.index_buffer_size: 30%
      
  rabbitmq:
    version: $RABBITMQ_VERSION
    resources:
      cpu: 2
      memory: 4Gi

monitoring:
  prometheus:
    retention: 7d
    scrape_interval: 15s
  grafana:
    dashboards:
      - performance-overview
      - service-metrics
      - infrastructure-metrics
      - api-performance
      - video-streaming
EOF
    
    log_success "Performance configuration created"
}

# Create Docker Compose file for performance environment
create_docker_compose() {
    log "Creating Docker Compose configuration..."
    
    cat > "$PROJECT_ROOT/$DOCKER_COMPOSE_FILE" << 'EOF'
version: '3.8'

services:
  # PostgreSQL with performance tuning
  postgres:
    image: postgres:${POSTGRES_VERSION:-15}
    container_name: ${ENVIRONMENT_NAME}-postgres
    environment:
      POSTGRES_DB: sparc_perf
      POSTGRES_USER: sparc
      POSTGRES_PASSWORD: sparc_perf_2024
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=en_US.UTF-8"
    command:
      - postgres
      - -c
      - max_connections=1000
      - -c
      - shared_buffers=4GB
      - -c
      - effective_cache_size=12GB
      - -c
      - maintenance_work_mem=512MB
      - -c
      - checkpoint_completion_target=0.9
      - -c
      - wal_buffers=16MB
      - -c
      - default_statistics_target=100
      - -c
      - random_page_cost=1.1
      - -c
      - effective_io_concurrency=200
      - -c
      - work_mem=16MB
      - -c
      - min_wal_size=1GB
      - -c
      - max_wal_size=4GB
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 16G
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sparc"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis with performance configuration
  redis:
    image: redis:${REDIS_VERSION:-7}-alpine
    container_name: ${ENVIRONMENT_NAME}-redis
    command:
      - redis-server
      - --maxmemory 6gb
      - --maxmemory-policy allkeys-lru
      - --save ""
      - --appendonly no
      - --tcp-backlog 511
      - --tcp-keepalive 60
      - --timeout 0
    ports:
      - "6379:6379"
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 8G
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Elasticsearch for event processing
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:${ELASTICSEARCH_VERSION:-8.11.0}
    container_name: ${ENVIRONMENT_NAME}-elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms8g -Xmx8g"
      - xpack.security.enabled=false
      - indices.memory.index_buffer_size=30%
      - indices.queries.cache.size=15%
      - indices.fielddata.cache.size=20%
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
      - "9300:9300"
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 16G
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:9200/_cluster/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5

  # RabbitMQ for message queuing
  rabbitmq:
    image: rabbitmq:${RABBITMQ_VERSION:-3.12}-management-alpine
    container_name: ${ENVIRONMENT_NAME}-rabbitmq
    environment:
      RABBITMQ_DEFAULT_USER: sparc
      RABBITMQ_DEFAULT_PASS: sparc_perf_2024
      RABBITMQ_VM_MEMORY_HIGH_WATERMARK: 0.8
    ports:
      - "5672:5672"
      - "15672:15672"
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

  # Prometheus for metrics collection
  prometheus:
    image: prom/prometheus:latest
    container_name: ${ENVIRONMENT_NAME}-prometheus
    volumes:
      - ./monitoring/prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=7d'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
    ports:
      - "9090:9090"
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G

  # Grafana for visualization
  grafana:
    image: grafana/grafana:latest
    container_name: ${ENVIRONMENT_NAME}-grafana
    environment:
      GF_SECURITY_ADMIN_PASSWORD: sparc_perf_2024
      GF_USERS_ALLOW_SIGN_UP: "false"
    volumes:
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning
      - ./monitoring/grafana/dashboards:/var/lib/grafana/dashboards
      - grafana_data:/var/lib/grafana
    ports:
      - "3001:3000"
    depends_on:
      - prometheus
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G

  # Load generator service
  load-generator:
    build:
      context: ./tests/performance
      dockerfile: Dockerfile.load-generator
    container_name: ${ENVIRONMENT_NAME}-load-generator
    environment:
      TARGET_URL: http://host.docker.internal:3000
      CONCURRENT_USERS: ${CONCURRENT_USERS:-1000}
      DURATION: ${TEST_DURATION:-3600}
      SCENARIO: ${TEST_SCENARIO:-mixed}
    volumes:
      - ./tests/performance/scenarios:/scenarios
      - ./reports/performance:/reports
    depends_on:
      - postgres
      - redis
      - elasticsearch
      - rabbitmq
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G

volumes:
  postgres_data:
  elasticsearch_data:
  rabbitmq_data:
  prometheus_data:
  grafana_data:

networks:
  default:
    name: ${ENVIRONMENT_NAME}-network
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/16
EOF
    
    log_success "Docker Compose configuration created"
}

# Start infrastructure services
start_infrastructure() {
    log "Starting infrastructure services..."
    
    cd "$PROJECT_ROOT"
    
    # Set environment variables
    export ENVIRONMENT_NAME
    export POSTGRES_VERSION
    export REDIS_VERSION
    export ELASTICSEARCH_VERSION
    export RABBITMQ_VERSION
    export CONCURRENT_USERS
    export VIDEO_STREAMS
    
    # Start services
    docker-compose -f "$DOCKER_COMPOSE_FILE" -p "$ENVIRONMENT_NAME" up -d \
        postgres redis elasticsearch rabbitmq prometheus grafana
    
    # Wait for services to be healthy
    log "Waiting for services to be healthy..."
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        local all_healthy=true
        
        for service in postgres redis elasticsearch rabbitmq; do
            if ! docker-compose -f "$DOCKER_COMPOSE_FILE" -p "$ENVIRONMENT_NAME" \
                ps "$service" | grep -q "healthy"; then
                all_healthy=false
                break
            fi
        done
        
        if [ "$all_healthy" = "true" ]; then
            log_success "All services are healthy"
            break
        fi
        
        attempt=$((attempt + 1))
        echo -n "."
        sleep 5
    done
    
    if [ $attempt -eq $max_attempts ]; then
        log_error "Services failed to become healthy"
        docker-compose -f "$DOCKER_COMPOSE_FILE" -p "$ENVIRONMENT_NAME" ps
        exit 1
    fi
}

# Generate test data
generate_test_data() {
    if [ "$SKIP_DATA_GENERATION" = "true" ]; then
        log_warning "Skipping test data generation"
        return
    fi
    
    log "Generating test data..."
    
    # Run data generation script
    if [ -f "$SCRIPT_DIR/generate-performance-data.ts" ]; then
        npx tsx "$SCRIPT_DIR/generate-performance-data.ts" \
            --config "$PERF_CONFIG_FILE" \
            --connection "postgresql://sparc:sparc_perf_2024@localhost:5432/sparc_perf" \
            || log_warning "Data generation script not found or failed"
    else
        log_warning "Data generation script not found. Please create test data manually."
    fi
    
    log_success "Test data generation completed"
}

# Configure monitoring
setup_monitoring() {
    log "Setting up performance monitoring..."
    
    # Create Prometheus configuration if it doesn't exist
    mkdir -p "$PROJECT_ROOT/monitoring/prometheus"
    
    if [ ! -f "$PROJECT_ROOT/monitoring/prometheus/prometheus.yml" ]; then
        cat > "$PROJECT_ROOT/monitoring/prometheus/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['host.docker.internal:9100']

  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['host.docker.internal:9187']

  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['host.docker.internal:9121']

  - job_name: 'sparc-services'
    static_configs:
      - targets: 
        - 'host.docker.internal:3000'  # API Gateway
        - 'host.docker.internal:3001'  # Auth Service
        - 'host.docker.internal:3002'  # Video Service
        - 'host.docker.internal:3010'  # Tenant Service
EOF
    fi
    
    # Create Grafana dashboards directory
    mkdir -p "$PROJECT_ROOT/monitoring/grafana/dashboards"
    mkdir -p "$PROJECT_ROOT/monitoring/grafana/provisioning/dashboards"
    mkdir -p "$PROJECT_ROOT/monitoring/grafana/provisioning/datasources"
    
    # Create datasource configuration
    cat > "$PROJECT_ROOT/monitoring/grafana/provisioning/datasources/prometheus.yml" << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF
    
    # Create dashboard provisioning
    cat > "$PROJECT_ROOT/monitoring/grafana/provisioning/dashboards/dashboards.yml" << 'EOF'
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
EOF
    
    log_success "Monitoring setup completed"
}

# Display environment information
display_info() {
    log_success "Performance environment setup completed!"
    
    echo
    echo "=== Environment Information ==="
    echo "Name: $ENVIRONMENT_NAME"
    echo "Data Volume: $DATA_VOLUME"
    echo "Concurrent Users: $CONCURRENT_USERS"
    echo "Video Streams: $VIDEO_STREAMS"
    echo
    echo "=== Service URLs ==="
    echo "PostgreSQL: postgresql://sparc:sparc_perf_2024@localhost:5432/sparc_perf"
    echo "Redis: redis://localhost:6379"
    echo "Elasticsearch: http://localhost:9200"
    echo "RabbitMQ Management: http://localhost:15672 (sparc/sparc_perf_2024)"
    echo "Prometheus: http://localhost:9090"
    echo "Grafana: http://localhost:3001 (admin/sparc_perf_2024)"
    echo
    echo "=== Next Steps ==="
    echo "1. Start SPARC services with performance configuration"
    echo "2. Run performance tests: npm run test:performance"
    echo "3. Monitor metrics in Grafana"
    echo "4. Analyze results in reports/performance/"
    echo
    echo "To tear down: docker-compose -f $DOCKER_COMPOSE_FILE -p $ENVIRONMENT_NAME down -v"
    echo
    echo "Log file: $LOG_FILE"
}

# Main execution
main() {
    log "Starting SPARC Performance Testing Environment Setup"
    
    parse_args "$@"
    check_prerequisites
    create_perf_config
    create_docker_compose
    setup_monitoring
    start_infrastructure
    generate_test_data
    display_info
}

# Run main function
main "$@"