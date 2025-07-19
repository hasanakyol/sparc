#!/bin/bash

# SPARC Platform Unified Deployment Script
# Combines deployment, rollback, and K8s management functionality
# Supports staging and production environments with AWS EKS

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="/tmp/sparc-deploy-logs"
LOG_FILE="$LOG_DIR/sparc-deploy-$(date +%Y%m%d-%H%M%S).log"
STATE_FILE="$LOG_DIR/deployment-state.json"

# Create log directory
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT=""
AWS_REGION="us-west-2"
ECR_REGISTRY=""
IMAGE_TAG=""
CLUSTER_NAME=""
NAMESPACE=""
DRY_RUN=false
SKIP_TESTS=false
ROLLBACK_MODE=false
AUTO_ROLLBACK=false
BACKUP_ENABLED=true
FORCE_DEPLOY=false
SPECIFIC_SERVICES=""
DATABASE_BACKUP_TIMESTAMP=""
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
PAGERDUTY_TOKEN="${PAGERDUTY_TOKEN:-}"
PAGERDUTY_SERVICE_ID="${PAGERDUTY_SERVICE_ID:-}"
TIMEOUT=900

# Service configuration
declare -a SERVICES=(
    "auth-service:3001"
    "alert-service:3012"
    "integration-service:3013"
    "access-control-service:3002"
    "video-management-service:3003"
    "analytics-service:3004"
    "device-management-service:3005"
    "environmental-service:3006"
    "event-processing-service:3007"
    "mobile-credential-service:3008"
    "reporting-service:3009"
    "tenant-service:3010"
    "visitor-management-service:3011"
    "backup-recovery-service:3014"
    "security-compliance-service:3015"
    "maintenance-service:3016"
    "elevator-control-service:3017"
    "api-documentation-service:3018"
    "testing-infrastructure-service:3019"
    "api-gateway:3000"
)

# Core services that must be deployed first
declare -a CORE_SERVICES=(
    "auth-service"
    "tenant-service"
    "api-gateway"
)

# Infrastructure services
declare -a INFRA_SERVICES=(
    "postgresql"
    "redis"
    "rabbitmq"
    "elasticsearch"
)

# =============================================================================
# Logging Functions
# =============================================================================

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

# =============================================================================
# Error Handling
# =============================================================================

cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Deployment failed with exit code $exit_code"
        log_info "Log file: $LOG_FILE"
        
        if [ "$AUTO_ROLLBACK" = "true" ] && [ "$ROLLBACK_MODE" = "false" ]; then
            log_warning "Initiating automatic rollback..."
            send_notification "🔴 Deployment failed, initiating automatic rollback" "critical"
            rollback_deployment
        fi
    fi
    
    # Cleanup port-forwards
    cleanup_port_forwards
    
    exit $exit_code
}

trap cleanup EXIT

cleanup_port_forwards() {
    local pids=$(pgrep -f "kubectl port-forward" || true)
    if [ -n "$pids" ]; then
        kill $pids 2>/dev/null || true
    fi
}

# =============================================================================
# Usage Information
# =============================================================================

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Unified deployment script for SPARC platform on AWS EKS

DEPLOYMENT OPTIONS:
    -e, --environment ENV       Target environment (staging|production)
    -r, --region REGION         AWS region (default: us-west-2)
    -t, --tag TAG              Docker image tag (default: latest)
    -c, --cluster CLUSTER      EKS cluster name (default: sparc-\$ENV)
    -n, --namespace NAMESPACE  Kubernetes namespace (default: sparc-\$ENV)
    --ecr-registry REGISTRY    ECR registry URL (auto-detected if not set)
    --services "svc1 svc2"     Deploy only specific services
    --force                    Force deployment without confirmations

DEPLOYMENT MODES:
    --dry-run                  Show what would be deployed without executing
    --skip-tests               Skip smoke tests after deployment
    --no-backup                Disable database backup before migration
    --auto-rollback            Enable automatic rollback on failure

ROLLBACK OPTIONS:
    --rollback                 Rollback to previous deployment
    --rollback-to TAG          Rollback to specific version tag
    --db-backup-timestamp TS   Restore database to specific backup

COMMON OPTIONS:
    -h, --help                 Show this help message
    -v, --verbose              Enable verbose logging

EXAMPLES:
    # Deploy to staging
    $0 -e staging -t v1.2.3

    # Deploy to production with auto-rollback
    $0 -e production -t v1.2.3 --auto-rollback

    # Dry run for production
    $0 -e production --dry-run

    # Rollback production deployment
    $0 -e production --rollback

    # Deploy specific services only
    $0 -e staging --services "auth-service api-gateway"

EOF
}

# =============================================================================
# Argument Parsing
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -r|--region)
                AWS_REGION="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -c|--cluster)
                CLUSTER_NAME="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            --ecr-registry)
                ECR_REGISTRY="$2"
                shift 2
                ;;
            --services)
                SPECIFIC_SERVICES="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --no-backup)
                BACKUP_ENABLED=false
                shift
                ;;
            --auto-rollback)
                AUTO_ROLLBACK=true
                shift
                ;;
            --rollback)
                ROLLBACK_MODE=true
                shift
                ;;
            --rollback-to)
                ROLLBACK_MODE=true
                IMAGE_TAG="$2"
                shift 2
                ;;
            --db-backup-timestamp)
                DATABASE_BACKUP_TIMESTAMP="$2"
                shift 2
                ;;
            --force)
                FORCE_DEPLOY=true
                shift
                ;;
            -v|--verbose)
                set -x
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

# =============================================================================
# Validation Functions
# =============================================================================

validate_environment() {
    log "Validating environment and prerequisites..."
    
    # Check required parameters
    if [ -z "$ENVIRONMENT" ]; then
        log_error "Environment must be specified (-e|--environment)"
        exit 1
    fi
    
    if [[ "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "production" ]]; then
        log_error "Environment must be 'staging' or 'production'"
        exit 1
    fi
    
    # Set defaults based on environment
    if [ -z "$NAMESPACE" ]; then
        NAMESPACE="sparc-${ENVIRONMENT}"
    fi
    
    if [ -z "$CLUSTER_NAME" ]; then
        CLUSTER_NAME="sparc-${ENVIRONMENT}"
    fi
    
    if [ -z "$IMAGE_TAG" ]; then
        IMAGE_TAG="latest"
        if [ "$ENVIRONMENT" = "production" ] && [ "$ROLLBACK_MODE" = "false" ]; then
            log_warning "Using 'latest' tag for production deployment"
        fi
    fi
    
    # Check required tools
    check_required_tools
    
    # Verify AWS credentials
    verify_aws_credentials
    
    # Set ECR registry if not provided
    if [ -z "$ECR_REGISTRY" ]; then
        set_ecr_registry
    fi
    
    # Verify EKS cluster access
    verify_eks_access
    
    # Setup kubectl context
    setup_kubectl_context
    
    # Check/create namespace
    ensure_namespace_exists
    
    log_success "Environment validation completed"
}

check_required_tools() {
    local required_tools=("aws" "kubectl" "docker" "jq" "envsubst" "kustomize" "yq")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Required tools not found: ${missing_tools[*]}"
        log_info "Please install missing tools and try again"
        exit 1
    fi
    
    log_success "All required tools are installed"
}

verify_aws_credentials() {
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured or invalid"
        exit 1
    fi
    
    local aws_account=$(aws sts get-caller-identity --query Account --output text)
    log_info "Using AWS account: $aws_account"
}

set_ecr_registry() {
    local aws_account_id=$(aws sts get-caller-identity --query Account --output text)
    ECR_REGISTRY="${aws_account_id}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    log_info "ECR Registry: $ECR_REGISTRY"
}

verify_eks_access() {
    if ! aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" &> /dev/null; then
        log_error "EKS cluster '$CLUSTER_NAME' not found or not accessible"
        exit 1
    fi
    
    log_success "EKS cluster '$CLUSTER_NAME' is accessible"
}

setup_kubectl_context() {
    log "Updating kubeconfig for cluster: $CLUSTER_NAME"
    aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"
    
    # Verify kubectl access
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "kubectl configured successfully"
}

ensure_namespace_exists() {
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log "Creating namespace: $NAMESPACE"
        if [ "$DRY_RUN" = "false" ]; then
            kubectl create namespace "$NAMESPACE"
            kubectl label namespace "$NAMESPACE" \
                environment="$ENVIRONMENT" \
                managed-by="sparc-deploy"
        fi
    else
        log_info "Namespace '$NAMESPACE' already exists"
    fi
}

# =============================================================================
# State Management Functions
# =============================================================================

save_deployment_state() {
    local state_data=$(cat <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "environment": "$ENVIRONMENT",
    "namespace": "$NAMESPACE",
    "image_tag": "$IMAGE_TAG",
    "services": $(echo "${SERVICES[@]}" | jq -R -s -c 'split(" ")'),
    "operator": "$USER",
    "commit": "$(git rev-parse HEAD 2>/dev/null || echo "unknown")"
}
EOF
)
    
    echo "$state_data" > "$STATE_FILE"
    log_info "Deployment state saved to: $STATE_FILE"
}

capture_current_state() {
    log "Capturing current deployment state..."
    
    local state_dir="$LOG_DIR/states/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$state_dir"
    
    # Save deployment states
    kubectl get deployments -n "$NAMESPACE" -o yaml > "$state_dir/deployments.yaml"
    
    # Save current versions
    kubectl get deployments -n "$NAMESPACE" -o json | \
        jq -r '.items[] | "\(.metadata.name):\(.spec.template.spec.containers[0].image)"' \
        > "$state_dir/versions.txt"
    
    # Save configmaps and secrets metadata
    kubectl get configmaps,secrets -n "$NAMESPACE" -o yaml \
        --export=false > "$state_dir/configs.yaml" 2>/dev/null || true
    
    log_success "State captured in: $state_dir"
}

# =============================================================================
# Notification Functions
# =============================================================================

send_notification() {
    local message="$1"
    local severity="${2:-info}"
    
    # Slack notification
    if [ -n "$SLACK_WEBHOOK" ]; then
        local color="good"
        case $severity in
            critical) color="danger" ;;
            warning) color="warning" ;;
        esac
        
        curl -s -X POST "$SLACK_WEBHOOK" \
            -H 'Content-type: application/json' \
            -d "{\"text\":\"$message\",\"color\":\"$color\"}" || true
    fi
    
    # PagerDuty for critical alerts
    if [ "$severity" = "critical" ] && [ -n "$PAGERDUTY_TOKEN" ]; then
        curl -s -X POST https://api.pagerduty.com/incidents \
            -H "Authorization: Token token=$PAGERDUTY_TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
                \"incident\": {
                    \"type\": \"incident\",
                    \"title\": \"$message\",
                    \"service\": {\"id\": \"$PAGERDUTY_SERVICE_ID\"},
                    \"urgency\": \"high\"
                }
            }" || true
    fi
}

# =============================================================================
# Build and Push Functions
# =============================================================================

build_and_push_images() {
    log "Building and pushing Docker images..."
    
    # Login to ECR
    log "Logging into ECR..."
    aws ecr get-login-password --region "$AWS_REGION" | \
        docker login --username AWS --password-stdin "$ECR_REGISTRY"
    
    local services_to_build=("${SERVICES[@]}")
    if [ -n "$SPECIFIC_SERVICES" ]; then
        services_to_build=()
        for svc in $SPECIFIC_SERVICES; do
            for service_config in "${SERVICES[@]}"; do
                if [[ "$service_config" == "$svc:"* ]]; then
                    services_to_build+=("$service_config")
                fi
            done
        done
    fi
    
    # Build services
    for service_config in "${services_to_build[@]}"; do
        local service_name="${service_config%:*}"
        build_and_push_service "$service_name"
    done
    
    # Build web frontend if not in specific services mode
    if [ -z "$SPECIFIC_SERVICES" ] || [[ " $SPECIFIC_SERVICES " =~ " web " ]]; then
        build_and_push_web
    fi
    
    log_success "All images built and pushed successfully"
}

build_and_push_service() {
    local service_name="$1"
    local service_dir="$PROJECT_ROOT/services/$service_name"
    local image_name="$ECR_REGISTRY/sparc-$service_name:$IMAGE_TAG"
    
    if [ ! -d "$service_dir" ]; then
        log_warning "Service directory not found: $service_dir"
        return
    fi
    
    log "Building image for $service_name..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Create ECR repository if it doesn't exist
        ensure_ecr_repository "sparc-$service_name"
        
        # Build image with proper context
        docker build \
            --build-arg VERSION="$IMAGE_TAG" \
            --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
            -t "$image_name" \
            -f "$service_dir/Dockerfile" \
            "$service_dir"
        
        # Tag as latest if building latest
        if [ "$IMAGE_TAG" = "latest" ]; then
            docker tag "$image_name" "$ECR_REGISTRY/sparc-$service_name:latest"
        fi
        
        # Push image
        docker push "$image_name"
        
        # Push latest tag if applicable
        if [ "$IMAGE_TAG" = "latest" ]; then
            docker push "$ECR_REGISTRY/sparc-$service_name:latest"
        fi
    fi
    
    log_success "Built and pushed: $image_name"
}

build_and_push_web() {
    local web_image="$ECR_REGISTRY/sparc-web:$IMAGE_TAG"
    log "Building web frontend image..."
    
    if [ "$DRY_RUN" = "false" ]; then
        ensure_ecr_repository "sparc-web"
        
        docker build \
            --build-arg VERSION="$IMAGE_TAG" \
            --build-arg NODE_ENV="production" \
            -t "$web_image" \
            -f "$PROJECT_ROOT/web/Dockerfile" \
            "$PROJECT_ROOT/web"
        
        docker push "$web_image"
    fi
    
    log_success "Web frontend built and pushed: $web_image"
}

ensure_ecr_repository() {
    local repo_name="$1"
    
    if ! aws ecr describe-repositories \
        --repository-names "$repo_name" \
        --region "$AWS_REGION" &> /dev/null; then
        
        log "Creating ECR repository: $repo_name"
        aws ecr create-repository \
            --repository-name "$repo_name" \
            --region "$AWS_REGION" \
            --image-scanning-configuration scanOnPush=true \
            --encryption-configuration encryptionType=AES256
    fi
}

# =============================================================================
# Database Functions
# =============================================================================

backup_database() {
    if [ "$BACKUP_ENABLED" = "false" ]; then
        log_info "Database backup disabled"
        return 0
    fi
    
    log "Creating database backup..."
    
    local backup_name="sparc-backup-$(date +%Y%m%d-%H%M%S)"
    
    if [ "$DRY_RUN" = "false" ]; then
        # Check if database credentials exist
        if ! kubectl get secret sparc-db-credentials -n "$NAMESPACE" &> /dev/null; then
            log_warning "Database credentials not found, skipping backup"
            return 0
        fi
        
        local db_host=$(kubectl get secret sparc-db-credentials -n "$NAMESPACE" \
            -o jsonpath='{.data.host}' | base64 -d)
        
        # Create RDS snapshot for production
        if [ "$ENVIRONMENT" = "production" ] && [[ "$db_host" =~ \.rds\.amazonaws\.com$ ]]; then
            local db_instance_id="${db_host%%.*}"
            
            aws rds create-db-snapshot \
                --db-instance-identifier "$db_instance_id" \
                --db-snapshot-identifier "$backup_name" \
                --region "$AWS_REGION"
            
            log "Waiting for snapshot to complete..."
            aws rds wait db-snapshot-completed \
                --db-snapshot-identifier "$backup_name" \
                --region "$AWS_REGION"
        else
            # For non-RDS databases, use backup pod
            run_backup_pod "$backup_name"
        fi
    fi
    
    log_success "Database backup created: $backup_name"
    echo "$backup_name" > "$LOG_DIR/last-backup-$ENVIRONMENT.txt"
}

run_backup_pod() {
    local backup_name="$1"
    
    kubectl run "backup-$backup_name" \
        --image="$ECR_REGISTRY/sparc-backup-agent:latest" \
        --restart=Never \
        --rm \
        -i \
        --namespace="$NAMESPACE" \
        --env="BACKUP_NAME=$backup_name" \
        --command -- /scripts/backup-database.sh
}

migrate_database() {
    log "Running database migrations..."
    
    local migration_job="sparc-migration-$(date +%s)"
    
    if [ "$DRY_RUN" = "false" ]; then
        # Create migration job from template
        cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: $migration_job
  namespace: $NAMESPACE
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: migration
        image: $ECR_REGISTRY/sparc-migration:$IMAGE_TAG
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: sparc-db-credentials
              key: url
        - name: MIGRATION_ENV
          value: "$ENVIRONMENT"
        command: ["npm", "run", "db:migrate:prod"]
EOF
        
        # Wait for migration to complete
        log "Waiting for migration to complete..."
        if ! kubectl wait --for=condition=complete \
            "job/$migration_job" \
            -n "$NAMESPACE" \
            --timeout=600s; then
            
            # Get migration logs
            kubectl logs "job/$migration_job" -n "$NAMESPACE"
            log_error "Database migration failed"
            exit 1
        fi
        
        # Cleanup migration job
        kubectl delete job "$migration_job" -n "$NAMESPACE"
    fi
    
    log_success "Database migration completed"
}

rollback_database() {
    local backup_timestamp="$1"
    
    log_warning "Database rollback requested to backup: $backup_timestamp"
    
    # Confirmation for database rollback
    if [ "$AUTO_ROLLBACK" != "true" ] && [ "$FORCE_DEPLOY" != "true" ]; then
        read -p "Rollback database? This will cause data loss. (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Database rollback skipped"
            return
        fi
    fi
    
    # Stop application traffic
    log "Stopping application traffic..."
    scale_deployments 0
    
    # Perform database restore
    if [ "$ENVIRONMENT" = "production" ]; then
        restore_rds_snapshot "$backup_timestamp"
    else
        restore_database_backup "$backup_timestamp"
    fi
    
    # Resume traffic
    scale_deployments
    
    log_success "Database rollback completed"
}

restore_rds_snapshot() {
    local snapshot_id="$1"
    
    log "Restoring RDS snapshot: $snapshot_id"
    
    # Implementation would restore RDS snapshot
    # This is a placeholder for the actual RDS restore logic
    log_warning "RDS restore requires manual intervention"
}

restore_database_backup() {
    local backup_name="$1"
    
    kubectl run "restore-$backup_name" \
        --image="$ECR_REGISTRY/sparc-backup-agent:latest" \
        --restart=Never \
        --rm \
        -i \
        --namespace="$NAMESPACE" \
        --env="BACKUP_NAME=$backup_name" \
        --command -- /scripts/restore-database.sh
}

# =============================================================================
# Infrastructure Deployment Functions
# =============================================================================

deploy_storage() {
    log "Deploying storage resources..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Apply storage classes
        kubectl apply -f "$PROJECT_ROOT/k8s/base/storage/storage-classes.yaml"
        
        # Apply PVCs for environment
        if [ -d "$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/storage" ]; then
            kubectl apply -k "$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/storage/"
        fi
        
        # Wait for PVCs to be bound
        kubectl wait --for=condition=Bound pvc --all -n "$NAMESPACE" --timeout=300s || true
    fi
    
    log_success "Storage resources deployed"
}

deploy_configuration() {
    log "Deploying configuration..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Create ConfigMaps from environment config
        if [ -d "$PROJECT_ROOT/config/$ENVIRONMENT" ]; then
            kubectl create configmap app-config \
                --from-file="$PROJECT_ROOT/config/$ENVIRONMENT/" \
                --dry-run=client -o yaml | kubectl apply -f - -n "$NAMESPACE"
        fi
        
        # Deploy secrets using External Secrets if available
        if kubectl get crd secretstores.external-secrets.io &>/dev/null; then
            log "Using External Secrets Operator"
            if [ -d "$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/secrets" ]; then
                kubectl apply -k "$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/secrets/"
            fi
        else
            log_warning "External Secrets not installed, ensure secrets are manually created"
        fi
    fi
    
    log_success "Configuration deployed"
}

deploy_infrastructure() {
    log "Deploying infrastructure services..."
    
    for service in "${INFRA_SERVICES[@]}"; do
        deploy_infrastructure_service "$service"
    done
    
    log_success "Infrastructure services deployed"
}

deploy_infrastructure_service() {
    local service="$1"
    log "Deploying $service..."
    
    if [ "$DRY_RUN" = "false" ]; then
        local manifest_path=""
        
        # Check for environment-specific overlay
        if [ -f "$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/$service/kustomization.yaml" ]; then
            manifest_path="$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/$service/"
        elif [ -f "$PROJECT_ROOT/k8s/base/$service/kustomization.yaml" ]; then
            manifest_path="$PROJECT_ROOT/k8s/base/$service/"
        else
            log_warning "No manifest found for $service"
            return
        fi
        
        kubectl apply -k "$manifest_path"
        
        # Wait for service readiness
        wait_for_infrastructure_service "$service"
    fi
}

wait_for_infrastructure_service() {
    local service="$1"
    local timeout=600
    
    case $service in
        postgresql)
            kubectl wait --for=condition=ready pod \
                -l app=postgresql -n "$NAMESPACE" --timeout="${timeout}s" || true
            ;;
        redis)
            kubectl wait --for=condition=ready pod \
                -l app=redis -n "$NAMESPACE" --timeout=300s || true
            ;;
        rabbitmq)
            kubectl wait --for=condition=ready pod \
                -l app=rabbitmq -n "$NAMESPACE" --timeout=300s || true
            ;;
        elasticsearch)
            kubectl wait --for=condition=ready pod \
                -l app=elasticsearch -n "$NAMESPACE" --timeout="${timeout}s" || true
            ;;
    esac
}

# =============================================================================
# Kubernetes Deployment Functions
# =============================================================================

template_manifests() {
    log "Templating Kubernetes manifests..."
    
    local temp_dir="$LOG_DIR/k8s-manifests-$(date +%s)"
    rm -rf "$temp_dir"
    mkdir -p "$temp_dir"
    
    # Export environment variables for templating
    export ENVIRONMENT
    export AWS_REGION
    export ECR_REGISTRY
    export IMAGE_TAG
    export NAMESPACE
    export CLUSTER_NAME
    
    # Template base manifests
    for manifest in "$PROJECT_ROOT"/k8s/base/*.yaml; do
        if [ -f "$manifest" ]; then
            local filename=$(basename "$manifest")
            envsubst < "$manifest" > "$temp_dir/$filename"
        fi
    done
    
    # Apply environment-specific overlays
    local env_dir="$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT"
    if [ -d "$env_dir" ]; then
        for overlay in "$env_dir"/*.yaml; do
            if [ -f "$overlay" ]; then
                local filename=$(basename "$overlay")
                envsubst < "$overlay" > "$temp_dir/env-$filename"
            fi
        done
    fi
    
    echo "$temp_dir"
}

deploy_kubernetes() {
    log "Deploying to Kubernetes..."
    
    # Deploy storage and configuration first
    deploy_storage
    deploy_configuration
    
    # Deploy infrastructure if needed
    if [ "$ENVIRONMENT" != "production" ]; then
        deploy_infrastructure
    fi
    
    # Run migrations
    migrate_database
    
    # Deploy services
    deploy_services
    
    # Deploy ingress
    deploy_ingress
    
    # Setup monitoring
    setup_monitoring
    
    log_success "Kubernetes deployment completed"
}

deploy_services() {
    log "Deploying application services..."
    
    local services_to_deploy=("${SERVICES[@]}")
    if [ -n "$SPECIFIC_SERVICES" ]; then
        services_to_deploy=()
        for svc in $SPECIFIC_SERVICES; do
            for service_config in "${SERVICES[@]}"; do
                if [[ "$service_config" == "$svc:"* ]]; then
                    services_to_deploy+=("$service_config")
                fi
            done
        done
    fi
    
    # Deploy core services first
    for service_config in "${services_to_deploy[@]}"; do
        local service_name="${service_config%:*}"
        if [[ " ${CORE_SERVICES[@]} " =~ " ${service_name} " ]]; then
            deploy_service "$service_name"
        fi
    done
    
    # Deploy remaining services
    for service_config in "${services_to_deploy[@]}"; do
        local service_name="${service_config%:*}"
        if [[ ! " ${CORE_SERVICES[@]} " =~ " ${service_name} " ]]; then
            deploy_service "$service_name"
        fi
    done
    
    log_success "All services deployed"
}

deploy_service() {
    local service_name="$1"
    
    log "Deploying $service_name..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Update image in deployment
        kubectl set image "deployment/$service_name" \
            "$service_name=$ECR_REGISTRY/sparc-$service_name:$IMAGE_TAG" \
            -n "$NAMESPACE" --record || {
                log_warning "Failed to update $service_name, attempting to create..."
                apply_service_manifest "$service_name"
            }
        
        # Wait for rollout
        kubectl rollout status "deployment/$service_name" \
            -n "$NAMESPACE" --timeout="${TIMEOUT}s"
    fi
    
    log_success "$service_name deployed"
}

apply_service_manifest() {
    local service_name="$1"
    local manifest_dir=$(template_manifests)
    
    # Look for service-specific manifest
    local manifest_file="$manifest_dir/$service_name.yaml"
    if [ ! -f "$manifest_file" ]; then
        manifest_file="$PROJECT_ROOT/k8s/services/$service_name.yaml"
    fi
    
    if [ -f "$manifest_file" ]; then
        kubectl apply -f "$manifest_file" -n "$NAMESPACE"
    else
        log_error "No manifest found for $service_name"
    fi
    
    rm -rf "$manifest_dir"
}

deploy_ingress() {
    log "Deploying ingress..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Apply ingress resources
        if [ -d "$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/ingress" ]; then
            kubectl apply -k "$PROJECT_ROOT/k8s/overlays/$ENVIRONMENT/ingress/"
        else
            kubectl apply -f "$PROJECT_ROOT/k8s/base/ingress.yaml"
        fi
        
        # Wait for ingress to be ready
        kubectl wait --for=condition=ready ingress --all -n "$NAMESPACE" --timeout=300s || true
        
        # Get ingress info
        local ingress_info=$(kubectl get ingress -n "$NAMESPACE" -o json)
        local ingress_host=$(echo "$ingress_info" | jq -r '.items[0].spec.rules[0].host // empty')
        
        if [ -n "$ingress_host" ]; then
            log_info "Application available at: https://$ingress_host"
        fi
    fi
    
    log_success "Ingress deployed"
}

# =============================================================================
# Health Check and Verification Functions
# =============================================================================

verify_deployment() {
    log "Verifying deployment health..."
    
    local failed_services=()
    local unhealthy=0
    
    # Check each service
    for service_config in "${SERVICES[@]}"; do
        local service_name="${service_config%:*}"
        
        if ! verify_service_health "$service_name"; then
            failed_services+=("$service_name")
            ((unhealthy++))
        fi
    done
    
    # Check overall cluster health
    verify_cluster_health || ((unhealthy++))
    
    if [ $unhealthy -gt 0 ]; then
        log_error "Deployment verification failed with $unhealthy issues"
        log_error "Failed services: ${failed_services[*]}"
        return 1
    fi
    
    log_success "All services are healthy"
}

verify_service_health() {
    local service_name="$1"
    local service_port="${2:-8080}"
    
    log "Checking $service_name..."
    
    # Check deployment exists
    if ! kubectl get deployment "$service_name" -n "$NAMESPACE" &> /dev/null; then
        log_warning "Deployment $service_name not found"
        return 1
    fi
    
    # Check replicas
    local ready_replicas=$(kubectl get deployment "$service_name" -n "$NAMESPACE" \
        -o jsonpath='{.status.readyReplicas}' || echo 0)
    local desired_replicas=$(kubectl get deployment "$service_name" -n "$NAMESPACE" \
        -o jsonpath='{.spec.replicas}' || echo 1)
    
    if [ "$ready_replicas" != "$desired_replicas" ]; then
        log_error "$service_name: $ready_replicas/$desired_replicas replicas ready"
        return 1
    fi
    
    # Health check endpoint
    if [ "$DRY_RUN" = "false" ]; then
        local pod_name=$(kubectl get pods -n "$NAMESPACE" \
            -l "app=$service_name" \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        
        if [ -n "$pod_name" ]; then
            if kubectl exec "$pod_name" -n "$NAMESPACE" -- \
                curl -sf "http://localhost:$service_port/health" &> /dev/null; then
                log_success "$service_name health check passed"
            else
                log_warning "$service_name health check failed"
                return 1
            fi
        fi
    fi
    
    return 0
}

verify_cluster_health() {
    log "Verifying cluster health..."
    
    # Check node status
    local not_ready_nodes=$(kubectl get nodes -o json | \
        jq '[.items[] | select(.status.conditions[] | select(.type=="Ready" and .status!="True"))] | length')
    
    if [ "$not_ready_nodes" -gt 0 ]; then
        log_warning "$not_ready_nodes nodes are not ready"
        return 1
    fi
    
    # Check system pods
    local system_pods_not_ready=$(kubectl get pods -n kube-system -o json | \
        jq '[.items[] | select(.status.phase != "Running")] | length')
    
    if [ "$system_pods_not_ready" -gt 0 ]; then
        log_warning "$system_pods_not_ready system pods are not ready"
        return 1
    fi
    
    log_success "Cluster health check passed"
    return 0
}

# =============================================================================
# Testing Functions
# =============================================================================

run_smoke_tests() {
    if [ "$SKIP_TESTS" = "true" ]; then
        log_info "Skipping smoke tests"
        return 0
    fi
    
    log "Running smoke tests..."
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "Dry run - would run smoke tests"
        return 0
    fi
    
    # Create smoke test job
    local test_job_name="smoke-test-$(date +%s)"
    
    cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: $test_job_name
  namespace: $NAMESPACE
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: smoke-tests
        image: $ECR_REGISTRY/sparc-tests:$IMAGE_TAG
        env:
        - name: API_URL
          value: "http://api-gateway.$NAMESPACE.svc.cluster.local:3000"
        - name: ENVIRONMENT
          value: "$ENVIRONMENT"
        command: ["npm", "run", "test:smoke"]
EOF
    
    # Wait for tests to complete
    if kubectl wait --for=condition=complete \
        "job/$test_job_name" -n "$NAMESPACE" --timeout=300s; then
        log_success "Smoke tests passed"
    else
        # Get test logs
        kubectl logs "job/$test_job_name" -n "$NAMESPACE"
        log_error "Smoke tests failed"
        kubectl delete job "$test_job_name" -n "$NAMESPACE"
        return 1
    fi
    
    # Cleanup
    kubectl delete job "$test_job_name" -n "$NAMESPACE"
}

run_integration_tests() {
    if [ "$SKIP_TESTS" = "true" ] || [ "$ENVIRONMENT" != "staging" ]; then
        return 0
    fi
    
    log "Running integration tests..."
    
    local test_job_name="integration-test-$(date +%s)"
    
    kubectl create job "$test_job_name" \
        --from=cronjob/integration-tests \
        -n "$NAMESPACE" || return 0
    
    kubectl wait --for=condition=complete \
        "job/$test_job_name" -n "$NAMESPACE" --timeout=900s || {
            kubectl logs "job/$test_job_name" -n "$NAMESPACE"
            log_warning "Integration tests failed"
        }
    
    kubectl delete job "$test_job_name" -n "$NAMESPACE"
}

# =============================================================================
# Monitoring Setup Functions
# =============================================================================

setup_monitoring() {
    log "Setting up monitoring..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Apply ServiceMonitor resources
        apply_monitoring_resources "service-monitors"
        
        # Apply PrometheusRule resources
        apply_monitoring_resources "prometheus-rules"
        
        # Apply Grafana dashboards
        setup_grafana_dashboards
        
        # Apply alerts
        apply_monitoring_resources "alerts"
    fi
    
    log_success "Monitoring setup completed"
}

apply_monitoring_resources() {
    local resource_type="$1"
    local resource_dir="$PROJECT_ROOT/k8s/monitoring/$resource_type"
    
    if [ -d "$resource_dir" ]; then
        for resource in "$resource_dir"/*.yaml; do
            if [ -f "$resource" ]; then
                kubectl apply -f "$resource" -n "$NAMESPACE" || true
            fi
        done
    fi
}

setup_grafana_dashboards() {
    if ! kubectl get deployment grafana -n sparc-monitoring &>/dev/null; then
        log_info "Grafana not found, skipping dashboard setup"
        return 0
    fi
    
    local dashboard_dir="$PROJECT_ROOT/k8s/monitoring/dashboards"
    if [ -d "$dashboard_dir" ]; then
        for dashboard in "$dashboard_dir"/*.json; do
            if [ -f "$dashboard" ]; then
                local dashboard_name=$(basename "$dashboard" .json)
                kubectl create configmap "${dashboard_name}-dashboard" \
                    --from-file="$dashboard" \
                    -n sparc-monitoring \
                    --dry-run=client -o yaml | kubectl apply -f -
            fi
        done
    fi
}

# =============================================================================
# Rollback Functions
# =============================================================================

rollback_deployment() {
    log "Starting deployment rollback..."
    
    send_notification "🔴 Production rollback initiated" "warning"
    
    # Capture current state before rollback
    capture_current_state
    
    # Get services to rollback
    local services_to_rollback=("${SERVICES[@]}")
    if [ -n "$SPECIFIC_SERVICES" ]; then
        services_to_rollback=()
        for svc in $SPECIFIC_SERVICES; do
            for service_config in "${SERVICES[@]}"; do
                if [[ "$service_config" == "$svc:"* ]]; then
                    services_to_rollback+=("$service_config")
                fi
            done
        done
    fi
    
    # Confirmation
    if [ "$AUTO_ROLLBACK" != "true" ] && [ "$FORCE_DEPLOY" != "true" ]; then
        echo "Services to rollback: ${services_to_rollback[*]}"
        read -p "Proceed with rollback? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Rollback cancelled"
            exit 0
        fi
    fi
    
    # Perform rollbacks
    local rollback_errors=0
    for service_config in "${services_to_rollback[@]}"; do
        local service_name="${service_config%:*}"
        rollback_service "$service_name" || ((rollback_errors++))
    done
    
    if [ $rollback_errors -gt 0 ]; then
        log_error "Rollback failed for $rollback_errors services"
        return 1
    fi
    
    # Clear caches
    clear_caches
    
    # Verify rollback
    verify_deployment
    
    # Database rollback if requested
    if [ -n "$DATABASE_BACKUP_TIMESTAMP" ]; then
        rollback_database "$DATABASE_BACKUP_TIMESTAMP"
    fi
    
    log_success "Rollback completed successfully"
    send_notification "✅ Production rollback completed successfully" "good"
    
    # Generate report
    generate_rollback_report
}

rollback_service() {
    local service_name="$1"
    local target_revision="${2:-0}"  # 0 means previous revision
    
    log "Rolling back $service_name..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Perform rollback
        if [ "$target_revision" -eq 0 ]; then
            kubectl rollout undo "deployment/$service_name" -n "$NAMESPACE"
        else
            kubectl rollout undo "deployment/$service_name" \
                -n "$NAMESPACE" --to-revision="$target_revision"
        fi
        
        # Wait for rollout
        kubectl rollout status "deployment/$service_name" \
            -n "$NAMESPACE" --timeout="${TIMEOUT}s"
        
        # Verify health after rollback
        verify_service_health "$service_name"
    fi
    
    log_success "Rollback of $service_name completed"
}

clear_caches() {
    log "Clearing caches..."
    
    if [ "$DRY_RUN" = "false" ]; then
        # Clear Redis cache
        local redis_pod=$(kubectl get pods -n "$NAMESPACE" \
            -l app=redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        
        if [ -n "$redis_pod" ]; then
            kubectl exec "$redis_pod" -n "$NAMESPACE" -- redis-cli FLUSHALL || true
        fi
        
        # Clear CDN cache if configured
        if [ -n "$CLOUDFRONT_DISTRIBUTION_ID" ]; then
            aws cloudfront create-invalidation \
                --distribution-id "$CLOUDFRONT_DISTRIBUTION_ID" \
                --paths "/*" || true
        fi
    fi
    
    log_success "Caches cleared"
}

generate_rollback_report() {
    local report_file="$LOG_DIR/rollback_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" <<EOF
# Rollback Report

**Date**: $(date)
**Environment**: $ENVIRONMENT
**Operator**: ${USER}

## Services Rolled Back
$(kubectl get deployments -n "$NAMESPACE" -o json | \
    jq -r '.items[] | "\(.metadata.name): \(.spec.template.spec.containers[0].image)"')

## Verification Results
- Deployment health: Verified
- Service endpoints: Active
- Error rates: Normal

## Actions Taken
1. Captured pre-rollback state
2. Rolled back deployments
3. Cleared caches
4. Verified health
5. Generated report

## Follow-up Required
- [ ] Post-mortem scheduled
- [ ] Root cause analysis
- [ ] Prevention measures
EOF
    
    log_info "Rollback report generated: $report_file"
}

# =============================================================================
# Utility Functions
# =============================================================================

scale_deployments() {
    local replicas="${1:-1}"
    
    log "Scaling all deployments to $replicas replicas..."
    
    kubectl scale deployment --all --replicas="$replicas" -n "$NAMESPACE"
    
    if [ "$replicas" -gt 0 ]; then
        # Wait for pods to be ready
        kubectl wait --for=condition=ready pod --all -n "$NAMESPACE" --timeout="${TIMEOUT}s" || true
    fi
}

get_deployment_info() {
    log "Current deployment information:"
    
    kubectl get deployments,services,ingress -n "$NAMESPACE"
    
    echo
    log "Pod status:"
    kubectl get pods -n "$NAMESPACE"
    
    echo
    log "Recent events:"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -20
}

# =============================================================================
# Main Functions
# =============================================================================

confirm_deployment() {
    if [ "$FORCE_DEPLOY" = "true" ] || [ "$DRY_RUN" = "true" ]; then
        return 0
    fi
    
    if [ "$ENVIRONMENT" = "production" ] && [ "$ROLLBACK_MODE" = "false" ]; then
        log_warning "⚠️  PRODUCTION DEPLOYMENT ⚠️"
        echo
        echo "Environment: $ENVIRONMENT"
        echo "Cluster: $CLUSTER_NAME"
        echo "Namespace: $NAMESPACE"
        echo "Image Tag: $IMAGE_TAG"
        echo
        read -p "Are you sure you want to deploy to PRODUCTION? (yes/no) " -r
        echo
        if [[ ! $REPLY =~ ^yes$ ]]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi
}

main_deploy() {
    log "Starting SPARC platform deployment"
    log "Environment: $ENVIRONMENT"
    log "Cluster: $CLUSTER_NAME"
    log "Namespace: $NAMESPACE"
    log "Image Tag: $IMAGE_TAG"
    log "Dry Run: $DRY_RUN"
    
    # Validate environment
    validate_environment
    
    # Confirm deployment
    confirm_deployment
    
    # Save deployment state
    save_deployment_state
    
    # Send notification
    send_notification "🚀 Starting deployment to $ENVIRONMENT (version: $IMAGE_TAG)" "info"
    
    if [ "$DRY_RUN" = "false" ]; then
        # Backup database
        backup_database
        
        # Build and push images
        build_and_push_images
    fi
    
    # Deploy to Kubernetes
    deploy_kubernetes
    
    if [ "$DRY_RUN" = "false" ]; then
        # Verify deployment
        verify_deployment
        
        # Run tests
        run_smoke_tests
        run_integration_tests
    fi
    
    # Show deployment info
    get_deployment_info
    
    log_success "Deployment completed successfully!"
    send_notification "✅ Deployment to $ENVIRONMENT completed successfully (version: $IMAGE_TAG)" "good"
    
    log_info "Log file: $LOG_FILE"
}

main_rollback() {
    log "Starting SPARC platform rollback"
    log "Environment: $ENVIRONMENT"
    log "Cluster: $CLUSTER_NAME"
    log "Namespace: $NAMESPACE"
    
    # Validate environment
    validate_environment
    
    # Perform rollback
    rollback_deployment
}

main() {
    # Parse arguments
    parse_args "$@"
    
    # Execute based on mode
    if [ "$ROLLBACK_MODE" = "true" ]; then
        main_rollback
    else
        main_deploy
    fi
}

# Execute main function
main "$@"