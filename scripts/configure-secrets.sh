#!/bin/bash

# SPARC Platform Secret Configuration Script
# Automates creation and management of production secrets for AWS and Kubernetes

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/tmp/sparc-secrets-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT=""
AWS_REGION="us-west-2"
CLUSTER_NAME=""
NAMESPACE="sparc"
DRY_RUN=false
ROLLBACK=false
FORCE_UPDATE=false
BACKUP_SECRETS=true
SECRET_PREFIX="sparc"

# Secret categories and their AWS Secrets Manager names
declare -A SECRET_CATEGORIES=(
    ["database"]="$SECRET_PREFIX/database"
    ["redis"]="$SECRET_PREFIX/redis"
    ["jwt"]="$SECRET_PREFIX/jwt"
    ["aws"]="$SECRET_PREFIX/aws"
    ["encryption"]="$SECRET_PREFIX/encryption"
    ["external"]="$SECRET_PREFIX/external"
    ["mobile"]="$SECRET_PREFIX/mobile"
    ["notifications"]="$SECRET_PREFIX/notifications"
    ["monitoring"]="$SECRET_PREFIX/monitoring"
    ["ldap"]="$SECRET_PREFIX/ldap"
    ["building_automation"]="$SECRET_PREFIX/building-automation"
    ["manufacturer_apis"]="$SECRET_PREFIX/manufacturer-apis"
    ["ml_services"]="$SECRET_PREFIX/ml-services"
    ["certificates"]="$SECRET_PREFIX/certificates"
)

# Kubernetes secret names
declare -A K8S_SECRETS=(
    ["database-secrets"]="database"
    ["redis-secrets"]="redis"
    ["jwt-secrets"]="jwt"
    ["aws-secrets"]="aws"
    ["encryption-secrets"]="encryption"
    ["external-secrets"]="external"
    ["mobile-secrets"]="mobile"
    ["notification-secrets"]="notifications"
    ["monitoring-secrets"]="monitoring"
    ["ldap-secrets"]="ldap"
    ["building-automation-secrets"]="building_automation"
    ["manufacturer-api-secrets"]="manufacturer_apis"
    ["ml-service-secrets"]="ml_services"
    ["certificate-secrets"]="certificates"
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

# Error handling
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Secret configuration failed with exit code $exit_code"
        log "Log file: $LOG_FILE"
        if [ "$ROLLBACK" = "true" ]; then
            log "Initiating automatic rollback..."
            rollback_secrets
        fi
    fi
    exit $exit_code
}

trap cleanup EXIT

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Configure secrets for SPARC platform deployment

OPTIONS:
    -e, --environment ENV       Target environment (staging|production)
    -r, --region REGION         AWS region (default: us-west-2)
    -c, --cluster CLUSTER       EKS cluster name
    -n, --namespace NAMESPACE   Kubernetes namespace (default: sparc)
    --prefix PREFIX             Secret name prefix (default: sparc)
    --dry-run                   Show what would be configured without executing
    --force                     Force update existing secrets
    --rollback                  Enable automatic rollback on failure
    --no-backup                 Disable secret backup before updates
    -h, --help                  Show this help message

EXAMPLES:
    $0 -e staging
    $0 -e production -c sparc-prod --force
    $0 --dry-run -e staging

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
            -r|--region)
                AWS_REGION="$2"
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
            --prefix)
                SECRET_PREFIX="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE_UPDATE=true
                shift
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --no-backup)
                BACKUP_SECRETS=false
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

# Validate environment and prerequisites
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
    if [ -z "$CLUSTER_NAME" ]; then
        CLUSTER_NAME="sparc-${ENVIRONMENT}"
    fi

    # Update secret names with environment
    for category in "${!SECRET_CATEGORIES[@]}"; do
        SECRET_CATEGORIES[$category]="${SECRET_PREFIX}/${ENVIRONMENT}/${category}"
    done

    # Check required tools
    local required_tools=("aws" "kubectl" "jq" "openssl" "base64")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done

    # Verify AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured or invalid"
        exit 1
    fi

    # Verify EKS cluster access if not dry run
    if [ "$DRY_RUN" = "false" ]; then
        if ! aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" &> /dev/null; then
            log_error "EKS cluster '$CLUSTER_NAME' not found or not accessible"
            exit 1
        fi

        # Update kubeconfig
        aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"

        # Verify kubectl access
        if ! kubectl cluster-info &> /dev/null; then
            log_error "Cannot connect to Kubernetes cluster"
            exit 1
        fi

        # Check namespace
        if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
            log "Creating namespace: $NAMESPACE"
            kubectl create namespace "$NAMESPACE"
        fi
    fi

    log_success "Environment validation completed"
}

# Generate secure random values
generate_secure_value() {
    local length=${1:-32}
    local type=${2:-"alphanumeric"}
    
    case $type in
        "alphanumeric")
            openssl rand -base64 $((length * 3 / 4)) | tr -d "=+/" | cut -c1-${length}
            ;;
        "hex")
            openssl rand -hex $((length / 2))
            ;;
        "jwt")
            openssl rand -base64 64 | tr -d "=+/" | cut -c1-64
            ;;
        "uuid")
            python3 -c "import uuid; print(str(uuid.uuid4()))"
            ;;
        *)
            openssl rand -base64 $((length * 3 / 4)) | tr -d "=+/" | cut -c1-${length}
            ;;
    esac
}

# Backup existing secrets
backup_secrets() {
    if [ "$BACKUP_SECRETS" = "false" ]; then
        log "Secret backup disabled"
        return 0
    fi

    log "Backing up existing secrets..."

    local backup_dir="/tmp/sparc-secrets-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"

    if [ "$DRY_RUN" = "true" ]; then
        log "Dry run - would backup secrets to: $backup_dir"
        return 0
    fi

    # Backup AWS Secrets Manager secrets
    for category in "${!SECRET_CATEGORIES[@]}"; do
        local secret_name="${SECRET_CATEGORIES[$category]}"
        
        if aws secretsmanager describe-secret --secret-id "$secret_name" --region "$AWS_REGION" &> /dev/null; then
            log "Backing up AWS secret: $secret_name"
            aws secretsmanager get-secret-value --secret-id "$secret_name" --region "$AWS_REGION" \
                > "$backup_dir/aws-${category}.json" 2>/dev/null || true
        fi
    done

    # Backup Kubernetes secrets
    for k8s_secret in "${!K8S_SECRETS[@]}"; do
        if kubectl get secret "$k8s_secret" -n "$NAMESPACE" &> /dev/null; then
            log "Backing up Kubernetes secret: $k8s_secret"
            kubectl get secret "$k8s_secret" -n "$NAMESPACE" -o yaml \
                > "$backup_dir/k8s-${k8s_secret}.yaml"
        fi
    done

    echo "$backup_dir" > "/tmp/sparc-secrets-backup-${ENVIRONMENT}.txt"
    log_success "Secrets backed up to: $backup_dir"
}

# Create database secrets
create_database_secrets() {
    log "Creating database secrets..."

    local secret_name="${SECRET_CATEGORIES[database]}"
    local secret_data='{}'

    # Generate database credentials if not provided
    if [ "$ENVIRONMENT" = "production" ]; then
        secret_data=$(jq -n \
            --arg host "sparc-${ENVIRONMENT}-db.cluster-$(generate_secure_value 8 hex).${AWS_REGION}.rds.amazonaws.com" \
            --arg port "5432" \
            --arg database "sparc_${ENVIRONMENT}" \
            --arg username "sparc_admin" \
            --arg password "$(generate_secure_value 32)" \
            --arg ssl "true" \
            --arg pool_min "5" \
            --arg pool_max "20" \
            --arg connection_timeout "30000" \
            --arg idle_timeout "600000" \
            '{
                host: $host,
                port: $port,
                database: $database,
                username: $username,
                password: $password,
                ssl: $ssl,
                pool_min: $pool_min,
                pool_max: $pool_max,
                connection_timeout: $connection_timeout,
                idle_timeout: $idle_timeout,
                url: "postgresql://\($username):\($password)@\($host):\($port)/\($database)?sslmode=require"
            }')
    else
        secret_data=$(jq -n \
            --arg host "sparc-${ENVIRONMENT}-db.${AWS_REGION}.rds.amazonaws.com" \
            --arg port "5432" \
            --arg database "sparc_${ENVIRONMENT}" \
            --arg username "sparc_user" \
            --arg password "$(generate_secure_value 24)" \
            --arg ssl "true" \
            --arg pool_min "2" \
            --arg pool_max "10" \
            --arg connection_timeout "30000" \
            --arg idle_timeout "600000" \
            '{
                host: $host,
                port: $port,
                database: $database,
                username: $username,
                password: $password,
                ssl: $ssl,
                pool_min: $pool_min,
                pool_max: $pool_max,
                connection_timeout: $connection_timeout,
                idle_timeout: $idle_timeout,
                url: "postgresql://\($username):\($password)@\($host):\($port)/\($database)?sslmode=require"
            }')
    fi

    create_aws_secret "$secret_name" "$secret_data" "Database connection credentials"
}

# Create Redis secrets
create_redis_secrets() {
    log "Creating Redis secrets..."

    local secret_name="${SECRET_CATEGORIES[redis]}"
    local secret_data

    if [ "$ENVIRONMENT" = "production" ]; then
        secret_data=$(jq -n \
            --arg host "sparc-${ENVIRONMENT}-redis.cache.amazonaws.com" \
            --arg port "6379" \
            --arg password "$(generate_secure_value 32)" \
            --arg db "0" \
            --arg ttl "3600" \
            --arg max_retries "3" \
            --arg retry_delay "1000" \
            --arg session_host "sparc-${ENVIRONMENT}-session-redis.cache.amazonaws.com" \
            --arg session_db "1" \
            --arg session_ttl "86400" \
            '{
                host: $host,
                port: $port,
                password: $password,
                db: $db,
                ttl: $ttl,
                max_retries: $max_retries,
                retry_delay: $retry_delay,
                url: "redis://:\($password)@\($host):\($port)/\($db)",
                session_host: $session_host,
                session_db: $session_db,
                session_ttl: $session_ttl,
                session_url: "redis://:\($password)@\($session_host):\($port)/\($session_db)"
            }')
    else
        secret_data=$(jq -n \
            --arg host "sparc-${ENVIRONMENT}-redis.cache.amazonaws.com" \
            --arg port "6379" \
            --arg password "$(generate_secure_value 24)" \
            --arg db "0" \
            --arg ttl "3600" \
            --arg max_retries "3" \
            --arg retry_delay "1000" \
            --arg session_db "1" \
            --arg session_ttl "86400" \
            '{
                host: $host,
                port: $port,
                password: $password,
                db: $db,
                ttl: $ttl,
                max_retries: $max_retries,
                retry_delay: $retry_delay,
                url: "redis://:\($password)@\($host):\($port)/\($db)",
                session_host: $host,
                session_db: $session_db,
                session_ttl: $session_ttl,
                session_url: "redis://:\($password)@\($host):\($port)/\($session_db)"
            }')
    fi

    create_aws_secret "$secret_name" "$secret_data" "Redis cache and session store credentials"
}

# Create JWT secrets
create_jwt_secrets() {
    log "Creating JWT secrets..."

    local secret_name="${SECRET_CATEGORIES[jwt]}"
    local secret_data

    secret_data=$(jq -n \
        --arg jwt_secret "$(generate_secure_value 64 jwt)" \
        --arg jwt_refresh_secret "$(generate_secure_value 64 jwt)" \
        --arg jwt_expires_in "24h" \
        --arg jwt_refresh_expires_in "7d" \
        --arg jwt_issuer "sparc-platform-${ENVIRONMENT}" \
        --arg jwt_audience "sparc-users" \
        '{
            jwt_secret: $jwt_secret,
            jwt_refresh_secret: $jwt_refresh_secret,
            jwt_expires_in: $jwt_expires_in,
            jwt_refresh_expires_in: $jwt_refresh_expires_in,
            jwt_issuer: $jwt_issuer,
            jwt_audience: $jwt_audience
        }')

    create_aws_secret "$secret_name" "$secret_data" "JWT signing and refresh tokens"
}

# Create AWS service secrets
create_aws_secrets() {
    log "Creating AWS service secrets..."

    local secret_name="${SECRET_CATEGORIES[aws]}"
    local secret_data

    # Note: In production, these should be IAM roles, not access keys
    secret_data=$(jq -n \
        --arg region "$AWS_REGION" \
        --arg s3_bucket "sparc-${ENVIRONMENT}-video-storage" \
        --arg s3_video_bucket "sparc-${ENVIRONMENT}-video-recordings" \
        --arg s3_backup_bucket "sparc-${ENVIRONMENT}-backups" \
        --arg s3_presigned_url_expires "3600" \
        --arg cloudfront_domain "sparc-${ENVIRONMENT}.cloudfront.net" \
        --arg ses_from_email "noreply@sparc-${ENVIRONMENT}.com" \
        --arg ses_reply_to_email "support@sparc-${ENVIRONMENT}.com" \
        --arg sns_sender_id "SPARC" \
        '{
            region: $region,
            s3_bucket: $s3_bucket,
            s3_video_bucket: $s3_video_bucket,
            s3_backup_bucket: $s3_backup_bucket,
            s3_presigned_url_expires: $s3_presigned_url_expires,
            cloudfront_domain: $cloudfront_domain,
            ses_from_email: $ses_from_email,
            ses_reply_to_email: $ses_reply_to_email,
            sns_sender_id: $sns_sender_id
        }')

    create_aws_secret "$secret_name" "$secret_data" "AWS service configuration"
}

# Create encryption secrets
create_encryption_secrets() {
    log "Creating encryption secrets..."

    local secret_name="${SECRET_CATEGORIES[encryption]}"
    local secret_data

    secret_data=$(jq -n \
        --arg encryption_key "$(generate_secure_value 32 hex)" \
        --arg encryption_algorithm "aes-256-gcm" \
        --arg bcrypt_rounds "12" \
        --arg mobile_credential_key "$(generate_secure_value 32 hex)" \
        --arg webhook_secret "$(generate_secure_value 32)" \
        '{
            encryption_key: $encryption_key,
            encryption_algorithm: $encryption_algorithm,
            bcrypt_rounds: $bcrypt_rounds,
            mobile_credential_encryption_key: $mobile_credential_key,
            webhook_secret: $webhook_secret
        }')

    create_aws_secret "$secret_name" "$secret_data" "Encryption keys and security settings"
}

# Create external service secrets
create_external_secrets() {
    log "Creating external service secrets..."

    local secret_name="${SECRET_CATEGORIES[external]}"
    local secret_data

    secret_data=$(jq -n \
        --arg smtp_host "smtp.amazonaws.com" \
        --arg smtp_port "587" \
        --arg smtp_user "SMTP_USERNAME_PLACEHOLDER" \
        --arg smtp_password "SMTP_PASSWORD_PLACEHOLDER" \
        --arg smtp_tls "true" \
        --arg twilio_account_sid "TWILIO_SID_PLACEHOLDER" \
        --arg twilio_auth_token "TWILIO_TOKEN_PLACEHOLDER" \
        --arg twilio_phone_number "+1234567890" \
        --arg twilio_messaging_service_sid "TWILIO_MESSAGING_SID_PLACEHOLDER" \
        --arg firebase_project_id "sparc-${ENVIRONMENT}" \
        --arg firebase_private_key "FIREBASE_PRIVATE_KEY_PLACEHOLDER" \
        --arg firebase_client_email "firebase-adminsdk@sparc-${ENVIRONMENT}.iam.gserviceaccount.com" \
        --arg firebase_server_key "FIREBASE_SERVER_KEY_PLACEHOLDER" \
        --arg slack_webhook_url "SLACK_WEBHOOK_URL_PLACEHOLDER" \
        --arg slack_bot_token "SLACK_BOT_TOKEN_PLACEHOLDER" \
        --arg teams_webhook_url "TEAMS_WEBHOOK_URL_PLACEHOLDER" \
        --arg pagerduty_integration_key "PAGERDUTY_INTEGRATION_KEY_PLACEHOLDER" \
        --arg webhook_timeout "30000" \
        --arg notification_retry_attempts "3" \
        --arg notification_retry_delay "5000" \
        '{
            smtp_host: $smtp_host,
            smtp_port: $smtp_port,
            smtp_user: $smtp_user,
            smtp_password: $smtp_password,
            smtp_tls: $smtp_tls,
            twilio_account_sid: $twilio_account_sid,
            twilio_auth_token: $twilio_auth_token,
            twilio_phone_number: $twilio_phone_number,
            twilio_messaging_service_sid: $twilio_messaging_service_sid,
            firebase_project_id: $firebase_project_id,
            firebase_private_key: $firebase_private_key,
            firebase_client_email: $firebase_client_email,
            firebase_server_key: $firebase_server_key,
            slack_webhook_url: $slack_webhook_url,
            slack_bot_token: $slack_bot_token,
            teams_webhook_url: $teams_webhook_url,
            pagerduty_integration_key: $pagerduty_integration_key,
            webhook_timeout: $webhook_timeout,
            notification_retry_attempts: $notification_retry_attempts,
            notification_retry_delay: $notification_retry_delay
        }')

    create_aws_secret "$secret_name" "$secret_data" "External notification service credentials"
}

# Create mobile credential secrets
create_mobile_secrets() {
    log "Creating mobile credential secrets..."

    local secret_name="${SECRET_CATEGORIES[mobile]}"
    local secret_data

    secret_data=$(jq -n \
        --arg bundle_id "com.sparc.mobile.${ENVIRONMENT}" \
        --arg deep_link_scheme "sparc-${ENVIRONMENT}" \
        --arg firebase_project_id "sparc-${ENVIRONMENT}" \
        --arg firebase_private_key "FIREBASE_PRIVATE_KEY_PLACEHOLDER" \
        --arg firebase_client_email "firebase-adminsdk@sparc-${ENVIRONMENT}.iam.gserviceaccount.com" \
        --arg apns_key_id "APNS_KEY_ID_PLACEHOLDER" \
        --arg apns_team_id "APNS_TEAM_ID_PLACEHOLDER" \
        --arg apns_private_key "APNS_PRIVATE_KEY_PLACEHOLDER" \
        '{
            mobile_app_bundle_id: $bundle_id,
            mobile_app_deep_link_scheme: $deep_link_scheme,
            firebase_project_id: $firebase_project_id,
            firebase_private_key: $firebase_private_key,
            firebase_client_email: $firebase_client_email,
            apns_key_id: $apns_key_id,
            apns_team_id: $apns_team_id,
            apns_private_key: $apns_private_key
        }')

    create_aws_secret "$secret_name" "$secret_data" "Mobile application and push notification credentials"
}

# Create notification secrets
create_notification_secrets() {
    log "Creating notification secrets..."

    local secret_name="${SECRET_CATEGORIES[notifications]}"
    local secret_data

    secret_data=$(jq -n \
        --arg api_rate_limit_window "900000" \
        --arg api_rate_limit_max_requests "100" \
        --arg api_cors_origins "https://app.sparc-${ENVIRONMENT}.com" \
        --arg hsts_max_age "31536000" \
        --arg webhook_timeout "10000" \
        '{
            api_rate_limit_window: $api_rate_limit_window,
            api_rate_limit_max_requests: $api_rate_limit_max_requests,
            api_cors_origins: $api_cors_origins,
            hsts_max_age: $hsts_max_age,
            webhook_timeout: $webhook_timeout
        }')

    create_aws_secret "$secret_name" "$secret_data" "API security and notification settings"
}

# Create monitoring secrets
create_monitoring_secrets() {
    log "Creating monitoring secrets..."

    local secret_name="${SECRET_CATEGORIES[monitoring]}"
    local secret_data

    secret_data=$(jq -n \
        --arg apm_service_name "sparc-platform-${ENVIRONMENT}" \
        --arg apm_service_version "1.0.0" \
        --arg metrics_port "9090" \
        --arg health_check_interval "30000" \
        --arg health_check_timeout "5000" \
        '{
            apm_service_name: $apm_service_name,
            apm_service_version: $apm_service_version,
            metrics_port: $metrics_port,
            health_check_interval: $health_check_interval,
            health_check_timeout: $health_check_timeout
        }')

    create_aws_secret "$secret_name" "$secret_data" "Monitoring and observability configuration"
}

# Create LDAP/AD secrets
create_ldap_secrets() {
    log "Creating LDAP/AD secrets..."

    local secret_name="${SECRET_CATEGORIES[ldap]}"
    local secret_data

    secret_data=$(jq -n \
        --arg ldap_url "ldap://ldap.company.com:389" \
        --arg ldap_bind_dn "CN=sparc-service,OU=Service Accounts,DC=company,DC=com" \
        --arg ldap_bind_password "LDAP_BIND_PASSWORD_PLACEHOLDER" \
        --arg ldap_base_dn "DC=company,DC=com" \
        --arg ldap_user_search_base "OU=Users,DC=company,DC=com" \
        --arg ldap_group_search_base "OU=Groups,DC=company,DC=com" \
        --arg ldap_user_filter "(objectClass=user)" \
        --arg ldap_group_filter "(objectClass=group)" \
        --arg ldap_user_id_attribute "sAMAccountName" \
        --arg ldap_user_email_attribute "mail" \
        --arg ldap_user_name_attribute "displayName" \
        --arg ldap_group_name_attribute "cn" \
        --arg ldap_group_member_attribute "member" \
        --arg ldap_tls_enabled "true" \
        --arg ldap_tls_reject_unauthorized "true" \
        --arg ldap_sync_interval "3600000" \
        --arg ldap_connection_timeout "10000" \
        --arg ldap_search_timeout "30000" \
        --arg ad_domain "company.com" \
        --arg ad_global_catalog_port "3268" \
        '{
            ldap_url: $ldap_url,
            ldap_bind_dn: $ldap_bind_dn,
            ldap_bind_password: $ldap_bind_password,
            ldap_base_dn: $ldap_base_dn,
            ldap_user_search_base: $ldap_user_search_base,
            ldap_group_search_base: $ldap_group_search_base,
            ldap_user_filter: $ldap_user_filter,
            ldap_group_filter: $ldap_group_filter,
            ldap_user_id_attribute: $ldap_user_id_attribute,
            ldap_user_email_attribute: $ldap_user_email_attribute,
            ldap_user_name_attribute: $ldap_user_name_attribute,
            ldap_group_name_attribute: $ldap_group_name_attribute,
            ldap_group_member_attribute: $ldap_group_member_attribute,
            ldap_tls_enabled: $ldap_tls_enabled,
            ldap_tls_reject_unauthorized: $ldap_tls_reject_unauthorized,
            ldap_sync_interval: $ldap_sync_interval,
            ldap_connection_timeout: $ldap_connection_timeout,
            ldap_search_timeout: $ldap_search_timeout,
            ad_domain: $ad_domain,
            ad_global_catalog_port: $ad_global_catalog_port
        }')

    create_aws_secret "$secret_name" "$secret_data" "LDAP/Active Directory integration credentials"
}

# Create building automation secrets
create_building_automation_secrets() {
    log "Creating building automation secrets..."

    local secret_name="${SECRET_CATEGORIES[building_automation]}"
    local secret_data

    secret_data=$(jq -n \
        --arg hvac_api_url "https://hvac.company.com/api" \
        --arg hvac_api_key "HVAC_API_KEY_PLACEHOLDER" \
        --arg hvac_username "HVAC_USERNAME_PLACEHOLDER" \
        --arg hvac_password "HVAC_PASSWORD_PLACEHOLDER" \
        --arg hvac_protocol "bacnet" \
        --arg hvac_device_id "1001" \
        --arg fire_safety_api_url "https://fire.company.com/api" \
        --arg fire_safety_api_key "FIRE_SAFETY_API_KEY_PLACEHOLDER" \
        --arg fire_safety_username "FIRE_SAFETY_USERNAME_PLACEHOLDER" \
        --arg fire_safety_password "FIRE_SAFETY_PASSWORD_PLACEHOLDER" \
        --arg lighting_api_url "https://lighting.company.com/api" \
        --arg lighting_api_key "LIGHTING_API_KEY_PLACEHOLDER" \
        --arg lighting_username "LIGHTING_USERNAME_PLACEHOLDER" \
        --arg lighting_password "LIGHTING_PASSWORD_PLACEHOLDER" \
        --arg bacnet_device_id "1000" \
        --arg bacnet_port "47808" \
        --arg modbus_host "modbus.company.com" \
        --arg modbus_port "502" \
        --arg modbus_unit_id "1" \
        --arg snmp_community "public" \
        --arg snmp_version "2c" \
        --arg snmp_port "161" \
        --arg connection_timeout "30000" \
        --arg retry_attempts "3" \
        --arg retry_delay "5000" \
        '{
            hvac_api_url: $hvac_api_url,
            hvac_api_key: $hvac_api_key,
            hvac_username: $hvac_username,
            hvac_password: $hvac_password,
            hvac_protocol: $hvac_protocol,
            hvac_device_id: $hvac_device_id,
            fire_safety_api_url: $fire_safety_api_url,
            fire_safety_api_key: $fire_safety_api_key,
            fire_safety_username: $fire_safety_username,
            fire_safety_password: $fire_safety_password,
            lighting_api_url: $lighting_api_url,
            lighting_api_key: $lighting_api_key,
            lighting_username: $lighting_username,
            lighting_password: $lighting_password,
            bacnet_device_id: $bacnet_device_id,
            bacnet_port: $bacnet_port,
            modbus_host: $modbus_host,
            modbus_port: $modbus_port,
            modbus_unit_id: $modbus_unit_id,
            snmp_community: $snmp_community,
            snmp_version: $snmp_version,
            snmp_port: $snmp_port,
            connection_timeout: $connection_timeout,
            retry_attempts: $retry_attempts,
            retry_delay: $retry_delay
        }')

    create_aws_secret "$secret_name" "$secret_data" "Building automation system credentials and configuration"
}

# Create manufacturer API secrets
create_manufacturer_api_secrets() {
    log "Creating manufacturer API secrets..."

    local secret_name="${SECRET_CATEGORIES[manufacturer_apis]}"
    local secret_data

    secret_data=$(jq -n \
        --arg hid_api_url "https://api.hidglobal.com" \
        --arg hid_api_key "HID_API_KEY_PLACEHOLDER" \
        --arg hid_client_id "HID_CLIENT_ID_PLACEHOLDER" \
        --arg hid_client_secret "HID_CLIENT_SECRET_PLACEHOLDER" \
        --arg honeywell_api_url "https://api.honeywell.com" \
        --arg honeywell_api_key "HONEYWELL_API_KEY_PLACEHOLDER" \
        --arg honeywell_client_id "HONEYWELL_CLIENT_ID_PLACEHOLDER" \
        --arg honeywell_client_secret "HONEYWELL_CLIENT_SECRET_PLACEHOLDER" \
        --arg bosch_api_url "https://api.boschsecurity.com" \
        --arg bosch_api_key "BOSCH_API_KEY_PLACEHOLDER" \
        --arg bosch_username "BOSCH_USERNAME_PLACEHOLDER" \
        --arg bosch_password "BOSCH_PASSWORD_PLACEHOLDER" \
        --arg axis_api_url "https://api.axis.com" \
        --arg axis_username "AXIS_USERNAME_PLACEHOLDER" \
        --arg axis_password "AXIS_PASSWORD_PLACEHOLDER" \
        --arg hikvision_username "HIKVISION_USERNAME_PLACEHOLDER" \
        --arg hikvision_password "HIKVISION_PASSWORD_PLACEHOLDER" \
        --arg dahua_username "DAHUA_USERNAME_PLACEHOLDER" \
        --arg dahua_password "DAHUA_PASSWORD_PLACEHOLDER" \
        --arg hanwha_username "HANWHA_USERNAME_PLACEHOLDER" \
        --arg hanwha_password "HANWHA_PASSWORD_PLACEHOLDER" \
        --arg genetec_api_url "https://api.genetec.com" \
        --arg genetec_api_key "GENETEC_API_KEY_PLACEHOLDER" \
        --arg genetec_username "GENETEC_USERNAME_PLACEHOLDER" \
        --arg genetec_password "GENETEC_PASSWORD_PLACEHOLDER" \
        --arg otis_api_url "https://api.otis.com" \
        --arg otis_api_key "OTIS_API_KEY_PLACEHOLDER" \
        --arg otis_client_id "OTIS_CLIENT_ID_PLACEHOLDER" \
        --arg otis_client_secret "OTIS_CLIENT_SECRET_PLACEHOLDER" \
        --arg kone_api_url "https://api.kone.com" \
        --arg kone_api_key "KONE_API_KEY_PLACEHOLDER" \
        --arg kone_client_id "KONE_CLIENT_ID_PLACEHOLDER" \
        --arg kone_client_secret "KONE_CLIENT_SECRET_PLACEHOLDER" \
        --arg schindler_api_url "https://api.schindler.com" \
        --arg schindler_api_key "SCHINDLER_API_KEY_PLACEHOLDER" \
        --arg schindler_username "SCHINDLER_USERNAME_PLACEHOLDER" \
        --arg schindler_password "SCHINDLER_PASSWORD_PLACEHOLDER" \
        --arg thyssenkrupp_api_url "https://api.thyssenkrupp.com" \
        --arg thyssenkrupp_api_key "THYSSENKRUPP_API_KEY_PLACEHOLDER" \
        --arg thyssenkrupp_client_id "THYSSENKRUPP_CLIENT_ID_PLACEHOLDER" \
        --arg thyssenkrupp_client_secret "THYSSENKRUPP_CLIENT_SECRET_PLACEHOLDER" \
        --arg connection_timeout "30000" \
        --arg request_timeout "60000" \
        --arg retry_attempts "3" \
        --arg retry_delay "5000" \
        '{
            hid_api_url: $hid_api_url,
            hid_api_key: $hid_api_key,
            hid_client_id: $hid_client_id,
            hid_client_secret: $hid_client_secret,
            honeywell_api_url: $honeywell_api_url,
            honeywell_api_key: $honeywell_api_key,
            honeywell_client_id: $honeywell_client_id,
            honeywell_client_secret: $honeywell_client_secret,
            bosch_api_url: $bosch_api_url,
            bosch_api_key: $bosch_api_key,
            bosch_username: $bosch_username,
            bosch_password: $bosch_password,
            axis_api_url: $axis_api_url,
            axis_username: $axis_username,
            axis_password: $axis_password,
            hikvision_username: $hikvision_username,
            hikvision_password: $hikvision_password,
            dahua_username: $dahua_username,
            dahua_password: $dahua_password,
            hanwha_username: $hanwha_username,
            hanwha_password: $hanwha_password,
            genetec_api_url: $genetec_api_url,
            genetec_api_key: $genetec_api_key,
            genetec_username: $genetec_username,
            genetec_password: $genetec_password,
            otis_api_url: $otis_api_url,
            otis_api_key: $otis_api_key,
            otis_client_id: $otis_client_id,
            otis_client_secret: $otis_client_secret,
            kone_api_url: $kone_api_url,
            kone_api_key: $kone_api_key,
            kone_client_id: $kone_client_id,
            kone_client_secret: $kone_client_secret,
            schindler_api_url: $schindler_api_url,
            schindler_api_key: $schindler_api_key,
            schindler_username: $schindler_username,
            schindler_password: $schindler_password,
            thyssenkrupp_api_url: $thyssenkrupp_api_url,
            thyssenkrupp_api_key: $thyssenkrupp_api_key,
            thyssenkrupp_client_id: $thyssenkrupp_client_id,
            thyssenkrupp_client_secret: $thyssenkrupp_client_secret,
            connection_timeout: $connection_timeout,
            request_timeout: $request_timeout,
            retry_attempts: $retry_attempts,
            retry_delay: $retry_delay
        }')

    create_aws_secret "$secret_name" "$secret_data" "Manufacturer API credentials for hardware integrations"
}

# Create ML service secrets
create_ml_service_secrets() {
    log "Creating ML service secrets..."

    local secret_name="${SECRET_CATEGORIES[ml_services]}"
    local secret_data

    secret_data=$(jq -n \
        --arg aws_rekognition_region "$AWS_REGION" \
        --arg azure_face_api_key "AZURE_FACE_API_KEY_PLACEHOLDER" \
        --arg azure_face_endpoint "https://face-api.cognitiveservices.azure.com" \
        --arg google_vision_api_key "GOOGLE_VISION_API_KEY_PLACEHOLDER" \
        --arg google_vision_project_id "GOOGLE_VISION_PROJECT_ID_PLACEHOLDER" \
        --arg openalpr_api_key "OPENALPR_API_KEY_PLACEHOLDER" \
        --arg openalpr_endpoint "https://api.openalpr.com" \
        --arg platerecognizer_api_key "PLATERECOGNIZER_API_KEY_PLACEHOLDER" \
        --arg platerecognizer_endpoint "https://api.platerecognizer.com" \
        --arg custom_ml_endpoint "https://ml.company.com/api" \
        --arg custom_ml_api_key "CUSTOM_ML_API_KEY_PLACEHOLDER" \
        --arg custom_ml_username "CUSTOM_ML_USERNAME_PLACEHOLDER" \
        --arg custom_ml_password "CUSTOM_ML_PASSWORD_PLACEHOLDER" \
        --arg face_recognition_confidence_threshold "0.85" \
        --arg lpr_confidence_threshold "0.90" \
        --arg behavioral_analysis_sensitivity "0.75" \
        --arg crowd_analysis_threshold "10" \
        --arg loitering_detection_timeout "300000" \
        --arg model_update_interval "86400000" \
        --arg inference_timeout "30000" \
        --arg batch_processing_size "10" \
        --arg gpu_enabled "false" \
        '{
            aws_rekognition_region: $aws_rekognition_region,
            azure_face_api_key: $azure_face_api_key,
            azure_face_endpoint: $azure_face_endpoint,
            google_vision_api_key: $google_vision_api_key,
            google_vision_project_id: $google_vision_project_id,
            openalpr_api_key: $openalpr_api_key,
            openalpr_endpoint: $openalpr_endpoint,
            platerecognizer_api_key: $platerecognizer_api_key,
            platerecognizer_endpoint: $platerecognizer_endpoint,
            custom_ml_endpoint: $custom_ml_endpoint,
            custom_ml_api_key: $custom_ml_api_key,
            custom_ml_username: $custom_ml_username,
            custom_ml_password: $custom_ml_password,
            face_recognition_confidence_threshold: $face_recognition_confidence_threshold,
            lpr_confidence_threshold: $lpr_confidence_threshold,
            behavioral_analysis_sensitivity: $behavioral_analysis_sensitivity,
            crowd_analysis_threshold: $crowd_analysis_threshold,
            loitering_detection_timeout: $loitering_detection_timeout,
            model_update_interval: $model_update_interval,
            inference_timeout: $inference_timeout,
            batch_processing_size: $batch_processing_size,
            gpu_enabled: $gpu_enabled
        }')

    create_aws_secret "$secret_name" "$secret_data" "Machine learning service credentials and configuration"
}

# Create certificate management secrets
create_certificate_secrets() {
    log "Creating certificate management secrets..."

    local secret_name="${SECRET_CATEGORIES[certificates]}"
    local secret_data

    secret_data=$(jq -n \
        --arg ca_certificate_path "/etc/ssl/certs/sparc-ca.crt" \
        --arg ca_private_key_path "/etc/ssl/private/sparc-ca.key" \
        --arg ca_private_key_password "CA_PRIVATE_KEY_PASSWORD_PLACEHOLDER" \
        --arg server_certificate_path "/etc/ssl/certs/sparc-server.crt" \
        --arg server_private_key_path "/etc/ssl/private/sparc-server.key" \
        --arg client_certificate_path "/etc/ssl/certs/sparc-client.crt" \
        --arg client_private_key_path "/etc/ssl/private/sparc-client.key" \
        --arg certificate_validity_days "365" \
        --arg certificate_renewal_threshold_days "30" \
        --arg certificate_key_size "2048" \
        --arg certificate_algorithm "RSA" \
        --arg certificate_digest "sha256" \
        --arg acme_server_url "https://acme-v02.api.letsencrypt.org/directory" \
        --arg acme_email "certificates@sparc-${ENVIRONMENT}.com" \
        --arg acme_challenge_type "dns-01" \
        --arg aws_acm_region "$AWS_REGION" \
        --arg certificate_monitoring_enabled "true" \
        --arg certificate_auto_renewal_enabled "true" \
        --arg certificate_backup_enabled "true" \
        --arg certificate_audit_enabled "true" \
        '{
            ca_certificate_path: $ca_certificate_path,
            ca_private_key_path: $ca_private_key_path,
            ca_private_key_password: $ca_private_key_password,
            server_certificate_path: $server_certificate_path,
            server_private_key_path: $server_private_key_path,
            client_certificate_path: $client_certificate_path,
            client_private_key_path: $client_private_key_path,
            certificate_validity_days: $certificate_validity_days,
            certificate_renewal_threshold_days: $certificate_renewal_threshold_days,
            certificate_key_size: $certificate_key_size,
            certificate_algorithm: $certificate_algorithm,
            certificate_digest: $certificate_digest,
            acme_server_url: $acme_server_url,
            acme_email: $acme_email,
            acme_challenge_type: $acme_challenge_type,
            aws_acm_region: $aws_acm_region,
            certificate_monitoring_enabled: $certificate_monitoring_enabled,
            certificate_auto_renewal_enabled: $certificate_auto_renewal_enabled,
            certificate_backup_enabled: $certificate_backup_enabled,
            certificate_audit_enabled: $certificate_audit_enabled
        }')

    create_aws_secret "$secret_name" "$secret_data" "Certificate management and PKI configuration"
}

# Create AWS Secrets Manager secret
create_aws_secret() {
    local secret_name="$1"
    local secret_data="$2"
    local description="$3"

    if [ "$DRY_RUN" = "true" ]; then
        log "Dry run - would create AWS secret: $secret_name"
        return 0
    fi

    # Check if secret exists
    if aws secretsmanager describe-secret --secret-id "$secret_name" --region "$AWS_REGION" &> /dev/null; then
        if [ "$FORCE_UPDATE" = "true" ]; then
            log "Updating existing AWS secret: $secret_name"
            aws secretsmanager update-secret \
                --secret-id "$secret_name" \
                --secret-string "$secret_data" \
                --description "$description" \
                --region "$AWS_REGION" > /dev/null
        else
            log_warning "AWS secret already exists: $secret_name (use --force to update)"
            return 0
        fi
    else
        log "Creating AWS secret: $secret_name"
        aws secretsmanager create-secret \
            --name "$secret_name" \
            --secret-string "$secret_data" \
            --description "$description" \
            --region "$AWS_REGION" > /dev/null
    fi

    log_success "AWS secret configured: $secret_name"
}

# Create Kubernetes secrets from AWS Secrets Manager
create_kubernetes_secrets() {
    log "Creating Kubernetes secrets..."

    if [ "$DRY_RUN" = "true" ]; then
        log "Dry run - would create Kubernetes secrets"
        return 0
    fi

    for k8s_secret in "${!K8S_SECRETS[@]}"; do
        local category="${K8S_SECRETS[$k8s_secret]}"
        local aws_secret_name="${SECRET_CATEGORIES[$category]}"

        log "Creating Kubernetes secret: $k8s_secret"

        # Get secret data from AWS Secrets Manager
        local secret_json=$(aws secretsmanager get-secret-value \
            --secret-id "$aws_secret_name" \
            --region "$AWS_REGION" \
            --query 'SecretString' \
            --output text)

        # Create Kubernetes secret manifest
        local temp_manifest="/tmp/k8s-secret-${k8s_secret}.yaml"
        
        cat > "$temp_manifest" << EOF
apiVersion: v1
kind: Secret
metadata:
  name: $k8s_secret
  namespace: $NAMESPACE
  labels:
    app.kubernetes.io/name: sparc
    app.kubernetes.io/component: secrets
    app.kubernetes.io/environment: $ENVIRONMENT
  annotations:
    sparc.io/secret-category: $category
    sparc.io/aws-secret-name: $aws_secret_name
type: Opaque
data:
EOF

        # Convert JSON to base64 encoded key-value pairs
        echo "$secret_json" | jq -r 'to_entries[] | "  \(.key): \(.value | @base64)"' >> "$temp_manifest"

        # Apply the secret
        if kubectl get secret "$k8s_secret" -n "$NAMESPACE" &> /dev/null; then
            if [ "$FORCE_UPDATE" = "true" ]; then
                kubectl apply -f "$temp_manifest"
            else
                log_warning "Kubernetes secret already exists: $k8s_secret (use --force to update)"
            fi
        else
            kubectl apply -f "$temp_manifest"
        fi

        # Cleanup temp file
        rm -f "$temp_manifest"

        log_success "Kubernetes secret configured: $k8s_secret"
    done
}

# Validate secrets configuration
validate_secrets() {
    log "Validating secrets configuration..."

    local validation_errors=0

    # Validate AWS Secrets Manager secrets
    for category in "${!SECRET_CATEGORIES[@]}"; do
        local secret_name="${SECRET_CATEGORIES[$category]}"
        
        if [ "$DRY_RUN" = "true" ]; then
            log "Dry run - would validate AWS secret: $secret_name"
            continue
        fi

        if aws secretsmanager describe-secret --secret-id "$secret_name" --region "$AWS_REGION" &> /dev/null; then
            # Validate secret can be retrieved
            if aws secretsmanager get-secret-value --secret-id "$secret_name" --region "$AWS_REGION" &> /dev/null; then
                log_success "AWS secret validated: $secret_name"
            else
                log_error "Cannot retrieve AWS secret: $secret_name"
                ((validation_errors++))
            fi
        else
            log_error "AWS secret not found: $secret_name"
            ((validation_errors++))
        fi
    done

    # Validate Kubernetes secrets
    if [ "$DRY_RUN" = "false" ]; then
        for k8s_secret in "${!K8S_SECRETS[@]}"; do
            if kubectl get secret "$k8s_secret" -n "$NAMESPACE" &> /dev/null; then
                # Validate secret has required keys
                local secret_keys=$(kubectl get secret "$k8s_secret" -n "$NAMESPACE" -o jsonpath='{.data}' | jq -r 'keys[]')
                if [ -n "$secret_keys" ]; then
                    log_success "Kubernetes secret validated: $k8s_secret"
                else
                    log_error "Kubernetes secret has no data: $k8s_secret"
                    ((validation_errors++))
                fi
            else
                log_error "Kubernetes secret not found: $k8s_secret"
                ((validation_errors++))
            fi
        done
    fi

    if [ $validation_errors -gt 0 ]; then
        log_error "Secret validation failed with $validation_errors errors"
        return 1
    fi

    log_success "All secrets validated successfully"
}

# Rollback secrets
rollback_secrets() {
    log "Rolling back secrets..."

    local backup_file="/tmp/sparc-secrets-backup-${ENVIRONMENT}.txt"
    if [ ! -f "$backup_file" ]; then
        log_error "No backup file found for rollback"
        return 1
    fi

    local backup_dir=$(cat "$backup_file")
    if [ ! -d "$backup_dir" ]; then
        log_error "Backup directory not found: $backup_dir"
        return 1
    fi

    if [ "$DRY_RUN" = "true" ]; then
        log "Dry run - would rollback secrets from: $backup_dir"
        return 0
    fi

    # Rollback AWS Secrets Manager secrets
    for backup_file in "$backup_dir"/aws-*.json; do
        if [ -f "$backup_file" ]; then
            local category=$(basename "$backup_file" .json | sed 's/aws-//')
            local secret_name="${SECRET_CATEGORIES[$category]}"
            local secret_data=$(jq -r '.SecretString' "$backup_file")

            log "Rolling back AWS secret: $secret_name"
            aws secretsmanager update-secret \
                --secret-id "$secret_name" \
                --secret-string "$secret_data" \
                --region "$AWS_REGION" > /dev/null
        fi
    done

    # Rollback Kubernetes secrets
    for backup_file in "$backup_dir"/k8s-*.yaml; do
        if [ -f "$backup_file" ]; then
            log "Rolling back Kubernetes secret: $(basename "$backup_file" .yaml | sed 's/k8s-//')"
            kubectl apply -f "$backup_file"
        fi
    done

    log_success "Secret rollback completed"
}

# Generate environment file from secrets
generate_env_file() {
    log "Generating environment file from secrets..."

    local env_file="$PROJECT_ROOT/.env.$ENVIRONMENT"

    if [ "$DRY_RUN" = "true" ]; then
        log "Dry run - would generate environment file: $env_file"
        return 0
    fi

    cat > "$env_file" << EOF
# SPARC Platform Environment Configuration - $ENVIRONMENT
# Generated automatically by configure-secrets.sh
# DO NOT EDIT MANUALLY - Use AWS Secrets Manager to update values

NODE_ENV=$ENVIRONMENT
LOG_LEVEL=info
ENVIRONMENT=$ENVIRONMENT
AWS_REGION=$AWS_REGION

# Secrets are loaded from AWS Secrets Manager and Kubernetes secrets
# This file contains only non-sensitive configuration values

# Service URLs (will be updated by deployment)
API_GATEWAY_URL=https://api.sparc-${ENVIRONMENT}.com
AUTH_SERVICE_URL=http://auth-service:3001
TENANT_SERVICE_URL=http://tenant-service:3002
ACCESS_CONTROL_SERVICE_URL=http://access-control-service:3003
DEVICE_MANAGEMENT_SERVICE_URL=http://device-management-service:3004
VIDEO_MANAGEMENT_SERVICE_URL=http://video-management-service:3005
EVENT_PROCESSING_SERVICE_URL=http://event-processing-service:3006
ANALYTICS_SERVICE_URL=http://analytics-service:3007
REPORTING_SERVICE_URL=http://reporting-service:3008
MOBILE_CREDENTIAL_SERVICE_URL=http://mobile-credential-service:3009
VISITOR_MANAGEMENT_SERVICE_URL=http://visitor-management-service:3010
ENVIRONMENTAL_SERVICE_URL=http://environmental-service:3011

# Feature flags
OFFLINE_MODE_ENABLED=true
VIDEO_RECORDING_ENABLED=true
ENVIRONMENTAL_MONITORING_ENABLED=true
BEHAVIORAL_ANALYTICS_ENABLED=false
FACE_RECOGNITION_ENABLED=false
LPR_ENABLED=false

# Resource limits
DEFAULT_TENANT_USER_LIMIT=1000
DEFAULT_TENANT_DEVICE_LIMIT=5000
DEFAULT_TENANT_STORAGE_LIMIT_GB=1000
DEFAULT_TENANT_BANDWIDTH_LIMIT_MBPS=1000

EOF

    log_success "Environment file generated: $env_file"
}

# Main function
main() {
    log "Starting SPARC platform secret configuration"
    log "Environment: $ENVIRONMENT"
    log "AWS Region: $AWS_REGION"
    log "Namespace: $NAMESPACE"
    log "Dry Run: $DRY_RUN"

    validate_environment
    backup_secrets

    # Create all secret categories
    create_database_secrets
    create_redis_secrets
    create_jwt_secrets
    create_aws_secrets
    create_encryption_secrets
    create_external_secrets
    create_mobile_secrets
    create_notification_secrets
    create_monitoring_secrets
    create_ldap_secrets
    create_building_automation_secrets
    create_manufacturer_api_secrets
    create_ml_service_secrets
    create_certificate_secrets

    # Create Kubernetes secrets
    create_kubernetes_secrets

    # Validate configuration
    validate_secrets

    # Generate environment file
    generate_env_file

    log_success "Secret configuration completed successfully!"
    log "Log file: $LOG_FILE"

    if [ "$DRY_RUN" = "false" ]; then
        log ""
        log "Next steps:"
        log "1. Update placeholder values in AWS Secrets Manager for external services"
        log "2. Configure IAM roles for production AWS access"
        log "3. Run deployment script: ./scripts/deploy.sh -e $ENVIRONMENT"
        log ""
        log "Important: Review and update the following placeholder values:"
        log "- SMTP credentials in external secrets"
        log "- Twilio credentials for SMS notifications"
        log "- Firebase credentials for push notifications"
        log "- LDAP/AD connection credentials"
        log "- Building automation system credentials (HVAC, Fire Safety, Lighting)"
        log "- Manufacturer API keys (HID, Honeywell, Bosch, Axis, etc.)"
        log "- Elevator manufacturer credentials (Otis, KONE, Schindler, ThyssenKrupp)"
        log "- ML service API keys (Azure Face, Google Vision, OpenALPR, etc.)"
        log "- Certificate management passwords and ACME configuration"
        log "- Slack, Teams, and PagerDuty integration credentials"
    fi
}

# Parse arguments and run main function
parse_args "$@"
main
