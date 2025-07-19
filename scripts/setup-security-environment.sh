#!/bin/bash

# SPARC Security Testing Environment Setup Script
# Creates an isolated environment for security testing and vulnerability scanning

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT_NAME="sparc-security-test"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="/tmp/${ENVIRONMENT_NAME}-setup-${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration
SECURITY_TOOLS="all" # all, sast, dast, dependency, container
ENABLE_WAF=true
ENABLE_MONITORING=true
CLEANUP_ON_ERROR=true
VULNERABILITY_DB_UPDATE=true

# Security test configuration
SEC_CONFIG_FILE="$PROJECT_ROOT/security-test-config.yaml"

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

SPARC Security Testing Environment Setup

Options:
    -n, --name NAME              Environment name (default: sparc-security-test)
    -t, --tools TOOLS            Security tools: all, sast, dast, dependency, container (default: all)
    --no-waf                     Disable WAF setup
    --no-monitoring              Disable security monitoring
    --skip-updates               Skip vulnerability database updates
    --no-cleanup                 Don't cleanup on error
    -h, --help                   Show this help message

Examples:
    # Full security testing environment
    $0 --tools all

    # SAST and dependency scanning only
    $0 --tools sast,dependency --no-waf

    # Quick setup without updates
    $0 --skip-updates --no-monitoring

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
            -t|--tools)
                SECURITY_TOOLS="$2"
                shift 2
                ;;
            --no-waf)
                ENABLE_WAF=false
                shift
                ;;
            --no-monitoring)
                ENABLE_MONITORING=false
                shift
                ;;
            --skip-updates)
                VULNERABILITY_DB_UPDATE=false
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
        log_warning "Cleaning up security environment..."
        docker-compose -f "$PROJECT_ROOT/docker-compose.security.yml" -p "$ENVIRONMENT_NAME" down -v || true
        rm -f "$SEC_CONFIG_FILE" || true
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
    for tool in docker docker-compose git python3 npm; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check optional security tools
    local optional_tools=("semgrep" "gitleaks" "trivy" "nuclei")
    local missing_optional=()
    
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_optional+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    if [ ${#missing_optional[@]} -gt 0 ]; then
        log_warning "Missing optional security tools: ${missing_optional[*]}"
        log_warning "Some security tests may be limited"
    fi
    
    log_success "Prerequisites check passed"
}

# Create security test configuration
create_security_config() {
    log "Creating security test configuration..."
    
    cat > "$SEC_CONFIG_FILE" << EOF
# SPARC Security Test Configuration
# Generated: $(date)

environment:
  name: $ENVIRONMENT_NAME
  type: security
  created_at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

security_tools:
  enabled: $SECURITY_TOOLS
  
  sast:
    semgrep:
      enabled: true
      rules:
        - auto
        - p/security-audit
        - p/owasp-top-ten
        - p/nodejs
        - p/typescript
        - p/react
    eslint:
      enabled: true
      config: .eslintrc.security.js
    sonarqube:
      enabled: false
      url: http://localhost:9000
    
  dast:
    zap:
      enabled: true
      port: 8090
      api_key: generated-at-runtime
    nuclei:
      enabled: true
      templates:
        - cves
        - vulnerabilities
        - exposed-panels
        - misconfigurations
    
  dependency:
    npm_audit:
      enabled: true
      level: moderate
    snyk:
      enabled: false
      severity_threshold: medium
    owasp_dependency_check:
      enabled: true
      suppression_file: odc-suppressions.xml
    
  container:
    trivy:
      enabled: true
      severity: CRITICAL,HIGH,MEDIUM
    docker_scout:
      enabled: true
    grype:
      enabled: true
      
  secrets:
    gitleaks:
      enabled: true
      config: .gitleaks.toml
    detect_secrets:
      enabled: true
      baseline: .secrets.baseline
      
  infrastructure:
    tfsec:
      enabled: true
    checkov:
      enabled: true
    terrascan:
      enabled: true

waf_configuration:
  enabled: $ENABLE_WAF
  rules:
    - OWASP Core Rule Set 3.3
    - Custom SPARC Rules
  mode: detection
  
monitoring:
  enabled: $ENABLE_MONITORING
  prometheus:
    port: 9090
  grafana:
    port: 3002
  falco:
    enabled: true
    rules: /etc/falco/rules.d
    
test_targets:
  api_gateway:
    url: http://localhost:3000
    auth_required: true
  web_app:
    url: http://localhost:3003
    auth_required: true
  admin_panel:
    url: http://localhost:3003/admin
    auth_required: true
    
test_accounts:
  admin:
    username: security-test-admin
    password: SecTest#2024Admin
    role: super_admin
  user:
    username: security-test-user
    password: SecTest#2024User
    role: user
  attacker:
    username: security-test-attacker
    password: SecTest#2024Attack
    role: none

reporting:
  format:
    - json
    - sarif
    - html
  output_dir: ./reports/security
  consolidate: true
EOF
    
    log_success "Security configuration created"
}

# Create Docker Compose file for security environment
create_docker_compose() {
    log "Creating Docker Compose configuration..."
    
    cat > "$PROJECT_ROOT/docker-compose.security.yml" << 'EOF'
version: '3.8'

services:
  # OWASP ZAP for DAST
  zap:
    image: owasp/zap2docker-stable
    container_name: ${ENVIRONMENT_NAME}-zap
    command: zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=false
    ports:
      - "8090:8090"
    volumes:
      - zap_data:/zap/data
      - ./reports/security/zap:/zap/reports
    networks:
      - security-net

  # SonarQube for code analysis
  sonarqube:
    image: sonarqube:community
    container_name: ${ENVIRONMENT_NAME}-sonarqube
    environment:
      SONAR_ES_BOOTSTRAP_CHECKS_DISABLE: "true"
    ports:
      - "9000:9000"
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs
    networks:
      - security-net

  # DefectDojo for vulnerability management
  defectdojo:
    image: defectdojo/defectdojo-django:latest
    container_name: ${ENVIRONMENT_NAME}-defectdojo
    environment:
      DD_ADMIN_USER: admin
      DD_ADMIN_PASSWORD: SecTest#2024Admin
      DD_ALLOWED_HOSTS: "*"
      DD_DATABASE_URL: postgresql://dojo:dojo@defectdojo-postgres:5432/dojo
    depends_on:
      - defectdojo-postgres
    ports:
      - "8080:8080"
    volumes:
      - defectdojo_media:/app/media
    networks:
      - security-net

  defectdojo-postgres:
    image: postgres:15
    container_name: ${ENVIRONMENT_NAME}-defectdojo-db
    environment:
      POSTGRES_DB: dojo
      POSTGRES_USER: dojo
      POSTGRES_PASSWORD: dojo
    volumes:
      - defectdojo_postgres:/var/lib/postgresql/data
    networks:
      - security-net

  # Vault for secrets management testing
  vault:
    image: vault:latest
    container_name: ${ENVIRONMENT_NAME}-vault
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: security-test-token
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports:
      - "8200:8200"
    networks:
      - security-net

  # ModSecurity WAF
  modsecurity:
    image: owasp/modsecurity-crs:apache
    container_name: ${ENVIRONMENT_NAME}-waf
    environment:
      PARANOIA: 1
      ANOMALY_INBOUND: 5
      ANOMALY_OUTBOUND: 4
      BACKEND: http://host.docker.internal:3000
    ports:
      - "8081:80"
      - "8443:443"
    volumes:
      - ./security/waf/rules:/etc/modsecurity.d/owasp-crs/rules
      - waf_logs:/var/log/apache2
    networks:
      - security-net

  # Falco for runtime security monitoring
  falco:
    image: falcosecurity/falco:latest
    container_name: ${ENVIRONMENT_NAME}-falco
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - /dev:/host/dev
      - /proc:/host/proc:ro
      - /boot:/host/boot:ro
      - /lib/modules:/host/lib/modules:ro
      - /usr:/host/usr:ro
      - ./security/falco/rules:/etc/falco/rules.d
      - falco_logs:/var/log/falco
    networks:
      - security-net

  # Vulnerability database updater
  vuln-db-updater:
    build:
      context: ./security
      dockerfile: Dockerfile.vuln-updater
    container_name: ${ENVIRONMENT_NAME}-vuln-updater
    environment:
      UPDATE_INTERVAL: 3600
      NVD_API_KEY: ${NVD_API_KEY:-}
    volumes:
      - vuln_db:/var/lib/vulnerability-db
    networks:
      - security-net

  # Security dashboard
  security-dashboard:
    build:
      context: ./security/dashboard
      dockerfile: Dockerfile
    container_name: ${ENVIRONMENT_NAME}-dashboard
    ports:
      - "3004:3000"
    environment:
      API_URL: http://host.docker.internal:3000
      DEFECTDOJO_URL: http://defectdojo:8080
      SONARQUBE_URL: http://sonarqube:9000
    depends_on:
      - defectdojo
      - sonarqube
    networks:
      - security-net

volumes:
  zap_data:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  defectdojo_media:
  defectdojo_postgres:
  waf_logs:
  falco_logs:
  vuln_db:

networks:
  security-net:
    name: ${ENVIRONMENT_NAME}-network
    driver: bridge
EOF
    
    log_success "Docker Compose configuration created"
}

# Install security testing tools
install_security_tools() {
    log "Installing security testing tools..."
    
    # Install Python-based tools
    if command -v pip3 &> /dev/null; then
        log "Installing Python security tools..."
        pip3 install --user \
            semgrep \
            detect-secrets \
            bandit \
            safety \
            checkov \
            || log_warning "Some Python tools failed to install"
    fi
    
    # Install Node.js security tools
    log "Installing Node.js security tools..."
    npm install -g \
        @security/eslint-plugin-security \
        npm-audit-resolver \
        snyk \
        || log_warning "Some Node.js tools failed to install"
    
    # Install other tools
    if ! command -v gitleaks &> /dev/null; then
        log "Installing gitleaks..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install gitleaks || log_warning "Failed to install gitleaks"
        else
            wget -q https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64 -O /tmp/gitleaks
            chmod +x /tmp/gitleaks
            sudo mv /tmp/gitleaks /usr/local/bin/ || log_warning "Failed to install gitleaks"
        fi
    fi
    
    if ! command -v trivy &> /dev/null; then
        log "Installing trivy..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install trivy || log_warning "Failed to install trivy"
        else
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            sudo apt-get update && sudo apt-get install trivy || log_warning "Failed to install trivy"
        fi
    fi
    
    log_success "Security tools installation completed"
}

# Setup WAF rules
setup_waf_rules() {
    if [ "$ENABLE_WAF" != "true" ]; then
        log_warning "WAF setup skipped"
        return
    fi
    
    log "Setting up WAF rules..."
    
    mkdir -p "$PROJECT_ROOT/security/waf/rules"
    
    # Create custom SPARC WAF rules
    cat > "$PROJECT_ROOT/security/waf/rules/sparc-custom.conf" << 'EOF'
# SPARC Custom Security Rules

# Block common attack patterns
SecRule REQUEST_URI "@contains /api/v" \
    "id:1001,\
    phase:1,\
    block,\
    msg:'API version probing detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    severity:'WARNING',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-discovery',\
    tag:'SPARC-CUSTOM',\
    ver:'SPARC/1.0'"

# Protect against JWT attacks
SecRule REQUEST_HEADERS:Authorization "@rx ^Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.?$" \
    "id:1002,\
    phase:1,\
    block,\
    msg:'Malformed JWT token detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    severity:'ERROR',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-injection',\
    tag:'SPARC-CUSTOM',\
    ver:'SPARC/1.0'"

# Rate limiting rules
SecRule IP:REQUEST_COUNTER "@gt 100" \
    "id:1003,\
    phase:1,\
    block,\
    msg:'Rate limit exceeded',\
    logdata:'IP: %{REMOTE_ADDR} - Rate: %{IP:REQUEST_COUNTER}',\
    severity:'WARNING',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-dos',\
    tag:'SPARC-CUSTOM',\
    ver:'SPARC/1.0'"
EOF
    
    log_success "WAF rules configured"
}

# Setup Falco rules
setup_falco_rules() {
    if [ "$ENABLE_MONITORING" != "true" ]; then
        return
    fi
    
    log "Setting up Falco security monitoring rules..."
    
    mkdir -p "$PROJECT_ROOT/security/falco/rules"
    
    # Create custom Falco rules for SPARC
    cat > "$PROJECT_ROOT/security/falco/rules/sparc.yaml" << 'EOF'
- rule: Unauthorized Database Access
  desc: Detect unauthorized database connection attempts
  condition: >
    spawned_process and proc.name in (psql, mysql, mongosh) and
    not proc.pname in (node, npm, yarn)
  output: >
    Unauthorized database access attempt (user=%user.name command=%proc.cmdline container=%container.id)
  priority: WARNING
  tags: [database, security]

- rule: Suspicious File Access
  desc: Detect access to sensitive configuration files
  condition: >
    open_read and 
    (fd.name contains ".env" or 
     fd.name contains "config.json" or
     fd.name contains "credentials") and
    not proc.name in (node, npm, cat, less, vim)
  output: >
    Suspicious file access (user=%user.name file=%fd.name command=%proc.cmdline)
  priority: WARNING
  tags: [filesystem, security]

- rule: Cryptomining Detection
  desc: Detect potential cryptomining activity
  condition: >
    spawned_process and
    (proc.name in (xmrig, minerd, cpuminer) or
     proc.cmdline contains "stratum+tcp")
  output: >
    Cryptomining activity detected (user=%user.name command=%proc.cmdline container=%container.id)
  priority: CRITICAL
  tags: [cryptomining, security]

- rule: Container Escape Attempt
  desc: Detect potential container escape attempts
  condition: >
    spawned_process and 
    proc.name in (docker, kubectl, crictl) and
    container.id != host
  output: >
    Container escape attempt detected (user=%user.name command=%proc.cmdline container=%container.id)
  priority: CRITICAL
  tags: [container, security]
EOF
    
    log_success "Falco rules configured"
}

# Update vulnerability databases
update_vulnerability_databases() {
    if [ "$VULNERABILITY_DB_UPDATE" != "true" ]; then
        log_warning "Skipping vulnerability database updates"
        return
    fi
    
    log "Updating vulnerability databases..."
    
    # Update Trivy database
    if command -v trivy &> /dev/null; then
        log "Updating Trivy vulnerability database..."
        trivy image --download-db-only || log_warning "Failed to update Trivy database"
    fi
    
    # Update npm audit database
    log "Updating npm audit database..."
    npm update -g npm || log_warning "Failed to update npm"
    
    # Update OWASP Dependency Check database
    if [ -f "$PROJECT_ROOT/tools/dependency-check/bin/dependency-check.sh" ]; then
        log "Updating OWASP Dependency Check database..."
        "$PROJECT_ROOT/tools/dependency-check/bin/dependency-check.sh" --updateonly || log_warning "Failed to update OWASP DC"
    fi
    
    log_success "Vulnerability databases updated"
}

# Start security infrastructure
start_security_infrastructure() {
    log "Starting security infrastructure..."
    
    cd "$PROJECT_ROOT"
    
    # Set environment variables
    export ENVIRONMENT_NAME
    
    # Start services based on selected tools
    local services=""
    
    case "$SECURITY_TOOLS" in
        all)
            services="zap sonarqube defectdojo defectdojo-postgres vault"
            [ "$ENABLE_WAF" = "true" ] && services="$services modsecurity"
            [ "$ENABLE_MONITORING" = "true" ] && services="$services falco"
            ;;
        sast)
            services="sonarqube"
            ;;
        dast)
            services="zap"
            [ "$ENABLE_WAF" = "true" ] && services="$services modsecurity"
            ;;
        *)
            services="defectdojo defectdojo-postgres"
            ;;
    esac
    
    # Start selected services
    docker-compose -f docker-compose.security.yml -p "$ENVIRONMENT_NAME" up -d $services
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 30
    
    # Initialize services
    initialize_security_services
    
    log_success "Security infrastructure started"
}

# Initialize security services
initialize_security_services() {
    log "Initializing security services..."
    
    # Initialize ZAP API key
    if docker ps | grep -q "${ENVIRONMENT_NAME}-zap"; then
        local zap_api_key=$(openssl rand -hex 16)
        docker exec "${ENVIRONMENT_NAME}-zap" \
            zap-cli --zap-url http://0.0.0.0 --port 8090 \
            status --api-key "$zap_api_key" || true
        
        echo "ZAP_API_KEY=$zap_api_key" >> "$PROJECT_ROOT/.env.security"
    fi
    
    # Initialize SonarQube
    if docker ps | grep -q "${ENVIRONMENT_NAME}-sonarqube"; then
        log "Waiting for SonarQube to initialize..."
        until curl -s http://localhost:9000/api/system/status | grep -q "UP"; do
            sleep 5
        done
        
        # Create security project
        curl -u admin:admin -X POST \
            "http://localhost:9000/api/projects/create?project=sparc-security&name=SPARC%20Security%20Scan" || true
    fi
    
    # Initialize DefectDojo
    if docker ps | grep -q "${ENVIRONMENT_NAME}-defectdojo"; then
        log "Waiting for DefectDojo to initialize..."
        sleep 60  # DefectDojo takes time to initialize
        
        # Create product for SPARC
        # This would normally be done via API after DefectDojo is ready
    fi
    
    log_success "Security services initialized"
}

# Create security test scripts
create_test_scripts() {
    log "Creating security test scripts..."
    
    mkdir -p "$PROJECT_ROOT/tests/security"
    
    # Create main security test runner
    cat > "$PROJECT_ROOT/tests/security/run-security-tests.sh" << 'EOF'
#!/bin/bash

# SPARC Security Test Runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source configuration
source "$PROJECT_ROOT/.env.security" 2>/dev/null || true

echo "Starting SPARC Security Tests..."

# Run SAST
echo "Running SAST tests..."
"$SCRIPT_DIR/sast/run-sast.sh"

# Run dependency scanning
echo "Running dependency scanning..."
"$SCRIPT_DIR/dependency/run-dependency-scan.sh"

# Run container scanning
echo "Running container scanning..."
"$SCRIPT_DIR/container/run-container-scan.sh"

# Run secret scanning
echo "Running secret scanning..."
"$SCRIPT_DIR/secrets/run-secret-scan.sh"

# Run DAST (if services are running)
if curl -s http://localhost:3000/health > /dev/null; then
    echo "Running DAST tests..."
    "$SCRIPT_DIR/dast/run-dast.sh"
else
    echo "Skipping DAST - services not running"
fi

# Consolidate reports
echo "Consolidating security reports..."
"$SCRIPT_DIR/consolidate-reports.sh"

echo "Security tests completed!"
EOF
    
    chmod +x "$PROJECT_ROOT/tests/security/run-security-tests.sh"
    
    log_success "Security test scripts created"
}

# Display environment information
display_info() {
    log_success "Security testing environment setup completed!"
    
    echo
    echo "=== Environment Information ==="
    echo "Name: $ENVIRONMENT_NAME"
    echo "Security Tools: $SECURITY_TOOLS"
    echo "WAF Enabled: $ENABLE_WAF"
    echo "Monitoring Enabled: $ENABLE_MONITORING"
    echo
    echo "=== Service URLs ==="
    
    if docker ps | grep -q "${ENVIRONMENT_NAME}-zap"; then
        echo "OWASP ZAP: http://localhost:8090"
    fi
    
    if docker ps | grep -q "${ENVIRONMENT_NAME}-sonarqube"; then
        echo "SonarQube: http://localhost:9000 (admin/admin)"
    fi
    
    if docker ps | grep -q "${ENVIRONMENT_NAME}-defectdojo"; then
        echo "DefectDojo: http://localhost:8080 (admin/SecTest#2024Admin)"
    fi
    
    if docker ps | grep -q "${ENVIRONMENT_NAME}-vault"; then
        echo "Vault: http://localhost:8200 (Token: security-test-token)"
    fi
    
    if [ "$ENABLE_WAF" = "true" ] && docker ps | grep -q "${ENVIRONMENT_NAME}-waf"; then
        echo "WAF Proxy: http://localhost:8081"
    fi
    
    echo
    echo "=== Next Steps ==="
    echo "1. Run security tests: ./tests/security/run-security-tests.sh"
    echo "2. View results in DefectDojo"
    echo "3. Check security monitoring dashboards"
    echo "4. Analyze reports in ./reports/security/"
    echo
    echo "To tear down: docker-compose -f docker-compose.security.yml -p $ENVIRONMENT_NAME down -v"
    echo
    echo "Configuration: $SEC_CONFIG_FILE"
    echo "Log file: $LOG_FILE"
}

# Main execution
main() {
    log "Starting SPARC Security Testing Environment Setup"
    
    parse_args "$@"
    check_prerequisites
    create_security_config
    create_docker_compose
    install_security_tools
    setup_waf_rules
    setup_falco_rules
    update_vulnerability_databases
    start_security_infrastructure
    create_test_scripts
    display_info
}

# Run main function
main "$@"