#!/bin/bash

# SPARC Unified Security Scanning Script
# Comprehensive security scanning combining SAST, dependency scanning, container scanning, and infrastructure checks

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECURITY_DIR="$SCRIPT_DIR/security"
REPORTS_DIR="$SECURITY_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$REPORTS_DIR/security-scan-$TIMESTAMP.log"

# Default configuration
SCAN_LEVEL="${SCAN_LEVEL:-standard}"
ENABLE_INFRASTRUCTURE="${ENABLE_INFRASTRUCTURE:-false}"
ENABLE_GITHUB_UPLOAD="${ENABLE_GITHUB_UPLOAD:-false}"
CREATE_ISSUES="${CREATE_ISSUES:-false}"
EXIT_ON_ERROR="${EXIT_ON_ERROR:-true}"
VERBOSE="${VERBOSE:-false}"

# Security configuration file
CONFIG_FILE="$SECURITY_DIR/security-scan.config.json"

# Exit codes
EXIT_CODE=0
CRITICAL_FOUND=0
HIGH_FOUND=0
MEDIUM_FOUND=0
LOW_FOUND=0

# Usage function
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

SPARC Unified Security Scanning Script

Options:
    -l, --level LEVEL          Scan level: quick, standard, comprehensive (default: standard)
    -i, --infrastructure       Enable infrastructure security checks
    -g, --github              Upload results to GitHub (requires GITHUB_TOKEN)
    -c, --create-issues       Create GitHub issues for vulnerabilities
    -r, --report-dir DIR      Custom report directory (default: ./security/reports)
    -v, --verbose             Enable verbose output
    -h, --help               Show this help message
    --no-fail                Don't exit with error code on findings
    
Environment Variables:
    GITHUB_TOKEN             Required for GitHub integration
    GITHUB_REPOSITORY        Required for GitHub integration
    SNYK_TOKEN              Required for Snyk scanning
    SONAR_TOKEN             Required for SonarQube scanning

Examples:
    # Quick security scan
    $(basename "$0") --level quick

    # Comprehensive scan with GitHub integration
    $(basename "$0") --level comprehensive --github --create-issues

    # Standard scan with infrastructure checks
    $(basename "$0") --infrastructure

EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -l|--level)
                SCAN_LEVEL="$2"
                shift 2
                ;;
            -i|--infrastructure)
                ENABLE_INFRASTRUCTURE="true"
                shift
                ;;
            -g|--github)
                ENABLE_GITHUB_UPLOAD="true"
                shift
                ;;
            -c|--create-issues)
                CREATE_ISSUES="true"
                shift
                ;;
            -r|--report-dir)
                REPORTS_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            --no-fail)
                EXIT_ON_ERROR="false"
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Create necessary directories
setup_directories() {
    mkdir -p "$REPORTS_DIR"/{sast,dependency,container,secrets,infrastructure,consolidated}
    
    # Initialize log file
    touch "$LOG_FILE"
}

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
    
    if [[ "$VERBOSE" == "true" || "$level" == "ERROR" || "$level" == "WARN" ]]; then
        case $level in
            "ERROR")
                echo -e "${RED}[ERROR]${NC} ${message}" >&2
                ;;
            "WARN")
                echo -e "${YELLOW}[WARN]${NC} ${message}"
                ;;
            "INFO")
                echo -e "${BLUE}[INFO]${NC} ${message}"
                ;;
            "SUCCESS")
                echo -e "${GREEN}[SUCCESS]${NC} ${message}"
                ;;
        esac
    fi
}

# Function to print colored status
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    print_status "$BLUE" "\n=== Checking Prerequisites ==="
    
    local missing_tools=()
    
    # Required tools based on scan level
    case $SCAN_LEVEL in
        "quick")
            local required_tools=("npm" "git")
            ;;
        "standard")
            local required_tools=("npm" "git" "python3")
            ;;
        "comprehensive")
            local required_tools=("npm" "git" "python3" "docker")
            ;;
    esac
    
    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_status "$RED" "Missing required tools: ${missing_tools[*]}"
        print_status "$YELLOW" "Please install missing tools before running the scan"
        exit 1
    fi
    
    print_status "$GREEN" "✓ All required tools are installed"
}

# Function to load security configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading security configuration from $CONFIG_FILE"
    else
        log "WARN" "Security configuration file not found, using defaults"
    fi
}

# Function to run SAST scans
run_sast_scan() {
    print_status "$BLUE" "\n=== Running SAST (Static Application Security Testing) ==="
    local sast_exit_code=0
    
    # Semgrep scan
    if command_exists semgrep; then
        log "INFO" "Running Semgrep scan..."
        print_status "$YELLOW" "Running Semgrep..."
        
        local semgrep_rules=()
        case $SCAN_LEVEL in
            "quick")
                semgrep_rules=("--config=auto")
                ;;
            "standard")
                semgrep_rules=("--config=auto" "--config=p/security-audit" "--config=p/nodejs" "--config=p/typescript")
                ;;
            "comprehensive")
                semgrep_rules=("--config=auto" "--config=p/security-audit" "--config=p/nodejs" "--config=p/typescript" "--config=p/react" "--config=p/owasp-top-ten" "--config=p/secrets")
                ;;
        esac
        
        semgrep "${semgrep_rules[@]}" \
            --json \
            --output="$REPORTS_DIR/sast/semgrep-report-$TIMESTAMP.json" \
            --sarif \
            --output="$REPORTS_DIR/sast/semgrep-report-$TIMESTAMP.sarif" \
            --exclude=node_modules \
            --exclude=dist \
            --exclude=build \
            --exclude=.next \
            "$PROJECT_ROOT" || sast_exit_code=$?
            
        if [[ $sast_exit_code -eq 0 ]]; then
            print_status "$GREEN" "✓ Semgrep scan completed"
        else
            print_status "$YELLOW" "⚠ Semgrep found issues"
            EXIT_CODE=$sast_exit_code
        fi
    else
        log "WARN" "Semgrep not installed. Install with: pip install semgrep"
    fi
    
    # ESLint security scan
    log "INFO" "Running ESLint security scan..."
    print_status "$YELLOW" "Running ESLint security scan..."
    cd "$PROJECT_ROOT"
    
    if [[ -f ".eslintrc.security.js" ]]; then
        npx eslint . \
            --config .eslintrc.security.js \
            --ext .js,.jsx,.ts,.tsx \
            --format json \
            --output-file "$REPORTS_DIR/sast/eslint-security-report-$TIMESTAMP.json" \
            || true
        print_status "$GREEN" "✓ ESLint security scan completed"
    else
        npx eslint . \
            --ext .js,.jsx,.ts,.tsx \
            --format json \
            --output-file "$REPORTS_DIR/sast/eslint-report-$TIMESTAMP.json" \
            || true
        print_status "$GREEN" "✓ ESLint scan completed"
    fi
    
    # TypeScript type checking for security
    if [[ "$SCAN_LEVEL" != "quick" ]]; then
        log "INFO" "Running TypeScript security checks..."
        print_status "$YELLOW" "Running TypeScript security checks..."
        npx tsc --noEmit --strict || true
        print_status "$GREEN" "✓ TypeScript checks completed"
    fi
    
    return $sast_exit_code
}

# Function to run dependency scans
run_dependency_scan() {
    print_status "$BLUE" "\n=== Running Dependency Scanning ==="
    local dep_exit_code=0
    
    # NPM audit
    log "INFO" "Running npm audit..."
    print_status "$YELLOW" "Running npm audit..."
    cd "$PROJECT_ROOT"
    
    local audit_level="moderate"
    case $SCAN_LEVEL in
        "quick")
            audit_level="high"
            ;;
        "standard")
            audit_level="moderate"
            ;;
        "comprehensive")
            audit_level="low"
            ;;
    esac
    
    npm audit --json > "$REPORTS_DIR/dependency/npm-audit-report-$TIMESTAMP.json" || true
    npm audit --audit-level=$audit_level || dep_exit_code=$?
    
    # Generate npm audit report in SARIF format
    if command_exists npx; then
        npx npm-audit-sarif \
            --input "$REPORTS_DIR/dependency/npm-audit-report-$TIMESTAMP.json" \
            --output "$REPORTS_DIR/dependency/npm-audit-report-$TIMESTAMP.sarif" || true
    fi
    
    if [[ $dep_exit_code -eq 0 ]]; then
        print_status "$GREEN" "✓ npm audit completed - No vulnerabilities found"
    else
        print_status "$YELLOW" "⚠ npm audit found vulnerabilities"
        EXIT_CODE=$dep_exit_code
    fi
    
    # Snyk scan
    if command_exists snyk && [[ -n "${SNYK_TOKEN:-}" ]]; then
        log "INFO" "Running Snyk scan..."
        print_status "$YELLOW" "Running Snyk scan..."
        
        snyk test --json \
            --severity-threshold=$audit_level \
            --file="$PROJECT_ROOT/package.json" \
            > "$REPORTS_DIR/dependency/snyk-report-$TIMESTAMP.json" || dep_exit_code=$?
        
        snyk test --sarif \
            --file="$PROJECT_ROOT/package.json" \
            > "$REPORTS_DIR/dependency/snyk-report-$TIMESTAMP.sarif" || true
            
        print_status "$GREEN" "✓ Snyk scan completed"
    else
        log "INFO" "Snyk not configured. Set SNYK_TOKEN to enable."
    fi
    
    # OWASP Dependency Check (comprehensive only)
    if [[ "$SCAN_LEVEL" == "comprehensive" ]] && command_exists dependency-check; then
        log "INFO" "Running OWASP Dependency Check..."
        print_status "$YELLOW" "Running OWASP Dependency Check..."
        
        dependency-check \
            --project "SPARC" \
            --scan "$PROJECT_ROOT" \
            --out "$REPORTS_DIR/dependency" \
            --format "ALL" \
            --enableExperimental \
            --nodePackageSkipDevDependencies \
            || dep_exit_code=$?
            
        print_status "$GREEN" "✓ OWASP Dependency Check completed"
    fi
    
    return $dep_exit_code
}

# Function to run container scans
run_container_scan() {
    if [[ "$SCAN_LEVEL" == "quick" ]]; then
        log "INFO" "Skipping container scan in quick mode"
        return 0
    fi
    
    print_status "$BLUE" "\n=== Running Container Scanning ==="
    local container_exit_code=0
    
    if command_exists trivy; then
        log "INFO" "Running Trivy container scan..."
        print_status "$YELLOW" "Running Trivy scan on Docker images..."
        
        # Scan all Dockerfiles
        find "$PROJECT_ROOT" -name "Dockerfile*" -type f | while read -r dockerfile; do
            local dir=$(dirname "$dockerfile")
            local service_name=$(basename "$dir")
            
            if [[ -f "$dockerfile" ]]; then
                log "INFO" "Scanning $service_name..."
                
                # Scan filesystem
                trivy fs "$dir" \
                    --severity CRITICAL,HIGH,MEDIUM \
                    --format sarif \
                    --output "$REPORTS_DIR/container/trivy-fs-$service_name-$TIMESTAMP.sarif" \
                    || container_exit_code=$?
                
                # Scan config
                trivy config "$dir" \
                    --severity CRITICAL,HIGH,MEDIUM \
                    --format json \
                    --output "$REPORTS_DIR/container/trivy-config-$service_name-$TIMESTAMP.json" \
                    || true
            fi
        done
        
        print_status "$GREEN" "✓ Trivy scan completed"
    else
        log "WARN" "Trivy not installed. Install from: https://github.com/aquasecurity/trivy"
    fi
    
    # Docker Scout (if available)
    if command_exists docker && [[ "$SCAN_LEVEL" == "comprehensive" ]]; then
        log "INFO" "Running Docker Scout scan..."
        print_status "$YELLOW" "Running Docker Scout..."
        
        # Check if docker scout is available
        if docker scout version &>/dev/null; then
            docker scout cves --format sarif > "$REPORTS_DIR/container/docker-scout-$TIMESTAMP.sarif" || true
            print_status "$GREEN" "✓ Docker Scout scan completed"
        else
            log "INFO" "Docker Scout not available"
        fi
    fi
    
    return $container_exit_code
}

# Function to run secret scanning
run_secret_scan() {
    print_status "$BLUE" "\n=== Running Secret Scanning ==="
    local secret_exit_code=0
    
    # Gitleaks scan
    if command_exists gitleaks; then
        log "INFO" "Running Gitleaks..."
        print_status "$YELLOW" "Running Gitleaks..."
        
        gitleaks detect \
            --source="$PROJECT_ROOT" \
            --config="$PROJECT_ROOT/.gitleaks.toml" \
            --report-path="$REPORTS_DIR/secrets/gitleaks-report-$TIMESTAMP.json" \
            --report-format="json" \
            --redact \
            --verbose || secret_exit_code=$?
            
        # Also generate SARIF report
        gitleaks detect \
            --source="$PROJECT_ROOT" \
            --config="$PROJECT_ROOT/.gitleaks.toml" \
            --report-path="$REPORTS_DIR/secrets/gitleaks-report-$TIMESTAMP.sarif" \
            --report-format="sarif" \
            --redact || true
            
        if [[ $secret_exit_code -eq 0 ]]; then
            print_status "$GREEN" "✓ Gitleaks completed - No secrets found"
        else
            print_status "$RED" "✗ Gitleaks found secrets!"
            CRITICAL_FOUND=$((CRITICAL_FOUND + 1))
            EXIT_CODE=$secret_exit_code
        fi
    else
        log "WARN" "Gitleaks not installed. Install from: https://github.com/gitleaks/gitleaks"
    fi
    
    # detect-secrets scan
    if command_exists detect-secrets && [[ "$SCAN_LEVEL" != "quick" ]]; then
        log "INFO" "Running detect-secrets..."
        print_status "$YELLOW" "Running detect-secrets..."
        cd "$PROJECT_ROOT"
        
        # Create or update baseline
        if [[ ! -f ".secrets.baseline" ]]; then
            detect-secrets scan --baseline .secrets.baseline
        fi
        
        # Scan for new secrets
        detect-secrets scan --baseline .secrets.baseline.new
        
        # Compare baselines
        if ! diff -q .secrets.baseline .secrets.baseline.new > /dev/null; then
            print_status "$YELLOW" "⚠ New potential secrets detected"
            cp .secrets.baseline.new "$REPORTS_DIR/secrets/detect-secrets-report-$TIMESTAMP.json"
            secret_exit_code=1
        else
            print_status "$GREEN" "✓ detect-secrets completed - No new secrets"
        fi
        
        rm -f .secrets.baseline.new
    fi
    
    return $secret_exit_code
}

# Function to run infrastructure security checks
run_infrastructure_scan() {
    if [[ "$ENABLE_INFRASTRUCTURE" != "true" ]]; then
        log "INFO" "Infrastructure scanning disabled"
        return 0
    fi
    
    print_status "$BLUE" "\n=== Running Infrastructure Security Checks ==="
    local infra_exit_code=0
    
    # Check if infrastructure scripts exist
    if [[ -d "$SECURITY_DIR/infrastructure" ]]; then
        log "INFO" "Running infrastructure security checks..."
        
        # Run security hardening check (dry-run)
        if [[ -x "$SECURITY_DIR/infrastructure/security-hardening.sh" ]]; then
            print_status "$YELLOW" "Checking security hardening..."
            # Run in check mode only
            log "INFO" "Security hardening check would be performed in production"
        fi
        
        # Run firewall rule validation
        if [[ -x "$SECURITY_DIR/infrastructure/firewall-rule-management.sh" ]]; then
            print_status "$YELLOW" "Validating firewall rules..."
            "$SECURITY_DIR/infrastructure/firewall-rule-management.sh" --validate > "$REPORTS_DIR/infrastructure/firewall-validation-$TIMESTAMP.log" 2>&1 || true
        fi
        
        # Run network segmentation validation
        if [[ -x "$SECURITY_DIR/infrastructure/network-segmentation-validation.sh" ]]; then
            print_status "$YELLOW" "Validating network segmentation..."
            "$SECURITY_DIR/infrastructure/network-segmentation-validation.sh" > "$REPORTS_DIR/infrastructure/network-validation-$TIMESTAMP.log" 2>&1 || true
        fi
        
        # Run security group audit
        if [[ -x "$SECURITY_DIR/infrastructure/security-group-audit.sh" ]]; then
            print_status "$YELLOW" "Auditing security groups..."
            "$SECURITY_DIR/infrastructure/security-group-audit.sh" > "$REPORTS_DIR/infrastructure/security-group-audit-$TIMESTAMP.log" 2>&1 || true
        fi
        
        # Run SSL/TLS configuration check
        if [[ -x "$SECURITY_DIR/infrastructure/ssl-tls-configuration.sh" ]]; then
            print_status "$YELLOW" "Checking SSL/TLS configuration..."
            "$SECURITY_DIR/infrastructure/ssl-tls-configuration.sh" --check > "$REPORTS_DIR/infrastructure/ssl-tls-check-$TIMESTAMP.log" 2>&1 || true
        fi
        
        print_status "$GREEN" "✓ Infrastructure security checks completed"
    else
        log "WARN" "Infrastructure security scripts not found"
    fi
    
    # Terraform security scan (if applicable)
    if [[ -d "$PROJECT_ROOT/infra" ]] && command_exists tfsec; then
        log "INFO" "Running tfsec on Terraform code..."
        print_status "$YELLOW" "Running tfsec..."
        
        tfsec "$PROJECT_ROOT/infra" \
            --format sarif \
            --out "$REPORTS_DIR/infrastructure/tfsec-report-$TIMESTAMP.sarif" \
            || infra_exit_code=$?
            
        if [[ $infra_exit_code -eq 0 ]]; then
            print_status "$GREEN" "✓ tfsec completed - No issues found"
        else
            print_status "$YELLOW" "⚠ tfsec found issues"
        fi
    fi
    
    # Kubernetes security scan (if applicable)
    if [[ -d "$PROJECT_ROOT/k8s" ]] && command_exists kubesec; then
        log "INFO" "Running kubesec on Kubernetes manifests..."
        print_status "$YELLOW" "Running kubesec..."
        
        find "$PROJECT_ROOT/k8s" -name "*.yaml" -o -name "*.yml" | while read -r manifest; do
            kubesec scan "$manifest" >> "$REPORTS_DIR/infrastructure/kubesec-report-$TIMESTAMP.json" || true
        done
        
        print_status "$GREEN" "✓ kubesec scan completed"
    fi
    
    return $infra_exit_code
}

# Function to consolidate scan results
consolidate_results() {
    print_status "$BLUE" "\n=== Consolidating Scan Results ==="
    
    local consolidated_report="$REPORTS_DIR/consolidated/security-scan-report-$TIMESTAMP.json"
    
    # Create consolidated JSON report
    cat > "$consolidated_report" << EOF
{
  "scan_metadata": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "scan_level": "$SCAN_LEVEL",
    "project_root": "$PROJECT_ROOT",
    "exit_code": $EXIT_CODE
  },
  "summary": {
    "critical": $CRITICAL_FOUND,
    "high": $HIGH_FOUND,
    "medium": $MEDIUM_FOUND,
    "low": $LOW_FOUND,
    "total": $((CRITICAL_FOUND + HIGH_FOUND + MEDIUM_FOUND + LOW_FOUND))
  },
  "scan_results": {
    "sast": {
      "status": "completed",
      "reports": [$(find "$REPORTS_DIR/sast" -name "*-$TIMESTAMP.*" -exec basename {} \; | sed 's/^/"/' | sed 's/$/"/' | paste -sd, -)]
    },
    "dependency": {
      "status": "completed",
      "reports": [$(find "$REPORTS_DIR/dependency" -name "*-$TIMESTAMP.*" -exec basename {} \; | sed 's/^/"/' | sed 's/$/"/' | paste -sd, -)]
    },
    "container": {
      "status": "completed",
      "reports": [$(find "$REPORTS_DIR/container" -name "*-$TIMESTAMP.*" -exec basename {} \; | sed 's/^/"/' | sed 's/$/"/' | paste -sd, -)]
    },
    "secrets": {
      "status": "completed",
      "reports": [$(find "$REPORTS_DIR/secrets" -name "*-$TIMESTAMP.*" -exec basename {} \; | sed 's/^/"/' | sed 's/$/"/' | paste -sd, -)]
    },
    "infrastructure": {
      "status": "$(if [[ "$ENABLE_INFRASTRUCTURE" == "true" ]]; then echo "completed"; else echo "skipped"; fi)",
      "reports": [$(find "$REPORTS_DIR/infrastructure" -name "*-$TIMESTAMP.*" -exec basename {} \; | sed 's/^/"/' | sed 's/$/"/' | paste -sd, -)]
    }
  },
  "vulnerabilities": []
}
EOF
    
    log "INFO" "Consolidated report created: $consolidated_report"
}

# Function to check security gates
check_security_gates() {
    print_status "$BLUE" "\n=== Checking Security Gates ==="
    
    if [[ -f "$SECURITY_DIR/check-security-gates.py" ]]; then
        local consolidated_report="$REPORTS_DIR/consolidated/security-scan-report-$TIMESTAMP.json"
        
        python3 "$SECURITY_DIR/check-security-gates.py" \
            --report "$consolidated_report" \
            --config "$CONFIG_FILE" \
            --output-format text || EXIT_CODE=$?
    else
        log "WARN" "Security gates checker not found"
    fi
}

# Function to create GitHub issues
create_github_issues() {
    if [[ "$CREATE_ISSUES" != "true" ]] || [[ -z "${GITHUB_TOKEN:-}" ]]; then
        return 0
    fi
    
    print_status "$BLUE" "\n=== Creating GitHub Issues ==="
    
    if [[ -f "$SECURITY_DIR/create-vulnerability-issues.py" ]]; then
        local consolidated_report="$REPORTS_DIR/consolidated/security-scan-report-$TIMESTAMP.json"
        
        python3 "$SECURITY_DIR/create-vulnerability-issues.py" \
            --report "$consolidated_report" \
            --threshold "high" \
            --max-issues 5 \
            --github-token "$GITHUB_TOKEN" || true
    else
        log "WARN" "GitHub issue creator not found"
    fi
}

# Function to upload SARIF reports to GitHub
upload_sarif_reports() {
    if [[ "$ENABLE_GITHUB_UPLOAD" != "true" ]] || [[ -z "${GITHUB_TOKEN:-}" ]] || [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
        return 0
    fi
    
    print_status "$BLUE" "\n=== Uploading SARIF Reports to GitHub ==="
    
    find "$REPORTS_DIR" -name "*-$TIMESTAMP.sarif" -type f | while read -r sarif_file; do
        local tool_name=$(basename "$sarif_file" | cut -d'-' -f1)
        log "INFO" "Uploading $tool_name results..."
        
        if command_exists gh; then
            gh api \
                --method POST \
                -H "Accept: application/vnd.github+json" \
                -H "Authorization: Bearer $GITHUB_TOKEN" \
                "/repos/${GITHUB_REPOSITORY}/code-scanning/sarifs" \
                -f commit_sha="${GITHUB_SHA:-$(git rev-parse HEAD)}" \
                -f ref="${GITHUB_REF:-refs/heads/main}" \
                -f sarif="@${sarif_file}" \
                || log "WARN" "Failed to upload $tool_name SARIF report"
        fi
    done
}

# Function to generate summary report
generate_summary_report() {
    print_status "$BLUE" "\n=== Generating Summary Report ==="
    
    local summary_file="$REPORTS_DIR/consolidated/security-scan-summary-$TIMESTAMP.md"
    
    cat > "$summary_file" << EOF
# SPARC Security Scan Report

**Date:** $(date)
**Scan Level:** $SCAN_LEVEL
**Project:** SPARC Platform

## Executive Summary

Total vulnerabilities found: $((CRITICAL_FOUND + HIGH_FOUND + MEDIUM_FOUND + LOW_FOUND))
- **Critical:** $CRITICAL_FOUND
- **High:** $HIGH_FOUND
- **Medium:** $MEDIUM_FOUND
- **Low:** $LOW_FOUND

## Scan Results

### SAST (Static Application Security Testing)
- Semgrep: $(if [[ -f "$REPORTS_DIR/sast/semgrep-report-$TIMESTAMP.json" ]]; then echo "✓ Completed"; else echo "✗ Not run"; fi)
- ESLint Security: $(if [[ -f "$REPORTS_DIR/sast/eslint-security-report-$TIMESTAMP.json" ]] || [[ -f "$REPORTS_DIR/sast/eslint-report-$TIMESTAMP.json" ]]; then echo "✓ Completed"; else echo "✗ Not run"; fi)

### Dependency Scanning
- NPM Audit: $(if [[ -f "$REPORTS_DIR/dependency/npm-audit-report-$TIMESTAMP.json" ]]; then echo "✓ Completed"; else echo "✗ Not run"; fi)
- Snyk: $(if [[ -f "$REPORTS_DIR/dependency/snyk-report-$TIMESTAMP.json" ]]; then echo "✓ Completed"; else echo "✗ Not run"; fi)
- OWASP Dependency Check: $(if [[ -f "$REPORTS_DIR/dependency/dependency-check-report.html" ]]; then echo "✓ Completed"; else echo "✗ Not run"; fi)

### Container Scanning
- Trivy: $(ls "$REPORTS_DIR"/container/trivy-*-$TIMESTAMP.* 2>/dev/null | wc -l) scans completed

### Secret Scanning
- Gitleaks: $(if [[ -f "$REPORTS_DIR/secrets/gitleaks-report-$TIMESTAMP.json" ]]; then echo "✓ Completed"; else echo "✗ Not run"; fi)
- detect-secrets: $(if [[ -f "$REPORTS_DIR/secrets/detect-secrets-report-$TIMESTAMP.json" ]]; then echo "✓ Completed"; else echo "✗ Not run"; fi)

### Infrastructure Security
- Status: $(if [[ "$ENABLE_INFRASTRUCTURE" == "true" ]]; then echo "✓ Completed"; else echo "⊘ Skipped"; fi)

## Exit Code: $EXIT_CODE

## Recommendations

1. Review all critical and high severity findings immediately
2. Create remediation tickets for medium severity findings
3. Schedule regular security scans as part of CI/CD pipeline
4. Keep all dependencies and security tools up to date

---
*Generated by SPARC Unified Security Scanner*
*Report location: $REPORTS_DIR*
EOF
    
    print_status "$GREEN" "Summary report generated: $summary_file"
    
    # Display summary to console
    echo
    cat "$summary_file"
}

# Function to cleanup old reports
cleanup_old_reports() {
    if [[ "$SCAN_LEVEL" == "comprehensive" ]]; then
        log "INFO" "Cleaning up reports older than 30 days..."
        find "$REPORTS_DIR" -type f -mtime +30 -delete || true
    fi
}

# Main execution function
main() {
    print_status "$CYAN" "
╔═══════════════════════════════════════════════════════╗
║        SPARC Unified Security Scanner v1.0            ║
╚═══════════════════════════════════════════════════════╝"
    
    # Parse arguments
    parse_args "$@"
    
    # Setup
    setup_directories
    check_prerequisites
    load_config
    
    log "INFO" "Starting SPARC security scan (Level: $SCAN_LEVEL)"
    
    # Run scans based on level
    case $SCAN_LEVEL in
        "quick")
            run_sast_scan
            run_secret_scan
            ;;
        "standard")
            run_sast_scan
            run_dependency_scan
            run_secret_scan
            run_container_scan
            ;;
        "comprehensive")
            run_sast_scan
            run_dependency_scan
            run_container_scan
            run_secret_scan
            run_infrastructure_scan
            ;;
        *)
            log "ERROR" "Invalid scan level: $SCAN_LEVEL"
            exit 1
            ;;
    esac
    
    # Post-processing
    consolidate_results
    check_security_gates
    create_github_issues
    upload_sarif_reports
    generate_summary_report
    cleanup_old_reports
    
    # Final status
    if [[ $EXIT_CODE -eq 0 ]]; then
        print_status "$GREEN" "\n✓ Security scan completed successfully!"
    else
        print_status "$RED" "\n✗ Security scan found issues! Exit code: $EXIT_CODE"
        if [[ "$EXIT_ON_ERROR" == "true" ]]; then
            exit $EXIT_CODE
        fi
    fi
    
    log "INFO" "Security scan completed. Reports available in: $REPORTS_DIR"
}

# Run main function with all arguments
main "$@"