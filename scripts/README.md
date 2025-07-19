# SPARC Scripts Directory

This directory contains all operational scripts for the SPARC security platform in a single flat structure. All scripts are now in the root scripts directory with category prefixes for easy identification.

> **Note**: Major consolidation completed:
> - **`deploy-unified.sh`**: All deployment, rollback, and basic validation operations
> - **`validate-unified.sh`**: Comprehensive validation, health checks, and readiness verification
> - **`security-scan-unified.sh`**: All security scanning, auditing, and vulnerability detection
> - **Flat structure**: No subdirectories - all scripts use prefixes (e.g., `security-*` for security scripts)
> - **23 essential scripts** remain from 40+ original scripts

## Table of Contents

- [Overview](#overview)
- [Script Categories](#script-categories)
  - [Development Setup](#development-setup)
  - [Deployment & Operations](#deployment--operations)
  - [Testing & Validation](#testing--validation)
  - [Security](#security)
  - [Database & Backups](#database--backups)
  - [Documentation](#documentation)
  - [Infrastructure](#infrastructure)
- [Common Workflows](#common-workflows)
- [Environment Variables](#environment-variables)
- [Prerequisites](#prerequisites)

## Overview

The scripts in this directory are designed to automate common tasks and ensure consistency across development, staging, and production environments. All scripts follow these principles:

- **Idempotent**: Can be run multiple times safely
- **Environment-aware**: Respect environment variables and configurations
- **Logged**: Provide clear output and error messages
- **Documented**: Include usage instructions and examples

## Script Categories

### Development Setup

#### `setup.sh`
**Purpose**: Complete development environment setup
```bash
# Usage
./scripts/setup.sh

# What it does:
# - Installs dependencies
# - Sets up local databases
# - Configures environment variables
# - Initializes Docker containers
# - Runs initial migrations
```
**Prerequisites**: Docker, Node.js 18+, PostgreSQL client

#### `demo-setup.sh`
**Purpose**: Quick demo environment with sample data
```bash
# Usage
./scripts/demo-setup.sh

# Creates demo organization with:
# - Sample users and roles
# - Mock camera feeds
# - Example incidents
# - Test analytics data
```
**Prerequisites**: Running database, completed setup.sh

#### `configure-secrets.sh`
**Purpose**: Set up local development secrets
```bash
# Usage
./scripts/configure-secrets.sh [environment]

# Examples:
./scripts/configure-secrets.sh development
./scripts/configure-secrets.sh staging
```
**Required Environment Variables**:
- `VAULT_ADDR`: HashiCorp Vault address
- `VAULT_TOKEN`: Authentication token

### Deployment & Operations

#### `deploy-unified.sh`
**Purpose**: Unified deployment script for all environments with integrated validation and rollback
```bash
# Usage
./scripts/deploy-unified.sh [environment] [options]

# Examples:
./scripts/deploy-unified.sh staging --dry-run
./scripts/deploy-unified.sh production --service auth
./scripts/deploy-unified.sh development --all
./scripts/deploy-unified.sh production --rollback v1.2.2

# Features:
# - Integrated pre-deployment checks
# - Built-in health validation
# - Automatic rollback on failure
# - Blue-green deployment for production
# - Service-specific or full deployment
# - Dry-run mode for safety
```
**Required Environment Variables**:
- `KUBE_CONFIG`: Kubernetes configuration
- `DOCKER_REGISTRY`: Container registry URL
- `ENVIRONMENT`: Target environment
**Prerequisites**: Appropriate environment access, approved change request for production

#### `deployment/disaster-recovery.sh`
**Purpose**: Disaster recovery automation
```bash
# Usage
./scripts/deployment/disaster-recovery.sh [recovery-type]

# Examples:
./scripts/deployment/disaster-recovery.sh database
./scripts/deployment/disaster-recovery.sh full-system
```

#### `deploy-service-mesh.sh`
**Purpose**: Deploy Istio service mesh configuration
```bash
# Usage
./scripts/deploy-service-mesh.sh [environment]
```

#### `setup-jaeger.sh`
**Purpose**: Set up Jaeger distributed tracing
```bash
# Usage
./scripts/setup-jaeger.sh
```

### Testing & Validation

#### `test-coverage.sh`
**Purpose**: Run full test suite with coverage report
```bash
# Usage
./scripts/test-coverage.sh [options]

# Examples:
./scripts/test-coverage.sh --unit
./scripts/test-coverage.sh --integration
./scripts/test-coverage.sh --e2e
./scripts/test-coverage.sh --all --report
```
**Output**: Coverage reports in `coverage/` directory

#### `integration-test.sh`
**Purpose**: Run integration tests across services
```bash
# Usage
./scripts/integration-test.sh [service-name]

# Examples:
./scripts/integration-test.sh auth
./scripts/integration-test.sh video-processor
./scripts/integration-test.sh --all
```

#### Note on Validation Scripts
**The validation functionality has been integrated into `deploy-unified.sh`**

The unified deployment script now includes:
- Health checks (previously in `health-check.sh`)
- Deployment validation (previously in `validate-deployment.sh`) 
- Production readiness checks (previously in `production-readiness-check.sh`)

Use `deploy-unified.sh` with appropriate flags for validation:
```bash
# Health check only
./scripts/deploy-unified.sh [environment] --health-check-only

# Full validation without deployment
./scripts/deploy-unified.sh [environment] --validate-only

# Deployment with automatic validation
./scripts/deploy-unified.sh [environment]
```

#### `improve-test-coverage.sh`
**Purpose**: Identify and improve test coverage gaps
```bash
# Usage
./scripts/improve-test-coverage.sh [threshold]

# Example:
./scripts/improve-test-coverage.sh 80
```

### Security

#### Note on Security Auditing
**Security audit functionality is now integrated into the unified deployment workflow**

Security checks are automatically performed during deployment:
```bash
# Run deployment with security validation
./scripts/deploy-unified.sh [environment] --with-security-scan

# Security scan only (no deployment)
./scripts/deploy-unified.sh [environment] --security-scan-only
```

For detailed security scanning, use the dedicated security scripts below.

#### `security/run-security-scan.sh`
**Purpose**: Execute all security scans
```bash
# Usage
./scripts/security/run-security-scan.sh

# Runs:
# - SAST (Static Application Security Testing)
# - Dependency scanning
# - Container scanning
# - Secret detection
```

#### `security/check-security-gates.py`
**Purpose**: Enforce security quality gates
```bash
# Usage
python scripts/security/check-security-gates.py

# Checks against thresholds for:
# - Critical vulnerabilities: 0
# - High vulnerabilities: < 5
# - Security score: > 85%
```

#### `security/create-vulnerability-issues.py`
**Purpose**: Create GitHub/GitLab issues for vulnerabilities
```bash
# Usage
python scripts/security/create-vulnerability-issues.py --severity high
```

#### `security-report-generator.py`
**Purpose**: Generate executive security reports
```bash
# Usage
python scripts/security-report-generator.py --format pdf --output report.pdf
```

#### `apply-basic-security-configurations.sh`
**Purpose**: Apply baseline security configurations
```bash
# Usage
./scripts/apply-basic-security-configurations.sh
```

#### Security Infrastructure Scripts

- `security/infrastructure/firewall-rule-management.sh`: Manage firewall rules
- `security/infrastructure/network-segmentation-validation.sh`: Validate network isolation
- `security/infrastructure/security-group-audit.sh`: Audit cloud security groups
- `security/infrastructure/security-hardening.sh`: Apply security hardening
- `security/infrastructure/ssl-tls-configuration.sh`: Configure TLS/SSL

### Database & Backups

#### `apply-database-indexes.ts`
**Purpose**: Apply performance-critical database indexes
```bash
# Usage
npm run script scripts/apply-database-indexes.ts

# Applies indexes for:
# - Tenant isolation queries
# - Time-series data
# - Search operations
# - Join optimizations
```

#### `apply-new-migrations.sh`
**Purpose**: Apply pending database migrations
```bash
# Usage
./scripts/apply-new-migrations.sh [environment]

# Examples:
./scripts/apply-new-migrations.sh development
./scripts/apply-new-migrations.sh production --dry-run
```

#### `backup/backup-scheduler.ts`
**Purpose**: Automated backup scheduling
```bash
# Usage
npm run script scripts/backup/backup-scheduler.ts

# Schedules:
# - Hourly incremental backups
# - Daily full backups
# - Weekly archival backups
```
**Required Environment Variables**:
- `BACKUP_S3_BUCKET`: S3 bucket for backups
- `BACKUP_RETENTION_DAYS`: Retention period

#### `migrate-db-pooling.sh`
**Purpose**: Migrate to connection pooling
```bash
# Usage
./scripts/migrate-db-pooling.sh
```

### Documentation

#### `generate-api-docs.ts`
**Purpose**: Generate OpenAPI documentation
```bash
# Usage
npm run script scripts/generate-api-docs.ts

# Generates:
# - OpenAPI 3.0 specifications
# - Postman collections
# - API documentation site
```
**Output**: `docs/api/` directory

#### `docs/generate-api-docs.sh`
**Purpose**: Shell wrapper for API documentation
```bash
# Usage
./scripts/docs/generate-api-docs.sh [service-name]
```

#### `update-service-openapi.ts`
**Purpose**: Update OpenAPI specs for services
```bash
# Usage
npm run script scripts/update-service-openapi.ts [service-name]
```

### Infrastructure

#### `apply-performance-optimizations.sh`
**Purpose**: Apply performance tuning
```bash
# Usage
./scripts/apply-performance-optimizations.sh [target]

# Targets:
# - database: Query optimization
# - cache: Redis configuration
# - cdn: CDN rules
# - all: Everything
```

#### `apply-basic-performance-optimizations.sh`
**Purpose**: Quick performance wins
```bash
# Usage
./scripts/apply-basic-performance-optimizations.sh
```

#### `apply-basic-performance-optimizations-dry-run.sh`
**Purpose**: Preview performance changes
```bash
# Usage
./scripts/apply-basic-performance-optimizations-dry-run.sh
```

#### `update-health-endpoints.sh`
**Purpose**: Update service health check endpoints
```bash
# Usage
./scripts/update-health-endpoints.sh
```

#### `bulk-update-health-checks.sh`
**Purpose**: Bulk update health check configurations
```bash
# Usage
./scripts/bulk-update-health-checks.sh [config-file]
```

#### `update-auth-middleware.sh`
**Purpose**: Update authentication middleware
```bash
# Usage
./scripts/update-auth-middleware.sh [version]
```

#### `modularize-service.sh`
**Purpose**: Break monolithic service into microservices
```bash
# Usage
./scripts/modularize-service.sh [service-name]
```

## Common Workflows

### Setting Up Development Environment

```bash
# 1. Clone repository
git clone https://github.com/sparc/sparc.git
cd sparc

# 2. Run setup script
./scripts/setup.sh

# 3. Configure secrets
./scripts/configure-secrets.sh development

# 4. Load demo data (optional)
./scripts/demo-setup.sh

# 5. Verify setup
./scripts/deploy-unified.sh local --health-check-only
```

### Deploying to Production

```bash
# 1. Run pre-deployment checks
./scripts/deploy-unified.sh production --validate-only

# 2. Create backup
npm run script scripts/backup/backup-scheduler.ts

# 3. Deploy with validation
./scripts/deploy-unified.sh production --version v1.2.3

# 4. Monitor deployment (automatic validation included)
# The deploy-unified.sh script includes post-deployment validation

# 5. If issues arise, rollback
./scripts/deploy-unified.sh production --rollback v1.2.2
```

### Running Security Audit

```bash
# 1. Full security scan
./scripts/security/run-security-scan.sh

# 2. Check quality gates
python scripts/security/check-security-gates.py

# 3. Generate report
python scripts/security-report-generator.py --format pdf

# 4. Create issues for findings
python scripts/security/create-vulnerability-issues.py --severity high
```

### Database Migration

```bash
# 1. Test migrations locally
./scripts/apply-new-migrations.sh development

# 2. Dry run on staging
./scripts/apply-new-migrations.sh staging --dry-run

# 3. Backup production
npm run script scripts/backup/backup-scheduler.ts

# 4. Apply to production
./scripts/apply-new-migrations.sh production

# 5. Verify indexes
npm run script scripts/apply-database-indexes.ts
```

## Environment Variables

### Required for All Environments
```bash
NODE_ENV=development|staging|production
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
JWT_SECRET=...
```

### Deployment Variables
```bash
KUBE_CONFIG=/path/to/kubeconfig
DOCKER_REGISTRY=registry.sparc.io
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

### Security Variables
```bash
VAULT_ADDR=https://vault.sparc.io
VAULT_TOKEN=...
GITHUB_TOKEN=... # For issue creation
SLACK_WEBHOOK=... # For alerts
```

### Backup Variables
```bash
BACKUP_S3_BUCKET=sparc-backups
BACKUP_RETENTION_DAYS=30
BACKUP_ENCRYPTION_KEY=...
```

## Prerequisites

### System Requirements
- Node.js 18+ with npm 9+
- Docker 20+ and Docker Compose 2+
- PostgreSQL client tools (psql)
- Python 3.9+ (for security scripts)
- kubectl (for Kubernetes operations)
- AWS CLI (for cloud operations)

### Access Requirements
- GitHub/GitLab access for source control
- Kubernetes cluster access (for deployments)
- AWS/Azure/GCP credentials (environment-specific)
- Vault access (for secrets)
- Monitoring system access (Grafana, Prometheus)

### Development Tools
```bash
# Install required tools
brew install node postgresql kubernetes-cli aws-cli python@3.9
npm install -g typescript ts-node

# Verify installations
node --version    # Should be 18+
npm --version     # Should be 9+
docker --version  # Should be 20+
kubectl version   # Should be 1.25+
python3 --version # Should be 3.9+
```

## Troubleshooting

### Common Issues

1. **Script Permission Denied**
   ```bash
   chmod +x scripts/*.sh
   chmod +x scripts/**/*.sh
   ```

2. **Database Connection Failed**
   ```bash
   # Check DATABASE_URL
   echo $DATABASE_URL
   # Test connection
   psql $DATABASE_URL -c "SELECT 1"
   ```

3. **Docker Not Running**
   ```bash
   # Start Docker
   docker info
   # If failed, start Docker Desktop
   ```

4. **Missing Environment Variables**
   ```bash
   # Check required variables
   ./scripts/verify-environment.sh
   ```

## Contributing

When adding new scripts:
1. Follow naming convention: `action-target.sh` (e.g., `deploy-frontend.sh`)
2. Add usage documentation at the top of the script
3. Update this README with the new script
4. Ensure idempotency
5. Add error handling and logging
6. Test in all environments

## Support

For issues or questions:
- Check script logs in `/tmp/sparc/logs/`
- Review environment variables
- Consult team documentation in `docs/`
- Contact DevOps team via Slack #sparc-devops