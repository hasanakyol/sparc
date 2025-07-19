# SPARC Platform Deployment Guide

This guide provides comprehensive deployment instructions for the SPARC (Secure Physical Access and Real-time Control) platform, covering local development, staging, and production environments across all supported deployment models.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Local Development Setup](#local-development-setup)
4. [Staging Deployment](#staging-deployment)
5. [Production Deployment](#production-deployment)
6. [Deployment Models](#deployment-models)
7. [Infrastructure Requirements](#infrastructure-requirements)
8. [Security Configuration](#security-configuration)
9. [Monitoring Setup](#monitoring-setup)
10. [Troubleshooting](#troubleshooting)
11. [Maintenance and Updates](#maintenance-and-updates)

## Overview

SPARC is a unified physical access control and video surveillance platform designed for enterprise-scale deployments. The platform supports three deployment models:

- **SSP-Managed**: Service provider manages the platform for multiple client organizations
- **Self-Managed**: Enterprise manages their own dedicated instance
- **Hybrid**: Shared responsibility between service provider and enterprise

### Architecture Components

- **Microservices**: 12+ containerized services (auth, tenant, access-control, video-management, etc.)
- **Web Frontend**: Next.js application with responsive design
- **Database**: PostgreSQL with multi-tenant isolation
- **Cache**: Redis for sessions and real-time data
- **Storage**: S3-compatible storage for video and documents
- **Infrastructure**: AWS-based with Kubernetes orchestration

## Prerequisites

### Development Environment

- **Node.js**: 18.x or higher
- **Docker**: 24.x or higher with Docker Compose
- **Git**: Latest version
- **AWS CLI**: v2.x (for cloud deployments)
- **kubectl**: v1.28+ (for Kubernetes deployments)
- **Helm**: v3.12+ (for Kubernetes package management)

### System Requirements

#### Minimum Development
- **CPU**: 4 cores
- **RAM**: 16GB
- **Storage**: 100GB SSD
- **Network**: Broadband internet connection

#### Production (per 1,000 doors, 100 cameras)
- **CPU**: 32 cores
- **RAM**: 128GB
- **Storage**: 10TB (video storage scales with retention requirements)
- **Network**: 1Gbps dedicated connection
- **Database**: RDS PostgreSQL db.r6g.2xlarge or equivalent
- **Cache**: ElastiCache Redis cache.r6g.xlarge or equivalent

## Local Development Setup

### 1. Repository Setup

```bash
# Clone the repository
git clone https://github.com/your-org/sparc.git
cd sparc

# Install dependencies
npm install

# Install workspace dependencies
npm run install:all
```

### 2. Environment Configuration

```bash
# Copy environment template
cp .env.example .env.local

# Edit environment variables
nano .env.local
```

Required environment variables:
```env
# Database
DATABASE_URL="postgresql://sparc:password@localhost:5432/sparc_dev"
REDIS_URL="redis://localhost:6379"

# JWT Configuration
JWT_SECRET="your-super-secret-jwt-key-min-32-chars"
JWT_EXPIRES_IN="24h"
REFRESH_TOKEN_EXPIRES_IN="7d"

# AWS Configuration (for local S3 simulation)
AWS_REGION="us-east-1"
AWS_ACCESS_KEY_ID="minioadmin"
AWS_SECRET_ACCESS_KEY="minioadmin"
S3_BUCKET="sparc-dev"
S3_ENDPOINT="http://localhost:9000"

# Service Configuration
API_GATEWAY_PORT=3000
AUTH_SERVICE_PORT=3001
TENANT_SERVICE_PORT=3002
ACCESS_CONTROL_SERVICE_PORT=3003
VIDEO_MANAGEMENT_SERVICE_PORT=3004
EVENT_PROCESSING_SERVICE_PORT=3005

# Development Settings
NODE_ENV="development"
LOG_LEVEL="debug"
ENABLE_CORS="true"
```

### 3. Database Setup

```bash
# Start infrastructure services
docker-compose up -d postgres redis minio

# Wait for services to be ready
npm run wait-for-services

# Generate Prisma client
npm run db:generate

# Run database migrations
npm run db:migrate

# Seed development data
npm run db:seed
```

### 4. Start Development Services

```bash
# Start all microservices in development mode
npm run dev

# Or start services individually
npm run dev:auth-service
npm run dev:tenant-service
npm run dev:access-control-service
npm run dev:video-management-service
npm run dev:event-processing-service
npm run dev:api-gateway
npm run dev:web
```

### 5. Verify Installation

```bash
# Check service health
curl http://localhost:3000/health

# Check API gateway
curl http://localhost:3000/api/v1/health

# Access web interface
open http://localhost:3000
```

Default development credentials:
- **Username**: admin@sparc.dev
- **Password**: admin123
- **Tenant**: development

## Staging Deployment

### 1. Infrastructure Preparation

```bash
# Deploy staging infrastructure
cd infra
npm install
npx cdk deploy StagingStack --profile staging

# Configure kubectl for staging cluster
aws eks update-kubeconfig --region us-east-1 --name sparc-staging --profile staging
```

### 2. Environment Configuration

Create staging environment file:
```bash
# Create staging secrets
kubectl create namespace sparc-staging

kubectl create secret generic sparc-secrets \
  --from-literal=database-url="postgresql://..." \
  --from-literal=redis-url="redis://..." \
  --from-literal=jwt-secret="..." \
  --namespace=sparc-staging
```

### 3. Database Migration

```bash
# Run migrations on staging database
npm run db:migrate:staging

# Verify migration status
npm run db:status:staging
```

### 4. Application Deployment

```bash
# Build and push container images
npm run build:staging
npm run push:staging

# Deploy to Kubernetes
helm upgrade --install sparc-staging ./k8s/helm/sparc \
  --namespace sparc-staging \
  --values ./k8s/helm/values-staging.yaml \
  --wait --timeout=600s
```

### 5. Verification

```bash
# Check deployment status
kubectl get pods -n sparc-staging
kubectl get services -n sparc-staging
kubectl get ingress -n sparc-staging

# Run health checks
npm run health-check:staging

# Run integration tests
npm run test:integration:staging
```

## Production Deployment

### 1. Pre-Deployment Checklist

- [ ] Infrastructure provisioned and tested
- [ ] SSL certificates configured
- [ ] DNS records configured
- [ ] Backup procedures tested
- [ ] Monitoring and alerting configured
- [ ] Security scanning completed
- [ ] Performance testing completed
- [ ] Disaster recovery plan documented

### 2. Infrastructure Deployment

```bash
# Deploy production infrastructure
cd infra
npx cdk deploy ProductionStack --profile production

# Configure additional security
npx cdk deploy SecurityStack --profile production
npx cdk deploy MonitoringStack --profile production
```

### 3. Database Setup

```bash
# Create production database
aws rds create-db-instance \
  --db-instance-identifier sparc-prod \
  --db-instance-class db.r6g.2xlarge \
  --engine postgres \
  --engine-version 15.4 \
  --allocated-storage 1000 \
  --storage-type gp3 \
  --storage-encrypted \
  --multi-az \
  --backup-retention-period 30 \
  --deletion-protection

# Configure read replicas for reporting
aws rds create-db-instance-read-replica \
  --db-instance-identifier sparc-prod-read \
  --source-db-instance-identifier sparc-prod
```

### 4. Security Configuration

```bash
# Configure AWS KMS
aws kms create-key \
  --description "SPARC Production Encryption Key" \
  --key-usage ENCRYPT_DECRYPT

# Configure AWS Certificate Manager
aws acm request-certificate \
  --domain-name sparc.yourdomain.com \
  --subject-alternative-names "*.sparc.yourdomain.com" \
  --validation-method DNS

# Configure AWS WAF
aws wafv2 create-web-acl \
  --name sparc-production-waf \
  --scope CLOUDFRONT \
  --default-action Allow={}
```

### 5. Application Deployment

```bash
# Build production images
npm run build:production
npm run push:production

# Deploy with zero-downtime strategy
helm upgrade sparc-production ./k8s/helm/sparc \
  --namespace sparc-production \
  --values ./k8s/helm/values-production.yaml \
  --strategy RollingUpdate \
  --wait --timeout=900s

# Verify deployment
kubectl rollout status deployment/api-gateway -n sparc-production
kubectl rollout status deployment/auth-service -n sparc-production
```

### 6. Post-Deployment Verification

```bash
# Run comprehensive health checks
npm run health-check:production

# Run smoke tests
npm run test:smoke:production

# Verify SSL configuration
curl -I https://sparc.yourdomain.com

# Check monitoring dashboards
open https://monitoring.sparc.yourdomain.com
```

## Deployment Models

### SSP-Managed Deployment

Service providers managing multiple client organizations.

#### Configuration

```yaml
# values-ssp.yaml
deployment:
  model: "ssp-managed"
  multiTenant: true
  clientIsolation: "strict"

auth:
  ssoEnabled: true
  tenantSwitching: true
  
monitoring:
  clientDashboards: true
  aggregatedReporting: true

billing:
  enabled: true
  meteringInterval: "hourly"
```

#### Setup Process

```bash
# Deploy SSP infrastructure
helm install sparc-ssp ./k8s/helm/sparc \
  --values ./k8s/helm/values-ssp.yaml \
  --namespace sparc-ssp

# Configure client onboarding
kubectl apply -f ./k8s/manifests/client-onboarding-job.yaml

# Set up billing integration
kubectl create secret generic billing-config \
  --from-file=billing-config.json
```

#### Client Onboarding

```bash
# Create new client tenant
curl -X POST https://api.sparc.ssp.com/api/v1/tenants \
  -H "Authorization: Bearer $SSP_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Client Organization",
    "domain": "client.com",
    "plan": "enterprise",
    "limits": {
      "doors": 1000,
      "cameras": 100,
      "users": 500
    }
  }'
```

### Self-Managed Deployment

Enterprise organizations managing their own instance.

#### Configuration

```yaml
# values-enterprise.yaml
deployment:
  model: "self-managed"
  multiTenant: false
  singleOrganization: true

auth:
  ldapIntegration: true
  ssoProvider: "okta"

monitoring:
  internalOnly: true
  detailedMetrics: true

backup:
  frequency: "daily"
  retention: "90d"
  crossRegion: true
```

#### Setup Process

```bash
# Deploy enterprise infrastructure
helm install sparc-enterprise ./k8s/helm/sparc \
  --values ./k8s/helm/values-enterprise.yaml \
  --namespace sparc-enterprise

# Configure LDAP integration
kubectl create secret generic ldap-config \
  --from-literal=url="ldaps://ldap.company.com" \
  --from-literal=bind-dn="cn=sparc,ou=service,dc=company,dc=com" \
  --from-literal=bind-password="$LDAP_PASSWORD"

# Set up backup procedures
kubectl apply -f ./k8s/manifests/backup-cronjob.yaml
```

### Hybrid Deployment

Shared responsibility between SSP and enterprise.

#### Configuration

```yaml
# values-hybrid.yaml
deployment:
  model: "hybrid"
  sharedResponsibility: true
  handoffSchedule: "business-hours"

auth:
  dualAccess: true
  roleBasedSwitching: true

monitoring:
  splitDashboards: true
  escalationRules: true

operations:
  businessHours: "enterprise"
  afterHours: "ssp"
  emergencyOverride: "ssp"
```

#### Responsibility Matrix

| Function | Business Hours | After Hours | Emergency |
|----------|---------------|-------------|-----------|
| Monitoring | Enterprise | SSP | SSP |
| Incident Response | Enterprise | SSP | SSP |
| User Management | Enterprise | Enterprise | SSP |
| System Updates | Shared | SSP | SSP |
| Backup Management | SSP | SSP | SSP |

## Infrastructure Requirements

### AWS Services

#### Core Services
- **EKS**: Kubernetes cluster management
- **RDS**: PostgreSQL database with Multi-AZ
- **ElastiCache**: Redis for caching and sessions
- **S3**: Video storage and backups
- **CloudFront**: CDN for video streaming
- **ALB**: Application Load Balancer
- **Route53**: DNS management

#### Security Services
- **KMS**: Encryption key management
- **Certificate Manager**: SSL/TLS certificates
- **WAF**: Web application firewall
- **GuardDuty**: Threat detection
- **Security Hub**: Security posture management
- **CloudTrail**: Audit logging

#### Monitoring Services
- **CloudWatch**: Metrics and logging
- **X-Ray**: Distributed tracing
- **SNS**: Alerting and notifications
- **Systems Manager**: Configuration management

### Network Architecture

```
Internet Gateway
    |
Application Load Balancer (Public Subnets)
    |
EKS Worker Nodes (Private Subnets)
    |
RDS/ElastiCache (Database Subnets)
```

#### Security Groups

```bash
# Web tier security group
aws ec2 create-security-group \
  --group-name sparc-web-sg \
  --description "SPARC Web Tier Security Group"

aws ec2 authorize-security-group-ingress \
  --group-id sg-web \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# Application tier security group
aws ec2 create-security-group \
  --group-name sparc-app-sg \
  --description "SPARC Application Tier Security Group"

aws ec2 authorize-security-group-ingress \
  --group-id sg-app \
  --protocol tcp \
  --port 8080 \
  --source-group sg-web

# Database tier security group
aws ec2 create-security-group \
  --group-name sparc-db-sg \
  --description "SPARC Database Tier Security Group"

aws ec2 authorize-security-group-ingress \
  --group-id sg-db \
  --protocol tcp \
  --port 5432 \
  --source-group sg-app
```

## Security Configuration

### SSL/TLS Configuration

```nginx
# nginx.conf for production
server {
    listen 443 ssl http2;
    server_name sparc.yourdomain.com;
    
    ssl_certificate /etc/ssl/certs/sparc.crt;
    ssl_certificate_key /etc/ssl/private/sparc.key;
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    location / {
        proxy_pass http://sparc-web:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Database Security

```sql
-- Create application user with limited privileges
CREATE USER sparc_app WITH PASSWORD 'secure_password';

-- Grant necessary permissions
GRANT CONNECT ON DATABASE sparc TO sparc_app;
GRANT USAGE ON SCHEMA public TO sparc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sparc_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sparc_app;

-- Enable row-level security for multi-tenancy
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users FOR ALL TO sparc_app USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

### Secrets Management

```bash
# Create Kubernetes secrets
kubectl create secret generic sparc-database \
  --from-literal=url="postgresql://user:pass@host:5432/db" \
  --from-literal=ssl-mode="require"

kubectl create secret generic sparc-jwt \
  --from-literal=secret="your-jwt-secret" \
  --from-literal=expires-in="24h"

kubectl create secret generic sparc-aws \
  --from-literal=access-key-id="AKIA..." \
  --from-literal=secret-access-key="..."

# Use AWS Secrets Manager for production
aws secretsmanager create-secret \
  --name sparc/production/database \
  --description "SPARC Production Database Credentials" \
  --secret-string '{"username":"sparc","password":"secure_password"}'
```

## Monitoring Setup

### CloudWatch Configuration

```yaml
# cloudwatch-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cloudwatch-config
data:
  cwagentconfig.json: |
    {
      "metrics": {
        "namespace": "SPARC/Production",
        "metrics_collected": {
          "cpu": {
            "measurement": ["cpu_usage_idle", "cpu_usage_iowait"],
            "metrics_collection_interval": 60
          },
          "disk": {
            "measurement": ["used_percent"],
            "metrics_collection_interval": 60,
            "resources": ["*"]
          },
          "mem": {
            "measurement": ["mem_used_percent"],
            "metrics_collection_interval": 60
          }
        }
      },
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/sparc/*.log",
                "log_group_name": "/aws/sparc/application",
                "log_stream_name": "{instance_id}"
              }
            ]
          }
        }
      }
    }
```

### Prometheus Configuration

```yaml
# prometheus-config.yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "sparc-alerts.yml"

scrape_configs:
  - job_name: 'sparc-services'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Alert Rules

```yaml
# sparc-alerts.yml
groups:
  - name: sparc-system
    rules:
      - alert: HighCPUUsage
        expr: cpu_usage_active > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% for more than 5 minutes"

      - alert: DatabaseConnectionFailure
        expr: up{job="postgres"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection failure"
          description: "PostgreSQL database is not responding"

      - alert: AccessControlServiceDown
        expr: up{job="access-control-service"} == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Access control service is down"
          description: "Critical security service is not responding"

      - alert: VideoStreamFailure
        expr: video_streams_active < video_streams_expected * 0.9
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Video stream failure detected"
          description: "More than 10% of video streams are offline"
```

### Grafana Dashboards

```json
{
  "dashboard": {
    "title": "SPARC System Overview",
    "panels": [
      {
        "title": "System Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=~\"sparc-.*\"}",
            "legendFormat": "{{job}}"
          }
        ]
      },
      {
        "title": "API Response Times",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Active Access Points",
        "type": "stat",
        "targets": [
          {
            "expr": "sparc_access_points_active",
            "legendFormat": "Active Doors"
          }
        ]
      },
      {
        "title": "Video Streams",
        "type": "stat",
        "targets": [
          {
            "expr": "sparc_video_streams_active",
            "legendFormat": "Active Streams"
          }
        ]
      }
    ]
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Service Discovery Problems

**Symptoms**: Services cannot communicate with each other
```bash
# Check DNS resolution
kubectl exec -it pod-name -- nslookup auth-service.sparc.svc.cluster.local

# Check service endpoints
kubectl get endpoints -n sparc

# Verify network policies
kubectl get networkpolicies -n sparc
```

**Solution**:
```bash
# Restart CoreDNS
kubectl rollout restart deployment/coredns -n kube-system

# Check service configuration
kubectl describe service auth-service -n sparc
```

#### 2. Database Connection Issues

**Symptoms**: Applications cannot connect to PostgreSQL
```bash
# Check database connectivity
kubectl exec -it auth-service-pod -- pg_isready -h postgres-service -p 5432

# Check connection pool status
kubectl logs auth-service-pod | grep "connection pool"
```

**Solution**:
```bash
# Verify database credentials
kubectl get secret sparc-database -o yaml

# Check database resource limits
kubectl describe pod postgres-pod

# Restart database connections
kubectl rollout restart deployment/auth-service
```

#### 3. Video Streaming Problems

**Symptoms**: Video feeds not loading or poor quality
```bash
# Check video service logs
kubectl logs video-management-service-pod

# Verify S3 connectivity
kubectl exec -it video-service-pod -- aws s3 ls s3://sparc-video-bucket

# Check network bandwidth
kubectl exec -it video-service-pod -- iperf3 -c bandwidth-test-server
```

**Solution**:
```bash
# Restart video services
kubectl rollout restart deployment/video-management-service

# Check CDN configuration
aws cloudfront get-distribution --id DISTRIBUTION_ID

# Verify transcoding settings
kubectl get configmap video-config -o yaml
```

#### 4. Authentication Failures

**Symptoms**: Users cannot log in or tokens are invalid
```bash
# Check auth service logs
kubectl logs auth-service-pod | grep "authentication"

# Verify JWT configuration
kubectl get secret sparc-jwt -o yaml

# Check Redis connectivity
kubectl exec -it auth-service-pod -- redis-cli -h redis-service ping
```

**Solution**:
```bash
# Restart auth service
kubectl rollout restart deployment/auth-service

# Clear Redis cache
kubectl exec -it redis-pod -- redis-cli FLUSHDB

# Regenerate JWT secrets if compromised
kubectl create secret generic sparc-jwt-new --from-literal=secret="new-secret"
```

### Performance Issues

#### High Memory Usage
```bash
# Check memory usage by pod
kubectl top pods -n sparc

# Analyze memory leaks
kubectl exec -it pod-name -- node --inspect-brk=0.0.0.0:9229 app.js

# Adjust resource limits
kubectl patch deployment service-name -p '{"spec":{"template":{"spec":{"containers":[{"name":"container-name","resources":{"limits":{"memory":"2Gi"}}}]}}}}'
```

#### Slow Database Queries
```sql
-- Enable query logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Analyze slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check index usage
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats 
WHERE tablename = 'access_events';
```

### Log Analysis

#### Centralized Logging
```bash
# View aggregated logs
kubectl logs -f deployment/api-gateway -n sparc

# Search logs with specific patterns
kubectl logs deployment/auth-service -n sparc | grep "ERROR"

# Export logs for analysis
kubectl logs deployment/access-control-service -n sparc --since=1h > access-control.log
```

#### Log Correlation
```bash
# Find logs by correlation ID
kubectl logs -n sparc --selector=app=sparc | grep "correlation-id-12345"

# Analyze error patterns
kubectl logs -n sparc --selector=app=sparc | grep "ERROR" | awk '{print $3}' | sort | uniq -c
```

## Maintenance and Updates

### Rolling Updates

```bash
# Update application version
helm upgrade sparc-production ./k8s/helm/sparc \
  --set image.tag=v2.1.0 \
  --namespace sparc-production

# Monitor rollout status
kubectl rollout status deployment/api-gateway -n sparc-production

# Rollback if needed
kubectl rollout undo deployment/api-gateway -n sparc-production
```

### Database Maintenance

```bash
# Backup before maintenance
pg_dump -h postgres-host -U sparc -d sparc_production > backup-$(date +%Y%m%d).sql

# Run maintenance tasks
psql -h postgres-host -U sparc -d sparc_production -c "VACUUM ANALYZE;"
psql -h postgres-host -U sparc -d sparc_production -c "REINDEX DATABASE sparc_production;"

# Update statistics
psql -h postgres-host -U sparc -d sparc_production -c "ANALYZE;"
```

### Security Updates

```bash
# Scan for vulnerabilities
npm audit
docker scan sparc/auth-service:latest

# Update base images
docker build --no-cache -t sparc/auth-service:v2.1.1 .

# Apply security patches
kubectl patch deployment auth-service -p '{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","image":"sparc/auth-service:v2.1.1"}]}}}}'
```

### Backup Procedures

#### Database Backups
```bash
# Daily automated backup
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME | gzip > /backups/sparc_${DATE}.sql.gz

# Upload to S3
aws s3 cp /backups/sparc_${DATE}.sql.gz s3://sparc-backups/database/

# Cleanup old backups (keep 30 days)
find /backups -name "sparc_*.sql.gz" -mtime +30 -delete
```

#### Configuration Backups
```bash
# Backup Kubernetes configurations
kubectl get all -n sparc-production -o yaml > k8s-backup-$(date +%Y%m%d).yaml

# Backup Helm values
helm get values sparc-production > helm-values-backup-$(date +%Y%m%d).yaml

# Backup secrets (encrypted)
kubectl get secrets -n sparc-production -o yaml | gpg --encrypt > secrets-backup-$(date +%Y%m%d).yaml.gpg
```

### Disaster Recovery

#### Recovery Procedures
```bash
# 1. Restore infrastructure
cd infra
npx cdk deploy --all

# 2. Restore database
gunzip -c sparc_backup.sql.gz | psql -h new-db-host -U sparc -d sparc_production

# 3. Restore application
helm install sparc-production ./k8s/helm/sparc \
  --values ./backup/helm-values-backup.yaml \
  --namespace sparc-production

# 4. Verify recovery
npm run health-check:production
npm run test:smoke:production
```

#### RTO/RPO Targets
- **Recovery Time Objective (RTO)**: 4 hours
- **Recovery Point Objective (RPO)**: 1 hour
- **Database Backup Frequency**: Every 15 minutes
- **Configuration Backup Frequency**: Daily
- **Cross-region Replication**: Enabled for critical data

---

## Support and Contact

For deployment support and troubleshooting assistance:

- **Documentation**: https://docs.sparc.platform
- **Support Portal**: https://support.sparc.platform
- **Emergency Contact**: +1-800-SPARC-911
- **Email**: support@sparc.platform

### Escalation Matrix

| Severity | Response Time | Contact |
|----------|---------------|---------|
| Critical (P1) | 15 minutes | On-call engineer |
| High (P2) | 2 hours | Support team |
| Medium (P3) | 8 hours | Support team |
| Low (P4) | 24 hours | Support team |

---

*Last updated: December 2024*
*Version: 1.0.0*