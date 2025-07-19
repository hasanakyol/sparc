# SPARC Platform Deployment Guide

**Version:** 1.0  
**Last Updated:** 2025-01-19  
**Audience:** DevOps Engineers, SRE Teams, System Administrators

## Overview

This guide provides comprehensive instructions for deploying the SPARC Security Platform across various environments. The platform consists of 24 microservices, a Next.js frontend, and supporting infrastructure components designed to handle 10,000+ concurrent users and 100,000+ video streams.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Deployment Overview](#deployment-overview)
3. [Local Development](#local-development)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Cloud-Specific Deployments](#cloud-specific-deployments)
   - [AWS Deployment](#aws-deployment)
   - [Azure Deployment](#azure-deployment)
   - [Google Cloud Platform](#google-cloud-platform)
7. [Production Deployment](#production-deployment)
8. [Post-Deployment Configuration](#post-deployment-configuration)
9. [Monitoring and Observability](#monitoring-and-observability)
10. [Backup and Recovery](#backup-and-recovery)
11. [Troubleshooting](#troubleshooting)
12. [Rollback Procedures](#rollback-procedures)

## Prerequisites

### Required Tools

Install the following tools based on your deployment target:

**Common Tools (All Deployments)**
```bash
# Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Docker
sudo apt-get update
sudo apt-get install docker.io
sudo usermod -aG docker $USER

# kubectl (for Kubernetes deployments)
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Helm v3
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

**AWS-Specific Tools**
```bash
# AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# eksctl
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# AWS CDK v2
npm install -g aws-cdk@latest
```

**Azure-Specific Tools**
```bash
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Azure Kubernetes Service CLI
az aks install-cli
```

**GCP-Specific Tools**
```bash
# Google Cloud SDK
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
sudo apt-get update && sudo apt-get install google-cloud-sdk
```

### System Requirements

- **CPU**: Minimum 16 cores for production
- **Memory**: Minimum 64GB RAM for production
- **Storage**: 500GB+ SSD storage for video data
- **Network**: 1Gbps+ network connectivity
- **OS**: Ubuntu 20.04+ or RHEL 8+

## Deployment Overview

SPARC supports multiple deployment models:

1. **Local Development**: Single-machine deployment for development
2. **Docker Compose**: Container-based deployment for testing
3. **Kubernetes**: Production-grade orchestration
4. **Managed Cloud Services**: AWS EKS, Azure AKS, Google GKE

### Architecture Components

The platform consists of:
- **24 Microservices**: Core business logic
- **API Gateway**: Central routing and authentication
- **PostgreSQL**: Primary database (multi-tenant)
- **Redis**: Caching and session storage
- **S3/Blob Storage**: Video and file storage
- **Message Queue**: Event-driven communication
- **Monitoring Stack**: Prometheus, Grafana, OpenTelemetry

## Local Development

### Quick Start

```bash
# Clone repository
git clone <repository-url>
cd sparc

# Automated setup
npm run setup:dev

# Start all services
npm run dev
```

### Manual Setup

```bash
# Install dependencies
npm install

# Database setup
npm run db:generate
npm run db:push
npm run db:seed

# Start services individually
npm run dev:web     # Frontend only
npm run dev:api     # Backend only
npm run dev:all     # Everything
```

### Environment Configuration

Create `.env` file:
```env
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/sparc
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-secret-key-here
JWT_EXPIRES_IN=1d

# Services
API_GATEWAY_URL=http://localhost:3000
WEB_APP_URL=http://localhost:3003

# Storage
S3_BUCKET=sparc-dev
S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
```

## Docker Deployment

### Building Images

```bash
# Build all services
npm run build:docker

# Build specific service
docker build -f services/api-gateway/Dockerfile -t sparc/api-gateway:latest .

# Build with BuildKit (recommended)
DOCKER_BUILDKIT=1 docker build --target production -f services/api-gateway/Dockerfile -t sparc/api-gateway:latest .
```

### Docker Compose Deployment

```bash
# Start all services
docker-compose up -d

# Scale specific services
docker-compose up -d --scale video-processor=3

# View logs
docker-compose logs -f api-gateway

# Stop services
docker-compose down
```

### Docker Compose Configuration

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: sparc
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    ports:
      - "6379:6379"

  api-gateway:
    image: sparc/api-gateway:latest
    environment:
      DATABASE_URL: postgresql://postgres:${DB_PASSWORD}@postgres:5432/sparc
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
      JWT_SECRET: ${JWT_SECRET}
    ports:
      - "3000:3000"
    depends_on:
      - postgres
      - redis

  # Additional services...
```

## Kubernetes Deployment

### Cluster Setup

**Local Kubernetes (Minikube)**
```bash
# Start cluster
minikube start --cpus=4 --memory=8192 --disk-size=50g

# Enable addons
minikube addons enable ingress
minikube addons enable metrics-server
```

**Production Kubernetes**
See cloud-specific sections for managed Kubernetes setup.

### Deploying with Helm

```bash
# Add SPARC Helm repository
helm repo add sparc https://charts.sparc.io
helm repo update

# Install SPARC
helm install sparc sparc/sparc \
  --namespace sparc \
  --create-namespace \
  --values values-production.yaml
```

### Helm Values Configuration

```yaml
# values-production.yaml
global:
  image:
    registry: your-registry.io
    tag: v1.0.0
    pullPolicy: IfNotPresent

  ingress:
    enabled: true
    hostname: sparc.company.com
    tls:
      enabled: true
      secretName: sparc-tls

  postgresql:
    enabled: true
    auth:
      postgresPassword: secure-password
      database: sparc

  redis:
    enabled: true
    auth:
      enabled: true
      password: secure-redis-password

services:
  apiGateway:
    replicas: 3
    resources:
      requests:
        cpu: 500m
        memory: 512Mi
      limits:
        cpu: 2000m
        memory: 2Gi

  videoProcessor:
    replicas: 5
    resources:
      requests:
        cpu: 1000m
        memory: 2Gi
      limits:
        cpu: 4000m
        memory: 8Gi

# Additional service configurations...
```

### Applying Kubernetes Manifests

```bash
# Apply base manifests
kubectl apply -k k8s/base

# Apply environment-specific overlays
kubectl apply -k k8s/overlays/production

# Verify deployment
kubectl get pods -n sparc
kubectl get svc -n sparc
kubectl get ingress -n sparc
```

## Cloud-Specific Deployments

### AWS Deployment

#### Infrastructure Setup with CDK

```bash
# Configure AWS credentials
aws configure

# Bootstrap CDK
cdk bootstrap aws://ACCOUNT-ID/REGION

# Deploy infrastructure
cd infra/aws
cdk deploy SparcProductionStack \
  --parameters VpcCidr=10.0.0.0/16 \
  --parameters Environment=production \
  --parameters DomainName=sparc.company.com
```

#### EKS Cluster Deployment

```bash
# Create EKS cluster
eksctl create cluster \
  --name sparc-production \
  --version 1.28 \
  --region us-east-1 \
  --nodegroup-name worker-nodes \
  --node-type m5.xlarge \
  --nodes 5 \
  --nodes-min 3 \
  --nodes-max 10 \
  --managed

# Configure kubectl
aws eks update-kubeconfig --region us-east-1 --name sparc-production

# Install AWS Load Balancer Controller
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller/crds"
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=sparc-production
```

#### RDS Database Setup

```bash
# Create RDS instance (via CDK or manually)
aws rds create-db-instance \
  --db-instance-identifier sparc-production-db \
  --db-instance-class db.r6g.2xlarge \
  --engine postgres \
  --engine-version 15.4 \
  --master-username postgres \
  --master-user-password $DB_PASSWORD \
  --allocated-storage 100 \
  --storage-encrypted \
  --backup-retention-period 30 \
  --multi-az \
  --vpc-security-group-ids sg-xxxxxx
```

### Azure Deployment

#### Resource Group and AKS Setup

```bash
# Create resource group
az group create --name sparc-production --location eastus

# Create AKS cluster
az aks create \
  --resource-group sparc-production \
  --name sparc-aks \
  --node-count 5 \
  --node-vm-size Standard_D4s_v3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group sparc-production --name sparc-aks

# Create Azure Database for PostgreSQL
az postgres server create \
  --resource-group sparc-production \
  --name sparc-db \
  --location eastus \
  --admin-user postgres \
  --admin-password $DB_PASSWORD \
  --sku-name GP_Gen5_4 \
  --version 11
```

### Google Cloud Platform

#### GKE Cluster Setup

```bash
# Set project
gcloud config set project YOUR-PROJECT-ID

# Create GKE cluster
gcloud container clusters create sparc-production \
  --zone us-central1-a \
  --num-nodes 5 \
  --machine-type n2-standard-4 \
  --enable-autoscaling \
  --min-nodes 3 \
  --max-nodes 10 \
  --enable-autorepair \
  --enable-stackdriver-kubernetes

# Get credentials
gcloud container clusters get-credentials sparc-production --zone us-central1-a

# Create Cloud SQL instance
gcloud sql instances create sparc-db \
  --database-version=POSTGRES_15 \
  --tier=db-n1-standard-4 \
  --region=us-central1 \
  --network=default \
  --backup-start-time=03:00
```

## Production Deployment

### Pre-Deployment Checklist

- [ ] **Infrastructure**: All cloud resources provisioned
- [ ] **Security**: SSL certificates, firewalls, IAM roles configured
- [ ] **Database**: Production database created and secured
- [ ] **Secrets**: All secrets stored in Secret Manager/Key Vault
- [ ] **Monitoring**: Prometheus, Grafana, alerting configured
- [ ] **Backup**: Automated backup procedures in place
- [ ] **Load Testing**: Performance validated under expected load
- [ ] **Documentation**: Runbooks and procedures updated

### Deployment Steps

1. **Database Migration**
   ```bash
   # Run migrations
   npm run db:migrate:production
   
   # Verify schema
   npm run db:validate:production
   ```

2. **Deploy Services**
   ```bash
   # Deploy using Helm
   helm upgrade --install sparc sparc/sparc \
     --namespace sparc \
     --values values-production.yaml \
     --atomic \
     --timeout 10m
   ```

3. **Verify Deployment**
   ```bash
   # Check pod status
   kubectl get pods -n sparc
   
   # Run health checks
   ./scripts/health-check.sh production
   
   # Smoke tests
   npm run test:smoke:production
   ```

4. **Configure DNS**
   ```bash
   # Update DNS records to point to load balancer
   # Get load balancer endpoint
   kubectl get ingress -n sparc
   ```

### Blue-Green Deployment

```bash
# Deploy to green environment
helm install sparc-green sparc/sparc \
  --namespace sparc-green \
  --values values-production-green.yaml

# Test green environment
./scripts/test-environment.sh sparc-green

# Switch traffic
kubectl patch ingress sparc-ingress \
  -n sparc \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/rules/0/http/paths/0/backend/service/name", "value":"sparc-green"}]'

# Remove blue environment after validation
helm uninstall sparc-blue -n sparc-blue
```

## Post-Deployment Configuration

### Multi-Tenant Setup

```bash
# Create initial organization
curl -X POST https://api.sparc.company.com/v1/organizations \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ACME Corporation",
    "subdomain": "acme",
    "settings": {
      "maxUsers": 1000,
      "maxSites": 10,
      "features": ["video", "analytics", "incidents"]
    }
  }'
```

### SSL/TLS Configuration

```bash
# Using cert-manager for automatic certificate management
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create certificate issuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@company.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

### Security Hardening

```bash
# Apply network policies
kubectl apply -f k8s/security/network-policies.yaml

# Configure pod security policies
kubectl apply -f k8s/security/pod-security-policies.yaml

# Enable audit logging
kubectl apply -f k8s/security/audit-policy.yaml
```

## Monitoring and Observability

### Prometheus Setup

```bash
# Install Prometheus Operator
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --values monitoring/prometheus-values.yaml
```

### Grafana Dashboards

```bash
# Import SPARC dashboards
kubectl apply -f monitoring/dashboards/

# Access Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80
# Default credentials: admin/prom-operator
```

### Log Aggregation

```bash
# Install Fluentd
kubectl apply -f monitoring/fluentd-config.yaml
kubectl apply -f monitoring/fluentd-daemonset.yaml

# Configure log forwarding to CloudWatch/Azure Monitor/Stackdriver
```

## Backup and Recovery

### Database Backups

```bash
# Manual backup
kubectl exec -n sparc postgres-0 -- pg_dump -U postgres sparc > backup-$(date +%Y%m%d).sql

# Automated backups (CronJob)
kubectl apply -f k8s/backup/postgres-backup-cronjob.yaml
```

### Application State Backup

```bash
# Backup persistent volumes
velero backup create sparc-backup --include-namespaces sparc

# Restore from backup
velero restore create --from-backup sparc-backup
```

## Troubleshooting

### Common Issues

#### Pods Not Starting
```bash
# Check pod events
kubectl describe pod <pod-name> -n sparc

# Check logs
kubectl logs <pod-name> -n sparc --previous

# Check resource constraints
kubectl top nodes
kubectl top pods -n sparc
```

#### Database Connection Issues
```bash
# Test database connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- psql -h postgres-service -U postgres

# Check database logs
kubectl logs postgres-0 -n sparc
```

#### Service Discovery Issues
```bash
# Check services
kubectl get svc -n sparc

# Test DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup api-gateway.sparc.svc.cluster.local
```

### Performance Issues

```bash
# Check resource usage
kubectl top pods -n sparc --sort-by=cpu
kubectl top pods -n sparc --sort-by=memory

# Scale services
kubectl scale deployment api-gateway -n sparc --replicas=5

# Check HPA status
kubectl get hpa -n sparc
```

## Rollback Procedures

### Helm Rollback

```bash
# List releases
helm list -n sparc

# Check release history
helm history sparc -n sparc

# Rollback to previous version
helm rollback sparc 1 -n sparc

# Rollback with specific revision
helm rollback sparc 3 -n sparc --wait
```

### Database Rollback

```bash
# Stop application
kubectl scale deployment --all --replicas=0 -n sparc

# Restore database
kubectl exec -n sparc postgres-0 -- psql -U postgres -d sparc < backup-20240119.sql

# Start application
kubectl scale deployment --all --replicas=3 -n sparc
```

### Emergency Procedures

```bash
# Switch to maintenance mode
kubectl apply -f k8s/maintenance/maintenance-page.yaml

# Redirect traffic to maintenance page
kubectl patch ingress sparc-ingress -n sparc --type='json' \
  -p='[{"op": "replace", "path": "/spec/rules/0/http/paths/0/backend/service/name", "value":"maintenance-service"}]'

# Investigate and fix issues
# ...

# Restore normal operation
kubectl patch ingress sparc-ingress -n sparc --type='json' \
  -p='[{"op": "replace", "path": "/spec/rules/0/http/paths/0/backend/service/name", "value":"api-gateway"}]'
```

## Best Practices

1. **Always test in staging** before production deployment
2. **Use GitOps** for configuration management
3. **Implement proper monitoring** before going live
4. **Document all customizations** and configurations
5. **Regular backup testing** to ensure recovery procedures work
6. **Security scanning** of images and configurations
7. **Load testing** to validate performance under stress
8. **Gradual rollouts** using canary or blue-green deployments

## Support

- **Documentation**: See `/docs` directory
- **Issues**: GitHub Issues
- **Emergency**: Follow incident response procedures
- **Community**: Slack channel #sparc-deployment

---

*For specific cloud provider details, see the respective sections. For development setup, refer to the [Development Guide](../development/contributing.md).*