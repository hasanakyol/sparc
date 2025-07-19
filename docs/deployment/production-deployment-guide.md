# SPARC Platform Production Deployment Guide

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Infrastructure Deployment with CDK](#infrastructure-deployment-with-cdk)
4. [Kubernetes Cluster Setup](#kubernetes-cluster-setup)
5. [Service Deployment](#service-deployment)
6. [Database Migration and Tenant Setup](#database-migration-and-tenant-setup)
7. [Monitoring and Alerting Configuration](#monitoring-and-alerting-configuration)
8. [Security Hardening](#security-hardening)
9. [Post-Deployment Validation](#post-deployment-validation)
10. [Rollback Procedures](#rollback-procedures)
11. [Troubleshooting Guide](#troubleshooting-guide)
12. [Maintenance Procedures](#maintenance-procedures)

## Overview

This guide provides comprehensive instructions for deploying the fully functional SPARC platform to production environments. The SPARC platform is a complete access control and security management system with 85-90% functional implementation including:

### Architecture Components

- **20 Microservices**: Complete implementation including auth-service, access-control-service, video-management-service, device-management-service, tenant-service, event-processing-service, analytics-service, mobile-credential-service, environmental-service, visitor-management-service, reporting-service, and more
- **Web Application**: Next.js frontend with 250+ UI components, comprehensive dashboard, and real-time capabilities
- **Database**: Multi-tenant PostgreSQL Aurora cluster with Redis caching and full schema implementation
- **Infrastructure**: Complete AWS CDK infrastructure with EKS, RDS, ElastiCache, S3, CloudFront, and monitoring
- **Security**: End-to-end encryption, multi-factor authentication, RBAC, and compliance controls (SOX, HIPAA, PCI-DSS)
- **Offline Resilience**: 72-hour offline operation with mesh networking and local storage
- **Real-time Features**: WebSocket connections, live video streaming, and instant notifications

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CloudFront CDN                          │
│                    (Video & Static Assets)                     │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────────┐
│                Application Load Balancer                       │
│                     (SSL Termination)                          │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────────┐
│                    EKS Cluster                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │ API Gateway │ │ Auth Service│ │ Web App     │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │Access Ctrl  │ │Video Mgmt   │ │Device Mgmt  │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │Analytics    │ │Event Proc   │ │Mobile Cred  │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────────┐
│                    Data Layer                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │PostgreSQL   │ │Redis Cache  │ │S3 Storage   │              │
│  │Aurora       │ │ElastiCache  │ │Video/Docs   │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### AWS Account Setup

#### Required AWS Services and Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:*",
        "ec2:*",
        "rds:*",
        "elasticache:*",
        "s3:*",
        "cloudfront:*",
        "route53:*",
        "acm:*",
        "iam:*",
        "kms:*",
        "logs:*",
        "cloudwatch:*",
        "sns:*",
        "sqs:*",
        "secretsmanager:*",
        "ssm:*",
        "backup:*",
        "opensearch:*"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Domain Configuration

1. **Primary Domain**: `sparc.company`
2. **API Subdomain**: `api.sparc.company`
3. **CDN Subdomain**: `cdn.sparc.company`
4. **Admin Subdomain**: `admin.sparc.company`

#### SSL Certificate Management

```bash
# Request wildcard certificate for all subdomains
aws acm request-certificate \
  --domain-name "sparc.company" \
  --subject-alternative-names "*.sparc.company" \
  --validation-method DNS \
  --region us-east-1

# Validate domain ownership
aws acm describe-certificate --certificate-arn arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT-ID
```

### Infrastructure Requirements Checklist

- [ ] AWS Account with CDK deployment permissions
- [ ] Domain name registered and DNS configured
- [ ] SSL certificates requested and validated
- [ ] AWS CLI and CDK CLI installed and configured
- [ ] kubectl and helm installed
- [ ] Docker installed for image building
- [ ] Node.js 18+ and npm installed
- [ ] Git repository access configured

### Application Requirements Checklist

- [ ] All 24 microservices code reviewed and tested
- [ ] Database schema and migrations validated
- [ ] Environment-specific configuration prepared
- [ ] Secrets and credentials securely stored
- [ ] Container images built and scanned
- [ ] Kubernetes manifests prepared
- [ ] Monitoring and logging configured

### Security Requirements Checklist

- [ ] SSL/TLS certificates obtained and validated
- [ ] WAF rules configured for protection
- [ ] Security scanning completed (SAST/DAST)
- [ ] Penetration testing performed
- [ ] Compliance requirements validated (SOX, HIPAA, PCI-DSS)
- [ ] Audit logging and monitoring configured
- [ ] RBAC and IAM policies reviewed
- [ ] Encryption at rest and in transit configured

### Team Readiness Checklist

- [ ] Deployment team trained on procedures
- [ ] Rollback procedures documented and tested
- [ ] Emergency contacts and escalation paths established
- [ ] Monitoring dashboards and alerts configured
- [ ] Incident response procedures documented
- [ ] Change management process established
- [ ] Communication plan for deployment

## Infrastructure Deployment with CDK

### 1. CDK Environment Setup

#### Install CDK and Dependencies

```bash
# Install AWS CDK CLI
npm install -g aws-cdk

# Navigate to infrastructure directory
cd infra

# Install dependencies
npm install

# Bootstrap CDK (one-time setup per account/region)
cdk bootstrap aws://ACCOUNT-NUMBER/us-west-2
```

#### Configure CDK Context

Create `cdk.context.json`:

```json
{
  "environment": "production",
  "domainName": "sparc.company",
  "certificateArn": "arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT-ID",
  "hostedZoneId": "Z1234567890ABC",
  "enableDeletionProtection": true,
  "enableBackup": true,
  "multiAz": true
}
```

### 2. Deploy Infrastructure Stacks

#### Deploy Core Infrastructure

```bash
# Deploy main SPARC stack with VPC, EKS, RDS, Redis, S3, CloudFront
cdk deploy SparcStack-production \
  --parameters environment=production \
  --parameters domainName=sparc.company \
  --parameters certificateArn=arn:aws:acm:us-east-1:ACCOUNT:certificate/CERT-ID \
  --require-approval never

# Deploy security stack with KMS, WAF, security groups
cdk deploy SecurityStack-production \
  --require-approval never

# Deploy monitoring stack with CloudWatch, SNS, alarms
cdk deploy MonitoringStack-production \
  --require-approval never

# Deploy Kubernetes integration stack
cdk deploy KubernetesIntegrationStack-production \
  --require-approval never
```

#### Verify Infrastructure Deployment

```bash
# Check stack status
cdk list
aws cloudformation describe-stacks --stack-name SparcStack-production

# Get infrastructure outputs
aws cloudformation describe-stacks \
  --stack-name SparcStack-production \
  --query 'Stacks[0].Outputs'
```

### 3. Infrastructure Components Created

The CDK deployment creates the following components:

#### Networking
- **VPC**: 10.0.0.0/16 with 3 AZs for high availability
- **Public Subnets**: For load balancers and NAT gateways
- **Private Subnets**: For EKS worker nodes
- **Database Subnets**: Isolated subnets for RDS
- **Security Groups**: Properly configured for each tier

#### Compute
- **EKS Cluster**: Kubernetes 1.28 with managed node groups
- **General Node Group**: m5.xlarge instances for general workloads
- **Video Node Group**: c5n.2xlarge instances for video processing
- **Auto Scaling**: Configured for 3-20 nodes based on demand

#### Database
- **RDS Aurora PostgreSQL**: Multi-AZ cluster with 3 instances
- **ElastiCache Redis**: Multi-AZ replication group
- **Backup Configuration**: 30-day retention with point-in-time recovery

#### Storage
- **S3 Video Bucket**: Encrypted storage with lifecycle policies
- **S3 Backup Bucket**: Cross-region replication enabled
- **CloudFront Distribution**: Global CDN for video delivery

#### Security
- **KMS Keys**: Customer-managed encryption keys
- **IAM Roles**: Service-specific roles with least privilege
- **Security Groups**: Network-level access controls
- **WAF**: Web application firewall rules

#### Monitoring
- **CloudWatch**: Comprehensive logging and metrics
- **SNS Topics**: Alert notifications
- **OpenSearch**: Log aggregation and analytics

## Kubernetes Cluster Setup

### 1. Configure kubectl Access

```bash
# Update kubeconfig for EKS cluster
aws eks update-kubeconfig \
  --region us-west-2 \
  --name sparc-production

# Verify cluster access
kubectl cluster-info
kubectl get nodes
```

### 2. Install Required Add-ons

#### AWS Load Balancer Controller

```bash
# Create IAM role for AWS Load Balancer Controller
eksctl create iamserviceaccount \
  --cluster=sparc-production \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn=arn:aws:iam::ACCOUNT:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

# Install AWS Load Balancer Controller
helm repo add eks https://aws.github.io/eks-charts
helm repo update

helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=sparc-production \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
```

#### External Secrets Operator

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace

# Create SecretStore for AWS Secrets Manager
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets-manager
  namespace: sparc
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-west-2
      auth:
        serviceAccount:
          name: external-secrets-sa
EOF
```

#### Cluster Autoscaler

```bash
# Install Cluster Autoscaler
kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml

# Configure for EKS cluster
kubectl -n kube-system annotate deployment.apps/cluster-autoscaler \
  cluster-autoscaler.kubernetes.io/safe-to-evict="false"

kubectl -n kube-system edit deployment.apps/cluster-autoscaler
# Add --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/sparc-production
```

### 3. Deploy RBAC Configuration

```bash
# Apply RBAC manifests
kubectl apply -f k8s/rbac.yaml

# Verify RBAC setup
kubectl get serviceaccounts -n sparc
kubectl get roles,rolebindings -n sparc
kubectl get clusterroles,clusterrolebindings | grep sparc
```

### 4. Create Namespace and ConfigMaps

```bash
# Create SPARC namespace
kubectl create namespace sparc

# Create ConfigMaps from CDK outputs
kubectl create configmap sparc-config -n sparc \
  --from-literal=DATABASE_HOST=$(aws ssm get-parameter --name /sparc/production/database/host --query 'Parameter.Value' --output text) \
  --from-literal=REDIS_HOST=$(aws ssm get-parameter --name /sparc/production/redis/host --query 'Parameter.Value' --output text) \
  --from-literal=S3_BUCKET=$(aws ssm get-parameter --name /sparc/production/s3/video-bucket --query 'Parameter.Value' --output text) \
  --from-literal=CLOUDFRONT_DOMAIN=$(aws ssm get-parameter --name /sparc/production/cloudfront/domain --query 'Parameter.Value' --output text)

# Create secrets from AWS Secrets Manager
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: sparc-database-credentials
  namespace: sparc
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: sparc-db-credentials
    creationPolicy: Owner
  data:
  - secretKey: username
    remoteRef:
      key: sparc-production/database
      property: username
  - secretKey: password
    remoteRef:
      key: sparc-production/database
      property: password
EOF
```

## Service Deployment

### 1. Build and Push Container Images

```bash
# Use the automated deployment script
cd /Users/hasanakyol/Code/sparc
./scripts/deploy.sh -e production -t $(git rev-parse --short HEAD) --rollback

# Or manually build and push images
export ECR_REGISTRY=$(aws sts get-caller-identity --query Account --output text).dkr.ecr.us-west-2.amazonaws.com
export IMAGE_TAG=$(git rev-parse --short HEAD)

# Login to ECR
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin $ECR_REGISTRY

# Build and push each service
for service in auth-service api-gateway access-control-service video-management-service device-management-service tenant-service event-processing-service analytics-service mobile-credential-service environmental-service visitor-management-service reporting-service; do
  echo "Building $service..."
  docker build -t $ECR_REGISTRY/sparc-$service:$IMAGE_TAG services/$service/
  docker push $ECR_REGISTRY/sparc-$service:$IMAGE_TAG
done

# Build and push web application
docker build -t $ECR_REGISTRY/sparc-web:$IMAGE_TAG web/
docker push $ECR_REGISTRY/sparc-web:$IMAGE_TAG
```

### 2. Deploy Services in Order

#### Core Infrastructure Services

```bash
# Deploy Services (networking layer)
kubectl apply -f k8s/services/

# Deploy Ingress Controller
kubectl apply -f k8s/ingress.yaml

# Verify ingress setup
kubectl get ingress -n sparc
kubectl describe ingress sparc-ingress -n sparc
```

#### Authentication and Core Services

```bash
# Deploy auth-service first (required by other services)
envsubst < k8s/auth-service.yaml | kubectl apply -f -
kubectl rollout status deployment/auth-service -n sparc

# Deploy tenant-service
envsubst < k8s/tenant-service.yaml | kubectl apply -f -
kubectl rollout status deployment/tenant-service -n sparc

# Deploy api-gateway
envsubst < k8s/api-gateway.yaml | kubectl apply -f -
kubectl rollout status deployment/api-gateway -n sparc
```

#### Business Logic Services

```bash
# Deploy access control service
envsubst < k8s/access-control-service.yaml | kubectl apply -f -
kubectl rollout status deployment/access-control-service -n sparc

# Deploy video management service
envsubst < k8s/video-management-service.yaml | kubectl apply -f -
kubectl rollout status deployment/video-management-service -n sparc

# Deploy device management service
envsubst < k8s/device-management-service.yaml | kubectl apply -f -
kubectl rollout status deployment/device-management-service -n sparc

# Deploy event processing service
envsubst < k8s/event-processing-service.yaml | kubectl apply -f -
kubectl rollout status deployment/event-processing-service -n sparc

# Deploy analytics service
envsubst < k8s/analytics-service.yaml | kubectl apply -f -
kubectl rollout status deployment/analytics-service -n sparc

# Deploy mobile credential service
envsubst < k8s/mobile-credential-service.yaml | kubectl apply -f -
kubectl rollout status deployment/mobile-credential-service -n sparc
```

#### Supporting Services

```bash
# Deploy environmental service
envsubst < k8s/environmental-service.yaml | kubectl apply -f -
kubectl rollout status deployment/environmental-service -n sparc

# Deploy visitor management service
envsubst < k8s/visitor-management-service.yaml | kubectl apply -f -
kubectl rollout status deployment/visitor-management-service -n sparc

# Deploy reporting service
envsubst < k8s/reporting-service.yaml | kubectl apply -f -
kubectl rollout status deployment/reporting-service -n sparc
```

#### Web Application

```bash
# Deploy web application
envsubst < k8s/web-app.yaml | kubectl apply -f -
kubectl rollout status deployment/web-app -n sparc
```

### 3. Verify Service Deployment

```bash
# Check all deployments
kubectl get deployments -n sparc

# Check all pods
kubectl get pods -n sparc

# Check services
kubectl get services -n sparc

# Check ingress
kubectl get ingress -n sparc

# Test service connectivity
kubectl exec -it deployment/api-gateway -n sparc -- curl http://auth-service:3001/health
kubectl exec -it deployment/api-gateway -n sparc -- curl http://access-control-service:3002/health
```

### 4. Configure Horizontal Pod Autoscaling

```bash
# Apply HPA configurations
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: sparc
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
EOF

# Apply HPA for video-intensive services
kubectl apply -f - <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: video-management-service-hpa
  namespace: sparc
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: video-management-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 60
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 70
EOF
```

## Database Migration and Tenant Setup

### 1. Run Database Migrations

```bash
# Create migration job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: sparc-migration-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: migration
        image: $ECR_REGISTRY/sparc-auth-service:$IMAGE_TAG
        command: ["npm", "run", "migrate:production"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: sparc-db-credentials
              key: url
        - name: NODE_ENV
          value: "production"
      restartPolicy: Never
  backoffLimit: 3
EOF

# Wait for migration to complete
kubectl wait --for=condition=complete job/sparc-migration-* -n sparc --timeout=600s

# Check migration logs
kubectl logs job/sparc-migration-* -n sparc
```

### 2. Initialize Default Tenant

```bash
# Create tenant initialization job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: sparc-tenant-init-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: tenant-init
        image: $ECR_REGISTRY/sparc-tenant-service:$IMAGE_TAG
        command: ["npm", "run", "init:default-tenant"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: sparc-db-credentials
              key: url
        - name: ADMIN_EMAIL
          value: "admin@sparc.company"
        - name: ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: sparc-admin-credentials
              key: password
      restartPolicy: Never
  backoffLimit: 3
EOF

# Wait for tenant initialization
kubectl wait --for=condition=complete job/sparc-tenant-init-* -n sparc --timeout=300s
```

### 3. Seed Initial Data

```bash
# Create data seeding job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: sparc-data-seed-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: data-seed
        image: $ECR_REGISTRY/sparc-tenant-service:$IMAGE_TAG
        command: ["npm", "run", "seed:production"]
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: sparc-db-credentials
              key: url
        - name: TENANT_ID
          value: "default"
      restartPolicy: Never
  backoffLimit: 3
EOF

# Verify data seeding
kubectl logs job/sparc-data-seed-* -n sparc
```

### 4. Configure Multi-Tenant Isolation

```bash
# Apply tenant isolation policies
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-isolation
  namespace: sparc
spec:
  podSelector:
    matchLabels:
      app: sparc
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: sparc
    - namespaceSelector:
        matchLabels:
          name: sparc
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: sparc
  - to: []
    ports:
    - protocol: TCP
      port: 5432  # Database
    - protocol: TCP
      port: 6379  # Redis
    - protocol: TCP
      port: 443   # HTTPS
    - protocol: TCP
      port: 53    # DNS
    - protocol: UDP
      port: 53    # DNS
EOF
```

## Monitoring and Alerting Configuration

### 1. Deploy Monitoring Stack

```bash
# Apply ServiceMonitor resources for Prometheus
kubectl apply -f k8s/monitoring/

# Apply PrometheusRule resources for alerting
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: sparc-alerts
  namespace: sparc
spec:
  groups:
  - name: sparc.rules
    rules:
    - alert: SparcServiceDown
      expr: up{job=~"sparc-.*"} == 0
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "SPARC service {{ \$labels.job }} is down"
        description: "Service {{ \$labels.job }} has been down for more than 5 minutes"
    
    - alert: SparcHighCPU
      expr: rate(container_cpu_usage_seconds_total{namespace="sparc"}[5m]) > 0.8
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "High CPU usage in SPARC namespace"
        description: "CPU usage is above 80% for {{ \$labels.pod }}"
    
    - alert: SparcHighMemory
      expr: container_memory_usage_bytes{namespace="sparc"} / container_spec_memory_limit_bytes > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage in SPARC namespace"
        description: "Memory usage is above 90% for {{ \$labels.pod }}"
    
    - alert: SparcDatabaseConnections
      expr: pg_stat_database_numbackends{datname="sparc"} > 80
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High database connection count"
        description: "Database has {{ \$value }} active connections"
EOF
```

### 2. Configure Grafana Dashboards

```bash
# Create Grafana dashboard ConfigMap
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: sparc-dashboard
  namespace: monitoring
data:
  sparc-overview.json: |
    {
      "dashboard": {
        "title": "SPARC Platform Overview",
        "panels": [
          {
            "title": "Service Health",
            "type": "stat",
            "targets": [
              {
                "expr": "up{job=~\"sparc-.*\"}",
                "legendFormat": "{{ job }}"
              }
            ]
          },
          {
            "title": "Request Rate",
            "type": "graph",
            "targets": [
              {
                "expr": "rate(http_requests_total{namespace=\"sparc\"}[5m])",
                "legendFormat": "{{ service }}"
              }
            ]
          },
          {
            "title": "Response Time",
            "type": "graph",
            "targets": [
              {
                "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{namespace=\"sparc\"}[5m]))",
                "legendFormat": "95th percentile"
              }
            ]
          },
          {
            "title": "Database Performance",
            "type": "graph",
            "targets": [
              {
                "expr": "rate(pg_stat_database_tup_returned{datname=\"sparc\"}[5m])",
                "legendFormat": "Rows returned/sec"
              }
            ]
          }
        ]
      }
    }
EOF
```

### 3. Configure CloudWatch Integration

```bash
# Deploy CloudWatch agent for container insights
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: cwagentconfig
  namespace: amazon-cloudwatch
data:
  cwagentconfig.json: |
    {
      "logs": {
        "metrics_collected": {
          "kubernetes": {
            "cluster_name": "sparc-production",
            "metrics_collection_interval": 60
          }
        },
        "force_flush_interval": 5
      },
      "metrics": {
        "namespace": "CWAgent",
        "metrics_collected": {
          "cpu": {
            "measurement": ["cpu_usage_idle", "cpu_usage_iowait", "cpu_usage_user", "cpu_usage_system"],
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
      }
    }
EOF

# Apply CloudWatch agent DaemonSet
kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/cloudwatch-namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/cwagent/cwagent-daemonset.yaml
```

### 4. Set Up Custom Metrics

```bash
# Deploy custom metrics for SPARC-specific monitoring
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: sparc-metrics-config
  namespace: sparc
data:
  metrics.yaml: |
    metrics:
      - name: door_access_rate
        description: "Rate of door access events"
        type: counter
        labels: ["tenant_id", "door_id", "access_type"]
      
      - name: video_stream_health
        description: "Health status of video streams"
        type: gauge
        labels: ["camera_id", "stream_quality"]
      
      - name: offline_device_count
        description: "Number of devices currently offline"
        type: gauge
        labels: ["device_type", "location"]
      
      - name: authentication_latency
        description: "Authentication request latency"
        type: histogram
        labels: ["auth_method", "tenant_id"]
EOF
```

## Security Hardening

### 1. Network Security

#### Pod Security Standards

```bash
# Apply Pod Security Standards
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: sparc
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
EOF
```

#### Network Policies

```bash
# Apply comprehensive network policies
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sparc-network-policy
  namespace: sparc
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - podSelector:
        matchLabels:
          app: sparc
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: sparc
  - to: []
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
    - protocol: TCP
      port: 6379  # Redis
    - protocol: TCP
      port: 443   # HTTPS
    - protocol: TCP
      port: 53    # DNS
    - protocol: UDP
      port: 53    # DNS
EOF
```

### 2. RBAC Configuration

```bash
# Apply service-specific RBAC
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sparc-auth-service
  namespace: sparc
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/sparc-auth-service-role
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sparc-auth-service-role
  namespace: sparc
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sparc-auth-service-binding
  namespace: sparc
subjects:
- kind: ServiceAccount
  name: sparc-auth-service
  namespace: sparc
roleRef:
  kind: Role
  name: sparc-auth-service-role
  apiGroup: rbac.authorization.k8s.io
EOF
```

### 3. Security Scanning and Compliance

```bash
# Run security scan on deployed containers
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: security-scan-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: trivy-scanner
        image: aquasec/trivy:latest
        command: ["trivy"]
        args: ["image", "--exit-code", "1", "--severity", "HIGH,CRITICAL", "$ECR_REGISTRY/sparc-auth-service:$IMAGE_TAG"]
      restartPolicy: Never
  backoffLimit: 1
EOF

# Check compliance with security policies
kubectl get pods -n sparc -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext}{"\n"}{end}'
```

### 4. Secrets Management

```bash
# Rotate secrets regularly
kubectl create secret generic sparc-jwt-secret \
  --from-literal=secret=$(openssl rand -base64 32) \
  --namespace=sparc \
  --dry-run=client -o yaml | kubectl apply -f -

# Update database credentials
aws secretsmanager update-secret \
  --secret-id sparc-production/database \
  --secret-string "{\"username\":\"sparcadmin\",\"password\":\"$(openssl rand -base64 32)\"}"

# Restart services to pick up new secrets
kubectl rollout restart deployment/auth-service -n sparc
```

## Post-Deployment Validation

### 1. Comprehensive Health Checks

```bash
# Run the validation suite
cd /Users/hasanakyol/Code/sparc
./scripts/validation-suite.sh

# Check all service health endpoints
for service in auth-service api-gateway access-control-service video-management-service device-management-service tenant-service event-processing-service analytics-service mobile-credential-service; do
  echo "Checking $service health..."
  kubectl exec -it deployment/api-gateway -n sparc -- curl -f http://$service:$(kubectl get service $service -n sparc -o jsonpath='{.spec.ports[0].port}')/health || echo "$service health check failed"
done

# Test external access
curl -f https://sparc.company/health || echo "Web application health check failed"
curl -f https://api.sparc.company/health || echo "API Gateway health check failed"
```

### 2. Integration Testing

```bash
# Run end-to-end requirements validation
cd tests/validation
npm test -- --testNamePattern="REQ-01|REQ-02|REQ-03|REQ-04|REQ-05"

# Test authentication flow
curl -X POST https://api.sparc.company/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sparc.company","password":"admin123"}' \
  -c cookies.txt

# Test access control
curl -X POST https://api.sparc.company/access-control/doors/door-001/access \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat token.txt)" \
  -d '{"credentialId":"card-123","accessType":"entry"}'

# Test video management
curl -X GET https://api.sparc.company/video-management/cameras \
  -H "Authorization: Bearer $(cat token.txt)"

# Test real-time features
wscat -c wss://api.sparc.company/ws/events \
  -H "Authorization: Bearer $(cat token.txt)"
```

### 3. Performance Validation

```bash
# Run performance tests
cd tests/performance
node scalability-validation.js

# Load test with realistic patterns
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: load-test-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: load-test
        image: loadimpact/k6:latest
        command: ["k6", "run", "--vus", "100", "--duration", "10m", "/scripts/load-test.js"]
        volumeMounts:
        - name: test-scripts
          mountPath: /scripts
      volumes:
      - name: test-scripts
        configMap:
          name: load-test-scripts
      restartPolicy: Never
EOF

# Monitor performance during load test
kubectl top pods -n sparc
kubectl get hpa -n sparc
```

### 4. Security Validation

```bash
# Run security validation
npm run test:security

# Test WAF protection
curl -X POST https://api.sparc.company/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sparc.company","password":"admin123 OR 1=1"}' \
  --max-time 10

# Test rate limiting
for i in {1..100}; do
  curl -X POST https://api.sparc.company/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrongpassword"}' &
done
wait

# Verify SSL/TLS configuration
testssl.sh https://sparc.company
testssl.sh https://api.sparc.company
```

### 5. Compliance Validation

```bash
# Run compliance checks
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: compliance-check-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: compliance-checker
        image: $ECR_REGISTRY/sparc-security-compliance-service:$IMAGE_TAG
        command: ["npm", "run", "compliance:validate"]
        env:
        - name: COMPLIANCE_STANDARDS
          value: "SOX,HIPAA,PCI-DSS"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: sparc-db-credentials
              key: url
      restartPolicy: Never
EOF

# Check audit logging
kubectl logs -l app=sparc -n sparc --since=1h | grep -i audit | head -20

# Verify data encryption
kubectl exec -it deployment/auth-service -n sparc -- \
  psql $DATABASE_URL -c "SELECT pg_is_in_recovery(), current_setting('ssl');"
```

### 6. Offline Resilience Testing

```bash
# Test offline operation capabilities
cd tests/offline
npm test -- --testNamePattern="mesh-networking"

# Simulate network partition
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: simulate-partition
  namespace: sparc
spec:
  podSelector:
    matchLabels:
      app: access-control-service
  policyTypes:
  - Egress
  egress: []
EOF

# Wait and test offline functionality
sleep 30
curl -X POST https://api.sparc.company/access-control/doors/door-001/access \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat token.txt)" \
  -d '{"credentialId":"card-123","accessType":"entry","offline":true}'

# Restore connectivity
kubectl delete networkpolicy simulate-partition -n sparc
```

## Rollback Procedures

### 1. Automated Rollback

```bash
# Use the deployment script with rollback capability
./scripts/deploy.sh -e production --rollback

# Or manually rollback specific services
kubectl rollout undo deployment/auth-service -n sparc
kubectl rollout undo deployment/api-gateway -n sparc
kubectl rollout undo deployment/access-control-service -n sparc

# Check rollback status
kubectl rollout status deployment/auth-service -n sparc
kubectl get pods -n sparc -l app=auth-service
```

### 2. Database Rollback

```bash
# List available database snapshots
aws rds describe-db-cluster-snapshots \
  --db-cluster-identifier sparc-production-cluster \
  --query 'DBClusterSnapshots[*].[DBClusterSnapshotIdentifier,SnapshotCreateTime]' \
  --output table

# Restore from snapshot (creates new cluster)
aws rds restore-db-cluster-from-snapshot \
  --db-cluster-identifier sparc-production-rollback \
  --snapshot-identifier sparc-production-snapshot-20231201-120000 \
  --engine aurora-postgresql

# Update connection strings to point to rollback cluster
kubectl patch secret sparc-db-credentials -n sparc -p '{"data":{"host":"'$(echo -n "sparc-production-rollback.cluster-xyz.us-west-2.rds.amazonaws.com" | base64)'"}}'

# Restart services to pick up new database
kubectl rollout restart deployment -n sparc
```

### 3. Infrastructure Rollback

```bash
# Rollback CDK stacks to previous version
cdk deploy SparcStack-production \
  --parameters environment=production \
  --parameters imageTag=previous-stable-tag \
  --require-approval never

# Or rollback to specific git commit
git checkout <previous-stable-commit>
cdk deploy SparcStack-production --require-approval never
git checkout main
```

### 4. Traffic Rollback

```bash
# Switch traffic back to previous version using ingress
kubectl patch ingress sparc-ingress -n sparc -p '{"spec":{"rules":[{"host":"api.sparc.company","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"api-gateway-previous","port":{"number":3000}}}}]}}]}}'

# Or use AWS ALB target group switching
aws elbv2 modify-listener \
  --listener-arn $(aws elbv2 describe-listeners --load-balancer-arn $(aws elbv2 describe-load-balancers --names sparc-production-alb --query 'LoadBalancers[0].LoadBalancerArn' --output text) --query 'Listeners[0].ListenerArn' --output text) \
  --default-actions Type=forward,TargetGroupArn=$(aws elbv2 describe-target-groups --names sparc-api-gateway-previous --query 'TargetGroups[0].TargetGroupArn' --output text)
```

### 5. Validation After Rollback

```bash
# Run health checks after rollback
for service in auth-service api-gateway access-control-service; do
  echo "Checking $service after rollback..."
  kubectl exec -it deployment/api-gateway -n sparc -- curl -f http://$service:$(kubectl get service $service -n sparc -o jsonpath='{.spec.ports[0].port}')/health
done

# Test critical functionality
curl -X POST https://api.sparc.company/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sparc.company","password":"admin123"}'

# Run smoke tests
npm run test:smoke:production
```

## Troubleshooting Guide

### 1. Common Deployment Issues

#### Pod Startup Failures

**Symptoms:**
- Pods stuck in `Pending` or `CrashLoopBackOff` state
- ImagePullBackOff errors
- Health check failures

**Diagnosis:**
```bash
# Check pod status and events
kubectl get pods -n sparc
kubectl describe pod <pod-name> -n sparc

# Check pod logs
kubectl logs <pod-name> -n sparc --previous

# Check resource constraints
kubectl top pods -n sparc
kubectl describe nodes
```

**Solutions:**
1. Verify container image exists in ECR
2. Check resource requests and limits
3. Verify secrets and configmaps are available
4. Check node capacity and scheduling constraints
5. Verify RBAC permissions

#### Service Discovery Issues

**Symptoms:**
- Services cannot communicate with each other
- DNS resolution failures
- Connection timeouts between services

**Diagnosis:**
```bash
# Test service discovery
kubectl exec -it deployment/api-gateway -n sparc -- nslookup auth-service.sparc.svc.cluster.local

# Check service endpoints
kubectl get endpoints -n sparc

# Test connectivity between services
kubectl exec -it deployment/api-gateway -n sparc -- curl -v http://auth-service:3001/health
```

**Solutions:**
1. Verify service selectors match pod labels
2. Check service port configurations
3. Verify network policies allow traffic
4. Check DNS configuration in cluster
5. Verify service mesh configuration if applicable

#### Database Connection Issues

**Symptoms:**
- Connection timeouts to RDS
- Authentication failures
- SSL/TLS connection errors

**Diagnosis:**
```bash
# Test database connectivity from pod
kubectl exec -it deployment/auth-service -n sparc -- \
  psql "postgresql://username:password@host:5432/sparc" -c "SELECT 1;"

# Check database cluster status
aws rds describe-db-clusters --db-cluster-identifier sparc-production-cluster

# Check security groups
aws ec2 describe-security-groups --group-ids $(aws rds describe-db-clusters --db-cluster-identifier sparc-production-cluster --query 'DBClusters[0].VpcSecurityGroups[0].VpcSecurityGroupId' --output text)
```

**Solutions:**
1. Verify database credentials in secrets
2. Check RDS security group allows EKS traffic
3. Verify database is in available state
4. Check SSL certificate configuration
5. Verify connection pool settings

### 2. Performance Issues

#### High Resource Usage

**Diagnosis:**
```bash
# Check resource usage across cluster
kubectl top nodes
kubectl top pods -n sparc --sort-by=cpu
kubectl top pods -n sparc --sort-by=memory

# Check HPA status
kubectl get hpa -n sparc
kubectl describe hpa auth-service-hpa -n sparc

# Check cluster autoscaler logs
kubectl logs -n kube-system deployment/cluster-autoscaler
```

**Solutions:**
1. Scale up deployments manually or adjust HPA settings
2. Optimize application code and database queries
3. Implement caching strategies
4. Add more nodes to cluster
5. Review resource requests and limits

#### Slow Response Times

**Diagnosis:**
```bash
# Check application metrics
kubectl exec -it deployment/api-gateway -n sparc -- curl http://localhost:3000/metrics

# Check database performance
aws rds describe-db-clusters --db-cluster-identifier sparc-production-cluster --query 'DBClusters[0].PerformanceInsightsEnabled'

# Monitor CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/EKS \
  --metric-name cluster_failed_request_count \
  --dimensions Name=ClusterName,Value=sparc-production \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

**Solutions:**
1. Optimize database queries and add indexes
2. Implement Redis caching
3. Scale up database instances
4. Optimize application code
5. Implement CDN for static assets

### 3. Security Issues

#### Certificate Problems

**Diagnosis:**
```bash
# Check certificate status in ACM
aws acm describe-certificate --certificate-arn $(aws acm list-certificates --query 'CertificateSummaryList[?DomainName==`sparc.company`].CertificateArn' --output text)

# Test SSL configuration
openssl s_client -connect sparc.company:443 -servername sparc.company

# Check ingress TLS configuration
kubectl describe ingress sparc-ingress -n sparc
```

**Solutions:**
1. Renew expired certificates
2. Update certificate ARN in ingress
3. Verify domain validation
4. Check certificate chain
5. Update TLS security policies

#### Authentication Failures

**Diagnosis:**
```bash
# Check auth service logs
kubectl logs deployment/auth-service -n sparc --tail=100

# Test authentication endpoint
curl -X POST https://api.sparc.company/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sparc.company","password":"admin123"}' \
  -v

# Check JWT secret configuration
kubectl get secret sparc-jwt-secret -n sparc -o yaml
```

**Solutions:**
1. Verify JWT secret is correctly configured
2. Check database connectivity from auth service
3. Verify user credentials in database
4. Check session timeout settings
5. Review authentication middleware configuration

### 4. Networking Issues

#### Ingress Not Working

**Diagnosis:**
```bash
# Check ingress controller status
kubectl get pods -n ingress-nginx
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller

# Check ingress configuration
kubectl describe ingress sparc-ingress -n sparc

# Check AWS Load Balancer Controller
kubectl logs -n kube-system deployment/aws-load-balancer-controller
```

**Solutions:**
1. Verify ingress controller is running
2. Check ingress annotations for ALB
3. Verify service selectors and ports
4. Check security groups for load balancer
5. Verify DNS configuration

#### Network Policy Blocking Traffic

**Diagnosis:**
```bash
# Check network policies
kubectl get networkpolicies -n sparc
kubectl describe networkpolicy sparc-network-policy -n sparc

# Test connectivity with network policies disabled
kubectl delete networkpolicy sparc-network-policy -n sparc
# Test connectivity
kubectl apply -f k8s/network-policies.yaml
```

**Solutions:**
1. Review network policy rules
2. Add necessary ingress/egress rules
3. Check pod labels and selectors
4. Verify namespace labels
5. Test connectivity step by step

## Maintenance Procedures

### 1. Regular Maintenance Tasks

#### Daily Tasks

```bash
#!/bin/bash
# daily-maintenance.sh

# Check cluster health
kubectl get nodes
kubectl get pods -n sparc --field-selector=status.phase!=Running

# Check critical alerts
kubectl get events -n sparc --field-selector type=Warning --sort-by='.lastTimestamp'

# Check resource usage
kubectl top nodes
kubectl top pods -n sparc --sort-by=cpu | head -10

# Check backup status
aws rds describe-db-cluster-snapshots \
  --db-cluster-identifier sparc-production-cluster \
  --max-items 1 \
  --query 'DBClusterSnapshots[0].[DBClusterSnapshotIdentifier,Status,SnapshotCreateTime]'
```

#### Weekly Tasks

```bash
#!/bin/bash
# weekly-maintenance.sh

# Update container images
./scripts/deploy.sh -e production -t latest --skip-tests

# Review and rotate secrets
kubectl create secret generic sparc-jwt-secret \
  --from-literal=secret=$(openssl rand -base64 32) \
  --namespace=sparc \
  --dry-run=client -o yaml | kubectl apply -f -

# Check certificate expiration
aws acm describe-certificate \
  --certificate-arn $(aws acm list-certificates --query 'CertificateSummaryList[?DomainName==`sparc.company`].CertificateArn' --output text) \
  --query 'Certificate.[DomainName,Status,NotAfter]'

# Performance review
kubectl top pods -n sparc --sort-by=memory | head -20
kubectl get hpa -n sparc

# Security audit
kubectl get pods -n sparc -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.runAsNonRoot}{"\n"}{end}'
```

#### Monthly Tasks

```bash
#!/bin/bash
# monthly-maintenance.sh

# Update EKS cluster version
aws eks update-cluster-version \
  --name sparc-production \
  --version 1.28

# Update node groups
aws eks update-nodegroup-version \
  --cluster-name sparc-production \
  --nodegroup-name sparc-general

# Review resource quotas and limits
kubectl describe resourcequota -n sparc
kubectl describe limitrange -n sparc

# Compliance audit
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: compliance-audit-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: compliance-audit
        image: $ECR_REGISTRY/sparc-security-compliance-service:latest
        command: ["npm", "run", "audit:monthly"]
      restartPolicy: Never
EOF

# Cost optimization review
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '30 days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --group-by Type=DIMENSION,Key=SERVICE
```

### 2. Scaling Procedures

#### Horizontal Scaling

```bash
# Scale specific deployments
kubectl scale deployment auth-service --replicas=10 -n sparc
kubectl scale deployment video-management-service --replicas=5 -n sparc

# Update HPA settings
kubectl patch hpa auth-service-hpa -n sparc -p '{"spec":{"maxReplicas":30}}'

# Scale cluster nodes
aws eks update-nodegroup-config \
  --cluster-name sparc-production \
  --nodegroup-name sparc-general \
  --scaling-config minSize=5,maxSize=30,desiredSize=10
```

#### Vertical Scaling

```bash
# Update resource requests and limits
kubectl patch deployment auth-service -n sparc -p '{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"requests":{"cpu":"200m","memory":"512Mi"},"limits":{"cpu":"1000m","memory":"1Gi"}}}]}}}}'

# Scale database
aws rds modify-db-instance \
  --db-instance-identifier sparc-production-cluster-instance-1 \
  --db-instance-class db.r6g.2xlarge \
  --apply-immediately
```

### 3. Disaster Recovery

#### Multi-Region Failover

```bash
# Deploy to backup region
export AWS_REGION=us-east-1
cdk deploy SparcStack-production-dr \
  --parameters environment=production-dr \
  --require-approval never

# Setup cross-region database replication
aws rds create-db-cluster \
  --db-cluster-identifier sparc-production-dr \
  --engine aurora-postgresql \
  --replication-source-identifier arn:aws:rds:us-west-2:ACCOUNT:cluster:sparc-production-cluster \
  --region us-east-1

# Update DNS for failover
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch file://dns-failover.json
```

#### Data Recovery

```bash
# Restore from point-in-time
aws rds restore-db-cluster-to-point-in-time \
  --db-cluster-identifier sparc-production-restored \
  --source-db-cluster-identifier sparc-production-cluster \
  --restore-to-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S)

# Restore S3 data from backup
aws s3 sync s3://sparc-production-assets-backup s3://sparc-production-assets-restored --delete

# Restore Kubernetes configuration
kubectl apply -f backup/kubernetes-manifests/
```

### 4. Security Maintenance

#### Regular Security Updates

```bash
# Update base images
for service in auth-service api-gateway access-control-service video-management-service; do
  docker build --pull -t $ECR_REGISTRY/sparc-$service:security-update services/$service/
  docker push $ECR_REGISTRY/sparc-$service:security-update
done

# Update Kubernetes
kubectl set image deployment/auth-service auth-service=$ECR_REGISTRY/sparc-auth-service:security-update -n sparc

# Scan for vulnerabilities
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: security-scan-$(date +%s)
  namespace: sparc
spec:
  template:
    spec:
      containers:
      - name: trivy-scanner
        image: aquasec/trivy:latest
        command: ["trivy", "image", "--exit-code", "1", "--severity", "HIGH,CRITICAL", "$ECR_REGISTRY/sparc-auth-service:latest"]
      restartPolicy: Never
EOF
```

## Conclusion

This comprehensive production deployment guide provides step-by-step instructions for deploying the fully functional SPARC platform using modern cloud-native technologies. The guide covers:

- **Complete CDK-based infrastructure** with AWS best practices
- **Kubernetes deployment** with proper RBAC, monitoring, and security
- **Production-ready configurations** for all 24 microservices
- **Comprehensive monitoring and alerting** setup
- **Security hardening** and compliance validation
- **Robust rollback procedures** for safe deployments
- **Detailed troubleshooting** for common issues
- **Maintenance procedures** for ongoing operations

### Key Success Metrics

- **Availability**: 99.9% uptime with multi-AZ deployment
- **Performance**: < 200ms response time for 95% of requests
- **Security**: Zero security incidents with comprehensive monitoring
- **Scalability**: Support for 10,000 doors and 1,000 concurrent video streams
- **Compliance**: SOX, HIPAA, and PCI-DSS compliance maintained
- **Offline Resilience**: 72-hour offline operation capability
- **Real-time Performance**: Sub-second access control decisions

### Platform Capabilities

The deployed SPARC platform provides:

- **Complete Access Control**: Physical and digital access management
- **Video Management**: Real-time streaming, recording, and analytics
- **Environmental Monitoring**: Temperature, humidity, and leak detection
- **Visitor Management**: Pre-registration, check-in, and tracking
- **Mobile Credentials**: iOS/Android app with NFC/BLE support
- **Compliance Reporting**: Automated audit trails and compliance checks
- **Multi-tenant Architecture**: Complete tenant isolation and management
- **Offline Operation**: Mesh networking and local decision making

### Emergency Contacts

- **DevOps Team**: devops@sparc.company
- **Security Team**: security@sparc.company
- **Platform Engineering**: platform@sparc.company
- **On-Call Engineer**: +1-555-SPARC-911
- **AWS Support**: Enterprise Support Case

### Additional Resources

- **Platform Documentation**: https://docs.sparc.company
- **API Documentation**: https://api.sparc.company/docs
- **Status Page**: https://status.sparc.company
- **Support Portal**: https://support.sparc.company

For additional support or questions, refer to the SPARC platform documentation or contact the development team through the appropriate channels.
