# Kubernetes Deployment Guide

## Overview

This guide provides comprehensive procedures for deploying the SPARC platform on Kubernetes. It covers cluster requirements, manifest deployment, configuration management, scaling procedures, and monitoring setup.

## Cluster Requirements

### Minimum Cluster Specifications

| Component | Development | Staging | Production |
|-----------|-------------|---------|------------|
| **Nodes** | 3 nodes | 10 nodes | 20+ nodes |
| **CPU per Node** | 4 vCPU | 8 vCPU | 16 vCPU |
| **Memory per Node** | 16 GB | 32 GB | 64 GB |
| **Storage per Node** | 100 GB SSD | 250 GB SSD | 500 GB SSD |
| **Kubernetes Version** | 1.28+ | 1.28+ | 1.28+ |
| **Network Plugin** | Calico/Cilium | Calico/Cilium | Calico/Cilium |

### Required Add-ons

```bash
# Essential cluster add-ons
- Ingress Controller (NGINX/Traefik)
- DNS (CoreDNS)
- Certificate Manager (cert-manager)
- Metrics Server
- Storage Classes (EBS/GCE-PD/Azure Disk)
- Network Policies support
- Pod Security Standards
```

### Node Pool Configuration

```yaml
# Production node pool configuration
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: sparc-prod
  region: us-east-1
  version: "1.28"

nodeGroups:
  - name: system
    instanceType: m5.xlarge
    desiredCapacity: 3
    minSize: 3
    maxSize: 5
    labels:
      role: system
    taints:
      - key: CriticalAddonsOnly
        value: "true"
        effect: NoSchedule
        
  - name: api
    instanceType: m5.2xlarge
    desiredCapacity: 6
    minSize: 3
    maxSize: 12
    labels:
      role: api
      workload: stateless
    
  - name: video
    instanceType: m5.4xlarge
    desiredCapacity: 8
    minSize: 4
    maxSize: 20
    labels:
      role: video
      workload: cpu-intensive
    volumeSize: 500
    
  - name: database
    instanceType: r5.2xlarge
    desiredCapacity: 3
    minSize: 3
    maxSize: 6
    labels:
      role: database
      workload: stateful
    volumeSize: 1000
    volumeType: gp3
    volumeIOPS: 10000
```

## Pre-Deployment Setup

### 1. Cluster Preparation

```bash
#!/bin/bash
# Kubernetes cluster preparation script

prepare_cluster() {
  echo "Preparing Kubernetes cluster..."
  
  # 1. Create namespaces
  kubectl create namespace sparc-prod
  kubectl create namespace sparc-monitoring
  kubectl create namespace sparc-ingress
  kubectl create namespace sparc-storage
  
  # 2. Label namespaces
  kubectl label namespace sparc-prod environment=production
  kubectl label namespace sparc-prod app=sparc
  
  # 3. Set default resource quotas
  kubectl apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: sparc-quota
  namespace: sparc-prod
spec:
  hard:
    requests.cpu: "1000"
    requests.memory: "2000Gi"
    requests.storage: "10Ti"
    persistentvolumeclaims: "100"
    services.loadbalancers: "10"
EOF

  # 4. Set default network policies
  kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: sparc-prod
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

  # 5. Create pod security policies
  kubectl apply -f k8s/base/security/pod-security-policies.yaml
  
  echo "Cluster preparation completed"
}

prepare_cluster
```

### 2. Install Required Operators

```bash
#!/bin/bash
# Install Kubernetes operators

install_operators() {
  # 1. Install cert-manager for TLS
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
  
  # 2. Install NGINX Ingress Controller
  helm upgrade --install ingress-nginx ingress-nginx \
    --repo https://kubernetes.github.io/ingress-nginx \
    --namespace sparc-ingress \
    --set controller.service.type=LoadBalancer \
    --set controller.metrics.enabled=true \
    --set controller.podAnnotations."prometheus\.io/scrape"=true
  
  # 3. Install Prometheus Operator
  helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
    --namespace sparc-monitoring \
    --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
    --set prometheus.prometheusSpec.retention=30d \
    --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=100Gi
  
  # 4. Install External Secrets Operator
  helm upgrade --install external-secrets external-secrets/external-secrets \
    --namespace external-secrets-system \
    --create-namespace
  
  # 5. Install Keda for autoscaling
  helm upgrade --install keda kedacore/keda \
    --namespace keda \
    --create-namespace
  
  # Wait for operators to be ready
  kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=cert-manager -n cert-manager --timeout=300s
  kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=ingress-nginx -n sparc-ingress --timeout=300s
}

install_operators
```

## Manifest Deployment Order

### 1. Storage Configuration

```yaml
# storage-classes.yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp3
  iops: "10000"
  throughput: "250"
  encrypted: "true"
  kmsKeyId: "arn:aws:kms:us-east-1:123456789:key/xxx"
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
---
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: video-storage
provisioner: kubernetes.io/aws-ebs
parameters:
  type: st1
  encrypted: "true"
allowVolumeExpansion: true
volumeBindingMode: WaitForFirstConsumer
```

### 2. ConfigMaps and Secrets

```bash
#!/bin/bash
# Deploy configuration and secrets

deploy_config() {
  # 1. Create ConfigMaps from files
  kubectl create configmap app-config \
    --from-file=config/production/ \
    -n sparc-prod
  
  # 2. Create Secrets using External Secrets
  cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets
  namespace: sparc-prod
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: sparc-prod
spec:
  secretStoreRef:
    name: aws-secrets
    kind: SecretStore
  target:
    name: database-credentials
  data:
    - secretKey: username
      remoteRef:
        key: prod/sparc/database
        property: username
    - secretKey: password
      remoteRef:
        key: prod/sparc/database
        property: password
EOF

  # 3. Create TLS certificates
  cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: sparc-tls
  namespace: sparc-prod
spec:
  secretName: sparc-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - api.sparc.com
    - "*.sparc.com"
EOF
}

deploy_config
```

### 3. Database Deployment

```yaml
# postgresql-deployment.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgresql
  namespace: sparc-prod
spec:
  serviceName: postgresql
  replicas: 3
  selector:
    matchLabels:
      app: postgresql
  template:
    metadata:
      labels:
        app: postgresql
    spec:
      nodeSelector:
        role: database
      containers:
      - name: postgresql
        image: postgres:15-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: sparc_prod
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: password
        - name: POSTGRES_REPLICATION_MODE
          value: master
        - name: POSTGRES_REPLICATION_USER
          value: replicator
        - name: POSTGRES_REPLICATION_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: replication_password
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
        - name: config
          mountPath: /etc/postgresql/postgresql.conf
          subPath: postgresql.conf
        resources:
          requests:
            memory: "8Gi"
            cpu: "4"
          limits:
            memory: "16Gi"
            cpu: "8"
        livenessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - pg_isready
            - -U
            - postgres
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: postgresql-config
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 500Gi
```

### 4. Core Services Deployment

```bash
#!/bin/bash
# Deploy core services in order

deploy_core_services() {
  echo "Deploying core services..."
  
  # 1. Deploy Redis
  kubectl apply -k k8s/overlays/production/redis/
  kubectl wait --for=condition=ready pod -l app=redis -n sparc-prod --timeout=300s
  
  # 2. Deploy message queue
  kubectl apply -k k8s/overlays/production/rabbitmq/
  kubectl wait --for=condition=ready pod -l app=rabbitmq -n sparc-prod --timeout=300s
  
  # 3. Deploy authentication service
  kubectl apply -k k8s/overlays/production/auth-service/
  kubectl wait --for=condition=ready pod -l app=auth-service -n sparc-prod --timeout=300s
  
  # 4. Deploy core services
  for service in organization-service user-service permission-service; do
    kubectl apply -k k8s/overlays/production/$service/
  done
  
  # 5. Wait for all core services
  kubectl wait --for=condition=ready pod -l tier=core -n sparc-prod --timeout=600s
}

deploy_core_services
```

### 5. Application Services Deployment

```yaml
# kustomization.yaml for production overlay
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: sparc-prod

bases:
  - ../../../base

patchesStrategicMerge:
  - deployment-patches.yaml
  - service-patches.yaml

configMapGenerator:
  - name: app-config
    literals:
      - ENVIRONMENT=production
      - LOG_LEVEL=info
      - ENABLE_METRICS=true

secretGenerator:
  - name: app-secrets
    literals:
      - DATABASE_URL=postgresql://user:pass@postgresql:5432/sparc_prod

images:
  - name: api-gateway
    newName: registry.sparc.com/api-gateway
    newTag: v1.2.3
  - name: video-processor
    newName: registry.sparc.com/video-processor
    newTag: v1.2.3

replicas:
  - name: api-gateway
    count: 10
  - name: video-processor
    count: 20

resources:
  - hpa.yaml
  - pdb.yaml
  - network-policy.yaml
```

### 6. Ingress Configuration

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sparc-ingress
  namespace: sparc-prod
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.sparc.com
    - app.sparc.com
    secretName: sparc-tls
  rules:
  - host: api.sparc.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway
            port:
              number: 80
  - host: app.sparc.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-app
            port:
              number: 3000
```

## Scaling Procedures

### 1. Horizontal Pod Autoscaling

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
  namespace: sparc-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  minReplicas: 5
  maxReplicas: 50
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
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
      - type: Pods
        value: 5
        periodSeconds: 60
```

### 2. Vertical Pod Autoscaling

```yaml
# vpa.yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: video-processor-vpa
  namespace: sparc-prod
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: video-processor
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: video-processor
      minAllowed:
        cpu: 1
        memory: 2Gi
      maxAllowed:
        cpu: 8
        memory: 16Gi
      controlledResources: ["cpu", "memory"]
```

### 3. Cluster Autoscaling

```yaml
# cluster-autoscaler-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cluster-autoscaler
  template:
    metadata:
      labels:
        app: cluster-autoscaler
    spec:
      serviceAccountName: cluster-autoscaler
      containers:
      - image: k8s.gcr.io/autoscaling/cluster-autoscaler:v1.28.0
        name: cluster-autoscaler
        command:
        - ./cluster-autoscaler
        - --v=4
        - --stderrthreshold=info
        - --cloud-provider=aws
        - --skip-nodes-with-local-storage=false
        - --expander=least-waste
        - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/sparc-prod
        - --balance-similar-node-groups
        - --skip-nodes-with-system-pods=false
        env:
        - name: AWS_REGION
          value: us-east-1
```

### 4. KEDA Scaling for Video Processing

```yaml
# keda-scaledobject.yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: video-processor-scaler
  namespace: sparc-prod
spec:
  scaleTargetRef:
    name: video-processor
  minReplicaCount: 5
  maxReplicaCount: 100
  triggers:
  - type: rabbitmq
    metadata:
      host: amqp://rabbitmq.sparc-prod:5672
      queueName: video-processing-queue
      queueLength: "10"
  - type: prometheus
    metadata:
      serverAddress: http://prometheus:9090
      metricName: video_processing_queue_depth
      threshold: "50"
      query: sum(rabbitmq_queue_messages{queue="video-processing-queue"})
```

## Monitoring Setup

### 1. Prometheus Configuration

```yaml
# prometheus-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: sparc-monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
      external_labels:
        cluster: 'sparc-prod'
        environment: 'production'
    
    scrape_configs:
    - job_name: 'kubernetes-apiservers'
      kubernetes_sd_configs:
      - role: endpoints
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
      relabel_configs:
      - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
        action: keep
        regex: default;kubernetes;https
    
    - job_name: 'kubernetes-nodes'
      kubernetes_sd_configs:
      - role: node
      scheme: https
      tls_config:
        ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    
    - job_name: 'kubernetes-pods'
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
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
    
    - job_name: 'sparc-services'
      kubernetes_sd_configs:
      - role: service
        namespaces:
          names:
          - sparc-prod
      relabel_configs:
      - source_labels: [__meta_kubernetes_service_annotation_prometheus_io_scrape]
        action: keep
        regex: true
```

### 2. Grafana Dashboards

```json
{
  "dashboard": {
    "title": "SPARC Platform Overview",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{namespace=\"sparc-prod\"}[5m])) by (service)"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{namespace=\"sparc-prod\",status=~\"5..\"}[5m])) by (service)"
          }
        ]
      },
      {
        "title": "Response Time (p95)",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{namespace=\"sparc-prod\"}[5m])) by (service, le))"
          }
        ]
      },
      {
        "title": "Pod CPU Usage",
        "targets": [
          {
            "expr": "sum(rate(container_cpu_usage_seconds_total{namespace=\"sparc-prod\"}[5m])) by (pod)"
          }
        ]
      }
    ]
  }
}
```

### 3. ServiceMonitor Configuration

```yaml
# servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: sparc-services
  namespace: sparc-prod
spec:
  selector:
    matchLabels:
      app: sparc
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
    relabelings:
    - sourceLabels: [__meta_kubernetes_pod_name]
      targetLabel: pod
    - sourceLabels: [__meta_kubernetes_namespace]
      targetLabel: namespace
    - sourceLabels: [__meta_kubernetes_service_name]
      targetLabel: service
```

### 4. Alerting Rules

```yaml
# alerting-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: sparc-alerts
  namespace: sparc-monitoring
spec:
  groups:
  - name: sparc.rules
    interval: 30s
    rules:
    - alert: HighErrorRate
      expr: |
        sum(rate(http_requests_total{namespace="sparc-prod",status=~"5.."}[5m])) by (service)
        /
        sum(rate(http_requests_total{namespace="sparc-prod"}[5m])) by (service)
        > 0.05
      for: 5m
      labels:
        severity: critical
        team: platform
      annotations:
        summary: "High error rate for {{ $labels.service }}"
        description: "{{ $labels.service }} has error rate of {{ $value | humanizePercentage }}"
    
    - alert: PodMemoryUsage
      expr: |
        container_memory_usage_bytes{namespace="sparc-prod"} 
        / 
        container_spec_memory_limit_bytes{namespace="sparc-prod"} 
        > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage for {{ $labels.pod }}"
        description: "Pod {{ $labels.pod }} memory usage is above 90%"
    
    - alert: PersistentVolumeSpaceLow
      expr: |
        kubelet_volume_stats_available_bytes{namespace="sparc-prod"} 
        / 
        kubelet_volume_stats_capacity_bytes{namespace="sparc-prod"} 
        < 0.1
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "PV space low for {{ $labels.persistentvolumeclaim }}"
        description: "PVC {{ $labels.persistentvolumeclaim }} has less than 10% space available"
```

## Deployment Automation

### Complete Deployment Script

```bash
#!/bin/bash
# Complete Kubernetes deployment automation

set -e

ENVIRONMENT=${1:-production}
VERSION=${2:-latest}
NAMESPACE="sparc-${ENVIRONMENT}"

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

deploy_sparc_platform() {
  log "Starting deployment of SPARC platform version $VERSION to $ENVIRONMENT"
  
  # 1. Prepare cluster
  log "Preparing cluster..."
  ./scripts/prepare-cluster.sh $ENVIRONMENT
  
  # 2. Deploy infrastructure components
  log "Deploying infrastructure..."
  kubectl apply -k k8s/overlays/$ENVIRONMENT/infrastructure/
  
  # 3. Wait for infrastructure
  log "Waiting for infrastructure to be ready..."
  kubectl wait --for=condition=ready pod -l tier=infrastructure -n $NAMESPACE --timeout=600s
  
  # 4. Run database migrations
  log "Running database migrations..."
  kubectl create job --from=cronjob/db-migration db-migration-$VERSION -n $NAMESPACE
  kubectl wait --for=condition=complete job/db-migration-$VERSION -n $NAMESPACE --timeout=600s
  
  # 5. Deploy core services
  log "Deploying core services..."
  kubectl apply -k k8s/overlays/$ENVIRONMENT/core/
  
  # 6. Deploy application services
  log "Deploying application services..."
  kubectl apply -k k8s/overlays/$ENVIRONMENT/apps/
  
  # 7. Update image versions
  log "Updating image versions to $VERSION..."
  for deployment in $(kubectl get deployments -n $NAMESPACE -o name); do
    kubectl set image $deployment *=$VERSION -n $NAMESPACE --record
  done
  
  # 8. Wait for rollout
  log "Waiting for rollout to complete..."
  kubectl rollout status deployment --timeout=600s -n $NAMESPACE
  
  # 9. Run post-deployment tests
  log "Running post-deployment tests..."
  kubectl create job post-deploy-test-$VERSION \
    --from=cronjob/post-deploy-test -n $NAMESPACE
  kubectl wait --for=condition=complete job/post-deploy-test-$VERSION -n $NAMESPACE --timeout=300s
  
  # 10. Update monitoring
  log "Updating monitoring configuration..."
  kubectl apply -k k8s/overlays/$ENVIRONMENT/monitoring/
  
  log "Deployment completed successfully!"
}

# Execute deployment
deploy_sparc_platform
```

### GitOps with ArgoCD

```yaml
# argocd-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sparc-production
  namespace: argocd
spec:
  project: production
  source:
    repoURL: https://github.com/sparc/platform
    targetRevision: main
    path: k8s/overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: sparc-prod
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
  revisionHistoryLimit: 10
```

## Troubleshooting

### Common Issues and Solutions

```bash
#!/bin/bash
# Kubernetes troubleshooting commands

# 1. Pod issues
kubectl describe pod <pod-name> -n sparc-prod
kubectl logs <pod-name> -n sparc-prod --previous
kubectl exec -it <pod-name> -n sparc-prod -- /bin/sh

# 2. Service connectivity
kubectl get endpoints -n sparc-prod
kubectl run debug --image=nicolaka/netshoot -it --rm
kubectl port-forward svc/api-gateway 8080:80 -n sparc-prod

# 3. Resource issues
kubectl top nodes
kubectl top pods -n sparc-prod
kubectl describe node <node-name>

# 4. Network policies
kubectl get networkpolicy -n sparc-prod
kubectl describe networkpolicy <policy-name> -n sparc-prod

# 5. Storage issues
kubectl get pv,pvc -n sparc-prod
kubectl describe pvc <pvc-name> -n sparc-prod

# 6. Ingress issues
kubectl describe ingress sparc-ingress -n sparc-prod
kubectl logs -n sparc-ingress deployment/ingress-nginx-controller

# 7. Certificate issues
kubectl describe certificate sparc-tls -n sparc-prod
kubectl logs -n cert-manager deployment/cert-manager

# 8. HPA issues
kubectl describe hpa -n sparc-prod
kubectl get hpa -n sparc-prod --watch
```

## Security Best Practices

### 1. RBAC Configuration

```yaml
# rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: sparc-service-role
  namespace: sparc-prod
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sparc-service-binding
  namespace: sparc-prod
subjects:
- kind: ServiceAccount
  name: sparc-service-account
  namespace: sparc-prod
roleRef:
  kind: Role
  name: sparc-service-role
  apiGroup: rbac.authorization.k8s.io
```

### 2. Pod Security Standards

```yaml
# pod-security-policy.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: sparc-restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

## Maintenance Procedures

### 1. Node Maintenance

```bash
#!/bin/bash
# Node maintenance script

perform_node_maintenance() {
  local node=$1
  
  # 1. Cordon node
  kubectl cordon $node
  
  # 2. Drain node
  kubectl drain $node \
    --ignore-daemonsets \
    --delete-emptydir-data \
    --force \
    --timeout=300s
  
  # 3. Perform maintenance
  echo "Node $node is ready for maintenance"
  
  # 4. Uncordon node after maintenance
  read -p "Press enter when maintenance is complete..."
  kubectl uncordon $node
}
```

### 2. Rolling Updates

```bash
#!/bin/bash
# Rolling update with validation

perform_rolling_update() {
  local deployment=$1
  local image=$2
  
  # 1. Update deployment
  kubectl set image deployment/$deployment \
    $deployment=$image \
    -n sparc-prod \
    --record
  
  # 2. Watch rollout
  kubectl rollout status deployment/$deployment -n sparc-prod
  
  # 3. Verify new pods
  kubectl get pods -l app=$deployment -n sparc-prod
  
  # 4. Check for errors
  kubectl logs -l app=$deployment -n sparc-prod --tail=100
}
```