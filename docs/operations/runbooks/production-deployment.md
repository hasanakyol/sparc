# SPARC Production Deployment Runbook

## Overview
This runbook provides step-by-step instructions for deploying the SPARC Security Platform to production environments.

## Pre-Deployment Checklist

### 1. Environment Verification
- [ ] All environment variables configured in `.env.production`
- [ ] Database connection strings verified
- [ ] Redis cluster endpoints configured
- [ ] S3 buckets created and accessible
- [ ] SSL certificates installed
- [ ] Domain names configured

### 2. Infrastructure Requirements
- [ ] Kubernetes cluster v1.28+ available
- [ ] Minimum 6 nodes (2 master, 4 worker)
- [ ] 32GB RAM per node
- [ ] 500GB SSD storage per node
- [ ] Network policies configured
- [ ] Load balancer provisioned

### 3. Security Prerequisites
- [ ] Secrets management system configured (Vault/AWS Secrets Manager)
- [ ] WAF rules deployed
- [ ] Network segmentation verified
- [ ] Backup encryption keys stored securely
- [ ] Audit logging enabled

## Deployment Steps

### Step 1: Database Migration
```bash
# 1. Backup existing database
pg_dump $PROD_DATABASE_URL > backup-$(date +%Y%m%d-%H%M%S).sql

# 2. Apply migrations
cd packages/database
npm run migrate:prod

# 3. Verify migrations
psql $PROD_DATABASE_URL -c "SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 5;"
```

### Step 2: Build and Push Docker Images
```bash
# 1. Set production registry
export DOCKER_REGISTRY=your-registry.com/sparc

# 2. Build all services
npm run build:docker:prod

# 3. Tag and push images
./scripts/deployment/push-images.sh --tag $(git rev-parse --short HEAD)

# 4. Verify images
docker images | grep sparc
```

### Step 3: Deploy Core Services
```bash
# 1. Deploy infrastructure services
kubectl apply -f k8s/infrastructure/

# 2. Wait for infrastructure to be ready
kubectl wait --for=condition=ready pod -l tier=infrastructure --timeout=300s

# 3. Deploy Redis cluster
kubectl apply -f k8s/redis/

# 4. Deploy PostgreSQL (if not using managed service)
kubectl apply -f k8s/postgresql/
```

### Step 4: Deploy Application Services
```bash
# 1. Deploy services in order
kubectl apply -f k8s/services/auth-service/
kubectl apply -f k8s/services/tenant-service/
kubectl apply -f k8s/services/api-gateway/

# 2. Wait for each service to be ready
kubectl rollout status deployment/auth-service
kubectl rollout status deployment/tenant-service
kubectl rollout status deployment/api-gateway

# 3. Deploy remaining services
kubectl apply -f k8s/services/
```

### Step 5: Configure Ingress and Load Balancer
```bash
# 1. Deploy Ingress controller
kubectl apply -f k8s/ingress/nginx-ingress.yaml

# 2. Configure SSL certificates
kubectl create secret tls sparc-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem

# 3. Apply Ingress rules
kubectl apply -f k8s/ingress/sparc-ingress.yaml

# 4. Verify endpoints
curl -k https://api.your-domain.com/health
```

### Step 6: Deploy Monitoring Stack
```bash
# 1. Deploy Prometheus
kubectl apply -f monitoring/prometheus/

# 2. Deploy Grafana
kubectl apply -f monitoring/grafana/

# 3. Deploy Jaeger
kubectl apply -f monitoring/jaeger/

# 4. Configure dashboards
./scripts/setup-monitoring-dashboards.sh
```

### Step 7: Perform Health Checks
```bash
# 1. Run automated health checks
./scripts/deployment/health-check-all.sh

# 2. Verify service mesh
istioctl analyze

# 3. Check database connections
kubectl exec -it deployment/api-gateway -- npm run db:ping

# 4. Test API endpoints
./scripts/deployment/smoke-tests.sh
```

### Step 8: Configure Auto-scaling
```bash
# 1. Apply HPA policies
kubectl apply -f k8s/autoscaling/

# 2. Configure cluster autoscaler
kubectl apply -f k8s/cluster-autoscaler.yaml

# 3. Set up PodDisruptionBudgets
kubectl apply -f k8s/pdb/
```

### Step 9: Enable Backup Systems
```bash
# 1. Configure database backups
kubectl apply -f k8s/backup/postgres-backup-cronjob.yaml

# 2. Configure S3 backup for media files
kubectl apply -f k8s/backup/media-backup-cronjob.yaml

# 3. Test backup restoration
./scripts/backup/test-restore.sh
```

### Step 10: Final Verification
```bash
# 1. Run integration tests
npm run test:e2e:prod

# 2. Verify performance metrics
./scripts/performance/load-test.sh --target prod

# 3. Check security posture
./scripts/security/production-scan.sh

# 4. Generate deployment report
./scripts/deployment/generate-report.sh > deployment-report-$(date +%Y%m%d).html
```

## Post-Deployment Tasks

### 1. Update DNS Records
- Point production domain to load balancer IP
- Configure CDN endpoints
- Update API documentation URLs

### 2. Configure Monitoring Alerts
```bash
# Apply alert rules
kubectl apply -f monitoring/alerts/

# Configure PagerDuty integration
kubectl create secret generic pagerduty-key --from-literal=key=$PAGERDUTY_KEY
```

### 3. Security Hardening
```bash
# Apply network policies
kubectl apply -f k8s/network-policies/

# Enable Pod Security Standards
kubectl label namespace default pod-security.kubernetes.io/enforce=restricted

# Configure RBAC
kubectl apply -f k8s/rbac/
```

## Rollback Procedures

### Quick Rollback (< 5 minutes)
```bash
# 1. Identify previous version
kubectl rollout history deployment/api-gateway

# 2. Rollback to previous version
kubectl rollout undo deployment/api-gateway

# 3. Verify rollback
kubectl rollout status deployment/api-gateway
```

### Full Rollback (database changes)
```bash
# 1. Stop traffic to the application
kubectl scale deployment --all --replicas=0

# 2. Restore database backup
psql $PROD_DATABASE_URL < backup-file.sql

# 3. Deploy previous version
kubectl set image deployment/api-gateway api-gateway=$DOCKER_REGISTRY/api-gateway:previous-tag

# 4. Scale back up
kubectl scale deployment --all --replicas=3
```

## Troubleshooting

### Service Not Starting
```bash
# Check logs
kubectl logs -f deployment/service-name

# Check events
kubectl describe pod -l app=service-name

# Check resource limits
kubectl top pods -l app=service-name
```

### Database Connection Issues
```bash
# Test connection from pod
kubectl exec -it deployment/api-gateway -- psql $DATABASE_URL -c "SELECT 1"

# Check secrets
kubectl get secret db-credentials -o yaml

# Verify network policies
kubectl get networkpolicies
```

### Performance Issues
```bash
# Check resource usage
kubectl top nodes
kubectl top pods --all-namespaces

# Check HPA status
kubectl get hpa

# Review slow queries
kubectl exec -it deployment/postgresql -- psql -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10"
```

## Emergency Contacts

- **DevOps On-Call**: +1-XXX-XXX-XXXX
- **Database Admin**: +1-XXX-XXX-XXXX
- **Security Team**: +1-XXX-XXX-XXXX
- **Escalation**: escalation@company.com

## Maintenance Windows

- **Scheduled**: Sundays 2:00 AM - 6:00 AM UTC
- **Emergency**: Requires VP approval
- **Notification**: 48 hours advance notice via status page

## Compliance Notes

- All deployments must be logged in change management system
- Security scan required before each deployment
- Deployment approval required from:
  - Engineering Manager
  - Security Team
  - Operations Team