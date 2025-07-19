# Service Down Runbook

## Alert: ServiceDown

### Overview
This alert fires when a service health check fails and the service is unreachable for more than 1 minute.

### Severity: CRITICAL - P1 Incident

### Impact
- Complete service unavailability
- All requests to the service are failing
- Dependent services may experience cascading failures
- Complete loss of functionality for affected users

### Immediate Actions (First 3 Minutes)

1. **Verify Service Status**
   ```bash
   # Check pod status
   kubectl get pods -l app=<service-name> -n sparc
   
   # Check deployment status
   kubectl get deployment <service-name> -n sparc
   
   # Check recent events
   kubectl get events --sort-by=.lastTimestamp -n sparc | grep <service-name>
   ```

2. **Quick Recovery Attempt**
   ```bash
   # Restart pods
   kubectl rollout restart deployment/<service-name> -n sparc
   
   # Monitor restart
   kubectl rollout status deployment/<service-name> -n sparc --timeout=60s
   ```

3. **Check Infrastructure**
   ```bash
   # Node status
   kubectl get nodes
   
   # Check if pods are stuck in pending
   kubectl describe pods -l app=<service-name> -n sparc | grep -A5 "Events:"
   ```

### Diagnosis Steps

1. **Pod Investigation**
   ```bash
   # Get pod logs (if available)
   kubectl logs -l app=<service-name> -n sparc --tail=100
   
   # Previous pod logs (if crashed)
   kubectl logs -l app=<service-name> -n sparc --previous --tail=100
   
   # Pod details
   kubectl describe pods -l app=<service-name> -n sparc
   ```

2. **Resource Issues**
   ```bash
   # Check resource availability
   kubectl top nodes
   kubectl describe nodes | grep -A5 "Allocated resources:"
   
   # Check PVC status
   kubectl get pvc -n sparc | grep <service-name>
   ```

3. **Network Connectivity**
   ```bash
   # Test service endpoint
   kubectl run debug --image=busybox -it --rm --restart=Never -- \
     wget -qO- http://<service-name>.<namespace>.svc.cluster.local/health
   
   # Check service endpoints
   kubectl get endpoints <service-name> -n sparc
   ```

4. **Configuration Issues**
   ```bash
   # Check ConfigMaps
   kubectl get configmap -n sparc | grep <service-name>
   kubectl describe configmap <service-name>-config -n sparc
   
   # Check Secrets
   kubectl get secrets -n sparc | grep <service-name>
   ```

### Recovery Procedures

1. **Force Pod Recreation**
   ```bash
   # Delete stuck pods
   kubectl delete pods -l app=<service-name> -n sparc --force --grace-period=0
   
   # Scale down and up
   kubectl scale deployment/<service-name> --replicas=0 -n sparc
   sleep 10
   kubectl scale deployment/<service-name> --replicas=3 -n sparc
   ```

2. **Node Recovery**
   ```bash
   # If node issue detected
   # Cordon problematic node
   kubectl cordon <node-name>
   
   # Drain node
   kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data
   ```

3. **Emergency Deployment**
   ```bash
   # Deploy previous known-good version
   kubectl set image deployment/<service-name> \
     <container-name>=<service-name>:<last-known-good-tag> -n sparc
   ```

4. **DNS and Service Mesh**
   ```bash
   # Restart CoreDNS if DNS issues
   kubectl rollout restart deployment/coredns -n kube-system
   
   # Check service mesh (if applicable)
   istioctl proxy-status
   ```

### Failover Procedures

1. **Multi-Region Failover**
   ```bash
   # Update DNS to point to backup region
   # This varies by DNS provider
   
   # Update load balancer
   kubectl patch service <service-name>-lb -n sparc \
     -p '{"spec":{"selector":{"region":"backup"}}}'
   ```

2. **Database Failover**
   ```bash
   # If database-related
   # Promote read replica (example for PostgreSQL)
   kubectl exec -it postgres-primary-0 -n sparc -- \
     patronictl failover --force
   ```

### Verification Steps

1. **Service Health**
   ```bash
   # Check pod readiness
   kubectl get pods -l app=<service-name> -n sparc -o wide
   
   # Test service endpoint
   curl -f http://<service-external-ip>/health || echo "Still down"
   ```

2. **Monitoring Recovery**
   ```bash
   # Check Prometheus metrics
   curl http://prometheus:9090/api/v1/query?query=up{job="<service-name>"}
   ```

3. **End-to-End Test**
   ```bash
   # Run smoke tests
   kubectl exec -it test-runner -n sparc -- /run-smoke-tests.sh <service-name>
   ```

### Communication

1. **Status Page Update**
   - Mark service as experiencing issues
   - Provide ETA if possible
   - Update every 15 minutes

2. **Internal Communication**
   - Slack: #incidents channel
   - Email: incidents@sparc.com
   - War room: Meet link in incident channel

3. **Customer Communication**
   - For outages > 5 minutes
   - Use pre-approved templates
   - Coordinate with Customer Success

### Escalation Timeline

- **0-3 minutes**: On-call engineer
- **3-10 minutes**: Service owner + backup on-call
- **10-20 minutes**: SRE lead + Engineering manager
- **20+ minutes**: VP Engineering + CTO

### Prevention Measures

1. **Health Check Improvements**
   - Implement deep health checks
   - Add dependency checks
   - Set appropriate timeouts

2. **Resilience**
   - Implement pod disruption budgets
   - Configure proper resource requests/limits
   - Add pod anti-affinity rules

3. **Monitoring**
   - Add predictive alerts
   - Monitor resource utilization trends
   - Track deployment success rates

### Related Documentation
- [Kubernetes Troubleshooting Guide](https://wiki.sparc.com/k8s-troubleshooting)
- [Service Architecture](https://wiki.sparc.com/services/<service-name>)
- [Disaster Recovery Plan](https://wiki.sparc.com/disaster-recovery)

### Dashboard Links
- [Service Health Dashboard](https://grafana.sparc.com/d/sparc-service-health)
- [Kubernetes Cluster Status](https://grafana.sparc.com/d/sparc-k8s-cluster)
- [Real-time Alerts](https://grafana.sparc.com/d/sparc-real-time-error-alerts)