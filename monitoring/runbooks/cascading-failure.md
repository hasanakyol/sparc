# Cascading Failure Runbook

## Alert: CascadingFailureDetected

### Overview
This critical alert indicates multiple services are failing simultaneously with circuit breakers opening, suggesting a cascading failure scenario.

### Impact
- Multiple services degraded or unavailable
- Platform-wide impact likely
- User experience severely affected
- Revenue impact probable

### Immediate Actions (First 5 Minutes)

1. **Assess scope**
   ```
   https://grafana.sparc.com/d/sparc-dependency-errors
   ```
   - Count affected services
   - Identify failure origin

2. **Activate incident response**
   ```bash
   # Create incident channel
   /incident declare severity:sev1 title:"Cascading failure detected"
   ```

3. **Enable emergency mode** (if configured)
   ```bash
   kubectl apply -f /k8s/emergency/circuit-breaker-override.yaml
   ```

### Diagnosis Steps

1. **Identify root cause service**
   ```bash
   # Check which service failed first
   kubectl logs -l tier=backend -n sparc --since=30m | grep -E "(ERROR|PANIC)" | head -50
   ```

2. **Check infrastructure components**
   ```bash
   # Database status
   kubectl get pods -n database -o wide
   
   # Redis status
   redis-cli -h redis-cluster ping
   
   # Message queue status
   kubectl exec -it kafka-0 -n messaging -- kafka-topics.sh --list --bootstrap-server localhost:9092
   ```

3. **Review dependency graph**
   - Check service mesh topology
   - Identify critical path services
   - Look for single points of failure

### Mitigation Steps

1. **Break cascading chain**
   - Enable service isolation mode
   ```bash
   kubectl apply -f /k8s/emergency/service-isolation.yaml
   ```

2. **Implement traffic shedding**
   ```bash
   # Reduce traffic to 50%
   kubectl patch ingress main-ingress -n sparc --type='json' \
     -p='[{"op": "replace", "path": "/spec/rules/0/http/paths/0/backend/service/weight", "value":50}]'
   ```

3. **Progressive recovery**
   - Start with leaf services
   - Gradually enable dependencies
   - Monitor each step

4. **Manual circuit breaker control**
   ```bash
   # Force circuit breaker to half-open
   curl -X POST http://<service>:8080/admin/circuit-breaker/half-open
   ```

### Recovery Verification

1. **Service health checks**
   ```bash
   for service in $(kubectl get svc -n sparc -o name); do
     echo "Checking $service..."
     kubectl exec -it deployment/${service#*/} -n sparc -- curl -s localhost:8080/health
   done
   ```

2. **Error rate normalization**
   - Monitor error rates returning to baseline
   - Verify circuit breakers closing
   - Check queue depths

3. **End-to-end testing**
   ```bash
   kubectl apply -f /tests/e2e/smoke-test.yaml
   ```

### Communication

1. **Internal**
   - Update incident channel every 15 minutes
   - Executive summary every 30 minutes

2. **External**
   - Status page update within 5 minutes
   - Customer communication if impact > 15 minutes

### Post-Incident Actions

1. Run chaos engineering tests
2. Review service dependencies
3. Implement bulkheading
4. Increase circuit breaker thresholds
5. Add service mesh retry budgets

### Prevention Strategies

1. **Architecture improvements**
   - Reduce service coupling
   - Implement async communication
   - Add request hedging

2. **Operational improvements**
   - Regular failure injection testing
   - Dependency mapping updates
   - Circuit breaker tuning

3. **Monitoring enhancements**
   - Early warning indicators
   - Dependency health scoring
   - Predictive failure detection

### Related Documentation
- Service Mesh Configuration Guide
- Circuit Breaker Tuning Guide
- Disaster Recovery Procedures