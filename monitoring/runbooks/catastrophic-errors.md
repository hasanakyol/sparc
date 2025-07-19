# Catastrophic Error Rate Runbook

## Alert: CatastrophicErrorRate

### Overview
This alert fires when a service experiences an error rate above 25% for more than 30 seconds. This indicates a severe service degradation that requires immediate action.

### Severity: CRITICAL - P1 Incident

### Impact
- Significant portion of user requests are failing
- Service is effectively non-functional for many users
- High risk of cascading failures to dependent services
- Potential data inconsistency or loss

### Immediate Actions (First 5 Minutes)

1. **Acknowledge Alert**
   ```bash
   # Acknowledge in AlertManager
   amtool alert ack <alert-id> --alertmanager.url=http://alertmanager:9093
   ```

2. **Assess Scope**
   ```bash
   # Check affected service metrics
   curl -s http://<service>:9090/metrics | grep -E "http_requests_total|error_rate"
   
   # Check service logs for error patterns
   kubectl logs -l app=<service-name> -n sparc --tail=100 | grep -E "ERROR|FATAL|PANIC"
   ```

3. **Emergency Rollback (if recent deployment)**
   ```bash
   # Check recent deployments
   kubectl rollout history deployment/<service-name> -n sparc
   
   # Immediate rollback
   kubectl rollout undo deployment/<service-name> -n sparc
   
   # Monitor rollback status
   kubectl rollout status deployment/<service-name> -n sparc
   ```

### Diagnosis Steps

1. **Identify Error Patterns**
   ```bash
   # Group errors by type
   kubectl logs -l app=<service-name> -n sparc --tail=1000 | \
     grep ERROR | awk '{print $4}' | sort | uniq -c | sort -nr
   ```

2. **Check Dependencies**
   - Database connectivity
   - Redis/Cache availability
   - External API status
   - Message queue health

3. **Resource Exhaustion**
   ```bash
   # Check pod resources
   kubectl top pods -l app=<service-name> -n sparc
   
   # Check for OOM kills
   kubectl describe pods -l app=<service-name> -n sparc | grep -i "OOMKilled"
   ```

4. **Circuit Breaker Status**
   ```bash
   # Check circuit breakers
   curl http://<service>:9090/metrics | grep circuit_breaker_state
   ```

### Mitigation Strategies

1. **Load Shedding**
   ```bash
   # Enable emergency rate limiting
   kubectl patch configmap <service>-config -n sparc \
     -p '{"data":{"RATE_LIMIT_EMERGENCY":"true"}}'
   
   # Restart pods to apply
   kubectl rollout restart deployment/<service-name> -n sparc
   ```

2. **Horizontal Scaling**
   ```bash
   # Emergency scale-up
   kubectl scale deployment/<service-name> --replicas=10 -n sparc
   ```

3. **Traffic Diversion**
   ```bash
   # Divert traffic to healthy region/cluster
   kubectl patch service <service-name> -n sparc \
     -p '{"spec":{"selector":{"region":"backup"}}}'
   ```

4. **Feature Flags**
   ```bash
   # Disable non-critical features
   curl -X POST http://feature-flags-service/disable \
     -d '{"features": ["video-analytics", "ml-predictions"]}'
   ```

### Recovery Verification

1. **Monitor Error Rate**
   ```bash
   # Watch error rate recovery
   watch -n 5 'curl -s http://<service>:9090/metrics | grep error_rate'
   ```

2. **Health Checks**
   ```bash
   # Verify service health
   curl http://<service>/health
   
   # Check readiness
   kubectl get pods -l app=<service-name> -n sparc
   ```

3. **Dependency Verification**
   ```bash
   # Test critical paths
   curl -X POST http://<service>/api/test-critical-path
   ```

### Post-Incident Actions

1. **Incident Report**
   - Document timeline
   - Root cause analysis
   - Actions taken
   - Lessons learned

2. **Preventive Measures**
   - Add additional monitoring
   - Implement circuit breakers
   - Review capacity planning
   - Update runbooks

3. **Communication**
   - Update status page
   - Notify affected customers
   - Internal postmortem meeting

### Escalation Path

- **0-5 minutes**: On-call engineer
- **5-15 minutes**: Service owner + SRE lead
- **15-30 minutes**: Engineering manager + VP Engineering
- **30+ minutes**: CTO + Customer Success lead

### Related Runbooks
- [Cascading Failure](./cascading-failure.md)
- [Service Down](./service-down.md)
- [Emergency Rollback](./emergency-rollback.md)

### Monitoring Links
- [Error Dashboard](https://grafana.sparc.com/d/sparc-error-monitoring-overview)
- [Service Metrics](https://grafana.sparc.com/d/sparc-service-metrics)
- [Real-time Alerts](https://grafana.sparc.com/d/sparc-real-time-error-alerts)