# High Error Rate Runbook

## Alert: HighErrorRate

### Overview
This alert fires when a service experiences an error rate above 5% for more than 5 minutes.

### Impact
- User requests are failing at an elevated rate
- Service reliability is degraded
- Potential cascading failures to dependent services

### Diagnosis Steps

1. **Check the error monitoring dashboard**
   ```
   https://grafana.sparc.com/d/sparc-error-monitoring-comprehensive
   ```
   - Filter by affected service
   - Identify error patterns and categories

2. **Check recent deployments**
   ```bash
   kubectl rollout history deployment/<service-name> -n sparc
   ```

3. **Check service logs**
   ```bash
   kubectl logs -l app=<service-name> -n sparc --tail=100 | grep ERROR
   ```

4. **Check circuit breaker states**
   ```bash
   curl http://<service>:9090/metrics | grep circuit_breaker_state
   ```

5. **Verify database connectivity**
   ```bash
   kubectl exec -it <service-pod> -n sparc -- nc -zv postgres-service 5432
   ```

### Mitigation Steps

1. **Immediate Actions**
   - If recent deployment: Rollback immediately
     ```bash
     kubectl rollout undo deployment/<service-name> -n sparc
     ```
   - Scale up if load-related:
     ```bash
     kubectl scale deployment/<service-name> --replicas=<new-count> -n sparc
     ```

2. **Circuit Breaker Management**
   - Check if circuit breakers need manual reset
   - Verify downstream service health

3. **Database Issues**
   - Check connection pool metrics
   - Verify database performance
   - Consider connection pool size increase

4. **External Dependencies**
   - Verify third-party API status
   - Check network connectivity
   - Review timeout configurations

### Escalation

- After 15 minutes: Page on-call engineer
- After 30 minutes: Escalate to service owner
- If multiple services affected: Declare incident and activate incident response team

### Prevention

1. Implement comprehensive error handling
2. Add retry logic with exponential backoff
3. Configure appropriate circuit breakers
4. Regular load testing
5. Canary deployments for all changes

### Related Alerts
- ErrorBudgetBurnRateHigh
- CircuitBreakerOpen
- DatabaseConnectionErrors