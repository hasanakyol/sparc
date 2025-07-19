# Error Budget Burn Rate Runbook

## Alert: ErrorBudgetBurnRateCritical

### Overview
This alert indicates a service is consuming its error budget at an unsustainable rate. At the current burn rate, the monthly error budget will be exhausted prematurely.

### Understanding Error Budgets
- **Error Budget**: The acceptable amount of errors (1 - SLO target)
- **Burn Rate**: How fast the budget is being consumed
- **14.4x burn rate**: Budget will be exhausted in 2 days instead of 30

### Impact Assessment

1. **Calculate time to exhaustion**
   ```
   Time remaining = (Budget remaining) / (Current burn rate)
   ```

2. **Business impact**
   - Current user impact
   - Projected impact if rate continues
   - SLA violation risk

### Diagnosis Steps

1. **Identify error patterns**
   ```
   https://grafana.sparc.com/d/sparc-error-budget
   ```
   - Check burn rate trends
   - Identify error categories
   - Look for patterns (time-based, load-based)

2. **Recent changes**
   ```bash
   # Check deployments in last 24h
   kubectl get events -n sparc --field-selector reason=ScalingReplicaSet | grep <service>
   
   # Check config changes
   kubectl get configmap -n sparc -o yaml | grep -A5 -B5 "last-applied"
   ```

3. **Error analysis**
   ```bash
   # Top error types
   kubectl logs -l app=<service> -n sparc --since=1h | \
     grep ERROR | awk '{print $5}' | sort | uniq -c | sort -nr | head -10
   ```

### Mitigation Strategies

1. **Immediate: Reduce error rate**
   - Enable caching for expensive operations
   ```bash
   kubectl set env deployment/<service> CACHE_ENABLED=true -n sparc
   ```
   
   - Increase timeout values temporarily
   ```bash
   kubectl patch deployment/<service> -n sparc -p \
     '{"spec":{"template":{"spec":{"containers":[{"name":"<service>","env":[{"name":"REQUEST_TIMEOUT","value":"30s"}]}]}}}}'
   ```

2. **Short-term: Traffic management**
   - Implement request rate limiting
   ```bash
   kubectl apply -f - <<EOF
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: rate-limit-<service>
   spec:
     rateLimit:
       requests: 1000
       period: 1s
   EOF
   ```

3. **Medium-term: Service improvements**
   - Add retries for transient failures
   - Implement graceful degradation
   - Optimize slow queries

### Error Budget Management

1. **Budget freeze consideration**
   - If budget < 20%, consider feature freeze
   - Focus on reliability improvements
   - Postpone risky deployments

2. **SLO adjustment evaluation**
   - Review if SLO is too aggressive
   - Analyze customer impact data
   - Consider tiered SLOs

3. **Communication**
   - Notify product team of budget status
   - Update deployment policies
   - Review with SRE team

### Burn Rate Thresholds

| Burn Rate | Time to Exhaustion | Action Required |
|-----------|-------------------|-----------------|
| 1x        | 30 days          | Normal          |
| 3x        | 10 days          | Investigation   |
| 6x        | 5 days           | Intervention    |
| 14.4x     | 2 days           | Emergency       |

### Recovery Tracking

1. **Monitor burn rate reduction**
   ```promql
   # Current burn rate
   (1 - (sum(rate(http_requests_total{status!~"5..",service="<service>"}[1h])) 
   / sum(rate(http_requests_total{service="<service>"}[1h])))) / 0.01
   ```

2. **Project budget recovery**
   - Calculate days to recover budget
   - Set target burn rate < 0.5x

### Prevention

1. **Testing improvements**
   - Load testing with error injection
   - Canary analysis includes error budget impact
   - Automated rollback on budget burn

2. **Architecture improvements**
   - Implement request hedging
   - Add fallback mechanisms
   - Improve timeout configurations

3. **Operational improvements**
   - Error budget dashboards for all teams
   - Automated alerts at multiple thresholds
   - Regular SLO reviews

### Escalation Path

1. 14.4x burn rate: Page SRE on-call
2. 6x burn rate sustained > 1hr: Notify service owner
3. Budget < 10%: Freeze deployments, notify management

### References
- [Google SRE Book: Error Budgets](https://sre.google/sre-book/error-budget/)
- [SLO/SLI Dashboard](https://grafana.sparc.com/d/slo-dashboard)
- [Error Budget Policy](https://wiki.sparc.com/error-budget-policy)