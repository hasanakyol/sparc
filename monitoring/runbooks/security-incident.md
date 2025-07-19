# Security Incident Response Runbook

## Alert: SecurityIncidentDetected / AuthenticationFailureSpike

### Overview
This alert fires when abnormally high authentication or authorization failures are detected, indicating a potential security incident such as brute force attack, credential stuffing, or unauthorized access attempts.

### Severity: CRITICAL - P1 Security Incident

### Impact
- Potential unauthorized access to system
- Risk of data breach
- Service availability may be affected by attack
- Compliance and audit implications

### Immediate Actions (First 2 Minutes)

1. **Activate Security Response**
   ```bash
   # Create security incident
   ./scripts/create-security-incident.sh --severity=critical --type=auth-attack
   
   # Enable enhanced logging
   kubectl set env deployment/auth-service SECURITY_LOG_LEVEL=DEBUG -n sparc
   kubectl set env deployment/api-gateway SECURITY_LOG_LEVEL=DEBUG -n sparc
   ```

2. **Enable Emergency Security Mode**
   ```bash
   # Enable strict authentication mode
   kubectl patch configmap security-config -n sparc \
     -p '{"data":{"EMERGENCY_MODE":"true","MAX_LOGIN_ATTEMPTS":"3"}}'
   
   # Apply immediately
   kubectl rollout restart deployment/auth-service -n sparc
   kubectl rollout restart deployment/api-gateway -n sparc
   ```

3. **Capture Evidence**
   ```bash
   # Start packet capture
   kubectl exec -it security-monitor -n sparc -- \
     tcpdump -i any -w /tmp/security-incident-$(date +%s).pcap
   
   # Export recent logs
   kubectl logs -l app=auth-service -n sparc --since=1h > auth-logs-$(date +%s).log
   kubectl logs -l app=api-gateway -n sparc --since=1h > gateway-logs-$(date +%s).log
   ```

### Investigation Steps

1. **Identify Attack Pattern**
   ```bash
   # Analyze authentication failures by IP
   kubectl logs -l app=auth-service -n sparc --tail=1000 | \
     grep "auth_failed" | awk '{print $5}' | sort | uniq -c | sort -nr | head -20
   
   # Check for credential stuffing patterns
   kubectl logs -l app=auth-service -n sparc --tail=1000 | \
     grep "auth_failed" | grep -E "user_not_found|invalid_password" | \
     awk '{print $3,$5}' | sort | uniq -c | sort -nr
   ```

2. **Identify Affected Accounts**
   ```bash
   # List targeted accounts
   kubectl exec -it auth-service-0 -n sparc -- \
     psql -U auth_user -d auth_db -c \
     "SELECT username, failed_attempts, last_failed_attempt 
      FROM users 
      WHERE failed_attempts > 5 
      ORDER BY failed_attempts DESC;"
   ```

3. **Check for Successful Breaches**
   ```bash
   # Look for successful logins after multiple failures
   kubectl logs -l app=auth-service -n sparc --tail=5000 | \
     grep -B5 -A5 "auth_success" | grep -E "auth_failed.*auth_success"
   
   # Check for unusual access patterns
   kubectl logs -l app=api-gateway -n sparc --tail=5000 | \
     grep "admin\|export\|bulk" | grep -v "GET /health"
   ```

4. **Trace Attack Source**
   ```bash
   # GeoIP analysis
   kubectl exec -it security-monitor -n sparc -- \
     ./geoip-analyze.sh /tmp/suspicious-ips.txt
   
   # Check for known malicious IPs
   kubectl exec -it security-monitor -n sparc -- \
     ./threat-intel-check.sh /tmp/suspicious-ips.txt
   ```

### Containment Actions

1. **Block Malicious IPs**
   ```bash
   # Add IPs to blocklist
   kubectl exec -it api-gateway-0 -n sparc -- \
     redis-cli SADD blocked_ips "1.2.3.4" "5.6.7.8"
   
   # Update WAF rules
   kubectl patch configmap waf-rules -n sparc \
     --type merge -p '{"data":{"blocked_ips":"1.2.3.4,5.6.7.8"}}'
   ```

2. **Force Password Resets**
   ```bash
   # For compromised accounts
   kubectl exec -it auth-service-0 -n sparc -- \
     psql -U auth_user -d auth_db -c \
     "UPDATE users SET force_password_reset = true 
      WHERE username IN ('user1', 'user2', 'user3');"
   ```

3. **Revoke Active Sessions**
   ```bash
   # Clear all sessions for affected users
   kubectl exec -it auth-service-0 -n sparc -- \
     redis-cli --scan --pattern "session:user1:*" | xargs redis-cli DEL
   ```

4. **Enable Additional Security Measures**
   ```bash
   # Enable CAPTCHA for all logins
   kubectl patch configmap auth-config -n sparc \
     -p '{"data":{"CAPTCHA_ENABLED":"true","MFA_REQUIRED":"true"}}'
   
   # Enable rate limiting
   kubectl patch configmap api-gateway-config -n sparc \
     -p '{"data":{"RATE_LIMIT_AUTH":"10/hour"}}'
   ```

### Forensic Analysis

1. **Timeline Construction**
   ```bash
   # Generate attack timeline
   kubectl logs -l app=auth-service -n sparc --since=2h | \
     grep -E "auth_failed|auth_success|password_reset" | \
     awk '{print $1,$2,$3,$5,$7}' > attack-timeline.log
   ```

2. **Data Access Audit**
   ```bash
   # Check for data exfiltration attempts
   kubectl logs -l app=api-gateway -n sparc --since=2h | \
     grep -E "GET.*export|POST.*bulk|large_response" | \
     awk '$8 > 1000000 {print $0}'
   ```

3. **Lateral Movement Detection**
   ```bash
   # Check for privilege escalation attempts
   kubectl logs -n sparc --since=2h | \
     grep -E "permission_denied|unauthorized|forbidden" | \
     grep -v "health_check"
   ```

### Recovery Actions

1. **Restore Normal Operations**
   ```bash
   # After threat is contained
   kubectl patch configmap security-config -n sparc \
     -p '{"data":{"EMERGENCY_MODE":"false"}}'
   
   # Restore normal rate limits
   kubectl patch configmap api-gateway-config -n sparc \
     -p '{"data":{"RATE_LIMIT_AUTH":"100/hour"}}'
   ```

2. **Security Hardening**
   ```bash
   # Update security policies
   kubectl apply -f security-policies/post-incident-hardening.yaml
   
   # Deploy additional monitoring
   kubectl apply -f monitoring/enhanced-security-alerts.yaml
   ```

### Communication Protocol

1. **Internal Notification**
   - Security team: Immediate
   - Legal team: Within 5 minutes
   - Executive team: Within 15 minutes
   - All staff: As appropriate

2. **External Communication**
   - Affected customers: Within 1 hour (if breach confirmed)
   - Regulatory bodies: As required by compliance
   - Law enforcement: If criminal activity suspected

3. **Documentation**
   - Incident timeline
   - Affected systems and data
   - Actions taken
   - Evidence collected

### Post-Incident Actions

1. **Security Audit**
   - Full authentication system review
   - Penetration testing
   - Code security audit
   - Access control review

2. **Implement Improvements**
   - Multi-factor authentication
   - Anomaly detection systems
   - Enhanced logging
   - Security training

3. **Compliance Requirements**
   - File breach notifications if required
   - Update security documentation
   - Review and update policies
   - Conduct security training

### Escalation Path

- **0-2 minutes**: Security team + On-call engineer
- **2-5 minutes**: CISO + Engineering lead
- **5-15 minutes**: Legal + VP Engineering
- **15+ minutes**: CEO + Board notification (if breach)

### Evidence Preservation

```bash
# Create evidence bundle
mkdir -p /tmp/incident-evidence-$(date +%s)
cd /tmp/incident-evidence-*

# Collect all evidence
kubectl cp security-monitor:/tmp/security-incident-*.pcap ./
kubectl logs -n sparc --since=2h > all-logs.txt
kubectl get events -n sparc > k8s-events.txt

# Create encrypted archive
tar -czf - * | gpg -c > evidence-$(date +%s).tar.gz.gpg
```

### Related Documentation
- [Security Incident Response Plan](https://wiki.sparc.com/security/incident-response)
- [Data Breach Procedure](https://wiki.sparc.com/security/data-breach)
- [Security Contacts](https://wiki.sparc.com/security/contacts)

### Security Dashboards
- [Security Events Dashboard](https://grafana.sparc.com/d/sparc-security-events)
- [Authentication Monitoring](https://grafana.sparc.com/d/sparc-auth-monitoring)
- [WAF Dashboard](https://grafana.sparc.com/d/sparc-waf-dashboard)