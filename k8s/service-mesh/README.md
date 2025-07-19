# SPARC Platform Service Mesh Configuration

This directory contains the service mesh configuration for the SPARC platform, providing advanced traffic management, security, and observability capabilities for our microservices architecture.

## Overview

The service mesh implementation provides:
- **Automatic mutual TLS (mTLS)** between all services
- **Zero-trust security model** with fine-grained authorization policies
- **Advanced traffic management** including canary deployments and circuit breakers
- **Distributed tracing** for request flow visualization
- **Service-to-service metrics** and observability
- **Fault injection** for chaos engineering

## Directory Structure

```
k8s/service-mesh/
├── istio/                    # Istio service mesh configuration (primary)
│   ├── namespace.yaml        # Istio namespaces
│   ├── istio-config.yaml     # IstioOperator configuration
│   ├── peer-authentication.yaml  # mTLS policies
│   ├── authorization-policies.yaml  # Service access control
│   ├── destination-rules.yaml     # Traffic policies & circuit breakers
│   ├── virtual-services.yaml      # Request routing rules
│   ├── gateway.yaml              # Ingress gateway configuration
│   ├── telemetry.yaml           # Metrics, logs, and traces config
│   └── service-entries.yaml     # External service definitions
├── linkerd/                  # Linkerd configuration (alternative)
│   ├── linkerd-config.yaml   # Control plane configuration
│   └── traffic-policies.yaml # Service profiles and policies
├── policies/                 # Mesh-agnostic policies
│   ├── zero-trust-network-policies.yaml  # Network segmentation
│   ├── canary-deployment.yaml            # Progressive delivery
│   ├── fault-injection.yaml              # Chaos testing
│   └── load-balancing.yaml               # LB configurations
└── scripts/                  # Automation scripts
    ├── install-istio.sh      # Istio installation
    ├── install-linkerd.sh    # Linkerd installation
    ├── onboard-service.sh    # Service mesh onboarding
    ├── validate-policies.sh  # Policy validation
    └── observability-setup.sh # Monitoring setup
```

## Quick Start

### 1. Install Istio (Recommended)

```bash
cd k8s/service-mesh/scripts
./install-istio.sh
```

### 2. Install Linkerd (Alternative)

```bash
cd k8s/service-mesh/scripts
./install-linkerd.sh
```

### 3. Verify Installation

```bash
# For Istio
istioctl verify-install
istioctl proxy-status

# For Linkerd
linkerd check
linkerd viz check
```

### 4. Set Up Observability

```bash
./observability-setup.sh
```

## Service Onboarding

To onboard a new service to the mesh:

```bash
./scripts/onboard-service.sh -s <service-name> -n <namespace> -m istio
```

Example:
```bash
./scripts/onboard-service.sh -s new-service -n sparc -m istio --enable-canary
```

## Key Features

### 1. Zero-Trust Security

All services enforce mutual TLS and follow a deny-by-default authorization model:

- **mTLS**: Automatic certificate rotation and encrypted service-to-service communication
- **Authorization**: Fine-grained RBAC policies based on service identities
- **Network Policies**: Additional defense-in-depth with Kubernetes NetworkPolicies

### 2. Traffic Management

Advanced traffic control capabilities:

- **Canary Deployments**: Gradual rollout with automatic rollback
- **A/B Testing**: Route traffic based on headers or percentages
- **Circuit Breakers**: Automatic failure detection and recovery
- **Retries & Timeouts**: Configurable per-service resilience
- **Load Balancing**: Multiple algorithms (round-robin, least-request, consistent-hash)

### 3. Observability

Comprehensive monitoring and tracing:

- **Metrics**: Prometheus integration with custom dashboards
- **Tracing**: Distributed tracing with Jaeger
- **Logging**: Structured access logs with OpenTelemetry
- **Visualization**: Kiali (Istio) or Linkerd Viz for service mesh topology

### 4. Multi-Cluster Support

Both Istio and Linkerd support multi-cluster deployments for:
- Geographic distribution
- High availability
- Disaster recovery

## Service-Specific Configurations

### API Gateway
- Handles external traffic ingress
- Rate limiting and authentication
- Request/response transformation

### Video Services
- Optimized for streaming workloads
- Session affinity for video streams
- Higher connection limits

### Analytics Services
- Configured for batch processing
- Extended timeouts for long-running operations
- Canary deployment for ML model updates

### Database Services
- TCP-level proxying
- Connection pooling
- Circuit breakers for database protection

## Monitoring and Dashboards

Access the various dashboards:

```bash
# Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80
# Default credentials: admin/admin

# Prometheus
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090

# Jaeger
kubectl port-forward -n monitoring svc/jaeger-query 16686:16686

# Istio-specific
istioctl dashboard kiali
istioctl dashboard grafana

# Linkerd-specific
linkerd viz dashboard
```

## Policy Validation

Validate service mesh policies:

```bash
./scripts/validate-policies.sh
```

This will check:
- mTLS configuration
- Authorization policies
- Network policies
- Service connectivity
- Policy violations

## Troubleshooting

### Common Issues

1. **Pod not receiving traffic**
   ```bash
   # Check sidecar injection
   kubectl get pod <pod-name> -n <namespace> -o yaml | grep -i sidecar
   
   # Check proxy configuration
   istioctl proxy-config all <pod-name> -n <namespace>
   ```

2. **Authorization errors**
   ```bash
   # Check authorization policies
   kubectl get authorizationpolicy -n <namespace>
   
   # Check service account
   kubectl get pod <pod-name> -n <namespace> -o yaml | grep serviceAccount
   ```

3. **High latency**
   ```bash
   # Check circuit breaker status
   istioctl proxy-config cluster <pod-name> -n <namespace> | grep -i circuit
   
   # Check outlier detection
   kubectl get destinationrule -n <namespace> -o yaml
   ```

### Debug Commands

```bash
# Istio
istioctl analyze -n <namespace>
istioctl proxy-config routes <pod-name> -n <namespace>
istioctl proxy-config listeners <pod-name> -n <namespace>
istioctl proxy-config clusters <pod-name> -n <namespace>
istioctl proxy-config endpoints <pod-name> -n <namespace>

# Linkerd
linkerd viz edges -n <namespace>
linkerd viz routes -n <namespace>
linkerd viz tap deploy/<deployment> -n <namespace>
```

## Performance Tuning

### Sidecar Resource Limits

Adjust in `istio-config.yaml` or during service onboarding:
```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 2000m
    memory: 1024Mi
```

### Connection Pool Settings

Configure in destination rules:
```yaml
connectionPool:
  tcp:
    maxConnections: 100
  http:
    http2MaxRequests: 1000
    maxRequestsPerConnection: 2
```

## Security Best Practices

1. **Always use STRICT mTLS** in production namespaces
2. **Implement deny-by-default** authorization policies
3. **Regularly rotate certificates** (automatic with Istio/Linkerd)
4. **Monitor policy violations** through alerts
5. **Use network policies** as additional defense layer
6. **Restrict egress traffic** to known external services

## Maintenance

### Upgrading Istio

```bash
# Check current version
istioctl version

# Download new version
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.20.1 sh -

# Upgrade
istioctl upgrade -f istio/istio-config.yaml
```

### Upgrading Linkerd

```bash
# Check current version
linkerd version

# Upgrade CLI
curl -sL https://run.linkerd.io/install | sh

# Upgrade control plane
linkerd upgrade | kubectl apply -f -
```

## Contributing

When adding new services or policies:

1. Follow the existing naming conventions
2. Update authorization policies to maintain zero-trust
3. Add appropriate destination rules and virtual services
4. Test with policy validation script
5. Update documentation

## References

- [Istio Documentation](https://istio.io/latest/docs/)
- [Linkerd Documentation](https://linkerd.io/docs/)
- [CNCF Service Mesh Landscape](https://landscape.cncf.io/card-mode?category=service-mesh)
- [Service Mesh Patterns](https://www.oreilly.com/library/view/service-mesh-patterns/9781492086444/)