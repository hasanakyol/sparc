# SPARC Documentation

**Version:** 1.0  
**Last Updated:** 2025-01-19  
**Platform:** SPARC Security Platform

## Overview

Welcome to the SPARC Security Platform documentation. SPARC is a comprehensive physical security management system handling video surveillance, access control, environmental monitoring, and incident management for 10,000+ concurrent users and 100,000+ video streams.

## Documentation Structure

### 🚀 Getting Started
- **[Quick Start Guide](getting-started/quickstart.md)** - Get up and running in 5 minutes
- **[Installation Guide](getting-started/installation.md)** - Detailed setup instructions
- **[Architecture Overview](getting-started/architecture-overview.md)** - System design and components

### 🔌 API Documentation
- **[API Reference](api/reference.md)** - Complete API documentation for all 24 microservices
- **[Authentication Guide](api/authentication.md)** - JWT authentication and authorization
- **[API Versioning](api/guides/versioning-strategy.md)** - API versioning approach
- **[OpenAPI Specifications](api/openapi/)** - Service-specific API specs

### 🚢 Deployment
- **[Deployment Guide](deployment/guide.md)** - Comprehensive deployment instructions
- **[AWS Deployment](deployment/aws.md)** - AWS-specific configuration
- **[Azure Deployment](deployment/azure.md)** - Azure-specific configuration
- **[Kubernetes Configuration](deployment/kubernetes.md)** - K8s manifests and setup

### 🔒 Security
- **[Security Architecture](security/architecture.md)** - Security design and implementation
- **[Security Best Practices](security/best-practices.md)** - Secure coding guidelines
- **[Incident Response](security/incident-response.md)** - Security incident procedures
- **[Compliance Guide](security/compliance.md)** - Regulatory compliance (SOC2, HIPAA, etc.)
- **[Threat Model](security/THREAT_MODEL.md)** - Security threat analysis

### 🔧 Operations
- **[Monitoring & Observability](operations/monitoring.md)** - Prometheus, Grafana, OpenTelemetry
- **[Backup & Recovery](operations/backup-recovery.md)** - Data protection procedures
- **[Troubleshooting Guide](operations/troubleshooting.md)** - Common issues and solutions
- **[Performance Tuning](operations/performance-tuning.md)** - Optimization guidelines
- **[Runbooks](operations/runbooks/)** - Operational procedures

### 💻 Development
- **[Contributing Guide](development/contributing.md)** - How to contribute to SPARC
- **[Testing Strategy](development/testing.md)** - Test framework and coverage requirements
- **[Error Handling](development/error-handling.md)** - Error patterns and best practices
- **[Microservices Guide](development/microservices.md)** - Service development patterns

### 📖 User Guides
- **[Administrator Guide](user-guides/administrator-guide.md)** - Admin tasks and configuration
- **[Operator Guide](user-guides/operator-guide.md)** - Daily operational tasks

### 🏗️ Architecture Decisions
- **[ADR-001: Microservices Architecture](architecture/ADR-001-microservices-architecture.md)**
- **[ADR-002: Technology Stack](architecture/ADR-002-technology-stack.md)**
- **[ADR-003: Multi-Tenancy Strategy](architecture/ADR-003-multi-tenancy-strategy.md)**
- **[ADR-004: Video Architecture](architecture/ADR-004-video-architecture.md)**
- **[ADR-005: Security Architecture](architecture/ADR-005-security-architecture.md)**

## Quick Links

### For Developers
1. [Quick Start](getting-started/quickstart.md) → [API Reference](api/reference.md) → [Testing Guide](development/testing.md)

### For DevOps/SRE
1. [Deployment Guide](deployment/guide.md) → [Monitoring](operations/monitoring.md) → [Troubleshooting](operations/troubleshooting.md)

### For Security Teams
1. [Security Architecture](security/architecture.md) → [Threat Model](security/THREAT_MODEL.md) → [Incident Response](security/incident-response.md)

### For Administrators
1. [Installation](getting-started/installation.md) → [Administrator Guide](user-guides/administrator-guide.md) → [Backup Procedures](operations/backup-recovery.md)

## Platform Overview

### Core Services (24 Total)
- **API Gateway** - Central entry point and routing
- **Auth Service** - Authentication and authorization
- **Video Management** - Video streaming and recording
- **Access Control** - Physical access management
- **Analytics** - Real-time analytics and insights
- [View all services →](getting-started/architecture-overview.md#services)

### Key Features
- Multi-tenant architecture with organization/site/zone hierarchy
- Real-time video processing with AI/ML analytics
- Offline operation support with automatic sync
- Horizontal scaling to 100,000+ video streams
- Enterprise security with SOC2/HIPAA compliance

### Technology Stack
- **Backend**: Node.js, TypeScript, Hono framework
- **Frontend**: Next.js 14, React, Tailwind CSS
- **Database**: PostgreSQL with Drizzle ORM
- **Infrastructure**: Kubernetes, Terraform
- **Monitoring**: Prometheus, Grafana, OpenTelemetry

## Documentation Standards

All documentation follows these standards:
- Clear version and update tracking
- Consistent markdown formatting
- Real-world examples (no placeholders)
- Cross-references between related docs
- Regular accuracy reviews

## Contributing to Documentation

See our [Contributing Guide](development/contributing.md#documentation) for:
- Documentation style guide
- Review process
- Update procedures
- Template usage

## Getting Help

- **GitHub Issues**: [github.com/sparc/sparc/issues](https://github.com/sparc/sparc/issues)
- **API Support**: api-support@sparc.com
- **Security Issues**: security@sparc.com (see [Security Policy](security/SECURITY.md))

---

*This documentation is continuously updated. For the latest changes, check our [changelog](CHANGELOG.md).*