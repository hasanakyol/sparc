# SPARC Architecture Overview

**Version:** 1.0  
**Last Updated:** 2025-01-19  
**Audience:** Developers, Architects, DevOps Engineers

## Overview

SPARC is a comprehensive physical security management platform built on a modern microservices architecture. The system is designed to handle enterprise-scale deployments with 10,000+ concurrent users and 100,000+ video streams while maintaining high availability and performance.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Applications                        │
│    Web App (Next.js)  │  Mobile Apps  │  Third-party Systems    │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────────┐
│                         API Gateway                              │
│              (Authentication, Routing, Rate Limiting)            │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────────┐
│                     Microservices Layer                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐  │
│  │Auth Service │ │Video Service│ │Access Control│ │Analytics │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐  │
│  │Tenant Mgmt  │ │Event Process│ │Alert Service │ │  Device  │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘  │
│                        ... (24 services total) ...               │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────────┐
│                        Data Layer                                │
│  ┌────────────┐  ┌─────────────┐  ┌──────────┐  ┌───────────┐  │
│  │ PostgreSQL │  │    Redis    │  │    S3    │  │Message Queue│ │
│  │(Multi-tenant)│ │  (Cache)    │  │ (Video)  │  │  (Events)  │ │
│  └────────────┘  └─────────────┘  └──────────┘  └───────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. **Client Layer**
- **Web Application**: Next.js 14 with App Router, React, TypeScript
- **Mobile Applications**: Native iOS/Android with offline support
- **Third-party Integrations**: REST API and webhook support

### 2. **API Gateway**
- Central entry point for all client requests
- JWT-based authentication and authorization
- Request routing to appropriate microservices
- Rate limiting and DDoS protection
- API versioning support

### 3. **Microservices (24 Total)**

#### Core Services
- **Auth Service**: Authentication, authorization, JWT management
- **Tenant Service**: Multi-tenant management, organization hierarchy
- **User Management**: User profiles, roles, permissions
- **API Gateway**: Request routing, authentication validation

#### Security Services
- **Access Control**: Physical access management, badge readers
- **Video Management**: Live streaming, recording, playback
- **Security Monitoring**: Real-time threat detection
- **Security Compliance**: Audit logs, compliance reporting

#### Operational Services
- **Alert Service**: Notification management, escalation
- **Analytics Service**: Real-time analytics, reporting
- **Event Processing**: Event streaming, complex event processing
- **Incident Management**: Incident tracking and response

#### Device Services
- **Device Management**: Camera, sensor configuration
- **Device Provisioning**: Zero-touch device setup
- **Environmental Service**: Temperature, humidity monitoring
- **Elevator Control**: Elevator access integration

#### Support Services
- **Integration Service**: Third-party system integration
- **Maintenance Service**: Scheduled maintenance tracking
- **Visitor Management**: Visitor registration, badge printing
- **Backup Recovery**: Data backup and restore

#### Infrastructure Services
- **API Documentation**: OpenAPI documentation
- **Testing Infrastructure**: Automated testing support
- **Reporting Service**: Custom report generation
- **Mobile Credential**: Mobile access credentials

### 4. **Data Layer**

#### PostgreSQL (Primary Database)
- Multi-tenant data isolation
- Row-level security
- JSON/JSONB for flexible schemas
- Automated backups and replication

#### Redis (Cache & Sessions)
- Session storage
- API response caching
- Real-time data caching
- Pub/sub for events

#### S3/Blob Storage
- Video file storage
- Document storage
- Backup archives
- Static asset hosting

#### Message Queue
- Event-driven communication
- Asynchronous processing
- Service decoupling
- Reliable message delivery

## Multi-Tenant Architecture

### Hierarchy
```
Organization (e.g., "ACME Corp")
├── Site (e.g., "Chicago HQ")
│   ├── Zone (e.g., "Building A - Floor 2")
│   │   ├── Cameras
│   │   ├── Access Points
│   │   └── Sensors
│   └── Zone (e.g., "Parking Garage")
└── Site (e.g., "NYC Office")
```

### Tenant Isolation
- **Database**: Row-level security with tenant_id
- **API**: Automatic tenant context injection
- **Storage**: Isolated S3 buckets/prefixes
- **Cache**: Tenant-prefixed keys

## Communication Patterns

### Synchronous Communication
- REST APIs for CRUD operations
- gRPC for inter-service communication
- GraphQL for flexible queries (future)

### Asynchronous Communication
- Message queues for event processing
- WebSockets for real-time updates
- Server-sent events for notifications

### Event-Driven Architecture
```
Service A → Event → Message Queue → Service B
                               ↓
                          Service C
```

## Security Architecture

### Defense in Depth
1. **Network Security**: VPC, security groups, WAF
2. **Application Security**: Authentication, authorization, input validation
3. **Data Security**: Encryption at rest and in transit
4. **Operational Security**: Audit logs, monitoring, incident response

### Authentication Flow
```
Client → API Gateway → Auth Service → JWT Token
                  ↓
         Subsequent Requests with JWT
                  ↓
         API Gateway validates → Microservice
```

## Scalability Patterns

### Horizontal Scaling
- Kubernetes HPA for auto-scaling
- Database read replicas
- CDN for static assets
- Load balancing across instances

### Performance Optimization
- Redis caching strategy
- Database query optimization
- Video streaming optimization
- Connection pooling

## High Availability

### Redundancy
- Multi-AZ deployment
- Database replication
- Service mesh for failover
- Health checks and auto-recovery

### Disaster Recovery
- Automated backups
- Cross-region replication
- RTO: 15 minutes
- RPO: 5 minutes

## Technology Stack

### Backend
- **Runtime**: Node.js 18+
- **Language**: TypeScript
- **Framework**: Hono (lightweight, fast)
- **ORM**: Drizzle (type-safe, performant)

### Frontend
- **Framework**: Next.js 14 (App Router)
- **UI Library**: React 18
- **Styling**: Tailwind CSS
- **State Management**: Zustand/TanStack Query

### Infrastructure
- **Orchestration**: Kubernetes
- **Service Mesh**: Istio
- **CI/CD**: GitHub Actions
- **IaC**: Terraform

### Monitoring
- **Metrics**: Prometheus
- **Visualization**: Grafana
- **Tracing**: OpenTelemetry
- **Logs**: ELK Stack

## Development Principles

### Design Patterns
- Domain-Driven Design (DDD)
- Repository pattern
- Dependency injection
- CQRS for complex domains

### Best Practices
- API-first development
- Test-driven development
- Infrastructure as code
- GitOps deployment

### Code Organization
```
service/
├── src/
│   ├── routes/     # API endpoints
│   ├── services/   # Business logic
│   ├── models/     # Data models
│   ├── middleware/ # Cross-cutting concerns
│   └── utils/      # Utilities
├── tests/          # Test files
└── docs/           # Service documentation
```

## Performance Requirements

### Response Times
- API endpoints: < 200ms (p95)
- Video stream start: < 500ms
- Dashboard load: < 2 seconds
- Search operations: < 1 second

### Throughput
- 10,000+ concurrent users
- 100,000+ video streams
- 1M+ API requests/minute
- 10GB+ video ingestion/minute

### Availability
- 99.99% uptime SLA
- Zero-downtime deployments
- Automatic failover
- Self-healing systems

## Next Steps

1. Review [API Reference](../api/reference.md) for endpoint details
2. Follow [Quick Start Guide](quickstart.md) to run locally
3. Read [Deployment Guide](../deployment/guide.md) for production setup
4. Check [Security Best Practices](../security/best-practices.md)

---

*For detailed architectural decisions, see the [Architecture Decision Records](../architecture/).*