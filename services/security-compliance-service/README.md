# Security Compliance Service

A comprehensive security and compliance management service for the SPARC platform that handles compliance reporting, audit logs, security policy enforcement, and regulatory requirements.

## Features

### Core Functionality
- **Audit Logging**: Comprehensive audit trail management with retention policies
- **Compliance Reporting**: Support for multiple frameworks (SOC2, HIPAA, PCI-DSS, GDPR, ISO27001)
- **GDPR Compliance**: Full GDPR request handling (access, erasure, portability, rectification)
- **Policy Engine**: Dynamic security policy creation and enforcement
- **Security Scanning**: Integration with vulnerability scanners (SonarQube, Snyk)
- **Data Retention**: Automated retention policy management with legal hold support

### Compliance Frameworks
- SOC 2 Type II
- HIPAA
- PCI DSS v4.0
- GDPR
- ISO/IEC 27001:2022
- NIST
- CCPA
- FISMA

### Key Capabilities
- Multi-tenant architecture with tenant isolation
- OpenTelemetry instrumentation for observability
- Real-time compliance monitoring and alerting
- Automated compliance checks and reporting
- Security incident tracking and response
- Certificate management
- Encryption key lifecycle management

## Architecture

The service follows the MicroserviceBase pattern and includes:

```
src/
├── routes/           # API endpoints
│   ├── audit.ts     # Audit log management
│   ├── compliance.ts # Compliance reporting
│   ├── gdpr.ts      # GDPR request handling
│   ├── policy.ts    # Security policy management
│   ├── security.ts  # Security scanning
│   └── retention.ts # Data retention management
├── services/        # Business logic
│   ├── audit-service.ts
│   ├── compliance-service.ts
│   ├── gdpr-service.ts
│   ├── policy-engine.ts
│   ├── security-scan-service.ts
│   ├── retention-service.ts
│   └── compliance-queue.ts
├── types/           # TypeScript types and schemas
│   ├── enums.ts
│   ├── interfaces.ts
│   └── schemas.ts
└── config/          # Configuration
    ├── compliance-controls.ts
    └── policy-templates.ts
```

## API Endpoints

### Audit Management
- `GET /api/audit` - Get audit logs with filtering
- `POST /api/audit` - Create audit log entry
- `GET /api/audit/stats` - Get audit statistics
- `POST /api/audit/export` - Export audit logs
- `GET /api/audit/:id` - Get specific audit log

### Compliance
- `GET /api/compliance/dashboard` - Compliance dashboard
- `GET /api/compliance/frameworks` - Available frameworks
- `POST /api/compliance/reports` - Generate compliance report
- `GET /api/compliance/reports/:id/download` - Download report
- `GET /api/compliance/findings` - Get compliance findings
- `POST /api/compliance/check/:framework` - Run compliance check

### GDPR
- `POST /api/gdpr/requests` - Create GDPR request
- `GET /api/gdpr/requests` - List GDPR requests
- `POST /api/gdpr/export/:userId` - Export user data
- `DELETE /api/gdpr/data/:userId` - Delete user data
- `PUT /api/gdpr/data/:userId/rectify` - Rectify user data
- `POST /api/gdpr/portability/:userId` - Generate portable data

### Policy Management
- `GET /api/policy` - List policies
- `POST /api/policy` - Create policy
- `PUT /api/policy/:id` - Update policy
- `DELETE /api/policy/:id` - Delete policy
- `POST /api/policy/evaluate` - Evaluate policies
- `GET /api/policy/templates` - Get policy templates

### Security Scanning
- `POST /api/security/scans` - Initiate security scan
- `GET /api/security/scans` - List scans
- `GET /api/security/dashboard` - Security dashboard
- `GET /api/security/posture` - Security posture score
- `POST /api/security/scans/schedule` - Schedule recurring scan

### Data Retention
- `GET /api/retention/policies` - List retention policies
- `POST /api/retention/policies` - Create retention policy
- `POST /api/retention/legal-hold` - Apply legal hold
- `POST /api/retention/execute` - Execute retention
- `GET /api/retention/dashboard` - Retention dashboard

## Environment Variables

```bash
# Service Configuration
PORT=3015
NODE_ENV=production

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/sparc

# Redis
REDIS_URL=redis://localhost:6379

# JWT Authentication
JWT_SECRET=your-jwt-secret

# Compliance Settings
AUDIT_LOG_RETENTION_DAYS=2555  # 7 years
COMPLIANCE_CHECK_INTERVAL=3600000  # 1 hour
ENCRYPTION_KEY_ROTATION_DAYS=90
MAX_EXPORT_SIZE_MB=100

# Security Scanners
SONARQUBE_URL=http://sonarqube:9000
SONARQUBE_API_KEY=your-api-key
SNYK_API_URL=https://api.snyk.io
SNYK_API_KEY=your-api-key
DEPENDENCY_CHECK_URL=http://dependency-check:8080

# Compliance Frameworks
COMPLIANCE_FRAMEWORKS=SOC2,HIPAA,PCI-DSS,GDPR,ISO27001

# Data Classifications
DATA_CLASSIFICATIONS=PUBLIC,INTERNAL,CONFIDENTIAL,RESTRICTED

# OpenTelemetry
OTEL_EXPORTER_JAEGER_ENDPOINT=http://jaeger:4317
```

## Development

### Setup
```bash
npm install
npm run db:generate
npm run db:push
```

### Running
```bash
# Development
npm run dev

# Production
npm run build
npm start
```

### Testing
```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

## Security Considerations

1. **Tenant Isolation**: All operations are scoped to tenant context
2. **Audit Trail**: All sensitive operations are logged
3. **Encryption**: Sensitive data is encrypted at rest and in transit
4. **Access Control**: Role-based access control for all endpoints
5. **Data Retention**: Automated data lifecycle management
6. **Legal Hold**: Support for legal hold requirements

## Compliance Features

### SOC2 Compliance
- Access control audit trails
- Change management logging
- System monitoring
- Risk assessment reports

### HIPAA Compliance
- PHI access logging
- Encryption verification
- Breach detection
- Administrative safeguards

### PCI DSS Compliance
- Cardholder data access logs
- Network security controls
- Vulnerability management
- Security testing reports

### GDPR Compliance
- Right to access
- Right to erasure
- Right to rectification
- Data portability
- Consent management

## Performance

- Handles 10,000+ concurrent users
- Sub-200ms response time for queries
- Efficient batch processing for reports
- Redis caching for frequently accessed data
- Background job queue for long-running tasks

## Monitoring

The service provides:
- Health check endpoint: `/health`
- Readiness check: `/ready`
- Metrics endpoint: `/metrics`
- OpenTelemetry instrumentation
- Structured logging with correlation IDs

## Integration

### External Services
- SonarQube for code quality scanning
- Snyk for dependency vulnerability scanning
- AWS KMS for encryption key management
- AWS Certificate Manager for SSL certificates

### Internal Services
- Auth Service for authentication
- Alert Service for notifications
- Reporting Service for document generation
- Event Processing for real-time updates

## License

Copyright (c) 2024 SPARC Platform. All rights reserved.