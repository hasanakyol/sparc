# SPARC Platform API Reference

## Quick Start

### 1. Obtain API Credentials

Contact your administrator to create API credentials for your application.

### 2. Authentication

```bash
# Login to get JWT token
curl -X POST https://api.sparc.platform/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "your-secure-password",
    "tenantId": "123e4567-e89b-12d3-a456-426614174000"
  }'
```

Response:
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600,
    "user": {
      "id": "user-uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "roles": ["admin", "operator"],
      "permissions": ["access:read", "video:view", "analytics:read"],
      "tenantId": "tenant-uuid"
    }
  }
}
```

### 3. Make Authenticated Requests

Use the JWT token in subsequent requests:

```bash
curl -X GET https://api.sparc.platform/v1/access-control/doors \
  -H "Authorization: Bearer {accessToken}" \
  -H "X-Tenant-ID: {tenantId}"
```

## Table of Contents
- [API Overview](#api-overview)
- [Authentication](#authentication)
- [Multi-Tenant Context](#multi-tenant-context)
- [Core Services](#core-services)
- [Specialized Services](#specialized-services)
- [Real-time Events](#real-time-events)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [SDK Examples](#sdk-examples)
- [Webhooks](#webhooks)
- [Best Practices](#best-practices)

## API Overview

The SPARC platform implements an API-first architecture using a microservices pattern with a centralized API Gateway. All client interactions flow through the gateway, which handles authentication, routing, rate limiting, and cross-cutting concerns.

### Architecture Pattern
- **API Gateway**: Single entry point at `https://api.sparc.platform`
- **Service Discovery**: Automatic routing to 24 microservices
- **Load Balancing**: Intelligent distribution across service instances
- **Circuit Breaker**: Fault tolerance and graceful degradation
- **Request/Response Transformation**: Standardized formats across services

### Base URL
```
Production: https://api.sparc.platform/v1
Staging: https://staging-api.sparc.platform/v1
Development: http://localhost:3000/api/v1
```

### API Versioning
- **URL Versioning**: `/v1/`, `/v2/` in the path
- **Header Versioning**: `API-Version: 1.0` header support
- **Backward Compatibility**: Maintained for 2 major versions

### Content Types
- **Request**: `application/json`
- **Response**: `application/json`
- **File Uploads**: `multipart/form-data`
- **Video Streams**: `application/octet-stream`

## Authentication

The SPARC platform uses JWT-based authentication with refresh token rotation for secure, stateless authentication across all microservices.

### Authentication Flow

#### 1. Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123",
  "tenantId": "tenant-uuid-here"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600,
    "user": {
      "id": "user-uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "roles": ["admin", "operator"],
      "permissions": ["access:read", "video:view", "analytics:read"],
      "tenantId": "tenant-uuid"
    }
  }
}
```

#### 2. Token Refresh
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### 3. Logout
```http
POST /auth/logout
Authorization: Bearer {accessToken}
```

### JWT Token Structure

**Access Token Claims:**
```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "tenantId": "tenant-uuid",
  "roles": ["admin", "operator"],
  "permissions": ["access:read", "video:view"],
  "iat": 1640995200,
  "exp": 1640998800,
  "iss": "sparc-auth-service",
  "aud": "sparc-platform"
}
```

### Authorization Headers
All authenticated requests must include:
```http
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}
```

### Session Management
- **Access Token Lifetime**: 1 hour
- **Refresh Token Lifetime**: 30 days
- **Automatic Refresh**: 5 minutes before expiration
- **Concurrent Sessions**: Limited to 5 per user
- **Session Invalidation**: On password change or admin action

### Multi-Factor Authentication (MFA)

If MFA is enabled for your account:

```http
POST /auth/mfa/setup
Authorization: Bearer {accessToken}

{
  "method": "totp|sms|email",
  "phoneNumber": "+1234567890" // for SMS
}
```

```http
POST /auth/mfa/verify
Authorization: Bearer {accessToken}

{
  "code": "123456",
  "method": "totp"
}
```

## Multi-Tenant Context

The SPARC platform supports three tenant models with complete data isolation and context propagation across all microservices.

### Tenant Models
1. **SSP (Shared Service Provider)**: Multi-customer shared infrastructure
2. **Enterprise**: Single organization with multiple sites
3. **Hybrid**: Mixed model with both shared and dedicated resources

### Tenant Context Headers
```http
X-Tenant-ID: tenant-uuid-here
X-Organization-ID: org-uuid-here
X-Site-ID: site-uuid-here
X-Building-ID: building-uuid-here
X-Floor-ID: floor-uuid-here
```

### Tenant Isolation
- **Database**: Row-level security with tenant_id filtering
- **Storage**: Tenant-specific S3 buckets and prefixes
- **Caching**: Tenant-namespaced Redis keys
- **Events**: Tenant-scoped event streams
- **Analytics**: Tenant-isolated data processing

### Tenant Switching
```http
POST /auth/switch-tenant
Authorization: Bearer {accessToken}
Content-Type: application/json

{
  "tenantId": "new-tenant-uuid"
}
```

## Core Services

### Authentication Service

Base path: `/auth`

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | User authentication |
| POST | `/logout` | Session termination |
| POST | `/refresh` | Token refresh |
| POST | `/forgot-password` | Password reset request |
| POST | `/reset-password` | Password reset confirmation |
| POST | `/change-password` | Password change |
| GET | `/me` | Current user profile |
| PUT | `/me` | Update user profile |
| POST | `/switch-tenant` | Switch tenant context |

### Tenant Management Service

Base path: `/tenants`

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | List accessible tenants |
| POST | `/` | Create new tenant |
| GET | `/{tenantId}` | Get tenant details |
| PUT | `/{tenantId}` | Update tenant |
| DELETE | `/{tenantId}` | Delete tenant |
| GET | `/{tenantId}/organizations` | List organizations |
| POST | `/{tenantId}/organizations` | Create organization |
| GET | `/{tenantId}/sites` | List sites |
| POST | `/{tenantId}/sites` | Create site |
| GET | `/{tenantId}/users` | List tenant users |
| POST | `/{tenantId}/users` | Invite user |

#### Tenant Configuration
```http
PUT /tenants/{tenantId}/config
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "features": {
    "videoAnalytics": true,
    "mobileCredentials": true,
    "visitorManagement": true,
    "environmentalMonitoring": true
  },
  "limits": {
    "maxDoors": 10000,
    "maxCameras": 1000,
    "maxUsers": 50000,
    "storageGB": 10000
  },
  "compliance": {
    "sox": true,
    "hipaa": false,
    "pciDss": true
  }
}
```

### Access Control Service

Base path: `/access-control`

#### Door Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/doors` | List doors |
| POST | `/doors` | Create door |
| GET | `/doors/{doorId}` | Get door details |
| PUT | `/doors/{doorId}` | Update door |
| DELETE | `/doors/{doorId}` | Delete door |
| POST | `/doors/{doorId}/unlock` | Unlock door |
| POST | `/doors/{doorId}/lock` | Lock door |
| GET | `/doors/{doorId}/status` | Get door status |
| GET | `/doors/{doorId}/events` | Get door events |

#### Access Groups and Permissions
```http
GET /access-control/groups
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

Response:
{
  "success": true,
  "data": [
    {
      "id": "group-uuid",
      "name": "Executive Access",
      "description": "C-level executive access",
      "doors": ["door-1", "door-2"],
      "schedules": ["schedule-1"],
      "users": ["user-1", "user-2"],
      "validFrom": "2024-01-01T00:00:00Z",
      "validTo": "2024-12-31T23:59:59Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 25,
    "pages": 1
  }
}
```

#### Access Events
```http
GET /access-control/events
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

Query Parameters:
- startDate: ISO 8601 date
- endDate: ISO 8601 date
- doorId: UUID
- userId: UUID
- eventType: granted|denied|forced|held_open
- page: number
- limit: number (max 1000)

Response:
{
  "success": true,
  "data": [
    {
      "id": "event-uuid",
      "timestamp": "2024-01-15T10:30:00Z",
      "doorId": "door-uuid",
      "doorName": "Main Entrance",
      "userId": "user-uuid",
      "userName": "John Doe",
      "eventType": "granted",
      "credentialType": "card|mobile|pin|biometric",
      "credentialId": "credential-uuid",
      "result": "success|failure",
      "reason": "valid_access|expired_credential|invalid_schedule"
    }
  ]
}
```

### Video Management Service

Base path: `/video`

#### Camera Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cameras` | List cameras |
| POST | `/cameras` | Add camera |
| GET | `/cameras/{cameraId}` | Get camera details |
| PUT | `/cameras/{cameraId}` | Update camera |
| DELETE | `/cameras/{cameraId}` | Remove camera |
| GET | `/cameras/{cameraId}/live` | Live stream URL |
| POST | `/cameras/{cameraId}/ptz` | PTZ control |
| GET | `/cameras/{cameraId}/recordings` | List recordings |

#### Live Streaming
```http
GET /video/cameras/{cameraId}/live
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

Response:
{
  "success": true,
  "data": {
    "streamUrl": "wss://stream.sparc.platform/live/{streamToken}",
    "streamToken": "encrypted-stream-token",
    "resolution": "1920x1080",
    "fps": 30,
    "codec": "h264",
    "expiresAt": "2024-01-15T11:30:00Z"
  }
}
```

#### Recording Management
```http
GET /video/recordings
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

Query Parameters:
- cameraId: UUID
- startDate: ISO 8601 date
- endDate: ISO 8601 date
- eventType: motion|access|alarm|manual
- page: number
- limit: number

Response:
{
  "success": true,
  "data": [
    {
      "id": "recording-uuid",
      "cameraId": "camera-uuid",
      "cameraName": "Lobby Camera 1",
      "startTime": "2024-01-15T10:00:00Z",
      "endTime": "2024-01-15T10:05:00Z",
      "duration": 300,
      "fileSize": 52428800,
      "resolution": "1920x1080",
      "eventType": "motion",
      "downloadUrl": "https://storage.sparc.platform/recordings/{token}",
      "thumbnailUrl": "https://storage.sparc.platform/thumbnails/{token}"
    }
  ]
}
```

#### Privacy Masks
```http
PUT /video/cameras/{cameraId}/privacy-masks
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "masks": [
    {
      "id": "mask-1",
      "name": "Reception Desk",
      "coordinates": {
        "x": 100,
        "y": 150,
        "width": 200,
        "height": 100
      },
      "active": true,
      "schedule": "business-hours"
    }
  ]
}
```

### Event Processing Service

Base path: `/events`

#### Event Stream Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/stream` | SSE event stream |
| POST | `/subscribe` | Subscribe to events |
| DELETE | `/subscribe/{subscriptionId}` | Unsubscribe |
| GET | `/history` | Event history |
| POST | `/trigger` | Manual event trigger |

#### Event Subscriptions
```http
POST /events/subscribe
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "eventTypes": ["access.granted", "access.denied", "alarm.triggered"],
  "filters": {
    "siteId": "site-uuid",
    "buildingId": "building-uuid",
    "severity": ["high", "critical"]
  },
  "delivery": {
    "method": "webhook|email|sms",
    "endpoint": "https://customer.com/webhooks/sparc",
    "headers": {
      "Authorization": "Bearer customer-token"
    }
  }
}
```

#### Real-time Event Stream (SSE)
```http
GET /events/stream
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}
Accept: text/event-stream

Response:
data: {"type":"access.granted","timestamp":"2024-01-15T10:30:00Z","doorId":"door-1","userId":"user-1"}

data: {"type":"alarm.triggered","timestamp":"2024-01-15T10:31:00Z","deviceId":"sensor-1","severity":"high"}
```

### Analytics Service

Base path: `/analytics`

#### Dashboard Data

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard` | Dashboard metrics |
| GET | `/reports` | Available reports |
| POST | `/reports/{reportId}/generate` | Generate report |
| GET | `/reports/{reportId}/download` | Download report |
| GET | `/metrics/access` | Access metrics |
| GET | `/metrics/video` | Video metrics |
| GET | `/metrics/system` | System metrics |

#### Access Analytics
```http
GET /analytics/metrics/access
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

Query Parameters:
- period: hour|day|week|month|year
- startDate: ISO 8601 date
- endDate: ISO 8601 date
- groupBy: door|user|time|building

Response:
{
  "success": true,
  "data": {
    "totalEvents": 15420,
    "successfulAccess": 14890,
    "deniedAccess": 530,
    "successRate": 96.56,
    "peakHours": [
      {"hour": 9, "count": 1250},
      {"hour": 17, "count": 1180}
    ],
    "topDoors": [
      {"doorId": "door-1", "name": "Main Entrance", "count": 3420},
      {"doorId": "door-2", "name": "Parking Garage", "count": 2890}
    ],
    "trends": {
      "daily": [
        {"date": "2024-01-15", "count": 1420},
        {"date": "2024-01-16", "count": 1380}
      ]
    }
  }
}
```

#### Custom Reports
```http
POST /analytics/reports/custom/generate
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "name": "Monthly Access Report",
  "type": "access_summary",
  "parameters": {
    "startDate": "2024-01-01",
    "endDate": "2024-01-31",
    "groupBy": "building",
    "includeCharts": true,
    "format": "pdf|excel|csv"
  },
  "schedule": {
    "frequency": "monthly",
    "dayOfMonth": 1,
    "time": "09:00",
    "timezone": "America/New_York"
  },
  "delivery": {
    "email": ["admin@company.com"],
    "webhook": "https://company.com/reports"
  }
}
```

### Incident Management Service

Base path: `/incidents`

#### Create Incident
```http
POST /incidents
Content-Type: application/json
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "title": "Unauthorized Access Attempt",
  "description": "Individual attempted to enter restricted area",
  "type": "intrusion",
  "severity": "high",
  "location": {
    "siteId": "site-001",
    "building": "HQ",
    "floor": "3",
    "zone": "Server Room"
  }
}
```

#### List Incidents
```http
GET /incidents?status=open&severity=high&page=1
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}
```

## Specialized Services

### Device Management Service

Base path: `/devices`

#### Device Discovery and Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | List devices |
| POST | `/discover` | Discover devices |
| POST | `/` | Add device |
| GET | `/{deviceId}` | Get device details |
| PUT | `/{deviceId}` | Update device |
| DELETE | `/{deviceId}` | Remove device |
| POST | `/{deviceId}/reboot` | Reboot device |
| GET | `/{deviceId}/diagnostics` | Device diagnostics |
| POST | `/{deviceId}/firmware/update` | Update firmware |

#### Device Configuration
```http
PUT /devices/{deviceId}/config
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "network": {
    "ip": "192.168.1.100",
    "subnet": "255.255.255.0",
    "gateway": "192.168.1.1",
    "dns": ["8.8.8.8", "8.8.4.4"]
  },
  "security": {
    "encryption": "aes256",
    "certificateId": "cert-uuid",
    "tamperDetection": true
  },
  "operation": {
    "unlockDuration": 5,
    "relockDelay": 2,
    "alarmTimeout": 30,
    "heartbeatInterval": 60
  }
}
```

### Environmental Monitoring Service

Base path: `/environmental`

#### Sensor Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/sensors` | List sensors |
| POST | `/sensors` | Add sensor |
| GET | `/sensors/{sensorId}` | Get sensor details |
| PUT | `/sensors/{sensorId}` | Update sensor |
| DELETE | `/sensors/{sensorId}` | Remove sensor |
| GET | `/sensors/{sensorId}/readings` | Get readings |
| POST | `/sensors/{sensorId}/calibrate` | Calibrate sensor |

#### Environmental Data
```http
GET /environmental/sensors/{sensorId}/readings
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

Query Parameters:
- startDate: ISO 8601 date
- endDate: ISO 8601 date
- interval: minute|hour|day
- metrics: temperature,humidity,co2,air_quality

Response:
{
  "success": true,
  "data": {
    "sensorId": "sensor-uuid",
    "sensorName": "Lobby Temperature",
    "location": "Building A - Lobby",
    "readings": [
      {
        "timestamp": "2024-01-15T10:00:00Z",
        "temperature": 22.5,
        "humidity": 45.2,
        "co2": 420,
        "airQuality": "good"
      }
    ],
    "statistics": {
      "temperature": {
        "min": 20.1,
        "max": 24.8,
        "avg": 22.3,
        "trend": "stable"
      }
    }
  }
}
```

#### HVAC Integration
```http
POST /environmental/hvac/control
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "zoneId": "zone-uuid",
  "action": "set_temperature|set_schedule|override",
  "parameters": {
    "targetTemperature": 22.0,
    "mode": "heat|cool|auto",
    "duration": 3600
  }
}
```

### Visitor Management Service

Base path: `/visitors`

#### Visitor Workflow

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | List visitors |
| POST | `/pre-register` | Pre-register visitor |
| POST | `/check-in` | Check in visitor |
| POST | `/{visitorId}/check-out` | Check out visitor |
| GET | `/{visitorId}` | Get visitor details |
| PUT | `/{visitorId}` | Update visitor |
| POST | `/{visitorId}/extend` | Extend visit |
| GET | `/{visitorId}/badge` | Generate visitor badge |

#### Visitor Pre-registration
```http
POST /visitors/pre-register
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "visitor": {
    "firstName": "Jane",
    "lastName": "Smith",
    "email": "jane.smith@company.com",
    "phone": "+1234567890",
    "company": "ABC Corp",
    "purpose": "Business Meeting"
  },
  "visit": {
    "hostUserId": "host-uuid",
    "scheduledDate": "2024-01-16",
    "scheduledTime": "14:00",
    "duration": 120,
    "areas": ["lobby", "conference-room-a"],
    "escortRequired": false
  },
  "requirements": {
    "backgroundCheck": false,
    "nda": true,
    "photoId": true,
    "healthScreening": false
  }
}
```

#### Visitor Check-in
```http
POST /visitors/check-in
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "visitorId": "visitor-uuid",
  "checkInMethod": "qr_code|manual|kiosk",
  "photoCapture": "base64-encoded-photo",
  "documentScan": "base64-encoded-id",
  "healthDeclaration": {
    "temperature": 98.6,
    "symptoms": false,
    "exposure": false
  },
  "agreements": {
    "nda": true,
    "safetyRules": true,
    "dataPrivacy": true
  }
}
```

### Maintenance Management Service

Base path: `/maintenance`

#### Work Order Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/work-orders` | List work orders |
| POST | `/work-orders` | Create work order |
| GET | `/work-orders/{orderId}` | Get work order |
| PUT | `/work-orders/{orderId}` | Update work order |
| POST | `/work-orders/{orderId}/assign` | Assign technician |
| POST | `/work-orders/{orderId}/complete` | Complete work order |
| GET | `/schedules` | Maintenance schedules |
| POST | `/schedules` | Create schedule |

#### Preventive Maintenance
```http
POST /maintenance/schedules
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "name": "Door Controller Maintenance",
  "description": "Quarterly maintenance for door controllers",
  "deviceType": "door_controller",
  "devices": ["device-1", "device-2"],
  "tasks": [
    {
      "name": "Firmware Update Check",
      "description": "Check and update firmware if needed",
      "estimatedDuration": 30,
      "required": true
    },
    {
      "name": "Hardware Inspection",
      "description": "Visual inspection of hardware components",
      "estimatedDuration": 15,
      "required": true
    }
  ],
  "schedule": {
    "frequency": "quarterly",
    "startDate": "2024-01-01",
    "preferredTime": "02:00",
    "timezone": "America/New_York"
  },
  "assignedTo": "technician-uuid"
}
```

### Integration Management Service

Base path: `/integrations`

#### Third-party Integrations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | List integrations |
| POST | `/` | Create integration |
| GET | `/{integrationId}` | Get integration |
| PUT | `/{integrationId}` | Update integration |
| DELETE | `/{integrationId}` | Delete integration |
| POST | `/{integrationId}/test` | Test integration |
| GET | `/{integrationId}/logs` | Integration logs |

#### HR System Integration
```http
POST /integrations
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "name": "Workday HR Integration",
  "type": "hr_system",
  "provider": "workday",
  "configuration": {
    "apiEndpoint": "https://company.workday.com/api",
    "authentication": {
      "type": "oauth2",
      "clientId": "client-id",
      "clientSecret": "client-secret",
      "scope": "employee_read"
    },
    "syncSettings": {
      "frequency": "daily",
      "time": "02:00",
      "timezone": "America/New_York",
      "fields": ["employee_id", "first_name", "last_name", "email", "department", "status"]
    }
  },
  "mapping": {
    "employeeId": "employee_id",
    "email": "email",
    "firstName": "first_name",
    "lastName": "last_name",
    "department": "department",
    "status": "status"
  },
  "filters": {
    "activeOnly": true,
    "departments": ["Engineering", "Sales", "Marketing"]
  }
}
```

## Real-time Events

The SPARC platform provides real-time event streaming using Socket.IO for instant notifications and updates across all connected clients.

### Connection Setup
```javascript
import io from 'socket.io-client';

const socket = io('wss://api.sparc.platform', {
  auth: {
    token: 'your-jwt-token'
  },
  query: {
    tenantId: 'tenant-uuid'
  }
});
```

### Event Types

#### Access Control Events
```javascript
// Door access granted
socket.on('access.granted', (data) => {
  console.log('Access granted:', data);
  // {
  //   eventId: 'event-uuid',
  //   timestamp: '2024-01-15T10:30:00Z',
  //   doorId: 'door-uuid',
  //   doorName: 'Main Entrance',
  //   userId: 'user-uuid',
  //   userName: 'John Doe',
  //   credentialType: 'card'
  // }
});

// Door access denied
socket.on('access.denied', (data) => {
  console.log('Access denied:', data);
});

// Door forced open
socket.on('door.forced', (data) => {
  console.log('Door forced:', data);
});

// Door held open
socket.on('door.held_open', (data) => {
  console.log('Door held open:', data);
});
```

#### Video Events
```javascript
// Motion detected
socket.on('video.motion', (data) => {
  console.log('Motion detected:', data);
  // {
  //   cameraId: 'camera-uuid',
  //   cameraName: 'Lobby Camera',
  //   timestamp: '2024-01-15T10:30:00Z',
  //   confidence: 0.95,
  //   boundingBox: { x: 100, y: 150, width: 200, height: 300 }
  // }
});

// Camera offline
socket.on('camera.offline', (data) => {
  console.log('Camera offline:', data);
});

// Recording started
socket.on('recording.started', (data) => {
  console.log('Recording started:', data);
});
```

#### System Events
```javascript
// Device status change
socket.on('device.status', (data) => {
  console.log('Device status:', data);
  // {
  //   deviceId: 'device-uuid',
  //   deviceName: 'Door Controller 1',
  //   status: 'online|offline|error',
  //   timestamp: '2024-01-15T10:30:00Z'
  // }
});

// System alert
socket.on('system.alert', (data) => {
  console.log('System alert:', data);
  // {
  //   alertId: 'alert-uuid',
  //   type: 'security|maintenance|system',
  //   severity: 'low|medium|high|critical',
  //   message: 'Alert description',
  //   timestamp: '2024-01-15T10:30:00Z'
  // }
});
```

#### Environmental Events
```javascript
// Threshold exceeded
socket.on('environmental.threshold', (data) => {
  console.log('Environmental threshold:', data);
  // {
  //   sensorId: 'sensor-uuid',
  //   sensorName: 'Lobby Temperature',
  //   metric: 'temperature',
  //   value: 26.5,
  //   threshold: 25.0,
  //   severity: 'warning'
  // }
});
```

### Event Subscriptions
```javascript
// Subscribe to specific events
socket.emit('subscribe', {
  events: ['access.granted', 'access.denied'],
  filters: {
    buildingId: 'building-uuid',
    severity: ['high', 'critical']
  }
});

// Unsubscribe from events
socket.emit('unsubscribe', {
  events: ['access.granted']
});
```

### Room-based Events
```javascript
// Join tenant room
socket.emit('join', `tenant:${tenantId}`);

// Join building room
socket.emit('join', `building:${buildingId}`);

// Leave room
socket.emit('leave', `building:${buildingId}`);
```

## Error Handling

The SPARC platform uses standardized error responses across all microservices for consistent error handling and debugging.

### Error Response Format
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "requestId": "req-uuid-here",
    "path": "/auth/login"
  }
}
```

### HTTP Status Codes

| Status | Code | Description |
|--------|------|-------------|
| 200 | OK | Request successful |
| 201 | CREATED | Resource created |
| 400 | BAD_REQUEST | Invalid request |
| 401 | UNAUTHORIZED | Authentication required |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 409 | CONFLICT | Resource conflict |
| 422 | VALIDATION_ERROR | Validation failed |
| 429 | RATE_LIMITED | Rate limit exceeded |
| 500 | INTERNAL_ERROR | Server error |
| 502 | BAD_GATEWAY | Service unavailable |
| 503 | SERVICE_UNAVAILABLE | Service temporarily unavailable |

### Error Codes

#### Authentication Errors
- `AUTH_INVALID_CREDENTIALS`: Invalid username/password
- `AUTH_TOKEN_EXPIRED`: JWT token expired
- `AUTH_TOKEN_INVALID`: Invalid JWT token
- `AUTH_MFA_REQUIRED`: Multi-factor authentication required
- `AUTH_ACCOUNT_LOCKED`: Account temporarily locked

#### Authorization Errors
- `AUTHZ_INSUFFICIENT_PERMISSIONS`: Missing required permissions
- `AUTHZ_TENANT_ACCESS_DENIED`: No access to tenant
- `AUTHZ_RESOURCE_FORBIDDEN`: Resource access forbidden

#### Validation Errors
- `VALIDATION_REQUIRED_FIELD`: Required field missing
- `VALIDATION_INVALID_FORMAT`: Invalid field format
- `VALIDATION_OUT_OF_RANGE`: Value out of acceptable range
- `VALIDATION_DUPLICATE_VALUE`: Duplicate value not allowed

#### Resource Errors
- `RESOURCE_NOT_FOUND`: Requested resource not found
- `RESOURCE_CONFLICT`: Resource already exists
- `RESOURCE_LOCKED`: Resource is locked for editing

#### System Errors
- `SYSTEM_MAINTENANCE`: System under maintenance
- `SYSTEM_OVERLOADED`: System temporarily overloaded
- `SYSTEM_DATABASE_ERROR`: Database connection error

### Error Handling Best Practices

#### Client-side Error Handling
```javascript
try {
  const response = await fetch('/api/v1/doors', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Tenant-ID': tenantId
    }
  });
  
  if (!response.ok) {
    const error = await response.json();
    
    switch (error.error.code) {
      case 'AUTH_TOKEN_EXPIRED':
        // Refresh token and retry
        await refreshToken();
        return retryRequest();
        
      case 'AUTHZ_INSUFFICIENT_PERMISSIONS':
        // Show permission denied message
        showError('You do not have permission to access this resource');
        break;
        
      case 'RATE_LIMITED':
        // Implement exponential backoff
        await delay(error.error.retryAfter * 1000);
        return retryRequest();
        
      default:
        showError(error.error.message);
    }
  }
  
  return await response.json();
} catch (error) {
  console.error('Request failed:', error);
  showError('Network error occurred');
}
```

## Rate Limiting

The SPARC platform implements comprehensive rate limiting to ensure fair usage and system stability.

### Rate Limit Headers
All API responses include rate limiting information:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640998800
X-RateLimit-Window: 3600
```

### Rate Limit Tiers

#### By User Type
| User Type | Requests/Hour | Burst Limit |
|-----------|---------------|-------------|
| Admin | 10,000 | 100/minute |
| Operator | 5,000 | 50/minute |
| Viewer | 1,000 | 20/minute |
| API Client | 50,000 | 500/minute |

#### By Endpoint Category
| Category | Requests/Hour | Notes |
|----------|---------------|-------|
| Authentication | 100 | Per IP address |
| Read Operations | 5,000 | GET requests |
| Write Operations | 1,000 | POST/PUT/DELETE |
| Video Streaming | 100 | Concurrent streams |
| File Downloads | 500 | Large file downloads |
| Analytics | 1,000 | Report generation |

### Rate Limiting Strategies

#### Token Bucket Algorithm
- **Bucket Size**: Based on user tier
- **Refill Rate**: Constant rate per second
- **Burst Handling**: Allow temporary spikes

#### Sliding Window
- **Window Size**: 1 hour
- **Granularity**: 1 minute intervals
- **Memory Efficient**: Redis-based implementation

### Rate Limit Bypass
```http
X-RateLimit-Bypass: emergency-token-here
```
Emergency bypass tokens for critical operations.

### Rate Limit Monitoring
```http
GET /system/rate-limits
Authorization: Bearer {adminToken}

Response:
{
  "success": true,
  "data": {
    "currentUsage": {
      "userId": "user-uuid",
      "requests": 450,
      "limit": 1000,
      "resetTime": "2024-01-15T11:00:00Z"
    },
    "topUsers": [
      {
        "userId": "user-1",
        "requests": 4500,
        "percentage": 90
      }
    ]
  }
}
```

## SDK Examples

### JavaScript/TypeScript SDK

#### Installation
```bash
npm install @sparc/platform-sdk
```

#### Basic Setup
```typescript
import { SparcClient } from '@sparc/platform-sdk';

const client = new SparcClient({
  baseUrl: 'https://api.sparc.platform/v1',
  tenantId: 'your-tenant-id',
  apiKey: 'your-api-key', // Optional for service-to-service
});

// Authenticate with user credentials
await client.auth.login({
  email: 'user@example.com',
  password: 'password',
  tenantId: 'tenant-id'
});
```

#### Access Control Operations
```typescript
// List doors
const doors = await client.accessControl.doors.list({
  buildingId: 'building-uuid',
  page: 1,
  limit: 50
});

// Unlock door
await client.accessControl.doors.unlock('door-uuid');

// Get access events
const events = await client.accessControl.events.list({
  startDate: '2024-01-01',
  endDate: '2024-01-31',
  doorId: 'door-uuid'
});

// Create access group
const group = await client.accessControl.groups.create({
  name: 'Executive Access',
  description: 'C-level executive access',
  doors: ['door-1', 'door-2'],
  users: ['user-1', 'user-2'],
  schedules: ['schedule-1']
});
```

#### Video Management
```typescript
// List cameras
const cameras = await client.video.cameras.list();

// Get live stream
const stream = await client.video.cameras.getLiveStream('camera-uuid');

// Search recordings
const recordings = await client.video.recordings.search({
  cameraId: 'camera-uuid',
  startDate: '2024-01-15T00:00:00Z',
  endDate: '2024-01-15T23:59:59Z',
  eventType: 'motion'
});

// Download recording
const downloadUrl = await client.video.recordings.getDownloadUrl('recording-uuid');
```

#### Real-time Events
```typescript
// Subscribe to events
client.events.on('access.granted', (event) => {
  console.log('Access granted:', event);
});

client.events.on('door.forced', (event) => {
  console.log('Door forced open:', event);
  // Trigger security alert
});

// Subscribe to specific building events
client.events.subscribe({
  events: ['access.*', 'door.*'],
  filters: {
    buildingId: 'building-uuid'
  }
});
```

#### Analytics and Reporting
```typescript
// Get dashboard metrics
const metrics = await client.analytics.getDashboardMetrics({
  period: 'day',
  startDate: '2024-01-15',
  endDate: '2024-01-15'
});

// Generate custom report
const report = await client.analytics.reports.generate({
  type: 'access_summary',
  parameters: {
    startDate: '2024-01-01',
    endDate: '2024-01-31',
    groupBy: 'building'
  },
  format: 'pdf'
});

// Download report
const reportUrl = await client.analytics.reports.getDownloadUrl(report.id);
```

### Python SDK

#### Installation
```bash
pip install sparc-platform-sdk
```

#### Basic Usage
```python
from sparc_sdk import SparcClient

# Initialize client
client = SparcClient(
    base_url='https://api.sparc.platform/v1',
    tenant_id='your-tenant-id'
)

# Authenticate
await client.auth.login(
    email='user@example.com',
    password='password',
    tenant_id='tenant-id'
)

# List doors
doors = await client.access_control.doors.list(
    building_id='building-uuid',
    page=1,
    limit=50
)

# Unlock door
await client.access_control.doors.unlock('door-uuid')

# Get access events
events = await client.access_control.events.list(
    start_date='2024-01-01',
    end_date='2024-01-31',
    door_id='door-uuid'
)
```

### Go SDK
```go
import "github.com/sparc/sparc-go"

client := sparc.NewClient("your-api-key")

// Get camera stream
stream, err := client.Cameras.GetStream("cam-001", &sparc.StreamOptions{
    Quality: "high",
})

// List incidents
incidents, err := client.Incidents.List(&sparc.IncidentFilters{
    Status: "open",
    Severity: "high",
})
```

### REST API Examples

#### cURL Examples
```bash
# Login
curl -X POST https://api.sparc.platform/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password",
    "tenantId": "tenant-uuid"
  }'

# List doors
curl -X GET https://api.sparc.platform/v1/access-control/doors \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "X-Tenant-ID: ${TENANT_ID}"

# Unlock door
curl -X POST https://api.sparc.platform/v1/access-control/doors/door-uuid/unlock \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "X-Tenant-ID: ${TENANT_ID}"

# Get live stream
curl -X GET https://api.sparc.platform/v1/video/cameras/camera-uuid/live \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "X-Tenant-ID: ${TENANT_ID}"
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Webhook Setup
```http
POST /integrations/webhooks
Authorization: Bearer {accessToken}
X-Tenant-ID: {tenantId}

{
  "name": "Security Alerts",
  "url": "https://your-system.com/webhooks/sparc",
  "events": ["access.denied", "door.forced", "alarm.triggered"],
  "headers": {
    "Authorization": "Bearer your-webhook-secret"
  },
  "retryPolicy": {
    "maxRetries": 3,
    "backoffMultiplier": 2,
    "initialDelay": 1000
  }
}
```

### Webhook Payload Example
```json
{
  "eventId": "event-uuid",
  "eventType": "access.denied",
  "timestamp": "2024-01-15T10:30:00Z",
  "tenantId": "tenant-uuid",
  "data": {
    "doorId": "door-uuid",
    "doorName": "Main Entrance",
    "userId": "user-uuid",
    "userName": "John Doe",
    "reason": "expired_credential",
    "credentialType": "card"
  },
  "signature": "sha256=webhook-signature"
}
```

### Webhook Verification
```javascript
const crypto = require('crypto');

function verifyWebhook(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
    
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(`sha256=${expectedSignature}`)
  );
}
```

## Best Practices

### 1. Use Pagination

Always use pagination for list endpoints:

```bash
GET /users?page=1&limit=50
```

### 2. Filter Results

Use query parameters to filter results:

```bash
GET /incidents?status=open&severity=high&type=intrusion
```

### 3. Handle Rate Limits

Implement exponential backoff:

```javascript
async function makeRequest(url, options, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.status === 429) {
        const retryAfter = response.headers.get('X-RateLimit-Reset');
        await sleep(retryAfter * 1000);
        continue;
      }
      return response;
    } catch (error) {
      if (i === retries - 1) throw error;
      await sleep(Math.pow(2, i) * 1000);
    }
  }
}
```

### 4. Use Efficient Queries

- Request only needed fields (when supported)
- Use appropriate time ranges
- Cache responses when appropriate

### 5. Secure API Keys

- Never expose API keys in client-side code
- Use environment variables
- Rotate keys regularly
- Restrict key permissions

---

## Support and Resources

- **API Documentation**: https://docs.sparc.platform/api
- **Developer Portal**: https://developers.sparc.platform
- **Status Page**: https://status.sparc.platform
- **Support**: support@sparc.platform
- **Community**: https://community.sparc.platform

For additional examples and advanced integration patterns, visit our [Developer Portal](https://developers.sparc.platform) or contact our support team.