# SPARC Platform API Documentation

## Overview

The SPARC (Secure Physical Access and Real-time Control) platform provides a comprehensive API-first architecture for unified physical access control and video surveillance management. This documentation covers all microservices, endpoints, authentication requirements, and integration examples.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [API Services](#api-services)
- [OpenAPI Specifications](#openapi-specifications)
- [Integration Examples](#integration-examples)
- [SDKs and Libraries](#sdks-and-libraries)

## Architecture Overview

The SPARC platform follows a microservices architecture with the following core services:

- **API Gateway** - Central entry point for all API requests
- **Authentication Service** - User authentication and authorization
- **Tenant Service** - Multi-tenant organization management
- **Access Control Service** - Physical access control management
- **Video Management Service** - Video surveillance and streaming
- **Event Processing Service** - Real-time event monitoring and alerting
- **Device Management Service** - Hardware integration and device management
- **Mobile Credential Service** - Mobile access credential management
- **Analytics Service** - Advanced analytics and intelligence
- **Environmental Service** - Environmental monitoring
- **Visitor Management Service** - Visitor registration and management
- **Reporting Service** - Dashboard and reporting capabilities

### Base URL

All API requests are made through the API Gateway:

```
Production: https://api.sparc.platform/v1
Staging: https://staging-api.sparc.platform/v1
Development: https://dev-api.sparc.platform/v1
```

## Authentication

### JWT Token Authentication

The SPARC platform uses JWT (JSON Web Token) based authentication for all API requests.

#### Authentication Flow

1. **Login**: POST `/auth/login` with credentials
2. **Receive Tokens**: Get access token (15 min) and refresh token (7 days)
3. **API Requests**: Include access token in Authorization header
4. **Token Refresh**: Use refresh token to get new access token

#### Headers

```http
Authorization: Bearer <access_token>
X-Tenant-ID: <tenant_id>
Content-Type: application/json
```

#### Login Request

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123",
  "tenantId": "tenant_123"
}
```

#### Login Response

```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 900,
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "SECURITY_ADMIN",
      "tenantId": "tenant_123",
      "permissions": ["ACCESS_CONTROL_READ", "ACCESS_CONTROL_WRITE"]
    }
  }
}
```

#### Token Refresh

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

## Rate Limiting

The API implements rate limiting to ensure system stability and fair usage:

### Rate Limits

- **Per User**: 1000 requests per hour
- **Per Tenant**: 10,000 requests per hour
- **Per Endpoint**: Varies by endpoint complexity
- **Authentication**: 10 login attempts per 15 minutes

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
X-RateLimit-Retry-After: 3600
```

### Rate Limit Exceeded Response

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 3600 seconds.",
    "details": {
      "limit": 1000,
      "remaining": 0,
      "resetTime": "2024-01-01T12:00:00Z"
    }
  }
}
```

## Error Handling

### Standard Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": {
      "field": "Additional error details"
    },
    "timestamp": "2024-01-01T12:00:00Z",
    "requestId": "req_123456789"
  }
}
```

### HTTP Status Codes

| Status Code | Description |
|-------------|-------------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid request parameters |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation errors |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |
| 503 | Service Unavailable - Service temporarily unavailable |

### Common Error Codes

| Error Code | Description |
|------------|-------------|
| `INVALID_CREDENTIALS` | Invalid username or password |
| `TOKEN_EXPIRED` | JWT token has expired |
| `INSUFFICIENT_PERMISSIONS` | User lacks required permissions |
| `TENANT_NOT_FOUND` | Specified tenant does not exist |
| `RESOURCE_NOT_FOUND` | Requested resource not found |
| `VALIDATION_ERROR` | Request validation failed |
| `RATE_LIMIT_EXCEEDED` | API rate limit exceeded |
| `DEVICE_OFFLINE` | Hardware device is offline |
| `DOOR_LOCKED` | Door cannot be unlocked |

## API Services

### Authentication Service

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | User login |
| POST | `/auth/logout` | User logout |
| POST | `/auth/refresh` | Refresh access token |
| GET | `/auth/me` | Get current user info |
| POST | `/auth/change-password` | Change user password |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password with token |

#### Get Current User

```http
GET /auth/me
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "user_123",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "role": "SECURITY_ADMIN",
    "tenantId": "tenant_123",
    "permissions": ["ACCESS_CONTROL_READ", "ACCESS_CONTROL_WRITE"],
    "lastLogin": "2024-01-01T12:00:00Z",
    "createdAt": "2024-01-01T00:00:00Z"
  }
}
```

### Tenant Service

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/tenants` | List tenants |
| POST | `/tenants` | Create tenant |
| GET | `/tenants/{id}` | Get tenant details |
| PUT | `/tenants/{id}` | Update tenant |
| DELETE | `/tenants/{id}` | Delete tenant |
| GET | `/tenants/{id}/organizations` | List organizations |
| POST | `/tenants/{id}/organizations` | Create organization |
| GET | `/organizations/{id}/sites` | List sites |
| POST | `/organizations/{id}/sites` | Create site |
| GET | `/sites/{id}/buildings` | List buildings |
| POST | `/sites/{id}/buildings` | Create building |

#### Create Tenant

```http
POST /tenants
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Acme Corporation",
  "domain": "acme.com",
  "contactEmail": "admin@acme.com",
  "plan": "ENTERPRISE",
  "settings": {
    "maxUsers": 1000,
    "maxDoors": 500,
    "maxCameras": 200,
    "retentionDays": 90
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "tenant_123",
    "name": "Acme Corporation",
    "domain": "acme.com",
    "contactEmail": "admin@acme.com",
    "plan": "ENTERPRISE",
    "status": "ACTIVE",
    "settings": {
      "maxUsers": 1000,
      "maxDoors": 500,
      "maxCameras": 200,
      "retentionDays": 90
    },
    "createdAt": "2024-01-01T12:00:00Z",
    "updatedAt": "2024-01-01T12:00:00Z"
  }
}
```

### Access Control Service

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/doors` | List doors |
| POST | `/doors` | Create door |
| GET | `/doors/{id}` | Get door details |
| PUT | `/doors/{id}` | Update door |
| DELETE | `/doors/{id}` | Delete door |
| POST | `/doors/{id}/unlock` | Unlock door |
| POST | `/doors/{id}/lock` | Lock door |
| GET | `/doors/{id}/status` | Get door status |
| GET | `/access-events` | List access events |
| POST | `/access-events` | Create access event |
| GET | `/access-groups` | List access groups |
| POST | `/access-groups` | Create access group |
| GET | `/credentials` | List credentials |
| POST | `/credentials` | Create credential |

#### List Doors

```http
GET /doors?buildingId=building_123&page=1&limit=50
Authorization: Bearer <access_token>
X-Tenant-ID: tenant_123
```

**Response:**
```json
{
  "success": true,
  "data": {
    "doors": [
      {
        "id": "door_123",
        "name": "Main Entrance",
        "description": "Building main entrance door",
        "buildingId": "building_123",
        "floorId": "floor_123",
        "zoneId": "zone_123",
        "status": "LOCKED",
        "isOnline": true,
        "lastActivity": "2024-01-01T12:00:00Z",
        "hardware": {
          "panelId": "panel_123",
          "readerId": "reader_123",
          "lockType": "MAGNETIC"
        },
        "settings": {
          "unlockDuration": 5,
          "doorAjarTimeout": 30,
          "antiPassback": true
        }
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total": 125,
      "totalPages": 3
    }
  }
}
```

#### Unlock Door

```http
POST /doors/door_123/unlock
Authorization: Bearer <access_token>
X-Tenant-ID: tenant_123
Content-Type: application/json

{
  "reason": "EMERGENCY_OVERRIDE",
  "duration": 10,
  "userId": "user_123"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "doorId": "door_123",
    "action": "UNLOCK",
    "status": "UNLOCKED",
    "duration": 10,
    "reason": "EMERGENCY_OVERRIDE",
    "userId": "user_123",
    "timestamp": "2024-01-01T12:00:00Z",
    "eventId": "event_123"
  }
}
```

#### List Access Events

```http
GET /access-events?startDate=2024-01-01&endDate=2024-01-02&doorId=door_123&page=1&limit=100
Authorization: Bearer <access_token>
X-Tenant-ID: tenant_123
```

**Response:**
```json
{
  "success": true,
  "data": {
    "events": [
      {
        "id": "event_123",
        "type": "ACCESS_GRANTED",
        "doorId": "door_123",
        "doorName": "Main Entrance",
        "userId": "user_123",
        "userName": "John Doe",
        "credentialId": "cred_123",
        "credentialType": "CARD",
        "timestamp": "2024-01-01T12:00:00Z",
        "result": "SUCCESS",
        "reason": "VALID_CREDENTIAL",
        "buildingId": "building_123",
        "floorId": "floor_123"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 100,
      "total": 1250,
      "totalPages": 13
    }
  }
}
```

### Video Management Service

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cameras` | List cameras |
| POST | `/cameras` | Create camera |
| GET | `/cameras/{id}` | Get camera details |
| PUT | `/cameras/{id}` | Update camera |
| DELETE | `/cameras/{id}` | Delete camera |
| GET | `/cameras/{id}/stream` | Get live stream URL |
| GET | `/cameras/{id}/recordings` | List recordings |
| POST | `/cameras/{id}/recordings` | Start recording |
| GET | `/recordings/{id}` | Get recording details |
| POST | `/recordings/{id}/export` | Export recording |
| GET | `/cameras/{id}/snapshot` | Get camera snapshot |

#### List Cameras

```http
GET /cameras?buildingId=building_123&status=ONLINE&page=1&limit=50
Authorization: Bearer <access_token>
X-Tenant-ID: tenant_123
```

**Response:**
```json
{
  "success": true,
  "data": {
    "cameras": [
      {
        "id": "camera_123",
        "name": "Lobby Camera 1",
        "description": "Main lobby surveillance camera",
        "buildingId": "building_123",
        "floorId": "floor_123",
        "zoneId": "zone_123",
        "status": "ONLINE",
        "type": "IP_CAMERA",
        "manufacturer": "AXIS",
        "model": "P3245-LV",
        "ipAddress": "192.168.1.100",
        "streamUrl": "rtsp://192.168.1.100/axis-media/media.amp",
        "resolution": "1920x1080",
        "fps": 30,
        "location": {
          "x": 100,
          "y": 200,
          "rotation": 45
        },
        "settings": {
          "recordingEnabled": true,
          "motionDetection": true,
          "nightVision": true,
          "audioEnabled": false
        },
        "lastSeen": "2024-01-01T12:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total": 85,
      "totalPages": 2
    }
  }
}
```

#### Get Live Stream

```http
GET /cameras/camera_123/stream?quality=high
Authorization: Bearer <access_token>
X-Tenant-ID: tenant_123
```

**Response:**
```json
{
  "success": true,
  "data": {
    "cameraId": "camera_123",
    "streamUrls": {
      "hls": "https://stream.sparc.platform/camera_123/playlist.m3u8",
      "webrtc": "wss://stream.sparc.platform/camera_123/webrtc",
      "rtsp": "rtsp://stream.sparc.platform/camera_123/stream"
    },
    "quality": "high",
    "resolution": "1920x1080",
    "fps": 30,
    "token": "stream_token_123",
    "expiresAt": "2024-01-01T13:00:00Z"
  }
}
```

### Event Processing Service

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/events` | List events |
| POST | `/events` | Create event |
| GET | `/events/{id}` | Get event details |
| PUT | `/events/{id}/acknowledge` | Acknowledge event |
| GET | `/alerts` | List alerts |
| POST | `/alerts` | Create alert |
| GET | `/alerts/{id}` | Get alert details |
| PUT | `/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/notifications` | List notifications |
| POST | `/notifications` | Send notification |

#### List Alerts

```http
GET /alerts?severity=HIGH&status=ACTIVE&page=1&limit=50
Authorization: Bearer <access_token>
X-Tenant-ID: tenant_123
```

**Response:**
```json
{
  "success": true,
  "data": {
    "alerts": [
      {
        "id": "alert_123",
        "type": "UNAUTHORIZED_ACCESS",
        "severity": "HIGH",
        "status": "ACTIVE",
        "title": "Unauthorized Access Attempt",
        "description": "Multiple failed access attempts detected at Main Entrance",
        "source": {
          "type": "DOOR",
          "id": "door_123",
          "name": "Main Entrance"
        },
        "metadata": {
          "attempts": 5,
          "lastAttempt": "2024-01-01T12:00:00Z",
          "credentialId": "cred_456"
        },
        "createdAt": "2024-01-01T12:00:00Z",
        "acknowledgedAt": null,
        "acknowledgedBy": null
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total": 23,
      "totalPages": 1
    }
  }
}
```

### Device Management Service

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/devices` | List devices |
| POST | `/devices` | Add device |
| GET | `/devices/{id}` | Get device details |
| PUT | `/devices/{id}` | Update device |
| DELETE | `/devices/{id}` | Remove device |
| POST | `/devices/discover` | Discover devices |
| GET | `/devices/{id}/status` | Get device status |
| POST | `/devices/{id}/reboot` | Reboot device |
| POST | `/devices/{id}/firmware` | Update firmware |

#### Discover Devices

```http
POST /devices/discover
Authorization: Bearer <access_token>
X-Tenant-ID: tenant_123
Content-Type: application/json

{
  "networkRange": "192.168.1.0/24",
  "deviceTypes": ["ACCESS_PANEL", "CARD_READER", "IP_CAMERA"],
  "timeout": 30
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "discoveryId": "discovery_123",
    "status": "IN_PROGRESS",
    "devicesFound": [
      {
        "ipAddress": "192.168.1.100",
        "macAddress": "00:40:8c:12:34:56",
        "deviceType": "IP_CAMERA",
        "manufacturer": "AXIS",
        "model": "P3245-LV",
        "firmwareVersion": "10.12.0",
        "protocols": ["ONVIF", "RTSP", "HTTP"]
      }
    ],
    "startedAt": "2024-01-01T12:00:00Z",
    "estimatedCompletion": "2024-01-01T12:00:30Z"
  }
}
```

## OpenAPI Specifications

### Complete OpenAPI 3.0 Specification

```yaml
openapi: 3.0.3
info:
  title: SPARC Platform API
  description: |
    Comprehensive API for the SPARC (Secure Physical Access and Real-time Control) platform.
    
    The SPARC platform provides unified physical access control and video surveillance 
    management through a modern, API-first architecture.
    
    ## Features
    - Multi-tenant architecture
    - Real-time event processing
    - Advanced access control
    - Video management and streaming
    - Mobile credential support
    - Environmental monitoring
    - Comprehensive reporting
    
    ## Authentication
    All API endpoints require JWT authentication. Include the access token in the 
    Authorization header: `Bearer <access_token>`
    
    ## Rate Limiting
    - Per User: 1000 requests/hour
    - Per Tenant: 10,000 requests/hour
    - Authentication: 10 attempts per 15 minutes
  version: 1.0.0
  contact:
    name: SPARC API Support
    email: api-support@sparc.platform
    url: https://docs.sparc.platform
  license:
    name: Proprietary
    url: https://sparc.platform/license

servers:
  - url: https://api.sparc.platform/v1
    description: Production server
  - url: https://staging-api.sparc.platform/v1
    description: Staging server
  - url: https://dev-api.sparc.platform/v1
    description: Development server

security:
  - BearerAuth: []

paths:
  /auth/login:
    post:
      tags:
        - Authentication
      summary: User login
      description: Authenticate user credentials and return JWT tokens
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'

  /auth/me:
    get:
      tags:
        - Authentication
      summary: Get current user
      description: Retrieve information about the currently authenticated user
      responses:
        '200':
          description: User information retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'

  /doors:
    get:
      tags:
        - Access Control
      summary: List doors
      description: Retrieve a list of doors with optional filtering
      parameters:
        - $ref: '#/components/parameters/TenantId'
        - name: buildingId
          in: query
          schema:
            type: string
          description: Filter by building ID
        - name: floorId
          in: query
          schema:
            type: string
          description: Filter by floor ID
        - name: status
          in: query
          schema:
            type: string
            enum: [LOCKED, UNLOCKED, UNKNOWN]
          description: Filter by door status
        - $ref: '#/components/parameters/Page'
        - $ref: '#/components/parameters/Limit'
      responses:
        '200':
          description: Doors retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DoorsResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '403':
          $ref: '#/components/responses/Forbidden'

  /doors/{doorId}/unlock:
    post:
      tags:
        - Access Control
      summary: Unlock door
      description: Unlock a specific door with optional duration and reason
      parameters:
        - name: doorId
          in: path
          required: true
          schema:
            type: string
          description: Door ID
        - $ref: '#/components/parameters/TenantId'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UnlockDoorRequest'
      responses:
        '200':
          description: Door unlocked successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DoorActionResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '403':
          $ref: '#/components/responses/Forbidden'
        '404':
          $ref: '#/components/responses/NotFound'

  /cameras:
    get:
      tags:
        - Video Management
      summary: List cameras
      description: Retrieve a list of cameras with optional filtering
      parameters:
        - $ref: '#/components/parameters/TenantId'
        - name: buildingId
          in: query
          schema:
            type: string
          description: Filter by building ID
        - name: status
          in: query
          schema:
            type: string
            enum: [ONLINE, OFFLINE, ERROR]
          description: Filter by camera status
        - $ref: '#/components/parameters/Page'
        - $ref: '#/components/parameters/Limit'
      responses:
        '200':
          description: Cameras retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CamerasResponse'

  /cameras/{cameraId}/stream:
    get:
      tags:
        - Video Management
      summary: Get live stream
      description: Get live video stream URLs for a camera
      parameters:
        - name: cameraId
          in: path
          required: true
          schema:
            type: string
          description: Camera ID
        - $ref: '#/components/parameters/TenantId'
        - name: quality
          in: query
          schema:
            type: string
            enum: [low, medium, high]
            default: medium
          description: Stream quality
      responses:
        '200':
          description: Stream URLs retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/StreamResponse'

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  parameters:
    TenantId:
      name: X-Tenant-ID
      in: header
      required: true
      schema:
        type: string
      description: Tenant identifier

    Page:
      name: page
      in: query
      schema:
        type: integer
        minimum: 1
        default: 1
      description: Page number for pagination

    Limit:
      name: limit
      in: query
      schema:
        type: integer
        minimum: 1
        maximum: 100
        default: 50
      description: Number of items per page

  schemas:
    LoginRequest:
      type: object
      required:
        - email
        - password
        - tenantId
      properties:
        email:
          type: string
          format: email
          example: user@example.com
        password:
          type: string
          format: password
          example: securePassword123
        tenantId:
          type: string
          example: tenant_123

    LoginResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          type: object
          properties:
            accessToken:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
            refreshToken:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
            expiresIn:
              type: integer
              example: 900
            user:
              $ref: '#/components/schemas/User'

    User:
      type: object
      properties:
        id:
          type: string
          example: user_123
        email:
          type: string
          format: email
          example: user@example.com
        firstName:
          type: string
          example: John
        lastName:
          type: string
          example: Doe
        role:
          type: string
          enum: [SUPER_ADMIN, TENANT_ADMIN, SECURITY_ADMIN, SECURITY_OPERATOR, USER]
          example: SECURITY_ADMIN
        tenantId:
          type: string
          example: tenant_123
        permissions:
          type: array
          items:
            type: string
          example: [ACCESS_CONTROL_READ, ACCESS_CONTROL_WRITE]
        lastLogin:
          type: string
          format: date-time
          example: 2024-01-01T12:00:00Z
        createdAt:
          type: string
          format: date-time
          example: 2024-01-01T00:00:00Z

    UserResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          $ref: '#/components/schemas/User'

    Door:
      type: object
      properties:
        id:
          type: string
          example: door_123
        name:
          type: string
          example: Main Entrance
        description:
          type: string
          example: Building main entrance door
        buildingId:
          type: string
          example: building_123
        floorId:
          type: string
          example: floor_123
        zoneId:
          type: string
          example: zone_123
        status:
          type: string
          enum: [LOCKED, UNLOCKED, UNKNOWN]
          example: LOCKED
        isOnline:
          type: boolean
          example: true
        lastActivity:
          type: string
          format: date-time
          example: 2024-01-01T12:00:00Z
        hardware:
          type: object
          properties:
            panelId:
              type: string
              example: panel_123
            readerId:
              type: string
              example: reader_123
            lockType:
              type: string
              enum: [MAGNETIC, ELECTRIC_STRIKE, MOTORIZED]
              example: MAGNETIC
        settings:
          type: object
          properties:
            unlockDuration:
              type: integer
              example: 5
            doorAjarTimeout:
              type: integer
              example: 30
            antiPassback:
              type: boolean
              example: true

    DoorsResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          type: object
          properties:
            doors:
              type: array
              items:
                $ref: '#/components/schemas/Door'
            pagination:
              $ref: '#/components/schemas/Pagination'

    UnlockDoorRequest:
      type: object
      properties:
        reason:
          type: string
          enum: [EMERGENCY_OVERRIDE, MAINTENANCE, MANUAL_UNLOCK]
          example: EMERGENCY_OVERRIDE
        duration:
          type: integer
          minimum: 1
          maximum: 300
          example: 10
        userId:
          type: string
          example: user_123

    DoorActionResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          type: object
          properties:
            doorId:
              type: string
              example: door_123
            action:
              type: string
              enum: [UNLOCK, LOCK]
              example: UNLOCK
            status:
              type: string
              enum: [LOCKED, UNLOCKED, UNKNOWN]
              example: UNLOCKED
            duration:
              type: integer
              example: 10
            reason:
              type: string
              example: EMERGENCY_OVERRIDE
            userId:
              type: string
              example: user_123
            timestamp:
              type: string
              format: date-time
              example: 2024-01-01T12:00:00Z
            eventId:
              type: string
              example: event_123

    Camera:
      type: object
      properties:
        id:
          type: string
          example: camera_123
        name:
          type: string
          example: Lobby Camera 1
        description:
          type: string
          example: Main lobby surveillance camera
        buildingId:
          type: string
          example: building_123
        floorId:
          type: string
          example: floor_123
        zoneId:
          type: string
          example: zone_123
        status:
          type: string
          enum: [ONLINE, OFFLINE, ERROR]
          example: ONLINE
        type:
          type: string
          enum: [IP_CAMERA, ANALOG_CAMERA, PTZ_CAMERA]
          example: IP_CAMERA
        manufacturer:
          type: string
          example: AXIS
        model:
          type: string
          example: P3245-LV
        ipAddress:
          type: string
          format: ipv4
          example: 192.168.1.100
        resolution:
          type: string
          example: 1920x1080
        fps:
          type: integer
          example: 30
        location:
          type: object
          properties:
            x:
              type: number
              example: 100
            y:
              type: number
              example: 200
            rotation:
              type: number
              example: 45
        settings:
          type: object
          properties:
            recordingEnabled:
              type: boolean
              example: true
            motionDetection:
              type: boolean
              example: true
            nightVision:
              type: boolean
              example: true
            audioEnabled:
              type: boolean
              example: false
        lastSeen:
          type: string
          format: date-time
          example: 2024-01-01T12:00:00Z

    CamerasResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          type: object
          properties:
            cameras:
              type: array
              items:
                $ref: '#/components/schemas/Camera'
            pagination:
              $ref: '#/components/schemas/Pagination'

    StreamResponse:
      type: object
      properties:
        success:
          type: boolean
          example: true
        data:
          type: object
          properties:
            cameraId:
              type: string
              example: camera_123
            streamUrls:
              type: object
              properties:
                hls:
                  type: string
                  format: uri
                  example: https://stream.sparc.platform/camera_123/playlist.m3u8
                webrtc:
                  type: string
                  format: uri
                  example: wss://stream.sparc.platform/camera_123/webrtc
                rtsp:
                  type: string
                  format: uri
                  example: rtsp://stream.sparc.platform/camera_123/stream
            quality:
              type: string
              enum: [low, medium, high]
              example: high
            resolution:
              type: string
              example: 1920x1080
            fps:
              type: integer
              example: 30
            token:
              type: string
              example: stream_token_123
            expiresAt:
              type: string
              format: date-time
              example: 2024-01-01T13:00:00Z

    Pagination:
      type: object
      properties:
        page:
          type: integer
          example: 1
        limit:
          type: integer
          example: 50
        total:
          type: integer
          example: 125
        totalPages:
          type: integer
          example: 3

    Error:
      type: object
      properties:
        success:
          type: boolean
          example: false
        error:
          type: object
          properties:
            code:
              type: string
              example: VALIDATION_ERROR
            message:
              type: string
              example: Request validation failed
            details:
              type: object
              additionalProperties: true
            timestamp:
              type: string
              format: date-time
              example: 2024-01-01T12:00:00Z
            requestId:
              type: string
              example: req_123456789

  responses:
    BadRequest:
      description: Bad request - Invalid parameters
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    Unauthorized:
      description: Unauthorized - Authentication required
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    Forbidden:
      description: Forbidden - Insufficient permissions
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    NotFound:
      description: Not found - Resource does not exist
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    RateLimitExceeded:
      description: Rate limit exceeded
      headers:
        X-RateLimit-Limit:
          schema:
            type: integer
          description: Request limit per hour
        X-RateLimit-Remaining:
          schema:
            type: integer
          description: Remaining requests in current window
        X-RateLimit-Reset:
          schema:
            type: integer
          description: Time when rate limit resets (Unix timestamp)
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
```

## Integration Examples

### JavaScript/TypeScript SDK

```typescript
import { SparcClient } from '@sparc/sdk';

// Initialize client
const client = new SparcClient({
  baseUrl: 'https://api.sparc.platform/v1',
  apiKey: 'your-api-key'
});

// Authenticate
const auth = await client.auth.login({
  email: 'user@example.com',
  password: 'password',
  tenantId: 'tenant_123'
});

// Set authentication token
client.setToken(auth.data.accessToken);

// List doors
const doors = await client.accessControl.listDoors({
  buildingId: 'building_123',
  page: 1,
  limit: 50
});

// Unlock door
const result = await client.accessControl.unlockDoor('door_123', {
  reason: 'EMERGENCY_OVERRIDE',
  duration: 10,
  userId: 'user_123'
});

// Get live camera stream
const stream = await client.video.getLiveStream('camera_123', {
  quality: 'high'
});

// Listen to real-time events
client.events.subscribe('access-events', (event) => {
  console.log('Access event:', event);
});
```

### Python SDK

```python
from sparc_sdk import SparcClient

# Initialize client
client = SparcClient(
    base_url='https://api.sparc.platform/v1',
    api_key='your-api-key'
)

# Authenticate
auth = client.auth.login(
    email='user@example.com',
    password='password',
    tenant_id='tenant_123'
)

# Set authentication token
client.set_token(auth['data']['accessToken'])

# List doors
doors = client.access_control.list_doors(
    building_id='building_123',
    page=1,
    limit=50
)

# Unlock door
result = client.access_control.unlock_door(
    door_id='door_123',
    reason='EMERGENCY_OVERRIDE',
    duration=10,
    user_id='user_123'
)

# Get cameras
cameras = client.video.list_cameras(
    building_id='building_123',
    status='ONLINE'
)
```

### cURL Examples

#### Authentication

```bash
# Login
curl -X POST https://api.sparc.platform/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password",
    "tenantId": "tenant_123"
  }'

# Get current user
curl -X GET https://api.sparc.platform/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
```

#### Access Control

```bash
# List doors
curl -X GET "https://api.sparc.platform/v1/doors?buildingId=building_123" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: tenant_123"

# Unlock door
curl -X POST https://api.sparc.platform/v1/doors/door_123/unlock \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: tenant_123" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "EMERGENCY_OVERRIDE",
    "duration": 10,
    "userId": "user_123"
  }'
```

#### Video Management

```bash
# List cameras
curl -X GET "https://api.sparc.platform/v1/cameras?status=ONLINE" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: tenant_123"

# Get live stream
curl -X GET "https://api.sparc.platform/v1/cameras/camera_123/stream?quality=high" \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: tenant_123"
```

### Webhook Integration

The SPARC platform supports webhooks for real-time event notifications:

```json
{
  "webhookId": "webhook_123",
  "eventType": "access.granted",
  "timestamp": "2024-01-01T12:00:00Z",
  "tenantId": "tenant_123",
  "data": {
    "eventId": "event_123",
    "doorId": "door_123",
    "doorName": "Main Entrance",
    "userId": "user_123",
    "userName": "John Doe",
    "credentialType": "CARD",
    "result": "SUCCESS"
  }
}
```

#### Webhook Configuration

```bash
# Create webhook
curl -X POST https://api.sparc.platform/v1/webhooks \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Tenant-ID: tenant_123" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/webhooks/sparc",
    "events": ["access.granted", "access.denied", "alert.created"],
    "secret": "your-webhook-secret"
  }'
```

## SDKs and Libraries

### Official SDKs

- **JavaScript/TypeScript**: `@sparc/sdk`
- **Python**: `sparc-sdk`
- **C#**: `Sparc.SDK`
- **Java**: `com.sparc.sdk`
- **Go**: `github.com/sparc/go-sdk`

### Installation

```bash
# JavaScript/TypeScript
npm install @sparc/sdk

# Python
pip install sparc-sdk

# C#
dotnet add package Sparc.SDK

# Java
<dependency>
  <groupId>com.sparc</groupId>
  <artifactId>sparc-sdk</artifactId>
  <version>1.0.0</version>
</dependency>

# Go
go get github.com/sparc/go-sdk
```

### Community Libraries

- **PHP**: `sparc/php-client`
- **Ruby**: `sparc-ruby`
- **Rust**: `sparc-rs`

## Support and Resources

### Documentation

- **API Reference**: https://docs.sparc.platform/api
- **Developer Guide**: https://docs.sparc.platform/developers
- **Integration Examples**: https://docs.sparc.platform/examples
- **SDK Documentation**: https://docs.sparc.platform/sdks

### Support Channels

- **Email**: api-support@sparc.platform
- **Developer Forum**: https://community.sparc.platform
- **GitHub Issues**: https://github.com/sparc-platform/issues
- **Status Page**: https://status.sparc.platform

### Rate Limits and Quotas

| Plan | Requests/Hour | Concurrent Streams | Storage |
|------|---------------|-------------------|---------|
| Starter | 1,000 | 10 | 100 GB |
| Professional | 10,000 | 50 | 1 TB |
| Enterprise | 100,000 | 200 | 10 TB |
| Custom | Unlimited | Unlimited | Unlimited |

### API Versioning

The SPARC API uses semantic versioning:

- **Major versions** (v1, v2): Breaking changes
- **Minor versions** (v1.1, v1.2): New features, backward compatible
- **Patch versions** (v1.1.1, v1.1.2): Bug fixes, backward compatible

Current version: **v1.0.0**

### Changelog

#### v1.0.0 (2024-01-01)
- Initial release
- Complete access control API
- Video management API
- Event processing API
- Device management API
- Multi-tenant support
- Real-time streaming
- Mobile credential support

---

*This documentation is automatically generated from the OpenAPI specification. For the most up-to-date information, please refer to the interactive API documentation at https://docs.sparc.platform/api*