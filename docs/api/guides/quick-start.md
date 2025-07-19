# SPARC API Quick Start Guide

Welcome to the SPARC Security Platform API! This guide will help you get started with the SPARC API in just a few minutes.

## Overview

The SPARC API is a RESTful API that provides programmatic access to all features of the SPARC security platform. The API follows REST conventions and returns JSON responses.

## Base URL

```
Production: https://api.sparc.security/v1
Staging: https://staging-api.sparc.security/v1
Local: http://localhost:3000/v1
```

## Authentication

SPARC uses JWT (JSON Web Tokens) for authentication. You'll need to obtain an access token before making API requests.

### Step 1: Get Your Credentials

First, you'll need:
- Your email address
- Your password
- Your organization ID (provided during setup)

### Step 2: Obtain an Access Token

```bash
curl -X POST https://api.sparc.security/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your-email@example.com",
    "password": "your-password"
  }'
```

Response:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "your-email@example.com",
    "organizationId": "123e4567-e89b-12d3-a456-426614174001",
    "role": "admin"
  }
}
```

### Step 3: Use the Access Token

Include the access token in the Authorization header for all subsequent requests:

```bash
curl https://api.sparc.security/v1/api/video/cameras \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Tenant-ID: 123e4567-e89b-12d3-a456-426614174001"
```

## Required Headers

Most API endpoints require these headers:

| Header | Description | Example |
|--------|-------------|---------|
| `Authorization` | Bearer token for authentication | `Bearer eyJhbGc...` |
| `X-Tenant-ID` | Your organization ID | `123e4567-e89b-12d3-a456-426614174001` |
| `Content-Type` | For POST/PUT requests | `application/json` |

## Your First API Call

Let's list all cameras in your organization:

```bash
curl https://api.sparc.security/v1/api/video/cameras \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

Response:
```json
{
  "cameras": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174002",
      "name": "Main Entrance",
      "status": "online",
      "type": "fixed",
      "siteId": "123e4567-e89b-12d3-a456-426614174003",
      "connectionUrl": "rtsp://camera1.local:554/stream"
    }
  ],
  "pagination": {
    "page": 1,
    "pageSize": 20,
    "totalItems": 1,
    "totalPages": 1
  }
}
```

## Common Operations

### 1. List Sites

Get all sites in your organization:

```bash
curl https://api.sparc.security/v1/api/tenant/sites \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

### 2. Get Live Video Stream

Get a live stream URL for a camera:

```bash
curl https://api.sparc.security/v1/api/video/streams/CAMERA_ID/live?protocol=hls \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

### 3. List Recent Access Events

Get recent access control events:

```bash
curl "https://api.sparc.security/v1/api/access/events?startTime=2024-01-18T00:00:00Z&endTime=2024-01-18T23:59:59Z" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

### 4. Create an Alert

Create a new security alert:

```bash
curl -X POST https://api.sparc.security/v1/api/alert/alerts \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "security",
    "severity": "high",
    "title": "Unauthorized Access Attempt",
    "description": "Multiple failed access attempts at North Gate",
    "siteId": "123e4567-e89b-12d3-a456-426614174003",
    "source": {
      "type": "access_control",
      "id": "123e4567-e89b-12d3-a456-426614174004"
    }
  }'
```

### 5. Get Analytics Dashboard

Retrieve real-time analytics data:

```bash
curl https://api.sparc.security/v1/api/analytics/dashboards/DASHBOARD_ID \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

## Error Handling

The API returns standard HTTP status codes and error responses:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The request body is invalid",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    }
  }
}
```

Common status codes:
- `200 OK` - Request succeeded
- `201 Created` - Resource created
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

## Rate Limiting

API rate limits depend on your subscription tier:
- **Starter**: 1,000 requests/minute
- **Professional**: 5,000 requests/minute
- **Enterprise**: 10,000 requests/minute

Rate limit headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1642521600
```

## Pagination

List endpoints support pagination:

```bash
curl "https://api.sparc.security/v1/api/video/cameras?page=2&pageSize=50" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

Pagination response:
```json
{
  "data": [...],
  "pagination": {
    "page": 2,
    "pageSize": 50,
    "totalItems": 125,
    "totalPages": 3
  }
}
```

## WebSocket Connection

For real-time updates, connect to our WebSocket endpoint:

```javascript
const ws = new WebSocket('wss://api.sparc.security/v1/ws?token=YOUR_ACCESS_TOKEN');

ws.onopen = () => {
  // Subscribe to alerts
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'alerts',
    filters: {
      severity: ['high', 'critical'],
      siteId: 'YOUR_SITE_ID'
    }
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
```

## SDK Examples

### JavaScript/Node.js

```javascript
const SparcAPI = require('@sparc/sdk');

const client = new SparcAPI({
  apiKey: 'YOUR_API_KEY',
  organizationId: 'YOUR_ORGANIZATION_ID'
});

// List cameras
const cameras = await client.video.listCameras();

// Get live stream
const stream = await client.video.getLiveStream(cameraId, {
  protocol: 'hls',
  quality: 'high'
});

// Subscribe to events
client.events.on('alert', (alert) => {
  console.log('New alert:', alert);
});
```

### Python

```python
from sparc import SparcClient

client = SparcClient(
    api_key='YOUR_API_KEY',
    organization_id='YOUR_ORGANIZATION_ID'
)

# List cameras
cameras = client.video.list_cameras()

# Get live stream
stream = client.video.get_live_stream(
    camera_id=camera_id,
    protocol='hls',
    quality='high'
)

# Subscribe to events
@client.events.on('alert')
def handle_alert(alert):
    print(f'New alert: {alert}')
```

## Best Practices

1. **Token Management**
   - Store tokens securely
   - Refresh tokens before expiration
   - Don't hardcode credentials

2. **Error Handling**
   - Implement retry logic for transient errors
   - Log errors for debugging
   - Handle rate limit responses gracefully

3. **Performance**
   - Use pagination for large datasets
   - Cache responses when appropriate
   - Batch operations when possible

4. **Security**
   - Always use HTTPS
   - Validate SSL certificates
   - Keep your API keys confidential
   - Use IP allowlisting if available

## Next Steps

- [Authentication Guide](./authentication.md) - Deep dive into authentication
- [API Reference](../openapi/) - Complete API documentation
- [WebSocket Guide](./websocket.md) - Real-time communication
- [Common Use Cases](./use-cases.md) - Example implementations
- [SDKs](./sdks.md) - Language-specific libraries

## Support

Need help? Contact us:
- Email: api-support@sparc.security
- Documentation: https://docs.sparc.security
- Status Page: https://status.sparc.security