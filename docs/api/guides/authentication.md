# SPARC API Authentication Guide

This guide provides comprehensive information about authentication in the SPARC API, including JWT tokens, refresh tokens, MFA, and security best practices.

## Table of Contents

1. [Overview](#overview)
2. [Authentication Flow](#authentication-flow)
3. [Token Management](#token-management)
4. [Multi-Factor Authentication](#multi-factor-authentication)
5. [API Keys](#api-keys)
6. [SSO Integration](#sso-integration)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

## Overview

SPARC uses a JWT-based authentication system with the following features:

- **Dual-token system**: Short-lived access tokens and long-lived refresh tokens
- **Multi-factor authentication (MFA)**: Optional TOTP-based 2FA
- **Session management**: Track and revoke active sessions
- **API keys**: For service-to-service authentication
- **SSO support**: SAML, OAuth, and OpenID Connect

## Authentication Flow

### 1. Initial Login

```mermaid
sequenceDiagram
    Client->>API: POST /auth/login
    API->>API: Validate credentials
    API->>API: Check MFA requirement
    alt MFA Required
        API-->>Client: 202 MFA Required + Session ID
        Client->>API: POST /auth/mfa/verify
        API->>API: Validate TOTP code
    end
    API-->>Client: 200 OK + Tokens
```

#### Login Request

```bash
curl -X POST https://api.sparc.security/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure-password",
    "rememberMe": true
  }'
```

#### Login Response (Success)

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900,
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "role": "admin",
    "organizationId": "123e4567-e89b-12d3-a456-426614174001",
    "mfaEnabled": false
  }
}
```

The response also sets an HTTP-only cookie with the refresh token:
```
Set-Cookie: refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800
```

### 2. Using Access Tokens

Include the access token in the Authorization header:

```bash
curl https://api.sparc.security/v1/api/video/cameras \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Tenant-ID: 123e4567-e89b-12d3-a456-426614174001"
```

### 3. Token Structure

Access tokens contain the following claims:

```json
{
  "sub": "123e4567-e89b-12d3-a456-426614174000",  // User ID
  "email": "user@example.com",
  "organizationId": "123e4567-e89b-12d3-a456-426614174001",
  "role": "admin",
  "permissions": ["video.view", "video.manage", "access.view"],
  "iat": 1705589400,  // Issued at
  "exp": 1705590300,  // Expires at (15 minutes)
  "iss": "sparc-auth",
  "aud": "sparc-api"
}
```

## Token Management

### Refresh Token Flow

When your access token expires, use the refresh token to obtain a new one:

```bash
curl -X POST https://api.sparc.security/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -H "Cookie: refreshToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{}'
```

Or if passing in the body:

```bash
curl -X POST https://api.sparc.security/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

Response:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 900
}
```

### Token Lifecycle

| Token Type | Default Lifetime | Configurable | Storage |
|------------|-----------------|--------------|----------|
| Access Token | 15 minutes | No | Memory/Local Storage |
| Refresh Token | 7 days | Yes (rememberMe: 30 days) | HTTP-only Cookie |

### Automatic Token Refresh

Example implementation with axios interceptors:

```javascript
import axios from 'axios';

const api = axios.create({
  baseURL: 'https://api.sparc.security/v1',
  withCredentials: true  // Include cookies
});

// Request interceptor to add token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    config.headers['X-Tenant-ID'] = localStorage.getItem('organizationId');
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const response = await api.post('/auth/refresh');
        localStorage.setItem('accessToken', response.data.accessToken);
        originalRequest.headers.Authorization = `Bearer ${response.data.accessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed, redirect to login
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);
```

## Multi-Factor Authentication

### Enabling MFA

1. Request MFA setup:

```bash
curl -X POST https://api.sparc.security/v1/auth/mfa/enable \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Response:
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qrCode": "data:image/png;base64,iVBORw0KGgoAAAANS...",
  "backupCodes": [
    "a1b2c3d4e5",
    "f6g7h8i9j0",
    "k1l2m3n4o5",
    "p6q7r8s9t0",
    "u1v2w3x4y5"
  ]
}
```

2. Confirm MFA setup:

```bash
curl -X POST https://api.sparc.security/v1/auth/mfa/confirm \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456"
  }'
```

### MFA Login Flow

When MFA is enabled, login returns a session ID:

```json
{
  "sessionId": "mfa_session_123",
  "message": "MFA verification required"
}
```

Complete authentication with MFA code:

```bash
curl -X POST https://api.sparc.security/v1/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "mfa_session_123",
    "code": "123456"
  }'
```

## API Keys

API keys are used for service-to-service authentication and automation.

### Creating an API Key

```bash
curl -X POST https://api.sparc.security/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Pipeline",
    "permissions": ["video.view", "analytics.view"],
    "expiresAt": "2024-12-31T23:59:59Z"
  }'
```

Response:
```json
{
  "id": "key_123",
  "key": "sk_live_abcdef123456...",  // Only shown once!
  "name": "CI/CD Pipeline",
  "permissions": ["video.view", "analytics.view"],
  "createdAt": "2024-01-18T10:00:00Z",
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

### Using API Keys

Include the API key in the Authorization header:

```bash
curl https://api.sparc.security/v1/api/video/cameras \
  -H "Authorization: ApiKey sk_live_abcdef123456..." \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

## SSO Integration

SPARC supports SSO through SAML 2.0, OAuth 2.0, and OpenID Connect.

### SAML Configuration

1. Get SAML metadata:

```bash
curl https://api.sparc.security/v1/auth/sso/saml/metadata \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID"
```

2. Configure IdP settings:

```bash
curl -X PUT https://api.sparc.security/v1/auth/sso/saml/config \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "idpMetadataUrl": "https://idp.example.com/metadata",
    "idpEntityId": "https://idp.example.com",
    "attributeMapping": {
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "firstName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
      "lastName": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    }
  }'
```

### SSO Login Flow

Redirect users to:
```
https://api.sparc.security/v1/auth/sso/login?provider=saml&redirect_uri=https://app.sparc.security/dashboard
```

After successful SSO authentication, users are redirected back with tokens.

## Security Best Practices

### 1. Token Storage

**DO:**
- Store access tokens in memory or sessionStorage
- Use HTTP-only cookies for refresh tokens
- Clear tokens on logout

**DON'T:**
- Store tokens in localStorage (XSS vulnerable)
- Include tokens in URLs
- Log tokens

### 2. Token Rotation

Implement token rotation for enhanced security:

```javascript
class TokenManager {
  constructor() {
    this.accessToken = null;
    this.refreshTimer = null;
  }

  setAccessToken(token, expiresIn) {
    this.accessToken = token;
    
    // Refresh 1 minute before expiration
    const refreshIn = (expiresIn - 60) * 1000;
    
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    
    this.refreshTimer = setTimeout(() => {
      this.refreshAccessToken();
    }, refreshIn);
  }

  async refreshAccessToken() {
    try {
      const response = await fetch('/auth/refresh', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        this.setAccessToken(data.accessToken, data.expiresIn);
      }
    } catch (error) {
      console.error('Token refresh failed:', error);
    }
  }

  getAccessToken() {
    return this.accessToken;
  }

  clear() {
    this.accessToken = null;
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }
}
```

### 3. Session Management

List active sessions:

```bash
curl https://api.sparc.security/v1/auth/sessions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Revoke a session:

```bash
curl -X DELETE https://api.sparc.security/v1/auth/sessions/SESSION_ID \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. IP Allowlisting

Configure allowed IP ranges for your organization:

```bash
curl -X PUT https://api.sparc.security/v1/tenant/settings \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "security": {
      "allowedIpRanges": [
        "192.168.1.0/24",
        "10.0.0.0/8"
      ]
    }
  }'
```

### 5. Password Policy

Enforce strong password policies:

```json
{
  "security": {
    "passwordPolicy": {
      "minLength": 12,
      "requireUppercase": true,
      "requireLowercase": true,
      "requireNumbers": true,
      "requireSpecialChars": true,
      "expirationDays": 90,
      "historyCount": 5
    }
  }
}
```

## Troubleshooting

### Common Authentication Errors

#### 1. Invalid Credentials (401)

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password"
  }
}
```

**Solutions:**
- Verify email and password
- Check if account is locked
- Ensure correct environment (production vs staging)

#### 2. Token Expired (401)

```json
{
  "error": {
    "code": "TOKEN_EXPIRED",
    "message": "Access token has expired"
  }
}
```

**Solutions:**
- Use refresh token to get new access token
- Implement automatic token refresh
- Check token expiration before requests

#### 3. Invalid Token (401)

```json
{
  "error": {
    "code": "INVALID_TOKEN",
    "message": "Token signature verification failed"
  }
}
```

**Solutions:**
- Ensure token hasn't been modified
- Verify using correct environment
- Check for token truncation

#### 4. Account Locked (423)

```json
{
  "error": {
    "code": "ACCOUNT_LOCKED",
    "message": "Account locked due to too many failed attempts",
    "details": {
      "locked_until": "2024-01-18T11:30:00Z"
    }
  }
}
```

**Solutions:**
- Wait for lockout period to expire
- Contact administrator to unlock
- Use password reset if available

#### 5. MFA Required (202)

```json
{
  "sessionId": "mfa_session_123",
  "message": "MFA verification required"
}
```

**Solutions:**
- Complete MFA verification
- Use backup codes if device unavailable
- Contact support if MFA device lost

### Debug Headers

Include these headers for troubleshooting:

```bash
curl https://api.sparc.security/v1/api/video/cameras \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Tenant-ID: YOUR_ORGANIZATION_ID" \
  -H "X-Request-ID: unique-request-id" \
  -H "X-Debug: true"
```

Debug response headers:
```
X-Request-ID: unique-request-id
X-Auth-User-ID: 123e4567-e89b-12d3-a456-426614174000
X-Auth-Organization-ID: 123e4567-e89b-12d3-a456-426614174001
X-Token-Expires-At: 2024-01-18T11:00:00Z
```

## Next Steps

- [API Reference](../openapi/) - Complete API documentation
- [Security Best Practices](./security.md) - Additional security guidelines
- [Rate Limiting](./rate-limiting.md) - Understanding rate limits
- [WebSocket Authentication](./websocket.md) - Real-time connection auth