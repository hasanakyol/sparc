# SPARC API Versioning Strategy

## Overview

This document outlines the API versioning strategy for the SPARC Security Platform. Our versioning approach ensures backward compatibility, smooth migrations, and clear communication of changes to API consumers.

## Versioning Principles

### 1. Semantic Versioning

We follow semantic versioning (SemVer) principles for our API:

- **Major Version (v1, v2)**: Breaking changes that require client updates
- **Minor Version (1.x)**: New features, backward compatible
- **Patch Version (1.x.x)**: Bug fixes, backward compatible

### 2. URL-Based Versioning

The API version is included in the URL path:

```
https://api.sparc.security/v1/...
https://api.sparc.security/v2/...
```

### 3. Version Lifecycle

| Stage | Duration | Description |
|-------|----------|-------------|
| **Preview** | 3-6 months | New version available for testing |
| **Current** | 18-24 months | Recommended version for production |
| **Deprecated** | 12 months | Still supported but migration recommended |
| **Sunset** | N/A | No longer available |

## Breaking vs Non-Breaking Changes

### Non-Breaking Changes (No Version Bump)

- Adding new endpoints
- Adding new optional request parameters
- Adding new fields to responses
- Adding new values to enums (with caution)
- Adding new error codes
- Performance improvements
- Bug fixes

### Breaking Changes (Require New Version)

- Removing or renaming endpoints
- Removing or renaming fields
- Changing field types
- Changing authentication methods
- Modifying validation rules
- Changing error response formats
- Removing enum values
- Changing default behaviors

## Implementation Guidelines

### 1. Response Evolution

When adding new fields to responses:

```json
// v1 Response
{
  "id": "123",
  "name": "Main Entrance",
  "status": "online"
}

// v1 Response (with addition - non-breaking)
{
  "id": "123",
  "name": "Main Entrance",
  "status": "online",
  "lastSeen": "2024-01-18T10:00:00Z"  // New optional field
}
```

### 2. Request Parameter Evolution

Adding optional parameters:

```bash
# v1 - Original
GET /api/v1/cameras?siteId=123

# v1 - With new optional parameter (non-breaking)
GET /api/v1/cameras?siteId=123&status=online
```

### 3. Deprecation Headers

When deprecating features, include headers:

```
X-API-Deprecation-Date: 2024-12-31
X-API-Deprecation-Info: https://docs.sparc.security/deprecations/camera-type
X-API-Sunset-Date: 2025-06-30
```

### 4. Version Selection

Clients can request specific API versions:

```bash
# URL versioning (recommended)
GET https://api.sparc.security/v1/cameras

# Header versioning (alternative)
GET https://api.sparc.security/cameras
Accept: application/vnd.sparc.v1+json
```

## Migration Strategy

### 1. Announcement Timeline

- **T-6 months**: Announce new version in preview
- **T-3 months**: New version becomes current
- **T-0**: Previous version marked deprecated
- **T+12 months**: Previous version sunset

### 2. Migration Guides

For each major version, provide:

1. **Breaking Changes List**
   ```markdown
   ## Breaking Changes in v2
   
   ### Authentication
   - Changed from API keys to OAuth 2.0
   - Removed basic authentication support
   
   ### Endpoints
   - `/cameras` → `/video/cameras`
   - Removed `/legacy/*` endpoints
   
   ### Response Format
   - Standardized error responses
   - Changed timestamp format to ISO 8601
   ```

2. **Migration Examples**
   ```javascript
   // v1 Code
   const response = await api.get('/v1/cameras');
   const cameras = response.data;
   
   // v2 Code
   const response = await api.get('/v2/video/cameras');
   const cameras = response.data.cameras; // Note: nested under 'cameras'
   ```

3. **Automated Migration Tools**
   ```bash
   # Use our migration CLI tool
   sparc-api-migrate --from v1 --to v2 --dry-run
   sparc-api-migrate --from v1 --to v2 --apply
   ```

### 3. Parallel Running

Support running multiple versions simultaneously:

```javascript
class SparcClient {
  constructor(config) {
    this.v1 = new SparcV1Client(config);
    this.v2 = new SparcV2Client(config);
    this.currentVersion = config.apiVersion || 'v2';
  }

  // Gradual migration approach
  async getCameras() {
    if (this.currentVersion === 'v2') {
      return this.v2.video.getCameras();
    }
    return this.v1.getCameras();
  }
}
```

## Feature Flags

Use feature flags for gradual rollout:

```json
{
  "features": {
    "newVideoAPI": {
      "enabled": true,
      "percentage": 50,  // 50% of requests use new API
      "allowList": ["customer-123", "customer-456"]
    }
  }
}
```

## Version Discovery

### 1. Version Endpoint

```bash
GET https://api.sparc.security/versions
```

Response:
```json
{
  "versions": [
    {
      "version": "v1",
      "status": "deprecated",
      "deprecationDate": "2024-01-01",
      "sunsetDate": "2025-01-01",
      "endpoints": "https://api.sparc.security/v1"
    },
    {
      "version": "v2",
      "status": "current",
      "releaseDate": "2024-01-01",
      "endpoints": "https://api.sparc.security/v2"
    },
    {
      "version": "v3",
      "status": "preview",
      "releaseDate": "2024-06-01",
      "endpoints": "https://api.sparc.security/v3"
    }
  ],
  "recommended": "v2"
}
```

### 2. Root API Response

```bash
GET https://api.sparc.security/
```

Response:
```json
{
  "name": "SPARC Security API",
  "versions": {
    "v1": {
      "status": "deprecated",
      "links": {
        "self": "https://api.sparc.security/v1",
        "docs": "https://docs.sparc.security/api/v1"
      }
    },
    "v2": {
      "status": "current",
      "links": {
        "self": "https://api.sparc.security/v2",
        "docs": "https://docs.sparc.security/api/v2"
      }
    }
  }
}
```

## SDK Versioning

### 1. SDK Version Mapping

| API Version | SDK Version | Support Status |
|-------------|-------------|----------------|
| v1 | 1.x.x | Security fixes only |
| v2 | 2.x.x | Active development |
| v3-preview | 3.0.0-beta.x | Preview |

### 2. Multi-Version Support

SDKs should support multiple API versions:

```javascript
// JavaScript SDK
const sparc = new SparcSDK({
  apiKey: 'your-key',
  apiVersion: 'v2'  // Optional, defaults to latest stable
});

// Force specific version for certain calls
const legacyData = await sparc.v1.cameras.list();
const currentData = await sparc.v2.video.cameras.list();
```

## Communication Strategy

### 1. Deprecation Notices

- Email notifications to all API users
- Dashboard notifications in developer portal
- API response headers
- SDK console warnings
- Documentation banners

### 2. Changelog

Maintain detailed changelog:

```markdown
# API Changelog

## v2.3.0 (2024-01-18)
### Added
- New endpoint: GET /video/cameras/{id}/analytics
- New field: Camera.metadata.firmwareVersion

### Changed
- Increased rate limit for Premium tier to 10,000/min

### Deprecated
- Field: Camera.legacy_id (use Camera.id instead)

### Fixed
- Fixed timezone handling in event timestamps
```

### 3. Developer Portal

Provide version-specific documentation:

- Interactive API explorer for each version
- Migration guides and tools
- Version comparison tools
- Deprecation timeline
- Breaking change analyzer

## Testing Strategy

### 1. Version Compatibility Testing

```javascript
describe('API Version Compatibility', () => {
  it('should handle v1 response format', async () => {
    const v1Response = await apiV1.get('/cameras');
    expect(v1Response.data).toBeInstanceOf(Array);
  });

  it('should handle v2 response format', async () => {
    const v2Response = await apiV2.get('/video/cameras');
    expect(v2Response.data).toHaveProperty('cameras');
    expect(v2Response.data.cameras).toBeInstanceOf(Array);
  });
});
```

### 2. Contract Testing

Use contract testing to ensure version compatibility:

```yaml
# pact/v1-v2-compatibility.yaml
consumer: ClientApp
provider: SparcAPI
interactions:
  - description: "v1 camera list maintains compatibility"
    request:
      method: GET
      path: /v1/cameras
    response:
      status: 200
      body:
        - id: string
          name: string
          status: string
```

## Monitoring and Analytics

### 1. Version Usage Metrics

Track API version adoption:

```json
{
  "metrics": {
    "api_version_usage": {
      "v1": {
        "requests_per_day": 50000,
        "unique_clients": 123,
        "percentage": 20
      },
      "v2": {
        "requests_per_day": 200000,
        "unique_clients": 456,
        "percentage": 80
      }
    }
  }
}
```

### 2. Migration Progress Dashboard

Monitor client migration status:

- Clients still on deprecated versions
- Migration velocity
- Feature adoption rates
- Breaking change impact analysis

## Best Practices for API Consumers

1. **Always specify version explicitly**
   ```javascript
   const API_BASE = 'https://api.sparc.security/v2';
   ```

2. **Handle version-specific responses**
   ```javascript
   function normalizeResponse(response, version) {
     if (version === 'v1') {
       return { cameras: response.data };
     }
     return response.data;
   }
   ```

3. **Implement graceful degradation**
   ```javascript
   try {
     // Try new version first
     return await apiV2.video.getAnalytics();
   } catch (error) {
     if (error.status === 404) {
       // Fall back to v1 if endpoint doesn't exist
       return await apiV1.getBasicStats();
     }
     throw error;
   }
   ```

4. **Monitor deprecation warnings**
   ```javascript
   api.interceptors.response.use(response => {
     if (response.headers['x-api-deprecation-date']) {
       console.warn('API deprecation warning:', {
         endpoint: response.config.url,
         deprecationDate: response.headers['x-api-deprecation-date'],
         info: response.headers['x-api-deprecation-info']
       });
     }
     return response;
   });
   ```

## Future Considerations

### 1. GraphQL Migration

Consider GraphQL for v3+ to provide:
- Client-specified queries
- Reduced over-fetching
- Strong typing
- Built-in versioning through schema evolution

### 2. API Gateway Features

Leverage API gateway for:
- Automatic version routing
- Response transformation
- Legacy adapter patterns
- A/B testing new versions

### 3. Microservice Versioning

Coordinate versions across microservices:
- Service mesh for version routing
- Canary deployments
- Blue-green deployments
- Feature flag integration

## Conclusion

Our API versioning strategy prioritizes:
1. **Stability**: Long support windows for each version
2. **Clarity**: Clear communication of changes
3. **Compatibility**: Backward compatibility when possible
4. **Migration**: Smooth transition paths between versions

By following these guidelines, we ensure that API consumers can rely on SPARC's API for their critical security operations while still allowing the platform to evolve and improve.