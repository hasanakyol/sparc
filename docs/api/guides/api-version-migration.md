# API Version Migration Guide

## Overview

This guide helps you migrate your SPARC API integration from older versions to newer ones. Follow the steps below for a smooth transition.

## Migration Paths

### From v1.0 to v1.1 (Non-breaking)

Version 1.1 adds new optional fields and features while maintaining full backward compatibility.

#### What's New
- Added `location` field to incidents
- Added `affected_assets` array to incidents  
- Added pagination metadata to list responses
- New `Accept-Version` header support

#### Migration Steps
1. **No immediate changes required** - v1.0 requests continue to work
2. **Optional**: Update to use new fields in responses
3. **Optional**: Add `Accept-Version: 1.1` header for explicit version selection

#### Code Example
```javascript
// v1.0 (still works)
const response = await fetch('/v1/incidents', {
  headers: {
    'Authorization': 'Bearer YOUR_TOKEN'
  }
});

// v1.1 (with new features)
const response = await fetch('/v1/incidents', {
  headers: {
    'Authorization': 'Bearer YOUR_TOKEN',
    'Accept-Version': '1.1'
  }
});

// Response includes new fields
{
  "incidents": [{
    "incident_id": "...",
    "location": "Building A - Floor 2",     // New
    "affected_assets": ["camera-001"],      // New
    // ... other fields
  }],
  "page": 1,      // New
  "limit": 20     // New
}
```

### From v1.x to v2.0 (Breaking Changes)

Version 2.0 introduces significant improvements but requires code changes.

#### Major Changes

1. **Field Naming Convention**
   - Snake_case → camelCase
   - `incident_id` → `id`
   - `created_at` → `createdAt`
   - `created_by` → `createdBy`

2. **Response Structure**
   - Responses wrapped in `data` field
   - Consistent pagination format
   - Added `_links` for HATEOAS

3. **Status Values**
   - Added new status: `investigating`, `mitigating`
   - Priority values: `low/medium/high/critical` → `P1/P2/P3/P4`

4. **New Required Fields**
   - `title` field for incidents
   - `severity` field separate from priority

#### Migration Steps

##### Step 1: Update Base URL
```javascript
// Old
const API_BASE = 'https://api.sparc.io/v1';

// New
const API_BASE = 'https://api.sparc.io/v2';
```

##### Step 2: Update Request Payloads
```javascript
// v1.x
const incident = {
  incident_type: 'security',
  priority: 'high',
  description: 'Unauthorized access',
  created_by: 'user123'
};

// v2.0
const incident = {
  category: 'security',        // renamed
  priority: 'P2',             // new format
  severity: 'high',           // new field
  title: 'Unauthorized Access', // new required
  description: 'Unauthorized access attempt detected',
  createdBy: 'user123'        // camelCase
};
```

##### Step 3: Update Response Handling
```javascript
// v1.x
const incidents = response.incidents;
const total = response.total;

// v2.0
const incidents = response.data;
const total = response.pagination.total;
const hasMore = response.pagination.hasMore;
```

##### Step 4: Handle New Status Values
```javascript
// v1.x
if (incident.status === 'in_progress') {
  // Handle in progress
}

// v2.0
if (incident.status === 'investigating' || incident.status === 'mitigating') {
  // Handle active investigation
}
```

## Using the Migration CLI

### Installation
```bash
npm install -g @sparc/migration-cli
```

### Setup
```bash
sparc-migrate init
```

### Validate Your Data
```bash
# Test transformation of your incident data
sparc-migrate validate Incident sample-incident.json

# Check compatibility
sparc-migrate check

# Run full test suite
sparc-migrate test
```

### Generate Migration Report
```bash
sparc-migrate report
```

## Gradual Migration Strategy

### Phase 1: Compatibility Mode (Weeks 1-2)
1. Enable version headers in your application
2. Log deprecation warnings
3. Monitor API responses for deprecation headers

```javascript
class SparcClient {
  constructor() {
    this.version = '1.1'; // Current version
  }

  async request(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        ...options.headers,
        'Accept-Version': this.version
      }
    });

    // Check for deprecation warnings
    if (response.headers.get('X-API-Deprecation')) {
      console.warn('API Deprecation:', {
        message: response.headers.get('X-API-Deprecation-Message'),
        sunset: response.headers.get('X-API-Sunset-Date'),
        guide: response.headers.get('X-API-Migration-Guide')
      });
    }

    return response;
  }
}
```

### Phase 2: Dual Support (Weeks 3-4)
1. Implement version detection
2. Support both old and new formats
3. Add transformation layer

```javascript
class VersionAwareClient {
  transformIncidentToV2(v1Incident) {
    return {
      id: v1Incident.incident_id,
      category: v1Incident.incident_type,
      priority: this.mapPriority(v1Incident.priority),
      severity: v1Incident.priority,
      title: v1Incident.description.substring(0, 50),
      description: v1Incident.description,
      createdBy: v1Incident.created_by,
      createdAt: v1Incident.created_at
    };
  }

  mapPriority(v1Priority) {
    const mapping = {
      'critical': 'P1',
      'high': 'P2',
      'medium': 'P3',
      'low': 'P4'
    };
    return mapping[v1Priority] || 'P3';
  }
}
```

### Phase 3: Migration (Weeks 5-6)
1. Switch to v2 endpoints
2. Update all data models
3. Remove compatibility code

### Phase 4: Cleanup (Week 7)
1. Remove v1 support code
2. Update documentation
3. Archive old integration code

## Common Migration Issues

### Issue 1: Missing Required Fields
**Error**: `"title" is required`

**Solution**: Ensure all new required fields are included
```javascript
// Add default title from description
if (!incident.title && incident.description) {
  incident.title = incident.description.substring(0, 100);
}
```

### Issue 2: Invalid Status Values
**Error**: `Invalid status value`

**Solution**: Map old statuses to new ones
```javascript
const statusMapping = {
  'in_progress': 'investigating',
  'resolved': 'resolved',
  'closed': 'closed',
  'open': 'open'
};
incident.status = statusMapping[incident.status] || 'open';
```

### Issue 3: Authentication Failures
**Error**: `401 Unauthorized`

**Solution**: Ensure headers are properly set
```javascript
headers: {
  'Authorization': `Bearer ${token}`,
  'Accept-Version': '2.0',
  'Content-Type': 'application/json'
}
```

## Testing Your Migration

### Unit Tests
```javascript
describe('API Migration', () => {
  it('should transform v1 incident to v2', () => {
    const v1Incident = {
      incident_id: '123',
      incident_type: 'security',
      priority: 'high'
    };

    const v2Incident = transformer.toV2(v1Incident);

    expect(v2Incident).toEqual({
      id: '123',
      category: 'security',
      priority: 'P2',
      severity: 'high'
    });
  });
});
```

### Integration Tests
```javascript
it('should work with both API versions', async () => {
  // Test v1
  const v1Response = await client.get('/v1/incidents');
  expect(v1Response.incidents).toBeDefined();

  // Test v2
  const v2Response = await client.get('/v2/incidents');
  expect(v2Response.data).toBeDefined();
  expect(v2Response.pagination).toBeDefined();
});
```

## Rollback Plan

If issues arise during migration:

1. **Immediate Rollback**
   ```javascript
   // Switch back to v1
   const API_VERSION = '1.1';
   ```

2. **Gradual Rollback**
   - Use feature flags to control version
   - Route percentage of traffic to old version
   - Monitor error rates

3. **Data Cleanup**
   - Revert any data transformations
   - Clear caches
   - Update client configurations

## Support Resources

- **Documentation**: https://docs.sparc.io/api/versions
- **Migration Tools**: https://github.com/sparc/migration-tools
- **Support Forum**: https://community.sparc.io/migration
- **Email Support**: api-migration@sparc.io

## Version Support Timeline

| Version | Status | End of Life |
|---------|--------|-------------|
| v1.0 | Deprecated | June 30, 2024 |
| v1.1 | Current | December 31, 2024 |
| v2.0 | Current | December 31, 2025 |
| v2.1 | Preview | - |
| v3.0 | Planning | - |

## Best Practices

1. **Always Specify Version**
   - Use explicit version headers
   - Don't rely on default behavior

2. **Monitor Deprecations**
   - Log deprecation warnings
   - Track usage of deprecated features
   - Plan migrations early

3. **Test Thoroughly**
   - Test with production-like data
   - Verify all endpoints
   - Check error handling

4. **Gradual Migration**
   - Migrate one service at a time
   - Use feature flags
   - Monitor metrics

5. **Keep Dependencies Updated**
   - Use latest SDKs
   - Update API clients
   - Review third-party integrations