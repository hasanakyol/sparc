# Redis Caching Layer Implementation

## Overview

A comprehensive Redis caching layer has been implemented across SPARC services to improve performance by reducing database queries and external API calls. The caching system provides automatic cache management, invalidation, and monitoring.

## Architecture

### Core Components

1. **CacheService** (`packages/shared/src/utils/cache.ts`)
   - Centralized cache management
   - Key generation and namespacing
   - TTL management
   - Cache statistics
   - Tag-based invalidation

2. **Cache Middleware** (`packages/shared/src/middleware/cache.ts`)
   - Automatic HTTP response caching
   - Conditional caching based on request method
   - Cache invalidation on data mutations
   - Per-tenant cache isolation

## Features

### 1. Automatic Caching
```typescript
// Apply to routes
app.use('/api/*', cacheMiddleware(cache, {
  ttl: 300, // 5 minutes
  namespace: 'api',
  condition: (c) => c.req.method === 'GET'
}));
```

### 2. Manual Cache Management
```typescript
// Get or set pattern
const data = await cache.getOrSet(
  'expensive-query',
  async () => await performExpensiveQuery(),
  600 // 10 minutes TTL
);
```

### 3. Cache Invalidation
```typescript
// Invalidate specific key
await cache.delete('user:123');

// Invalidate by pattern
await cache.deletePattern('user:*');

// Invalidate by tags
await cache.invalidateByTags(['users', 'permissions']);
```

### 4. Method Decorators
```typescript
class UserService {
  @Cacheable({ ttl: 300, namespace: 'users' })
  async getUser(id: string) {
    return await prisma.user.findUnique({ where: { id } });
  }

  @InvalidateCache({ tags: ['users'] })
  async updateUser(id: string, data: any) {
    return await prisma.user.update({ where: { id }, data });
  }
}
```

## Implementation Status

### Services with Caching Enabled

1. **API Gateway**
   - Caches responses from downstream services
   - 1-minute TTL for frequently accessed resources
   - Per-tenant cache isolation
   - Endpoints cached:
     - Organizations, Sites, Buildings, Floors
     - Zones, Cameras, Devices
     - Analytics data, Reports, Dashboards

2. **Analytics Service**
   - Caches expensive analytics queries
   - 5-minute TTL for analytics data
   - Automatic invalidation on data updates
   - OpenSearch query results cached

3. **Reporting Service**
   - Dashboard data caching (ready for implementation)
   - Report generation caching (ready for implementation)

### Cache Key Patterns

```
{prefix}:{namespace}:{tenant_id}:{resource}:{params_hash}

Examples:
- api-gateway:api:123e4567:organizations:a1b2c3
- analytics:analytics:123e4567:/analytics/security:query_hash
- reporting:dashboards:123e4567:widget_data:params_hash
```

## Performance Improvements

### Expected Improvements

1. **API Gateway Response Times**
   - Before: 100-500ms (database queries)
   - After: 5-20ms (cache hits)
   - Cache hit ratio target: >80%

2. **Analytics Queries**
   - Before: 500-3000ms (complex aggregations)
   - After: 10-50ms (cache hits)
   - Significant reduction in OpenSearch load

3. **Database Load Reduction**
   - 60-80% reduction in read queries
   - Improved scalability for concurrent users
   - Better resource utilization

## Configuration

### Environment Variables
```bash
# Redis connection
REDIS_URL=redis://localhost:6379

# Cache TTL defaults (seconds)
CACHE_DEFAULT_TTL=300
CACHE_API_TTL=60
CACHE_ANALYTICS_TTL=300
```

### Service-Specific Configuration
```typescript
// Initialize cache with custom settings
const cache = new CacheService(redis, {
  prefix: 'service-name',
  ttl: 300, // 5 minutes default
  compress: true // Enable for large values
});
```

## Monitoring

### Cache Statistics
```typescript
// Get cache performance metrics
const stats = cache.getStats();
console.log({
  hitRate: stats.hits / (stats.hits + stats.misses),
  totalRequests: stats.hits + stats.misses,
  errors: stats.errors
});
```

### Redis Monitoring Commands
```bash
# Monitor cache operations
redis-cli MONITOR

# Get cache keys by pattern
redis-cli KEYS "api-gateway:*"

# Check memory usage
redis-cli INFO memory

# View cache hit/miss ratio
redis-cli INFO stats
```

## Best Practices

1. **TTL Guidelines**
   - Static data: 1-24 hours
   - Dynamic data: 1-5 minutes
   - User-specific data: 30-60 seconds
   - Real-time data: Don't cache

2. **Cache Key Design**
   - Include tenant ID for multi-tenancy
   - Use consistent parameter ordering
   - Hash complex parameters
   - Keep keys reasonably short

3. **Invalidation Strategy**
   - Invalidate on write operations
   - Use tags for related data
   - Clear namespace for bulk invalidation
   - Monitor for stale data

4. **Memory Management**
   - Set Redis maxmemory policy
   - Use eviction policy: allkeys-lru
   - Monitor memory usage
   - Implement cache warming for critical data

## Testing Cache Behavior

```bash
# Test cache hit
curl -H "X-Tenant-ID: 123" http://localhost:3000/api/v1/organizations
# Check X-Cache: MISS header

# Repeat request
curl -H "X-Tenant-ID: 123" http://localhost:3000/api/v1/organizations
# Check X-Cache: HIT header

# Force cache invalidation
curl -X POST -H "X-Tenant-ID: 123" http://localhost:3000/api/v1/organizations
# Subsequent GET will show X-Cache: MISS
```

## Future Enhancements

1. **Distributed Cache Invalidation**
   - Redis pub/sub for multi-instance invalidation
   - Event-driven cache updates

2. **Cache Warming**
   - Pre-populate critical data
   - Background refresh for expiring entries

3. **Advanced Features**
   - Compression for large values
   - Partial response caching
   - Edge caching integration
   - Cache analytics dashboard

4. **Service Mesh Integration**
   - Envoy/Istio cache filters
   - Distributed tracing for cache operations

## Troubleshooting

### Common Issues

1. **High Cache Misses**
   - Check TTL settings
   - Verify key generation logic
   - Monitor invalidation patterns

2. **Memory Issues**
   - Review eviction policy
   - Check for memory leaks
   - Implement key expiration

3. **Stale Data**
   - Verify invalidation logic
   - Check cache TTL
   - Monitor update patterns

### Debug Mode
```typescript
// Enable cache debugging
const cache = new CacheService(redis, {
  debug: true, // Logs all operations
  prefix: 'debug'
});
```