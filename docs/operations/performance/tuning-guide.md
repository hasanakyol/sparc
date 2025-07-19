# SPARC Performance Tuning Guide

## Overview
This guide provides comprehensive performance tuning recommendations for the SPARC Security Platform to achieve optimal performance at scale.

## Performance Targets

### System-Wide SLOs
- **API Response Time**: < 200ms (p95)
- **Video Stream Latency**: < 500ms
- **Dashboard Load Time**: < 2 seconds
- **Concurrent Users**: 10,000+
- **Video Streams**: 100,000+
- **Events/Second**: 50,000+

## Database Performance Tuning

### PostgreSQL Configuration

#### Connection Pool Settings
```sql
-- postgresql.conf
max_connections = 500
shared_buffers = 8GB  # 25% of RAM
effective_cache_size = 24GB  # 75% of RAM
work_mem = 64MB
maintenance_work_mem = 2GB
wal_buffers = 16MB
checkpoint_completion_target = 0.9
```

#### Query Optimization
```sql
-- Enable query parallelization
max_parallel_workers_per_gather = 4
max_parallel_workers = 8
parallel_setup_cost = 1000
parallel_tuple_cost = 0.1

-- Statistics and planning
default_statistics_target = 100
random_page_cost = 1.1  # For SSDs
effective_io_concurrency = 200
```

#### Critical Indexes
```sql
-- User activity patterns
CREATE INDEX CONCURRENTLY idx_user_activity 
ON user_activity(user_id, timestamp DESC) 
WHERE deleted_at IS NULL;

-- Video metadata searches
CREATE INDEX CONCURRENTLY idx_video_metadata_gin 
ON videos USING GIN(metadata jsonb_path_ops);

-- Event correlation
CREATE INDEX CONCURRENTLY idx_events_correlation 
ON security_events(correlation_id, timestamp DESC) 
INCLUDE (event_type, severity);

-- Access control lookups
CREATE INDEX CONCURRENTLY idx_access_control_composite 
ON access_rules(user_id, resource_type, resource_id) 
WHERE is_active = true AND expires_at > NOW();
```

#### Partitioning Strategy
```sql
-- Partition large tables by time
CREATE TABLE events_2024_01 PARTITION OF events
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Automated partition management
CREATE OR REPLACE FUNCTION create_monthly_partitions()
RETURNS void AS $$
DECLARE
  start_date date;
  end_date date;
BEGIN
  start_date := date_trunc('month', CURRENT_DATE);
  end_date := start_date + interval '1 month';
  
  EXECUTE format('CREATE TABLE IF NOT EXISTS events_%s PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
    to_char(start_date, 'YYYY_MM'),
    start_date,
    end_date
  );
END;
$$ LANGUAGE plpgsql;

-- Schedule monthly
SELECT cron.schedule('create-partitions', '0 0 1 * *', 'SELECT create_monthly_partitions()');
```

### Redis Optimization

#### Memory Configuration
```bash
# redis.conf
maxmemory 16gb
maxmemory-policy allkeys-lru
maxmemory-samples 5

# Persistence settings for cache
save ""  # Disable RDB snapshots for cache
appendonly no

# For session store
appendonly yes
appendfsync everysec
```

#### Key Optimization Patterns
```typescript
// Use hash tags for related keys to ensure same slot
const userSessionKey = `{user:${userId}}:session`;
const userPermissionsKey = `{user:${userId}}:permissions`;
const userPreferencesKey = `{user:${userId}}:preferences`;

// Use pipelines for batch operations
const pipeline = redis.pipeline();
userIds.forEach(id => {
  pipeline.get(`user:${id}:profile`);
  pipeline.get(`user:${id}:settings`);
});
const results = await pipeline.exec();

// Set appropriate TTLs
await redis.setex('cache:expensive-query:' + hash, 300, JSON.stringify(result)); // 5 min cache
await redis.setex('session:' + sessionId, 1800, JSON.stringify(session)); // 30 min session
```

## Application-Level Optimizations

### API Gateway

#### Request/Response Optimization
```typescript
// Enable compression
app.use(compress({
  threshold: 1024, // Only compress responses > 1KB
  encodings: ['gzip', 'br', 'deflate']
}));

// Implement response caching
app.use(async (c, next) => {
  const cacheKey = `api:${c.req.method}:${c.req.path}:${c.req.query}`;
  
  if (c.req.method === 'GET') {
    const cached = await redis.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached), 200, {
        'X-Cache': 'HIT'
      });
    }
  }
  
  await next();
  
  // Cache successful GET responses
  if (c.req.method === 'GET' && c.res.status === 200) {
    const body = await c.res.json();
    await redis.setex(cacheKey, 60, JSON.stringify(body));
  }
});
```

#### Connection Pooling
```typescript
// Database connection pool
const pool = new Pool({
  max: 20, // Maximum connections per service
  min: 5,  // Minimum idle connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  statementTimeout: 5000,
});

// HTTP keep-alive for service-to-service
const agent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 1000,
  maxSockets: 100,
  maxFreeSockets: 10,
  timeout: 60000,
});
```

### Video Service Optimization

#### Adaptive Bitrate Streaming
```typescript
// HLS configuration for optimal performance
const hlsConfig = {
  segmentDuration: 6,  // 6-second segments
  playlistLength: 10,  // Keep 10 segments in playlist
  variants: [
    { bitrate: 400000, resolution: '426x240' },    // Mobile
    { bitrate: 800000, resolution: '640x360' },    // SD
    { bitrate: 1200000, resolution: '854x480' },   // HD
    { bitrate: 2500000, resolution: '1280x720' },  // Full HD
    { bitrate: 5000000, resolution: '1920x1080' }, // Ultra HD
  ],
};

// Intelligent transcoding queue
const transcodingQueue = new Bull('transcoding', {
  defaultJobOptions: {
    priority: (job) => {
      // Prioritize based on viewer count and account tier
      const priority = job.data.viewerCount * job.data.accountTier;
      return Math.min(priority, 1000);
    },
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 2000,
    },
  },
});
```

#### CDN Configuration
```typescript
// Multi-CDN strategy
const cdnProviders = [
  { name: 'cloudfront', weight: 0.6, regions: ['us', 'eu'] },
  { name: 'fastly', weight: 0.3, regions: ['us', 'asia'] },
  { name: 'akamai', weight: 0.1, regions: ['global'] },
];

function selectCDN(userRegion: string, contentType: string) {
  const eligibleCDNs = cdnProviders.filter(cdn => 
    cdn.regions.includes(userRegion) || cdn.regions.includes('global')
  );
  
  // Weighted random selection
  const random = Math.random();
  let accumulator = 0;
  
  for (const cdn of eligibleCDNs) {
    accumulator += cdn.weight;
    if (random <= accumulator) {
      return cdn.name;
    }
  }
  
  return eligibleCDNs[0].name;
}
```

### Frontend Optimization

#### Code Splitting and Lazy Loading
```typescript
// Route-based code splitting
const DashboardPage = lazy(() => 
  import(/* webpackChunkName: "dashboard" */ './pages/Dashboard')
);

const VideoPlayerPage = lazy(() => 
  import(/* webpackChunkName: "video-player" */ './pages/VideoPlayer')
);

// Component-level splitting for heavy components
const AdvancedAnalytics = lazy(() =>
  import(/* webpackChunkName: "analytics" */ './components/AdvancedAnalytics')
);
```

#### Resource Optimization
```typescript
// Image optimization with Next.js
import Image from 'next/image';

<Image
  src="/camera-feed.jpg"
  alt="Camera Feed"
  width={640}
  height={480}
  loading="lazy"
  placeholder="blur"
  quality={85}
/>

// Preload critical resources
<link
  rel="preload"
  href="/fonts/inter-var.woff2"
  as="font"
  type="font/woff2"
  crossOrigin="anonymous"
/>

// Prefetch likely navigation targets
const router = useRouter();
useEffect(() => {
  router.prefetch('/dashboard');
  router.prefetch('/cameras');
}, []);
```

#### State Management Optimization
```typescript
// Use React Query for server state
const { data, error } = useQuery({
  queryKey: ['cameras', siteId],
  queryFn: () => fetchCameras(siteId),
  staleTime: 5 * 60 * 1000, // 5 minutes
  cacheTime: 10 * 60 * 1000, // 10 minutes
  refetchOnWindowFocus: false,
});

// Optimize re-renders with memo
const CameraGrid = memo(({ cameras }) => {
  return cameras.map(camera => (
    <CameraCard key={camera.id} camera={camera} />
  ));
}, (prevProps, nextProps) => {
  // Custom comparison for shallow equality
  return prevProps.cameras.length === nextProps.cameras.length &&
         prevProps.cameras.every((cam, idx) => 
           cam.id === nextProps.cameras[idx].id &&
           cam.status === nextProps.cameras[idx].status
         );
});
```

## Infrastructure Optimization

### Kubernetes Performance

#### Resource Limits and Requests
```yaml
# Optimized resource allocation
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "1000m"

# JVM-based services
env:
  - name: JAVA_OPTS
    value: "-Xms512m -Xmx1g -XX:+UseG1GC -XX:MaxGCPauseMillis=100"

# Node.js services
env:
  - name: NODE_OPTIONS
    value: "--max-old-space-size=1024 --max-semi-space-size=64"
```

#### Horizontal Pod Autoscaling
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 60
      - type: Pods
        value: 5
        periodSeconds: 60
```

#### Network Policies for Performance
```yaml
# Optimize internal communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: optimize-internal-traffic
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: backend
    - podSelector:
        matchLabels:
          app: api-gateway
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: backend
  - to:
    - podSelector:
        matchLabels:
          app: postgresql
  - to:
    - podSelector:
        matchLabels:
          app: redis
```

### Load Balancing Strategies

#### Service Mesh Configuration
```yaml
# Istio load balancing
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: api-gateway-lb
spec:
  host: api-gateway
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 100
        http2MaxRequests: 100
        maxRequestsPerConnection: 2
    loadBalancer:
      consistentHash:
        httpCookie:
          name: "session"
          ttl: 3600s
    outlierDetection:
      consecutiveErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
```

## Monitoring and Alerting

### Key Performance Metrics

#### Application Metrics
```yaml
# Prometheus queries for key metrics
- alert: HighResponseTime
  expr: histogram_quantile(0.95, http_request_duration_seconds_bucket) > 0.2
  for: 5m
  annotations:
    summary: "API response time is above 200ms (p95)"

- alert: HighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.01
  for: 5m
  annotations:
    summary: "Error rate is above 1%"

- alert: DatabaseConnectionPoolExhaustion
  expr: pg_stat_database_numbackends / pg_settings_max_connections > 0.8
  for: 5m
  annotations:
    summary: "Database connection pool is 80% utilized"
```

#### Infrastructure Metrics
```yaml
- alert: HighMemoryUsage
  expr: container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.9
  for: 5m
  annotations:
    summary: "Container memory usage is above 90%"

- alert: HighCPUThrottling
  expr: rate(container_cpu_throttled_seconds_total[5m]) > 0.1
  for: 5m
  annotations:
    summary: "CPU throttling is occurring"
```

### Performance Testing

#### Load Testing Configuration
```yaml
# k6 load test script
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '5m', target: 100 },   // Ramp up
    { duration: '10m', target: 1000 },  // Stay at 1000 users
    { duration: '5m', target: 5000 },   // Spike test
    { duration: '10m', target: 1000 },  // Recovery
    { duration: '5m', target: 0 },      // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<200'], // 95% of requests under 200ms
    http_req_failed: ['rate<0.01'],   // Error rate under 1%
  },
};

export default function() {
  // Simulate realistic user behavior
  let responses = http.batch([
    ['GET', `${__ENV.API_URL}/api/sites`],
    ['GET', `${__ENV.API_URL}/api/cameras`],
    ['GET', `${__ENV.API_URL}/api/events?limit=50`],
  ]);
  
  responses.forEach(response => {
    check(response, {
      'status is 200': (r) => r.status === 200,
      'response time < 200ms': (r) => r.timings.duration < 200,
    });
  });
  
  sleep(1);
}
```

## Optimization Checklist

### Database
- [ ] Connection pooling configured
- [ ] Critical indexes created
- [ ] Query performance analyzed
- [ ] Partitioning implemented for large tables
- [ ] Vacuum and analyze scheduled
- [ ] Replication lag monitored

### Caching
- [ ] Redis cluster deployed
- [ ] Cache warming implemented
- [ ] TTLs optimized
- [ ] Cache hit rates monitored
- [ ] Eviction policies configured

### Application
- [ ] Response compression enabled
- [ ] Connection keep-alive configured
- [ ] Request batching implemented
- [ ] Async processing for heavy operations
- [ ] Circuit breakers configured

### Frontend
- [ ] Code splitting implemented
- [ ] Images optimized
- [ ] Critical CSS inlined
- [ ] Service worker caching
- [ ] Bundle size monitored

### Infrastructure
- [ ] Auto-scaling configured
- [ ] Resource limits optimized
- [ ] Network policies defined
- [ ] Load balancing tuned
- [ ] CDN configured

### Monitoring
- [ ] Performance metrics tracked
- [ ] Alerts configured
- [ ] Dashboards created
- [ ] SLOs defined
- [ ] Regular load testing scheduled