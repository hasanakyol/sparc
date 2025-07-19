# CDN and Database Connection Pooling Configuration

This document describes the CloudFront CDN configuration for video streaming and the database connection pooling setup for the SPARC platform.

## CloudFront CDN Configuration

### Overview

The CDN configuration provides global content delivery with optimizations for:
- Video streaming from S3
- API Gateway requests
- Static asset delivery
- WebSocket connections

### Key Features

1. **Multiple Origins**
   - S3 bucket for video storage with Origin Access Identity
   - S3 bucket for static assets
   - API Gateway origin
   - Video streaming service origin with Origin Shield

2. **Optimized Cache Behaviors**
   - `/video/*` - Long-term caching (1 day default, 1 year max) for video content
   - `/api/*` - Short caching (5 minutes max) with authorization header consideration
   - `/ws/*` - No caching for WebSocket connections
   - Default - Static assets with 1-day caching

3. **Security Features**
   - WAF integration with rate limiting and SQL injection protection
   - Field-level encryption for sensitive video metadata
   - Security headers (HSTS, CSP, X-Frame-Options, etc.)
   - Lambda@Edge for authentication and header manipulation

4. **Performance Optimizations**
   - Origin Shield for video streaming
   - Smooth streaming enabled for video content
   - Compression for non-video content
   - Real-time logging to Kinesis

5. **Monitoring**
   - CloudWatch alarms for 4xx/5xx errors and origin latency
   - Real-time logs streamed to Kinesis
   - Standard logs to S3

### Deployment

```bash
cd infra/terraform/modules/cdn
terraform init
terraform plan -var-file=../../environments/production/terraform.tfvars
terraform apply
```

### Required Variables

```hcl
module "cdn" {
  source = "../../modules/cdn"
  
  environment            = "production"
  api_gateway_domain    = "api.sparc.io"
  video_streaming_domain = "video.sparc.io"
  cdn_domain_name       = "cdn.sparc.io"
  jwt_public_key        = var.jwt_public_key
  field_encryption_public_key = var.field_encryption_public_key
  sns_alert_topic_arn   = aws_sns_topic.alerts.arn
}
```

## Database Connection Pooling

### Overview

The database connection pooling configuration provides:
- Optimized connection management
- Read replica support
- Automatic retry logic
- Health monitoring
- Performance metrics

### Key Features

1. **Connection Pool Management**
   - Configurable min/max connections per service
   - Idle timeout and connection timeout settings
   - PgBouncer compatibility
   - SSL/TLS support

2. **Service-Specific Configurations**
   - API Gateway: 10-50 connections
   - Video Management: 5-20 connections with longer timeouts
   - Analytics: 5-30 connections with read replica support
   - Auth Service: 10-40 connections with fast timeouts
   - Event Processing: 5-25 connections for batch operations

3. **Read Replica Support**
   - Automatic routing of read queries to replicas
   - Weighted load balancing
   - Fallback to primary on replica failure

4. **Monitoring and Health Checks**
   - Automatic metrics export (Prometheus format)
   - Connection pool statistics
   - Query performance tracking
   - Health check endpoint

### Usage in Services

#### 1. Import the configured connection

```typescript
import { db, connectionPool } from '@sparc/database/connection';

// Use with Drizzle ORM
const users = await db.select().from(usersTable).where(eq(usersTable.tenantId, tenantId));

// Use with raw queries
const result = await connectionPool.query(
  'SELECT * FROM videos WHERE tenant_id = $1',
  [tenantId],
  { useReadReplica: true }
);
```

#### 2. Service-specific configuration

```typescript
import { createDatabasePool } from '@sparc/database/connection-pool';
import { getPoolConfig } from '@sparc/database/config/pool-config';

const poolConfig = getPoolConfig('video-management');
const pool = createDatabasePool(poolConfig);
```

#### 3. Transactions with retry

```typescript
const result = await connectionPool.transaction(async (client) => {
  await client.query('INSERT INTO logs (action) VALUES ($1)', ['user_login']);
  await client.query('UPDATE users SET last_login = NOW() WHERE id = $1', [userId]);
}, {
  timeout: 10000,
  retries: 3
});
```

### Environment Variables

```bash
# Primary database
DATABASE_URL=postgresql://user:pass@host:5432/dbname

# Read replicas (comma-separated)
DATABASE_READ_REPLICAS=postgresql://user:pass@replica1:5432/dbname,postgresql://user:pass@replica2:5432/dbname

# Pool configuration overrides
DB_POOL_MIN=10
DB_POOL_MAX=50
DB_IDLE_TIMEOUT=30000
DB_CONNECTION_TIMEOUT=2000
DB_STATEMENT_TIMEOUT=5000
DB_QUERY_TIMEOUT=10000
```

### Monitoring

#### Grafana Dashboard

A comprehensive dashboard is available at `/monitoring/grafana/dashboards/database-connection-pool.json` showing:
- Pool utilization
- Connection status (total, idle, waiting)
- Query performance metrics
- Error rates
- Read replica status

#### Prometheus Alerts

Alerts are configured in `/monitoring/alerts/database-pool-alerts.yaml`:
- Pool exhaustion
- High utilization (>80%)
- Connection errors
- Slow queries
- Health check failures

### Best Practices

1. **Connection Pool Sizing**
   - Start with default configurations
   - Monitor utilization and adjust based on actual usage
   - Consider service-specific requirements

2. **Query Optimization**
   - Use read replicas for analytics and reporting
   - Set appropriate timeouts for different query types
   - Implement retry logic for transient failures

3. **Monitoring**
   - Set up alerts for pool exhaustion
   - Track slow queries and optimize them
   - Monitor connection errors for network issues

4. **Graceful Shutdown**
   - Always close connections on service shutdown
   - Implement signal handlers for SIGTERM/SIGINT
   - Allow time for in-flight queries to complete

## Integration with Existing Services

To integrate these configurations with existing services:

1. **Update service dependencies**:
   ```json
   {
     "dependencies": {
       "@sparc/database": "workspace:*"
     }
   }
   ```

2. **Replace direct pool creation with configured pools**:
   ```typescript
   // Old
   const pool = new Pool({ connectionString: process.env.DATABASE_URL });
   
   // New
   import { pool, db, connectionPool } from '@sparc/database/connection';
   ```

3. **For Prisma-based services**:
   ```typescript
   import { getPrismaConnectionUrl } from '@sparc/database/connection';
   process.env.DATABASE_URL = getPrismaConnectionUrl();
   ```

4. **Add health checks**:
   ```typescript
   import { checkDatabaseHealth } from '@sparc/database/connection';
   
   app.get('/health', async (c) => {
     const dbHealth = await checkDatabaseHealth();
     return c.json({ database: dbHealth ? 'healthy' : 'unhealthy' });
   });
   ```

## Troubleshooting

### CDN Issues

1. **Origin Errors**: Check origin health and security groups
2. **Cache Misses**: Verify cache behaviors and TTL settings
3. **Access Denied**: Check S3 bucket policies and OAI configuration

### Database Pool Issues

1. **Pool Exhaustion**: Increase max connections or optimize query performance
2. **Connection Timeouts**: Check network connectivity and firewall rules
3. **Slow Queries**: Enable query logging and analyze with EXPLAIN
4. **Read Replica Lag**: Monitor replication delay and adjust routing

## Performance Targets

Based on the requirements in fix.md:
- API response time: < 200ms (p95)
- Video latency: < 500ms
- Database query latency: < 50ms (p95)
- Connection pool utilization: < 80%
- CDN cache hit rate: > 90% for static content