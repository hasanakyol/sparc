import { Hono } from 'hono';
import { z } from 'zod';
import { HTTPException } from 'hono/http-exception';
import { eq, and, desc, gte, lte, sql } from 'drizzle-orm';
import { db, schema } from '../db';
import { 
  iotMetricSchema,
  iotMetricBatchSchema,
  IotMetricInput,
  IotMetricBatchInput
} from '../types';
import { logger } from '@sparc/shared';
import { trace } from '@opentelemetry/api';
import Redis from 'ioredis';

const tracer = trace.getTracer('maintenance-service');
const app = new Hono<{ Variables: { tenantId: string; userId: string; redis: Redis } }>();

// Ingest IoT metrics (single metric)
app.post('/metrics', async (c) => {
  const span = tracer.startSpan('ingestIotMetric');
  
  try {
    const tenantId = c.get('tenantId');
    const redis = c.get('redis');
    const body = await c.req.json();
    
    // Validate input
    const input = iotMetricSchema.parse(body) as IotMetricInput;
    
    span.setAttributes({
      'iot.deviceId': input.deviceId,
      'iot.metricType': input.metricType,
      'iot.value': input.value
    });
    
    // Check for anomaly
    const anomalyDetected = await detectAnomaly(tenantId, input);
    
    // Save metric
    const [metric] = await db.insert(schema.iotDeviceMetrics)
      .values({
        tenantId,
        deviceId: input.deviceId,
        metricType: input.metricType,
        value: input.value.toString(),
        unit: input.unit,
        threshold: input.threshold?.toString(),
        anomalyDetected: anomalyDetected ? 1 : 0,
        metadata: input.metadata || {}
      })
      .returning();
    
    // Handle anomaly
    if (anomalyDetected) {
      await handleAnomaly(tenantId, input, metric, redis);
    }
    
    // Update real-time metrics cache
    await redis.setex(
      `iot:latest:${tenantId}:${input.deviceId}:${input.metricType}`,
      300, // 5 minutes TTL
      JSON.stringify({
        value: input.value,
        unit: input.unit,
        timestamp: metric.recordedAt,
        anomaly: anomalyDetected
      })
    );
    
    return c.json({
      metric,
      anomalyDetected,
      message: anomalyDetected ? 'Anomaly detected - alert generated' : 'Metric recorded successfully'
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to ingest IoT metric', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid metric data', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to ingest metric' });
  } finally {
    span.end();
  }
});

// Ingest IoT metrics (batch)
app.post('/metrics/batch', async (c) => {
  const span = tracer.startSpan('ingestIotMetricsBatch');
  
  try {
    const tenantId = c.get('tenantId');
    const redis = c.get('redis');
    const body = await c.req.json();
    
    // Validate input
    const input = iotMetricBatchSchema.parse(body) as IotMetricBatchInput;
    
    span.setAttributes({ 'iot.batch.size': input.metrics.length });
    
    const results = [];
    const anomalies = [];
    
    // Process metrics in batches
    const batchSize = 100;
    for (let i = 0; i < input.metrics.length; i += batchSize) {
      const batch = input.metrics.slice(i, i + batchSize);
      
      // Check for anomalies
      const metricsWithAnomalies = await Promise.all(
        batch.map(async (metric) => ({
          ...metric,
          anomalyDetected: await detectAnomaly(tenantId, metric)
        }))
      );
      
      // Insert batch
      const inserted = await db.insert(schema.iotDeviceMetrics)
        .values(metricsWithAnomalies.map(m => ({
          tenantId,
          deviceId: m.deviceId,
          metricType: m.metricType,
          value: m.value.toString(),
          unit: m.unit,
          threshold: m.threshold?.toString(),
          anomalyDetected: m.anomalyDetected ? 1 : 0,
          metadata: m.metadata || {}
        })))
        .returning();
      
      results.push(...inserted);
      
      // Handle anomalies
      for (let j = 0; j < metricsWithAnomalies.length; j++) {
        const metric = metricsWithAnomalies[j];
        if (metric.anomalyDetected) {
          anomalies.push({
            metric: inserted[j],
            input: metric
          });
        }
        
        // Update cache
        await redis.setex(
          `iot:latest:${tenantId}:${metric.deviceId}:${metric.metricType}`,
          300,
          JSON.stringify({
            value: metric.value,
            unit: metric.unit,
            timestamp: inserted[j].recordedAt,
            anomaly: metric.anomalyDetected
          })
        );
      }
    }
    
    // Process anomalies
    for (const anomaly of anomalies) {
      await handleAnomaly(tenantId, anomaly.input, anomaly.metric, redis);
    }
    
    logger.info('IoT metrics batch ingested', {
      count: results.length,
      anomalies: anomalies.length
    });
    
    return c.json({
      processed: results.length,
      anomaliesDetected: anomalies.length,
      message: `Processed ${results.length} metrics, ${anomalies.length} anomalies detected`
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to ingest IoT metrics batch', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid batch data', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to ingest metrics batch' });
  } finally {
    span.end();
  }
});

// Get device metrics
app.get('/metrics/:deviceId', async (c) => {
  const span = tracer.startSpan('getDeviceMetrics');
  
  try {
    const tenantId = c.get('tenantId');
    const deviceId = c.req.param('deviceId');
    const metricType = c.req.query('metricType');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const limit = parseInt(c.req.query('limit') || '1000');
    const aggregation = c.req.query('aggregation'); // 'none', 'hour', 'day'
    
    span.setAttributes({
      'device.id': deviceId,
      'metrics.type': metricType || 'all',
      'metrics.aggregation': aggregation || 'none'
    });
    
    const conditions = [
      eq(schema.iotDeviceMetrics.tenantId, tenantId),
      eq(schema.iotDeviceMetrics.deviceId, deviceId)
    ];
    
    if (metricType) {
      conditions.push(eq(schema.iotDeviceMetrics.metricType, metricType));
    }
    
    if (startDate) {
      conditions.push(gte(schema.iotDeviceMetrics.recordedAt, new Date(startDate)));
    }
    
    if (endDate) {
      conditions.push(lte(schema.iotDeviceMetrics.recordedAt, new Date(endDate)));
    }
    
    // Get metrics based on aggregation
    if (aggregation && aggregation !== 'none') {
      const dateFormat = aggregation === 'hour' ? '%Y-%m-%d %H:00:00' : '%Y-%m-%d';
      
      const aggregatedMetrics = await db.select({
        metricType: schema.iotDeviceMetrics.metricType,
        period: sql`TO_CHAR(recorded_at, ${dateFormat})`,
        avgValue: sql`AVG(value::numeric)`,
        minValue: sql`MIN(value::numeric)`,
        maxValue: sql`MAX(value::numeric)`,
        stdDev: sql`STDDEV(value::numeric)`,
        count: sql`COUNT(*)`,
        anomalyCount: sql`SUM(anomaly_detected)`
      })
      .from(schema.iotDeviceMetrics)
      .where(and(...conditions))
      .groupBy(
        schema.iotDeviceMetrics.metricType,
        sql`TO_CHAR(recorded_at, ${dateFormat})`
      )
      .orderBy(sql`TO_CHAR(recorded_at, ${dateFormat}) DESC`)
      .limit(limit);
      
      return c.json({
        deviceId,
        aggregation,
        metrics: aggregatedMetrics.map(m => ({
          metricType: m.metricType,
          period: m.period,
          avgValue: Number(m.avgValue),
          minValue: Number(m.minValue),
          maxValue: Number(m.maxValue),
          stdDev: Number(m.stdDev),
          count: Number(m.count),
          anomalyCount: Number(m.anomalyCount)
        }))
      });
    } else {
      // Get raw metrics
      const metrics = await db.select()
        .from(schema.iotDeviceMetrics)
        .where(and(...conditions))
        .orderBy(desc(schema.iotDeviceMetrics.recordedAt))
        .limit(limit);
      
      return c.json({
        deviceId,
        metrics: metrics.map(m => ({
          ...m,
          value: Number(m.value),
          threshold: m.threshold ? Number(m.threshold) : null
        }))
      });
    }
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get device metrics', { error });
    throw new HTTPException(500, { message: 'Failed to get device metrics' });
  } finally {
    span.end();
  }
});

// Get latest metrics for a device
app.get('/metrics/:deviceId/latest', async (c) => {
  const span = tracer.startSpan('getLatestDeviceMetrics');
  
  try {
    const tenantId = c.get('tenantId');
    const deviceId = c.req.param('deviceId');
    const redis = c.get('redis');
    
    span.setAttributes({ 'device.id': deviceId });
    
    // Try to get from cache first
    const cacheKeys = await redis.keys(`iot:latest:${tenantId}:${deviceId}:*`);
    
    if (cacheKeys.length > 0) {
      const latestMetrics = await Promise.all(
        cacheKeys.map(async (key) => {
          const data = await redis.get(key);
          const metricType = key.split(':').pop();
          return {
            metricType,
            ...JSON.parse(data || '{}')
          };
        })
      );
      
      return c.json({ deviceId, latestMetrics });
    }
    
    // Fallback to database
    const latestMetrics = await db.select({
      metricType: schema.iotDeviceMetrics.metricType,
      value: sql`FIRST_VALUE(value) OVER (PARTITION BY metric_type ORDER BY recorded_at DESC)`,
      unit: sql`FIRST_VALUE(unit) OVER (PARTITION BY metric_type ORDER BY recorded_at DESC)`,
      timestamp: sql`FIRST_VALUE(recorded_at) OVER (PARTITION BY metric_type ORDER BY recorded_at DESC)`,
      anomaly: sql`FIRST_VALUE(anomaly_detected) OVER (PARTITION BY metric_type ORDER BY recorded_at DESC)`
    })
    .from(schema.iotDeviceMetrics)
    .where(and(
      eq(schema.iotDeviceMetrics.tenantId, tenantId),
      eq(schema.iotDeviceMetrics.deviceId, deviceId),
      gte(schema.iotDeviceMetrics.recordedAt, new Date(Date.now() - 24 * 60 * 60 * 1000))
    ))
    .groupBy(
      schema.iotDeviceMetrics.metricType,
      schema.iotDeviceMetrics.value,
      schema.iotDeviceMetrics.unit,
      schema.iotDeviceMetrics.recordedAt,
      schema.iotDeviceMetrics.anomalyDetected
    );
    
    return c.json({
      deviceId,
      latestMetrics: latestMetrics.map(m => ({
        metricType: m.metricType,
        value: Number(m.value),
        unit: m.unit,
        timestamp: m.timestamp,
        anomaly: m.anomaly === 1
      }))
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get latest device metrics', { error });
    throw new HTTPException(500, { message: 'Failed to get latest metrics' });
  } finally {
    span.end();
  }
});

// Get anomaly history
app.get('/anomalies', async (c) => {
  const span = tracer.startSpan('getAnomalyHistory');
  
  try {
    const tenantId = c.get('tenantId');
    const deviceId = c.req.query('deviceId');
    const metricType = c.req.query('metricType');
    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const page = parseInt(c.req.query('page') || '1');
    const limit = parseInt(c.req.query('limit') || '50');
    
    const conditions = [
      eq(schema.iotDeviceMetrics.tenantId, tenantId),
      eq(schema.iotDeviceMetrics.anomalyDetected, 1)
    ];
    
    if (deviceId) {
      conditions.push(eq(schema.iotDeviceMetrics.deviceId, deviceId));
    }
    
    if (metricType) {
      conditions.push(eq(schema.iotDeviceMetrics.metricType, metricType));
    }
    
    if (startDate) {
      conditions.push(gte(schema.iotDeviceMetrics.recordedAt, new Date(startDate)));
    }
    
    if (endDate) {
      conditions.push(lte(schema.iotDeviceMetrics.recordedAt, new Date(endDate)));
    }
    
    const offset = (page - 1) * limit;
    
    const [anomalies, totalCount] = await Promise.all([
      db.select()
        .from(schema.iotDeviceMetrics)
        .where(and(...conditions))
        .orderBy(desc(schema.iotDeviceMetrics.recordedAt))
        .limit(limit)
        .offset(offset),
      
      db.select({ count: sql`count(*)` })
        .from(schema.iotDeviceMetrics)
        .where(and(...conditions))
    ]);
    
    // Get device information
    const deviceIds = [...new Set(anomalies.map(a => a.deviceId))];
    const devices = deviceIds.length > 0
      ? await db.select()
          .from(schema.devices)
          .where(and(
            eq(schema.devices.tenantId, tenantId),
            inArray(schema.devices.id, deviceIds)
          ))
      : [];
    
    const deviceMap = new Map(devices.map(d => [d.id, d]));
    
    span.setAttributes({
      'anomalies.count': anomalies.length,
      'anomalies.total': Number(totalCount[0].count)
    });
    
    return c.json({
      anomalies: anomalies.map(a => ({
        ...a,
        value: Number(a.value),
        threshold: a.threshold ? Number(a.threshold) : null,
        device: deviceMap.get(a.deviceId) || null
      })),
      pagination: {
        page,
        limit,
        total: Number(totalCount[0].count),
        totalPages: Math.ceil(Number(totalCount[0].count) / limit)
      }
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to get anomaly history', { error });
    throw new HTTPException(500, { message: 'Failed to get anomaly history' });
  } finally {
    span.end();
  }
});

// Configure anomaly detection thresholds
app.post('/thresholds', async (c) => {
  const span = tracer.startSpan('configureThresholds');
  
  try {
    const tenantId = c.get('tenantId');
    const redis = c.get('redis');
    const body = await c.req.json();
    
    const { deviceId, metricType, threshold, enabled } = z.object({
      deviceId: z.string().uuid(),
      metricType: z.string(),
      threshold: z.object({
        min: z.number().optional(),
        max: z.number().optional(),
        stdDevMultiplier: z.number().default(2)
      }),
      enabled: z.boolean().default(true)
    }).parse(body);
    
    span.setAttributes({
      'threshold.deviceId': deviceId,
      'threshold.metricType': metricType,
      'threshold.enabled': enabled
    });
    
    // Store threshold configuration
    const key = `iot:threshold:${tenantId}:${deviceId}:${metricType}`;
    
    if (enabled) {
      await redis.set(key, JSON.stringify({
        ...threshold,
        updatedAt: new Date()
      }));
    } else {
      await redis.del(key);
    }
    
    logger.info('IoT threshold configured', { deviceId, metricType, enabled });
    
    return c.json({
      deviceId,
      metricType,
      threshold,
      enabled,
      message: enabled ? 'Threshold configured' : 'Threshold disabled'
    });
  } catch (error) {
    span.recordException(error as Error);
    logger.error('Failed to configure threshold', { error });
    
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { message: 'Invalid threshold configuration', cause: error.errors });
    }
    
    throw new HTTPException(500, { message: 'Failed to configure threshold' });
  } finally {
    span.end();
  }
});

// Helper functions

async function detectAnomaly(tenantId: string, metric: IotMetricInput): Promise<boolean> {
  // Check against configured threshold
  if (metric.threshold) {
    return metric.value > metric.threshold || metric.value < 0;
  }
  
  // Get historical data for statistical analysis
  const historicalData = await db.select({
    avgValue: sql`AVG(value::numeric)`,
    stdDev: sql`STDDEV(value::numeric)`,
    minValue: sql`MIN(value::numeric)`,
    maxValue: sql`MAX(value::numeric)`
  })
  .from(schema.iotDeviceMetrics)
  .where(and(
    eq(schema.iotDeviceMetrics.tenantId, tenantId),
    eq(schema.iotDeviceMetrics.deviceId, metric.deviceId),
    eq(schema.iotDeviceMetrics.metricType, metric.metricType),
    gte(schema.iotDeviceMetrics.recordedAt, new Date(Date.now() - 7 * 24 * 60 * 60 * 1000))
  ));
  
  if (historicalData.length === 0 || !historicalData[0].avgValue || !historicalData[0].stdDev) {
    return false; // Not enough data
  }
  
  const avg = Number(historicalData[0].avgValue);
  const stdDev = Number(historicalData[0].stdDev);
  
  // Detect anomaly if value is more than 2 standard deviations from mean
  return Math.abs(metric.value - avg) > 2 * stdDev;
}

async function handleAnomaly(
  tenantId: string, 
  metric: IotMetricInput, 
  savedMetric: any,
  redis: Redis
): Promise<void> {
  // Get device info
  const [device] = await db.select()
    .from(schema.devices)
    .where(and(
      eq(schema.devices.id, metric.deviceId),
      eq(schema.devices.tenantId, tenantId)
    ))
    .limit(1);
  
  if (!device) return;
  
  // Check if we should create a work order
  const recentWorkOrders = await db.select()
    .from(schema.workOrders)
    .where(and(
      eq(schema.workOrders.tenantId, tenantId),
      eq(schema.workOrders.deviceId, metric.deviceId),
      eq(schema.workOrders.workOrderType, 'predictive'),
      gte(schema.workOrders.createdAt, new Date(Date.now() - 24 * 60 * 60 * 1000))
    ))
    .limit(1);
  
  if (recentWorkOrders.length === 0) {
    // Create predictive maintenance work order
    const [workOrder] = await db.insert(schema.workOrders)
      .values({
        tenantId,
        deviceId: metric.deviceId,
        deviceType: device.type,
        workOrderType: 'corrective',
        priority: 'high',
        title: `Anomaly Detected: ${metric.metricType}`,
        description: `Anomalous ${metric.metricType} reading detected. Value: ${metric.value} ${metric.unit}`,
        diagnosticData: {
          metricType: metric.metricType,
          value: metric.value,
          unit: metric.unit,
          threshold: metric.threshold,
          timestamp: savedMetric.recordedAt
        },
        status: 'open'
      })
      .returning();
    
    // Publish events
    await redis.publish('maintenance:work-order:update', JSON.stringify({
      action: 'created',
      tenantId,
      workOrder
    }));
  }
  
  // Publish predictive alert
  await redis.publish('maintenance:predictive:alert', JSON.stringify({
    tenantId,
    deviceId: metric.deviceId,
    alert: {
      type: 'iot_anomaly',
      metricType: metric.metricType,
      value: metric.value,
      unit: metric.unit,
      severity: 'high',
      timestamp: savedMetric.recordedAt,
      device: {
        id: device.id,
        name: device.name,
        type: device.type
      }
    }
  }));
  
  // Update metrics
  await redis.incr('metrics:predictive:alerts');
}

export default app;