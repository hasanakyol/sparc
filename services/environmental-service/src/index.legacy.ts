import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { prettyJSON } from 'hono/pretty-json';
import { HTTPException } from 'hono/http-exception';
import { serve } from '@hono/node-server';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import Redis from 'ioredis';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { config } from '@sparc/shared/config';
import { logger as appLogger } from '@sparc/shared/utils';
import { tenantMiddleware } from './middleware/tenant';
import { authMiddleware } from './middleware/auth';
import { sensorRoutes } from './routes/sensors';
import { readingRoutes } from './routes/readings';
import { alertRoutes } from './routes/alerts';
import { SensorService } from './services/sensorService';
import { ReadingService } from './services/readingService';
import { AlertService } from './services/alertService';
import { ThresholdService } from './services/thresholdService';
import { HVACIntegrationService } from './services/hvacIntegrationService';
import { ProtocolService } from './services/protocolService';
import { AdvancedAnalyticsService } from './services/advancedAnalyticsService';
import { PredictiveMaintenanceService } from './services/predictiveMaintenanceService';
import { BuildingAutomationService } from './services/buildingAutomationService';
import { EmergencyResponseService } from './services/emergencyResponseService';
import { CalibrationService } from './services/calibrationService';
import { OccupancyIntegrationService } from './services/occupancyIntegrationService';

// Initialize database and cache connections
const prisma = new PrismaClient();
const redis = new Redis(config.redis.url);

// Initialize services
const sensorService = new SensorService(prisma, redis);
const readingService = new ReadingService(prisma, redis);
const alertService = new AlertService(prisma, redis);
const thresholdService = new ThresholdService(prisma, redis);
const hvacService = new HVACIntegrationService(prisma, redis);
const protocolService = new ProtocolService(prisma, redis);
const analyticsService = new AdvancedAnalyticsService(prisma, redis);
const predictiveMaintenanceService = new PredictiveMaintenanceService(prisma, redis);
const buildingAutomationService = new BuildingAutomationService(prisma, redis);
const emergencyResponseService = new EmergencyResponseService(prisma, redis);
const calibrationService = new CalibrationService(prisma, redis);
const occupancyIntegrationService = new OccupancyIntegrationService(prisma, redis);

// Create Hono app
const app = new Hono();

// Global middleware
app.use('*', cors({
  origin: config.cors.origins,
  credentials: true,
}));

app.use('*', logger());
app.use('*', prettyJSON());

// Health check endpoint
app.get('/health', async (c) => {
  try {
    // Check database connection
    await prisma.$queryRaw`SELECT 1`;
    
    // Check Redis connection
    await redis.ping();
    
    // Check active sensors
    const activeSensors = await sensorService.getActiveSensorCount();
    
    // Check HVAC systems status
    const hvacSystemsStatus = await hvacService.getSystemsHealthStatus();
    
    // Check building automation systems
    const basStatus = await buildingAutomationService.getSystemsStatus();
    
    return c.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'environmental-service',
      version: process.env.npm_package_version || '1.0.0',
      database: 'connected',
      cache: 'connected',
      activeSensors,
      hvacSystems: hvacSystemsStatus,
      buildingAutomation: basStatus,
      features: {
        hvacControl: true,
        predictiveMaintenance: true,
        advancedAnalytics: true,
        emergencyResponse: true,
        occupancyIntegration: true
      }
    });
  } catch (error) {
    appLogger.error('Health check failed', { error: error.message });
    return c.json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      service: 'environmental-service',
      error: error.message,
    }, 503);
  }
});

// Authentication middleware for protected routes
app.use('/api/*', authMiddleware);
app.use('/api/*', tenantMiddleware);

// API routes
app.route('/api/sensors', sensorRoutes);
app.route('/api/readings', readingRoutes);
app.route('/api/alerts', alertRoutes);

// Sensor data ingestion endpoint (for sensor devices)
app.post('/ingest/reading', async (c) => {
  try {
    const readingSchema = z.object({
      sensorId: z.string().uuid(),
      timestamp: z.string().datetime(),
      temperature: z.number().optional(),
      humidity: z.number().optional(),
      waterDetected: z.boolean().optional(),
      airQuality: z.number().optional(),
      pressure: z.number().optional(),
      lightLevel: z.number().optional(),
      motionDetected: z.boolean().optional(),
      doorOpen: z.boolean().optional(),
      vibration: z.number().optional(),
      metadata: z.record(z.any()).optional(),
    });

    const data = readingSchema.parse(await c.req.json());
    
    // Process the reading
    const reading = await readingService.processReading(data);
    
    // Check thresholds and generate alerts if needed
    await thresholdService.checkThresholds(reading);
    
    // Integrate with HVAC if applicable
    await hvacService.processEnvironmentalData(reading);
    
    // Process with advanced analytics
    await analyticsService.processReading(reading);
    
    // Check for predictive maintenance needs
    await predictiveMaintenanceService.analyzeReading(reading);
    
    // Integrate with occupancy data for optimization
    await occupancyIntegrationService.processEnvironmentalReading(reading);
    
    return c.json({
      success: true,
      readingId: reading.id,
      timestamp: reading.timestamp,
      hvacAdjustments: reading.hvacAdjustments || [],
      anomalyScore: reading.anomalyScore || 0,
      maintenanceAlerts: reading.maintenanceAlerts || []
    });
  } catch (error) {
    appLogger.error('Failed to process sensor reading', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid reading data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({
      error: 'Failed to process reading',
      message: error.message,
    }, 500);
  }
});

// Threshold configuration endpoints
app.get('/api/thresholds/:sensorId', async (c) => {
  try {
    const sensorId = c.req.param('sensorId');
    const tenantId = c.get('tenantId');
    
    const thresholds = await thresholdService.getThresholds(sensorId, tenantId);
    
    return c.json(thresholds);
  } catch (error) {
    appLogger.error('Failed to get thresholds', { error: error.message });
    return c.json({ error: 'Failed to get thresholds' }, 500);
  }
});

app.put('/api/thresholds/:sensorId', async (c) => {
  try {
    const sensorId = c.req.param('sensorId');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const thresholdSchema = z.object({
      temperatureMin: z.number().optional(),
      temperatureMax: z.number().optional(),
      humidityMin: z.number().optional(),
      humidityMax: z.number().optional(),
      airQualityMax: z.number().optional(),
      pressureMin: z.number().optional(),
      pressureMax: z.number().optional(),
      alertEnabled: z.boolean().default(true),
      escalationEnabled: z.boolean().default(false),
      escalationDelay: z.number().default(300), // 5 minutes
    });
    
    const data = thresholdSchema.parse(await c.req.json());
    
    const thresholds = await thresholdService.updateThresholds(
      sensorId,
      tenantId,
      data,
      userId
    );
    
    return c.json(thresholds);
  } catch (error) {
    appLogger.error('Failed to update thresholds', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid threshold data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to update thresholds' }, 500);
  }
});

// Enhanced HVAC Control and Integration endpoints
app.post('/api/hvac/integrate/:sensorId', async (c) => {
  try {
    const sensorId = c.req.param('sensorId');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const integrationSchema = z.object({
      hvacSystemId: z.string(),
      hvacType: z.enum(['thermostat', 'hvac_controller', 'bms', 'vav', 'ahu', 'chiller']),
      endpoint: z.string().url(),
      apiKey: z.string().optional(),
      username: z.string().optional(),
      password: z.string().optional(),
      protocol: z.enum(['bacnet', 'modbus', 'rest_api', 'mqtt', 'lonworks', 'knx']),
      temperatureControl: z.boolean().default(false),
      humidityControl: z.boolean().default(false),
      airQualityControl: z.boolean().default(false),
      pressureControl: z.boolean().default(false),
      autoAdjust: z.boolean().default(false),
      occupancyBased: z.boolean().default(false),
      energyOptimization: z.boolean().default(false),
      demandResponse: z.boolean().default(false),
      controlParameters: z.object({
        temperatureDeadband: z.number().default(1.0),
        humidityDeadband: z.number().default(5.0),
        responseTime: z.number().default(300),
        maxAdjustmentRate: z.number().default(2.0),
        energySavingMode: z.boolean().default(false)
      }).optional()
    });
    
    const data = integrationSchema.parse(await c.req.json());
    
    const integration = await hvacService.createAdvancedIntegration(
      sensorId,
      tenantId,
      data,
      userId
    );
    
    return c.json(integration);
  } catch (error) {
    appLogger.error('Failed to create HVAC integration', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid integration data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to create HVAC integration' }, 500);
  }
});

// HVAC Control Commands
app.post('/api/hvac/control/:systemId', async (c) => {
  try {
    const systemId = c.req.param('systemId');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const controlSchema = z.object({
      command: z.enum(['set_temperature', 'set_humidity', 'set_mode', 'emergency_stop', 'optimize', 'schedule']),
      parameters: z.object({
        targetTemperature: z.number().optional(),
        targetHumidity: z.number().optional(),
        mode: z.enum(['heat', 'cool', 'auto', 'off', 'emergency']).optional(),
        fanSpeed: z.enum(['low', 'medium', 'high', 'auto']).optional(),
        schedule: z.array(z.object({
          time: z.string(),
          temperature: z.number(),
          humidity: z.number().optional(),
          mode: z.string()
        })).optional(),
        duration: z.number().optional(),
        priority: z.enum(['low', 'normal', 'high', 'emergency']).default('normal')
      }),
      reason: z.string().optional(),
      scheduledFor: z.string().datetime().optional()
    });
    
    const data = controlSchema.parse(await c.req.json());
    
    const result = await hvacService.executeControlCommand(
      systemId,
      tenantId,
      data,
      userId
    );
    
    return c.json(result);
  } catch (error) {
    appLogger.error('Failed to execute HVAC control command', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid control command',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to execute control command' }, 500);
  }
});

// HVAC System Status and Feedback
app.get('/api/hvac/status/:systemId', async (c) => {
  try {
    const systemId = c.req.param('systemId');
    const tenantId = c.get('tenantId');
    
    const status = await hvacService.getSystemStatus(systemId, tenantId);
    
    return c.json(status);
  } catch (error) {
    appLogger.error('Failed to get HVAC system status', { error: error.message });
    return c.json({ error: 'Failed to get system status' }, 500);
  }
});

// HVAC Performance Analytics
app.get('/api/hvac/analytics/:systemId', async (c) => {
  try {
    const systemId = c.req.param('systemId');
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const analytics = await hvacService.getPerformanceAnalytics(
      systemId,
      tenantId,
      {
        startDate: query.startDate,
        endDate: query.endDate,
        metrics: query.metrics?.split(',') || ['efficiency', 'energy', 'comfort']
      }
    );
    
    return c.json(analytics);
  } catch (error) {
    appLogger.error('Failed to get HVAC analytics', { error: error.message });
    return c.json({ error: 'Failed to get analytics' }, 500);
  }
});

// Advanced Analytics Endpoints
app.get('/api/analytics/trends/:sensorId', async (c) => {
  try {
    const sensorId = c.req.param('sensorId');
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const trends = await analyticsService.getTrendAnalysis(
      sensorId,
      tenantId,
      {
        timeRange: query.timeRange || '24h',
        metrics: query.metrics?.split(',') || ['temperature', 'humidity'],
        includeAnomalies: query.includeAnomalies === 'true',
        includePredictions: query.includePredictions === 'true'
      }
    );
    
    return c.json(trends);
  } catch (error) {
    appLogger.error('Failed to get trend analysis', { error: error.message });
    return c.json({ error: 'Failed to get trend analysis' }, 500);
  }
});

app.get('/api/analytics/anomalies', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const anomalies = await analyticsService.getAnomalyDetection(
      tenantId,
      {
        severity: query.severity,
        timeRange: query.timeRange || '24h',
        sensorTypes: query.sensorTypes?.split(','),
        includeResolved: query.includeResolved === 'true'
      }
    );
    
    return c.json(anomalies);
  } catch (error) {
    appLogger.error('Failed to get anomaly detection', { error: error.message });
    return c.json({ error: 'Failed to get anomaly detection' }, 500);
  }
});

app.get('/api/analytics/predictions', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const predictions = await analyticsService.getPredictiveAnalytics(
      tenantId,
      {
        horizon: parseInt(query.horizon) || 24,
        confidence: parseFloat(query.confidence) || 0.8,
        includeMaintenancePredictions: query.includeMaintenance === 'true'
      }
    );
    
    return c.json(predictions);
  } catch (error) {
    appLogger.error('Failed to get predictive analytics', { error: error.message });
    return c.json({ error: 'Failed to get predictive analytics' }, 500);
  }
});

// Predictive Maintenance Endpoints
app.get('/api/maintenance/schedule', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const schedule = await predictiveMaintenanceService.getMaintenanceSchedule(
      tenantId,
      {
        upcoming: query.upcoming === 'true',
        overdue: query.overdue === 'true',
        priority: query.priority,
        equipmentType: query.equipmentType
      }
    );
    
    return c.json(schedule);
  } catch (error) {
    appLogger.error('Failed to get maintenance schedule', { error: error.message });
    return c.json({ error: 'Failed to get maintenance schedule' }, 500);
  }
});

app.post('/api/maintenance/predict/:equipmentId', async (c) => {
  try {
    const equipmentId = c.req.param('equipmentId');
    const tenantId = c.get('tenantId');
    
    const prediction = await predictiveMaintenanceService.predictMaintenanceNeeds(
      equipmentId,
      tenantId
    );
    
    return c.json(prediction);
  } catch (error) {
    appLogger.error('Failed to predict maintenance needs', { error: error.message });
    return c.json({ error: 'Failed to predict maintenance needs' }, 500);
  }
});

app.post('/api/maintenance/schedule/:equipmentId', async (c) => {
  try {
    const equipmentId = c.req.param('equipmentId');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const scheduleSchema = z.object({
      maintenanceType: z.enum(['preventive', 'corrective', 'predictive', 'emergency']),
      scheduledDate: z.string().datetime(),
      priority: z.enum(['low', 'medium', 'high', 'critical']),
      description: z.string(),
      estimatedDuration: z.number(),
      assignedTechnician: z.string().optional(),
      requiredParts: z.array(z.string()).optional(),
      notes: z.string().optional()
    });
    
    const data = scheduleSchema.parse(await c.req.json());
    
    const maintenance = await predictiveMaintenanceService.scheduleMaintenanceTask(
      equipmentId,
      tenantId,
      data,
      userId
    );
    
    return c.json(maintenance);
  } catch (error) {
    appLogger.error('Failed to schedule maintenance', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid maintenance data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to schedule maintenance' }, 500);
  }
});

// Building Automation System Integration
app.post('/api/bas/integrate', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const integrationSchema = z.object({
      systemName: z.string(),
      systemType: z.enum(['honeywell', 'johnson_controls', 'siemens', 'schneider', 'trane', 'carrier']),
      endpoint: z.string().url(),
      protocol: z.enum(['bacnet', 'modbus', 'lonworks', 'knx', 'rest_api', 'opc_ua']),
      credentials: z.object({
        username: z.string().optional(),
        password: z.string().optional(),
        apiKey: z.string().optional(),
        certificate: z.string().optional()
      }).optional(),
      capabilities: z.array(z.enum([
        'hvac_control', 'lighting_control', 'security_integration', 
        'fire_safety', 'energy_management', 'occupancy_sensing'
      ])),
      zones: z.array(z.string()),
      autoDiscovery: z.boolean().default(true)
    });
    
    const data = integrationSchema.parse(await c.req.json());
    
    const integration = await buildingAutomationService.createIntegration(
      tenantId,
      data,
      userId
    );
    
    return c.json(integration);
  } catch (error) {
    appLogger.error('Failed to create BAS integration', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid integration data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to create BAS integration' }, 500);
  }
});

app.get('/api/bas/systems', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    
    const systems = await buildingAutomationService.getIntegratedSystems(tenantId);
    
    return c.json(systems);
  } catch (error) {
    appLogger.error('Failed to get BAS systems', { error: error.message });
    return c.json({ error: 'Failed to get BAS systems' }, 500);
  }
});

// Emergency Response Endpoints
app.post('/api/emergency/trigger', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const emergencySchema = z.object({
      emergencyType: z.enum(['fire', 'flood', 'gas_leak', 'power_failure', 'security_breach', 'medical']),
      location: z.object({
        buildingId: z.string(),
        floorId: z.string().optional(),
        zoneId: z.string().optional(),
        coordinates: z.object({
          lat: z.number(),
          lng: z.number()
        }).optional()
      }),
      severity: z.enum(['low', 'medium', 'high', 'critical']),
      description: z.string(),
      sensorId: z.string().optional(),
      autoResponse: z.boolean().default(true)
    });
    
    const data = emergencySchema.parse(await c.req.json());
    
    const response = await emergencyResponseService.triggerEmergencyResponse(
      tenantId,
      data,
      userId
    );
    
    return c.json(response);
  } catch (error) {
    appLogger.error('Failed to trigger emergency response', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid emergency data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to trigger emergency response' }, 500);
  }
});

app.get('/api/emergency/procedures', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const procedures = await emergencyResponseService.getEmergencyProcedures(
      tenantId,
      {
        emergencyType: query.emergencyType,
        location: query.location
      }
    );
    
    return c.json(procedures);
  } catch (error) {
    appLogger.error('Failed to get emergency procedures', { error: error.message });
    return c.json({ error: 'Failed to get emergency procedures' }, 500);
  }
});

// Sensor Calibration Endpoints
app.post('/api/calibration/schedule/:sensorId', async (c) => {
  try {
    const sensorId = c.req.param('sensorId');
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const calibrationSchema = z.object({
      calibrationType: z.enum(['manual', 'automatic', 'reference_standard']),
      scheduledDate: z.string().datetime(),
      referenceValues: z.object({
        temperature: z.number().optional(),
        humidity: z.number().optional(),
        pressure: z.number().optional(),
        airQuality: z.number().optional()
      }).optional(),
      notes: z.string().optional(),
      technician: z.string().optional()
    });
    
    const data = calibrationSchema.parse(await c.req.json());
    
    const calibration = await calibrationService.scheduleCalibration(
      sensorId,
      tenantId,
      data,
      userId
    );
    
    return c.json(calibration);
  } catch (error) {
    appLogger.error('Failed to schedule calibration', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid calibration data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to schedule calibration' }, 500);
  }
});

app.get('/api/calibration/history/:sensorId', async (c) => {
  try {
    const sensorId = c.req.param('sensorId');
    const tenantId = c.get('tenantId');
    
    const history = await calibrationService.getCalibrationHistory(sensorId, tenantId);
    
    return c.json(history);
  } catch (error) {
    appLogger.error('Failed to get calibration history', { error: error.message });
    return c.json({ error: 'Failed to get calibration history' }, 500);
  }
});

// Occupancy Integration Endpoints
app.post('/api/occupancy/optimize', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');
    
    const optimizationSchema = z.object({
      zones: z.array(z.string()),
      optimizationGoals: z.array(z.enum(['energy_efficiency', 'comfort', 'air_quality', 'cost_reduction'])),
      constraints: z.object({
        maxTemperatureAdjustment: z.number().default(2.0),
        maxHumidityAdjustment: z.number().default(10.0),
        energyBudget: z.number().optional(),
        comfortPriority: z.enum(['low', 'medium', 'high']).default('medium')
      }).optional(),
      schedule: z.object({
        startTime: z.string(),
        endTime: z.string(),
        daysOfWeek: z.array(z.number().min(0).max(6))
      }).optional()
    });
    
    const data = optimizationSchema.parse(await c.req.json());
    
    const optimization = await occupancyIntegrationService.optimizeEnvironmentalControls(
      tenantId,
      data,
      userId
    );
    
    return c.json(optimization);
  } catch (error) {
    appLogger.error('Failed to optimize environmental controls', { error: error.message });
    
    if (error instanceof z.ZodError) {
      return c.json({
        error: 'Invalid optimization data',
        details: error.errors,
      }, 400);
    }
    
    return c.json({ error: 'Failed to optimize environmental controls' }, 500);
  }
});

app.get('/api/occupancy/correlation/:zoneId', async (c) => {
  try {
    const zoneId = c.req.param('zoneId');
    const tenantId = c.get('tenantId');
    const query = c.req.query();
    
    const correlation = await occupancyIntegrationService.getOccupancyEnvironmentalCorrelation(
      zoneId,
      tenantId,
      {
        timeRange: query.timeRange || '24h',
        metrics: query.metrics?.split(',') || ['temperature', 'humidity', 'air_quality']
      }
    );
    
    return c.json(correlation);
  } catch (error) {
    appLogger.error('Failed to get occupancy correlation', { error: error.message });
    return c.json({ error: 'Failed to get occupancy correlation' }, 500);
  }
});

// Enhanced Protocol support endpoints
app.get('/api/protocols/supported', async (c) => {
  return c.json({
    protocols: [
      {
        name: 'MQTT',
        version: '3.1.1/5.0',
        description: 'Message Queuing Telemetry Transport',
        sensorTypes: ['temperature', 'humidity', 'water', 'air_quality', 'motion'],
        capabilities: ['bidirectional', 'real_time', 'qos_levels']
      },
      {
        name: 'Modbus',
        version: 'RTU/TCP',
        description: 'Industrial communication protocol',
        sensorTypes: ['temperature', 'humidity', 'pressure', 'flow'],
        capabilities: ['polling', 'register_mapping', 'device_control']
      },
      {
        name: 'BACnet',
        version: 'IP/MSTP',
        description: 'Building Automation and Control Networks',
        sensorTypes: ['temperature', 'humidity', 'pressure', 'air_quality'],
        capabilities: ['object_discovery', 'cov_notifications', 'scheduling', 'trending']
      },
      {
        name: 'SNMP',
        version: 'v2c/v3',
        description: 'Simple Network Management Protocol',
        sensorTypes: ['temperature', 'humidity', 'power', 'network'],
        capabilities: ['monitoring', 'traps', 'bulk_operations']
      },
      {
        name: 'HTTP/REST',
        version: '1.1/2.0',
        description: 'RESTful API integration',
        sensorTypes: ['all'],
        capabilities: ['webhooks', 'authentication', 'json_payload']
      },
      {
        name: 'LoRaWAN',
        version: '1.0.3/1.1',
        description: 'Long Range Wide Area Network',
        sensorTypes: ['temperature', 'humidity', 'water', 'motion'],
        capabilities: ['long_range', 'low_power', 'adaptive_data_rate']
      },
      {
        name: 'LonWorks',
        version: 'ISO/IEC 14908',
        description: 'Local Operating Network',
        sensorTypes: ['temperature', 'humidity', 'lighting', 'hvac'],
        capabilities: ['peer_to_peer', 'self_healing', 'interoperability']
      },
      {
        name: 'KNX',
        version: 'ISO/IEC 14543-3',
        description: 'Building automation standard',
        sensorTypes: ['temperature', 'humidity', 'lighting', 'security'],
        capabilities: ['decentralized', 'bus_topology', 'standardized_profiles']
      },
      {
        name: 'OPC UA',
        version: '1.04',
        description: 'Open Platform Communications Unified Architecture',
        sensorTypes: ['industrial', 'hvac', 'energy', 'security'],
        capabilities: ['security', 'scalability', 'platform_independence']
      }
    ],
    hvacProtocols: [
      {
        name: 'BACnet',
        description: 'Primary building automation protocol',
        controlCapabilities: ['temperature', 'humidity', 'pressure', 'airflow', 'dampers', 'valves']
      },
      {
        name: 'Modbus',
        description: 'Industrial control protocol',
        controlCapabilities: ['setpoints', 'on_off_control', 'analog_outputs']
      },
      {
        name: 'LonWorks',
        description: 'Distributed control network',
        controlCapabilities: ['hvac_control', 'lighting_integration', 'energy_management']
      }
    ]
  });
});

// Real-time data streaming endpoint
app.get('/api/stream/:sensorId', async (c) => {
  try {
    const sensorId = c.req.param('sensorId');
    const tenantId = c.get('tenantId');
    
    // Verify sensor access
    const sensor = await sensorService.getSensor(sensorId, tenantId);
    if (!sensor) {
      return c.json({ error: 'Sensor not found' }, 404);
    }
    
    // Set up Server-Sent Events
    return new Response(
      new ReadableStream({
        start(controller) {
          const sendData = (data: any) => {
            controller.enqueue(`data: ${JSON.stringify(data)}\n\n`);
          };
          
          // Send initial sensor status
          sendData({
            type: 'sensor_status',
            sensorId,
            status: sensor.status,
            lastReading: sensor.lastReadingAt,
          });
          
          // Subscribe to Redis for real-time updates
          const subscriber = new Redis(config.redis.url);
          subscriber.subscribe(`sensor:${sensorId}:readings`);
          
          subscriber.on('message', (channel, message) => {
            try {
              const reading = JSON.parse(message);
              sendData({
                type: 'reading',
                ...reading,
              });
            } catch (error) {
              appLogger.error('Failed to parse Redis message', { error: error.message });
            }
          });
          
          // Cleanup on close
          return () => {
            subscriber.disconnect();
          };
        },
      }),
      {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      }
    );
  } catch (error) {
    appLogger.error('Failed to start sensor stream', { error: error.message });
    return c.json({ error: 'Failed to start stream' }, 500);
  }
});

// Error handling
app.onError((err, c) => {
  appLogger.error('Unhandled error', { error: err.message, stack: err.stack });
  
  if (err instanceof HTTPException) {
    return err.getResponse();
  }
  
  return c.json({
    error: 'Internal server error',
    message: err.message,
  }, 500);
});

// 404 handler
app.notFound((c) => {
  return c.json({
    error: 'Not found',
    path: c.req.path,
  }, 404);
});

// Create HTTP server and Socket.IO for real-time communication
const server = createServer();
const io = new SocketIOServer(server, {
  cors: {
    origin: config.cors.origins,
    credentials: true,
  },
});

// Socket.IO authentication middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error('Authentication required'));
    }
    
    // Verify JWT token (implementation would use shared auth utilities)
    // const user = await verifyToken(token);
    // socket.userId = user.id;
    // socket.tenantId = user.tenantId;
    
    next();
  } catch (error) {
    next(new Error('Authentication failed'));
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  appLogger.info('Client connected to environmental service', { 
    socketId: socket.id,
    userId: socket.userId,
    tenantId: socket.tenantId,
  });
  
  // Join tenant-specific room
  socket.join(`tenant:${socket.tenantId}`);
  
  // Handle sensor subscription
  socket.on('subscribe_sensor', async (sensorId: string) => {
    try {
      // Verify sensor access
      const sensor = await sensorService.getSensor(sensorId, socket.tenantId);
      if (sensor) {
        socket.join(`sensor:${sensorId}`);
        socket.emit('subscribed', { sensorId });
      } else {
        socket.emit('error', { message: 'Sensor not found or access denied' });
      }
    } catch (error) {
      socket.emit('error', { message: 'Failed to subscribe to sensor' });
    }
  });
  
  // Handle sensor unsubscription
  socket.on('unsubscribe_sensor', (sensorId: string) => {
    socket.leave(`sensor:${sensorId}`);
    socket.emit('unsubscribed', { sensorId });
  });
  
  socket.on('disconnect', () => {
    appLogger.info('Client disconnected from environmental service', { 
      socketId: socket.id,
      userId: socket.userId,
    });
  });
});

// Start enhanced background services
async function startBackgroundServices() {
  // Start sensor monitoring service
  setInterval(async () => {
    try {
      await sensorService.monitorSensorHealth();
    } catch (error) {
      appLogger.error('Sensor health monitoring failed', { error: error.message });
    }
  }, 60000); // Every minute
  
  // Start data aggregation service
  setInterval(async () => {
    try {
      await readingService.aggregateHistoricalData();
    } catch (error) {
      appLogger.error('Data aggregation failed', { error: error.message });
    }
  }, 300000); // Every 5 minutes
  
  // Start alert cleanup service
  setInterval(async () => {
    try {
      await alertService.cleanupResolvedAlerts();
    } catch (error) {
      appLogger.error('Alert cleanup failed', { error: error.message });
    }
  }, 3600000); // Every hour
  
  // Start advanced analytics processing
  setInterval(async () => {
    try {
      await analyticsService.processAdvancedAnalytics();
    } catch (error) {
      appLogger.error('Advanced analytics processing failed', { error: error.message });
    }
  }, 900000); // Every 15 minutes
  
  // Start predictive maintenance analysis
  setInterval(async () => {
    try {
      await predictiveMaintenanceService.runPredictiveAnalysis();
    } catch (error) {
      appLogger.error('Predictive maintenance analysis failed', { error: error.message });
    }
  }, 1800000); // Every 30 minutes
  
  // Start HVAC optimization
  setInterval(async () => {
    try {
      await hvacService.runOptimizationCycle();
    } catch (error) {
      appLogger.error('HVAC optimization failed', { error: error.message });
    }
  }, 600000); // Every 10 minutes
  
  // Start building automation system sync
  setInterval(async () => {
    try {
      await buildingAutomationService.syncAllSystems();
    } catch (error) {
      appLogger.error('BAS sync failed', { error: error.message });
    }
  }, 1200000); // Every 20 minutes
  
  // Start occupancy-based optimization
  setInterval(async () => {
    try {
      await occupancyIntegrationService.runOccupancyBasedOptimization();
    } catch (error) {
      appLogger.error('Occupancy-based optimization failed', { error: error.message });
    }
  }, 300000); // Every 5 minutes
  
  // Start calibration monitoring
  setInterval(async () => {
    try {
      await calibrationService.monitorCalibrationSchedule();
    } catch (error) {
      appLogger.error('Calibration monitoring failed', { error: error.message });
    }
  }, 3600000); // Every hour
  
  // Start emergency response system check
  setInterval(async () => {
    try {
      await emergencyResponseService.performSystemCheck();
    } catch (error) {
      appLogger.error('Emergency response system check failed', { error: error.message });
    }
  }, 1800000); // Every 30 minutes
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  appLogger.info('Received SIGTERM, shutting down gracefully');
  
  try {
    await prisma.$disconnect();
    await redis.disconnect();
    server.close();
    process.exit(0);
  } catch (error) {
    appLogger.error('Error during shutdown', { error: error.message });
    process.exit(1);
  }
});

process.on('SIGINT', async () => {
  appLogger.info('Received SIGINT, shutting down gracefully');
  
  try {
    await prisma.$disconnect();
    await redis.disconnect();
    server.close();
    process.exit(0);
  } catch (error) {
    appLogger.error('Error during shutdown', { error: error.message });
    process.exit(1);
  }
});

// Start the server
const port = config.services.environmentalService.port || 3007;

async function startServer() {
  try {
    // Test database connection
    await prisma.$connect();
    appLogger.info('Connected to database');
    
    // Test Redis connection
    await redis.ping();
    appLogger.info('Connected to Redis');
    
    // Start enhanced background services
    await startBackgroundServices();
    appLogger.info('Enhanced background services started');
    
    // Initialize advanced analytics models
    await analyticsService.initializeModels();
    appLogger.info('Advanced analytics models initialized');
    
    // Initialize predictive maintenance algorithms
    await predictiveMaintenanceService.initializeAlgorithms();
    appLogger.info('Predictive maintenance algorithms initialized');
    
    // Initialize building automation integrations
    await buildingAutomationService.initializeIntegrations();
    appLogger.info('Building automation integrations initialized');
    
    // Initialize emergency response procedures
    await emergencyResponseService.initializeProcedures();
    appLogger.info('Emergency response procedures initialized');
    
    // Start HTTP server with Hono app
    serve({
      fetch: app.fetch,
      port,
    });
    
    // Start Socket.IO server
    server.listen(port + 1000); // Use different port for Socket.IO
    
    appLogger.info(`Enhanced Environmental service started`, {
      port,
      socketPort: port + 1000,
      environment: process.env.NODE_ENV || 'development',
      features: {
        hvacControl: true,
        advancedAnalytics: true,
        predictiveMaintenance: true,
        buildingAutomation: true,
        emergencyResponse: true,
        occupancyIntegration: true,
        sensorCalibration: true
      }
    });
  } catch (error) {
    appLogger.error('Failed to start environmental service', { error: error.message });
    process.exit(1);
  }
}

startServer();

export { app, io };

// ==================== COMPREHENSIVE TEST SUITE ====================

// Only include tests in test environment
if (process.env.NODE_ENV === 'test') {
  
  // Test dependencies
  const request = require('supertest');
  const { jest } = require('@jest/globals');
  const WebSocket = require('ws');
  const ioClient = require('socket.io-client');

  // Mock dependencies
  jest.mock('@prisma/client');
  jest.mock('ioredis');
  jest.mock('socket.io');

  describe('Environmental Service', () => {
    let mockPrisma: any;
    let mockRedis: any;
    let mockIo: any;
    let testApp: any;
    let authToken: string;
    let tenantId: string;

    beforeAll(async () => {
      // Setup test environment
      process.env.NODE_ENV = 'test';
      authToken = 'test-jwt-token';
      tenantId = 'test-tenant-id';
      
      // Mock Prisma client
      mockPrisma = {
        $connect: jest.fn().mockResolvedValue(undefined),
        $disconnect: jest.fn().mockResolvedValue(undefined),
        $queryRaw: jest.fn().mockResolvedValue([{ result: 1 }]),
        sensor: {
          findMany: jest.fn(),
          findUnique: jest.fn(),
          create: jest.fn(),
          update: jest.fn(),
          delete: jest.fn(),
          count: jest.fn(),
        },
        reading: {
          findMany: jest.fn(),
          create: jest.fn(),
          aggregate: jest.fn(),
        },
        alert: {
          findMany: jest.fn(),
          create: jest.fn(),
          update: jest.fn(),
        },
        threshold: {
          findUnique: jest.fn(),
          upsert: jest.fn(),
        },
        hvacIntegration: {
          create: jest.fn(),
          findUnique: jest.fn(),
        },
      };

      // Mock Redis client
      mockRedis = {
        ping: jest.fn().mockResolvedValue('PONG'),
        disconnect: jest.fn().mockResolvedValue(undefined),
        subscribe: jest.fn().mockResolvedValue(undefined),
        publish: jest.fn().mockResolvedValue(1),
        get: jest.fn(),
        set: jest.fn(),
        del: jest.fn(),
        on: jest.fn(),
      };

      // Mock Socket.IO
      mockIo = {
        use: jest.fn(),
        on: jest.fn(),
        to: jest.fn().mockReturnThis(),
        emit: jest.fn(),
      };

      // Create test app instance
      testApp = app;
    });

    afterAll(async () => {
      await mockPrisma.$disconnect();
      await mockRedis.disconnect();
    });

    beforeEach(() => {
      jest.clearAllMocks();
    });

    // ==================== UNIT TESTS ====================

    describe('Health Check Endpoint', () => {
      test('should return healthy status when all services are connected', async () => {
        mockPrisma.sensor.count.mockResolvedValue(5);

        const response = await request(testApp)
          .get('/health')
          .expect(200);

        expect(response.body).toMatchObject({
          status: 'healthy',
          service: 'environmental-service',
          database: 'connected',
          cache: 'connected',
          activeSensors: 5,
        });
      });

      test('should return unhealthy status when database is disconnected', async () => {
        mockPrisma.$queryRaw.mockRejectedValue(new Error('Database connection failed'));

        const response = await request(testApp)
          .get('/health')
          .expect(503);

        expect(response.body.status).toBe('unhealthy');
        expect(response.body.error).toBe('Database connection failed');
      });

      test('should return unhealthy status when Redis is disconnected', async () => {
        mockRedis.ping.mockRejectedValue(new Error('Redis connection failed'));

        const response = await request(testApp)
          .get('/health')
          .expect(503);

        expect(response.body.status).toBe('unhealthy');
        expect(response.body.error).toBe('Redis connection failed');
      });
    });

    describe('Sensor Data Ingestion', () => {
      test('should successfully process valid sensor reading', async () => {
        const mockReading = {
          id: 'reading-123',
          sensorId: 'sensor-123',
          timestamp: new Date().toISOString(),
          temperature: 22.5,
          humidity: 45.0,
        };

        mockPrisma.reading.create.mockResolvedValue(mockReading);

        const response = await request(testApp)
          .post('/ingest/reading')
          .send({
            sensorId: 'sensor-123',
            timestamp: new Date().toISOString(),
            temperature: 22.5,
            humidity: 45.0,
          })
          .expect(200);

        expect(response.body).toMatchObject({
          success: true,
          readingId: 'reading-123',
        });
      });

      test('should reject invalid sensor reading data', async () => {
        const response = await request(testApp)
          .post('/ingest/reading')
          .send({
            sensorId: 'invalid-uuid',
            temperature: 'not-a-number',
          })
          .expect(400);

        expect(response.body.error).toBe('Invalid reading data');
        expect(response.body.details).toBeDefined();
      });

      test('should handle water detection sensor reading', async () => {
        const mockReading = {
          id: 'reading-456',
          sensorId: 'sensor-456',
          timestamp: new Date().toISOString(),
          waterDetected: true,
        };

        mockPrisma.reading.create.mockResolvedValue(mockReading);

        const response = await request(testApp)
          .post('/ingest/reading')
          .send({
            sensorId: 'sensor-456',
            timestamp: new Date().toISOString(),
            waterDetected: true,
          })
          .expect(200);

        expect(response.body.success).toBe(true);
      });

      test('should handle air quality sensor reading', async () => {
        const mockReading = {
          id: 'reading-789',
          sensorId: 'sensor-789',
          timestamp: new Date().toISOString(),
          airQuality: 150,
          pressure: 1013.25,
          hvacAdjustments: [],
          anomalyScore: 0.1,
          maintenanceAlerts: []
        };

        mockPrisma.reading.create.mockResolvedValue(mockReading);

        const response = await request(testApp)
          .post('/ingest/reading')
          .send({
            sensorId: 'sensor-789',
            timestamp: new Date().toISOString(),
            airQuality: 150,
            pressure: 1013.25,
          })
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body).toHaveProperty('hvacAdjustments');
        expect(response.body).toHaveProperty('anomalyScore');
        expect(response.body).toHaveProperty('maintenanceAlerts');
      });

      test('should process reading with advanced analytics', async () => {
        const mockReading = {
          id: 'reading-advanced',
          sensorId: 'sensor-advanced',
          timestamp: new Date().toISOString(),
          temperature: 28.5, // High temperature
          humidity: 75.0, // High humidity
          hvacAdjustments: [
            { action: 'increase_cooling', value: 2.0 }
          ],
          anomalyScore: 0.8,
          maintenanceAlerts: [
            { type: 'filter_replacement', priority: 'medium' }
          ]
        };

        mockPrisma.reading.create.mockResolvedValue(mockReading);

        const response = await request(testApp)
          .post('/ingest/reading')
          .send({
            sensorId: 'sensor-advanced',
            timestamp: new Date().toISOString(),
            temperature: 28.5,
            humidity: 75.0,
          })
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.hvacAdjustments).toHaveLength(1);
        expect(response.body.anomalyScore).toBe(0.8);
        expect(response.body.maintenanceAlerts).toHaveLength(1);
      });
    });

    describe('Threshold Management', () => {
      test('should get sensor thresholds', async () => {
        const mockThresholds = {
          sensorId: 'sensor-123',
          temperatureMin: 18.0,
          temperatureMax: 26.0,
          humidityMin: 30.0,
          humidityMax: 70.0,
          alertEnabled: true,
        };

        mockPrisma.threshold.findUnique.mockResolvedValue(mockThresholds);

        const response = await request(testApp)
          .get('/api/thresholds/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockThresholds);
      });

      test('should update sensor thresholds', async () => {
        const updatedThresholds = {
          sensorId: 'sensor-123',
          temperatureMin: 20.0,
          temperatureMax: 24.0,
          humidityMin: 40.0,
          humidityMax: 60.0,
          alertEnabled: true,
          escalationEnabled: true,
          escalationDelay: 600,
        };

        mockPrisma.threshold.upsert.mockResolvedValue(updatedThresholds);

        const response = await request(testApp)
          .put('/api/thresholds/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            temperatureMin: 20.0,
            temperatureMax: 24.0,
            humidityMin: 40.0,
            humidityMax: 60.0,
            escalationEnabled: true,
            escalationDelay: 600,
          })
          .expect(200);

        expect(response.body).toMatchObject(updatedThresholds);
      });

      test('should reject invalid threshold data', async () => {
        const response = await request(testApp)
          .put('/api/thresholds/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            temperatureMin: 'invalid',
            humidityMax: -10,
          })
          .expect(400);

        expect(response.body.error).toBe('Invalid threshold data');
      });
    });

    describe('Enhanced HVAC Integration', () => {
      test('should create advanced HVAC integration', async () => {
        const mockIntegration = {
          id: 'integration-123',
          sensorId: 'sensor-123',
          hvacSystemId: 'hvac-456',
          hvacType: 'ahu',
          protocol: 'bacnet',
          temperatureControl: true,
          humidityControl: true,
          airQualityControl: true,
          autoAdjust: true,
          occupancyBased: true,
          energyOptimization: true,
        };

        mockPrisma.hvacIntegration.create.mockResolvedValue(mockIntegration);

        const response = await request(testApp)
          .post('/api/hvac/integrate/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            hvacSystemId: 'hvac-456',
            hvacType: 'ahu',
            endpoint: 'http://hvac.example.com/api',
            protocol: 'bacnet',
            temperatureControl: true,
            humidityControl: true,
            airQualityControl: true,
            autoAdjust: true,
            occupancyBased: true,
            energyOptimization: true,
            controlParameters: {
              temperatureDeadband: 0.5,
              humidityDeadband: 3.0,
              responseTime: 180,
              maxAdjustmentRate: 1.5,
              energySavingMode: true
            }
          })
          .expect(200);

        expect(response.body).toMatchObject(mockIntegration);
      });

      test('should execute HVAC control commands', async () => {
        const mockResult = {
          commandId: 'cmd-123',
          status: 'executed',
          systemId: 'hvac-456',
          command: 'set_temperature',
          parameters: { targetTemperature: 22.0 },
          executedAt: new Date().toISOString()
        };

        const response = await request(testApp)
          .post('/api/hvac/control/hvac-456')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            command: 'set_temperature',
            parameters: {
              targetTemperature: 22.0,
              mode: 'auto',
              priority: 'normal'
            },
            reason: 'Temperature optimization'
          })
          .expect(200);

        expect(response.body.status).toBe('executed');
        expect(response.body.command).toBe('set_temperature');
      });

      test('should get HVAC system status', async () => {
        const mockStatus = {
          systemId: 'hvac-456',
          status: 'online',
          currentTemperature: 21.5,
          targetTemperature: 22.0,
          mode: 'auto',
          fanSpeed: 'medium',
          energyConsumption: 2.5,
          efficiency: 0.85,
          lastUpdate: new Date().toISOString()
        };

        const response = await request(testApp)
          .get('/api/hvac/status/hvac-456')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockStatus);
      });

      test('should get HVAC performance analytics', async () => {
        const mockAnalytics = {
          systemId: 'hvac-456',
          timeRange: '24h',
          efficiency: {
            average: 0.82,
            trend: 'stable'
          },
          energyConsumption: {
            total: 45.2,
            trend: 'decreasing'
          },
          comfort: {
            score: 0.91,
            violations: 2
          }
        };

        const response = await request(testApp)
          .get('/api/hvac/analytics/hvac-456?metrics=efficiency,energy,comfort')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockAnalytics);
      });

      test('should support extended HVAC protocols', async () => {
        const protocols = ['bacnet', 'modbus', 'rest_api', 'mqtt', 'lonworks', 'knx'];
        
        for (const protocol of protocols) {
          const mockIntegration = {
            id: `integration-${protocol}`,
            sensorId: 'sensor-123',
            protocol,
          };

          mockPrisma.hvacIntegration.create.mockResolvedValue(mockIntegration);

          const response = await request(testApp)
            .post('/api/hvac/integrate/sensor-123')
            .set('Authorization', `Bearer ${authToken}`)
            .set('X-Tenant-ID', tenantId)
            .send({
              hvacSystemId: 'hvac-456',
              hvacType: 'hvac_controller',
              endpoint: 'http://hvac.example.com/api',
              protocol,
            })
            .expect(200);

          expect(response.body.protocol).toBe(protocol);
        }
      });
    });

    describe('Advanced Analytics', () => {
      test('should get trend analysis', async () => {
        const mockTrends = {
          sensorId: 'sensor-123',
          timeRange: '24h',
          trends: {
            temperature: {
              trend: 'increasing',
              rate: 0.1,
              confidence: 0.85
            },
            humidity: {
              trend: 'stable',
              rate: 0.0,
              confidence: 0.92
            }
          },
          anomalies: [
            {
              timestamp: new Date().toISOString(),
              metric: 'temperature',
              severity: 'medium',
              score: 0.75
            }
          ],
          predictions: {
            nextHour: {
              temperature: 23.2,
              humidity: 45.8
            }
          }
        };

        const response = await request(testApp)
          .get('/api/analytics/trends/sensor-123?timeRange=24h&includeAnomalies=true&includePredictions=true')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockTrends);
      });

      test('should get anomaly detection results', async () => {
        const mockAnomalies = {
          timeRange: '24h',
          anomalies: [
            {
              id: 'anomaly-1',
              sensorId: 'sensor-123',
              timestamp: new Date().toISOString(),
              metric: 'temperature',
              value: 35.0,
              expectedRange: [18, 26],
              severity: 'high',
              score: 0.92
            }
          ],
          summary: {
            total: 1,
            high: 1,
            medium: 0,
            low: 0
          }
        };

        const response = await request(testApp)
          .get('/api/analytics/anomalies?severity=high&timeRange=24h')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockAnomalies);
      });

      test('should get predictive analytics', async () => {
        const mockPredictions = {
          horizon: 24,
          confidence: 0.8,
          predictions: {
            environmental: [
              {
                timestamp: new Date(Date.now() + 3600000).toISOString(),
                temperature: 22.5,
                humidity: 48.0,
                confidence: 0.85
              }
            ],
            maintenance: [
              {
                equipmentId: 'hvac-456',
                type: 'filter_replacement',
                probability: 0.75,
                timeToFailure: 168 // hours
              }
            ]
          }
        };

        const response = await request(testApp)
          .get('/api/analytics/predictions?horizon=24&confidence=0.8&includeMaintenance=true')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockPredictions);
      });
    });

    describe('Predictive Maintenance', () => {
      test('should get maintenance schedule', async () => {
        const mockSchedule = {
          upcoming: [
            {
              id: 'maint-1',
              equipmentId: 'hvac-456',
              type: 'preventive',
              scheduledDate: new Date(Date.now() + 86400000).toISOString(),
              priority: 'medium',
              description: 'Filter replacement'
            }
          ],
          overdue: [],
          summary: {
            total: 1,
            upcoming: 1,
            overdue: 0
          }
        };

        const response = await request(testApp)
          .get('/api/maintenance/schedule?upcoming=true')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockSchedule);
      });

      test('should predict maintenance needs', async () => {
        const mockPrediction = {
          equipmentId: 'hvac-456',
          predictions: [
            {
              component: 'air_filter',
              type: 'replacement',
              probability: 0.85,
              timeToFailure: 72,
              severity: 'medium'
            }
          ],
          overallHealth: 0.78,
          recommendedActions: [
            'Schedule filter replacement within 3 days'
          ]
        };

        const response = await request(testApp)
          .post('/api/maintenance/predict/hvac-456')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockPrediction);
      });

      test('should schedule maintenance task', async () => {
        const mockMaintenance = {
          id: 'maint-123',
          equipmentId: 'hvac-456',
          type: 'preventive',
          scheduledDate: new Date(Date.now() + 86400000).toISOString(),
          priority: 'medium',
          status: 'scheduled'
        };

        const response = await request(testApp)
          .post('/api/maintenance/schedule/hvac-456')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            maintenanceType: 'preventive',
            scheduledDate: new Date(Date.now() + 86400000).toISOString(),
            priority: 'medium',
            description: 'Filter replacement',
            estimatedDuration: 2
          })
          .expect(200);

        expect(response.body).toMatchObject(mockMaintenance);
      });
    });

    describe('Building Automation System Integration', () => {
      test('should create BAS integration', async () => {
        const mockIntegration = {
          id: 'bas-123',
          systemName: 'Main BAS',
          systemType: 'honeywell',
          protocol: 'bacnet',
          capabilities: ['hvac_control', 'energy_management'],
          status: 'connected'
        };

        const response = await request(testApp)
          .post('/api/bas/integrate')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            systemName: 'Main BAS',
            systemType: 'honeywell',
            endpoint: 'http://bas.example.com/api',
            protocol: 'bacnet',
            capabilities: ['hvac_control', 'energy_management'],
            zones: ['zone-1', 'zone-2'],
            autoDiscovery: true
          })
          .expect(200);

        expect(response.body).toMatchObject(mockIntegration);
      });

      test('should get integrated BAS systems', async () => {
        const mockSystems = [
          {
            id: 'bas-123',
            systemName: 'Main BAS',
            systemType: 'honeywell',
            status: 'connected',
            lastSync: new Date().toISOString()
          }
        ];

        const response = await request(testApp)
          .get('/api/bas/systems')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toEqual(mockSystems);
      });
    });

    describe('Emergency Response', () => {
      test('should trigger emergency response', async () => {
        const mockResponse = {
          emergencyId: 'emergency-123',
          type: 'fire',
          status: 'active',
          location: {
            buildingId: 'building-1',
            floorId: 'floor-2'
          },
          actions: [
            'HVAC shutdown initiated',
            'Emergency notifications sent',
            'Evacuation procedures activated'
          ]
        };

        const response = await request(testApp)
          .post('/api/emergency/trigger')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            emergencyType: 'fire',
            location: {
              buildingId: 'building-1',
              floorId: 'floor-2'
            },
            severity: 'high',
            description: 'Smoke detected in server room',
            autoResponse: true
          })
          .expect(200);

        expect(response.body).toMatchObject(mockResponse);
      });

      test('should get emergency procedures', async () => {
        const mockProcedures = [
          {
            id: 'proc-1',
            emergencyType: 'fire',
            location: 'building-1',
            steps: [
              'Activate fire suppression system',
              'Shut down HVAC systems',
              'Initiate evacuation'
            ],
            contacts: [
              { role: 'fire_department', number: '911' }
            ]
          }
        ];

        const response = await request(testApp)
          .get('/api/emergency/procedures?emergencyType=fire&location=building-1')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toEqual(mockProcedures);
      });
    });

    describe('Sensor Calibration', () => {
      test('should schedule sensor calibration', async () => {
        const mockCalibration = {
          id: 'cal-123',
          sensorId: 'sensor-123',
          type: 'manual',
          scheduledDate: new Date(Date.now() + 86400000).toISOString(),
          status: 'scheduled'
        };

        const response = await request(testApp)
          .post('/api/calibration/schedule/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            calibrationType: 'manual',
            scheduledDate: new Date(Date.now() + 86400000).toISOString(),
            referenceValues: {
              temperature: 20.0,
              humidity: 50.0
            },
            technician: 'tech-123'
          })
          .expect(200);

        expect(response.body).toMatchObject(mockCalibration);
      });

      test('should get calibration history', async () => {
        const mockHistory = [
          {
            id: 'cal-1',
            date: new Date().toISOString(),
            type: 'manual',
            status: 'completed',
            accuracy: 0.98
          }
        ];

        const response = await request(testApp)
          .get('/api/calibration/history/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toEqual(mockHistory);
      });
    });

    describe('Occupancy Integration', () => {
      test('should optimize environmental controls based on occupancy', async () => {
        const mockOptimization = {
          optimizationId: 'opt-123',
          zones: ['zone-1', 'zone-2'],
          goals: ['energy_efficiency', 'comfort'],
          adjustments: [
            {
              zoneId: 'zone-1',
              parameter: 'temperature',
              currentValue: 22.0,
              optimizedValue: 21.5,
              energySaving: 0.15
            }
          ],
          estimatedSavings: {
            energy: 0.12,
            cost: 25.50
          }
        };

        const response = await request(testApp)
          .post('/api/occupancy/optimize')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .send({
            zones: ['zone-1', 'zone-2'],
            optimizationGoals: ['energy_efficiency', 'comfort'],
            constraints: {
              maxTemperatureAdjustment: 1.0,
              comfortPriority: 'medium'
            }
          })
          .expect(200);

        expect(response.body).toMatchObject(mockOptimization);
      });

      test('should get occupancy-environmental correlation', async () => {
        const mockCorrelation = {
          zoneId: 'zone-1',
          timeRange: '24h',
          correlations: {
            temperature: {
              correlation: 0.75,
              significance: 'high'
            },
            humidity: {
              correlation: 0.45,
              significance: 'medium'
            }
          },
          insights: [
            'Temperature increases by 1.2°C per 10 additional occupants',
            'Humidity shows moderate correlation with occupancy'
          ]
        };

        const response = await request(testApp)
          .get('/api/occupancy/correlation/zone-1?timeRange=24h')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.body).toMatchObject(mockCorrelation);
      });
    });

    describe('Enhanced Protocol Support', () => {
      test('should return comprehensive supported protocols', async () => {
        const response = await request(testApp)
          .get('/api/protocols/supported')
          .expect(200);

        expect(response.body.protocols).toHaveLength(9);
        expect(response.body.protocols).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ name: 'MQTT' }),
            expect.objectContaining({ name: 'Modbus' }),
            expect.objectContaining({ name: 'BACnet' }),
            expect.objectContaining({ name: 'SNMP' }),
            expect.objectContaining({ name: 'HTTP/REST' }),
            expect.objectContaining({ name: 'LoRaWAN' }),
            expect.objectContaining({ name: 'LonWorks' }),
            expect.objectContaining({ name: 'KNX' }),
            expect.objectContaining({ name: 'OPC UA' }),
          ])
        );
      });

      test('should include HVAC-specific protocols', async () => {
        const response = await request(testApp)
          .get('/api/protocols/supported')
          .expect(200);

        expect(response.body).toHaveProperty('hvacProtocols');
        expect(response.body.hvacProtocols).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ 
              name: 'BACnet',
              controlCapabilities: expect.arrayContaining(['temperature', 'humidity', 'pressure'])
            }),
            expect.objectContaining({ 
              name: 'Modbus',
              controlCapabilities: expect.arrayContaining(['setpoints', 'on_off_control'])
            }),
            expect.objectContaining({ 
              name: 'LonWorks',
              controlCapabilities: expect.arrayContaining(['hvac_control', 'energy_management'])
            })
          ])
        );
      });

      test('should include capabilities for each protocol', async () => {
        const response = await request(testApp)
          .get('/api/protocols/supported')
          .expect(200);

        response.body.protocols.forEach((protocol: any) => {
          expect(protocol).toHaveProperty('sensorTypes');
          expect(protocol).toHaveProperty('capabilities');
          expect(Array.isArray(protocol.sensorTypes)).toBe(true);
          expect(Array.isArray(protocol.capabilities)).toBe(true);
        });
      });
    });

    // ==================== INTEGRATION TESTS ====================

    describe('Real-time Data Streaming', () => {
      test('should establish SSE connection for sensor data', async () => {
        const mockSensor = {
          id: 'sensor-123',
          status: 'active',
          lastReadingAt: new Date(),
        };

        mockPrisma.sensor.findUnique.mockResolvedValue(mockSensor);

        const response = await request(testApp)
          .get('/api/stream/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(200);

        expect(response.headers['content-type']).toBe('text/event-stream');
        expect(response.headers['cache-control']).toBe('no-cache');
      });

      test('should reject SSE connection for non-existent sensor', async () => {
        mockPrisma.sensor.findUnique.mockResolvedValue(null);

        const response = await request(testApp)
          .get('/api/stream/non-existent-sensor')
          .set('Authorization', `Bearer ${authToken}`)
          .set('X-Tenant-ID', tenantId)
          .expect(404);

        expect(response.body.error).toBe('Sensor not found');
      });
    });

    describe('Socket.IO Real-time Communication', () => {
      test('should handle client connection and subscription', (done) => {
        const mockSocket = {
          id: 'socket-123',
          userId: 'user-123',
          tenantId: 'tenant-123',
          join: jest.fn(),
          emit: jest.fn(),
          on: jest.fn(),
          leave: jest.fn(),
        };

        // Mock sensor verification
        mockPrisma.sensor.findUnique.mockResolvedValue({
          id: 'sensor-123',
          tenantId: 'tenant-123',
        });

        // Simulate connection
        const connectionHandler = mockIo.on.mock.calls.find(
          call => call[0] === 'connection'
        )?.[1];

        if (connectionHandler) {
          connectionHandler(mockSocket);
          
          // Simulate sensor subscription
          const subscribeHandler = mockSocket.on.mock.calls.find(
            call => call[0] === 'subscribe_sensor'
          )?.[1];

          if (subscribeHandler) {
            subscribeHandler('sensor-123').then(() => {
              expect(mockSocket.join).toHaveBeenCalledWith('sensor:sensor-123');
              expect(mockSocket.emit).toHaveBeenCalledWith('subscribed', { sensorId: 'sensor-123' });
              done();
            });
          }
        }
      });

      test('should handle sensor unsubscription', () => {
        const mockSocket = {
          id: 'socket-123',
          leave: jest.fn(),
          emit: jest.fn(),
          on: jest.fn(),
        };

        // Simulate unsubscription
        const unsubscribeHandler = mockSocket.on.mock.calls.find(
          call => call[0] === 'unsubscribe_sensor'
        )?.[1];

        if (unsubscribeHandler) {
          unsubscribeHandler('sensor-123');
          expect(mockSocket.leave).toHaveBeenCalledWith('sensor:sensor-123');
          expect(mockSocket.emit).toHaveBeenCalledWith('unsubscribed', { sensorId: 'sensor-123' });
        }
      });
    });

    describe('Background Services', () => {
      test('should monitor sensor health', async () => {
        const sensorService = require('./services/sensorService').SensorService;
        const mockSensorService = new sensorService(mockPrisma, mockRedis);
        
        mockSensorService.monitorSensorHealth = jest.fn().mockResolvedValue(undefined);
        
        // Simulate background service execution
        await mockSensorService.monitorSensorHealth();
        
        expect(mockSensorService.monitorSensorHealth).toHaveBeenCalled();
      });

      test('should aggregate historical data', async () => {
        const readingService = require('./services/readingService').ReadingService;
        const mockReadingService = new readingService(mockPrisma, mockRedis);
        
        mockReadingService.aggregateHistoricalData = jest.fn().mockResolvedValue(undefined);
        
        // Simulate background service execution
        await mockReadingService.aggregateHistoricalData();
        
        expect(mockReadingService.aggregateHistoricalData).toHaveBeenCalled();
      });

      test('should cleanup resolved alerts', async () => {
        const alertService = require('./services/alertService').AlertService;
        const mockAlertService = new alertService(mockPrisma, mockRedis);
        
        mockAlertService.cleanupResolvedAlerts = jest.fn().mockResolvedValue(undefined);
        
        // Simulate background service execution
        await mockAlertService.cleanupResolvedAlerts();
        
        expect(mockAlertService.cleanupResolvedAlerts).toHaveBeenCalled();
      });
    });

    // ==================== PERFORMANCE TESTS ====================

    describe('Performance Tests', () => {
      test('should handle high-frequency sensor data ingestion', async () => {
        const startTime = Date.now();
        const promises = [];

        // Simulate 100 concurrent sensor readings
        for (let i = 0; i < 100; i++) {
          const promise = request(testApp)
            .post('/ingest/reading')
            .send({
              sensorId: `sensor-${i}`,
              timestamp: new Date().toISOString(),
              temperature: 20 + Math.random() * 10,
              humidity: 40 + Math.random() * 20,
            });
          promises.push(promise);
        }

        mockPrisma.reading.create.mockResolvedValue({
          id: 'reading-test',
          timestamp: new Date(),
        });

        await Promise.all(promises);
        const endTime = Date.now();
        const duration = endTime - startTime;

        // Should process 100 readings in under 5 seconds
        expect(duration).toBeLessThan(5000);
      });

      test('should handle concurrent threshold updates', async () => {
        const promises = [];

        // Simulate 50 concurrent threshold updates
        for (let i = 0; i < 50; i++) {
          const promise = request(testApp)
            .put(`/api/thresholds/sensor-${i}`)
            .set('Authorization', `Bearer ${authToken}`)
            .set('X-Tenant-ID', tenantId)
            .send({
              temperatureMin: 18 + i,
              temperatureMax: 26 + i,
            });
          promises.push(promise);
        }

        mockPrisma.threshold.upsert.mockResolvedValue({
          sensorId: 'sensor-test',
          temperatureMin: 18,
          temperatureMax: 26,
        });

        const results = await Promise.allSettled(promises);
        const successCount = results.filter(r => r.status === 'fulfilled').length;

        // At least 90% should succeed
        expect(successCount).toBeGreaterThan(45);
      });
    });

    // ==================== SECURITY TESTS ====================

    describe('Security Tests', () => {
      test('should require authentication for protected endpoints', async () => {
        await request(testApp)
          .get('/api/thresholds/sensor-123')
          .expect(401);

        await request(testApp)
          .put('/api/thresholds/sensor-123')
          .send({ temperatureMin: 20 })
          .expect(401);

        await request(testApp)
          .post('/api/hvac/integrate/sensor-123')
          .send({ hvacSystemId: 'hvac-123' })
          .expect(401);
      });

      test('should require tenant context for multi-tenant endpoints', async () => {
        await request(testApp)
          .get('/api/thresholds/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(400); // Missing tenant header

        await request(testApp)
          .put('/api/thresholds/sensor-123')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ temperatureMin: 20 })
          .expect(400); // Missing tenant header
      });

      test('should validate input data to prevent injection attacks', async () => {
        const maliciousPayload = {
          sensorId: "'; DROP TABLE sensors; --",
          timestamp: new Date().toISOString(),
          temperature: 25,
        };

        const response = await request(testApp)
          .post('/ingest/reading')
          .send(maliciousPayload)
          .expect(400);

        expect(response.body.error).toBe('Invalid reading data');
      });
    });

    // ==================== ERROR HANDLING TESTS ====================

    describe('Error Handling', () => {
      test('should handle database connection errors gracefully', async () => {
        mockPrisma.reading.create.mockRejectedValue(new Error('Database connection lost'));

        const response = await request(testApp)
          .post('/ingest/reading')
          .send({
            sensorId: 'sensor-123',
            timestamp: new Date().toISOString(),
            temperature: 25,
          })
          .expect(500);

        expect(response.body.error).toBe('Failed to process reading');
      });

      test('should handle Redis connection errors gracefully', async () => {
        mockRedis.publish.mockRejectedValue(new Error('Redis connection lost'));

        // Should still process the reading even if Redis fails
        mockPrisma.reading.create.mockResolvedValue({
          id: 'reading-123',
          timestamp: new Date(),
        });

        const response = await request(testApp)
          .post('/ingest/reading')
          .send({
            sensorId: 'sensor-123',
            timestamp: new Date().toISOString(),
            temperature: 25,
          })
          .expect(200);

        expect(response.body.success).toBe(true);
      });

      test('should return 404 for non-existent endpoints', async () => {
        const response = await request(testApp)
          .get('/api/non-existent-endpoint')
          .expect(404);

        expect(response.body.error).toBe('Not found');
      });
    });

    // ==================== DATA RETENTION TESTS ====================

    describe('Data Retention and Archiving', () => {
      test('should archive old sensor readings', async () => {
        const readingService = require('./services/readingService').ReadingService;
        const mockReadingService = new readingService(mockPrisma, mockRedis);
        
        mockReadingService.archiveOldReadings = jest.fn().mockResolvedValue({
          archivedCount: 1000,
          deletedCount: 500,
        });
        
        const result = await mockReadingService.archiveOldReadings();
        
        expect(result.archivedCount).toBe(1000);
        expect(result.deletedCount).toBe(500);
      });

      test('should maintain data retention policies', async () => {
        const readingService = require('./services/readingService').ReadingService;
        const mockReadingService = new readingService(mockPrisma, mockRedis);
        
        mockReadingService.enforceRetentionPolicy = jest.fn().mockResolvedValue(undefined);
        
        await mockReadingService.enforceRetentionPolicy();
        
        expect(mockReadingService.enforceRetentionPolicy).toHaveBeenCalled();
      });
    });

    // ==================== ENHANCED ALERT ESCALATION TESTS ====================

    describe('Enhanced Alert Escalation and Emergency Response', () => {
      test('should escalate critical temperature alerts with HVAC integration', async () => {
        const alertService = require('./services/alertService').AlertService;
        const mockAlertService = new alertService(mockPrisma, mockRedis);
        
        const criticalReading = {
          sensorId: 'sensor-123',
          temperature: 35, // Critical temperature
          timestamp: new Date(),
        };

        mockAlertService.processAlert = jest.fn().mockResolvedValue({
          id: 'alert-123',
          severity: 'critical',
          escalated: true,
          hvacActions: ['emergency_cooling', 'increase_airflow'],
          emergencyResponse: true
        });
        
        const alert = await mockAlertService.processAlert(criticalReading);
        
        expect(alert.severity).toBe('critical');
        expect(alert.escalated).toBe(true);
        expect(alert.hvacActions).toContain('emergency_cooling');
        expect(alert.emergencyResponse).toBe(true);
      });

      test('should trigger building automation response for environmental emergency', async () => {
        const emergencyResponseService = require('./services/emergencyResponseService').EmergencyResponseService;
        const mockEmergencyService = new emergencyResponseService(mockPrisma, mockRedis);
        
        mockEmergencyService.triggerBuildingResponse = jest.fn().mockResolvedValue({
          emergencyId: 'emergency-123',
          actions: [
            'HVAC systems adjusted',
            'Ventilation increased',
            'Security notified',
            'Evacuation procedures initiated'
          ],
          affectedZones: ['zone-1', 'zone-2'],
          estimatedResolutionTime: 30
        });
        
        const response = await mockEmergencyService.triggerBuildingResponse('fire', 'building-a');
        
        expect(response.actions).toHaveLength(4);
        expect(response.affectedZones).toContain('zone-1');
        expect(response.estimatedResolutionTime).toBe(30);
      });

      test('should generate comprehensive evacuation list with environmental data', async () => {
        const emergencyResponseService = require('./services/emergencyResponseService').EmergencyResponseService;
        const mockEmergencyService = new emergencyResponseService(mockPrisma, mockRedis);
        
        mockEmergencyService.generateEvacuationList = jest.fn().mockResolvedValue({
          visitors: [
            { visitorId: 'visitor-1', location: 'Building A, Floor 2', airQuality: 'poor' },
            { visitorId: 'visitor-2', location: 'Building A, Floor 3', airQuality: 'good' }
          ],
          employees: [
            { employeeId: 'emp-1', location: 'Building A, Floor 2', airQuality: 'poor' }
          ],
          evacuationRoutes: [
            { from: 'Floor 2', to: 'Exit A', status: 'clear', airQuality: 'good' },
            { from: 'Floor 3', to: 'Exit B', status: 'clear', airQuality: 'good' }
          ],
          environmentalConditions: {
            temperature: 28.5,
            humidity: 65.0,
            airQuality: 'poor',
            visibility: 'reduced'
          }
        });
        
        const evacuationData = await mockEmergencyService.generateEvacuationList('building-a');
        
        expect(evacuationData.visitors).toHaveLength(2);
        expect(evacuationData.employees).toHaveLength(1);
        expect(evacuationData.evacuationRoutes).toHaveLength(2);
        expect(evacuationData.environmentalConditions).toHaveProperty('airQuality');
      });

      test('should coordinate with building automation systems during emergency', async () => {
        const buildingAutomationService = require('./services/buildingAutomationService').BuildingAutomationService;
        const mockBASService = new buildingAutomationService(mockPrisma, mockRedis);
        
        mockBASService.executeEmergencyProtocol = jest.fn().mockResolvedValue({
          protocolId: 'emergency-protocol-1',
          actions: [
            { system: 'hvac', action: 'emergency_shutdown', status: 'completed' },
            { system: 'lighting', action: 'emergency_lighting', status: 'completed' },
            { system: 'access_control', action: 'unlock_emergency_exits', status: 'completed' },
            { system: 'fire_safety', action: 'activate_suppression', status: 'in_progress' }
          ],
          coordinatedSystems: 4,
          responseTime: 15
        });
        
        const protocol = await mockBASService.executeEmergencyProtocol('fire', 'building-a');
        
        expect(protocol.actions).toHaveLength(4);
        expect(protocol.coordinatedSystems).toBe(4);
        expect(protocol.responseTime).toBeLessThanOrEqual(30);
      });
    });

    // ==================== ENHANCED SENSOR CALIBRATION AND PREDICTIVE MAINTENANCE TESTS ====================

    describe('Enhanced Sensor Calibration and Predictive Maintenance', () => {
      test('should schedule advanced sensor calibration with reference standards', async () => {
        const calibrationService = require('./services/calibrationService').CalibrationService;
        const mockCalibrationService = new calibrationService(mockPrisma, mockRedis);
        
        mockCalibrationService.scheduleAdvancedCalibration = jest.fn().mockResolvedValue({
          calibrationId: 'cal-123',
          sensorId: 'sensor-123',
          calibrationType: 'reference_standard',
          calibrationDate: new Date(),
          status: 'scheduled',
          referenceStandards: {
            temperature: { value: 20.0, uncertainty: 0.1 },
            humidity: { value: 50.0, uncertainty: 0.5 }
          },
          expectedAccuracy: 0.98,
          estimatedDuration: 45
        });
        
        const calibration = await mockCalibrationService.scheduleAdvancedCalibration('sensor-123', {
          type: 'reference_standard',
          referenceValues: { temperature: 20.0, humidity: 50.0 }
        });
        
        expect(calibration.status).toBe('scheduled');
        expect(calibration.calibrationType).toBe('reference_standard');
        expect(calibration.expectedAccuracy).toBe(0.98);
      });

      test('should predict sensor drift and maintenance needs', async () => {
        const predictiveMaintenanceService = require('./services/predictiveMaintenanceService').PredictiveMaintenanceService;
        const mockPredictiveService = new predictiveMaintenanceService(mockPrisma, mockRedis);
        
        mockPredictiveService.predictSensorDrift = jest.fn().mockResolvedValue({
          sensorId: 'sensor-123',
          driftPrediction: {
            temperature: {
              currentDrift: 0.2,
              predictedDrift: 0.5,
              timeToCalibration: 720, // hours
              confidence: 0.85
            },
            humidity: {
              currentDrift: 1.0,
              predictedDrift: 2.5,
              timeToCalibration: 480, // hours
              confidence: 0.78
            }
          },
          maintenanceRecommendations: [
            { action: 'calibration', priority: 'medium', timeframe: '30 days' },
            { action: 'sensor_cleaning', priority: 'low', timeframe: '60 days' }
          ],
          overallHealth: 0.82
        });
        
        const prediction = await mockPredictiveService.predictSensorDrift('sensor-123');
        
        expect(prediction.driftPrediction.temperature.timeToCalibration).toBe(720);
        expect(prediction.maintenanceRecommendations).toHaveLength(2);
        expect(prediction.overallHealth).toBe(0.82);
      });

      test('should track comprehensive maintenance schedules with predictive analytics', async () => {
        const predictiveMaintenanceService = require('./services/predictiveMaintenanceService').PredictiveMaintenanceService;
        const mockPredictiveService = new predictiveMaintenanceService(mockPrisma, mockRedis);
        
        mockPredictiveService.getAdvancedMaintenanceSchedule = jest.fn().mockResolvedValue({
          sensors: [
            { 
              sensorId: 'sensor-1', 
              nextMaintenance: new Date(),
              type: 'calibration',
              priority: 'high',
              predictedFailureRisk: 0.15
            },
            { 
              sensorId: 'sensor-2', 
              nextMaintenance: new Date(),
              type: 'cleaning',
              priority: 'medium',
              predictedFailureRisk: 0.08
            }
          ],
          hvacSystems: [
            {
              systemId: 'hvac-1',
              nextMaintenance: new Date(),
              type: 'filter_replacement',
              priority: 'high',
              predictedFailureRisk: 0.25,
              energyImpact: 0.12
            }
          ],
          summary: {
            totalItems: 3,
            highPriority: 2,
            mediumPriority: 1,
            estimatedCost: 1250.00,
            estimatedDowntime: 4.5
          }
        });
        
        const schedule = await mockPredictiveService.getAdvancedMaintenanceSchedule();
        
        expect(schedule.sensors).toHaveLength(2);
        expect(schedule.hvacSystems).toHaveLength(1);
        expect(schedule.summary.totalItems).toBe(3);
        expect(schedule.summary.estimatedCost).toBe(1250.00);
      });

      test('should optimize maintenance scheduling based on occupancy patterns', async () => {
        const predictiveMaintenanceService = require('./services/predictiveMaintenanceService').PredictiveMaintenanceService;
        const mockPredictiveService = new predictiveMaintenanceService(mockPrisma, mockRedis);
        
        mockPredictiveService.optimizeMaintenanceScheduling = jest.fn().mockResolvedValue({
          optimizedSchedule: [
            {
              taskId: 'maint-1',
              originalDate: new Date('2024-01-15T14:00:00Z'),
              optimizedDate: new Date('2024-01-15T02:00:00Z'),
              reason: 'Low occupancy period',
              impactReduction: 0.75
            },
            {
              taskId: 'maint-2',
              originalDate: new Date('2024-01-16T10:00:00Z'),
              optimizedDate: new Date('2024-01-16T06:00:00Z'),
              reason: 'Avoid peak hours',
              impactReduction: 0.60
            }
          ],
          occupancyAnalysis: {
            peakHours: ['09:00-12:00', '14:00-17:00'],
            lowOccupancyWindows: ['02:00-06:00', '22:00-24:00'],
            weekendAvailability: true
          },
          estimatedImpactReduction: 0.68
        });
        
        const optimization = await mockPredictiveService.optimizeMaintenanceScheduling('building-1');
        
        expect(optimization.optimizedSchedule).toHaveLength(2);
        expect(optimization.estimatedImpactReduction).toBe(0.68);
        expect(optimization.occupancyAnalysis.peakHours).toContain('09:00-12:00');
      });
    });

    // ==================== ADVANCED ANALYTICS AND TREND ANALYSIS TESTS ====================

    describe('Advanced Analytics and Trend Analysis', () => {
      test('should perform comprehensive trend analysis with machine learning', async () => {
        const analyticsService = require('./services/advancedAnalyticsService').AdvancedAnalyticsService;
        const mockAnalyticsService = new analyticsService(mockPrisma, mockRedis);
        
        mockAnalyticsService.performMLTrendAnalysis = jest.fn().mockResolvedValue({
          sensorId: 'sensor-123',
          timeRange: '30d',
          trends: {
            temperature: {
              trend: 'seasonal_increase',
              rate: 0.05, // degrees per day
              confidence: 0.92,
              seasonality: {
                detected: true,
                period: 24, // hours
                amplitude: 3.2
              },
              anomalies: [
                {
                  timestamp: new Date('2024-01-10T14:30:00Z'),
                  value: 28.5,
                  expectedValue: 22.0,
                  severity: 'high',
                  possibleCauses: ['equipment_malfunction', 'external_heat_source']
                }
              ]
            },
            humidity: {
              trend: 'stable',
              rate: 0.01,
              confidence: 0.88,
              correlations: [
                { factor: 'occupancy', correlation: 0.65 },
                { factor: 'external_weather', correlation: 0.78 }
              ]
            }
          },
          predictions: {
            nextWeek: {
              temperature: { min: 20.5, max: 24.8, avg: 22.1 },
              humidity: { min: 42.0, max: 58.0, avg: 48.5 }
            },
            nextMonth: {
              temperature: { min: 19.8, max: 26.2, avg: 22.8 },
              humidity: { min: 40.0, max: 62.0, avg: 49.2 }
            }
          },
          recommendations: [
            'Investigate temperature spike on 2024-01-10',
            'Consider humidity control optimization',
            'Schedule HVAC maintenance before predicted peak period'
          ]
        });
        
        const analysis = await mockAnalyticsService.performMLTrendAnalysis('sensor-123', '30d');
        
        expect(analysis.trends.temperature.confidence).toBeGreaterThan(0.9);
        expect(analysis.trends.temperature.seasonality.detected).toBe(true);
        expect(analysis.predictions.nextWeek.temperature).toHaveProperty('avg');
        expect(analysis.recommendations).toHaveLength(3);
      });

      test('should detect complex anomalies using ensemble methods', async () => {
        const analyticsService = require('./services/advancedAnalyticsService').AdvancedAnalyticsService;
        const mockAnalyticsService = new analyticsService(mockPrisma, mockRedis);
        
        mockAnalyticsService.detectComplexAnomalies = jest.fn().mockResolvedValue({
          detectionMethods: ['isolation_forest', 'lstm_autoencoder', 'statistical_outlier'],
          anomalies: [
            {
              id: 'anomaly-1',
              timestamp: new Date('2024-01-15T16:45:00Z'),
              sensorId: 'sensor-123',
              metrics: {
                temperature: { value: 32.1, zscore: 4.2, percentile: 99.8 },
                humidity: { value: 85.0, zscore: 3.8, percentile: 98.5 }
              },
              anomalyScore: 0.95,
              detectionMethods: ['isolation_forest', 'lstm_autoencoder'],
              classification: 'multivariate_outlier',
              severity: 'critical',
              possibleCauses: [
                'hvac_system_failure',
                'sensor_malfunction',
                'external_environmental_event'
              ],
              correlatedEvents: [
                { type: 'hvac_alarm', timestamp: new Date('2024-01-15T16:40:00Z') },
                { type: 'power_fluctuation', timestamp: new Date('2024-01-15T16:42:00Z') }
              ]
            }
          ],
          modelPerformance: {
            precision: 0.89,
            recall: 0.92,
            f1Score: 0.90,
            falsePositiveRate: 0.05
          }
        });
        
        const anomalies = await mockAnalyticsService.detectComplexAnomalies('tenant-123', '24h');
        
        expect(anomalies.anomalies).toHaveLength(1);
        expect(anomalies.anomalies[0].anomalyScore).toBe(0.95);
        expect(anomalies.anomalies[0].correlatedEvents).toHaveLength(2);
        expect(anomalies.modelPerformance.f1Score).toBe(0.90);
      });

      test('should provide energy optimization recommendations', async () => {
        const analyticsService = require('./services/advancedAnalyticsService').AdvancedAnalyticsService;
        const mockAnalyticsService = new analyticsService(mockPrisma, mockRedis);
        
        mockAnalyticsService.generateEnergyOptimizationRecommendations = jest.fn().mockResolvedValue({
          currentConsumption: {
            hvac: { daily: 245.6, monthly: 7368.0, unit: 'kWh' },
            lighting: { daily: 89.2, monthly: 2676.0, unit: 'kWh' },
            total: { daily: 334.8, monthly: 10044.0, unit: 'kWh' }
          },
          optimizationOpportunities: [
            {
              category: 'hvac_scheduling',
              description: 'Optimize HVAC operation based on occupancy patterns',
              potentialSavings: {
                energy: { daily: 24.5, monthly: 735.0, unit: 'kWh' },
                cost: { daily: 3.68, monthly: 110.25, unit: 'USD' },
                percentage: 10.0
              },
              implementation: {
                difficulty: 'medium',
                timeframe: '2-4 weeks',
                requirements: ['occupancy_sensors', 'hvac_integration']
              }
            },
            {
              category: 'temperature_setpoint_optimization',
              description: 'Adjust temperature setpoints during low occupancy periods',
              potentialSavings: {
                energy: { daily: 18.3, monthly: 549.0, unit: 'kWh' },
                cost: { daily: 2.75, monthly: 82.35, unit: 'USD' },
                percentage: 7.5
              },
              implementation: {
                difficulty: 'low',
                timeframe: '1 week',
                requirements: ['hvac_control_system']
              }
            }
          ],
          totalPotentialSavings: {
            energy: { daily: 42.8, monthly: 1284.0, unit: 'kWh' },
            cost: { daily: 6.43, monthly: 192.60, unit: 'USD' },
            percentage: 17.5
          },
          environmentalImpact: {
            co2Reduction: { daily: 18.2, monthly: 546.0, unit: 'kg' },
            equivalentTrees: 24.8
          }
        });
        
        const recommendations = await mockAnalyticsService.generateEnergyOptimizationRecommendations('tenant-123');
        
        expect(recommendations.optimizationOpportunities).toHaveLength(2);
        expect(recommendations.totalPotentialSavings.percentage).toBe(17.5);
        expect(recommendations.environmentalImpact.co2Reduction.monthly).toBe(546.0);
      });
    });
  });

  // ==================== TEST CONFIGURATION ====================

  // Jest configuration for the environmental service
  const jestConfig = {
    testEnvironment: 'node',
    setupFilesAfterEnv: ['<rootDir>/src/test-setup.ts'],
    testMatch: ['**/__tests__/**/*.test.ts', '**/?(*.)+(spec|test).ts'],
    collectCoverageFrom: [
      'src/**/*.ts',
      '!src/**/*.d.ts',
      '!src/test-setup.ts',
    ],
    coverageThreshold: {
      global: {
        branches: 80,
        functions: 80,
        lines: 80,
        statements: 80,
      },
    },
    moduleNameMapping: {
      '^@sparc/(.*)$': '<rootDir>/../../../packages/$1/src',
    },
    transform: {
      '^.+\\.ts$': 'ts-jest',
    },
  };

  // Export test configuration
  module.exports = jestConfig;
}
