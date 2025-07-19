import { Context } from 'hono';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';

interface HealthCheckResult {
  status: 'healthy' | 'unhealthy';
  timestamp: string;
  service: string;
  version: string;
  uptime: number;
  environment: string;
  dependencies?: {
    database?: 'connected' | 'disconnected';
    cache?: 'connected' | 'disconnected';
    [key: string]: any;
  };
  error?: string;
}

interface HealthCheckOptions {
  serviceName: string;
  version?: string;
  environment?: string;
  checkDatabase?: boolean;
  checkRedis?: boolean;
  prismaClient?: PrismaClient;
  redisClient?: Redis;
  customChecks?: Record<string, () => Promise<boolean>>;
}

/**
 * Create an async health check handler for Hono services
 */
export function createHealthCheckHandler(options: HealthCheckOptions) {
  return async (c: Context) => {
    const {
      serviceName,
      version = process.env.npm_package_version || '1.0.0',
      environment = process.env.NODE_ENV || 'development',
      checkDatabase = true,
      checkRedis = true,
      prismaClient,
      redisClient,
      customChecks = {}
    } = options;

    const result: HealthCheckResult = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: serviceName,
      version,
      uptime: process.uptime(),
      environment,
      dependencies: {}
    };

    try {
      // Check database if configured
      if (checkDatabase && prismaClient) {
        try {
          await prismaClient.$queryRaw`SELECT 1`;
          result.dependencies!.database = 'connected';
        } catch (error) {
          result.dependencies!.database = 'disconnected';
          throw new Error('Database connection failed');
        }
      }

      // Check Redis if configured
      if (checkRedis && redisClient) {
        try {
          const pong = await redisClient.ping();
          if (pong === 'PONG') {
            result.dependencies!.cache = 'connected';
          } else {
            throw new Error('Redis ping failed');
          }
        } catch (error) {
          result.dependencies!.cache = 'disconnected';
          throw new Error('Redis connection failed');
        }
      }

      // Run custom health checks
      for (const [name, check] of Object.entries(customChecks)) {
        try {
          const isHealthy = await check();
          result.dependencies![name] = isHealthy ? 'connected' : 'disconnected';
          if (!isHealthy) {
            throw new Error(`${name} check failed`);
          }
        } catch (error) {
          result.dependencies![name] = 'disconnected';
          throw new Error(`${name} check failed: ${error.message}`);
        }
      }

      return c.json(result);
    } catch (error) {
      result.status = 'unhealthy';
      result.error = error.message;
      return c.json(result, 503);
    }
  };
}

/**
 * Create a simple async health check handler without dependencies
 */
export function createSimpleHealthCheckHandler(serviceName: string) {
  return async (c: Context) => {
    return c.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: serviceName,
      version: process.env.npm_package_version || '1.0.0',
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development'
    });
  };
}

/**
 * Check if a service is healthy by calling its health endpoint
 */
export async function checkServiceHealth(serviceUrl: string): Promise<boolean> {
  try {
    const response = await fetch(`${serviceUrl}/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(5000) // 5 second timeout
    });
    
    if (!response.ok) {
      return false;
    }
    
    const data = await response.json();
    return data.status === 'healthy';
  } catch (error) {
    return false;
  }
}