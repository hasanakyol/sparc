import Redis from 'ioredis';

export interface ServiceInstance {
  id: string;
  name: string;
  version: string;
  host: string;
  port: number;
  protocol: 'http' | 'https' | 'grpc';
  healthCheck: string;
  metadata?: Record<string, any>;
  registeredAt: Date;
  lastHeartbeat: Date;
}

export class ServiceRegistry {
  private redis: Redis;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private readonly TTL = 30; // seconds
  private readonly HEARTBEAT_INTERVAL = 10000; // 10 seconds

  constructor(redisUrl: string) {
    this.redis = new Redis(redisUrl);
  }

  /**
   * Register a service instance
   */
  async register(service: Omit<ServiceInstance, 'registeredAt' | 'lastHeartbeat'>): Promise<void> {
    const instance: ServiceInstance = {
      ...service,
      registeredAt: new Date(),
      lastHeartbeat: new Date()
    };

    const key = `service:${service.name}:${service.id}`;
    await this.redis.setex(key, this.TTL, JSON.stringify(instance));

    // Add to service index
    await this.redis.sadd(`services:${service.name}`, service.id);

    // Start heartbeat
    this.startHeartbeat(service);
  }

  /**
   * Deregister a service instance
   */
  async deregister(serviceName: string, instanceId: string): Promise<void> {
    const key = `service:${serviceName}:${instanceId}`;
    await this.redis.del(key);
    await this.redis.srem(`services:${serviceName}`, instanceId);
    
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
  }

  /**
   * Get all instances of a service
   */
  async getInstances(serviceName: string): Promise<ServiceInstance[]> {
    const instanceIds = await this.redis.smembers(`services:${serviceName}`);
    const instances: ServiceInstance[] = [];

    for (const id of instanceIds) {
      const key = `service:${serviceName}:${id}`;
      const data = await this.redis.get(key);
      
      if (data) {
        instances.push(JSON.parse(data));
      } else {
        // Remove stale instance from index
        await this.redis.srem(`services:${serviceName}`, id);
      }
    }

    return instances.filter(instance => this.isHealthy(instance));
  }

  /**
   * Get a single healthy instance of a service (load balancing)
   */
  async getInstance(serviceName: string): Promise<ServiceInstance | null> {
    const instances = await this.getInstances(serviceName);
    
    if (instances.length === 0) {
      return null;
    }

    // Simple round-robin selection
    const index = Math.floor(Math.random() * instances.length);
    return instances[index];
  }

  /**
   * Get all registered services
   */
  async getAllServices(): Promise<string[]> {
    const keys = await this.redis.keys('services:*');
    return keys.map(key => key.replace('services:', ''));
  }

  /**
   * Check if a service instance is healthy
   */
  private isHealthy(instance: ServiceInstance): boolean {
    const now = new Date();
    const lastHeartbeat = new Date(instance.lastHeartbeat);
    const timeSinceHeartbeat = now.getTime() - lastHeartbeat.getTime();
    
    // Consider unhealthy if no heartbeat for 2x the TTL
    return timeSinceHeartbeat < this.TTL * 2000;
  }

  /**
   * Start heartbeat for a service
   */
  private startHeartbeat(service: Omit<ServiceInstance, 'registeredAt' | 'lastHeartbeat'>): void {
    this.heartbeatInterval = setInterval(async () => {
      const key = `service:${service.name}:${service.id}`;
      const instance: ServiceInstance = {
        ...service,
        registeredAt: new Date(),
        lastHeartbeat: new Date()
      };
      
      await this.redis.setex(key, this.TTL, JSON.stringify(instance));
    }, this.HEARTBEAT_INTERVAL);
  }

  /**
   * Create service URL
   */
  static createServiceUrl(instance: ServiceInstance, path: string = ''): string {
    return `${instance.protocol}://${instance.host}:${instance.port}${path}`;
  }

  /**
   * Close the registry connection
   */
  async close(): Promise<void> {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
    await this.redis.quit();
  }
}

/**
 * Service discovery client for use in services
 */
export class ServiceDiscovery {
  private registry: ServiceRegistry;
  private cache: Map<string, { instances: ServiceInstance[], timestamp: number }> = new Map();
  private readonly CACHE_TTL = 5000; // 5 seconds

  constructor(redisUrl: string) {
    this.registry = new ServiceRegistry(redisUrl);
  }

  /**
   * Discover and call a service
   */
  async call(
    serviceName: string,
    path: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const instance = await this.getHealthyInstance(serviceName);
    
    if (!instance) {
      throw new Error(`No healthy instances found for service: ${serviceName}`);
    }

    const url = ServiceRegistry.createServiceUrl(instance, path);
    
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          'X-Service-Name': process.env.SERVICE_NAME || 'unknown',
          'X-Service-Instance': process.env.HOSTNAME || 'unknown',
          ...options.headers
        }
      });

      return response;
    } catch (error) {
      // Try another instance if available
      const instances = await this.getInstances(serviceName);
      const otherInstances = instances.filter(i => i.id !== instance.id);
      
      if (otherInstances.length > 0) {
        const fallbackInstance = otherInstances[0];
        const fallbackUrl = ServiceRegistry.createServiceUrl(fallbackInstance, path);
        
        return fetch(fallbackUrl, options);
      }

      throw error;
    }
  }

  /**
   * Get a healthy instance with caching
   */
  private async getHealthyInstance(serviceName: string): Promise<ServiceInstance | null> {
    const instances = await this.getInstances(serviceName);
    
    if (instances.length === 0) {
      return null;
    }

    // Round-robin selection
    const index = Math.floor(Math.random() * instances.length);
    return instances[index];
  }

  /**
   * Get instances with caching
   */
  private async getInstances(serviceName: string): Promise<ServiceInstance[]> {
    const cached = this.cache.get(serviceName);
    const now = Date.now();

    if (cached && (now - cached.timestamp) < this.CACHE_TTL) {
      return cached.instances;
    }

    const instances = await this.registry.getInstances(serviceName);
    this.cache.set(serviceName, { instances, timestamp: now });
    
    return instances;
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Close the discovery client
   */
  async close(): Promise<void> {
    await this.registry.close();
  }
}