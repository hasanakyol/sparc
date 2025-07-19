/**
 * Service-to-Service Authentication Utilities
 * 
 * This module provides utilities for generating and validating
 * service tokens for internal API communication.
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Redis } from 'ioredis';

export interface ServiceTokenOptions {
  serviceId: string;
  serviceName: string;
  permissions: string[];
  expiresIn?: string;
  audience?: string;
  issuer?: string;
}

export interface ServiceRegistration {
  id: string;
  name: string;
  publicKey?: string;
  permissions: string[];
  allowedTargets: string[];
  createdAt: Date;
  lastUsedAt?: Date;
  isActive: boolean;
}

/**
 * Service Authentication Manager
 */
export class ServiceAuthManager {
  private jwtSecret: string;
  private redis: Redis;
  private readonly REGISTRY_KEY = 'services:registry';
  private readonly TOKEN_PREFIX = 'service:token:';

  constructor(redis: Redis, jwtSecret?: string) {
    this.redis = redis;
    this.jwtSecret = jwtSecret || process.env.JWT_SECRET || '';
    
    if (!this.jwtSecret) {
      throw new Error('JWT_SECRET is required for service authentication');
    }
  }

  /**
   * Register a new service
   */
  async registerService(
    serviceId: string,
    serviceName: string,
    permissions: string[],
    allowedTargets: string[] = ['*']
  ): Promise<ServiceRegistration> {
    const registration: ServiceRegistration = {
      id: serviceId,
      name: serviceName,
      permissions,
      allowedTargets,
      createdAt: new Date(),
      isActive: true
    };

    // Store in Redis
    await this.redis.hset(
      this.REGISTRY_KEY,
      serviceId,
      JSON.stringify(registration)
    );

    return registration;
  }

  /**
   * Generate a service token
   */
  async generateServiceToken(options: ServiceTokenOptions): Promise<string> {
    const {
      serviceId,
      serviceName,
      permissions,
      expiresIn = '1h',
      audience = 'sparc-services',
      issuer = 'sparc-auth'
    } = options;

    // Verify service is registered
    const registration = await this.getServiceRegistration(serviceId);
    if (!registration || !registration.isActive) {
      throw new Error(`Service ${serviceId} is not registered or inactive`);
    }

    // Generate unique JTI
    const jti = crypto.randomUUID();

    // Create token payload
    const payload = {
      sub: serviceId,
      name: serviceName,
      type: 'service',
      permissions,
      serviceId,
      tenantId: 'system', // Service tokens operate at system level
      role: 'SERVICE',
      jti
    };

    // Sign token
    const token = jwt.sign(payload, this.jwtSecret, {
      expiresIn,
      audience,
      issuer
    });

    // Store token metadata for tracking
    const tokenData = {
      serviceId,
      serviceName,
      issuedAt: Date.now(),
      expiresAt: Date.now() + this.parseExpiry(expiresIn),
      jti
    };

    await this.redis.setex(
      `${this.TOKEN_PREFIX}${jti}`,
      this.parseExpiry(expiresIn) / 1000,
      JSON.stringify(tokenData)
    );

    // Update last used timestamp
    await this.updateServiceLastUsed(serviceId);

    return token;
  }

  /**
   * Validate a service token
   */
  async validateServiceToken(token: string): Promise<any> {
    try {
      // Verify JWT
      const payload = jwt.verify(token, this.jwtSecret) as any;

      // Check if it's a service token
      if (payload.type !== 'service') {
        throw new Error('Not a service token');
      }

      // Check if service is still active
      const registration = await this.getServiceRegistration(payload.serviceId);
      if (!registration || !registration.isActive) {
        throw new Error('Service is not active');
      }

      // Check if token is in registry (not revoked)
      const tokenData = await this.redis.get(`${this.TOKEN_PREFIX}${payload.jti}`);
      if (!tokenData) {
        throw new Error('Token not found or revoked');
      }

      return payload;

    } catch (error) {
      throw new Error(`Service token validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Revoke a service token
   */
  async revokeServiceToken(jti: string): Promise<void> {
    await this.redis.del(`${this.TOKEN_PREFIX}${jti}`);
  }

  /**
   * Get service registration
   */
  async getServiceRegistration(serviceId: string): Promise<ServiceRegistration | null> {
    const data = await this.redis.hget(this.REGISTRY_KEY, serviceId);
    return data ? JSON.parse(data) : null;
  }

  /**
   * List all registered services
   */
  async listServices(): Promise<ServiceRegistration[]> {
    const services = await this.redis.hgetall(this.REGISTRY_KEY);
    return Object.values(services).map(s => JSON.parse(s));
  }

  /**
   * Deactivate a service
   */
  async deactivateService(serviceId: string): Promise<void> {
    const registration = await this.getServiceRegistration(serviceId);
    if (registration) {
      registration.isActive = false;
      await this.redis.hset(
        this.REGISTRY_KEY,
        serviceId,
        JSON.stringify(registration)
      );
    }
  }

  /**
   * Update service last used timestamp
   */
  private async updateServiceLastUsed(serviceId: string): Promise<void> {
    const registration = await this.getServiceRegistration(serviceId);
    if (registration) {
      registration.lastUsedAt = new Date();
      await this.redis.hset(
        this.REGISTRY_KEY,
        serviceId,
        JSON.stringify(registration)
      );
    }
  }

  /**
   * Parse expiry string to milliseconds
   */
  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error('Invalid expiry format');
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: throw new Error('Invalid time unit');
    }
  }
}

/**
 * Service discovery helper
 */
export class ServiceDiscovery {
  private services: Map<string, string>;

  constructor() {
    this.services = new Map();
    this.loadServicesFromEnv();
  }

  /**
   * Load service URLs from environment
   */
  private loadServicesFromEnv(): void {
    const serviceEnvs = {
      'auth': process.env.AUTH_SERVICE_URL,
      'tenant': process.env.TENANT_SERVICE_URL,
      'access-control': process.env.ACCESS_CONTROL_SERVICE_URL,
      'credential': process.env.CREDENTIAL_SERVICE_URL,
      'video': process.env.VIDEO_SERVICE_URL,
      'hardware': process.env.HARDWARE_SERVICE_URL,
      'analytics': process.env.ANALYTICS_SERVICE_URL,
      'notification': process.env.NOTIFICATION_SERVICE_URL,
      'sync': process.env.SYNC_SERVICE_URL,
      'api-gateway': process.env.API_GATEWAY_URL
    };

    for (const [name, url] of Object.entries(serviceEnvs)) {
      if (url) {
        this.services.set(name, url);
      }
    }
  }

  /**
   * Get service URL
   */
  getServiceUrl(serviceName: string): string | undefined {
    return this.services.get(serviceName);
  }

  /**
   * Get all service URLs
   */
  getAllServices(): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [name, url] of this.services) {
      result[name] = url;
    }
    return result;
  }

  /**
   * Register a dynamic service
   */
  registerService(name: string, url: string): void {
    this.services.set(name, url);
  }

  /**
   * Health check all services
   */
  async healthCheckAll(): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};

    for (const [name, url] of this.services) {
      try {
        const response = await fetch(`${url}/health`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000)
        });
        results[name] = response.ok;
      } catch {
        results[name] = false;
      }
    }

    return results;
  }
}

/**
 * Service client with authentication
 */
export class AuthenticatedServiceClient {
  private serviceAuth: ServiceAuthManager;
  private discovery: ServiceDiscovery;
  private serviceId: string;
  private serviceName: string;
  private permissions: string[];

  constructor(
    serviceAuth: ServiceAuthManager,
    serviceId: string,
    serviceName: string,
    permissions: string[] = []
  ) {
    this.serviceAuth = serviceAuth;
    this.discovery = new ServiceDiscovery();
    this.serviceId = serviceId;
    this.serviceName = serviceName;
    this.permissions = permissions;
  }

  /**
   * Make authenticated request to another service
   */
  async request(
    targetService: string,
    path: string,
    options: RequestInit = {}
  ): Promise<Response> {
    // Get target service URL
    const baseUrl = this.discovery.getServiceUrl(targetService);
    if (!baseUrl) {
      throw new Error(`Service ${targetService} not found`);
    }

    // Generate service token
    const token = await this.serviceAuth.generateServiceToken({
      serviceId: this.serviceId,
      serviceName: this.serviceName,
      permissions: this.permissions
    });

    // Prepare headers
    const headers = new Headers(options.headers);
    headers.set('Authorization', `Bearer ${token}`);
    headers.set('X-Service-ID', this.serviceId);
    headers.set('X-Service-Name', this.serviceName);

    // Make request
    const url = `${baseUrl}${path}`;
    const response = await fetch(url, {
      ...options,
      headers
    });

    return response;
  }

  /**
   * GET request helper
   */
  async get(targetService: string, path: string): Promise<any> {
    const response = await this.request(targetService, path, {
      method: 'GET'
    });

    if (!response.ok) {
      throw new Error(`Service request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * POST request helper
   */
  async post(targetService: string, path: string, data: any): Promise<any> {
    const response = await this.request(targetService, path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      throw new Error(`Service request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * PUT request helper
   */
  async put(targetService: string, path: string, data: any): Promise<any> {
    const response = await this.request(targetService, path, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      throw new Error(`Service request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * DELETE request helper
   */
  async delete(targetService: string, path: string): Promise<any> {
    const response = await this.request(targetService, path, {
      method: 'DELETE'
    });

    if (!response.ok) {
      throw new Error(`Service request failed: ${response.status} ${response.statusText}`);
    }

    return response.json();
  }
}

/**
 * Initialize service authentication for a service
 */
export async function initializeServiceAuth(
  redis: Redis,
  serviceId: string,
  serviceName: string,
  permissions: string[] = []
): Promise<{
  manager: ServiceAuthManager;
  client: AuthenticatedServiceClient;
}> {
  const manager = new ServiceAuthManager(redis);
  
  // Register this service
  await manager.registerService(serviceId, serviceName, permissions);
  
  // Create authenticated client
  const client = new AuthenticatedServiceClient(
    manager,
    serviceId,
    serviceName,
    permissions
  );

  return { manager, client };
}