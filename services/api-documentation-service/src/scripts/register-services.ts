#!/usr/bin/env ts-node

import fetch from 'node-fetch';
import { logger } from '@sparc/shared';

interface ServiceConfig {
  name: string;
  port: number;
  description: string;
}

const SERVICES: ServiceConfig[] = [
  { name: 'auth-service', port: 3001, description: 'Authentication and authorization service' },
  { name: 'tenant-service', port: 3002, description: 'Tenant and organization management' },
  { name: 'access-control-service', port: 3003, description: 'Access control and door management' },
  { name: 'video-management-service', port: 3004, description: 'Video streaming and recording management' },
  { name: 'event-processing-service', port: 3005, description: 'Real-time event processing and distribution' },
  { name: 'device-management-service', port: 3006, description: 'IoT device management and control' },
  { name: 'analytics-service', port: 3007, description: 'Data analytics and reporting' },
  { name: 'alert-service', port: 3008, description: 'Alert generation and notification' },
  { name: 'environmental-service', port: 3009, description: 'Environmental monitoring and control' },
  { name: 'visitor-management-service', port: 3010, description: 'Visitor registration and tracking' },
  { name: 'reporting-service', port: 3011, description: 'Report generation and scheduling' },
  { name: 'mobile-credential-service', port: 3013, description: 'Mobile credential management' },
  { name: 'security-monitoring-service', port: 3014, description: 'Security monitoring and threat detection' },
  { name: 'user-management-service', port: 3015, description: 'User account management' }
];

const API_DOC_SERVICE_URL = process.env.API_DOC_SERVICE_URL || 'http://localhost:3012';

async function fetchServiceSpec(service: ServiceConfig): Promise<any | null> {
  try {
    const response = await fetch(`http://localhost:${service.port}/openapi.json`, {
      timeout: 5000
    });

    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    logger.warn(`Failed to fetch spec from ${service.name}:`, error);
  }

  return null;
}

async function registerService(service: ServiceConfig, spec: any): Promise<boolean> {
  try {
    const response = await fetch(`${API_DOC_SERVICE_URL}/api/v1/discovery/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        serviceName: service.name,
        version: spec.info?.version || '1.0.0',
        specification: spec,
        url: `http://${service.name}:${service.port}`,
        healthEndpoint: '/health',
        specEndpoint: '/openapi.json'
      })
    });

    return response.ok;
  } catch (error) {
    logger.error(`Failed to register ${service.name}:`, error);
    return false;
  }
}

async function main() {
  logger.info('Starting service registration...');

  let successCount = 0;
  let failureCount = 0;

  for (const service of SERVICES) {
    logger.info(`Processing ${service.name}...`);

    // Fetch OpenAPI spec
    const spec = await fetchServiceSpec(service);
    
    if (!spec) {
      logger.warn(`No OpenAPI spec available for ${service.name}`);
      failureCount++;
      continue;
    }

    // Ensure spec has proper metadata
    if (!spec.info) {
      spec.info = {};
    }
    spec.info.title = spec.info.title || `${service.name} API`;
    spec.info.description = spec.info.description || service.description;
    spec.info.version = spec.info.version || '1.0.0';

    // Register with documentation service
    const success = await registerService(service, spec);
    
    if (success) {
      logger.info(`✅ Successfully registered ${service.name}`);
      successCount++;
    } else {
      logger.error(`❌ Failed to register ${service.name}`);
      failureCount++;
    }
  }

  logger.info(`\nRegistration complete: ${successCount} succeeded, ${failureCount} failed`);

  // Generate unified spec
  if (successCount > 0) {
    logger.info('\nTrigggering unified spec generation...');
    
    try {
      const response = await fetch(`${API_DOC_SERVICE_URL}/api/v1/specs/unified`);
      if (response.ok) {
        logger.info('✅ Unified spec generated successfully');
      }
    } catch (error) {
      logger.error('Failed to generate unified spec:', error);
    }
  }
}

if (require.main === module) {
  main().catch(console.error);
}

export { main as registerServices };