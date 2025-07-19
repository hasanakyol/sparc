/**
 * Example protocol-specific configurations for each elevator manufacturer
 * Copy and modify these configurations based on your actual elevator systems
 */

import { ElevatorConfig } from '../src/adapters/base.adapter';

// OTIS Configuration Example
export const otisConfig: ElevatorConfig = {
  baseUrl: process.env.OTIS_API_URL || 'https://api.otis.com/elevator/v1',
  apiKey: process.env.OTIS_API_KEY || '',
  timeout: 5000,
  retryAttempts: 3,
  retryDelay: 1000,
  connectionPoolSize: 5,
  simulatorMode: process.env.NODE_ENV === 'development',
  simulatorOptions: {
    responseDelay: 100,
    failureRate: 0.05,
    randomizeStatus: true,
    floors: 20,
    travelTimePerFloor: 3000
  }
};

// KONE Configuration Example with OAuth2
export const koneConfig: ElevatorConfig = {
  baseUrl: process.env.KONE_API_URL || 'https://api.kone.com/elevator/v2',
  apiKey: process.env.KONE_CLIENT_ID || '', // Used as OAuth2 client ID
  timeout: 5000,
  retryAttempts: 3,
  retryDelay: 1000,
  connectionPoolSize: 10, // KONE supports more concurrent connections
  simulatorMode: process.env.NODE_ENV === 'development',
  simulatorOptions: {
    responseDelay: 150,
    failureRate: 0.02, // KONE has lower failure rate
    randomizeStatus: true,
    floors: 50, // KONE supports up to 50 floors
    travelTimePerFloor: 2500
  }
};

// Additional KONE OAuth2 configuration
export const koneOAuth2Config = {
  clientSecret: process.env.KONE_CLIENT_SECRET || '',
  tokenUrl: process.env.KONE_TOKEN_URL || 'https://auth.kone.com/oauth/token',
  scope: 'elevator.control elevator.monitor',
  grantType: 'client_credentials'
};

// Schindler PORT Technology Configuration
export const schindlerConfig: ElevatorConfig = {
  baseUrl: process.env.SCHINDLER_API_URL || 'https://port.schindler.com/api/v3',
  apiKey: process.env.SCHINDLER_API_KEY || '',
  timeout: 5000,
  retryAttempts: 3,
  retryDelay: 1000,
  connectionPoolSize: 8,
  simulatorMode: process.env.NODE_ENV === 'development',
  simulatorOptions: {
    responseDelay: 120,
    failureRate: 0.01, // Schindler has very low failure rate
    randomizeStatus: true,
    floors: 60, // Schindler handles tall buildings
    travelTimePerFloor: 2000
  }
};

// Schindler certificate configuration for mutual TLS
export const schindlerCertConfig = {
  certificatePath: process.env.SCHINDLER_CERT_PATH || '/etc/ssl/schindler/client.crt',
  privateKeyPath: process.env.SCHINDLER_KEY_PATH || '/etc/ssl/schindler/client.key',
  caPath: process.env.SCHINDLER_CA_PATH || '/etc/ssl/schindler/ca.crt',
  passphrase: process.env.SCHINDLER_CERT_PASSPHRASE
};

// ThyssenKrupp MAX Platform Configuration
export const thyssenkruppConfig: ElevatorConfig = {
  baseUrl: process.env.TK_MAX_URL || 'https://max.thyssenkrupp.com/api/v4',
  apiKey: process.env.TK_API_KEY || '',
  timeout: 10000, // Longer timeout for MAX cloud operations
  retryAttempts: 3,
  retryDelay: 1500,
  connectionPoolSize: 12, // MAX supports many connections
  simulatorMode: process.env.NODE_ENV === 'development',
  simulatorOptions: {
    responseDelay: 100,
    failureRate: 0.005, // TK has exceptional reliability
    randomizeStatus: true,
    floors: 100, // MULTI systems can handle 100+ floors
    travelTimePerFloor: 1500 // Faster with MULTI technology
  }
};

// ThyssenKrupp legacy TCP configuration for older systems
export const thyssenkruppTcpConfig = {
  host: process.env.TK_TCP_HOST || '192.168.1.100',
  port: parseInt(process.env.TK_TCP_PORT || '8899'),
  keepAlive: true,
  keepAliveDelay: 30000,
  noDelay: true,
  encoding: 'binary' as const
};

// Mitsubishi MELDAS Configuration
export const mitsubishiConfig: ElevatorConfig = {
  baseUrl: process.env.MITSUBISHI_API_URL || 'https://meldas.mitsubishi.com/api/v2',
  apiKey: process.env.MITSUBISHI_API_KEY || '',
  timeout: 8000,
  retryAttempts: 3,
  retryDelay: 1000,
  connectionPoolSize: 10,
  simulatorMode: process.env.NODE_ENV === 'development',
  simulatorOptions: {
    responseDelay: 80,
    failureRate: 0.003, // Mitsubishi has exceptional reliability
    randomizeStatus: true,
    floors: 80, // Supports super high-rise buildings
    travelTimePerFloor: 2000
  }
};

// Mitsubishi MODBUS configuration for industrial systems
export const mitsubishiModbusConfig = {
  host: process.env.MITSUBISHI_MODBUS_HOST || '192.168.1.200',
  port: parseInt(process.env.MITSUBISHI_MODBUS_PORT || '502'),
  unitId: parseInt(process.env.MITSUBISHI_MODBUS_UNIT || '1'),
  timeout: 5000,
  autoReconnect: true,
  reconnectTimeout: 30000,
  logEnabled: process.env.NODE_ENV === 'development'
};

// Mitsubishi device certificate for M2M communication
export const mitsubishiDeviceCert = {
  deviceId: process.env.MITSUBISHI_DEVICE_ID || '',
  certificateData: process.env.MITSUBISHI_DEVICE_CERT || '',
  m2mEndpoint: process.env.MITSUBISHI_M2M_URL || 'https://m2m.mitsubishi.com'
};

// Generic/Fallback Configuration
export const genericConfig: ElevatorConfig = {
  baseUrl: process.env.GENERIC_ELEVATOR_URL || 'http://localhost:8080',
  apiKey: process.env.GENERIC_API_KEY || 'generic-key',
  timeout: 5000,
  retryAttempts: 3,
  retryDelay: 1000,
  connectionPoolSize: 5,
  simulatorMode: true, // Always use simulator for generic
  simulatorOptions: {
    responseDelay: 100,
    failureRate: 0.05,
    randomizeStatus: true,
    floors: 20,
    travelTimePerFloor: 3000
  }
};

// Protocol-specific webhook configurations
export const webhookConfigs = {
  otis: {
    statusUpdateUrl: process.env.OTIS_WEBHOOK_URL,
    secret: process.env.OTIS_WEBHOOK_SECRET,
    events: ['status_change', 'emergency', 'maintenance', 'fault']
  },
  kone: {
    statusUpdateUrl: process.env.KONE_WEBHOOK_URL,
    bearerToken: process.env.KONE_WEBHOOK_TOKEN,
    events: ['real_time_status', 'alarm', 'maintenance_required']
  },
  schindler: {
    mqttBroker: process.env.SCHINDLER_MQTT_BROKER || 'mqtt://port.schindler.com',
    mqttUsername: process.env.SCHINDLER_MQTT_USER,
    mqttPassword: process.env.SCHINDLER_MQTT_PASS,
    topics: ['elevators/+/status', 'elevators/+/events', 'elevators/+/alarms']
  },
  thyssenkrupp: {
    sseEndpoint: process.env.TK_SSE_ENDPOINT,
    sseToken: process.env.TK_SSE_TOKEN,
    eventTypes: ['status', 'predictive', 'emergency', 'energy']
  },
  mitsubishi: {
    websocketUrl: process.env.MITSUBISHI_WS_URL || 'wss://meldas.mitsubishi.com/ws',
    websocketProtocol: 'meldas-v2',
    binaryFrames: true,
    compression: true
  }
};

// Performance tuning configurations
export const performanceConfigs = {
  otis: {
    maxConcurrentRequests: 10,
    requestQueueSize: 100,
    circuitBreakerThreshold: 5,
    circuitBreakerTimeout: 60000
  },
  kone: {
    maxConcurrentRequests: 20, // KONE handles more concurrent requests
    requestQueueSize: 200,
    circuitBreakerThreshold: 3,
    circuitBreakerTimeout: 30000,
    tokenRefreshBuffer: 300000 // Refresh token 5 minutes before expiry
  },
  schindler: {
    maxConcurrentRequests: 15,
    requestQueueSize: 150,
    circuitBreakerThreshold: 3,
    circuitBreakerTimeout: 45000,
    sessionRenewalInterval: 3600000 // Renew session every hour
  },
  thyssenkrupp: {
    maxConcurrentRequests: 25, // MAX platform is highly scalable
    requestQueueSize: 250,
    circuitBreakerThreshold: 5,
    circuitBreakerTimeout: 30000,
    predictiveCacheSize: 1000,
    predictiveCacheTTL: 300000
  },
  mitsubishi: {
    maxConcurrentRequests: 20,
    requestQueueSize: 200,
    circuitBreakerThreshold: 3,
    circuitBreakerTimeout: 40000,
    aiOptimizationEnabled: true,
    energyOptimizationMode: 'aggressive'
  }
};

// Export a function to get configuration by manufacturer
export function getProtocolConfig(manufacturer: string): ElevatorConfig {
  const configs: Record<string, ElevatorConfig> = {
    OTIS: otisConfig,
    KONE: koneConfig,
    SCHINDLER: schindlerConfig,
    THYSSENKRUPP: thyssenkruppConfig,
    MITSUBISHI: mitsubishiConfig,
    GENERIC: genericConfig
  };
  
  return configs[manufacturer] || genericConfig;
}

// Export all configurations
export default {
  otis: {
    config: otisConfig,
    webhook: webhookConfigs.otis,
    performance: performanceConfigs.otis
  },
  kone: {
    config: koneConfig,
    oauth2: koneOAuth2Config,
    webhook: webhookConfigs.kone,
    performance: performanceConfigs.kone
  },
  schindler: {
    config: schindlerConfig,
    certificates: schindlerCertConfig,
    webhook: webhookConfigs.schindler,
    performance: performanceConfigs.schindler
  },
  thyssenkrupp: {
    config: thyssenkruppConfig,
    tcp: thyssenkruppTcpConfig,
    webhook: webhookConfigs.thyssenkrupp,
    performance: performanceConfigs.thyssenkrupp
  },
  mitsubishi: {
    config: mitsubishiConfig,
    modbus: mitsubishiModbusConfig,
    device: mitsubishiDeviceCert,
    webhook: webhookConfigs.mitsubishi,
    performance: performanceConfigs.mitsubishi
  },
  generic: {
    config: genericConfig
  }
};