// Export all types and interfaces for the service
export interface ServiceConfig {
  port: number;
  redisUrl: string;
  jwtSecret: string;
  // Add service-specific config
}

// Add service-specific types here
