import { Logger } from '../utils/logger';

export interface ElevatorStatus {
  currentFloor: number;
  direction: 'UP' | 'DOWN' | 'STATIONARY';
  doorStatus: 'OPEN' | 'CLOSED' | 'OPENING' | 'CLOSING' | 'BLOCKED';
  operationalStatus: 'NORMAL' | 'MAINTENANCE' | 'OUT_OF_SERVICE' | 'EMERGENCY';
  emergencyMode: boolean;
  load: number; // Percentage of max capacity
  speed: number; // Current speed in m/s
  errorCodes: string[];
  lastUpdate: string;
  temperature?: number;
  motorStatus?: string;
  brakeStatus?: string;
}

export interface ElevatorConfig {
  baseUrl: string;
  apiKey: string;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
  connectionPoolSize?: number;
  simulatorMode?: boolean;
  simulatorOptions?: SimulatorOptions;
}

export interface SimulatorOptions {
  responseDelay?: number; // ms
  failureRate?: number; // 0-1
  randomizeStatus?: boolean;
  floors?: number;
  travelTimePerFloor?: number; // ms
}

export interface FloorRequest {
  elevatorId: string;
  floor: number;
  userId: string;
  priority?: 'LOW' | 'NORMAL' | 'HIGH' | 'EMERGENCY';
  direction?: 'UP' | 'DOWN';
}

export interface AccessGrant {
  elevatorId: string;
  floor: number;
  userId: string;
  duration: number; // seconds
  accessCode?: string;
}

export abstract class BaseElevatorAdapter {
  protected logger: Logger;
  protected config: ElevatorConfig;
  protected isConnected: boolean = false;
  protected connectionPool: any[] = [];
  protected retryCount: Map<string, number> = new Map();

  constructor(config: ElevatorConfig, logger: Logger) {
    this.config = {
      timeout: 5000,
      retryAttempts: 3,
      retryDelay: 1000,
      connectionPoolSize: 5,
      simulatorMode: false,
      ...config
    };
    this.logger = logger;
  }

  /**
   * Establish connection to elevator system
   */
  abstract connect(): Promise<boolean>;

  /**
   * Disconnect from elevator system
   */
  abstract disconnect(): Promise<void>;

  /**
   * Call elevator to a specific floor
   */
  abstract callElevator(request: FloorRequest): Promise<boolean>;

  /**
   * Grant access to a specific floor
   */
  abstract grantAccess(grant: AccessGrant): Promise<boolean>;

  /**
   * Get current elevator status
   */
  abstract getStatus(elevatorId: string): Promise<ElevatorStatus | null>;

  /**
   * Emergency control
   */
  abstract emergency(elevatorId: string, action: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN', reason: string): Promise<boolean>;

  /**
   * Set elevator to maintenance mode
   */
  abstract setMaintenanceMode(elevatorId: string, enabled: boolean, reason: string): Promise<boolean>;

  /**
   * Reset elevator system
   */
  abstract reset(elevatorId: string): Promise<boolean>;

  /**
   * Get diagnostic information
   */
  abstract getDiagnostics(elevatorId: string): Promise<any>;

  /**
   * Register for real-time updates
   */
  abstract subscribeToUpdates(elevatorId: string, callback: (status: ElevatorStatus) => void): Promise<void>;

  /**
   * Unregister from real-time updates
   */
  abstract unsubscribeFromUpdates(elevatorId: string): Promise<void>;

  /**
   * Helper method for retry logic
   */
  protected async withRetry<T>(
    operation: () => Promise<T>,
    operationName: string,
    context?: any
  ): Promise<T> {
    const maxAttempts = this.config.retryAttempts || 3;
    const retryDelay = this.config.retryDelay || 1000;
    const key = `${operationName}-${JSON.stringify(context)}`;
    
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        this.logger.debug(`Attempting ${operationName} (attempt ${attempt}/${maxAttempts})`, context);
        const result = await operation();
        
        // Reset retry count on success
        this.retryCount.delete(key);
        
        return result;
      } catch (error) {
        lastError = error as Error;
        this.logger.warn(`${operationName} failed (attempt ${attempt}/${maxAttempts})`, {
          error: error.message,
          context,
          attempt
        });
        
        if (attempt < maxAttempts) {
          await this.delay(retryDelay * attempt); // Exponential backoff
        }
      }
    }
    
    // All attempts failed
    this.logger.error(`${operationName} failed after ${maxAttempts} attempts`, {
      error: lastError?.message,
      context
    });
    
    throw lastError || new Error(`${operationName} failed after ${maxAttempts} attempts`);
  }

  /**
   * Helper method for delays
   */
  protected delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Validate elevator ID format
   */
  protected validateElevatorId(elevatorId: string): boolean {
    // Basic validation - can be overridden by specific adapters
    return /^[a-zA-Z0-9-_]+$/.test(elevatorId);
  }

  /**
   * Validate floor number
   */
  protected validateFloor(floor: number, maxFloor: number = 100): boolean {
    return Number.isInteger(floor) && floor >= -10 && floor <= maxFloor;
  }

  /**
   * Get connection from pool
   */
  protected async getConnection(): Promise<any> {
    if (this.connectionPool.length === 0) {
      throw new Error('No connections available in pool');
    }
    
    // Simple round-robin
    const connection = this.connectionPool.shift();
    this.connectionPool.push(connection);
    
    return connection;
  }

  /**
   * Check if connected
   */
  public isSystemConnected(): boolean {
    return this.isConnected;
  }

  /**
   * Get adapter information
   */
  public getAdapterInfo(): any {
    return {
      connected: this.isConnected,
      poolSize: this.connectionPool.length,
      simulatorMode: this.config.simulatorMode,
      retryAttempts: this.config.retryAttempts,
      timeout: this.config.timeout
    };
  }
}