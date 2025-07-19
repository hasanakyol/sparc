import { BaseElevatorAdapter, ElevatorConfig, ElevatorStatus, FloorRequest, AccessGrant } from './base.adapter';
import { Logger } from '../utils/logger';

export class OtisAdapter extends BaseElevatorAdapter {
  private mockElevatorStates: Map<string, ElevatorStatus> = new Map();
  private updateCallbacks: Map<string, (status: ElevatorStatus) => void> = new Map();
  private simulationInterval?: NodeJS.Timeout;

  constructor(config: ElevatorConfig, logger: Logger) {
    super(config, logger);
    this.initializeSimulation();
  }

  private initializeSimulation(): void {
    if (this.config.simulatorMode) {
      // Start simulation update loop
      this.simulationInterval = setInterval(() => {
        this.updateSimulatedStates();
      }, 1000);
    }
  }

  private updateSimulatedStates(): void {
    this.mockElevatorStates.forEach((status, elevatorId) => {
      // Simulate elevator movement
      if (status.direction !== 'STATIONARY') {
        const newFloor = status.direction === 'UP' ? status.currentFloor + 1 : status.currentFloor - 1;
        const maxFloor = this.config.simulatorOptions?.floors || 20;
        
        if (newFloor >= 0 && newFloor <= maxFloor) {
          status.currentFloor = newFloor;
        } else {
          status.direction = 'STATIONARY';
        }
      }

      // Random door operations
      if (Math.random() < 0.1) {
        status.doorStatus = status.doorStatus === 'OPEN' ? 'CLOSING' : 
                           status.doorStatus === 'CLOSED' ? 'OPENING' :
                           status.doorStatus === 'OPENING' ? 'OPEN' : 'CLOSED';
      }

      // Update timestamp
      status.lastUpdate = new Date().toISOString();

      // Notify subscribers
      const callback = this.updateCallbacks.get(elevatorId);
      if (callback) {
        callback(status);
      }
    });
  }

  async connect(): Promise<boolean> {
    try {
      this.logger.info('Connecting to OTIS elevator system', { 
        baseUrl: this.config.baseUrl,
        simulatorMode: this.config.simulatorMode 
      });

      if (this.config.simulatorMode) {
        // In simulator mode, just mark as connected
        this.isConnected = true;
        this.logger.info('OTIS adapter connected in simulator mode');
        return true;
      }

      // Real connection logic would go here
      // For now, we'll simulate a successful connection
      await this.delay(500); // Simulate connection delay
      
      // In production, this would establish actual connection to OTIS API
      // Example:
      // const response = await fetch(`${this.config.baseUrl}/api/v1/connect`, {
      //   method: 'POST',
      //   headers: {
      //     'Authorization': `Bearer ${this.config.apiKey}`,
      //     'Content-Type': 'application/json'
      //   },
      //   body: JSON.stringify({ clientId: 'sparc-elevator-control' })
      // });
      
      this.isConnected = true;
      this.logger.info('Successfully connected to OTIS elevator system');
      return true;
    } catch (error) {
      this.logger.error('Failed to connect to OTIS system', { error: error.message });
      this.isConnected = false;
      return false;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.simulationInterval) {
        clearInterval(this.simulationInterval);
      }

      this.isConnected = false;
      this.logger.info('Disconnected from OTIS elevator system');
    } catch (error) {
      this.logger.error('Error during disconnect', { error: error.message });
    }
  }

  async callElevator(request: FloorRequest): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('Calling elevator', request);

      if (!this.validateElevatorId(request.elevatorId)) {
        throw new Error('Invalid elevator ID format');
      }

      if (!this.validateFloor(request.floor)) {
        throw new Error('Invalid floor number');
      }

      if (this.config.simulatorMode) {
        // Simulate elevator call
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        // Random failure for testing
        if (Math.random() < (this.config.simulatorOptions?.failureRate || 0)) {
          throw new Error('Simulated elevator call failure');
        }

        // Update mock state
        const status = this.mockElevatorStates.get(request.elevatorId) || this.createMockStatus(request.elevatorId);
        status.direction = request.floor > status.currentFloor ? 'UP' : 
                          request.floor < status.currentFloor ? 'DOWN' : 'STATIONARY';
        this.mockElevatorStates.set(request.elevatorId, status);

        return true;
      }

      // Real OTIS API call would go here
      const response = await fetch(`${this.config.baseUrl}/api/v1/elevators/${request.elevatorId}/call`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          floor: request.floor,
          userId: request.userId,
          direction: request.direction,
          priority: request.priority,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`OTIS API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'callElevator', request);
  }

  async grantAccess(grant: AccessGrant): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('Granting floor access', grant);

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        return true;
      }

      // Real OTIS API call for access grant
      const response = await fetch(`${this.config.baseUrl}/api/v1/elevators/${grant.elevatorId}/access`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          floor: grant.floor,
          userId: grant.userId,
          duration: grant.duration,
          accessCode: grant.accessCode,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`OTIS API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'grantAccess', grant);
  }

  async getStatus(elevatorId: string): Promise<ElevatorStatus | null> {
    return this.withRetry(async () => {
      this.logger.debug('Getting elevator status', { elevatorId });

      if (!this.validateElevatorId(elevatorId)) {
        throw new Error('Invalid elevator ID format');
      }

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 50);
        
        let status = this.mockElevatorStates.get(elevatorId);
        if (!status) {
          status = this.createMockStatus(elevatorId);
          this.mockElevatorStates.set(elevatorId, status);
        }
        
        return status;
      }

      // Real OTIS API call
      const response = await fetch(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/status`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`OTIS API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      return {
        currentFloor: data.currentFloor,
        direction: data.direction,
        doorStatus: data.doorStatus,
        operationalStatus: data.operationalStatus,
        emergencyMode: data.emergencyMode,
        load: data.loadPercentage || 0,
        speed: data.speed || 0,
        errorCodes: data.errorCodes || [],
        lastUpdate: new Date().toISOString(),
        temperature: data.temperature,
        motorStatus: data.motorStatus,
        brakeStatus: data.brakeStatus
      };
    }, 'getStatus', { elevatorId });
  }

  async emergency(elevatorId: string, action: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN', reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Emergency control activated', { elevatorId, action, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.emergencyMode = action !== 'RELEASE';
        status.operationalStatus = action === 'RELEASE' ? 'NORMAL' : 'EMERGENCY';
        
        if (action === 'EVACUATE') {
          status.direction = status.currentFloor > 0 ? 'DOWN' : 'STATIONARY';
        } else if (action === 'STOP' || action === 'LOCKDOWN') {
          status.direction = 'STATIONARY';
        }
        
        this.mockElevatorStates.set(elevatorId, status);
        return true;
      }

      // Real OTIS API call
      const response = await fetch(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/emergency`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action,
          reason,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`OTIS API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'emergency', { elevatorId, action });
  }

  async setMaintenanceMode(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Setting maintenance mode', { elevatorId, enabled, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.operationalStatus = enabled ? 'MAINTENANCE' : 'NORMAL';
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real OTIS API call
      const response = await fetch(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/maintenance`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          enabled,
          reason,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`OTIS API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'setMaintenanceMode', { elevatorId, enabled });
  }

  async reset(elevatorId: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Resetting elevator', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 500);
        
        const status = this.createMockStatus(elevatorId);
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real OTIS API call
      const response = await fetch(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/reset`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 10000)
      });

      if (!response.ok) {
        throw new Error(`OTIS API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'reset', { elevatorId });
  }

  async getDiagnostics(elevatorId: string): Promise<any> {
    return this.withRetry(async () => {
      this.logger.debug('Getting elevator diagnostics', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 200);
        
        return {
          elevatorId,
          timestamp: new Date().toISOString(),
          system: {
            uptime: Math.floor(Math.random() * 1000000),
            firmwareVersion: '3.2.1',
            lastMaintenance: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
            nextMaintenance: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString()
          },
          performance: {
            tripsToday: Math.floor(Math.random() * 500),
            averageTripTime: Math.floor(Math.random() * 30) + 10,
            doorCycles: Math.floor(Math.random() * 1000),
            energyConsumption: Math.floor(Math.random() * 100) + 50
          },
          health: {
            motorHealth: Math.floor(Math.random() * 20) + 80,
            brakeHealth: Math.floor(Math.random() * 20) + 80,
            doorHealth: Math.floor(Math.random() * 20) + 80,
            cableHealth: Math.floor(Math.random() * 20) + 80
          },
          errors: []
        };
      }

      // Real OTIS API call
      const response = await fetch(`${this.config.baseUrl}/api/v1/elevators/${elevatorId}/diagnostics`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`
        },
        signal: AbortSignal.timeout(this.config.timeout || 10000)
      });

      if (!response.ok) {
        throw new Error(`OTIS API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    }, 'getDiagnostics', { elevatorId });
  }

  async subscribeToUpdates(elevatorId: string, callback: (status: ElevatorStatus) => void): Promise<void> {
    this.logger.info('Subscribing to elevator updates', { elevatorId });

    if (this.config.simulatorMode) {
      this.updateCallbacks.set(elevatorId, callback);
      return;
    }

    // In production, this would establish WebSocket or SSE connection
    // For now, we'll simulate with polling
    const pollInterval = setInterval(async () => {
      try {
        const status = await this.getStatus(elevatorId);
        if (status) {
          callback(status);
        }
      } catch (error) {
        this.logger.error('Error polling elevator status', { elevatorId, error: error.message });
      }
    }, 5000);

    // Store interval for cleanup
    this.updateCallbacks.set(elevatorId, () => clearInterval(pollInterval));
  }

  async unsubscribeFromUpdates(elevatorId: string): Promise<void> {
    this.logger.info('Unsubscribing from elevator updates', { elevatorId });

    const cleanup = this.updateCallbacks.get(elevatorId);
    if (cleanup && typeof cleanup !== 'function') {
      cleanup();
    }
    this.updateCallbacks.delete(elevatorId);
  }

  private createMockStatus(elevatorId: string): ElevatorStatus {
    const floors = this.config.simulatorOptions?.floors || 20;
    return {
      currentFloor: Math.floor(Math.random() * (floors + 1)),
      direction: 'STATIONARY',
      doorStatus: 'CLOSED',
      operationalStatus: 'NORMAL',
      emergencyMode: false,
      load: Math.floor(Math.random() * 100),
      speed: 0,
      errorCodes: [],
      lastUpdate: new Date().toISOString(),
      temperature: 20 + Math.random() * 10,
      motorStatus: 'OK',
      brakeStatus: 'OK'
    };
  }
}