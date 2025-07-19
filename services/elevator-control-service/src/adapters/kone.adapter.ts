import { BaseElevatorAdapter, ElevatorConfig, ElevatorStatus, FloorRequest, AccessGrant } from './base.adapter';
import { Logger } from '../utils/logger';

/**
 * KONE Elevator Control Protocol Adapter
 * Implements communication with KONE elevator systems using their proprietary API
 * 
 * Protocol specifications:
 * - Uses REST API with JSON payloads
 * - Authentication via OAuth2 bearer tokens
 * - Real-time updates via WebSocket connections
 * - Supports KONE's DX and MonoSpace series
 */
export class KoneAdapter extends BaseElevatorAdapter {
  private mockElevatorStates: Map<string, ElevatorStatus> = new Map();
  private updateCallbacks: Map<string, (status: ElevatorStatus) => void> = new Map();
  private simulationInterval?: NodeJS.Timeout;
  private accessToken?: string;
  private tokenExpiry?: Date;
  private webSocketConnections: Map<string, WebSocket> = new Map();

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
      // Simulate elevator movement with KONE-specific behavior
      if (status.direction !== 'STATIONARY') {
        const newFloor = status.direction === 'UP' ? status.currentFloor + 1 : status.currentFloor - 1;
        const maxFloor = this.config.simulatorOptions?.floors || 20;
        
        if (newFloor >= -2 && newFloor <= maxFloor) { // KONE typically supports basement floors
          status.currentFloor = newFloor;
          // KONE elevators have smooth acceleration/deceleration
          status.speed = this.calculateSpeed(status.currentFloor, maxFloor);
        } else {
          status.direction = 'STATIONARY';
          status.speed = 0;
        }
      }

      // KONE-specific door operation patterns
      if (Math.random() < 0.08) {
        status.doorStatus = status.doorStatus === 'OPEN' ? 'CLOSING' : 
                           status.doorStatus === 'CLOSED' ? 'OPENING' :
                           status.doorStatus === 'OPENING' ? 'OPEN' : 'CLOSED';
      }

      // Update load with KONE's people flow intelligence simulation
      if (status.doorStatus === 'OPEN') {
        status.load = Math.min(100, status.load + Math.floor(Math.random() * 20));
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

  private calculateSpeed(currentFloor: number, maxFloor: number): number {
    // KONE elevators have variable speed based on distance to travel
    const middleFloor = maxFloor / 2;
    const distanceFromMiddle = Math.abs(currentFloor - middleFloor);
    const maxSpeed = 6.0; // m/s for high-speed KONE elevators
    return Math.min(maxSpeed, 1.0 + (distanceFromMiddle / middleFloor) * (maxSpeed - 1.0));
  }

  private async refreshAccessToken(): Promise<void> {
    if (this.accessToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return; // Token still valid
    }

    try {
      this.logger.debug('Refreshing KONE access token');
      
      const response = await fetch(`${this.config.baseUrl}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: this.config.apiKey,
          client_secret: process.env.KONE_CLIENT_SECRET || '',
          scope: 'elevator.control elevator.monitor'
        })
      });

      if (!response.ok) {
        throw new Error(`KONE OAuth error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      this.accessToken = data.access_token;
      this.tokenExpiry = new Date(Date.now() + (data.expires_in - 60) * 1000); // Refresh 1 minute before expiry
      
      this.logger.info('KONE access token refreshed successfully');
    } catch (error) {
      this.logger.error('Failed to refresh KONE access token', { error: error.message });
      throw error;
    }
  }

  async connect(): Promise<boolean> {
    try {
      this.logger.info('Connecting to KONE elevator system', { 
        baseUrl: this.config.baseUrl,
        simulatorMode: this.config.simulatorMode 
      });

      if (this.config.simulatorMode) {
        // In simulator mode, just mark as connected
        this.isConnected = true;
        this.logger.info('KONE adapter connected in simulator mode');
        return true;
      }

      // Refresh access token
      await this.refreshAccessToken();
      
      // Verify connection with KONE API
      const response = await fetch(`${this.config.baseUrl}/api/v2/system/status`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'X-KONE-Client-Version': '2.0'
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`KONE connection verification failed: ${response.status}`);
      }

      const systemStatus = await response.json();
      this.logger.info('Connected to KONE system', { 
        version: systemStatus.version,
        region: systemStatus.region 
      });
      
      this.isConnected = true;
      return true;
    } catch (error) {
      this.logger.error('Failed to connect to KONE system', { error: error.message });
      this.isConnected = false;
      return false;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.simulationInterval) {
        clearInterval(this.simulationInterval);
      }

      // Close all WebSocket connections
      this.webSocketConnections.forEach((ws, elevatorId) => {
        ws.close();
        this.logger.debug(`Closed WebSocket for elevator ${elevatorId}`);
      });
      this.webSocketConnections.clear();

      this.isConnected = false;
      this.logger.info('Disconnected from KONE elevator system');
    } catch (error) {
      this.logger.error('Error during disconnect', { error: error.message });
    }
  }

  async callElevator(request: FloorRequest): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('KONE: Calling elevator', request);

      if (!this.validateElevatorId(request.elevatorId)) {
        throw new Error('Invalid elevator ID format');
      }

      if (!this.validateFloor(request.floor, 50)) { // KONE supports up to 50 floors typically
        throw new Error('Invalid floor number');
      }

      if (this.config.simulatorMode) {
        // Simulate elevator call with KONE-specific behavior
        await this.delay(this.config.simulatorOptions?.responseDelay || 150);
        
        // KONE has lower failure rates due to robust systems
        if (Math.random() < (this.config.simulatorOptions?.failureRate || 0.02)) {
          throw new Error('Simulated KONE elevator call failure');
        }

        // Update mock state
        const status = this.mockElevatorStates.get(request.elevatorId) || this.createMockStatus(request.elevatorId);
        
        // KONE's destination control system optimization
        if (request.priority === 'EMERGENCY') {
          status.direction = request.floor > status.currentFloor ? 'UP' : 'DOWN';
          status.operationalStatus = 'EMERGENCY';
        } else {
          status.direction = request.floor > status.currentFloor ? 'UP' : 
                          request.floor < status.currentFloor ? 'DOWN' : 'STATIONARY';
        }
        
        this.mockElevatorStates.set(request.elevatorId, status);
        return true;
      }

      // Real KONE API call
      await this.refreshAccessToken();
      
      const response = await fetch(`${this.config.baseUrl}/api/v2/elevators/${request.elevatorId}/call`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
          'X-KONE-Client-Version': '2.0'
        },
        body: JSON.stringify({
          destinationFloor: request.floor,
          requesterId: request.userId,
          direction: request.direction || 'ANY',
          priority: request.priority || 'NORMAL',
          requestTime: new Date().toISOString(),
          accessibility: false // Could be enhanced with user preferences
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`KONE API error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      this.logger.info('KONE elevator called successfully', { 
        elevatorId: request.elevatorId,
        assignedCar: result.assignedCar 
      });
      
      return true;
    }, 'callElevator', request);
  }

  async grantAccess(grant: AccessGrant): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('KONE: Granting floor access', grant);

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        return true;
      }

      // KONE uses their Access Control Integration
      await this.refreshAccessToken();
      
      const response = await fetch(`${this.config.baseUrl}/api/v2/elevators/${grant.elevatorId}/access-control`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
          'X-KONE-Client-Version': '2.0'
        },
        body: JSON.stringify({
          floor: grant.floor,
          userId: grant.userId,
          validityPeriod: grant.duration,
          accessCode: grant.accessCode,
          grantTime: new Date().toISOString(),
          accessType: 'TEMPORARY'
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`KONE API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'grantAccess', grant);
  }

  async getStatus(elevatorId: string): Promise<ElevatorStatus | null> {
    return this.withRetry(async () => {
      this.logger.debug('KONE: Getting elevator status', { elevatorId });

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

      // Real KONE API call
      await this.refreshAccessToken();
      
      const response = await fetch(`${this.config.baseUrl}/api/v2/elevators/${elevatorId}/status`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'X-KONE-Client-Version': '2.0'
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`KONE API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      // Map KONE-specific status format
      return {
        currentFloor: data.position.floor,
        direction: data.movement.direction.toUpperCase(),
        doorStatus: this.mapKoneDoorStatus(data.door.state),
        operationalStatus: this.mapKoneOperationalStatus(data.operational.mode),
        emergencyMode: data.safety.emergencyActive,
        load: data.car.loadPercentage || 0,
        speed: data.movement.velocity || 0,
        errorCodes: data.diagnostics.activeFaults || [],
        lastUpdate: new Date().toISOString(),
        temperature: data.environment.temperature,
        motorStatus: data.motor.condition,
        brakeStatus: data.brake.condition
      };
    }, 'getStatus', { elevatorId });
  }

  private mapKoneDoorStatus(koneStatus: string): ElevatorStatus['doorStatus'] {
    const mapping: Record<string, ElevatorStatus['doorStatus']> = {
      'FULLY_OPEN': 'OPEN',
      'FULLY_CLOSED': 'CLOSED',
      'OPENING': 'OPENING',
      'CLOSING': 'CLOSING',
      'OBSTRUCTED': 'BLOCKED',
      'SAFETY_EDGE_ACTIVATED': 'BLOCKED'
    };
    return mapping[koneStatus] || 'CLOSED';
  }

  private mapKoneOperationalStatus(koneMode: string): ElevatorStatus['operationalStatus'] {
    const mapping: Record<string, ElevatorStatus['operationalStatus']> = {
      'NORMAL_OPERATION': 'NORMAL',
      'MAINTENANCE_MODE': 'MAINTENANCE',
      'OUT_OF_ORDER': 'OUT_OF_SERVICE',
      'EMERGENCY_OPERATION': 'EMERGENCY',
      'FIRE_SERVICE': 'EMERGENCY',
      'INSPECTION_MODE': 'MAINTENANCE'
    };
    return mapping[koneMode] || 'NORMAL';
  }

  async emergency(elevatorId: string, action: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN', reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('KONE: Emergency control activated', { elevatorId, action, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.emergencyMode = action !== 'RELEASE';
        status.operationalStatus = action === 'RELEASE' ? 'NORMAL' : 'EMERGENCY';
        
        // KONE-specific emergency behavior
        if (action === 'EVACUATE') {
          // KONE elevators go to nearest floor in evacuation mode
          status.direction = 'STATIONARY';
          status.doorStatus = 'OPEN';
        } else if (action === 'STOP') {
          status.direction = 'STATIONARY';
          status.speed = 0;
        } else if (action === 'LOCKDOWN') {
          status.direction = 'STATIONARY';
          status.doorStatus = 'CLOSED';
        }
        
        this.mockElevatorStates.set(elevatorId, status);
        return true;
      }

      // Real KONE API call
      await this.refreshAccessToken();
      
      const response = await fetch(`${this.config.baseUrl}/api/v2/elevators/${elevatorId}/emergency-control`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
          'X-KONE-Client-Version': '2.0',
          'X-KONE-Emergency-Override': 'true'
        },
        body: JSON.stringify({
          command: action,
          reason: reason,
          requestTime: new Date().toISOString(),
          operatorId: 'SPARC_SYSTEM'
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`KONE API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'emergency', { elevatorId, action });
  }

  async setMaintenanceMode(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('KONE: Setting maintenance mode', { elevatorId, enabled, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.operationalStatus = enabled ? 'MAINTENANCE' : 'NORMAL';
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real KONE API call
      await this.refreshAccessToken();
      
      const response = await fetch(`${this.config.baseUrl}/api/v2/elevators/${elevatorId}/maintenance`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
          'X-KONE-Client-Version': '2.0'
        },
        body: JSON.stringify({
          maintenanceMode: enabled,
          reason: reason,
          scheduledBy: 'SPARC_SYSTEM',
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`KONE API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'setMaintenanceMode', { elevatorId, enabled });
  }

  async reset(elevatorId: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('KONE: Resetting elevator', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 800);
        
        const status = this.createMockStatus(elevatorId);
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real KONE API call
      await this.refreshAccessToken();
      
      const response = await fetch(`${this.config.baseUrl}/api/v2/elevators/${elevatorId}/reset`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
          'X-KONE-Client-Version': '2.0'
        },
        body: JSON.stringify({
          resetType: 'SOFT_RESET',
          clearFaults: true,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 10000)
      });

      if (!response.ok) {
        throw new Error(`KONE API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'reset', { elevatorId });
  }

  async getDiagnostics(elevatorId: string): Promise<any> {
    return this.withRetry(async () => {
      this.logger.debug('KONE: Getting elevator diagnostics', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 200);
        
        return {
          elevatorId,
          timestamp: new Date().toISOString(),
          system: {
            uptime: Math.floor(Math.random() * 2000000),
            firmwareVersion: 'KONE-DX-4.5.2',
            lastMaintenance: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
            nextMaintenance: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000).toISOString(),
            manufacturer: 'KONE Corporation',
            model: 'MonoSpace DX'
          },
          performance: {
            tripsToday: Math.floor(Math.random() * 600),
            averageTripTime: Math.floor(Math.random() * 25) + 15,
            doorCycles: Math.floor(Math.random() * 1200),
            energyConsumption: Math.floor(Math.random() * 80) + 40,
            peopleFlowEfficiency: Math.floor(Math.random() * 20) + 75
          },
          health: {
            motorHealth: Math.floor(Math.random() * 15) + 85,
            brakeHealth: Math.floor(Math.random() * 15) + 85,
            doorHealth: Math.floor(Math.random() * 15) + 85,
            cableHealth: Math.floor(Math.random() * 15) + 85,
            controlSystemHealth: Math.floor(Math.random() * 10) + 90
          },
          koneSpecific: {
            ecoEfficiencyRating: 'A+',
            peopleFlowIntelligence: true,
            connectedServices: ['24/7 Connected', 'KONE Care', 'People Flow Planning']
          },
          errors: []
        };
      }

      // Real KONE API call
      await this.refreshAccessToken();
      
      const response = await fetch(`${this.config.baseUrl}/api/v2/elevators/${elevatorId}/diagnostics/full`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'X-KONE-Client-Version': '2.0'
        },
        signal: AbortSignal.timeout(this.config.timeout || 10000)
      });

      if (!response.ok) {
        throw new Error(`KONE API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    }, 'getDiagnostics', { elevatorId });
  }

  async subscribeToUpdates(elevatorId: string, callback: (status: ElevatorStatus) => void): Promise<void> {
    this.logger.info('KONE: Subscribing to elevator updates', { elevatorId });

    if (this.config.simulatorMode) {
      this.updateCallbacks.set(elevatorId, callback);
      return;
    }

    // KONE uses WebSocket for real-time updates
    await this.refreshAccessToken();
    
    const wsUrl = this.config.baseUrl.replace('https://', 'wss://').replace('http://', 'ws://');
    const ws = new WebSocket(`${wsUrl}/ws/elevators/${elevatorId}?token=${this.accessToken}`);
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const status: ElevatorStatus = {
          currentFloor: data.position.floor,
          direction: data.movement.direction.toUpperCase(),
          doorStatus: this.mapKoneDoorStatus(data.door.state),
          operationalStatus: this.mapKoneOperationalStatus(data.operational.mode),
          emergencyMode: data.safety.emergencyActive,
          load: data.car.loadPercentage || 0,
          speed: data.movement.velocity || 0,
          errorCodes: data.diagnostics.activeFaults || [],
          lastUpdate: new Date().toISOString(),
          temperature: data.environment.temperature,
          motorStatus: data.motor.condition,
          brakeStatus: data.brake.condition
        };
        callback(status);
      } catch (error) {
        this.logger.error('Error parsing KONE WebSocket message', { elevatorId, error: error.message });
      }
    };

    ws.onerror = (error) => {
      this.logger.error('KONE WebSocket error', { elevatorId, error });
    };

    ws.onclose = () => {
      this.logger.info('KONE WebSocket closed', { elevatorId });
      this.webSocketConnections.delete(elevatorId);
    };

    this.webSocketConnections.set(elevatorId, ws);
    this.updateCallbacks.set(elevatorId, callback);
  }

  async unsubscribeFromUpdates(elevatorId: string): Promise<void> {
    this.logger.info('KONE: Unsubscribing from elevator updates', { elevatorId });

    const ws = this.webSocketConnections.get(elevatorId);
    if (ws) {
      ws.close();
      this.webSocketConnections.delete(elevatorId);
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
      load: Math.floor(Math.random() * 70), // KONE typically has lower average loads due to efficient dispatching
      speed: 0,
      errorCodes: [],
      lastUpdate: new Date().toISOString(),
      temperature: 22 + Math.random() * 5, // KONE elevators have good climate control
      motorStatus: 'OPTIMAL',
      brakeStatus: 'OPTIMAL'
    };
  }
}