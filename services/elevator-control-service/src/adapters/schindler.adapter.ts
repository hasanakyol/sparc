import { BaseElevatorAdapter, ElevatorConfig, ElevatorStatus, FloorRequest, AccessGrant } from './base.adapter';
import { Logger } from '../utils/logger';

/**
 * Schindler Elevator Control Protocol Adapter
 * Implements communication with Schindler elevator systems using their PORT Technology API
 * 
 * Protocol specifications:
 * - Uses SOAP/XML for legacy systems, REST/JSON for newer PORT systems
 * - Authentication via API key and certificate-based mutual TLS
 * - Real-time updates via MQTT broker
 * - Supports Schindler 3300, 5500, and PORT Technology elevators
 */
export class SchindlerAdapter extends BaseElevatorAdapter {
  private mockElevatorStates: Map<string, ElevatorStatus> = new Map();
  private updateCallbacks: Map<string, (status: ElevatorStatus) => void> = new Map();
  private simulationInterval?: NodeJS.Timeout;
  private mqttClient?: any; // Would be MQTT client in production
  private sessionId?: string;
  private certificateFingerprint?: string;

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
      // Simulate elevator movement with Schindler-specific behavior
      if (status.direction !== 'STATIONARY') {
        const newFloor = status.direction === 'UP' ? status.currentFloor + 1 : status.currentFloor - 1;
        const maxFloor = this.config.simulatorOptions?.floors || 25; // Schindler typically handles taller buildings
        
        if (newFloor >= -3 && newFloor <= maxFloor) { // Schindler supports multiple basement levels
          status.currentFloor = newFloor;
          // Schindler PORT technology optimizes speed based on traffic patterns
          status.speed = this.calculateOptimizedSpeed(status);
        } else {
          status.direction = 'STATIONARY';
          status.speed = 0;
        }
      }

      // Schindler-specific door operation with miconic 10 integration
      if (Math.random() < 0.09) {
        if (status.doorStatus === 'CLOSED' && status.direction === 'STATIONARY') {
          status.doorStatus = 'OPENING';
        } else if (status.doorStatus === 'OPEN') {
          // Schindler has adaptive door timing
          const doorOpenDuration = status.load > 70 ? 0.15 : 0.1;
          if (Math.random() < doorOpenDuration) {
            status.doorStatus = 'CLOSING';
          }
        } else if (status.doorStatus === 'OPENING') {
          status.doorStatus = 'OPEN';
        } else if (status.doorStatus === 'CLOSING') {
          status.doorStatus = 'CLOSED';
        }
      }

      // PORT Technology destination dispatch simulation
      if (status.doorStatus === 'OPEN' && Math.random() < 0.2) {
        const loadChange = Math.floor(Math.random() * 30) - 15;
        status.load = Math.max(0, Math.min(100, status.load + loadChange));
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

  private calculateOptimizedSpeed(status: ElevatorStatus): number {
    // Schindler PORT optimizes speed based on load and destination
    const baseSpeed = 4.0; // m/s for Schindler 5500
    const loadFactor = 1 - (status.load / 100) * 0.2; // Slower with higher load
    const emergencyFactor = status.emergencyMode ? 1.2 : 1.0;
    return baseSpeed * loadFactor * emergencyFactor;
  }

  private async authenticateWithSchindler(): Promise<void> {
    try {
      this.logger.debug('Authenticating with Schindler PORT system');
      
      // In production, this would use certificate-based authentication
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/auth/session`, {
        method: 'POST',
        headers: {
          'X-API-Key': this.config.apiKey,
          'X-Certificate-Fingerprint': this.certificateFingerprint || 'mock-fingerprint',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          clientId: 'sparc-elevator-control',
          timestamp: new Date().toISOString(),
          capabilities: ['control', 'monitor', 'destination-dispatch']
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Schindler authentication failed: ${response.status}`);
      }

      const data = await response.json();
      this.sessionId = data.sessionId;
      
      this.logger.info('Schindler authentication successful', { 
        sessionId: this.sessionId,
        expiresIn: data.expiresIn 
      });
    } catch (error) {
      this.logger.error('Failed to authenticate with Schindler', { error: error.message });
      throw error;
    }
  }

  async connect(): Promise<boolean> {
    try {
      this.logger.info('Connecting to Schindler PORT system', { 
        baseUrl: this.config.baseUrl,
        simulatorMode: this.config.simulatorMode 
      });

      if (this.config.simulatorMode) {
        // In simulator mode, just mark as connected
        this.isConnected = true;
        this.logger.info('Schindler adapter connected in simulator mode');
        return true;
      }

      // Authenticate with Schindler system
      await this.authenticateWithSchindler();
      
      // Initialize MQTT connection for real-time updates
      // In production: this.mqttClient = mqtt.connect(...)
      
      // Verify connection with PORT API
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/system/health`, {
        method: 'GET',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Schindler connection verification failed: ${response.status}`);
      }

      const health = await response.json();
      this.logger.info('Connected to Schindler PORT system', { 
        version: health.version,
        portTechnology: health.portEnabled 
      });
      
      this.isConnected = true;
      return true;
    } catch (error) {
      this.logger.error('Failed to connect to Schindler system', { error: error.message });
      this.isConnected = false;
      return false;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.simulationInterval) {
        clearInterval(this.simulationInterval);
      }

      // Close MQTT connection
      if (this.mqttClient) {
        // this.mqttClient.end();
      }

      // End session
      if (this.sessionId && !this.config.simulatorMode) {
        await fetch(`${this.config.baseUrl}/port/api/v3/auth/session/${this.sessionId}`, {
          method: 'DELETE',
          headers: {
            'X-API-Key': this.config.apiKey
          }
        });
      }

      this.isConnected = false;
      this.logger.info('Disconnected from Schindler PORT system');
    } catch (error) {
      this.logger.error('Error during disconnect', { error: error.message });
    }
  }

  async callElevator(request: FloorRequest): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('Schindler: Calling elevator', request);

      if (!this.validateElevatorId(request.elevatorId)) {
        throw new Error('Invalid elevator ID format');
      }

      if (!this.validateFloor(request.floor, 60)) { // Schindler handles tall buildings
        throw new Error('Invalid floor number');
      }

      if (this.config.simulatorMode) {
        // Simulate elevator call with Schindler PORT behavior
        await this.delay(this.config.simulatorOptions?.responseDelay || 120);
        
        // Schindler has very low failure rates
        if (Math.random() < (this.config.simulatorOptions?.failureRate || 0.01)) {
          throw new Error('Simulated Schindler elevator call failure');
        }

        // Update mock state with PORT optimization
        const status = this.mockElevatorStates.get(request.elevatorId) || this.createMockStatus(request.elevatorId);
        
        // Schindler PORT destination dispatch logic
        if (request.priority === 'EMERGENCY') {
          status.direction = request.floor > status.currentFloor ? 'UP' : 'DOWN';
          status.operationalStatus = 'EMERGENCY';
          status.speed = this.calculateOptimizedSpeed(status);
        } else {
          // Intelligent routing based on current position and load
          const distance = Math.abs(request.floor - status.currentFloor);
          if (distance > 0) {
            status.direction = request.floor > status.currentFloor ? 'UP' : 'DOWN';
          }
        }
        
        this.mockElevatorStates.set(request.elevatorId, status);
        return true;
      }

      // Real Schindler PORT API call
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/elevators/${request.elevatorId}/destination-request`, {
        method: 'POST',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          destinationFloor: request.floor,
          passengerId: request.userId,
          requestedDirection: request.direction,
          priority: request.priority || 'NORMAL',
          requestTimestamp: new Date().toISOString(),
          accessibilityRequired: false,
          vipStatus: request.priority === 'HIGH'
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Schindler API error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      this.logger.info('Schindler elevator called successfully', { 
        elevatorId: request.elevatorId,
        assignedCar: result.assignedElevator,
        estimatedTime: result.estimatedArrivalTime 
      });
      
      return true;
    }, 'callElevator', request);
  }

  async grantAccess(grant: AccessGrant): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('Schindler: Granting floor access', grant);

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        return true;
      }

      // Schindler PORT Access Control Integration
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/elevators/${grant.elevatorId}/access-permissions`, {
        method: 'POST',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          floor: grant.floor,
          passengerId: grant.userId,
          validitySeconds: grant.duration,
          accessPin: grant.accessCode,
          grantTimestamp: new Date().toISOString(),
          permissionType: 'TEMPORARY_ACCESS'
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Schindler API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'grantAccess', grant);
  }

  async getStatus(elevatorId: string): Promise<ElevatorStatus | null> {
    return this.withRetry(async () => {
      this.logger.debug('Schindler: Getting elevator status', { elevatorId });

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

      // Real Schindler PORT API call
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/elevators/${elevatorId}/real-time-status`, {
        method: 'GET',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`Schindler API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      // Map Schindler PORT status format
      return {
        currentFloor: data.car.currentFloor,
        direction: this.mapSchindlerDirection(data.car.travelDirection),
        doorStatus: this.mapSchindlerDoorStatus(data.door.status),
        operationalStatus: this.mapSchindlerOperationalMode(data.system.operationMode),
        emergencyMode: data.safety.emergencyModeActive,
        load: data.car.loadPercentage || 0,
        speed: data.car.currentSpeed || 0,
        errorCodes: data.diagnostics.errorCodes || [],
        lastUpdate: new Date().toISOString(),
        temperature: data.environment.cabinTemperature,
        motorStatus: data.drive.motorCondition,
        brakeStatus: data.safety.brakeCondition
      };
    }, 'getStatus', { elevatorId });
  }

  private mapSchindlerDirection(portDirection: string): ElevatorStatus['direction'] {
    const mapping: Record<string, ElevatorStatus['direction']> = {
      'ASCENDING': 'UP',
      'DESCENDING': 'DOWN',
      'IDLE': 'STATIONARY',
      'PARKED': 'STATIONARY'
    };
    return mapping[portDirection] || 'STATIONARY';
  }

  private mapSchindlerDoorStatus(portStatus: string): ElevatorStatus['doorStatus'] {
    const mapping: Record<string, ElevatorStatus['doorStatus']> = {
      'OPEN_FULLY': 'OPEN',
      'CLOSED_FULLY': 'CLOSED',
      'IN_OPENING': 'OPENING',
      'IN_CLOSING': 'CLOSING',
      'SAFETY_EDGE_ACTIVE': 'BLOCKED',
      'OBSTRUCTION_DETECTED': 'BLOCKED'
    };
    return mapping[portStatus] || 'CLOSED';
  }

  private mapSchindlerOperationalMode(portMode: string): ElevatorStatus['operationalStatus'] {
    const mapping: Record<string, ElevatorStatus['operationalStatus']> = {
      'NORMAL_SERVICE': 'NORMAL',
      'MAINTENANCE_OPERATION': 'MAINTENANCE',
      'OUT_OF_ORDER': 'OUT_OF_SERVICE',
      'FIRE_SERVICE': 'EMERGENCY',
      'EMERGENCY_OPERATION': 'EMERGENCY',
      'INSPECTION_OPERATION': 'MAINTENANCE'
    };
    return mapping[portMode] || 'NORMAL';
  }

  async emergency(elevatorId: string, action: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN', reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Schindler: Emergency control activated', { elevatorId, action, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.emergencyMode = action !== 'RELEASE';
        status.operationalStatus = action === 'RELEASE' ? 'NORMAL' : 'EMERGENCY';
        
        // Schindler-specific emergency behavior
        if (action === 'EVACUATE') {
          // Schindler PORT evacuates to designated refuge floors
          status.direction = status.currentFloor > 10 ? 'DOWN' : 'STATIONARY';
          if (status.currentFloor === 0 || status.currentFloor === 10) {
            status.doorStatus = 'OPEN';
          }
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

      // Real Schindler PORT API call
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/elevators/${elevatorId}/emergency-control`, {
        method: 'POST',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey,
          'Content-Type': 'application/json',
          'X-Emergency-Override': 'true'
        },
        body: JSON.stringify({
          emergencyCommand: action,
          reason: reason,
          commandTimestamp: new Date().toISOString(),
          operatorId: 'SPARC_SYSTEM',
          notifyBuildingManagement: true
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Schindler API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'emergency', { elevatorId, action });
  }

  async setMaintenanceMode(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Schindler: Setting maintenance mode', { elevatorId, enabled, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.operationalStatus = enabled ? 'MAINTENANCE' : 'NORMAL';
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real Schindler PORT API call
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/elevators/${elevatorId}/maintenance-mode`, {
        method: 'PUT',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          maintenanceActive: enabled,
          reason: reason,
          technician: 'SPARC_SYSTEM',
          estimatedDuration: enabled ? 3600 : 0, // 1 hour default
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Schindler API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'setMaintenanceMode', { elevatorId, enabled });
  }

  async reset(elevatorId: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Schindler: Resetting elevator', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 1000);
        
        const status = this.createMockStatus(elevatorId);
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real Schindler PORT API call
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/elevators/${elevatorId}/system-reset`, {
        method: 'POST',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          resetLevel: 'STANDARD',
          clearErrors: true,
          reinitializePort: true,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 15000)
      });

      if (!response.ok) {
        throw new Error(`Schindler API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'reset', { elevatorId });
  }

  async getDiagnostics(elevatorId: string): Promise<any> {
    return this.withRetry(async () => {
      this.logger.debug('Schindler: Getting elevator diagnostics', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 200);
        
        return {
          elevatorId,
          timestamp: new Date().toISOString(),
          system: {
            uptime: Math.floor(Math.random() * 3000000),
            firmwareVersion: 'PORT-5.2.3',
            lastMaintenance: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
            nextMaintenance: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
            manufacturer: 'Schindler Group',
            model: '5500 with PORT Technology'
          },
          performance: {
            tripsToday: Math.floor(Math.random() * 800),
            averageTripTime: Math.floor(Math.random() * 20) + 12,
            doorCycles: Math.floor(Math.random() * 1600),
            energyConsumption: Math.floor(Math.random() * 60) + 30,
            destinationEfficiency: Math.floor(Math.random() * 15) + 80
          },
          health: {
            motorHealth: Math.floor(Math.random() * 10) + 90,
            brakeHealth: Math.floor(Math.random() * 10) + 90,
            doorHealth: Math.floor(Math.random() * 15) + 85,
            cableHealth: Math.floor(Math.random() * 10) + 90,
            portSystemHealth: Math.floor(Math.random() * 5) + 95
          },
          portTechnology: {
            destinationControl: true,
            touchlessOperation: true,
            predictiveDispatch: true,
            myPORT: true,
            connectedBuildings: 1
          },
          errors: []
        };
      }

      // Real Schindler PORT API call
      const response = await fetch(`${this.config.baseUrl}/port/api/v3/elevators/${elevatorId}/diagnostics/comprehensive`, {
        method: 'GET',
        headers: {
          'Authorization': `Session ${this.sessionId}`,
          'X-API-Key': this.config.apiKey
        },
        signal: AbortSignal.timeout(this.config.timeout || 10000)
      });

      if (!response.ok) {
        throw new Error(`Schindler API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    }, 'getDiagnostics', { elevatorId });
  }

  async subscribeToUpdates(elevatorId: string, callback: (status: ElevatorStatus) => void): Promise<void> {
    this.logger.info('Schindler: Subscribing to elevator updates', { elevatorId });

    if (this.config.simulatorMode) {
      this.updateCallbacks.set(elevatorId, callback);
      return;
    }

    // Schindler uses MQTT for real-time updates
    // In production, this would subscribe to MQTT topics like:
    // port/elevators/{elevatorId}/status
    // port/elevators/{elevatorId}/events
    
    // For now, simulate with polling
    const pollInterval = setInterval(async () => {
      try {
        const status = await this.getStatus(elevatorId);
        if (status) {
          callback(status);
        }
      } catch (error) {
        this.logger.error('Error polling Schindler elevator status', { elevatorId, error: error.message });
      }
    }, 3000); // Schindler updates every 3 seconds

    // Store interval for cleanup
    this.updateCallbacks.set(elevatorId, () => clearInterval(pollInterval));
  }

  async unsubscribeFromUpdates(elevatorId: string): Promise<void> {
    this.logger.info('Schindler: Unsubscribing from elevator updates', { elevatorId });

    const cleanup = this.updateCallbacks.get(elevatorId);
    if (cleanup && typeof cleanup !== 'function') {
      cleanup();
    }
    this.updateCallbacks.delete(elevatorId);
  }

  private createMockStatus(elevatorId: string): ElevatorStatus {
    const floors = this.config.simulatorOptions?.floors || 25;
    return {
      currentFloor: Math.floor(Math.random() * (floors + 1)),
      direction: 'STATIONARY',
      doorStatus: 'CLOSED',
      operationalStatus: 'NORMAL',
      emergencyMode: false,
      load: Math.floor(Math.random() * 60), // Schindler PORT optimizes for lower average loads
      speed: 0,
      errorCodes: [],
      lastUpdate: new Date().toISOString(),
      temperature: 21 + Math.random() * 4, // Schindler maintains precise climate control
      motorStatus: 'EXCELLENT',
      brakeStatus: 'EXCELLENT'
    };
  }
}