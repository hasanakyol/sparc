import { BaseElevatorAdapter, ElevatorConfig, ElevatorStatus, FloorRequest, AccessGrant } from './base.adapter';
import { Logger } from '../utils/logger';

/**
 * ThyssenKrupp Elevator Control Protocol Adapter
 * Implements communication with ThyssenKrupp elevator systems using their MAX digital platform
 * 
 * Protocol specifications:
 * - Uses proprietary binary protocol over TCP for legacy systems
 * - REST API with JSON for MAX-enabled elevators
 * - Authentication via certificate-based security
 * - Real-time monitoring via MAX cloud platform
 * - Supports TWIN and MULTI elevator systems
 */
export class ThyssenKruppAdapter extends BaseElevatorAdapter {
  private mockElevatorStates: Map<string, ElevatorStatus> = new Map();
  private updateCallbacks: Map<string, (status: ElevatorStatus) => void> = new Map();
  private simulationInterval?: NodeJS.Timeout;
  private tcpSocket?: any; // Would be TCP socket for legacy systems
  private maxSessionToken?: string;
  private cloudConnectionId?: string;
  private isMultiSystem: boolean = false;

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
      // Simulate elevator movement with ThyssenKrupp-specific behavior
      if (status.direction !== 'STATIONARY') {
        const newFloor = status.direction === 'UP' ? status.currentFloor + 1 : status.currentFloor - 1;
        const maxFloor = this.config.simulatorOptions?.floors || 30; // TK handles very tall buildings
        
        if (newFloor >= -4 && newFloor <= maxFloor) { // TK MULTI systems can have deep basements
          status.currentFloor = newFloor;
          // TWIN system allows two cabins in one shaft
          status.speed = this.calculateTwinOptimizedSpeed(status);
        } else {
          status.direction = 'STATIONARY';
          status.speed = 0;
        }
      }

      // ThyssenKrupp ACCEL door system simulation
      if (Math.random() < 0.1) {
        if (status.doorStatus === 'CLOSED' && status.direction === 'STATIONARY') {
          status.doorStatus = 'OPENING';
        } else if (status.doorStatus === 'OPEN') {
          // Accelerated door closing for efficiency
          const doorCloseChance = status.operationalStatus === 'NORMAL' ? 0.12 : 0.08;
          if (Math.random() < doorCloseChance) {
            status.doorStatus = 'CLOSING';
          }
        } else if (status.doorStatus === 'OPENING') {
          status.doorStatus = 'OPEN';
        } else if (status.doorStatus === 'CLOSING') {
          status.doorStatus = 'CLOSED';
        }
      }

      // MAX predictive maintenance simulation
      if (Math.random() < 0.001) {
        // Simulate minor issues detected by MAX
        status.errorCodes.push(`PREDICT_${Math.floor(Math.random() * 100)}`);
      }

      // Load simulation with MULTI system efficiency
      if (status.doorStatus === 'OPEN' && Math.random() < 0.25) {
        const loadChange = Math.floor(Math.random() * 25) - 12;
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

  private calculateTwinOptimizedSpeed(status: ElevatorStatus): number {
    // ThyssenKrupp TWIN/MULTI system optimization
    const baseSpeed = 10.0; // m/s for high-speed TK elevators
    const loadFactor = 1 - (status.load / 100) * 0.15;
    const multiSystemBonus = this.isMultiSystem ? 1.2 : 1.0; // MULTI systems are more efficient
    return baseSpeed * loadFactor * multiSystemBonus;
  }

  private async authenticateWithMAX(): Promise<void> {
    try {
      this.logger.debug('Authenticating with ThyssenKrupp MAX platform');
      
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/auth/connect`, {
        method: 'POST',
        headers: {
          'X-TK-API-Key': this.config.apiKey,
          'X-TK-Client-ID': 'sparc-elevator-control',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          clientType: 'CONTROL_SYSTEM',
          requestedCapabilities: ['control', 'monitor', 'predictive', 'multi-system'],
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp MAX authentication failed: ${response.status}`);
      }

      const data = await response.json();
      this.maxSessionToken = data.sessionToken;
      this.cloudConnectionId = data.cloudConnectionId;
      this.isMultiSystem = data.capabilities.includes('MULTI');
      
      this.logger.info('ThyssenKrupp MAX authentication successful', { 
        cloudConnectionId: this.cloudConnectionId,
        isMultiSystem: this.isMultiSystem 
      });
    } catch (error) {
      this.logger.error('Failed to authenticate with ThyssenKrupp MAX', { error: error.message });
      throw error;
    }
  }

  async connect(): Promise<boolean> {
    try {
      this.logger.info('Connecting to ThyssenKrupp elevator system', { 
        baseUrl: this.config.baseUrl,
        simulatorMode: this.config.simulatorMode 
      });

      if (this.config.simulatorMode) {
        // In simulator mode, just mark as connected
        this.isConnected = true;
        this.logger.info('ThyssenKrupp adapter connected in simulator mode');
        return true;
      }

      // Authenticate with MAX platform
      await this.authenticateWithMAX();
      
      // For legacy systems, establish TCP connection
      // In production: this.tcpSocket = net.connect(...)
      
      // Verify connection with MAX cloud
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/system/status`, {
        method: 'GET',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp connection verification failed: ${response.status}`);
      }

      const systemInfo = await response.json();
      this.logger.info('Connected to ThyssenKrupp system', { 
        maxVersion: systemInfo.maxVersion,
        elevatorType: systemInfo.elevatorType,
        predictiveEnabled: systemInfo.predictiveMaintenanceEnabled 
      });
      
      this.isConnected = true;
      return true;
    } catch (error) {
      this.logger.error('Failed to connect to ThyssenKrupp system', { error: error.message });
      this.isConnected = false;
      return false;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.simulationInterval) {
        clearInterval(this.simulationInterval);
      }

      // Close TCP socket for legacy systems
      if (this.tcpSocket) {
        // this.tcpSocket.destroy();
      }

      // Disconnect from MAX cloud
      if (this.maxSessionToken && !this.config.simulatorMode) {
        await fetch(`${this.config.baseUrl}/max/api/v4/auth/disconnect`, {
          method: 'POST',
          headers: {
            'Authorization': `MAX ${this.maxSessionToken}`,
            'X-TK-Cloud-ID': this.cloudConnectionId
          }
        });
      }

      this.isConnected = false;
      this.logger.info('Disconnected from ThyssenKrupp elevator system');
    } catch (error) {
      this.logger.error('Error during disconnect', { error: error.message });
    }
  }

  async callElevator(request: FloorRequest): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('ThyssenKrupp: Calling elevator', request);

      if (!this.validateElevatorId(request.elevatorId)) {
        throw new Error('Invalid elevator ID format');
      }

      if (!this.validateFloor(request.floor, 100)) { // TK MULTI can handle 100+ floors
        throw new Error('Invalid floor number');
      }

      if (this.config.simulatorMode) {
        // Simulate elevator call with TK-specific behavior
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        // ThyssenKrupp has excellent reliability
        if (Math.random() < (this.config.simulatorOptions?.failureRate || 0.005)) {
          throw new Error('Simulated ThyssenKrupp elevator call failure');
        }

        // Update mock state with MULTI system optimization
        const status = this.mockElevatorStates.get(request.elevatorId) || this.createMockStatus(request.elevatorId);
        
        // MULTI system can move horizontally and vertically
        if (this.isMultiSystem && Math.abs(request.floor - status.currentFloor) > 20) {
          // Simulate transfer to different shaft for efficiency
          this.logger.debug('MULTI system optimizing route with shaft transfer');
        }
        
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

      // Real ThyssenKrupp MAX API call
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/elevators/${request.elevatorId}/dispatch`, {
        method: 'POST',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          targetFloor: request.floor,
          passengerId: request.userId,
          direction: request.direction,
          priority: request.priority || 'NORMAL',
          requestTime: new Date().toISOString(),
          multiSystemOptimization: this.isMultiSystem,
          accessibilityMode: false
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp API error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      this.logger.info('ThyssenKrupp elevator dispatched successfully', { 
        elevatorId: request.elevatorId,
        assignedCabin: result.assignedCabin,
        estimatedArrival: result.eta,
        routeOptimized: result.multiSystemRouteUsed 
      });
      
      return true;
    }, 'callElevator', request);
  }

  async grantAccess(grant: AccessGrant): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('ThyssenKrupp: Granting floor access', grant);

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        return true;
      }

      // ThyssenKrupp MAX Access Management
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/elevators/${grant.elevatorId}/access`, {
        method: 'POST',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          targetFloor: grant.floor,
          userId: grant.userId,
          validityDuration: grant.duration,
          accessPin: grant.accessCode,
          grantTime: new Date().toISOString(),
          accessLevel: 'TEMPORARY'
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'grantAccess', grant);
  }

  async getStatus(elevatorId: string): Promise<ElevatorStatus | null> {
    return this.withRetry(async () => {
      this.logger.debug('ThyssenKrupp: Getting elevator status', { elevatorId });

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

      // Real ThyssenKrupp MAX API call
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/elevators/${elevatorId}/realtime`, {
        method: 'GET',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`ThyssenKrupp API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      // Map ThyssenKrupp MAX status format
      return {
        currentFloor: data.cabin.position.floor,
        direction: this.mapTKDirection(data.cabin.movement),
        doorStatus: this.mapTKDoorStatus(data.doors.state),
        operationalStatus: this.mapTKOperationalStatus(data.system.mode),
        emergencyMode: data.safety.emergencyActive,
        load: data.cabin.loadPercent || 0,
        speed: data.cabin.velocity || 0,
        errorCodes: data.predictive.alerts || [],
        lastUpdate: new Date().toISOString(),
        temperature: data.environment.cabinTemp,
        motorStatus: data.drive.health,
        brakeStatus: data.safety.brakeHealth
      };
    }, 'getStatus', { elevatorId });
  }

  private mapTKDirection(movement: any): ElevatorStatus['direction'] {
    if (movement.vertical === 'UP') return 'UP';
    if (movement.vertical === 'DOWN') return 'DOWN';
    return 'STATIONARY';
  }

  private mapTKDoorStatus(doorState: string): ElevatorStatus['doorStatus'] {
    const mapping: Record<string, ElevatorStatus['doorStatus']> = {
      'OPEN': 'OPEN',
      'CLOSED': 'CLOSED',
      'OPENING': 'OPENING',
      'CLOSING': 'CLOSING',
      'BLOCKED': 'BLOCKED',
      'SAFETY_ACTIVE': 'BLOCKED'
    };
    return mapping[doorState] || 'CLOSED';
  }

  private mapTKOperationalStatus(mode: string): ElevatorStatus['operationalStatus'] {
    const mapping: Record<string, ElevatorStatus['operationalStatus']> = {
      'NORMAL': 'NORMAL',
      'MAINTENANCE': 'MAINTENANCE',
      'OUT_OF_SERVICE': 'OUT_OF_SERVICE',
      'EMERGENCY': 'EMERGENCY',
      'FIRE_SERVICE': 'EMERGENCY',
      'INSPECTION': 'MAINTENANCE',
      'MULTI_TRANSFER': 'NORMAL' // MULTI system transferring between shafts
    };
    return mapping[mode] || 'NORMAL';
  }

  async emergency(elevatorId: string, action: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN', reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('ThyssenKrupp: Emergency control activated', { elevatorId, action, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.emergencyMode = action !== 'RELEASE';
        status.operationalStatus = action === 'RELEASE' ? 'NORMAL' : 'EMERGENCY';
        
        // ThyssenKrupp-specific emergency behavior
        if (action === 'EVACUATE') {
          // TWIN/MULTI systems coordinate evacuation
          status.direction = status.currentFloor > 0 ? 'DOWN' : 'STATIONARY';
          if (status.currentFloor === 0) {
            status.doorStatus = 'OPEN';
          }
        } else if (action === 'STOP') {
          status.direction = 'STATIONARY';
          status.speed = 0;
          // Engage safety brakes
          status.brakeStatus = 'ENGAGED_EMERGENCY';
        } else if (action === 'LOCKDOWN') {
          status.direction = 'STATIONARY';
          status.doorStatus = 'CLOSED';
        }
        
        this.mockElevatorStates.set(elevatorId, status);
        return true;
      }

      // Real ThyssenKrupp MAX API call
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/elevators/${elevatorId}/emergency`, {
        method: 'POST',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId,
          'Content-Type': 'application/json',
          'X-TK-Emergency-Override': 'true'
        },
        body: JSON.stringify({
          emergencyAction: action,
          reason: reason,
          timestamp: new Date().toISOString(),
          initiatedBy: 'SPARC_SYSTEM',
          notifyMAX: true,
          coordinateMultiSystem: this.isMultiSystem
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'emergency', { elevatorId, action });
  }

  async setMaintenanceMode(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('ThyssenKrupp: Setting maintenance mode', { elevatorId, enabled, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.operationalStatus = enabled ? 'MAINTENANCE' : 'NORMAL';
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real ThyssenKrupp MAX API call
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/elevators/${elevatorId}/maintenance`, {
        method: 'PUT',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          maintenanceEnabled: enabled,
          reason: reason,
          technician: 'SPARC_SYSTEM',
          predictiveData: true, // Include MAX predictive maintenance data
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'setMaintenanceMode', { elevatorId, enabled });
  }

  async reset(elevatorId: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('ThyssenKrupp: Resetting elevator', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 1200);
        
        const status = this.createMockStatus(elevatorId);
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real ThyssenKrupp MAX API call
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/elevators/${elevatorId}/reset`, {
        method: 'POST',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          resetType: 'COMPREHENSIVE',
          clearPredictiveAlerts: true,
          recalibratePosition: true,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 20000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'reset', { elevatorId });
  }

  async getDiagnostics(elevatorId: string): Promise<any> {
    return this.withRetry(async () => {
      this.logger.debug('ThyssenKrupp: Getting elevator diagnostics', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 200);
        
        return {
          elevatorId,
          timestamp: new Date().toISOString(),
          system: {
            uptime: Math.floor(Math.random() * 5000000),
            firmwareVersion: 'MAX-6.1.0',
            lastMaintenance: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString(),
            nextMaintenance: new Date(Date.now() + 70 * 24 * 60 * 60 * 1000).toISOString(),
            manufacturer: 'ThyssenKrupp Elevator',
            model: this.isMultiSystem ? 'MULTI' : 'TWIN'
          },
          performance: {
            tripsToday: Math.floor(Math.random() * 1000),
            averageTripTime: Math.floor(Math.random() * 15) + 8,
            doorCycles: Math.floor(Math.random() * 2000),
            energyConsumption: Math.floor(Math.random() * 50) + 25,
            shaftTransfers: this.isMultiSystem ? Math.floor(Math.random() * 50) : 0
          },
          health: {
            motorHealth: Math.floor(Math.random() * 5) + 95,
            brakeHealth: Math.floor(Math.random() * 5) + 95,
            doorHealth: Math.floor(Math.random() * 10) + 90,
            cableHealth: this.isMultiSystem ? 100 : Math.floor(Math.random() * 5) + 95, // MULTI is cable-less
            maxPredictiveScore: Math.floor(Math.random() * 10) + 90
          },
          maxInsights: {
            predictiveMaintenanceActive: true,
            cloudConnected: true,
            anomaliesDetected: Math.floor(Math.random() * 3),
            recommendedActions: [],
            aiOptimizationEnabled: true
          },
          errors: []
        };
      }

      // Real ThyssenKrupp MAX API call
      const response = await fetch(`${this.config.baseUrl}/max/api/v4/elevators/${elevatorId}/diagnostics/detailed`, {
        method: 'GET',
        headers: {
          'Authorization': `MAX ${this.maxSessionToken}`,
          'X-TK-Cloud-ID': this.cloudConnectionId,
          'X-TK-Include-Predictive': 'true'
        },
        signal: AbortSignal.timeout(this.config.timeout || 15000)
      });

      if (!response.ok) {
        throw new Error(`ThyssenKrupp API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    }, 'getDiagnostics', { elevatorId });
  }

  async subscribeToUpdates(elevatorId: string, callback: (status: ElevatorStatus) => void): Promise<void> {
    this.logger.info('ThyssenKrupp: Subscribing to elevator updates', { elevatorId });

    if (this.config.simulatorMode) {
      this.updateCallbacks.set(elevatorId, callback);
      return;
    }

    // ThyssenKrupp MAX uses Server-Sent Events for real-time updates
    const eventSource = new EventSource(
      `${this.config.baseUrl}/max/api/v4/elevators/${elevatorId}/stream?token=${this.maxSessionToken}`
    );

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const status: ElevatorStatus = {
          currentFloor: data.cabin.position.floor,
          direction: this.mapTKDirection(data.cabin.movement),
          doorStatus: this.mapTKDoorStatus(data.doors.state),
          operationalStatus: this.mapTKOperationalStatus(data.system.mode),
          emergencyMode: data.safety.emergencyActive,
          load: data.cabin.loadPercent || 0,
          speed: data.cabin.velocity || 0,
          errorCodes: data.predictive.alerts || [],
          lastUpdate: new Date().toISOString(),
          temperature: data.environment.cabinTemp,
          motorStatus: data.drive.health,
          brakeStatus: data.safety.brakeHealth
        };
        callback(status);
      } catch (error) {
        this.logger.error('Error parsing ThyssenKrupp SSE message', { elevatorId, error: error.message });
      }
    };

    eventSource.onerror = (error) => {
      this.logger.error('ThyssenKrupp SSE error', { elevatorId, error });
    };

    // Store cleanup function
    this.updateCallbacks.set(elevatorId, () => eventSource.close());
  }

  async unsubscribeFromUpdates(elevatorId: string): Promise<void> {
    this.logger.info('ThyssenKrupp: Unsubscribing from elevator updates', { elevatorId });

    const cleanup = this.updateCallbacks.get(elevatorId);
    if (cleanup && typeof cleanup !== 'function') {
      cleanup();
    }
    this.updateCallbacks.delete(elevatorId);
  }

  private createMockStatus(elevatorId: string): ElevatorStatus {
    const floors = this.config.simulatorOptions?.floors || 30;
    return {
      currentFloor: Math.floor(Math.random() * (floors + 1)),
      direction: 'STATIONARY',
      doorStatus: 'CLOSED',
      operationalStatus: 'NORMAL',
      emergencyMode: false,
      load: Math.floor(Math.random() * 50), // TK systems optimize for lower loads
      speed: 0,
      errorCodes: [],
      lastUpdate: new Date().toISOString(),
      temperature: 20 + Math.random() * 3, // Excellent climate control
      motorStatus: 'HEALTHY',
      brakeStatus: 'HEALTHY'
    };
  }
}