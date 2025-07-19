import { BaseElevatorAdapter, ElevatorConfig, ElevatorStatus, FloorRequest, AccessGrant } from './base.adapter';
import { Logger } from '../utils/logger';

/**
 * Mitsubishi Elevator Control Protocol Adapter
 * Implements communication with Mitsubishi Electric elevator systems using their MELDAS protocol
 * 
 * Protocol specifications:
 * - Uses MELDAS (Mitsubishi Electric Ladder Diagram Ascending System) protocol
 * - MODBUS TCP/IP for newer systems
 * - Authentication via device certificates and secure tokens
 * - Real-time monitoring via Mitsubishi's M2M cloud platform
 * - Supports NEXIEZ-MR and NEXIEZ-GPX series
 */
export class MitsubishiAdapter extends BaseElevatorAdapter {
  private mockElevatorStates: Map<string, ElevatorStatus> = new Map();
  private updateCallbacks: Map<string, (status: ElevatorStatus) => void> = new Map();
  private simulationInterval?: NodeJS.Timeout;
  private modbusClient?: any; // Would be MODBUS client in production
  private meldasSessionId?: string;
  private m2mConnectionToken?: string;
  private deviceCertificate?: string;

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
      // Simulate elevator movement with Mitsubishi-specific behavior
      if (status.direction !== 'STATIONARY') {
        const newFloor = status.direction === 'UP' ? status.currentFloor + 1 : status.currentFloor - 1;
        const maxFloor = this.config.simulatorOptions?.floors || 40; // Mitsubishi handles super high-rise buildings
        
        if (newFloor >= -5 && newFloor <= maxFloor) { // Deep basement support for Asian markets
          status.currentFloor = newFloor;
          // Mitsubishi's AI-powered speed optimization
          status.speed = this.calculateAIOptimizedSpeed(status);
        } else {
          status.direction = 'STATIONARY';
          status.speed = 0;
        }
      }

      // Mitsubishi's advanced door control system
      if (Math.random() < 0.11) {
        if (status.doorStatus === 'CLOSED' && status.direction === 'STATIONARY') {
          status.doorStatus = 'OPENING';
        } else if (status.doorStatus === 'OPEN') {
          // Variable door timing based on AI prediction
          const doorCloseChance = this.calculateDoorCloseProbability(status);
          if (Math.random() < doorCloseChance) {
            status.doorStatus = 'CLOSING';
          }
        } else if (status.doorStatus === 'OPENING') {
          status.doorStatus = 'OPEN';
        } else if (status.doorStatus === 'CLOSING') {
          status.doorStatus = 'CLOSED';
        }
      }

      // Simulate Mitsubishi's energy regeneration system
      if (status.direction === 'DOWN' && status.load > 50) {
        // Regenerating energy when going down with heavy load
        this.logger.debug('Energy regeneration active', { 
          elevatorId, 
          regeneratedPower: (status.load - 50) * 2 
        });
      }

      // Load simulation with AI prediction
      if (status.doorStatus === 'OPEN' && Math.random() < 0.22) {
        const loadChange = this.predictLoadChange(status.currentFloor);
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

  private calculateAIOptimizedSpeed(status: ElevatorStatus): number {
    // Mitsubishi's AI Group Control System optimization
    const baseSpeed = 8.0; // m/s for NEXIEZ series
    const loadFactor = 1 - (status.load / 100) * 0.1; // Less impact on speed
    const floorFactor = status.currentFloor > 20 ? 1.2 : 1.0; // Faster at higher floors
    const aiBoost = Math.random() * 0.1 + 0.95; // AI optimization factor
    return baseSpeed * loadFactor * floorFactor * aiBoost;
  }

  private calculateDoorCloseProbability(status: ElevatorStatus): number {
    // AI-based door closing probability
    const baseProbability = 0.1;
    const loadFactor = status.load > 70 ? 1.5 : 1.0; // Close faster when crowded
    const timeFactor = 1.2; // Could be based on time of day in production
    return baseProbability * loadFactor * timeFactor;
  }

  private predictLoadChange(floor: number): number {
    // Simulate AI load prediction based on floor
    if (floor === 0) return Math.floor(Math.random() * 40) - 20; // Lobby has high traffic
    if (floor % 10 === 0) return Math.floor(Math.random() * 30) - 15; // Sky lobbies
    return Math.floor(Math.random() * 20) - 10; // Regular floors
  }

  private async authenticateWithMELDAS(): Promise<void> {
    try {
      this.logger.debug('Authenticating with Mitsubishi MELDAS system');
      
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/auth/initialize`, {
        method: 'POST',
        headers: {
          'X-MELDAS-API-Key': this.config.apiKey,
          'X-Device-Certificate': this.deviceCertificate || 'mock-certificate',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          clientId: 'sparc-elevator-control',
          deviceType: 'CONTROL_SYSTEM',
          capabilities: ['control', 'monitor', 'ai-integration', 'energy-management'],
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi MELDAS authentication failed: ${response.status}`);
      }

      const data = await response.json();
      this.meldasSessionId = data.sessionId;
      this.m2mConnectionToken = data.m2mToken;
      
      this.logger.info('Mitsubishi MELDAS authentication successful', { 
        sessionId: this.meldasSessionId,
        aiEnabled: data.aiGroupControlEnabled 
      });
    } catch (error) {
      this.logger.error('Failed to authenticate with Mitsubishi MELDAS', { error: error.message });
      throw error;
    }
  }

  async connect(): Promise<boolean> {
    try {
      this.logger.info('Connecting to Mitsubishi elevator system', { 
        baseUrl: this.config.baseUrl,
        simulatorMode: this.config.simulatorMode 
      });

      if (this.config.simulatorMode) {
        // In simulator mode, just mark as connected
        this.isConnected = true;
        this.logger.info('Mitsubishi adapter connected in simulator mode');
        return true;
      }

      // Authenticate with MELDAS system
      await this.authenticateWithMELDAS();
      
      // For MODBUS systems, establish connection
      // In production: this.modbusClient = new ModbusRTU()
      
      // Verify connection with M2M cloud
      const response = await fetch(`${this.config.baseUrl}/m2m/api/v2/system/health`, {
        method: 'GET',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi connection verification failed: ${response.status}`);
      }

      const systemHealth = await response.json();
      this.logger.info('Connected to Mitsubishi system', { 
        meldasVersion: systemHealth.meldasVersion,
        elevatorSeries: systemHealth.series,
        aiGroupControl: systemHealth.aiGroupControlActive 
      });
      
      this.isConnected = true;
      return true;
    } catch (error) {
      this.logger.error('Failed to connect to Mitsubishi system', { error: error.message });
      this.isConnected = false;
      return false;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.simulationInterval) {
        clearInterval(this.simulationInterval);
      }

      // Close MODBUS connection
      if (this.modbusClient) {
        // this.modbusClient.close();
      }

      // Terminate MELDAS session
      if (this.meldasSessionId && !this.config.simulatorMode) {
        await fetch(`${this.config.baseUrl}/meldas/api/v2/auth/terminate`, {
          method: 'POST',
          headers: {
            'Authorization': `MELDAS ${this.meldasSessionId}`,
            'X-M2M-Token': this.m2mConnectionToken
          }
        });
      }

      this.isConnected = false;
      this.logger.info('Disconnected from Mitsubishi elevator system');
    } catch (error) {
      this.logger.error('Error during disconnect', { error: error.message });
    }
  }

  async callElevator(request: FloorRequest): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('Mitsubishi: Calling elevator', request);

      if (!this.validateElevatorId(request.elevatorId)) {
        throw new Error('Invalid elevator ID format');
      }

      if (!this.validateFloor(request.floor, 80)) { // Mitsubishi supports very tall buildings
        throw new Error('Invalid floor number');
      }

      if (this.config.simulatorMode) {
        // Simulate elevator call with Mitsubishi AI behavior
        await this.delay(this.config.simulatorOptions?.responseDelay || 80);
        
        // Mitsubishi has exceptional reliability
        if (Math.random() < (this.config.simulatorOptions?.failureRate || 0.003)) {
          throw new Error('Simulated Mitsubishi elevator call failure');
        }

        // Update mock state with AI Group Control
        const status = this.mockElevatorStates.get(request.elevatorId) || this.createMockStatus(request.elevatorId);
        
        // AI determines optimal routing
        const aiDecision = this.simulateAIGroupControl(request, status);
        
        if (request.priority === 'EMERGENCY') {
          status.direction = request.floor > status.currentFloor ? 'UP' : 'DOWN';
          status.operationalStatus = 'EMERGENCY';
        } else {
          status.direction = aiDecision.recommendedDirection;
        }
        
        this.mockElevatorStates.set(request.elevatorId, status);
        return true;
      }

      // Real Mitsubishi MELDAS API call
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/elevators/${request.elevatorId}/call`, {
        method: 'POST',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          destinationFloor: request.floor,
          userId: request.userId,
          direction: request.direction,
          priority: request.priority || 'NORMAL',
          requestTime: new Date().toISOString(),
          aiGroupControl: true,
          energyOptimization: true
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi API error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      this.logger.info('Mitsubishi elevator called successfully', { 
        elevatorId: request.elevatorId,
        assignedByAI: result.aiAssigned,
        estimatedTime: result.estimatedArrivalTime,
        energySaved: result.energyOptimizationApplied 
      });
      
      return true;
    }, 'callElevator', request);
  }

  private simulateAIGroupControl(request: FloorRequest, currentStatus: ElevatorStatus): any {
    // Simulate Mitsubishi's AI Group Control decision
    const distance = Math.abs(request.floor - currentStatus.currentFloor);
    const loadOptimal = currentStatus.load < 70;
    const energyEfficient = (request.floor < currentStatus.currentFloor && currentStatus.load > 50) ||
                           (request.floor > currentStatus.currentFloor && currentStatus.load < 30);
    
    return {
      recommendedDirection: request.floor > currentStatus.currentFloor ? 'UP' : 
                           request.floor < currentStatus.currentFloor ? 'DOWN' : 'STATIONARY',
      aiConfidence: 0.85 + Math.random() * 0.15,
      energyOptimal: energyEfficient,
      loadOptimal: loadOptimal
    };
  }

  async grantAccess(grant: AccessGrant): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.debug('Mitsubishi: Granting floor access', grant);

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        return true;
      }

      // Mitsubishi Security Integration
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/elevators/${grant.elevatorId}/security/access`, {
        method: 'POST',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          floor: grant.floor,
          userId: grant.userId,
          validitySeconds: grant.duration,
          securityCode: grant.accessCode,
          grantTime: new Date().toISOString(),
          securityLevel: 'STANDARD'
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'grantAccess', grant);
  }

  async getStatus(elevatorId: string): Promise<ElevatorStatus | null> {
    return this.withRetry(async () => {
      this.logger.debug('Mitsubishi: Getting elevator status', { elevatorId });

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

      // Real Mitsubishi MELDAS API call
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/elevators/${elevatorId}/status`, {
        method: 'GET',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken
        },
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error(`Mitsubishi API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      // Map Mitsubishi MELDAS status format
      return {
        currentFloor: data.position.currentFloor,
        direction: this.mapMitsubishiDirection(data.motion.direction),
        doorStatus: this.mapMitsubishiDoorStatus(data.door.state),
        operationalStatus: this.mapMitsubishiOperationalMode(data.operation.mode),
        emergencyMode: data.safety.emergencyActive,
        load: data.car.loadRate || 0,
        speed: data.motion.currentSpeed || 0,
        errorCodes: data.diagnostics.faultCodes || [],
        lastUpdate: new Date().toISOString(),
        temperature: data.environment.temperature,
        motorStatus: data.drive.motorCondition,
        brakeStatus: data.safety.brakeCondition
      };
    }, 'getStatus', { elevatorId });
  }

  private mapMitsubishiDirection(meldasDirection: string): ElevatorStatus['direction'] {
    const mapping: Record<string, ElevatorStatus['direction']> = {
      'ASCENDING': 'UP',
      'DESCENDING': 'DOWN',
      'STOPPED': 'STATIONARY',
      'IDLE': 'STATIONARY'
    };
    return mapping[meldasDirection] || 'STATIONARY';
  }

  private mapMitsubishiDoorStatus(meldasStatus: string): ElevatorStatus['doorStatus'] {
    const mapping: Record<string, ElevatorStatus['doorStatus']> = {
      'FULLY_OPEN': 'OPEN',
      'FULLY_CLOSED': 'CLOSED',
      'OPENING': 'OPENING',
      'CLOSING': 'CLOSING',
      'OBSTRUCTION': 'BLOCKED',
      'SAFETY_EDGE': 'BLOCKED'
    };
    return mapping[meldasStatus] || 'CLOSED';
  }

  private mapMitsubishiOperationalMode(meldasMode: string): ElevatorStatus['operationalStatus'] {
    const mapping: Record<string, ElevatorStatus['operationalStatus']> = {
      'NORMAL_OPERATION': 'NORMAL',
      'MAINTENANCE_MODE': 'MAINTENANCE',
      'OUT_OF_SERVICE': 'OUT_OF_SERVICE',
      'EMERGENCY_OPERATION': 'EMERGENCY',
      'FIRE_OPERATION': 'EMERGENCY',
      'INSPECTION_MODE': 'MAINTENANCE',
      'ENERGY_SAVING': 'NORMAL' // Mitsubishi's unique energy-saving mode
    };
    return mapping[meldasMode] || 'NORMAL';
  }

  async emergency(elevatorId: string, action: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN', reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Mitsubishi: Emergency control activated', { elevatorId, action, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.emergencyMode = action !== 'RELEASE';
        status.operationalStatus = action === 'RELEASE' ? 'NORMAL' : 'EMERGENCY';
        
        // Mitsubishi-specific emergency behavior
        if (action === 'EVACUATE') {
          // AI-controlled evacuation to safe floors
          const safeFloor = this.determineSafeFloor(status.currentFloor);
          status.direction = safeFloor > status.currentFloor ? 'UP' : 
                           safeFloor < status.currentFloor ? 'DOWN' : 'STATIONARY';
          if (status.currentFloor === safeFloor) {
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

      // Real Mitsubishi MELDAS API call
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/elevators/${elevatorId}/emergency`, {
        method: 'POST',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken,
          'Content-Type': 'application/json',
          'X-Emergency-Priority': 'HIGHEST'
        },
        body: JSON.stringify({
          emergencyAction: action,
          reason: reason,
          timestamp: new Date().toISOString(),
          initiator: 'SPARC_SYSTEM',
          notifyAIControl: true,
          coordinateGroupEvacuation: action === 'EVACUATE'
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'emergency', { elevatorId, action });
  }

  private determineSafeFloor(currentFloor: number): number {
    // Mitsubishi's AI determines optimal evacuation floor
    if (currentFloor <= 5) return 0; // Ground floor
    if (currentFloor <= 15) return 10; // Mid-rise refuge
    if (currentFloor <= 30) return 20; // High-rise refuge
    return 30; // Sky lobby refuge
  }

  async setMaintenanceMode(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Mitsubishi: Setting maintenance mode', { elevatorId, enabled, reason });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 100);
        
        const status = this.mockElevatorStates.get(elevatorId) || this.createMockStatus(elevatorId);
        status.operationalStatus = enabled ? 'MAINTENANCE' : 'NORMAL';
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real Mitsubishi MELDAS API call
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/elevators/${elevatorId}/maintenance`, {
        method: 'PUT',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          maintenanceActive: enabled,
          reason: reason,
          technician: 'SPARC_SYSTEM',
          aiDiagnostics: true,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 5000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'setMaintenanceMode', { elevatorId, enabled });
  }

  async reset(elevatorId: string): Promise<boolean> {
    return this.withRetry(async () => {
      this.logger.info('Mitsubishi: Resetting elevator', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 1500);
        
        const status = this.createMockStatus(elevatorId);
        this.mockElevatorStates.set(elevatorId, status);
        
        return true;
      }

      // Real Mitsubishi MELDAS API call
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/elevators/${elevatorId}/reset`, {
        method: 'POST',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          resetLevel: 'FULL_SYSTEM',
          clearFaults: true,
          recalibrateAI: true,
          resetEnergyCounters: true,
          timestamp: new Date().toISOString()
        }),
        signal: AbortSignal.timeout(this.config.timeout || 25000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi API error: ${response.status} ${response.statusText}`);
      }

      return true;
    }, 'reset', { elevatorId });
  }

  async getDiagnostics(elevatorId: string): Promise<any> {
    return this.withRetry(async () => {
      this.logger.debug('Mitsubishi: Getting elevator diagnostics', { elevatorId });

      if (this.config.simulatorMode) {
        await this.delay(this.config.simulatorOptions?.responseDelay || 200);
        
        return {
          elevatorId,
          timestamp: new Date().toISOString(),
          system: {
            uptime: Math.floor(Math.random() * 8000000),
            firmwareVersion: 'MELDAS-7.3.2',
            lastMaintenance: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
            nextMaintenance: new Date(Date.now() + 75 * 24 * 60 * 60 * 1000).toISOString(),
            manufacturer: 'Mitsubishi Electric',
            model: 'NEXIEZ-MR with AI Group Control'
          },
          performance: {
            tripsToday: Math.floor(Math.random() * 1200),
            averageTripTime: Math.floor(Math.random() * 12) + 10,
            doorCycles: Math.floor(Math.random() * 2400),
            energyConsumption: Math.floor(Math.random() * 40) + 20,
            energyRegenerated: Math.floor(Math.random() * 20) + 5,
            aiOptimizationRate: Math.floor(Math.random() * 15) + 85
          },
          health: {
            motorHealth: Math.floor(Math.random() * 3) + 97,
            brakeHealth: Math.floor(Math.random() * 3) + 97,
            doorHealth: Math.floor(Math.random() * 5) + 95,
            cableHealth: Math.floor(Math.random() * 3) + 97,
            aiSystemHealth: Math.floor(Math.random() * 2) + 98
          },
          aiInsights: {
            trafficPredictionAccuracy: Math.floor(Math.random() * 10) + 90,
            energyOptimizationActive: true,
            groupControlEfficiency: Math.floor(Math.random() * 10) + 88,
            predictedMaintenanceItems: [],
            anomaliesDetected: Math.floor(Math.random() * 2)
          },
          energyData: {
            dailyConsumption: Math.floor(Math.random() * 100) + 200,
            dailyRegeneration: Math.floor(Math.random() * 30) + 20,
            carbonFootprint: Math.floor(Math.random() * 50) + 100,
            greenModeActive: true
          },
          errors: []
        };
      }

      // Real Mitsubishi MELDAS API call
      const response = await fetch(`${this.config.baseUrl}/meldas/api/v2/elevators/${elevatorId}/diagnostics/comprehensive`, {
        method: 'GET',
        headers: {
          'Authorization': `MELDAS ${this.meldasSessionId}`,
          'X-M2M-Token': this.m2mConnectionToken,
          'X-Include-AI-Analytics': 'true',
          'X-Include-Energy-Data': 'true'
        },
        signal: AbortSignal.timeout(this.config.timeout || 20000)
      });

      if (!response.ok) {
        throw new Error(`Mitsubishi API error: ${response.status} ${response.statusText}`);
      }

      return await response.json();
    }, 'getDiagnostics', { elevatorId });
  }

  async subscribeToUpdates(elevatorId: string, callback: (status: ElevatorStatus) => void): Promise<void> {
    this.logger.info('Mitsubishi: Subscribing to elevator updates', { elevatorId });

    if (this.config.simulatorMode) {
      this.updateCallbacks.set(elevatorId, callback);
      return;
    }

    // Mitsubishi uses WebSocket with binary frames for efficiency
    const wsUrl = this.config.baseUrl.replace('https://', 'wss://').replace('http://', 'ws://');
    const ws = new WebSocket(`${wsUrl}/meldas/ws/elevators/${elevatorId}?session=${this.meldasSessionId}`);
    
    ws.binaryType = 'arraybuffer';
    
    ws.onmessage = (event) => {
      try {
        // In production, this would parse binary MELDAS protocol
        const data = JSON.parse(event.data);
        const status: ElevatorStatus = {
          currentFloor: data.position.currentFloor,
          direction: this.mapMitsubishiDirection(data.motion.direction),
          doorStatus: this.mapMitsubishiDoorStatus(data.door.state),
          operationalStatus: this.mapMitsubishiOperationalMode(data.operation.mode),
          emergencyMode: data.safety.emergencyActive,
          load: data.car.loadRate || 0,
          speed: data.motion.currentSpeed || 0,
          errorCodes: data.diagnostics.faultCodes || [],
          lastUpdate: new Date().toISOString(),
          temperature: data.environment.temperature,
          motorStatus: data.drive.motorCondition,
          brakeStatus: data.safety.brakeCondition
        };
        callback(status);
      } catch (error) {
        this.logger.error('Error parsing Mitsubishi WebSocket message', { elevatorId, error: error.message });
      }
    };

    ws.onerror = (error) => {
      this.logger.error('Mitsubishi WebSocket error', { elevatorId, error });
    };

    ws.onclose = () => {
      this.logger.info('Mitsubishi WebSocket closed', { elevatorId });
    };

    // Store cleanup function
    this.updateCallbacks.set(elevatorId, () => ws.close());
  }

  async unsubscribeFromUpdates(elevatorId: string): Promise<void> {
    this.logger.info('Mitsubishi: Unsubscribing from elevator updates', { elevatorId });

    const cleanup = this.updateCallbacks.get(elevatorId);
    if (cleanup && typeof cleanup !== 'function') {
      cleanup();
    }
    this.updateCallbacks.delete(elevatorId);
  }

  private createMockStatus(elevatorId: string): ElevatorStatus {
    const floors = this.config.simulatorOptions?.floors || 40;
    return {
      currentFloor: Math.floor(Math.random() * (floors + 1)),
      direction: 'STATIONARY',
      doorStatus: 'CLOSED',
      operationalStatus: 'NORMAL',
      emergencyMode: false,
      load: Math.floor(Math.random() * 45), // Mitsubishi AI optimizes for lower average loads
      speed: 0,
      errorCodes: [],
      lastUpdate: new Date().toISOString(),
      temperature: 22 + Math.random() * 2, // Precise temperature control
      motorStatus: 'OPTIMAL',
      brakeStatus: 'OPTIMAL'
    };
  }
}