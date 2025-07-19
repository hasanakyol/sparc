import { BaseElevatorAdapter, ElevatorStatus, FloorRequest, AccessGrant } from '../../adapters/base.adapter';
import { Logger } from '../../utils/logger';
import { EventEmitter } from 'events';

/**
 * Mock hardware simulator for testing elevator control protocol adapters
 * Simulates realistic elevator behavior including:
 * - Travel time based on distance
 * - Door operation timing
 * - Load changes at floors
 * - Mechanical failures
 * - Energy consumption and regeneration
 */
export class ElevatorSimulator extends EventEmitter {
  private elevators: Map<string, SimulatedElevator> = new Map();
  private adapters: Map<string, BaseElevatorAdapter> = new Map();
  private simulationInterval?: NodeJS.Timer;
  private logger: Logger;
  private config: SimulatorConfig;

  constructor(config: SimulatorConfig, logger: Logger) {
    super();
    this.config = {
      updateInterval: 100,
      realtimeMode: false,
      mechanicalFailureRate: 0.001,
      ...config
    };
    this.logger = logger;
  }

  /**
   * Register an adapter with the simulator
   */
  registerAdapter(manufacturerId: string, adapter: BaseElevatorAdapter): void {
    this.adapters.set(manufacturerId, adapter);
    this.logger.info(`Registered ${manufacturerId} adapter with simulator`);
  }

  /**
   * Add an elevator to the simulation
   */
  addElevator(elevatorId: string, config: ElevatorConfig): void {
    const elevator = new SimulatedElevator(elevatorId, config);
    this.elevators.set(elevatorId, elevator);
    this.logger.info(`Added elevator ${elevatorId} to simulation`, config);
  }

  /**
   * Start the simulation
   */
  start(): void {
    if (this.simulationInterval) {
      return;
    }

    this.simulationInterval = setInterval(() => {
      this.updateSimulation();
    }, this.config.updateInterval);

    this.logger.info('Elevator simulation started');
    this.emit('simulationStarted');
  }

  /**
   * Stop the simulation
   */
  stop(): void {
    if (this.simulationInterval) {
      clearInterval(this.simulationInterval);
      this.simulationInterval = undefined;
    }

    this.logger.info('Elevator simulation stopped');
    this.emit('simulationStopped');
  }

  /**
   * Update all elevators in the simulation
   */
  private updateSimulation(): void {
    const deltaTime = this.config.updateInterval / 1000; // Convert to seconds

    for (const [elevatorId, elevator] of this.elevators) {
      // Update physics
      this.updateElevatorPhysics(elevator, deltaTime);
      
      // Update door state
      this.updateDoorState(elevator, deltaTime);
      
      // Process queued requests
      this.processQueuedRequests(elevator);
      
      // Simulate random events
      this.simulateRandomEvents(elevator);
      
      // Update energy metrics
      this.updateEnergyMetrics(elevator, deltaTime);
      
      // Emit status update
      this.emit('statusUpdate', elevatorId, elevator.getStatus());
    }
  }

  /**
   * Update elevator movement physics
   */
  private updateElevatorPhysics(elevator: SimulatedElevator, deltaTime: number): void {
    if (elevator.state.direction === 'STATIONARY') {
      elevator.state.speed = 0;
      elevator.state.acceleration = 0;
      return;
    }

    const targetFloor = elevator.getNextTargetFloor();
    if (targetFloor === null) {
      elevator.state.direction = 'STATIONARY';
      return;
    }

    const distance = Math.abs(targetFloor - elevator.state.currentPosition);
    const maxSpeed = elevator.config.maxSpeed;
    const acceleration = elevator.config.acceleration;
    const deceleration = elevator.config.deceleration;

    // Calculate stopping distance
    const stoppingDistance = (elevator.state.speed * elevator.state.speed) / (2 * deceleration);

    if (distance <= stoppingDistance + 0.1) {
      // Decelerate
      elevator.state.acceleration = -deceleration;
      elevator.state.speed = Math.max(0, elevator.state.speed - deceleration * deltaTime);
    } else if (elevator.state.speed < maxSpeed) {
      // Accelerate
      elevator.state.acceleration = acceleration;
      elevator.state.speed = Math.min(maxSpeed, elevator.state.speed + acceleration * deltaTime);
    } else {
      // Maintain speed
      elevator.state.acceleration = 0;
      elevator.state.speed = maxSpeed;
    }

    // Update position
    const movement = elevator.state.speed * deltaTime * (elevator.state.direction === 'UP' ? 1 : -1);
    elevator.state.currentPosition += movement;

    // Check if reached target floor
    if (Math.abs(elevator.state.currentPosition - targetFloor) < 0.05) {
      elevator.state.currentPosition = targetFloor;
      elevator.state.currentFloor = targetFloor;
      elevator.state.speed = 0;
      elevator.state.acceleration = 0;
      elevator.arrivedAtFloor(targetFloor);
      
      this.logger.debug(`Elevator ${elevator.id} arrived at floor ${targetFloor}`);
      this.emit('floorReached', elevator.id, targetFloor);
    }
  }

  /**
   * Update door state machine
   */
  private updateDoorState(elevator: SimulatedElevator, deltaTime: number): void {
    const doorTimer = elevator.state.doorTimer;
    
    switch (elevator.state.doorStatus) {
      case 'OPENING':
        elevator.state.doorTimer += deltaTime;
        if (doorTimer >= elevator.config.doorOpenTime) {
          elevator.state.doorStatus = 'OPEN';
          elevator.state.doorTimer = 0;
          this.emit('doorOpened', elevator.id);
        }
        break;
        
      case 'OPEN':
        elevator.state.doorTimer += deltaTime;
        if (doorTimer >= elevator.config.doorWaitTime) {
          if (!elevator.state.doorHoldRequested) {
            elevator.state.doorStatus = 'CLOSING';
            elevator.state.doorTimer = 0;
          }
        }
        break;
        
      case 'CLOSING':
        if (elevator.state.doorObstructed) {
          // Safety: reopen if obstructed
          elevator.state.doorStatus = 'OPENING';
          elevator.state.doorTimer = 0;
          elevator.state.doorObstructed = false;
          this.emit('doorObstructed', elevator.id);
        } else {
          elevator.state.doorTimer += deltaTime;
          if (doorTimer >= elevator.config.doorCloseTime) {
            elevator.state.doorStatus = 'CLOSED';
            elevator.state.doorTimer = 0;
            this.emit('doorClosed', elevator.id);
          }
        }
        break;
    }
  }

  /**
   * Process queued floor requests
   */
  private processQueuedRequests(elevator: SimulatedElevator): void {
    if (elevator.state.direction === 'STATIONARY' && elevator.state.doorStatus === 'CLOSED') {
      const nextFloor = elevator.getNextTargetFloor();
      if (nextFloor !== null) {
        elevator.state.direction = nextFloor > elevator.state.currentFloor ? 'UP' : 'DOWN';
        this.emit('movementStarted', elevator.id, elevator.state.direction);
      }
    }
  }

  /**
   * Simulate random events like load changes and failures
   */
  private simulateRandomEvents(elevator: SimulatedElevator): void {
    // Load changes when doors are open
    if (elevator.state.doorStatus === 'OPEN' && Math.random() < 0.1) {
      const loadChange = (Math.random() - 0.5) * 30;
      elevator.state.load = Math.max(0, Math.min(100, elevator.state.load + loadChange));
      this.emit('loadChanged', elevator.id, elevator.state.load);
    }

    // Mechanical failures
    if (!elevator.state.emergencyMode && Math.random() < this.config.mechanicalFailureRate) {
      const failureType = this.selectRandomFailure();
      this.simulateMechanicalFailure(elevator, failureType);
    }

    // Door obstruction simulation
    if (elevator.state.doorStatus === 'CLOSING' && Math.random() < 0.05) {
      elevator.state.doorObstructed = true;
    }
  }

  /**
   * Update energy consumption and regeneration
   */
  private updateEnergyMetrics(elevator: SimulatedElevator, deltaTime: number): void {
    const metrics = elevator.state.energyMetrics;
    const load = elevator.state.load / 100; // Normalize to 0-1
    const speed = elevator.state.speed;
    
    if (elevator.state.direction !== 'STATIONARY') {
      // Energy consumption/regeneration calculation
      const basePower = elevator.config.motorPower;
      let powerUsage: number;
      
      if (elevator.state.direction === 'UP') {
        // Going up always consumes energy, more with higher load
        powerUsage = basePower * (0.5 + load * 0.5) * (speed / elevator.config.maxSpeed);
      } else {
        // Going down can regenerate energy with heavy loads
        if (load > 0.5) {
          // Regeneration
          powerUsage = -basePower * (load - 0.5) * 0.6 * (speed / elevator.config.maxSpeed);
        } else {
          // Light load still consumes some energy
          powerUsage = basePower * 0.2 * (speed / elevator.config.maxSpeed);
        }
      }
      
      const energyDelta = powerUsage * deltaTime / 3600; // Convert to kWh
      
      if (energyDelta > 0) {
        metrics.totalEnergyConsumed += energyDelta;
      } else {
        metrics.totalEnergyRegenerated += Math.abs(energyDelta);
      }
      
      metrics.currentPowerDraw = powerUsage;
    } else {
      // Standby power
      metrics.currentPowerDraw = elevator.config.motorPower * 0.05;
      metrics.totalEnergyConsumed += metrics.currentPowerDraw * deltaTime / 3600;
    }
  }

  /**
   * Simulate a mechanical failure
   */
  private simulateMechanicalFailure(elevator: SimulatedElevator, failureType: string): void {
    this.logger.warn(`Mechanical failure in elevator ${elevator.id}: ${failureType}`);
    
    switch (failureType) {
      case 'DOOR_MALFUNCTION':
        elevator.state.errorCodes.push('DOOR_FAULT_01');
        elevator.state.doorObstructed = true;
        break;
        
      case 'MOTOR_OVERHEAT':
        elevator.state.errorCodes.push('MOTOR_TEMP_HIGH');
        elevator.state.temperature = 85;
        elevator.state.operationalStatus = 'OUT_OF_SERVICE';
        break;
        
      case 'BRAKE_ISSUE':
        elevator.state.errorCodes.push('BRAKE_WEAR_WARNING');
        elevator.state.brakeStatus = 'WORN';
        break;
        
      case 'SENSOR_FAULT':
        elevator.state.errorCodes.push('POSITION_SENSOR_ERR');
        break;
    }
    
    this.emit('mechanicalFailure', elevator.id, failureType, elevator.state.errorCodes);
  }

  /**
   * Select a random failure type
   */
  private selectRandomFailure(): string {
    const failures = ['DOOR_MALFUNCTION', 'MOTOR_OVERHEAT', 'BRAKE_ISSUE', 'SENSOR_FAULT'];
    return failures[Math.floor(Math.random() * failures.length)];
  }

  /**
   * Get current status of an elevator
   */
  getElevatorStatus(elevatorId: string): ElevatorStatus | null {
    const elevator = this.elevators.get(elevatorId);
    return elevator ? elevator.getStatus() : null;
  }

  /**
   * Call an elevator to a floor
   */
  callElevator(request: FloorRequest): boolean {
    const elevator = this.elevators.get(request.elevatorId);
    if (!elevator) {
      return false;
    }

    elevator.addFloorRequest(request.floor, request.priority || 'NORMAL');
    this.emit('elevatorCalled', request);
    return true;
  }

  /**
   * Set emergency mode
   */
  setEmergencyMode(elevatorId: string, action: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN'): boolean {
    const elevator = this.elevators.get(elevatorId);
    if (!elevator) {
      return false;
    }

    switch (action) {
      case 'STOP':
        elevator.state.emergencyMode = true;
        elevator.state.operationalStatus = 'EMERGENCY';
        elevator.state.direction = 'STATIONARY';
        elevator.state.speed = 0;
        elevator.clearAllRequests();
        break;
        
      case 'RELEASE':
        elevator.state.emergencyMode = false;
        elevator.state.operationalStatus = 'NORMAL';
        break;
        
      case 'EVACUATE':
        elevator.state.emergencyMode = true;
        elevator.state.operationalStatus = 'EMERGENCY';
        elevator.clearAllRequests();
        // Move to nearest safe floor
        const safeFloor = this.findNearestSafeFloor(elevator.state.currentFloor);
        elevator.addFloorRequest(safeFloor, 'EMERGENCY');
        break;
        
      case 'LOCKDOWN':
        elevator.state.emergencyMode = true;
        elevator.state.operationalStatus = 'EMERGENCY';
        elevator.state.doorStatus = 'CLOSED';
        elevator.state.doorHoldRequested = false;
        elevator.clearAllRequests();
        break;
    }

    this.emit('emergencyModeChanged', elevatorId, action);
    return true;
  }

  /**
   * Find nearest safe floor for evacuation
   */
  private findNearestSafeFloor(currentFloor: number): number {
    const safeFloors = [0, 10, 20, 30]; // Ground floor and sky lobbies
    return safeFloors.reduce((nearest, floor) => 
      Math.abs(floor - currentFloor) < Math.abs(nearest - currentFloor) ? floor : nearest
    );
  }

  /**
   * Get simulation metrics
   */
  getSimulationMetrics(): SimulationMetrics {
    const metrics: SimulationMetrics = {
      totalElevators: this.elevators.size,
      activeElevators: 0,
      totalTrips: 0,
      totalEnergyConsumed: 0,
      totalEnergyRegenerated: 0,
      mechanicalFailures: 0,
      averageWaitTime: 0,
      uptime: Date.now() - this.config.startTime
    };

    for (const elevator of this.elevators.values()) {
      if (elevator.state.operationalStatus === 'NORMAL') {
        metrics.activeElevators++;
      }
      metrics.totalTrips += elevator.state.tripCount;
      metrics.totalEnergyConsumed += elevator.state.energyMetrics.totalEnergyConsumed;
      metrics.totalEnergyRegenerated += elevator.state.energyMetrics.totalEnergyRegenerated;
      metrics.mechanicalFailures += elevator.state.errorCodes.length;
    }

    return metrics;
  }
}

/**
 * Individual elevator simulation
 */
class SimulatedElevator {
  id: string;
  config: ElevatorConfig;
  state: ElevatorState;
  private floorQueue: Set<number> = new Set();
  private priorityQueue: Map<number, string> = new Map();

  constructor(id: string, config: ElevatorConfig) {
    this.id = id;
    this.config = config;
    this.state = {
      currentFloor: 0,
      currentPosition: 0,
      direction: 'STATIONARY',
      doorStatus: 'CLOSED',
      doorTimer: 0,
      doorHoldRequested: false,
      doorObstructed: false,
      operationalStatus: 'NORMAL',
      emergencyMode: false,
      load: 20,
      speed: 0,
      acceleration: 0,
      temperature: 22,
      motorStatus: 'OK',
      brakeStatus: 'OK',
      errorCodes: [],
      tripCount: 0,
      energyMetrics: {
        totalEnergyConsumed: 0,
        totalEnergyRegenerated: 0,
        currentPowerDraw: 0
      }
    };
  }

  getStatus(): ElevatorStatus {
    return {
      currentFloor: this.state.currentFloor,
      direction: this.state.direction,
      doorStatus: this.state.doorStatus,
      operationalStatus: this.state.operationalStatus,
      emergencyMode: this.state.emergencyMode,
      load: Math.round(this.state.load),
      speed: Math.round(this.state.speed * 10) / 10,
      errorCodes: [...this.state.errorCodes],
      lastUpdate: new Date().toISOString(),
      temperature: Math.round(this.state.temperature),
      motorStatus: this.state.motorStatus,
      brakeStatus: this.state.brakeStatus
    };
  }

  addFloorRequest(floor: number, priority: string): void {
    this.floorQueue.add(floor);
    this.priorityQueue.set(floor, priority);
  }

  getNextTargetFloor(): number | null {
    if (this.floorQueue.size === 0) {
      return null;
    }

    // Handle emergency priority
    for (const [floor, priority] of this.priorityQueue) {
      if (priority === 'EMERGENCY') {
        return floor;
      }
    }

    // Otherwise, use directional logic
    const floors = Array.from(this.floorQueue).sort((a, b) => a - b);
    
    if (this.state.direction === 'UP') {
      const upFloors = floors.filter(f => f > this.state.currentFloor);
      return upFloors.length > 0 ? upFloors[0] : floors[floors.length - 1];
    } else if (this.state.direction === 'DOWN') {
      const downFloors = floors.filter(f => f < this.state.currentFloor).reverse();
      return downFloors.length > 0 ? downFloors[0] : floors[0];
    } else {
      // Find nearest floor
      return floors.reduce((nearest, floor) => 
        Math.abs(floor - this.state.currentFloor) < Math.abs(nearest - this.state.currentFloor) ? floor : nearest
      );
    }
  }

  arrivedAtFloor(floor: number): void {
    this.floorQueue.delete(floor);
    this.priorityQueue.delete(floor);
    this.state.doorStatus = 'OPENING';
    this.state.doorTimer = 0;
    this.state.tripCount++;
  }

  clearAllRequests(): void {
    this.floorQueue.clear();
    this.priorityQueue.clear();
  }
}

// Type definitions
interface SimulatorConfig {
  updateInterval: number;
  realtimeMode: boolean;
  mechanicalFailureRate: number;
  startTime: number;
}

interface ElevatorConfig {
  manufacturer: string;
  floors: number;
  maxSpeed: number; // m/s
  acceleration: number; // m/s²
  deceleration: number; // m/s²
  doorOpenTime: number; // seconds
  doorCloseTime: number; // seconds
  doorWaitTime: number; // seconds
  motorPower: number; // kW
}

interface ElevatorState {
  currentFloor: number;
  currentPosition: number; // Precise position for smooth movement
  direction: 'UP' | 'DOWN' | 'STATIONARY';
  doorStatus: 'OPEN' | 'CLOSED' | 'OPENING' | 'CLOSING';
  doorTimer: number;
  doorHoldRequested: boolean;
  doorObstructed: boolean;
  operationalStatus: 'NORMAL' | 'MAINTENANCE' | 'OUT_OF_SERVICE' | 'EMERGENCY';
  emergencyMode: boolean;
  load: number;
  speed: number;
  acceleration: number;
  temperature: number;
  motorStatus: string;
  brakeStatus: string;
  errorCodes: string[];
  tripCount: number;
  energyMetrics: {
    totalEnergyConsumed: number;
    totalEnergyRegenerated: number;
    currentPowerDraw: number;
  };
}

interface SimulationMetrics {
  totalElevators: number;
  activeElevators: number;
  totalTrips: number;
  totalEnergyConsumed: number;
  totalEnergyRegenerated: number;
  mechanicalFailures: number;
  averageWaitTime: number;
  uptime: number;
}

export { SimulatorConfig, ElevatorConfig, SimulationMetrics };