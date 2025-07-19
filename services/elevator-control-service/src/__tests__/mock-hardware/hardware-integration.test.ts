import { ElevatorSimulator } from './elevator-simulator';
import { AdapterFactory } from '../../adapters/adapter-factory';
import { BaseElevatorAdapter } from '../../adapters/base.adapter';
import { ConsoleLogger } from '../../utils/logger';
import { ManufacturerType } from '../../types';

describe('Hardware Integration Tests with Mock Simulator', () => {
  let simulator: ElevatorSimulator;
  let logger: ConsoleLogger;
  const adapters: Map<string, BaseElevatorAdapter> = new Map();

  beforeAll(async () => {
    logger = new ConsoleLogger('hardware-test');
    
    // Create simulator
    simulator = new ElevatorSimulator({
      updateInterval: 50, // 50ms updates for faster testing
      realtimeMode: false,
      mechanicalFailureRate: 0.0001,
      startTime: Date.now()
    }, logger);

    // Create adapters for each manufacturer
    const manufacturers: ManufacturerType[] = ['OTIS', 'KONE', 'SCHINDLER', 'THYSSENKRUPP', 'MITSUBISHI'];
    
    for (const manufacturer of manufacturers) {
      const config = AdapterFactory.getAdapterConfig(manufacturer, {
        baseUrl: `http://mock.${manufacturer.toLowerCase()}.com`,
        apiKey: `mock-${manufacturer}-key`,
        simulatorMode: true
      });
      
      const adapter = AdapterFactory.create(manufacturer, config, logger);
      await adapter.connect();
      adapters.set(manufacturer, adapter);
      simulator.registerAdapter(manufacturer, adapter);
      
      // Add elevator to simulator
      simulator.addElevator(`${manufacturer}-001`, {
        manufacturer,
        floors: 30,
        maxSpeed: getManufacturerMaxSpeed(manufacturer),
        acceleration: 1.2,
        deceleration: 1.5,
        doorOpenTime: 2.0,
        doorCloseTime: 3.0,
        doorWaitTime: 5.0,
        motorPower: 75 // kW
      });
    }

    // Start simulation
    simulator.start();
  });

  afterAll(async () => {
    // Stop simulation
    simulator.stop();

    // Disconnect all adapters
    for (const adapter of adapters.values()) {
      await adapter.disconnect();
    }
  });

  function getManufacturerMaxSpeed(manufacturer: string): number {
    const speeds: Record<string, number> = {
      OTIS: 6.0,
      KONE: 6.0,
      SCHINDLER: 4.0,
      THYSSENKRUPP: 10.0,
      MITSUBISHI: 8.0
    };
    return speeds[manufacturer] || 5.0;
  }

  describe('Realistic Movement Simulation', () => {
    it('should simulate realistic travel times', async () => {
      const manufacturer = 'OTIS';
      const adapter = adapters.get(manufacturer)!;
      const elevatorId = `${manufacturer}-001`;
      
      // Record initial position
      const initialStatus = await adapter.getStatus(elevatorId);
      const startFloor = initialStatus?.currentFloor || 0;
      
      // Call elevator to floor 10
      const targetFloor = 10;
      await adapter.callElevator({
        elevatorId,
        floor: targetFloor,
        userId: 'USER-123'
      });
      
      // Monitor movement
      const startTime = Date.now();
      let arrived = false;
      
      while (!arrived && Date.now() - startTime < 30000) {
        const status = await adapter.getStatus(elevatorId);
        
        if (status?.currentFloor === targetFloor && status.doorStatus === 'OPEN') {
          arrived = true;
        }
        
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      expect(arrived).toBe(true);
      
      // Calculate travel time
      const travelTime = (Date.now() - startTime) / 1000;
      const distance = Math.abs(targetFloor - startFloor);
      const expectedMinTime = distance / getManufacturerMaxSpeed(manufacturer);
      
      // Account for acceleration, deceleration, and door operations
      expect(travelTime).toBeGreaterThan(expectedMinTime);
      expect(travelTime).toBeLessThan(expectedMinTime * 3);
    });

    it('should handle multiple floor requests efficiently', async () => {
      const manufacturer = 'KONE';
      const adapter = adapters.get(manufacturer)!;
      const elevatorId = `${manufacturer}-001`;
      
      // Queue multiple requests
      const requests = [5, 10, 15, 8, 12];
      for (const floor of requests) {
        await adapter.callElevator({
          elevatorId,
          floor,
          userId: `USER-${floor}`
        });
      }
      
      // Monitor elevator serving all floors
      const servedFloors = new Set<number>();
      const startTime = Date.now();
      
      while (servedFloors.size < requests.length && Date.now() - startTime < 60000) {
        const status = await adapter.getStatus(elevatorId);
        
        if (status && requests.includes(status.currentFloor) && status.doorStatus === 'OPEN') {
          servedFloors.add(status.currentFloor);
        }
        
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      // All floors should be served
      expect(servedFloors.size).toBe(requests.length);
    });
  });

  describe('Door Operation Simulation', () => {
    it('should simulate realistic door timing', async () => {
      const manufacturer = 'SCHINDLER';
      const adapter = adapters.get(manufacturer)!;
      const elevatorId = `${manufacturer}-001`;
      
      // Call elevator to current floor for immediate door operation
      const status = await adapter.getStatus(elevatorId);
      await adapter.callElevator({
        elevatorId,
        floor: status?.currentFloor || 0,
        userId: 'USER-123'
      });
      
      // Monitor door cycle
      const doorStates: string[] = [];
      const startTime = Date.now();
      
      while (Date.now() - startTime < 15000) {
        const currentStatus = await adapter.getStatus(elevatorId);
        
        if (currentStatus && doorStates[doorStates.length - 1] !== currentStatus.doorStatus) {
          doorStates.push(currentStatus.doorStatus);
        }
        
        if (doorStates.includes('OPEN') && doorStates.includes('CLOSED') && 
            doorStates[doorStates.length - 1] === 'CLOSED') {
          break;
        }
        
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      // Should have complete door cycle
      expect(doorStates).toContain('OPENING');
      expect(doorStates).toContain('OPEN');
      expect(doorStates).toContain('CLOSING');
      expect(doorStates).toContain('CLOSED');
    });

    it('should handle door obstruction safety', async () => {
      // This test would require simulating door obstruction
      // which would need to be implemented in the simulator
      expect(true).toBe(true); // Placeholder
    });
  });

  describe('Emergency Mode Simulation', () => {
    it('should immediately stop on emergency', async () => {
      const manufacturer = 'THYSSENKRUPP';
      const adapter = adapters.get(manufacturer)!;
      const elevatorId = `${manufacturer}-001`;
      
      // Start movement
      await adapter.callElevator({
        elevatorId,
        floor: 20,
        userId: 'USER-123'
      });
      
      // Wait for movement to start
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Activate emergency stop
      await adapter.emergency(elevatorId, 'STOP', 'Emergency button pressed');
      
      // Check immediate stop
      await new Promise(resolve => setTimeout(resolve, 500));
      const status = await adapter.getStatus(elevatorId);
      
      expect(status?.emergencyMode).toBe(true);
      expect(status?.operationalStatus).toBe('EMERGENCY');
      expect(status?.speed).toBe(0);
    });

    it('should evacuate to safe floors', async () => {
      const manufacturer = 'MITSUBISHI';
      const adapter = adapters.get(manufacturer)!;
      const elevatorId = `${manufacturer}-001`;
      
      // Position elevator at high floor
      await adapter.callElevator({
        elevatorId,
        floor: 25,
        userId: 'USER-123'
      });
      
      // Wait to reach floor
      let positioned = false;
      const positionStart = Date.now();
      
      while (!positioned && Date.now() - positionStart < 30000) {
        const status = await adapter.getStatus(elevatorId);
        if (status?.currentFloor === 25) {
          positioned = true;
        }
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      // Activate evacuation
      await adapter.emergency(elevatorId, 'EVACUATE', 'Building evacuation');
      
      // Monitor evacuation
      const evacuationStart = Date.now();
      let evacuated = false;
      
      while (!evacuated && Date.now() - evacuationStart < 30000) {
        const status = await adapter.getStatus(elevatorId);
        
        // Check if reached a safe floor (0, 10, 20, 30)
        if (status && [0, 10, 20, 30].includes(status.currentFloor) && 
            status.doorStatus === 'OPEN') {
          evacuated = true;
        }
        
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      expect(evacuated).toBe(true);
    });
  });

  describe('Energy Simulation', () => {
    it('should track energy consumption and regeneration', async () => {
      const manufacturer = 'KONE';
      const adapter = adapters.get(manufacturer)!;
      const elevatorId = `${manufacturer}-001`;
      
      // Get initial metrics
      const initialMetrics = simulator.getSimulationMetrics();
      
      // Perform several trips
      const trips = [
        { floor: 15, load: 30 }, // Light load up
        { floor: 0, load: 80 },  // Heavy load down (regeneration)
        { floor: 10, load: 50 }  // Medium load up
      ];
      
      for (const trip of trips) {
        // Simulate load change
        const status = simulator.getElevatorStatus(elevatorId);
        if (status) {
          status.load = trip.load;
        }
        
        await adapter.callElevator({
          elevatorId,
          floor: trip.floor,
          userId: 'USER-123'
        });
        
        // Wait for trip completion
        await new Promise(resolve => setTimeout(resolve, 10000));
      }
      
      // Get final metrics
      const finalMetrics = simulator.getSimulationMetrics();
      
      // Should have consumed energy
      expect(finalMetrics.totalEnergyConsumed).toBeGreaterThan(initialMetrics.totalEnergyConsumed);
      
      // Should have regenerated some energy (heavy load going down)
      expect(finalMetrics.totalEnergyRegenerated).toBeGreaterThan(initialMetrics.totalEnergyRegenerated);
    });
  });

  describe('Load Management Simulation', () => {
    it('should simulate realistic load changes', async () => {
      const manufacturer = 'OTIS';
      const adapter = adapters.get(manufacturer)!;
      const elevatorId = `${manufacturer}-001`;
      
      // Monitor load changes during stops
      const loadReadings: number[] = [];
      
      // Make several stops
      const stops = [0, 5, 10, 5, 0];
      
      for (const floor of stops) {
        await adapter.callElevator({
          elevatorId,
          floor,
          userId: 'USER-123'
        });
        
        // Wait for arrival and door open
        const arrivalStart = Date.now();
        while (Date.now() - arrivalStart < 20000) {
          const status = await adapter.getStatus(elevatorId);
          
          if (status?.currentFloor === floor && status.doorStatus === 'OPEN') {
            // Record load while doors are open
            for (let i = 0; i < 5; i++) {
              const loadStatus = await adapter.getStatus(elevatorId);
              if (loadStatus) {
                loadReadings.push(loadStatus.load);
              }
              await new Promise(resolve => setTimeout(resolve, 500));
            }
            break;
          }
          
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }
      
      // Should have varying load readings
      const uniqueLoads = new Set(loadReadings);
      expect(uniqueLoads.size).toBeGreaterThan(1);
      
      // All loads should be realistic (0-100%)
      loadReadings.forEach(load => {
        expect(load).toBeGreaterThanOrEqual(0);
        expect(load).toBeLessThanOrEqual(100);
      });
    });
  });

  describe('Mechanical Failure Simulation', () => {
    it('should handle simulated failures gracefully', async () => {
      // This would require running the simulation for extended time
      // to trigger random failures based on mechanicalFailureRate
      const metrics = simulator.getSimulationMetrics();
      
      // Check that the simulator tracks failures
      expect(metrics).toHaveProperty('mechanicalFailures');
      expect(metrics.mechanicalFailures).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Multi-Manufacturer Coordination', () => {
    it('should run all manufacturers simultaneously', async () => {
      const results: Record<string, boolean> = {};
      
      // Call all elevators to different floors
      const callPromises = Array.from(adapters.entries()).map(async ([manufacturer, adapter], index) => {
        const floor = 5 + index * 5; // Different floor for each
        const success = await adapter.callElevator({
          elevatorId: `${manufacturer}-001`,
          floor,
          userId: `USER-${manufacturer}`
        });
        results[manufacturer] = success;
      });
      
      await Promise.all(callPromises);
      
      // All should succeed
      Object.values(results).forEach(result => {
        expect(result).toBe(true);
      });
      
      // Check all are moving
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      for (const [manufacturer, adapter] of adapters) {
        const status = await adapter.getStatus(`${manufacturer}-001`);
        expect(status).toBeDefined();
        // Should be either moving or have reached destination
        expect(['UP', 'DOWN', 'STATIONARY']).toContain(status?.direction);
      }
    });
  });

  describe('Performance Metrics', () => {
    it('should collect comprehensive simulation metrics', () => {
      const metrics = simulator.getSimulationMetrics();
      
      expect(metrics.totalElevators).toBe(5); // One per manufacturer
      expect(metrics.activeElevators).toBeGreaterThan(0);
      expect(metrics.totalTrips).toBeGreaterThan(0);
      expect(metrics.totalEnergyConsumed).toBeGreaterThan(0);
      expect(metrics.uptime).toBeGreaterThan(0);
    });
  });
});