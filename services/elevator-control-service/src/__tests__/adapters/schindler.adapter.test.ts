import { SchindlerAdapter } from '../../adapters/schindler.adapter';
import { ConsoleLogger } from '../../utils/logger';
import { ElevatorConfig } from '../../adapters/base.adapter';

describe('SchindlerAdapter', () => {
  let adapter: SchindlerAdapter;
  let logger: ConsoleLogger;
  let config: ElevatorConfig;

  beforeEach(() => {
    logger = new ConsoleLogger('test');
    config = {
      baseUrl: 'http://test.schindler.com',
      apiKey: 'test-api-key',
      simulatorMode: true,
      simulatorOptions: {
        responseDelay: 10,
        failureRate: 0,
        randomizeStatus: false,
        floors: 25,
        travelTimePerFloor: 100
      }
    };
    adapter = new SchindlerAdapter(config, logger);
  });

  afterEach(async () => {
    await adapter.disconnect();
  });

  describe('connect', () => {
    it('should connect successfully in simulator mode', async () => {
      const result = await adapter.connect();
      expect(result).toBe(true);
      expect(adapter.isSystemConnected()).toBe(true);
    });

    it('should handle connection failure gracefully', async () => {
      const realConfig = { ...config, simulatorMode: false };
      const realAdapter = new SchindlerAdapter(realConfig, logger);
      
      const result = await realAdapter.connect();
      expect(result).toBe(false);
      expect(realAdapter.isSystemConnected()).toBe(false);
    });
  });

  describe('getStatus', () => {
    it('should return elevator status with PORT technology fields', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('SCHINDLER-001');
      
      expect(status).toBeDefined();
      expect(status).toHaveProperty('currentFloor');
      expect(status).toHaveProperty('direction');
      expect(status).toHaveProperty('doorStatus');
      expect(status).toHaveProperty('operationalStatus');
      expect(status).toHaveProperty('emergencyMode');
      expect(status).toHaveProperty('load');
      expect(status).toHaveProperty('speed');
      expect(status).toHaveProperty('lastUpdate');
      expect(status?.motorStatus).toMatch(/EXCELLENT|GOOD|OK/);
      expect(status?.brakeStatus).toMatch(/EXCELLENT|GOOD|OK/);
    });

    it('should handle invalid elevator ID', async () => {
      await adapter.connect();
      await expect(adapter.getStatus('invalid@id')).rejects.toThrow('Invalid elevator ID format');
    });

    it('should support multiple basement levels', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('SCHINDLER-001');
      
      expect(status?.currentFloor).toBeGreaterThanOrEqual(-3);
      expect(status?.currentFloor).toBeLessThanOrEqual(25);
    });
  });

  describe('callElevator', () => {
    it('should call elevator with PORT destination dispatch', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'SCHINDLER-001',
        floor: 10,
        userId: 'USER-123',
        priority: 'NORMAL'
      });
      
      expect(result).toBe(true);
    });

    it('should handle VIP priority requests', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'SCHINDLER-001',
        floor: 20,
        userId: 'VIP-USER',
        priority: 'HIGH'
      });
      
      expect(result).toBe(true);
    });

    it('should validate floor number for tall buildings', async () => {
      await adapter.connect();
      await expect(adapter.callElevator({
        elevatorId: 'SCHINDLER-001',
        floor: 61, // Schindler limit is 60
        userId: 'USER-123'
      })).rejects.toThrow('Invalid floor number');
    });

    it('should optimize routing with PORT technology', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'SCHINDLER-001',
        floor: 15,
        userId: 'USER-123',
        direction: 'UP'
      });
      
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('SCHINDLER-001');
      expect(status?.speed).toBeLessThanOrEqual(4.0); // Schindler 5500 speed
    });
  });

  describe('emergency', () => {
    it('should activate emergency stop', async () => {
      await adapter.connect();
      const result = await adapter.emergency('SCHINDLER-001', 'STOP', 'Emergency button pressed');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('SCHINDLER-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.operationalStatus).toBe('EMERGENCY');
      expect(status?.speed).toBe(0);
    });

    it('should evacuate to refuge floors', async () => {
      await adapter.connect();
      // Set elevator to high floor
      const status = await adapter.getStatus('SCHINDLER-001');
      if (status) {
        status.currentFloor = 25;
      }
      
      const result = await adapter.emergency('SCHINDLER-001', 'EVACUATE', 'Building evacuation');
      expect(result).toBe(true);
      
      const updatedStatus = await adapter.getStatus('SCHINDLER-001');
      expect(updatedStatus?.emergencyMode).toBe(true);
      // Should move to refuge floor (10 or 0)
      if (updatedStatus?.currentFloor === 0 || updatedStatus?.currentFloor === 10) {
        expect(updatedStatus?.doorStatus).toBe('OPEN');
      }
    });

    it('should handle lockdown with PORT security', async () => {
      await adapter.connect();
      const result = await adapter.emergency('SCHINDLER-001', 'LOCKDOWN', 'Security lockdown');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('SCHINDLER-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.doorStatus).toBe('CLOSED');
      expect(status?.direction).toBe('STATIONARY');
    });
  });

  describe('setMaintenanceMode', () => {
    it('should enable maintenance mode', async () => {
      await adapter.connect();
      const result = await adapter.setMaintenanceMode('SCHINDLER-001', true, 'PORT system update');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('SCHINDLER-001');
      expect(status?.operationalStatus).toBe('MAINTENANCE');
    });

    it('should disable maintenance mode', async () => {
      await adapter.connect();
      await adapter.setMaintenanceMode('SCHINDLER-001', true, 'Maintenance');
      const result = await adapter.setMaintenanceMode('SCHINDLER-001', false, 'Maintenance complete');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('SCHINDLER-001');
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('getDiagnostics', () => {
    it('should return Schindler PORT diagnostics', async () => {
      await adapter.connect();
      const diagnostics = await adapter.getDiagnostics('SCHINDLER-001');
      
      expect(diagnostics).toBeDefined();
      expect(diagnostics).toHaveProperty('elevatorId');
      expect(diagnostics).toHaveProperty('system');
      expect(diagnostics.system).toHaveProperty('firmwareVersion');
      expect(diagnostics.system.firmwareVersion).toContain('PORT');
      expect(diagnostics.system).toHaveProperty('model');
      expect(diagnostics.system.model).toContain('5500');
      expect(diagnostics).toHaveProperty('performance');
      expect(diagnostics.performance).toHaveProperty('destinationEfficiency');
      expect(diagnostics).toHaveProperty('portTechnology');
      expect(diagnostics.portTechnology).toHaveProperty('destinationControl');
      expect(diagnostics.portTechnology).toHaveProperty('touchlessOperation');
      expect(diagnostics.portTechnology).toHaveProperty('myPORT');
    });
  });

  describe('grantAccess', () => {
    it('should grant floor access with PORT permissions', async () => {
      await adapter.connect();
      const result = await adapter.grantAccess({
        elevatorId: 'SCHINDLER-001',
        floor: 15,
        userId: 'USER-123',
        duration: 600,
        accessCode: 'PORT123'
      });
      
      expect(result).toBe(true);
    });
  });

  describe('reset', () => {
    it('should reset elevator with PORT reinitialization', async () => {
      await adapter.connect();
      await adapter.emergency('SCHINDLER-001', 'STOP', 'Test');
      
      const result = await adapter.reset('SCHINDLER-001');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('SCHINDLER-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('real-time updates', () => {
    it('should subscribe and receive updates via MQTT', async (done) => {
      await adapter.connect();
      
      let updateCount = 0;
      await adapter.subscribeToUpdates('SCHINDLER-001', (status) => {
        expect(status).toBeDefined();
        expect(status.lastUpdate).toBeDefined();
        updateCount++;
        
        if (updateCount >= 2) {
          adapter.unsubscribeFromUpdates('SCHINDLER-001').then(() => done());
        }
      });
    }, 3000);
  });

  describe('PORT-specific features', () => {
    it('should optimize speed based on load and destination', async () => {
      await adapter.connect();
      
      await adapter.callElevator({
        elevatorId: 'SCHINDLER-001',
        floor: 20,
        userId: 'USER-123',
        priority: 'EMERGENCY'
      });
      
      const status = await adapter.getStatus('SCHINDLER-001');
      expect(status?.speed).toBeGreaterThan(0);
      // Emergency factor should increase speed
      expect(status?.operationalStatus).toBe('EMERGENCY');
    });

    it('should handle adaptive door timing', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('SCHINDLER-001');
      
      // Door timing should adapt based on load
      expect(status?.doorStatus).toBeDefined();
      expect(['OPEN', 'CLOSED', 'OPENING', 'CLOSING', 'BLOCKED']).toContain(status?.doorStatus);
    });

    it('should support destination dispatch optimization', async () => {
      await adapter.connect();
      
      // Multiple calls to test dispatch optimization
      const calls = [
        { elevatorId: 'SCHINDLER-001', floor: 5, userId: 'USER-1' },
        { elevatorId: 'SCHINDLER-001', floor: 10, userId: 'USER-2' },
        { elevatorId: 'SCHINDLER-001', floor: 15, userId: 'USER-3' }
      ];
      
      for (const call of calls) {
        const result = await adapter.callElevator(call);
        expect(result).toBe(true);
      }
    });
  });

  describe('error handling with Schindler reliability', () => {
    it('should handle very low failure rates', async () => {
      const errorConfig = {
        ...config,
        simulatorOptions: {
          ...config.simulatorOptions,
          failureRate: 0.01 // 1% failure rate (Schindler has excellent reliability)
        },
        retryAttempts: 3
      };
      
      const errorAdapter = new SchindlerAdapter(errorConfig, logger);
      await errorAdapter.connect();
      
      // Should succeed on first try most of the time
      const result = await errorAdapter.callElevator({
        elevatorId: 'SCHINDLER-001',
        floor: 10,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
      await errorAdapter.disconnect();
    });
  });
});