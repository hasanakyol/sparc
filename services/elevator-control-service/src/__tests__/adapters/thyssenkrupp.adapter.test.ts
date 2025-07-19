import { ThyssenKruppAdapter } from '../../adapters/thyssenkrupp.adapter';
import { ConsoleLogger } from '../../utils/logger';
import { ElevatorConfig } from '../../adapters/base.adapter';

describe('ThyssenKruppAdapter', () => {
  let adapter: ThyssenKruppAdapter;
  let logger: ConsoleLogger;
  let config: ElevatorConfig;

  beforeEach(() => {
    logger = new ConsoleLogger('test');
    config = {
      baseUrl: 'http://test.thyssenkrupp.com',
      apiKey: 'test-api-key',
      simulatorMode: true,
      simulatorOptions: {
        responseDelay: 10,
        failureRate: 0,
        randomizeStatus: false,
        floors: 30,
        travelTimePerFloor: 100
      }
    };
    adapter = new ThyssenKruppAdapter(config, logger);
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
      const realAdapter = new ThyssenKruppAdapter(realConfig, logger);
      
      const result = await realAdapter.connect();
      expect(result).toBe(false);
      expect(realAdapter.isSystemConnected()).toBe(false);
    });
  });

  describe('getStatus', () => {
    it('should return elevator status with MAX platform data', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('TK-001');
      
      expect(status).toBeDefined();
      expect(status).toHaveProperty('currentFloor');
      expect(status).toHaveProperty('direction');
      expect(status).toHaveProperty('doorStatus');
      expect(status).toHaveProperty('operationalStatus');
      expect(status).toHaveProperty('emergencyMode');
      expect(status).toHaveProperty('load');
      expect(status).toHaveProperty('speed');
      expect(status).toHaveProperty('errorCodes');
      expect(status).toHaveProperty('lastUpdate');
      expect(status?.motorStatus).toMatch(/HEALTHY|OPTIMAL|GOOD|OK/);
      expect(status?.brakeStatus).toMatch(/HEALTHY|OPTIMAL|GOOD|OK|ENGAGED_EMERGENCY/);
    });

    it('should handle deep basement floors for MULTI systems', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('TK-MULTI-001');
      
      expect(status?.currentFloor).toBeGreaterThanOrEqual(-4);
      expect(status?.currentFloor).toBeLessThanOrEqual(30);
    });

    it('should include predictive maintenance alerts', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('TK-001');
      
      expect(status?.errorCodes).toBeDefined();
      expect(Array.isArray(status?.errorCodes)).toBe(true);
    });
  });

  describe('callElevator', () => {
    it('should call elevator with TWIN/MULTI optimization', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'TK-001',
        floor: 15,
        userId: 'USER-123',
        priority: 'NORMAL'
      });
      
      expect(result).toBe(true);
    });

    it('should handle MULTI system shaft transfers', async () => {
      await adapter.connect();
      // Simulate long-distance call that would benefit from shaft transfer
      const result = await adapter.callElevator({
        elevatorId: 'TK-MULTI-001',
        floor: 25,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
      // In MULTI systems, this might trigger a shaft transfer
    });

    it('should validate floor number for very tall buildings', async () => {
      await adapter.connect();
      await expect(adapter.callElevator({
        elevatorId: 'TK-001',
        floor: 101, // ThyssenKrupp MULTI can handle 100+ floors
        userId: 'USER-123'
      })).rejects.toThrow('Invalid floor number');
    });

    it('should optimize speed for high-speed elevators', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'TK-001',
        floor: 30,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.speed).toBeLessThanOrEqual(10.0); // TK high-speed elevators
    });
  });

  describe('emergency', () => {
    it('should activate emergency stop with safety brakes', async () => {
      await adapter.connect();
      const result = await adapter.emergency('TK-001', 'STOP', 'Emergency stop activated');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.operationalStatus).toBe('EMERGENCY');
      expect(status?.direction).toBe('STATIONARY');
      expect(status?.speed).toBe(0);
      expect(status?.brakeStatus).toBe('ENGAGED_EMERGENCY');
    });

    it('should coordinate TWIN/MULTI evacuation', async () => {
      await adapter.connect();
      const result = await adapter.emergency('TK-001', 'EVACUATE', 'Fire alarm');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.emergencyMode).toBe(true);
      if (status?.currentFloor === 0) {
        expect(status?.doorStatus).toBe('OPEN');
      }
    });

    it('should handle lockdown mode', async () => {
      await adapter.connect();
      const result = await adapter.emergency('TK-001', 'LOCKDOWN', 'Security threat');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.doorStatus).toBe('CLOSED');
      expect(status?.direction).toBe('STATIONARY');
    });

    it('should release emergency mode', async () => {
      await adapter.connect();
      await adapter.emergency('TK-001', 'STOP', 'Test');
      const result = await adapter.emergency('TK-001', 'RELEASE', 'All clear');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('setMaintenanceMode', () => {
    it('should enable maintenance mode with predictive data', async () => {
      await adapter.connect();
      const result = await adapter.setMaintenanceMode('TK-001', true, 'MAX predictive maintenance');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.operationalStatus).toBe('MAINTENANCE');
    });

    it('should disable maintenance mode', async () => {
      await adapter.connect();
      await adapter.setMaintenanceMode('TK-001', true, 'Maintenance');
      const result = await adapter.setMaintenanceMode('TK-001', false, 'Maintenance complete');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('getDiagnostics', () => {
    it('should return ThyssenKrupp MAX diagnostics', async () => {
      await adapter.connect();
      const diagnostics = await adapter.getDiagnostics('TK-001');
      
      expect(diagnostics).toBeDefined();
      expect(diagnostics).toHaveProperty('elevatorId');
      expect(diagnostics).toHaveProperty('system');
      expect(diagnostics.system).toHaveProperty('firmwareVersion');
      expect(diagnostics.system.firmwareVersion).toContain('MAX');
      expect(diagnostics.system).toHaveProperty('model');
      expect(diagnostics.system.model).toMatch(/TWIN|MULTI/);
      expect(diagnostics).toHaveProperty('performance');
      expect(diagnostics).toHaveProperty('health');
      expect(diagnostics.health).toHaveProperty('maxPredictiveScore');
      expect(diagnostics).toHaveProperty('maxInsights');
      expect(diagnostics.maxInsights).toHaveProperty('predictiveMaintenanceActive');
      expect(diagnostics.maxInsights).toHaveProperty('cloudConnected');
      expect(diagnostics.maxInsights).toHaveProperty('aiOptimizationEnabled');
    });

    it('should include MULTI system specific metrics', async () => {
      await adapter.connect();
      const diagnostics = await adapter.getDiagnostics('TK-MULTI-001');
      
      expect(diagnostics.performance).toHaveProperty('shaftTransfers');
      expect(diagnostics.health.cableHealth).toBe(100); // MULTI is cable-less
    });
  });

  describe('grantAccess', () => {
    it('should grant floor access via MAX platform', async () => {
      await adapter.connect();
      const result = await adapter.grantAccess({
        elevatorId: 'TK-001',
        floor: 20,
        userId: 'USER-123',
        duration: 900,
        accessCode: 'MAX123'
      });
      
      expect(result).toBe(true);
    });
  });

  describe('reset', () => {
    it('should perform comprehensive reset', async () => {
      await adapter.connect();
      await adapter.emergency('TK-001', 'STOP', 'Test');
      
      const result = await adapter.reset('TK-001');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
      expect(status?.errorCodes).toEqual([]);
    });
  });

  describe('real-time updates', () => {
    it('should subscribe to Server-Sent Events', async (done) => {
      await adapter.connect();
      
      let updateCount = 0;
      await adapter.subscribeToUpdates('TK-001', (status) => {
        expect(status).toBeDefined();
        expect(status.lastUpdate).toBeDefined();
        updateCount++;
        
        if (updateCount >= 2) {
          adapter.unsubscribeFromUpdates('TK-001').then(() => done());
        }
      });
    }, 3000);
  });

  describe('ThyssenKrupp-specific features', () => {
    it('should calculate TWIN optimized speed', async () => {
      await adapter.connect();
      
      await adapter.callElevator({
        elevatorId: 'TK-001',
        floor: 25,
        userId: 'USER-123'
      });
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.speed).toBeGreaterThan(0);
      expect(status?.speed).toBeLessThanOrEqual(12.0); // MULTI systems can be faster
    });

    it('should handle ACCEL door system', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('TK-001');
      
      // ACCEL system provides accelerated door operations
      expect(status?.doorStatus).toBeDefined();
      expect(['OPEN', 'CLOSED', 'OPENING', 'CLOSING', 'BLOCKED']).toContain(status?.doorStatus);
    });

    it('should simulate MAX predictive maintenance', async () => {
      await adapter.connect();
      
      // Run for a while to potentially generate predictive alerts
      for (let i = 0; i < 10; i++) {
        await adapter.getStatus('TK-001');
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      const status = await adapter.getStatus('TK-001');
      expect(status?.errorCodes).toBeDefined();
      // May have predictive maintenance codes
    });

    it('should optimize for lower average loads', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('TK-001');
      
      expect(status?.load).toBeDefined();
      expect(status?.load).toBeGreaterThanOrEqual(0);
      expect(status?.load).toBeLessThanOrEqual(100);
    });
  });

  describe('error handling with MAX reliability', () => {
    it('should handle exceptional reliability', async () => {
      const errorConfig = {
        ...config,
        simulatorOptions: {
          ...config.simulatorOptions,
          failureRate: 0.005 // 0.5% failure rate (TK has excellent reliability)
        },
        retryAttempts: 3
      };
      
      const errorAdapter = new ThyssenKruppAdapter(errorConfig, logger);
      await errorAdapter.connect();
      
      // Should almost always succeed on first try
      const result = await errorAdapter.callElevator({
        elevatorId: 'TK-001',
        floor: 15,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
      await errorAdapter.disconnect();
    });
  });
});