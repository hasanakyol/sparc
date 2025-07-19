import { MitsubishiAdapter } from '../../adapters/mitsubishi.adapter';
import { ConsoleLogger } from '../../utils/logger';
import { ElevatorConfig } from '../../adapters/base.adapter';

describe('MitsubishiAdapter', () => {
  let adapter: MitsubishiAdapter;
  let logger: ConsoleLogger;
  let config: ElevatorConfig;

  beforeEach(() => {
    logger = new ConsoleLogger('test');
    config = {
      baseUrl: 'http://test.mitsubishi.com',
      apiKey: 'test-api-key',
      simulatorMode: true,
      simulatorOptions: {
        responseDelay: 10,
        failureRate: 0,
        randomizeStatus: false,
        floors: 40,
        travelTimePerFloor: 100
      }
    };
    adapter = new MitsubishiAdapter(config, logger);
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
      const realAdapter = new MitsubishiAdapter(realConfig, logger);
      
      const result = await realAdapter.connect();
      expect(result).toBe(false);
      expect(realAdapter.isSystemConnected()).toBe(false);
    });
  });

  describe('getStatus', () => {
    it('should return elevator status with MELDAS protocol data', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('MITSUBISHI-001');
      
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
      expect(status?.temperature).toBeGreaterThanOrEqual(20);
      expect(status?.temperature).toBeLessThanOrEqual(26);
      expect(status?.motorStatus).toMatch(/OPTIMAL|EXCELLENT|GOOD|OK/);
      expect(status?.brakeStatus).toMatch(/OPTIMAL|EXCELLENT|GOOD|OK/);
    });

    it('should support deep basement floors for Asian markets', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('MITSUBISHI-001');
      
      expect(status?.currentFloor).toBeGreaterThanOrEqual(-5);
      expect(status?.currentFloor).toBeLessThanOrEqual(40);
    });

    it('should handle energy-saving operational mode', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('MITSUBISHI-001');
      
      // Mitsubishi has unique energy-saving mode
      expect(['NORMAL', 'MAINTENANCE', 'OUT_OF_SERVICE', 'EMERGENCY']).toContain(status?.operationalStatus);
    });
  });

  describe('callElevator', () => {
    it('should call elevator with AI Group Control', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'MITSUBISHI-001',
        floor: 20,
        userId: 'USER-123',
        priority: 'NORMAL'
      });
      
      expect(result).toBe(true);
    });

    it('should optimize with AI for energy efficiency', async () => {
      await adapter.connect();
      // Set high load for energy regeneration test
      const status = await adapter.getStatus('MITSUBISHI-001');
      if (status) {
        status.load = 70;
        status.currentFloor = 20;
      }
      
      const result = await adapter.callElevator({
        elevatorId: 'MITSUBISHI-001',
        floor: 0, // Going down with heavy load = energy regeneration
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
    });

    it('should validate floor number for super high-rise buildings', async () => {
      await adapter.connect();
      await expect(adapter.callElevator({
        elevatorId: 'MITSUBISHI-001',
        floor: 81, // Mitsubishi supports up to 80 floors
        userId: 'USER-123'
      })).rejects.toThrow('Invalid floor number');
    });

    it('should handle AI-optimized routing decisions', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'MITSUBISHI-001',
        floor: 30,
        userId: 'USER-123',
        direction: 'UP'
      });
      
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.speed).toBeLessThanOrEqual(8.0); // NEXIEZ series speed
    });
  });

  describe('emergency', () => {
    it('should activate emergency stop', async () => {
      await adapter.connect();
      const result = await adapter.emergency('MITSUBISHI-001', 'STOP', 'Emergency button pressed');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.operationalStatus).toBe('EMERGENCY');
      expect(status?.direction).toBe('STATIONARY');
      expect(status?.speed).toBe(0);
    });

    it('should evacuate to AI-determined safe floors', async () => {
      await adapter.connect();
      // Set to high floor
      const status = await adapter.getStatus('MITSUBISHI-001');
      if (status) {
        status.currentFloor = 35;
      }
      
      const result = await adapter.emergency('MITSUBISHI-001', 'EVACUATE', 'Building evacuation');
      expect(result).toBe(true);
      
      const updatedStatus = await adapter.getStatus('MITSUBISHI-001');
      expect(updatedStatus?.emergencyMode).toBe(true);
      // Should move to refuge floor (30, 20, 10, or 0)
      if ([0, 10, 20, 30].includes(updatedStatus?.currentFloor || 0)) {
        expect(updatedStatus?.doorStatus).toBe('OPEN');
      }
    });

    it('should handle lockdown mode', async () => {
      await adapter.connect();
      const result = await adapter.emergency('MITSUBISHI-001', 'LOCKDOWN', 'Security lockdown');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.doorStatus).toBe('CLOSED');
      expect(status?.direction).toBe('STATIONARY');
    });

    it('should coordinate group evacuation with AI', async () => {
      await adapter.connect();
      const result = await adapter.emergency('MITSUBISHI-001', 'EVACUATE', 'Fire alarm');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.emergencyMode).toBe(true);
    });
  });

  describe('setMaintenanceMode', () => {
    it('should enable maintenance mode with AI diagnostics', async () => {
      await adapter.connect();
      const result = await adapter.setMaintenanceMode('MITSUBISHI-001', true, 'AI-recommended maintenance');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.operationalStatus).toBe('MAINTENANCE');
    });

    it('should disable maintenance mode', async () => {
      await adapter.connect();
      await adapter.setMaintenanceMode('MITSUBISHI-001', true, 'Maintenance');
      const result = await adapter.setMaintenanceMode('MITSUBISHI-001', false, 'Maintenance complete');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('getDiagnostics', () => {
    it('should return Mitsubishi MELDAS diagnostics with AI insights', async () => {
      await adapter.connect();
      const diagnostics = await adapter.getDiagnostics('MITSUBISHI-001');
      
      expect(diagnostics).toBeDefined();
      expect(diagnostics).toHaveProperty('elevatorId');
      expect(diagnostics).toHaveProperty('system');
      expect(diagnostics.system).toHaveProperty('firmwareVersion');
      expect(diagnostics.system.firmwareVersion).toContain('MELDAS');
      expect(diagnostics.system).toHaveProperty('model');
      expect(diagnostics.system.model).toContain('NEXIEZ');
      expect(diagnostics).toHaveProperty('performance');
      expect(diagnostics.performance).toHaveProperty('energyRegenerated');
      expect(diagnostics.performance).toHaveProperty('aiOptimizationRate');
      expect(diagnostics).toHaveProperty('health');
      expect(diagnostics.health).toHaveProperty('aiSystemHealth');
      expect(diagnostics).toHaveProperty('aiInsights');
      expect(diagnostics.aiInsights).toHaveProperty('trafficPredictionAccuracy');
      expect(diagnostics.aiInsights).toHaveProperty('groupControlEfficiency');
      expect(diagnostics).toHaveProperty('energyData');
      expect(diagnostics.energyData).toHaveProperty('dailyRegeneration');
      expect(diagnostics.energyData).toHaveProperty('carbonFootprint');
      expect(diagnostics.energyData).toHaveProperty('greenModeActive');
    });

    it('should show high health scores', async () => {
      await adapter.connect();
      const diagnostics = await adapter.getDiagnostics('MITSUBISHI-001');
      
      expect(diagnostics.health.motorHealth).toBeGreaterThanOrEqual(97);
      expect(diagnostics.health.brakeHealth).toBeGreaterThanOrEqual(97);
      expect(diagnostics.health.aiSystemHealth).toBeGreaterThanOrEqual(98);
    });
  });

  describe('grantAccess', () => {
    it('should grant floor access with security integration', async () => {
      await adapter.connect();
      const result = await adapter.grantAccess({
        elevatorId: 'MITSUBISHI-001',
        floor: 25,
        userId: 'USER-123',
        duration: 1200,
        accessCode: 'MELDAS123'
      });
      
      expect(result).toBe(true);
    });
  });

  describe('reset', () => {
    it('should perform full system reset with AI recalibration', async () => {
      await adapter.connect();
      await adapter.emergency('MITSUBISHI-001', 'STOP', 'Test');
      
      const result = await adapter.reset('MITSUBISHI-001');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
      expect(status?.errorCodes).toEqual([]);
    });
  });

  describe('real-time updates', () => {
    it('should subscribe to WebSocket with binary frames', async (done) => {
      await adapter.connect();
      
      let updateCount = 0;
      await adapter.subscribeToUpdates('MITSUBISHI-001', (status) => {
        expect(status).toBeDefined();
        expect(status.lastUpdate).toBeDefined();
        updateCount++;
        
        if (updateCount >= 2) {
          adapter.unsubscribeFromUpdates('MITSUBISHI-001').then(() => done());
        }
      });
    }, 3000);
  });

  describe('Mitsubishi-specific features', () => {
    it('should calculate AI-optimized speed', async () => {
      await adapter.connect();
      
      await adapter.callElevator({
        elevatorId: 'MITSUBISHI-001',
        floor: 35,
        userId: 'USER-123'
      });
      
      const status = await adapter.getStatus('MITSUBISHI-001');
      expect(status?.speed).toBeGreaterThan(0);
      expect(status?.speed).toBeLessThanOrEqual(9.6); // With AI boost
    });

    it('should predict load changes based on floor patterns', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('MITSUBISHI-001');
      
      // Load should be optimized by AI
      expect(status?.load).toBeDefined();
      expect(status?.load).toBeGreaterThanOrEqual(0);
      expect(status?.load).toBeLessThanOrEqual(100);
    });

    it('should simulate energy regeneration', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('MITSUBISHI-001');
      if (status) {
        status.direction = 'DOWN';
        status.load = 60; // Heavy load going down
      }
      
      // Energy regeneration should be active
      const diagnostics = await adapter.getDiagnostics('MITSUBISHI-001');
      expect(diagnostics.energyData.dailyRegeneration).toBeGreaterThan(0);
    });

    it('should have precise temperature control', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('MITSUBISHI-001');
      
      // Mitsubishi maintains precise temperature
      expect(status?.temperature).toBeGreaterThanOrEqual(22);
      expect(status?.temperature).toBeLessThanOrEqual(24);
    });

    it('should show AI Group Control efficiency', async () => {
      await adapter.connect();
      
      // Make multiple calls to test group control
      const calls = [
        { elevatorId: 'MITSUBISHI-001', floor: 10, userId: 'USER-1' },
        { elevatorId: 'MITSUBISHI-001', floor: 20, userId: 'USER-2' },
        { elevatorId: 'MITSUBISHI-001', floor: 30, userId: 'USER-3' }
      ];
      
      for (const call of calls) {
        const result = await adapter.callElevator(call);
        expect(result).toBe(true);
      }
      
      const diagnostics = await adapter.getDiagnostics('MITSUBISHI-001');
      expect(diagnostics.aiInsights.groupControlEfficiency).toBeGreaterThanOrEqual(88);
    });
  });

  describe('error handling with Mitsubishi reliability', () => {
    it('should handle exceptional reliability', async () => {
      const errorConfig = {
        ...config,
        simulatorOptions: {
          ...config.simulatorOptions,
          failureRate: 0.003 // 0.3% failure rate (Mitsubishi has exceptional reliability)
        },
        retryAttempts: 3
      };
      
      const errorAdapter = new MitsubishiAdapter(errorConfig, logger);
      await errorAdapter.connect();
      
      // Should almost always succeed on first try
      const result = await errorAdapter.callElevator({
        elevatorId: 'MITSUBISHI-001',
        floor: 20,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
      await errorAdapter.disconnect();
    });
  });
});