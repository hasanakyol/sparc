import { KoneAdapter } from '../../adapters/kone.adapter';
import { ConsoleLogger } from '../../utils/logger';
import { ElevatorConfig } from '../../adapters/base.adapter';

describe('KoneAdapter', () => {
  let adapter: KoneAdapter;
  let logger: ConsoleLogger;
  let config: ElevatorConfig;

  beforeEach(() => {
    logger = new ConsoleLogger('test');
    config = {
      baseUrl: 'http://test.kone.com',
      apiKey: 'test-api-key',
      simulatorMode: true,
      simulatorOptions: {
        responseDelay: 10,
        failureRate: 0,
        randomizeStatus: false,
        floors: 20,
        travelTimePerFloor: 100
      }
    };
    adapter = new KoneAdapter(config, logger);
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
      // Test with real mode to simulate failure
      const realConfig = { ...config, simulatorMode: false };
      const realAdapter = new KoneAdapter(realConfig, logger);
      
      const result = await realAdapter.connect();
      expect(result).toBe(false);
      expect(realAdapter.isSystemConnected()).toBe(false);
    });
  });

  describe('getStatus', () => {
    it('should return elevator status with KONE-specific fields', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('KONE-001');
      
      expect(status).toBeDefined();
      expect(status).toHaveProperty('currentFloor');
      expect(status).toHaveProperty('direction');
      expect(status).toHaveProperty('doorStatus');
      expect(status).toHaveProperty('operationalStatus');
      expect(status).toHaveProperty('emergencyMode');
      expect(status).toHaveProperty('load');
      expect(status).toHaveProperty('speed');
      expect(status).toHaveProperty('lastUpdate');
      expect(status).toHaveProperty('temperature');
      expect(status).toHaveProperty('motorStatus');
      expect(status).toHaveProperty('brakeStatus');
    });

    it('should handle invalid elevator ID', async () => {
      await adapter.connect();
      await expect(adapter.getStatus('invalid@id')).rejects.toThrow('Invalid elevator ID format');
    });

    it('should create new status for unknown elevator', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('KONE-NEW-001');
      
      expect(status).toBeDefined();
      expect(status?.direction).toBe('STATIONARY');
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('callElevator', () => {
    it('should call elevator successfully with KONE optimization', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'KONE-001',
        floor: 5,
        userId: 'USER-123',
        priority: 'NORMAL'
      });
      
      expect(result).toBe(true);
    });

    it('should handle emergency priority correctly', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'KONE-001',
        floor: 10,
        userId: 'USER-123',
        priority: 'EMERGENCY'
      });
      
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.operationalStatus).toBe('EMERGENCY');
    });

    it('should validate floor number within KONE limits', async () => {
      await adapter.connect();
      await expect(adapter.callElevator({
        elevatorId: 'KONE-001',
        floor: 51, // KONE limit is 50
        userId: 'USER-123'
      })).rejects.toThrow('Invalid floor number');
    });

    it('should support basement floors', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'KONE-001',
        floor: -2,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
    });
  });

  describe('emergency', () => {
    it('should activate emergency stop', async () => {
      await adapter.connect();
      const result = await adapter.emergency('KONE-001', 'STOP', 'Test emergency');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.operationalStatus).toBe('EMERGENCY');
      expect(status?.direction).toBe('STATIONARY');
    });

    it('should handle evacuate with KONE logic', async () => {
      await adapter.connect();
      const result = await adapter.emergency('KONE-001', 'EVACUATE', 'Fire drill');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.direction).toBe('STATIONARY');
      expect(status?.doorStatus).toBe('OPEN');
    });

    it('should handle lockdown mode', async () => {
      await adapter.connect();
      const result = await adapter.emergency('KONE-001', 'LOCKDOWN', 'Security threat');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.doorStatus).toBe('CLOSED');
    });

    it('should release emergency mode', async () => {
      await adapter.connect();
      await adapter.emergency('KONE-001', 'STOP', 'Test emergency');
      const result = await adapter.emergency('KONE-001', 'RELEASE', 'Emergency cleared');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('setMaintenanceMode', () => {
    it('should enable maintenance mode', async () => {
      await adapter.connect();
      const result = await adapter.setMaintenanceMode('KONE-001', true, 'Scheduled maintenance');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.operationalStatus).toBe('MAINTENANCE');
    });

    it('should disable maintenance mode', async () => {
      await adapter.connect();
      await adapter.setMaintenanceMode('KONE-001', true, 'Scheduled maintenance');
      const result = await adapter.setMaintenanceMode('KONE-001', false, 'Maintenance complete');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('getDiagnostics', () => {
    it('should return KONE-specific diagnostics', async () => {
      await adapter.connect();
      const diagnostics = await adapter.getDiagnostics('KONE-001');
      
      expect(diagnostics).toBeDefined();
      expect(diagnostics).toHaveProperty('elevatorId');
      expect(diagnostics).toHaveProperty('timestamp');
      expect(diagnostics).toHaveProperty('system');
      expect(diagnostics.system).toHaveProperty('firmwareVersion');
      expect(diagnostics.system.firmwareVersion).toContain('KONE');
      expect(diagnostics).toHaveProperty('performance');
      expect(diagnostics.performance).toHaveProperty('peopleFlowEfficiency');
      expect(diagnostics).toHaveProperty('health');
      expect(diagnostics).toHaveProperty('koneSpecific');
      expect(diagnostics.koneSpecific).toHaveProperty('ecoEfficiencyRating');
      expect(diagnostics.koneSpecific).toHaveProperty('peopleFlowIntelligence');
      expect(diagnostics.koneSpecific).toHaveProperty('connectedServices');
    });
  });

  describe('grantAccess', () => {
    it('should grant floor access with KONE access control', async () => {
      await adapter.connect();
      const result = await adapter.grantAccess({
        elevatorId: 'KONE-001',
        floor: 10,
        userId: 'USER-123',
        duration: 300,
        accessCode: '1234'
      });
      
      expect(result).toBe(true);
    });
  });

  describe('reset', () => {
    it('should reset elevator to default state', async () => {
      await adapter.connect();
      // Set emergency mode first
      await adapter.emergency('KONE-001', 'STOP', 'Test');
      
      const result = await adapter.reset('KONE-001');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('KONE-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
      expect(status?.direction).toBe('STATIONARY');
    });
  });

  describe('real-time updates', () => {
    it('should subscribe and receive updates', async (done) => {
      await adapter.connect();
      
      let updateCount = 0;
      await adapter.subscribeToUpdates('KONE-001', (status) => {
        expect(status).toBeDefined();
        expect(status.lastUpdate).toBeDefined();
        updateCount++;
        
        if (updateCount >= 2) {
          adapter.unsubscribeFromUpdates('KONE-001').then(() => done());
        }
      });
    }, 3000);
  });

  describe('KONE-specific features', () => {
    it('should simulate smooth acceleration/deceleration', async () => {
      await adapter.connect();
      
      // Call elevator to a distant floor
      await adapter.callElevator({
        elevatorId: 'KONE-001',
        floor: 15,
        userId: 'USER-123'
      });
      
      // Check speed calculation
      const status = await adapter.getStatus('KONE-001');
      expect(status?.speed).toBeGreaterThan(0);
      expect(status?.speed).toBeLessThanOrEqual(6.0); // KONE max speed
    });

    it('should optimize door operations based on load', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('KONE-001');
      
      // The door operation logic should adjust based on load
      expect(status?.load).toBeDefined();
      expect(status?.load).toBeGreaterThanOrEqual(0);
      expect(status?.load).toBeLessThanOrEqual(100);
    });
  });

  describe('error handling with retries', () => {
    it('should retry failed operations with KONE reliability', async () => {
      // Configure adapter with higher failure rate
      const errorConfig = {
        ...config,
        simulatorOptions: {
          ...config.simulatorOptions,
          failureRate: 0.5 // 50% failure rate
        },
        retryAttempts: 5
      };
      
      const errorAdapter = new KoneAdapter(errorConfig, logger);
      await errorAdapter.connect();
      
      // Should eventually succeed due to retries (KONE has low failure rate)
      const result = await errorAdapter.callElevator({
        elevatorId: 'KONE-001',
        floor: 5,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
      await errorAdapter.disconnect();
    });
  });
});