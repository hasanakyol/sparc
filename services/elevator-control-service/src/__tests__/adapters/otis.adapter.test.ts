import { OtisAdapter } from '../../adapters/otis.adapter';
import { ConsoleLogger } from '../../utils/logger';
import { ElevatorConfig } from '../../adapters/base.adapter';

describe('OtisAdapter', () => {
  let adapter: OtisAdapter;
  let logger: ConsoleLogger;
  let config: ElevatorConfig;

  beforeEach(() => {
    logger = new ConsoleLogger('test');
    config = {
      baseUrl: 'http://test.otis.com',
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
    adapter = new OtisAdapter(config, logger);
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
  });

  describe('getStatus', () => {
    it('should return elevator status', async () => {
      await adapter.connect();
      const status = await adapter.getStatus('ELEV-001');
      
      expect(status).toBeDefined();
      expect(status).toHaveProperty('currentFloor');
      expect(status).toHaveProperty('direction');
      expect(status).toHaveProperty('doorStatus');
      expect(status).toHaveProperty('operationalStatus');
      expect(status).toHaveProperty('emergencyMode');
      expect(status).toHaveProperty('lastUpdate');
    });

    it('should handle invalid elevator ID', async () => {
      await adapter.connect();
      await expect(adapter.getStatus('invalid@id')).rejects.toThrow('Invalid elevator ID format');
    });
  });

  describe('callElevator', () => {
    it('should call elevator successfully', async () => {
      await adapter.connect();
      const result = await adapter.callElevator({
        elevatorId: 'ELEV-001',
        floor: 5,
        userId: 'USER-123',
        priority: 'NORMAL'
      });
      
      expect(result).toBe(true);
    });

    it('should validate floor number', async () => {
      await adapter.connect();
      await expect(adapter.callElevator({
        elevatorId: 'ELEV-001',
        floor: 999,
        userId: 'USER-123'
      })).rejects.toThrow('Invalid floor number');
    });
  });

  describe('emergency', () => {
    it('should activate emergency stop', async () => {
      await adapter.connect();
      const result = await adapter.emergency('ELEV-001', 'STOP', 'Test emergency');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('ELEV-001');
      expect(status?.emergencyMode).toBe(true);
      expect(status?.operationalStatus).toBe('EMERGENCY');
    });

    it('should release emergency mode', async () => {
      await adapter.connect();
      await adapter.emergency('ELEV-001', 'STOP', 'Test emergency');
      const result = await adapter.emergency('ELEV-001', 'RELEASE', 'Emergency cleared');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('ELEV-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
    });

    it('should handle evacuate action', async () => {
      await adapter.connect();
      const result = await adapter.emergency('ELEV-001', 'EVACUATE', 'Fire alarm');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('ELEV-001');
      expect(status?.emergencyMode).toBe(true);
    });
  });

  describe('setMaintenanceMode', () => {
    it('should enable maintenance mode', async () => {
      await adapter.connect();
      const result = await adapter.setMaintenanceMode('ELEV-001', true, 'Scheduled maintenance');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('ELEV-001');
      expect(status?.operationalStatus).toBe('MAINTENANCE');
    });

    it('should disable maintenance mode', async () => {
      await adapter.connect();
      await adapter.setMaintenanceMode('ELEV-001', true, 'Scheduled maintenance');
      const result = await adapter.setMaintenanceMode('ELEV-001', false, 'Maintenance complete');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('ELEV-001');
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('getDiagnostics', () => {
    it('should return diagnostics data', async () => {
      await adapter.connect();
      const diagnostics = await adapter.getDiagnostics('ELEV-001');
      
      expect(diagnostics).toBeDefined();
      expect(diagnostics).toHaveProperty('elevatorId');
      expect(diagnostics).toHaveProperty('timestamp');
      expect(diagnostics).toHaveProperty('system');
      expect(diagnostics).toHaveProperty('performance');
      expect(diagnostics).toHaveProperty('health');
    });
  });

  describe('grantAccess', () => {
    it('should grant floor access', async () => {
      await adapter.connect();
      const result = await adapter.grantAccess({
        elevatorId: 'ELEV-001',
        floor: 10,
        userId: 'USER-123',
        duration: 300
      });
      
      expect(result).toBe(true);
    });
  });

  describe('reset', () => {
    it('should reset elevator', async () => {
      await adapter.connect();
      // Set emergency mode first
      await adapter.emergency('ELEV-001', 'STOP', 'Test');
      
      const result = await adapter.reset('ELEV-001');
      expect(result).toBe(true);
      
      const status = await adapter.getStatus('ELEV-001');
      expect(status?.emergencyMode).toBe(false);
      expect(status?.operationalStatus).toBe('NORMAL');
    });
  });

  describe('real-time updates', () => {
    it('should subscribe and receive updates', async (done) => {
      await adapter.connect();
      
      let updateCount = 0;
      await adapter.subscribeToUpdates('ELEV-001', (status) => {
        expect(status).toBeDefined();
        expect(status.lastUpdate).toBeDefined();
        updateCount++;
        
        if (updateCount >= 2) {
          adapter.unsubscribeFromUpdates('ELEV-001').then(() => done());
        }
      });
    }, 3000);
  });

  describe('error handling with retries', () => {
    it('should retry failed operations', async () => {
      // Configure adapter with higher failure rate
      const errorConfig = {
        ...config,
        simulatorOptions: {
          ...config.simulatorOptions,
          failureRate: 0.8 // 80% failure rate
        },
        retryAttempts: 5
      };
      
      const errorAdapter = new OtisAdapter(errorConfig, logger);
      await errorAdapter.connect();
      
      // Should eventually succeed due to retries
      const result = await errorAdapter.callElevator({
        elevatorId: 'ELEV-001',
        floor: 5,
        userId: 'USER-123'
      });
      
      expect(result).toBe(true);
      await errorAdapter.disconnect();
    });
  });
});