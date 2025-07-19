import { AdapterFactory } from '../../adapters/adapter-factory';
import { BaseElevatorAdapter, ElevatorConfig } from '../../adapters/base.adapter';
import { ConsoleLogger } from '../../utils/logger';
import { ManufacturerType } from '../../types';

describe('Elevator Adapter Integration Tests', () => {
  let logger: ConsoleLogger;
  let baseConfig: ElevatorConfig;
  const manufacturers: ManufacturerType[] = ['OTIS', 'KONE', 'SCHINDLER', 'THYSSENKRUPP', 'MITSUBISHI'];
  const adapters: Map<string, BaseElevatorAdapter> = new Map();

  beforeAll(async () => {
    logger = new ConsoleLogger('integration-test');
    baseConfig = {
      baseUrl: 'http://test.elevator.com',
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

    // Create and connect all adapters
    for (const manufacturer of manufacturers) {
      const config = AdapterFactory.getAdapterConfig(manufacturer, baseConfig);
      const adapter = AdapterFactory.create(manufacturer, config, logger);
      await adapter.connect();
      adapters.set(manufacturer, adapter);
    }
  });

  afterAll(async () => {
    // Disconnect all adapters
    for (const adapter of adapters.values()) {
      await adapter.disconnect();
    }
  });

  describe('Factory Pattern', () => {
    it('should create correct adapter for each manufacturer', () => {
      for (const manufacturer of manufacturers) {
        const adapter = adapters.get(manufacturer);
        expect(adapter).toBeDefined();
        expect(adapter?.isSystemConnected()).toBe(true);
        
        // Check adapter type based on manufacturer
        const adapterName = adapter?.constructor.name;
        expect(adapterName?.toLowerCase()).toContain(manufacturer.toLowerCase());
      }
    });

    it('should handle unknown manufacturer with fallback', () => {
      const adapter = AdapterFactory.create('GENERIC' as ManufacturerType, baseConfig, logger);
      expect(adapter).toBeDefined();
      expect(adapter.constructor.name).toBe('OtisAdapter');
    });
  });

  describe('Common Interface Compliance', () => {
    it('all adapters should implement BaseElevatorAdapter interface', () => {
      for (const [manufacturer, adapter] of adapters) {
        // Check all required methods exist
        expect(typeof adapter.connect).toBe('function');
        expect(typeof adapter.disconnect).toBe('function');
        expect(typeof adapter.callElevator).toBe('function');
        expect(typeof adapter.grantAccess).toBe('function');
        expect(typeof adapter.getStatus).toBe('function');
        expect(typeof adapter.emergency).toBe('function');
        expect(typeof adapter.setMaintenanceMode).toBe('function');
        expect(typeof adapter.reset).toBe('function');
        expect(typeof adapter.getDiagnostics).toBe('function');
        expect(typeof adapter.subscribeToUpdates).toBe('function');
        expect(typeof adapter.unsubscribeFromUpdates).toBe('function');
      }
    });

    it('all adapters should return consistent status format', async () => {
      for (const [manufacturer, adapter] of adapters) {
        const status = await adapter.getStatus(`${manufacturer}-001`);
        
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
        
        // Validate enum values
        expect(['UP', 'DOWN', 'STATIONARY']).toContain(status?.direction);
        expect(['OPEN', 'CLOSED', 'OPENING', 'CLOSING', 'BLOCKED']).toContain(status?.doorStatus);
        expect(['NORMAL', 'MAINTENANCE', 'OUT_OF_SERVICE', 'EMERGENCY']).toContain(status?.operationalStatus);
      }
    });
  });

  describe('Cross-Adapter Functionality', () => {
    it('all adapters should handle elevator calls', async () => {
      const results: Record<string, boolean> = {};
      
      for (const [manufacturer, adapter] of adapters) {
        const result = await adapter.callElevator({
          elevatorId: `${manufacturer}-001`,
          floor: 10,
          userId: 'USER-123',
          priority: 'NORMAL'
        });
        results[manufacturer] = result;
      }
      
      // All should succeed
      for (const [manufacturer, result] of Object.entries(results)) {
        expect(result).toBe(true);
      }
    });

    it('all adapters should handle emergency operations', async () => {
      for (const [manufacturer, adapter] of adapters) {
        // Activate emergency
        const stopResult = await adapter.emergency(`${manufacturer}-001`, 'STOP', 'Test emergency');
        expect(stopResult).toBe(true);
        
        // Verify emergency mode
        const status = await adapter.getStatus(`${manufacturer}-001`);
        expect(status?.emergencyMode).toBe(true);
        expect(status?.operationalStatus).toBe('EMERGENCY');
        
        // Release emergency
        const releaseResult = await adapter.emergency(`${manufacturer}-001`, 'RELEASE', 'All clear');
        expect(releaseResult).toBe(true);
        
        // Verify normal mode restored
        const normalStatus = await adapter.getStatus(`${manufacturer}-001`);
        expect(normalStatus?.emergencyMode).toBe(false);
        expect(normalStatus?.operationalStatus).toBe('NORMAL');
      }
    });

    it('all adapters should handle maintenance mode', async () => {
      for (const [manufacturer, adapter] of adapters) {
        // Enable maintenance
        const enableResult = await adapter.setMaintenanceMode(`${manufacturer}-001`, true, 'Test maintenance');
        expect(enableResult).toBe(true);
        
        // Verify maintenance mode
        const maintenanceStatus = await adapter.getStatus(`${manufacturer}-001`);
        expect(maintenanceStatus?.operationalStatus).toBe('MAINTENANCE');
        
        // Disable maintenance
        const disableResult = await adapter.setMaintenanceMode(`${manufacturer}-001`, false, 'Complete');
        expect(disableResult).toBe(true);
        
        // Verify normal mode
        const normalStatus = await adapter.getStatus(`${manufacturer}-001`);
        expect(normalStatus?.operationalStatus).toBe('NORMAL');
      }
    });
  });

  describe('Manufacturer-Specific Features', () => {
    it('should handle manufacturer-specific diagnostics', async () => {
      const diagnosticsResults: Record<string, any> = {};
      
      for (const [manufacturer, adapter] of adapters) {
        const diagnostics = await adapter.getDiagnostics(`${manufacturer}-001`);
        diagnosticsResults[manufacturer] = diagnostics;
      }
      
      // Common fields
      for (const [manufacturer, diagnostics] of Object.entries(diagnosticsResults)) {
        expect(diagnostics).toHaveProperty('elevatorId');
        expect(diagnostics).toHaveProperty('timestamp');
        expect(diagnostics).toHaveProperty('system');
        expect(diagnostics).toHaveProperty('performance');
        expect(diagnostics).toHaveProperty('health');
      }
      
      // Manufacturer-specific fields
      expect(diagnosticsResults.KONE).toHaveProperty('koneSpecific');
      expect(diagnosticsResults.SCHINDLER).toHaveProperty('portTechnology');
      expect(diagnosticsResults.THYSSENKRUPP).toHaveProperty('maxInsights');
      expect(diagnosticsResults.MITSUBISHI).toHaveProperty('aiInsights');
      expect(diagnosticsResults.MITSUBISHI).toHaveProperty('energyData');
    });

    it('should respect manufacturer-specific limits', async () => {
      // Test floor limits
      const floorLimits: Record<string, number> = {
        OTIS: 100,
        KONE: 50,
        SCHINDLER: 60,
        THYSSENKRUPP: 100,
        MITSUBISHI: 80
      };
      
      for (const [manufacturer, adapter] of adapters) {
        const limit = floorLimits[manufacturer];
        
        // Should succeed within limit
        const validResult = await adapter.callElevator({
          elevatorId: `${manufacturer}-001`,
          floor: Math.floor(limit / 2),
          userId: 'USER-123'
        });
        expect(validResult).toBe(true);
        
        // Should fail beyond limit
        await expect(adapter.callElevator({
          elevatorId: `${manufacturer}-001`,
          floor: limit + 1,
          userId: 'USER-123'
        })).rejects.toThrow('Invalid floor number');
      }
    });
  });

  describe('Performance Characteristics', () => {
    it('should have manufacturer-appropriate speeds', async () => {
      const speedRanges: Record<string, { min: number; max: number }> = {
        OTIS: { min: 0, max: 6.0 },
        KONE: { min: 0, max: 6.0 },
        SCHINDLER: { min: 0, max: 4.0 },
        THYSSENKRUPP: { min: 0, max: 10.0 },
        MITSUBISHI: { min: 0, max: 8.0 }
      };
      
      for (const [manufacturer, adapter] of adapters) {
        // Trigger movement
        await adapter.callElevator({
          elevatorId: `${manufacturer}-001`,
          floor: 20,
          userId: 'USER-123'
        });
        
        // Check speed
        const status = await adapter.getStatus(`${manufacturer}-001`);
        const range = speedRanges[manufacturer];
        expect(status?.speed).toBeGreaterThanOrEqual(range.min);
        expect(status?.speed).toBeLessThanOrEqual(range.max);
      }
    });

    it('should have manufacturer-appropriate reliability', async () => {
      const failureRates: Record<string, number> = {
        OTIS: 0.05,
        KONE: 0.02,
        SCHINDLER: 0.01,
        THYSSENKRUPP: 0.005,
        MITSUBISHI: 0.003
      };
      
      // Test with simulated failures
      for (const [manufacturer, expectedRate] of Object.entries(failureRates)) {
        const testConfig = {
          ...baseConfig,
          simulatorOptions: {
            ...baseConfig.simulatorOptions,
            failureRate: expectedRate
          }
        };
        
        const testAdapter = AdapterFactory.create(manufacturer as ManufacturerType, testConfig, logger);
        await testAdapter.connect();
        
        let failures = 0;
        const attempts = 100;
        
        for (let i = 0; i < attempts; i++) {
          try {
            await testAdapter.callElevator({
              elevatorId: `${manufacturer}-TEST`,
              floor: 5,
              userId: 'USER-TEST'
            });
          } catch {
            failures++;
          }
        }
        
        const actualRate = failures / attempts;
        // Allow some variance due to randomness
        expect(actualRate).toBeCloseTo(expectedRate, 1);
        
        await testAdapter.disconnect();
      }
    });
  });

  describe('Real-time Updates', () => {
    it('all adapters should support real-time updates', async (done) => {
      const updatePromises: Promise<void>[] = [];
      let completedCount = 0;
      
      for (const [manufacturer, adapter] of adapters) {
        const promise = new Promise<void>((resolve) => {
          let updateCount = 0;
          adapter.subscribeToUpdates(`${manufacturer}-001`, (status) => {
            expect(status).toBeDefined();
            expect(status.lastUpdate).toBeDefined();
            updateCount++;
            
            if (updateCount >= 2) {
              adapter.unsubscribeFromUpdates(`${manufacturer}-001`).then(() => {
                completedCount++;
                if (completedCount === manufacturers.length) {
                  done();
                }
                resolve();
              });
            }
          });
        });
        
        updatePromises.push(promise);
      }
      
      // Wait for all to complete
      await Promise.race([
        Promise.all(updatePromises),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000))
      ]);
    }, 10000);
  });

  describe('Error Recovery', () => {
    it('all adapters should recover from errors gracefully', async () => {
      for (const [manufacturer, adapter] of adapters) {
        // Cause an error with invalid elevator ID
        try {
          await adapter.getStatus('invalid@id!');
        } catch (error) {
          expect(error.message).toContain('Invalid elevator ID');
        }
        
        // Should still work after error
        const status = await adapter.getStatus(`${manufacturer}-001`);
        expect(status).toBeDefined();
        expect(adapter.isSystemConnected()).toBe(true);
      }
    });

    it('all adapters should maintain connection after failures', async () => {
      for (const [manufacturer, adapter] of adapters) {
        // Multiple operations that might fail
        const operations = [
          () => adapter.callElevator({ elevatorId: `${manufacturer}-001`, floor: 999, userId: 'USER' }),
          () => adapter.getStatus('invalid-id'),
          () => adapter.emergency(`${manufacturer}-001`, 'INVALID' as any, 'Test')
        ];
        
        for (const op of operations) {
          try {
            await op();
          } catch {
            // Expected to fail
          }
        }
        
        // Connection should still be active
        expect(adapter.isSystemConnected()).toBe(true);
        
        // Should still work
        const result = await adapter.callElevator({
          elevatorId: `${manufacturer}-001`,
          floor: 5,
          userId: 'USER-123'
        });
        expect(result).toBe(true);
      }
    });
  });
});