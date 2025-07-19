#!/usr/bin/env tsx

import { OtisAdapter } from './adapters/otis.adapter';
import { ConsoleLogger } from './utils/logger';

async function testOtisAdapter() {
  const logger = new ConsoleLogger('test-adapter');
  
  // Create adapter in simulator mode
  const adapter = new OtisAdapter({
    baseUrl: 'http://localhost:8080',
    apiKey: 'test-api-key',
    simulatorMode: true,
    simulatorOptions: {
      responseDelay: 100,
      failureRate: 0.1,
      randomizeStatus: true,
      floors: 20,
      travelTimePerFloor: 3000
    }
  }, logger);

  try {
    console.log('🔧 Testing OTIS Adapter in Simulator Mode\n');

    // Test connection
    console.log('1. Testing connection...');
    const connected = await adapter.connect();
    console.log(`   ✅ Connected: ${connected}\n`);

    // Test elevator status
    console.log('2. Getting elevator status...');
    const status = await adapter.getStatus('ELEV-001');
    console.log('   ✅ Status:', JSON.stringify(status, null, 2), '\n');

    // Test calling elevator
    console.log('3. Calling elevator to floor 5...');
    const callSuccess = await adapter.callElevator({
      elevatorId: 'ELEV-001',
      floor: 5,
      userId: 'USER-123',
      priority: 'NORMAL'
    });
    console.log(`   ✅ Call successful: ${callSuccess}\n`);

    // Test granting access
    console.log('4. Granting floor access...');
    const accessSuccess = await adapter.grantAccess({
      elevatorId: 'ELEV-001',
      floor: 10,
      userId: 'USER-123',
      duration: 300
    });
    console.log(`   ✅ Access granted: ${accessSuccess}\n`);

    // Test emergency mode
    console.log('5. Testing emergency stop...');
    const emergencySuccess = await adapter.emergency('ELEV-001', 'STOP', 'Test emergency');
    console.log(`   ✅ Emergency activated: ${emergencySuccess}\n`);

    // Get status after emergency
    console.log('6. Status after emergency...');
    const emergencyStatus = await adapter.getStatus('ELEV-001');
    console.log('   ✅ Emergency status:', JSON.stringify(emergencyStatus, null, 2), '\n');

    // Release emergency
    console.log('7. Releasing emergency mode...');
    const releaseSuccess = await adapter.emergency('ELEV-001', 'RELEASE', 'Test complete');
    console.log(`   ✅ Emergency released: ${releaseSuccess}\n`);

    // Test maintenance mode
    console.log('8. Setting maintenance mode...');
    const maintenanceSuccess = await adapter.setMaintenanceMode('ELEV-001', true, 'Scheduled maintenance');
    console.log(`   ✅ Maintenance mode set: ${maintenanceSuccess}\n`);

    // Get diagnostics
    console.log('9. Getting diagnostics...');
    const diagnostics = await adapter.getDiagnostics('ELEV-001');
    console.log('   ✅ Diagnostics:', JSON.stringify(diagnostics, null, 2), '\n');

    // Test real-time updates
    console.log('10. Subscribing to real-time updates...');
    await adapter.subscribeToUpdates('ELEV-001', (status) => {
      console.log('   📡 Real-time update:', JSON.stringify(status, null, 2));
    });
    console.log('   ✅ Subscribed to updates\n');

    // Wait for a few updates
    console.log('   ⏳ Waiting for real-time updates (5 seconds)...');
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Unsubscribe
    console.log('\n11. Unsubscribing from updates...');
    await adapter.unsubscribeFromUpdates('ELEV-001');
    console.log('   ✅ Unsubscribed\n');

    // Reset elevator
    console.log('12. Resetting elevator...');
    const resetSuccess = await adapter.reset('ELEV-001');
    console.log(`   ✅ Reset successful: ${resetSuccess}\n`);

    // Disconnect
    console.log('13. Disconnecting...');
    await adapter.disconnect();
    console.log('   ✅ Disconnected\n');

    console.log('✨ All tests completed successfully!');
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

// Run the test
testOtisAdapter().catch(console.error);