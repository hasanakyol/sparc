import { test, expect, Page, BrowserContext } from '@playwright/test';
import { randomUUID } from 'crypto';

// Test data interfaces
interface TestUser {
  id: string;
  email: string;
  password: string;
  role: string;
  tenantId: string;
}

interface TestDoor {
  id: string;
  name: string;
  buildingId: string;
  floorId: string;
  zoneId: string;
  status: 'locked' | 'unlocked' | 'offline';
}

interface AccessEvent {
  id: string;
  userId: string;
  doorId: string;
  timestamp: string;
  result: 'granted' | 'denied';
  reason?: string;
}

// Test configuration
const TEST_CONFIG = {
  baseURL: process.env.TEST_BASE_URL || 'http://localhost:3000',
  apiURL: process.env.TEST_API_URL || 'http://localhost:8080',
  timeout: 30000,
  offlineTimeout: 72 * 60 * 60 * 1000, // 72 hours in milliseconds
};

// Helper functions
class AccessControlTestHelper {
  constructor(private page: Page) {}

  async login(user: TestUser) {
    await this.page.goto(`${TEST_CONFIG.baseURL}/auth/login`);
    await this.page.fill('[data-testid="email-input"]', user.email);
    await this.page.fill('[data-testid="password-input"]', user.password);
    await this.page.click('[data-testid="login-button"]');
    await this.page.waitForURL('**/dashboard');
  }

  async navigateToAccessControl() {
    await this.page.click('[data-testid="nav-access-control"]');
    await this.page.waitForURL('**/access-control');
  }

  async createTestDoor(door: Partial<TestDoor>) {
    await this.page.click('[data-testid="add-door-button"]');
    await this.page.fill('[data-testid="door-name-input"]', door.name || 'Test Door');
    await this.page.selectOption('[data-testid="building-select"]', door.buildingId || '');
    await this.page.selectOption('[data-testid="floor-select"]', door.floorId || '');
    await this.page.selectOption('[data-testid="zone-select"]', door.zoneId || '');
    await this.page.click('[data-testid="save-door-button"]');
    await this.page.waitForSelector('[data-testid="door-created-success"]');
  }

  async simulateCardPresentation(doorId: string, cardId: string) {
    // Simulate API call to present card at door
    const response = await this.page.request.post(`${TEST_CONFIG.apiURL}/api/access-control/doors/${doorId}/access`, {
      data: { cardId, timestamp: new Date().toISOString() }
    });
    return response;
  }

  async waitForAccessEvent(doorId: string, timeout = 5000) {
    return this.page.waitForSelector(`[data-testid="access-event-${doorId}"]`, { timeout });
  }

  async toggleOfflineMode(enabled: boolean) {
    // Simulate network disconnection for offline testing
    if (enabled) {
      await this.page.context().setOffline(true);
    } else {
      await this.page.context().setOffline(false);
    }
  }

  async verifyDoorStatus(doorId: string, expectedStatus: string) {
    const statusElement = await this.page.locator(`[data-testid="door-status-${doorId}"]`);
    await expect(statusElement).toHaveText(expectedStatus);
  }

  async verifyAccessEventLogged(doorId: string, result: 'granted' | 'denied') {
    const eventElement = await this.page.locator(`[data-testid="access-event-${doorId}"]`);
    await expect(eventElement).toContainText(result);
  }
}

// Test data setup
const testUsers: TestUser[] = [
  {
    id: randomUUID(),
    email: 'admin@test.com',
    password: 'TestPassword123!',
    role: 'admin',
    tenantId: 'tenant-1'
  },
  {
    id: randomUUID(),
    email: 'employee@test.com',
    password: 'TestPassword123!',
    role: 'employee',
    tenantId: 'tenant-1'
  },
  {
    id: randomUUID(),
    email: 'visitor@test.com',
    password: 'TestPassword123!',
    role: 'visitor',
    tenantId: 'tenant-1'
  }
];

const testDoors: TestDoor[] = [
  {
    id: 'door-main-entrance',
    name: 'Main Entrance',
    buildingId: 'building-1',
    floorId: 'floor-1',
    zoneId: 'zone-lobby',
    status: 'locked'
  },
  {
    id: 'door-server-room',
    name: 'Server Room',
    buildingId: 'building-1',
    floorId: 'floor-2',
    zoneId: 'zone-secure',
    status: 'locked'
  }
];

test.describe('Access Control - Physical Access Management (Requirement 2)', () => {
  let helper: AccessControlTestHelper;

  test.beforeEach(async ({ page }) => {
    helper = new AccessControlTestHelper(page);
    await helper.login(testUsers[0]); // Login as admin
    await helper.navigateToAccessControl();
  });

  test('should authenticate valid credentials and grant access', async ({ page }) => {
    // Requirement 2.1: Verify permissions and log attempt
    const doorId = testDoors[0].id;
    const validCardId = 'card-123-valid';

    // Present valid card
    const response = await helper.simulateCardPresentation(doorId, validCardId);
    expect(response.status()).toBe(200);

    // Verify door unlocks
    await helper.verifyDoorStatus(doorId, 'unlocked');

    // Verify access event is logged
    await helper.verifyAccessEventLogged(doorId, 'granted');

    // Verify audit log entry
    await page.click('[data-testid="audit-logs-tab"]');
    const auditEntry = page.locator('[data-testid="audit-entry"]').first();
    await expect(auditEntry).toContainText('Access granted');
    await expect(auditEntry).toContainText(doorId);
    await expect(auditEntry).toContainText(validCardId);
  });

  test('should deny access for invalid credentials', async ({ page }) => {
    // Requirement 2.3: Keep door locked and log failed attempt
    const doorId = testDoors[0].id;
    const invalidCardId = 'card-999-invalid';

    // Present invalid card
    const response = await helper.simulateCardPresentation(doorId, invalidCardId);
    expect(response.status()).toBe(403);

    // Verify door remains locked
    await helper.verifyDoorStatus(doorId, 'locked');

    // Verify access denial is logged with reason
    await helper.verifyAccessEventLogged(doorId, 'denied');

    // Check denial reason
    const eventDetails = page.locator(`[data-testid="access-event-details-${doorId}"]`);
    await expect(eventDetails).toContainText('Invalid credentials');
  });

  test('should handle time-based access restrictions', async ({ page }) => {
    // Test access outside allowed hours
    const doorId = testDoors[1].id; // Server room with restricted hours
    const validCardId = 'card-123-valid';

    // Simulate access attempt outside business hours
    await page.evaluate(() => {
      // Mock current time to be outside business hours (e.g., 2 AM)
      const mockDate = new Date();
      mockDate.setHours(2, 0, 0, 0);
      jest.spyOn(Date, 'now').mockReturnValue(mockDate.getTime());
    });

    const response = await helper.simulateCardPresentation(doorId, validCardId);
    expect(response.status()).toBe(403);

    await helper.verifyDoorStatus(doorId, 'locked');
    await helper.verifyAccessEventLogged(doorId, 'denied');

    const eventDetails = page.locator(`[data-testid="access-event-details-${doorId}"]`);
    await expect(eventDetails).toContainText('Outside allowed hours');
  });

  test('should support emergency override functionality', async ({ page }) => {
    // Test emergency unlock override
    const doorId = testDoors[0].id;

    // Activate emergency mode
    await page.click('[data-testid="emergency-mode-toggle"]');
    await page.click('[data-testid="confirm-emergency-mode"]');

    // Verify emergency mode is active
    await expect(page.locator('[data-testid="emergency-mode-indicator"]')).toBeVisible();

    // Verify door unlocks in emergency mode
    await helper.verifyDoorStatus(doorId, 'unlocked');

    // Verify emergency event is logged
    await page.click('[data-testid="audit-logs-tab"]');
    const emergencyLog = page.locator('[data-testid="audit-entry"]').first();
    await expect(emergencyLog).toContainText('Emergency mode activated');
  });

  test('should handle door-ajar alerts', async ({ page }) => {
    // Simulate door held open beyond configured time
    const doorId = testDoors[0].id;

    // Grant access first
    await helper.simulateCardPresentation(doorId, 'card-123-valid');
    await helper.verifyDoorStatus(doorId, 'unlocked');

    // Wait for door-ajar timeout (simulate 30 seconds)
    await page.waitForTimeout(2000); // Shortened for test

    // Verify door-ajar alert is generated
    const alertElement = page.locator('[data-testid="door-ajar-alert"]');
    await expect(alertElement).toBeVisible();
    await expect(alertElement).toContainText('Door held open');
    await expect(alertElement).toContainText(testDoors[0].name);
  });
});

test.describe('Access Control - Offline Resilience (Requirement 27)', () => {
  let helper: AccessControlTestHelper;

  test.beforeEach(async ({ page }) => {
    helper = new AccessControlTestHelper(page);
    await helper.login(testUsers[0]);
    await helper.navigateToAccessControl();
  });

  test('should continue access control operations when offline', async ({ page }) => {
    // Requirement 27.1: Continue operating for up to 72 hours
    const doorId = testDoors[0].id;
    const validCardId = 'card-123-valid';

    // Go offline
    await helper.toggleOfflineMode(true);

    // Verify offline indicator is shown
    await expect(page.locator('[data-testid="offline-indicator"]')).toBeVisible();

    // Present valid card while offline
    const response = await helper.simulateCardPresentation(doorId, validCardId);
    
    // Should still work with cached permissions
    expect(response.status()).toBe(200);
    await helper.verifyDoorStatus(doorId, 'unlocked');

    // Verify offline event is queued
    const offlineQueue = page.locator('[data-testid="offline-event-queue"]');
    await expect(offlineQueue).toContainText('1 event queued');
  });

  test('should maintain audit logs during offline operation', async ({ page }) => {
    // Requirement 27.3: Maintain complete audit logs
    const doorId = testDoors[0].id;
    const validCardId = 'card-123-valid';

    // Go offline
    await helper.toggleOfflineMode(true);

    // Perform multiple access attempts
    await helper.simulateCardPresentation(doorId, validCardId);
    await helper.simulateCardPresentation(doorId, 'card-456-valid');
    await helper.simulateCardPresentation(doorId, 'card-999-invalid');

    // Verify events are logged locally
    await page.click('[data-testid="offline-logs-tab"]');
    const offlineLogs = page.locator('[data-testid="offline-log-entry"]');
    await expect(offlineLogs).toHaveCount(3);
  });

  test('should propagate credential revocations via mesh networking', async ({ page }) => {
    // Requirement 27.4: Propagate revocations within 15 minutes
    const revokedCardId = 'card-789-revoked';

    // Simulate credential revocation while offline
    await helper.toggleOfflineMode(true);
    
    // Revoke credential
    await page.click('[data-testid="credentials-tab"]');
    await page.click(`[data-testid="revoke-card-${revokedCardId}"]`);
    await page.click('[data-testid="confirm-revocation"]');

    // Verify revocation is queued for mesh propagation
    const meshQueue = page.locator('[data-testid="mesh-propagation-queue"]');
    await expect(meshQueue).toContainText('Credential revocation queued');

    // Simulate mesh network propagation
    await page.click('[data-testid="simulate-mesh-propagation"]');

    // Verify revocation status
    const revocationStatus = page.locator(`[data-testid="card-status-${revokedCardId}"]`);
    await expect(revocationStatus).toContainText('Revoked (propagated)');
  });

  test('should synchronize offline data when connectivity is restored', async ({ page }) => {
    // Requirement 27.5: Automatically synchronize with priority-based ordering
    const doorId = testDoors[0].id;

    // Go offline and generate events
    await helper.toggleOfflineMode(true);
    
    // Generate multiple types of events
    await helper.simulateCardPresentation(doorId, 'card-123-valid');
    await page.click('[data-testid="emergency-mode-toggle"]');
    await helper.simulateCardPresentation(doorId, 'card-456-valid');

    // Verify offline queue
    const queueCount = page.locator('[data-testid="offline-queue-count"]');
    await expect(queueCount).toContainText('3');

    // Restore connectivity
    await helper.toggleOfflineMode(false);

    // Verify synchronization starts
    const syncIndicator = page.locator('[data-testid="sync-indicator"]');
    await expect(syncIndicator).toBeVisible();
    await expect(syncIndicator).toContainText('Synchronizing...');

    // Wait for sync completion
    await page.waitForSelector('[data-testid="sync-complete"]', { timeout: 10000 });

    // Verify all events are synchronized
    await expect(queueCount).toContainText('0');
    
    // Verify priority ordering (emergency events first)
    await page.click('[data-testid="sync-log-tab"]');
    const syncLogs = page.locator('[data-testid="sync-log-entry"]');
    await expect(syncLogs.first()).toContainText('Emergency mode');
  });

  test('should handle conflicts during synchronization', async ({ page }) => {
    // Requirement 27.7: Apply predefined resolution rules with audit trails
    const doorId = testDoors[0].id;
    const conflictCardId = 'card-conflict-test';

    // Create conflict scenario
    await helper.toggleOfflineMode(true);
    
    // Modify card permissions offline
    await page.click('[data-testid="credentials-tab"]');
    await page.click(`[data-testid="edit-card-${conflictCardId}"]`);
    await page.selectOption('[data-testid="access-level-select"]', 'restricted');
    await page.click('[data-testid="save-card"]');

    // Simulate server-side change (different access level)
    await page.evaluate(() => {
      window.simulateServerConflict = true;
    });

    // Restore connectivity
    await helper.toggleOfflineMode(false);

    // Wait for conflict detection
    const conflictDialog = page.locator('[data-testid="conflict-resolution-dialog"]');
    await expect(conflictDialog).toBeVisible();

    // Verify conflict details
    await expect(conflictDialog).toContainText('Access level conflict');
    await expect(conflictDialog).toContainText(conflictCardId);

    // Apply resolution rule (server wins)
    await page.click('[data-testid="apply-server-version"]');

    // Verify conflict resolution is logged
    await page.click('[data-testid="audit-logs-tab"]');
    const conflictLog = page.locator('[data-testid="audit-entry"]').first();
    await expect(conflictLog).toContainText('Conflict resolved');
    await expect(conflictLog).toContainText('Server version applied');
  });

  test('should provide offline capability testing tools', async ({ page }) => {
    // Requirement 27.8: Tools to test and verify offline capabilities
    
    // Navigate to offline testing tools
    await page.click('[data-testid="system-tools-menu"]');
    await page.click('[data-testid="offline-testing-tools"]');

    // Run offline capability test
    await page.click('[data-testid="run-offline-test"]');

    // Verify test results
    const testResults = page.locator('[data-testid="offline-test-results"]');
    await expect(testResults).toBeVisible();

    // Check individual test components
    await expect(page.locator('[data-testid="cache-test-result"]')).toContainText('PASS');
    await expect(page.locator('[data-testid="mesh-test-result"]')).toContainText('PASS');
    await expect(page.locator('[data-testid="storage-test-result"]')).toContainText('PASS');
    await expect(page.locator('[data-testid="sync-test-result"]')).toContainText('PASS');

    // Verify 72-hour capacity test
    await expect(page.locator('[data-testid="capacity-test-result"]')).toContainText('72 hours supported');
  });
});

test.describe('Access Control - Emergency Scenarios and System Recovery', () => {
  let helper: AccessControlTestHelper;

  test.beforeEach(async ({ page }) => {
    helper = new AccessControlTestHelper(page);
    await helper.login(testUsers[0]);
    await helper.navigateToAccessControl();
  });

  test('should handle fire alarm integration and emergency unlock', async ({ page }) => {
    // Test fire safety system integration
    
    // Simulate fire alarm activation
    await page.evaluate(() => {
      window.simulateFireAlarm = true;
    });

    // Trigger fire alarm
    await page.click('[data-testid="simulate-fire-alarm"]');

    // Verify all doors unlock immediately
    for (const door of testDoors) {
      await helper.verifyDoorStatus(door.id, 'unlocked');
    }

    // Verify emergency unlock event is logged
    await page.click('[data-testid="audit-logs-tab"]');
    const emergencyLog = page.locator('[data-testid="audit-entry"]').first();
    await expect(emergencyLog).toContainText('Fire alarm - Emergency unlock');

    // Verify emergency notification is sent
    const notification = page.locator('[data-testid="emergency-notification"]');
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Fire alarm activated');
  });

  test('should support building-wide lockdown procedures', async ({ page }) => {
    // Test security lockdown functionality
    
    // Initiate lockdown
    await page.click('[data-testid="security-lockdown-button"]');
    await page.selectOption('[data-testid="lockdown-scope"]', 'building-1');
    await page.fill('[data-testid="lockdown-reason"]', 'Security threat detected');
    await page.click('[data-testid="confirm-lockdown"]');

    // Verify all doors in building are locked
    for (const door of testDoors.filter(d => d.buildingId === 'building-1')) {
      await helper.verifyDoorStatus(door.id, 'locked');
    }

    // Verify lockdown status indicator
    const lockdownIndicator = page.locator('[data-testid="lockdown-indicator"]');
    await expect(lockdownIndicator).toBeVisible();
    await expect(lockdownIndicator).toContainText('Building 1 - LOCKDOWN ACTIVE');

    // Test override access during lockdown
    await page.click('[data-testid="emergency-override-button"]');
    await page.fill('[data-testid="override-reason"]', 'Emergency response team');
    await page.click('[data-testid="confirm-override"]');

    // Verify override is logged
    await page.click('[data-testid="audit-logs-tab"]');
    const overrideLog = page.locator('[data-testid="audit-entry"]').first();
    await expect(overrideLog).toContainText('Lockdown override');
  });

  test('should recover from system failures gracefully', async ({ page }) => {
    // Test system recovery procedures
    
    // Simulate database connection failure
    await page.evaluate(() => {
      window.simulateDBFailure = true;
    });

    // Verify fallback to cached data
    const fallbackIndicator = page.locator('[data-testid="fallback-mode-indicator"]');
    await expect(fallbackIndicator).toBeVisible();
    await expect(fallbackIndicator).toContainText('Operating on cached data');

    // Verify access control still functions
    const doorId = testDoors[0].id;
    const response = await helper.simulateCardPresentation(doorId, 'card-123-valid');
    expect(response.status()).toBe(200);

    // Simulate recovery
    await page.evaluate(() => {
      window.simulateDBFailure = false;
    });

    await page.click('[data-testid="test-connection-button"]');

    // Verify normal operation resumes
    await expect(fallbackIndicator).not.toBeVisible();
    const normalIndicator = page.locator('[data-testid="normal-operation-indicator"]');
    await expect(normalIndicator).toBeVisible();
  });

  test('should handle device communication failures', async ({ page }) => {
    // Test hardware device failure scenarios
    
    const doorId = testDoors[0].id;

    // Simulate device offline
    await page.evaluate((id) => {
      window.simulateDeviceOffline = id;
    }, doorId);

    // Verify device status shows offline
    await helper.verifyDoorStatus(doorId, 'offline');

    // Verify offline alert is generated
    const deviceAlert = page.locator('[data-testid="device-offline-alert"]');
    await expect(deviceAlert).toBeVisible();
    await expect(deviceAlert).toContainText(testDoors[0].name);

    // Test automatic reconnection
    await page.click('[data-testid="retry-device-connection"]');

    // Simulate device coming back online
    await page.evaluate(() => {
      window.simulateDeviceOffline = null;
    });

    // Verify device status returns to normal
    await helper.verifyDoorStatus(doorId, 'locked');

    // Verify recovery is logged
    await page.click('[data-testid="audit-logs-tab"]');
    const recoveryLog = page.locator('[data-testid="audit-entry"]').first();
    await expect(recoveryLog).toContainText('Device reconnected');
  });

  test('should maintain security during power failures', async ({ page }) => {
    // Test UPS and power failure scenarios
    
    // Simulate power failure
    await page.evaluate(() => {
      window.simulatePowerFailure = true;
    });

    // Verify UPS mode activation
    const upsIndicator = page.locator('[data-testid="ups-mode-indicator"]');
    await expect(upsIndicator).toBeVisible();
    await expect(upsIndicator).toContainText('UPS Power Active');

    // Verify fail-secure behavior (doors remain locked)
    for (const door of testDoors) {
      await helper.verifyDoorStatus(door.id, 'locked');
    }

    // Test emergency power override
    await page.click('[data-testid="emergency-power-override"]');
    await page.fill('[data-testid="override-authorization"]', 'EMERGENCY-123');
    await page.click('[data-testid="confirm-power-override"]');

    // Verify critical doors can be unlocked
    const criticalDoorId = testDoors[0].id; // Main entrance
    await helper.verifyDoorStatus(criticalDoorId, 'unlocked');

    // Verify power event is logged
    await page.click('[data-testid="audit-logs-tab"]');
    const powerLog = page.locator('[data-testid="audit-entry"]').first();
    await expect(powerLog).toContainText('Power failure - UPS active');
  });
});

test.describe('Access Control - Multi-Tenant Isolation', () => {
  let helper: AccessControlTestHelper;

  test.beforeEach(async ({ page }) => {
    helper = new AccessControlTestHelper(page);
  });

  test('should enforce tenant isolation for access control', async ({ page }) => {
    // Login as tenant 1 admin
    await helper.login(testUsers[0]);
    await helper.navigateToAccessControl();

    // Verify only tenant 1 doors are visible
    const doorList = page.locator('[data-testid="door-list-item"]');
    await expect(doorList).toHaveCount(testDoors.length);

    // Logout and login as different tenant
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout"]');

    const tenant2User = { ...testUsers[0], tenantId: 'tenant-2', email: 'admin2@test.com' };
    await helper.login(tenant2User);
    await helper.navigateToAccessControl();

    // Verify no doors from tenant 1 are visible
    await expect(doorList).toHaveCount(0);

    // Verify tenant context in UI
    const tenantIndicator = page.locator('[data-testid="tenant-indicator"]');
    await expect(tenantIndicator).toContainText('tenant-2');
  });

  test('should prevent cross-tenant access attempts', async ({ page }) => {
    // Login as tenant 1 user
    await helper.login(testUsers[1]); // Employee user
    
    // Attempt to access tenant 2 door via API
    const tenant2DoorId = 'tenant2-door-1';
    const response = await page.request.post(`${TEST_CONFIG.apiURL}/api/access-control/doors/${tenant2DoorId}/access`, {
      data: { cardId: 'card-123-valid', timestamp: new Date().toISOString() }
    });

    // Should be forbidden
    expect(response.status()).toBe(403);

    // Verify error message
    const responseBody = await response.json();
    expect(responseBody.error).toContain('Access denied - invalid tenant');
  });
});

// Test cleanup and utilities
test.afterEach(async ({ page }) => {
  // Clean up test data
  await page.evaluate(() => {
    // Reset any simulation flags
    window.simulateFireAlarm = false;
    window.simulateDBFailure = false;
    window.simulateDeviceOffline = null;
    window.simulatePowerFailure = false;
    window.simulateServerConflict = false;
  });
});

test.afterAll(async () => {
  // Clean up test database
  console.log('Cleaning up test data...');
  // Implementation would clean up test users, doors, events, etc.
});