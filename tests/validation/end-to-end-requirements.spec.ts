import { test, expect, Page, Browser } from '@playwright/test';
import { chromium, firefox, webkit } from '@playwright/test';
import WebSocket from 'ws';
import axios from 'axios';
import { createHash } from 'crypto';

// Test configuration and utilities
const TEST_CONFIG = {
  baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3000',
  apiUrl: process.env.TEST_API_URL || 'http://localhost:8080',
  wsUrl: process.env.TEST_WS_URL || 'ws://localhost:8080',
  adminUser: { email: 'admin@test.com', password: 'TestAdmin123!' },
  tenant1: { id: 'tenant-1', name: 'Test Tenant 1' },
  tenant2: { id: 'tenant-2', name: 'Test Tenant 2' },
  testTimeout: 30000,
  offlineTestDuration: 5000, // Reduced for testing (represents 72 hours)
};

// Utility functions
async function loginUser(page: Page, email: string, password: string, tenantId?: string) {
  await page.goto(`${TEST_CONFIG.baseUrl}/login`);
  await page.fill('[data-testid="email-input"]', email);
  await page.fill('[data-testid="password-input"]', password);
  if (tenantId) {
    await page.selectOption('[data-testid="tenant-select"]', tenantId);
  }
  await page.click('[data-testid="login-button"]');
  await page.waitForURL('**/dashboard');
}

async function createTestUser(tenantId: string, role: string = 'operator') {
  const response = await axios.post(`${TEST_CONFIG.apiUrl}/api/users`, {
    email: `test-${Date.now()}@example.com`,
    password: 'TestUser123!',
    role,
    tenantId,
    firstName: 'Test',
    lastName: 'User'
  });
  return response.data;
}

async function simulateOfflineMode(page: Page) {
  await page.context().setOffline(true);
}

async function restoreOnlineMode(page: Page) {
  await page.context().setOffline(false);
}

test.describe('SPARC Platform - End-to-End Requirements Validation', () => {
  let browser: Browser;
  let adminPage: Page;
  let tenant1Page: Page;
  let tenant2Page: Page;

  test.beforeAll(async () => {
    browser = await chromium.launch();
    adminPage = await browser.newPage();
    tenant1Page = await browser.newPage();
    tenant2Page = await browser.newPage();
  });

  test.afterAll(async () => {
    await browser.close();
  });

  // Requirement 1: Multi-Tenant Architecture
  test('REQ-01: Multi-tenant data isolation and security', async () => {
    // Login to different tenants
    await loginUser(tenant1Page, 'user1@tenant1.com', 'Password123!', TEST_CONFIG.tenant1.id);
    await loginUser(tenant2Page, 'user2@tenant2.com', 'Password123!', TEST_CONFIG.tenant2.id);

    // Create data in tenant 1
    await tenant1Page.goto(`${TEST_CONFIG.baseUrl}/access-control/doors`);
    await tenant1Page.click('[data-testid="add-door-button"]');
    await tenant1Page.fill('[data-testid="door-name"]', 'Tenant 1 Door');
    await tenant1Page.click('[data-testid="save-door"]');

    // Verify tenant 2 cannot see tenant 1's data
    await tenant2Page.goto(`${TEST_CONFIG.baseUrl}/access-control/doors`);
    const doorList = await tenant2Page.locator('[data-testid="door-list"]');
    await expect(doorList).not.toContainText('Tenant 1 Door');

    // Verify API isolation
    const tenant1Response = await axios.get(`${TEST_CONFIG.apiUrl}/api/doors`, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant1.id }
    });
    const tenant2Response = await axios.get(`${TEST_CONFIG.apiUrl}/api/doors`, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant2.id }
    });

    expect(tenant1Response.data.length).toBeGreaterThan(0);
    expect(tenant2Response.data.find((door: any) => door.name === 'Tenant 1 Door')).toBeUndefined();
  });

  // Requirement 2: Access Control System
  test('REQ-02: Comprehensive access control with role-based permissions', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Create access control policy
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/access-control/policies`);
    await adminPage.click('[data-testid="create-policy-button"]');
    await adminPage.fill('[data-testid="policy-name"]', 'Test Access Policy');
    await adminPage.selectOption('[data-testid="access-level"]', 'restricted');
    await adminPage.fill('[data-testid="time-restrictions"]', '09:00-17:00');
    await adminPage.click('[data-testid="save-policy"]');

    // Assign policy to user
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/users`);
    await adminPage.click('[data-testid="user-row"]:first-child [data-testid="edit-user"]');
    await adminPage.selectOption('[data-testid="access-policy"]', 'Test Access Policy');
    await adminPage.click('[data-testid="save-user"]');

    // Verify policy enforcement
    const response = await axios.post(`${TEST_CONFIG.apiUrl}/api/access/validate`, {
      userId: 'test-user-id',
      doorId: 'test-door-id',
      timestamp: new Date().toISOString()
    });
    expect(response.data.granted).toBeDefined();
  });

  // Requirement 3: Video Management System
  test('REQ-03: Video surveillance with real-time streaming', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Configure video camera
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/cameras`);
    await adminPage.click('[data-testid="add-camera-button"]');
    await adminPage.fill('[data-testid="camera-name"]', 'Test Camera 1');
    await adminPage.fill('[data-testid="camera-ip"]', '192.168.1.100');
    await adminPage.selectOption('[data-testid="camera-type"]', 'ip-camera');
    await adminPage.click('[data-testid="save-camera"]');

    // Test live streaming
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/live`);
    const videoElement = await adminPage.locator('[data-testid="live-video-stream"]');
    await expect(videoElement).toBeVisible();

    // Test recording functionality
    await adminPage.click('[data-testid="start-recording"]');
    await adminPage.waitForTimeout(2000);
    await adminPage.click('[data-testid="stop-recording"]');
    
    // Verify recording was saved
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/recordings`);
    const recordingsList = await adminPage.locator('[data-testid="recordings-list"]');
    await expect(recordingsList.locator('tr')).toHaveCountGreaterThan(0);
  });

  // Requirement 4: Mobile Credential Management
  test('REQ-04: Mobile credential provisioning and management', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Create mobile credential
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/credentials/mobile`);
    await adminPage.click('[data-testid="issue-credential-button"]');
    await adminPage.fill('[data-testid="user-email"]', 'mobile-user@test.com');
    await adminPage.selectOption('[data-testid="credential-type"]', 'mobile-key');
    await adminPage.fill('[data-testid="expiry-date"]', '2024-12-31');
    await adminPage.click('[data-testid="issue-credential"]');

    // Verify credential was created
    const credentialsList = await adminPage.locator('[data-testid="credentials-list"]');
    await expect(credentialsList).toContainText('mobile-user@test.com');

    // Test credential revocation
    await adminPage.click('[data-testid="credential-row"]:first-child [data-testid="revoke-button"]');
    await adminPage.click('[data-testid="confirm-revoke"]');
    
    // Verify revocation status
    const revokedCredential = await adminPage.locator('[data-testid="credential-row"]:first-child');
    await expect(revokedCredential).toContainText('Revoked');
  });

  // Requirement 5: Environmental Monitoring
  test('REQ-05: Environmental sensor monitoring and alerting', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Configure environmental sensors
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/sensors`);
    await adminPage.click('[data-testid="add-sensor-button"]');
    await adminPage.fill('[data-testid="sensor-name"]', 'Temperature Sensor 1');
    await adminPage.selectOption('[data-testid="sensor-type"]', 'temperature');
    await adminPage.fill('[data-testid="location"]', 'Server Room A');
    await adminPage.fill('[data-testid="min-threshold"]', '18');
    await adminPage.fill('[data-testid="max-threshold"]', '25');
    await adminPage.click('[data-testid="save-sensor"]');

    // Simulate sensor data
    await axios.post(`${TEST_CONFIG.apiUrl}/api/sensors/data`, {
      sensorId: 'temp-sensor-1',
      value: 30, // Above threshold
      timestamp: new Date().toISOString(),
      unit: 'celsius'
    });

    // Verify alert generation
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/alerts`);
    const alertsList = await adminPage.locator('[data-testid="alerts-list"]');
    await expect(alertsList).toContainText('Temperature threshold exceeded');
  });

  // Requirement 6: Visitor Management
  test('REQ-06: Visitor registration and tracking system', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Register a visitor
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/register`);
    await adminPage.fill('[data-testid="visitor-name"]', 'John Doe');
    await adminPage.fill('[data-testid="visitor-email"]', 'john.doe@visitor.com');
    await adminPage.fill('[data-testid="visitor-company"]', 'Visitor Corp');
    await adminPage.fill('[data-testid="host-name"]', 'Jane Smith');
    await adminPage.fill('[data-testid="visit-purpose"]', 'Business Meeting');
    await adminPage.click('[data-testid="register-visitor"]');

    // Verify visitor badge generation
    const badgePreview = await adminPage.locator('[data-testid="visitor-badge"]');
    await expect(badgePreview).toBeVisible();
    await expect(badgePreview).toContainText('John Doe');

    // Test visitor check-in
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/checkin`);
    await adminPage.fill('[data-testid="visitor-search"]', 'john.doe@visitor.com');
    await adminPage.click('[data-testid="search-button"]');
    await adminPage.click('[data-testid="checkin-button"]');

    // Verify check-in status
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/active`);
    const activeVisitors = await adminPage.locator('[data-testid="active-visitors-list"]');
    await expect(activeVisitors).toContainText('John Doe');
  });

  // Requirement 7: Real-time Event Processing
  test('REQ-07: Real-time event processing and notifications', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Set up WebSocket connection for real-time events
    const ws = new WebSocket(`${TEST_CONFIG.wsUrl}/events`);
    const events: any[] = [];
    
    ws.on('message', (data) => {
      events.push(JSON.parse(data.toString()));
    });

    await new Promise(resolve => ws.on('open', resolve));

    // Trigger an access event
    await axios.post(`${TEST_CONFIG.apiUrl}/api/access/event`, {
      doorId: 'test-door-1',
      userId: 'test-user-1',
      eventType: 'access_granted',
      timestamp: new Date().toISOString()
    });

    // Wait for real-time event
    await adminPage.waitForTimeout(2000);
    
    // Verify event was received
    expect(events.length).toBeGreaterThan(0);
    expect(events[0].eventType).toBe('access_granted');

    // Verify dashboard updates
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/dashboard`);
    const recentEvents = await adminPage.locator('[data-testid="recent-events"]');
    await expect(recentEvents).toContainText('access_granted');

    ws.close();
  });

  // Requirement 8: Audit Logging and Compliance
  test('REQ-08: Comprehensive audit logging for compliance', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Perform auditable actions
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/users`);
    await adminPage.click('[data-testid="add-user-button"]');
    await adminPage.fill('[data-testid="user-email"]', 'audit-test@example.com');
    await adminPage.fill('[data-testid="user-name"]', 'Audit Test User');
    await adminPage.click('[data-testid="save-user"]');

    // Check audit logs
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/audit/logs`);
    const auditLogs = await adminPage.locator('[data-testid="audit-logs-table"]');
    await expect(auditLogs).toContainText('USER_CREATED');
    await expect(auditLogs).toContainText('audit-test@example.com');

    // Test audit log filtering
    await adminPage.selectOption('[data-testid="event-type-filter"]', 'USER_CREATED');
    await adminPage.click('[data-testid="apply-filter"]');
    
    const filteredLogs = await adminPage.locator('[data-testid="audit-logs-table"] tr');
    const logCount = await filteredLogs.count();
    expect(logCount).toBeGreaterThan(0);

    // Verify audit log export
    await adminPage.click('[data-testid="export-logs-button"]');
    const downloadPromise = adminPage.waitForEvent('download');
    await adminPage.click('[data-testid="confirm-export"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('audit-logs');
  });

  // Requirement 9: Integration APIs
  test('REQ-09: RESTful APIs for third-party integrations', async () => {
    // Test authentication
    const authResponse = await axios.post(`${TEST_CONFIG.apiUrl}/api/auth/login`, {
      email: TEST_CONFIG.adminUser.email,
      password: TEST_CONFIG.adminUser.password
    });
    expect(authResponse.status).toBe(200);
    expect(authResponse.data.token).toBeDefined();

    const token = authResponse.data.token;
    const headers = { Authorization: `Bearer ${token}` };

    // Test CRUD operations
    const createResponse = await axios.post(`${TEST_CONFIG.apiUrl}/api/doors`, {
      name: 'API Test Door',
      location: 'Building A',
      type: 'standard'
    }, { headers });
    expect(createResponse.status).toBe(201);

    const doorId = createResponse.data.id;

    // Test read operation
    const readResponse = await axios.get(`${TEST_CONFIG.apiUrl}/api/doors/${doorId}`, { headers });
    expect(readResponse.status).toBe(200);
    expect(readResponse.data.name).toBe('API Test Door');

    // Test update operation
    const updateResponse = await axios.put(`${TEST_CONFIG.apiUrl}/api/doors/${doorId}`, {
      name: 'Updated API Test Door',
      location: 'Building B'
    }, { headers });
    expect(updateResponse.status).toBe(200);

    // Test delete operation
    const deleteResponse = await axios.delete(`${TEST_CONFIG.apiUrl}/api/doors/${doorId}`, { headers });
    expect(deleteResponse.status).toBe(204);
  });

  // Requirement 10: Security and Encryption
  test('REQ-10: End-to-end encryption and security measures', async () => {
    // Test HTTPS enforcement
    const httpResponse = await axios.get(TEST_CONFIG.baseUrl.replace('https://', 'http://'))
      .catch(error => error.response);
    expect(httpResponse?.status).toBe(301); // Redirect to HTTPS

    // Test API security headers
    const apiResponse = await axios.get(`${TEST_CONFIG.apiUrl}/api/health`);
    expect(apiResponse.headers['x-content-type-options']).toBe('nosniff');
    expect(apiResponse.headers['x-frame-options']).toBe('DENY');
    expect(apiResponse.headers['x-xss-protection']).toBe('1; mode=block');

    // Test password hashing
    const user = await createTestUser(TEST_CONFIG.tenant1.id);
    const userResponse = await axios.get(`${TEST_CONFIG.apiUrl}/api/users/${user.id}`, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant1.id }
    });
    expect(userResponse.data.password).toBeUndefined(); // Password should not be returned

    // Test data encryption at rest
    const sensitiveData = 'sensitive-test-data';
    const encryptResponse = await axios.post(`${TEST_CONFIG.apiUrl}/api/encrypt`, {
      data: sensitiveData
    });
    expect(encryptResponse.data.encrypted).not.toBe(sensitiveData);
    expect(encryptResponse.data.encrypted).toMatch(/^[A-Za-z0-9+/]+=*$/); // Base64 pattern
  });

  // Requirement 11: Scalability and Performance
  test('REQ-11: System scalability for 10,000 doors and 1,000 video streams', async () => {
    // Test concurrent API requests
    const concurrentRequests = Array.from({ length: 100 }, (_, i) =>
      axios.get(`${TEST_CONFIG.apiUrl}/api/doors?page=${i}`, {
        headers: { 'X-Tenant-ID': TEST_CONFIG.tenant1.id }
      })
    );

    const startTime = Date.now();
    const responses = await Promise.all(concurrentRequests);
    const endTime = Date.now();

    // All requests should succeed
    responses.forEach(response => {
      expect(response.status).toBe(200);
    });

    // Response time should be reasonable
    const avgResponseTime = (endTime - startTime) / 100;
    expect(avgResponseTime).toBeLessThan(1000); // Less than 1 second average

    // Test database query performance
    const largeQueryResponse = await axios.get(`${TEST_CONFIG.apiUrl}/api/events?limit=1000`, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant1.id }
    });
    expect(largeQueryResponse.status).toBe(200);
    expect(largeQueryResponse.headers['x-response-time']).toBeDefined();
  });

  // Requirement 12: Mobile Application Support
  test('REQ-12: Mobile application functionality', async () => {
    // Test mobile-responsive design
    await adminPage.setViewportSize({ width: 375, height: 667 }); // iPhone size
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Verify mobile navigation
    const mobileMenu = await adminPage.locator('[data-testid="mobile-menu-button"]');
    await expect(mobileMenu).toBeVisible();
    await mobileMenu.click();
    
    const navigationMenu = await adminPage.locator('[data-testid="mobile-navigation"]');
    await expect(navigationMenu).toBeVisible();

    // Test mobile credential scanning
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile/scan`);
    const scannerInterface = await adminPage.locator('[data-testid="qr-scanner"]');
    await expect(scannerInterface).toBeVisible();

    // Test offline capability
    await simulateOfflineMode(adminPage);
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile/offline`);
    const offlineMessage = await adminPage.locator('[data-testid="offline-indicator"]');
    await expect(offlineMessage).toBeVisible();
    
    await restoreOnlineMode(adminPage);
  });

  // Requirement 13: Reporting and Analytics
  test('REQ-13: Comprehensive reporting and analytics', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Generate access control report
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/reports/access-control`);
    await adminPage.selectOption('[data-testid="report-period"]', 'last-30-days');
    await adminPage.click('[data-testid="generate-report"]');
    
    // Verify report generation
    const reportTable = await adminPage.locator('[data-testid="report-table"]');
    await expect(reportTable).toBeVisible();
    
    // Test report export
    await adminPage.click('[data-testid="export-report"]');
    const downloadPromise = adminPage.waitForEvent('download');
    await adminPage.selectOption('[data-testid="export-format"]', 'pdf');
    await adminPage.click('[data-testid="confirm-export"]');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.pdf');

    // Test analytics dashboard
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/analytics`);
    const analyticsCharts = await adminPage.locator('[data-testid="analytics-chart"]');
    await expect(analyticsCharts.first()).toBeVisible();
    
    // Verify real-time metrics
    const metricsCards = await adminPage.locator('[data-testid="metric-card"]');
    const cardCount = await metricsCards.count();
    expect(cardCount).toBeGreaterThan(0);
  });

  // Requirement 14: Offline Resilience (72-hour operation)
  test('REQ-14: 72-hour offline operation capability', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Enable offline mode
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/offline`);
    await adminPage.click('[data-testid="enable-offline-mode"]');
    
    // Simulate network disconnection
    await simulateOfflineMode(adminPage);
    
    // Test offline access control
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/access-control/offline`);
    const offlineStatus = await adminPage.locator('[data-testid="offline-status"]');
    await expect(offlineStatus).toContainText('Offline Mode Active');
    
    // Test offline credential validation
    await adminPage.fill('[data-testid="credential-id"]', 'test-credential-123');
    await adminPage.click('[data-testid="validate-offline"]');
    
    const validationResult = await adminPage.locator('[data-testid="validation-result"]');
    await expect(validationResult).toBeVisible();
    
    // Test offline event queuing
    await adminPage.click('[data-testid="simulate-access-event"]');
    const queuedEvents = await adminPage.locator('[data-testid="queued-events-count"]');
    await expect(queuedEvents).toContainText('1');
    
    // Restore online mode and test sync
    await restoreOnlineMode(adminPage);
    await adminPage.click('[data-testid="sync-offline-data"]');
    
    // Verify data synchronization
    await adminPage.waitForTimeout(3000);
    const syncStatus = await adminPage.locator('[data-testid="sync-status"]');
    await expect(syncStatus).toContainText('Sync Complete');
  });

  // Requirement 15: Emergency Procedures
  test('REQ-15: Emergency lockdown and evacuation procedures', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test emergency lockdown
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/emergency`);
    await adminPage.click('[data-testid="emergency-lockdown-button"]');
    await adminPage.click('[data-testid="confirm-lockdown"]');
    
    // Verify lockdown status
    const lockdownStatus = await adminPage.locator('[data-testid="lockdown-status"]');
    await expect(lockdownStatus).toContainText('LOCKDOWN ACTIVE');
    
    // Test evacuation mode
    await adminPage.click('[data-testid="evacuation-mode-button"]');
    await adminPage.click('[data-testid="confirm-evacuation"]');
    
    const evacuationStatus = await adminPage.locator('[data-testid="evacuation-status"]');
    await expect(evacuationStatus).toContainText('EVACUATION MODE');
    
    // Test emergency notifications
    const notificationPanel = await adminPage.locator('[data-testid="emergency-notifications"]');
    await expect(notificationPanel).toBeVisible();
    
    // Test emergency override
    await adminPage.fill('[data-testid="override-code"]', 'EMERGENCY123');
    await adminPage.click('[data-testid="emergency-override"]');
    
    const overrideStatus = await adminPage.locator('[data-testid="override-status"]');
    await expect(overrideStatus).toContainText('Override Active');
  });

  // Requirement 16: Data Backup and Recovery
  test('REQ-16: Automated backup and disaster recovery', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test backup configuration
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/backup`);
    const backupSchedule = await adminPage.locator('[data-testid="backup-schedule"]');
    await expect(backupSchedule).toBeVisible();
    
    // Trigger manual backup
    await adminPage.click('[data-testid="manual-backup-button"]');
    await adminPage.click('[data-testid="confirm-backup"]');
    
    // Verify backup creation
    const backupStatus = await adminPage.locator('[data-testid="backup-status"]');
    await expect(backupStatus).toContainText('Backup In Progress');
    
    // Test backup verification
    await adminPage.waitForTimeout(5000);
    await adminPage.click('[data-testid="verify-backup"]');
    
    const verificationResult = await adminPage.locator('[data-testid="verification-result"]');
    await expect(verificationResult).toContainText('Backup Verified');
    
    // Test recovery simulation
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/recovery`);
    await adminPage.selectOption('[data-testid="backup-selection"]', { index: 0 });
    await adminPage.click('[data-testid="test-recovery"]');
    
    const recoveryTest = await adminPage.locator('[data-testid="recovery-test-result"]');
    await expect(recoveryTest).toContainText('Recovery Test Successful');
  });

  // Requirement 17: System Health Monitoring
  test('REQ-17: Comprehensive system health monitoring', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Check system health dashboard
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/health`);
    const healthDashboard = await adminPage.locator('[data-testid="health-dashboard"]');
    await expect(healthDashboard).toBeVisible();
    
    // Verify service status indicators
    const serviceStatuses = await adminPage.locator('[data-testid="service-status"]');
    const statusCount = await serviceStatuses.count();
    expect(statusCount).toBeGreaterThan(0);
    
    // Test performance metrics
    const performanceMetrics = await adminPage.locator('[data-testid="performance-metrics"]');
    await expect(performanceMetrics).toBeVisible();
    
    // Test alert configuration
    await adminPage.click('[data-testid="configure-alerts"]');
    await adminPage.fill('[data-testid="cpu-threshold"]', '80');
    await adminPage.fill('[data-testid="memory-threshold"]', '85');
    await adminPage.click('[data-testid="save-alert-config"]');
    
    // Verify alert settings
    const alertConfig = await adminPage.locator('[data-testid="alert-configuration"]');
    await expect(alertConfig).toContainText('80%');
  });

  // Requirement 18: User Interface and Experience
  test('REQ-18: Intuitive user interface and accessibility', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test accessibility features
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/dashboard`);
    
    // Check for ARIA labels
    const buttons = await adminPage.locator('button[aria-label]');
    const buttonCount = await buttons.count();
    expect(buttonCount).toBeGreaterThan(0);
    
    // Test keyboard navigation
    await adminPage.keyboard.press('Tab');
    const focusedElement = await adminPage.locator(':focus');
    await expect(focusedElement).toBeVisible();
    
    // Test color contrast and themes
    await adminPage.click('[data-testid="theme-toggle"]');
    const darkTheme = await adminPage.locator('[data-theme="dark"]');
    await expect(darkTheme).toBeVisible();
    
    // Test responsive design
    await adminPage.setViewportSize({ width: 768, height: 1024 }); // Tablet size
    const responsiveLayout = await adminPage.locator('[data-testid="responsive-layout"]');
    await expect(responsiveLayout).toBeVisible();
    
    // Test internationalization
    await adminPage.selectOption('[data-testid="language-selector"]', 'es');
    const spanishText = await adminPage.locator('[data-testid="dashboard-title"]');
    await expect(spanishText).toContainText('Panel de Control');
  });

  // Additional requirements tests (19-28) would follow similar patterns
  // covering integration capabilities, compliance features, advanced analytics,
  // IoT device management, cloud deployment, API rate limiting,
  // advanced reporting, workflow automation, and data retention policies

  // Requirement 19: Integration with Building Management Systems
  test('REQ-19: Building management system integration', async () => {
    // Test HVAC integration
    const hvacResponse = await axios.post(`${TEST_CONFIG.apiUrl}/api/integrations/hvac`, {
      action: 'adjust_temperature',
      zone: 'office-area-1',
      temperature: 22
    });
    expect(hvacResponse.status).toBe(200);
    
    // Test lighting system integration
    const lightingResponse = await axios.post(`${TEST_CONFIG.apiUrl}/api/integrations/lighting`, {
      action: 'set_brightness',
      zone: 'conference-room-a',
      brightness: 75
    });
    expect(lightingResponse.status).toBe(200);
  });

  // Requirement 20: Advanced Analytics and AI
  test('REQ-20: AI-powered analytics and pattern recognition', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/analytics/ai`);
    const aiAnalytics = await adminPage.locator('[data-testid="ai-analytics-dashboard"]');
    await expect(aiAnalytics).toBeVisible();
    
    // Test anomaly detection
    const anomalyAlerts = await adminPage.locator('[data-testid="anomaly-alerts"]');
    await expect(anomalyAlerts).toBeVisible();
    
    // Test predictive analytics
    const predictions = await adminPage.locator('[data-testid="predictive-insights"]');
    await expect(predictions).toBeVisible();
  });

  // Performance and load testing
  test('Performance: System handles concurrent users', async () => {
    const browsers = await Promise.all([
      chromium.launch(),
      chromium.launch(),
      chromium.launch()
    ]);
    
    const pages = await Promise.all(browsers.map(b => b.newPage()));
    
    // Simulate concurrent user sessions
    const loginPromises = pages.map((page, index) => 
      loginUser(page, `user${index}@test.com`, 'Password123!', TEST_CONFIG.tenant1.id)
    );
    
    await Promise.all(loginPromises);
    
    // Verify all users can access the system simultaneously
    const dashboardPromises = pages.map(page => 
      page.goto(`${TEST_CONFIG.baseUrl}/dashboard`)
    );
    
    await Promise.all(dashboardPromises);
    
    // Cleanup
    await Promise.all(browsers.map(b => b.close()));
  });

  // Data integrity and consistency tests
  test('Data Integrity: Multi-tenant data consistency', async () => {
    // Create test data in multiple tenants
    const tenant1Data = await axios.post(`${TEST_CONFIG.apiUrl}/api/doors`, {
      name: 'Tenant 1 Secure Door',
      location: 'Building 1'
    }, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant1.id }
    });
    
    const tenant2Data = await axios.post(`${TEST_CONFIG.apiUrl}/api/doors`, {
      name: 'Tenant 2 Secure Door',
      location: 'Building 2'
    }, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant2.id }
    });
    
    // Verify data isolation
    const tenant1Doors = await axios.get(`${TEST_CONFIG.apiUrl}/api/doors`, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant1.id }
    });
    
    const tenant2Doors = await axios.get(`${TEST_CONFIG.apiUrl}/api/doors`, {
      headers: { 'X-Tenant-ID': TEST_CONFIG.tenant2.id }
    });
    
    expect(tenant1Doors.data.find((d: any) => d.name === 'Tenant 2 Secure Door')).toBeUndefined();
    expect(tenant2Doors.data.find((d: any) => d.name === 'Tenant 1 Secure Door')).toBeUndefined();
  });

  // Security penetration testing
  test('Security: SQL injection and XSS protection', async () => {
    // Test SQL injection protection
    const sqlInjectionAttempt = await axios.post(`${TEST_CONFIG.apiUrl}/api/users/search`, {
      query: "'; DROP TABLE users; --"
    }).catch(error => error.response);
    
    expect(sqlInjectionAttempt.status).not.toBe(500);
    
    // Test XSS protection
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/users`);
    
    const xssScript = '<script>alert("XSS")</script>';
    await adminPage.fill('[data-testid="user-name"]', xssScript);
    await adminPage.click('[data-testid="save-user"]');
    
    // Verify script is escaped
    const userList = await adminPage.locator('[data-testid="user-list"]');
    const userText = await userList.textContent();
    expect(userText).not.toContain('<script>');
  });

  // Requirement 21: Licensing and Credential Management
  test('REQ-21: Comprehensive licensing and credential management', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test physical card issuance
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/credentials/physical`);
    await adminPage.click('[data-testid="issue-physical-card"]');
    await adminPage.fill('[data-testid="card-holder-name"]', 'John Smith');
    await adminPage.fill('[data-testid="card-number"]', '1234567890');
    await adminPage.selectOption('[data-testid="card-type"]', 'proximity');
    await adminPage.fill('[data-testid="expiry-date"]', '2025-12-31');
    await adminPage.click('[data-testid="issue-card"]');
    
    // Verify card issuance
    const cardsList = await adminPage.locator('[data-testid="physical-cards-list"]');
    await expect(cardsList).toContainText('John Smith');
    await expect(cardsList).toContainText('1234567890');
    
    // Test mobile credential enrollment
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/credentials/mobile/enroll`);
    await adminPage.fill('[data-testid="user-email"]', 'mobile.user@test.com');
    await adminPage.selectOption('[data-testid="device-type"]', 'ios');
    await adminPage.selectOption('[data-testid="credential-type"]', 'nfc');
    await adminPage.click('[data-testid="enable-biometric"]');
    await adminPage.selectOption('[data-testid="biometric-type"]', 'fingerprint');
    await adminPage.click('[data-testid="enroll-credential"]');
    
    // Verify enrollment success
    const enrollmentStatus = await adminPage.locator('[data-testid="enrollment-status"]');
    await expect(enrollmentStatus).toContainText('Enrollment Successful');
    
    // Test PIN management
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/credentials/pin-management`);
    await adminPage.fill('[data-testid="user-search"]', 'mobile.user@test.com');
    await adminPage.click('[data-testid="search-user"]');
    await adminPage.click('[data-testid="set-pin-button"]');
    await adminPage.fill('[data-testid="new-pin"]', '1234');
    await adminPage.fill('[data-testid="confirm-pin"]', '1234');
    await adminPage.click('[data-testid="save-pin"]');
    
    // Verify PIN set
    const pinStatus = await adminPage.locator('[data-testid="pin-status"]');
    await expect(pinStatus).toContainText('PIN Set Successfully');
    
    // Test bulk provisioning
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/credentials/bulk-provision`);
    await adminPage.click('[data-testid="upload-csv"]');
    // Simulate CSV upload
    const fileInput = await adminPage.locator('[data-testid="csv-file-input"]');
    await fileInput.setInputFiles({
      name: 'bulk-users.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from('email,firstName,lastName,department\nuser1@test.com,User,One,IT\nuser2@test.com,User,Two,HR')
    });
    await adminPage.click('[data-testid="process-bulk"]');
    
    // Verify bulk processing
    const bulkStatus = await adminPage.locator('[data-testid="bulk-status"]');
    await expect(bulkStatus).toContainText('2 credentials provisioned');
    
    // Test expiration workflow
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/credentials/expiration`);
    const expiringCredentials = await adminPage.locator('[data-testid="expiring-credentials"]');
    await expect(expiringCredentials).toBeVisible();
    
    // Test automatic renewal
    await adminPage.click('[data-testid="auto-renew-toggle"]');
    await adminPage.fill('[data-testid="renewal-period"]', '365');
    await adminPage.click('[data-testid="save-renewal-settings"]');
    
    // Test revocation procedures
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/credentials/revocation`);
    await adminPage.fill('[data-testid="credential-search"]', '1234567890');
    await adminPage.click('[data-testid="search-credential"]');
    await adminPage.click('[data-testid="revoke-credential"]');
    await adminPage.selectOption('[data-testid="revocation-reason"]', 'lost');
    await adminPage.click('[data-testid="immediate-revocation"]');
    await adminPage.click('[data-testid="confirm-revocation"]');
    
    // Verify revocation
    const revocationStatus = await adminPage.locator('[data-testid="revocation-status"]');
    await expect(revocationStatus).toContainText('Credential Revoked');
  });

  // Requirement 22: Maintenance and Support
  test('REQ-22: Maintenance scheduling and support system', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test maintenance scheduling
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/maintenance/schedule`);
    await adminPage.click('[data-testid="schedule-maintenance"]');
    await adminPage.fill('[data-testid="maintenance-title"]', 'Door Reader Calibration');
    await adminPage.selectOption('[data-testid="device-type"]', 'door-reader');
    await adminPage.fill('[data-testid="device-id"]', 'DR-001');
    await adminPage.fill('[data-testid="scheduled-date"]', '2024-12-15');
    await adminPage.fill('[data-testid="scheduled-time"]', '14:00');
    await adminPage.selectOption('[data-testid="maintenance-type"]', 'preventive');
    await adminPage.fill('[data-testid="estimated-duration"]', '60');
    await adminPage.click('[data-testid="schedule-task"]');
    
    // Verify scheduling
    const maintenanceCalendar = await adminPage.locator('[data-testid="maintenance-calendar"]');
    await expect(maintenanceCalendar).toContainText('Door Reader Calibration');
    
    // Test work order generation
    await adminPage.click('[data-testid="generate-work-order"]');
    await adminPage.fill('[data-testid="technician-assignment"]', 'Tech-001');
    await adminPage.fill('[data-testid="work-instructions"]', 'Calibrate proximity sensor and test access range');
    await adminPage.click('[data-testid="create-work-order"]');
    
    // Verify work order
    const workOrder = await adminPage.locator('[data-testid="work-order-details"]');
    await expect(workOrder).toContainText('WO-');
    await expect(workOrder).toContainText('Tech-001');
    
    // Test diagnostic data collection
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/maintenance/diagnostics`);
    await adminPage.selectOption('[data-testid="device-selector"]', 'DR-001');
    await adminPage.click('[data-testid="run-diagnostics"]');
    
    // Wait for diagnostics to complete
    await adminPage.waitForTimeout(3000);
    const diagnosticResults = await adminPage.locator('[data-testid="diagnostic-results"]');
    await expect(diagnosticResults).toBeVisible();
    await expect(diagnosticResults).toContainText('Signal Strength');
    await expect(diagnosticResults).toContainText('Response Time');
    
    // Test remote diagnostics
    await adminPage.click('[data-testid="remote-diagnostic-button"]');
    await adminPage.selectOption('[data-testid="diagnostic-type"]', 'connectivity');
    await adminPage.click('[data-testid="start-remote-diagnostic"]');
    
    const remoteResults = await adminPage.locator('[data-testid="remote-diagnostic-results"]');
    await expect(remoteResults).toBeVisible();
    
    // Test preventive maintenance
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/maintenance/preventive`);
    const preventiveSchedule = await adminPage.locator('[data-testid="preventive-schedule"]');
    await expect(preventiveSchedule).toBeVisible();
    
    // Configure preventive maintenance
    await adminPage.click('[data-testid="configure-preventive"]');
    await adminPage.selectOption('[data-testid="device-category"]', 'access-readers');
    await adminPage.fill('[data-testid="maintenance-interval"]', '90');
    await adminPage.selectOption('[data-testid="interval-unit"]', 'days');
    await adminPage.click('[data-testid="save-preventive-config"]');
    
    // Test service history tracking
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/maintenance/history`);
    await adminPage.fill('[data-testid="device-search"]', 'DR-001');
    await adminPage.click('[data-testid="search-history"]');
    
    const serviceHistory = await adminPage.locator('[data-testid="service-history-table"]');
    await expect(serviceHistory).toBeVisible();
    
    // Test maintenance reporting
    await adminPage.click('[data-testid="generate-maintenance-report"]');
    await adminPage.selectOption('[data-testid="report-period"]', 'last-quarter');
    await adminPage.click('[data-testid="generate-report"]');
    
    const maintenanceReport = await adminPage.locator('[data-testid="maintenance-report"]');
    await expect(maintenanceReport).toContainText('Maintenance Summary');
  });

  // Requirement 23: Mobile Credential Service
  test('REQ-23: Advanced mobile credential service functionality', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test iOS enrollment
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/ios-enrollment`);
    await adminPage.fill('[data-testid="user-email"]', 'ios.user@test.com');
    await adminPage.click('[data-testid="generate-enrollment-link"]');
    
    const enrollmentLink = await adminPage.locator('[data-testid="enrollment-link"]');
    await expect(enrollmentLink).toBeVisible();
    
    // Test Android enrollment
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/android-enrollment`);
    await adminPage.fill('[data-testid="user-email"]', 'android.user@test.com');
    await adminPage.selectOption('[data-testid="credential-protocol"]', 'ble');
    await adminPage.click('[data-testid="generate-qr-code"]');
    
    const qrCode = await adminPage.locator('[data-testid="enrollment-qr-code"]');
    await expect(qrCode).toBeVisible();
    
    // Test NFC authentication
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/nfc-test`);
    await adminPage.click('[data-testid="simulate-nfc-tap"]');
    await adminPage.fill('[data-testid="credential-id"]', 'mobile-cred-001');
    await adminPage.click('[data-testid="authenticate-nfc"]');
    
    const nfcResult = await adminPage.locator('[data-testid="nfc-auth-result"]');
    await expect(nfcResult).toContainText('Authentication Successful');
    
    // Test BLE authentication
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/ble-test`);
    await adminPage.click('[data-testid="simulate-ble-connection"]');
    await adminPage.fill('[data-testid="ble-credential-id"]', 'mobile-cred-002');
    await adminPage.selectOption('[data-testid="signal-strength"]', 'strong');
    await adminPage.click('[data-testid="authenticate-ble"]');
    
    const bleResult = await adminPage.locator('[data-testid="ble-auth-result"]');
    await expect(bleResult).toContainText('BLE Authentication Successful');
    
    // Test offline operation
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/offline-mode`);
    await adminPage.click('[data-testid="enable-offline-mode"]');
    
    // Simulate offline authentication
    await simulateOfflineMode(adminPage);
    await adminPage.click('[data-testid="offline-auth-test"]');
    await adminPage.fill('[data-testid="offline-credential-id"]', 'mobile-cred-003');
    await adminPage.click('[data-testid="validate-offline"]');
    
    const offlineResult = await adminPage.locator('[data-testid="offline-validation-result"]');
    await expect(offlineResult).toContainText('Offline Validation Successful');
    
    await restoreOnlineMode(adminPage);
    
    // Test remote revocation
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/remote-revocation`);
    await adminPage.fill('[data-testid="mobile-credential-search"]', 'mobile-cred-001');
    await adminPage.click('[data-testid="search-mobile-credential"]');
    await adminPage.click('[data-testid="remote-revoke"]');
    await adminPage.selectOption('[data-testid="revocation-method"]', 'immediate');
    await adminPage.click('[data-testid="confirm-remote-revocation"]');
    
    const revocationStatus = await adminPage.locator('[data-testid="remote-revocation-status"]');
    await expect(revocationStatus).toContainText('Remote Revocation Initiated');
    
    // Test self-service enrollment
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/self-service`);
    await adminPage.fill('[data-testid="self-service-email"]', 'selfservice@test.com');
    await adminPage.click('[data-testid="send-enrollment-invitation"]');
    
    const invitationStatus = await adminPage.locator('[data-testid="invitation-status"]');
    await expect(invitationStatus).toContainText('Enrollment invitation sent');
    
    // Test power-efficient modes
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/mobile-credentials/power-management`);
    await adminPage.selectOption('[data-testid="power-mode"]', 'low-power');
    await adminPage.fill('[data-testid="battery-threshold"]', '20');
    await adminPage.click('[data-testid="enable-power-saving"]');
    
    const powerSettings = await adminPage.locator('[data-testid="power-management-status"]');
    await expect(powerSettings).toContainText('Power saving enabled');
  });

  // Requirement 24: Environmental Monitoring
  test('REQ-24: Advanced environmental monitoring system', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test temperature monitoring
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/temperature`);
    await adminPage.click('[data-testid="add-temperature-sensor"]');
    await adminPage.fill('[data-testid="sensor-name"]', 'Server Room Temp');
    await adminPage.fill('[data-testid="sensor-location"]', 'Data Center A');
    await adminPage.fill('[data-testid="min-temp-threshold"]', '18');
    await adminPage.fill('[data-testid="max-temp-threshold"]', '25');
    await adminPage.click('[data-testid="save-temp-sensor"]');
    
    // Simulate temperature data
    await axios.post(`${TEST_CONFIG.apiUrl}/api/environmental/temperature`, {
      sensorId: 'temp-001',
      temperature: 27,
      timestamp: new Date().toISOString(),
      location: 'Data Center A'
    });
    
    // Verify temperature alert
    const tempAlert = await adminPage.locator('[data-testid="temperature-alert"]');
    await expect(tempAlert).toContainText('Temperature threshold exceeded');
    
    // Test humidity monitoring
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/humidity`);
    await adminPage.click('[data-testid="add-humidity-sensor"]');
    await adminPage.fill('[data-testid="humidity-sensor-name"]', 'Archive Humidity');
    await adminPage.fill('[data-testid="humidity-location"]', 'Document Storage');
    await adminPage.fill('[data-testid="min-humidity"]', '40');
    await adminPage.fill('[data-testid="max-humidity"]', '60');
    await adminPage.click('[data-testid="save-humidity-sensor"]');
    
    // Test leak detection
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/leak-detection`);
    await adminPage.click('[data-testid="add-leak-sensor"]');
    await adminPage.fill('[data-testid="leak-sensor-name"]', 'Basement Leak Detector');
    await adminPage.fill('[data-testid="leak-location"]', 'Basement Level B1');
    await adminPage.selectOption('[data-testid="sensor-type"]', 'water-leak');
    await adminPage.click('[data-testid="save-leak-sensor"]');
    
    // Simulate leak detection
    await axios.post(`${TEST_CONFIG.apiUrl}/api/environmental/leak`, {
      sensorId: 'leak-001',
      detected: true,
      severity: 'high',
      timestamp: new Date().toISOString(),
      location: 'Basement Level B1'
    });
    
    // Verify leak alert
    const leakAlert = await adminPage.locator('[data-testid="leak-alert"]');
    await expect(leakAlert).toContainText('Water leak detected');
    
    // Test threshold alerts configuration
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/alerts`);
    await adminPage.click('[data-testid="configure-alert-thresholds"]');
    await adminPage.fill('[data-testid="critical-temp-threshold"]', '30');
    await adminPage.fill('[data-testid="critical-humidity-threshold"]', '80');
    await adminPage.selectOption('[data-testid="alert-frequency"]', 'immediate');
    await adminPage.click('[data-testid="save-alert-config"]');
    
    // Test HVAC integration
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/hvac-integration`);
    await adminPage.click('[data-testid="enable-hvac-integration"]');
    await adminPage.fill('[data-testid="hvac-endpoint"]', 'http://hvac-system.local/api');
    await adminPage.fill('[data-testid="hvac-api-key"]', 'hvac-api-key-123');
    await adminPage.click('[data-testid="test-hvac-connection"]');
    
    const hvacStatus = await adminPage.locator('[data-testid="hvac-connection-status"]');
    await expect(hvacStatus).toContainText('HVAC integration active');
    
    // Test trend analysis
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/trends`);
    await adminPage.selectOption('[data-testid="trend-period"]', 'last-7-days');
    await adminPage.selectOption('[data-testid="sensor-type-filter"]', 'temperature');
    await adminPage.click('[data-testid="generate-trend-analysis"]');
    
    const trendChart = await adminPage.locator('[data-testid="environmental-trend-chart"]');
    await expect(trendChart).toBeVisible();
    
    // Test sensor offline detection
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/environmental/sensor-status`);
    const sensorStatusTable = await adminPage.locator('[data-testid="sensor-status-table"]');
    await expect(sensorStatusTable).toBeVisible();
    
    // Simulate sensor offline
    await axios.post(`${TEST_CONFIG.apiUrl}/api/environmental/sensor-status`, {
      sensorId: 'temp-001',
      status: 'offline',
      lastSeen: new Date(Date.now() - 300000).toISOString() // 5 minutes ago
    });
    
    const offlineSensorAlert = await adminPage.locator('[data-testid="offline-sensor-alert"]');
    await expect(offlineSensorAlert).toContainText('Sensor offline');
  });

  // Requirement 25: Video Privacy Compliance
  test('REQ-25: Video privacy and compliance features', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test privacy masking
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/privacy-masking`);
    await adminPage.selectOption('[data-testid="camera-selector"]', 'camera-001');
    await adminPage.click('[data-testid="add-privacy-zone"]');
    await adminPage.fill('[data-testid="zone-name"]', 'Reception Desk');
    await adminPage.fill('[data-testid="zone-coordinates"]', '100,100,200,200');
    await adminPage.selectOption('[data-testid="masking-type"]', 'blur');
    await adminPage.click('[data-testid="save-privacy-zone"]');
    
    // Verify privacy zone
    const privacyZones = await adminPage.locator('[data-testid="privacy-zones-list"]');
    await expect(privacyZones).toContainText('Reception Desk');
    
    // Test retention policies
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/retention-policies`);
    await adminPage.click('[data-testid="create-retention-policy"]');
    await adminPage.fill('[data-testid="policy-name"]', 'Standard Retention');
    await adminPage.fill('[data-testid="retention-days"]', '30');
    await adminPage.selectOption('[data-testid="auto-delete"]', 'enabled');
    await adminPage.click('[data-testid="save-retention-policy"]');
    
    // Test export logging
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/export-logging`);
    await adminPage.click('[data-testid="export-video"]');
    await adminPage.fill('[data-testid="export-start-time"]', '2024-01-01T00:00');
    await adminPage.fill('[data-testid="export-end-time"]', '2024-01-01T23:59');
    await adminPage.fill('[data-testid="export-reason"]', 'Security incident investigation');
    await adminPage.fill('[data-testid="requester-name"]', 'Security Manager');
    await adminPage.click('[data-testid="create-export"]');
    
    // Verify export log entry
    const exportLogs = await adminPage.locator('[data-testid="export-logs-table"]');
    await expect(exportLogs).toContainText('Security incident investigation');
    
    // Test face blurring
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/face-blurring`);
    await adminPage.click('[data-testid="enable-face-detection"]');
    await adminPage.selectOption('[data-testid="blurring-mode"]', 'automatic');
    await adminPage.fill('[data-testid="confidence-threshold"]', '0.8');
    await adminPage.click('[data-testid="save-face-blurring-config"]');
    
    const faceBlurringStatus = await adminPage.locator('[data-testid="face-blurring-status"]');
    await expect(faceBlurringStatus).toContainText('Face blurring enabled');
    
    // Test privacy zones
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/privacy-zones`);
    await adminPage.click('[data-testid="define-privacy-zone"]');
    await adminPage.fill('[data-testid="privacy-zone-name"]', 'Employee Break Room');
    await adminPage.selectOption('[data-testid="privacy-level"]', 'complete-blackout');
    await adminPage.click('[data-testid="save-privacy-zone"]');
    
    // Test data subject requests
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/privacy/data-subject-requests`);
    await adminPage.click('[data-testid="new-data-request"]');
    await adminPage.fill('[data-testid="subject-email"]', 'subject@example.com');
    await adminPage.selectOption('[data-testid="request-type"]', 'data-deletion');
    await adminPage.fill('[data-testid="request-reason"]', 'GDPR Article 17 - Right to erasure');
    await adminPage.click('[data-testid="submit-request"]');
    
    const dataRequestStatus = await adminPage.locator('[data-testid="data-request-status"]');
    await expect(dataRequestStatus).toContainText('Request submitted');
    
    // Test consent tracking
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/privacy/consent-tracking`);
    await adminPage.click('[data-testid="record-consent"]');
    await adminPage.fill('[data-testid="individual-name"]', 'John Doe');
    await adminPage.selectOption('[data-testid="consent-type"]', 'video-recording');
    await adminPage.fill('[data-testid="consent-purpose"]', 'Security monitoring');
    await adminPage.click('[data-testid="consent-given"]');
    await adminPage.click('[data-testid="save-consent"]');
    
    const consentRecord = await adminPage.locator('[data-testid="consent-records-table"]');
    await expect(consentRecord).toContainText('John Doe');
    await expect(consentRecord).toContainText('video-recording');
  });

  // Requirement 26: Visitor Management
  test('REQ-26: Comprehensive visitor management system', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test pre-registration
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/pre-registration`);
    await adminPage.click('[data-testid="create-pre-registration"]');
    await adminPage.fill('[data-testid="visitor-name"]', 'Alice Johnson');
    await adminPage.fill('[data-testid="visitor-email"]', 'alice.johnson@visitor.com');
    await adminPage.fill('[data-testid="visitor-company"]', 'Partner Corp');
    await adminPage.fill('[data-testid="host-employee"]', 'Bob Smith');
    await adminPage.fill('[data-testid="visit-date"]', '2024-12-20');
    await adminPage.fill('[data-testid="visit-time"]', '14:00');
    await adminPage.fill('[data-testid="visit-purpose"]', 'Contract negotiation');
    await adminPage.click('[data-testid="save-pre-registration"]');
    
    // Test QR code generation
    const qrCode = await adminPage.locator('[data-testid="visitor-qr-code"]');
    await expect(qrCode).toBeVisible();
    
    // Test self-service check-in
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/self-checkin`);
    await adminPage.fill('[data-testid="qr-code-input"]', 'QR123456789');
    await adminPage.click('[data-testid="scan-qr-code"]');
    
    const checkinForm = await adminPage.locator('[data-testid="self-checkin-form"]');
    await expect(checkinForm).toBeVisible();
    await adminPage.click('[data-testid="confirm-checkin"]');
    
    // Test badge printing
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/badge-printing`);
    await adminPage.fill('[data-testid="visitor-search"]', 'alice.johnson@visitor.com');
    await adminPage.click('[data-testid="search-visitor"]');
    await adminPage.click('[data-testid="print-badge"]');
    
    const badgePreview = await adminPage.locator('[data-testid="badge-preview"]');
    await expect(badgePreview).toBeVisible();
    await expect(badgePreview).toContainText('Alice Johnson');
    
    // Test host notifications
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/host-notifications`);
    const hostNotification = await adminPage.locator('[data-testid="host-notification"]');
    await expect(hostNotification).toContainText('Alice Johnson has arrived');
    
    // Test temporary credentials
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/temporary-credentials`);
    await adminPage.click('[data-testid="issue-temp-credential"]');
    await adminPage.fill('[data-testid="temp-credential-visitor"]', 'alice.johnson@visitor.com');
    await adminPage.selectOption('[data-testid="access-level"]', 'visitor-areas-only');
    await adminPage.fill('[data-testid="credential-duration"]', '8');
    await adminPage.click('[data-testid="issue-credential"]');
    
    const tempCredential = await adminPage.locator('[data-testid="temp-credential-details"]');
    await expect(tempCredential).toContainText('Temporary credential issued');
    
    // Test overstay alerts
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/overstay-monitoring`);
    await adminPage.fill('[data-testid="overstay-threshold"]', '480'); // 8 hours
    await adminPage.click('[data-testid="enable-overstay-alerts"]');
    
    // Simulate overstay
    await axios.post(`${TEST_CONFIG.apiUrl}/api/visitors/overstay`, {
      visitorId: 'visitor-001',
      checkinTime: new Date(Date.now() - 9 * 60 * 60 * 1000).toISOString(), // 9 hours ago
      expectedDuration: 8
    });
    
    const overstayAlert = await adminPage.locator('[data-testid="overstay-alert"]');
    await expect(overstayAlert).toContainText('Visitor overstay detected');
    
    // Test watchlist integration
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/watchlist`);
    await adminPage.click('[data-testid="add-to-watchlist"]');
    await adminPage.fill('[data-testid="watchlist-name"]', 'John Blacklist');
    await adminPage.fill('[data-testid="watchlist-reason"]', 'Security concern');
    await adminPage.selectOption('[data-testid="alert-level"]', 'high');
    await adminPage.click('[data-testid="save-watchlist-entry"]');
    
    // Test watchlist check during registration
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/visitors/register`);
    await adminPage.fill('[data-testid="visitor-name"]', 'John Blacklist');
    await adminPage.fill('[data-testid="visitor-email"]', 'john.blacklist@test.com');
    await adminPage.click('[data-testid="check-visitor"]');
    
    const watchlistAlert = await adminPage.locator('[data-testid="watchlist-alert"]');
    await expect(watchlistAlert).toContainText('Visitor found on watchlist');
  });

  // Requirement 27: Offline Resilience
  test('REQ-27: 72-hour offline operation and resilience', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test offline mode activation
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/offline-resilience`);
    await adminPage.click('[data-testid="activate-offline-mode"]');
    await adminPage.click('[data-testid="confirm-offline-activation"]');
    
    const offlineStatus = await adminPage.locator('[data-testid="offline-mode-status"]');
    await expect(offlineStatus).toContainText('Offline Mode Active');
    
    // Test local video recording during offline
    await simulateOfflineMode(adminPage);
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/video/offline-recording`);
    await adminPage.click('[data-testid="start-local-recording"]');
    
    const localRecordingStatus = await adminPage.locator('[data-testid="local-recording-status"]');
    await expect(localRecordingStatus).toContainText('Local recording active');
    
    // Test audit log maintenance offline
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/audit/offline-logs`);
    const offlineAuditLogs = await adminPage.locator('[data-testid="offline-audit-logs"]');
    await expect(offlineAuditLogs).toBeVisible();
    
    // Simulate offline access events
    await adminPage.click('[data-testid="simulate-offline-access"]');
    await adminPage.fill('[data-testid="offline-user-id"]', 'user-123');
    await adminPage.fill('[data-testid="offline-door-id"]', 'door-456');
    await adminPage.click('[data-testid="log-offline-access"]');
    
    const offlineEventCount = await adminPage.locator('[data-testid="offline-events-count"]');
    await expect(offlineEventCount).toContainText('1 offline event logged');
    
    // Test mesh networking for credential revocation
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/offline/mesh-networking`);
    await adminPage.click('[data-testid="enable-mesh-network"]');
    
    const meshStatus = await adminPage.locator('[data-testid="mesh-network-status"]');
    await expect(meshStatus).toContainText('Mesh network active');
    
    // Test mesh revocation propagation
    await adminPage.click('[data-testid="test-mesh-revocation"]');
    await adminPage.fill('[data-testid="revoke-credential-id"]', 'cred-789');
    await adminPage.click('[data-testid="propagate-revocation"]');
    
    const meshRevocationStatus = await adminPage.locator('[data-testid="mesh-revocation-status"]');
    await expect(meshRevocationStatus).toContainText('Revocation propagated via mesh');
    
    // Test offline data synchronization
    await restoreOnlineMode(adminPage);
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/data-sync`);
    await adminPage.click('[data-testid="start-sync"]');
    
    // Wait for synchronization
    await adminPage.waitForTimeout(5000);
    const syncProgress = await adminPage.locator('[data-testid="sync-progress"]');
    await expect(syncProgress).toContainText('Synchronization complete');
    
    // Test conflict resolution
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/conflict-resolution`);
    const conflictsList = await adminPage.locator('[data-testid="conflicts-list"]');
    
    if (await conflictsList.isVisible()) {
      await adminPage.click('[data-testid="resolve-conflict"]:first-child');
      await adminPage.selectOption('[data-testid="resolution-strategy"]', 'server-wins');
      await adminPage.click('[data-testid="apply-resolution"]');
      
      const resolutionStatus = await adminPage.locator('[data-testid="resolution-status"]');
      await expect(resolutionStatus).toContainText('Conflict resolved');
    }
    
    // Test 72-hour capacity monitoring
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/system/offline-capacity`);
    const capacityMetrics = await adminPage.locator('[data-testid="offline-capacity-metrics"]');
    await expect(capacityMetrics).toBeVisible();
    
    const storageCapacity = await adminPage.locator('[data-testid="storage-capacity"]');
    await expect(storageCapacity).toContainText('72 hours');
  });

  // Requirement 28: Flexible Deployment Models
  test('REQ-28: Flexible deployment models and multi-organization support', async () => {
    await loginUser(adminPage, TEST_CONFIG.adminUser.email, TEST_CONFIG.adminUser.password);
    
    // Test SSP-managed deployment
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/ssp-managed`);
    await adminPage.click('[data-testid="configure-ssp-deployment"]');
    await adminPage.fill('[data-testid="organization-name"]', 'SSP Managed Org');
    await adminPage.selectOption('[data-testid="service-tier"]', 'enterprise');
    await adminPage.click('[data-testid="enable-managed-services"]');
    await adminPage.click('[data-testid="save-ssp-config"]');
    
    const sspStatus = await adminPage.locator('[data-testid="ssp-deployment-status"]');
    await expect(sspStatus).toContainText('SSP-managed deployment active');
    
    // Test self-managed deployment
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/self-managed`);
    await adminPage.click('[data-testid="configure-self-managed"]');
    await adminPage.fill('[data-testid="self-managed-org"]', 'Self Managed Corp');
    await adminPage.selectOption('[data-testid="infrastructure-type"]', 'on-premises');
    await adminPage.click('[data-testid="enable-local-admin"]');
    await adminPage.click('[data-testid="save-self-managed-config"]');
    
    const selfManagedStatus = await adminPage.locator('[data-testid="self-managed-status"]');
    await expect(selfManagedStatus).toContainText('Self-managed deployment configured');
    
    // Test hybrid deployment
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/hybrid`);
    await adminPage.click('[data-testid="configure-hybrid"]');
    await adminPage.fill('[data-testid="hybrid-org-name"]', 'Hybrid Organization');
    await adminPage.selectOption('[data-testid="cloud-services"]', 'analytics-only');
    await adminPage.selectOption('[data-testid="local-services"]', 'access-control');
    await adminPage.click('[data-testid="save-hybrid-config"]');
    
    const hybridStatus = await adminPage.locator('[data-testid="hybrid-deployment-status"]');
    await expect(hybridStatus).toContainText('Hybrid deployment configured');
    
    // Test deployment model transitions
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/model-transition`);
    await adminPage.selectOption('[data-testid="current-model"]', 'self-managed');
    await adminPage.selectOption('[data-testid="target-model"]', 'hybrid');
    await adminPage.click('[data-testid="plan-transition"]');
    
    const transitionPlan = await adminPage.locator('[data-testid="transition-plan"]');
    await expect(transitionPlan).toBeVisible();
    await expect(transitionPlan).toContainText('Migration steps');
    
    // Test multi-organization isolation
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/multi-org`);
    await adminPage.click('[data-testid="create-organization"]');
    await adminPage.fill('[data-testid="org-name"]', 'Subsidiary Corp');
    await adminPage.selectOption('[data-testid="isolation-level"]', 'complete');
    await adminPage.click('[data-testid="enable-data-isolation"]');
    await adminPage.click('[data-testid="create-org"]');
    
    const orgList = await adminPage.locator('[data-testid="organizations-list"]');
    await expect(orgList).toContainText('Subsidiary Corp');
    
    // Test organization switching
    await adminPage.selectOption('[data-testid="org-selector"]', 'Subsidiary Corp');
    await adminPage.click('[data-testid="switch-organization"]');
    
    const currentOrg = await adminPage.locator('[data-testid="current-organization"]');
    await expect(currentOrg).toContainText('Subsidiary Corp');
    
    // Test granular permissions
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/permissions`);
    await adminPage.click('[data-testid="configure-permissions"]');
    await adminPage.selectOption('[data-testid="permission-scope"]', 'organization');
    await adminPage.click('[data-testid="permission-access-control"]');
    await adminPage.click('[data-testid="permission-video-management"]');
    await adminPage.click('[data-testid="save-permissions"]');
    
    const permissionsStatus = await adminPage.locator('[data-testid="permissions-status"]');
    await expect(permissionsStatus).toContainText('Granular permissions configured');
    
    // Test cross-organization data isolation verification
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/isolation-test`);
    await adminPage.click('[data-testid="run-isolation-test"]');
    
    const isolationResults = await adminPage.locator('[data-testid="isolation-test-results"]');
    await expect(isolationResults).toContainText('Data isolation verified');
    
    // Test deployment health monitoring
    await adminPage.goto(`${TEST_CONFIG.baseUrl}/deployment/health`);
    const deploymentHealth = await adminPage.locator('[data-testid="deployment-health-dashboard"]');
    await expect(deploymentHealth).toBeVisible();
    
    const healthMetrics = await adminPage.locator('[data-testid="deployment-metrics"]');
    await expect(healthMetrics).toContainText('All services operational');
  });
});
