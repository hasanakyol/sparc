import { test, expect, Page, BrowserContext } from '@playwright/test';

// Test data and configuration
const TEST_CONFIG = {
  baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3000',
  apiUrl: process.env.TEST_API_URL || 'http://localhost:8080',
  timeout: 30000,
  users: {
    superAdmin: {
      email: 'superadmin@sparc.test',
      password: 'SuperAdmin123!',
      role: 'super_admin',
      tenantId: null
    },
    tenantAdmin: {
      email: 'admin@tenant1.test',
      password: 'TenantAdmin123!',
      role: 'tenant_admin',
      tenantId: 'tenant-1'
    },
    securityOperator: {
      email: 'operator@tenant1.test',
      password: 'Operator123!',
      role: 'security_operator',
      tenantId: 'tenant-1'
    },
    viewer: {
      email: 'viewer@tenant1.test',
      password: 'Viewer123!',
      role: 'viewer',
      tenantId: 'tenant-1'
    },
    disabledUser: {
      email: 'disabled@tenant1.test',
      password: 'Disabled123!',
      role: 'viewer',
      tenantId: 'tenant-1',
      disabled: true
    }
  }
};

// Helper functions
async function loginUser(page: Page, email: string, password: string) {
  await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
  await page.fill('[data-testid="email-input"]', email);
  await page.fill('[data-testid="password-input"]', password);
  await page.click('[data-testid="login-button"]');
}

async function getAuthToken(page: Page): Promise<string | null> {
  return await page.evaluate(() => {
    return localStorage.getItem('auth_token');
  });
}

async function clearAuthData(page: Page) {
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
}

async function waitForDashboard(page: Page) {
  await page.waitForURL('**/dashboard', { timeout: TEST_CONFIG.timeout });
  await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
}

async function expectToBeOnLoginPage(page: Page) {
  await page.waitForURL('**/auth/login', { timeout: TEST_CONFIG.timeout });
  await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
}

test.describe('Authentication Flows', () => {
  test.beforeEach(async ({ page }) => {
    await clearAuthData(page);
  });

  test.describe('Login Functionality', () => {
    test('should successfully login with valid credentials', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Verify JWT token is stored
      const token = await getAuthToken(page);
      expect(token).toBeTruthy();
      
      // Verify user info is displayed
      await expect(page.locator('[data-testid="user-menu"]')).toContainText(user.email);
      
      // Verify tenant context is set
      await expect(page.locator('[data-testid="tenant-selector"]')).toContainText('Tenant 1');
    });

    test('should reject invalid credentials', async ({ page }) => {
      await loginUser(page, 'invalid@test.com', 'wrongpassword');
      
      // Should remain on login page
      await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
      
      // Should display error message
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid credentials');
      
      // Should not have auth token
      const token = await getAuthToken(page);
      expect(token).toBeFalsy();
    });

    test('should reject disabled user account', async ({ page }) => {
      const user = TEST_CONFIG.users.disabledUser;
      
      await loginUser(page, user.email, user.password);
      
      // Should remain on login page
      await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
      
      // Should display account disabled message
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Account disabled');
      
      // Should not have auth token
      const token = await getAuthToken(page);
      expect(token).toBeFalsy();
    });

    test('should handle empty form submission', async ({ page }) => {
      await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
      await page.click('[data-testid="login-button"]');
      
      // Should show validation errors
      await expect(page.locator('[data-testid="email-error"]')).toContainText('Email is required');
      await expect(page.locator('[data-testid="password-error"]')).toContainText('Password is required');
      
      // Should remain on login page
      await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    });

    test('should validate email format', async ({ page }) => {
      await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
      await page.fill('[data-testid="email-input"]', 'invalid-email');
      await page.fill('[data-testid="password-input"]', 'password123');
      await page.click('[data-testid="login-button"]');
      
      // Should show email format error
      await expect(page.locator('[data-testid="email-error"]')).toContainText('Invalid email format');
    });

    test('should handle network errors gracefully', async ({ page }) => {
      // Intercept login request and simulate network error
      await page.route('**/api/auth/login', route => {
        route.abort('failed');
      });
      
      const user = TEST_CONFIG.users.tenantAdmin;
      await loginUser(page, user.email, user.password);
      
      // Should display network error message
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Network error');
      
      // Should remain on login page
      await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    });
  });

  test.describe('Logout Functionality', () => {
    test('should successfully logout user', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      // Login first
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Logout
      await page.click('[data-testid="user-menu"]');
      await page.click('[data-testid="logout-button"]');
      
      // Should redirect to login page
      await expectToBeOnLoginPage(page);
      
      // Should clear auth token
      const token = await getAuthToken(page);
      expect(token).toBeFalsy();
    });

    test('should handle logout API errors', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      // Login first
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Intercept logout request and simulate error
      await page.route('**/api/auth/logout', route => {
        route.fulfill({ status: 500, body: 'Server error' });
      });
      
      // Logout
      await page.click('[data-testid="user-menu"]');
      await page.click('[data-testid="logout-button"]');
      
      // Should still redirect to login page (client-side logout)
      await expectToBeOnLoginPage(page);
      
      // Should clear auth token locally
      const token = await getAuthToken(page);
      expect(token).toBeFalsy();
    });
  });

  test.describe('Token Refresh', () => {
    test('should automatically refresh expired tokens', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      // Login first
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      const initialToken = await getAuthToken(page);
      
      // Mock token refresh response
      await page.route('**/api/auth/refresh', route => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            token: 'new-jwt-token',
            refreshToken: 'new-refresh-token',
            expiresIn: 3600
          })
        });
      });
      
      // Simulate token expiration by making an API call that returns 401
      await page.route('**/api/**', route => {
        if (route.request().url().includes('/auth/')) {
          route.continue();
        } else {
          route.fulfill({ status: 401, body: 'Unauthorized' });
        }
      }, { times: 1 });
      
      // Trigger an API call that would cause token refresh
      await page.click('[data-testid="refresh-data-button"]');
      
      // Wait for token refresh
      await page.waitForTimeout(1000);
      
      const newToken = await getAuthToken(page);
      expect(newToken).toBeTruthy();
      expect(newToken).not.toBe(initialToken);
      
      // Should remain on dashboard
      await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
    });

    test('should redirect to login when refresh token is invalid', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      // Login first
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Mock failed token refresh
      await page.route('**/api/auth/refresh', route => {
        route.fulfill({ status: 401, body: 'Invalid refresh token' });
      });
      
      // Simulate token expiration
      await page.route('**/api/**', route => {
        if (route.request().url().includes('/auth/')) {
          route.continue();
        } else {
          route.fulfill({ status: 401, body: 'Unauthorized' });
        }
      }, { times: 1 });
      
      // Trigger an API call that would cause token refresh
      await page.click('[data-testid="refresh-data-button"]');
      
      // Should redirect to login page
      await expectToBeOnLoginPage(page);
      
      // Should clear auth token
      const token = await getAuthToken(page);
      expect(token).toBeFalsy();
    });
  });

  test.describe('Role-Based Access Control', () => {
    test('super admin should access all features', async ({ page }) => {
      const user = TEST_CONFIG.users.superAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should see tenant management
      await expect(page.locator('[data-testid="tenant-management-nav"]')).toBeVisible();
      
      // Should see system configuration
      await expect(page.locator('[data-testid="system-config-nav"]')).toBeVisible();
      
      // Should see all tenant data
      await expect(page.locator('[data-testid="all-tenants-selector"]')).toBeVisible();
    });

    test('tenant admin should access tenant-specific features', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should see access control management
      await expect(page.locator('[data-testid="access-control-nav"]')).toBeVisible();
      
      // Should see video management
      await expect(page.locator('[data-testid="video-management-nav"]')).toBeVisible();
      
      // Should see user management
      await expect(page.locator('[data-testid="user-management-nav"]')).toBeVisible();
      
      // Should NOT see tenant management
      await expect(page.locator('[data-testid="tenant-management-nav"]')).not.toBeVisible();
      
      // Should NOT see system configuration
      await expect(page.locator('[data-testid="system-config-nav"]')).not.toBeVisible();
    });

    test('security operator should have limited access', async ({ page }) => {
      const user = TEST_CONFIG.users.securityOperator;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should see access control monitoring
      await expect(page.locator('[data-testid="access-control-nav"]')).toBeVisible();
      
      // Should see video monitoring
      await expect(page.locator('[data-testid="video-management-nav"]')).toBeVisible();
      
      // Should NOT see user management
      await expect(page.locator('[data-testid="user-management-nav"]')).not.toBeVisible();
      
      // Should NOT see system configuration
      await expect(page.locator('[data-testid="system-config-nav"]')).not.toBeVisible();
    });

    test('viewer should have read-only access', async ({ page }) => {
      const user = TEST_CONFIG.users.viewer;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should see dashboard
      await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
      
      // Should see reports
      await expect(page.locator('[data-testid="reports-nav"]')).toBeVisible();
      
      // Should NOT see management features
      await expect(page.locator('[data-testid="user-management-nav"]')).not.toBeVisible();
      await expect(page.locator('[data-testid="device-management-nav"]')).not.toBeVisible();
      
      // Control buttons should be disabled
      await expect(page.locator('[data-testid="door-unlock-button"]')).toBeDisabled();
    });

    test('should prevent unauthorized access to protected pages', async ({ page }) => {
      const user = TEST_CONFIG.users.viewer;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Try to access user management directly
      await page.goto(`${TEST_CONFIG.baseUrl}/admin/users`);
      
      // Should redirect to unauthorized page or dashboard
      await expect(page.locator('[data-testid="unauthorized-message"]')).toBeVisible();
    });
  });

  test.describe('Tenant Switching', () => {
    test('super admin should switch between tenants', async ({ page }) => {
      const user = TEST_CONFIG.users.superAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should see tenant selector
      await expect(page.locator('[data-testid="tenant-selector"]')).toBeVisible();
      
      // Switch to specific tenant
      await page.click('[data-testid="tenant-selector"]');
      await page.click('[data-testid="tenant-option-1"]');
      
      // Should update context
      await expect(page.locator('[data-testid="tenant-selector"]')).toContainText('Tenant 1');
      
      // Should show tenant-specific data
      await expect(page.locator('[data-testid="tenant-dashboard"]')).toBeVisible();
      
      // Switch to all tenants view
      await page.click('[data-testid="tenant-selector"]');
      await page.click('[data-testid="all-tenants-option"]');
      
      // Should show aggregated view
      await expect(page.locator('[data-testid="all-tenants-dashboard"]')).toBeVisible();
    });

    test('tenant users should not see tenant selector', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should NOT see tenant selector
      await expect(page.locator('[data-testid="tenant-selector"]')).not.toBeVisible();
      
      // Should show current tenant name
      await expect(page.locator('[data-testid="current-tenant"]')).toContainText('Tenant 1');
    });

    test('should maintain tenant context across page navigation', async ({ page }) => {
      const user = TEST_CONFIG.users.superAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Switch to specific tenant
      await page.click('[data-testid="tenant-selector"]');
      await page.click('[data-testid="tenant-option-1"]');
      
      // Navigate to different page
      await page.click('[data-testid="access-control-nav"]');
      
      // Should maintain tenant context
      await expect(page.locator('[data-testid="tenant-selector"]')).toContainText('Tenant 1');
      
      // Should show tenant-specific access control data
      await expect(page.locator('[data-testid="tenant-access-control"]')).toBeVisible();
    });
  });

  test.describe('Security Requirements', () => {
    test('should prevent session fixation attacks', async ({ page }) => {
      // Get initial session
      await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
      const initialSessionId = await page.evaluate(() => document.cookie);
      
      // Login
      const user = TEST_CONFIG.users.tenantAdmin;
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Session should be regenerated
      const newSessionId = await page.evaluate(() => document.cookie);
      expect(newSessionId).not.toBe(initialSessionId);
    });

    test('should implement proper CSRF protection', async ({ page }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Check for CSRF token in forms
      await page.goto(`${TEST_CONFIG.baseUrl}/admin/users/new`);
      const csrfToken = await page.locator('[name="csrf_token"]').getAttribute('value');
      expect(csrfToken).toBeTruthy();
    });

    test('should enforce secure headers', async ({ page }) => {
      await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
      
      // Check for security headers (this would need to be implemented in the response)
      const response = await page.waitForResponse('**/auth/login');
      const headers = response.headers();
      
      expect(headers['x-frame-options']).toBe('DENY');
      expect(headers['x-content-type-options']).toBe('nosniff');
      expect(headers['x-xss-protection']).toBe('1; mode=block');
    });

    test('should handle concurrent sessions properly', async ({ browser }) => {
      const user = TEST_CONFIG.users.tenantAdmin;
      
      // Create two browser contexts (different sessions)
      const context1 = await browser.newContext();
      const context2 = await browser.newContext();
      
      const page1 = await context1.newPage();
      const page2 = await context2.newPage();
      
      // Login in first session
      await loginUser(page1, user.email, user.password);
      await waitForDashboard(page1);
      
      // Login in second session
      await loginUser(page2, user.email, user.password);
      await waitForDashboard(page2);
      
      // Both sessions should be valid
      await expect(page1.locator('[data-testid="dashboard-container"]')).toBeVisible();
      await expect(page2.locator('[data-testid="dashboard-container"]')).toBeVisible();
      
      await context1.close();
      await context2.close();
    });

    test('should rate limit login attempts', async ({ page }) => {
      const maxAttempts = 5;
      
      // Make multiple failed login attempts
      for (let i = 0; i < maxAttempts + 1; i++) {
        await loginUser(page, 'invalid@test.com', 'wrongpassword');
        await page.waitForTimeout(100);
      }
      
      // Should be rate limited
      await expect(page.locator('[data-testid="rate-limit-message"]')).toContainText('Too many attempts');
      
      // Login button should be disabled
      await expect(page.locator('[data-testid="login-button"]')).toBeDisabled();
    });
  });

  test.describe('Error Handling', () => {
    test('should handle server errors gracefully', async ({ page }) => {
      // Mock server error
      await page.route('**/api/auth/login', route => {
        route.fulfill({ status: 500, body: 'Internal server error' });
      });
      
      const user = TEST_CONFIG.users.tenantAdmin;
      await loginUser(page, user.email, user.password);
      
      // Should display user-friendly error message
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Server temporarily unavailable');
      
      // Should remain on login page
      await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    });

    test('should handle timeout errors', async ({ page }) => {
      // Mock timeout
      await page.route('**/api/auth/login', route => {
        // Don't respond to simulate timeout
      });
      
      const user = TEST_CONFIG.users.tenantAdmin;
      await loginUser(page, user.email, user.password);
      
      // Should display timeout message
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Request timeout');
    });

    test('should handle malformed responses', async ({ page }) => {
      // Mock malformed response
      await page.route('**/api/auth/login', route => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: 'invalid json'
        });
      });
      
      const user = TEST_CONFIG.users.tenantAdmin;
      await loginUser(page, user.email, user.password);
      
      // Should display error message
      await expect(page.locator('[data-testid="error-message"]')).toContainText('Invalid response');
    });
  });

  test.describe('Accessibility', () => {
    test('should support keyboard navigation', async ({ page }) => {
      await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
      
      // Tab through form elements
      await page.keyboard.press('Tab');
      await expect(page.locator('[data-testid="email-input"]')).toBeFocused();
      
      await page.keyboard.press('Tab');
      await expect(page.locator('[data-testid="password-input"]')).toBeFocused();
      
      await page.keyboard.press('Tab');
      await expect(page.locator('[data-testid="login-button"]')).toBeFocused();
      
      // Submit with Enter key
      await page.fill('[data-testid="email-input"]', TEST_CONFIG.users.tenantAdmin.email);
      await page.fill('[data-testid="password-input"]', TEST_CONFIG.users.tenantAdmin.password);
      await page.keyboard.press('Enter');
      
      await waitForDashboard(page);
    });

    test('should have proper ARIA labels', async ({ page }) => {
      await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
      
      // Check for ARIA labels
      await expect(page.locator('[data-testid="email-input"]')).toHaveAttribute('aria-label', 'Email address');
      await expect(page.locator('[data-testid="password-input"]')).toHaveAttribute('aria-label', 'Password');
      await expect(page.locator('[data-testid="login-button"]')).toHaveAttribute('aria-label', 'Sign in');
    });
  });

  test.describe('Multi-Device Support', () => {
    test('should work on mobile devices', async ({ browser }) => {
      const context = await browser.newContext({
        viewport: { width: 375, height: 667 }, // iPhone SE
        userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
      });
      
      const page = await context.newPage();
      const user = TEST_CONFIG.users.tenantAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should display mobile-optimized layout
      await expect(page.locator('[data-testid="mobile-nav"]')).toBeVisible();
      await expect(page.locator('[data-testid="desktop-nav"]')).not.toBeVisible();
      
      await context.close();
    });

    test('should work on tablets', async ({ browser }) => {
      const context = await browser.newContext({
        viewport: { width: 768, height: 1024 }, // iPad
        userAgent: 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
      });
      
      const page = await context.newPage();
      const user = TEST_CONFIG.users.tenantAdmin;
      
      await loginUser(page, user.email, user.password);
      await waitForDashboard(page);
      
      // Should display tablet-optimized layout
      await expect(page.locator('[data-testid="tablet-nav"]')).toBeVisible();
      
      await context.close();
    });
  });
});

test.describe('Session Management', () => {
  test('should handle session expiration', async ({ page }) => {
    const user = TEST_CONFIG.users.tenantAdmin;
    
    await loginUser(page, user.email, user.password);
    await waitForDashboard(page);
    
    // Simulate session expiration by clearing token
    await page.evaluate(() => {
      localStorage.removeItem('auth_token');
    });
    
    // Try to navigate to protected page
    await page.goto(`${TEST_CONFIG.baseUrl}/admin/users`);
    
    // Should redirect to login
    await expectToBeOnLoginPage(page);
  });

  test('should remember user preference for "Remember Me"', async ({ page }) => {
    const user = TEST_CONFIG.users.tenantAdmin;
    
    await page.goto(`${TEST_CONFIG.baseUrl}/auth/login`);
    await page.fill('[data-testid="email-input"]', user.email);
    await page.fill('[data-testid="password-input"]', user.password);
    await page.check('[data-testid="remember-me-checkbox"]');
    await page.click('[data-testid="login-button"]');
    
    await waitForDashboard(page);
    
    // Close and reopen browser
    await page.close();
    const newPage = await page.context().newPage();
    
    // Should still be logged in
    await newPage.goto(`${TEST_CONFIG.baseUrl}/dashboard`);
    await expect(newPage.locator('[data-testid="dashboard-container"]')).toBeVisible();
  });
});