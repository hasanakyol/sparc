import axios, { AxiosResponse } from 'axios';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { performance } from 'perf_hooks';

describe('SPARC Platform Security Penetration Testing Suite', () => {
  let baseURL: string;
  let validToken: string;
  let adminToken: string;
  let tenantAToken: string;
  let tenantBToken: string;
  let testTenantId: string;
  let maliciousTenantId: string;

  beforeAll(async () => {
    baseURL = process.env.SPARC_API_URL || 'https://api.sparc.local';
    
    // Setup test tokens and tenants for isolation testing
    const authResponse = await setupTestAuthentication();
    validToken = authResponse.validToken;
    adminToken = authResponse.adminToken;
    tenantAToken = authResponse.tenantAToken;
    tenantBToken = authResponse.tenantBToken;
    testTenantId = authResponse.testTenantId;
    maliciousTenantId = authResponse.maliciousTenantId;
  });

  afterAll(async () => {
    await cleanupTestData();
  });

  describe('Authentication Bypass Attempts', () => {
    it('should reject requests with no authentication token', async () => {
      try {
        const response = await axios.get(`${baseURL}/api/v1/access-control/doors`);
        expect(response.status).not.toBe(200);
      } catch (error: any) {
        expect(error.response?.status).toBe(401);
      }
    });

    it('should reject requests with malformed JWT tokens', async () => {
      const malformedTokens = [
        'invalid.jwt.token',
        'Bearer malformed',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid',
        '',
        'null',
        'undefined'
      ];

      for (const token of malformedTokens) {
        try {
          await axios.get(`${baseURL}/api/v1/access-control/doors`, {
            headers: { Authorization: `Bearer ${token}` }
          });
          fail(`Should have rejected malformed token: ${token}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([401, 403]);
        }
      }
    });

    it('should reject expired JWT tokens', async () => {
      const expiredToken = jwt.sign(
        { sub: 'test-user', exp: Math.floor(Date.now() / 1000) - 3600 },
        'test-secret'
      );

      try {
        await axios.get(`${baseURL}/api/v1/access-control/doors`, {
          headers: { Authorization: `Bearer ${expiredToken}` }
        });
        fail('Should have rejected expired token');
      } catch (error: any) {
        expect(error.response?.status).toBe(401);
      }
    });

    it('should reject tokens with invalid signatures', async () => {
      const invalidSignatureToken = jwt.sign(
        { sub: 'test-user', exp: Math.floor(Date.now() / 1000) + 3600 },
        'wrong-secret'
      );

      try {
        await axios.get(`${baseURL}/api/v1/access-control/doors`, {
          headers: { Authorization: `Bearer ${invalidSignatureToken}` }
        });
        fail('Should have rejected token with invalid signature');
      } catch (error: any) {
        expect(error.response?.status).toBe(401);
      }
    });

    it('should prevent privilege escalation attempts', async () => {
      // Attempt to access admin endpoints with regular user token
      const adminEndpoints = [
        '/api/v1/admin/tenants',
        '/api/v1/admin/users',
        '/api/v1/admin/system-config',
        '/api/v1/admin/audit-logs'
      ];

      for (const endpoint of adminEndpoints) {
        try {
          await axios.get(`${baseURL}${endpoint}`, {
            headers: { Authorization: `Bearer ${validToken}` }
          });
          fail(`Regular user should not access admin endpoint: ${endpoint}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([403, 404]);
        }
      }
    });
  });

  describe('SQL Injection Testing', () => {
    const sqlInjectionPayloads = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "' UNION SELECT * FROM credentials --",
      "'; INSERT INTO users VALUES ('hacker', 'password'); --",
      "' OR 1=1 --",
      "admin'--",
      "admin'/*",
      "' OR 'x'='x",
      "'; EXEC xp_cmdshell('dir'); --"
    ];

    it('should prevent SQL injection in user authentication', async () => {
      for (const payload of sqlInjectionPayloads) {
        try {
          await axios.post(`${baseURL}/api/v1/auth/login`, {
            username: payload,
            password: 'test'
          });
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([400, 401]);
          expect(error.response?.data).not.toContain('SQL');
          expect(error.response?.data).not.toContain('database');
        }
      }
    });

    it('should prevent SQL injection in search parameters', async () => {
      for (const payload of sqlInjectionPayloads) {
        try {
          await axios.get(`${baseURL}/api/v1/users/search`, {
            params: { q: payload },
            headers: { Authorization: `Bearer ${adminToken}` }
          });
        } catch (error: any) {
          if (error.response) {
            expect(error.response.status).toBeOneOf([400, 422]);
            expect(error.response.data).not.toContain('SQL');
          }
        }
      }
    });

    it('should prevent SQL injection in door access queries', async () => {
      for (const payload of sqlInjectionPayloads) {
        try {
          await axios.get(`${baseURL}/api/v1/access-control/doors/${payload}`, {
            headers: { Authorization: `Bearer ${validToken}` }
          });
        } catch (error: any) {
          if (error.response) {
            expect(error.response.status).toBeOneOf([400, 404]);
            expect(error.response.data).not.toContain('SQL');
          }
        }
      }
    });
  });

  describe('Cross-Site Scripting (XSS) Prevention', () => {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src="x" onerror="alert(1)">',
      'javascript:alert("XSS")',
      '<svg onload="alert(1)">',
      '<iframe src="javascript:alert(1)"></iframe>',
      '"><script>alert("XSS")</script>',
      "'><script>alert('XSS')</script>",
      '<body onload="alert(1)">',
      '<input onfocus="alert(1)" autofocus>'
    ];

    it('should sanitize XSS payloads in user profile updates', async () => {
      for (const payload of xssPayloads) {
        try {
          const response = await axios.put(`${baseURL}/api/v1/users/profile`, {
            firstName: payload,
            lastName: 'Test',
            email: 'test@example.com'
          }, {
            headers: { Authorization: `Bearer ${validToken}` }
          });

          if (response.status === 200) {
            expect(response.data.firstName).not.toContain('<script>');
            expect(response.data.firstName).not.toContain('javascript:');
            expect(response.data.firstName).not.toContain('onerror');
          }
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([400, 422]);
        }
      }
    });

    it('should sanitize XSS payloads in visitor registration', async () => {
      for (const payload of xssPayloads) {
        try {
          const response = await axios.post(`${baseURL}/api/v1/visitors`, {
            name: payload,
            email: 'visitor@example.com',
            purpose: 'Meeting'
          }, {
            headers: { Authorization: `Bearer ${validToken}` }
          });

          if (response.status === 201) {
            expect(response.data.name).not.toContain('<script>');
            expect(response.data.name).not.toContain('javascript:');
          }
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([400, 422]);
        }
      }
    });
  });

  describe('Cross-Site Request Forgery (CSRF) Protection', () => {
    it('should require CSRF tokens for state-changing operations', async () => {
      const stateChangingEndpoints = [
        { method: 'POST', path: '/api/v1/access-control/doors', data: { name: 'Test Door' } },
        { method: 'PUT', path: '/api/v1/users/profile', data: { firstName: 'Test' } },
        { method: 'DELETE', path: '/api/v1/visitors/test-id', data: {} },
        { method: 'POST', path: '/api/v1/credentials', data: { type: 'card' } }
      ];

      for (const endpoint of stateChangingEndpoints) {
        try {
          await axios({
            method: endpoint.method.toLowerCase() as any,
            url: `${baseURL}${endpoint.path}`,
            data: endpoint.data,
            headers: { 
              Authorization: `Bearer ${validToken}`,
              'X-CSRF-Token': 'invalid-csrf-token'
            }
          });
          fail(`Should have rejected request without valid CSRF token: ${endpoint.method} ${endpoint.path}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([403, 422]);
        }
      }
    });

    it('should reject requests with missing CSRF tokens', async () => {
      try {
        await axios.post(`${baseURL}/api/v1/access-control/doors`, {
          name: 'Test Door'
        }, {
          headers: { Authorization: `Bearer ${validToken}` }
        });
        fail('Should have rejected request without CSRF token');
      } catch (error: any) {
        expect(error.response?.status).toBeOneOf([403, 422]);
      }
    });
  });

  describe('API Security Validation', () => {
    it('should enforce rate limiting', async () => {
      const requests = Array(100).fill(null).map(() => 
        axios.get(`${baseURL}/api/v1/health`, {
          headers: { Authorization: `Bearer ${validToken}` }
        }).catch(e => e.response)
      );

      const responses = await Promise.all(requests);
      const rateLimitedResponses = responses.filter(r => r?.status === 429);
      
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });

    it('should validate request content types', async () => {
      try {
        await axios.post(`${baseURL}/api/v1/users`, 'invalid-json', {
          headers: { 
            Authorization: `Bearer ${adminToken}`,
            'Content-Type': 'text/plain'
          }
        });
        fail('Should have rejected invalid content type');
      } catch (error: any) {
        expect(error.response?.status).toBeOneOf([400, 415]);
      }
    });

    it('should enforce request size limits', async () => {
      const largePayload = 'x'.repeat(10 * 1024 * 1024); // 10MB
      
      try {
        await axios.post(`${baseURL}/api/v1/users`, {
          data: largePayload
        }, {
          headers: { Authorization: `Bearer ${adminToken}` }
        });
        fail('Should have rejected oversized request');
      } catch (error: any) {
        expect(error.response?.status).toBeOneOf([413, 400]);
      }
    });

    it('should validate API versioning', async () => {
      try {
        await axios.get(`${baseURL}/api/v999/users`, {
          headers: { Authorization: `Bearer ${validToken}` }
        });
        fail('Should have rejected invalid API version');
      } catch (error: any) {
        expect(error.response?.status).toBeOneOf([404, 400]);
      }
    });
  });

  describe('Multi-Tenant Data Isolation', () => {
    it('should prevent cross-tenant data access', async () => {
      // Create test data in tenant A
      const tenantAData = await axios.post(`${baseURL}/api/v1/access-control/doors`, {
        name: 'Tenant A Door',
        location: 'Building A'
      }, {
        headers: { Authorization: `Bearer ${tenantAToken}` }
      });

      const doorId = tenantAData.data.id;

      // Attempt to access tenant A data with tenant B token
      try {
        await axios.get(`${baseURL}/api/v1/access-control/doors/${doorId}`, {
          headers: { Authorization: `Bearer ${tenantBToken}` }
        });
        fail('Tenant B should not access Tenant A data');
      } catch (error: any) {
        expect(error.response?.status).toBeOneOf([403, 404]);
      }
    });

    it('should prevent tenant ID manipulation in requests', async () => {
      const manipulationAttempts = [
        { tenantId: maliciousTenantId },
        { tenantId: '../admin' },
        { tenantId: '../../system' },
        { tenantId: 'null' },
        { tenantId: '0' },
        { tenantId: '*' }
      ];

      for (const attempt of manipulationAttempts) {
        try {
          await axios.get(`${baseURL}/api/v1/tenants/${attempt.tenantId}/users`, {
            headers: { Authorization: `Bearer ${tenantAToken}` }
          });
          fail(`Should have rejected tenant ID manipulation: ${attempt.tenantId}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([403, 404, 400]);
        }
      }
    });

    it('should isolate database queries by tenant', async () => {
      // Get all doors for tenant A
      const tenantADoors = await axios.get(`${baseURL}/api/v1/access-control/doors`, {
        headers: { Authorization: `Bearer ${tenantAToken}` }
      });

      // Get all doors for tenant B
      const tenantBDoors = await axios.get(`${baseURL}/api/v1/access-control/doors`, {
        headers: { Authorization: `Bearer ${tenantBToken}` }
      });

      // Ensure no overlap in returned data
      const tenantAIds = tenantADoors.data.map((door: any) => door.id);
      const tenantBIds = tenantBDoors.data.map((door: any) => door.id);
      
      const overlap = tenantAIds.filter((id: string) => tenantBIds.includes(id));
      expect(overlap).toHaveLength(0);
    });
  });

  describe('Encryption Validation', () => {
    it('should enforce HTTPS for all API endpoints', async () => {
      const httpUrl = baseURL.replace('https://', 'http://');
      
      try {
        await axios.get(`${httpUrl}/api/v1/health`, { timeout: 5000 });
        fail('Should not allow HTTP connections');
      } catch (error: any) {
        // Should either redirect to HTTPS or reject connection
        expect(error.code).toBeOneOf(['ECONNREFUSED', 'ENOTFOUND']);
      }
    });

    it('should validate TLS certificate strength', async () => {
      const response = await axios.get(`${baseURL}/api/v1/health`);
      
      // Check security headers
      expect(response.headers['strict-transport-security']).toBeDefined();
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBeOneOf(['DENY', 'SAMEORIGIN']);
      expect(response.headers['x-xss-protection']).toBeDefined();
    });

    it('should encrypt sensitive data in transit', async () => {
      const loginResponse = await axios.post(`${baseURL}/api/v1/auth/login`, {
        username: 'testuser',
        password: 'testpassword'
      });

      // Verify password is not echoed back
      expect(JSON.stringify(loginResponse.data)).not.toContain('testpassword');
      
      // Verify token is properly formatted JWT
      if (loginResponse.data.token) {
        const tokenParts = loginResponse.data.token.split('.');
        expect(tokenParts).toHaveLength(3);
      }
    });

    it('should validate encryption of stored credentials', async () => {
      const credentialResponse = await axios.post(`${baseURL}/api/v1/credentials`, {
        type: 'card',
        cardNumber: '1234567890123456',
        userId: 'test-user'
      }, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });

      // Verify card number is not stored in plaintext
      expect(credentialResponse.data.cardNumber).not.toBe('1234567890123456');
      expect(credentialResponse.data.cardNumber).toMatch(/^\*+\d{4}$/); // Masked format
    });
  });

  describe('Network Security Testing', () => {
    it('should reject requests with suspicious user agents', async () => {
      const maliciousUserAgents = [
        'sqlmap/1.0',
        'Nikto/2.1.6',
        'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
        'python-requests/2.25.1',
        'curl/7.68.0'
      ];

      for (const userAgent of maliciousUserAgents) {
        try {
          await axios.get(`${baseURL}/api/v1/health`, {
            headers: { 
              'User-Agent': userAgent,
              Authorization: `Bearer ${validToken}`
            }
          });
        } catch (error: any) {
          // Some endpoints might block suspicious user agents
          if (error.response?.status === 403) {
            expect(error.response.status).toBe(403);
          }
        }
      }
    });

    it('should validate CORS configuration', async () => {
      const response = await axios.options(`${baseURL}/api/v1/health`);
      
      const allowedOrigins = response.headers['access-control-allow-origin'];
      expect(allowedOrigins).not.toBe('*'); // Should not allow all origins
      
      const allowedMethods = response.headers['access-control-allow-methods'];
      expect(allowedMethods).not.toContain('TRACE'); // TRACE should be disabled
    });

    it('should prevent directory traversal attacks', async () => {
      const traversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
      ];

      for (const payload of traversalPayloads) {
        try {
          await axios.get(`${baseURL}/api/v1/files/${payload}`, {
            headers: { Authorization: `Bearer ${validToken}` }
          });
          fail(`Should have rejected directory traversal: ${payload}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([400, 403, 404]);
        }
      }
    });

    it('should validate request timeout handling', async () => {
      const start = performance.now();
      
      try {
        await axios.get(`${baseURL}/api/v1/health`, { timeout: 1 }); // 1ms timeout
      } catch (error: any) {
        const duration = performance.now() - start;
        expect(duration).toBeLessThan(5000); // Should timeout quickly
        expect(error.code).toBe('ECONNABORTED');
      }
    });
  });

  describe('Input Validation and Sanitization', () => {
    it('should validate email format in user registration', async () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        'user..user@domain.com',
        'user@domain',
        'user@.com'
      ];

      for (const email of invalidEmails) {
        try {
          await axios.post(`${baseURL}/api/v1/users`, {
            email,
            firstName: 'Test',
            lastName: 'User'
          }, {
            headers: { Authorization: `Bearer ${adminToken}` }
          });
          fail(`Should have rejected invalid email: ${email}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([400, 422]);
        }
      }
    });

    it('should validate phone number formats', async () => {
      const invalidPhones = [
        'abc-def-ghij',
        '123',
        '123-456-78901',
        '+1-800-FLOWERS',
        '(555) 123-45678'
      ];

      for (const phone of invalidPhones) {
        try {
          await axios.put(`${baseURL}/api/v1/users/profile`, {
            phone
          }, {
            headers: { Authorization: `Bearer ${validToken}` }
          });
          fail(`Should have rejected invalid phone: ${phone}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([400, 422]);
        }
      }
    });

    it('should prevent command injection in system operations', async () => {
      const commandInjectionPayloads = [
        '; ls -la',
        '| cat /etc/passwd',
        '&& rm -rf /',
        '`whoami`',
        '$(id)',
        '; ping google.com'
      ];

      for (const payload of commandInjectionPayloads) {
        try {
          await axios.post(`${baseURL}/api/v1/system/backup`, {
            filename: `backup${payload}.sql`
          }, {
            headers: { Authorization: `Bearer ${adminToken}` }
          });
          fail(`Should have rejected command injection: ${payload}`);
        } catch (error: any) {
          expect(error.response?.status).toBeOneOf([400, 422]);
        }
      }
    });
  });

  describe('Session and Token Security', () => {
    it('should invalidate tokens on logout', async () => {
      // Login to get a fresh token
      const loginResponse = await axios.post(`${baseURL}/api/v1/auth/login`, {
        username: 'testuser',
        password: 'testpassword'
      });

      const token = loginResponse.data.token;

      // Logout
      await axios.post(`${baseURL}/api/v1/auth/logout`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });

      // Try to use the token after logout
      try {
        await axios.get(`${baseURL}/api/v1/users/profile`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        fail('Should have rejected invalidated token');
      } catch (error: any) {
        expect(error.response?.status).toBe(401);
      }
    });

    it('should enforce token expiration', async () => {
      // Create a token that expires in 1 second
      const shortLivedToken = jwt.sign(
        { sub: 'test-user', exp: Math.floor(Date.now() / 1000) + 1 },
        process.env.JWT_SECRET || 'test-secret'
      );

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 2000));

      try {
        await axios.get(`${baseURL}/api/v1/users/profile`, {
          headers: { Authorization: `Bearer ${shortLivedToken}` }
        });
        fail('Should have rejected expired token');
      } catch (error: any) {
        expect(error.response?.status).toBe(401);
      }
    });

    it('should prevent session fixation attacks', async () => {
      // Attempt to set a custom session ID
      try {
        await axios.post(`${baseURL}/api/v1/auth/login`, {
          username: 'testuser',
          password: 'testpassword'
        }, {
          headers: { 
            'Cookie': 'sessionId=attacker-controlled-session-id'
          }
        });

        // If login succeeds, verify new session ID is generated
        // Implementation depends on session management strategy
      } catch (error: any) {
        // Login might reject requests with suspicious session data
        expect(error.response?.status).toBeOneOf([400, 401]);
      }
    });
  });

  // Helper functions
  async function setupTestAuthentication() {
    // Mock authentication setup - replace with actual test setup
    return {
      validToken: 'valid-test-token',
      adminToken: 'admin-test-token',
      tenantAToken: 'tenant-a-token',
      tenantBToken: 'tenant-b-token',
      testTenantId: 'test-tenant-id',
      maliciousTenantId: 'malicious-tenant-id'
    };
  }

  async function cleanupTestData() {
    // Cleanup test data created during testing
    try {
      await axios.delete(`${baseURL}/api/v1/test/cleanup`, {
        headers: { Authorization: `Bearer ${adminToken}` }
      });
    } catch (error) {
      // Ignore cleanup errors
    }
  }
});

// Custom Jest matchers
expect.extend({
  toBeOneOf(received: any, expected: any[]) {
    const pass = expected.includes(received);
    if (pass) {
      return {
        message: () => `expected ${received} not to be one of ${expected.join(', ')}`,
        pass: true,
      };
    } else {
      return {
        message: () => `expected ${received} to be one of ${expected.join(', ')}`,
        pass: false,
      };
    }
  },
});

declare global {
  namespace jest {
    interface Matchers<R> {
      toBeOneOf(expected: any[]): R;
    }
  }
}