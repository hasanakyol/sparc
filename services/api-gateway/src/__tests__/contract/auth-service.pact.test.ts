import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { Pact } from '@pact-foundation/pact';
import { like, term, eachLike } from '@pact-foundation/pact/src/dsl/matchers';
import path from 'path';
import { sign } from 'hono/jwt';

// Mock service client for testing
class AuthServiceClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  async login(email: string, password: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    
    if (!response.ok) {
      throw new Error(`Login failed: ${response.statusText}`);
    }
    
    return response.json();
  }

  async validateToken(token: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}/auth/validate`, {
      headers: { 
        'Authorization': `Bearer ${token}`,
      },
    });
    
    if (!response.ok) {
      throw new Error(`Token validation failed: ${response.statusText}`);
    }
    
    return response.json();
  }

  async logout(token: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}/auth/logout`, {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${token}`,
      },
    });
    
    if (!response.ok) {
      throw new Error(`Logout failed: ${response.statusText}`);
    }
    
    return response.json();
  }

  async refreshToken(refreshToken: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    
    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.statusText}`);
    }
    
    return response.json();
  }
}

describe('API Gateway → Auth Service Contract', () => {
  const provider = new Pact({
    consumer: 'api-gateway',
    provider: 'auth-service',
    port: 8091,
    log: path.resolve(process.cwd(), 'logs', 'pact.log'),
    dir: path.resolve(process.cwd(), 'pacts'),
    logLevel: 'warn',
  });

  let client: AuthServiceClient;

  beforeAll(async () => {
    await provider.setup();
    client = new AuthServiceClient(provider.mockService.baseUrl);
  });

  afterAll(async () => {
    await provider.finalize();
  });

  describe('Authentication Flow', () => {
    it('should handle successful login', async () => {
      const email = 'test@example.com';
      const password = 'password123';

      await provider.addInteraction({
        state: 'user exists with valid credentials',
        uponReceiving: 'a login request with valid credentials',
        withRequest: {
          method: 'POST',
          path: '/auth/login',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            email,
            password,
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: {
              user: {
                id: like('user-123'),
                email,
                name: like('Test User'),
                tenantId: like('tenant-456'),
                organizationId: like('org-789'),
                roles: eachLike('user'),
                permissions: eachLike('read'),
              },
              tokens: {
                accessToken: term({
                  matcher: '^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$',
                  generate: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                }),
                refreshToken: term({
                  matcher: '^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$',
                  generate: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsInR5cGUiOiJyZWZyZXNoIiwiaWF0IjoxNTE2MjM5MDIyfQ.dBjftJeZ83CVx6Qc0tXcgOJdHp5r7JQpCMwCPYnFbSQ',
                }),
                expiresIn: like(900),
                tokenType: 'Bearer',
              },
            },
          },
        },
      });

      const response = await client.login(email, password);

      expect(response.success).toBe(true);
      expect(response.data.user.email).toBe(email);
      expect(response.data.tokens.accessToken).toMatch(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/);
      expect(response.data.tokens.tokenType).toBe('Bearer');
    });

    it('should handle failed login with invalid credentials', async () => {
      await provider.addInteraction({
        state: 'user exists',
        uponReceiving: 'a login request with invalid credentials',
        withRequest: {
          method: 'POST',
          path: '/auth/login',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            email: 'test@example.com',
            password: 'wrong-password',
          },
        },
        willRespondWith: {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: false,
            error: 'Invalid credentials',
            code: 'AUTH_INVALID_CREDENTIALS',
          },
        },
      });

      try {
        await client.login('test@example.com', 'wrong-password');
        fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toContain('Login failed');
      }
    });

    it('should handle token validation', async () => {
      const validToken = await sign({
        sub: 'user-123',
        email: 'test@example.com',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 900,
      }, 'test-secret');

      await provider.addInteraction({
        state: 'user has valid session',
        uponReceiving: 'a token validation request',
        withRequest: {
          method: 'GET',
          path: '/auth/validate',
          headers: {
            Authorization: term({
              matcher: '^Bearer [A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$',
              generate: `Bearer ${validToken}`,
            }),
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            valid: true,
            user: {
              id: like('user-123'),
              email: like('test@example.com'),
              tenantId: like('tenant-456'),
              roles: eachLike('user'),
              permissions: eachLike('read'),
            },
          },
        },
      });

      const response = await client.validateToken(validToken);

      expect(response.valid).toBe(true);
      expect(response.user).toBeDefined();
      expect(response.user.email).toBeTruthy();
    });

    it('should handle token refresh', async () => {
      const refreshToken = 'valid-refresh-token';

      await provider.addInteraction({
        state: 'user has valid refresh token',
        uponReceiving: 'a token refresh request',
        withRequest: {
          method: 'POST',
          path: '/auth/refresh',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            refreshToken,
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: {
              accessToken: term({
                matcher: '^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$',
                generate: 'new.access.token',
              }),
              refreshToken: term({
                matcher: '^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$',
                generate: 'new.refresh.token',
              }),
              expiresIn: like(900),
              tokenType: 'Bearer',
            },
          },
        },
      });

      const response = await client.refreshToken(refreshToken);

      expect(response.success).toBe(true);
      expect(response.data.accessToken).toBeTruthy();
      expect(response.data.refreshToken).toBeTruthy();
      expect(response.data.tokenType).toBe('Bearer');
    });

    it('should handle logout', async () => {
      const token = 'valid-access-token';

      await provider.addInteraction({
        state: 'user is logged in',
        uponReceiving: 'a logout request',
        withRequest: {
          method: 'POST',
          path: '/auth/logout',
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            message: 'Logged out successfully',
          },
        },
      });

      const response = await client.logout(token);

      expect(response.success).toBe(true);
      expect(response.message).toBe('Logged out successfully');
    });
  });

  describe('Error Scenarios', () => {
    it('should handle user not found', async () => {
      await provider.addInteraction({
        state: 'user does not exist',
        uponReceiving: 'a login request for non-existent user',
        withRequest: {
          method: 'POST',
          path: '/auth/login',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            email: 'nonexistent@example.com',
            password: 'password123',
          },
        },
        willRespondWith: {
          status: 404,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: false,
            error: 'User not found',
            code: 'AUTH_USER_NOT_FOUND',
          },
        },
      });

      try {
        await client.login('nonexistent@example.com', 'password123');
        fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toContain('Login failed');
      }
    });

    it('should handle account locked', async () => {
      await provider.addInteraction({
        state: 'user account is locked',
        uponReceiving: 'a login request for locked account',
        withRequest: {
          method: 'POST',
          path: '/auth/login',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            email: 'locked@example.com',
            password: 'password123',
          },
        },
        willRespondWith: {
          status: 423,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: false,
            error: 'Account is locked',
            code: 'AUTH_ACCOUNT_LOCKED',
            lockedUntil: like('2024-01-01T00:00:00Z'),
          },
        },
      });

      try {
        await client.login('locked@example.com', 'password123');
        fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toContain('Login failed');
      }
    });

    it('should handle expired refresh token', async () => {
      await provider.addInteraction({
        state: 'refresh token is expired',
        uponReceiving: 'a token refresh request with expired token',
        withRequest: {
          method: 'POST',
          path: '/auth/refresh',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            refreshToken: 'expired-refresh-token',
          },
        },
        willRespondWith: {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: false,
            error: 'Refresh token expired',
            code: 'AUTH_REFRESH_TOKEN_EXPIRED',
          },
        },
      });

      try {
        await client.refreshToken('expired-refresh-token');
        fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).toContain('Token refresh failed');
      }
    });
  });

  describe('Multi-tenant Scenarios', () => {
    it('should include tenant information in login response', async () => {
      await provider.addInteraction({
        state: 'user belongs to multiple tenants',
        uponReceiving: 'a login request from multi-tenant user',
        withRequest: {
          method: 'POST',
          path: '/auth/login',
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            email: 'multitenant@example.com',
            password: 'password123',
          },
        },
        willRespondWith: {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
          },
          body: {
            success: true,
            data: {
              user: {
                id: like('user-456'),
                email: 'multitenant@example.com',
                name: like('Multi Tenant User'),
                tenants: eachLike({
                  id: like('tenant-001'),
                  name: like('Tenant One'),
                  role: like('admin'),
                }),
              },
              requiresTenantSelection: true,
              tokens: {
                temporaryToken: like('temp-token'),
                expiresIn: like(300),
              },
            },
          },
        },
      });

      const response = await client.login('multitenant@example.com', 'password123');

      expect(response.success).toBe(true);
      expect(response.data.requiresTenantSelection).toBe(true);
      expect(response.data.user.tenants).toBeDefined();
      expect(response.data.user.tenants.length).toBeGreaterThan(0);
    });
  });
});