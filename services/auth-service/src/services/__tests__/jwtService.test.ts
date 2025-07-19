import { describe, it, expect, beforeEach, jest, afterEach } from '@jest/globals';
import { JWTService, JWTConfig } from '../jwtService';
import { getSecretsManager } from '../secretsManager';

// Mock the secrets manager
jest.mock('../secretsManager', () => ({
  getSecretsManager: jest.fn(() => ({
    getSecret: jest.fn(),
    rotateSecret: jest.fn(),
    clearCache: jest.fn()
  }))
}));

// Mock logger
jest.mock('@sparc/shared/logging', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
  }
}));

describe('JWTService', () => {
  let jwtService: JWTService;
  let mockSecretsManager: any;
  
  const config: JWTConfig = {
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    issuer: 'test-issuer',
    audience: 'test-audience',
    algorithm: 'HS256'
  };
  
  beforeEach(() => {
    // Reset singleton
    (JWTService as any).instance = undefined;
    
    // Get mock secrets manager
    mockSecretsManager = getSecretsManager();
    
    // Setup default mock implementations
    mockSecretsManager.getSecret.mockImplementation((key: string) => {
      if (key === 'JWT_ACCESS_SECRET') {
        return Promise.resolve('test-access-secret');
      }
      if (key === 'JWT_REFRESH_SECRET') {
        return Promise.resolve('test-refresh-secret');
      }
      return Promise.reject(new Error(`Unknown secret: ${key}`));
    });
    
    jwtService = JWTService.getInstance(config);
  });
  
  afterEach(() => {
    jest.clearAllMocks();
  });
  
  describe('Token Generation', () => {
    it('should generate valid token pairs', async () => {
      // Allow time for initialization
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const tokens = await jwtService.generateTokens(
        'user-123',
        'org-456',
        'test@example.com',
        'USER',
        ['read', 'write']
      );
      
      expect(tokens).toHaveProperty('accessToken');
      expect(tokens).toHaveProperty('refreshToken');
      expect(tokens).toHaveProperty('sessionId');
      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.refreshToken).toBeTruthy();
      expect(tokens.sessionId).toBeTruthy();
    });
    
    it('should generate tokens with custom session ID', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const customSessionId = 'custom-session-123';
      const tokens = await jwtService.generateTokens(
        'user-123',
        'org-456',
        'test@example.com',
        'USER',
        ['read'],
        customSessionId
      );
      
      expect(tokens.sessionId).toBe(customSessionId);
    });
  });
  
  describe('Token Verification', () => {
    it('should verify valid access tokens', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const tokens = await jwtService.generateTokens(
        'user-123',
        'org-456',
        'test@example.com',
        'USER',
        ['read', 'write']
      );
      
      const payload = await jwtService.verifyAccessToken(tokens.accessToken);
      
      expect(payload.sub).toBe('user-123');
      expect(payload.organizationId).toBe('org-456');
      expect(payload.email).toBe('test@example.com');
      expect(payload.role).toBe('USER');
      expect(payload.permissions).toEqual(['read', 'write']);
      expect(payload.type).toBe('access');
    });
    
    it('should verify valid refresh tokens', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const tokens = await jwtService.generateTokens(
        'user-123',
        'org-456',
        'test@example.com',
        'USER',
        ['read']
      );
      
      const payload = await jwtService.verifyRefreshToken(tokens.refreshToken);
      
      expect(payload.sub).toBe('user-123');
      expect(payload.type).toBe('refresh');
      expect(payload.sessionId).toBe(tokens.sessionId);
    });
    
    it('should reject invalid tokens', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const invalidToken = 'invalid.jwt.token';
      
      await expect(jwtService.verifyAccessToken(invalidToken))
        .rejects.toThrow();
      
      await expect(jwtService.verifyRefreshToken(invalidToken))
        .rejects.toThrow();
    });
  });
  
  describe('Secret Rotation', () => {
    it('should rotate secrets successfully', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      await jwtService.rotateSecrets();
      
      expect(mockSecretsManager.rotateSecret).toHaveBeenCalledWith(
        'JWT_ACCESS_SECRET',
        expect.any(String)
      );
      expect(mockSecretsManager.rotateSecret).toHaveBeenCalledWith(
        'JWT_REFRESH_SECRET',
        expect.any(String)
      );
    });
    
    it('should maintain backward compatibility during rotation', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Generate tokens before rotation
      const tokensBeforeRotation = await jwtService.generateTokens(
        'user-123',
        'org-456',
        'test@example.com',
        'USER',
        ['read']
      );
      
      // Rotate secrets
      await jwtService.rotateSecrets();
      
      // Update mock to return new secrets
      mockSecretsManager.getSecret.mockImplementation((key: string) => {
        if (key === 'JWT_ACCESS_SECRET') {
          return Promise.resolve('new-access-secret');
        }
        if (key === 'JWT_REFRESH_SECRET') {
          return Promise.resolve('new-refresh-secret');
        }
        return Promise.reject(new Error(`Unknown secret: ${key}`));
      });
      
      // Old tokens should still be valid during grace period
      const accessPayload = await jwtService.verifyAccessToken(tokensBeforeRotation.accessToken);
      expect(accessPayload.sub).toBe('user-123');
      
      const refreshPayload = await jwtService.verifyRefreshToken(tokensBeforeRotation.refreshToken);
      expect(refreshPayload.sub).toBe('user-123');
      
      // New tokens should use new secrets
      const tokensAfterRotation = await jwtService.generateTokens(
        'user-456',
        'org-789',
        'new@example.com',
        'ADMIN',
        ['admin']
      );
      
      // Verify new tokens work
      const newAccessPayload = await jwtService.verifyAccessToken(tokensAfterRotation.accessToken);
      expect(newAccessPayload.sub).toBe('user-456');
    });
    
    it('should report rotation status correctly', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Before rotation
      let status = jwtService.getRotationStatus();
      expect(status.inRotation).toBe(false);
      expect(status.rotationTimestamp).toBeUndefined();
      expect(status.gracePeriodEnds).toBeUndefined();
      
      // Start rotation
      await jwtService.rotateSecrets();
      
      // During rotation
      status = jwtService.getRotationStatus();
      expect(status.inRotation).toBe(true);
      expect(status.rotationTimestamp).toBeInstanceOf(Date);
      expect(status.gracePeriodEnds).toBeInstanceOf(Date);
      expect(status.gracePeriodEnds!.getTime()).toBeGreaterThan(status.rotationTimestamp!.getTime());
    });
  });
  
  describe('Secret Reloading', () => {
    it('should reload secrets from AWS Secrets Manager', async () => {
      await new Promise(resolve => setTimeout(resolve, 100));
      
      await jwtService.reloadSecrets();
      
      expect(mockSecretsManager.clearCache).toHaveBeenCalledWith('JWT_ACCESS_SECRET');
      expect(mockSecretsManager.clearCache).toHaveBeenCalledWith('JWT_REFRESH_SECRET');
      expect(mockSecretsManager.getSecret).toHaveBeenCalledWith('JWT_ACCESS_SECRET');
      expect(mockSecretsManager.getSecret).toHaveBeenCalledWith('JWT_REFRESH_SECRET');
    });
  });
  
  describe('Error Handling', () => {
    it('should fall back to environment variables if Secrets Manager fails', async () => {
      // Reset singleton
      (JWTService as any).instance = undefined;
      
      // Mock secrets manager to fail
      mockSecretsManager.getSecret.mockRejectedValue(new Error('AWS error'));
      
      // Set environment variables
      process.env.JWT_ACCESS_SECRET = 'env-access-secret';
      process.env.JWT_REFRESH_SECRET = 'env-refresh-secret';
      
      const service = JWTService.getInstance(config);
      
      // Allow time for initialization
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Should still be able to generate tokens using env vars
      const tokens = await service.generateTokens(
        'user-123',
        'org-456',
        'test@example.com',
        'USER',
        ['read']
      );
      
      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.refreshToken).toBeTruthy();
      
      // Clean up
      delete process.env.JWT_ACCESS_SECRET;
      delete process.env.JWT_REFRESH_SECRET;
    });
    
    it('should throw error if no secrets are available', async () => {
      // Reset singleton
      (JWTService as any).instance = undefined;
      
      // Mock secrets manager to fail
      mockSecretsManager.getSecret.mockRejectedValue(new Error('AWS error'));
      
      // Ensure no env vars
      delete process.env.JWT_ACCESS_SECRET;
      delete process.env.JWT_REFRESH_SECRET;
      delete process.env.JWT_SECRET;
      
      expect(() => JWTService.getInstance(config)).not.toThrow(); // Constructor doesn't throw
      
      const service = JWTService.getInstance(config);
      
      // Allow time for initialization to fail
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // Should throw when trying to generate tokens
      await expect(service.generateTokens(
        'user-123',
        'org-456',
        'test@example.com',
        'USER',
        ['read']
      )).rejects.toThrow();
    });
  });
});