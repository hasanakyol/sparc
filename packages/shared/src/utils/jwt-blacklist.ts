import { Redis } from 'ioredis';
import jwt from 'jsonwebtoken';

export interface BlacklistOptions {
  redis: Redis;
  keyPrefix?: string;
  defaultTTL?: number; // seconds
}

export interface JWTPayload {
  userId: string;
  tenantId: string;
  sessionId?: string;
  exp?: number;
  iat?: number;
  jti?: string;
}

export class JWTBlacklistService {
  private redis: Redis;
  private keyPrefix: string;
  private defaultTTL: number;

  constructor(options: BlacklistOptions) {
    this.redis = options.redis;
    this.keyPrefix = options.keyPrefix || 'blacklist';
    this.defaultTTL = options.defaultTTL || 86400; // 24 hours default
  }

  /**
   * Blacklist a JWT token
   */
  async blacklistToken(token: string, reason?: string): Promise<void> {
    try {
      // Decode token to get expiration
      const decoded = jwt.decode(token) as JWTPayload;
      if (!decoded) {
        throw new Error('Invalid token format');
      }

      const key = `${this.keyPrefix}:${token}`;
      const ttl = decoded.exp 
        ? Math.max(decoded.exp - Math.floor(Date.now() / 1000), 0)
        : this.defaultTTL;

      // Store blacklist entry with reason and metadata
      const blacklistData = {
        reason: reason || 'User logout',
        userId: decoded.userId,
        tenantId: decoded.tenantId,
        sessionId: decoded.sessionId,
        blacklistedAt: new Date().toISOString()
      };

      if (ttl > 0) {
        await this.redis.setex(key, ttl, JSON.stringify(blacklistData));
      }
    } catch (error) {
      throw new Error(`Failed to blacklist token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Check if a token is blacklisted
   */
  async isBlacklisted(token: string): Promise<boolean> {
    try {
      const key = `${this.keyPrefix}:${token}`;
      const exists = await this.redis.exists(key);
      return exists === 1;
    } catch (error) {
      // In case of Redis error, fail closed (treat as blacklisted)
      console.error('Error checking token blacklist:', error);
      return true;
    }
  }

  /**
   * Get blacklist information for a token
   */
  async getBlacklistInfo(token: string): Promise<any | null> {
    try {
      const key = `${this.keyPrefix}:${token}`;
      const data = await this.redis.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Blacklist all tokens for a user
   */
  async blacklistUserTokens(userId: string, tenantId: string, reason?: string): Promise<number> {
    try {
      // Get all user sessions
      const sessionPattern = `session:${userId}:${tenantId}:*`;
      const sessionKeys = await this.redis.keys(sessionPattern);
      
      let blacklistedCount = 0;
      
      for (const sessionKey of sessionKeys) {
        const sessionData = await this.redis.get(sessionKey);
        if (sessionData) {
          try {
            const session = JSON.parse(sessionData);
            if (session.accessToken) {
              await this.blacklistToken(session.accessToken, reason || 'User tokens revoked');
              blacklistedCount++;
            }
            if (session.refreshToken) {
              await this.blacklistToken(session.refreshToken, reason || 'User tokens revoked');
              blacklistedCount++;
            }
          } catch (parseError) {
            console.error('Error parsing session data:', parseError);
          }
        }
      }
      
      // Also blacklist by user ID pattern (if tokens are stored separately)
      const tokenPattern = `token:${userId}:${tenantId}:*`;
      const tokenKeys = await this.redis.keys(tokenPattern);
      
      for (const tokenKey of tokenKeys) {
        const token = await this.redis.get(tokenKey);
        if (token) {
          await this.blacklistToken(token, reason || 'User tokens revoked');
          blacklistedCount++;
        }
      }
      
      return blacklistedCount;
    } catch (error) {
      throw new Error(`Failed to blacklist user tokens: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Blacklist all tokens for a session
   */
  async blacklistSessionTokens(userId: string, tenantId: string, sessionId: string, reason?: string): Promise<void> {
    try {
      const sessionKey = `session:${userId}:${tenantId}:${sessionId}`;
      const sessionData = await this.redis.get(sessionKey);
      
      if (sessionData) {
        const session = JSON.parse(sessionData);
        if (session.accessToken) {
          await this.blacklistToken(session.accessToken, reason || 'Session revoked');
        }
        if (session.refreshToken) {
          await this.blacklistToken(session.refreshToken, reason || 'Session revoked');
        }
      }
    } catch (error) {
      throw new Error(`Failed to blacklist session tokens: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Clean up expired blacklist entries
   */
  async cleanup(): Promise<number> {
    try {
      const pattern = `${this.keyPrefix}:*`;
      const keys = await this.redis.keys(pattern);
      let cleaned = 0;
      
      for (const key of keys) {
        const ttl = await this.redis.ttl(key);
        if (ttl === -1) {
          // No expiration set, check token expiration
          const token = key.replace(`${this.keyPrefix}:`, '');
          try {
            const decoded = jwt.decode(token) as JWTPayload;
            if (decoded?.exp && decoded.exp < Math.floor(Date.now() / 1000)) {
              await this.redis.del(key);
              cleaned++;
            }
          } catch {
            // Invalid token, remove from blacklist
            await this.redis.del(key);
            cleaned++;
          }
        }
      }
      
      return cleaned;
    } catch (error) {
      throw new Error(`Failed to cleanup blacklist: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get blacklist statistics
   */
  async getStats(): Promise<{
    totalBlacklisted: number;
    byUser: Record<string, number>;
    byTenant: Record<string, number>;
    byReason: Record<string, number>;
  }> {
    try {
      const pattern = `${this.keyPrefix}:*`;
      const keys = await this.redis.keys(pattern);
      
      const stats = {
        totalBlacklisted: keys.length,
        byUser: {} as Record<string, number>,
        byTenant: {} as Record<string, number>,
        byReason: {} as Record<string, number>
      };
      
      for (const key of keys) {
        const data = await this.redis.get(key);
        if (data) {
          try {
            const blacklistInfo = JSON.parse(data);
            
            // Count by user
            if (blacklistInfo.userId) {
              stats.byUser[blacklistInfo.userId] = (stats.byUser[blacklistInfo.userId] || 0) + 1;
            }
            
            // Count by tenant
            if (blacklistInfo.tenantId) {
              stats.byTenant[blacklistInfo.tenantId] = (stats.byTenant[blacklistInfo.tenantId] || 0) + 1;
            }
            
            // Count by reason
            const reason = blacklistInfo.reason || 'Unknown';
            stats.byReason[reason] = (stats.byReason[reason] || 0) + 1;
          } catch {
            // Ignore parse errors
          }
        }
      }
      
      return stats;
    } catch (error) {
      throw new Error(`Failed to get blacklist stats: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

// Express/Hono middleware factory
export function createBlacklistMiddleware(blacklistService: JWTBlacklistService) {
  return async (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }
    
    const token = authHeader.substring(7);
    
    try {
      const isBlacklisted = await blacklistService.isBlacklisted(token);
      
      if (isBlacklisted) {
        return res.status(401).json({
          error: 'TOKEN_REVOKED',
          message: 'Token has been revoked'
        });
      }
      
      next();
    } catch (error) {
      // Fail closed - deny access on error
      return res.status(503).json({
        error: 'SERVICE_UNAVAILABLE',
        message: 'Unable to verify token status'
      });
    }
  };
}