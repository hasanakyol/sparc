import { CacheService } from './cacheService';
import { UserSession, AccessTokenPayload, RefreshTokenPayload } from '../types';
import { logger } from '../logger';

export interface SessionCacheConfig {
  ttl?: {
    session?: number;
    accessToken?: number;
    refreshToken?: number;
    blacklist?: number;
  };
  maxConcurrentSessions?: number;
}

export class SessionCache {
  private cache: CacheService;
  private config: SessionCacheConfig;
  private namespace = 'session';

  constructor(cache: CacheService, config: SessionCacheConfig = {}) {
    this.cache = cache;
    this.config = {
      ttl: {
        session: config.ttl?.session || 86400, // 24 hours
        accessToken: config.ttl?.accessToken || 900, // 15 minutes
        refreshToken: config.ttl?.refreshToken || 604800, // 7 days
        blacklist: config.ttl?.blacklist || 604800, // 7 days
      },
      maxConcurrentSessions: config.maxConcurrentSessions || 5,
    };
  }

  /**
   * Get user session
   */
  async getSession(sessionId: string): Promise<UserSession | null> {
    const key = `session:${sessionId}`;
    return this.cache.get<UserSession>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.session,
    });
  }

  /**
   * Set user session
   */
  async setSession(session: UserSession): Promise<boolean> {
    const key = `session:${session.id}`;
    const result = await this.cache.set(key, session, {
      prefix: this.namespace,
      ttl: this.config.ttl?.session,
      tags: [`user:${session.userId}`, `tenant:${session.tenantId}`],
    });

    // Update user's session list
    if (result) {
      await this.addUserSession(session.userId, session.id);
    }

    return result;
  }

  /**
   * Delete session
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);
    if (session) {
      await this.removeUserSession(session.userId, sessionId);
    }

    const key = `session:${sessionId}`;
    return this.cache.delete(key, { prefix: this.namespace });
  }

  /**
   * Get all sessions for a user
   */
  async getUserSessions(userId: string): Promise<string[]> {
    const key = `user:${userId}:sessions`;
    const sessions = await this.cache.get<string[]>(key, {
      prefix: this.namespace,
    });
    return sessions || [];
  }

  /**
   * Add session to user's session list
   */
  private async addUserSession(userId: string, sessionId: string): Promise<void> {
    const key = `user:${userId}:sessions`;
    const sessions = await this.getUserSessions(userId);
    
    // Add new session
    sessions.push(sessionId);
    
    // Enforce max concurrent sessions
    if (sessions.length > this.config.maxConcurrentSessions!) {
      const sessionsToRemove = sessions.slice(0, sessions.length - this.config.maxConcurrentSessions!);
      for (const oldSessionId of sessionsToRemove) {
        await this.deleteSession(oldSessionId);
      }
      sessions.splice(0, sessionsToRemove.length);
    }

    await this.cache.set(key, sessions, {
      prefix: this.namespace,
      ttl: this.config.ttl?.session,
      tags: [`user:${userId}`],
    });
  }

  /**
   * Remove session from user's session list
   */
  private async removeUserSession(userId: string, sessionId: string): Promise<void> {
    const key = `user:${userId}:sessions`;
    const sessions = await this.getUserSessions(userId);
    const filtered = sessions.filter(id => id !== sessionId);
    
    if (filtered.length > 0) {
      await this.cache.set(key, filtered, {
        prefix: this.namespace,
        ttl: this.config.ttl?.session,
        tags: [`user:${userId}`],
      });
    } else {
      await this.cache.delete(key, { prefix: this.namespace });
    }
  }

  /**
   * Invalidate all sessions for a user
   */
  async invalidateUserSessions(userId: string): Promise<number> {
    const sessions = await this.getUserSessions(userId);
    
    for (const sessionId of sessions) {
      await this.deleteSession(sessionId);
    }

    // Clear user's session list
    const key = `user:${userId}:sessions`;
    await this.cache.delete(key, { prefix: this.namespace });

    logger.info('Invalidated user sessions', { userId, count: sessions.length });
    return sessions.length;
  }

  /**
   * Store access token metadata
   */
  async setAccessTokenMetadata(
    tokenId: string,
    metadata: AccessTokenPayload
  ): Promise<boolean> {
    const key = `access:${tokenId}`;
    return this.cache.set(key, metadata, {
      prefix: this.namespace,
      ttl: this.config.ttl?.accessToken,
      tags: [
        `user:${metadata.sub}`,
        `tenant:${metadata.tenantId}`,
        `session:${metadata.sessionId}`,
      ],
    });
  }

  /**
   * Get access token metadata
   */
  async getAccessTokenMetadata(tokenId: string): Promise<AccessTokenPayload | null> {
    const key = `access:${tokenId}`;
    return this.cache.get<AccessTokenPayload>(key, {
      prefix: this.namespace,
    });
  }

  /**
   * Store refresh token metadata
   */
  async setRefreshTokenMetadata(
    tokenId: string,
    metadata: RefreshTokenPayload
  ): Promise<boolean> {
    const key = `refresh:${tokenId}`;
    return this.cache.set(key, metadata, {
      prefix: this.namespace,
      ttl: this.config.ttl?.refreshToken,
      tags: [
        `user:${metadata.sub}`,
        `tenant:${metadata.tenantId}`,
        `session:${metadata.sessionId}`,
      ],
    });
  }

  /**
   * Get refresh token metadata
   */
  async getRefreshTokenMetadata(tokenId: string): Promise<RefreshTokenPayload | null> {
    const key = `refresh:${tokenId}`;
    return this.cache.get<RefreshTokenPayload>(key, {
      prefix: this.namespace,
    });
  }

  /**
   * Delete refresh token
   */
  async deleteRefreshToken(tokenId: string): Promise<boolean> {
    const key = `refresh:${tokenId}`;
    return this.cache.delete(key, { prefix: this.namespace });
  }

  /**
   * Add token to blacklist
   */
  async blacklistToken(tokenId: string, type: 'access' | 'refresh', expiresAt: Date): Promise<boolean> {
    const key = `blacklist:${type}:${tokenId}`;
    const ttl = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));
    
    return this.cache.set(key, { blacklisted: true, type, tokenId }, {
      prefix: this.namespace,
      ttl: Math.min(ttl, this.config.ttl?.blacklist || 604800),
    });
  }

  /**
   * Check if token is blacklisted
   */
  async isTokenBlacklisted(tokenId: string, type: 'access' | 'refresh'): Promise<boolean> {
    const key = `blacklist:${type}:${tokenId}`;
    const result = await this.cache.get(key, { prefix: this.namespace });
    return result !== null;
  }

  /**
   * Update session activity
   */
  async updateSessionActivity(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);
    if (!session) return false;

    session.lastAccessedAt = new Date().toISOString();
    return this.setSession(session);
  }

  /**
   * Get active session count for a tenant
   */
  async getTenantSessionCount(tenantId: string): Promise<number> {
    const key = `tenant:${tenantId}:session:count`;
    const count = await this.cache.get<number>(key, {
      prefix: this.namespace,
    });
    return count || 0;
  }

  /**
   * Update tenant session count
   */
  async updateTenantSessionCount(tenantId: string, delta: number): Promise<void> {
    const key = `tenant:${tenantId}:session:count`;
    const current = await this.getTenantSessionCount(tenantId);
    const newCount = Math.max(0, current + delta);
    
    await this.cache.set(key, newCount, {
      prefix: this.namespace,
      ttl: 3600, // 1 hour
      tags: [`tenant:${tenantId}`],
    });
  }

  /**
   * Store failed login attempt
   */
  async recordFailedLogin(email: string, tenantId: string): Promise<number> {
    const key = `failed:${tenantId}:${email}`;
    const current = await this.cache.get<number>(key, { prefix: this.namespace }) || 0;
    const attempts = current + 1;
    
    await this.cache.set(key, attempts, {
      prefix: this.namespace,
      ttl: 900, // 15 minutes
    });
    
    return attempts;
  }

  /**
   * Clear failed login attempts
   */
  async clearFailedLogins(email: string, tenantId: string): Promise<boolean> {
    const key = `failed:${tenantId}:${email}`;
    return this.cache.delete(key, { prefix: this.namespace });
  }

  /**
   * Get failed login attempts
   */
  async getFailedLoginAttempts(email: string, tenantId: string): Promise<number> {
    const key = `failed:${tenantId}:${email}`;
    const attempts = await this.cache.get<number>(key, { prefix: this.namespace });
    return attempts || 0;
  }

  /**
   * Store device info for session
   */
  async setDeviceInfo(sessionId: string, deviceInfo: any): Promise<boolean> {
    const key = `device:${sessionId}`;
    return this.cache.set(key, deviceInfo, {
      prefix: this.namespace,
      ttl: this.config.ttl?.session,
    });
  }

  /**
   * Get device info for session
   */
  async getDeviceInfo(sessionId: string): Promise<any | null> {
    const key = `device:${sessionId}`;
    return this.cache.get(key, { prefix: this.namespace });
  }

  /**
   * Cleanup expired sessions
   */
  async cleanupExpiredSessions(): Promise<number> {
    // This would typically be handled by Redis TTL, but we can implement
    // additional cleanup logic if needed
    logger.info('Session cleanup completed');
    return 0;
  }

  /**
   * Get session statistics
   */
  async getSessionStats(): Promise<{
    totalSessions: number;
    activeSessions: number;
    blacklistedTokens: number;
  }> {
    // Implementation would depend on tracking these metrics
    return {
      totalSessions: 0,
      activeSessions: 0,
      blacklistedTokens: 0,
    };
  }
}