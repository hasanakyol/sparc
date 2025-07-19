import { CacheService } from './cacheService';
import { PermissionStructure, AccessGroup, Schedule } from '../types';
import { logger } from '../logger';

export interface PermissionCacheConfig {
  ttl?: {
    userPermissions?: number;
    rolePermissions?: number;
    accessGroup?: number;
    schedule?: number;
    doorAccess?: number;
  };
}

export class PermissionCache {
  private cache: CacheService;
  private config: PermissionCacheConfig;
  private namespace = 'permission';

  constructor(cache: CacheService, config: PermissionCacheConfig = {}) {
    this.cache = cache;
    this.config = {
      ttl: {
        userPermissions: config.ttl?.userPermissions || 1800, // 30 minutes
        rolePermissions: config.ttl?.rolePermissions || 3600, // 1 hour
        accessGroup: config.ttl?.accessGroup || 3600, // 1 hour
        schedule: config.ttl?.schedule || 3600, // 1 hour
        doorAccess: config.ttl?.doorAccess || 900, // 15 minutes
      },
    };
  }

  /**
   * Get user permissions
   */
  async getUserPermissions(userId: string, tenantId: string): Promise<PermissionStructure | null> {
    const key = `user:${tenantId}:${userId}:permissions`;
    return this.cache.get<PermissionStructure>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.userPermissions,
      tags: [`user:${userId}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Set user permissions
   */
  async setUserPermissions(
    userId: string,
    tenantId: string,
    permissions: PermissionStructure
  ): Promise<boolean> {
    const key = `user:${tenantId}:${userId}:permissions`;
    return this.cache.set(key, permissions, {
      prefix: this.namespace,
      ttl: this.config.ttl?.userPermissions,
      tags: [`user:${userId}`, `tenant:${tenantId}`, `role:${permissions.role}`],
    });
  }

  /**
   * Get role permissions
   */
  async getRolePermissions(role: string, tenantId: string): Promise<PermissionStructure | null> {
    const key = `role:${tenantId}:${role}:permissions`;
    return this.cache.get<PermissionStructure>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.rolePermissions,
      tags: [`role:${role}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Set role permissions
   */
  async setRolePermissions(
    role: string,
    tenantId: string,
    permissions: PermissionStructure
  ): Promise<boolean> {
    const key = `role:${tenantId}:${role}:permissions`;
    return this.cache.set(key, permissions, {
      prefix: this.namespace,
      ttl: this.config.ttl?.rolePermissions,
      tags: [`role:${role}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Get access group
   */
  async getAccessGroup(groupId: string): Promise<AccessGroup | null> {
    const key = `group:${groupId}`;
    return this.cache.get<AccessGroup>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.accessGroup,
      tags: [`group:${groupId}`],
    });
  }

  /**
   * Set access group
   */
  async setAccessGroup(group: AccessGroup): Promise<boolean> {
    const key = `group:${group.id}`;
    return this.cache.set(key, group, {
      prefix: this.namespace,
      ttl: this.config.ttl?.accessGroup,
      tags: [`group:${group.id}`, `tenant:${group.tenant_id}`],
    });
  }

  /**
   * Get user's access groups
   */
  async getUserAccessGroups(userId: string, tenantId: string): Promise<string[] | null> {
    const key = `user:${tenantId}:${userId}:groups`;
    return this.cache.get<string[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.accessGroup,
      tags: [`user:${userId}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Set user's access groups
   */
  async setUserAccessGroups(
    userId: string,
    tenantId: string,
    groupIds: string[]
  ): Promise<boolean> {
    const key = `user:${tenantId}:${userId}:groups`;
    return this.cache.set(key, groupIds, {
      prefix: this.namespace,
      ttl: this.config.ttl?.accessGroup,
      tags: [`user:${userId}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Get schedule
   */
  async getSchedule(scheduleId: string): Promise<Schedule | null> {
    const key = `schedule:${scheduleId}`;
    return this.cache.get<Schedule>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.schedule,
      tags: [`schedule:${scheduleId}`],
    });
  }

  /**
   * Set schedule
   */
  async setSchedule(schedule: Schedule): Promise<boolean> {
    const key = `schedule:${schedule.id}`;
    return this.cache.set(key, schedule, {
      prefix: this.namespace,
      ttl: this.config.ttl?.schedule,
      tags: [`schedule:${schedule.id}`, `tenant:${schedule.tenant_id}`],
    });
  }

  /**
   * Check if user has access to a door at current time
   */
  async getUserDoorAccess(
    userId: string,
    doorId: string,
    tenantId: string
  ): Promise<boolean | null> {
    const key = `access:${tenantId}:${userId}:door:${doorId}`;
    return this.cache.get<boolean>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.doorAccess,
    });
  }

  /**
   * Set user door access
   */
  async setUserDoorAccess(
    userId: string,
    doorId: string,
    tenantId: string,
    hasAccess: boolean
  ): Promise<boolean> {
    const key = `access:${tenantId}:${userId}:door:${doorId}`;
    return this.cache.set(key, hasAccess, {
      prefix: this.namespace,
      ttl: this.config.ttl?.doorAccess,
      tags: [`user:${userId}`, `door:${doorId}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Get effective permissions for a user (combined from roles and direct permissions)
   */
  async getEffectivePermissions(
    userId: string,
    tenantId: string
  ): Promise<PermissionStructure | null> {
    const key = `effective:${tenantId}:${userId}:permissions`;
    return this.cache.get<PermissionStructure>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.userPermissions,
      tags: [`user:${userId}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Set effective permissions
   */
  async setEffectivePermissions(
    userId: string,
    tenantId: string,
    permissions: PermissionStructure
  ): Promise<boolean> {
    const key = `effective:${tenantId}:${userId}:permissions`;
    return this.cache.set(key, permissions, {
      prefix: this.namespace,
      ttl: this.config.ttl?.userPermissions,
      tags: [`user:${userId}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Get door schedules
   */
  async getDoorSchedules(doorId: string): Promise<string[] | null> {
    const key = `door:${doorId}:schedules`;
    return this.cache.get<string[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.schedule,
      tags: [`door:${doorId}`],
    });
  }

  /**
   * Set door schedules
   */
  async setDoorSchedules(doorId: string, scheduleIds: string[]): Promise<boolean> {
    const key = `door:${doorId}:schedules`;
    return this.cache.set(key, scheduleIds, {
      prefix: this.namespace,
      ttl: this.config.ttl?.schedule,
      tags: [`door:${doorId}`],
    });
  }

  /**
   * Invalidate user permissions
   */
  async invalidateUserPermissions(userId: string): Promise<void> {
    await this.cache.invalidateByTags([`user:${userId}`]);
    logger.info('Invalidated user permissions cache', { userId });
  }

  /**
   * Invalidate role permissions
   */
  async invalidateRolePermissions(role: string): Promise<void> {
    await this.cache.invalidateByTags([`role:${role}`]);
    logger.info('Invalidated role permissions cache', { role });
  }

  /**
   * Invalidate access group
   */
  async invalidateAccessGroup(groupId: string): Promise<void> {
    await this.cache.invalidateByTags([`group:${groupId}`]);
    logger.info('Invalidated access group cache', { groupId });
  }

  /**
   * Invalidate door access
   */
  async invalidateDoorAccess(doorId: string): Promise<void> {
    await this.cache.invalidateByTags([`door:${doorId}`]);
    logger.info('Invalidated door access cache', { doorId });
  }

  /**
   * Batch check door access for multiple doors
   */
  async batchCheckDoorAccess(
    userId: string,
    doorIds: string[],
    tenantId: string
  ): Promise<Record<string, boolean | null>> {
    const keys = doorIds.map(doorId => `access:${tenantId}:${userId}:door:${doorId}`);
    const results = await this.cache.mget<boolean>(keys, { prefix: this.namespace });
    
    const accessMap: Record<string, boolean | null> = {};
    doorIds.forEach((doorId, index) => {
      accessMap[doorId] = results[index];
    });
    
    return accessMap;
  }

  /**
   * Cache permission check result
   */
  async cachePermissionCheck(
    userId: string,
    tenantId: string,
    resource: string,
    action: string,
    allowed: boolean
  ): Promise<boolean> {
    const key = `check:${tenantId}:${userId}:${resource}:${action}`;
    return this.cache.set(key, allowed, {
      prefix: this.namespace,
      ttl: 300, // 5 minutes
      tags: [`user:${userId}`, `tenant:${tenantId}`],
    });
  }

  /**
   * Get cached permission check result
   */
  async getCachedPermissionCheck(
    userId: string,
    tenantId: string,
    resource: string,
    action: string
  ): Promise<boolean | null> {
    const key = `check:${tenantId}:${userId}:${resource}:${action}`;
    return this.cache.get<boolean>(key, { prefix: this.namespace });
  }

  /**
   * Warm up permissions cache
   */
  async warmup(data: {
    userPermissions?: Array<{ userId: string; tenantId: string; permissions: PermissionStructure }>;
    rolePermissions?: Array<{ role: string; tenantId: string; permissions: PermissionStructure }>;
    accessGroups?: AccessGroup[];
    schedules?: Schedule[];
  }): Promise<void> {
    const operations = [];

    if (data.userPermissions) {
      for (const item of data.userPermissions) {
        operations.push(
          this.setUserPermissions(item.userId, item.tenantId, item.permissions)
        );
      }
    }

    if (data.rolePermissions) {
      for (const item of data.rolePermissions) {
        operations.push(
          this.setRolePermissions(item.role, item.tenantId, item.permissions)
        );
      }
    }

    if (data.accessGroups) {
      for (const group of data.accessGroups) {
        operations.push(this.setAccessGroup(group));
      }
    }

    if (data.schedules) {
      for (const schedule of data.schedules) {
        operations.push(this.setSchedule(schedule));
      }
    }

    await Promise.all(operations);
    logger.info('Permission cache warmed up', {
      userPermissions: data.userPermissions?.length || 0,
      rolePermissions: data.rolePermissions?.length || 0,
      accessGroups: data.accessGroups?.length || 0,
      schedules: data.schedules?.length || 0,
    });
  }
}