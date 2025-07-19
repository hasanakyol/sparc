import Redis from 'ioredis';
import { eq, and, or, sql, gt, isNull } from 'drizzle-orm';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import {
  permissions,
  roles,
  rolePermissions,
  userRoles,
  Permission
} from '@sparc/database/schemas/user-management';

export class PermissionService {
  constructor(
    private db: PostgresJsDatabase,
    private redis: Redis
  ) {}

  async listPermissions() {
    // Try cache first
    const cacheKey = 'permissions:all';
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    const allPermissions = await this.db
      .select()
      .from(permissions)
      .orderBy(permissions.resource, permissions.action);

    // Group permissions by resource
    const groupedPermissions = allPermissions.reduce((acc, permission) => {
      if (!acc[permission.resource]) {
        acc[permission.resource] = [];
      }
      acc[permission.resource].push(permission);
      return acc;
    }, {} as Record<string, Permission[]>);

    // Cache for 1 hour (permissions rarely change)
    await this.redis.setex(cacheKey, 3600, JSON.stringify(groupedPermissions));

    return groupedPermissions;
  }

  async getPermissionsByResource(resource: string) {
    const resourcePermissions = await this.db
      .select()
      .from(permissions)
      .where(eq(permissions.resource, resource))
      .orderBy(permissions.action);

    return resourcePermissions;
  }

  async getUserPermissions(userId: string, organizationId: string) {
    // Get user's active roles
    const userRolesData = await this.db
      .select({
        userRole: userRoles,
        role: roles,
        rolePermission: rolePermissions,
        permission: permissions
      })
      .from(userRoles)
      .innerJoin(roles, eq(userRoles.roleId, roles.id))
      .innerJoin(rolePermissions, eq(roles.id, rolePermissions.roleId))
      .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
      .where(
        and(
          eq(userRoles.userId, userId),
          eq(userRoles.organizationId, organizationId),
          eq(userRoles.isActive, true),
          or(
            isNull(userRoles.expiresAt),
            gt(userRoles.expiresAt, new Date())
          )
        )
      );

    // Collect all permissions with their constraints
    const permissionMap = new Map<string, any>();

    userRolesData.forEach(data => {
      const permission = data.permission;
      const key = `${permission.resource}:${permission.action}`;
      
      if (!permissionMap.has(key)) {
        permissionMap.set(key, {
          ...permission,
          constraints: [],
          scopes: []
        });
      }

      const perm = permissionMap.get(key);
      
      // Merge constraints from role-permission mapping
      if (data.rolePermission.constraints) {
        perm.constraints.push(data.rolePermission.constraints);
      }

      // Merge scope from user-role assignment
      if (data.userRole.scope) {
        perm.scopes.push(data.userRole.scope);
      }
    });

    return Array.from(permissionMap.values());
  }

  async checkUserPermission(
    userId: string,
    organizationId: string,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): Promise<boolean> {
    // Cache key for user permissions
    const cacheKey = `user:permissions:${organizationId}:${userId}`;
    let userPermissions: any[];

    // Try cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      userPermissions = JSON.parse(cached);
    } else {
      userPermissions = await this.getUserPermissions(userId, organizationId);
      // Cache for 5 minutes
      await this.redis.setex(cacheKey, 300, JSON.stringify(userPermissions));
    }

    // Check if user has the permission
    const permission = userPermissions.find(
      p => p.resource === resource && p.action === action
    );

    if (!permission) {
      return false;
    }

    // If no context or no constraints/scopes, permission is granted
    if (!context || (permission.constraints.length === 0 && permission.scopes.length === 0)) {
      return true;
    }

    // Check constraints and scopes
    // This is a simplified version - you might want to implement more complex logic
    for (const scope of permission.scopes) {
      if (scope.siteIds && context.siteId && !scope.siteIds.includes(context.siteId)) {
        return false;
      }
      if (scope.zoneIds && context.zoneId && !scope.zoneIds.includes(context.zoneId)) {
        return false;
      }
    }

    return true;
  }

  async seedDefaultPermissions() {
    const defaultPermissions = [
      // User management
      { resource: 'users', action: 'create', description: 'Create new users' },
      { resource: 'users', action: 'read', description: 'View user details' },
      { resource: 'users', action: 'update', description: 'Update user information' },
      { resource: 'users', action: 'delete', description: 'Delete users' },
      { resource: 'users', action: 'list', description: 'List users' },
      { resource: 'users', action: 'activate', description: 'Activate users' },
      { resource: 'users', action: 'deactivate', description: 'Deactivate users' },
      
      // Role management
      { resource: 'roles', action: 'create', description: 'Create new roles' },
      { resource: 'roles', action: 'read', description: 'View role details' },
      { resource: 'roles', action: 'update', description: 'Update roles' },
      { resource: 'roles', action: 'delete', description: 'Delete roles' },
      { resource: 'roles', action: 'list', description: 'List roles' },
      { resource: 'roles', action: 'assign', description: 'Assign roles to users' },
      
      // Camera management
      { resource: 'cameras', action: 'create', description: 'Add new cameras' },
      { resource: 'cameras', action: 'read', description: 'View camera details' },
      { resource: 'cameras', action: 'update', description: 'Update camera settings' },
      { resource: 'cameras', action: 'delete', description: 'Remove cameras' },
      { resource: 'cameras', action: 'list', description: 'List cameras' },
      { resource: 'cameras', action: 'view_stream', description: 'View live camera streams' },
      { resource: 'cameras', action: 'control_ptz', description: 'Control PTZ cameras' },
      
      // Incident management
      { resource: 'incidents', action: 'create', description: 'Create incidents' },
      { resource: 'incidents', action: 'read', description: 'View incident details' },
      { resource: 'incidents', action: 'update', description: 'Update incidents' },
      { resource: 'incidents', action: 'delete', description: 'Delete incidents' },
      { resource: 'incidents', action: 'list', description: 'List incidents' },
      { resource: 'incidents', action: 'assign', description: 'Assign incidents' },
      { resource: 'incidents', action: 'resolve', description: 'Resolve incidents' },
      
      // Access control
      { resource: 'access_control', action: 'manage_doors', description: 'Manage door access' },
      { resource: 'access_control', action: 'view_events', description: 'View access events' },
      { resource: 'access_control', action: 'manage_credentials', description: 'Manage access credentials' },
      { resource: 'access_control', action: 'override', description: 'Override access controls' },
      
      // Analytics
      { resource: 'analytics', action: 'view_reports', description: 'View analytics reports' },
      { resource: 'analytics', action: 'create_reports', description: 'Create custom reports' },
      { resource: 'analytics', action: 'export_data', description: 'Export analytics data' },
      
      // System settings
      { resource: 'system', action: 'manage_settings', description: 'Manage system settings' },
      { resource: 'system', action: 'view_audit_logs', description: 'View audit logs' },
      { resource: 'system', action: 'manage_integrations', description: 'Manage integrations' },
      { resource: 'system', action: 'backup_restore', description: 'Backup and restore system' }
    ];

    // Insert permissions that don't exist
    for (const permission of defaultPermissions) {
      // Check if permission exists
      const [existing] = await this.db
        .select()
        .from(permissions)
        .where(
          and(
            eq(permissions.resource, permission.resource),
            eq(permissions.action, permission.action)
          )
        )
        .limit(1);

      if (!existing) {
        await this.db
          .insert(permissions)
          .values(permission);
      } else if (existing.description !== permission.description) {
        // Update description if different
        await this.db
          .update(permissions)
          .set({ description: permission.description })
          .where(
            and(
              eq(permissions.resource, permission.resource),
              eq(permissions.action, permission.action)
            )
          );
      }
    }

    // Clear cache
    await this.redis.del('permissions:all');
  }
}