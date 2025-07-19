import { HTTPException } from 'hono/http-exception';
import Redis from 'ioredis';
import { eq, and, or, like, ilike, sql, not } from 'drizzle-orm';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import { PrismaClient } from '@prisma/client';
import {
  CreateRoleInput,
  UpdateRoleInput,
  RoleQueryInput,
  AssignRolesInput
} from '../types/schemas';
import {
  roles,
  permissions,
  rolePermissions,
  userRoles,
  userAuditLog,
  usersExtended,
  Role,
  NewRole,
  RolePermission,
  NewRolePermission,
  UserRole,
  NewUserRole
} from '@sparc/database/schemas/user-management';

export class RoleService {
  constructor(
    private db: PostgresJsDatabase,
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async createRole(data: CreateRoleInput & { organizationId: string }, createdBy: string) {
    // Check if role name already exists
    const [existingRole] = await this.db
      .select()
      .from(roles)
      .where(
        and(
          eq(roles.organizationId, data.organizationId),
          eq(roles.name, data.name)
        )
      )
      .limit(1);

    if (existingRole) {
      throw new HTTPException(409, { message: 'Role with this name already exists' });
    }

    // Verify permissions exist
    const validPermissions = await this.db
      .select()
      .from(permissions)
      .where(sql`${permissions.id} = ANY(${data.permissionIds})`);

    if (validPermissions.length !== data.permissionIds.length) {
      throw new HTTPException(400, { message: 'One or more invalid permission IDs' });
    }

    // Create role
    const [role] = await this.db
      .insert(roles)
      .values({
        organizationId: data.organizationId,
        name: data.name,
        description: data.description,
        isDefault: data.isDefault,
        metadata: data.metadata || {},
        createdBy,
        updatedBy: createdBy
      })
      .returning();

    // Assign permissions
    if (data.permissionIds.length > 0) {
      await this.db
        .insert(rolePermissions)
        .values(
          data.permissionIds.map(permissionId => ({
            roleId: role.id,
            permissionId,
            grantedBy: createdBy
          }))
        );
    }

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId: createdBy,
        organizationId: data.organizationId,
        action: 'created',
        entityType: 'role',
        entityId: role.id,
        metadata: {
          roleName: role.name,
          permissions: data.permissionIds
        },
        performedBy: createdBy
      });

    // Invalidate cache
    await this.invalidateRoleCache(data.organizationId);

    return {
      ...role,
      permissions: validPermissions
    };
  }

  async updateRole(roleId: string, organizationId: string, data: UpdateRoleInput, updatedBy: string) {
    const role = await this.getRoleById(roleId, organizationId);
    if (!role) {
      throw new HTTPException(404, { message: 'Role not found' });
    }

    if (role.isSystem) {
      throw new HTTPException(403, { message: 'System roles cannot be modified' });
    }

    // Check if new name conflicts
    if (data.name && data.name !== role.name) {
      const [existingRole] = await this.db
        .select()
        .from(roles)
        .where(
          and(
            eq(roles.organizationId, organizationId),
            eq(roles.name, data.name),
            not(eq(roles.id, roleId))
          )
        )
        .limit(1);

      if (existingRole) {
        throw new HTTPException(409, { message: 'Role with this name already exists' });
      }
    }

    const changes: Record<string, any> = {};
    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined && key !== 'permissionIds' && value !== (role as any)[key]) {
        changes[key] = { from: (role as any)[key], to: value };
      }
    });

    // Update role
    const [updatedRole] = await this.db
      .update(roles)
      .set({
        name: data.name,
        description: data.description,
        isDefault: data.isDefault,
        metadata: data.metadata,
        updatedBy,
        updatedAt: new Date()
      })
      .where(eq(roles.id, roleId))
      .returning();

    // Update permissions if provided
    if (data.permissionIds) {
      // Verify permissions exist
      const validPermissions = await this.db
        .select()
        .from(permissions)
        .where(sql`${permissions.id} = ANY(${data.permissionIds})`);

      if (validPermissions.length !== data.permissionIds.length) {
        throw new HTTPException(400, { message: 'One or more invalid permission IDs' });
      }

      // Get current permissions
      const currentPermissions = await this.db
        .select()
        .from(rolePermissions)
        .where(eq(rolePermissions.roleId, roleId));

      const currentPermissionIds = currentPermissions.map(p => p.permissionId);
      const toAdd = data.permissionIds.filter(id => !currentPermissionIds.includes(id));
      const toRemove = currentPermissionIds.filter(id => !data.permissionIds.includes(id));

      // Remove permissions
      if (toRemove.length > 0) {
        await this.db
          .delete(rolePermissions)
          .where(
            and(
              eq(rolePermissions.roleId, roleId),
              sql`${rolePermissions.permissionId} = ANY(${toRemove})`
            )
          );
      }

      // Add permissions
      if (toAdd.length > 0) {
        await this.db
          .insert(rolePermissions)
          .values(
            toAdd.map(permissionId => ({
              roleId,
              permissionId,
              grantedBy: updatedBy
            }))
          );
      }

      changes.permissions = {
        added: toAdd,
        removed: toRemove
      };
    }

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId: updatedBy,
        organizationId,
        action: 'updated',
        entityType: 'role',
        entityId: roleId,
        changes,
        performedBy: updatedBy
      });

    // Invalidate cache
    await this.invalidateRoleCache(organizationId, roleId);

    return updatedRole;
  }

  async deleteRole(roleId: string, organizationId: string, deletedBy: string) {
    const role = await this.getRoleById(roleId, organizationId);
    if (!role) {
      throw new HTTPException(404, { message: 'Role not found' });
    }

    if (role.isSystem) {
      throw new HTTPException(403, { message: 'System roles cannot be deleted' });
    }

    // Check if role is assigned to any users
    const [{ count }] = await this.db
      .select({ count: sql<number>`count(*)` })
      .from(userRoles)
      .where(
        and(
          eq(userRoles.roleId, roleId),
          eq(userRoles.organizationId, organizationId),
          eq(userRoles.isActive, true)
        )
      );

    if (Number(count) > 0) {
      throw new HTTPException(400, { 
        message: `Cannot delete role. It is assigned to ${count} user(s).` 
      });
    }

    // Delete role (cascade will handle rolePermissions)
    await this.db
      .delete(roles)
      .where(eq(roles.id, roleId));

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId: deletedBy,
        organizationId,
        action: 'deleted',
        entityType: 'role',
        entityId: roleId,
        metadata: { roleName: role.name },
        performedBy: deletedBy
      });

    // Invalidate cache
    await this.invalidateRoleCache(organizationId, roleId);
  }

  async getRoleById(roleId: string, organizationId: string) {
    const cacheKey = `role:${organizationId}:${roleId}`;
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    const [role] = await this.db
      .select()
      .from(roles)
      .where(
        and(
          eq(roles.id, roleId),
          eq(roles.organizationId, organizationId)
        )
      )
      .limit(1);

    if (!role) return null;

    // Get permissions
    const rolePermissionsData = await this.db
      .select({
        permission: permissions
      })
      .from(rolePermissions)
      .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
      .where(eq(rolePermissions.roleId, roleId));

    const enrichedRole = {
      ...role,
      permissions: rolePermissionsData.map(rp => rp.permission)
    };

    await this.redis.setex(cacheKey, 300, JSON.stringify(enrichedRole));

    return enrichedRole;
  }

  async listRoles(organizationId: string, query: RoleQueryInput) {
    const { page, limit, search, includeSystem } = query;
    const offset = (page - 1) * limit;

    const conditions = [eq(roles.organizationId, organizationId)];

    if (search) {
      conditions.push(
        or(
          ilike(roles.name, `%${search}%`),
          ilike(roles.description, `%${search}%`)
        )!
      );
    }

    if (!includeSystem) {
      conditions.push(eq(roles.isSystem, false));
    }

    const [rolesData, [{ count }]] = await Promise.all([
      this.db
        .select()
        .from(roles)
        .where(and(...conditions))
        .orderBy(roles.name)
        .limit(limit)
        .offset(offset),
      this.db
        .select({ count: sql<number>`count(*)` })
        .from(roles)
        .where(and(...conditions))
    ]);

    // Get permissions and user counts for each role
    const roleIds = rolesData.map(r => r.id);

    const [rolePermissionsData, userCountsData] = await Promise.all([
      this.db
        .select({
          roleId: rolePermissions.roleId,
          permission: permissions
        })
        .from(rolePermissions)
        .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
        .where(sql`${rolePermissions.roleId} = ANY(${roleIds})`),
      this.db
        .select({
          roleId: userRoles.roleId,
          count: sql<number>`count(*)`
        })
        .from(userRoles)
        .where(
          and(
            sql`${userRoles.roleId} = ANY(${roleIds})`,
            eq(userRoles.isActive, true)
          )
        )
        .groupBy(userRoles.roleId)
    ]);

    // Group permissions by role
    const permissionsByRole = rolePermissionsData.reduce((acc, rp) => {
      if (!acc[rp.roleId]) acc[rp.roleId] = [];
      acc[rp.roleId].push(rp.permission);
      return acc;
    }, {} as Record<string, typeof permissions.$inferSelect[]>);

    // Create user count map
    const userCountMap = new Map(userCountsData.map(uc => [uc.roleId, Number(uc.count)]));

    const enrichedRoles = rolesData.map(role => ({
      ...role,
      permissions: permissionsByRole[role.id] || [],
      userCount: userCountMap.get(role.id) || 0
    }));

    return {
      data: enrichedRoles,
      pagination: {
        page,
        limit,
        total: Number(count),
        totalPages: Math.ceil(Number(count) / limit)
      }
    };
  }

  async assignRolesToUser(
    userId: string,
    organizationId: string,
    data: AssignRolesInput,
    assignedBy: string
  ) {
    // Verify user exists
    const [user] = await this.db
      .select()
      .from(usersExtended)
      .where(
        and(
          eq(usersExtended.userId, userId),
          eq(usersExtended.organizationId, organizationId)
        )
      )
      .limit(1);

    if (!user) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    // Verify roles exist and belong to organization
    const validRoles = await this.db
      .select()
      .from(roles)
      .where(
        and(
          sql`${roles.id} = ANY(${data.roleIds})`,
          eq(roles.organizationId, organizationId)
        )
      );

    if (validRoles.length !== data.roleIds.length) {
      throw new HTTPException(400, { message: 'One or more invalid role IDs' });
    }

    // Get current roles
    const currentRoles = await this.db
      .select()
      .from(userRoles)
      .where(
        and(
          eq(userRoles.userId, userId),
          eq(userRoles.organizationId, organizationId),
          eq(userRoles.isActive, true)
        )
      );

    const currentRoleIds = currentRoles.map(ur => ur.roleId);
    const toAdd = data.roleIds.filter(id => !currentRoleIds.includes(id));

    // Add new roles
    if (toAdd.length > 0) {
      await this.db
        .insert(userRoles)
        .values(
          toAdd.map(roleId => ({
            userId,
            roleId,
            organizationId,
            assignedBy,
            scope: data.scope,
            expiresAt: data.expiresAt ? new Date(data.expiresAt) : undefined
          }))
        );
    }

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId,
        organizationId,
        action: 'role_assigned',
        entityType: 'user',
        entityId: userId,
        metadata: {
          roleIds: toAdd,
          scope: data.scope,
          expiresAt: data.expiresAt
        },
        performedBy: assignedBy
      });

    // Invalidate user cache
    await this.invalidateUserCache(organizationId, userId);

    return { assigned: toAdd.length };
  }

  async removeRoleFromUser(
    userId: string,
    roleId: string,
    organizationId: string,
    removedBy: string
  ) {
    const [userRole] = await this.db
      .select()
      .from(userRoles)
      .where(
        and(
          eq(userRoles.userId, userId),
          eq(userRoles.roleId, roleId),
          eq(userRoles.organizationId, organizationId),
          eq(userRoles.isActive, true)
        )
      )
      .limit(1);

    if (!userRole) {
      throw new HTTPException(404, { message: 'User role assignment not found' });
    }

    // Deactivate role assignment
    await this.db
      .update(userRoles)
      .set({
        isActive: false
      })
      .where(
        and(
          eq(userRoles.userId, userId),
          eq(userRoles.roleId, roleId),
          eq(userRoles.organizationId, organizationId)
        )
      );

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId,
        organizationId,
        action: 'role_removed',
        entityType: 'user',
        entityId: userId,
        metadata: { roleId },
        performedBy: removedBy
      });

    // Invalidate user cache
    await this.invalidateUserCache(organizationId, userId);
  }

  private async invalidateRoleCache(organizationId: string, roleId?: string) {
    if (roleId) {
      await this.redis.del(`role:${organizationId}:${roleId}`);
    } else {
      const keys = await this.redis.keys(`role:${organizationId}:*`);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    }
  }

  private async invalidateUserCache(organizationId: string, userId: string) {
    await this.redis.del(`user:${organizationId}:${userId}`);
  }
}