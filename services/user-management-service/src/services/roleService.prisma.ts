import { PrismaClient } from '@prisma/client';
import { HTTPException } from 'hono/http-exception';
import Redis from 'ioredis';
import {
  CreateRoleInput,
  UpdateRoleInput,
  RoleQueryInput,
  AssignRolesInput
} from '../types/schemas';
import {
  Role,
  NewRole,
  RolePermission,
  NewRolePermission,
  UserRole,
  NewUserRole
} from '@sparc/database/schemas/user-management';

export class RoleService {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async createRole(data: CreateRoleInput & { organizationId: string }, createdBy: string) {
    // Check if role name already exists
    const existingRole = await this.prisma.roles.findFirst({
      where: {
        organizationId: data.organizationId,
        name: data.name
      }
    });

    if (existingRole) {
      throw new HTTPException(409, { message: 'Role with this name already exists' });
    }

    // Verify permissions exist
    const permissions = await this.prisma.permissions.findMany({
      where: {
        id: { in: data.permissionIds }
      }
    });

    if (permissions.length !== data.permissionIds.length) {
      throw new HTTPException(400, { message: 'One or more invalid permission IDs' });
    }

    return await this.prisma.$transaction(async (tx) => {
      // Create role
      const role = await tx.roles.create({
        data: {
          organizationId: data.organizationId,
          name: data.name,
          description: data.description,
          isDefault: data.isDefault,
          metadata: data.metadata || {},
          createdBy,
          updatedBy: createdBy
        }
      });

      // Assign permissions
      if (data.permissionIds.length > 0) {
        await tx.rolePermissions.createMany({
          data: data.permissionIds.map(permissionId => ({
            roleId: role.id,
            permissionId,
            grantedBy: createdBy
          }))
        });
      }

      // Create audit log
      await tx.userAuditLog.create({
        data: {
          userId: createdBy,
          organizationId: data.organizationId,
          action: 'created',
          entityType: 'role',
          entityId: role.id,
          metadata: {
            roleName: role.name,
            permissions: data.permissionIds
          },
          performedBy: createdBy,
          performedAt: new Date()
        }
      });

      // Invalidate cache
      await this.invalidateRoleCache(data.organizationId);

      return {
        ...role,
        permissions: permissions
      };
    });
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
      const existingRole = await this.prisma.roles.findFirst({
        where: {
          organizationId,
          name: data.name,
          id: { not: roleId }
        }
      });

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

    return await this.prisma.$transaction(async (tx) => {
      // Update role
      const updatedRole = await tx.roles.update({
        where: { id: roleId },
        data: {
          name: data.name,
          description: data.description,
          isDefault: data.isDefault,
          metadata: data.metadata,
          updatedBy,
          updatedAt: new Date()
        }
      });

      // Update permissions if provided
      if (data.permissionIds) {
        // Verify permissions exist
        const permissions = await tx.permissions.findMany({
          where: { id: { in: data.permissionIds } }
        });

        if (permissions.length !== data.permissionIds.length) {
          throw new HTTPException(400, { message: 'One or more invalid permission IDs' });
        }

        // Get current permissions
        const currentPermissions = await tx.rolePermissions.findMany({
          where: { roleId },
          select: { permissionId: true }
        });

        const currentPermissionIds = currentPermissions.map(p => p.permissionId);
        const toAdd = data.permissionIds.filter(id => !currentPermissionIds.includes(id));
        const toRemove = currentPermissionIds.filter(id => !data.permissionIds.includes(id));

        // Remove permissions
        if (toRemove.length > 0) {
          await tx.rolePermissions.deleteMany({
            where: {
              roleId,
              permissionId: { in: toRemove }
            }
          });
        }

        // Add permissions
        if (toAdd.length > 0) {
          await tx.rolePermissions.createMany({
            data: toAdd.map(permissionId => ({
              roleId,
              permissionId,
              grantedBy: updatedBy
            }))
          });
        }

        changes.permissions = {
          added: toAdd,
          removed: toRemove
        };
      }

      // Create audit log
      await tx.userAuditLog.create({
        data: {
          userId: updatedBy,
          organizationId,
          action: 'updated',
          entityType: 'role',
          entityId: roleId,
          changes,
          performedBy: updatedBy,
          performedAt: new Date()
        }
      });

      // Invalidate cache
      await this.invalidateRoleCache(organizationId, roleId);

      return updatedRole;
    });
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
    const userCount = await this.prisma.userRoles.count({
      where: {
        roleId,
        organizationId,
        isActive: true
      }
    });

    if (userCount > 0) {
      throw new HTTPException(400, { 
        message: `Cannot delete role. It is assigned to ${userCount} user(s).` 
      });
    }

    await this.prisma.$transaction(async (tx) => {
      // Delete role (cascade will handle rolePermissions)
      await tx.roles.delete({
        where: { id: roleId }
      });

      // Create audit log
      await tx.userAuditLog.create({
        data: {
          userId: deletedBy,
          organizationId,
          action: 'deleted',
          entityType: 'role',
          entityId: roleId,
          metadata: { roleName: role.name },
          performedBy: deletedBy,
          performedAt: new Date()
        }
      });
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

    const role = await this.prisma.roles.findFirst({
      where: {
        id: roleId,
        organizationId
      },
      include: {
        permissions: {
          include: {
            permission: true
          }
        }
      }
    });

    if (role) {
      await this.redis.setex(cacheKey, 300, JSON.stringify(role));
    }

    return role;
  }

  async listRoles(organizationId: string, query: RoleQueryInput) {
    const { page, limit, search, includeSystem } = query;
    const skip = (page - 1) * limit;

    const where: any = { organizationId };

    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } }
      ];
    }

    if (!includeSystem) {
      where.isSystem = false;
    }

    const [roles, total] = await Promise.all([
      this.prisma.roles.findMany({
        where,
        skip,
        take: limit,
        orderBy: { name: 'asc' },
        include: {
          permissions: {
            include: {
              permission: true
            }
          },
          users: {
            where: { isActive: true },
            select: { userId: true }
          }
        }
      }),
      this.prisma.roles.count({ where })
    ]);

    const enrichedRoles = roles.map(role => ({
      ...role,
      permissions: role.permissions.map(rp => rp.permission),
      userCount: role.users.length
    }));

    return {
      data: enrichedRoles,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
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
    const user = await this.prisma.usersExtended.findFirst({
      where: { userId, organizationId }
    });

    if (!user) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    // Verify roles exist and belong to organization
    const roles = await this.prisma.roles.findMany({
      where: {
        id: { in: data.roleIds },
        organizationId
      }
    });

    if (roles.length !== data.roleIds.length) {
      throw new HTTPException(400, { message: 'One or more invalid role IDs' });
    }

    return await this.prisma.$transaction(async (tx) => {
      // Get current roles
      const currentRoles = await tx.userRoles.findMany({
        where: {
          userId,
          organizationId,
          isActive: true
        }
      });

      const currentRoleIds = currentRoles.map(ur => ur.roleId);
      const toAdd = data.roleIds.filter(id => !currentRoleIds.includes(id));

      // Add new roles
      if (toAdd.length > 0) {
        await tx.userRoles.createMany({
          data: toAdd.map(roleId => ({
            userId,
            roleId,
            organizationId,
            assignedBy,
            scope: data.scope,
            expiresAt: data.expiresAt
          }))
        });
      }

      // Create audit log
      await tx.userAuditLog.create({
        data: {
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
          performedBy: assignedBy,
          performedAt: new Date()
        }
      });

      // Invalidate user cache
      await this.invalidateUserCache(organizationId, userId);

      return { assigned: toAdd.length };
    });
  }

  async removeRoleFromUser(
    userId: string,
    roleId: string,
    organizationId: string,
    removedBy: string
  ) {
    const userRole = await this.prisma.userRoles.findFirst({
      where: {
        userId,
        roleId,
        organizationId,
        isActive: true
      }
    });

    if (!userRole) {
      throw new HTTPException(404, { message: 'User role assignment not found' });
    }

    await this.prisma.$transaction(async (tx) => {
      // Deactivate role assignment
      await tx.userRoles.update({
        where: {
          userId_roleId_organizationId: {
            userId,
            roleId,
            organizationId
          }
        },
        data: {
          isActive: false
        }
      });

      // Create audit log
      await tx.userAuditLog.create({
        data: {
          userId,
          organizationId,
          action: 'role_removed',
          entityType: 'user',
          entityId: userId,
          metadata: { roleId },
          performedBy: removedBy,
          performedAt: new Date()
        }
      });
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