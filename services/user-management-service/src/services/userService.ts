import { HTTPException } from 'hono/http-exception';
import bcrypt from 'bcryptjs';
import { nanoid } from 'nanoid';
import Redis from 'ioredis';
import { eq, and, or, like, ilike, isNull, isNotNull, sql, desc, asc } from 'drizzle-orm';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import { PrismaClient } from '@prisma/client';
import {
  CreateUserInput,
  UpdateUserInput,
  UserQueryInput,
  ChangePasswordInput,
  DeactivateUserInput,
  ActivateUserInput
} from '../types/schemas';
import {
  usersExtended,
  userRoles,
  roles,
  rolePermissions,
  permissions,
  userAuditLog,
  UserExtended,
  NewUserExtended,
  UserRole,
  NewUserRole,
  NewUserAuditLog
} from '@sparc/database/schemas/user-management';

export class UserService {
  constructor(
    private db: PostgresJsDatabase,
    private prisma: PrismaClient, // For auth.users table
    private redis: Redis
  ) {}

  async createUser(data: CreateUserInput & { organizationId: string }, createdBy: string) {
    // Check if email already exists in auth service
    const existingAuthUser = await this.prisma.user.findFirst({
      where: { 
        email: data.email,
        tenantId: data.organizationId 
      }
    });

    if (existingAuthUser) {
      throw new HTTPException(409, { message: 'User with this email already exists' });
    }

    // Start transaction
    try {
      // Create user in auth.users table first (using Prisma)
      const authUser = await this.prisma.user.create({
        data: {
          tenantId: data.organizationId,
          username: data.email, // Use email as username
          email: data.email,
          passwordHash: await bcrypt.hash(data.password, 12),
          active: true,
          roles: []
        }
      });

      // Create extended user profile (using Drizzle)
      const [userExtendedRecord] = await this.db
        .insert(usersExtended)
        .values({
          userId: authUser.id,
          organizationId: data.organizationId,
          firstName: data.firstName,
          lastName: data.lastName,
          displayName: data.displayName || `${data.firstName} ${data.lastName}`,
          phone: data.phone,
          department: data.department,
          jobTitle: data.jobTitle,
          location: data.location,
          metadata: data.metadata || {}
        })
        .returning();

      // Assign roles if provided
      if (data.roleIds && data.roleIds.length > 0) {
        // Verify roles exist and belong to the organization
        const validRoles = await this.db
          .select()
          .from(roles)
          .where(
            and(
              sql`${roles.id} = ANY(${data.roleIds})`,
              eq(roles.organizationId, data.organizationId)
            )
          );

        if (validRoles.length !== data.roleIds.length) {
          throw new HTTPException(400, { message: 'One or more invalid role IDs' });
        }

        // Create user-role mappings
        await this.db
          .insert(userRoles)
          .values(
            data.roleIds.map(roleId => ({
              userId: authUser.id,
              roleId,
              organizationId: data.organizationId,
              assignedBy: createdBy
            }))
          );
      } else {
        // Assign default role if exists
        const [defaultRole] = await this.db
          .select()
          .from(roles)
          .where(
            and(
              eq(roles.organizationId, data.organizationId),
              eq(roles.isDefault, true)
            )
          )
          .limit(1);

        if (defaultRole) {
          await this.db
            .insert(userRoles)
            .values({
              userId: authUser.id,
              roleId: defaultRole.id,
              organizationId: data.organizationId,
              assignedBy: createdBy
            });
        }
      }

      // Create audit log entry
      await this.db
        .insert(userAuditLog)
        .values({
          userId: authUser.id,
          organizationId: data.organizationId,
          action: 'created',
          entityType: 'user',
          entityId: authUser.id,
          performedBy: createdBy,
          metadata: {
            roles: data.roleIds || [],
            sendWelcomeEmail: data.sendWelcomeEmail
          }
        });

      // Invalidate cache
      await this.invalidateUserCache(data.organizationId);

      return {
        ...userExtendedRecord,
        email: authUser.email,
        roles: data.roleIds || []
      };
    } catch (error) {
      // If anything fails, we should clean up the auth user
      // This is a simplified version - in production you'd want proper transaction handling
      throw error;
    }
  }

  async updateUser(userId: string, organizationId: string, data: UpdateUserInput, updatedBy: string) {
    const user = await this.getUserById(userId, organizationId);
    if (!user) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    const changes: Record<string, any> = {};
    Object.entries(data).forEach(([key, value]) => {
      if (value !== undefined && value !== (user as any)[key]) {
        changes[key] = { from: (user as any)[key], to: value };
      }
    });

    if (Object.keys(changes).length === 0) {
      return user;
    }

    const [updatedUser] = await this.db
      .update(usersExtended)
      .set({
        ...data,
        updatedAt: new Date()
      })
      .where(
        and(
          eq(usersExtended.userId, userId),
          eq(usersExtended.organizationId, organizationId)
        )
      )
      .returning();

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId,
        organizationId,
        action: 'updated',
        entityType: 'user',
        entityId: userId,
        changes,
        performedBy: updatedBy
      });

    // Invalidate cache
    await this.invalidateUserCache(organizationId, userId);

    return updatedUser;
  }

  async getUserById(userId: string, organizationId: string) {
    // Try cache first
    const cacheKey = `user:${organizationId}:${userId}`;
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

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

    if (!user) return null;

    // Get user's roles
    const userRolesData = await this.db
      .select({
        role: roles,
        userRole: userRoles
      })
      .from(userRoles)
      .innerJoin(roles, eq(userRoles.roleId, roles.id))
      .where(
        and(
          eq(userRoles.userId, userId),
          eq(userRoles.organizationId, organizationId),
          eq(userRoles.isActive, true)
        )
      );

    const enrichedUser = {
      ...user,
      roles: userRolesData
    };

    // Cache for 5 minutes
    await this.redis.setex(cacheKey, 300, JSON.stringify(enrichedUser));

    return enrichedUser;
  }

  async listUsers(organizationId: string, query: UserQueryInput) {
    const { page, limit, search, department, roleId, isActive, sortBy, sortOrder } = query;
    const offset = (page - 1) * limit;

    // Build where conditions
    const conditions = [eq(usersExtended.organizationId, organizationId)];

    if (search) {
      conditions.push(
        or(
          ilike(usersExtended.firstName, `%${search}%`),
          ilike(usersExtended.lastName, `%${search}%`),
          ilike(usersExtended.displayName, `%${search}%`)
        )!
      );
    }

    if (department) {
      conditions.push(eq(usersExtended.department, department));
    }

    if (isActive !== undefined) {
      conditions.push(isActive ? isNull(usersExtended.deactivatedAt) : isNotNull(usersExtended.deactivatedAt));
    }

    // Base query for users
    let baseQuery = this.db
      .select()
      .from(usersExtended)
      .where(and(...conditions));

    // If filtering by role, we need to join with userRoles
    if (roleId) {
      baseQuery = this.db
        .select({
          user: usersExtended
        })
        .from(usersExtended)
        .innerJoin(
          userRoles,
          and(
            eq(userRoles.userId, usersExtended.userId),
            eq(userRoles.roleId, roleId),
            eq(userRoles.isActive, true)
          )
        )
        .where(and(...conditions));
    }

    // Apply sorting
    const orderByColumn = sortBy === 'name' ? usersExtended.firstName : 
                         sortBy === 'createdAt' ? usersExtended.createdAt :
                         sortBy === 'lastActiveAt' ? usersExtended.lastActiveAt :
                         usersExtended.firstName;
    
    const orderDirection = sortOrder === 'desc' ? desc : asc;

    // Execute queries
    const [users, [{ count }]] = await Promise.all([
      baseQuery
        .orderBy(orderDirection(orderByColumn))
        .limit(limit)
        .offset(offset),
      this.db
        .select({ count: sql<number>`count(*)` })
        .from(usersExtended)
        .where(and(...conditions))
    ]);

    // Get auth data for emails
    const userIds = (roleId ? users.map(u => u.user.userId) : users.map(u => u.userId)) as string[];
    const authUsers = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: { id: true, email: true }
    });

    const emailMap = new Map(authUsers.map(u => [u.id, u.email]));

    // Get roles for each user
    const userRolesData = await this.db
      .select({
        userId: userRoles.userId,
        role: roles
      })
      .from(userRoles)
      .innerJoin(roles, eq(userRoles.roleId, roles.id))
      .where(
        and(
          sql`${userRoles.userId} = ANY(${userIds})`,
          eq(userRoles.isActive, true)
        )
      );

    // Group roles by user
    const rolesByUser = userRolesData.reduce((acc, ur) => {
      if (!acc[ur.userId]) acc[ur.userId] = [];
      acc[ur.userId].push(ur.role);
      return acc;
    }, {} as Record<string, typeof roles.$inferSelect[]>);

    const enrichedUsers = (roleId ? users.map(u => u.user) : users).map(user => ({
      ...user,
      email: emailMap.get(user.userId) || '',
      roles: rolesByUser[user.userId] || []
    }));

    return {
      data: enrichedUsers,
      pagination: {
        page,
        limit,
        total: Number(count),
        totalPages: Math.ceil(Number(count) / limit)
      }
    };
  }

  async deactivateUser(userId: string, organizationId: string, data: DeactivateUserInput, deactivatedBy: string) {
    const user = await this.getUserById(userId, organizationId);
    if (!user) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    if (user.deactivatedAt) {
      throw new HTTPException(400, { message: 'User is already deactivated' });
    }

    // Update user status
    await this.db
      .update(usersExtended)
      .set({
        deactivatedAt: new Date(),
        deactivatedBy,
        deactivationReason: data.reason
      })
      .where(
        and(
          eq(usersExtended.userId, userId),
          eq(usersExtended.organizationId, organizationId)
        )
      );

    // Deactivate in auth table
    await this.prisma.user.update({
      where: { id: userId },
      data: { active: false }
    });

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId,
        organizationId,
        action: 'deactivated',
        entityType: 'user',
        entityId: userId,
        metadata: { reason: data.reason },
        performedBy: deactivatedBy
      });

    // Invalidate cache and sessions
    await this.invalidateUserCache(organizationId, userId);
    await this.invalidateUserSessions(userId);
  }

  async activateUser(userId: string, organizationId: string, data: ActivateUserInput, activatedBy: string) {
    const user = await this.getUserById(userId, organizationId);
    if (!user) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    if (!user.deactivatedAt) {
      throw new HTTPException(400, { message: 'User is already active' });
    }

    // Update user status
    await this.db
      .update(usersExtended)
      .set({
        deactivatedAt: null,
        deactivatedBy: null,
        deactivationReason: null
      })
      .where(
        and(
          eq(usersExtended.userId, userId),
          eq(usersExtended.organizationId, organizationId)
        )
      );

    // Activate in auth table
    await this.prisma.user.update({
      where: { id: userId },
      data: { active: true }
    });

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId,
        organizationId,
        action: 'activated',
        entityType: 'user',
        entityId: userId,
        metadata: { reason: data.reason },
        performedBy: activatedBy
      });

    // Invalidate cache
    await this.invalidateUserCache(organizationId, userId);
  }

  async changePassword(userId: string, organizationId: string, data: ChangePasswordInput) {
    // Verify current password
    const authUser = await this.prisma.user.findUnique({
      where: { id: userId }
    });

    if (!authUser) {
      throw new HTTPException(404, { message: 'User not found' });
    }

    const isValidPassword = await bcrypt.compare(data.currentPassword, authUser.passwordHash);
    if (!isValidPassword) {
      throw new HTTPException(401, { message: 'Current password is incorrect' });
    }

    // Update password
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash: await bcrypt.hash(data.newPassword, 12)
      }
    });

    // Log out all devices if requested
    if (data.logoutAllDevices) {
      await this.invalidateUserSessions(userId);
    }

    // Create audit log
    await this.db
      .insert(userAuditLog)
      .values({
        userId,
        organizationId,
        action: 'password_changed',
        entityType: 'user',
        entityId: userId,
        metadata: { logoutAllDevices: data.logoutAllDevices },
        performedBy: userId
      });
  }

  private async invalidateUserCache(organizationId: string, userId?: string) {
    if (userId) {
      await this.redis.del(`user:${organizationId}:${userId}`);
    } else {
      const keys = await this.redis.keys(`user:${organizationId}:*`);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    }
  }

  private async invalidateUserSessions(userId: string) {
    // Get all sessions for the user
    const sessionKeys = await this.redis.keys(`session:${userId}:*`);
    if (sessionKeys.length > 0) {
      await this.redis.del(...sessionKeys);
    }

    // Add user to blacklist to force re-authentication
    await this.redis.setex(`blacklist:user:${userId}`, 86400, '1'); // 24 hours
  }
}