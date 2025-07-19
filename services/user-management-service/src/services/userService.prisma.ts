import { HTTPException } from 'hono/http-exception';
import bcrypt from 'bcryptjs';
import { nanoid } from 'nanoid';
import Redis from 'ioredis';
import { eq, and, or, like, isNull, isNotNull, sql, desc, asc } from 'drizzle-orm';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
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
  userAuditLog,
  UserExtended,
  NewUserExtended,
  UserRole,
  NewUserRole,
  NewUserAuditLog
} from '@sparc/database/schemas/user-management';

export class UserService {
  constructor(
    private prisma: PrismaClient,
    private redis: Redis
  ) {}

  async createUser(data: CreateUserInput & { organizationId: string }, createdBy: string) {
    // Check if email already exists in auth service
    const existingAuthUser = await this.prisma.users.findUnique({
      where: { email: data.email }
    });

    if (existingAuthUser) {
      throw new HTTPException(409, { message: 'User with this email already exists' });
    }

    // Start transaction
    return await this.prisma.$transaction(async (tx) => {
      // Create user in auth.users table first
      const authUser = await tx.users.create({
        data: {
          email: data.email,
          passwordHash: await bcrypt.hash(data.password, 12),
          organizationId: data.organizationId,
          emailVerified: false,
          isActive: true
        }
      });

      // Create extended user profile
      const userExtended = await tx.usersExtended.create({
        data: {
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
        }
      });

      // Assign roles if provided
      if (data.roleIds && data.roleIds.length > 0) {
        // Verify roles exist and belong to the organization
        const roles = await tx.roles.findMany({
          where: {
            id: { in: data.roleIds },
            organizationId: data.organizationId
          }
        });

        if (roles.length !== data.roleIds.length) {
          throw new HTTPException(400, { message: 'One or more invalid role IDs' });
        }

        // Create user-role mappings
        await tx.userRoles.createMany({
          data: data.roleIds.map(roleId => ({
            userId: authUser.id,
            roleId,
            organizationId: data.organizationId,
            assignedBy: createdBy
          }))
        });
      } else {
        // Assign default role if exists
        const defaultRole = await tx.roles.findFirst({
          where: {
            organizationId: data.organizationId,
            isDefault: true
          }
        });

        if (defaultRole) {
          await tx.userRoles.create({
            data: {
              userId: authUser.id,
              roleId: defaultRole.id,
              organizationId: data.organizationId,
              assignedBy: createdBy
            }
          });
        }
      }

      // Create audit log entry
      await tx.userAuditLog.create({
        data: {
          userId: authUser.id,
          organizationId: data.organizationId,
          action: 'created',
          entityType: 'user',
          entityId: authUser.id,
          performedBy: createdBy,
          performedAt: new Date(),
          metadata: {
            roles: data.roleIds || [],
            sendWelcomeEmail: data.sendWelcomeEmail
          }
        }
      });

      // Invalidate cache
      await this.invalidateUserCache(data.organizationId);

      return {
        ...userExtended,
        email: authUser.email,
        roles: data.roleIds || []
      };
    });
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

    const updatedUser = await this.prisma.$transaction(async (tx) => {
      const updated = await tx.usersExtended.update({
        where: {
          userId,
          organizationId
        },
        data: {
          ...data,
          updatedAt: new Date()
        }
      });

      // Create audit log
      await tx.userAuditLog.create({
        data: {
          userId,
          organizationId,
          action: 'updated',
          entityType: 'user',
          entityId: userId,
          changes,
          performedBy: updatedBy,
          performedAt: new Date()
        }
      });

      return updated;
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

    const user = await this.prisma.usersExtended.findFirst({
      where: {
        userId,
        organizationId
      },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true
                  }
                }
              }
            }
          }
        }
      }
    });

    if (user) {
      // Cache for 5 minutes
      await this.redis.setex(cacheKey, 300, JSON.stringify(user));
    }

    return user;
  }

  async listUsers(organizationId: string, query: UserQueryInput) {
    const { page, limit, search, department, roleId, isActive, sortBy, sortOrder } = query;
    const skip = (page - 1) * limit;

    const where: any = { organizationId };

    if (search) {
      where.OR = [
        { firstName: { contains: search, mode: 'insensitive' } },
        { lastName: { contains: search, mode: 'insensitive' } },
        { displayName: { contains: search, mode: 'insensitive' } },
        { email: { contains: search, mode: 'insensitive' } }
      ];
    }

    if (department) {
      where.department = department;
    }

    if (roleId) {
      where.roles = {
        some: {
          roleId,
          isActive: true
        }
      };
    }

    if (isActive !== undefined) {
      where.deactivatedAt = isActive ? null : { not: null };
    }

    const [users, total] = await Promise.all([
      this.prisma.usersExtended.findMany({
        where,
        skip,
        take: limit,
        orderBy: {
          [sortBy]: sortOrder
        },
        include: {
          roles: {
            where: { isActive: true },
            include: {
              role: true
            }
          }
        }
      }),
      this.prisma.usersExtended.count({ where })
    ]);

    // Get auth data for emails
    const userIds = users.map(u => u.userId);
    const authUsers = await this.prisma.users.findMany({
      where: { id: { in: userIds } },
      select: { id: true, email: true }
    });

    const emailMap = new Map(authUsers.map(u => [u.id, u.email]));

    const enrichedUsers = users.map(user => ({
      ...user,
      email: emailMap.get(user.userId) || '',
      roles: user.roles.map(ur => ur.role)
    }));

    return {
      data: enrichedUsers,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
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

    await this.prisma.$transaction(async (tx) => {
      // Update user status
      await tx.usersExtended.update({
        where: { userId, organizationId },
        data: {
          deactivatedAt: new Date(),
          deactivatedBy,
          deactivationReason: data.reason
        }
      });

      // Deactivate in auth table
      await tx.users.update({
        where: { id: userId },
        data: { isActive: false }
      });

      // Create audit log
      await tx.userAuditLog.create({
        data: {
          userId,
          organizationId,
          action: 'deactivated',
          entityType: 'user',
          entityId: userId,
          metadata: { reason: data.reason },
          performedBy: deactivatedBy,
          performedAt: new Date()
        }
      });
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

    await this.prisma.$transaction(async (tx) => {
      // Update user status
      await tx.usersExtended.update({
        where: { userId, organizationId },
        data: {
          deactivatedAt: null,
          deactivatedBy: null,
          deactivationReason: null
        }
      });

      // Activate in auth table
      await tx.users.update({
        where: { id: userId },
        data: { isActive: true }
      });

      // Create audit log
      await tx.userAuditLog.create({
        data: {
          userId,
          organizationId,
          action: 'activated',
          entityType: 'user',
          entityId: userId,
          metadata: { reason: data.reason },
          performedBy: activatedBy,
          performedAt: new Date()
        }
      });
    });

    // Invalidate cache
    await this.invalidateUserCache(organizationId, userId);
  }

  async changePassword(userId: string, organizationId: string, data: ChangePasswordInput) {
    // Verify current password
    const authUser = await this.prisma.users.findUnique({
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
    await this.prisma.users.update({
      where: { id: userId },
      data: {
        passwordHash: await bcrypt.hash(data.newPassword, 12),
        passwordChangedAt: new Date()
      }
    });

    // Log out all devices if requested
    if (data.logoutAllDevices) {
      await this.invalidateUserSessions(userId);
    }

    // Create audit log
    await this.prisma.userAuditLog.create({
      data: {
        userId,
        organizationId,
        action: 'password_changed',
        entityType: 'user',
        entityId: userId,
        metadata: { logoutAllDevices: data.logoutAllDevices },
        performedBy: userId,
        performedAt: new Date()
      }
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