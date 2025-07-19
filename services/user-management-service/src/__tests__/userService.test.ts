import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { UserService } from '../services/userService';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { HTTPException } from 'hono/http-exception';
import bcrypt from 'bcryptjs';

// Mock dependencies
jest.mock('@prisma/client');
jest.mock('ioredis');
jest.mock('bcryptjs');

describe('UserService', () => {
  let userService: UserService;
  let mockPrisma: jest.Mocked<PrismaClient>;
  let mockRedis: jest.Mocked<Redis>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    mockRedis = new Redis() as jest.Mocked<Redis>;
    userService = new UserService(mockPrisma, mockRedis);

    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create a new user successfully', async () => {
      const mockAuthUser = { id: 'user-123', email: 'test@example.com' };
      const mockUserExtended = {
        userId: 'user-123',
        organizationId: 'org-123',
        firstName: 'John',
        lastName: 'Doe'
      };

      mockPrisma.users.findUnique = jest.fn().mockResolvedValue(null);
      mockPrisma.$transaction = jest.fn().mockImplementation(async (fn) => {
        const tx = {
          users: {
            create: jest.fn().mockResolvedValue(mockAuthUser)
          },
          usersExtended: {
            create: jest.fn().mockResolvedValue(mockUserExtended)
          },
          roles: {
            findFirst: jest.fn().mockResolvedValue({ id: 'role-123' })
          },
          userRoles: {
            create: jest.fn().mockResolvedValue({})
          },
          userAuditLog: {
            create: jest.fn().mockResolvedValue({})
          }
        };
        return fn(tx);
      });

      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
      mockRedis.del = jest.fn().mockResolvedValue(1);
      mockRedis.keys = jest.fn().mockResolvedValue([]);

      const result = await userService.createUser(
        {
          email: 'test@example.com',
          password: 'password123',
          firstName: 'John',
          lastName: 'Doe',
          organizationId: 'org-123',
          sendWelcomeEmail: true
        },
        'admin-123'
      );

      expect(result).toMatchObject({
        userId: 'user-123',
        firstName: 'John',
        lastName: 'Doe',
        email: 'test@example.com'
      });
    });

    it('should throw error if email already exists', async () => {
      mockPrisma.users.findUnique = jest.fn().mockResolvedValue({ id: 'existing-user' });

      await expect(
        userService.createUser(
          {
            email: 'existing@example.com',
            password: 'password123',
            firstName: 'John',
            lastName: 'Doe',
            organizationId: 'org-123',
            sendWelcomeEmail: true
          },
          'admin-123'
        )
      ).rejects.toThrow(HTTPException);
    });
  });

  describe('getUserById', () => {
    it('should return cached user if available', async () => {
      const cachedUser = {
        userId: 'user-123',
        firstName: 'John',
        lastName: 'Doe'
      };

      mockRedis.get = jest.fn().mockResolvedValue(JSON.stringify(cachedUser));

      const result = await userService.getUserById('user-123', 'org-123');

      expect(result).toEqual(cachedUser);
      expect(mockPrisma.usersExtended.findFirst).not.toHaveBeenCalled();
    });

    it('should fetch user from database if not cached', async () => {
      const dbUser = {
        userId: 'user-123',
        firstName: 'John',
        lastName: 'Doe',
        roles: []
      };

      mockRedis.get = jest.fn().mockResolvedValue(null);
      mockRedis.setex = jest.fn().mockResolvedValue('OK');
      mockPrisma.usersExtended.findFirst = jest.fn().mockResolvedValue(dbUser);

      const result = await userService.getUserById('user-123', 'org-123');

      expect(result).toEqual(dbUser);
      expect(mockRedis.setex).toHaveBeenCalledWith(
        'user:org-123:user-123',
        300,
        JSON.stringify(dbUser)
      );
    });
  });

  describe('deactivateUser', () => {
    it('should deactivate an active user', async () => {
      const mockUser = {
        userId: 'user-123',
        deactivatedAt: null
      };

      jest.spyOn(userService, 'getUserById').mockResolvedValue(mockUser as any);
      
      mockPrisma.$transaction = jest.fn().mockImplementation(async (fn) => {
        const tx = {
          usersExtended: {
            update: jest.fn().mockResolvedValue({})
          },
          users: {
            update: jest.fn().mockResolvedValue({})
          },
          userAuditLog: {
            create: jest.fn().mockResolvedValue({})
          }
        };
        return fn(tx);
      });

      mockRedis.del = jest.fn().mockResolvedValue(1);
      mockRedis.keys = jest.fn().mockResolvedValue([]);

      await userService.deactivateUser(
        'user-123',
        'org-123',
        { reason: 'Security violation' },
        'admin-123'
      );

      expect(mockPrisma.$transaction).toHaveBeenCalled();
    });

    it('should throw error if user is already deactivated', async () => {
      const mockUser = {
        userId: 'user-123',
        deactivatedAt: new Date()
      };

      jest.spyOn(userService, 'getUserById').mockResolvedValue(mockUser as any);

      await expect(
        userService.deactivateUser(
          'user-123',
          'org-123',
          { reason: 'Test' },
          'admin-123'
        )
      ).rejects.toThrow('User is already deactivated');
    });
  });
});