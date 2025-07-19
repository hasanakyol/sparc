import { z } from 'zod';

// User schemas
export const createUserSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  firstName: z.string().min(1, 'First name is required').max(100),
  lastName: z.string().min(1, 'Last name is required').max(100),
  displayName: z.string().max(200).optional(),
  phone: z.string().regex(/^[+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/im, 'Invalid phone number').optional(),
  department: z.string().max(100).optional(),
  jobTitle: z.string().max(100).optional(),
  location: z.string().max(200).optional(),
  roleIds: z.array(z.string().uuid()).optional(),
  metadata: z.record(z.any()).optional(),
  sendWelcomeEmail: z.boolean().default(true)
});

export const updateUserSchema = z.object({
  firstName: z.string().min(1).max(100).optional(),
  lastName: z.string().min(1).max(100).optional(),
  displayName: z.string().max(200).optional(),
  phone: z.string().regex(/^[+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/im, 'Invalid phone number').optional(),
  avatarUrl: z.string().url().optional(),
  bio: z.string().max(1000).optional(),
  department: z.string().max(100).optional(),
  jobTitle: z.string().max(100).optional(),
  location: z.string().max(200).optional(),
  metadata: z.record(z.any()).optional(),
  preferences: z.object({
    notifications: z.object({
      email: z.boolean(),
      sms: z.boolean(),
      push: z.boolean()
    }).optional(),
    theme: z.enum(['light', 'dark', 'system']).optional(),
    language: z.string().optional()
  }).optional()
});

export const userQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
  search: z.string().optional(),
  department: z.string().optional(),
  roleId: z.string().uuid().optional(),
  isActive: z.enum(['true', 'false']).transform(val => val === 'true').optional(),
  sortBy: z.enum(['name', 'email', 'createdAt', 'lastActiveAt']).default('name'),
  sortOrder: z.enum(['asc', 'desc']).default('asc')
});

export const changePasswordSchema = z.object({
  currentPassword: z.string(),
  newPassword: z.string().min(8, 'Password must be at least 8 characters'),
  logoutAllDevices: z.boolean().default(false)
});

export const resetPasswordSchema = z.object({
  token: z.string(),
  newPassword: z.string().min(8, 'Password must be at least 8 characters')
});

export const requestPasswordResetSchema = z.object({
  email: z.string().email('Invalid email address')
});

// Role schemas
export const createRoleSchema = z.object({
  name: z.string().min(1, 'Role name is required').max(100),
  description: z.string().max(500).optional(),
  permissionIds: z.array(z.string().uuid()).min(1, 'At least one permission is required'),
  isDefault: z.boolean().default(false),
  metadata: z.record(z.any()).optional()
});

export const updateRoleSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
  permissionIds: z.array(z.string().uuid()).optional(),
  isDefault: z.boolean().optional(),
  metadata: z.record(z.any()).optional()
});

export const roleQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
  search: z.string().optional(),
  includeSystem: z.enum(['true', 'false']).transform(val => val === 'true').default('false')
});

// User role assignment schemas
export const assignRolesSchema = z.object({
  roleIds: z.array(z.string().uuid()).min(1, 'At least one role is required'),
  scope: z.object({
    siteIds: z.array(z.string().uuid()).optional(),
    zoneIds: z.array(z.string().uuid()).optional()
  }).optional(),
  expiresAt: z.string().datetime().optional()
});

export const removeRoleSchema = z.object({
  roleId: z.string().uuid()
});

// Activation/Deactivation schemas
export const activateUserSchema = z.object({
  reason: z.string().max(500).optional()
});

export const deactivateUserSchema = z.object({
  reason: z.string().min(1, 'Deactivation reason is required').max(500)
});

// Bulk operations schemas
export const bulkOperationSchema = z.object({
  userIds: z.array(z.string().uuid()).min(1, 'At least one user ID is required').max(100),
  operation: z.enum(['activate', 'deactivate', 'delete', 'assignRole', 'removeRole']),
  data: z.record(z.any()).optional()
});

// Type exports
export type CreateUserInput = z.infer<typeof createUserSchema>;
export type UpdateUserInput = z.infer<typeof updateUserSchema>;
export type UserQueryInput = z.infer<typeof userQuerySchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
export type RequestPasswordResetInput = z.infer<typeof requestPasswordResetSchema>;
export type CreateRoleInput = z.infer<typeof createRoleSchema>;
export type UpdateRoleInput = z.infer<typeof updateRoleSchema>;
export type RoleQueryInput = z.infer<typeof roleQuerySchema>;
export type AssignRolesInput = z.infer<typeof assignRolesSchema>;
export type RemoveRoleInput = z.infer<typeof removeRoleSchema>;
export type ActivateUserInput = z.infer<typeof activateUserSchema>;
export type DeactivateUserInput = z.infer<typeof deactivateUserSchema>;
export type BulkOperationInput = z.infer<typeof bulkOperationSchema>;