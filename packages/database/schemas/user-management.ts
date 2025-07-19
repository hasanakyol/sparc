import { pgTable, uuid, varchar, text, timestamp, boolean, jsonb, primaryKey, unique, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { sql } from 'drizzle-orm';

// Extended user profile data beyond basic auth
export const usersExtended = pgTable('users_extended', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().unique(), // References auth.users
  organizationId: uuid('organization_id').notNull(),
  firstName: varchar('first_name', { length: 100 }),
  lastName: varchar('last_name', { length: 100 }),
  displayName: varchar('display_name', { length: 200 }),
  phone: varchar('phone', { length: 20 }),
  phoneVerified: boolean('phone_verified').default(false),
  avatarUrl: text('avatar_url'),
  bio: text('bio'),
  department: varchar('department', { length: 100 }),
  jobTitle: varchar('job_title', { length: 100 }),
  location: varchar('location', { length: 200 }),
  metadata: jsonb('metadata').default({}),
  preferences: jsonb('preferences').default({
    notifications: {
      email: true,
      sms: false,
      push: true
    },
    theme: 'system',
    language: 'en'
  }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  lastActiveAt: timestamp('last_active_at'),
  deactivatedAt: timestamp('deactivated_at'),
  deactivatedBy: uuid('deactivated_by'),
  deactivationReason: text('deactivation_reason')
}, (table) => ({
  organizationIdx: index('users_extended_organization_idx').on(table.organizationId),
  userIdx: index('users_extended_user_idx').on(table.userId),
  phoneIdx: index('users_extended_phone_idx').on(table.phone),
  activeIdx: index('users_extended_active_idx').on(table.deactivatedAt),
  lastActiveIdx: index('users_extended_last_active_idx').on(table.lastActiveAt)
}));

// Roles table
export const roles = pgTable('roles', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull(),
  name: varchar('name', { length: 100 }).notNull(),
  description: text('description'),
  isSystem: boolean('is_system').default(false).notNull(), // System roles cannot be deleted
  isDefault: boolean('is_default').default(false).notNull(), // Assigned to new users by default
  metadata: jsonb('metadata').default({}),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: uuid('created_by'),
  updatedBy: uuid('updated_by')
}, (table) => ({
  organizationNameUnique: unique('roles_organization_name_unique').on(table.organizationId, table.name),
  organizationIdx: index('roles_organization_idx').on(table.organizationId),
  systemIdx: index('roles_system_idx').on(table.isSystem)
}));

// Permissions table
export const permissions = pgTable('permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  resource: varchar('resource', { length: 100 }).notNull(), // e.g., 'users', 'cameras', 'incidents'
  action: varchar('action', { length: 50 }).notNull(), // e.g., 'create', 'read', 'update', 'delete', 'list'
  description: text('description'),
  isSystem: boolean('is_system').default(true).notNull(), // System permissions cannot be deleted
  createdAt: timestamp('created_at').defaultNow().notNull()
}, (table) => ({
  resourceActionUnique: unique('permissions_resource_action_unique').on(table.resource, table.action),
  resourceIdx: index('permissions_resource_idx').on(table.resource),
  actionIdx: index('permissions_action_idx').on(table.action)
}));

// Role-Permission mapping
export const rolePermissions = pgTable('role_permissions', {
  roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
  permissionId: uuid('permission_id').notNull().references(() => permissions.id, { onDelete: 'cascade' }),
  constraints: jsonb('constraints').default({}), // Additional constraints (e.g., { siteIds: [...], zoneIds: [...] })
  grantedAt: timestamp('granted_at').defaultNow().notNull(),
  grantedBy: uuid('granted_by')
}, (table) => ({
  pk: primaryKey({ columns: [table.roleId, table.permissionId] }),
  roleIdx: index('role_permissions_role_idx').on(table.roleId),
  permissionIdx: index('role_permissions_permission_idx').on(table.permissionId)
}));

// User-Role mapping
export const userRoles = pgTable('user_roles', {
  userId: uuid('user_id').notNull(),
  roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').notNull(),
  assignedAt: timestamp('assigned_at').defaultNow().notNull(),
  assignedBy: uuid('assigned_by'),
  expiresAt: timestamp('expires_at'), // For temporary role assignments
  scope: jsonb('scope').default({}), // Scope constraints (e.g., { siteIds: [...], zoneIds: [...] })
  isActive: boolean('is_active').default(true).notNull()
}, (table) => ({
  pk: primaryKey({ columns: [table.userId, table.roleId, table.organizationId] }),
  userIdx: index('user_roles_user_idx').on(table.userId),
  roleIdx: index('user_roles_role_idx').on(table.roleId),
  organizationIdx: index('user_roles_organization_idx').on(table.organizationId),
  activeIdx: index('user_roles_active_idx').on(table.isActive),
  expiresIdx: index('user_roles_expires_idx').on(table.expiresAt)
}));

// User audit log
export const userAuditLog = pgTable('user_audit_log', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull(),
  organizationId: uuid('organization_id').notNull(),
  action: varchar('action', { length: 50 }).notNull(), // e.g., 'created', 'updated', 'deleted', 'activated', 'deactivated', 'role_assigned', 'role_removed'
  entityType: varchar('entity_type', { length: 50 }).notNull(), // e.g., 'user', 'role', 'permission'
  entityId: uuid('entity_id'),
  changes: jsonb('changes').default({}), // JSON diff of changes
  metadata: jsonb('metadata').default({}), // Additional context
  performedBy: uuid('performed_by').notNull(),
  performedAt: timestamp('performed_at').defaultNow().notNull(),
  ipAddress: varchar('ip_address', { length: 45 }),
  userAgent: text('user_agent')
}, (table) => ({
  userIdx: index('user_audit_log_user_idx').on(table.userId),
  organizationIdx: index('user_audit_log_organization_idx').on(table.organizationId),
  performedAtIdx: index('user_audit_log_performed_at_idx').on(table.performedAt),
  actionIdx: index('user_audit_log_action_idx').on(table.action),
  entityIdx: index('user_audit_log_entity_idx').on(table.entityType, table.entityId)
}));

// Relations
export const usersExtendedRelations = relations(usersExtended, ({ many }) => ({
  roles: many(userRoles),
  auditLogs: many(userAuditLog)
}));

export const rolesRelations = relations(roles, ({ many }) => ({
  permissions: many(rolePermissions),
  users: many(userRoles)
}));

export const permissionsRelations = relations(permissions, ({ many }) => ({
  roles: many(rolePermissions)
}));

export const rolePermissionsRelations = relations(rolePermissions, ({ one }) => ({
  role: one(roles, {
    fields: [rolePermissions.roleId],
    references: [roles.id]
  }),
  permission: one(permissions, {
    fields: [rolePermissions.permissionId],
    references: [permissions.id]
  })
}));

export const userRolesRelations = relations(userRoles, ({ one }) => ({
  role: one(roles, {
    fields: [userRoles.roleId],
    references: [roles.id]
  }),
  user: one(usersExtended, {
    fields: [userRoles.userId],
    references: [usersExtended.userId]
  })
}));

// Type exports
export type UserExtended = typeof usersExtended.$inferSelect;
export type NewUserExtended = typeof usersExtended.$inferInsert;
export type Role = typeof roles.$inferSelect;
export type NewRole = typeof roles.$inferInsert;
export type Permission = typeof permissions.$inferSelect;
export type NewPermission = typeof permissions.$inferInsert;
export type RolePermission = typeof rolePermissions.$inferSelect;
export type NewRolePermission = typeof rolePermissions.$inferInsert;
export type UserRole = typeof userRoles.$inferSelect;
export type NewUserRole = typeof userRoles.$inferInsert;
export type UserAuditLog = typeof userAuditLog.$inferSelect;
export type NewUserAuditLog = typeof userAuditLog.$inferInsert;