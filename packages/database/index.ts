// Export all database schemas
export * from './schemas/user-management';
export * from './schemas/alerts';

// Re-export commonly used types
export type {
  UserExtended,
  NewUserExtended,
  Role,
  NewRole,
  Permission,
  NewPermission,
  RolePermission,
  NewRolePermission,
  UserRole,
  NewUserRole,
  UserAuditLog,
  NewUserAuditLog
} from './schemas/user-management';