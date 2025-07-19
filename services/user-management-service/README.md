# User Management Service

The User Management Service is a core microservice in the SPARC platform that handles user profiles, roles, permissions, and access control. It extends the MicroserviceBase pattern and integrates with the auth-service for authentication.

## Features

- **User Management**: CRUD operations for user profiles
- **Role-Based Access Control (RBAC)**: Flexible role and permission system
- **Profile Management**: User self-service profile updates
- **Audit Logging**: Comprehensive tracking of all user-related changes
- **Multi-tenant Support**: Organization-based data isolation
- **Caching**: Redis-based caching for improved performance

## Architecture

The service follows the established SPARC microservice patterns:

```
user-management-service/
├── src/
│   ├── __tests__/        # Unit tests
│   ├── middleware/       # Auth and permission middleware
│   ├── routes/           # API endpoint handlers
│   ├── services/         # Business logic
│   ├── types/            # TypeScript types and schemas
│   ├── utils/            # Helper functions
│   └── index.ts          # Service entry point
├── package.json
├── tsconfig.json
└── README.md
```

## API Endpoints

### User Management
- `GET /api/users` - List users (paginated)
- `GET /api/users/:userId` - Get user details
- `POST /api/users` - Create new user
- `PATCH /api/users/:userId` - Update user
- `POST /api/users/:userId/change-password` - Change user password
- `POST /api/users/:userId/deactivate` - Deactivate user
- `POST /api/users/:userId/activate` - Activate user
- `POST /api/users/bulk` - Bulk operations

### Role Management
- `GET /api/roles` - List roles
- `GET /api/roles/:roleId` - Get role details
- `POST /api/roles` - Create new role
- `PATCH /api/roles/:roleId` - Update role
- `DELETE /api/roles/:roleId` - Delete role
- `POST /api/roles/assign/:userId` - Assign roles to user
- `DELETE /api/roles/assign/:userId/:roleId` - Remove role from user

### Permission Management
- `GET /api/permissions` - List all permissions
- `GET /api/permissions/resource/:resource` - Get permissions by resource
- `GET /api/permissions/my-permissions` - Get current user's permissions
- `GET /api/permissions/user/:userId` - Get specific user's permissions
- `POST /api/permissions/check` - Check if user has permission

### Profile Management
- `GET /api/profile` - Get current user's profile
- `PATCH /api/profile` - Update current user's profile
- `POST /api/profile/change-password` - Change own password
- `GET /api/profile/permissions` - Get own permissions
- `GET /api/profile/roles` - Get own roles

## Database Schema

The service uses the following main tables:

- `users_extended` - Extended user profile data
- `roles` - Role definitions
- `permissions` - Permission definitions
- `role_permissions` - Role-permission mappings
- `user_roles` - User-role assignments
- `user_audit_log` - Audit trail for all changes

## Integration with Auth Service

The User Management Service works in conjunction with the auth-service:

1. **Authentication**: Auth service handles login/logout and JWT token generation
2. **User Creation**: Creates records in both auth.users and users_extended tables
3. **Password Management**: Delegates password hashing and validation to auth service
4. **Session Management**: Coordinates with auth service for session invalidation

## Permission System

The service implements a flexible RBAC system:

1. **Resources**: Logical groupings (users, cameras, incidents, etc.)
2. **Actions**: Operations on resources (create, read, update, delete, etc.)
3. **Roles**: Named collections of permissions
4. **Constraints**: Optional scope limitations (site-specific, zone-specific)

### Default Permissions

The service includes default permissions for common resources:
- User management
- Role management
- Camera operations
- Incident handling
- Access control
- Analytics
- System settings

## Development

### Prerequisites
- Node.js 18+
- PostgreSQL
- Redis
- Access to shared packages (@sparc/shared, @sparc/database)

### Setup
```bash
# Install dependencies
npm install

# Run migrations
npm run db:push

# Seed permissions
npm run seed:permissions

# Start development server
npm run dev
```

### Testing
```bash
# Run unit tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Environment Variables
```env
DATABASE_URL=postgresql://...
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-jwt-secret
PORT=3010
```

## Security Considerations

1. **Authentication**: All endpoints require valid JWT tokens
2. **Authorization**: Permission-based access control
3. **Data Isolation**: Tenant-based data separation
4. **Audit Trail**: All changes are logged
5. **Password Security**: Bcrypt hashing with configurable rounds
6. **Input Validation**: Zod schemas for all inputs

## Performance

- **Caching**: User and role data cached in Redis (5-minute TTL)
- **Database Indexes**: Optimized queries with proper indexes
- **Pagination**: All list endpoints support pagination
- **Connection Pooling**: Efficient database connection management

## Monitoring

The service exposes metrics at `/metrics`:
- Total users count
- Active users count
- Total roles count
- Request latency
- Error rates

Health checks available at:
- `/health` - Overall service health
- `/ready` - Readiness probe

## Error Handling

Standardized error responses:
```json
{
  "error": "User not found",
  "code": "E404",
  "details": {}
}
```

Common error codes:
- 400: Validation errors
- 401: Authentication required
- 403: Permission denied
- 404: Resource not found
- 409: Conflict (duplicate)
- 500: Internal server error