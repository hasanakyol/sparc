# Mobile Credential Service - Modular Architecture

## Overview

The Mobile Credential Service has been refactored from a monolithic 3,055-line file into a clean, modular architecture following best practices for separation of concerns, maintainability, and testability.

## Architecture

### Directory Structure

```
mobile-credential-service/src/
├── index.modular.ts      # Main application entry point
├── types/                # TypeScript types and interfaces
│   ├── index.ts         # Core interfaces
│   └── schemas.ts       # Zod validation schemas
├── protocols/            # Protocol implementations
│   ├── ble-handler.ts   # Bluetooth Low Energy handler
│   ├── nfc-handler.ts   # Near Field Communication handler
│   └── mesh-network.ts  # Mesh networking implementation
├── services/             # Business logic services
│   ├── credential-service.ts       # Core credential operations
│   ├── biometric-service.ts       # Biometric enrollment/verification
│   └── device-management-service.ts # Device control operations
└── routes/               # HTTP route handlers
    ├── credentials.ts    # Credential management endpoints
    ├── biometric.ts     # Biometric endpoints
    ├── device-management.ts # Device management endpoints
    ├── mesh-network.ts  # Mesh network endpoints
    └── offline-sync.ts  # Offline synchronization endpoints
```

## Module Descriptions

### Types (`/types`)
- **index.ts**: Core interfaces for BLE, NFC, mesh networking, biometric, and device management configurations
- **schemas.ts**: Zod validation schemas for request/response validation

### Protocols (`/protocols`)
- **ble-handler.ts**: Manages Bluetooth Low Energy communication for mobile credentials
- **nfc-handler.ts**: Handles NFC tag reading/writing and authentication
- **mesh-network.ts**: Implements P2P mesh networking for offline credential revocation

### Services (`/services`)
- **credential-service.ts**: Core business logic for credential lifecycle management
- **biometric-service.ts**: Biometric enrollment, verification, and security management
- **device-management-service.ts**: Remote device actions (wipe, lock, compliance checks)

### Routes (`/routes`)
- **credentials.ts**: REST endpoints for credential operations
- **biometric.ts**: Endpoints for biometric management
- **device-management.ts**: Device control endpoints
- **mesh-network.ts**: Mesh network status and messaging
- **offline-sync.ts**: Offline event synchronization

## Key Features

### 1. Mobile Credential Management
- Enrollment with BLE/NFC protocol support
- Cryptographic authentication
- Offline validation capabilities
- Multi-protocol support (standard, BLE, NFC)

### 2. Biometric Authentication
- Multiple biometric types (fingerprint, face, voice, iris)
- Template hashing for security
- Failed attempt tracking and lockout
- Quality and liveness checks

### 3. Device Management
- Remote wipe capabilities
- Device lock/unlock
- Location tracking
- Compliance checking
- Certificate management

### 4. Mesh Networking
- P2P credential revocation
- UDP multicast and TCP communication
- Message signing and verification
- Automatic peer discovery

### 5. Offline Synchronization
- Event queuing and replay
- Credential update synchronization
- Mesh message propagation
- Conflict resolution

## API Endpoints

### Credentials
- `POST /api/credentials/enroll` - Enroll new credential
- `POST /api/credentials/authenticate` - Authenticate credential
- `POST /api/credentials/revoke` - Revoke credentials
- `GET /api/credentials` - List credentials
- `GET /api/credentials/:id` - Get credential details
- `PATCH /api/credentials/:id/status` - Update status
- `POST /api/credentials/:id/challenge` - Generate challenge

### Biometric
- `POST /api/credentials/:id/biometric` - Enroll biometric
- `POST /api/credentials/:id/biometric/verify` - Verify biometric
- `GET /api/credentials/:id/biometric` - List biometrics
- `DELETE /api/credentials/:id/biometric/:type` - Delete biometric

### Device Management
- `POST /api/device-management` - Execute device action
- `GET /api/device-management/:id/power-status` - Get power status
- `GET /api/device-management/compliance/:id` - Check compliance

### Mesh Network
- `GET /api/mesh/status` - Network status
- `GET /api/mesh/peers` - List peers
- `POST /api/mesh/message` - Send message

### Offline Sync
- `POST /api/sync/offline-events` - Sync offline events
- `GET /api/sync/sync-status/:id` - Get sync status
- `GET /api/sync/pending-updates/:id` - Get pending updates

## Configuration

Environment variables:
- `PORT` - Service port (default: 3016)
- `JWT_SECRET` - JWT signing secret
- `ENCRYPTION_KEY` - Data encryption key
- `REDIS_URL` - Redis connection URL
- `MESH_NETWORK_ENABLED` - Enable mesh networking
- `DEVICE_ID` - Unique device identifier
- `BIOMETRIC_MAX_ATTEMPTS` - Max failed attempts
- `BIOMETRIC_LOCKOUT_DURATION` - Lockout time in seconds
- `MIN_APP_VERSION` - Minimum app version

## Migration from Monolithic

To migrate from the monolithic `index.ts` to the modular structure:

1. Rename current `index.ts` to `index.legacy.ts`
2. Rename `index.modular.ts` to `index.ts`
3. Update imports in other services that reference this service
4. Test all endpoints to ensure functionality is preserved

## Testing

The modular architecture makes unit testing much easier:

```typescript
// Test individual services
import { CredentialService } from './services/credential-service';

// Test protocol handlers
import { BLEProtocolHandler } from './protocols/ble-handler';

// Test routes independently
import { createCredentialsRoutes } from './routes/credentials';
```

## Benefits of Modularization

1. **Maintainability**: Each module has a single responsibility
2. **Testability**: Components can be tested in isolation
3. **Reusability**: Services and protocols can be reused
4. **Scalability**: Easy to add new features without affecting existing code
5. **Developer Experience**: Easier to navigate and understand codebase
6. **Performance**: Smaller files load and parse faster

## Next Steps

1. Add comprehensive unit tests for each module
2. Implement dependency injection for better testability
3. Add OpenAPI documentation for all endpoints
4. Create integration tests for complete workflows
5. Add performance monitoring and metrics