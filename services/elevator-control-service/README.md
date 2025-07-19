# Elevator Control Service

The Elevator Control Service manages integration with various elevator control systems, providing a unified API for elevator operations, access control, and monitoring.

## Features

- **Multi-Manufacturer Support**: Adapter pattern for different elevator manufacturers (OTIS, KONE, Schindler, etc.)
- **Access Control Integration**: Floor-based access permissions synchronized with access control service
- **Emergency Override**: Support for emergency operations (stop, evacuate, lockdown)
- **Destination Dispatch**: Optimized elevator assignment for multiple requests
- **Real-time Monitoring**: Live status updates and diagnostics
- **Maintenance Mode**: Support for scheduled and emergency maintenance
- **Alert Integration**: Automatic alerts for faults, emergencies, and maintenance needs
- **Webhook Support**: Receive events from external elevator systems

## Architecture

The service uses the adapter pattern to support multiple elevator manufacturers:

```
ElevatorControlService
    ├── BaseElevatorAdapter (abstract)
    │   ├── OtisAdapter ✅ (implemented)
    │   ├── KoneAdapter (TODO)
    │   ├── SchindlerAdapter (TODO)
    │   ├── ThyssenKruppAdapter (TODO)
    │   ├── MitsubishiAdapter (TODO)
    │   └── FujitecAdapter (TODO)
    └── AdapterFactory
```

## Configuration

### Environment Variables

```bash
# Service Configuration
PORT=3017
JWT_SECRET=your-jwt-secret
DATABASE_URL=postgresql://user:pass@localhost:5432/sparc
REDIS_URL=redis://localhost:6379

# External Services
ALERT_SERVICE_URL=http://alert-service:3012
ACCESS_CONTROL_SERVICE_URL=http://access-control-service:3003

# Elevator Configuration
ELEVATOR_SIMULATOR_MODE=true  # Enable simulator mode for testing
DEFAULT_TIMEOUT=5000
MAX_RETRIES=3

# Manufacturer API Keys (when not in simulator mode)
OTIS_API_KEY=your-otis-api-key
OTIS_API_URL=https://api.otis.com/v1
KONE_API_KEY=your-kone-api-key
KONE_API_URL=https://api.kone.com/v1
# ... other manufacturers
```

## API Endpoints

### Elevator Management

- `GET /api/elevators` - List all elevators
- `GET /api/elevators/:id` - Get elevator details with real-time status
- `POST /api/elevators` - Create new elevator configuration
- `PUT /api/elevators/:id` - Update elevator configuration
- `DELETE /api/elevators/:id` - Delete elevator configuration

### Elevator Operations

- `POST /api/elevators/:id/access` - Request floor access
- `POST /api/elevators/:id/emergency` - Emergency override (stop, evacuate, lockdown)
- `GET /api/elevators/:id/status` - Get real-time elevator status
- `GET /api/elevators/:id/diagnostics` - Get elevator diagnostics (maintenance only)
- `POST /api/elevators/:id/maintenance` - Set maintenance mode
- `POST /api/elevators/:id/reset` - Reset elevator system

### Building Operations

- `POST /api/buildings/:id/dispatch` - Destination dispatch for multiple requests
- `GET /api/buildings/:id/elevators/status` - Get all elevator statuses in building

### Integrations

- `POST /api/integrations/access-control/sync` - Sync access control permissions
- `POST /api/integrations/test-connections` - Test elevator connections

### Webhooks

- `POST /api/webhooks/elevator-events` - Receive events from elevator systems

## Testing the OTIS Adapter

The service includes a test script for the OTIS adapter:

```bash
npm run dev
# In another terminal:
npx tsx src/test-adapter.ts
```

This will run through various elevator operations in simulator mode.

## Simulator Mode

When `ELEVATOR_SIMULATOR_MODE=true`, the service runs with mock elevator responses, useful for:
- Development and testing
- Demonstrations
- Integration testing without real hardware

Simulator features:
- Realistic elevator movement simulation
- Random door operations
- Configurable failure rates
- Real-time status updates

## Extending with New Manufacturers

To add support for a new manufacturer:

1. Create a new adapter class extending `BaseElevatorAdapter`:
```typescript
// src/adapters/kone.adapter.ts
export class KoneAdapter extends BaseElevatorAdapter {
  // Implement all abstract methods
}
```

2. Update the `AdapterFactory` to include the new adapter:
```typescript
case 'KONE':
  return new KoneAdapter(config, logger);
```

3. Add manufacturer-specific configuration in `AdapterFactory.getAdapterConfig()`

4. Add the manufacturer to the `ManufacturerType` enum in types

## Security Considerations

- All API endpoints require JWT authentication (except webhooks)
- Tenant isolation is enforced at all levels
- Emergency operations require special roles (SECURITY_ADMIN, EMERGENCY_RESPONDER)
- Maintenance operations require MAINTENANCE or ADMIN roles
- Webhook signatures should be verified in production

## Monitoring

The service provides:
- Health check endpoint: `GET /health`
- Readiness check: `GET /ready`
- Metrics endpoint: `GET /metrics`
- Service info: `GET /info`

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build

# Run tests
npm test

# Type checking
npm run typecheck

# Linting
npm run lint
```

## Production Deployment

The service is designed to run in Kubernetes with:
- Horizontal scaling support
- Health and readiness probes
- Graceful shutdown handling
- Connection pooling for elevator systems
- Redis-based caching for status data

## Future Enhancements

- [ ] Implement remaining manufacturer adapters
- [ ] Add WebSocket support for real-time status updates
- [ ] Implement predictive maintenance based on diagnostics
- [ ] Add support for multi-car elevator groups
- [ ] Implement advanced destination dispatch algorithms
- [ ] Add support for elevator advertising displays
- [ ] Implement energy optimization features