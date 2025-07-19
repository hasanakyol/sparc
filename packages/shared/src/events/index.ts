/**
 * Event Bus exports for SPARC platform
 */

// Core event bus
export {
  EventBus,
  TypedEventBus,
  DomainEvent,
  EventHandler,
  EventBusConfig,
  StoredEvent
} from './eventBus';

// Domain events
export * from './domainEvents';
export { SparcDomainEvents, EVENT_VERSIONS } from './domainEvents';

// Event handlers
export {
  BaseEventHandler,
  CompositeEventHandler,
  ConditionalEventHandler,
  BatchEventHandler,
  TransformEventHandler,
  DedupeEventHandler,
  AggregatorEventHandler,
  HandlerRegistry,
  EventCorrelator
} from './eventHandlers';

// Monitoring and debugging
export {
  EventBusMetrics,
  EventFlowTracer,
  EventTrace,
  TraceStep,
  EventDebugger,
  DebugFilter,
  EventHistoryQuery,
  QueryCriteria,
  EventBusHealthChecker,
  HealthCheckResult,
  HealthCheck
} from './eventMonitoring';

// Factory function for creating a typed event bus
import { EventBusConfig } from './eventBus';
import { TypedEventBus } from './eventBus';
import { SparcDomainEvents } from './domainEvents';

export function createSparcEventBus(config: EventBusConfig): TypedEventBus<SparcDomainEvents> {
  return new TypedEventBus<SparcDomainEvents>(config);
}