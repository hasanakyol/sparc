// Unified WebSocket exports

export { UnifiedWebSocketService, UnifiedWebSocketConfig } from './unifiedWebSocket';
export { 
  WebSocketClient, 
  WebSocketClientConfig,
  ConnectionState,
  WebSocketEvent,
  ClientEvents,
  VideoWebSocketClient,
  AlertWebSocketClient,
  MonitoringWebSocketClient
} from './client';

export * from './events';

// Re-export common types
export type { ClientMetadata, NamespaceConfig } from './unifiedWebSocket';