import { io, Socket } from 'socket.io-client';
import { EventEmitter } from 'events';
import { logger } from '../logger';

// WebSocket client configuration
export interface WebSocketClientConfig {
  url: string;
  namespace: string;
  token: string;
  autoReconnect?: boolean;
  reconnectInterval?: number;
  reconnectAttempts?: number;
  timeout?: number;
}

// Connection state
export enum ConnectionState {
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  RECONNECTING = 'reconnecting',
  ERROR = 'error',
}

// Base event interface
export interface WebSocketEvent<T = any> {
  timestamp: string;
  event: string;
  data: T;
}

// Client event types
export interface ClientEvents {
  'state:changed': (state: ConnectionState) => void;
  'connected': (data: { clientId: string; namespace: string; tenantId: string }) => void;
  'disconnected': (reason: string) => void;
  'error': (error: Error) => void;
  'subscribed': (data: { channels: string[] }) => void;
  'unsubscribed': (data: { channels: string[] }) => void;
  'message': (event: WebSocketEvent) => void;
}

export class WebSocketClient extends EventEmitter {
  private socket: Socket | null = null;
  private config: Required<WebSocketClientConfig>;
  private state: ConnectionState = ConnectionState.DISCONNECTED;
  private reconnectTimer?: NodeJS.Timeout;
  private reconnectCount: number = 0;
  private subscriptions: Set<string> = new Set();

  constructor(config: WebSocketClientConfig) {
    super();

    this.config = {
      autoReconnect: true,
      reconnectInterval: 5000,
      reconnectAttempts: 10,
      timeout: 10000,
      ...config,
    };
  }

  // Type-safe event emitter
  public emit<K extends keyof ClientEvents>(
    event: K,
    ...args: Parameters<ClientEvents[K]>
  ): boolean {
    return super.emit(event, ...args);
  }

  public on<K extends keyof ClientEvents>(
    event: K,
    listener: ClientEvents[K]
  ): this {
    return super.on(event, listener);
  }

  public off<K extends keyof ClientEvents>(
    event: K,
    listener: ClientEvents[K]
  ): this {
    return super.off(event, listener);
  }

  // Connection management
  public connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.state === ConnectionState.CONNECTED) {
        resolve();
        return;
      }

      this.setState(ConnectionState.CONNECTING);

      try {
        const url = `${this.config.url}/${this.config.namespace}`;
        
        this.socket = io(url, {
          auth: {
            token: this.config.token,
          },
          transports: ['websocket', 'polling'],
          timeout: this.config.timeout,
          reconnection: false, // We handle reconnection manually
        });

        this.setupEventHandlers();

        // Set up connection timeout
        const timeout = setTimeout(() => {
          this.disconnect();
          reject(new Error('Connection timeout'));
        }, this.config.timeout);

        this.socket.once('connect', () => {
          clearTimeout(timeout);
          this.setState(ConnectionState.CONNECTED);
          this.reconnectCount = 0;
          resolve();
        });

        this.socket.once('connect_error', (error) => {
          clearTimeout(timeout);
          this.setState(ConnectionState.ERROR);
          reject(error);
        });
      } catch (error) {
        this.setState(ConnectionState.ERROR);
        reject(error);
      }
    });
  }

  public disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }

    if (this.socket) {
      this.socket.removeAllListeners();
      this.socket.disconnect();
      this.socket = null;
    }

    this.setState(ConnectionState.DISCONNECTED);
    this.subscriptions.clear();
  }

  public async reconnect(): Promise<void> {
    this.disconnect();
    await this.connect();

    // Re-subscribe to previous channels
    if (this.subscriptions.size > 0) {
      await this.subscribe(Array.from(this.subscriptions));
    }
  }

  // Subscription management
  public async subscribe(channels: string | string[]): Promise<void> {
    const channelArray = Array.isArray(channels) ? channels : [channels];
    
    if (!this.isConnected()) {
      throw new Error('Not connected to WebSocket server');
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Subscribe timeout'));
      }, 5000);

      this.socket!.emit('subscribe', { channels: channelArray });

      this.socket!.once('subscribed', (data: { channels: string[] }) => {
        clearTimeout(timeout);
        data.channels.forEach(channel => this.subscriptions.add(channel));
        this.emit('subscribed', data);
        resolve();
      });

      this.socket!.once('error', (error: any) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  public async unsubscribe(channels: string | string[]): Promise<void> {
    const channelArray = Array.isArray(channels) ? channels : [channels];
    
    if (!this.isConnected()) {
      throw new Error('Not connected to WebSocket server');
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Unsubscribe timeout'));
      }, 5000);

      this.socket!.emit('unsubscribe', { channels: channelArray });

      this.socket!.once('unsubscribed', (data: { channels: string[] }) => {
        clearTimeout(timeout);
        data.channels.forEach(channel => this.subscriptions.delete(channel));
        this.emit('unsubscribed', data);
        resolve();
      });

      this.socket!.once('error', (error: any) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  // Send messages
  public send(event: string, data: any): void {
    if (!this.isConnected()) {
      throw new Error('Not connected to WebSocket server');
    }

    this.socket!.emit(event, data);
  }

  // Request-response pattern
  public async request<T = any>(event: string, data: any, timeout: number = 5000): Promise<T> {
    if (!this.isConnected()) {
      throw new Error('Not connected to WebSocket server');
    }

    return new Promise((resolve, reject) => {
      const responseEvent = `${event}:response`;
      
      const timer = setTimeout(() => {
        this.socket!.off(responseEvent);
        reject(new Error(`Request timeout for event: ${event}`));
      }, timeout);

      this.socket!.once(responseEvent, (response: T) => {
        clearTimeout(timer);
        resolve(response);
      });

      this.socket!.once('error', (error: any) => {
        clearTimeout(timer);
        reject(error);
      });

      this.socket!.emit(event, data);
    });
  }

  // State management
  private setState(state: ConnectionState): void {
    if (this.state !== state) {
      this.state = state;
      this.emit('state:changed', state);
    }
  }

  private setupEventHandlers(): void {
    if (!this.socket) return;

    // Connection events
    this.socket.on('connected', (data) => {
      logger.info('WebSocket connected', data);
      this.emit('connected', data);
    });

    this.socket.on('disconnect', (reason) => {
      logger.info('WebSocket disconnected', { reason });
      this.emit('disconnected', reason);
      this.setState(ConnectionState.DISCONNECTED);
      
      if (this.config.autoReconnect && this.reconnectCount < this.config.reconnectAttempts) {
        this.scheduleReconnect();
      }
    });

    this.socket.on('error', (error) => {
      logger.error('WebSocket error', { error });
      this.emit('error', error);
    });

    // Ping-pong for keepalive
    this.socket.on('ping', (data) => {
      this.socket!.emit('pong', data);
    });

    // Handle incoming messages
    this.socket.onAny((eventName, ...args) => {
      // Skip internal events
      if (['connected', 'disconnect', 'error', 'ping', 'pong', 'subscribed', 'unsubscribed'].includes(eventName)) {
        return;
      }

      const event: WebSocketEvent = {
        timestamp: new Date().toISOString(),
        event: eventName,
        data: args[0],
      };

      this.emit('message', event);
    });
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;

    this.setState(ConnectionState.RECONNECTING);
    this.reconnectCount++;

    const delay = Math.min(
      this.config.reconnectInterval * Math.pow(2, this.reconnectCount - 1),
      30000 // Max 30 seconds
    );

    logger.info(`Scheduling reconnect attempt ${this.reconnectCount}/${this.config.reconnectAttempts} in ${delay}ms`);

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = undefined;
      
      try {
        await this.connect();
      } catch (error) {
        logger.error('Reconnect failed', { error, attempt: this.reconnectCount });
        
        if (this.reconnectCount < this.config.reconnectAttempts) {
          this.scheduleReconnect();
        } else {
          this.setState(ConnectionState.ERROR);
          this.emit('error', new Error('Max reconnection attempts reached'));
        }
      }
    }, delay);
  }

  // Utility methods
  public isConnected(): boolean {
    return this.state === ConnectionState.CONNECTED && this.socket?.connected === true;
  }

  public getState(): ConnectionState {
    return this.state;
  }

  public getSubscriptions(): string[] {
    return Array.from(this.subscriptions);
  }
}

// Specialized clients for each namespace
export class VideoWebSocketClient extends WebSocketClient {
  constructor(config: Omit<WebSocketClientConfig, 'namespace'>) {
    super({ ...config, namespace: 'video' });
  }

  // Video-specific methods
  public async startStream(cameraId: string, quality: string = 'high'): Promise<void> {
    await this.request('stream:start', { cameraId, quality });
  }

  public async stopStream(cameraId: string): Promise<void> {
    await this.request('stream:stop', { cameraId });
  }

  public async startRecording(cameraId: string, duration?: number): Promise<void> {
    await this.request('recording:start', { cameraId, duration });
  }

  public async stopRecording(cameraId: string): Promise<void> {
    await this.request('recording:stop', { cameraId });
  }
}

export class AlertWebSocketClient extends WebSocketClient {
  constructor(config: Omit<WebSocketClientConfig, 'namespace'>) {
    super({ ...config, namespace: 'alerts' });
  }

  // Alert-specific methods
  public async subscribeToAlerts(alertTypes?: string[], priorities?: string[]): Promise<void> {
    await this.request('subscribe', { alertTypes, priorities });
  }

  public async acknowledgeAlert(alertId: string): Promise<void> {
    await this.request('acknowledge', { alertId });
  }
}

export class MonitoringWebSocketClient extends WebSocketClient {
  constructor(config: Omit<WebSocketClientConfig, 'namespace'>) {
    super({ ...config, namespace: 'monitoring' });
  }

  // Monitoring-specific methods
  public async subscribeToMetrics(metrics: string[], interval: number = 5000): Promise<void> {
    await this.request('metrics:subscribe', { metrics, interval });
  }

  public async subscribeToEvents(eventTypes: string[]): Promise<void> {
    await this.request('events:subscribe', { eventTypes });
  }
}