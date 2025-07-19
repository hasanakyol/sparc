import net from 'net';
import { EventEmitter } from 'events';
import { logger } from '@sparc/shared';

interface PanelConfig {
  host: string;
  port: number;
  panelId: string;
  username?: string;
  password?: string;
  keepAliveInterval?: number;
  reconnectDelay?: number;
  commandTimeout?: number;
}

interface DoorStatus {
  locked: boolean;
  doorContact: boolean;
  forcedOpen: boolean;
  heldOpen: boolean;
  offline: boolean;
}

enum CommandType {
  UNLOCK_DOOR = 0x01,
  LOCK_DOOR = 0x02,
  GET_STATUS = 0x03,
  SET_LED = 0x04,
  ACTIVATE_RELAY = 0x05,
  CARD_READ = 0x10,
  ALARM_EVENT = 0x20,
  HEARTBEAT = 0xFF,
}

export class TCPPanelHandler extends EventEmitter {
  private client: net.Socket | null = null;
  private config: PanelConfig;
  private connected: boolean = false;
  private reconnectTimer: NodeJS.Timer | null = null;
  private keepAliveTimer: NodeJS.Timer | null = null;
  private commandQueue: Map<string, { resolve: Function; reject: Function; timeout: NodeJS.Timer }> = new Map();
  private commandSequence: number = 0;

  constructor(config: PanelConfig) {
    super();
    this.config = {
      keepAliveInterval: 30000, // 30 seconds
      reconnectDelay: 5000, // 5 seconds
      commandTimeout: 5000, // 5 seconds
      ...config,
    };
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.client = new net.Socket();
      
      this.client.on('connect', () => {
        logger.info('TCP panel connected', { 
          host: this.config.host, 
          port: this.config.port,
          panelId: this.config.panelId 
        });
        this.connected = true;
        this.startKeepAlive();
        
        // Authenticate if credentials provided
        if (this.config.username && this.config.password) {
          this.authenticate().then(() => resolve()).catch(reject);
        } else {
          resolve();
        }
        
        this.emit('connected');
      });

      this.client.on('data', (data: Buffer) => {
        this.handleData(data);
      });

      this.client.on('error', (error) => {
        logger.error('TCP panel connection error', { 
          error, 
          panelId: this.config.panelId 
        });
        this.emit('error', error);
      });

      this.client.on('close', () => {
        logger.info('TCP panel disconnected', { panelId: this.config.panelId });
        this.connected = false;
        this.stopKeepAlive();
        this.emit('disconnected');
        this.scheduleReconnect();
      });

      this.client.connect(this.config.port, this.config.host);
      
      // Set connection timeout
      setTimeout(() => {
        if (!this.connected) {
          this.client?.destroy();
          reject(new Error('Connection timeout'));
        }
      }, 10000);
    });
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    this.stopKeepAlive();
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.client) {
      this.client.destroy();
      this.client = null;
    }

    // Clear pending commands
    this.commandQueue.forEach(({ reject, timeout }) => {
      clearTimeout(timeout);
      reject(new Error('Connection closed'));
    });
    this.commandQueue.clear();
  }

  async unlockDoor(doorId: number, duration: number = 5): Promise<boolean> {
    try {
      const command = this.buildCommand(CommandType.UNLOCK_DOOR, {
        doorId,
        duration,
      });

      const response = await this.sendCommand(command);
      const success = response.readUInt8(0) === 0x00; // Success code
      
      if (success) {
        logger.info('Door unlocked via TCP', { 
          panelId: this.config.panelId, 
          doorId, 
          duration 
        });
        
        this.emit('doorUnlocked', { doorId, duration });
        
        // Schedule automatic relock
        setTimeout(() => {
          this.lockDoor(doorId);
        }, duration * 1000);
      }
      
      return success;
    } catch (error) {
      logger.error('Failed to unlock door via TCP', { 
        error, 
        panelId: this.config.panelId, 
        doorId 
      });
      return false;
    }
  }

  async lockDoor(doorId: number): Promise<boolean> {
    try {
      const command = this.buildCommand(CommandType.LOCK_DOOR, { doorId });
      const response = await this.sendCommand(command);
      const success = response.readUInt8(0) === 0x00;
      
      if (success) {
        logger.info('Door locked via TCP', { 
          panelId: this.config.panelId, 
          doorId 
        });
        this.emit('doorLocked', { doorId });
      }
      
      return success;
    } catch (error) {
      logger.error('Failed to lock door via TCP', { 
        error, 
        panelId: this.config.panelId, 
        doorId 
      });
      return false;
    }
  }

  async getDoorStatus(doorId: number): Promise<DoorStatus> {
    try {
      const command = this.buildCommand(CommandType.GET_STATUS, { doorId });
      const response = await this.sendCommand(command);
      
      // Parse status bytes
      const statusByte = response.readUInt8(1);
      const alarmByte = response.readUInt8(2);
      
      return {
        locked: (statusByte & 0x01) === 0,
        doorContact: (statusByte & 0x02) === 0x02,
        forcedOpen: (alarmByte & 0x01) === 0x01,
        heldOpen: (alarmByte & 0x02) === 0x02,
        offline: (statusByte & 0x80) === 0x80,
      };
    } catch (error) {
      logger.error('Failed to get door status via TCP', { 
        error, 
        panelId: this.config.panelId, 
        doorId 
      });
      throw error;
    }
  }

  async setLED(doorId: number, ledId: number, state: 'off' | 'on' | 'blink', color?: 'red' | 'green' | 'amber'): Promise<boolean> {
    try {
      const stateMap = { off: 0, on: 1, blink: 2 };
      const colorMap = { red: 1, green: 2, amber: 3 };
      
      const command = this.buildCommand(CommandType.SET_LED, {
        doorId,
        ledId,
        state: stateMap[state],
        color: color ? colorMap[color] : 2, // Default to green
      });

      const response = await this.sendCommand(command);
      return response.readUInt8(0) === 0x00;
    } catch (error) {
      logger.error('Failed to set LED via TCP', { 
        error, 
        panelId: this.config.panelId, 
        doorId,
        ledId 
      });
      return false;
    }
  }

  async activateRelay(relayId: number, duration: number = 1): Promise<boolean> {
    try {
      const command = this.buildCommand(CommandType.ACTIVATE_RELAY, {
        relayId,
        duration,
      });

      const response = await this.sendCommand(command);
      return response.readUInt8(0) === 0x00;
    } catch (error) {
      logger.error('Failed to activate relay via TCP', { 
        error, 
        panelId: this.config.panelId, 
        relayId 
      });
      return false;
    }
  }

  private async authenticate(): Promise<void> {
    // Build authentication packet
    const authData = Buffer.alloc(64);
    authData.write(this.config.username!, 0, 32, 'utf8');
    authData.write(this.config.password!, 32, 32, 'utf8');
    
    const response = await this.sendRawData(authData);
    if (response.readUInt8(0) !== 0x00) {
      throw new Error('Authentication failed');
    }
    
    logger.info('TCP panel authenticated', { panelId: this.config.panelId });
  }

  private buildCommand(type: CommandType, data: any): Buffer {
    const payload = Buffer.from(JSON.stringify(data));
    const command = Buffer.alloc(8 + payload.length);
    
    // Header
    command.writeUInt8(0xAA, 0); // Start byte
    command.writeUInt8(type, 1); // Command type
    command.writeUInt16LE(this.commandSequence++, 2); // Sequence
    command.writeUInt16LE(payload.length, 4); // Payload length
    command.writeUInt16LE(this.calculateChecksum(payload), 6); // Checksum
    
    // Payload
    payload.copy(command, 8);
    
    return command;
  }

  private async sendCommand(command: Buffer): Promise<Buffer> {
    if (!this.connected || !this.client) {
      throw new Error('Not connected to panel');
    }

    const commandId = command.readUInt16LE(2).toString();
    
    return new Promise((resolve, reject) => {
      // Set timeout
      const timeout = setTimeout(() => {
        this.commandQueue.delete(commandId);
        reject(new Error('Command timeout'));
      }, this.config.commandTimeout!);

      // Store promise handlers
      this.commandQueue.set(commandId, { resolve, reject, timeout });
      
      // Send command
      this.client!.write(command);
    });
  }

  private async sendRawData(data: Buffer): Promise<Buffer> {
    if (!this.connected || !this.client) {
      throw new Error('Not connected to panel');
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Response timeout'));
      }, this.config.commandTimeout!);

      const responseHandler = (response: Buffer) => {
        clearTimeout(timeout);
        this.client!.removeListener('data', responseHandler);
        resolve(response);
      };

      this.client!.once('data', responseHandler);
      this.client!.write(data);
    });
  }

  private handleData(data: Buffer): void {
    // Check for valid packet
    if (data.length < 8 || data.readUInt8(0) !== 0xBB) {
      return;
    }

    const type = data.readUInt8(1);
    const sequence = data.readUInt16LE(2);
    const payloadLength = data.readUInt16LE(4);
    const payload = data.slice(8, 8 + payloadLength);

    // Handle different message types
    switch (type) {
      case CommandType.CARD_READ:
        this.handleCardRead(payload);
        break;
      case CommandType.ALARM_EVENT:
        this.handleAlarmEvent(payload);
        break;
      case CommandType.HEARTBEAT:
        // Panel heartbeat - no action needed
        break;
      default:
        // Response to a command
        const commandId = sequence.toString();
        const pendingCommand = this.commandQueue.get(commandId);
        if (pendingCommand) {
          clearTimeout(pendingCommand.timeout);
          pendingCommand.resolve(payload);
          this.commandQueue.delete(commandId);
        }
    }
  }

  private handleCardRead(data: Buffer): void {
    try {
      const event = JSON.parse(data.toString());
      this.emit('cardRead', {
        panelId: this.config.panelId,
        readerId: event.readerId,
        cardNumber: event.cardNumber,
        facilityCode: event.facilityCode,
        timestamp: new Date(event.timestamp),
      });
    } catch (error) {
      logger.error('Failed to parse card read event', { error, panelId: this.config.panelId });
    }
  }

  private handleAlarmEvent(data: Buffer): void {
    try {
      const event = JSON.parse(data.toString());
      this.emit('alarm', {
        panelId: this.config.panelId,
        type: event.type,
        doorId: event.doorId,
        description: event.description,
        timestamp: new Date(event.timestamp),
      });
      
      logger.warn('Panel alarm event', { 
        panelId: this.config.panelId, 
        event 
      });
    } catch (error) {
      logger.error('Failed to parse alarm event', { error, panelId: this.config.panelId });
    }
  }

  private startKeepAlive(): void {
    this.keepAliveTimer = setInterval(() => {
      if (this.connected && this.client) {
        const heartbeat = this.buildCommand(CommandType.HEARTBEAT, {});
        this.client.write(heartbeat);
      }
    }, this.config.keepAliveInterval!);
  }

  private stopKeepAlive(): void {
    if (this.keepAliveTimer) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (!this.reconnectTimer) {
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        logger.info('Attempting to reconnect to TCP panel', { panelId: this.config.panelId });
        this.connect().catch((error) => {
          logger.error('Reconnection failed', { error, panelId: this.config.panelId });
        });
      }, this.config.reconnectDelay!);
    }
  }

  private calculateChecksum(data: Buffer): number {
    let sum = 0;
    for (const byte of data) {
      sum = (sum + byte) & 0xFFFF;
    }
    return sum;
  }
}