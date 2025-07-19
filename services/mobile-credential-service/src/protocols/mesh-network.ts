import { EventEmitter } from 'events';
import * as dgram from 'dgram';
import * as net from 'net';
import crypto from 'crypto';
import { promisify } from 'util';
import { MeshMessage } from '../types';

export class MobileCredentialMeshNetwork extends EventEmitter {
  private udpSocket: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private meshPeers: Map<string, any> = new Map();
  private messageCache: Map<string, Date> = new Map();
  private deviceId: string;
  private networkKey: Buffer;
  private logger: any;

  constructor(deviceId: string, logger: any) {
    super();
    this.deviceId = deviceId;
    this.networkKey = crypto.randomBytes(32);
    this.logger = logger;
  }

  async initialize(): Promise<void> {
    await this.initializeUDPSocket();
    await this.initializeTCPServer();
    this.startHeartbeat();
  }

  private async initializeUDPSocket(): Promise<void> {
    this.udpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    
    this.udpSocket.on('message', async (msg, rinfo) => {
      try {
        const message = JSON.parse(msg.toString());
        await this.processMeshMessage(message);
      } catch (error) {
        this.logger.warn('Invalid mesh message received', { error, from: rinfo.address });
      }
    });

    await promisify(this.udpSocket.bind.bind(this.udpSocket))(9998);
  }

  private async initializeTCPServer(): Promise<void> {
    this.tcpServer = net.createServer();
    
    this.tcpServer.on('connection', (socket) => {
      this.handleTCPConnection(socket);
    });

    await promisify(this.tcpServer.listen.bind(this.tcpServer))(9997);
  }

  private handleTCPConnection(socket: net.Socket): void {
    let buffer = '';
    
    socket.on('data', (data) => {
      buffer += data.toString();
      
      let newlineIndex;
      while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
        const messageStr = buffer.slice(0, newlineIndex);
        buffer = buffer.slice(newlineIndex + 1);
        
        try {
          const message = JSON.parse(messageStr);
          this.processMeshMessage(message);
        } catch (error) {
          this.logger.warn('Invalid TCP mesh message', { error });
        }
      }
    });
  }

  async broadcastCredentialRevocation(credentialIds: string[], tenantId: string, reason: string): Promise<void> {
    const message: MeshMessage = {
      id: crypto.randomUUID(),
      type: 'credential_revocation',
      sourceDeviceId: this.deviceId,
      tenantId,
      payload: { credentialIds, reason, timestamp: new Date() },
      timestamp: new Date(),
      ttl: 30,
      signature: this.signMessage({ credentialIds, reason })
    };

    await this.broadcastMessage(message);
  }

  async broadcastDeviceWipe(deviceIds: string[], tenantId: string): Promise<void> {
    const message: MeshMessage = {
      id: crypto.randomUUID(),
      type: 'device_wipe',
      sourceDeviceId: this.deviceId,
      tenantId,
      payload: { deviceIds, timestamp: new Date() },
      timestamp: new Date(),
      ttl: 30,
      signature: this.signMessage({ deviceIds })
    };

    await this.broadcastMessage(message);
  }

  private async broadcastMessage(message: MeshMessage): Promise<void> {
    const messageBuffer = Buffer.from(JSON.stringify(message));
    
    if (this.udpSocket) {
      await promisify(this.udpSocket.send.bind(this.udpSocket))(
        messageBuffer, 9998, '239.255.42.98'
      );
    }

    // Send to known TCP peers
    for (const peer of this.meshPeers.values()) {
      try {
        await this.sendMessageToPeer(message, peer);
      } catch (error) {
        this.logger.warn('Failed to send to peer', { peerId: peer.id, error: error.message });
      }
    }
  }

  private async sendMessageToPeer(message: MeshMessage, peer: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(peer.port, peer.address);
      const messageStr = JSON.stringify(message) + '\n';
      
      socket.on('connect', () => {
        socket.write(messageStr);
        socket.end();
        resolve();
      });
      
      socket.on('error', reject);
      setTimeout(() => {
        socket.destroy();
        reject(new Error('Connection timeout'));
      }, 5000);
    });
  }

  private async processMeshMessage(message: MeshMessage): Promise<void> {
    if (message.sourceDeviceId === this.deviceId) return;
    if (this.messageCache.has(message.id)) return;

    this.messageCache.set(message.id, new Date());
    this.cleanupMessageCache();

    switch (message.type) {
      case 'credential_revocation':
        this.emit('credentialRevocation', message.payload);
        break;
      case 'device_wipe':
        this.emit('deviceWipe', message.payload);
        break;
      case 'status_update':
        this.emit('statusUpdate', message.payload);
        break;
    }

    // Forward message if TTL allows
    if (message.ttl > 1) {
      message.ttl--;
      await this.broadcastMessage(message);
    }
  }

  private signMessage(payload: any): string {
    return crypto.createHmac('sha256', this.networkKey)
      .update(JSON.stringify(payload))
      .digest('hex');
  }

  private startHeartbeat(): void {
    setInterval(() => {
      this.broadcastMessage({
        id: crypto.randomUUID(),
        type: 'heartbeat',
        sourceDeviceId: this.deviceId,
        tenantId: 'system',
        payload: { timestamp: new Date(), status: 'active' },
        timestamp: new Date(),
        ttl: 3,
        signature: this.signMessage({ timestamp: new Date() })
      });
    }, 30000);
  }

  private cleanupMessageCache(): void {
    const now = new Date();
    for (const [messageId, timestamp] of this.messageCache.entries()) {
      if (now.getTime() - timestamp.getTime() > 300000) { // 5 minutes
        this.messageCache.delete(messageId);
      }
    }
  }

  async shutdown(): Promise<void> {
    if (this.udpSocket) this.udpSocket.close();
    if (this.tcpServer) await promisify(this.tcpServer.close.bind(this.tcpServer))();
  }
}