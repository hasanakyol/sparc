import { EventEmitter } from 'events';
import SerialPort from 'serialport';
import { logger } from '@sparc/shared';

// OSDP Command codes
enum OSDPCommand {
  POLL = 0x60,
  ID = 0x61,
  CAP = 0x62,
  LSTAT = 0x64,
  ISTAT = 0x65,
  OSTAT = 0x66,
  RSTAT = 0x67,
  OUT = 0x68,
  LED = 0x69,
  BUZ = 0x6A,
  TEXT = 0x6B,
  COMSET = 0x6E,
  MFG = 0x80,
}

// OSDP Reply codes
enum OSDPReply {
  ACK = 0x40,
  NAK = 0x41,
  PDID = 0x45,
  PDCAP = 0x46,
  LSTATR = 0x48,
  ISTATR = 0x49,
  OSTATR = 0x4A,
  RSTATR = 0x4B,
  RAW = 0x50,
  FMT = 0x51,
  KEYPAD = 0x53,
  COM = 0x54,
  MFGREP = 0x90,
}

interface OSDPDevice {
  address: number;
  online: boolean;
  lastSeen: Date;
  capabilities: Map<string, any>;
  serialNumber?: string;
  firmwareVersion?: string;
}

interface DoorStatus {
  locked: boolean;
  doorContact: boolean;
  rexActive: boolean;
  exitButton: boolean;
  tamper: boolean;
}

export class OSDPHandler extends EventEmitter {
  private port: SerialPort | null = null;
  private devices: Map<number, OSDPDevice> = new Map();
  private sequence: Map<number, number> = new Map();
  private readonly baudRate: number = 9600;
  private readonly timeout: number = 200; // ms
  private pollInterval: NodeJS.Timer | null = null;

  constructor(private portPath: string) {
    super();
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.port = new SerialPort(this.portPath, {
        baudRate: this.baudRate,
        dataBits: 8,
        parity: 'none',
        stopBits: 1,
      });

      this.port.on('open', () => {
        logger.info(`OSDP handler connected to ${this.portPath}`);
        this.startPolling();
        resolve();
      });

      this.port.on('error', (error) => {
        logger.error('OSDP port error', { error, port: this.portPath });
        reject(error);
      });

      this.port.on('data', (data: Buffer) => {
        this.processResponse(data);
      });
    });
  }

  async disconnect(): Promise<void> {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }

    if (this.port && this.port.isOpen) {
      return new Promise((resolve) => {
        this.port!.close(() => {
          logger.info('OSDP handler disconnected');
          resolve();
        });
      });
    }
  }

  async discoverDevices(startAddress: number = 0, endAddress: number = 127): Promise<number[]> {
    const foundDevices: number[] = [];

    for (let address = startAddress; address <= endAddress; address++) {
      try {
        const response = await this.sendCommand(address, OSDPCommand.POLL);
        if (response) {
          foundDevices.push(address);
          this.devices.set(address, {
            address,
            online: true,
            lastSeen: new Date(),
            capabilities: new Map(),
          });
        }
      } catch (error) {
        // Device not found at this address
      }
    }

    logger.info(`OSDP discovery complete. Found ${foundDevices.length} devices`, { devices: foundDevices });
    return foundDevices;
  }

  async getDeviceInfo(address: number): Promise<any> {
    const idResponse = await this.sendCommand(address, OSDPCommand.ID);
    const capResponse = await this.sendCommand(address, OSDPCommand.CAP);

    if (idResponse && capResponse) {
      const device = this.devices.get(address);
      if (device) {
        // Parse ID response
        const id = this.parseIDResponse(idResponse);
        device.serialNumber = id.serialNumber;
        device.firmwareVersion = id.firmwareVersion;

        // Parse capabilities
        const capabilities = this.parseCapabilities(capResponse);
        device.capabilities = capabilities;

        return {
          address,
          ...id,
          capabilities: Object.fromEntries(capabilities),
        };
      }
    }

    throw new Error(`Failed to get device info for address ${address}`);
  }

  async unlockDoor(address: number, doorNumber: number = 0, duration: number = 5): Promise<boolean> {
    try {
      // Send output command to unlock
      const command = Buffer.alloc(4);
      command[0] = doorNumber;
      command[1] = 0x01; // Output on
      command[2] = duration; // Duration in seconds
      command[3] = 0x00; // Timer LSB

      const response = await this.sendCommand(address, OSDPCommand.OUT, command);
      
      if (response && response[0] === OSDPReply.ACK) {
        logger.info('Door unlocked via OSDP', { address, doorNumber, duration });
        this.emit('doorUnlocked', { address, doorNumber });
        
        // Schedule relock
        setTimeout(() => {
          this.lockDoor(address, doorNumber);
        }, duration * 1000);
        
        return true;
      }
      
      return false;
    } catch (error) {
      logger.error('Failed to unlock door via OSDP', { error, address, doorNumber });
      return false;
    }
  }

  async lockDoor(address: number, doorNumber: number = 0): Promise<boolean> {
    try {
      // Send output command to lock
      const command = Buffer.alloc(4);
      command[0] = doorNumber;
      command[1] = 0x00; // Output off
      command[2] = 0x00;
      command[3] = 0x00;

      const response = await this.sendCommand(address, OSDPCommand.OUT, command);
      
      if (response && response[0] === OSDPReply.ACK) {
        logger.info('Door locked via OSDP', { address, doorNumber });
        this.emit('doorLocked', { address, doorNumber });
        return true;
      }
      
      return false;
    } catch (error) {
      logger.error('Failed to lock door via OSDP', { error, address, doorNumber });
      return false;
    }
  }

  async getDoorStatus(address: number): Promise<DoorStatus> {
    try {
      const lstatResponse = await this.sendCommand(address, OSDPCommand.LSTAT);
      const istatResponse = await this.sendCommand(address, OSDPCommand.ISTAT);

      if (lstatResponse && istatResponse) {
        return {
          locked: (lstatResponse[1] & 0x01) === 0,
          doorContact: (istatResponse[1] & 0x01) === 1,
          rexActive: (istatResponse[1] & 0x02) === 2,
          exitButton: (istatResponse[1] & 0x04) === 4,
          tamper: (istatResponse[1] & 0x08) === 8,
        };
      }

      throw new Error('Failed to get door status');
    } catch (error) {
      logger.error('Failed to get door status via OSDP', { error, address });
      throw error;
    }
  }

  async setLED(address: number, ledNumber: number, color: 'red' | 'green' | 'amber', mode: 'off' | 'on' | 'blink'): Promise<boolean> {
    try {
      const colorMap = { red: 1, green: 2, amber: 3 };
      const modeMap = { off: 0, on: 1, blink: 2 };

      const command = Buffer.alloc(4);
      command[0] = ledNumber;
      command[1] = colorMap[color];
      command[2] = modeMap[mode];
      command[3] = mode === 'blink' ? 10 : 0; // Blink rate

      const response = await this.sendCommand(address, OSDPCommand.LED, command);
      return response && response[0] === OSDPReply.ACK;
    } catch (error) {
      logger.error('Failed to set LED via OSDP', { error, address, ledNumber });
      return false;
    }
  }

  async buzzer(address: number, mode: 'off' | 'on' | 'beep', duration: number = 1): Promise<boolean> {
    try {
      const modeMap = { off: 0, on: 1, beep: 2 };

      const command = Buffer.alloc(4);
      command[0] = modeMap[mode];
      command[1] = mode === 'on' ? 15 : 5; // Tone
      command[2] = duration; // Duration in 100ms units
      command[3] = 0;

      const response = await this.sendCommand(address, OSDPCommand.BUZ, command);
      return response && response[0] === OSDPReply.ACK;
    } catch (error) {
      logger.error('Failed to control buzzer via OSDP', { error, address });
      return false;
    }
  }

  private async sendCommand(address: number, command: OSDPCommand, data?: Buffer): Promise<Buffer | null> {
    return new Promise((resolve) => {
      const sequence = this.getNextSequence(address);
      const packet = this.buildPacket(address, command, sequence, data);

      // Set timeout
      const timeout = setTimeout(() => {
        resolve(null);
      }, this.timeout);

      // Listen for response
      const responseHandler = (response: Buffer) => {
        clearTimeout(timeout);
        this.port!.removeListener('data', responseHandler);
        resolve(response);
      };

      this.port!.on('data', responseHandler);
      this.port!.write(packet);
    });
  }

  private buildPacket(address: number, command: OSDPCommand, sequence: number, data?: Buffer): Buffer {
    const dataLength = data ? data.length : 0;
    const packetLength = 8 + dataLength; // Header(5) + Command(1) + Data + CRC(2)
    
    const packet = Buffer.alloc(packetLength);
    let offset = 0;

    // Start of Message
    packet[offset++] = 0x53;
    
    // Address
    packet[offset++] = address | 0x80; // Set high bit for "secured" communication
    
    // Length
    packet.writeUInt16LE(packetLength, offset);
    offset += 2;
    
    // Control
    packet[offset++] = sequence & 0x03;
    
    // Command
    packet[offset++] = command;
    
    // Data
    if (data) {
      data.copy(packet, offset);
      offset += data.length;
    }
    
    // CRC
    const crc = this.calculateCRC16(packet.slice(0, offset));
    packet.writeUInt16LE(crc, offset);

    return packet;
  }

  private processResponse(data: Buffer): void {
    // Validate packet structure
    if (data.length < 8 || data[0] !== 0x53) {
      return;
    }

    const address = data[1] & 0x7F;
    const length = data.readUInt16LE(2);
    const control = data[4];
    const reply = data[5];
    
    const device = this.devices.get(address);
    if (device) {
      device.lastSeen = new Date();
      device.online = true;
    }

    // Process card read events
    if (reply === OSDPReply.RAW || reply === OSDPReply.FMT) {
      const cardData = data.slice(6, length - 2);
      this.emit('cardRead', {
        address,
        raw: reply === OSDPReply.RAW,
        data: cardData.toString('hex'),
      });
    }

    // Process keypad events
    if (reply === OSDPReply.KEYPAD) {
      const keyData = data.slice(6, length - 2);
      this.emit('keypadEntry', {
        address,
        keys: keyData.toString(),
      });
    }
  }

  private parseIDResponse(data: Buffer): any {
    return {
      vendorCode: data.slice(1, 4).toString('hex'),
      modelNumber: data[4],
      version: data[5],
      serialNumber: data.slice(6, 10).readUInt32LE(0).toString(),
      firmwareVersion: `${data[10]}.${data[11]}.${data[12]}`,
    };
  }

  private parseCapabilities(data: Buffer): Map<string, any> {
    const capabilities = new Map();
    let offset = 1;

    while (offset < data.length - 2) {
      const function_code = data[offset++];
      const compliance = data[offset++];
      const number = data[offset++];

      capabilities.set(`cap_${function_code}`, {
        compliance,
        number,
      });
    }

    return capabilities;
  }

  private startPolling(): void {
    this.pollInterval = setInterval(() => {
      this.devices.forEach((device, address) => {
        this.sendCommand(address, OSDPCommand.POLL).then((response) => {
          if (!response) {
            device.online = false;
            this.emit('deviceOffline', { address });
          }
        });
      });
    }, 5000); // Poll every 5 seconds
  }

  private getNextSequence(address: number): number {
    const current = this.sequence.get(address) || 0;
    const next = (current + 1) % 4;
    this.sequence.set(address, next);
    return next;
  }

  private calculateCRC16(data: Buffer): number {
    let crc = 0x1D0F;
    
    for (const byte of data) {
      crc ^= byte << 8;
      for (let i = 0; i < 8; i++) {
        if (crc & 0x8000) {
          crc = (crc << 1) ^ 0x1021;
        } else {
          crc <<= 1;
        }
      }
    }
    
    return crc & 0xFFFF;
  }
}