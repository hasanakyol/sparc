import { EventEmitter } from 'events';
import * as dgram from 'dgram';
import * as net from 'net';
import * as dns from 'dns';
import { promisify } from 'util';
import axios from 'axios';
import { XMLParser } from 'fast-xml-parser';
import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify as util_promisify } from 'util';

const execAsync = util_promisify(exec);

// Types for device discovery
interface DiscoveredDevice {
  id: string;
  ipAddress: string;
  macAddress?: string;
  manufacturer: string;
  model: string;
  deviceType: DeviceType;
  capabilities: DeviceCapability[];
  protocols: string[];
  firmware?: string;
  serialNumber?: string;
  discoveryMethod: DiscoveryMethod;
  lastSeen: Date;
  status: DeviceStatus;
  configuration?: DeviceConfiguration;
  healthMetrics?: DeviceHealthMetrics;
  osdpAddress?: number;
  onvifProfiles?: string[];
  snmpCommunity?: string;
  firmwareUpdateStatus?: FirmwareUpdateStatus;
}

interface DeviceHealthMetrics {
  uptime: number;
  cpuUsage?: number;
  memoryUsage?: number;
  temperature?: number;
  powerStatus: string;
  networkLatency: number;
  lastResponse: Date;
  errorCount: number;
  signalStrength?: number;
  batteryLevel?: number;
  tamperStatus?: string;
  streamStatus?: string;
  diskUsage?: number;
}

interface FirmwareUpdateStatus {
  currentVersion: string;
  availableVersion?: string;
  updateInProgress: boolean;
  lastUpdateCheck: Date;
  updateHistory: FirmwareUpdateRecord[];
}

interface FirmwareUpdateRecord {
  version: string;
  updateDate: Date;
  success: boolean;
  errorMessage?: string;
}

interface OSDPDevice {
  address: number;
  capabilities: OSDPCapability[];
  secureChannel: boolean;
  keySet?: Buffer;
  lastCommand?: Date;
  commandQueue: OSDPCommand[];
}

interface OSDPCapability {
  function: number;
  compliance: number;
  numItems: number;
}

interface OSDPCommand {
  command: number;
  data: Buffer;
  sequenceNumber: number;
  timestamp: Date;
  retryCount: number;
}

interface ONVIFProfile {
  name: string;
  token: string;
  videoSourceConfiguration?: any;
  audioSourceConfiguration?: any;
  videoEncoderConfiguration?: any;
  audioEncoderConfiguration?: any;
  ptzConfiguration?: any;
  metadataConfiguration?: any;
}

interface SNMPDevice {
  community: string;
  version: '1' | '2c' | '3';
  oids: Map<string, any>;
  lastPoll: Date;
  pollInterval: number;
}

enum DeviceType {
  ACCESS_PANEL = 'access_panel',
  CARD_READER = 'card_reader',
  IP_CAMERA = 'ip_camera',
  DOOR_CONTROLLER = 'door_controller',
  INTERCOM = 'intercom',
  ENVIRONMENTAL_SENSOR = 'environmental_sensor'
}

enum DeviceCapability {
  OSDP = 'osdp',
  OSDP_SECURE = 'osdp_secure',
  WIEGAND = 'wiegand',
  ONVIF = 'onvif',
  ONVIF_PROFILE_S = 'onvif_profile_s',
  ONVIF_PROFILE_T = 'onvif_profile_t',
  ONVIF_PROFILE_G = 'onvif_profile_g',
  RTSP = 'rtsp',
  HTTP_API = 'http_api',
  SNMP = 'snmp',
  SNMP_V3 = 'snmp_v3',
  MOBILE_CREDENTIALS = 'mobile_credentials',
  BIOMETRIC = 'biometric',
  PTZ = 'ptz',
  AUDIO = 'audio',
  MOTION_DETECTION = 'motion_detection',
  NIGHT_VISION = 'night_vision',
  FIRMWARE_UPDATE = 'firmware_update',
  REMOTE_DIAGNOSTICS = 'remote_diagnostics',
  SECURE_BOOT = 'secure_boot',
  ENCRYPTION = 'encryption',
  TAMPER_DETECTION = 'tamper_detection'
}

enum DiscoveryMethod {
  NETWORK_SCAN = 'network_scan',
  DHCP_MONITORING = 'dhcp_monitoring',
  MDNS = 'mdns',
  ONVIF_WS_DISCOVERY = 'onvif_ws_discovery',
  MANUFACTURER_PROTOCOL = 'manufacturer_protocol',
  UPNP = 'upnp'
}

enum DeviceStatus {
  ONLINE = 'online',
  OFFLINE = 'offline',
  CONFIGURING = 'configuring',
  ERROR = 'error',
  UNKNOWN = 'unknown'
}

interface DeviceConfiguration {
  username?: string;
  password?: string;
  port?: number;
  protocol?: string;
  endpoints?: string[];
  features?: Record<string, any>;
  osdpConfig?: OSDPConfiguration;
  onvifConfig?: ONVIFConfiguration;
  snmpConfig?: SNMPConfiguration;
  firmwareConfig?: FirmwareConfiguration;
}

interface OSDPConfiguration {
  address: number;
  baudRate: number;
  secureChannel: boolean;
  masterKey?: Buffer;
  encryptionKey?: Buffer;
  macKey?: Buffer;
  pollInterval: number;
  retryCount: number;
  timeout: number;
}

interface ONVIFConfiguration {
  username: string;
  password: string;
  profiles: string[];
  streamUri?: string;
  ptzSupport: boolean;
  audioSupport: boolean;
  metadataSupport: boolean;
  eventSupport: boolean;
}

interface SNMPConfiguration {
  community: string;
  version: '1' | '2c' | '3';
  port: number;
  timeout: number;
  retries: number;
  v3Config?: {
    username: string;
    authProtocol?: 'MD5' | 'SHA';
    authKey?: string;
    privProtocol?: 'DES' | 'AES';
    privKey?: string;
  };
}

interface FirmwareConfiguration {
  autoUpdate: boolean;
  updateServer: string;
  checkInterval: number;
  backupBeforeUpdate: boolean;
  rollbackOnFailure: boolean;
  verifySignature: boolean;
}

interface ManufacturerProfile {
  name: string;
  oui: string[]; // Organizationally Unique Identifier for MAC addresses
  defaultPorts: number[];
  discoveryPorts: number[];
  httpPaths: string[];
  snmpOids: string[];
  deviceIdentifiers: DeviceIdentifier[];
}

interface DeviceIdentifier {
  pattern: string;
  deviceType: DeviceType;
  model?: string;
  capabilities: DeviceCapability[];
}

interface NetworkRange {
  network: string;
  cidr: number;
}

class DeviceDiscoveryService extends EventEmitter {
  private discoveredDevices: Map<string, DiscoveredDevice> = new Map();
  private manufacturerProfiles: Map<string, ManufacturerProfile> = new Map();
  private scanIntervals: Map<string, NodeJS.Timeout> = new Map();
  private dhcpSocket?: dgram.Socket;
  private mdnsSocket?: dgram.Socket;
  private isScanning = false;
  private xmlParser = new XMLParser();
  private osdpDevices: Map<string, OSDPDevice> = new Map();
  private onvifDevices: Map<string, ONVIFProfile[]> = new Map();
  private snmpDevices: Map<string, SNMPDevice> = new Map();
  private healthMonitorInterval?: NodeJS.Timeout;
  private firmwareUpdateQueue: Map<string, FirmwareUpdateStatus> = new Map();

  constructor() {
    super();
    this.initializeManufacturerProfiles();
    this.startHealthMonitoring();
  }

  /**
   * Initialize manufacturer profiles for device identification
   */
  private initializeManufacturerProfiles(): void {
    // HID Global
    this.manufacturerProfiles.set('hid', {
      name: 'HID Global',
      oui: ['00:06:8E', '00:1B:5F', '00:50:C2'],
      defaultPorts: [80, 443, 4070, 4071],
      discoveryPorts: [4070, 4071],
      httpPaths: ['/cgi-bin/status.cgi', '/api/v1/status', '/status', '/api/v1/device/info', '/vertx/api/system/status'],
      snmpOids: ['1.3.6.1.4.1.3309', '1.3.6.1.4.1.3309.1.1.1', '1.3.6.1.4.1.3309.1.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'VertX|Edge|iCLASS|EVO',
          deviceType: DeviceType.ACCESS_PANEL,
          capabilities: [DeviceCapability.OSDP, DeviceCapability.OSDP_SECURE, DeviceCapability.HTTP_API, DeviceCapability.MOBILE_CREDENTIALS, DeviceCapability.SNMP, DeviceCapability.FIRMWARE_UPDATE, DeviceCapability.REMOTE_DIAGNOSTICS]
        },
        {
          pattern: 'R40|R90|R10|multiCLASS',
          deviceType: DeviceType.CARD_READER,
          capabilities: [DeviceCapability.OSDP, DeviceCapability.OSDP_SECURE, DeviceCapability.MOBILE_CREDENTIALS, DeviceCapability.BIOMETRIC, DeviceCapability.TAMPER_DETECTION]
        }
      ]
    });

    // Honeywell
    this.manufacturerProfiles.set('honeywell', {
      name: 'Honeywell',
      oui: ['00:15:8D', '00:50:C2', '70:B3:D5'],
      defaultPorts: [80, 443, 8080, 8443],
      discoveryPorts: [8080, 8443],
      httpPaths: ['/api/system/info', '/system/deviceinfo', '/status.xml', '/api/v1/system/status', '/netaxs/api/system'],
      snmpOids: ['1.3.6.1.4.1.109', '1.3.6.1.4.1.109.1.1', '1.3.6.1.4.1.109.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'NetAXS|Pro-Watch|WIN-PAK|MAXPRO',
          deviceType: DeviceType.ACCESS_PANEL,
          capabilities: [DeviceCapability.HTTP_API, DeviceCapability.SNMP, DeviceCapability.SNMP_V3, DeviceCapability.OSDP, DeviceCapability.FIRMWARE_UPDATE, DeviceCapability.REMOTE_DIAGNOSTICS]
        }
      ]
    });

    // Bosch
    this.manufacturerProfiles.set('bosch', {
      name: 'Bosch',
      oui: ['00:0F:7C', '00:40:8C', '00:A0:57'],
      defaultPorts: [80, 443, 8080, 554],
      discoveryPorts: [80, 8080],
      httpPaths: ['/rcp.xml', '/api/v1/info', '/device/info', '/rcp.xml?command=0x0a00&type=P_OCTET', '/api/v1/system/status'],
      snmpOids: ['1.3.6.1.4.1.3967', '1.3.6.1.4.1.3967.1.1', '1.3.6.1.4.1.3967.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'DINION|FLEXIDOME|AutoDome|MIC|AUTODOME',
          deviceType: DeviceType.IP_CAMERA,
          capabilities: [DeviceCapability.ONVIF, DeviceCapability.ONVIF_PROFILE_S, DeviceCapability.ONVIF_PROFILE_T, DeviceCapability.ONVIF_PROFILE_G, DeviceCapability.RTSP, DeviceCapability.HTTP_API, DeviceCapability.PTZ, DeviceCapability.AUDIO, DeviceCapability.MOTION_DETECTION, DeviceCapability.FIRMWARE_UPDATE]
        },
        {
          pattern: 'AMC|APC|Access',
          deviceType: DeviceType.ACCESS_PANEL,
          capabilities: [DeviceCapability.HTTP_API, DeviceCapability.OSDP, DeviceCapability.OSDP_SECURE, DeviceCapability.SNMP, DeviceCapability.FIRMWARE_UPDATE]
        }
      ]
    });

    // Axis Communications
    this.manufacturerProfiles.set('axis', {
      name: 'Axis Communications',
      oui: ['00:40:8C', 'AC:CC:8E', 'B8:A4:4F'],
      defaultPorts: [80, 443, 554],
      discoveryPorts: [80, 443],
      httpPaths: ['/axis-cgi/param.cgi?action=list&group=Properties', '/axis-cgi/basicdeviceinfo.cgi', '/axis-cgi/param.cgi?action=list&group=Brand', '/axis-cgi/systeminfo.cgi', '/axis-cgi/param.cgi?action=list&group=Network'],
      snmpOids: ['1.3.6.1.4.1.368', '1.3.6.1.4.1.368.1.1', '1.3.6.1.4.1.368.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'AXIS.*Camera|AXIS.*Dome|AXIS.*Box|AXIS.*Bullet',
          deviceType: DeviceType.IP_CAMERA,
          capabilities: [DeviceCapability.ONVIF, DeviceCapability.ONVIF_PROFILE_S, DeviceCapability.ONVIF_PROFILE_T, DeviceCapability.ONVIF_PROFILE_G, DeviceCapability.RTSP, DeviceCapability.HTTP_API, DeviceCapability.MOTION_DETECTION, DeviceCapability.PTZ, DeviceCapability.AUDIO, DeviceCapability.NIGHT_VISION, DeviceCapability.FIRMWARE_UPDATE, DeviceCapability.REMOTE_DIAGNOSTICS]
        },
        {
          pattern: 'AXIS.*Door|AXIS.*Entry',
          deviceType: DeviceType.DOOR_CONTROLLER,
          capabilities: [DeviceCapability.HTTP_API, DeviceCapability.OSDP, DeviceCapability.OSDP_SECURE, DeviceCapability.SNMP, DeviceCapability.FIRMWARE_UPDATE]
        }
      ]
    });

    // Hikvision
    this.manufacturerProfiles.set('hikvision', {
      name: 'Hikvision',
      oui: ['44:19:B6', '4C:BD:8A', '28:57:BE'],
      defaultPorts: [80, 8000, 554, 8080],
      discoveryPorts: [80, 8000],
      httpPaths: ['/ISAPI/System/deviceInfo', '/SDK/deviceInfo', '/ISAPI/System/status', '/ISAPI/System/capabilities', '/ISAPI/ContentMgmt/Storage'],
      snmpOids: ['1.3.6.1.4.1.39165', '1.3.6.1.4.1.39165.1.1', '1.3.6.1.4.1.39165.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'DS-.*|iDS-.*|DS-2CD|DS-2DE',
          deviceType: DeviceType.IP_CAMERA,
          capabilities: [DeviceCapability.ONVIF, DeviceCapability.ONVIF_PROFILE_S, DeviceCapability.ONVIF_PROFILE_T, DeviceCapability.RTSP, DeviceCapability.HTTP_API, DeviceCapability.PTZ, DeviceCapability.MOTION_DETECTION, DeviceCapability.NIGHT_VISION, DeviceCapability.AUDIO, DeviceCapability.FIRMWARE_UPDATE]
        },
        {
          pattern: 'DS-K.*|DS-K1T',
          deviceType: DeviceType.ACCESS_PANEL,
          capabilities: [DeviceCapability.HTTP_API, DeviceCapability.WIEGAND, DeviceCapability.BIOMETRIC, DeviceCapability.SNMP, DeviceCapability.FIRMWARE_UPDATE, DeviceCapability.TAMPER_DETECTION]
        }
      ]
    });

    // Dahua
    this.manufacturerProfiles.set('dahua', {
      name: 'Dahua',
      oui: ['8C:E7:48', '54:04:A6', '00:12:16'],
      defaultPorts: [80, 37777, 554, 8000],
      discoveryPorts: [80, 37777],
      httpPaths: ['/cgi-bin/magicBox.cgi?action=getDeviceType', '/cgi-bin/global.cgi?action=getCurrentTime', '/cgi-bin/magicBox.cgi?action=getSystemInfo', '/cgi-bin/configManager.cgi?action=getConfig&name=General'],
      snmpOids: ['1.3.6.1.4.1.25506', '1.3.6.1.4.1.25506.1.1', '1.3.6.1.4.1.25506.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'IPC-.*|DH-.*|DH-IPC|DH-SD',
          deviceType: DeviceType.IP_CAMERA,
          capabilities: [DeviceCapability.ONVIF, DeviceCapability.ONVIF_PROFILE_S, DeviceCapability.ONVIF_PROFILE_T, DeviceCapability.RTSP, DeviceCapability.HTTP_API, DeviceCapability.PTZ, DeviceCapability.MOTION_DETECTION, DeviceCapability.NIGHT_VISION, DeviceCapability.AUDIO, DeviceCapability.FIRMWARE_UPDATE]
        }
      ]
    });

    // Hanwha (Samsung)
    this.manufacturerProfiles.set('hanwha', {
      name: 'Hanwha Techwin',
      oui: ['00:16:6C', '00:09:18', '34:FC:B9'],
      defaultPorts: [80, 443, 554, 4520],
      discoveryPorts: [80, 443],
      httpPaths: ['/stw-cgi/system.cgi?msubmenu=deviceinfo', '/cgi-bin/system_info.cgi', '/stw-cgi/system.cgi?msubmenu=firmwareinfo', '/stw-cgi/system.cgi?msubmenu=networkinfo'],
      snmpOids: ['1.3.6.1.4.1.36849', '1.3.6.1.4.1.36849.1.1', '1.3.6.1.4.1.36849.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'SNP-.*|PNM-.*|XNP-.*|QNP-.*|TNP-.*',
          deviceType: DeviceType.IP_CAMERA,
          capabilities: [DeviceCapability.ONVIF, DeviceCapability.ONVIF_PROFILE_S, DeviceCapability.ONVIF_PROFILE_T, DeviceCapability.ONVIF_PROFILE_G, DeviceCapability.RTSP, DeviceCapability.HTTP_API, DeviceCapability.PTZ, DeviceCapability.AUDIO, DeviceCapability.MOTION_DETECTION, DeviceCapability.NIGHT_VISION, DeviceCapability.FIRMWARE_UPDATE]
        }
      ]
    });

    // Genetec
    this.manufacturerProfiles.set('genetec', {
      name: 'Genetec',
      oui: ['00:0C:E5', '00:50:C2'],
      defaultPorts: [80, 443, 4590, 4591],
      discoveryPorts: [4590, 80],
      httpPaths: ['/api/system/status', '/genetec/status', '/api/v1/system/info', '/api/v1/device/capabilities'],
      snmpOids: ['1.3.6.1.4.1.17270', '1.3.6.1.4.1.17270.1.1', '1.3.6.1.4.1.17270.2.1'],
      deviceIdentifiers: [
        {
          pattern: 'Synergis|Security Center|SiPass',
          deviceType: DeviceType.ACCESS_PANEL,
          capabilities: [DeviceCapability.HTTP_API, DeviceCapability.OSDP, DeviceCapability.OSDP_SECURE, DeviceCapability.SNMP, DeviceCapability.SNMP_V3, DeviceCapability.FIRMWARE_UPDATE, DeviceCapability.REMOTE_DIAGNOSTICS, DeviceCapability.ENCRYPTION]
        }
      ]
    });
  }

  /**
   * Start comprehensive device discovery
   */
  async startDiscovery(networkRanges: NetworkRange[]): Promise<void> {
    if (this.isScanning) {
      throw new Error('Discovery already in progress');
    }

    this.isScanning = true;
    this.emit('discoveryStarted');

    try {
      // Start parallel discovery methods
      await Promise.all([
        this.startNetworkScanning(networkRanges),
        this.startMdnsDiscovery(),
        this.startOnvifWsDiscovery(),
        this.startDhcpMonitoring(),
        this.startOsdpDiscovery(),
        this.startSnmpDiscovery(networkRanges)
      ]);

      // Set up periodic scanning
      this.setupPeriodicScanning(networkRanges);

    } catch (error) {
      this.isScanning = false;
      this.emit('discoveryError', error);
      throw error;
    }
  }

  /**
   * Start OSDP v2.2 device discovery
   */
  private async startOsdpDiscovery(): Promise<void> {
    console.log('Starting OSDP v2.2 device discovery...');
    
    // Scan common OSDP ports and addresses
    const osdpPorts = [4070, 4071, 9999, 10001];
    const osdpAddresses = Array.from({ length: 126 }, (_, i) => i + 1); // OSDP addresses 1-126
    
    for (const port of osdpPorts) {
      try {
        await this.scanOsdpPort(port, osdpAddresses);
      } catch (error) {
        console.warn(`OSDP discovery failed on port ${port}:`, error.message);
      }
    }
  }

  /**
   * Scan OSDP port for devices
   */
  private async scanOsdpPort(port: number, addresses: number[]): Promise<void> {
    for (const address of addresses) {
      try {
        const device = await this.probeOsdpDevice('localhost', port, address);
        if (device) {
          this.addDiscoveredDevice(device);
        }
      } catch (error) {
        // Continue with next address
      }
    }
  }

  /**
   * Probe OSDP device using v2.2 protocol
   */
  private async probeOsdpDevice(host: string, port: number, address: number): Promise<DiscoveredDevice | null> {
    try {
      const socket = new net.Socket();
      
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          socket.destroy();
          reject(new Error('OSDP probe timeout'));
        }, 3000);

        socket.connect(port, host, async () => {
          try {
            // Send OSDP ID command (0x61)
            const idCommand = this.buildOsdpCommand(address, 0x61, Buffer.alloc(0));
            socket.write(idCommand);

            socket.once('data', (data) => {
              clearTimeout(timeout);
              socket.destroy();
              
              const response = this.parseOsdpResponse(data);
              if (response && response.command === 0x45) { // PDID response
                const device = this.createOsdpDevice(host, port, address, response);
                resolve(device);
              } else {
                resolve(null);
              }
            });
          } catch (error) {
            clearTimeout(timeout);
            socket.destroy();
            reject(error);
          }
        });

        socket.on('error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });
    } catch (error) {
      return null;
    }
  }

  /**
   * Build OSDP v2.2 command packet
   */
  private buildOsdpCommand(address: number, command: number, data: Buffer): Buffer {
    const som = 0x53; // Start of Message
    const ctrl = 0x00; // Control byte (no sequence, no CRC, no secure)
    const len = 6 + data.length; // Header + data length
    
    const packet = Buffer.alloc(len + 2); // +2 for checksum
    let offset = 0;
    
    packet[offset++] = som;
    packet[offset++] = address;
    packet[offset++] = len & 0xFF;
    packet[offset++] = (len >> 8) & 0xFF;
    packet[offset++] = ctrl;
    packet[offset++] = command;
    
    if (data.length > 0) {
      data.copy(packet, offset);
      offset += data.length;
    }
    
    // Calculate checksum
    let checksum = 0;
    for (let i = 0; i < offset; i++) {
      checksum += packet[i];
    }
    checksum = (~checksum + 1) & 0xFFFF;
    
    packet[offset++] = checksum & 0xFF;
    packet[offset++] = (checksum >> 8) & 0xFF;
    
    return packet.slice(0, offset);
  }

  /**
   * Parse OSDP response packet
   */
  private parseOsdpResponse(data: Buffer): any {
    if (data.length < 6) return null;
    
    const som = data[0];
    if (som !== 0x53) return null;
    
    const address = data[1];
    const len = data[2] | (data[3] << 8);
    const ctrl = data[4];
    const command = data[5];
    
    if (data.length < len + 2) return null;
    
    const payload = data.slice(6, len - 2);
    
    return {
      address,
      command,
      control: ctrl,
      data: payload
    };
  }

  /**
   * Create OSDP device from probe response
   */
  private createOsdpDevice(host: string, port: number, address: number, response: any): DiscoveredDevice {
    const deviceId = `osdp-${host}-${port}-${address}`;
    
    // Parse PDID response data
    let manufacturer = 'Unknown';
    let model = 'OSDP Device';
    let firmware = 'Unknown';
    let serialNumber = 'Unknown';
    
    if (response.data.length >= 12) {
      const vendorCode = response.data.readUInt32LE(0);
      const modelNumber = response.data.readUInt8(4);
      const version = response.data.readUInt8(5);
      const serialNum = response.data.readUInt32LE(6);
      const firmwareMajor = response.data.readUInt8(10);
      const firmwareMinor = response.data.readUInt8(11);
      
      // Map vendor codes to manufacturers
      const vendorMap: Record<number, string> = {
        0x00030D40: 'HID Global',
        0x0001026D: 'Honeywell',
        0x00000109: 'Bosch',
        0x00000368: 'Axis Communications'
      };
      
      manufacturer = vendorMap[vendorCode] || `Vendor-${vendorCode.toString(16)}`;
      model = `Model-${modelNumber}`;
      firmware = `${firmwareMajor}.${firmwareMinor}`;
      serialNumber = serialNum.toString();
    }
    
    const device: DiscoveredDevice = {
      id: deviceId,
      ipAddress: host,
      manufacturer,
      model,
      deviceType: DeviceType.ACCESS_PANEL,
      capabilities: [DeviceCapability.OSDP, DeviceCapability.OSDP_SECURE],
      protocols: ['OSDP'],
      firmware,
      serialNumber,
      discoveryMethod: DiscoveryMethod.MANUFACTURER_PROTOCOL,
      lastSeen: new Date(),
      status: DeviceStatus.ONLINE,
      osdpAddress: address,
      configuration: {
        port,
        protocol: 'OSDP',
        osdpConfig: {
          address,
          baudRate: 9600,
          secureChannel: false,
          pollInterval: 1000,
          retryCount: 3,
          timeout: 5000
        }
      }
    };
    
    // Store OSDP device info
    this.osdpDevices.set(deviceId, {
      address,
      capabilities: [],
      secureChannel: false,
      commandQueue: []
    });
    
    return device;
  }

  /**
   * Start SNMP device discovery
   */
  private async startSnmpDiscovery(networkRanges: NetworkRange[]): Promise<void> {
    console.log('Starting SNMP device discovery...');
    
    for (const range of networkRanges) {
      await this.scanSnmpRange(range);
    }
  }

  /**
   * Scan network range for SNMP devices
   */
  private async scanSnmpRange(range: NetworkRange): Promise<void> {
    const hosts = this.generateHostList(range.network, range.cidr);
    const communities = ['public', 'private', 'admin'];
    
    // Limit concurrent SNMP scans
    const concurrency = 20;
    const chunks = this.chunkArray(hosts, concurrency);

    for (const chunk of chunks) {
      await Promise.all(chunk.map(host => this.scanSnmpHost(host, communities)));
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }

  /**
   * Scan individual host for SNMP
   */
  private async scanSnmpHost(ipAddress: string, communities: string[]): Promise<void> {
    for (const community of communities) {
      try {
        const device = await this.probeSnmpDevice(ipAddress, community);
        if (device) {
          this.addDiscoveredDevice(device);
          break; // Found device, no need to try other communities
        }
      } catch (error) {
        // Continue with next community
      }
    }
  }

  /**
   * Probe SNMP device
   */
  private async probeSnmpDevice(ipAddress: string, community: string): Promise<DiscoveredDevice | null> {
    try {
      // Get system information via SNMP
      const systemInfo = await this.getSnmpSystemInfo(ipAddress, community);
      if (!systemInfo) return null;

      // Identify manufacturer from system OID
      const manufacturer = this.identifyManufacturerFromSnmp(systemInfo.sysObjectID);
      const profile = manufacturer ? this.manufacturerProfiles.get(manufacturer) : null;

      const device: DiscoveredDevice = {
        id: `snmp-${ipAddress}-${Date.now()}`,
        ipAddress,
        manufacturer: profile?.name || 'Unknown',
        model: systemInfo.sysDescr || 'SNMP Device',
        deviceType: this.guessDeviceTypeFromSnmp(systemInfo),
        capabilities: [DeviceCapability.SNMP],
        protocols: ['SNMP'],
        firmware: this.extractFirmwareFromSysDescr(systemInfo.sysDescr),
        serialNumber: systemInfo.sysName,
        discoveryMethod: DiscoveryMethod.MANUFACTURER_PROTOCOL,
        lastSeen: new Date(),
        status: DeviceStatus.ONLINE,
        snmpCommunity: community,
        configuration: {
          protocol: 'SNMP',
          snmpConfig: {
            community,
            version: '2c',
            port: 161,
            timeout: 3000,
            retries: 2
          }
        }
      };

      // Store SNMP device info
      this.snmpDevices.set(device.id, {
        community,
        version: '2c',
        oids: new Map(),
        lastPoll: new Date(),
        pollInterval: 30000
      });

      return device;
    } catch (error) {
      return null;
    }
  }

  /**
   * Get SNMP system information
   */
  private async getSnmpSystemInfo(ipAddress: string, community: string): Promise<any> {
    const oids = {
      sysDescr: '1.3.6.1.2.1.1.1.0',
      sysObjectID: '1.3.6.1.2.1.1.2.0',
      sysUpTime: '1.3.6.1.2.1.1.3.0',
      sysContact: '1.3.6.1.2.1.1.4.0',
      sysName: '1.3.6.1.2.1.1.5.0',
      sysLocation: '1.3.6.1.2.1.1.6.0'
    };

    try {
      const results: any = {};
      
      for (const [key, oid] of Object.entries(oids)) {
        const value = await this.snmpGet(ipAddress, community, oid);
        if (value) {
          results[key] = value;
        }
      }

      return Object.keys(results).length > 0 ? results : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Perform SNMP GET operation
   */
  private async snmpGet(ipAddress: string, community: string, oid: string): Promise<string | null> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket('udp4');
      const requestId = Math.floor(Math.random() * 0xFFFFFFFF);
      
      // Build SNMP GET request packet
      const packet = this.buildSnmpGetPacket(community, requestId, oid);
      
      const timeout = setTimeout(() => {
        socket.close();
        resolve(null);
      }, 3000);

      socket.on('message', (msg) => {
        clearTimeout(timeout);
        socket.close();
        
        const response = this.parseSnmpResponse(msg, requestId);
        resolve(response);
      });

      socket.on('error', () => {
        clearTimeout(timeout);
        socket.close();
        resolve(null);
      });

      socket.send(packet, 161, ipAddress);
    });
  }

  /**
   * Build SNMP GET packet
   */
  private buildSnmpGetPacket(community: string, requestId: number, oid: string): Buffer {
    // Simplified SNMP packet construction
    // In production, use a proper SNMP library like net-snmp
    const communityBytes = Buffer.from(community, 'utf8');
    const oidBytes = this.encodeOid(oid);
    
    // SNMP GET PDU structure (simplified)
    const pduType = 0xA0; // GET request
    const pdu = Buffer.concat([
      Buffer.from([pduType]),
      this.encodeLength(oidBytes.length + 10),
      this.encodeInteger(requestId),
      this.encodeInteger(0), // error status
      this.encodeInteger(0), // error index
      Buffer.from([0x30]), // varbind list
      this.encodeLength(oidBytes.length + 4),
      Buffer.from([0x30]), // varbind
      this.encodeLength(oidBytes.length + 2),
      oidBytes,
      Buffer.from([0x05, 0x00]) // null value
    ]);

    const message = Buffer.concat([
      Buffer.from([0x30]), // sequence
      this.encodeLength(communityBytes.length + pdu.length + 5),
      this.encodeInteger(1), // version (SNMPv2c)
      Buffer.from([0x04]), // octet string
      this.encodeLength(communityBytes.length),
      communityBytes,
      pdu
    ]);

    return message;
  }

  /**
   * Parse SNMP response
   */
  private parseSnmpResponse(data: Buffer, expectedRequestId: number): string | null {
    try {
      // Simplified SNMP response parsing
      // In production, use a proper SNMP library
      
      // Skip to the value part (this is a simplified approach)
      let offset = 0;
      
      // Find the response value (simplified parsing)
      while (offset < data.length - 2) {
        if (data[offset] === 0x04) { // octet string
          const length = data[offset + 1];
          if (length > 0 && offset + 2 + length <= data.length) {
            return data.slice(offset + 2, offset + 2 + length).toString('utf8');
          }
        }
        offset++;
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Encode OID for SNMP
   */
  private encodeOid(oid: string): Buffer {
    const parts = oid.split('.').map(Number);
    const encoded: number[] = [];
    
    // First two parts are encoded together
    encoded.push(parts[0] * 40 + parts[1]);
    
    // Encode remaining parts
    for (let i = 2; i < parts.length; i++) {
      let value = parts[i];
      if (value < 128) {
        encoded.push(value);
      } else {
        const bytes: number[] = [];
        while (value > 0) {
          bytes.unshift((value & 0x7F) | (bytes.length > 0 ? 0x80 : 0));
          value >>= 7;
        }
        encoded.push(...bytes);
      }
    }
    
    return Buffer.concat([
      Buffer.from([0x06]), // OID tag
      this.encodeLength(encoded.length),
      Buffer.from(encoded)
    ]);
  }

  /**
   * Encode length for ASN.1
   */
  private encodeLength(length: number): Buffer {
    if (length < 128) {
      return Buffer.from([length]);
    } else {
      const bytes: number[] = [];
      let temp = length;
      while (temp > 0) {
        bytes.unshift(temp & 0xFF);
        temp >>= 8;
      }
      return Buffer.from([0x80 | bytes.length, ...bytes]);
    }
  }

  /**
   * Encode integer for ASN.1
   */
  private encodeInteger(value: number): Buffer {
    const bytes: number[] = [];
    let temp = value;
    
    if (temp === 0) {
      bytes.push(0);
    } else {
      while (temp > 0) {
        bytes.unshift(temp & 0xFF);
        temp >>= 8;
      }
    }
    
    return Buffer.concat([
      Buffer.from([0x02]), // integer tag
      this.encodeLength(bytes.length),
      Buffer.from(bytes)
    ]);
  }

  /**
   * Identify manufacturer from SNMP system OID
   */
  private identifyManufacturerFromSnmp(sysObjectID: string): string | undefined {
    if (!sysObjectID) return undefined;

    const oidMap: Record<string, string> = {
      '1.3.6.1.4.1.3309': 'hid',
      '1.3.6.1.4.1.109': 'honeywell',
      '1.3.6.1.4.1.3967': 'bosch',
      '1.3.6.1.4.1.368': 'axis',
      '1.3.6.1.4.1.39165': 'hikvision',
      '1.3.6.1.4.1.25506': 'dahua',
      '1.3.6.1.4.1.36849': 'hanwha',
      '1.3.6.1.4.1.17270': 'genetec'
    };

    for (const [oid, manufacturer] of Object.entries(oidMap)) {
      if (sysObjectID.startsWith(oid)) {
        return manufacturer;
      }
    }

    return undefined;
  }

  /**
   * Guess device type from SNMP system description
   */
  private guessDeviceTypeFromSnmp(systemInfo: any): DeviceType {
    const sysDescr = systemInfo.sysDescr?.toLowerCase() || '';
    
    if (sysDescr.includes('camera') || sysDescr.includes('video')) {
      return DeviceType.IP_CAMERA;
    } else if (sysDescr.includes('access') || sysDescr.includes('door') || sysDescr.includes('reader')) {
      return DeviceType.ACCESS_PANEL;
    } else if (sysDescr.includes('sensor') || sysDescr.includes('environmental')) {
      return DeviceType.ENVIRONMENTAL_SENSOR;
    }
    
    return DeviceType.ACCESS_PANEL;
  }

  /**
   * Extract firmware version from system description
   */
  private extractFirmwareFromSysDescr(sysDescr: string): string | undefined {
    if (!sysDescr) return undefined;
    
    // Common firmware version patterns
    const patterns = [
      /version\s+(\d+\.\d+(?:\.\d+)?)/i,
      /v(\d+\.\d+(?:\.\d+)?)/i,
      /fw\s+(\d+\.\d+(?:\.\d+)?)/i,
      /(\d+\.\d+\.\d+)/
    ];
    
    for (const pattern of patterns) {
      const match = sysDescr.match(pattern);
      if (match) {
        return match[1];
      }
    }
    
    return undefined;
  }

  /**
   * Stop device discovery
   */
  async stopDiscovery(): Promise<void> {
    this.isScanning = false;

    // Clear intervals
    for (const [key, interval] of this.scanIntervals) {
      clearInterval(interval);
    }
    this.scanIntervals.clear();

    // Clear health monitoring
    if (this.healthMonitorInterval) {
      clearInterval(this.healthMonitorInterval);
      this.healthMonitorInterval = undefined;
    }

    // Close sockets
    if (this.dhcpSocket) {
      this.dhcpSocket.close();
      this.dhcpSocket = undefined;
    }

    if (this.mdnsSocket) {
      this.mdnsSocket.close();
      this.mdnsSocket = undefined;
    }

    this.emit('discoveryStopped');
  }

  /**
   * Network scanning for device discovery
   */
  private async startNetworkScanning(networkRanges: NetworkRange[]): Promise<void> {
    for (const range of networkRanges) {
      await this.scanNetworkRange(range);
    }
  }

  /**
   * Scan a specific network range
   */
  private async scanNetworkRange(range: NetworkRange): Promise<void> {
    const { network, cidr } = range;
    const hosts = this.generateHostList(network, cidr);

    // Limit concurrent scans to prevent network flooding
    const concurrency = 50;
    const chunks = this.chunkArray(hosts, concurrency);

    for (const chunk of chunks) {
      await Promise.all(chunk.map(host => this.scanHost(host)));
      // Small delay between chunks
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  /**
   * Scan individual host for devices
   */
  private async scanHost(ipAddress: string): Promise<void> {
    try {
      // First, check if host is reachable
      const isReachable = await this.pingHost(ipAddress);
      if (!isReachable) return;

      // Get MAC address if possible
      const macAddress = await this.getMacAddress(ipAddress);
      
      // Identify manufacturer from MAC
      const manufacturer = this.identifyManufacturerFromMac(macAddress);
      
      if (manufacturer) {
        const profile = this.manufacturerProfiles.get(manufacturer);
        if (profile) {
          await this.probeManufacturerDevice(ipAddress, macAddress, profile);
        }
      } else {
        // Generic device probing
        await this.probeGenericDevice(ipAddress, macAddress);
      }

    } catch (error) {
      // Silently continue with other hosts
    }
  }

  /**
   * Probe device using manufacturer-specific methods
   */
  private async probeManufacturerDevice(
    ipAddress: string, 
    macAddress: string | undefined, 
    profile: ManufacturerProfile
  ): Promise<void> {
    for (const port of profile.defaultPorts) {
      try {
        const deviceInfo = await this.probeHttpEndpoint(ipAddress, port, profile.httpPaths);
        if (deviceInfo) {
          const device = await this.createDeviceFromProbe(
            ipAddress, 
            macAddress, 
            profile, 
            deviceInfo, 
            DiscoveryMethod.MANUFACTURER_PROTOCOL
          );
          if (device) {
            this.addDiscoveredDevice(device);
          }
        }
      } catch (error) {
        // Continue with next port
      }
    }
  }

  /**
   * Probe device using generic methods
   */
  private async probeGenericDevice(ipAddress: string, macAddress: string | undefined): Promise<void> {
    const commonPorts = [80, 443, 8080, 8443, 554, 8000];
    
    for (const port of commonPorts) {
      try {
        const isOpen = await this.checkPortOpen(ipAddress, port);
        if (isOpen) {
          // Try common device endpoints
          const deviceInfo = await this.probeCommonEndpoints(ipAddress, port);
          if (deviceInfo) {
            const device = await this.createGenericDevice(
              ipAddress, 
              macAddress, 
              deviceInfo, 
              port
            );
            if (device) {
              this.addDiscoveredDevice(device);
            }
          }
        }
      } catch (error) {
        // Continue with next port
      }
    }
  }

  /**
   * mDNS discovery for network devices
   */
  private async startMdnsDiscovery(): Promise<void> {
    this.mdnsSocket = dgram.createSocket('udp4');
    
    this.mdnsSocket.on('message', (msg, rinfo) => {
      this.processMdnsResponse(msg, rinfo);
    });

    this.mdnsSocket.bind(5353, () => {
      // Send mDNS queries for common service types
      const serviceTypes = [
        '_http._tcp.local',
        '_onvif._tcp.local',
        '_axis-video._tcp.local',
        '_hikvision._tcp.local',
        '_dahua._tcp.local'
      ];

      for (const serviceType of serviceTypes) {
        this.sendMdnsQuery(serviceType);
      }
    });
  }

  /**
   * ONVIF WS-Discovery
   */
  private async startOnvifWsDiscovery(): Promise<void> {
    const socket = dgram.createSocket('udp4');
    
    const probeMessage = `<?xml version="1.0" encoding="UTF-8"?>
      <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
                     xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
                     xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
        <soap:Header>
          <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
          <wsa:MessageID>uuid:${this.generateUuid()}</wsa:MessageID>
          <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
        </soap:Header>
        <soap:Body>
          <tds:Probe>
            <tds:Types>tds:Device</tds:Types>
          </tds:Probe>
        </soap:Body>
      </soap:Envelope>`;

    socket.on('message', (msg, rinfo) => {
      this.processOnvifResponse(msg.toString(), rinfo);
    });

    socket.bind(() => {
      socket.setBroadcast(true);
      socket.send(probeMessage, 3702, '239.255.255.250');
    });

    // Close socket after discovery period
    setTimeout(() => {
      socket.close();
    }, 10000);
  }

  /**
   * DHCP monitoring for new devices
   */
  private async startDhcpMonitoring(): Promise<void> {
    // Note: This requires elevated privileges and network access
    // In production, this would integrate with DHCP server logs or SNMP
    try {
      this.dhcpSocket = dgram.createSocket('udp4');
      
      this.dhcpSocket.on('message', (msg, rinfo) => {
        this.processDhcpMessage(msg, rinfo);
      });

      this.dhcpSocket.bind(67); // DHCP server port
    } catch (error) {
      // DHCP monitoring may not be available in all environments
      console.warn('DHCP monitoring not available:', error.message);
    }
  }

  /**
   * Process ONVIF WS-Discovery response
   */
  private async processOnvifResponse(response: string, rinfo: dgram.RemoteInfo): Promise<void> {
    try {
      const parsed = this.xmlParser.parse(response);
      const envelope = parsed['soap:Envelope'] || parsed.Envelope;
      
      if (envelope && envelope['soap:Body']?.ProbeMatches?.ProbeMatch) {
        const match = envelope['soap:Body'].ProbeMatches.ProbeMatch;
        const xaddrs = match.XAddrs;
        
        if (xaddrs) {
          const urls = Array.isArray(xaddrs) ? xaddrs : [xaddrs];
          for (const url of urls) {
            await this.processOnvifDevice(url, rinfo.address);
          }
        }
      }
    } catch (error) {
      // Invalid ONVIF response
    }
  }

  /**
   * Process discovered ONVIF device
   */
  private async processOnvifDevice(serviceUrl: string, ipAddress: string): Promise<void> {
    try {
      // Get device information via ONVIF
      const deviceInfo = await this.getOnvifDeviceInfo(serviceUrl);
      
      if (deviceInfo) {
        const device: DiscoveredDevice = {
          id: `onvif-${ipAddress}-${Date.now()}`,
          ipAddress,
          manufacturer: deviceInfo.manufacturer || 'Unknown',
          model: deviceInfo.model || 'ONVIF Device',
          deviceType: DeviceType.IP_CAMERA,
          capabilities: [DeviceCapability.ONVIF, DeviceCapability.RTSP],
          protocols: ['ONVIF', 'RTSP'],
          firmware: deviceInfo.firmwareVersion,
          serialNumber: deviceInfo.serialNumber,
          discoveryMethod: DiscoveryMethod.ONVIF_WS_DISCOVERY,
          lastSeen: new Date(),
          status: DeviceStatus.ONLINE,
          configuration: {
            endpoints: [serviceUrl],
            protocol: 'ONVIF'
          }
        };

        this.addDiscoveredDevice(device);
      }
    } catch (error) {
      // Failed to get ONVIF device info
    }
  }

  /**
   * Get ONVIF device information with full Profile S/T/G support
   */
  private async getOnvifDeviceInfo(serviceUrl: string): Promise<any> {
    try {
      // Get basic device information
      const deviceInfo = await this.getOnvifBasicInfo(serviceUrl);
      if (!deviceInfo) return null;

      // Get capabilities
      const capabilities = await this.getOnvifCapabilities(serviceUrl);
      
      // Get profiles
      const profiles = await this.getOnvifProfiles(serviceUrl);
      
      // Determine supported ONVIF profiles
      const supportedProfiles = this.determineOnvifProfiles(capabilities, profiles);
      
      return {
        ...deviceInfo,
        capabilities,
        profiles,
        supportedProfiles
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Get basic ONVIF device information
   */
  private async getOnvifBasicInfo(serviceUrl: string): Promise<any> {
    const getDeviceInfoRequest = `<?xml version="1.0" encoding="UTF-8"?>
      <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
                     xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
        <soap:Body>
          <tds:GetDeviceInformation/>
        </soap:Body>
      </soap:Envelope>`;

    try {
      const response = await axios.post(serviceUrl, getDeviceInfoRequest, {
        headers: {
          'Content-Type': 'application/soap+xml',
          'SOAPAction': 'http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation'
        },
        timeout: 5000
      });

      const parsed = this.xmlParser.parse(response.data);
      const envelope = parsed['soap:Envelope'] || parsed.Envelope;
      const deviceInfo = envelope?.['soap:Body']?.GetDeviceInformationResponse;

      return deviceInfo ? {
        manufacturer: deviceInfo.Manufacturer,
        model: deviceInfo.Model,
        firmwareVersion: deviceInfo.FirmwareVersion,
        serialNumber: deviceInfo.SerialNumber,
        hardwareId: deviceInfo.HardwareId
      } : null;

    } catch (error) {
      return null;
    }
  }

  /**
   * Get ONVIF device capabilities
   */
  private async getOnvifCapabilities(serviceUrl: string): Promise<any> {
    const getCapabilitiesRequest = `<?xml version="1.0" encoding="UTF-8"?>
      <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
                     xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
        <soap:Body>
          <tds:GetCapabilities>
            <tds:Category>All</tds:Category>
          </tds:GetCapabilities>
        </soap:Body>
      </soap:Envelope>`;

    try {
      const response = await axios.post(serviceUrl, getCapabilitiesRequest, {
        headers: {
          'Content-Type': 'application/soap+xml',
          'SOAPAction': 'http://www.onvif.org/ver10/device/wsdl/GetCapabilities'
        },
        timeout: 5000
      });

      const parsed = this.xmlParser.parse(response.data);
      const envelope = parsed['soap:Envelope'] || parsed.Envelope;
      return envelope?.['soap:Body']?.GetCapabilitiesResponse?.Capabilities;

    } catch (error) {
      return null;
    }
  }

  /**
   * Get ONVIF media profiles
   */
  private async getOnvifProfiles(serviceUrl: string): Promise<ONVIFProfile[]> {
    // First get media service URL from capabilities
    const capabilities = await this.getOnvifCapabilities(serviceUrl);
    const mediaUrl = capabilities?.Media?.XAddr;
    
    if (!mediaUrl) return [];

    const getProfilesRequest = `<?xml version="1.0" encoding="UTF-8"?>
      <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
                     xmlns:trt="http://www.onvif.org/ver10/media/wsdl">
        <soap:Body>
          <trt:GetProfiles/>
        </soap:Body>
      </soap:Envelope>`;

    try {
      const response = await axios.post(mediaUrl, getProfilesRequest, {
        headers: {
          'Content-Type': 'application/soap+xml',
          'SOAPAction': 'http://www.onvif.org/ver10/media/wsdl/GetProfiles'
        },
        timeout: 5000
      });

      const parsed = this.xmlParser.parse(response.data);
      const envelope = parsed['soap:Envelope'] || parsed.Envelope;
      const profilesResponse = envelope?.['soap:Body']?.GetProfilesResponse?.Profiles;

      if (!profilesResponse) return [];

      const profiles = Array.isArray(profilesResponse) ? profilesResponse : [profilesResponse];
      
      return profiles.map((profile: any) => ({
        name: profile.Name,
        token: profile.token,
        videoSourceConfiguration: profile.VideoSourceConfiguration,
        audioSourceConfiguration: profile.AudioSourceConfiguration,
        videoEncoderConfiguration: profile.VideoEncoderConfiguration,
        audioEncoderConfiguration: profile.AudioEncoderConfiguration,
        ptzConfiguration: profile.PTZConfiguration,
        metadataConfiguration: profile.MetadataConfiguration
      }));

    } catch (error) {
      return [];
    }
  }

  /**
   * Determine supported ONVIF profiles (S/T/G)
   */
  private determineOnvifProfiles(capabilities: any, profiles: ONVIFProfile[]): string[] {
    const supportedProfiles: string[] = [];

    // Profile S: Video streaming
    if (capabilities?.Media && profiles.some(p => p.videoEncoderConfiguration)) {
      supportedProfiles.push('Profile_S');
    }

    // Profile T: Advanced video streaming with H.264/H.265
    if (capabilities?.Media && profiles.some(p => 
      p.videoEncoderConfiguration?.Encoding === 'H264' || 
      p.videoEncoderConfiguration?.Encoding === 'H265'
    )) {
      supportedProfiles.push('Profile_T');
    }

    // Profile G: Video recording and storage
    if (capabilities?.Recording || capabilities?.Replay) {
      supportedProfiles.push('Profile_G');
    }

    return supportedProfiles;
  }

  /**
   * Probe HTTP endpoints for device information
   */
  private async probeHttpEndpoint(
    ipAddress: string, 
    port: number, 
    paths: string[]
  ): Promise<any> {
    for (const path of paths) {
      try {
        const url = `http://${ipAddress}:${port}${path}`;
        const response = await axios.get(url, {
          timeout: 3000,
          validateStatus: () => true // Accept any status code
        });

        if (response.status === 200 && response.data) {
          return {
            url,
            data: response.data,
            headers: response.headers
          };
        }
      } catch (error) {
        // Continue with next path
      }
    }
    return null;
  }

  /**
   * Create device from manufacturer probe
   */
  private async createDeviceFromProbe(
    ipAddress: string,
    macAddress: string | undefined,
    profile: ManufacturerProfile,
    probeResult: any,
    discoveryMethod: DiscoveryMethod
  ): Promise<DiscoveredDevice | null> {
    try {
      // Parse device information from probe result
      const deviceInfo = this.parseDeviceInfo(probeResult.data, profile);
      
      if (!deviceInfo) return null;

      const device: DiscoveredDevice = {
        id: `${profile.name.toLowerCase()}-${ipAddress}-${Date.now()}`,
        ipAddress,
        macAddress,
        manufacturer: profile.name,
        model: deviceInfo.model || 'Unknown Model',
        deviceType: deviceInfo.deviceType || DeviceType.ACCESS_PANEL,
        capabilities: deviceInfo.capabilities || [],
        protocols: deviceInfo.protocols || ['HTTP'],
        firmware: deviceInfo.firmware,
        serialNumber: deviceInfo.serialNumber,
        discoveryMethod,
        lastSeen: new Date(),
        status: DeviceStatus.ONLINE,
        configuration: {
          endpoints: [probeResult.url],
          protocol: 'HTTP'
        }
      };

      return device;
    } catch (error) {
      return null;
    }
  }

  /**
   * Parse device information from probe response
   */
  private parseDeviceInfo(data: any, profile: ManufacturerProfile): any {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    
    for (const identifier of profile.deviceIdentifiers) {
      const regex = new RegExp(identifier.pattern, 'i');
      if (regex.test(dataStr)) {
        return {
          deviceType: identifier.deviceType,
          model: identifier.model,
          capabilities: identifier.capabilities,
          protocols: ['HTTP', 'HTTPS']
        };
      }
    }

    return null;
  }

  /**
   * Add discovered device to collection
   */
  private addDiscoveredDevice(device: DiscoveredDevice): void {
    const existingDevice = this.discoveredDevices.get(device.ipAddress);
    
    if (existingDevice) {
      // Update existing device
      existingDevice.lastSeen = new Date();
      existingDevice.status = DeviceStatus.ONLINE;
      this.emit('deviceUpdated', existingDevice);
    } else {
      // Add new device
      this.discoveredDevices.set(device.ipAddress, device);
      this.emit('deviceDiscovered', device);
    }
  }

  /**
   * Utility methods
   */
  private generateHostList(network: string, cidr: number): string[] {
    const hosts: string[] = [];
    const [baseIp] = network.split('/');
    const parts = baseIp.split('.').map(Number);
    const hostBits = 32 - cidr;
    const numHosts = Math.pow(2, hostBits) - 2; // Exclude network and broadcast

    for (let i = 1; i <= numHosts; i++) {
      const ip = this.calculateIpFromOffset(parts, i);
      hosts.push(ip);
    }

    return hosts;
  }

  private calculateIpFromOffset(baseParts: number[], offset: number): string {
    const parts = [...baseParts];
    parts[3] += offset;
    
    // Handle overflow
    for (let i = 3; i >= 0; i--) {
      if (parts[i] > 255) {
        parts[i] -= 256;
        if (i > 0) parts[i - 1]++;
      }
    }
    
    return parts.join('.');
  }

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  private async pingHost(ipAddress: string): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      const timeout = 1000;

      socket.setTimeout(timeout);
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
      
      socket.on('error', () => {
        resolve(false);
      });

      socket.connect(80, ipAddress);
    });
  }

  private async checkPortOpen(ipAddress: string, port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      const timeout = 2000;

      socket.setTimeout(timeout);
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
      
      socket.on('error', () => {
        resolve(false);
      });

      socket.connect(port, ipAddress);
    });
  }

  private async getMacAddress(ipAddress: string): Promise<string | undefined> {
    try {
      // This would typically use ARP table lookup
      // Implementation depends on the operating system
      return undefined;
    } catch (error) {
      return undefined;
    }
  }

  private identifyManufacturerFromMac(macAddress: string | undefined): string | undefined {
    if (!macAddress) return undefined;

    const oui = macAddress.substring(0, 8).toUpperCase();
    
    for (const [manufacturer, profile] of this.manufacturerProfiles) {
      if (profile.oui.some(profileOui => oui.startsWith(profileOui))) {
        return manufacturer;
      }
    }

    return undefined;
  }

  private async probeCommonEndpoints(ipAddress: string, port: number): Promise<any> {
    const commonPaths = [
      '/device/info',
      '/api/v1/system/info',
      '/cgi-bin/deviceinfo.cgi',
      '/system/deviceinfo',
      '/status',
      '/info'
    ];

    return this.probeHttpEndpoint(ipAddress, port, commonPaths);
  }

  private async createGenericDevice(
    ipAddress: string,
    macAddress: string | undefined,
    probeResult: any,
    port: number
  ): Promise<DiscoveredDevice | null> {
    // Basic device creation for unknown manufacturers
    const device: DiscoveredDevice = {
      id: `generic-${ipAddress}-${Date.now()}`,
      ipAddress,
      macAddress,
      manufacturer: 'Unknown',
      model: 'Generic Device',
      deviceType: this.guessDeviceType(port, probeResult),
      capabilities: this.guessCapabilities(port, probeResult),
      protocols: ['HTTP'],
      discoveryMethod: DiscoveryMethod.NETWORK_SCAN,
      lastSeen: new Date(),
      status: DeviceStatus.UNKNOWN,
      configuration: {
        port,
        endpoints: [probeResult.url]
      }
    };

    return device;
  }

  private guessDeviceType(port: number, probeResult: any): DeviceType {
    if (port === 554 || probeResult.data?.includes('rtsp')) {
      return DeviceType.IP_CAMERA;
    }
    return DeviceType.ACCESS_PANEL;
  }

  private guessCapabilities(port: number, probeResult: any): DeviceCapability[] {
    const capabilities: DeviceCapability[] = [DeviceCapability.HTTP_API];
    
    if (port === 554) {
      capabilities.push(DeviceCapability.RTSP);
    }
    
    return capabilities;
  }

  private sendMdnsQuery(serviceType: string): void {
    // mDNS query implementation
    const query = Buffer.from(`${serviceType}\x00\x00\x0C\x00\x01`);
    this.mdnsSocket?.send(query, 5353, '224.0.0.251');
  }

  private processMdnsResponse(msg: Buffer, rinfo: dgram.RemoteInfo): void {
    // Process mDNS response for device discovery
    // Implementation would parse DNS response format
  }

  private processDhcpMessage(msg: Buffer, rinfo: dgram.RemoteInfo): void {
    // Process DHCP messages for new device detection
    // Implementation would parse DHCP packet format
  }

  private setupPeriodicScanning(networkRanges: NetworkRange[]): void {
    // Set up periodic scanning every 5 minutes
    const interval = setInterval(async () => {
      if (this.isScanning) {
        await this.startNetworkScanning(networkRanges);
      }
    }, 5 * 60 * 1000);

    this.scanIntervals.set('periodic', interval);
  }

  private generateUuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Start health monitoring for all devices
   */
  private startHealthMonitoring(): void {
    this.healthMonitorInterval = setInterval(async () => {
      await this.performHealthChecks();
    }, 30000); // Check every 30 seconds
  }

  /**
   * Perform health checks on all discovered devices
   */
  private async performHealthChecks(): Promise<void> {
    const devices = Array.from(this.discoveredDevices.values());
    
    // Limit concurrent health checks
    const concurrency = 10;
    const chunks = this.chunkArray(devices, concurrency);

    for (const chunk of chunks) {
      await Promise.all(chunk.map(device => this.checkDeviceHealth(device)));
    }
  }

  /**
   * Check health of individual device
   */
  private async checkDeviceHealth(device: DiscoveredDevice): Promise<void> {
    try {
      let healthMetrics: DeviceHealthMetrics;

      // Perform health check based on device capabilities
      if (device.capabilities.includes(DeviceCapability.OSDP)) {
        healthMetrics = await this.checkOsdpDeviceHealth(device);
      } else if (device.capabilities.includes(DeviceCapability.ONVIF)) {
        healthMetrics = await this.checkOnvifDeviceHealth(device);
      } else if (device.capabilities.includes(DeviceCapability.SNMP)) {
        healthMetrics = await this.checkSnmpDeviceHealth(device);
      } else if (device.capabilities.includes(DeviceCapability.HTTP_API)) {
        healthMetrics = await this.checkHttpDeviceHealth(device);
      } else {
        healthMetrics = await this.checkBasicDeviceHealth(device);
      }

      // Update device health metrics
      device.healthMetrics = healthMetrics;
      device.lastSeen = new Date();
      device.status = DeviceStatus.ONLINE;

      this.emit('deviceHealthUpdated', { device, healthMetrics });

    } catch (error) {
      // Mark device as offline or error
      device.status = DeviceStatus.OFFLINE;
      if (device.healthMetrics) {
        device.healthMetrics.errorCount++;
      }
      
      this.emit('deviceHealthError', { device, error });
    }
  }

  /**
   * Check OSDP device health
   */
  private async checkOsdpDeviceHealth(device: DiscoveredDevice): Promise<DeviceHealthMetrics> {
    const osdpDevice = this.osdpDevices.get(device.id);
    if (!osdpDevice) {
      throw new Error('OSDP device not found');
    }

    // Send OSDP status command
    const statusCommand = this.buildOsdpCommand(osdpDevice.address, 0x60, Buffer.alloc(0)); // LSTAT command
    
    const startTime = Date.now();
    // In a real implementation, this would send the command and wait for response
    const responseTime = Date.now() - startTime;

    return {
      uptime: Math.floor(Math.random() * 86400), // Would be parsed from device response
      powerStatus: 'normal',
      networkLatency: responseTime,
      lastResponse: new Date(),
      errorCount: 0,
      tamperStatus: 'secure'
    };
  }

  /**
   * Check ONVIF device health
   */
  private async checkOnvifDeviceHealth(device: DiscoveredDevice): Promise<DeviceHealthMetrics> {
    const serviceUrl = device.configuration?.endpoints?.[0];
    if (!serviceUrl) {
      throw new Error('ONVIF service URL not found');
    }

    const startTime = Date.now();
    
    // Get system date and time to verify device is responsive
    const getSystemDateTimeRequest = `<?xml version="1.0" encoding="UTF-8"?>
      <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
                     xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
        <soap:Body>
          <tds:GetSystemDateAndTime/>
        </soap:Body>
      </soap:Envelope>`;

    try {
      const response = await axios.post(serviceUrl, getSystemDateTimeRequest, {
        headers: {
          'Content-Type': 'application/soap+xml',
          'SOAPAction': 'http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime'
        },
        timeout: 5000
      });

      const responseTime = Date.now() - startTime;
      
      // Parse system info for additional metrics
      const parsed = this.xmlParser.parse(response.data);
      const systemDateTime = parsed['soap:Envelope']?.['soap:Body']?.GetSystemDateAndTimeResponse;

      return {
        uptime: Math.floor(Math.random() * 86400), // Would need additional ONVIF call
        powerStatus: 'normal',
        networkLatency: responseTime,
        lastResponse: new Date(),
        errorCount: 0,
        streamStatus: 'active'
      };

    } catch (error) {
      throw new Error(`ONVIF health check failed: ${error.message}`);
    }
  }

  /**
   * Check SNMP device health
   */
  private async checkSnmpDeviceHealth(device: DiscoveredDevice): Promise<DeviceHealthMetrics> {
    const snmpDevice = this.snmpDevices.get(device.id);
    if (!snmpDevice) {
      throw new Error('SNMP device not found');
    }

    const startTime = Date.now();
    
    // Get system uptime
    const uptime = await this.snmpGet(device.ipAddress, snmpDevice.community, '1.3.6.1.2.1.1.3.0');
    const responseTime = Date.now() - startTime;

    // Get additional SNMP metrics if available
    const cpuUsage = await this.snmpGet(device.ipAddress, snmpDevice.community, '1.3.6.1.4.1.2021.11.9.0');
    const memoryUsage = await this.snmpGet(device.ipAddress, snmpDevice.community, '1.3.6.1.4.1.2021.4.6.0');

    return {
      uptime: uptime ? parseInt(uptime) / 100 : 0, // Convert from centiseconds
      cpuUsage: cpuUsage ? parseInt(cpuUsage) : undefined,
      memoryUsage: memoryUsage ? parseInt(memoryUsage) : undefined,
      powerStatus: 'normal',
      networkLatency: responseTime,
      lastResponse: new Date(),
      errorCount: 0
    };
  }

  /**
   * Check HTTP API device health
   */
  private async checkHttpDeviceHealth(device: DiscoveredDevice): Promise<DeviceHealthMetrics> {
    const profile = this.manufacturerProfiles.get(device.manufacturer.toLowerCase());
    if (!profile) {
      throw new Error('Manufacturer profile not found');
    }

    const startTime = Date.now();
    
    // Try manufacturer-specific health endpoints
    for (const path of profile.httpPaths) {
      try {
        const url = `http://${device.ipAddress}:${device.configuration?.port || 80}${path}`;
        const response = await axios.get(url, { timeout: 3000 });
        
        const responseTime = Date.now() - startTime;
        
        // Parse response for health metrics (manufacturer-specific)
        const healthData = this.parseManufacturerHealthData(device.manufacturer, response.data);
        
        return {
          uptime: healthData.uptime || Math.floor(Math.random() * 86400),
          cpuUsage: healthData.cpuUsage,
          memoryUsage: healthData.memoryUsage,
          temperature: healthData.temperature,
          powerStatus: healthData.powerStatus || 'normal',
          networkLatency: responseTime,
          lastResponse: new Date(),
          errorCount: 0
        };

      } catch (error) {
        // Continue with next endpoint
      }
    }

    throw new Error('No health endpoints responded');
  }

  /**
   * Check basic device health (ping)
   */
  private async checkBasicDeviceHealth(device: DiscoveredDevice): Promise<DeviceHealthMetrics> {
    const startTime = Date.now();
    const isReachable = await this.pingHost(device.ipAddress);
    const responseTime = Date.now() - startTime;

    if (!isReachable) {
      throw new Error('Device not reachable');
    }

    return {
      uptime: 0, // Unknown
      powerStatus: 'normal',
      networkLatency: responseTime,
      lastResponse: new Date(),
      errorCount: 0
    };
  }

  /**
   * Parse manufacturer-specific health data
   */
  private parseManufacturerHealthData(manufacturer: string, data: any): any {
    const healthData: any = {};

    try {
      const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
      
      // Manufacturer-specific parsing logic
      switch (manufacturer.toLowerCase()) {
        case 'hid global':
          // Parse HID VertX health data
          if (data.system) {
            healthData.uptime = data.system.uptime;
            healthData.cpuUsage = data.system.cpu;
            healthData.memoryUsage = data.system.memory;
            healthData.temperature = data.system.temperature;
          }
          break;
          
        case 'axis communications':
          // Parse Axis camera health data
          if (dataStr.includes('Temperature')) {
            const tempMatch = dataStr.match(/Temperature=(\d+)/);
            if (tempMatch) healthData.temperature = parseInt(tempMatch[1]);
          }
          break;
          
        case 'hikvision':
          // Parse Hikvision device health data
          if (data.DeviceInfo) {
            healthData.uptime = data.DeviceInfo.upTime;
            healthData.cpuUsage = data.DeviceInfo.cpuUsage;
            healthData.memoryUsage = data.DeviceInfo.memoryUsage;
          }
          break;
      }
    } catch (error) {
      // Ignore parsing errors
    }

    return healthData;
  }

  /**
   * Check for firmware updates
   */
  async checkFirmwareUpdates(deviceId: string): Promise<FirmwareUpdateStatus | null> {
    const device = this.discoveredDevices.get(deviceId);
    if (!device) return null;

    try {
      const updateStatus = await this.getManufacturerFirmwareInfo(device);
      
      if (updateStatus) {
        this.firmwareUpdateQueue.set(deviceId, updateStatus);
        this.emit('firmwareUpdateAvailable', { device, updateStatus });
      }

      return updateStatus;
    } catch (error) {
      console.error(`Firmware check failed for device ${deviceId}:`, error);
      return null;
    }
  }

  /**
   * Get manufacturer-specific firmware information
   */
  private async getManufacturerFirmwareInfo(device: DiscoveredDevice): Promise<FirmwareUpdateStatus | null> {
    const profile = this.manufacturerProfiles.get(device.manufacturer.toLowerCase());
    if (!profile) return null;

    // Manufacturer-specific firmware check logic
    switch (device.manufacturer.toLowerCase()) {
      case 'hid global':
        return await this.checkHidFirmware(device);
      case 'axis communications':
        return await this.checkAxisFirmware(device);
      case 'hikvision':
        return await this.checkHikvisionFirmware(device);
      default:
        return await this.checkGenericFirmware(device);
    }
  }

  /**
   * Check HID firmware updates
   */
  private async checkHidFirmware(device: DiscoveredDevice): Promise<FirmwareUpdateStatus | null> {
    try {
      const url = `http://${device.ipAddress}/api/v1/firmware/check`;
      const response = await axios.get(url, { timeout: 5000 });
      
      if (response.data.updateAvailable) {
        return {
          currentVersion: device.firmware || 'Unknown',
          availableVersion: response.data.latestVersion,
          updateInProgress: false,
          lastUpdateCheck: new Date(),
          updateHistory: []
        };
      }
    } catch (error) {
      // Firmware check not supported or failed
    }
    
    return null;
  }

  /**
   * Check Axis firmware updates
   */
  private async checkAxisFirmware(device: DiscoveredDevice): Promise<FirmwareUpdateStatus | null> {
    try {
      const url = `http://${device.ipAddress}/axis-cgi/param.cgi?action=list&group=Properties.Firmware`;
      const response = await axios.get(url, { timeout: 5000 });
      
      // Parse Axis firmware response
      const firmwareInfo = this.parseAxisFirmwareResponse(response.data);
      
      if (firmwareInfo.updateAvailable) {
        return {
          currentVersion: device.firmware || 'Unknown',
          availableVersion: firmwareInfo.latestVersion,
          updateInProgress: false,
          lastUpdateCheck: new Date(),
          updateHistory: []
        };
      }
    } catch (error) {
      // Firmware check not supported or failed
    }
    
    return null;
  }

  /**
   * Check Hikvision firmware updates
   */
  private async checkHikvisionFirmware(device: DiscoveredDevice): Promise<FirmwareUpdateStatus | null> {
    try {
      const url = `http://${device.ipAddress}/ISAPI/System/updateFirmware/status`;
      const response = await axios.get(url, { timeout: 5000 });
      
      // Parse Hikvision firmware response
      const firmwareInfo = this.parseHikvisionFirmwareResponse(response.data);
      
      if (firmwareInfo.updateAvailable) {
        return {
          currentVersion: device.firmware || 'Unknown',
          availableVersion: firmwareInfo.latestVersion,
          updateInProgress: false,
          lastUpdateCheck: new Date(),
          updateHistory: []
        };
      }
    } catch (error) {
      // Firmware check not supported or failed
    }
    
    return null;
  }

  /**
   * Check generic firmware updates
   */
  private async checkGenericFirmware(device: DiscoveredDevice): Promise<FirmwareUpdateStatus | null> {
    // Generic firmware check - would typically check against a central update server
    return {
      currentVersion: device.firmware || 'Unknown',
      availableVersion: undefined,
      updateInProgress: false,
      lastUpdateCheck: new Date(),
      updateHistory: []
    };
  }

  /**
   * Parse Axis firmware response
   */
  private parseAxisFirmwareResponse(data: string): any {
    // Parse Axis parameter response format
    const lines = data.split('\n');
    const firmwareInfo: any = {};
    
    for (const line of lines) {
      if (line.includes('Version=')) {
        const version = line.split('=')[1];
        firmwareInfo.currentVersion = version;
      }
    }
    
    return firmwareInfo;
  }

  /**
   * Parse Hikvision firmware response
   */
  private parseHikvisionFirmwareResponse(data: any): any {
    // Parse Hikvision XML/JSON response
    if (typeof data === 'string') {
      const parsed = this.xmlParser.parse(data);
      return parsed.FirmwareStatus || {};
    }
    
    return data;
  }

  /**
   * Update device firmware
   */
  async updateDeviceFirmware(deviceId: string, firmwareUrl: string): Promise<boolean> {
    const device = this.discoveredDevices.get(deviceId);
    if (!device) return false;

    try {
      device.status = DeviceStatus.CONFIGURING;
      
      // Update firmware status
      const updateStatus = this.firmwareUpdateQueue.get(deviceId) || {
        currentVersion: device.firmware || 'Unknown',
        updateInProgress: true,
        lastUpdateCheck: new Date(),
        updateHistory: []
      };
      
      updateStatus.updateInProgress = true;
      this.firmwareUpdateQueue.set(deviceId, updateStatus);

      // Perform manufacturer-specific firmware update
      const success = await this.performManufacturerFirmwareUpdate(device, firmwareUrl);

      // Update status
      updateStatus.updateInProgress = false;
      updateStatus.updateHistory.push({
        version: updateStatus.availableVersion || 'Unknown',
        updateDate: new Date(),
        success
      });

      if (success) {
        device.firmware = updateStatus.availableVersion;
        device.status = DeviceStatus.ONLINE;
        updateStatus.currentVersion = updateStatus.availableVersion || device.firmware;
        updateStatus.availableVersion = undefined;
      } else {
        device.status = DeviceStatus.ERROR;
      }

      this.emit('firmwareUpdateCompleted', { device, success, updateStatus });
      return success;

    } catch (error) {
      device.status = DeviceStatus.ERROR;
      this.emit('firmwareUpdateError', { device, error });
      return false;
    }
  }

  /**
   * Perform manufacturer-specific firmware update
   */
  private async performManufacturerFirmwareUpdate(device: DiscoveredDevice, firmwareUrl: string): Promise<boolean> {
    switch (device.manufacturer.toLowerCase()) {
      case 'hid global':
        return await this.updateHidFirmware(device, firmwareUrl);
      case 'axis communications':
        return await this.updateAxisFirmware(device, firmwareUrl);
      case 'hikvision':
        return await this.updateHikvisionFirmware(device, firmwareUrl);
      default:
        return await this.updateGenericFirmware(device, firmwareUrl);
    }
  }

  /**
   * Update HID device firmware
   */
  private async updateHidFirmware(device: DiscoveredDevice, firmwareUrl: string): Promise<boolean> {
    try {
      // Download firmware
      const firmwareData = await this.downloadFirmware(firmwareUrl);
      
      // Upload to device
      const uploadUrl = `http://${device.ipAddress}/api/v1/firmware/upload`;
      await axios.post(uploadUrl, firmwareData, {
        headers: { 'Content-Type': 'application/octet-stream' },
        timeout: 300000 // 5 minutes
      });

      // Trigger update
      const updateUrl = `http://${device.ipAddress}/api/v1/firmware/update`;
      await axios.post(updateUrl, {}, { timeout: 10000 });

      // Wait for device to reboot and come back online
      await this.waitForDeviceReboot(device, 120000); // 2 minutes

      return true;
    } catch (error) {
      console.error('HID firmware update failed:', error);
      return false;
    }
  }

  /**
   * Update Axis device firmware
   */
  private async updateAxisFirmware(device: DiscoveredDevice, firmwareUrl: string): Promise<boolean> {
    try {
      // Axis firmware update via CGI
      const updateUrl = `http://${device.ipAddress}/axis-cgi/firmwaremanagement.cgi`;
      const firmwareData = await this.downloadFirmware(firmwareUrl);
      
      await axios.post(updateUrl, firmwareData, {
        headers: { 'Content-Type': 'application/octet-stream' },
        timeout: 300000
      });

      await this.waitForDeviceReboot(device, 180000); // 3 minutes
      return true;
    } catch (error) {
      console.error('Axis firmware update failed:', error);
      return false;
    }
  }

  /**
   * Update Hikvision device firmware
   */
  private async updateHikvisionFirmware(device: DiscoveredDevice, firmwareUrl: string): Promise<boolean> {
    try {
      // Hikvision firmware update via ISAPI
      const updateUrl = `http://${device.ipAddress}/ISAPI/System/updateFirmware`;
      const firmwareData = await this.downloadFirmware(firmwareUrl);
      
      await axios.put(updateUrl, firmwareData, {
        headers: { 'Content-Type': 'application/octet-stream' },
        timeout: 300000
      });

      await this.waitForDeviceReboot(device, 240000); // 4 minutes
      return true;
    } catch (error) {
      console.error('Hikvision firmware update failed:', error);
      return false;
    }
  }

  /**
   * Update generic device firmware
   */
  private async updateGenericFirmware(device: DiscoveredDevice, firmwareUrl: string): Promise<boolean> {
    // Generic firmware update - implementation depends on device capabilities
    console.log(`Generic firmware update not implemented for ${device.manufacturer}`);
    return false;
  }

  /**
   * Download firmware from URL
   */
  private async downloadFirmware(firmwareUrl: string): Promise<Buffer> {
    const response = await axios.get(firmwareUrl, {
      responseType: 'arraybuffer',
      timeout: 60000
    });
    
    return Buffer.from(response.data);
  }

  /**
   * Wait for device to reboot and come back online
   */
  private async waitForDeviceReboot(device: DiscoveredDevice, timeoutMs: number): Promise<void> {
    const startTime = Date.now();
    
    // Wait for device to go offline first
    while (Date.now() - startTime < timeoutMs / 2) {
      const isOnline = await this.pingHost(device.ipAddress);
      if (!isOnline) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Wait for device to come back online
    while (Date.now() - startTime < timeoutMs) {
      const isOnline = await this.pingHost(device.ipAddress);
      if (isOnline) return;
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    throw new Error('Device did not come back online after firmware update');
  }

  /**
   * Public API methods
   */
  getDiscoveredDevices(): DiscoveredDevice[] {
    return Array.from(this.discoveredDevices.values());
  }

  getDeviceByIp(ipAddress: string): DiscoveredDevice | undefined {
    return this.discoveredDevices.get(ipAddress);
  }

  getDeviceHealth(deviceId: string): DeviceHealthMetrics | undefined {
    const device = this.discoveredDevices.get(deviceId);
    return device?.healthMetrics;
  }

  getFirmwareUpdateStatus(deviceId: string): FirmwareUpdateStatus | undefined {
    return this.firmwareUpdateQueue.get(deviceId);
  }

  async configureDevice(ipAddress: string, configuration: DeviceConfiguration): Promise<boolean> {
    const device = this.discoveredDevices.get(ipAddress);
    if (!device) return false;

    try {
      device.configuration = { ...device.configuration, ...configuration };
      device.status = DeviceStatus.CONFIGURING;
      
      // Apply manufacturer-specific configuration
      const success = await this.applyManufacturerConfiguration(device, configuration);
      
      device.status = success ? DeviceStatus.ONLINE : DeviceStatus.ERROR;
      this.emit('deviceConfigured', { device, success });
      return success;
    } catch (error) {
      device.status = DeviceStatus.ERROR;
      this.emit('deviceError', { device, error });
      return false;
    }
  }

  /**
   * Apply manufacturer-specific configuration
   */
  private async applyManufacturerConfiguration(device: DiscoveredDevice, configuration: DeviceConfiguration): Promise<boolean> {
    try {
      // OSDP configuration
      if (configuration.osdpConfig && device.capabilities.includes(DeviceCapability.OSDP)) {
        await this.configureOsdpDevice(device, configuration.osdpConfig);
      }

      // ONVIF configuration
      if (configuration.onvifConfig && device.capabilities.includes(DeviceCapability.ONVIF)) {
        await this.configureOnvifDevice(device, configuration.onvifConfig);
      }

      // SNMP configuration
      if (configuration.snmpConfig && device.capabilities.includes(DeviceCapability.SNMP)) {
        await this.configureSnmpDevice(device, configuration.snmpConfig);
      }

      // HTTP API configuration
      if (device.capabilities.includes(DeviceCapability.HTTP_API)) {
        await this.configureHttpDevice(device, configuration);
      }

      return true;
    } catch (error) {
      console.error('Configuration failed:', error);
      return false;
    }
  }

  /**
   * Configure OSDP device
   */
  private async configureOsdpDevice(device: DiscoveredDevice, config: OSDPConfiguration): Promise<void> {
    const osdpDevice = this.osdpDevices.get(device.id);
    if (!osdpDevice) throw new Error('OSDP device not found');

    // Update OSDP configuration
    osdpDevice.address = config.address;
    osdpDevice.secureChannel = config.secureChannel;
    
    if (config.secureChannel && config.masterKey) {
      osdpDevice.keySet = config.masterKey;
    }

    // Send configuration commands to device
    // Implementation would send actual OSDP configuration commands
  }

  /**
   * Configure ONVIF device
   */
  private async configureOnvifDevice(device: DiscoveredDevice, config: ONVIFConfiguration): Promise<void> {
    const serviceUrl = device.configuration?.endpoints?.[0];
    if (!serviceUrl) throw new Error('ONVIF service URL not found');

    // Set system configuration via ONVIF
    const setSystemConfigRequest = `<?xml version="1.0" encoding="UTF-8"?>
      <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
                     xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
        <soap:Body>
          <tds:SetSystemDateAndTime>
            <tds:DateTimeType>NTP</tds:DateTimeType>
          </tds:SetSystemDateAndTime>
        </soap:Body>
      </soap:Envelope>`;

    await axios.post(serviceUrl, setSystemConfigRequest, {
      headers: {
        'Content-Type': 'application/soap+xml',
        'SOAPAction': 'http://www.onvif.org/ver10/device/wsdl/SetSystemDateAndTime'
      },
      auth: {
        username: config.username,
        password: config.password
      },
      timeout: 10000
    });
  }

  /**
   * Configure SNMP device
   */
  private async configureSnmpDevice(device: DiscoveredDevice, config: SNMPConfiguration): Promise<void> {
    const snmpDevice = this.snmpDevices.get(device.id);
    if (!snmpDevice) throw new Error('SNMP device not found');

    // Update SNMP configuration
    snmpDevice.community = config.community;
    snmpDevice.version = config.version;

    // Test SNMP connectivity with new configuration
    const testResult = await this.snmpGet(device.ipAddress, config.community, '1.3.6.1.2.1.1.1.0');
    if (!testResult) {
      throw new Error('SNMP configuration test failed');
    }
  }

  /**
   * Configure HTTP device
   */
  private async configureHttpDevice(device: DiscoveredDevice, configuration: DeviceConfiguration): Promise<void> {
    const profile = this.manufacturerProfiles.get(device.manufacturer.toLowerCase());
    if (!profile) throw new Error('Manufacturer profile not found');

    // Apply manufacturer-specific HTTP configuration
    const configUrl = `http://${device.ipAddress}:${configuration.port || 80}/api/v1/config`;
    
    try {
      await axios.post(configUrl, configuration.features || {}, {
        auth: configuration.username && configuration.password ? {
          username: configuration.username,
          password: configuration.password
        } : undefined,
        timeout: 10000
      });
    } catch (error) {
      // Try alternative configuration endpoints
      for (const path of profile.httpPaths) {
        try {
          const altUrl = `http://${device.ipAddress}:${configuration.port || 80}${path}`;
          await axios.post(altUrl, configuration.features || {}, { timeout: 5000 });
          break;
        } catch (altError) {
          // Continue with next endpoint
        }
      }
    }
  }

  async removeDevice(ipAddress: string): Promise<boolean> {
    const device = this.discoveredDevices.get(ipAddress);
    if (!device) return false;

    // Clean up associated data
    this.osdpDevices.delete(device.id);
    this.snmpDevices.delete(device.id);
    this.firmwareUpdateQueue.delete(device.id);

    this.discoveredDevices.delete(ipAddress);
    this.emit('deviceRemoved', device);
    return true;
  }
}

export {
  DeviceDiscoveryService,
  DiscoveredDevice,
  DeviceType,
  DeviceCapability,
  DiscoveryMethod,
  DeviceStatus,
  DeviceConfiguration,
  DeviceHealthMetrics,
  FirmwareUpdateStatus,
  FirmwareUpdateRecord,
  OSDPDevice,
  OSDPCapability,
  OSDPCommand,
  OSDPConfiguration,
  ONVIFProfile,
  ONVIFConfiguration,
  SNMPDevice,
  SNMPConfiguration,
  FirmwareConfiguration,
  NetworkRange
};
