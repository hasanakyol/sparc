import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { DeviceManagementRequest } from '../types/schemas';
import { DeviceManagementConfig, PowerManagementConfig } from '../types';

export class DeviceManagementService {
  private prisma: PrismaClient;
  private redis: Redis;
  private config: any;

  constructor(prisma: PrismaClient, redis: Redis, config: any) {
    this.prisma = prisma;
    this.redis = redis;
    this.config = config;
  }

  async executeDeviceAction(managementData: DeviceManagementRequest, userId: string, tenantId: string): Promise<any> {
    const results = [];
    
    for (const deviceId of managementData.deviceIds) {
      try {
        const result = await this.executeActionForDevice(
          deviceId,
          managementData.action,
          managementData.parameters,
          tenantId
        );
        results.push(result);
      } catch (error: any) {
        results.push({
          deviceId,
          action: managementData.action,
          success: false,
          error: error.message
        });
      }
    }

    // Log management action
    await this.logManagementAction(managementData.action, {
      deviceIds: managementData.deviceIds,
      userId,
      tenantId,
      parameters: managementData.parameters,
      results
    });

    return { results };
  }

  private async executeActionForDevice(deviceId: string, action: string, parameters: any, tenantId: string): Promise<any> {
    switch (action) {
      case 'wipe':
        return await this.wipeDevice(deviceId, tenantId);
      case 'lock':
        return await this.lockDevice(deviceId, tenantId);
      case 'unlock':
        return await this.unlockDevice(deviceId, tenantId);
      case 'locate':
        return await this.locateDevice(deviceId, tenantId);
      case 'compliance_check':
        return await this.checkDeviceCompliance(deviceId, tenantId);
      case 'certificate_update':
        return await this.updateDeviceCertificate(deviceId, parameters, tenantId);
      default:
        throw new Error(`Unknown device action: ${action}`);
    }
  }

  private async wipeDevice(deviceId: string, tenantId: string): Promise<any> {
    // Mark all credentials on device as wiped
    await this.prisma.mobileCredential.updateMany({
      where: {
        deviceInfo: {
          path: '$.deviceId',
          equals: deviceId
        },
        tenantId
      },
      data: {
        status: 'revoked',
        revokedAt: new Date(),
        revokedReason: 'device_wiped'
      }
    });

    // Send wipe command to device
    await this.sendDeviceCommand(deviceId, 'wipe', {
      wipeType: 'full',
      timestamp: new Date()
    });

    // Clear all cached data for device
    const keys = await this.redis.keys(`device:${deviceId}:*`);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }

    return {
      deviceId,
      action: 'wipe',
      success: true,
      wipedAt: new Date()
    };
  }

  private async lockDevice(deviceId: string, tenantId: string): Promise<any> {
    // Update device status
    await this.redis.set(`device:${deviceId}:locked`, 'true');
    
    // Suspend all credentials on device
    await this.prisma.mobileCredential.updateMany({
      where: {
        deviceInfo: {
          path: '$.deviceId',
          equals: deviceId
        },
        tenantId,
        status: 'active'
      },
      data: {
        status: 'suspended',
        suspendedAt: new Date(),
        suspendedReason: 'device_locked'
      }
    });

    // Send lock command to device
    await this.sendDeviceCommand(deviceId, 'lock', {
      lockType: 'full',
      message: 'Device locked by administrator',
      timestamp: new Date()
    });

    return {
      deviceId,
      action: 'lock',
      success: true,
      lockedAt: new Date()
    };
  }

  private async unlockDevice(deviceId: string, tenantId: string): Promise<any> {
    // Update device status
    await this.redis.del(`device:${deviceId}:locked`);
    
    // Reactivate suspended credentials
    await this.prisma.mobileCredential.updateMany({
      where: {
        deviceInfo: {
          path: '$.deviceId',
          equals: deviceId
        },
        tenantId,
        status: 'suspended',
        suspendedReason: 'device_locked'
      },
      data: {
        status: 'active',
        suspendedAt: null,
        suspendedReason: null
      }
    });

    // Send unlock command to device
    await this.sendDeviceCommand(deviceId, 'unlock', {
      timestamp: new Date()
    });

    return {
      deviceId,
      action: 'unlock',
      success: true,
      unlockedAt: new Date()
    };
  }

  private async locateDevice(deviceId: string, tenantId: string): Promise<any> {
    // Request location from device
    const locationData = await this.sendDeviceCommand(deviceId, 'locate', {
      accuracy: 'high',
      timeout: 30000
    });

    // Store location data
    await this.redis.setex(
      `device:${deviceId}:location`,
      300, // 5 minutes
      JSON.stringify({
        ...locationData,
        timestamp: new Date()
      })
    );

    return {
      deviceId,
      action: 'locate',
      success: true,
      location: locationData
    };
  }

  private async checkDeviceCompliance(deviceId: string, tenantId: string): Promise<any> {
    // Get device info
    const credential = await this.prisma.mobileCredential.findFirst({
      where: {
        deviceInfo: {
          path: '$.deviceId',
          equals: deviceId
        },
        tenantId
      }
    });

    if (!credential) {
      throw new Error('Device not found');
    }

    const deviceInfo = credential.deviceInfo as any;
    const complianceChecks = {
      jailbroken: !deviceInfo.jailbroken,
      osVersion: this.checkOSVersion(deviceInfo.os, deviceInfo.osVersion),
      appVersion: this.checkAppVersion(deviceInfo.appVersion),
      securityLevel: deviceInfo.securityLevel === 'enhanced' || deviceInfo.securityLevel === 'maximum',
      certificateValid: await this.checkCertificateValidity(deviceId)
    };

    const compliant = Object.values(complianceChecks).every(check => check);

    // Update compliance status
    await this.redis.setex(
      `device:${deviceId}:compliance`,
      3600, // 1 hour
      JSON.stringify({
        compliant,
        checks: complianceChecks,
        timestamp: new Date()
      })
    );

    return {
      deviceId,
      action: 'compliance_check',
      success: true,
      compliant,
      checks: complianceChecks
    };
  }

  private async updateDeviceCertificate(deviceId: string, parameters: any, tenantId: string): Promise<any> {
    const { certificate, certificateChain } = parameters;
    
    if (!certificate) {
      throw new Error('Certificate required for update');
    }

    // Update certificate in all credentials for device
    await this.prisma.mobileCredential.updateMany({
      where: {
        deviceInfo: {
          path: '$.deviceId',
          equals: deviceId
        },
        tenantId
      },
      data: {
        credentialData: {
          certificateChain: certificateChain || []
        }
      }
    });

    // Send certificate update to device
    await this.sendDeviceCommand(deviceId, 'update_certificate', {
      certificate,
      certificateChain,
      timestamp: new Date()
    });

    return {
      deviceId,
      action: 'certificate_update',
      success: true,
      updatedAt: new Date()
    };
  }

  async updatePowerStatus(credentialId: string, deviceStatus: any): Promise<void> {
    const powerStatus = {
      batteryLevel: deviceStatus.batteryLevel,
      isCharging: deviceStatus.isCharging,
      powerSavingMode: deviceStatus.powerSavingMode,
      networkConnectivity: deviceStatus.networkConnectivity,
      lastSyncTime: deviceStatus.lastSyncTime,
      timestamp: new Date()
    };

    // Store power status
    await this.redis.setex(
      `power_status:${credentialId}`,
      3600, // 1 hour
      JSON.stringify(powerStatus)
    );

    // Update credential with power management settings if needed
    if (deviceStatus.batteryLevel < 20 && !deviceStatus.isCharging) {
      await this.enablePowerSavingMode(credentialId);
    }
  }

  async getPowerStatus(credentialId: string): Promise<any> {
    const status = await this.redis.get(`power_status:${credentialId}`);
    return status ? JSON.parse(status) : null;
  }

  private async enablePowerSavingMode(credentialId: string): Promise<void> {
    await this.prisma.mobileCredential.update({
      where: { id: credentialId },
      data: {
        powerManagement: {
          powerSavingMode: true,
          reducedFunctionalityMode: true,
          backgroundSyncInterval: 300 // 5 minutes
        }
      }
    });
  }

  private async sendDeviceCommand(deviceId: string, command: string, parameters: any): Promise<any> {
    // In a real implementation, this would send commands via push notifications,
    // WebSocket, or other mobile device communication channels
    const commandPayload = {
      deviceId,
      command,
      parameters,
      timestamp: new Date()
    };

    // Queue command for device
    await this.redis.lpush(
      `device:${deviceId}:commands`,
      JSON.stringify(commandPayload)
    );

    // For simulation, return mock response
    if (command === 'locate') {
      return {
        latitude: 37.7749,
        longitude: -122.4194,
        accuracy: 10,
        timestamp: new Date()
      };
    }

    return { success: true };
  }

  private checkOSVersion(os: string, version: string): boolean {
    // Check minimum OS versions
    const minVersions: Record<string, string> = {
      ios: '14.0',
      android: '10.0'
    };

    const minVersion = minVersions[os.toLowerCase()];
    if (!minVersion) return true;

    return this.compareVersions(version, minVersion) >= 0;
  }

  private checkAppVersion(version: string): boolean {
    const minAppVersion = this.config.minAppVersion || '1.0.0';
    return this.compareVersions(version, minAppVersion) >= 0;
  }

  private compareVersions(v1: string, v2: string): number {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const part1 = parts1[i] || 0;
      const part2 = parts2[i] || 0;
      
      if (part1 > part2) return 1;
      if (part1 < part2) return -1;
    }
    
    return 0;
  }

  private async checkCertificateValidity(deviceId: string): Promise<boolean> {
    // In a real implementation, this would check device certificate validity
    return true;
  }

  private async logManagementAction(action: string, data: any): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        eventType: `device_management_${action}`,
        entityType: 'device',
        entityId: data.deviceIds.join(','),
        userId: data.userId,
        tenantId: data.tenantId,
        metadata: data
      }
    });
  }
}