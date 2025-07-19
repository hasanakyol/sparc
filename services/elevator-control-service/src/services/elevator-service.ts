import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { BaseElevatorAdapter } from '../adapters/base.adapter';
import { AdapterFactory } from '../adapters/adapter-factory';
import { Logger } from '../utils/logger';
import { ManufacturerType, ElevatorWithStatus } from '../types';

export class ElevatorService {
  private adapters: Map<string, BaseElevatorAdapter> = new Map();

  constructor(
    private prisma: PrismaClient,
    private redis: Redis,
    private logger: Logger,
    private config: {
      alertServiceUrl: string;
      accessControlServiceUrl: string;
    }
  ) {}

  async getAdapter(elevatorId: string): Promise<BaseElevatorAdapter> {
    // Check cache first
    let adapter = this.adapters.get(elevatorId);
    if (adapter && adapter.isSystemConnected()) {
      return adapter;
    }

    // Get elevator details from database
    const elevator = await this.prisma.elevatorControl.findUnique({
      where: { id: elevatorId }
    });

    if (!elevator) {
      throw new Error(`Elevator ${elevatorId} not found`);
    }

    // Create adapter if not exists
    const adapterConfig = AdapterFactory.getAdapterConfig(
      elevator.manufacturer as ManufacturerType,
      {
        baseUrl: `http://${elevator.ipAddress}`,
        apiKey: process.env[`${elevator.manufacturer}_API_KEY`] || '',
        simulatorMode: process.env.ELEVATOR_SIMULATOR_MODE === 'true'
      }
    );

    adapter = AdapterFactory.create(
      elevator.manufacturer as ManufacturerType,
      adapterConfig,
      this.logger
    );

    // Connect to elevator system
    const connected = await adapter.connect();
    if (!connected) {
      throw new Error(`Failed to connect to elevator ${elevatorId}`);
    }

    // Cache the adapter
    this.adapters.set(elevatorId, adapter);

    return adapter;
  }

  async getElevatorWithStatus(elevatorId: string, tenantId: string): Promise<ElevatorWithStatus | null> {
    const elevator = await this.prisma.elevatorControl.findFirst({
      where: { id: elevatorId, tenantId },
      include: {
        building: {
          select: {
            id: true,
            name: true,
            floors: true,
          },
        },
      },
    });

    if (!elevator) {
      return null;
    }

    try {
      const adapter = await this.getAdapter(elevatorId);
      const status = await adapter.getStatus(elevatorId);

      return {
        ...elevator,
        floorsServed: elevator.floorsServed as number[],
        manufacturer: elevator.manufacturer as ManufacturerType,
        protocol: elevator.protocol as any,
        realTimeStatus: status,
      };
    } catch (error) {
      this.logger.error('Failed to get elevator status', { elevatorId, error: error.message });
      return {
        ...elevator,
        floorsServed: elevator.floorsServed as number[],
        manufacturer: elevator.manufacturer as ManufacturerType,
        protocol: elevator.protocol as any,
        realTimeStatus: null,
      };
    }
  }

  async getAllElevatorsWithStatus(tenantId: string, buildingId?: string): Promise<ElevatorWithStatus[]> {
    const where: any = { tenantId };
    if (buildingId) {
      where.buildingId = buildingId;
    }

    const elevators = await this.prisma.elevatorControl.findMany({
      where,
      include: {
        building: {
          select: {
            id: true,
            name: true,
            floors: true,
          },
        },
      },
      orderBy: { name: 'asc' },
    });

    // Get real-time status for each elevator
    const elevatorsWithStatus = await Promise.all(
      elevators.map(async (elevator) => {
        try {
          const adapter = await this.getAdapter(elevator.id);
          const status = await adapter.getStatus(elevator.id);
          
          return {
            ...elevator,
            floorsServed: elevator.floorsServed as number[],
            manufacturer: elevator.manufacturer as ManufacturerType,
            protocol: elevator.protocol as any,
            realTimeStatus: status,
          };
        } catch (error) {
          this.logger.error('Failed to get elevator status', { 
            elevatorId: elevator.id, 
            error: error.message 
          });
          
          return {
            ...elevator,
            floorsServed: elevator.floorsServed as number[],
            manufacturer: elevator.manufacturer as ManufacturerType,
            protocol: elevator.protocol as any,
            realTimeStatus: null,
          };
        }
      })
    );

    return elevatorsWithStatus;
  }

  async sendFloorRequest(elevatorId: string, floor: number, userId: string): Promise<boolean> {
    const adapter = await this.getAdapter(elevatorId);
    return adapter.callElevator({
      elevatorId,
      floor,
      userId,
      priority: 'NORMAL'
    });
  }

  async setEmergencyOverride(elevatorId: string, action: string, reason: string): Promise<boolean> {
    const adapter = await this.getAdapter(elevatorId);
    
    let emergencyAction: 'STOP' | 'RELEASE' | 'EVACUATE' | 'LOCKDOWN';
    switch (action) {
      case 'ENABLE':
        emergencyAction = 'STOP';
        break;
      case 'DISABLE':
        emergencyAction = 'RELEASE';
        break;
      case 'EVACUATE':
        emergencyAction = 'EVACUATE';
        break;
      case 'LOCKDOWN':
        emergencyAction = 'LOCKDOWN';
        break;
      default:
        throw new Error(`Invalid emergency action: ${action}`);
    }

    return adapter.emergency(elevatorId, emergencyAction, reason);
  }

  async getElevatorStatus(elevatorId: string): Promise<any> {
    // Try cache first
    const cached = await this.redis.get(`elevator:status:${elevatorId}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get from adapter
    const adapter = await this.getAdapter(elevatorId);
    const status = await adapter.getStatus(elevatorId);

    // Cache for 30 seconds
    if (status) {
      await this.redis.setex(`elevator:status:${elevatorId}`, 30, JSON.stringify(status));
    }

    return status;
  }

  async subscribeTStatusUpdates(elevatorId: string, callback: (status: any) => void): Promise<void> {
    const adapter = await this.getAdapter(elevatorId);
    await adapter.subscribeToUpdates(elevatorId, callback);
  }

  async unsubscribeFromStatusUpdates(elevatorId: string): Promise<void> {
    const adapter = await this.getAdapter(elevatorId);
    await adapter.unsubscribeFromUpdates(elevatorId);
  }

  async getDiagnostics(elevatorId: string): Promise<any> {
    const adapter = await this.getAdapter(elevatorId);
    return adapter.getDiagnostics(elevatorId);
  }

  async setMaintenanceMode(elevatorId: string, enabled: boolean, reason: string): Promise<boolean> {
    const adapter = await this.getAdapter(elevatorId);
    const success = await adapter.setMaintenanceMode(elevatorId, enabled, reason);

    if (success) {
      // Update database
      await this.prisma.elevatorControl.update({
        where: { id: elevatorId },
        data: { 
          status: enabled ? 'maintenance' : 'normal',
          updatedAt: new Date()
        },
      });
    }

    return success;
  }

  async resetElevator(elevatorId: string): Promise<boolean> {
    const adapter = await this.getAdapter(elevatorId);
    return adapter.reset(elevatorId);
  }

  async cleanup(): Promise<void> {
    // Disconnect all adapters
    for (const [elevatorId, adapter] of this.adapters) {
      try {
        await adapter.disconnect();
      } catch (error) {
        this.logger.error('Error disconnecting adapter', { elevatorId, error: error.message });
      }
    }
    this.adapters.clear();
  }
}