import { z } from 'zod';

// Manufacturer types
export const ManufacturerType = z.enum(['OTIS', 'KONE', 'SCHINDLER', 'THYSSENKRUPP', 'MITSUBISHI', 'FUJITEC', 'GENERIC']);
export type ManufacturerType = z.infer<typeof ManufacturerType>;

// Protocol types
export const ProtocolType = z.enum(['REST', 'SOAP', 'TCP', 'MODBUS', 'BACNET']);
export type ProtocolType = z.infer<typeof ProtocolType>;

// Validation schemas
export const elevatorControlSchema = z.object({
  name: z.string().min(1).max(255),
  buildingId: z.string().cuid(),
  floorsServed: z.array(z.number().int().min(-10).max(200)),
  ipAddress: z.string().ip(),
  protocol: ProtocolType,
  manufacturer: ManufacturerType,
  accessRules: z.object({
    defaultAccess: z.boolean().default(false),
    timeBasedAccess: z.boolean().default(true),
    emergencyAccess: z.boolean().default(true),
    maintenanceAccess: z.boolean().default(false),
  }).default({}),
  configuration: z.record(z.any()).optional(),
});

export const floorAccessRequestSchema = z.object({
  userId: z.string().cuid(),
  targetFloor: z.number().int().min(-10).max(200),
  credentialId: z.string().cuid().optional(),
  reason: z.string().optional(),
});

export const emergencyOverrideSchema = z.object({
  action: z.enum(['ENABLE', 'DISABLE', 'EVACUATE', 'LOCKDOWN']),
  reason: z.string().min(1),
  duration: z.number().int().min(1).max(86400).optional(), // Max 24 hours
});

export const destinationDispatchSchema = z.object({
  userId: z.string().cuid(),
  targetFloor: z.number().int().min(-10).max(200),
  priority: z.enum(['LOW', 'NORMAL', 'HIGH', 'EMERGENCY']).default('NORMAL'),
});

// Service configuration
export interface ElevatorControlConfig {
  alertServiceUrl: string;
  accessControlServiceUrl: string;
  defaultTimeout: number;
  maxRetries: number;
}

// Response types
export interface ElevatorWithStatus {
  id: string;
  name: string;
  buildingId: string;
  floorsServed: number[];
  ipAddress: string;
  protocol: ProtocolType;
  manufacturer: ManufacturerType;
  accessRules: any;
  emergencyOverride: boolean;
  status: string;
  realTimeStatus?: any;
  building?: {
    id: string;
    name: string;
    floors: number;
  };
}

export interface FloorAccessResponse {
  message: string;
  elevatorId: string;
  targetFloor: number;
  timestamp: string;
}

export interface EmergencyOverrideResponse {
  message: string;
  elevatorId: string;
  action: string;
  emergencyEnabled: boolean;
  timestamp: string;
}

export interface DestinationDispatchAssignment {
  elevatorId: string;
  elevatorName?: string;
  userId: string;
  targetFloor: number;
  priority: string;
  estimatedArrival: Date;
  success?: boolean;
}

export interface DestinationDispatchResponse {
  message: string;
  buildingId: string;
  assignments: DestinationDispatchAssignment[];
  timestamp: string;
}