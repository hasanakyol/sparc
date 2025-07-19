import { z } from 'zod';

// Request Schemas
export const VisitorPreRegistrationSchema = z.object({
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  company: z.string().optional(),
  purpose: z.string().min(1).max(500),
  hostUserId: z.string().uuid(),
  expectedArrival: z.string().datetime(),
  expectedDeparture: z.string().datetime(),
  accessAreas: z.array(z.string()).optional(),
  requiresEscort: z.boolean().default(false),
  vehicleLicense: z.string().optional(),
  vehicleMake: z.string().optional(),
  vehicleModel: z.string().optional(),
  vehicleColor: z.string().optional(),
  specialRequirements: z.string().optional(),
  emergencyContactName: z.string().optional(),
  emergencyContactPhone: z.string().optional(),
});

export const VisitorCheckInSchema = z.object({
  visitorId: z.string().uuid().optional(),
  qrCode: z.string().optional(),
  invitationCode: z.string().optional(),
  firstName: z.string().min(1).max(100).optional(),
  lastName: z.string().min(1).max(100).optional(),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  company: z.string().optional(),
  purpose: z.string().min(1).max(500).optional(),
  hostUserId: z.string().uuid().optional(),
  photo: z.string().optional(), // Base64 encoded photo
  idDocument: z.string().optional(), // Base64 encoded ID
  idType: z.string().optional(),
  idNumber: z.string().optional(),
  vehicleLicense: z.string().optional(),
  vehicleMake: z.string().optional(),
  vehicleModel: z.string().optional(),
  vehicleColor: z.string().optional(),
  parkingSpot: z.string().optional(),
  emergencyContactName: z.string().optional(),
  emergencyContactPhone: z.string().optional(),
  accessAreas: z.array(z.string()).optional(),
}).refine(
  (data) => data.visitorId || data.qrCode || data.invitationCode || (data.firstName && data.lastName && data.purpose && data.hostUserId),
  { message: 'Either visitorId, qrCode, invitationCode, or complete walk-in visitor information is required' }
);

export const VisitorUpdateSchema = z.object({
  status: z.enum(['PENDING', 'APPROVED', 'CHECKED_IN', 'CHECKED_OUT', 'EXPIRED', 'DENIED', 'CANCELLED']).optional(),
  actualArrival: z.string().datetime().optional(),
  actualDeparture: z.string().datetime().optional(),
  accessAreas: z.array(z.string()).optional(),
  notes: z.string().optional(),
  parkingSpot: z.string().optional(),
  denialReason: z.string().optional(),
});

export const WatchlistCheckSchema = z.object({
  firstName: z.string(),
  lastName: z.string(),
  email: z.string().email().optional(),
  idNumber: z.string().optional(),
  company: z.string().optional(),
});

export const WatchlistEntrySchema = z.object({
  firstName: z.string().min(1).max(100),
  lastName: z.string().min(1).max(100),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  idNumber: z.string().optional(),
  company: z.string().optional(),
  reason: z.enum(['SECURITY_THREAT', 'PREVIOUS_INCIDENT', 'BANNED', 'INVESTIGATION', 'OTHER']),
  description: z.string().min(1),
  aliases: z.array(z.string()).optional(),
  photo: z.string().optional(),
  effectiveUntil: z.string().datetime().optional(),
  sourceSystem: z.string().optional(),
  externalId: z.string().optional(),
});

export const BadgePrintSchema = z.object({
  visitorId: z.string().uuid(),
  template: z.enum(['STANDARD', 'CONTRACTOR', 'VIP', 'ESCORT_REQUIRED', 'TEMPORARY', 'EVENT']).default('STANDARD'),
  validUntil: z.string().datetime().optional(),
});

export const VisitorGroupSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().optional(),
  groupSize: z.string(),
  members: z.array(z.object({
    firstName: z.string().min(1).max(100),
    lastName: z.string().min(1).max(100),
    email: z.string().email().optional(),
    phone: z.string().optional(),
    company: z.string().optional(),
    isPrimaryContact: z.boolean().default(false),
  })),
  purpose: z.string().min(1).max(500),
  hostUserId: z.string().uuid(),
  expectedArrival: z.string().datetime(),
  expectedDeparture: z.string().datetime(),
  accessAreas: z.array(z.string()).optional(),
  requiresEscort: z.boolean().default(false),
});

export const VisitorApprovalSchema = z.object({
  approved: z.boolean(),
  reason: z.string().optional(),
  accessAreas: z.array(z.string()).optional(),
  validUntil: z.string().datetime().optional(),
});

export const VisitorCredentialValidationSchema = z.object({
  credentialId: z.string().uuid().optional(),
  credentialData: z.string().optional(),
  accessPoint: z.string(),
}).refine(
  (data) => data.credentialId || data.credentialData,
  { message: 'Either credentialId or credentialData is required' }
);

export const VisitorSearchSchema = z.object({
  query: z.string().optional(),
  status: z.enum(['PENDING', 'APPROVED', 'CHECKED_IN', 'CHECKED_OUT', 'EXPIRED', 'DENIED', 'CANCELLED']).optional(),
  hostUserId: z.string().uuid().optional(),
  fromDate: z.string().datetime().optional(),
  toDate: z.string().datetime().optional(),
  includeExpired: z.boolean().default(false),
  page: z.number().int().positive().default(1),
  limit: z.number().int().positive().max(100).default(20),
  sortBy: z.enum(['expectedArrival', 'actualArrival', 'createdAt', 'lastName']).default('expectedArrival'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

export const AccessLogQuerySchema = z.object({
  visitorId: z.string().uuid().optional(),
  fromDate: z.string().datetime().optional(),
  toDate: z.string().datetime().optional(),
  accessPoint: z.string().optional(),
  granted: z.boolean().optional(),
  page: z.number().int().positive().default(1),
  limit: z.number().int().positive().max(100).default(20),
});

// Response Types
export type VisitorPreRegistration = z.infer<typeof VisitorPreRegistrationSchema>;
export type VisitorCheckIn = z.infer<typeof VisitorCheckInSchema>;
export type VisitorUpdate = z.infer<typeof VisitorUpdateSchema>;
export type WatchlistCheck = z.infer<typeof WatchlistCheckSchema>;
export type WatchlistEntry = z.infer<typeof WatchlistEntrySchema>;
export type BadgePrint = z.infer<typeof BadgePrintSchema>;
export type VisitorGroup = z.infer<typeof VisitorGroupSchema>;
export type VisitorApproval = z.infer<typeof VisitorApprovalSchema>;
export type VisitorCredentialValidation = z.infer<typeof VisitorCredentialValidationSchema>;
export type VisitorSearch = z.infer<typeof VisitorSearchSchema>;
export type AccessLogQuery = z.infer<typeof AccessLogQuerySchema>;

// WebSocket Event Types
export interface VisitorEvent {
  type: 'visitor:created' | 'visitor:updated' | 'visitor:checked-in' | 'visitor:checked-out' | 'visitor:approved' | 'visitor:denied';
  organizationId: string;
  data: {
    visitorId: string;
    visitor?: any;
    timestamp: string;
    performedBy: string;
  };
}

// Service Response Types
export interface ServiceResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    hasMore?: boolean;
  };
}

// Visitor Analytics Types
export interface VisitorAnalytics {
  totalVisitors: number;
  activeVisitors: number;
  pendingApprovals: number;
  todayCheckIns: number;
  todayCheckOuts: number;
  averageVisitDuration: number;
  topHosts: Array<{
    userId: string;
    name: string;
    visitorCount: number;
  }>;
  visitorsByStatus: Record<string, number>;
  visitorsByHour: Array<{
    hour: number;
    count: number;
  }>;
  overstayVisitors: number;
}