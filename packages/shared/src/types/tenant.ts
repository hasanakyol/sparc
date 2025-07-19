import { z } from 'zod';
import type { Tenant, Organization, Site, Building, Floor, Zone } from '@sparc/database/schemas/tenant';

// Enums
export const TenantStatus = z.enum(['ACTIVE', 'INACTIVE', 'SUSPENDED']);
export const SubscriptionPlan = z.enum(['FREE', 'STARTER', 'PROFESSIONAL', 'ENTERPRISE']);

// Resource Quotas Schema
export const ResourceQuotasSchema = z.object({
  maxUsers: z.number().positive().default(1000),
  maxDoors: z.number().positive().default(500),
  maxCameras: z.number().positive().default(100),
  storageQuotaGB: z.number().positive().default(100)
});

// Branding Config Schema
export const BrandingConfigSchema = z.object({
  logoUrl: z.string().url().optional(),
  primaryColor: z.string().optional(),
  secondaryColor: z.string().optional(),
  customCss: z.string().optional()
});

// Tenant Schemas
export const createTenantSchema = z.object({
  name: z.string().min(1).max(200),
  domain: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/, 'Domain must contain only lowercase letters, numbers, and hyphens'),
  contactEmail: z.string().email(),
  contactPhone: z.string().optional(),
  contactName: z.string().optional(),
  address: z.string().optional(),
  city: z.string().optional(),
  state: z.string().optional(),
  country: z.string().optional(),
  postalCode: z.string().optional(),
  timezone: z.string().default('UTC'),
  plan: SubscriptionPlan.optional(),
  settings: z.record(z.any()).optional(),
  resourceQuotas: ResourceQuotasSchema.optional(),
  brandingConfig: BrandingConfigSchema.optional(),
  metadata: z.record(z.any()).optional()
});

export const updateTenantSchema = createTenantSchema.partial().extend({
  status: TenantStatus.optional()
});

// Organization Schemas
export const createOrganizationSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  type: z.string().optional(),
  industry: z.string().optional(),
  size: z.string().optional(),
  contactEmail: z.string().email().optional(),
  contactPhone: z.string().optional(),
  contactName: z.string().optional(),
  address: z.string().optional(),
  city: z.string().optional(),
  state: z.string().optional(),
  country: z.string().optional(),
  postalCode: z.string().optional(),
  timezone: z.string().default('UTC'),
  settings: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional()
});

export const updateOrganizationSchema = createOrganizationSchema.partial().extend({
  isActive: z.boolean().optional()
});

// Site Schemas
export const createSiteSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  address: z.string().min(1),
  city: z.string().min(1).max(100),
  state: z.string().optional(),
  country: z.string().min(1).max(100),
  postalCode: z.string().optional(),
  latitude: z.string().optional(),
  longitude: z.string().optional(),
  timezone: z.string().default('UTC'),
  settings: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional()
});

export const updateSiteSchema = createSiteSchema.partial().extend({
  isActive: z.boolean().optional()
});

// Building Schemas
export const createBuildingSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  buildingCode: z.string().optional(),
  numberOfFloors: z.number().positive().default(1),
  yearBuilt: z.number().optional(),
  totalArea: z.number().positive().optional(),
  settings: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional()
});

export const updateBuildingSchema = createBuildingSchema.partial().extend({
  isActive: z.boolean().optional()
});

// Floor Schemas
export const createFloorSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  level: z.number(),
  floorPlanUrl: z.string().url().optional(),
  totalArea: z.number().positive().optional(),
  settings: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional()
});

export const updateFloorSchema = createFloorSchema.partial().extend({
  isActive: z.boolean().optional()
});

// Zone Schemas
export const createZoneSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().optional(),
  type: z.string().optional(),
  accessLevel: z.string().optional(),
  capacity: z.number().positive().optional(),
  settings: z.record(z.any()).optional(),
  metadata: z.record(z.any()).optional()
});

export const updateZoneSchema = createZoneSchema.partial().extend({
  isActive: z.boolean().optional()
});

// Query parameter schemas
export const paginationSchema = z.object({
  page: z.coerce.number().positive().default(1),
  limit: z.coerce.number().positive().max(100).default(10),
  search: z.string().optional(),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).default('asc')
});

export const tenantQuerySchema = z.object({
  includeStats: z.coerce.boolean().default(false),
  status: TenantStatus.optional(),
  plan: SubscriptionPlan.optional()
});

export const hierarchyQuerySchema = z.object({
  includeInactive: z.coerce.boolean().default(false),
  includeChildren: z.coerce.boolean().default(false)
});

// Response types with relations
export interface TenantWithRelations extends Tenant {
  organizations?: OrganizationWithRelations[];
  _count?: {
    organizations: number;
    users: number;
  };
  stats?: {
    organizationCount: number;
    userCount: number;
    siteCount: number;
    buildingCount: number;
    floorCount: number;
    zoneCount: number;
    doorCount: number;
    cameraCount: number;
  };
}

export interface OrganizationWithRelations extends Organization {
  tenant?: Tenant;
  sites?: SiteWithRelations[];
  _count?: {
    sites: number;
    users: number;
  };
}

export interface SiteWithRelations extends Site {
  tenant?: Tenant;
  organization?: Organization;
  buildings?: BuildingWithRelations[];
  _count?: {
    buildings: number;
  };
}

export interface BuildingWithRelations extends Building {
  tenant?: Tenant;
  organization?: Organization;
  site?: Site;
  floors?: FloorWithRelations[];
  _count?: {
    floors: number;
  };
}

export interface FloorWithRelations extends Floor {
  tenant?: Tenant;
  organization?: Organization;
  site?: Site;
  building?: Building;
  zones?: ZoneWithRelations[];
  _count?: {
    zones: number;
  };
}

export interface ZoneWithRelations extends Zone {
  tenant?: Tenant;
  organization?: Organization;
  site?: Site;
  building?: Building;
  floor?: Floor;
  _count?: {
    doors: number;
    cameras: number;
  };
}

// Pagination response
export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Resource usage response
export interface ResourceUsage {
  users: {
    current: number;
    quota: number;
    percentage: string;
  };
  doors: {
    current: number;
    quota: number;
    percentage: string;
  };
  cameras: {
    current: number;
    quota: number;
    percentage: string;
  };
  storage: {
    current: number;
    quota: number;
    percentage: string;
  };
}