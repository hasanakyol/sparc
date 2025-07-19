import { pgTable, uuid, varchar, text, timestamp, boolean, jsonb, unique, index, integer, pgEnum } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { sql } from 'drizzle-orm';

// Enums
export const tenantStatusEnum = pgEnum('tenant_status', ['ACTIVE', 'INACTIVE', 'SUSPENDED']);
export const subscriptionPlanEnum = pgEnum('subscription_plan', ['FREE', 'STARTER', 'PROFESSIONAL', 'ENTERPRISE']);

// Tenants table
export const tenants = pgTable('tenants', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 200 }).notNull(),
  domain: varchar('domain', { length: 100 }).notNull().unique(),
  status: tenantStatusEnum('status').default('ACTIVE').notNull(),
  plan: subscriptionPlanEnum('plan').default('FREE').notNull(),
  contactEmail: varchar('contact_email', { length: 255 }).notNull(),
  contactPhone: varchar('contact_phone', { length: 20 }),
  contactName: varchar('contact_name', { length: 200 }),
  address: text('address'),
  city: varchar('city', { length: 100 }),
  state: varchar('state', { length: 100 }),
  country: varchar('country', { length: 100 }),
  postalCode: varchar('postal_code', { length: 20 }),
  timezone: varchar('timezone', { length: 50 }).default('UTC').notNull(),
  settings: jsonb('settings').default({}).notNull(),
  resourceQuotas: jsonb('resource_quotas').default({
    maxUsers: 1000,
    maxDoors: 500,
    maxCameras: 100,
    storageQuotaGB: 100
  }).notNull(),
  brandingConfig: jsonb('branding_config').default({}).notNull(),
  metadata: jsonb('metadata').default({}).notNull(),
  activatedAt: timestamp('activated_at'),
  suspendedAt: timestamp('suspended_at'),
  suspensionReason: text('suspension_reason'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: uuid('created_by'),
  updatedBy: uuid('updated_by')
}, (table) => ({
  domainIdx: index('tenants_domain_idx').on(table.domain),
  statusIdx: index('tenants_status_idx').on(table.status),
  planIdx: index('tenants_plan_idx').on(table.plan),
  createdAtIdx: index('tenants_created_at_idx').on(table.createdAt)
}));

// Organizations table
export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 200 }).notNull(),
  description: text('description'),
  type: varchar('type', { length: 50 }), // e.g., 'corporate', 'government', 'education', 'healthcare'
  industry: varchar('industry', { length: 100 }),
  size: varchar('size', { length: 50 }), // e.g., 'small', 'medium', 'large', 'enterprise'
  contactEmail: varchar('contact_email', { length: 255 }),
  contactPhone: varchar('contact_phone', { length: 20 }),
  contactName: varchar('contact_name', { length: 200 }),
  address: text('address'),
  city: varchar('city', { length: 100 }),
  state: varchar('state', { length: 100 }),
  country: varchar('country', { length: 100 }),
  postalCode: varchar('postal_code', { length: 20 }),
  timezone: varchar('timezone', { length: 50 }).default('UTC').notNull(),
  settings: jsonb('settings').default({}).notNull(),
  metadata: jsonb('metadata').default({}).notNull(),
  isActive: boolean('is_active').default(true).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: uuid('created_by'),
  updatedBy: uuid('updated_by')
}, (table) => ({
  tenantNameUnique: unique('organizations_tenant_name_unique').on(table.tenantId, table.name),
  tenantIdx: index('organizations_tenant_idx').on(table.tenantId),
  activeIdx: index('organizations_active_idx').on(table.isActive),
  createdAtIdx: index('organizations_created_at_idx').on(table.createdAt)
}));

// Sites table
export const sites = pgTable('sites', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 200 }).notNull(),
  description: text('description'),
  address: text('address').notNull(),
  city: varchar('city', { length: 100 }).notNull(),
  state: varchar('state', { length: 100 }),
  country: varchar('country', { length: 100 }).notNull(),
  postalCode: varchar('postal_code', { length: 20 }),
  latitude: varchar('latitude', { length: 20 }),
  longitude: varchar('longitude', { length: 20 }),
  timezone: varchar('timezone', { length: 50 }).default('UTC').notNull(),
  settings: jsonb('settings').default({}).notNull(),
  metadata: jsonb('metadata').default({}).notNull(),
  isActive: boolean('is_active').default(true).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: uuid('created_by'),
  updatedBy: uuid('updated_by')
}, (table) => ({
  organizationNameUnique: unique('sites_organization_name_unique').on(table.organizationId, table.name),
  tenantIdx: index('sites_tenant_idx').on(table.tenantId),
  organizationIdx: index('sites_organization_idx').on(table.organizationId),
  activeIdx: index('sites_active_idx').on(table.isActive),
  locationIdx: index('sites_location_idx').on(table.latitude, table.longitude),
  createdAtIdx: index('sites_created_at_idx').on(table.createdAt)
}));

// Buildings table
export const buildings = pgTable('buildings', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  siteId: uuid('site_id').notNull().references(() => sites.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 200 }).notNull(),
  description: text('description'),
  buildingCode: varchar('building_code', { length: 50 }),
  numberOfFloors: integer('number_of_floors').default(1).notNull(),
  yearBuilt: integer('year_built'),
  totalArea: integer('total_area'), // in square feet/meters
  settings: jsonb('settings').default({}).notNull(),
  metadata: jsonb('metadata').default({}).notNull(),
  isActive: boolean('is_active').default(true).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: uuid('created_by'),
  updatedBy: uuid('updated_by')
}, (table) => ({
  siteNameUnique: unique('buildings_site_name_unique').on(table.siteId, table.name),
  tenantIdx: index('buildings_tenant_idx').on(table.tenantId),
  organizationIdx: index('buildings_organization_idx').on(table.organizationId),
  siteIdx: index('buildings_site_idx').on(table.siteId),
  activeIdx: index('buildings_active_idx').on(table.isActive),
  createdAtIdx: index('buildings_created_at_idx').on(table.createdAt)
}));

// Floors table
export const floors = pgTable('floors', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  siteId: uuid('site_id').notNull().references(() => sites.id, { onDelete: 'cascade' }),
  buildingId: uuid('building_id').notNull().references(() => buildings.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 200 }).notNull(),
  description: text('description'),
  level: integer('level').notNull(), // Floor number (can be negative for basements)
  floorPlanUrl: text('floor_plan_url'),
  totalArea: integer('total_area'), // in square feet/meters
  settings: jsonb('settings').default({}).notNull(),
  metadata: jsonb('metadata').default({}).notNull(),
  isActive: boolean('is_active').default(true).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: uuid('created_by'),
  updatedBy: uuid('updated_by')
}, (table) => ({
  buildingLevelUnique: unique('floors_building_level_unique').on(table.buildingId, table.level),
  tenantIdx: index('floors_tenant_idx').on(table.tenantId),
  organizationIdx: index('floors_organization_idx').on(table.organizationId),
  siteIdx: index('floors_site_idx').on(table.siteId),
  buildingIdx: index('floors_building_idx').on(table.buildingId),
  activeIdx: index('floors_active_idx').on(table.isActive),
  createdAtIdx: index('floors_created_at_idx').on(table.createdAt)
}));

// Zones table
export const zones = pgTable('zones', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  siteId: uuid('site_id').notNull().references(() => sites.id, { onDelete: 'cascade' }),
  buildingId: uuid('building_id').notNull().references(() => buildings.id, { onDelete: 'cascade' }),
  floorId: uuid('floor_id').notNull().references(() => floors.id, { onDelete: 'cascade' }),
  name: varchar('name', { length: 200 }).notNull(),
  description: text('description'),
  type: varchar('type', { length: 50 }), // e.g., 'office', 'common', 'restricted', 'emergency'
  accessLevel: varchar('access_level', { length: 50 }), // e.g., 'public', 'employee', 'secure', 'restricted'
  capacity: integer('capacity'), // Maximum occupancy
  settings: jsonb('settings').default({}).notNull(),
  metadata: jsonb('metadata').default({}).notNull(),
  isActive: boolean('is_active').default(true).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
  createdBy: uuid('created_by'),
  updatedBy: uuid('updated_by')
}, (table) => ({
  floorNameUnique: unique('zones_floor_name_unique').on(table.floorId, table.name),
  tenantIdx: index('zones_tenant_idx').on(table.tenantId),
  organizationIdx: index('zones_organization_idx').on(table.organizationId),
  siteIdx: index('zones_site_idx').on(table.siteId),
  buildingIdx: index('zones_building_idx').on(table.buildingId),
  floorIdx: index('zones_floor_idx').on(table.floorId),
  typeIdx: index('zones_type_idx').on(table.type),
  accessLevelIdx: index('zones_access_level_idx').on(table.accessLevel),
  activeIdx: index('zones_active_idx').on(table.isActive),
  createdAtIdx: index('zones_created_at_idx').on(table.createdAt)
}));

// Tenant resource usage tracking
export const tenantResourceUsage = pgTable('tenant_resource_usage', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
  date: timestamp('date').notNull(),
  userCount: integer('user_count').default(0).notNull(),
  doorCount: integer('door_count').default(0).notNull(),
  cameraCount: integer('camera_count').default(0).notNull(),
  storageUsedGB: integer('storage_used_gb').default(0).notNull(),
  apiCallCount: integer('api_call_count').default(0).notNull(),
  bandwidthUsedGB: integer('bandwidth_used_gb').default(0).notNull(),
  metadata: jsonb('metadata').default({}).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull()
}, (table) => ({
  tenantDateUnique: unique('tenant_resource_usage_tenant_date_unique').on(table.tenantId, table.date),
  tenantIdx: index('tenant_resource_usage_tenant_idx').on(table.tenantId),
  dateIdx: index('tenant_resource_usage_date_idx').on(table.date)
}));

// Relations
export const tenantsRelations = relations(tenants, ({ many }) => ({
  organizations: many(organizations),
  sites: many(sites),
  buildings: many(buildings),
  floors: many(floors),
  zones: many(zones),
  resourceUsage: many(tenantResourceUsage)
}));

export const organizationsRelations = relations(organizations, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [organizations.tenantId],
    references: [tenants.id]
  }),
  sites: many(sites),
  buildings: many(buildings),
  floors: many(floors),
  zones: many(zones)
}));

export const sitesRelations = relations(sites, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [sites.tenantId],
    references: [tenants.id]
  }),
  organization: one(organizations, {
    fields: [sites.organizationId],
    references: [organizations.id]
  }),
  buildings: many(buildings),
  floors: many(floors),
  zones: many(zones)
}));

export const buildingsRelations = relations(buildings, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [buildings.tenantId],
    references: [tenants.id]
  }),
  organization: one(organizations, {
    fields: [buildings.organizationId],
    references: [organizations.id]
  }),
  site: one(sites, {
    fields: [buildings.siteId],
    references: [sites.id]
  }),
  floors: many(floors),
  zones: many(zones)
}));

export const floorsRelations = relations(floors, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [floors.tenantId],
    references: [tenants.id]
  }),
  organization: one(organizations, {
    fields: [floors.organizationId],
    references: [organizations.id]
  }),
  site: one(sites, {
    fields: [floors.siteId],
    references: [sites.id]
  }),
  building: one(buildings, {
    fields: [floors.buildingId],
    references: [buildings.id]
  }),
  zones: many(zones)
}));

export const zonesRelations = relations(zones, ({ one }) => ({
  tenant: one(tenants, {
    fields: [zones.tenantId],
    references: [tenants.id]
  }),
  organization: one(organizations, {
    fields: [zones.organizationId],
    references: [organizations.id]
  }),
  site: one(sites, {
    fields: [zones.siteId],
    references: [sites.id]
  }),
  building: one(buildings, {
    fields: [zones.buildingId],
    references: [buildings.id]
  }),
  floor: one(floors, {
    fields: [zones.floorId],
    references: [floors.id]
  })
}));

export const tenantResourceUsageRelations = relations(tenantResourceUsage, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tenantResourceUsage.tenantId],
    references: [tenants.id]
  })
}));

// Type exports
export type Tenant = typeof tenants.$inferSelect;
export type NewTenant = typeof tenants.$inferInsert;
export type Organization = typeof organizations.$inferSelect;
export type NewOrganization = typeof organizations.$inferInsert;
export type Site = typeof sites.$inferSelect;
export type NewSite = typeof sites.$inferInsert;
export type Building = typeof buildings.$inferSelect;
export type NewBuilding = typeof buildings.$inferInsert;
export type Floor = typeof floors.$inferSelect;
export type NewFloor = typeof floors.$inferInsert;
export type Zone = typeof zones.$inferSelect;
export type NewZone = typeof zones.$inferInsert;
export type TenantResourceUsage = typeof tenantResourceUsage.$inferSelect;
export type NewTenantResourceUsage = typeof tenantResourceUsage.$inferInsert;