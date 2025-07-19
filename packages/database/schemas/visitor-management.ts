import { pgTable, uuid, varchar, text, timestamp, pgEnum, boolean, jsonb, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from './user-management';
import { organizations } from './tenant';

// Enums
export const visitorStatusEnum = pgEnum('visitor_status', [
  'PENDING',
  'APPROVED',
  'CHECKED_IN',
  'CHECKED_OUT',
  'EXPIRED',
  'DENIED',
  'CANCELLED'
]);

export const badgeTemplateEnum = pgEnum('badge_template', [
  'STANDARD',
  'CONTRACTOR',
  'VIP',
  'ESCORT_REQUIRED',
  'TEMPORARY',
  'EVENT'
]);

export const watchlistStatusEnum = pgEnum('watchlist_status', [
  'ACTIVE',
  'INACTIVE',
  'PENDING_REVIEW'
]);

export const watchlistReasonEnum = pgEnum('watchlist_reason', [
  'SECURITY_THREAT',
  'PREVIOUS_INCIDENT',
  'BANNED',
  'INVESTIGATION',
  'OTHER'
]);

// Tables
export const visitors = pgTable('visitors', {
  id: uuid('id').defaultRandom().primaryKey(),
  organizationId: uuid('organization_id').references(() => organizations.id).notNull(),
  
  // Personal Information
  firstName: varchar('first_name', { length: 100 }).notNull(),
  lastName: varchar('last_name', { length: 100 }).notNull(),
  email: varchar('email', { length: 255 }),
  phone: varchar('phone', { length: 50 }),
  company: varchar('company', { length: 255 }),
  
  // Visit Details
  purpose: text('purpose').notNull(),
  hostUserId: uuid('host_user_id').references(() => users.id).notNull(),
  status: visitorStatusEnum('status').default('PENDING').notNull(),
  
  // Timing
  expectedArrival: timestamp('expected_arrival', { withTimezone: true }).notNull(),
  expectedDeparture: timestamp('expected_departure', { withTimezone: true }).notNull(),
  actualArrival: timestamp('actual_arrival', { withTimezone: true }),
  actualDeparture: timestamp('actual_departure', { withTimezone: true }),
  
  // Security & Access
  invitationCode: varchar('invitation_code', { length: 100 }).unique(),
  requiresEscort: boolean('requires_escort').default(false),
  accessAreas: jsonb('access_areas').$type<string[]>().default([]),
  
  // Documentation
  photo: text('photo'), // Base64 encoded
  idDocument: text('id_document'), // Base64 encoded
  idType: varchar('id_type', { length: 50 }),
  idNumber: varchar('id_number', { length: 100 }),
  
  // Additional Information
  vehicleLicense: varchar('vehicle_license', { length: 50 }),
  vehicleMake: varchar('vehicle_make', { length: 100 }),
  vehicleModel: varchar('vehicle_model', { length: 100 }),
  vehicleColor: varchar('vehicle_color', { length: 50 }),
  parkingSpot: varchar('parking_spot', { length: 50 }),
  
  // Emergency Contact
  emergencyContactName: varchar('emergency_contact_name', { length: 200 }),
  emergencyContactPhone: varchar('emergency_contact_phone', { length: 50 }),
  
  // Special Requirements
  specialRequirements: text('special_requirements'),
  notes: text('notes'),
  
  // Badge Information
  badgeNumber: varchar('badge_number', { length: 100 }),
  badgeTemplate: badgeTemplateEnum('badge_template').default('STANDARD'),
  badgePrintedAt: timestamp('badge_printed_at', { withTimezone: true }),
  badgePrintedBy: uuid('badge_printed_by').references(() => users.id),
  
  // Approval
  approvedBy: uuid('approved_by').references(() => users.id),
  approvedAt: timestamp('approved_at', { withTimezone: true }),
  deniedBy: uuid('denied_by').references(() => users.id),
  deniedAt: timestamp('denied_at', { withTimezone: true }),
  denialReason: text('denial_reason'),
  
  // Check-in/out
  checkedInBy: uuid('checked_in_by').references(() => users.id),
  checkedOutBy: uuid('checked_out_by').references(() => users.id),
  
  // Audit
  createdBy: uuid('created_by').references(() => users.id).notNull(),
  updatedBy: uuid('updated_by').references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  organizationIdx: index('visitors_organization_idx').on(table.organizationId),
  hostIdx: index('visitors_host_idx').on(table.hostUserId),
  statusIdx: index('visitors_status_idx').on(table.status),
  expectedArrivalIdx: index('visitors_expected_arrival_idx').on(table.expectedArrival),
  emailIdx: index('visitors_email_idx').on(table.email),
  invitationCodeIdx: index('visitors_invitation_code_idx').on(table.invitationCode),
}));

export const visitorWatchlist = pgTable('visitor_watchlist', {
  id: uuid('id').defaultRandom().primaryKey(),
  organizationId: uuid('organization_id').references(() => organizations.id).notNull(),
  
  // Identity Information
  firstName: varchar('first_name', { length: 100 }).notNull(),
  lastName: varchar('last_name', { length: 100 }).notNull(),
  email: varchar('email', { length: 255 }),
  phone: varchar('phone', { length: 50 }),
  idNumber: varchar('id_number', { length: 100 }),
  company: varchar('company', { length: 255 }),
  
  // Watchlist Details
  status: watchlistStatusEnum('status').default('ACTIVE').notNull(),
  reason: watchlistReasonEnum('reason').notNull(),
  description: text('description').notNull(),
  
  // Additional Information
  aliases: jsonb('aliases').$type<string[]>().default([]),
  photo: text('photo'), // Base64 encoded
  
  // Validity
  effectiveFrom: timestamp('effective_from', { withTimezone: true }).defaultNow().notNull(),
  effectiveUntil: timestamp('effective_until', { withTimezone: true }),
  
  // Source
  sourceSystem: varchar('source_system', { length: 100 }),
  externalId: varchar('external_id', { length: 255 }),
  
  // Audit
  addedBy: uuid('added_by').references(() => users.id).notNull(),
  reviewedBy: uuid('reviewed_by').references(() => users.id),
  reviewedAt: timestamp('reviewed_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  organizationIdx: index('watchlist_organization_idx').on(table.organizationId),
  statusIdx: index('watchlist_status_idx').on(table.status),
  nameIdx: index('watchlist_name_idx').on(table.firstName, table.lastName),
  emailIdx: index('watchlist_email_idx').on(table.email),
  idNumberIdx: index('watchlist_id_number_idx').on(table.idNumber),
}));

export const visitorGroups = pgTable('visitor_groups', {
  id: uuid('id').defaultRandom().primaryKey(),
  organizationId: uuid('organization_id').references(() => organizations.id).notNull(),
  
  // Group Information
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  groupSize: varchar('group_size', { length: 10 }).notNull(),
  
  // Primary Contact
  primaryContactId: uuid('primary_contact_id').references(() => visitors.id),
  
  // Visit Details
  purpose: text('purpose').notNull(),
  hostUserId: uuid('host_user_id').references(() => users.id).notNull(),
  
  // Timing
  expectedArrival: timestamp('expected_arrival', { withTimezone: true }).notNull(),
  expectedDeparture: timestamp('expected_departure', { withTimezone: true }).notNull(),
  
  // Access
  accessAreas: jsonb('access_areas').$type<string[]>().default([]),
  requiresEscort: boolean('requires_escort').default(false),
  
  // Audit
  createdBy: uuid('created_by').references(() => users.id).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  organizationIdx: index('visitor_groups_organization_idx').on(table.organizationId),
  hostIdx: index('visitor_groups_host_idx').on(table.hostUserId),
}));

export const visitorGroupMembers = pgTable('visitor_group_members', {
  id: uuid('id').defaultRandom().primaryKey(),
  groupId: uuid('group_id').references(() => visitorGroups.id).notNull(),
  visitorId: uuid('visitor_id').references(() => visitors.id).notNull(),
  isPrimaryContact: boolean('is_primary_contact').default(false),
  
  // Audit
  addedAt: timestamp('added_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  groupIdx: index('group_members_group_idx').on(table.groupId),
  visitorIdx: index('group_members_visitor_idx').on(table.visitorId),
  uniqueGroupVisitor: index('unique_group_visitor').on(table.groupId, table.visitorId).unique(),
}));

export const visitorCredentials = pgTable('visitor_credentials', {
  id: uuid('id').defaultRandom().primaryKey(),
  visitorId: uuid('visitor_id').references(() => visitors.id).notNull(),
  organizationId: uuid('organization_id').references(() => organizations.id).notNull(),
  
  // Credential Details
  credentialType: varchar('credential_type', { length: 50 }).notNull(), // QR_CODE, NFC, MOBILE
  credentialData: text('credential_data').notNull(),
  
  // Validity
  issuedAt: timestamp('issued_at', { withTimezone: true }).defaultNow().notNull(),
  validFrom: timestamp('valid_from', { withTimezone: true }).notNull(),
  validUntil: timestamp('valid_until', { withTimezone: true }).notNull(),
  
  // Status
  isActive: boolean('is_active').default(true),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
  revokedBy: uuid('revoked_by').references(() => users.id),
  revocationReason: text('revocation_reason'),
  
  // Access Control
  accessAreas: jsonb('access_areas').$type<string[]>().default([]),
  
  // Audit
  issuedBy: uuid('issued_by').references(() => users.id).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  visitorIdx: index('credentials_visitor_idx').on(table.visitorId),
  organizationIdx: index('credentials_organization_idx').on(table.organizationId),
  activeIdx: index('credentials_active_idx').on(table.isActive),
  validityIdx: index('credentials_validity_idx').on(table.validFrom, table.validUntil),
}));

export const visitorAccessLogs = pgTable('visitor_access_logs', {
  id: uuid('id').defaultRandom().primaryKey(),
  visitorId: uuid('visitor_id').references(() => visitors.id).notNull(),
  organizationId: uuid('organization_id').references(() => organizations.id).notNull(),
  
  // Access Details
  accessPoint: varchar('access_point', { length: 255 }).notNull(),
  direction: varchar('direction', { length: 10 }).notNull(), // IN, OUT
  accessTime: timestamp('access_time', { withTimezone: true }).defaultNow().notNull(),
  
  // Credential Used
  credentialId: uuid('credential_id').references(() => visitorCredentials.id),
  credentialType: varchar('credential_type', { length: 50 }),
  
  // Result
  granted: boolean('granted').notNull(),
  denialReason: varchar('denial_reason', { length: 255 }),
  
  // Location
  zone: varchar('zone', { length: 255 }),
  building: varchar('building', { length: 255 }),
  floor: varchar('floor', { length: 50 }),
  
  // Device Information
  deviceId: varchar('device_id', { length: 255 }),
  deviceType: varchar('device_type', { length: 100 }),
  
  // Audit
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
  visitorIdx: index('access_logs_visitor_idx').on(table.visitorId),
  organizationIdx: index('access_logs_organization_idx').on(table.organizationId),
  accessTimeIdx: index('access_logs_time_idx').on(table.accessTime),
  accessPointIdx: index('access_logs_point_idx').on(table.accessPoint),
}));

// Relations
export const visitorsRelations = relations(visitors, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [visitors.organizationId],
    references: [organizations.id],
  }),
  host: one(users, {
    fields: [visitors.hostUserId],
    references: [users.id],
  }),
  createdByUser: one(users, {
    fields: [visitors.createdBy],
    references: [users.id],
  }),
  approvedByUser: one(users, {
    fields: [visitors.approvedBy],
    references: [users.id],
  }),
  credentials: many(visitorCredentials),
  accessLogs: many(visitorAccessLogs),
  groupMemberships: many(visitorGroupMembers),
}));

export const visitorWatchlistRelations = relations(visitorWatchlist, ({ one }) => ({
  organization: one(organizations, {
    fields: [visitorWatchlist.organizationId],
    references: [organizations.id],
  }),
  addedByUser: one(users, {
    fields: [visitorWatchlist.addedBy],
    references: [users.id],
  }),
  reviewedByUser: one(users, {
    fields: [visitorWatchlist.reviewedBy],
    references: [users.id],
  }),
}));

export const visitorGroupsRelations = relations(visitorGroups, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [visitorGroups.organizationId],
    references: [organizations.id],
  }),
  host: one(users, {
    fields: [visitorGroups.hostUserId],
    references: [users.id],
  }),
  primaryContact: one(visitors, {
    fields: [visitorGroups.primaryContactId],
    references: [visitors.id],
  }),
  members: many(visitorGroupMembers),
}));

export const visitorCredentialsRelations = relations(visitorCredentials, ({ one, many }) => ({
  visitor: one(visitors, {
    fields: [visitorCredentials.visitorId],
    references: [visitors.id],
  }),
  organization: one(organizations, {
    fields: [visitorCredentials.organizationId],
    references: [organizations.id],
  }),
  issuedByUser: one(users, {
    fields: [visitorCredentials.issuedBy],
    references: [users.id],
  }),
  accessLogs: many(visitorAccessLogs),
}));