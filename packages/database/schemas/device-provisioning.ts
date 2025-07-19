import { pgTable, uuid, varchar, text, timestamp, jsonb, integer, boolean, pgEnum, index, uniqueIndex } from 'drizzle-orm/pg-core';
import { createInsertSchema, createSelectSchema } from 'drizzle-zod';
import { z } from 'zod';

// Enums
export const provisioningMethodEnum = pgEnum('provisioning_method', ['manual', 'automatic', 'bulk', 'api', 'zero_touch']);
export const provisioningStatusEnum = pgEnum('provisioning_status', ['pending', 'in_progress', 'completed', 'failed', 'cancelled']);
export const stepStatusEnum = pgEnum('step_status', ['pending', 'in_progress', 'completed', 'failed', 'skipped']);
export const certificateTypeEnum = pgEnum('certificate_type', ['root', 'intermediate', 'device', 'client']);
export const certificateStatusEnum = pgEnum('certificate_status', ['active', 'expired', 'revoked', 'pending']);

// Device provisioning records table
export const deviceProvisioningRecords = pgTable('device_provisioning_records', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  deviceId: uuid('device_id').notNull(),
  provisioningMethod: provisioningMethodEnum('provisioning_method').notNull(),
  status: provisioningStatusEnum('status').notNull().default('pending'),
  templateId: uuid('template_id'),
  certificateId: uuid('certificate_id'),
  configurationVersion: integer('configuration_version').notNull().default(1),
  provisioningData: jsonb('provisioning_data'),
  metadata: jsonb('metadata'),
  errorMessage: text('error_message'),
  retryCount: integer('retry_count').notNull().default(0),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  startedAt: timestamp('started_at'),
  completedAt: timestamp('completed_at'),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => ({
  tenantIdx: index('idx_provisioning_tenant').on(table.tenantId),
  deviceIdx: index('idx_provisioning_device').on(table.deviceId),
  statusIdx: index('idx_provisioning_status').on(table.status),
  createdAtIdx: index('idx_provisioning_created').on(table.createdAt),
}));

// Provisioning steps table
export const provisioningSteps = pgTable('provisioning_steps', {
  id: uuid('id').primaryKey().defaultRandom(),
  provisioningRecordId: uuid('provisioning_record_id').notNull().references(() => deviceProvisioningRecords.id, { onDelete: 'cascade' }),
  stepName: varchar('step_name', { length: 100 }).notNull(),
  stepOrder: integer('step_order').notNull(),
  status: stepStatusEnum('status').notNull().default('pending'),
  errorMessage: text('error_message'),
  retryCount: integer('retry_count').notNull().default(0),
  stepData: jsonb('step_data'),
  startedAt: timestamp('started_at'),
  completedAt: timestamp('completed_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => ({
  recordIdx: index('idx_step_record').on(table.provisioningRecordId),
  statusIdx: index('idx_step_status').on(table.status),
}));

// Device certificates table
export const deviceCertificates = pgTable('device_certificates', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  deviceId: uuid('device_id').notNull(),
  certificateType: certificateTypeEnum('certificate_type').notNull(),
  status: certificateStatusEnum('status').notNull().default('active'),
  serialNumber: varchar('serial_number', { length: 100 }).notNull().unique(),
  fingerprint: varchar('fingerprint', { length: 100 }).notNull(),
  publicKey: text('public_key').notNull(),
  privateKeyPath: text('private_key_path'), // Encrypted path to key storage
  issuerCertificateId: uuid('issuer_certificate_id'),
  subject: jsonb('subject').notNull(),
  extensions: jsonb('extensions'),
  issuedAt: timestamp('issued_at').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  revokedAt: timestamp('revoked_at'),
  revocationReason: varchar('revocation_reason', { length: 255 }),
  lastUsedAt: timestamp('last_used_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => ({
  tenantIdx: index('idx_cert_tenant').on(table.tenantId),
  deviceIdx: index('idx_cert_device').on(table.deviceId),
  serialIdx: uniqueIndex('idx_cert_serial').on(table.serialNumber),
  fingerprintIdx: index('idx_cert_fingerprint').on(table.fingerprint),
  statusIdx: index('idx_cert_status').on(table.status),
  expiresIdx: index('idx_cert_expires').on(table.expiresAt),
}));

// Configuration templates table
export const configurationTemplates = pgTable('configuration_templates', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  deviceType: varchar('device_type', { length: 100 }).notNull(),
  manufacturer: varchar('manufacturer', { length: 100 }),
  model: varchar('model', { length: 100 }),
  version: integer('version').notNull().default(1),
  isDefault: boolean('is_default').notNull().default(false),
  configuration: jsonb('configuration').notNull(),
  validationSchema: jsonb('validation_schema'),
  metadata: jsonb('metadata'),
  active: boolean('active').notNull().default(true),
  createdBy: uuid('created_by').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => ({
  tenantIdx: index('idx_template_tenant').on(table.tenantId),
  deviceTypeIdx: index('idx_template_device_type').on(table.deviceType),
  activeIdx: index('idx_template_active').on(table.active),
  uniqueName: uniqueIndex('idx_template_unique_name').on(table.tenantId, table.name, table.version),
}));

// Certificate templates table
export const certificateTemplates = pgTable('certificate_templates', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  certificateType: certificateTypeEnum('certificate_type').notNull(),
  validityDays: integer('validity_days').notNull().default(365),
  keyAlgorithm: varchar('key_algorithm', { length: 50 }).notNull().default('RSA'),
  keySize: integer('key_size').notNull().default(2048),
  signatureAlgorithm: varchar('signature_algorithm', { length: 50 }).notNull().default('SHA256withRSA'),
  subjectTemplate: jsonb('subject_template').notNull(),
  extensions: jsonb('extensions').notNull(),
  active: boolean('active').notNull().default(true),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => ({
  tenantIdx: index('idx_cert_template_tenant').on(table.tenantId),
  typeIdx: index('idx_cert_template_type').on(table.certificateType),
}));

// Provisioning policies table
export const provisioningPolicies = pgTable('provisioning_policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  deviceType: varchar('device_type', { length: 100 }),
  rules: jsonb('rules').notNull(),
  priority: integer('priority').notNull().default(0),
  active: boolean('active').notNull().default(true),
  createdBy: uuid('created_by').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => ({
  tenantIdx: index('idx_policy_tenant').on(table.tenantId),
  priorityIdx: index('idx_policy_priority').on(table.priority),
  activeIdx: index('idx_policy_active').on(table.active),
}));

// Bulk provisioning jobs table
export const bulkProvisioningJobs = pgTable('bulk_provisioning_jobs', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  jobName: varchar('job_name', { length: 255 }).notNull(),
  templateId: uuid('template_id'),
  totalDevices: integer('total_devices').notNull(),
  successCount: integer('success_count').notNull().default(0),
  failureCount: integer('failure_count').notNull().default(0),
  status: provisioningStatusEnum('status').notNull().default('pending'),
  inputFile: text('input_file'),
  resultFile: text('result_file'),
  options: jsonb('options'),
  errorSummary: jsonb('error_summary'),
  createdBy: uuid('created_by').notNull(),
  startedAt: timestamp('started_at'),
  completedAt: timestamp('completed_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => ({
  tenantIdx: index('idx_bulk_tenant').on(table.tenantId),
  statusIdx: index('idx_bulk_status').on(table.status),
  createdAtIdx: index('idx_bulk_created').on(table.createdAt),
}));

// Device trust store table
export const deviceTrustStore = pgTable('device_trust_store', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  deviceId: uuid('device_id').notNull(),
  trustedCertificates: jsonb('trusted_certificates').notNull().default('[]'),
  pinnedCertificates: jsonb('pinned_certificates').default('[]'),
  allowedIssuers: jsonb('allowed_issuers').default('[]'),
  validationPolicy: jsonb('validation_policy'),
  lastValidated: timestamp('last_validated'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, (table) => ({
  tenantDeviceIdx: uniqueIndex('idx_trust_tenant_device').on(table.tenantId, table.deviceId),
}));

// Certificate revocation list
export const certificateRevocationList = pgTable('certificate_revocation_list', {
  id: uuid('id').primaryKey().defaultRandom(),
  tenantId: uuid('tenant_id').notNull(),
  certificateId: uuid('certificate_id').notNull().references(() => deviceCertificates.id),
  serialNumber: varchar('serial_number', { length: 100 }).notNull(),
  revocationDate: timestamp('revocation_date').notNull().defaultNow(),
  reason: varchar('reason', { length: 255 }).notNull(),
  revokedBy: uuid('revoked_by').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => ({
  tenantIdx: index('idx_crl_tenant').on(table.tenantId),
  serialIdx: index('idx_crl_serial').on(table.serialNumber),
  dateIdx: index('idx_crl_date').on(table.revocationDate),
}));

// Create Zod schemas for validation
export const insertDeviceProvisioningRecordSchema = createInsertSchema(deviceProvisioningRecords);
export const selectDeviceProvisioningRecordSchema = createSelectSchema(deviceProvisioningRecords);

export const insertProvisioningStepSchema = createInsertSchema(provisioningSteps);
export const selectProvisioningStepSchema = createSelectSchema(provisioningSteps);

export const insertDeviceCertificateSchema = createInsertSchema(deviceCertificates);
export const selectDeviceCertificateSchema = createSelectSchema(deviceCertificates);

export const insertConfigurationTemplateSchema = createInsertSchema(configurationTemplates);
export const selectConfigurationTemplateSchema = createSelectSchema(configurationTemplates);

export const insertCertificateTemplateSchema = createInsertSchema(certificateTemplates);
export const selectCertificateTemplateSchema = createSelectSchema(certificateTemplates);

export const insertProvisioningPolicySchema = createInsertSchema(provisioningPolicies);
export const selectProvisioningPolicySchema = createSelectSchema(provisioningPolicies);

export const insertBulkProvisioningJobSchema = createInsertSchema(bulkProvisioningJobs);
export const selectBulkProvisioningJobSchema = createSelectSchema(bulkProvisioningJobs);

export const insertDeviceTrustStoreSchema = createInsertSchema(deviceTrustStore);
export const selectDeviceTrustStoreSchema = createSelectSchema(deviceTrustStore);

export const insertCertificateRevocationSchema = createInsertSchema(certificateRevocationList);
export const selectCertificateRevocationSchema = createSelectSchema(certificateRevocationList);

// Type exports
export type DeviceProvisioningRecord = z.infer<typeof selectDeviceProvisioningRecordSchema>;
export type NewDeviceProvisioningRecord = z.infer<typeof insertDeviceProvisioningRecordSchema>;

export type ProvisioningStep = z.infer<typeof selectProvisioningStepSchema>;
export type NewProvisioningStep = z.infer<typeof insertProvisioningStepSchema>;

export type DeviceCertificate = z.infer<typeof selectDeviceCertificateSchema>;
export type NewDeviceCertificate = z.infer<typeof insertDeviceCertificateSchema>;

export type ConfigurationTemplate = z.infer<typeof selectConfigurationTemplateSchema>;
export type NewConfigurationTemplate = z.infer<typeof insertConfigurationTemplateSchema>;

export type CertificateTemplate = z.infer<typeof selectCertificateTemplateSchema>;
export type NewCertificateTemplate = z.infer<typeof insertCertificateTemplateSchema>;

export type ProvisioningPolicy = z.infer<typeof selectProvisioningPolicySchema>;
export type NewProvisioningPolicy = z.infer<typeof insertProvisioningPolicySchema>;

export type BulkProvisioningJob = z.infer<typeof selectBulkProvisioningJobSchema>;
export type NewBulkProvisioningJob = z.infer<typeof insertBulkProvisioningJobSchema>;

export type DeviceTrustStore = z.infer<typeof selectDeviceTrustStoreSchema>;
export type NewDeviceTrustStore = z.infer<typeof insertDeviceTrustStoreSchema>;

export type CertificateRevocation = z.infer<typeof selectCertificateRevocationSchema>;
export type NewCertificateRevocation = z.infer<typeof insertCertificateRevocationSchema>;