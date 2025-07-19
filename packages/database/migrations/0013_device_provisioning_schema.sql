-- Device Provisioning Schema Migration
-- This migration creates tables for the device provisioning system

-- Create enums
CREATE TYPE provisioning_method AS ENUM (
  'manual',
  'automatic',
  'bulk',
  'api',
  'zero_touch'
);

CREATE TYPE provisioning_status AS ENUM (
  'pending',
  'in_progress',
  'completed',
  'failed',
  'cancelled'
);

CREATE TYPE step_status AS ENUM (
  'pending',
  'in_progress',
  'completed',
  'failed',
  'skipped'
);

CREATE TYPE certificate_type AS ENUM (
  'root',
  'intermediate',
  'device',
  'client'
);

CREATE TYPE certificate_status AS ENUM (
  'active',
  'expired',
  'revoked',
  'pending'
);

-- Create device_provisioning_records table
CREATE TABLE device_provisioning_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  device_id UUID NOT NULL,
  provisioning_method provisioning_method NOT NULL,
  status provisioning_status NOT NULL DEFAULT 'pending',
  template_id UUID,
  certificate_id UUID,
  configuration_version INTEGER NOT NULL DEFAULT 1,
  provisioning_data JSONB,
  metadata JSONB,
  error_message TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create provisioning_steps table
CREATE TABLE provisioning_steps (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provisioning_record_id UUID NOT NULL REFERENCES device_provisioning_records(id) ON DELETE CASCADE,
  step_name VARCHAR(100) NOT NULL,
  step_order INTEGER NOT NULL,
  status step_status NOT NULL DEFAULT 'pending',
  error_message TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  step_data JSONB,
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create provisioning_templates table
CREATE TABLE provisioning_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  device_type VARCHAR(100),
  is_default BOOLEAN DEFAULT FALSE,
  configuration JSONB NOT NULL,
  steps JSONB NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create device_certificates table
CREATE TABLE device_certificates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  device_id UUID,
  certificate_type certificate_type NOT NULL,
  status certificate_status NOT NULL DEFAULT 'pending',
  subject VARCHAR(500) NOT NULL,
  issuer VARCHAR(500) NOT NULL,
  serial_number VARCHAR(100) NOT NULL,
  certificate_data TEXT NOT NULL,
  private_key_encrypted TEXT,
  public_key TEXT NOT NULL,
  fingerprint VARCHAR(100) NOT NULL,
  parent_certificate_id UUID REFERENCES device_certificates(id),
  valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
  valid_to TIMESTAMP WITH TIME ZONE NOT NULL,
  revoked_at TIMESTAMP WITH TIME ZONE,
  revocation_reason TEXT,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create provisioning_policies table
CREATE TABLE provisioning_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  device_type_pattern VARCHAR(255),
  network_requirements JSONB,
  security_requirements JSONB,
  compliance_requirements JSONB,
  auto_provision BOOLEAN DEFAULT FALSE,
  requires_approval BOOLEAN DEFAULT TRUE,
  approval_workflow JSONB,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create zero_touch_configs table
CREATE TABLE zero_touch_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  dhcp_options JSONB,
  tftp_server VARCHAR(255),
  config_server_url VARCHAR(500),
  authentication_method VARCHAR(50),
  network_patterns JSONB,
  device_patterns JSONB,
  default_template_id UUID REFERENCES provisioning_templates(id),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create bulk_provisioning_jobs table
CREATE TABLE bulk_provisioning_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  template_id UUID REFERENCES provisioning_templates(id),
  total_devices INTEGER NOT NULL,
  processed_devices INTEGER DEFAULT 0,
  successful_devices INTEGER DEFAULT 0,
  failed_devices INTEGER DEFAULT 0,
  input_data JSONB,
  error_report JSONB,
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by UUID
);

-- Create indexes
CREATE INDEX idx_provisioning_tenant ON device_provisioning_records(tenant_id);
CREATE INDEX idx_provisioning_device ON device_provisioning_records(device_id);
CREATE INDEX idx_provisioning_status ON device_provisioning_records(status);
CREATE INDEX idx_provisioning_created ON device_provisioning_records(created_at);

CREATE INDEX idx_steps_record ON provisioning_steps(provisioning_record_id);
CREATE INDEX idx_steps_status ON provisioning_steps(status);

CREATE INDEX idx_templates_tenant ON provisioning_templates(tenant_id);
CREATE UNIQUE INDEX idx_templates_tenant_name ON provisioning_templates(tenant_id, name);

CREATE INDEX idx_certificates_tenant ON device_certificates(tenant_id);
CREATE INDEX idx_certificates_device ON device_certificates(device_id);
CREATE INDEX idx_certificates_type ON device_certificates(certificate_type);
CREATE INDEX idx_certificates_status ON device_certificates(status);
CREATE INDEX idx_certificates_fingerprint ON device_certificates(fingerprint);
CREATE INDEX idx_certificates_valid_to ON device_certificates(valid_to);

CREATE INDEX idx_policies_tenant ON provisioning_policies(tenant_id);
CREATE INDEX idx_policies_active ON provisioning_policies(is_active);

CREATE INDEX idx_zero_touch_tenant ON zero_touch_configs(tenant_id);
CREATE INDEX idx_zero_touch_active ON zero_touch_configs(is_active);

CREATE INDEX idx_bulk_jobs_tenant ON bulk_provisioning_jobs(tenant_id);
CREATE INDEX idx_bulk_jobs_status ON bulk_provisioning_jobs(status);

-- Add updated_at triggers
CREATE TRIGGER update_provisioning_records_updated_at BEFORE UPDATE ON device_provisioning_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_templates_updated_at BEFORE UPDATE ON provisioning_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_certificates_updated_at BEFORE UPDATE ON device_certificates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON provisioning_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_zero_touch_updated_at BEFORE UPDATE ON zero_touch_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add row-level security policies (if RLS is enabled)
-- These will be created by the RLS migration script