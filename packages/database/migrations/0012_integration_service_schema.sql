-- Integration Service Schema Migration
-- This migration creates tables for the integration service

-- Create enums
CREATE TYPE integration_status AS ENUM (
  'ACTIVE',
  'INACTIVE',
  'PENDING',
  'ERROR',
  'SUSPENDED'
);

CREATE TYPE integration_type AS ENUM (
  'REST_API',
  'WEBHOOK',
  'OAUTH2',
  'SAML',
  'CUSTOM'
);

CREATE TYPE webhook_status AS ENUM (
  'ACTIVE',
  'INACTIVE',
  'FAILED',
  'SUSPENDED'
);

-- Create integrations table
CREATE TABLE integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Integration Information
  name VARCHAR(255) NOT NULL,
  description TEXT,
  type integration_type NOT NULL,
  status integration_status NOT NULL DEFAULT 'PENDING',
  
  -- Configuration
  config JSONB NOT NULL,
  credentials JSONB, -- Encrypted credentials
  
  -- API Information
  api_key VARCHAR(255),
  api_secret VARCHAR(255), -- Encrypted
  base_url VARCHAR(500),
  
  -- Rate Limiting
  rate_limit INTEGER,
  rate_limit_window INTEGER, -- in seconds
  
  -- Metadata
  version VARCHAR(50),
  tags JSONB,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_sync_at TIMESTAMP WITH TIME ZONE,
  created_by UUID REFERENCES users(id),
  updated_by UUID REFERENCES users(id)
);

-- Create webhooks table
CREATE TABLE webhooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id),
  integration_id UUID REFERENCES integrations(id) ON DELETE CASCADE,
  
  -- Webhook Information
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(500) NOT NULL,
  status webhook_status NOT NULL DEFAULT 'ACTIVE',
  
  -- Configuration
  events JSONB NOT NULL, -- Array of event types
  headers JSONB, -- Custom headers
  secret VARCHAR(255), -- For webhook signature verification
  
  -- Retry Configuration
  retry_enabled BOOLEAN DEFAULT TRUE,
  retry_attempts INTEGER DEFAULT 3,
  retry_delay INTEGER DEFAULT 60, -- in seconds
  
  -- Statistics
  total_calls INTEGER DEFAULT 0,
  successful_calls INTEGER DEFAULT 0,
  failed_calls INTEGER DEFAULT 0,
  last_call_at TIMESTAMP WITH TIME ZONE,
  last_error TEXT,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id),
  updated_by UUID REFERENCES users(id)
);

-- Create webhook_logs table
CREATE TABLE webhook_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Request Information
  event_type VARCHAR(100) NOT NULL,
  request_headers JSONB,
  request_body JSONB,
  
  -- Response Information
  response_status INTEGER,
  response_headers JSONB,
  response_body JSONB,
  
  -- Execution Information
  attempt_number INTEGER DEFAULT 1,
  duration_ms INTEGER,
  error_message TEXT,
  
  -- Timestamps
  sent_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMP WITH TIME ZONE
);

-- Create integration_mappings table
CREATE TABLE integration_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Mapping Information
  source_field VARCHAR(255) NOT NULL,
  target_field VARCHAR(255) NOT NULL,
  transformation JSONB, -- Transformation rules
  
  -- Configuration
  is_required BOOLEAN DEFAULT FALSE,
  default_value JSONB,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create integration_logs table
CREATE TABLE integration_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Log Information
  action VARCHAR(100) NOT NULL,
  status VARCHAR(50) NOT NULL,
  details JSONB,
  error_message TEXT,
  
  -- Timestamps
  occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  logged_by UUID REFERENCES users(id)
);

-- Create oauth_tokens table
CREATE TABLE oauth_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  integration_id UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Token Information
  access_token TEXT NOT NULL, -- Encrypted
  refresh_token TEXT, -- Encrypted
  token_type VARCHAR(50),
  scope TEXT,
  
  -- Expiration
  expires_at TIMESTAMP WITH TIME ZONE,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_integrations_organization ON integrations(organization_id);
CREATE INDEX idx_integrations_status ON integrations(status);
CREATE INDEX idx_integrations_type ON integrations(type);
CREATE UNIQUE INDEX idx_integrations_org_name ON integrations(organization_id, name);

CREATE INDEX idx_webhooks_organization ON webhooks(organization_id);
CREATE INDEX idx_webhooks_integration ON webhooks(integration_id);
CREATE INDEX idx_webhooks_status ON webhooks(status);
CREATE INDEX idx_webhooks_url ON webhooks(url);

CREATE INDEX idx_webhook_logs_webhook ON webhook_logs(webhook_id);
CREATE INDEX idx_webhook_logs_organization ON webhook_logs(organization_id);
CREATE INDEX idx_webhook_logs_sent_at ON webhook_logs(sent_at);
CREATE INDEX idx_webhook_logs_event_type ON webhook_logs(event_type);

CREATE INDEX idx_integration_mappings_integration ON integration_mappings(integration_id);
CREATE INDEX idx_integration_logs_integration ON integration_logs(integration_id);
CREATE INDEX idx_integration_logs_occurred ON integration_logs(occurred_at);

CREATE INDEX idx_oauth_tokens_integration ON oauth_tokens(integration_id);
CREATE INDEX idx_oauth_tokens_expires ON oauth_tokens(expires_at);

-- Add updated_at trigger
CREATE TRIGGER update_integrations_updated_at BEFORE UPDATE ON integrations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_webhooks_updated_at BEFORE UPDATE ON webhooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_integration_mappings_updated_at BEFORE UPDATE ON integration_mappings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_tokens_updated_at BEFORE UPDATE ON oauth_tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add row-level security policies (if RLS is enabled)
-- These will be created by the RLS migration script