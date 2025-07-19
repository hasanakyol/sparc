-- Visitor Management Schema Migration
-- This migration creates tables for the visitor management system

-- Create enums
CREATE TYPE visitor_status AS ENUM (
  'PENDING',
  'APPROVED',
  'CHECKED_IN',
  'CHECKED_OUT',
  'EXPIRED',
  'DENIED',
  'CANCELLED'
);

CREATE TYPE badge_template AS ENUM (
  'STANDARD',
  'CONTRACTOR',
  'VIP',
  'ESCORT_REQUIRED',
  'TEMPORARY',
  'EVENT'
);

CREATE TYPE watchlist_status AS ENUM (
  'ACTIVE',
  'INACTIVE',
  'PENDING_REVIEW'
);

CREATE TYPE watchlist_reason AS ENUM (
  'SECURITY_THREAT',
  'PREVIOUS_INCIDENT',
  'BANNED',
  'INVESTIGATION',
  'OTHER'
);

-- Create visitors table
CREATE TABLE visitors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Personal Information
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  email VARCHAR(255),
  phone VARCHAR(50),
  company VARCHAR(255),
  
  -- Visit Information
  status visitor_status NOT NULL DEFAULT 'PENDING',
  purpose_of_visit TEXT,
  host_id UUID REFERENCES users(id),
  host_name VARCHAR(255),
  expected_arrival TIMESTAMP WITH TIME ZONE,
  expected_departure TIMESTAMP WITH TIME ZONE,
  actual_arrival TIMESTAMP WITH TIME ZONE,
  actual_departure TIMESTAMP WITH TIME ZONE,
  
  -- Badge Information
  badge_number VARCHAR(50),
  badge_template badge_template DEFAULT 'STANDARD',
  badge_printed_at TIMESTAMP WITH TIME ZONE,
  
  -- Additional Information
  escort_required BOOLEAN DEFAULT FALSE,
  areas_of_access JSONB,
  documents JSONB,
  photo_url TEXT,
  signature_url TEXT,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id),
  updated_by UUID REFERENCES users(id)
);

-- Create watchlist table
CREATE TABLE watchlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Person Information
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  aliases JSONB,
  date_of_birth DATE,
  identification_numbers JSONB,
  
  -- Watchlist Information
  status watchlist_status NOT NULL DEFAULT 'ACTIVE',
  reason watchlist_reason NOT NULL,
  reason_details TEXT,
  threat_level INTEGER CHECK (threat_level >= 1 AND threat_level <= 5),
  
  -- Additional Information
  photo_url TEXT,
  last_seen_location TEXT,
  last_seen_date TIMESTAMP WITH TIME ZONE,
  notes TEXT,
  
  -- Timestamps
  added_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE,
  added_by UUID REFERENCES users(id),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_by UUID REFERENCES users(id)
);

-- Create visitor_logs table
CREATE TABLE visitor_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id UUID NOT NULL REFERENCES visitors(id),
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Log Information
  action VARCHAR(50) NOT NULL,
  location VARCHAR(255),
  device_id UUID,
  
  -- Additional Information
  details JSONB,
  
  -- Timestamps
  occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  logged_by UUID REFERENCES users(id)
);

-- Create visitor_appointments table
CREATE TABLE visitor_appointments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id UUID REFERENCES visitors(id),
  organization_id UUID NOT NULL REFERENCES organizations(id),
  
  -- Appointment Information
  appointment_date DATE NOT NULL,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  recurring BOOLEAN DEFAULT FALSE,
  recurrence_rule JSONB,
  
  -- Host Information
  host_id UUID REFERENCES users(id),
  host_name VARCHAR(255),
  
  -- Status
  confirmed BOOLEAN DEFAULT FALSE,
  cancelled BOOLEAN DEFAULT FALSE,
  cancellation_reason TEXT,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by UUID REFERENCES users(id),
  updated_by UUID REFERENCES users(id)
);

-- Create indexes
CREATE INDEX idx_visitors_organization ON visitors(organization_id);
CREATE INDEX idx_visitors_status ON visitors(status);
CREATE INDEX idx_visitors_host ON visitors(host_id);
CREATE INDEX idx_visitors_arrival ON visitors(expected_arrival);
CREATE INDEX idx_visitors_email ON visitors(email);
CREATE INDEX idx_visitors_badge ON visitors(badge_number);

CREATE INDEX idx_watchlist_organization ON watchlist(organization_id);
CREATE INDEX idx_watchlist_status ON watchlist(status);
CREATE INDEX idx_watchlist_name ON watchlist(first_name, last_name);

CREATE INDEX idx_visitor_logs_visitor ON visitor_logs(visitor_id);
CREATE INDEX idx_visitor_logs_organization ON visitor_logs(organization_id);
CREATE INDEX idx_visitor_logs_occurred ON visitor_logs(occurred_at);

CREATE INDEX idx_appointments_visitor ON visitor_appointments(visitor_id);
CREATE INDEX idx_appointments_organization ON visitor_appointments(organization_id);
CREATE INDEX idx_appointments_date ON visitor_appointments(appointment_date);
CREATE INDEX idx_appointments_host ON visitor_appointments(host_id);

-- Add updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_visitors_updated_at BEFORE UPDATE ON visitors
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_watchlist_updated_at BEFORE UPDATE ON watchlist
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_appointments_updated_at BEFORE UPDATE ON visitor_appointments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add row-level security policies (if RLS is enabled)
-- These will be created by the RLS migration script