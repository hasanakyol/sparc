-- Create security_events table for SIEM
CREATE TABLE IF NOT EXISTS security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_type VARCHAR(100) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  source VARCHAR(255) NOT NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  ip_address INET,
  user_agent TEXT,
  details JSONB NOT NULL DEFAULT '{}',
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX idx_security_events_event_type ON security_events(event_type);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_organization_id ON security_events(organization_id);
CREATE INDEX idx_security_events_ip_address ON security_events(ip_address);

-- Create alert_rules table
CREATE TABLE IF NOT EXISTS alert_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  conditions JSONB NOT NULL,
  actions JSONB NOT NULL,
  enabled BOOLEAN DEFAULT true,
  cooldown_minutes INTEGER,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create alert_history table
CREATE TABLE IF NOT EXISTS alert_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id UUID REFERENCES alert_rules(id) ON DELETE CASCADE,
  event_id UUID REFERENCES security_events(id) ON DELETE CASCADE,
  triggered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actions_executed JSONB,
  status VARCHAR(50) NOT NULL DEFAULT 'triggered'
);

-- Add RLS policies
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_history ENABLE ROW LEVEL SECURITY;

-- Security events are organization-scoped
CREATE POLICY "security_events_isolation" ON security_events
  FOR ALL
  USING (
    organization_id = current_setting('app.current_organization_id', true)::uuid
    OR current_setting('app.is_super_admin', true)::boolean = true
  );

-- Alert rules are global but only admins can manage
CREATE POLICY "alert_rules_admin_only" ON alert_rules
  FOR ALL
  USING (
    current_setting('app.is_admin', true)::boolean = true
    OR current_setting('app.is_super_admin', true)::boolean = true
  );

-- Alert history follows security events policy
CREATE POLICY "alert_history_isolation" ON alert_history
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM security_events se
      WHERE se.id = alert_history.event_id
      AND (
        se.organization_id = current_setting('app.current_organization_id', true)::uuid
        OR current_setting('app.is_super_admin', true)::boolean = true
      )
    )
  );

-- Grant permissions
GRANT ALL ON security_events TO authenticated;
GRANT ALL ON alert_rules TO authenticated;
GRANT ALL ON alert_history TO authenticated;