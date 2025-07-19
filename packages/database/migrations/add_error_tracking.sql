-- Create error_events table for error tracking
CREATE TABLE IF NOT EXISTS error_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  service VARCHAR(100) NOT NULL,
  environment VARCHAR(50) NOT NULL,
  error_type VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  stack TEXT,
  context JSONB DEFAULT '{}',
  user_data JSONB DEFAULT '{}',
  request_data JSONB DEFAULT '{}',
  tags JSONB DEFAULT '{}',
  fingerprint JSONB DEFAULT '[]',
  level VARCHAR(20) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_error_events_timestamp ON error_events(timestamp DESC);
CREATE INDEX idx_error_events_service ON error_events(service);
CREATE INDEX idx_error_events_error_type ON error_events(error_type);
CREATE INDEX idx_error_events_level ON error_events(level);
CREATE INDEX idx_error_events_fingerprint ON error_events USING GIN(fingerprint);

-- Create error_metrics_hourly table for aggregated metrics
CREATE TABLE IF NOT EXISTS error_metrics_hourly (
  hour TIMESTAMPTZ NOT NULL,
  service VARCHAR(100) NOT NULL,
  error_type VARCHAR(255),
  level VARCHAR(20),
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (hour, service, error_type, level)
);

-- Create error_trends table for trend analysis
CREATE TABLE IF NOT EXISTS error_trends (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  fingerprint TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  resolved BOOLEAN DEFAULT false,
  resolved_at TIMESTAMPTZ,
  notes TEXT,
  UNIQUE(fingerprint)
);

-- Function to aggregate hourly metrics
CREATE OR REPLACE FUNCTION aggregate_error_metrics()
RETURNS void AS $$
BEGIN
  INSERT INTO error_metrics_hourly (hour, service, error_type, level, count)
  SELECT 
    date_trunc('hour', timestamp) as hour,
    service,
    error_type,
    level,
    COUNT(*) as count
  FROM error_events
  WHERE timestamp >= NOW() - INTERVAL '2 hours'
    AND timestamp < date_trunc('hour', NOW())
  GROUP BY date_trunc('hour', timestamp), service, error_type, level
  ON CONFLICT (hour, service, error_type, level) 
  DO UPDATE SET count = EXCLUDED.count;
END;
$$ LANGUAGE plpgsql;

-- Function to update error trends
CREATE OR REPLACE FUNCTION update_error_trends()
RETURNS void AS $$
BEGIN
  -- Update existing trends
  UPDATE error_trends et
  SET 
    last_seen = NOW(),
    occurrence_count = occurrence_count + 1
  FROM (
    SELECT 
      fingerprint::text as fp,
      COUNT(*) as new_count
    FROM error_events
    WHERE timestamp >= NOW() - INTERVAL '1 hour'
    GROUP BY fingerprint::text
  ) new_errors
  WHERE et.fingerprint = new_errors.fp;

  -- Insert new trends
  INSERT INTO error_trends (fingerprint, first_seen, last_seen, occurrence_count)
  SELECT 
    fingerprint::text,
    MIN(timestamp),
    MAX(timestamp),
    COUNT(*)
  FROM error_events e
  WHERE timestamp >= NOW() - INTERVAL '1 hour'
    AND NOT EXISTS (
      SELECT 1 FROM error_trends et 
      WHERE et.fingerprint = e.fingerprint::text
    )
  GROUP BY fingerprint::text;
END;
$$ LANGUAGE plpgsql;

-- Create views for monitoring
CREATE OR REPLACE VIEW error_summary AS
SELECT 
  date_trunc('hour', timestamp) as hour,
  service,
  error_type,
  level,
  COUNT(*) as error_count,
  COUNT(DISTINCT fingerprint) as unique_errors
FROM error_events
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY date_trunc('hour', timestamp), service, error_type, level
ORDER BY hour DESC, error_count DESC;

CREATE OR REPLACE VIEW top_errors AS
SELECT 
  fingerprint::text,
  error_type,
  service,
  COUNT(*) as occurrence_count,
  MAX(timestamp) as last_seen,
  (SELECT message FROM error_events e2 
   WHERE e2.fingerprint = e1.fingerprint 
   ORDER BY timestamp DESC LIMIT 1) as latest_message
FROM error_events e1
WHERE timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY fingerprint::text, error_type, service
ORDER BY occurrence_count DESC
LIMIT 50;

-- Add RLS policies
ALTER TABLE error_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE error_metrics_hourly ENABLE ROW LEVEL SECURITY;
ALTER TABLE error_trends ENABLE ROW LEVEL SECURITY;

-- Error events are global but filtered by organization if user_data contains org
CREATE POLICY "error_events_access" ON error_events
  FOR ALL
  USING (
    current_setting('app.is_admin', true)::boolean = true
    OR current_setting('app.is_super_admin', true)::boolean = true
    OR (user_data->>'organizationId')::uuid = current_setting('app.current_organization_id', true)::uuid
    OR user_data->>'organizationId' IS NULL
  );

-- Metrics are accessible to admins only
CREATE POLICY "error_metrics_admin_only" ON error_metrics_hourly
  FOR ALL
  USING (
    current_setting('app.is_admin', true)::boolean = true
    OR current_setting('app.is_super_admin', true)::boolean = true
  );

-- Trends are accessible to admins only
CREATE POLICY "error_trends_admin_only" ON error_trends
  FOR ALL
  USING (
    current_setting('app.is_admin', true)::boolean = true
    OR current_setting('app.is_super_admin', true)::boolean = true
  );

-- Grant permissions
GRANT ALL ON error_events TO authenticated;
GRANT ALL ON error_metrics_hourly TO authenticated;
GRANT ALL ON error_trends TO authenticated;
GRANT SELECT ON error_summary TO authenticated;
GRANT SELECT ON top_errors TO authenticated;

-- Create scheduled jobs (using pg_cron if available)
-- Note: This requires pg_cron extension to be installed
-- SELECT cron.schedule('aggregate-error-metrics', '5 * * * *', 'SELECT aggregate_error_metrics();');
-- SELECT cron.schedule('update-error-trends', '*/10 * * * *', 'SELECT update_error_trends();');