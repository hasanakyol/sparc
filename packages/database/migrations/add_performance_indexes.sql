-- Performance indexes for SPARC platform
-- This migration adds indexes to improve query performance across all services

-- ============================================
-- Multi-tenant queries optimization
-- ============================================

-- Security incidents - tenant queries with status filtering
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status 
ON security_incidents(organization_id, status) 
WHERE deleted_at IS NULL;

-- Cameras - tenant and site filtering
CREATE INDEX IF NOT EXISTS idx_cameras_tenant_site 
ON cameras(organization_id, site_id) 
WHERE deleted_at IS NULL;

-- Access events - tenant queries with time-based filtering
CREATE INDEX IF NOT EXISTS idx_access_events_tenant_time 
ON access_events(organization_id, timestamp DESC);

-- Users - tenant-based lookups
CREATE INDEX IF NOT EXISTS idx_users_tenant_email 
ON users(organization_id, email) 
WHERE deleted_at IS NULL;

-- ============================================
-- Video system performance
-- ============================================

-- Video recordings - camera-based queries with time filtering
CREATE INDEX IF NOT EXISTS idx_recordings_camera_time 
ON video_recordings(camera_id, start_time DESC);

-- Video recordings - tenant retention queries
CREATE INDEX IF NOT EXISTS idx_recordings_tenant_retention 
ON video_recordings(organization_id, created_at) 
WHERE deleted_at IS NULL;

-- Video analytics - efficient video metadata lookups
CREATE INDEX IF NOT EXISTS idx_video_metadata_recording 
ON video_metadata(recording_id, created_at DESC);

-- Video exports - status tracking
CREATE INDEX IF NOT EXISTS idx_video_exports_status 
ON video_exports(organization_id, status, created_at DESC);

-- ============================================
-- Analytics and reporting
-- ============================================

-- Analytics events - type-based aggregation queries
CREATE INDEX IF NOT EXISTS idx_analytics_events_type_time 
ON analytics_events(event_type, created_at DESC);

-- Analytics events - tenant and camera filtering
CREATE INDEX IF NOT EXISTS idx_analytics_tenant_camera 
ON analytics_events(organization_id, camera_id, created_at DESC);

-- People counting analytics
CREATE INDEX IF NOT EXISTS idx_people_count_zone_time 
ON people_counting(zone_id, timestamp DESC);

-- Behavior analytics
CREATE INDEX IF NOT EXISTS idx_behavior_analytics_type 
ON behavior_analytics(organization_id, behavior_type, detected_at DESC);

-- ============================================
-- Security and access control
-- ============================================

-- Security events - efficient SIEM queries
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_type 
ON security_events(organization_id, event_type, timestamp DESC);

-- Security events - severity-based filtering
CREATE INDEX IF NOT EXISTS idx_security_events_severity 
ON security_events(organization_id, severity, timestamp DESC) 
WHERE severity IN ('critical', 'high');

-- Access logs - user activity tracking
CREATE INDEX IF NOT EXISTS idx_access_logs_user_time 
ON access_logs(user_id, timestamp DESC);

-- Permission checks - role-based access
CREATE INDEX IF NOT EXISTS idx_role_permissions_lookup 
ON role_permissions(role_id, resource_type, resource_id);

-- ============================================
-- Alert and notification system
-- ============================================

-- Alerts - active alert queries
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status 
ON alerts(organization_id, status, created_at DESC) 
WHERE status IN ('active', 'acknowledged');

-- Alert rules - efficient rule matching
CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant_type 
ON alert_rules(organization_id, rule_type, enabled) 
WHERE enabled = true;

-- Notifications - delivery tracking
CREATE INDEX IF NOT EXISTS idx_notifications_user_status 
ON notifications(user_id, delivered, created_at DESC);

-- ============================================
-- Device and sensor management
-- ============================================

-- Devices - status monitoring
CREATE INDEX IF NOT EXISTS idx_devices_tenant_status 
ON devices(organization_id, device_type, status) 
WHERE deleted_at IS NULL;

-- Device telemetry - time-series queries
CREATE INDEX IF NOT EXISTS idx_device_telemetry_time 
ON device_telemetry(device_id, timestamp DESC);

-- Sensor readings - efficient data retrieval
CREATE INDEX IF NOT EXISTS idx_sensor_readings_sensor_time 
ON sensor_readings(sensor_id, reading_time DESC);

-- ============================================
-- JSONB indexes for flexible queries
-- ============================================

-- Tenant settings - configuration lookups
CREATE INDEX IF NOT EXISTS idx_tenant_settings 
ON organizations USING gin(settings);

-- Camera configuration - settings queries
CREATE INDEX IF NOT EXISTS idx_camera_config 
ON cameras USING gin(configuration);

-- Alert rule conditions - complex rule matching
CREATE INDEX IF NOT EXISTS idx_alert_rule_conditions 
ON alert_rules USING gin(conditions);

-- Device metadata - flexible device queries
CREATE INDEX IF NOT EXISTS idx_device_metadata 
ON devices USING gin(metadata);

-- ============================================
-- Composite indexes for complex queries
-- ============================================

-- Incident timeline queries
CREATE INDEX IF NOT EXISTS idx_incident_timeline_composite 
ON security_incidents(organization_id, created_at DESC, severity, status) 
WHERE deleted_at IS NULL;

-- Video search optimization
CREATE INDEX IF NOT EXISTS idx_video_search_composite 
ON video_recordings(organization_id, camera_id, start_time DESC, end_time DESC) 
WHERE deleted_at IS NULL;

-- User activity dashboard
CREATE INDEX IF NOT EXISTS idx_user_activity_composite 
ON audit_logs(organization_id, user_id, created_at DESC, action_type);

-- ============================================
-- Partial indexes for specific scenarios
-- ============================================

-- Active incidents only
CREATE INDEX IF NOT EXISTS idx_active_incidents 
ON security_incidents(organization_id, severity, created_at DESC) 
WHERE status IN ('open', 'investigating') AND deleted_at IS NULL;

-- Recent video recordings (last 7 days)
CREATE INDEX IF NOT EXISTS idx_recent_recordings 
ON video_recordings(camera_id, start_time DESC) 
WHERE start_time > CURRENT_TIMESTAMP - INTERVAL '7 days';

-- Failed login attempts
CREATE INDEX IF NOT EXISTS idx_failed_logins 
ON audit_logs(user_email, created_at DESC) 
WHERE action_type = 'login_failed' AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours';

-- ============================================
-- Performance analysis views
-- ============================================

-- Create a view for monitoring index usage
CREATE OR REPLACE VIEW index_usage_stats AS
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- Create a view for identifying missing indexes
CREATE OR REPLACE VIEW missing_index_candidates AS
SELECT 
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    CASE 
        WHEN seq_scan > 0 THEN 
            ROUND(100.0 * idx_scan / (seq_scan + idx_scan), 2)
        ELSE 100
    END as index_hit_rate,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename::regclass)) as table_size
FROM pg_stat_user_tables
WHERE seq_scan > 1000
    AND pg_relation_size(schemaname||'.'||tablename::regclass) > 1000000
ORDER BY seq_scan DESC;

-- ============================================
-- Maintenance commands
-- ============================================

-- Analyze tables after creating indexes
ANALYZE security_incidents;
ANALYZE cameras;
ANALYZE video_recordings;
ANALYZE analytics_events;
ANALYZE security_events;
ANALYZE access_events;
ANALYZE users;
ANALYZE organizations;
ANALYZE devices;
ANALYZE alerts;

-- Add comment to track migration
COMMENT ON SCHEMA public IS 'SPARC Platform - Performance indexes applied';