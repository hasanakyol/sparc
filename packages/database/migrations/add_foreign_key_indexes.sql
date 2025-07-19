-- Add indexes on foreign keys for better query performance
-- This migration adds indexes on all foreign key columns that don't already have them

-- User table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);

-- Credential table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_credentials_tenant_id ON credentials(tenant_id);

-- AccessEvent table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_events_tenant_id ON access_events(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_events_user_id ON access_events(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_events_door_id ON access_events(door_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_events_credential_id ON access_events(credential_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_events_card_reader_id ON access_events(card_reader_id);

-- Camera table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cameras_floor_id ON cameras(floor_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cameras_zone_id ON cameras(zone_id);

-- VideoRecording table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_video_recordings_tenant_id ON video_recordings(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_video_recordings_camera_id ON video_recordings(camera_id);

-- Alert table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_tenant_id ON alerts(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_acknowledged_by ON alerts(acknowledged_by);

-- AuditLog table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);

-- Visitor table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_visitors_tenant_id ON visitors(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_visitors_host_user_id ON visitors(host_user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_visitors_credential_id ON visitors(credential_id);

-- MaintenanceWorkOrder table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_maintenance_work_orders_tenant_id ON maintenance_work_orders(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_maintenance_work_orders_assigned_to_user_id ON maintenance_work_orders(assigned_to_user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_maintenance_work_orders_door_id ON maintenance_work_orders(door_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_maintenance_work_orders_camera_id ON maintenance_work_orders(camera_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_maintenance_work_orders_access_panel_id ON maintenance_work_orders(access_panel_id);

-- IncidentReport table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incident_reports_tenant_id ON incident_reports(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incident_reports_reported_by_user_id ON incident_reports(reported_by_user_id);

-- EnvironmentalSensor table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_environmental_sensors_tenant_id ON environmental_sensors(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_environmental_sensors_floor_id ON environmental_sensors(floor_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_environmental_sensors_zone_id ON environmental_sensors(zone_id);

-- EnvironmentalReading table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_environmental_readings_tenant_id ON environmental_readings(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_environmental_readings_sensor_id ON environmental_readings(sensor_id);

-- MobileCredential table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mobile_credentials_tenant_id ON mobile_credentials(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mobile_credentials_user_id ON mobile_credentials(user_id);

-- PrivacyMask table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_privacy_masks_tenant_id ON privacy_masks(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_privacy_masks_camera_id ON privacy_masks(camera_id);

-- VideoExportLog table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_video_export_logs_tenant_id ON video_export_logs(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_video_export_logs_exported_by_user_id ON video_export_logs(exported_by_user_id);

-- ElevatorControl table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_elevator_controls_tenant_id ON elevator_controls(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_elevator_controls_building_id ON elevator_controls(building_id);

-- AccessPanel table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_panels_tenant_id ON access_panels(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_panels_floor_id ON access_panels(floor_id);

-- CardReader table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_card_readers_access_panel_id ON card_readers(access_panel_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_card_readers_door_id ON card_readers(door_id);

-- AccessGroup table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_groups_tenant_id ON access_groups(tenant_id);

-- AccessGroupMember table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_group_members_access_group_id ON access_group_members(access_group_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_group_members_user_id ON access_group_members(user_id);

-- Schedule table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_schedules_tenant_id ON schedules(tenant_id);

-- SystemConfiguration table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_system_configurations_tenant_id ON system_configurations(tenant_id);

-- OfflineEventQueue table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_offline_event_queues_tenant_id ON offline_event_queues(tenant_id);

-- PolicyTemplate table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_policy_templates_tenant_id ON policy_templates(tenant_id);

-- OfflineOperationLog table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_offline_operation_logs_tenant_id ON offline_operation_logs(tenant_id);

-- Certificate table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_certificates_tenant_id ON certificates(tenant_id);

-- BackupJob table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_backup_jobs_tenant_id ON backup_jobs(tenant_id);

-- IntegrationConfiguration table indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_integration_configurations_tenant_id ON integration_configurations(tenant_id);

-- Composite indexes for common query patterns
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_events_tenant_timestamp ON access_events(tenant_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_events_door_timestamp ON access_events(door_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_video_recordings_camera_timestamp ON video_recordings(camera_id, start_time DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_tenant_status ON alerts(tenant_id, status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_tenant_timestamp ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_environmental_readings_sensor_timestamp ON environmental_readings(sensor_id, timestamp DESC);

-- Partial indexes for filtered queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_open ON alerts(tenant_id, created_at DESC) WHERE status = 'open';
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_active ON users(tenant_id, email) WHERE active = true;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_credentials_active ON credentials(tenant_id, user_id) WHERE active = true;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_maintenance_work_orders_pending ON maintenance_work_orders(tenant_id, created_at DESC) WHERE status IN ('pending', 'in_progress');

-- Function-based indexes for JSON queries (PostgreSQL specific)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_details_type ON alerts USING gin((details->'type'));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_roles ON users USING gin(roles);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_organizations_settings ON organizations USING gin(settings);

-- Text search indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_search ON users USING btree(lower(email));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_message_search ON alerts USING gin(to_tsvector('english', message));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incident_reports_description_search ON incident_reports USING gin(to_tsvector('english', description));