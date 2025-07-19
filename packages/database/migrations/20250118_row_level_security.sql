-- Enable Row Level Security on all tables
-- This migration implements tenant isolation at the database level

-- Enable RLS on all tables
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE buildings ENABLE ROW LEVEL SECURITY;
ALTER TABLE floors ENABLE ROW LEVEL SECURITY;
ALTER TABLE zones ENABLE ROW LEVEL SECURITY;
ALTER TABLE doors ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE cameras ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_panels ENABLE ROW LEVEL SECURITY;
ALTER TABLE card_readers ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE video_recordings ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitors ENABLE ROW LEVEL SECURITY;
ALTER TABLE maintenance_work_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE environmental_sensors ENABLE ROW LEVEL SECURITY;
ALTER TABLE environmental_readings ENABLE ROW LEVEL SECURITY;
ALTER TABLE mobile_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_masks ENABLE ROW LEVEL SECURITY;
ALTER TABLE video_export_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE elevator_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE offline_event_queues ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE offline_operation_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE backup_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_configurations ENABLE ROW LEVEL SECURITY;

-- Create application user role if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sparc_app_user') THEN
        CREATE ROLE sparc_app_user;
    END IF;
END
$$;

-- Grant necessary permissions to the application role
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sparc_app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sparc_app_user;

-- Create a function to get current tenant ID from session
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS TEXT AS $$
BEGIN
    RETURN current_setting('app.tenant_id', true);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create a function to check if user is a super admin
CREATE OR REPLACE FUNCTION is_super_admin() RETURNS BOOLEAN AS $$
BEGIN
    RETURN current_setting('app.is_super_admin', true) = 'true';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Drop existing policies if they exist (for idempotency)
DO $$
DECLARE
    pol RECORD;
BEGIN
    FOR pol IN 
        SELECT schemaname, tablename, policyname 
        FROM pg_policies 
        WHERE schemaname = 'public'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', pol.policyname, pol.schemaname, pol.tablename);
    END LOOP;
END
$$;

-- Tenant table policies
-- Super admins can see all tenants, regular users only their own
CREATE POLICY tenant_select_policy ON tenants
    FOR SELECT
    USING (is_super_admin() OR id = current_tenant_id());

CREATE POLICY tenant_insert_policy ON tenants
    FOR INSERT
    WITH CHECK (is_super_admin());

CREATE POLICY tenant_update_policy ON tenants
    FOR UPDATE
    USING (is_super_admin() OR id = current_tenant_id())
    WITH CHECK (is_super_admin() OR id = current_tenant_id());

CREATE POLICY tenant_delete_policy ON tenants
    FOR DELETE
    USING (is_super_admin());

-- Organizations policies
CREATE POLICY org_select_policy ON organizations
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY org_insert_policy ON organizations
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY org_update_policy ON organizations
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY org_delete_policy ON organizations
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Sites policies
CREATE POLICY site_select_policy ON sites
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY site_insert_policy ON sites
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY site_update_policy ON sites
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY site_delete_policy ON sites
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Users policies
CREATE POLICY user_select_policy ON users
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY user_insert_policy ON users
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY user_update_policy ON users
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY user_delete_policy ON users
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Buildings policies (indirect tenant relationship through site)
CREATE POLICY building_select_policy ON buildings
    FOR SELECT
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM sites 
            WHERE sites.id = buildings.site_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY building_insert_policy ON buildings
    FOR INSERT
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM sites 
            WHERE sites.id = buildings.site_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY building_update_policy ON buildings
    FOR UPDATE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM sites 
            WHERE sites.id = buildings.site_id 
            AND sites.tenant_id = current_tenant_id()
        )
    )
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM sites 
            WHERE sites.id = buildings.site_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY building_delete_policy ON buildings
    FOR DELETE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM sites 
            WHERE sites.id = buildings.site_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

-- Floors policies (indirect tenant relationship through building->site)
CREATE POLICY floor_select_policy ON floors
    FOR SELECT
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM buildings 
            JOIN sites ON sites.id = buildings.site_id
            WHERE buildings.id = floors.building_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY floor_insert_policy ON floors
    FOR INSERT
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM buildings 
            JOIN sites ON sites.id = buildings.site_id
            WHERE buildings.id = floors.building_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY floor_update_policy ON floors
    FOR UPDATE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM buildings 
            JOIN sites ON sites.id = buildings.site_id
            WHERE buildings.id = floors.building_id 
            AND sites.tenant_id = current_tenant_id()
        )
    )
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM buildings 
            JOIN sites ON sites.id = buildings.site_id
            WHERE buildings.id = floors.building_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY floor_delete_policy ON floors
    FOR DELETE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM buildings 
            JOIN sites ON sites.id = buildings.site_id
            WHERE buildings.id = floors.building_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

-- Zones policies (indirect tenant relationship through floor->building->site)
CREATE POLICY zone_select_policy ON zones
    FOR SELECT
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = zones.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY zone_insert_policy ON zones
    FOR INSERT
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = zones.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY zone_update_policy ON zones
    FOR UPDATE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = zones.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    )
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = zones.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY zone_delete_policy ON zones
    FOR DELETE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = zones.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

-- Doors policies (indirect tenant relationship)
CREATE POLICY door_select_policy ON doors
    FOR SELECT
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = doors.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY door_insert_policy ON doors
    FOR INSERT
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = doors.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY door_update_policy ON doors
    FOR UPDATE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = doors.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    )
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = doors.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY door_delete_policy ON doors
    FOR DELETE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = doors.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

-- Cameras policies (indirect tenant relationship)
CREATE POLICY camera_select_policy ON cameras
    FOR SELECT
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = cameras.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY camera_insert_policy ON cameras
    FOR INSERT
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = cameras.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY camera_update_policy ON cameras
    FOR UPDATE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = cameras.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    )
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = cameras.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY camera_delete_policy ON cameras
    FOR DELETE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM floors
            JOIN buildings ON buildings.id = floors.building_id
            JOIN sites ON sites.id = buildings.site_id
            WHERE floors.id = cameras.floor_id 
            AND sites.tenant_id = current_tenant_id()
        )
    );

-- Direct tenant_id tables - Apply consistent policies
-- These tables have direct tenant_id columns

-- Access Events
CREATE POLICY access_event_select_policy ON access_events
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_event_insert_policy ON access_events
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_event_update_policy ON access_events
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_event_delete_policy ON access_events
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Access Panels
CREATE POLICY access_panel_select_policy ON access_panels
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_panel_insert_policy ON access_panels
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_panel_update_policy ON access_panels
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_panel_delete_policy ON access_panels
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Card Readers (indirect through access panels)
CREATE POLICY card_reader_select_policy ON card_readers
    FOR SELECT
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM access_panels 
            WHERE access_panels.id = card_readers.panel_id 
            AND access_panels.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY card_reader_insert_policy ON card_readers
    FOR INSERT
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM access_panels 
            WHERE access_panels.id = card_readers.panel_id 
            AND access_panels.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY card_reader_update_policy ON card_readers
    FOR UPDATE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM access_panels 
            WHERE access_panels.id = card_readers.panel_id 
            AND access_panels.tenant_id = current_tenant_id()
        )
    )
    WITH CHECK (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM access_panels 
            WHERE access_panels.id = card_readers.panel_id 
            AND access_panels.tenant_id = current_tenant_id()
        )
    );

CREATE POLICY card_reader_delete_policy ON card_readers
    FOR DELETE
    USING (
        is_super_admin() OR 
        EXISTS (
            SELECT 1 FROM access_panels 
            WHERE access_panels.id = card_readers.panel_id 
            AND access_panels.tenant_id = current_tenant_id()
        )
    );

-- Apply same pattern to all remaining tables with tenant_id
-- Credentials
CREATE POLICY credential_select_policy ON credentials
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY credential_insert_policy ON credentials
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY credential_update_policy ON credentials
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY credential_delete_policy ON credentials
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Access Groups
CREATE POLICY access_group_select_policy ON access_groups
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_group_insert_policy ON access_groups
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_group_update_policy ON access_groups
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY access_group_delete_policy ON access_groups
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Schedules
CREATE POLICY schedule_select_policy ON schedules
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY schedule_insert_policy ON schedules
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY schedule_update_policy ON schedules
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY schedule_delete_policy ON schedules
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Alerts
CREATE POLICY alert_select_policy ON alerts
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY alert_insert_policy ON alerts
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY alert_update_policy ON alerts
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY alert_delete_policy ON alerts
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Audit Logs (read-only for non-super admins)
CREATE POLICY audit_log_select_policy ON audit_logs
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY audit_log_insert_policy ON audit_logs
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

-- No update/delete policies for audit logs (immutable)

-- Video Recordings
CREATE POLICY video_recording_select_policy ON video_recordings
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY video_recording_insert_policy ON video_recordings
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY video_recording_update_policy ON video_recordings
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY video_recording_delete_policy ON video_recordings
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Visitors
CREATE POLICY visitor_select_policy ON visitors
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY visitor_insert_policy ON visitors
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY visitor_update_policy ON visitors
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY visitor_delete_policy ON visitors
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Maintenance Work Orders
CREATE POLICY maintenance_select_policy ON maintenance_work_orders
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY maintenance_insert_policy ON maintenance_work_orders
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY maintenance_update_policy ON maintenance_work_orders
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY maintenance_delete_policy ON maintenance_work_orders
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Incident Reports
CREATE POLICY incident_select_policy ON incident_reports
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY incident_insert_policy ON incident_reports
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY incident_update_policy ON incident_reports
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY incident_delete_policy ON incident_reports
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Environmental Sensors
CREATE POLICY env_sensor_select_policy ON environmental_sensors
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY env_sensor_insert_policy ON environmental_sensors
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY env_sensor_update_policy ON environmental_sensors
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY env_sensor_delete_policy ON environmental_sensors
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Environmental Readings
CREATE POLICY env_reading_select_policy ON environmental_readings
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY env_reading_insert_policy ON environmental_readings
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY env_reading_update_policy ON environmental_readings
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY env_reading_delete_policy ON environmental_readings
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Mobile Credentials
CREATE POLICY mobile_cred_select_policy ON mobile_credentials
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY mobile_cred_insert_policy ON mobile_credentials
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY mobile_cred_update_policy ON mobile_credentials
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY mobile_cred_delete_policy ON mobile_credentials
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Privacy Masks
CREATE POLICY privacy_mask_select_policy ON privacy_masks
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY privacy_mask_insert_policy ON privacy_masks
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY privacy_mask_update_policy ON privacy_masks
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY privacy_mask_delete_policy ON privacy_masks
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Video Export Logs
CREATE POLICY video_export_select_policy ON video_export_logs
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY video_export_insert_policy ON video_export_logs
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY video_export_update_policy ON video_export_logs
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY video_export_delete_policy ON video_export_logs
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Elevator Controls
CREATE POLICY elevator_select_policy ON elevator_controls
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY elevator_insert_policy ON elevator_controls
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY elevator_update_policy ON elevator_controls
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY elevator_delete_policy ON elevator_controls
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- System Configurations
CREATE POLICY sys_config_select_policy ON system_configurations
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY sys_config_insert_policy ON system_configurations
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY sys_config_update_policy ON system_configurations
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY sys_config_delete_policy ON system_configurations
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Offline Event Queues
CREATE POLICY offline_event_select_policy ON offline_event_queues
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY offline_event_insert_policy ON offline_event_queues
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY offline_event_update_policy ON offline_event_queues
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY offline_event_delete_policy ON offline_event_queues
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Policy Templates
CREATE POLICY policy_template_select_policy ON policy_templates
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY policy_template_insert_policy ON policy_templates
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY policy_template_update_policy ON policy_templates
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY policy_template_delete_policy ON policy_templates
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Offline Operation Logs
CREATE POLICY offline_op_select_policy ON offline_operation_logs
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY offline_op_insert_policy ON offline_operation_logs
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY offline_op_update_policy ON offline_operation_logs
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY offline_op_delete_policy ON offline_operation_logs
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Certificates
CREATE POLICY certificate_select_policy ON certificates
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY certificate_insert_policy ON certificates
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY certificate_update_policy ON certificates
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY certificate_delete_policy ON certificates
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Backup Jobs
CREATE POLICY backup_select_policy ON backup_jobs
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY backup_insert_policy ON backup_jobs
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY backup_update_policy ON backup_jobs
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY backup_delete_policy ON backup_jobs
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Integration Configurations
CREATE POLICY integration_select_policy ON integration_configurations
    FOR SELECT
    USING (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY integration_insert_policy ON integration_configurations
    FOR INSERT
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY integration_update_policy ON integration_configurations
    FOR UPDATE
    USING (is_super_admin() OR tenant_id = current_tenant_id())
    WITH CHECK (is_super_admin() OR tenant_id = current_tenant_id());

CREATE POLICY integration_delete_policy ON integration_configurations
    FOR DELETE
    USING (is_super_admin() OR tenant_id = current_tenant_id());

-- Create indexes to optimize RLS queries
CREATE INDEX IF NOT EXISTS idx_organizations_tenant_id ON organizations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sites_tenant_id ON sites(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_access_events_tenant_id ON access_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_credentials_tenant_id ON credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_access_groups_tenant_id ON access_groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_schedules_tenant_id ON schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_id ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_video_recordings_tenant_id ON video_recordings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_visitors_tenant_id ON visitors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_maintenance_tenant_id ON maintenance_work_orders(tenant_id);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_id ON incident_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_env_sensors_tenant_id ON environmental_sensors(tenant_id);
CREATE INDEX IF NOT EXISTS idx_env_readings_tenant_id ON environmental_readings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mobile_creds_tenant_id ON mobile_credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_privacy_masks_tenant_id ON privacy_masks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_video_exports_tenant_id ON video_export_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_elevators_tenant_id ON elevator_controls(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sys_config_tenant_id ON system_configurations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_offline_events_tenant_id ON offline_event_queues(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policy_templates_tenant_id ON policy_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_offline_ops_tenant_id ON offline_operation_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_certificates_tenant_id ON certificates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_backups_tenant_id ON backup_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_integrations_tenant_id ON integration_configurations(tenant_id);

-- Add comment to track RLS implementation
COMMENT ON SCHEMA public IS 'Row Level Security enabled on all tables for tenant isolation';