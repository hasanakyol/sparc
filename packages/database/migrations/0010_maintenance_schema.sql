-- Maintenance Service Schema Migration

-- Create enum types
CREATE TYPE work_order_type AS ENUM ('corrective', 'preventive', 'predictive', 'emergency');
CREATE TYPE work_order_status AS ENUM ('open', 'assigned', 'in_progress', 'on_hold', 'completed', 'cancelled');
CREATE TYPE work_order_priority AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE maintenance_frequency AS ENUM ('daily', 'weekly', 'monthly', 'quarterly', 'semi_annual', 'annual', 'custom');
CREATE TYPE maintenance_scope AS ENUM ('device_specific', 'device_type', 'all_devices');
CREATE TYPE part_category AS ENUM ('spare_parts', 'consumables', 'tools', 'safety_equipment', 'camera_parts', 'sensor_parts', 'network_equipment', 'other');
CREATE TYPE diagnostic_status AS ENUM ('pass', 'warning', 'fail');
CREATE TYPE iot_metric_type AS ENUM ('temperature', 'humidity', 'vibration', 'power_consumption', 'network_latency', 'cpu_usage', 'memory_usage', 'disk_usage', 'custom');

-- Work Orders table
CREATE TABLE IF NOT EXISTS work_orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES organizations(id),
  title VARCHAR(255) NOT NULL,
  description TEXT,
  device_id UUID REFERENCES devices(id),
  device_type VARCHAR(100),
  work_order_type work_order_type NOT NULL,
  priority work_order_priority NOT NULL DEFAULT 'medium',
  status work_order_status NOT NULL DEFAULT 'open',
  
  -- Assignment
  assigned_to UUID REFERENCES users(id),
  assigned_date TIMESTAMPTZ,
  
  -- Scheduling
  scheduled_date TIMESTAMPTZ,
  due_date TIMESTAMPTZ,
  estimated_hours DECIMAL(5,2),
  
  -- Completion
  completed_date TIMESTAMPTZ,
  completed_by UUID REFERENCES users(id),
  actual_hours DECIMAL(5,2),
  labor_hours DECIMAL(5,2),
  
  -- Details
  resolution_notes TEXT,
  failure_analysis TEXT,
  parts_cost DECIMAL(10,2),
  labor_cost DECIMAL(10,2),
  other_costs DECIMAL(10,2),
  total_cost DECIMAL(10,2) GENERATED ALWAYS AS (COALESCE(parts_cost, 0) + COALESCE(labor_cost, 0) + COALESCE(other_costs, 0)) STORED,
  
  -- References
  parent_work_order_id UUID REFERENCES work_orders(id),
  pm_schedule_id UUID,
  
  -- Metadata
  custom_fields JSONB DEFAULT '{}',
  attachments JSONB DEFAULT '[]',
  diagnostic_data JSONB,
  
  -- Tracking
  created_by UUID NOT NULL REFERENCES users(id),
  updated_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Preventive Maintenance Schedules
CREATE TABLE IF NOT EXISTS preventive_maintenance_schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES organizations(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  
  -- Schedule configuration
  frequency maintenance_frequency NOT NULL,
  custom_cron VARCHAR(100),
  start_date DATE NOT NULL,
  end_date DATE,
  
  -- Scope
  scope maintenance_scope NOT NULL,
  device_id UUID REFERENCES devices(id),
  device_type VARCHAR(100),
  device_filters JSONB DEFAULT '{}',
  
  -- Task template
  task_template JSONB NOT NULL,
  estimated_hours DECIMAL(5,2),
  required_parts JSONB DEFAULT '[]',
  
  -- Configuration
  advance_notice_days INTEGER DEFAULT 7,
  auto_assign BOOLEAN DEFAULT false,
  assigned_team_id UUID,
  assigned_user_id UUID REFERENCES users(id),
  
  -- Status
  is_active BOOLEAN DEFAULT true,
  last_generated_date TIMESTAMPTZ,
  next_due_date DATE,
  
  -- Tracking
  created_by UUID NOT NULL REFERENCES users(id),
  updated_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Parts Inventory
CREATE TABLE IF NOT EXISTS parts_inventory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES organizations(id),
  part_number VARCHAR(100) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  category part_category NOT NULL,
  
  -- Inventory levels
  quantity_on_hand INTEGER NOT NULL DEFAULT 0,
  quantity_reserved INTEGER DEFAULT 0,
  quantity_available INTEGER GENERATED ALWAYS AS (quantity_on_hand - COALESCE(quantity_reserved, 0)) STORED,
  reorder_point INTEGER,
  reorder_quantity INTEGER,
  max_stock_level INTEGER,
  
  -- Specifications
  manufacturer VARCHAR(255),
  model VARCHAR(255),
  specifications JSONB DEFAULT '{}',
  compatible_devices JSONB DEFAULT '[]',
  
  -- Costs
  unit_cost DECIMAL(10,2),
  currency VARCHAR(3) DEFAULT 'USD',
  
  -- Location
  storage_location VARCHAR(255),
  bin_number VARCHAR(50),
  
  -- Status
  is_active BOOLEAN DEFAULT true,
  is_critical BOOLEAN DEFAULT false,
  
  -- Tracking
  created_by UUID NOT NULL REFERENCES users(id),
  updated_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  CONSTRAINT unique_part_number_per_tenant UNIQUE (tenant_id, part_number)
);

-- Maintenance History
CREATE TABLE IF NOT EXISTS maintenance_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES organizations(id),
  device_id UUID REFERENCES devices(id),
  work_order_id UUID REFERENCES work_orders(id),
  
  -- Activity details
  activity_type VARCHAR(50) NOT NULL,
  description TEXT NOT NULL,
  performed_by UUID REFERENCES users(id),
  performed_date TIMESTAMPTZ DEFAULT NOW(),
  
  -- Additional data
  parts_used JSONB DEFAULT '[]',
  labor_hours DECIMAL(5,2),
  cost DECIMAL(10,2),
  
  -- Results
  findings TEXT,
  recommendations TEXT,
  next_action_date DATE,
  
  -- Metadata
  attachments JSONB DEFAULT '[]',
  metadata JSONB DEFAULT '{}',
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Device Diagnostics
CREATE TABLE IF NOT EXISTS device_diagnostics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES organizations(id),
  device_id UUID NOT NULL REFERENCES devices(id),
  device_type VARCHAR(100),
  
  -- Diagnostic run details
  run_type VARCHAR(50) NOT NULL,
  initiated_by UUID REFERENCES users(id),
  initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  
  -- Results
  overall_status diagnostic_status NOT NULL,
  results JSONB NOT NULL,
  error_codes JSONB DEFAULT '[]',
  recommendations JSONB DEFAULT '[]',
  
  -- Work order creation
  work_order_created BOOLEAN DEFAULT false,
  work_order_id UUID REFERENCES work_orders(id),
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Maintenance Costs
CREATE TABLE IF NOT EXISTS maintenance_costs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES organizations(id),
  work_order_id UUID REFERENCES work_orders(id),
  
  -- Cost breakdown
  cost_type VARCHAR(50) NOT NULL,
  category VARCHAR(100),
  description TEXT,
  
  -- Amount
  amount DECIMAL(10,2) NOT NULL,
  currency VARCHAR(3) DEFAULT 'USD',
  
  -- References
  part_id UUID REFERENCES parts_inventory(id),
  vendor_id UUID,
  invoice_number VARCHAR(100),
  
  -- Approval
  requires_approval BOOLEAN DEFAULT false,
  approved_by UUID REFERENCES users(id),
  approved_at TIMESTAMPTZ,
  
  -- Tracking
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Maintenance SLA Configuration
CREATE TABLE IF NOT EXISTS maintenance_sla_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES organizations(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  
  -- Applicability
  priority work_order_priority,
  work_order_types work_order_type[],
  device_types VARCHAR(100)[],
  
  -- Time limits (in hours)
  response_time_hours INTEGER NOT NULL,
  resolution_time_hours INTEGER NOT NULL,
  
  -- Escalation
  escalation_enabled BOOLEAN DEFAULT true,
  warning_threshold_percent INTEGER DEFAULT 80,
  escalation_contacts JSONB DEFAULT '[]',
  
  -- Status
  is_active BOOLEAN DEFAULT true,
  
  -- Tracking
  created_by UUID NOT NULL REFERENCES users(id),
  updated_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- IoT Device Metrics
CREATE TABLE IF NOT EXISTS iot_device_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id),
  metric_type iot_metric_type NOT NULL,
  
  -- Metric data
  value JSONB NOT NULL,
  unit VARCHAR(50),
  
  -- Analysis
  is_anomaly BOOLEAN DEFAULT false,
  anomaly_score DECIMAL(3,2),
  anomaly_reason TEXT,
  
  -- Context
  sensor_id VARCHAR(100),
  location VARCHAR(255),
  
  recorded_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_work_orders_tenant_status ON work_orders(tenant_id, status);
CREATE INDEX idx_work_orders_device ON work_orders(device_id);
CREATE INDEX idx_work_orders_assigned_to ON work_orders(assigned_to);
CREATE INDEX idx_work_orders_scheduled_date ON work_orders(scheduled_date);
CREATE INDEX idx_work_orders_due_date ON work_orders(due_date);
CREATE INDEX idx_work_orders_created_at ON work_orders(created_at DESC);

CREATE INDEX idx_pm_schedules_tenant_active ON preventive_maintenance_schedules(tenant_id, is_active);
CREATE INDEX idx_pm_schedules_next_due ON preventive_maintenance_schedules(next_due_date) WHERE is_active = true;

CREATE INDEX idx_parts_inventory_tenant ON parts_inventory(tenant_id);
CREATE INDEX idx_parts_inventory_low_stock ON parts_inventory(tenant_id, quantity_available) WHERE quantity_available <= reorder_point;

CREATE INDEX idx_maintenance_history_device ON maintenance_history(device_id);
CREATE INDEX idx_maintenance_history_work_order ON maintenance_history(work_order_id);
CREATE INDEX idx_maintenance_history_date ON maintenance_history(performed_date DESC);

CREATE INDEX idx_device_diagnostics_device ON device_diagnostics(device_id);
CREATE INDEX idx_device_diagnostics_status ON device_diagnostics(overall_status);
CREATE INDEX idx_device_diagnostics_created ON device_diagnostics(created_at DESC);

CREATE INDEX idx_maintenance_costs_work_order ON maintenance_costs(work_order_id);
CREATE INDEX idx_maintenance_costs_created ON maintenance_costs(created_at DESC);

CREATE INDEX idx_sla_config_tenant_active ON maintenance_sla_config(tenant_id, is_active);

CREATE INDEX idx_iot_metrics_device_time ON iot_device_metrics(device_id, recorded_at DESC);
CREATE INDEX idx_iot_metrics_anomalies ON iot_device_metrics(device_id, is_anomaly) WHERE is_anomaly = true;

-- Create triggers for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_work_orders_updated_at BEFORE UPDATE ON work_orders FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_pm_schedules_updated_at BEFORE UPDATE ON preventive_maintenance_schedules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_parts_inventory_updated_at BEFORE UPDATE ON parts_inventory FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sla_config_updated_at BEFORE UPDATE ON maintenance_sla_config FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();