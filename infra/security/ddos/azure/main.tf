# Azure DDoS Protection Module for SPARC Platform

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

# Variables
variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "sparc"
}

variable "enable_standard_protection" {
  description = "Enable DDoS Protection Standard (has cost implications)"
  type        = bool
  default     = false
}

variable "protected_public_ips" {
  description = "List of public IP resource IDs to protect"
  type        = list(string)
  default     = []
}

variable "protected_vnets" {
  description = "List of VNet configurations to protect"
  type = list(object({
    id                = string
    name              = string
    resource_group    = string
  }))
  default = []
}

variable "alert_email_addresses" {
  description = "Email addresses for DDoS alerts"
  type        = list(string)
  default     = []
}

variable "mitigation_policy" {
  description = "DDoS mitigation policy settings"
  type = object({
    tcp_syn_flood_threshold     = number
    udp_flood_threshold        = number
    icmp_flood_threshold       = number
    dns_query_flood_threshold  = number
  })
  default = {
    tcp_syn_flood_threshold    = 2000
    udp_flood_threshold        = 5000
    icmp_flood_threshold       = 1000
    dns_query_flood_threshold  = 500
  }
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Local variables
locals {
  name = "${var.name_prefix}-ddos-${var.environment}"
  common_tags = merge(var.tags, {
    Environment = var.environment
    Service     = "sparc-ddos-protection"
    ManagedBy   = "terraform"
  })
}

# DDoS Protection Plan (Standard tier)
resource "azurerm_network_ddos_protection_plan" "main" {
  count = var.enable_standard_protection ? 1 : 0

  name                = "${local.name}-plan"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = local.common_tags
}

# Associate VNets with DDoS Protection Plan
resource "azurerm_virtual_network_ddos_protection_plan" "vnets" {
  for_each = var.enable_standard_protection ? { for vnet in var.protected_vnets : vnet.name => vnet } : {}

  virtual_network_id       = each.value.id
  ddos_protection_plan_id = azurerm_network_ddos_protection_plan.main[0].id
}

# Log Analytics Workspace for DDoS logs
resource "azurerm_log_analytics_workspace" "ddos" {
  name                = "${local.name}-logs"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.environment == "prod" ? 90 : 30

  tags = local.common_tags
}

# Action Group for DDoS Alerts
resource "azurerm_monitor_action_group" "ddos_alerts" {
  name                = "${local.name}-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DDOSAlert"

  dynamic "email_receiver" {
    for_each = var.alert_email_addresses
    content {
      name          = "email-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }

  webhook_receiver {
    name        = "sparc-ddos-webhook"
    service_uri = var.webhook_url
  }

  tags = local.common_tags
}

# DDoS Protection Metrics Alerts
resource "azurerm_monitor_metric_alert" "ddos_attack_detected" {
  name                = "${local.name}-attack-detected"
  resource_group_name = var.resource_group_name
  scopes              = var.protected_public_ips
  description         = "Alert when DDoS attack is detected"
  severity            = 0
  frequency           = "PT1M"
  window_size         = "PT5M"

  criteria {
    metric_namespace = "Microsoft.Network/publicIPAddresses"
    metric_name      = "IfUnderDDoSAttack"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = 0
  }

  action {
    action_group_id = azurerm_monitor_action_group.ddos_alerts.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "ddos_mitigation_triggered" {
  name                = "${local.name}-mitigation-triggered"
  resource_group_name = var.resource_group_name
  scopes              = var.protected_public_ips
  description         = "Alert when DDoS mitigation is triggered"
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"

  criteria {
    metric_namespace = "Microsoft.Network/publicIPAddresses"
    metric_name      = "DDoSTriggerTCPPackets"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = var.mitigation_policy.tcp_syn_flood_threshold
  }

  action {
    action_group_id = azurerm_monitor_action_group.ddos_alerts.id
  }

  tags = local.common_tags
}

# Additional metric alerts for different attack vectors
resource "azurerm_monitor_metric_alert" "tcp_syn_flood" {
  name                = "${local.name}-tcp-syn-flood"
  resource_group_name = var.resource_group_name
  scopes              = var.protected_public_ips
  description         = "TCP SYN flood attack detected"
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"

  criteria {
    metric_namespace = "Microsoft.Network/publicIPAddresses"
    metric_name      = "PacketsInDDoS"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = var.mitigation_policy.tcp_syn_flood_threshold

    dimension {
      name     = "Protocol"
      operator = "Include"
      values   = ["TCP"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.ddos_alerts.id
  }

  tags = local.common_tags
}

resource "azurerm_monitor_metric_alert" "udp_flood" {
  name                = "${local.name}-udp-flood"
  resource_group_name = var.resource_group_name
  scopes              = var.protected_public_ips
  description         = "UDP flood attack detected"
  severity            = 1
  frequency           = "PT1M"
  window_size         = "PT5M"

  criteria {
    metric_namespace = "Microsoft.Network/publicIPAddresses"
    metric_name      = "PacketsInDDoS"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = var.mitigation_policy.udp_flood_threshold

    dimension {
      name     = "Protocol"
      operator = "Include"
      values   = ["UDP"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.ddos_alerts.id
  }

  tags = local.common_tags
}

# Diagnostic Settings for DDoS Protection
resource "azurerm_monitor_diagnostic_setting" "ddos_plan" {
  count = var.enable_standard_protection ? 1 : 0

  name                       = "${local.name}-diagnostics"
  target_resource_id         = azurerm_network_ddos_protection_plan.main[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.ddos.id

  enabled_log {
    category = "DDoSProtectionNotifications"
  }

  enabled_log {
    category = "DDoSMitigationFlowLogs"
  }

  enabled_log {
    category = "DDoSMitigationReports"
  }

  metric {
    category = "AllMetrics"
  }
}

# Azure Automation Account for DDoS Response
resource "azurerm_automation_account" "ddos_response" {
  name                = "${local.name}-automation"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "Basic"

  tags = local.common_tags
}

# Runbook for automated DDoS response
resource "azurerm_automation_runbook" "ddos_mitigation" {
  name                    = "${local.name}-mitigation"
  location                = var.location
  resource_group_name     = var.resource_group_name
  automation_account_name = azurerm_automation_account.ddos_response.name
  log_verbose             = true
  log_progress            = true
  description             = "Automated DDoS mitigation runbook"
  runbook_type            = "PowerShell"

  content = file("${path.module}/runbooks/ddos_mitigation.ps1")

  tags = local.common_tags
}

# Azure Monitor Workbook for DDoS Visualization
resource "azurerm_application_insights_workbook" "ddos_dashboard" {
  name                = "${local.name}-dashboard"
  location            = var.location
  resource_group_name = var.resource_group_name
  display_name        = "SPARC DDoS Protection Dashboard"
  
  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 1
        content = {
          json = "# SPARC DDoS Protection Dashboard\n\nMonitoring DDoS attacks and mitigation for ${var.environment} environment"
        }
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query = <<-EOT
            AzureMetrics
            | where MetricName == "IfUnderDDoSAttack"
            | summarize AttackStatus = max(Maximum) by bin(TimeGenerated, 5m), Resource
            | render timechart
          EOT
          size = 0
          title = "DDoS Attack Status"
          timeContext = {
            durationMs = 3600000
          }
          queryType = 0
          resourceType = "microsoft.operationalinsights/workspaces"
        }
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query = <<-EOT
            AzureMetrics
            | where MetricName in ("PacketsInDDoS", "PacketsDroppedDDoS", "PacketsForwardedDDoS")
            | summarize sum(Maximum) by bin(TimeGenerated, 1m), MetricName
            | render columnchart
          EOT
          size = 0
          title = "DDoS Traffic Analysis"
          timeContext = {
            durationMs = 3600000
          }
          queryType = 0
          resourceType = "microsoft.operationalinsights/workspaces"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Network Watcher Flow Logs for DDoS analysis
resource "azurerm_network_watcher_flow_log" "ddos" {
  for_each = { for vnet in var.protected_vnets : vnet.name => vnet }

  network_watcher_name = "NetworkWatcher_${var.location}"
  resource_group_name  = "NetworkWatcherRG"
  name                 = "${local.name}-${each.key}-flowlog"

  network_security_group_id = each.value.id
  storage_account_id        = var.storage_account_id
  enabled                   = true
  version                   = 2

  retention_policy {
    enabled = true
    days    = var.environment == "prod" ? 90 : 30
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.ddos.workspace_id
    workspace_region      = var.location
    workspace_resource_id = azurerm_log_analytics_workspace.ddos.id
    interval_in_minutes   = 10
  }

  tags = local.common_tags
}

# Application-level DDoS protection using Front Door
resource "azurerm_cdn_frontdoor_security_policy" "ddos" {
  count = var.enable_application_ddos ? 1 : 0

  name                     = "${local.name}-security-policy"
  cdn_frontdoor_profile_id = var.frontdoor_profile_id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.ddos[0].id

      association {
        domain {
          cdn_frontdoor_domain_id = var.frontdoor_domain_id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}

resource "azurerm_cdn_frontdoor_firewall_policy" "ddos" {
  count = var.enable_application_ddos ? 1 : 0

  name                              = "${local.name}-waf-policy"
  resource_group_name               = var.resource_group_name
  sku_name                          = var.frontdoor_sku
  enabled                           = true
  mode                              = "Prevention"
  custom_block_response_status_code = 429
  custom_block_response_body        = base64encode(jsonencode({
    error = "Too Many Requests"
    message = "Rate limit exceeded. Please try again later."
  }))

  # Rate limiting rule
  custom_rule {
    name                           = "RateLimitRule"
    enabled                        = true
    priority                       = 1
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = 100
    type                           = "RateLimitRule"
    action                         = "Block"

    match_condition {
      match_variable     = "RemoteAddr"
      operator           = "IPMatch"
      negation_condition = false
      match_values       = ["0.0.0.0/0"]
    }
  }

  # Geo-blocking rule
  custom_rule {
    name     = "GeoBlockRule"
    enabled  = true
    priority = 2
    type     = "MatchRule"
    action   = "Block"

    match_condition {
      match_variable     = "RemoteAddr"
      operator           = "GeoMatch"
      negation_condition = false
      match_values       = var.blocked_countries
    }
  }

  tags = local.common_tags
}

# Outputs
output "ddos_protection_plan_id" {
  description = "ID of the DDoS Protection Plan"
  value       = var.enable_standard_protection ? azurerm_network_ddos_protection_plan.main[0].id : null
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace for DDoS logs"
  value       = azurerm_log_analytics_workspace.ddos.id
}

output "action_group_id" {
  description = "ID of the action group for DDoS alerts"
  value       = azurerm_monitor_action_group.ddos_alerts.id
}

output "automation_account_name" {
  description = "Name of the automation account for DDoS response"
  value       = azurerm_automation_account.ddos_response.name
}

output "workbook_id" {
  description = "ID of the DDoS monitoring workbook"
  value       = azurerm_application_insights_workbook.ddos_dashboard.id
}

# Additional variables
variable "webhook_url" {
  description = "Webhook URL for DDoS alerts"
  type        = string
  default     = ""
}

variable "storage_account_id" {
  description = "Storage account ID for flow logs"
  type        = string
  default     = ""
}

variable "enable_application_ddos" {
  description = "Enable application-level DDoS protection"
  type        = bool
  default     = false
}

variable "frontdoor_profile_id" {
  description = "Front Door profile ID"
  type        = string
  default     = ""
}

variable "frontdoor_domain_id" {
  description = "Front Door domain ID"
  type        = string
  default     = ""
}

variable "frontdoor_sku" {
  description = "Front Door SKU"
  type        = string
  default     = "Premium_AzureFrontDoor"
}

variable "blocked_countries" {
  description = "List of country codes to block"
  type        = list(string)
  default     = []
}