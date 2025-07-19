# Azure Application Gateway WAF Module for SPARC Platform

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

variable "subnet_id" {
  description = "Subnet ID for Application Gateway"
  type        = string
}

variable "public_ip_id" {
  description = "Public IP ID for Application Gateway"
  type        = string
}

variable "backend_pool_fqdns" {
  description = "List of backend FQDNs"
  type        = list(string)
  default     = []
}

variable "backend_pool_ip_addresses" {
  description = "List of backend IP addresses"
  type        = list(string)
  default     = []
}

variable "enable_owasp_rules" {
  description = "Enable OWASP Core Rule Set"
  type        = bool
  default     = true
}

variable "owasp_rule_set_version" {
  description = "OWASP rule set version"
  type        = string
  default     = "3.2"
}

variable "waf_mode" {
  description = "WAF mode (Detection or Prevention)"
  type        = string
  default     = "Prevention"
}

variable "max_request_body_size_kb" {
  description = "Maximum request body size in KB"
  type        = number
  default     = 128
}

variable "file_upload_limit_mb" {
  description = "File upload limit in MB"
  type        = number
  default     = 100
}

variable "custom_rules" {
  description = "Custom WAF rules"
  type = list(object({
    name      = string
    priority  = number
    rule_type = string
    action    = string
    match_conditions = list(object({
      match_variable     = string
      selector          = string
      operator          = string
      negation_condition = bool
      match_values      = list(string)
      transforms        = list(string)
    }))
  }))
  default = []
}

variable "ssl_certificates" {
  description = "SSL certificates for HTTPS listeners"
  type = list(object({
    name                = string
    data                = string
    password            = string
    key_vault_secret_id = string
  }))
  default = []
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Local variables
locals {
  name = "${var.name_prefix}-appgw-${var.environment}"
  common_tags = merge(var.tags, {
    Environment = var.environment
    Service     = "sparc-waf"
    ManagedBy   = "terraform"
  })
}

# WAF Policy
resource "azurerm_web_application_firewall_policy" "main" {
  name                = "${local.name}-policy"
  resource_group_name = var.resource_group_name
  location            = var.location

  policy_settings {
    enabled                     = true
    mode                        = var.waf_mode
    request_body_check          = true
    file_upload_limit_in_mb     = var.file_upload_limit_mb
    max_request_body_size_in_kb = var.max_request_body_size_kb
  }

  # OWASP Core Rule Set
  dynamic "managed_rules" {
    for_each = var.enable_owasp_rules ? [1] : []
    content {
      managed_rule_set {
        type    = "OWASP"
        version = var.owasp_rule_set_version

        # Disable rules that may cause false positives for SPARC
        rule_group_override {
          rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
          rule {
            id      = "920300"
            enabled = false
          }
        }

        rule_group_override {
          rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
          rule {
            id      = "942430"
            enabled = true
            action  = "Block"
          }
        }
      }

      # Microsoft Default Rule Set
      managed_rule_set {
        type    = "Microsoft_DefaultRuleSet"
        version = "2.1"
      }

      # Bot Protection
      managed_rule_set {
        type    = "Microsoft_BotManagerRuleSet"
        version = "1.0"
      }
    }
  }

  # Custom Rules for SPARC-specific threats
  custom_rules {
    name      = "BlockSuspiciousVideoStreamRequests"
    priority  = 1
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }
      operator           = "Contains"
      negation_condition = false
      match_values       = ["/stream/", "/video/"]
      transforms         = ["Lowercase"]
    }

    match_conditions {
      match_variables {
        variable_name = "QueryString"
      }
      operator           = "RegEx"
      negation_condition = false
      match_values       = ["(script|javascript|onerror|onload)"]
      transforms         = ["Lowercase", "UrlDecode"]
    }
  }

  custom_rules {
    name      = "RateLimitPerIP"
    priority  = 2
    rule_type = "RateLimitRule"
    action    = "Block"
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = 100

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      negation_condition = true
      match_values       = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]  # Don't rate limit internal IPs
    }
  }

  custom_rules {
    name      = "BlockSQLInjection"
    priority  = 3
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "QueryString"
      }
      operator           = "RegEx"
      negation_condition = false
      match_values = [
        "(union.*select|select.*from|insert.*into|delete.*from|drop.*table|exec.*xp_)",
        "(script.*src|javascript:|onerror=|onload=|eval\\(|expression\\()"
      ]
      transforms = ["Lowercase", "UrlDecode", "HtmlEntityDecode"]
    }
  }

  custom_rules {
    name      = "BlockPathTraversal"
    priority  = 4
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }
      operator           = "RegEx"
      negation_condition = false
      match_values       = ["(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%252e%252e%252f)"]
      transforms         = ["Lowercase", "UrlDecode"]
    }
  }

  custom_rules {
    name      = "GeoBlockingRule"
    priority  = 5
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "GeoMatch"
      negation_condition = false
      match_values       = ["CN", "RU", "KP"]  # Example blocked countries
    }
  }

  # Enhanced rate limiting for sensitive endpoints
  custom_rules {
    name      = "RateLimitAuthEndpoints"
    priority  = 10
    rule_type = "RateLimitRule"
    action    = "Block"
    rate_limit_duration_in_minutes = 5
    rate_limit_threshold           = 10

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }
      operator           = "Contains"
      negation_condition = false
      match_values       = ["/api/auth/", "/api/login/"]
      transforms         = ["Lowercase"]
    }
  }

  # Additional custom rules from variable
  dynamic "custom_rules" {
    for_each = var.custom_rules
    content {
      name      = custom_rules.value.name
      priority  = custom_rules.value.priority
      rule_type = custom_rules.value.rule_type
      action    = custom_rules.value.action

      dynamic "match_conditions" {
        for_each = custom_rules.value.match_conditions
        content {
          match_variables {
            variable_name = match_conditions.value.match_variable
            selector      = match_conditions.value.selector
          }
          operator           = match_conditions.value.operator
          negation_condition = match_conditions.value.negation_condition
          match_values       = match_conditions.value.match_values
          transforms         = match_conditions.value.transforms
        }
      }
    }
  }

  tags = local.common_tags
}

# Application Gateway
resource "azurerm_application_gateway" "main" {
  name                = local.name
  resource_group_name = var.resource_group_name
  location            = var.location

  sku {
    name     = "WAF_v2"
    tier     = "WAF_v2"
    capacity = var.environment == "prod" ? 2 : 1
  }

  gateway_ip_configuration {
    name      = "gateway-ip-config"
    subnet_id = var.subnet_id
  }

  frontend_port {
    name = "http-port"
    port = 80
  }

  frontend_port {
    name = "https-port"
    port = 443
  }

  frontend_ip_configuration {
    name                 = "frontend-ip"
    public_ip_address_id = var.public_ip_id
  }

  backend_address_pool {
    name         = "sparc-backend-pool"
    fqdns        = var.backend_pool_fqdns
    ip_addresses = var.backend_pool_ip_addresses
  }

  backend_http_settings {
    name                  = "sparc-http-settings"
    cookie_based_affinity = "Enabled"
    port                  = 80
    protocol              = "Http"
    request_timeout       = 30
    probe_name            = "sparc-health-probe"

    connection_draining {
      enabled           = true
      drain_timeout_sec = 60
    }
  }

  backend_http_settings {
    name                  = "sparc-https-settings"
    cookie_based_affinity = "Enabled"
    port                  = 443
    protocol              = "Https"
    request_timeout       = 30
    probe_name            = "sparc-health-probe"
    pick_host_name_from_backend_address = true

    connection_draining {
      enabled           = true
      drain_timeout_sec = 60
    }
  }

  # Health probe
  probe {
    name                = "sparc-health-probe"
    protocol            = "Http"
    path                = "/health"
    host                = "127.0.0.1"
    interval            = 30
    timeout             = 30
    unhealthy_threshold = 3

    match {
      status_code = ["200-399"]
    }
  }

  # HTTP Listener
  http_listener {
    name                           = "http-listener"
    frontend_ip_configuration_name = "frontend-ip"
    frontend_port_name             = "http-port"
    protocol                       = "Http"
  }

  # HTTPS Listeners
  dynamic "http_listener" {
    for_each = var.ssl_certificates
    content {
      name                           = "https-listener-${http_listener.value.name}"
      frontend_ip_configuration_name = "frontend-ip"
      frontend_port_name             = "https-port"
      protocol                       = "Https"
      ssl_certificate_name           = http_listener.value.name
    }
  }

  # SSL Certificates
  dynamic "ssl_certificate" {
    for_each = var.ssl_certificates
    content {
      name                = ssl_certificate.value.name
      data                = ssl_certificate.value.data
      password            = ssl_certificate.value.password
      key_vault_secret_id = ssl_certificate.value.key_vault_secret_id
    }
  }

  # Redirect HTTP to HTTPS
  redirect_configuration {
    name                 = "http-to-https"
    redirect_type        = "Permanent"
    target_listener_name = length(var.ssl_certificates) > 0 ? "https-listener-${var.ssl_certificates[0].name}" : null
    include_path         = true
    include_query_string = true
  }

  # Request routing rules
  request_routing_rule {
    name                        = "http-to-https-rule"
    priority                    = 100
    rule_type                   = "Basic"
    http_listener_name          = "http-listener"
    redirect_configuration_name = "http-to-https"
  }

  dynamic "request_routing_rule" {
    for_each = var.ssl_certificates
    content {
      name                       = "https-rule-${request_routing_rule.value.name}"
      priority                   = 200 + request_routing_rule.key
      rule_type                  = "Basic"
      http_listener_name         = "https-listener-${request_routing_rule.value.name}"
      backend_address_pool_name  = "sparc-backend-pool"
      backend_http_settings_name = "sparc-https-settings"
    }
  }

  # WAF configuration
  waf_configuration {
    enabled                  = true
    firewall_mode            = var.waf_mode
    rule_set_type            = "OWASP"
    rule_set_version         = var.owasp_rule_set_version
    file_upload_limit_mb     = var.file_upload_limit_mb
    request_body_check       = true
    max_request_body_size_kb = var.max_request_body_size_kb

    # Disable specific rules that may cause false positives
    disabled_rule_group {
      rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
      rules           = ["920300"]
    }
  }

  firewall_policy_id = azurerm_web_application_firewall_policy.main.id

  enable_http2 = true

  autoscale_configuration {
    min_capacity = var.environment == "prod" ? 2 : 1
    max_capacity = var.environment == "prod" ? 10 : 3
  }

  tags = local.common_tags
}

# Diagnostic Settings
resource "azurerm_monitor_diagnostic_setting" "appgw" {
  name                       = "${local.name}-diagnostics"
  target_resource_id         = azurerm_application_gateway.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }

  enabled_log {
    category = "ApplicationGatewayPerformanceLog"
  }

  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }

  metric {
    category = "AllMetrics"
  }
}

# Outputs
output "application_gateway_id" {
  description = "The ID of the Application Gateway"
  value       = azurerm_application_gateway.main.id
}

output "application_gateway_public_ip" {
  description = "The public IP address of the Application Gateway"
  value       = var.public_ip_id
}

output "waf_policy_id" {
  description = "The ID of the WAF policy"
  value       = azurerm_web_application_firewall_policy.main.id
}

output "backend_address_pool_id" {
  description = "The ID of the backend address pool"
  value       = tolist(azurerm_application_gateway.main.backend_address_pool)[0].id
}

# Additional variables for monitoring
variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for diagnostics"
  type        = string
  default     = null
}