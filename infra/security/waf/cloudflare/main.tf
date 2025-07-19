# Cloudflare WAF Module for SPARC Platform

terraform {
  required_version = ">= 1.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 4.0"
    }
  }
}

# Variables
variable "cloudflare_zone_id" {
  description = "Cloudflare Zone ID"
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

variable "enable_owasp_rules" {
  description = "Enable OWASP Core Rule Set"
  type        = bool
  default     = true
}

variable "waf_sensitivity" {
  description = "WAF sensitivity level (low, medium, high)"
  type        = string
  default     = "medium"
}

variable "enable_rate_limiting" {
  description = "Enable rate limiting rules"
  type        = bool
  default     = true
}

variable "enable_bot_management" {
  description = "Enable bot management"
  type        = bool
  default     = true
}

variable "blocked_countries" {
  description = "List of country codes to block"
  type        = list(string)
  default     = []
}

variable "allowed_ips" {
  description = "List of IP addresses to allowlist"
  type        = list(string)
  default     = []
}

variable "blocked_ips" {
  description = "List of IP addresses to blocklist"
  type        = list(string)
  default     = []
}

variable "custom_rules" {
  description = "Custom firewall rules"
  type = list(object({
    expression  = string
    action      = string
    description = string
    products    = list(string)
    priority    = number
  }))
  default = []
}

# Local variables
locals {
  name = "${var.name_prefix}-${var.environment}"
  
  sensitivity_scores = {
    low    = 60
    medium = 40
    high   = 25
  }

  waf_score_threshold = local.sensitivity_scores[var.waf_sensitivity]
}

# IP Lists
resource "cloudflare_list" "allowlist" {
  account_id  = var.cloudflare_account_id
  name        = "${local.name}-allowlist"
  kind        = "ip"
  description = "SPARC Platform IP Allowlist"

  dynamic "item" {
    for_each = var.allowed_ips
    content {
      value {
        ip = item.value
      }
    }
  }
}

resource "cloudflare_list" "blocklist" {
  account_id  = var.cloudflare_account_id
  name        = "${local.name}-blocklist"
  kind        = "ip"
  description = "SPARC Platform IP Blocklist"

  dynamic "item" {
    for_each = var.blocked_ips
    content {
      value {
        ip = item.value
      }
    }
  }
}

# Custom list for SPARC-specific threat patterns
resource "cloudflare_list" "threat_patterns" {
  account_id  = var.cloudflare_account_id
  name        = "${local.name}-threat-patterns"
  kind        = "redirect"
  description = "SPARC-specific threat patterns"

  item {
    value {
      redirect {
        source_url = "*camera*script*"
        target_url = "/blocked"
      }
    }
  }

  item {
    value {
      redirect {
        source_url = "*video*javascript*"
        target_url = "/blocked"
      }
    }
  }

  item {
    value {
      redirect {
        source_url = "*incident*union*select*"
        target_url = "/blocked"
      }
    }
  }
}

# Firewall Rules

# Rule 1: Block IPs in blocklist
resource "cloudflare_firewall_rule" "block_ips" {
  zone_id     = var.cloudflare_zone_id
  description = "Block malicious IPs"
  expression  = "(ip.src in $blocklist)"
  action      = "block"
  priority    = 1

  depends_on = [cloudflare_list.blocklist]
}

# Rule 2: Allow trusted IPs
resource "cloudflare_firewall_rule" "allow_trusted_ips" {
  zone_id     = var.cloudflare_zone_id
  description = "Allow trusted IPs"
  expression  = "(ip.src in $allowlist)"
  action      = "allow"
  priority    = 2

  depends_on = [cloudflare_list.allowlist]
}

# Rule 3: SPARC-specific threat protection
resource "cloudflare_firewall_rule" "sparc_threats" {
  zone_id     = var.cloudflare_zone_id
  description = "Block SPARC-specific threats"
  expression  = <<-EOT
    (
      (http.request.uri.path contains "/camera" and http.request.uri.query contains "script") or
      (http.request.uri.path contains "/video" and http.request.uri.query contains "javascript") or
      (http.request.uri.path contains "/stream" and http.request.uri.query matches "(?i)(onerror|onload|eval)") or
      (http.request.uri.query matches "(?i)(union.*select|drop.*table|exec.*xp_)") or
      (http.request.uri.path matches "(?i)(\\.\\./|\\\\x5c|%2e%2e%2f)")
    )
  EOT
  action      = "block"
  priority    = 10
}

# Rule 4: Geo-blocking
resource "cloudflare_firewall_rule" "geo_block" {
  count       = length(var.blocked_countries) > 0 ? 1 : 0
  zone_id     = var.cloudflare_zone_id
  description = "Geographic blocking"
  expression  = "(ip.geoip.country in {${join(" ", formatlist("\"%s\"", var.blocked_countries))}})"
  action      = "block"
  priority    = 20
}

# Rule 5: Rate limiting for API endpoints
resource "cloudflare_rate_limit" "api_rate_limit" {
  count       = var.enable_rate_limiting ? 1 : 0
  zone_id     = var.cloudflare_zone_id
  description = "API rate limiting"
  
  threshold = 100
  period    = 60  # 1 minute
  
  match {
    request {
      url_pattern = "${var.domain}/api/*"
    }
  }
  
  action {
    mode    = "ban"
    timeout = 600  # 10 minutes
    
    response {
      content_type = "application/json"
      body         = jsonencode({
        error = "Rate limit exceeded"
        message = "Too many requests, please try again later"
      })
    }
  }
}

# Rule 6: Strict rate limiting for authentication endpoints
resource "cloudflare_rate_limit" "auth_rate_limit" {
  count       = var.enable_rate_limiting ? 1 : 0
  zone_id     = var.cloudflare_zone_id
  description = "Authentication endpoint rate limiting"
  
  threshold = 5
  period    = 300  # 5 minutes
  
  match {
    request {
      url_pattern = "${var.domain}/api/auth/*"
    }
  }
  
  action {
    mode    = "challenge"
    timeout = 3600  # 1 hour
  }
}

# WAF Package Rules
resource "cloudflare_waf_package" "owasp" {
  count       = var.enable_owasp_rules ? 1 : 0
  zone_id     = var.cloudflare_zone_id
  package_id  = "a25a9a7e9c00afc1fb2e0245519d725b"  # OWASP ModSecurity Core Rule Set
  sensitivity = var.waf_sensitivity
  action_mode = var.environment == "prod" ? "block" : "simulate"
}

# WAF Rules for SPARC-specific protections
resource "cloudflare_waf_rule" "sparc_custom_rules" {
  zone_id  = var.cloudflare_zone_id
  rule_id  = "100000"  # Custom rule ID
  mode     = var.environment == "prod" ? "block" : "simulate"
}

# Bot Management
resource "cloudflare_bot_management" "main" {
  count   = var.enable_bot_management ? 1 : 0
  zone_id = var.cloudflare_zone_id

  enable_js                = true
  fight_mode              = true
  session_score           = true
  suppress_session_score  = false

  # Auto-update model based on traffic patterns
  auto_update_model = true
  
  # Use ML to detect bots
  use_latest_model = true
}

# Page Rules for security headers
resource "cloudflare_page_rule" "security_headers" {
  zone_id  = var.cloudflare_zone_id
  target   = "${var.domain}/*"
  priority = 1

  actions {
    security_level = "high"
    ssl            = "strict"
    always_use_https = true
    
    # Security headers
    response_headers = {
      "X-Frame-Options"        = "SAMEORIGIN"
      "X-Content-Type-Options" = "nosniff"
      "X-XSS-Protection"       = "1; mode=block"
      "Referrer-Policy"        = "strict-origin-when-cross-origin"
      "Permissions-Policy"     = "geolocation=(), microphone=(), camera=(self)"
      "Content-Security-Policy" = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    }
  }
}

# DDoS Protection Settings
resource "cloudflare_zone_settings_override" "ddos" {
  zone_id = var.cloudflare_zone_id

  settings {
    # Security level
    security_level = var.environment == "prod" ? "high" : "medium"
    
    # Challenge TTL
    challenge_ttl = 1800
    
    # Browser check
    browser_check = "on"
    
    # Enable IPv6
    ipv6 = "on"
    
    # Minimum TLS version
    min_tls_version = "1.2"
    
    # Opportunistic encryption
    opportunistic_encryption = "on"
    
    # TLS 1.3
    tls_1_3 = "on"
    
    # Always use HTTPS
    always_use_https = "on"
    
    # HTTP/3 (QUIC)
    http3 = "on"
    
    # 0-RTT
    "0rtt" = "on"
    
    # Websockets
    websockets = "on"
    
    # IP Geolocation
    ip_geolocation = "on"
    
    # Privacy Pass
    privacy_pass = "on"
  }
}

# Advanced DDoS Protection
resource "cloudflare_ddos_override" "advanced" {
  zone_id     = var.cloudflare_zone_id
  description = "Advanced DDoS protection for SPARC"
  
  # HTTP DDoS attack protection
  http_adaptive {
    enabled    = true
    sensitivity_level = var.environment == "prod" ? "high" : "medium"
  }
  
  # L3/L4 DDoS attack protection  
  l3l4 {
    enabled = true
  }
}

# Custom Firewall Rules from variable
resource "cloudflare_firewall_rule" "custom" {
  for_each = { for idx, rule in var.custom_rules : idx => rule }
  
  zone_id     = var.cloudflare_zone_id
  description = each.value.description
  expression  = each.value.expression
  action      = each.value.action
  priority    = each.value.priority
  products    = each.value.products
}

# Managed Challenge for suspicious requests
resource "cloudflare_firewall_rule" "challenge_suspicious" {
  zone_id     = var.cloudflare_zone_id
  description = "Challenge suspicious requests"
  expression  = <<-EOT
    (
      (cf.threat_score > ${local.waf_score_threshold}) or
      (http.request.uri.query matches "(?i)(base64|eval|exec|shell)") or
      (http.user_agent matches "(?i)(sqlmap|nikto|nessus|metasploit)")
    )
  EOT
  action      = "challenge"
  priority    = 100
}

# Transform Rules for additional security
resource "cloudflare_transform_rule" "remove_headers" {
  zone_id     = var.cloudflare_zone_id
  description = "Remove sensitive headers"
  kind        = "response_headers"
  phase       = "http_response_headers_transform"
  
  expression = "true"
  
  actions {
    headers {
      operation = "remove"
      name      = "Server"
    }
    headers {
      operation = "remove"
      name      = "X-Powered-By"
    }
    headers {
      operation = "remove"
      name      = "X-AspNet-Version"
    }
  }
}

# Outputs
output "firewall_rule_ids" {
  description = "IDs of created firewall rules"
  value = {
    block_ips      = cloudflare_firewall_rule.block_ips.id
    allow_trusted  = cloudflare_firewall_rule.allow_trusted_ips.id
    sparc_threats  = cloudflare_firewall_rule.sparc_threats.id
    geo_block      = try(cloudflare_firewall_rule.geo_block[0].id, null)
  }
}

output "rate_limit_ids" {
  description = "IDs of rate limit rules"
  value = {
    api_rate_limit  = try(cloudflare_rate_limit.api_rate_limit[0].id, null)
    auth_rate_limit = try(cloudflare_rate_limit.auth_rate_limit[0].id, null)
  }
}

output "waf_package_id" {
  description = "ID of WAF package"
  value       = try(cloudflare_waf_package.owasp[0].id, null)
}

# Additional variables
variable "cloudflare_account_id" {
  description = "Cloudflare Account ID"
  type        = string
}

variable "domain" {
  description = "Domain name"
  type        = string
}