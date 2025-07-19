# Cloudflare DDoS Protection Module for SPARC Platform

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

variable "cloudflare_account_id" {
  description = "Cloudflare Account ID"
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

variable "enable_advanced_ddos" {
  description = "Enable Advanced DDoS Protection (requires Enterprise plan)"
  type        = bool
  default     = false
}

variable "ddos_sensitivity" {
  description = "DDoS detection sensitivity (low, medium, high)"
  type        = string
  default     = "medium"
}

variable "notification_emails" {
  description = "Email addresses for DDoS notifications"
  type        = list(string)
  default     = []
}

variable "webhook_url" {
  description = "Webhook URL for DDoS alerts"
  type        = string
  default     = ""
}

# Local variables
locals {
  name = "${var.name_prefix}-${var.environment}"
  
  # DDoS sensitivity thresholds
  sensitivity_settings = {
    low = {
      http_threshold = 10000
      tcp_threshold  = 50000
      udp_threshold  = 50000
      icmp_threshold = 10000
      packet_threshold = 100000
    }
    medium = {
      http_threshold = 5000
      tcp_threshold  = 25000
      udp_threshold  = 25000
      icmp_threshold = 5000
      packet_threshold = 50000
    }
    high = {
      http_threshold = 1000
      tcp_threshold  = 10000
      udp_threshold  = 10000
      icmp_threshold = 1000
      packet_threshold = 20000
    }
  }
  
  current_sensitivity = local.sensitivity_settings[var.ddos_sensitivity]
}

# DDoS Protection Settings
resource "cloudflare_zone_settings_override" "ddos_protection" {
  zone_id = var.cloudflare_zone_id

  settings {
    # Security Level
    security_level = var.environment == "prod" ? "high" : "medium"
    
    # Challenge TTL
    challenge_ttl = var.environment == "prod" ? 1800 : 900
    
    # Browser Integrity Check
    browser_check = "on"
    
    # Hotlink Protection
    hotlink_protection = "on"
    
    # IP Geolocation
    ip_geolocation = "on"
    
    # Email Obfuscation
    email_obfuscation = "on"
    
    # Server Side Excludes
    server_side_exclude = "on"
    
    # Always Use HTTPS
    always_use_https = "on"
    
    # Opportunistic Encryption
    opportunistic_encryption = "on"
    
    # Automatic HTTPS Rewrites
    automatic_https_rewrites = "on"
    
    # Privacy Pass
    privacy_pass = "on"
  }
}

# Advanced DDoS Protection Rules
resource "cloudflare_ruleset" "ddos_override" {
  zone_id     = var.cloudflare_zone_id
  name        = "${local.name}-ddos-rules"
  description = "SPARC Platform DDoS Protection Rules"
  kind        = "zone"
  phase       = "ddos_l7"

  # HTTP DDoS Protection
  rules {
    action = "execute"
    action_parameters {
      id = "default"
      overrides {
        sensitivity_level = var.ddos_sensitivity
        
        # Action overrides for specific attack types
        rules {
          id                = "fdfdac75dce34e859dcd6ed490f7e3c0"  # HTTP Flood
          sensitivity_level = "high"
          action           = "block"
        }
        
        rules {
          id                = "62d2c4b4147e4117bf956eb0e82c8c94"  # WordPress Attack
          sensitivity_level = "high"
          action           = "challenge"
        }
        
        rules {
          id                = "5d1b8f5c8c6f4b03bbf8dc8e38cdeb98"  # HTTP Anomaly
          sensitivity_level = var.ddos_sensitivity
          action           = var.environment == "prod" ? "block" : "challenge"
        }
      }
    }
    expression  = "true"
    description = "Override HTTP DDoS managed rules"
    enabled     = true
  }
}

# Network-layer DDoS Protection
resource "cloudflare_magic_transit_static_route" "ddos_protection" {
  count = var.enable_advanced_ddos ? 1 : 0

  account_id  = var.cloudflare_account_id
  description = "SPARC DDoS Protection Route"
  prefix      = var.network_prefix
  nexthop     = var.nexthop_ip
  priority    = 100
  weight      = 100
  
  colo_names = var.environment == "prod" ? ["*"] : var.colo_names
}

# Rate Limiting Rules for Application Layer DDoS
resource "cloudflare_rate_limit" "api_protection" {
  zone_id     = var.cloudflare_zone_id
  description = "API endpoint protection"
  threshold   = local.current_sensitivity.http_threshold
  period      = 60  # 1 minute
  
  match {
    request {
      url_pattern = "${var.domain}/api/*"
    }
  }
  
  action {
    mode    = "challenge"
    timeout = 600  # 10 minutes
    
    response {
      content_type = "application/json"
      body = jsonencode({
        error   = "rate_limit_exceeded"
        message = "Too many requests. Please try again later."
        retry_after = 600
      })
    }
  }
  
  correlate {
    by = "nat"
  }
  
  disabled = false
}

# Specific protection for video streaming endpoints
resource "cloudflare_rate_limit" "video_stream_protection" {
  zone_id     = var.cloudflare_zone_id
  description = "Video streaming DDoS protection"
  threshold   = 100  # Lower threshold for video streams
  period      = 60
  
  match {
    request {
      url_pattern = "${var.domain}/api/videos/stream/*"
    }
  }
  
  action {
    mode    = "ban"
    timeout = 3600  # 1 hour
  }
  
  disabled = false
}

# Advanced DDoS Analytics and Alerting
resource "cloudflare_notification_policy" "ddos_alerts" {
  account_id  = var.cloudflare_account_id
  name        = "${local.name}-ddos-alerts"
  description = "DDoS attack notifications for SPARC"
  enabled     = true
  
  alert_type = "advanced_ddos_attack_l7_alert"
  
  email_integration {
    id = var.notification_emails
  }
  
  webhooks_integration {
    id = var.webhook_url != "" ? [var.webhook_url] : []
  }
  
  filters {
    zones = [var.cloudflare_zone_id]
  }
}

# Additional notification for L3/L4 attacks
resource "cloudflare_notification_policy" "network_ddos_alerts" {
  account_id  = var.cloudflare_account_id
  name        = "${local.name}-network-ddos-alerts"
  description = "Network layer DDoS attack notifications"
  enabled     = true
  
  alert_type = "advanced_ddos_attack_l4_alert"
  
  email_integration {
    id = var.notification_emails
  }
  
  webhooks_integration {
    id = var.webhook_url != "" ? [var.webhook_url] : []
  }
}

# Firewall Rules for DDoS Mitigation
resource "cloudflare_firewall_rule" "ddos_mitigation_rules" {
  zone_id     = var.cloudflare_zone_id
  description = "DDoS mitigation based on threat score"
  expression  = "(cf.threat_score > 50)"
  action      = var.environment == "prod" ? "challenge" : "log"
  priority    = 1
}

# Under Attack Mode automation
resource "cloudflare_firewall_rule" "under_attack_mode" {
  zone_id     = var.cloudflare_zone_id
  description = "Enable Under Attack Mode for extreme DDoS"
  expression  = <<-EOT
    (
      rate(60) > ${local.current_sensitivity.http_threshold * 10} or
      cf.threat_score > 90
    )
  EOT
  action      = "js_challenge"
  priority    = 2
}

# Geographic-based DDoS mitigation
resource "cloudflare_firewall_rule" "geo_ddos_mitigation" {
  zone_id     = var.cloudflare_zone_id
  description = "Geographic DDoS mitigation"
  expression  = <<-EOT
    (
      ip.geoip.country in {"CN" "RU" "KP"} and 
      rate(60) > ${local.current_sensitivity.http_threshold / 2}
    )
  EOT
  action      = "block"
  priority    = 3
}

# Bot Management for DDoS
resource "cloudflare_bot_management" "ddos_bot_protection" {
  zone_id = var.cloudflare_zone_id
  
  enable_js         = true
  fight_mode       = true
  session_score    = true
  
  # Use ML to detect bot-driven DDoS
  use_latest_model = true
  auto_update_model = true
  
  # Verified bot settings
  verified_bots {
    cf_verified_bot_category = ["good_bot"]
    action = "allow"
  }
  
  # Likely automated traffic
  likely_automated {
    score_threshold = 30
    action = var.environment == "prod" ? "block" : "challenge"
  }
}

# Spectrum DDoS Protection (for non-HTTP/HTTPS traffic)
resource "cloudflare_spectrum_application" "tcp_protection" {
  count = var.enable_advanced_ddos ? 1 : 0
  
  zone_id     = var.cloudflare_zone_id
  protocol    = "tcp/22"
  dns {
    type = "CNAME"
    name = "ssh.${var.domain}"
  }
  origin_direct = var.origin_ips
  edge_ips      = "all"
  ip_firewall   = true
  proxy_protocol = "v1"
  tls           = "flexible"
  
  # DDoS protection enabled by default for Spectrum
}

# Load Balancing for DDoS Resilience
resource "cloudflare_load_balancer" "ddos_resilience" {
  count = var.enable_load_balancing ? 1 : 0
  
  zone_id          = var.cloudflare_zone_id
  name             = "${local.name}-lb"
  fallback_pool_id = cloudflare_load_balancer_pool.primary[0].id
  default_pool_ids = [cloudflare_load_balancer_pool.primary[0].id]
  description      = "Load balancer for DDoS resilience"
  proxied          = true
  steering_policy  = "dynamic_latency"
  session_affinity = "cookie"
  
  # Enable adaptive routing for DDoS
  adaptive_routing {
    failover_across_pools = true
  }
  
  # Location-based steering during attacks
  location_strategy {
    prefer_ecs = "always"
    mode       = "resolver_ip"
  }
  
  # Random steering to distribute attack traffic
  random_steering {
    pool_weights = {
      (cloudflare_load_balancer_pool.primary[0].id) = 0.8
      (cloudflare_load_balancer_pool.secondary[0].id) = 0.2
    }
  }
}

# Load Balancer Pools
resource "cloudflare_load_balancer_pool" "primary" {
  count = var.enable_load_balancing ? 1 : 0
  
  account_id         = var.cloudflare_account_id
  name               = "${local.name}-primary-pool"
  minimum_origins    = 1
  notification_email = var.notification_emails[0]
  
  dynamic "origins" {
    for_each = var.primary_origins
    content {
      name    = origins.value.name
      address = origins.value.address
      enabled = true
      weight  = origins.value.weight
    }
  }
  
  # Health check for origin availability
  monitor = cloudflare_load_balancer_monitor.health[0].id
}

resource "cloudflare_load_balancer_pool" "secondary" {
  count = var.enable_load_balancing ? 1 : 0
  
  account_id         = var.cloudflare_account_id
  name               = "${local.name}-secondary-pool"
  minimum_origins    = 1
  notification_email = var.notification_emails[0]
  
  dynamic "origins" {
    for_each = var.secondary_origins
    content {
      name    = origins.value.name
      address = origins.value.address
      enabled = true
      weight  = origins.value.weight
    }
  }
  
  monitor = cloudflare_load_balancer_monitor.health[0].id
}

# Health Monitor
resource "cloudflare_load_balancer_monitor" "health" {
  count = var.enable_load_balancing ? 1 : 0
  
  account_id     = var.cloudflare_account_id
  type           = "https"
  description    = "SPARC health check"
  method         = "GET"
  path           = "/health"
  interval       = 60
  retries        = 2
  timeout        = 5
  expected_codes = "200"
  
  header {
    header = "X-Health-Check"
    values = ["cloudflare"]
  }
}

# Outputs
output "ddos_protection_enabled" {
  description = "DDoS protection status"
  value       = true
}

output "ddos_sensitivity" {
  description = "Current DDoS sensitivity level"
  value       = var.ddos_sensitivity
}

output "rate_limit_rules" {
  description = "Rate limiting rules created"
  value = {
    api_protection = cloudflare_rate_limit.api_protection.id
    video_protection = cloudflare_rate_limit.video_stream_protection.id
  }
}

output "notification_policies" {
  description = "DDoS notification policy IDs"
  value = {
    l7_alerts = cloudflare_notification_policy.ddos_alerts.id
    l4_alerts = cloudflare_notification_policy.network_ddos_alerts.id
  }
}

# Additional variables
variable "domain" {
  description = "Domain name"
  type        = string
}

variable "network_prefix" {
  description = "Network prefix for Magic Transit"
  type        = string
  default     = ""
}

variable "nexthop_ip" {
  description = "Next hop IP for Magic Transit"
  type        = string
  default     = ""
}

variable "colo_names" {
  description = "Cloudflare colo names for Magic Transit"
  type        = list(string)
  default     = []
}

variable "origin_ips" {
  description = "Origin server IPs"
  type        = list(string)
  default     = []
}

variable "enable_load_balancing" {
  description = "Enable load balancing for DDoS resilience"
  type        = bool
  default     = false
}

variable "primary_origins" {
  description = "Primary origin servers"
  type = list(object({
    name    = string
    address = string
    weight  = number
  }))
  default = []
}

variable "secondary_origins" {
  description = "Secondary origin servers"
  type = list(object({
    name    = string
    address = string
    weight  = number
  }))
  default = []
}