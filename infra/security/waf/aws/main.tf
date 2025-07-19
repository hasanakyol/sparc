# AWS WAF Module for SPARC Platform

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Variables
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

variable "enable_rate_limiting" {
  description = "Enable rate limiting rules"
  type        = bool
  default     = true
}

variable "enable_geo_blocking" {
  description = "Enable geographic blocking"
  type        = bool
  default     = true
}

variable "blocked_countries" {
  description = "List of country codes to block"
  type        = list(string)
  default     = []
}

variable "rate_limit_per_ip" {
  description = "Rate limit per IP address (requests per 5 minutes)"
  type        = number
  default     = 2000
}

variable "rate_limit_per_uri" {
  description = "Rate limit per URI (requests per 5 minutes)"
  type        = number
  default     = 1000
}

variable "custom_rules" {
  description = "Custom WAF rules"
  type = list(object({
    name     = string
    priority = number
    action   = string
    statement = any
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
  name = "${var.name_prefix}-waf-${var.environment}"
  common_tags = merge(var.tags, {
    Environment = var.environment
    Service     = "sparc-waf"
    ManagedBy   = "terraform"
  })
}

# CloudWatch Log Group for WAF logs
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/wafv2/${local.name}"
  retention_in_days = var.environment == "prod" ? 90 : 30
  kms_key_id        = var.kms_key_id

  tags = local.common_tags
}

# IP Set for allowlist
resource "aws_wafv2_ip_set" "allowlist" {
  name               = "${local.name}-allowlist"
  description        = "IP addresses allowed to bypass certain WAF rules"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ips

  tags = local.common_tags
}

# IP Set for blocklist
resource "aws_wafv2_ip_set" "blocklist" {
  name               = "${local.name}-blocklist"
  description        = "IP addresses to block"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.blocked_ips

  tags = local.common_tags
}

# Regex Pattern Set for SPARC-specific threats
resource "aws_wafv2_regex_pattern_set" "sparc_threats" {
  name        = "${local.name}-threat-patterns"
  description = "Regex patterns for SPARC-specific security threats"
  scope       = "REGIONAL"

  regular_expression {
    regex_string = "(?i)(camera|video|stream).*(<script|javascript:|onerror=|onload=)"
  }

  regular_expression {
    regex_string = "(?i)(incident|alert|sensor).*(union.*select|drop.*table|exec.*xp_)"
  }

  regular_expression {
    regex_string = "(?i)(\\.\\./|\\\\x5c|%2e%2e%2f|%252e%252e%252f)"
  }

  tags = local.common_tags
}

# Main WAF Web ACL
resource "aws_wafv2_web_acl" "main" {
  name        = local.name
  description = "SPARC Platform WAF with OWASP Core Rule Set and custom protections"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: Block IPs in blocklist
  rule {
    name     = "BlocklistRule"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocklist.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-blocklist"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: SPARC-specific threat patterns
  rule {
    name     = "SparcThreatProtection"
    priority = 2

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.sparc_threats.arn
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.sparc_threats.arn
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
        statement {
          regex_pattern_set_reference_statement {
            arn = aws_wafv2_regex_pattern_set.sparc_threats.arn
            field_to_match {
              body {
                oversize_handling = "MATCH"
              }
            }
            text_transformation {
              priority = 1
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-sparc-threats"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: Rate limiting per IP
  dynamic "rule" {
    for_each = var.enable_rate_limiting ? [1] : []
    content {
      name     = "RateLimitPerIP"
      priority = 10

      action {
        block {}
      }

      statement {
        rate_based_statement {
          limit              = var.rate_limit_per_ip
          aggregate_key_type = "IP"

          scope_down_statement {
            not_statement {
              statement {
                ip_set_reference_statement {
                  arn = aws_wafv2_ip_set.allowlist.arn
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-rate-limit-ip"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 4: Enhanced rate limiting for sensitive endpoints
  dynamic "rule" {
    for_each = var.enable_rate_limiting ? [1] : []
    content {
      name     = "RateLimitSensitiveEndpoints"
      priority = 11

      action {
        block {}
      }

      statement {
        rate_based_statement {
          limit              = 100  # Stricter limit for sensitive endpoints
          aggregate_key_type = "IP"

          scope_down_statement {
            or_statement {
              statement {
                byte_match_statement {
                  search_string = "/api/auth/login"
                  field_to_match {
                    uri_path {}
                  }
                  positional_constraint = "STARTS_WITH"
                  text_transformation {
                    priority = 0
                    type     = "LOWERCASE"
                  }
                }
              }
              statement {
                byte_match_statement {
                  search_string = "/api/incidents/create"
                  field_to_match {
                    uri_path {}
                  }
                  positional_constraint = "STARTS_WITH"
                  text_transformation {
                    priority = 0
                    type     = "LOWERCASE"
                  }
                }
              }
              statement {
                byte_match_statement {
                  search_string = "/api/alerts/trigger"
                  field_to_match {
                    uri_path {}
                  }
                  positional_constraint = "STARTS_WITH"
                  text_transformation {
                    priority = 0
                    type     = "LOWERCASE"
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-rate-limit-sensitive"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 5: Geographic blocking
  dynamic "rule" {
    for_each = var.enable_geo_blocking && length(var.blocked_countries) > 0 ? [1] : []
    content {
      name     = "GeoBlockingRule"
      priority = 20

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.blocked_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-geo-block"
        sampled_requests_enabled   = true
      }
    }
  }

  # OWASP Managed Rules
  dynamic "rule" {
    for_each = var.enable_owasp_rules ? [1] : []
    content {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 30

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesCommonRuleSet"

          # Exclude rules that may cause false positives
          rule_action_override {
            name = "SizeRestrictions_BODY"
            action_to_use {
              count {}
            }
          }

          rule_action_override {
            name = "GenericRFI_BODY"
            action_to_use {
              count {}
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-owasp-common"
        sampled_requests_enabled   = true
      }
    }
  }

  # SQL Injection Protection
  dynamic "rule" {
    for_each = var.enable_owasp_rules ? [1] : []
    content {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = 31

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesSQLiRuleSet"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-sqli"
        sampled_requests_enabled   = true
      }
    }
  }

  # Known Bad Inputs
  dynamic "rule" {
    for_each = var.enable_owasp_rules ? [1] : []
    content {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = 32

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesKnownBadInputsRuleSet"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-bad-inputs"
        sampled_requests_enabled   = true
      }
    }
  }

  # Linux-specific protections (for API servers)
  dynamic "rule" {
    for_each = var.enable_owasp_rules ? [1] : []
    content {
      name     = "AWSManagedRulesLinuxRuleSet"
      priority = 33

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesLinuxRuleSet"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-linux"
        sampled_requests_enabled   = true
      }
    }
  }

  # Bot Control
  rule {
    name     = "AWSManagedRulesBotControlRuleSet"
    priority = 40

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesBotControlRuleSet"
        
        managed_rule_group_configs {
          aws_managed_rules_bot_control_rule_set {
            inspection_level = "COMMON"
          }
        }

        rule_action_override {
          name = "CategoryHttpLibrary"
          action_to_use {
            count {}
          }
        }

        rule_action_override {
          name = "SignalNonBrowserUserAgent"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-bot-control"
      sampled_requests_enabled   = true
    }
  }

  # Custom rules
  dynamic "rule" {
    for_each = var.custom_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      statement = rule.value.statement

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-${rule.value.name}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  redacted_fields {
    single_header {
      name = "x-auth-token"
    }
  }
}

# CloudWatch Dashboard for WAF metrics
resource "aws_cloudwatch_dashboard" "waf" {
  dashboard_name = "${local.name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", local.name, "Region", data.aws_region.current.name],
            [".", "AllowedRequests", ".", ".", ".", "."],
            [".", "CountedRequests", ".", ".", ".", "."]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "WAF Request Summary"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", local.name, "Region", data.aws_region.current.name, "Rule", "RateLimitPerIP"],
            ["...", "RateLimitSensitiveEndpoints"],
            ["...", "GeoBlockingRule"],
            ["...", "SparcThreatProtection"]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Blocked Requests by Rule"
        }
      }
    ]
  })
}

# Outputs
output "web_acl_id" {
  description = "The ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.id
}

output "web_acl_arn" {
  description = "The ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "web_acl_capacity" {
  description = "The capacity consumed by the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.capacity
}

output "log_group_name" {
  description = "The name of the CloudWatch log group for WAF logs"
  value       = aws_cloudwatch_log_group.waf_logs.name
}

# Data sources
data "aws_region" "current" {}

# Additional variables for complete configuration
variable "kms_key_id" {
  description = "KMS key ID for encrypting logs"
  type        = string
  default     = null
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