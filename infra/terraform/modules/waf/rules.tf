# Comprehensive WAF Rules for SPARC Platform

locals {
  # Common variables
  rate_limit_threshold = 2000
  geo_block_countries  = ["CN", "RU", "KP", "IR"] # High-risk countries
  
  # Tags for all WAF resources
  waf_tags = merge(var.common_tags, {
    Component = "WAF"
    Security  = "true"
  })
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "sparc_waf" {
  name        = "${var.project_name}-waf-${var.environment}"
  description = "SPARC Platform WAF with comprehensive security rules"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: Rate Limiting
  rule {
    name     = "RateLimitRule"
    priority = 1

    statement {
      rate_based_statement {
        limit              = local.rate_limit_threshold
        aggregate_key_type = "IP"

        scope_down_statement {
          not_statement {
            statement {
              byte_match_statement {
                search_string = "/health"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
                positional_constraint = "CONTAINS"
              }
            }
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "rate_limit_exceeded"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Geographic Restrictions
  rule {
    name     = "GeoBlockRule"
    priority = 2

    statement {
      geo_match_statement {
        country_codes = local.geo_block_countries
      }
    }

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "geo_blocked"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "GeoBlockRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: AWS Managed Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        excluded_rule {
          name = "SizeRestrictions_BODY"
        }

        excluded_rule {
          name = "GenericRFI_BODY"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: SQL Injection Protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 5

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: Linux-specific Protection
  rule {
    name     = "AWSManagedRulesLinuxRuleSet"
    priority = 6

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesLinuxRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesLinuxRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 7: POSIX OS Protection
  rule {
    name     = "AWSManagedRulesUnixRuleSet"
    priority = 7

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesUnixRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesUnixRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 8: Custom XSS Protection
  rule {
    name     = "CustomXSSProtection"
    priority = 8

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = "<script"
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string = "javascript:"
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string = "onerror="
            field_to_match {
              body {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "xss_detected"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CustomXSSProtection"
      sampled_requests_enabled   = true
    }
  }

  # Rule 9: Path Traversal Protection
  rule {
    name     = "PathTraversalProtection"
    priority = 9

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string = "../"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string = "..%2f"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }

        statement {
          byte_match_statement {
            search_string = "..%5c"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 403
          custom_response_body_key = "path_traversal_detected"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "PathTraversalProtection"
      sampled_requests_enabled   = true
    }
  }

  # Rule 10: API Abuse Protection
  rule {
    name     = "APIAbuseProtection"
    priority = 10

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string = "/api/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
            positional_constraint = "STARTS_WITH"
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "api_rate_limit_exceeded"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "APIAbuseProtection"
      sampled_requests_enabled   = true
    }
  }

  # Rule 11: Bot Control
  rule {
    name     = "AWSManagedRulesBotControlRuleSet"
    priority = 11

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"

        managed_rule_group_configs {
          aws_managed_rules_bot_control_rule_set {
            inspection_level = "COMMON"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesBotControlRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 12: Large Request Body Protection
  rule {
    name     = "LargeRequestBodyProtection"
    priority = 12

    statement {
      size_constraint_statement {
        field_to_match {
          body {}
        }
        comparison_operator = "GT"
        size                = 8192 # 8KB
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 413
          custom_response_body_key = "request_too_large"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "LargeRequestBodyProtection"
      sampled_requests_enabled   = true
    }
  }

  # Rule 13: Authentication Brute Force Protection
  rule {
    name     = "AuthBruteForceProtection"
    priority = 13

    statement {
      rate_based_statement {
        limit              = 5
        aggregate_key_type = "IP"

        scope_down_statement {
          and_statement {
            statement {
              byte_match_statement {
                search_string = "/auth/login"
                field_to_match {
                  uri_path {}
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
                positional_constraint = "ENDS_WITH"
              }
            }

            statement {
              byte_match_statement {
                search_string = "POST"
                field_to_match {
                  method {}
                }
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
                positional_constraint = "EXACTLY"
              }
            }
          }
        }
      }
    }

    action {
      block {
        custom_response {
          response_code = 429
          custom_response_body_key = "auth_rate_limit_exceeded"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AuthBruteForceProtection"
      sampled_requests_enabled   = true
    }
  }

  # Custom response bodies
  custom_response_body {
    key          = "rate_limit_exceeded"
    content      = jsonencode({
      error = "Rate limit exceeded. Please try again later."
      code  = "RATE_LIMIT_EXCEEDED"
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "geo_blocked"
    content      = jsonencode({
      error = "Access denied from your location."
      code  = "GEO_BLOCKED"
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "xss_detected"
    content      = jsonencode({
      error = "Potential XSS attack detected."
      code  = "XSS_DETECTED"
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "path_traversal_detected"
    content      = jsonencode({
      error = "Path traversal attempt detected."
      code  = "PATH_TRAVERSAL_DETECTED"
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "api_rate_limit_exceeded"
    content      = jsonencode({
      error = "API rate limit exceeded."
      code  = "API_RATE_LIMIT_EXCEEDED"
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "request_too_large"
    content      = jsonencode({
      error = "Request body too large."
      code  = "REQUEST_TOO_LARGE"
    })
    content_type = "APPLICATION_JSON"
  }

  custom_response_body {
    key          = "auth_rate_limit_exceeded"
    content      = jsonencode({
      error = "Too many authentication attempts. Please try again later."
      code  = "AUTH_RATE_LIMIT_EXCEEDED"
    })
    content_type = "APPLICATION_JSON"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "SPARCWebACL"
    sampled_requests_enabled   = true
  }

  tags = local.waf_tags
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "sparc_waf_logging" {
  resource_arn            = aws_wafv2_web_acl.sparc_waf.arn
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
      name = "x-api-key"
    }
  }
}

# CloudWatch Log Group for WAF
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/wafv2/${var.project_name}/${var.environment}"
  retention_in_days = 30
  kms_key_id        = var.kms_key_arn

  tags = local.waf_tags
}

# WAF IP Set for Allow List
resource "aws_wafv2_ip_set" "allow_list" {
  name               = "${var.project_name}-allow-list-${var.environment}"
  description        = "IP addresses allowed to bypass certain WAF rules"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.allowed_ips

  tags = local.waf_tags
}

# WAF IP Set for Block List
resource "aws_wafv2_ip_set" "block_list" {
  name               = "${var.project_name}-block-list-${var.environment}"
  description        = "IP addresses to block"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.blocked_ips

  tags = local.waf_tags
}

# WAF Regex Pattern Set for Malicious Patterns
resource "aws_wafv2_regex_pattern_set" "malicious_patterns" {
  name        = "${var.project_name}-malicious-patterns-${var.environment}"
  description = "Regex patterns for detecting malicious input"
  scope       = "REGIONAL"

  regular_expression {
    regex_string = "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set)"
  }

  regular_expression {
    regex_string = "(?i)(<script|javascript:|onerror=|onload=|onclick=|onmouseover=)"
  }

  regular_expression {
    regex_string = "(?i)(\\.\\.[\\/\\\\]|%2e%2e|%252e%252e)"
  }

  regular_expression {
    regex_string = "(?i)(etc\\/passwd|windows\\/system32|cmd\\.exe|powershell\\.exe)"
  }

  tags = local.waf_tags
}

# CloudWatch Alarms for WAF
resource "aws_cloudwatch_metric_alarm" "waf_blocked_requests_high" {
  alarm_name          = "${var.project_name}-waf-blocked-requests-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1000"
  alarm_description   = "This metric monitors high number of blocked requests"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    WebACL = aws_wafv2_web_acl.sparc_waf.name
    Region = var.aws_region
  }

  tags = local.waf_tags
}

resource "aws_cloudwatch_metric_alarm" "waf_allowed_requests_low" {
  alarm_name          = "${var.project_name}-waf-allowed-requests-low-${var.environment}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "AllowedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors unusually low allowed requests"
  alarm_actions       = [var.sns_topic_arn]

  dimensions = {
    WebACL = aws_wafv2_web_acl.sparc_waf.name
    Region = var.aws_region
  }

  tags = local.waf_tags
}

# Outputs
output "waf_web_acl_id" {
  description = "The ID of the WAF WebACL"
  value       = aws_wafv2_web_acl.sparc_waf.id
}

output "waf_web_acl_arn" {
  description = "The ARN of the WAF WebACL"
  value       = aws_wafv2_web_acl.sparc_waf.arn
}

output "waf_web_acl_capacity" {
  description = "The capacity consumed by the WAF WebACL"
  value       = aws_wafv2_web_acl.sparc_waf.capacity
}