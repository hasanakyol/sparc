# AWS Shield Advanced DDoS Protection Module for SPARC Platform

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

variable "enable_shield_advanced" {
  description = "Enable AWS Shield Advanced (requires subscription)"
  type        = bool
  default     = false
}

variable "protected_resources" {
  description = "List of resources to protect with Shield Advanced"
  type = list(object({
    resource_arn = string
    name         = string
    type         = string  # ELB, CF, EC2, ROUTE53
  }))
  default = []
}

variable "emergency_contacts" {
  description = "Emergency contacts for DDoS Response Team (DRT)"
  type = list(object({
    email_address = string
    phone_number  = string
    contact_notes = string
  }))
  default = []
}

variable "enable_proactive_engagement" {
  description = "Enable proactive engagement with DRT"
  type        = bool
  default     = true
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

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# SNS Topic for DDoS alerts
resource "aws_sns_topic" "ddos_alerts" {
  name              = "${local.name}-alerts"
  display_name      = "SPARC DDoS Protection Alerts"
  kms_master_key_id = var.kms_key_id

  tags = local.common_tags
}

# Subscribe emergency contacts to SNS topic
resource "aws_sns_topic_subscription" "emergency_contacts" {
  for_each = { for idx, contact in var.emergency_contacts : idx => contact }
  
  topic_arn = aws_sns_topic.ddos_alerts.arn
  protocol  = "email"
  endpoint  = each.value.email_address
}

# Shield Advanced Subscription (if enabled)
resource "aws_shield_subscription" "advanced" {
  count = var.enable_shield_advanced ? 1 : 0

  # Note: Shield Advanced has a monthly fee
  # Ensure billing alerts are set up
}

# Shield Advanced Protection for resources
resource "aws_shield_protection" "resources" {
  for_each = var.enable_shield_advanced ? { for idx, resource in var.protected_resources : resource.name => resource } : {}

  name         = "${local.name}-${each.key}"
  resource_arn = each.value.resource_arn

  tags = local.common_tags
}

# Shield Advanced Protection Group
resource "aws_shield_protection_group" "main" {
  count = var.enable_shield_advanced && length(var.protected_resources) > 0 ? 1 : 0

  protection_group_id = "${local.name}-group"
  aggregation        = "SUM"
  pattern           = "ALL"
  
  members = [for resource in var.protected_resources : resource.resource_arn]

  tags = local.common_tags
}

# DRT Access Role
resource "aws_iam_role" "drt_access" {
  count = var.enable_shield_advanced ? 1 : 0

  name = "${local.name}-drt-access-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "drt.shield.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

# DRT Access Policy
resource "aws_iam_role_policy" "drt_access" {
  count = var.enable_shield_advanced ? 1 : 0

  name = "${local.name}-drt-access-policy"
  role = aws_iam_role.drt_access[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:DescribeAlarms",
          "cloudwatch:GetMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "route53:ListHostedZones",
          "route53:ListResourceRecordSets",
          "wafv2:GetWebACL",
          "wafv2:ListWebACLs",
          "cloudfront:ListDistributions",
          "cloudfront:GetDistribution"
        ]
        Resource = "*"
      }
    ]
  })
}

# Associate DRT Role with Shield
resource "aws_shield_drt_access_role_arn_association" "main" {
  count = var.enable_shield_advanced ? 1 : 0

  role_arn = aws_iam_role.drt_access[0].arn
}

# Enable Proactive Engagement
resource "aws_shield_proactive_engagement" "main" {
  count = var.enable_shield_advanced && var.enable_proactive_engagement ? 1 : 0

  enabled = true

  dynamic "emergency_contact" {
    for_each = var.emergency_contacts
    content {
      email_address = emergency_contact.value.email_address
      phone_number  = emergency_contact.value.phone_number
      contact_notes = emergency_contact.value.contact_notes
    }
  }
}

# CloudWatch Dashboard for DDoS Monitoring
resource "aws_cloudwatch_dashboard" "ddos_monitoring" {
  dashboard_name = "${local.name}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # DDoS Detection Events
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/DDoSProtection", "DDoSDetected", { stat = "Sum", period = 300 }],
            [".", "DDoSAttackBitsPerSecond", { stat = "Maximum", period = 300 }],
            [".", "DDoSAttackPacketsPerSecond", { stat = "Maximum", period = 300 }],
            [".", "DDoSAttackRequestsPerSecond", { stat = "Maximum", period = 300 }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "DDoS Detection Overview"
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      # Attack Vectors
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/DDoSProtection", "AttackVectorCharacterization", "AttackVector", "UDP", { stat = "Sum" }],
            ["...", "TCP_SYN", { stat = "Sum" }],
            ["...", "REQUEST_FLOOD", { stat = "Sum" }],
            ["...", "ACK_FLOOD", { stat = "Sum" }]
          ]
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
          title  = "Attack Vectors"
        }
      },
      # Protected Resources Health
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          metrics = [
            for resource in var.protected_resources : [
              "AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", split("/", resource.resource_arn)[1],
              { label = resource.name }
            ] if resource.type == "ELB"
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Protected Resources Response Time"
        }
      }
    ]
  })
}

# CloudWatch Alarms for DDoS Detection
resource "aws_cloudwatch_metric_alarm" "ddos_detected" {
  alarm_name          = "${local.name}-ddos-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "DDoSDetected"
  namespace           = "AWS/DDoSProtection"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "DDoS attack detected on SPARC infrastructure"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.ddos_alerts.arn]
  ok_actions    = [aws_sns_topic.ddos_alerts.arn]

  tags = local.common_tags
}

# Application-level DDoS mitigation using WAF rules
resource "aws_wafv2_rate_based_rule" "ddos_mitigation" {
  name        = "${local.name}-rate-limit"
  scope       = "REGIONAL"
  description = "Application-level DDoS mitigation"

  action {
    block {}
  }

  statement {
    rate_based_statement {
      limit              = 10000  # Requests per 5 minutes
      aggregate_key_type = "IP"
      
      scope_down_statement {
        not_statement {
          statement {
            ip_set_reference_statement {
              arn = var.trusted_ip_set_arn
            }
          }
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-rate-limit"
    sampled_requests_enabled   = true
  }
}

# EventBridge Rule for DDoS Events
resource "aws_cloudwatch_event_rule" "ddos_events" {
  name        = "${local.name}-events"
  description = "Capture DDoS protection events"

  event_pattern = jsonencode({
    source      = ["aws.shield"]
    detail-type = ["DDoS Protection Event"]
  })

  tags = local.common_tags
}

# EventBridge Target for DDoS Events
resource "aws_cloudwatch_event_target" "ddos_sns" {
  rule      = aws_cloudwatch_event_rule.ddos_events.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.ddos_alerts.arn
}

# Lambda function for automated DDoS response
resource "aws_lambda_function" "ddos_response" {
  filename         = data.archive_file.ddos_response.output_path
  function_name    = "${local.name}-response"
  role            = aws_iam_role.ddos_response_lambda.arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.ddos_response.output_base64sha256
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 512

  environment {
    variables = {
      ENVIRONMENT = var.environment
      SNS_TOPIC   = aws_sns_topic.ddos_alerts.arn
    }
  }

  tags = local.common_tags
}

# IAM Role for DDoS Response Lambda
resource "aws_iam_role" "ddos_response_lambda" {
  name = "${local.name}-response-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# IAM Policy for DDoS Response Lambda
resource "aws_iam_role_policy" "ddos_response_lambda" {
  name = "${local.name}-response-lambda-policy"
  role = aws_iam_role.ddos_response_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.ddos_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "wafv2:UpdateWebACL",
          "wafv2:GetWebACL",
          "ec2:DescribeSecurityGroups",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "route53:ChangeResourceRecordSets"
        ]
        Resource = "*"
      }
    ]
  })
}

# Archive file for Lambda function
data "archive_file" "ddos_response" {
  type        = "zip"
  output_path = "/tmp/ddos_response.zip"
  
  source {
    content  = file("${path.module}/lambda/ddos_response.py")
    filename = "index.py"
  }
}

# EventBridge rule to trigger Lambda on DDoS events
resource "aws_cloudwatch_event_target" "ddos_lambda" {
  rule      = aws_cloudwatch_event_rule.ddos_events.name
  target_id = "DDoSResponseLambda"
  arn       = aws_lambda_function.ddos_response.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "ddos_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ddos_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ddos_events.arn
}

# Outputs
output "shield_advanced_enabled" {
  description = "Whether Shield Advanced is enabled"
  value       = var.enable_shield_advanced
}

output "protected_resources" {
  description = "List of protected resources"
  value       = var.enable_shield_advanced ? var.protected_resources : []
}

output "ddos_alerts_topic_arn" {
  description = "ARN of the DDoS alerts SNS topic"
  value       = aws_sns_topic.ddos_alerts.arn
}

output "ddos_response_lambda_arn" {
  description = "ARN of the DDoS response Lambda function"
  value       = aws_lambda_function.ddos_response.arn
}

output "dashboard_url" {
  description = "URL to the DDoS monitoring dashboard"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.ddos_monitoring.dashboard_name}"
}

# Additional variables
variable "kms_key_id" {
  description = "KMS key ID for encryption"
  type        = string
  default     = null
}

variable "trusted_ip_set_arn" {
  description = "ARN of the trusted IP set for rate limiting exclusions"
  type        = string
  default     = ""
}