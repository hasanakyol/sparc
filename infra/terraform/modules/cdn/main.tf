terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider for us-east-1 region (required for CloudFront)
provider "aws" {
  alias = "us_east_1"
  region = "us-east-1"
}

# CloudFront distribution for global content delivery
resource "aws_cloudfront_distribution" "sparc_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "SPARC CDN Distribution"
  default_root_object = "index.html"
  price_class         = "PriceClass_All"
  
  # Multiple origins for different content types
  
  # Static assets origin
  origin {
    domain_name = aws_s3_bucket.static_assets.bucket_regional_domain_name
    origin_id   = "S3-static-assets"
    
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.static_assets.cloudfront_access_identity_path
    }
  }
  
  # API Gateway origin
  origin {
    domain_name = var.api_gateway_domain
    origin_id   = "API-Gateway"
    
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      
      origin_keepalive_timeout = 60
      origin_read_timeout      = 30
    }
    
    custom_header {
      name  = "X-CDN-Request"
      value = "true"
    }
  }
  
  # Video streaming origin with shield
  origin {
    domain_name = var.video_streaming_domain
    origin_id   = "Video-Streaming"
    
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
    
    origin_shield {
      enabled              = true
      origin_shield_region = var.shield_region
    }
  }
  
  # S3 origin for video storage as specified in fix.md
  origin {
    domain_name = aws_s3_bucket.video_bucket.bucket_regional_domain_name
    origin_id   = "S3-video-storage"
    
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.video_oai.cloudfront_access_identity_path
    }
  }
  
  # Default cache behavior for static assets
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "S3-static-assets"
    
    forwarded_values {
      query_string = false
      headers      = ["Origin", "Access-Control-Request-Headers", "Access-Control-Request-Method"]
      
      cookies {
        forward = "none"
      }
    }
    
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400   # 1 day
    max_ttl                = 31536000 # 1 year
    compress               = true
    
    # Lambda@Edge functions
    lambda_function_association {
      event_type   = "viewer-request"
      lambda_arn   = aws_lambda_function.edge_auth.qualified_arn
      include_body = false
    }
    
    lambda_function_association {
      event_type   = "origin-response"
      lambda_arn   = aws_lambda_function.edge_headers.qualified_arn
      include_body = false
    }
  }
  
  # API cache behavior
  ordered_cache_behavior {
    path_pattern     = "/api/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "API-Gateway"
    
    forwarded_values {
      query_string = true
      headers      = ["*"]
      
      cookies {
        forward = "all"
      }
    }
    
    viewer_protocol_policy = "https-only"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 300 # 5 minutes max cache for API
    compress               = true
    
    # Cache based on authorization header
    cache_policy_id = aws_cloudfront_cache_policy.api_cache_policy.id
  }
  
  # Video streaming behavior - optimized for S3 storage as per fix.md
  ordered_cache_behavior {
    path_pattern     = "/video/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-video-storage"
    
    forwarded_values {
      query_string = true
      headers      = ["Range", "Origin", "Access-Control-Request-Headers", "Access-Control-Request-Method"]
      
      cookies {
        forward = "none"
      }
    }
    
    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400   # 1 day as specified in fix.md
    max_ttl                = 31536000 # 1 year for long-term video caching
    compress               = false    # Don't compress video
    
    # Enable smooth streaming
    smooth_streaming = true
    
    # Field-level encryption for sensitive video metadata
    field_level_encryption_id = aws_cloudfront_field_level_encryption_config.video_metadata.id
  }
  
  # WebSocket behavior
  ordered_cache_behavior {
    path_pattern     = "/ws/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "API-Gateway"
    
    forwarded_values {
      query_string = true
      headers      = ["*"]
      
      cookies {
        forward = "all"
      }
    }
    
    viewer_protocol_policy = "https-only"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
    compress               = false
  }
  
  # Custom error pages
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/error/403.html"
    error_caching_min_ttl = 300
  }
  
  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/error/404.html"
    error_caching_min_ttl = 300
  }
  
  custom_error_response {
    error_code            = 500
    response_code         = 200
    response_page_path    = "/error/500.html"
    error_caching_min_ttl = 60
  }
  
  # Geo restrictions
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  
  # SSL configuration
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cdn_cert.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
  
  # WAF association
  web_acl_id = aws_wafv2_web_acl.cdn_waf.arn
  
  # Logging
  logging_config {
    bucket          = aws_s3_bucket.cdn_logs.bucket_domain_name
    prefix          = "cloudfront/"
    include_cookies = false
  }
  
  # Real-time log configuration
  realtime_log_config_arn = aws_cloudfront_realtime_log_config.main.arn
  
  tags = {
    Name        = "sparc-cdn"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Cache policy for API endpoints
resource "aws_cloudfront_cache_policy" "api_cache_policy" {
  name        = "sparc-api-cache-policy"
  comment     = "Cache policy for SPARC API endpoints"
  default_ttl = 60
  max_ttl     = 300
  min_ttl     = 0
  
  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
    
    cookies_config {
      cookie_behavior = "none"
    }
    
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["Authorization", "X-Tenant-ID"]
      }
    }
    
    query_strings_config {
      query_string_behavior = "all"
    }
  }
}

# Origin request policy
resource "aws_cloudfront_origin_request_policy" "api_origin_policy" {
  name    = "sparc-api-origin-policy"
  comment = "Origin request policy for SPARC API"
  
  cookies_config {
    cookie_behavior = "all"
  }
  
  headers_config {
    header_behavior = "allViewer"
  }
  
  query_strings_config {
    query_string_behavior = "all"
  }
}

# Response headers policy
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name    = "sparc-security-headers"
  comment = "Security headers for SPARC CDN"
  
  security_headers_config {
    content_type_options {
      override = true
    }
    
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
    
    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' wss: https:; media-src 'self' blob: https:; object-src 'none'; frame-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests;"
      override                = true
    }
  }
  
  cors_config {
    access_control_allow_credentials = true
    
    access_control_allow_headers {
      items = ["*"]
    }
    
    access_control_allow_methods {
      items = ["GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"]
    }
    
    access_control_allow_origins {
      items = [var.allowed_origins]
    }
    
    access_control_expose_headers {
      items = ["X-Request-ID", "X-Trace-ID"]
    }
    
    access_control_max_age_sec = 86400
    origin_override            = true
  }
  
  custom_headers_config {
    items {
      header   = "X-CDN-Provider"
      value    = "CloudFront"
      override = false
    }
    
    items {
      header   = "X-Environment"
      value    = var.environment
      override = false
    }
  }
}

# Real-time log configuration
resource "aws_cloudfront_realtime_log_config" "main" {
  name = "sparc-realtime-logs"
  
  endpoint {
    stream_type = "Kinesis"
    
    kinesis_stream_config {
      role_arn   = aws_iam_role.cloudfront_logging.arn
      stream_arn = aws_kinesis_data_stream.cdn_logs.arn
    }
  }
  
  fields = [
    "timestamp",
    "c-ip",
    "c-country",
    "cs-method",
    "cs-uri-stem",
    "sc-status",
    "sc-bytes",
    "time-taken",
    "x-edge-location",
    "x-edge-request-id",
    "x-host-header",
    "cs-protocol",
    "cs-bytes",
    "x-edge-response-result-type",
    "cs-referer",
    "cs-user-agent",
    "x-edge-detailed-result-type"
  ]
  
  sampling_rate = 100
}

# Lambda@Edge function for authentication
resource "aws_lambda_function" "edge_auth" {
  filename         = "edge-auth.zip"
  function_name    = "sparc-edge-auth"
  role            = aws_iam_role.lambda_edge.arn
  handler         = "index.handler"
  source_code_hash = filebase64sha256("edge-auth.zip")
  runtime         = "nodejs18.x"
  timeout         = 5
  memory_size     = 128
  publish         = true
  
  environment {
    variables = {
      JWT_PUBLIC_KEY = var.jwt_public_key
    }
  }
}

# Lambda@Edge function for response headers
resource "aws_lambda_function" "edge_headers" {
  filename         = "edge-headers.zip"
  function_name    = "sparc-edge-headers"
  role            = aws_iam_role.lambda_edge.arn
  handler         = "index.handler"
  source_code_hash = filebase64sha256("edge-headers.zip")
  runtime         = "nodejs18.x"
  timeout         = 5
  memory_size     = 128
  publish         = true
}

# Field-level encryption for sensitive data
resource "aws_cloudfront_field_level_encryption_config" "video_metadata" {
  comment = "Encryption for sensitive video metadata"
  
  content_type_profile_config {
    forward_when_content_type_is_unknown = false
    
    content_type_profiles {
      items {
        content_type = "application/json"
        format       = "URLEncoded"
        
        profile_id = aws_cloudfront_field_level_encryption_profile.video_profile.id
      }
    }
  }
  
  query_arg_profile_config {
    forward_when_query_arg_profile_is_unknown = false
    
    query_arg_profiles {
      items {
        query_arg  = "metadata"
        profile_id = aws_cloudfront_field_level_encryption_profile.video_profile.id
      }
    }
  }
}

# Encryption profile
resource "aws_cloudfront_field_level_encryption_profile" "video_profile" {
  comment = "Video metadata encryption profile"
  name    = "sparc-video-metadata"
  
  encryption_entities {
    items {
      public_key_id = aws_cloudfront_public_key.encryption_key.id
      provider_id   = "sparc-video-provider"
      
      field_patterns {
        items = ["metadata.*", "location.*"]
      }
    }
  }
}

# S3 bucket for static assets
resource "aws_s3_bucket" "static_assets" {
  bucket = "${var.project_name}-static-assets-${var.environment}"
  
  tags = {
    Name        = "${var.project_name}-static-assets"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Origin Access Identity for static assets
resource "aws_cloudfront_origin_access_identity" "static_assets" {
  comment = "OAI for ${var.project_name} static assets"
}

# S3 bucket policy for static assets
resource "aws_s3_bucket_policy" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.static_assets.iam_arn
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.static_assets.arn}/*"
      }
    ]
  })
}

# S3 bucket for video storage
resource "aws_s3_bucket" "video_bucket" {
  bucket = "${var.project_name}-video-storage-${var.environment}"
  
  tags = {
    Name        = "${var.project_name}-video-storage"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# S3 bucket versioning
resource "aws_s3_bucket_versioning" "video_bucket" {
  bucket = aws_s3_bucket.video_bucket.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket lifecycle rules for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "video_bucket" {
  bucket = aws_s3_bucket.video_bucket.id
  
  rule {
    id     = "archive-old-videos"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365
    }
  }
}

# S3 bucket for CDN logs
resource "aws_s3_bucket" "cdn_logs" {
  bucket = "${var.project_name}-cdn-logs-${var.environment}"
  
  tags = {
    Name        = "${var.project_name}-cdn-logs"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Origin Access Identity for video bucket
resource "aws_cloudfront_origin_access_identity" "video_oai" {
  comment = "OAI for ${var.project_name} video bucket"
}

# S3 bucket policy for CloudFront access
resource "aws_s3_bucket_policy" "video_bucket" {
  bucket = aws_s3_bucket.video_bucket.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.video_oai.iam_arn
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.video_bucket.arn}/*"
      }
    ]
  })
}

# ACM Certificate for CloudFront
resource "aws_acm_certificate" "cdn_cert" {
  provider          = aws.us_east_1  # CloudFront requires certificates in us-east-1
  domain_name       = var.cdn_domain_name
  validation_method = "DNS"
  
  subject_alternative_names = [
    "*.${var.cdn_domain_name}"
  ]
  
  lifecycle {
    create_before_destroy = true
  }
  
  tags = {
    Name        = "${var.project_name}-cdn-cert"
    Environment = var.environment
  }
}

# WAF Web ACL for CloudFront
resource "aws_wafv2_web_acl" "cdn_waf" {
  provider = aws.us_east_1  # CloudFront requires WAF in us-east-1
  name     = "${var.project_name}-cdn-waf"
  scope    = "CLOUDFRONT"
  
  default_action {
    allow {}
  }
  
  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1
    
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }
  
  # SQL injection protection
  rule {
    name     = "SQLiProtection"
    priority = 2
    
    action {
      block {}
    }
    
    statement {
      or_statement {
        statement {
          sqli_match_statement {
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
          sqli_match_statement {
            field_to_match {
              body {}
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
      metric_name                = "SQLiProtection"
      sampled_requests_enabled   = true
    }
  }
  
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-cdn-waf"
    sampled_requests_enabled   = true
  }
  
  tags = {
    Name        = "${var.project_name}-cdn-waf"
    Environment = var.environment
  }
}

# Kinesis Data Stream for real-time logs
resource "aws_kinesis_data_stream" "cdn_logs" {
  name             = "${var.project_name}-cdn-logs"
  shard_count      = 1
  retention_period = 24
  
  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"
  
  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]
  
  tags = {
    Name        = "${var.project_name}-cdn-logs"
    Environment = var.environment
  }
}

# IAM Role for CloudFront logging
resource "aws_iam_role" "cloudfront_logging" {
  name = "${var.project_name}-cloudfront-logging"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudfront.amazonaws.com"
      }
    }]
  })
}

# IAM Policy for CloudFront logging
resource "aws_iam_role_policy" "cloudfront_logging" {
  name = "${var.project_name}-cloudfront-logging"
  role = aws_iam_role.cloudfront_logging.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kinesis:PutRecord",
        "kinesis:PutRecords"
      ]
      Resource = aws_kinesis_data_stream.cdn_logs.arn
    }]
  })
}

# IAM Role for Lambda@Edge
resource "aws_iam_role" "lambda_edge" {
  name = "${var.project_name}-lambda-edge"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "edgelambda.amazonaws.com"
          ]
        }
      }
    ]
  })
}

# IAM Policy for Lambda@Edge
resource "aws_iam_role_policy_attachment" "lambda_edge" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_edge.name
}

# CloudFront Public Key for field-level encryption
resource "aws_cloudfront_public_key" "encryption_key" {
  name        = "${var.project_name}-field-encryption"
  encoded_key = var.field_encryption_public_key
  comment     = "Public key for field-level encryption"
}

# CloudWatch Alarms for CDN monitoring
resource "aws_cloudwatch_metric_alarm" "cdn_4xx_errors" {
  alarm_name          = "${var.project_name}-cdn-4xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "4xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "5"
  alarm_description   = "This metric monitors CloudFront 4xx error rate"
  treat_missing_data  = "notBreaching"
  
  dimensions = {
    DistributionId = aws_cloudfront_distribution.sparc_cdn.id
  }
  
  alarm_actions = [var.sns_alert_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "cdn_5xx_errors" {
  alarm_name          = "${var.project_name}-cdn-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors CloudFront 5xx error rate"
  treat_missing_data  = "notBreaching"
  
  dimensions = {
    DistributionId = aws_cloudfront_distribution.sparc_cdn.id
  }
  
  alarm_actions = [var.sns_alert_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "cdn_origin_latency" {
  alarm_name          = "${var.project_name}-cdn-origin-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "OriginLatency"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "1000"
  alarm_description   = "This metric monitors CloudFront origin latency"
  treat_missing_data  = "notBreaching"
  
  dimensions = {
    DistributionId = aws_cloudfront_distribution.sparc_cdn.id
  }
  
  alarm_actions = [var.sns_alert_topic_arn]
}

# Outputs
output "cdn_domain_name" {
  value       = aws_cloudfront_distribution.sparc_cdn.domain_name
  description = "CloudFront distribution domain name"
}

output "cdn_distribution_id" {
  value       = aws_cloudfront_distribution.sparc_cdn.id
  description = "CloudFront distribution ID"
}

output "cdn_arn" {
  value       = aws_cloudfront_distribution.sparc_cdn.arn
  description = "CloudFront distribution ARN"
}

output "video_bucket_name" {
  value       = aws_s3_bucket.video_bucket.id
  description = "S3 video storage bucket name"
}

output "video_bucket_arn" {
  value       = aws_s3_bucket.video_bucket.arn
  description = "S3 video storage bucket ARN"
}