variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "sparc"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "api_gateway_domain" {
  description = "Domain name of the API Gateway"
  type        = string
}

variable "video_streaming_domain" {
  description = "Domain name of the video streaming service"
  type        = string
}

variable "shield_region" {
  description = "AWS region for Origin Shield"
  type        = string
  default     = "us-east-1"
}

variable "allowed_origins" {
  description = "Allowed origins for CORS"
  type        = list(string)
  default     = ["*"]
}

variable "jwt_public_key" {
  description = "Public key for JWT verification in Lambda@Edge"
  type        = string
  sensitive   = true
}

variable "sns_alert_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms"
  type        = string
}

variable "enable_geo_restrictions" {
  description = "Enable geographical restrictions"
  type        = bool
  default     = false
}

variable "geo_restriction_locations" {
  description = "List of country codes for geo restrictions"
  type        = list(string)
  default     = []
}

variable "geo_restriction_type" {
  description = "Type of geo restriction (whitelist or blacklist)"
  type        = string
  default     = "none"
}

variable "cdn_domain_name" {
  description = "Domain name for the CDN (e.g., cdn.example.com)"
  type        = string
}

variable "field_encryption_public_key" {
  description = "Public key for field-level encryption"
  type        = string
  sensitive   = true
}