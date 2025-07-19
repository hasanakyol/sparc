# Encryption module for SPARC platform
# Manages KMS keys, policies, and encryption configuration

# KMS Master Key for Database Encryption
resource "aws_kms_key" "database" {
  description             = "SPARC Database Encryption Key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name        = "sparc-database-key"
    Environment = var.environment
    Purpose     = "database-encryption"
  }
}

resource "aws_kms_alias" "database" {
  name          = "alias/sparc-database-${var.environment}"
  target_key_id = aws_kms_key.database.key_id
}

# KMS Key for Application Encryption
resource "aws_kms_key" "application" {
  description             = "SPARC Application Encryption Key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name        = "sparc-application-key"
    Environment = var.environment
    Purpose     = "application-encryption"
  }
}

resource "aws_kms_alias" "application" {
  name          = "alias/sparc-application-${var.environment}"
  target_key_id = aws_kms_key.application.key_id
}

# KMS Key for Backup Encryption
resource "aws_kms_key" "backup" {
  description             = "SPARC Backup Encryption Key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name        = "sparc-backup-key"
    Environment = var.environment
    Purpose     = "backup-encryption"
  }
}

resource "aws_kms_alias" "backup" {
  name          = "alias/sparc-backup-${var.environment}"
  target_key_id = aws_kms_key.backup.key_id
}

# KMS Key for Storage Encryption
resource "aws_kms_key" "storage" {
  description             = "SPARC Storage Encryption Key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name        = "sparc-storage-key"
    Environment = var.environment
    Purpose     = "storage-encryption"
  }
}

resource "aws_kms_alias" "storage" {
  name          = "alias/sparc-storage-${var.environment}"
  target_key_id = aws_kms_key.storage.key_id
}

# IAM Policy for Database Service
resource "aws_iam_policy" "database_encryption" {
  name        = "sparc-database-encryption-${var.environment}"
  description = "Policy for database encryption operations"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.database.arn]
      }
    ]
  })
}

# IAM Policy for Application Service
resource "aws_iam_policy" "application_encryption" {
  name        = "sparc-application-encryption-${var.environment}"
  description = "Policy for application encryption operations"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.application.arn]
      }
    ]
  })
}

# S3 Bucket for Encrypted Backups
resource "aws_s3_bucket" "backups" {
  bucket = "sparc-backups-${var.environment}-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Name        = "sparc-backups"
    Environment = var.environment
  }
}

# Enable versioning for backup bucket
resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption for backup bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.backup.arn
    }
    bucket_key_enabled = true
  }
}

# S3 Bucket for Encrypted Video Storage
resource "aws_s3_bucket" "video_storage" {
  bucket = "sparc-videos-${var.environment}-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Name        = "sparc-video-storage"
    Environment = var.environment
  }
}

# Enable encryption for video storage
resource "aws_s3_bucket_server_side_encryption_configuration" "video_storage" {
  bucket = aws_s3_bucket.video_storage.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
    bucket_key_enabled = true
  }
}

# Secrets Manager for Application Keys
resource "aws_secretsmanager_secret" "encryption_keys" {
  name                    = "sparc-encryption-keys-${var.environment}"
  description             = "Encryption keys for SPARC application"
  kms_key_id              = aws_kms_key.application.id
  recovery_window_in_days = 30
  
  tags = {
    Name        = "sparc-encryption-keys"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "encryption_keys" {
  secret_id = aws_secretsmanager_secret.encryption_keys.id
  
  secret_string = jsonencode({
    ENCRYPTION_KEY = random_password.encryption_key.result
    HASH_SALT      = random_password.hash_salt.result
    JWT_SECRET     = random_password.jwt_secret.result
  })
}

# Generate secure random keys
resource "random_password" "encryption_key" {
  length  = 32
  special = true
}

resource "random_password" "hash_salt" {
  length  = 32
  special = true
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

# CloudWatch Log Group for Encryption Monitoring
resource "aws_cloudwatch_log_group" "encryption_logs" {
  name              = "/aws/sparc/encryption/${var.environment}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.application.arn
  
  tags = {
    Name        = "sparc-encryption-logs"
    Environment = var.environment
  }
}

# CloudWatch Metric Alarms
resource "aws_cloudwatch_metric_alarm" "kms_key_usage" {
  alarm_name          = "sparc-kms-key-usage-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfOperations"
  namespace           = "AWS/KMS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10000"
  alarm_description   = "Alert when KMS key usage is high"
  
  dimensions = {
    KeyId = aws_kms_key.application.id
  }
  
  alarm_actions = [var.sns_alert_topic_arn]
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Variables
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "sns_alert_topic_arn" {
  description = "SNS topic ARN for alerts"
  type        = string
}

# Outputs
output "database_key_id" {
  value       = aws_kms_key.database.id
  description = "Database encryption KMS key ID"
}

output "application_key_id" {
  value       = aws_kms_key.application.id
  description = "Application encryption KMS key ID"
}

output "backup_key_id" {
  value       = aws_kms_key.backup.id
  description = "Backup encryption KMS key ID"
}

output "storage_key_id" {
  value       = aws_kms_key.storage.id
  description = "Storage encryption KMS key ID"
}

output "backup_bucket_name" {
  value       = aws_s3_bucket.backups.id
  description = "Encrypted backup bucket name"
}

output "video_storage_bucket_name" {
  value       = aws_s3_bucket.video_storage.id
  description = "Encrypted video storage bucket name"
}

output "encryption_keys_secret_arn" {
  value       = aws_secretsmanager_secret.encryption_keys.arn
  description = "ARN of the encryption keys secret"
}