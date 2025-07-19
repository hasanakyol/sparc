# OWASP Core Rule Set Configuration for SPARC Platform

terraform {
  required_version = ">= 1.0"
}

# OWASP CRS Variables and Configuration
locals {
  # OWASP Core Rule Set version
  owasp_crs_version = "3.3.5"
  
  # Paranoia levels (1-4, higher = more strict)
  paranoia_level = {
    dev     = 1
    staging = 2
    prod    = 3
  }
  
  # Anomaly scoring thresholds
  anomaly_thresholds = {
    inbound = {
      critical = 5
      error    = 4
      warning  = 3
      notice   = 2
    }
    outbound = {
      critical = 4
      error    = 3
      warning  = 2
      notice   = 1
    }
  }
}

# OWASP CRS Rule Categories for SPARC
variable "owasp_rule_categories" {
  description = "OWASP CRS rule categories to enable"
  type = object({
    protocol_enforcement     = bool
    protocol_attack          = bool
    application_attack_lfi   = bool
    application_attack_rfi   = bool
    application_attack_rce   = bool
    application_attack_php   = bool
    application_attack_xss   = bool
    application_attack_sqli  = bool
    application_attack_session = bool
    application_attack_java  = bool
    data_leakages           = bool
  })
  default = {
    protocol_enforcement     = true
    protocol_attack          = true
    application_attack_lfi   = true
    application_attack_rfi   = true
    application_attack_rce   = true
    application_attack_php   = false  # Not applicable for SPARC
    application_attack_xss   = true
    application_attack_sqli  = true
    application_attack_session = true
    application_attack_java  = false  # Not applicable for SPARC
    data_leakages           = true
  }
}

# SPARC-specific OWASP rule customizations
variable "sparc_owasp_customizations" {
  description = "SPARC-specific customizations for OWASP rules"
  type = object({
    # Video streaming specific
    allow_large_file_uploads = bool
    max_file_size_mb        = number
    allowed_file_extensions = list(string)
    
    # API specific
    allowed_http_methods    = list(string)
    allowed_content_types   = list(string)
    max_json_depth         = number
    
    # Security specific
    block_scanner_user_agents = bool
    block_common_exploits    = bool
    enable_ip_reputation     = bool
  })
  default = {
    # Video streaming
    allow_large_file_uploads = true
    max_file_size_mb        = 5000  # 5GB for video files
    allowed_file_extensions = [
      "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm",  # Video
      "jpg", "jpeg", "png", "gif", "bmp", "svg",         # Images
      "pdf", "doc", "docx", "xls", "xlsx",               # Documents
      "zip", "tar", "gz", "7z"                           # Archives
    ]
    
    # API
    allowed_http_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    allowed_content_types = [
      "application/json",
      "application/xml",
      "multipart/form-data",
      "application/x-www-form-urlencoded",
      "video/mp4",
      "video/webm",
      "image/jpeg",
      "image/png"
    ]
    max_json_depth = 10
    
    # Security
    block_scanner_user_agents = true
    block_common_exploits    = true
    enable_ip_reputation     = true
  }
}

# Output OWASP rule configuration for use in WAF modules
output "owasp_rules_config" {
  description = "OWASP CRS configuration for WAF"
  value = {
    # Rule IDs to disable (false positives for SPARC)
    disabled_rules = [
      # Protocol Enforcement
      "920230",  # Missing Accept header (API clients may not send)
      "920300",  # Missing Host header (handled by load balancer)
      "920350",  # Host header is IP address (development environments)
      
      # Application Attack
      "942100",  # SQL Injection Attack (false positive on video metadata)
      "942200",  # SQL Injection Attack (false positive on incident descriptions)
      "942430",  # Restricted SQL Character Anomaly Detection (alerts/incidents may contain SQL-like text)
      
      # Session Fixation
      "943100",  # Possible Session Fixation Attack (JWT tokens in headers)
      
      # Data Leakages
      "953120",  # Possible Server Side Include (SSI) injection (video timestamps)
    ]
    
    # Rule-specific configurations
    rule_configurations = {
      # REQUEST-901: Initialization
      "901001" = {
        paranoia_level = local.paranoia_level[var.environment]
      }
      
      # REQUEST-903: IP Reputation
      "903001" = {
        enabled = var.sparc_owasp_customizations.enable_ip_reputation
      }
      
      # REQUEST-905: Common Exceptions
      "905100" = {
        allowed_methods = join("|", var.sparc_owasp_customizations.allowed_http_methods)
      }
      "905110" = {
        allowed_content_types = join("|", var.sparc_owasp_customizations.allowed_content_types)
      }
      
      # REQUEST-913: Scanner Detection
      "913100" = {
        enabled = var.sparc_owasp_customizations.block_scanner_user_agents
        blocked_user_agents = [
          "nikto", "sqlmap", "nessus", "metasploit", "burp",
          "owasp", "zaproxy", "gobuster", "dirb", "wfuzz"
        ]
      }
      
      # REQUEST-920: Protocol Enforcement
      "920170" = {
        allowed_methods = var.sparc_owasp_customizations.allowed_http_methods
      }
      "920420" = {
        allowed_content_types = var.sparc_owasp_customizations.allowed_content_types
      }
      
      # REQUEST-930: Application Attack LFI
      "930100" = {
        restricted_paths = [
          "/etc/", "/proc/", "/var/", "/usr/",
          "C:\\", "\\windows\\", "\\system32\\"
        ]
      }
      
      # REQUEST-931: Application Attack RFI
      "931130" = {
        blocked_extensions = [
          "php", "phtml", "php3", "php4", "php5",
          "asp", "aspx", "jsp", "jspx"
        ]
      }
      
      # REQUEST-941: Application Attack XSS
      "941100" = {
        xss_score_threshold = 5
      }
      
      # REQUEST-942: Application Attack SQLi
      "942100" = {
        sqli_score_threshold = 5
        excluded_parameters = [
          "description",
          "incident_details",
          "alert_message",
          "metadata"
        ]
      }
    }
    
    # Custom rules for SPARC
    custom_sparc_rules = [
      {
        id          = "9001001"
        description = "Block video streaming exploitation attempts"
        expression  = "REQUEST_URI \"@rx (?i)(rtsp|rtmp|hls|dash).*(<script|javascript:|onerror=)\""
        action      = "block"
        severity    = "critical"
      },
      {
        id          = "9001002"
        description = "Block camera control exploitation"
        expression  = "REQUEST_URI \"@rx (?i)/api/cameras/.*/control.*[';\\\"\\)\\(]\""
        action      = "block"
        severity    = "critical"
      },
      {
        id          = "9001003"
        description = "Block incident system SQL injection"
        expression  = "ARGS \"@rx (?i)(incident|alert|event).*(union.*select|exec.*xp_)\""
        action      = "block"
        severity    = "critical"
      },
      {
        id          = "9001004"
        description = "Rate limit video download requests"
        expression  = "REQUEST_URI \"@rx (?i)/api/videos/.*/download\""
        action      = "rate_limit"
        rate_limit  = 10
        period      = 3600  # 1 hour
      },
      {
        id          = "9001005"
        description = "Protect administrative endpoints"
        expression  = "REQUEST_URI \"@beginsWith /api/admin/\" && !REMOTE_ADDR \"@ipMatch 10.0.0.0/8,172.16.0.0/12\""
        action      = "block"
        severity    = "critical"
      }
    ]
    
    # Anomaly scoring configuration
    anomaly_scoring = {
      # Inbound anomaly score thresholds
      inbound_anomaly_score_threshold = {
        critical = local.anomaly_thresholds.inbound.critical
        error    = local.anomaly_thresholds.inbound.error
        warning  = local.anomaly_thresholds.inbound.warning
        notice   = local.anomaly_thresholds.inbound.notice
      }
      
      # Outbound anomaly score thresholds
      outbound_anomaly_score_threshold = {
        critical = local.anomaly_thresholds.outbound.critical
        error    = local.anomaly_thresholds.outbound.error
        warning  = local.anomaly_thresholds.outbound.warning
        notice   = local.anomaly_thresholds.outbound.notice
      }
      
      # Actions based on anomaly scores
      anomaly_score_actions = {
        5 = "block"
        4 = "challenge"
        3 = "log"
        2 = "log"
        1 = "pass"
      }
    }
    
    # Exclusions for SPARC-specific paths
    path_exclusions = [
      {
        path = "/api/videos/upload"
        exclusions = [
          "920420",  # Content-Type validation (multipart uploads)
          "920180"   # POST without Content-Length
        ]
      },
      {
        path = "/api/streams/rtsp"
        exclusions = [
          "920170",  # GET/HEAD with body
          "920280"   # Missing/empty Host header
        ]
      },
      {
        path = "/health"
        exclusions = [
          "920280",  # Missing Host header
          "920230"   # Missing Accept header
        ]
      }
    ]
  }
}

# Environment-specific OWASP configurations
output "environment_owasp_config" {
  description = "Environment-specific OWASP configurations"
  value = {
    dev = {
      mode           = "detection"
      paranoia_level = 1
      sampling_rate  = 100
      log_level      = "debug"
    }
    staging = {
      mode           = "mixed"  # Block critical, detect others
      paranoia_level = 2
      sampling_rate  = 50
      log_level      = "info"
    }
    prod = {
      mode           = "prevention"
      paranoia_level = 3
      sampling_rate  = 10
      log_level      = "warning"
    }
  }
}

# Variable for environment
variable "environment" {
  description = "Environment name"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}