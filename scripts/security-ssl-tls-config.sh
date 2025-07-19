#!/bin/bash

# SPARC Platform SSL/TLS Configuration Script
# Configures and validates SSL/TLS settings for maximum security

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENVIRONMENT="${ENVIRONMENT:-dev}"
DOMAIN="${DOMAIN:-sparc.local}"
CERT_DIR="/etc/sparc/ssl"
NGINX_DIR="/etc/nginx"
LOG_FILE="/var/log/sparc-ssl-config-$(date +%Y%m%d-%H%M%S).log"

# SSL/TLS Configuration Standards
TLS_PROTOCOLS="TLSv1.2 TLSv1.3"
CIPHER_SUITE="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
ECDH_CURVE="X25519:secp384r1:secp521r1"
DH_PARAM_SIZE=4096

# Print functions
print_status() {
    local status=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $status in
        "success")
            echo -e "${GREEN}✓${NC} ${message}"
            ;;
        "error")
            echo -e "${RED}✗${NC} ${message}"
            ;;
        "warning")
            echo -e "${YELLOW}⚠${NC} ${message}"
            ;;
        "info")
            echo -e "${BLUE}ℹ${NC} ${message}"
            ;;
    esac
    
    echo "${timestamp} [${status^^}] ${message}" >> "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    print_status "info" "Checking prerequisites..."
    
    local missing_tools=()
    
    for tool in openssl nginx certbot curl jq; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_status "error" "Missing required tools: ${missing_tools[*]}"
        print_status "info" "Installing missing tools..."
        
        if [[ -f /etc/debian_version ]]; then
            apt-get update && apt-get install -y "${missing_tools[@]}"
        elif [[ -f /etc/redhat-release ]]; then
            yum install -y "${missing_tools[@]}"
        else
            print_status "error" "Please install missing tools manually"
            exit 1
        fi
    fi
    
    print_status "success" "All prerequisites met"
}

# Create directory structure
create_directories() {
    print_status "info" "Creating SSL/TLS directory structure..."
    
    mkdir -p "$CERT_DIR"/{certs,private,csr,dhparam}
    chmod 755 "$CERT_DIR"
    chmod 755 "$CERT_DIR"/{certs,csr}
    chmod 700 "$CERT_DIR"/private
    chmod 755 "$CERT_DIR"/dhparam
    
    print_status "success" "Directory structure created"
}

# Generate Diffie-Hellman parameters
generate_dhparam() {
    print_status "info" "Generating Diffie-Hellman parameters (this may take a while)..."
    
    if [[ ! -f "$CERT_DIR/dhparam/dhparam-$DH_PARAM_SIZE.pem" ]]; then
        openssl dhparam -out "$CERT_DIR/dhparam/dhparam-$DH_PARAM_SIZE.pem" $DH_PARAM_SIZE
        chmod 644 "$CERT_DIR/dhparam/dhparam-$DH_PARAM_SIZE.pem"
        print_status "success" "DH parameters generated"
    else
        print_status "info" "DH parameters already exist"
    fi
}

# Generate self-signed certificate for development
generate_self_signed_cert() {
    local cn="${1:-$DOMAIN}"
    
    print_status "info" "Generating self-signed certificate for $cn..."
    
    # Generate private key
    openssl genrsa -out "$CERT_DIR/private/$cn.key" 4096
    chmod 600 "$CERT_DIR/private/$cn.key"
    
    # Generate certificate
    openssl req -new -x509 -key "$CERT_DIR/private/$cn.key" \
        -out "$CERT_DIR/certs/$cn.crt" \
        -days 365 \
        -subj "/C=US/ST=State/L=City/O=SPARC/OU=Security/CN=$cn" \
        -addext "subjectAltName=DNS:$cn,DNS:*.$cn,IP:127.0.0.1"
    
    chmod 644 "$CERT_DIR/certs/$cn.crt"
    
    print_status "success" "Self-signed certificate generated"
}

# Configure Let's Encrypt for production
configure_letsencrypt() {
    local domain=$1
    local email="${2:-security@$domain}"
    
    print_status "info" "Configuring Let's Encrypt for $domain..."
    
    # Check if running in production
    if [[ "$ENVIRONMENT" != "prod" ]]; then
        print_status "warning" "Let's Encrypt should only be used in production"
        return
    fi
    
    # Use certbot to obtain certificate
    certbot certonly \
        --non-interactive \
        --agree-tos \
        --email "$email" \
        --webroot \
        --webroot-path /var/www/html \
        --domains "$domain,www.$domain" \
        --expand
    
    # Create renewal hook
    cat > /etc/letsencrypt/renewal-hooks/deploy/sparc-reload.sh << 'EOF'
#!/bin/bash
systemctl reload nginx
systemctl reload sparc-api-gateway || true
EOF
    
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/sparc-reload.sh
    
    # Enable auto-renewal
    systemctl enable certbot.timer
    systemctl start certbot.timer
    
    print_status "success" "Let's Encrypt configured with auto-renewal"
}

# Configure Nginx SSL/TLS
configure_nginx_ssl() {
    print_status "info" "Configuring Nginx SSL/TLS settings..."
    
    # Create SSL configuration snippet
    cat > "$NGINX_DIR/snippets/ssl-params.conf" << EOF
# SPARC SSL/TLS Security Configuration
# Based on Mozilla SSL Configuration Generator

# SSL protocols
ssl_protocols $TLS_PROTOCOLS;

# SSL ciphers
ssl_ciphers '$CIPHER_SUITE';
ssl_prefer_server_ciphers off;

# ECDH Curve
ssl_ecdh_curve $ECDH_CURVE;

# DH parameters
ssl_dhparam $CERT_DIR/dhparam/dhparam-$DH_PARAM_SIZE.pem;

# SSL session settings
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# Security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; media-src 'self' https:; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self' https:;" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()" always;

# Certificate Transparency
add_header Expect-CT "max-age=86400, enforce" always;
EOF
    
    # Create main SSL site configuration
    cat > "$NGINX_DIR/sites-available/sparc-ssl" << EOF
# SPARC Platform SSL Configuration

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN www.$DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

# Main HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN www.$DOMAIN;
    
    # SSL certificate
    ssl_certificate $CERT_DIR/certs/$DOMAIN.crt;
    ssl_certificate_key $CERT_DIR/private/$DOMAIN.key;
    
    # Include SSL parameters
    include snippets/ssl-params.conf;
    
    # Logging
    access_log /var/log/nginx/sparc-ssl-access.log;
    error_log /var/log/nginx/sparc-ssl-error.log;
    
    # Root directory
    root /var/www/sparc;
    index index.html;
    
    # Security
    client_max_body_size 100M;
    client_body_timeout 60;
    client_header_timeout 60;
    keepalive_timeout 65;
    send_timeout 60;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1000;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # API Gateway proxy
    location /api/ {
        proxy_pass http://localhost:3000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Security headers for API
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
    
    # Web application
    location / {
        try_files \$uri \$uri/ /index.html;
        
        # Security for static files
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        return 404;
    }
}

# Additional server blocks for subdomains
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name api.$DOMAIN;
    
    ssl_certificate $CERT_DIR/certs/$DOMAIN.crt;
    ssl_certificate_key $CERT_DIR/private/$DOMAIN.key;
    include snippets/ssl-params.conf;
    
    location / {
        proxy_pass http://localhost:3000;
        include snippets/proxy-params.conf;
    }
}
EOF
    
    # Create proxy parameters snippet
    cat > "$NGINX_DIR/snippets/proxy-params.conf" << 'EOF'
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection 'upgrade';
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Request-ID $request_id;
proxy_cache_bypass $http_upgrade;
proxy_read_timeout 300s;
proxy_connect_timeout 75s;
proxy_hide_header X-Powered-By;
proxy_hide_header Server;
EOF
    
    # Enable the site
    ln -sf "$NGINX_DIR/sites-available/sparc-ssl" "$NGINX_DIR/sites-enabled/"
    
    print_status "success" "Nginx SSL/TLS configured"
}

# Configure application SSL/TLS settings
configure_app_ssl() {
    print_status "info" "Configuring application SSL/TLS settings..."
    
    # Create TLS configuration for Node.js applications
    cat > /etc/sparc/tls-config.json << EOF
{
  "tls": {
    "minVersion": "TLSv1.2",
    "maxVersion": "TLSv1.3",
    "ciphers": "$CIPHER_SUITE",
    "ecdhCurve": "$ECDH_CURVE",
    "honorCipherOrder": false,
    "secureOptions": [
      "SSL_OP_NO_SSLv2",
      "SSL_OP_NO_SSLv3",
      "SSL_OP_NO_TLSv1",
      "SSL_OP_NO_TLSv1_1",
      "SSL_OP_NO_COMPRESSION",
      "SSL_OP_NO_TICKET"
    ]
  },
  "https": {
    "cert": "$CERT_DIR/certs/$DOMAIN.crt",
    "key": "$CERT_DIR/private/$DOMAIN.key",
    "ca": "$CERT_DIR/certs/ca-bundle.crt",
    "dhparam": "$CERT_DIR/dhparam/dhparam-$DH_PARAM_SIZE.pem"
  },
  "security": {
    "hsts": {
      "maxAge": 63072000,
      "includeSubDomains": true,
      "preload": true
    },
    "contentSecurityPolicy": {
      "directives": {
        "defaultSrc": ["'self'"],
        "scriptSrc": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        "styleSrc": ["'self'", "'unsafe-inline'"],
        "imgSrc": ["'self'", "data:", "https:"],
        "connectSrc": ["'self'", "https:", "wss:"],
        "fontSrc": ["'self'", "data:", "https:"],
        "objectSrc": ["'none'"],
        "mediaSrc": ["'self'", "https:"],
        "frameSrc": ["'self'"]
      }
    }
  }
}
EOF
    
    # Create environment-specific TLS configs
    for env in dev staging prod; do
        cat > /etc/sparc/tls-config-$env.json << EOF
{
  "extends": "/etc/sparc/tls-config.json",
  "environment": "$env",
  "strictSSL": $([ "$env" = "prod" ] && echo "true" || echo "false"),
  "rejectUnauthorized": $([ "$env" = "prod" ] && echo "true" || echo "false")
}
EOF
    done
    
    print_status "success" "Application SSL/TLS settings configured"
}

# Validate SSL/TLS configuration
validate_ssl_config() {
    print_status "info" "Validating SSL/TLS configuration..."
    
    # Test Nginx configuration
    if nginx -t 2>/dev/null; then
        print_status "success" "Nginx configuration is valid"
    else
        print_status "error" "Nginx configuration has errors"
        nginx -t
        return 1
    fi
    
    # Test SSL certificate
    if [[ -f "$CERT_DIR/certs/$DOMAIN.crt" ]]; then
        local cert_info=$(openssl x509 -in "$CERT_DIR/certs/$DOMAIN.crt" -noout -text)
        local expiry=$(openssl x509 -in "$CERT_DIR/certs/$DOMAIN.crt" -noout -enddate | cut -d= -f2)
        
        print_status "info" "Certificate expires: $expiry"
        
        # Check key strength
        local key_bits=$(openssl rsa -in "$CERT_DIR/private/$DOMAIN.key" -text -noout 2>/dev/null | grep "Private-Key:" | grep -oP '\d+')
        if [[ $key_bits -ge 2048 ]]; then
            print_status "success" "Key strength: $key_bits bits (secure)"
        else
            print_status "warning" "Key strength: $key_bits bits (should be at least 2048)"
        fi
    fi
    
    # Reload Nginx to apply changes
    systemctl reload nginx
    
    print_status "success" "SSL/TLS configuration validated"
}

# SSL/TLS security scan
run_ssl_scan() {
    local domain="${1:-$DOMAIN}"
    local port="${2:-443}"
    
    print_status "info" "Running SSL/TLS security scan for $domain:$port..."
    
    # Check SSL Labs grade (simulated for offline use)
    # In production, you would use: curl -s "https://api.ssllabs.com/api/v3/analyze?host=$domain"
    
    # Local SSL/TLS tests
    echo -e "\n=== SSL/TLS Protocol Support ==="
    for protocol in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        if timeout 5 openssl s_client -connect "$domain:$port" -$protocol < /dev/null 2>/dev/null | grep -q "CONNECTED"; then
            case $protocol in
                ssl2|ssl3|tls1|tls1_1)
                    print_status "error" "$protocol: ENABLED (insecure)"
                    ;;
                tls1_2|tls1_3)
                    print_status "success" "$protocol: ENABLED (secure)"
                    ;;
            esac
        else
            case $protocol in
                ssl2|ssl3|tls1|tls1_1)
                    print_status "success" "$protocol: DISABLED (good)"
                    ;;
                tls1_2|tls1_3)
                    print_status "warning" "$protocol: DISABLED"
                    ;;
            esac
        fi
    done
    
    echo -e "\n=== Cipher Suite Analysis ==="
    local ciphers=$(openssl s_client -connect "$domain:$port" -cipher 'ALL:eNULL' < /dev/null 2>/dev/null | grep "Cipher" | awk '{print $3}')
    if [[ -n "$ciphers" ]]; then
        print_status "info" "Negotiated cipher: $ciphers"
    fi
    
    echo -e "\n=== Certificate Chain ==="
    openssl s_client -connect "$domain:$port" -showcerts < /dev/null 2>/dev/null | grep -E "s:|i:"
    
    echo -e "\n=== Security Headers ==="
    local headers=$(curl -sI "https://$domain" | grep -iE "strict-transport-security|x-frame-options|x-content-type-options|content-security-policy")
    if [[ -n "$headers" ]]; then
        echo "$headers"
        print_status "success" "Security headers present"
    else
        print_status "warning" "Some security headers may be missing"
    fi
}

# Generate SSL/TLS report
generate_ssl_report() {
    local report_file="/var/log/sparc-ssl-report-$(date +%Y%m%d-%H%M%S).json"
    
    print_status "info" "Generating SSL/TLS security report..."
    
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "$ENVIRONMENT",
  "domain": "$DOMAIN",
  "configuration": {
    "tls_protocols": "$TLS_PROTOCOLS",
    "cipher_suite": "$CIPHER_SUITE",
    "ecdh_curve": "$ECDH_CURVE",
    "dh_param_size": $DH_PARAM_SIZE
  },
  "certificate": {
EOF
    
    if [[ -f "$CERT_DIR/certs/$DOMAIN.crt" ]]; then
        local subject=$(openssl x509 -in "$CERT_DIR/certs/$DOMAIN.crt" -noout -subject | sed 's/subject=//')
        local issuer=$(openssl x509 -in "$CERT_DIR/certs/$DOMAIN.crt" -noout -issuer | sed 's/issuer=//')
        local start=$(openssl x509 -in "$CERT_DIR/certs/$DOMAIN.crt" -noout -startdate | sed 's/notBefore=//')
        local end=$(openssl x509 -in "$CERT_DIR/certs/$DOMAIN.crt" -noout -enddate | sed 's/notAfter=//')
        local serial=$(openssl x509 -in "$CERT_DIR/certs/$DOMAIN.crt" -noout -serial | sed 's/serial=//')
        
        cat >> "$report_file" << EOF
    "subject": "$subject",
    "issuer": "$issuer",
    "valid_from": "$start",
    "valid_to": "$end",
    "serial": "$serial"
EOF
    fi
    
    cat >> "$report_file" << EOF
  },
  "validation_status": "complete"
}
EOF
    
    print_status "success" "SSL/TLS report generated: $report_file"
}

# Main menu
show_menu() {
    echo -e "\n${BLUE}SPARC SSL/TLS Configuration Menu${NC}"
    echo "1. Full SSL/TLS setup (recommended)"
    echo "2. Generate self-signed certificate"
    echo "3. Configure Let's Encrypt"
    echo "4. Configure Nginx SSL"
    echo "5. Validate configuration"
    echo "6. Run SSL security scan"
    echo "7. Generate report"
    echo "8. Exit"
    echo -n "Select option: "
}

# Main function
main() {
    print_status "info" "SPARC SSL/TLS Configuration Script"
    print_status "info" "Environment: $ENVIRONMENT"
    print_status "info" "Domain: $DOMAIN"
    
    # Check if running interactively
    if [[ -t 0 ]]; then
        while true; do
            show_menu
            read -r option
            
            case $option in
                1)
                    check_prerequisites
                    create_directories
                    generate_dhparam
                    if [[ "$ENVIRONMENT" == "prod" ]]; then
                        configure_letsencrypt "$DOMAIN"
                    else
                        generate_self_signed_cert "$DOMAIN"
                    fi
                    configure_nginx_ssl
                    configure_app_ssl
                    validate_ssl_config
                    run_ssl_scan "$DOMAIN"
                    generate_ssl_report
                    ;;
                2)
                    create_directories
                    generate_self_signed_cert "$DOMAIN"
                    ;;
                3)
                    configure_letsencrypt "$DOMAIN"
                    ;;
                4)
                    configure_nginx_ssl
                    ;;
                5)
                    validate_ssl_config
                    ;;
                6)
                    run_ssl_scan "$DOMAIN"
                    ;;
                7)
                    generate_ssl_report
                    ;;
                8)
                    print_status "info" "Exiting..."
                    exit 0
                    ;;
                *)
                    print_status "error" "Invalid option"
                    ;;
            esac
        done
    else
        # Non-interactive mode - run full setup
        check_prerequisites
        create_directories
        generate_dhparam
        if [[ "$ENVIRONMENT" == "prod" ]]; then
            configure_letsencrypt "$DOMAIN"
        else
            generate_self_signed_cert "$DOMAIN"
        fi
        configure_nginx_ssl
        configure_app_ssl
        validate_ssl_config
        generate_ssl_report
    fi
}

# Execute main function
main "$@"