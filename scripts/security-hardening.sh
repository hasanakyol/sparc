#!/bin/bash

# SPARC Platform Infrastructure Security Hardening Script
# This script implements security hardening measures for infrastructure components

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/sparc-security-hardening-$(date +%Y%m%d-%H%M%S).log"
ENVIRONMENT="${ENVIRONMENT:-dev}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-aws}"

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

# Print colored output
print_status() {
    local status=$1
    local message=$2
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
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "error" "This script must be run as root"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_status "error" "Cannot detect OS"
        exit 1
    fi
    print_status "info" "Detected OS: $OS $VER"
}

# Update system packages
update_system() {
    print_status "info" "Updating system packages..."
    
    case $OS in
        "Ubuntu"|"Debian")
            apt-get update -y
            apt-get upgrade -y
            apt-get dist-upgrade -y
            apt-get autoremove -y
            ;;
        "CentOS Linux"|"Red Hat Enterprise Linux")
            yum update -y
            yum autoremove -y
            ;;
        "Amazon Linux"|"Amazon Linux 2")
            yum update -y
            ;;
        *)
            print_status "warning" "Unsupported OS for automatic updates"
            ;;
    esac
    
    print_status "success" "System packages updated"
}

# Install security tools
install_security_tools() {
    print_status "info" "Installing security tools..."
    
    case $OS in
        "Ubuntu"|"Debian")
            apt-get install -y \
                fail2ban \
                ufw \
                auditd \
                aide \
                rkhunter \
                lynis \
                clamav \
                clamav-daemon \
                apparmor \
                apparmor-utils \
                libpam-pwquality \
                unattended-upgrades
            ;;
        "CentOS Linux"|"Red Hat Enterprise Linux"|"Amazon Linux"|"Amazon Linux 2")
            yum install -y \
                fail2ban \
                firewalld \
                audit \
                aide \
                rkhunter \
                lynis \
                clamav \
                clamav-update \
                selinux-policy \
                selinux-policy-targeted
            ;;
    esac
    
    print_status "success" "Security tools installed"
}

# Configure firewall
configure_firewall() {
    print_status "info" "Configuring firewall..."
    
    case $OS in
        "Ubuntu"|"Debian")
            # Configure UFW
            ufw --force enable
            ufw default deny incoming
            ufw default allow outgoing
            
            # Allow SSH (rate limited)
            ufw limit 22/tcp
            
            # Allow HTTP/HTTPS
            ufw allow 80/tcp
            ufw allow 443/tcp
            
            # Allow specific ports for SPARC services
            ufw allow 3000/tcp comment 'SPARC API Gateway'
            ufw allow 3001/tcp comment 'SPARC Auth Service'
            ufw allow 3002/tcp comment 'SPARC Video Service'
            ufw allow 3003/tcp comment 'SPARC Web App'
            
            # Allow monitoring ports (internal only)
            ufw allow from 10.0.0.0/8 to any port 9090 comment 'Prometheus'
            ufw allow from 10.0.0.0/8 to any port 3100 comment 'Grafana'
            
            ufw reload
            ;;
            
        "CentOS Linux"|"Red Hat Enterprise Linux"|"Amazon Linux"|"Amazon Linux 2")
            # Configure firewalld
            systemctl start firewalld
            systemctl enable firewalld
            
            # Set default zone
            firewall-cmd --set-default-zone=public
            
            # Allow services
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            
            # Allow SPARC ports
            firewall-cmd --permanent --add-port=3000/tcp
            firewall-cmd --permanent --add-port=3001/tcp
            firewall-cmd --permanent --add-port=3002/tcp
            firewall-cmd --permanent --add-port=3003/tcp
            
            # Allow monitoring (internal)
            firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port protocol="tcp" port="9090" accept'
            firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port protocol="tcp" port="3100" accept'
            
            firewall-cmd --reload
            ;;
    esac
    
    print_status "success" "Firewall configured"
}

# Configure SSH hardening
harden_ssh() {
    print_status "info" "Hardening SSH configuration..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup-$(date +%Y%m%d)
    
    # SSH hardening settings
    cat > /etc/ssh/sshd_config.d/99-sparc-hardening.conf << EOF
# SPARC SSH Hardening Configuration

# Protocol and Port
Protocol 2
Port 22

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30

# Security
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Crypto
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Session
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
MaxSessions 4

# Banner
Banner /etc/ssh/banner.txt
EOF

    # Create SSH banner
    cat > /etc/ssh/banner.txt << EOF
******************************************************************************
*                           SPARC SECURITY PLATFORM                          *
*                                                                            *
* This system is for authorized use only. All activity is monitored and     *
* logged. Unauthorized access is prohibited and will be prosecuted.          *
*                                                                            *
* By accessing this system, you consent to monitoring and recording.         *
******************************************************************************
EOF

    # Restart SSH service
    systemctl restart sshd
    
    print_status "success" "SSH hardened"
}

# Configure kernel security parameters
configure_kernel_security() {
    print_status "info" "Configuring kernel security parameters..."
    
    # Backup original sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup-$(date +%Y%m%d)
    
    # Kernel security parameters
    cat > /etc/sysctl.d/99-sparc-security.conf << EOF
# SPARC Security Kernel Parameters

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore Directed pings
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP/IP SYN cookies
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable packet forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable ExecShield
kernel.exec-shield = 1
kernel.randomize_va_space = 2

# Increase system file descriptor limit
fs.file-max = 65535

# Allow for more PIDs
kernel.pid_max = 65535

# Increase system IP port limits
net.ipv4.ip_local_port_range = 2000 65000

# TCP optimization
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr

# Security restrictions
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
net.core.bpf_jit_harden = 2

# Disable magic SysRq key
kernel.sysrq = 0
EOF

    # Apply kernel parameters
    sysctl -p /etc/sysctl.d/99-sparc-security.conf
    
    print_status "success" "Kernel security parameters configured"
}

# Configure audit daemon
configure_auditd() {
    print_status "info" "Configuring audit daemon..."
    
    # Ensure auditd is running
    systemctl enable auditd
    systemctl start auditd
    
    # Configure audit rules
    cat > /etc/audit/rules.d/sparc-security.rules << EOF
# SPARC Security Audit Rules

# Remove any existing rules
-D

# Buffer size
-b 8192

# Failure mode
-f 1

# Monitor authentication
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Monitor file deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Monitor admin actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor SPARC-specific directories
-w /opt/sparc/ -p wa -k sparc_config
-w /var/log/sparc/ -p wa -k sparc_logs
-w /etc/sparc/ -p wa -k sparc_etc

# Make configuration immutable
-e 2
EOF

    # Reload audit rules
    augenrules --load
    
    print_status "success" "Audit daemon configured"
}

# Configure fail2ban
configure_fail2ban() {
    print_status "info" "Configuring fail2ban..."
    
    # Create SPARC-specific jail configuration
    cat > /etc/fail2ban/jail.d/sparc.conf << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = security@sparc.local
sender = fail2ban@sparc.local
action = %(action_mwl)s

[sshd]
enabled = true
port = 22
logpath = %(sshd_log)s
maxretry = 3
bantime = 7200

[sparc-api]
enabled = true
port = 3000,3001,3002,3003
filter = sparc-api
logpath = /var/log/sparc/api*.log
maxretry = 10
findtime = 300
bantime = 1800

[sparc-auth]
enabled = true
port = 3001
filter = sparc-auth
logpath = /var/log/sparc/auth*.log
maxretry = 5
findtime = 900
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

    # Create SPARC API filter
    cat > /etc/fail2ban/filter.d/sparc-api.conf << EOF
[Definition]
failregex = ^.*\[ERROR\].*Failed API request from <HOST>.*$
            ^.*\[WARN\].*Suspicious activity from <HOST>.*$
            ^.*HTTP\/\d\.\d\" 429.*$
ignoreregex =
EOF

    # Create SPARC Auth filter
    cat > /etc/fail2ban/filter.d/sparc-auth.conf << EOF
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
ignoreregex =
EOF

    # Start and enable fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    print_status "success" "Fail2ban configured"
}

# Configure file integrity monitoring
configure_aide() {
    print_status "info" "Configuring AIDE file integrity monitoring..."
    
    # Initialize AIDE database
    aideinit
    
    # Configure AIDE
    cat >> /etc/aide/aide.conf << EOF

# SPARC-specific monitoring
/opt/sparc p+i+n+u+g+s+b+m+c+md5+sha256
/etc/sparc p+i+n+u+g+s+b+m+c+md5+sha256
/usr/local/bin/sparc p+i+n+u+g+s+b+m+c+md5+sha256
EOF

    # Create cron job for daily AIDE checks
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Integrity Check Report" security@sparc.local
EOF
    
    chmod +x /etc/cron.daily/aide-check
    
    print_status "success" "AIDE configured"
}

# Configure ClamAV
configure_clamav() {
    print_status "info" "Configuring ClamAV antivirus..."
    
    # Update ClamAV database
    freshclam
    
    # Configure ClamAV
    cat > /etc/clamav/clamd.conf << EOF
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 666
User clamav
ScanPE true
ScanOLE2 true
ScanHTML true
ScanMail true
ScanArchive true
ArchiveBlockEncrypted false
MaxDirectoryRecursion 15
FollowDirectorySymlinks false
FollowFileSymlinks false
ReadTimeout 180
MaxThreads 12
MaxConnectionQueueLength 15
LogSyslog true
LogFacility LOG_LOCAL6
LogClean false
LogVerbose false
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly false
SelfCheck 3600
Foreground false
Debug false
ScanELF true
DetectBrokenExecutables false
ExitOnOOM false
LeaveTemporaryFiles false
AlgorithmicDetection true
ScanOLE2 true
OLE2BlockMacros false
AllowAllMatchScan true
CrossFilesystems true
PhishingSignatures true
PhishingScanURLs true
PhishingAlwaysBlockSSLMismatch false
PhishingAlwaysBlockCloak false
PartitionIntersection false
DetectPUA false
ScanPartialMessages false
HeuristicScanPrecedence false
StructuredDataDetection false
CommandReadTimeout 5
SendBufTimeout 200
MaxQueue 100
ExtendedDetectionInfo true
OLE2BlockMacros false
AllowAllMatchScan true
ForceToDisk false
DisableCertCheck false
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 16
MaxFiles 10000
MaxEmbeddedPE 10M
MaxHTMLNormalize 10M
MaxHTMLNoTags 2M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
MaxPartitions 50
MaxIconsPE 100
PCREMatchLimit 10000
PCRERecMatchLimit 5000
PCREMaxFileSize 25M
ScanXMLDOCS true
ScanHWP3 true
MaxRecHWP3 16
EOF

    # Enable ClamAV daemon
    systemctl enable clamav-daemon
    systemctl start clamav-daemon
    
    # Create daily scan script
    cat > /etc/cron.daily/clamav-scan << 'EOF'
#!/bin/bash
LOGFILE="/var/log/clamav/daily-scan.log"
echo "Starting ClamAV scan at $(date)" >> $LOGFILE
clamscan -r /home /var/www /opt/sparc --infected --log=$LOGFILE
echo "ClamAV scan completed at $(date)" >> $LOGFILE
EOF
    
    chmod +x /etc/cron.daily/clamav-scan
    
    print_status "success" "ClamAV configured"
}

# Configure AppArmor/SELinux
configure_mandatory_access_control() {
    print_status "info" "Configuring mandatory access control..."
    
    case $OS in
        "Ubuntu"|"Debian")
            # Configure AppArmor
            systemctl enable apparmor
            systemctl start apparmor
            
            # Create SPARC profile
            cat > /etc/apparmor.d/sparc-services << EOF
#include <tunables/global>

/opt/sparc/*/bin/* {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  capability net_bind_service,
  capability setuid,
  capability setgid,
  
  network inet stream,
  network inet6 stream,
  
  /opt/sparc/** r,
  /opt/sparc/*/bin/* ix,
  /var/log/sparc/** w,
  /tmp/** rw,
  
  /proc/sys/kernel/random/uuid r,
  /dev/urandom r,
}
EOF
            
            # Load profile
            apparmor_parser -r /etc/apparmor.d/sparc-services
            ;;
            
        "CentOS Linux"|"Red Hat Enterprise Linux"|"Amazon Linux"|"Amazon Linux 2")
            # Configure SELinux
            setenforce 1
            sed -i 's/SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            
            # Create SPARC SELinux policy
            # This would require more complex policy development
            print_status "info" "SELinux set to enforcing mode"
            ;;
    esac
    
    print_status "success" "Mandatory access control configured"
}

# Configure log rotation
configure_log_rotation() {
    print_status "info" "Configuring log rotation..."
    
    cat > /etc/logrotate.d/sparc << EOF
/var/log/sparc/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 sparc sparc
    sharedscripts
    postrotate
        /bin/kill -USR1 \$(cat /var/run/sparc/*.pid 2>/dev/null) 2>/dev/null || true
    endscript
}

/var/log/sparc/security/*.log {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 0600 root root
    sharedscripts
}
EOF
    
    print_status "success" "Log rotation configured"
}

# Configure automated security updates
configure_auto_updates() {
    print_status "info" "Configuring automated security updates..."
    
    case $OS in
        "Ubuntu"|"Debian")
            # Configure unattended-upgrades
            cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "security@sparc.local";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

            # Enable automatic updates
            cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
            ;;
            
        "CentOS Linux"|"Red Hat Enterprise Linux"|"Amazon Linux"|"Amazon Linux 2")
            # Configure yum-cron
            sed -i 's/apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
            sed -i 's/update_cmd = default/update_cmd = security/' /etc/yum/yum-cron.conf
            
            systemctl enable yum-cron
            systemctl start yum-cron
            ;;
    esac
    
    print_status "success" "Automated security updates configured"
}

# Create security report
generate_security_report() {
    print_status "info" "Generating security report..."
    
    REPORT_FILE="/var/log/sparc-security-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$REPORT_FILE" << EOF
SPARC Platform Security Hardening Report
Generated: $(date)
Environment: $ENVIRONMENT
Cloud Provider: $CLOUD_PROVIDER

System Information:
- OS: $OS $VER
- Kernel: $(uname -r)
- Hostname: $(hostname)

Security Measures Applied:
1. System packages updated
2. Security tools installed
3. Firewall configured
4. SSH hardened
5. Kernel security parameters set
6. Audit daemon configured
7. Fail2ban configured
8. File integrity monitoring (AIDE) configured
9. Antivirus (ClamAV) configured
10. Mandatory access control configured
11. Log rotation configured
12. Automated security updates enabled

Security Tool Status:
EOF

    # Check service status
    for service in sshd auditd fail2ban clamav-daemon apparmor firewalld ufw; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo "- $service: ACTIVE" >> "$REPORT_FILE"
        else
            echo "- $service: INACTIVE or NOT INSTALLED" >> "$REPORT_FILE"
        fi
    done
    
    # Run Lynis audit
    echo -e "\nLynis Security Audit Summary:" >> "$REPORT_FILE"
    lynis audit system --quick --quiet >> "$REPORT_FILE" 2>&1
    
    print_status "success" "Security report generated: $REPORT_FILE"
}

# Main execution
main() {
    log "INFO" "Starting SPARC infrastructure security hardening"
    
    check_root
    detect_os
    
    # Execute hardening steps
    update_system
    install_security_tools
    configure_firewall
    harden_ssh
    configure_kernel_security
    configure_auditd
    configure_fail2ban
    configure_aide
    configure_clamav
    configure_mandatory_access_control
    configure_log_rotation
    configure_auto_updates
    
    # Generate report
    generate_security_report
    
    print_status "success" "Security hardening completed successfully"
    log "INFO" "Security hardening completed. Report: $REPORT_FILE"
}

# Run main function
main "$@"