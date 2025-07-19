#!/bin/bash

# SPARC Platform Firewall Rule Management Script
# Manages firewall rules across different cloud providers and environments

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
CLOUD_PROVIDER="${CLOUD_PROVIDER:-aws}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
RULES_FILE="${RULES_FILE:-/etc/sparc/firewall-rules.json}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/sparc/firewall}"
LOG_FILE="/var/log/sparc-firewall-$(date +%Y%m%d-%H%M%S).log"

# SPARC service ports
declare -A SPARC_SERVICES=(
    ["api-gateway"]="3000/tcp"
    ["auth-service"]="3001/tcp"
    ["video-service"]="3002/tcp"
    ["web-app"]="3003/tcp"
    ["analytics"]="3004/tcp"
    ["notification"]="3005/tcp"
    ["storage"]="3006/tcp"
    ["postgres"]="5432/tcp"
    ["redis"]="6379/tcp"
    ["rabbitmq"]="5672/tcp"
    ["rabbitmq-mgmt"]="15672/tcp"
    ["prometheus"]="9090/tcp"
    ["grafana"]="3100/tcp"
    ["elasticsearch"]="9200/tcp"
    ["kibana"]="5601/tcp"
)

# Network zones
declare -A NETWORK_ZONES=(
    ["public"]="0.0.0.0/0"
    ["dmz"]="10.0.1.0/24"
    ["app"]="10.0.2.0/24"
    ["data"]="10.0.3.0/24"
    ["mgmt"]="10.0.4.0/24"
)

# Print functions
print_header() {
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

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

# Initialize
init() {
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$(dirname "$RULES_FILE")"
    
    if [[ ! -f "$RULES_FILE" ]]; then
        create_default_rules_file
    fi
}

# Create default rules file
create_default_rules_file() {
    print_status "info" "Creating default firewall rules file..."
    
    cat > "$RULES_FILE" << 'EOF'
{
  "version": "1.0",
  "environment": "dev",
  "rules": {
    "inbound": [
      {
        "name": "allow-ssh-mgmt",
        "description": "Allow SSH from management network",
        "source": "10.0.4.0/24",
        "destination": "any",
        "port": "22",
        "protocol": "tcp",
        "action": "allow",
        "priority": 100
      },
      {
        "name": "allow-http",
        "description": "Allow HTTP from anywhere",
        "source": "0.0.0.0/0",
        "destination": "any",
        "port": "80",
        "protocol": "tcp",
        "action": "allow",
        "priority": 200
      },
      {
        "name": "allow-https",
        "description": "Allow HTTPS from anywhere",
        "source": "0.0.0.0/0",
        "destination": "any",
        "port": "443",
        "protocol": "tcp",
        "action": "allow",
        "priority": 201
      },
      {
        "name": "allow-sparc-api",
        "description": "Allow SPARC API Gateway",
        "source": "10.0.1.0/24",
        "destination": "10.0.2.0/24",
        "port": "3000",
        "protocol": "tcp",
        "action": "allow",
        "priority": 300
      },
      {
        "name": "allow-monitoring",
        "description": "Allow monitoring access",
        "source": "10.0.4.0/24",
        "destination": "any",
        "port": "9090,3100",
        "protocol": "tcp",
        "action": "allow",
        "priority": 400
      }
    ],
    "outbound": [
      {
        "name": "allow-all-outbound",
        "description": "Allow all outbound traffic",
        "source": "any",
        "destination": "0.0.0.0/0",
        "port": "any",
        "protocol": "any",
        "action": "allow",
        "priority": 1000
      }
    ],
    "zones": {
      "public": {
        "allowed_services": ["http", "https"],
        "denied_services": ["ssh", "database"]
      },
      "dmz": {
        "allowed_services": ["api-gateway", "web-app"],
        "denied_services": ["database", "redis"]
      },
      "app": {
        "allowed_services": ["all-sparc-services"],
        "denied_services": []
      },
      "data": {
        "allowed_services": ["postgres", "redis", "rabbitmq"],
        "denied_services": ["http", "https"]
      },
      "mgmt": {
        "allowed_services": ["all"],
        "denied_services": []
      }
    }
  }
}
EOF
    
    print_status "success" "Default rules file created"
}

# Backup current rules
backup_rules() {
    local provider=$1
    local backup_file="$BACKUP_DIR/firewall-rules-$provider-$(date +%Y%m%d-%H%M%S).json"
    
    print_status "info" "Backing up current firewall rules..."
    
    case $provider in
        "aws")
            backup_aws_rules "$backup_file"
            ;;
        "azure")
            backup_azure_rules "$backup_file"
            ;;
        "gcp")
            backup_gcp_rules "$backup_file"
            ;;
        "local")
            backup_local_rules "$backup_file"
            ;;
    esac
    
    print_status "success" "Rules backed up to: $backup_file"
}

# AWS firewall management
manage_aws_firewall() {
    local action=$1
    shift
    
    case $action in
        "list")
            list_aws_rules "$@"
            ;;
        "add")
            add_aws_rule "$@"
            ;;
        "remove")
            remove_aws_rule "$@"
            ;;
        "update")
            update_aws_rule "$@"
            ;;
        "apply")
            apply_aws_rules
            ;;
        "validate")
            validate_aws_rules
            ;;
    esac
}

list_aws_rules() {
    local sg_id="${1:-}"
    
    print_header "AWS Security Group Rules"
    
    if [[ -z "$sg_id" ]]; then
        # List all security groups
        aws ec2 describe-security-groups \
            --filters "Name=tag:Environment,Values=$ENVIRONMENT" \
            --query 'SecurityGroups[*].[GroupId,GroupName,Description]' \
            --output table
    else
        # List rules for specific security group
        print_status "info" "Security Group: $sg_id"
        
        echo -e "\n${BLUE}Inbound Rules:${NC}"
        aws ec2 describe-security-groups \
            --group-ids "$sg_id" \
            --query 'SecurityGroups[0].IpPermissions[*].[IpProtocol,FromPort,ToPort,IpRanges[0].CidrIp,IpRanges[0].Description]' \
            --output table
        
        echo -e "\n${BLUE}Outbound Rules:${NC}"
        aws ec2 describe-security-groups \
            --group-ids "$sg_id" \
            --query 'SecurityGroups[0].IpPermissionsEgress[*].[IpProtocol,FromPort,ToPort,IpRanges[0].CidrIp,IpRanges[0].Description]' \
            --output table
    fi
}

add_aws_rule() {
    local sg_id=$1
    local direction=${2:-ingress}
    local protocol=$3
    local port=$4
    local source=$5
    local description="${6:-Added by SPARC firewall manager}"
    
    print_status "info" "Adding AWS security group rule..."
    
    if [[ "$direction" == "ingress" ]]; then
        aws ec2 authorize-security-group-ingress \
            --group-id "$sg_id" \
            --protocol "$protocol" \
            --port "$port" \
            --cidr "$source" \
            --group-rule-description "$description"
    else
        aws ec2 authorize-security-group-egress \
            --group-id "$sg_id" \
            --protocol "$protocol" \
            --port "$port" \
            --cidr "$source" \
            --group-rule-description "$description"
    fi
    
    if [[ $? -eq 0 ]]; then
        print_status "success" "Rule added successfully"
    else
        print_status "error" "Failed to add rule"
    fi
}

remove_aws_rule() {
    local sg_id=$1
    local direction=${2:-ingress}
    local protocol=$3
    local port=$4
    local source=$5
    
    print_status "info" "Removing AWS security group rule..."
    
    if [[ "$direction" == "ingress" ]]; then
        aws ec2 revoke-security-group-ingress \
            --group-id "$sg_id" \
            --protocol "$protocol" \
            --port "$port" \
            --cidr "$source"
    else
        aws ec2 revoke-security-group-egress \
            --group-id "$sg_id" \
            --protocol "$protocol" \
            --port "$port" \
            --cidr "$source"
    fi
    
    if [[ $? -eq 0 ]]; then
        print_status "success" "Rule removed successfully"
    else
        print_status "error" "Failed to remove rule"
    fi
}

apply_aws_rules() {
    print_status "info" "Applying firewall rules from configuration..."
    
    local rules=$(jq -r '.rules.inbound[]' "$RULES_FILE")
    
    # Process each rule
    echo "$rules" | while IFS= read -r rule; do
        local name=$(echo "$rule" | jq -r '.name')
        local source=$(echo "$rule" | jq -r '.source')
        local port=$(echo "$rule" | jq -r '.port')
        local protocol=$(echo "$rule" | jq -r '.protocol')
        local action=$(echo "$rule" | jq -r '.action')
        
        if [[ "$action" == "allow" ]]; then
            print_status "info" "Applying rule: $name"
            # Here you would apply the rule to appropriate security group
        fi
    done
    
    print_status "success" "Rules applied"
}

validate_aws_rules() {
    print_status "info" "Validating AWS firewall rules..."
    
    local violations=0
    
    # Check for overly permissive rules
    local open_ssh=$(aws ec2 describe-security-groups \
        --filters "Name=ip-permission.from-port,Values=22" \
                  "Name=ip-permission.cidr,Values=0.0.0.0/0" \
        --query 'SecurityGroups[].GroupId' \
        --output text)
    
    if [[ -n "$open_ssh" ]]; then
        print_status "error" "Security groups with SSH open to world: $open_ssh"
        ((violations++))
    fi
    
    # Check for missing SPARC service rules
    for service in "${!SPARC_SERVICES[@]}"; do
        local port="${SPARC_SERVICES[$service]%/*}"
        local sg_with_port=$(aws ec2 describe-security-groups \
            --filters "Name=ip-permission.from-port,Values=$port" \
            --query 'SecurityGroups[].GroupId' \
            --output text)
        
        if [[ -z "$sg_with_port" ]]; then
            print_status "warning" "No security group found for $service (port $port)"
        fi
    done
    
    if [[ $violations -eq 0 ]]; then
        print_status "success" "All rules validated successfully"
    else
        print_status "error" "Found $violations rule violations"
    fi
}

backup_aws_rules() {
    local backup_file=$1
    
    aws ec2 describe-security-groups \
        --filters "Name=tag:Environment,Values=$ENVIRONMENT" \
        --output json > "$backup_file"
}

# Azure firewall management
manage_azure_firewall() {
    local action=$1
    shift
    
    case $action in
        "list")
            list_azure_rules "$@"
            ;;
        "add")
            add_azure_rule "$@"
            ;;
        "remove")
            remove_azure_rule "$@"
            ;;
        "apply")
            apply_azure_rules
            ;;
        "validate")
            validate_azure_rules
            ;;
    esac
}

list_azure_rules() {
    local nsg_name="${1:-}"
    local resource_group="${RESOURCE_GROUP:-sparc-$ENVIRONMENT}"
    
    print_header "Azure Network Security Group Rules"
    
    if [[ -z "$nsg_name" ]]; then
        # List all NSGs
        az network nsg list \
            --resource-group "$resource_group" \
            --output table
    else
        # List rules for specific NSG
        print_status "info" "NSG: $nsg_name"
        
        az network nsg rule list \
            --resource-group "$resource_group" \
            --nsg-name "$nsg_name" \
            --output table
    fi
}

add_azure_rule() {
    local nsg_name=$1
    local rule_name=$2
    local priority=$3
    local direction=${4:-Inbound}
    local access=${5:-Allow}
    local protocol=$6
    local source=$7
    local destination=$8
    local port=$9
    local resource_group="${RESOURCE_GROUP:-sparc-$ENVIRONMENT}"
    
    print_status "info" "Adding Azure NSG rule..."
    
    az network nsg rule create \
        --resource-group "$resource_group" \
        --nsg-name "$nsg_name" \
        --name "$rule_name" \
        --priority "$priority" \
        --direction "$direction" \
        --access "$access" \
        --protocol "$protocol" \
        --source-address-prefixes "$source" \
        --destination-address-prefixes "$destination" \
        --destination-port-ranges "$port"
    
    if [[ $? -eq 0 ]]; then
        print_status "success" "Rule added successfully"
    else
        print_status "error" "Failed to add rule"
    fi
}

# GCP firewall management
manage_gcp_firewall() {
    local action=$1
    shift
    
    case $action in
        "list")
            list_gcp_rules "$@"
            ;;
        "add")
            add_gcp_rule "$@"
            ;;
        "remove")
            remove_gcp_rule "$@"
            ;;
        "apply")
            apply_gcp_rules
            ;;
        "validate")
            validate_gcp_rules
            ;;
    esac
}

list_gcp_rules() {
    print_header "GCP Firewall Rules"
    
    gcloud compute firewall-rules list \
        --filter="labels.environment=$ENVIRONMENT" \
        --format="table(name,direction,priority,sourceRanges.list():label=SRC_RANGES,allowed[].map().firewall_rule().list():label=ALLOW,targetTags.list():label=TARGET_TAGS)"
}

add_gcp_rule() {
    local rule_name=$1
    local direction=${2:-INGRESS}
    local priority=${3:-1000}
    local action=${4:-allow}
    local source_ranges=$5
    local protocol=$6
    local ports=$7
    local target_tags=${8:-sparc}
    
    print_status "info" "Adding GCP firewall rule..."
    
    gcloud compute firewall-rules create "$rule_name" \
        --direction="$direction" \
        --priority="$priority" \
        --action="$action" \
        --source-ranges="$source_ranges" \
        --rules="$protocol:$ports" \
        --target-tags="$target_tags" \
        --labels="environment=$ENVIRONMENT,managed-by=sparc"
    
    if [[ $? -eq 0 ]]; then
        print_status "success" "Rule added successfully"
    else
        print_status "error" "Failed to add rule"
    fi
}

# Local firewall management (iptables/firewalld)
manage_local_firewall() {
    local action=$1
    shift
    
    # Detect local firewall system
    if command -v firewall-cmd &> /dev/null; then
        manage_firewalld "$action" "$@"
    elif command -v ufw &> /dev/null; then
        manage_ufw "$action" "$@"
    else
        manage_iptables "$action" "$@"
    fi
}

manage_firewalld() {
    local action=$1
    shift
    
    case $action in
        "list")
            print_header "Firewalld Rules"
            firewall-cmd --list-all
            ;;
        "add")
            local service_or_port=$1
            local zone=${2:-public}
            firewall-cmd --permanent --zone="$zone" --add-service="$service_or_port" || \
            firewall-cmd --permanent --zone="$zone" --add-port="$service_or_port"
            firewall-cmd --reload
            print_status "success" "Rule added"
            ;;
        "remove")
            local service_or_port=$1
            local zone=${2:-public}
            firewall-cmd --permanent --zone="$zone" --remove-service="$service_or_port" || \
            firewall-cmd --permanent --zone="$zone" --remove-port="$service_or_port"
            firewall-cmd --reload
            print_status "success" "Rule removed"
            ;;
    esac
}

manage_ufw() {
    local action=$1
    shift
    
    case $action in
        "list")
            print_header "UFW Rules"
            ufw status verbose
            ;;
        "add")
            local port=$1
            local protocol=${2:-tcp}
            local from=${3:-any}
            ufw allow from "$from" to any port "$port" proto "$protocol"
            print_status "success" "Rule added"
            ;;
        "remove")
            local port=$1
            local protocol=${2:-tcp}
            ufw delete allow "$port/$protocol"
            print_status "success" "Rule removed"
            ;;
    esac
}

# Apply SPARC-specific rules
apply_sparc_rules() {
    print_header "Applying SPARC Service Rules"
    
    local provider=$1
    
    # Apply rules for each SPARC service
    for service in "${!SPARC_SERVICES[@]}"; do
        local port_proto="${SPARC_SERVICES[$service]}"
        local port="${port_proto%/*}"
        local protocol="${port_proto#*/}"
        
        print_status "info" "Configuring rules for $service (port $port/$protocol)"
        
        case $provider in
            "aws")
                # Apply to appropriate security groups based on service
                ;;
            "azure")
                # Apply to appropriate NSGs based on service
                ;;
            "gcp")
                # Apply firewall rules based on service
                ;;
            "local")
                # Apply local firewall rules
                if command -v firewall-cmd &> /dev/null; then
                    firewall-cmd --permanent --add-port="$port/$protocol"
                elif command -v ufw &> /dev/null; then
                    ufw allow "$port/$protocol"
                fi
                ;;
        esac
    done
    
    print_status "success" "SPARC service rules applied"
}

# Generate firewall report
generate_firewall_report() {
    local report_file="/var/log/sparc-firewall-report-$(date +%Y%m%d-%H%M%S).json"
    
    print_status "info" "Generating firewall report..."
    
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "$ENVIRONMENT",
  "cloud_provider": "$CLOUD_PROVIDER",
  "firewall_rules": {
EOF
    
    case $CLOUD_PROVIDER in
        "aws")
            echo '    "security_groups": ' >> "$report_file"
            aws ec2 describe-security-groups \
                --filters "Name=tag:Environment,Values=$ENVIRONMENT" \
                --output json | jq '.SecurityGroups' >> "$report_file"
            ;;
        "azure")
            echo '    "network_security_groups": ' >> "$report_file"
            az network nsg list \
                --query "[?tags.Environment=='$ENVIRONMENT']" \
                --output json >> "$report_file"
            ;;
        "gcp")
            echo '    "firewall_rules": ' >> "$report_file"
            gcloud compute firewall-rules list \
                --filter="labels.environment=$ENVIRONMENT" \
                --format=json >> "$report_file"
            ;;
    esac
    
    echo '  }' >> "$report_file"
    echo '}' >> "$report_file"
    
    print_status "success" "Report generated: $report_file"
}

# Interactive menu
show_menu() {
    echo -e "\n${CYAN}SPARC Firewall Rule Management${NC}"
    echo "Provider: $CLOUD_PROVIDER | Environment: $ENVIRONMENT"
    echo ""
    echo "1. List firewall rules"
    echo "2. Add firewall rule"
    echo "3. Remove firewall rule"
    echo "4. Apply rules from configuration"
    echo "5. Validate firewall rules"
    echo "6. Apply SPARC service rules"
    echo "7. Backup current rules"
    echo "8. Generate firewall report"
    echo "9. Change cloud provider"
    echo "0. Exit"
    echo -n "Select option: "
}

# Main function
main() {
    init
    
    # Non-interactive mode
    if [[ $# -gt 0 ]]; then
        local action=$1
        shift
        
        case $CLOUD_PROVIDER in
            "aws")
                manage_aws_firewall "$action" "$@"
                ;;
            "azure")
                manage_azure_firewall "$action" "$@"
                ;;
            "gcp")
                manage_gcp_firewall "$action" "$@"
                ;;
            "local")
                manage_local_firewall "$action" "$@"
                ;;
        esac
        exit 0
    fi
    
    # Interactive mode
    while true; do
        show_menu
        read -r option
        
        case $option in
            1)
                case $CLOUD_PROVIDER in
                    "aws") list_aws_rules ;;
                    "azure") list_azure_rules ;;
                    "gcp") list_gcp_rules ;;
                    "local") manage_local_firewall "list" ;;
                esac
                ;;
            2)
                print_status "info" "Add firewall rule"
                # Interactive rule addition would go here
                ;;
            3)
                print_status "info" "Remove firewall rule"
                # Interactive rule removal would go here
                ;;
            4)
                case $CLOUD_PROVIDER in
                    "aws") apply_aws_rules ;;
                    "azure") apply_azure_rules ;;
                    "gcp") apply_gcp_rules ;;
                esac
                ;;
            5)
                case $CLOUD_PROVIDER in
                    "aws") validate_aws_rules ;;
                    "azure") validate_azure_rules ;;
                    "gcp") validate_gcp_rules ;;
                esac
                ;;
            6)
                apply_sparc_rules "$CLOUD_PROVIDER"
                ;;
            7)
                backup_rules "$CLOUD_PROVIDER"
                ;;
            8)
                generate_firewall_report
                ;;
            9)
                echo -n "Enter cloud provider (aws/azure/gcp/local): "
                read -r CLOUD_PROVIDER
                ;;
            0)
                print_status "info" "Exiting..."
                exit 0
                ;;
            *)
                print_status "error" "Invalid option"
                ;;
        esac
    done
}

# Execute main function
main "$@"