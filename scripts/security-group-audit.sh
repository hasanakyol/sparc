#!/bin/bash

# SPARC Platform Security Group Auditing Script
# Audits and reports on security group configurations across cloud providers

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
CLOUD_PROVIDER="${CLOUD_PROVIDER:-aws}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
AUDIT_REPORT="/var/log/sparc-sg-audit-$(date +%Y%m%d-%H%M%S).json"
COMPLIANCE_RULES_FILE="${COMPLIANCE_RULES:-/etc/sparc/sg-compliance-rules.json}"

# Risk levels
declare -A RISK_SCORES=(
    ["critical"]=10
    ["high"]=7
    ["medium"]=5
    ["low"]=3
    ["info"]=1
)

# Common risky ports
declare -A RISKY_PORTS=(
    ["22"]="SSH"
    ["23"]="Telnet"
    ["135"]="RPC"
    ["139"]="NetBIOS"
    ["445"]="SMB"
    ["1433"]="MSSQL"
    ["3306"]="MySQL"
    ["3389"]="RDP"
    ["5432"]="PostgreSQL"
    ["5984"]="CouchDB"
    ["6379"]="Redis"
    ["7001"]="Cassandra"
    ["8020"]="Hadoop"
    ["9200"]="Elasticsearch"
    ["27017"]="MongoDB"
)

# Print functions
print_header() {
    echo -e "\n${MAGENTA}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
    echo -e "${MAGENTA}$1${NC}"
    echo -e "${MAGENTA}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}"
}

print_status() {
    local status=$1
    local message=$2
    
    case $status in
        "critical")
            echo -e "${RED}[CRITICAL]${NC} ${message}"
            ;;
        "high")
            echo -e "${RED}[HIGH]${NC} ${message}"
            ;;
        "medium")
            echo -e "${YELLOW}[MEDIUM]${NC} ${message}"
            ;;
        "low")
            echo -e "${BLUE}[LOW]${NC} ${message}"
            ;;
        "pass")
            echo -e "${GREEN}[PASS]${NC} ${message}"
            ;;
        "info")
            echo -e "${CYAN}[INFO]${NC} ${message}"
            ;;
    esac
}

# Initialize audit report
init_audit_report() {
    cat > "$AUDIT_REPORT" << EOF
{
  "audit_metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "environment": "$ENVIRONMENT",
    "cloud_provider": "$CLOUD_PROVIDER",
    "auditor": "$(whoami)@$(hostname)"
  },
  "summary": {
    "total_security_groups": 0,
    "total_rules": 0,
    "critical_findings": 0,
    "high_findings": 0,
    "medium_findings": 0,
    "low_findings": 0,
    "compliance_score": 0
  },
  "findings": [],
  "security_groups": []
}
EOF
}

# Create default compliance rules
create_default_compliance_rules() {
    cat > "$COMPLIANCE_RULES_FILE" << 'EOF'
{
  "version": "1.0",
  "compliance_standards": ["CIS", "PCI-DSS", "HIPAA", "SOC2"],
  "rules": [
    {
      "id": "SG-001",
      "name": "No unrestricted SSH access",
      "description": "SSH (port 22) should not be open to 0.0.0.0/0",
      "severity": "critical",
      "check": {
        "port": 22,
        "protocol": "tcp",
        "source_not": "0.0.0.0/0"
      }
    },
    {
      "id": "SG-002",
      "name": "No unrestricted RDP access",
      "description": "RDP (port 3389) should not be open to 0.0.0.0/0",
      "severity": "critical",
      "check": {
        "port": 3389,
        "protocol": "tcp",
        "source_not": "0.0.0.0/0"
      }
    },
    {
      "id": "SG-003",
      "name": "No unrestricted database access",
      "description": "Database ports should not be open to 0.0.0.0/0",
      "severity": "high",
      "check": {
        "ports": [1433, 3306, 5432, 5984, 6379, 7001, 9200, 27017],
        "protocol": "tcp",
        "source_not": "0.0.0.0/0"
      }
    },
    {
      "id": "SG-004",
      "name": "Restrict administrative ports",
      "description": "Administrative ports should be restricted to known IPs",
      "severity": "high",
      "check": {
        "ports": [22, 3389, 5985, 5986],
        "source_cidrs_max": 5
      }
    },
    {
      "id": "SG-005",
      "name": "No unrestricted ICMP",
      "description": "ICMP should be restricted",
      "severity": "medium",
      "check": {
        "protocol": "icmp",
        "source_not": "0.0.0.0/0"
      }
    },
    {
      "id": "SG-006",
      "name": "Egress filtering",
      "description": "Outbound traffic should be restricted",
      "severity": "medium",
      "check": {
        "direction": "egress",
        "destination_not": "0.0.0.0/0"
      }
    },
    {
      "id": "SG-007",
      "name": "No unused security groups",
      "description": "Security groups should be attached to resources",
      "severity": "low",
      "check": {
        "attached": true
      }
    },
    {
      "id": "SG-008",
      "name": "Descriptive security group names",
      "description": "Security groups should have descriptive names",
      "severity": "low",
      "check": {
        "name_pattern": "^[a-zA-Z0-9-_]+$",
        "name_min_length": 5
      }
    }
  ]
}
EOF
}

# AWS Security Group Audit
audit_aws_security_groups() {
    print_header "AWS Security Groups Audit"
    
    local sgs=$(aws ec2 describe-security-groups \
        --filters "Name=tag:Environment,Values=$ENVIRONMENT" \
        --output json)
    
    local total_sgs=$(echo "$sgs" | jq '.SecurityGroups | length')
    print_status "info" "Found $total_sgs security groups"
    
    # Update report
    jq ".summary.total_security_groups = $total_sgs" "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
    
    # Audit each security group
    echo "$sgs" | jq -c '.SecurityGroups[]' | while read -r sg; do
        audit_aws_sg "$sg"
    done
    
    # Check for unused security groups
    check_unused_aws_sgs
    
    # Check for default security groups
    check_default_aws_sgs
}

audit_aws_sg() {
    local sg=$1
    local sg_id=$(echo "$sg" | jq -r '.GroupId')
    local sg_name=$(echo "$sg" | jq -r '.GroupName')
    local vpc_id=$(echo "$sg" | jq -r '.VpcId')
    
    echo -e "\n${CYAN}Auditing Security Group: $sg_name ($sg_id)${NC}"
    
    local findings=()
    local sg_risk_score=0
    
    # Check inbound rules
    local inbound_rules=$(echo "$sg" | jq -c '.IpPermissions[]?')
    if [[ -n "$inbound_rules" ]]; then
        echo "$inbound_rules" | while read -r rule; do
            audit_aws_rule "$sg_id" "$sg_name" "$rule" "inbound"
        done
    fi
    
    # Check outbound rules
    local outbound_rules=$(echo "$sg" | jq -c '.IpPermissionsEgress[]?')
    if [[ -n "$outbound_rules" ]]; then
        echo "$outbound_rules" | while read -r rule; do
            audit_aws_rule "$sg_id" "$sg_name" "$rule" "outbound"
        done
    fi
    
    # Add security group to report
    local sg_entry=$(echo "$sg" | jq "{
        id: .GroupId,
        name: .GroupName,
        vpc_id: .VpcId,
        description: .Description,
        rules_count: (.IpPermissions | length) + (.IpPermissionsEgress | length)
    }")
    
    jq ".security_groups += [$sg_entry]" "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
}

audit_aws_rule() {
    local sg_id=$1
    local sg_name=$2
    local rule=$3
    local direction=$4
    
    local protocol=$(echo "$rule" | jq -r '.IpProtocol')
    local from_port=$(echo "$rule" | jq -r '.FromPort // empty')
    local to_port=$(echo "$rule" | jq -r '.ToPort // empty')
    
    # Check each IP range
    echo "$rule" | jq -c '.IpRanges[]?' | while read -r ip_range; do
        local cidr=$(echo "$ip_range" | jq -r '.CidrIp')
        local description=$(echo "$ip_range" | jq -r '.Description // empty')
        
        # Check for risky configurations
        if [[ "$cidr" == "0.0.0.0/0" ]] && [[ "$direction" == "inbound" ]]; then
            check_public_access "$sg_id" "$sg_name" "$protocol" "$from_port" "$to_port" "$description"
        fi
        
        # Check for risky ports
        if [[ -n "$from_port" ]] && [[ "${RISKY_PORTS[$from_port]}" ]]; then
            check_risky_port "$sg_id" "$sg_name" "$protocol" "$from_port" "$cidr" "${RISKY_PORTS[$from_port]}" "$direction"
        fi
    done
    
    # Check for overly permissive protocols
    if [[ "$protocol" == "-1" ]]; then
        add_finding "high" "$sg_name" "All protocols allowed" \
            "Security group allows all protocols in $direction rules"
    fi
}

check_public_access() {
    local sg_id=$1
    local sg_name=$2
    local protocol=$3
    local port=$4
    local to_port=$5
    local description=$6
    
    local severity="medium"
    local service=""
    
    # Determine severity based on port
    case $port in
        22)
            severity="critical"
            service="SSH"
            ;;
        3389)
            severity="critical"
            service="RDP"
            ;;
        3306|5432|6379|27017)
            severity="critical"
            service="Database"
            ;;
        80|8080)
            severity="low"
            service="HTTP"
            ;;
        443|8443)
            severity="low"
            service="HTTPS"
            ;;
        *)
            if [[ -n "${RISKY_PORTS[$port]}" ]]; then
                severity="high"
                service="${RISKY_PORTS[$port]}"
            else
                severity="medium"
                service="Port $port"
            fi
            ;;
    esac
    
    add_finding "$severity" "$sg_name" "$service open to internet" \
        "Port $port ($service) is accessible from 0.0.0.0/0" \
        "{\"sg_id\": \"$sg_id\", \"port\": \"$port\", \"protocol\": \"$protocol\"}"
}

check_risky_port() {
    local sg_id=$1
    local sg_name=$2
    local protocol=$3
    local port=$4
    local cidr=$5
    local service=$6
    local direction=$7
    
    if [[ "$direction" == "inbound" ]]; then
        local severity="medium"
        
        # Calculate CIDR range size
        local cidr_bits=$(echo "$cidr" | cut -d'/' -f2)
        if [[ $cidr_bits -le 16 ]]; then
            severity="high"
        fi
        
        add_finding "$severity" "$sg_name" "Risky port exposed: $service" \
            "Port $port ($service) is accessible from $cidr" \
            "{\"sg_id\": \"$sg_id\", \"port\": \"$port\", \"cidr\": \"$cidr\"}"
    fi
}

check_unused_aws_sgs() {
    print_status "info" "Checking for unused security groups..."
    
    # Get all security groups
    local all_sgs=$(aws ec2 describe-security-groups \
        --filters "Name=tag:Environment,Values=$ENVIRONMENT" \
        --query 'SecurityGroups[].GroupId' \
        --output text)
    
    # Check each SG for associations
    for sg_id in $all_sgs; do
        local instances=$(aws ec2 describe-instances \
            --filters "Name=instance.group-id,Values=$sg_id" \
            --query 'Reservations[].Instances[].InstanceId' \
            --output text)
        
        if [[ -z "$instances" ]]; then
            # Check for other associations (ELB, RDS, etc.)
            local sg_name=$(aws ec2 describe-security-groups \
                --group-ids "$sg_id" \
                --query 'SecurityGroups[0].GroupName' \
                --output text)
            
            add_finding "low" "$sg_name" "Unused security group" \
                "Security group appears to be unused" \
                "{\"sg_id\": \"$sg_id\"}"
        fi
    done
}

check_default_aws_sgs() {
    print_status "info" "Checking default security groups..."
    
    local default_sgs=$(aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=default" \
        --output json)
    
    echo "$default_sgs" | jq -c '.SecurityGroups[]' | while read -r sg; do
        local sg_id=$(echo "$sg" | jq -r '.GroupId')
        local rule_count=$(echo "$sg" | jq '.IpPermissions | length')
        
        if [[ $rule_count -gt 0 ]]; then
            add_finding "high" "default" "Default security group has rules" \
                "Default security group should not have inbound rules" \
                "{\"sg_id\": \"$sg_id\", \"rule_count\": $rule_count}"
        fi
    done
}

# Azure NSG Audit
audit_azure_nsgs() {
    print_header "Azure Network Security Groups Audit"
    
    local resource_group="${RESOURCE_GROUP:-sparc-$ENVIRONMENT}"
    local nsgs=$(az network nsg list \
        --resource-group "$resource_group" \
        --output json)
    
    local total_nsgs=$(echo "$nsgs" | jq '. | length')
    print_status "info" "Found $total_nsgs network security groups"
    
    # Update report
    jq ".summary.total_security_groups = $total_nsgs" "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
    
    # Audit each NSG
    echo "$nsgs" | jq -c '.[]' | while read -r nsg; do
        audit_azure_nsg "$nsg"
    done
}

audit_azure_nsg() {
    local nsg=$1
    local nsg_name=$(echo "$nsg" | jq -r '.name')
    local nsg_id=$(echo "$nsg" | jq -r '.id')
    
    echo -e "\n${CYAN}Auditing NSG: $nsg_name${NC}"
    
    # Get detailed rules
    local resource_group=$(echo "$nsg_id" | cut -d'/' -f5)
    local rules=$(az network nsg rule list \
        --resource-group "$resource_group" \
        --nsg-name "$nsg_name" \
        --output json)
    
    # Audit each rule
    echo "$rules" | jq -c '.[]' | while read -r rule; do
        audit_azure_rule "$nsg_name" "$rule"
    done
}

audit_azure_rule() {
    local nsg_name=$1
    local rule=$2
    
    local rule_name=$(echo "$rule" | jq -r '.name')
    local direction=$(echo "$rule" | jq -r '.direction')
    local access=$(echo "$rule" | jq -r '.access')
    local protocol=$(echo "$rule" | jq -r '.protocol')
    local source=$(echo "$rule" | jq -r '.sourceAddressPrefix')
    local dest_port=$(echo "$rule" | jq -r '.destinationPortRange')
    
    # Check for risky configurations
    if [[ "$source" == "*" || "$source" == "0.0.0.0/0" ]] && [[ "$direction" == "Inbound" ]] && [[ "$access" == "Allow" ]]; then
        check_azure_public_access "$nsg_name" "$rule_name" "$protocol" "$dest_port"
    fi
}

check_azure_public_access() {
    local nsg_name=$1
    local rule_name=$2
    local protocol=$3
    local port_range=$4
    
    local severity="medium"
    local port=$(echo "$port_range" | cut -d'-' -f1)
    
    # Check specific ports
    if [[ "$port" == "22" ]] || [[ "$port" == "3389" ]]; then
        severity="critical"
    elif [[ -n "${RISKY_PORTS[$port]}" ]]; then
        severity="high"
    fi
    
    add_finding "$severity" "$nsg_name" "Public access on port $port" \
        "Rule '$rule_name' allows public access on port $port_range" \
        "{\"nsg\": \"$nsg_name\", \"rule\": \"$rule_name\", \"port\": \"$port_range\"}"
}

# GCP Firewall Rules Audit
audit_gcp_firewall_rules() {
    print_header "GCP Firewall Rules Audit"
    
    local rules=$(gcloud compute firewall-rules list \
        --filter="labels.environment=$ENVIRONMENT" \
        --format=json)
    
    local total_rules=$(echo "$rules" | jq '. | length')
    print_status "info" "Found $total_rules firewall rules"
    
    # Update report
    jq ".summary.total_security_groups = $total_rules" "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
    
    # Audit each rule
    echo "$rules" | jq -c '.[]' | while read -r rule; do
        audit_gcp_rule "$rule"
    done
}

audit_gcp_rule() {
    local rule=$1
    local rule_name=$(echo "$rule" | jq -r '.name')
    local direction=$(echo "$rule" | jq -r '.direction')
    local source_ranges=$(echo "$rule" | jq -r '.sourceRanges[]?')
    
    echo -e "\n${CYAN}Auditing Firewall Rule: $rule_name${NC}"
    
    # Check allowed rules
    echo "$rule" | jq -c '.allowed[]?' | while read -r allowed; do
        local protocol=$(echo "$allowed" | jq -r '.IPProtocol')
        local ports=$(echo "$allowed" | jq -r '.ports[]?')
        
        # Check for public access
        if [[ "$source_ranges" == *"0.0.0.0/0"* ]] && [[ "$direction" == "INGRESS" ]]; then
            for port in $ports; do
                check_gcp_public_access "$rule_name" "$protocol" "$port"
            done
        fi
    done
}

check_gcp_public_access() {
    local rule_name=$1
    local protocol=$2
    local port=$3
    
    local severity="medium"
    
    if [[ "$port" == "22" ]] || [[ "$port" == "3389" ]]; then
        severity="critical"
    elif [[ -n "${RISKY_PORTS[$port]}" ]]; then
        severity="high"
    fi
    
    add_finding "$severity" "$rule_name" "Public access on port $port" \
        "Firewall rule allows public access on port $port ($protocol)" \
        "{\"rule\": \"$rule_name\", \"port\": \"$port\", \"protocol\": \"$protocol\"}"
}

# Add finding to report
add_finding() {
    local severity=$1
    local resource=$2
    local title=$3
    local description=$4
    local details=${5:-"{}"}
    
    print_status "$severity" "$resource: $title"
    
    # Create finding object
    local finding=$(jq -n \
        --arg sev "$severity" \
        --arg res "$resource" \
        --arg tit "$title" \
        --arg desc "$description" \
        --argjson det "$details" \
        '{
            severity: $sev,
            resource: $res,
            title: $tit,
            description: $desc,
            details: $det,
            timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ")
        }')
    
    # Add to report
    jq ".findings += [$finding]" "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
    
    # Update summary counts
    case $severity in
        "critical")
            jq '.summary.critical_findings += 1' "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
            ;;
        "high")
            jq '.summary.high_findings += 1' "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
            ;;
        "medium")
            jq '.summary.medium_findings += 1' "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
            ;;
        "low")
            jq '.summary.low_findings += 1' "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
            ;;
    esac
}

# Calculate compliance score
calculate_compliance_score() {
    local total_findings=$(jq '.summary.critical_findings + .summary.high_findings + .summary.medium_findings + .summary.low_findings' "$AUDIT_REPORT")
    local weighted_score=$((
        $(jq '.summary.critical_findings' "$AUDIT_REPORT") * 10 +
        $(jq '.summary.high_findings' "$AUDIT_REPORT") * 7 +
        $(jq '.summary.medium_findings' "$AUDIT_REPORT") * 5 +
        $(jq '.summary.low_findings' "$AUDIT_REPORT") * 3
    ))
    
    local max_possible_score=$((total_findings * 10))
    local compliance_score=100
    
    if [[ $max_possible_score -gt 0 ]]; then
        compliance_score=$((100 - (weighted_score * 100 / max_possible_score)))
    fi
    
    jq ".summary.compliance_score = $compliance_score" "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
    
    return $compliance_score
}

# Generate remediation recommendations
generate_remediation_recommendations() {
    print_header "Remediation Recommendations"
    
    local recommendations=()
    
    # Process critical findings
    local critical_findings=$(jq -r '.findings[] | select(.severity == "critical")' "$AUDIT_REPORT")
    if [[ -n "$critical_findings" ]]; then
        echo -e "\n${RED}Critical Issues Requiring Immediate Action:${NC}"
        echo "$critical_findings" | jq -r '"\(.resource): \(.title)\n  Recommendation: \(.description)\n"'
    fi
    
    # Process high findings
    local high_findings=$(jq -r '.findings[] | select(.severity == "high")' "$AUDIT_REPORT")
    if [[ -n "$high_findings" ]]; then
        echo -e "\n${YELLOW}High Priority Issues:${NC}"
        echo "$high_findings" | jq -r '"\(.resource): \(.title)\n  Recommendation: \(.description)\n"'
    fi
    
    # Add recommendations to report
    local recommendations_json=$(cat << EOF
{
  "immediate_actions": [
    "Restrict all SSH/RDP access to specific IP ranges",
    "Close all database ports from public access",
    "Review and remove unused security groups",
    "Implement least privilege access principles"
  ],
  "best_practices": [
    "Use bastion hosts for administrative access",
    "Implement VPN for secure remote access",
    "Enable VPC Flow Logs for monitoring",
    "Regular security group audits (weekly)",
    "Document all security group changes",
    "Use infrastructure as code for consistency"
  ]
}
EOF
)
    
    jq ".remediation_recommendations = $recommendations_json" "$AUDIT_REPORT" > tmp.json && mv tmp.json "$AUDIT_REPORT"
}

# Display audit summary
display_audit_summary() {
    print_header "Security Group Audit Summary"
    
    local summary=$(jq '.summary' "$AUDIT_REPORT")
    local score=$(echo "$summary" | jq '.compliance_score')
    
    echo -e "\nEnvironment: ${BLUE}$ENVIRONMENT${NC}"
    echo -e "Cloud Provider: ${BLUE}$CLOUD_PROVIDER${NC}"
    echo -e "Audit Report: ${BLUE}$AUDIT_REPORT${NC}"
    echo ""
    echo -e "Total Security Groups/Rules: $(echo "$summary" | jq '.total_security_groups')"
    echo -e "Critical Findings: ${RED}$(echo "$summary" | jq '.critical_findings')${NC}"
    echo -e "High Findings: ${YELLOW}$(echo "$summary" | jq '.high_findings')${NC}"
    echo -e "Medium Findings: ${BLUE}$(echo "$summary" | jq '.medium_findings')${NC}"
    echo -e "Low Findings: ${CYAN}$(echo "$summary" | jq '.low_findings')${NC}"
    echo ""
    
    # Display compliance score with color
    if [[ $score -ge 90 ]]; then
        echo -e "Compliance Score: ${GREEN}${score}%${NC} (Excellent)"
    elif [[ $score -ge 70 ]]; then
        echo -e "Compliance Score: ${YELLOW}${score}%${NC} (Good)"
    elif [[ $score -ge 50 ]]; then
        echo -e "Compliance Score: ${YELLOW}${score}%${NC} (Needs Improvement)"
    else
        echo -e "Compliance Score: ${RED}${score}%${NC} (Poor)"
    fi
}

# Export findings to different formats
export_findings() {
    local format=${1:-json}
    local output_file="${AUDIT_REPORT%.json}"
    
    case $format in
        "csv")
            print_status "info" "Exporting to CSV..."
            jq -r '.findings[] | [.severity, .resource, .title, .description] | @csv' "$AUDIT_REPORT" > "${output_file}.csv"
            print_status "pass" "Exported to ${output_file}.csv"
            ;;
        "html")
            print_status "info" "Exporting to HTML..."
            generate_html_report > "${output_file}.html"
            print_status "pass" "Exported to ${output_file}.html"
            ;;
        "markdown")
            print_status "info" "Exporting to Markdown..."
            generate_markdown_report > "${output_file}.md"
            print_status "pass" "Exported to ${output_file}.md"
            ;;
    esac
}

generate_html_report() {
    cat << EOF
<!DOCTYPE html>
<html>
<head>
    <title>SPARC Security Group Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; }
        .critical { background-color: #e74c3c; color: white; padding: 10px; margin: 5px 0; }
        .high { background-color: #e67e22; color: white; padding: 10px; margin: 5px 0; }
        .medium { background-color: #f39c12; color: white; padding: 10px; margin: 5px 0; }
        .low { background-color: #3498db; color: white; padding: 10px; margin: 5px 0; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SPARC Security Group Audit Report</h1>
        <p>Generated: $(date)</p>
    </div>
EOF
    
    # Add summary
    local summary=$(jq '.summary' "$AUDIT_REPORT")
    echo "<div class='summary'>"
    echo "<h2>Summary</h2>"
    echo "<p>Environment: $ENVIRONMENT</p>"
    echo "<p>Cloud Provider: $CLOUD_PROVIDER</p>"
    echo "<p>Compliance Score: $(echo "$summary" | jq '.compliance_score')%</p>"
    echo "</div>"
    
    # Add findings table
    echo "<h2>Findings</h2>"
    echo "<table>"
    echo "<tr><th>Severity</th><th>Resource</th><th>Issue</th><th>Description</th></tr>"
    
    jq -r '.findings[] | "<tr class=\"\(.severity)\"><td>\(.severity | ascii_upcase)</td><td>\(.resource)</td><td>\(.title)</td><td>\(.description)</td></tr>"' "$AUDIT_REPORT"
    
    echo "</table>"
    echo "</body></html>"
}

generate_markdown_report() {
    echo "# SPARC Security Group Audit Report"
    echo ""
    echo "**Generated:** $(date)"
    echo "**Environment:** $ENVIRONMENT"
    echo "**Cloud Provider:** $CLOUD_PROVIDER"
    echo ""
    
    local summary=$(jq '.summary' "$AUDIT_REPORT")
    echo "## Summary"
    echo ""
    echo "- Total Security Groups: $(echo "$summary" | jq '.total_security_groups')"
    echo "- Critical Findings: $(echo "$summary" | jq '.critical_findings')"
    echo "- High Findings: $(echo "$summary" | jq '.high_findings')"
    echo "- Medium Findings: $(echo "$summary" | jq '.medium_findings')"
    echo "- Low Findings: $(echo "$summary" | jq '.low_findings')"
    echo "- Compliance Score: $(echo "$summary" | jq '.compliance_score')%"
    echo ""
    
    echo "## Findings"
    echo ""
    
    # Group by severity
    for severity in critical high medium low; do
        local findings=$(jq -r ".findings[] | select(.severity == \"$severity\")" "$AUDIT_REPORT")
        if [[ -n "$findings" ]]; then
            echo "### $(echo "$severity" | tr '[:lower:]' '[:upper:]') Severity"
            echo ""
            echo "$findings" | jq -r '"#### \(.resource): \(.title)\n\n\(.description)\n"'
        fi
    done
    
    echo "## Remediation Recommendations"
    echo ""
    jq -r '.remediation_recommendations.immediate_actions[] | "- \(.)"' "$AUDIT_REPORT"
}

# Main function
main() {
    print_header "SPARC Security Group Auditing System"
    print_status "info" "Starting security group audit..."
    print_status "info" "Environment: $ENVIRONMENT"
    print_status "info" "Cloud Provider: $CLOUD_PROVIDER"
    
    # Initialize
    init_audit_report
    
    if [[ ! -f "$COMPLIANCE_RULES_FILE" ]]; then
        create_default_compliance_rules
    fi
    
    # Run audit based on cloud provider
    case $CLOUD_PROVIDER in
        "aws")
            audit_aws_security_groups
            ;;
        "azure")
            audit_azure_nsgs
            ;;
        "gcp")
            audit_gcp_firewall_rules
            ;;
        *)
            print_status "critical" "Unsupported cloud provider: $CLOUD_PROVIDER"
            exit 1
            ;;
    esac
    
    # Calculate compliance score
    calculate_compliance_score
    
    # Generate recommendations
    generate_remediation_recommendations
    
    # Display summary
    display_audit_summary
    
    # Export options
    if [[ "$1" == "--export" ]]; then
        export_findings "${2:-json}"
    fi
    
    print_status "pass" "Audit completed successfully"
    print_status "info" "Full report available at: $AUDIT_REPORT"
}

# Execute main function
main "$@"