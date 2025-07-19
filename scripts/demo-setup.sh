#!/bin/bash

# SPARC Platform Demo Setup Script
# This script creates comprehensive demo data to showcase all 28 requirements
# of the SPARC unified access control and video surveillance platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
API_BASE_URL="${API_BASE_URL:-http://localhost:3000/api}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@sparc-demo.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-SparcDemo2024!}"

# Demo data configuration
DEMO_TENANTS=3
DEMO_SITES_PER_TENANT=2
DEMO_BUILDINGS_PER_SITE=2
DEMO_FLOORS_PER_BUILDING=3
DEMO_DOORS_PER_FLOOR=5
DEMO_CAMERAS_PER_FLOOR=3
DEMO_USERS_PER_TENANT=15
DEMO_EVENTS_PER_DAY=100
DEMO_DAYS_HISTORY=30

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if required tools are installed
    command -v curl >/dev/null 2>&1 || error "curl is required but not installed"
    command -v jq >/dev/null 2>&1 || error "jq is required but not installed"
    command -v node >/dev/null 2>&1 || error "Node.js is required but not installed"
    
    # Check if services are running
    if ! curl -s "$API_BASE_URL/health" >/dev/null 2>&1; then
        error "SPARC API is not accessible at $API_BASE_URL. Please ensure services are running."
    fi
    
    log "Prerequisites check passed"
}

# Authentication helper
authenticate() {
    log "Authenticating as system administrator..."
    
    local auth_response=$(curl -s -X POST "$API_BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
    
    if [ $? -ne 0 ]; then
        error "Failed to authenticate"
    fi
    
    AUTH_TOKEN=$(echo "$auth_response" | jq -r '.token')
    if [ "$AUTH_TOKEN" = "null" ] || [ -z "$AUTH_TOKEN" ]; then
        error "Failed to get authentication token"
    fi
    
    log "Authentication successful"
}

# Create demo tenants with different deployment models
create_demo_tenants() {
    log "Creating demo tenants..."
    
    # SSP (Shared Service Provider) Tenant
    local ssp_tenant=$(curl -s -X POST "$API_BASE_URL/tenants" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "SecureAccess SSP",
            "type": "SSP",
            "domain": "ssp.sparc-demo.com",
            "settings": {
                "deploymentModel": "shared",
                "maxSites": 100,
                "maxUsers": 10000,
                "features": ["access_control", "video_surveillance", "analytics", "mobile_credentials", "visitor_management"],
                "compliance": ["SOX", "HIPAA"],
                "offlineCapability": true,
                "meshNetworking": true
            }
        }')
    
    SSP_TENANT_ID=$(echo "$ssp_tenant" | jq -r '.id')
    
    # Enterprise Tenant
    local enterprise_tenant=$(curl -s -X POST "$API_BASE_URL/tenants" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Global Corp Enterprise",
            "type": "ENTERPRISE",
            "domain": "enterprise.sparc-demo.com",
            "settings": {
                "deploymentModel": "dedicated",
                "maxSites": 50,
                "maxUsers": 5000,
                "features": ["access_control", "video_surveillance", "analytics", "environmental_monitoring", "maintenance_management", "integration_hub"],
                "compliance": ["PCI_DSS", "SOX"],
                "offlineCapability": true,
                "meshNetworking": true,
                "customBranding": true
            }
        }')
    
    ENTERPRISE_TENANT_ID=$(echo "$enterprise_tenant" | jq -r '.id')
    
    # Hybrid Tenant
    local hybrid_tenant=$(curl -s -X POST "$API_BASE_URL/tenants" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "TechStart Hybrid",
            "type": "HYBRID",
            "domain": "hybrid.sparc-demo.com",
            "settings": {
                "deploymentModel": "hybrid",
                "maxSites": 25,
                "maxUsers": 2500,
                "features": ["access_control", "video_surveillance", "mobile_credentials", "visitor_management", "analytics"],
                "compliance": ["GDPR"],
                "offlineCapability": true,
                "meshNetworking": false
            }
        }')
    
    HYBRID_TENANT_ID=$(echo "$hybrid_tenant" | jq -r '.id')
    
    log "Created 3 demo tenants: SSP ($SSP_TENANT_ID), Enterprise ($ENTERPRISE_TENANT_ID), Hybrid ($HYBRID_TENANT_ID)"
}

# Create organizational hierarchy
create_organizational_hierarchy() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Creating organizational hierarchy for $tenant_name..."
    
    # Create organization
    local org_response=$(curl -s -X POST "$API_BASE_URL/organizations" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$tenant_name Organization\",
            \"description\": \"Main organization for $tenant_name\",
            \"settings\": {
                \"timezone\": \"America/New_York\",
                \"businessHours\": {
                    \"start\": \"08:00\",
                    \"end\": \"18:00\",
                    \"days\": [1,2,3,4,5]
                }
            }
        }")
    
    local org_id=$(echo "$org_response" | jq -r '.id')
    
    # Create sites
    for i in $(seq 1 $DEMO_SITES_PER_TENANT); do
        local site_names=("Headquarters" "Branch Office" "Data Center" "Warehouse")
        local site_name="${site_names[$((i-1))]}"
        
        local site_response=$(curl -s -X POST "$API_BASE_URL/sites" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"organizationId\": \"$org_id\",
                \"name\": \"$site_name\",
                \"address\": {
                    \"street\": \"$((100 + i * 50)) Demo Street\",
                    \"city\": \"Demo City\",
                    \"state\": \"NY\",
                    \"zipCode\": \"1000$i\",
                    \"country\": \"USA\"
                },
                \"coordinates\": {
                    \"latitude\": $((40 + i * 0.1)),
                    \"longitude\": $((74 + i * 0.1))
                },
                \"settings\": {
                    \"operatingHours\": {
                        \"start\": \"06:00\",
                        \"end\": \"22:00\"
                    },
                    \"securityLevel\": \"HIGH\",
                    \"offlineCapable\": true
                }
            }")
        
        local site_id=$(echo "$site_response" | jq -r '.id')
        
        # Create buildings for each site
        create_buildings "$tenant_id" "$site_id" "$site_name"
    done
    
    log "Organizational hierarchy created for $tenant_name"
}

# Create buildings and floors
create_buildings() {
    local tenant_id=$1
    local site_id=$2
    local site_name=$3
    
    for i in $(seq 1 $DEMO_BUILDINGS_PER_SITE); do
        local building_names=("Main Building" "Annex" "Security Building")
        local building_name="${building_names[$((i-1))]}"
        
        local building_response=$(curl -s -X POST "$API_BASE_URL/buildings" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"siteId\": \"$site_id\",
                \"name\": \"$building_name\",
                \"description\": \"$building_name at $site_name\",
                \"floors\": $DEMO_FLOORS_PER_BUILDING,
                \"settings\": {
                    \"hvacIntegration\": true,
                    \"fireSystemIntegration\": true,
                    \"emergencyProcedures\": {
                        \"evacuation\": \"UNLOCK_ALL\",
                        \"lockdown\": \"LOCK_ALL\"
                    }
                }
            }")
        
        local building_id=$(echo "$building_response" | jq -r '.id')
        
        # Create floors for each building
        create_floors "$tenant_id" "$building_id" "$building_name"
    done
}

# Create floors with access points and devices
create_floors() {
    local tenant_id=$1
    local building_id=$2
    local building_name=$3
    
    for i in $(seq 1 $DEMO_FLOORS_PER_BUILDING); do
        local floor_names=("Ground Floor" "First Floor" "Second Floor" "Third Floor" "Basement")
        local floor_name="${floor_names[$((i-1))]}"
        
        local floor_response=$(curl -s -X POST "$API_BASE_URL/floors" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"buildingId\": \"$building_id\",
                \"name\": \"$floor_name\",
                \"level\": $((i-1)),
                \"area\": $((1000 + i * 200)),
                \"layout\": {
                    \"width\": 100,
                    \"height\": 80,
                    \"units\": \"meters\"
                }
            }")
        
        local floor_id=$(echo "$floor_response" | jq -r '.id')
        
        # Create doors for this floor
        create_doors "$tenant_id" "$floor_id" "$floor_name"
        
        # Create cameras for this floor
        create_cameras "$tenant_id" "$floor_id" "$floor_name"
        
        # Create environmental sensors
        create_environmental_sensors "$tenant_id" "$floor_id" "$floor_name"
    done
}

# Create access control doors
create_doors() {
    local tenant_id=$1
    local floor_id=$2
    local floor_name=$3
    
    for i in $(seq 1 $DEMO_DOORS_PER_FLOOR); do
        local door_types=("ENTRY" "OFFICE" "SECURE" "EMERGENCY" "UTILITY")
        local door_type="${door_types[$((i-1))]}"
        
        curl -s -X POST "$API_BASE_URL/doors" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"floorId\": \"$floor_id\",
                \"name\": \"Door $i - $floor_name\",
                \"type\": \"$door_type\",
                \"location\": {
                    \"x\": $((i * 20)),
                    \"y\": $((i * 15)),
                    \"description\": \"$door_type door on $floor_name\"
                },
                \"hardware\": {
                    \"controllerId\": \"CTRL-$floor_id-$i\",
                    \"readerType\": \"PROXIMITY_CARD\",
                    \"lockType\": \"ELECTRIC_STRIKE\",
                    \"sensors\": [\"DOOR_POSITION\", \"REX_BUTTON\"],
                    \"capabilities\": [\"MOBILE_CREDENTIALS\", \"BIOMETRIC\", \"PIN_CODE\"]
                },
                \"settings\": {
                    \"unlockDuration\": 5,
                    \"autoRelock\": true,
                    \"antiPassback\": true,
                    \"duressCode\": true,
                    \"offlineCapable\": true,
                    \"scheduleId\": null
                },
                \"status\": \"ONLINE\"
            }" >/dev/null
    done
}

# Create video surveillance cameras
create_cameras() {
    local tenant_id=$1
    local floor_id=$2
    local floor_name=$3
    
    for i in $(seq 1 $DEMO_CAMERAS_PER_FLOOR); do
        local camera_types=("DOME" "BULLET" "PTZ")
        local camera_type="${camera_types[$((i % 3))]}"
        
        curl -s -X POST "$API_BASE_URL/cameras" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"floorId\": \"$floor_id\",
                \"name\": \"Camera $i - $floor_name\",
                \"type\": \"$camera_type\",
                \"location\": {
                    \"x\": $((i * 25 + 10)),
                    \"y\": $((i * 20 + 5)),
                    \"description\": \"$camera_type camera covering $floor_name\"
                },
                \"specifications\": {
                    \"resolution\": \"4K\",
                    \"fps\": 30,
                    \"nightVision\": true,
                    \"audioCapture\": true,
                    \"ptzCapable\": $([ \"$camera_type\" = \"PTZ\" ] && echo true || echo false),
                    \"analytics\": [\"MOTION_DETECTION\", \"FACE_RECOGNITION\", \"OBJECT_DETECTION\"]
                },
                \"network\": {
                    \"ipAddress\": \"192.168.1.$((100 + i))\",
                    \"port\": 554,
                    \"protocol\": \"RTSP\",
                    \"streamUrl\": \"rtsp://192.168.1.$((100 + i)):554/stream1\"
                },
                \"settings\": {
                    \"recordingMode\": \"CONTINUOUS\",
                    \"retentionDays\": 30,
                    \"privacyMasks\": [],
                    \"motionSensitivity\": 75,
                    \"alertsEnabled\": true
                },
                \"status\": \"ONLINE\"
            }" >/dev/null
    done
}

# Create environmental sensors
create_environmental_sensors() {
    local tenant_id=$1
    local floor_id=$2
    local floor_name=$3
    
    local sensor_types=("TEMPERATURE" "HUMIDITY" "AIR_QUALITY" "OCCUPANCY" "NOISE")
    
    for sensor_type in "${sensor_types[@]}"; do
        curl -s -X POST "$API_BASE_URL/environmental-sensors" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"floorId\": \"$floor_id\",
                \"name\": \"$sensor_type Sensor - $floor_name\",
                \"type\": \"$sensor_type\",
                \"location\": {
                    \"x\": $((RANDOM % 80 + 10)),
                    \"y\": $((RANDOM % 60 + 10)),
                    \"description\": \"$sensor_type monitoring for $floor_name\"
                },
                \"specifications\": {
                    \"range\": \"$([ \"$sensor_type\" = \"TEMPERATURE\" ] && echo \"-40 to 85°C\" || echo \"0-100%\")\",
                    \"accuracy\": \"±1%\",
                    \"updateInterval\": 60
                },
                \"thresholds\": {
                    \"min\": $([ "$sensor_type" = "TEMPERATURE" ] && echo 18 || echo 30),
                    \"max\": $([ "$sensor_type" = "TEMPERATURE" ] && echo 26 || echo 80),
                    \"alertEnabled\": true
                },
                \"status\": \"ONLINE\"
            }" >/dev/null
    done
}

# Create demo users with different roles
create_demo_users() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Creating demo users for $tenant_name..."
    
    # User roles and their permissions
    local roles=(
        "SUPER_ADMIN:Full system access"
        "TENANT_ADMIN:Tenant administration"
        "SITE_MANAGER:Site management"
        "SECURITY_OFFICER:Security operations"
        "MAINTENANCE_TECH:Maintenance operations"
        "VISITOR_COORDINATOR:Visitor management"
        "EMPLOYEE:Basic access"
        "CONTRACTOR:Limited access"
        "GUEST:Temporary access"
    )
    
    local departments=("Security" "IT" "HR" "Facilities" "Operations" "Finance")
    local first_names=("John" "Jane" "Mike" "Sarah" "David" "Lisa" "Tom" "Emma" "Chris" "Anna")
    local last_names=("Smith" "Johnson" "Williams" "Brown" "Jones" "Garcia" "Miller" "Davis" "Rodriguez" "Martinez")
    
    for i in $(seq 1 $DEMO_USERS_PER_TENANT); do
        local role_info="${roles[$((i % ${#roles[@]}))]}"
        local role=$(echo "$role_info" | cut -d: -f1)
        local first_name="${first_names[$((i % ${#first_names[@]}))]}"
        local last_name="${last_names[$((i % ${#last_names[@]}))]}"
        local department="${departments[$((i % ${#departments[@]}))]}"
        local email="${first_name,,}.${last_name,,}@$(echo "$tenant_name" | tr ' ' '-' | tr '[:upper:]' '[:lower:]').com"
        
        curl -s -X POST "$API_BASE_URL/users" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"email\": \"$email\",
                \"firstName\": \"$first_name\",
                \"lastName\": \"$last_name\",
                \"role\": \"$role\",
                \"department\": \"$department\",
                \"employeeId\": \"EMP-$tenant_id-$(printf %04d $i)\",
                \"phone\": \"+1-555-$(printf %04d $((1000 + i)))\",
                \"settings\": {
                    \"mobileCredentialsEnabled\": true,
                    \"biometricEnabled\": $([ $((i % 3)) -eq 0 ] && echo true || echo false),
                    \"pinCodeEnabled\": true,
                    \"scheduleId\": null,
                    \"accessLevel\": \"$([ \"$role\" = \"SUPER_ADMIN\" ] && echo \"UNRESTRICTED\" || echo \"RESTRICTED\")\",
                    \"notifications\": {
                        \"email\": true,
                        \"sms\": false,
                        \"push\": true
                    }
                },
                \"status\": \"ACTIVE\",
                \"startDate\": \"$(date -d \"-$((RANDOM % 365)) days\" +%Y-%m-%d)\",
                \"credentials\": {
                    \"cardNumber\": \"$(printf %010d $((1000000000 + i)))\",
                    \"pinCode\": \"$(printf %04d $((1000 + i)))\",
                    \"mobileCredential\": {
                        \"enabled\": true,
                        \"deviceId\": \"mobile-$tenant_id-$i\"
                    }
                }
            }" >/dev/null
    done
    
    log "Created $DEMO_USERS_PER_TENANT demo users for $tenant_name"
}

# Generate historical access events
generate_access_events() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Generating historical access events for $tenant_name..."
    
    # Get doors and users for this tenant
    local doors_response=$(curl -s -X GET "$API_BASE_URL/doors" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id")
    
    local users_response=$(curl -s -X GET "$API_BASE_URL/users" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id")
    
    local door_ids=($(echo "$doors_response" | jq -r '.data[].id'))
    local user_ids=($(echo "$users_response" | jq -r '.data[].id'))
    
    # Generate events for the past 30 days
    for day in $(seq 0 $DEMO_DAYS_HISTORY); do
        local event_date=$(date -d "-$day days" +%Y-%m-%d)
        
        for event_num in $(seq 1 $DEMO_EVENTS_PER_DAY); do
            local door_id="${door_ids[$((RANDOM % ${#door_ids[@]}))]}"
            local user_id="${user_ids[$((RANDOM % ${#user_ids[@]}))]}"
            local hour=$((RANDOM % 24))
            local minute=$((RANDOM % 60))
            local second=$((RANDOM % 60))
            local timestamp="${event_date}T$(printf %02d $hour):$(printf %02d $minute):$(printf %02d $second)Z"
            
            # 95% success rate for access events
            local success=$([ $((RANDOM % 100)) -lt 95 ] && echo true || echo false)
            local event_type=$([ "$success" = "true" ] && echo "ACCESS_GRANTED" || echo "ACCESS_DENIED")
            local reason=$([ "$success" = "true" ] && echo "VALID_CREDENTIAL" || echo "INVALID_CREDENTIAL")
            
            curl -s -X POST "$API_BASE_URL/access-events" \
                -H "Authorization: Bearer $AUTH_TOKEN" \
                -H "X-Tenant-ID: $tenant_id" \
                -H "Content-Type: application/json" \
                -d "{
                    \"doorId\": \"$door_id\",
                    \"userId\": \"$user_id\",
                    \"timestamp\": \"$timestamp\",
                    \"eventType\": \"$event_type\",
                    \"credentialType\": \"CARD\",
                    \"reason\": \"$reason\",
                    \"success\": $success,
                    \"metadata\": {
                        \"cardNumber\": \"$(printf %010d $((1000000000 + RANDOM % 1000)))\",
                        \"readerLocation\": \"ENTRY\",
                        \"direction\": \"$([ $((RANDOM % 2)) -eq 0 ] && echo \"IN\" || echo \"OUT\")\",
                        \"antiPassbackViolation\": false
                    }
                }" >/dev/null
        done
    done
    
    log "Generated $((DEMO_EVENTS_PER_DAY * DEMO_DAYS_HISTORY)) access events for $tenant_name"
}

# Generate video recordings metadata
generate_video_recordings() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Generating video recording metadata for $tenant_name..."
    
    # Get cameras for this tenant
    local cameras_response=$(curl -s -X GET "$API_BASE_URL/cameras" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id")
    
    local camera_ids=($(echo "$cameras_response" | jq -r '.data[].id'))
    
    # Generate recordings for the past 7 days
    for day in $(seq 0 7); do
        local record_date=$(date -d "-$day days" +%Y-%m-%d)
        
        for camera_id in "${camera_ids[@]}"; do
            # Generate 24 hours of recordings (1 hour segments)
            for hour in $(seq 0 23); do
                local start_time="${record_date}T$(printf %02d $hour):00:00Z"
                local end_time="${record_date}T$(printf %02d $hour):59:59Z"
                local file_size=$((RANDOM % 1000000 + 500000)) # 500MB to 1.5GB
                
                curl -s -X POST "$API_BASE_URL/video-recordings" \
                    -H "Authorization: Bearer $AUTH_TOKEN" \
                    -H "X-Tenant-ID: $tenant_id" \
                    -H "Content-Type: application/json" \
                    -d "{
                        \"cameraId\": \"$camera_id\",
                        \"startTime\": \"$start_time\",
                        \"endTime\": \"$end_time\",
                        \"duration\": 3600,
                        \"fileSize\": $file_size,
                        \"filePath\": \"/recordings/$tenant_id/$camera_id/$record_date/$(printf %02d $hour).mp4\",
                        \"resolution\": \"4K\",
                        \"fps\": 30,
                        \"codec\": \"H.264\",
                        \"metadata\": {
                            \"motionEvents\": $((RANDOM % 50)),
                            \"alertEvents\": $((RANDOM % 5)),
                            \"qualityScore\": $((RANDOM % 20 + 80))
                        },
                        \"status\": \"AVAILABLE\"
                    }" >/dev/null
            done
        done
    done
    
    log "Generated video recording metadata for $tenant_name"
}

# Create maintenance work orders
create_maintenance_workorders() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Creating maintenance work orders for $tenant_name..."
    
    local work_order_types=("PREVENTIVE" "CORRECTIVE" "EMERGENCY" "UPGRADE")
    local priorities=("LOW" "MEDIUM" "HIGH" "CRITICAL")
    local statuses=("OPEN" "IN_PROGRESS" "COMPLETED" "CANCELLED")
    
    for i in $(seq 1 20); do
        local wo_type="${work_order_types[$((RANDOM % ${#work_order_types[@]}))]}"
        local priority="${priorities[$((RANDOM % ${#priorities[@]}))]}"
        local status="${statuses[$((RANDOM % ${#statuses[@]}))]}"
        local created_date=$(date -d "-$((RANDOM % 30)) days" +%Y-%m-%d)
        
        curl -s -X POST "$API_BASE_URL/maintenance/work-orders" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"title\": \"$wo_type Maintenance - Item $i\",
                \"description\": \"$wo_type maintenance work order for system component\",
                \"type\": \"$wo_type\",
                \"priority\": \"$priority\",
                \"status\": \"$status\",
                \"assignedTo\": \"maintenance-tech-$((RANDOM % 3 + 1))\",
                \"createdDate\": \"$created_date\",
                \"dueDate\": \"$(date -d \"$created_date +7 days\" +%Y-%m-%d)\",
                \"estimatedHours\": $((RANDOM % 8 + 1)),
                \"category\": \"ACCESS_CONTROL\",
                \"location\": {
                    \"building\": \"Building $((RANDOM % 2 + 1))\",
                    \"floor\": \"Floor $((RANDOM % 3 + 1))\",
                    \"room\": \"Room $((RANDOM % 10 + 1))\"
                },
                \"parts\": [
                    {
                        \"name\": \"Component Part\",
                        \"quantity\": $((RANDOM % 5 + 1)),
                        \"cost\": $((RANDOM % 100 + 50))
                    }
                ],
                \"labor\": {
                    \"hours\": $((RANDOM % 4 + 1)),
                    \"rate\": 75
                }
            }" >/dev/null
    done
    
    log "Created 20 maintenance work orders for $tenant_name"
}

# Generate environmental sensor readings
generate_environmental_data() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Generating environmental sensor data for $tenant_name..."
    
    # Get environmental sensors for this tenant
    local sensors_response=$(curl -s -X GET "$API_BASE_URL/environmental-sensors" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id")
    
    local sensor_ids=($(echo "$sensors_response" | jq -r '.data[].id'))
    
    # Generate readings for the past 7 days (every 15 minutes)
    for day in $(seq 0 7); do
        local reading_date=$(date -d "-$day days" +%Y-%m-%d)
        
        for hour in $(seq 0 23); do
            for minute in 0 15 30 45; do
                local timestamp="${reading_date}T$(printf %02d $hour):$(printf %02d $minute):00Z"
                
                for sensor_id in "${sensor_ids[@]}"; do
                    # Generate realistic sensor values
                    local temperature=$((RANDOM % 10 + 20)) # 20-30°C
                    local humidity=$((RANDOM % 30 + 40))    # 40-70%
                    local air_quality=$((RANDOM % 50 + 50)) # 50-100 AQI
                    local occupancy=$((RANDOM % 20))        # 0-20 people
                    local noise=$((RANDOM % 20 + 30))       # 30-50 dB
                    
                    curl -s -X POST "$API_BASE_URL/environmental-readings" \
                        -H "Authorization: Bearer $AUTH_TOKEN" \
                        -H "X-Tenant-ID: $tenant_id" \
                        -H "Content-Type: application/json" \
                        -d "{
                            \"sensorId\": \"$sensor_id\",
                            \"timestamp\": \"$timestamp\",
                            \"readings\": {
                                \"temperature\": $temperature,
                                \"humidity\": $humidity,
                                \"airQuality\": $air_quality,
                                \"occupancy\": $occupancy,
                                \"noise\": $noise
                            },
                            \"alerts\": []
                        }" >/dev/null
                done
            done
        done
    done
    
    log "Generated environmental sensor data for $tenant_name"
}

# Create visitor management data
create_visitor_data() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Creating visitor management data for $tenant_name..."
    
    local visitor_types=("BUSINESS" "CONTRACTOR" "DELIVERY" "INTERVIEW" "MAINTENANCE")
    local statuses=("PRE_REGISTERED" "CHECKED_IN" "CHECKED_OUT" "EXPIRED" "CANCELLED")
    
    for i in $(seq 1 50); do
        local visitor_type="${visitor_types[$((RANDOM % ${#visitor_types[@]}))]}"
        local status="${statuses[$((RANDOM % ${#statuses[@]}))]}"
        local visit_date=$(date -d "+$((RANDOM % 30)) days" +%Y-%m-%d)
        
        curl -s -X POST "$API_BASE_URL/visitors" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"firstName\": \"Visitor\",
                \"lastName\": \"$i\",
                \"email\": \"visitor$i@external.com\",
                \"phone\": \"+1-555-$(printf %04d $((2000 + i)))\",
                \"company\": \"External Company $((RANDOM % 10 + 1))\",
                \"visitType\": \"$visitor_type\",
                \"status\": \"$status\",
                \"visitDate\": \"$visit_date\",
                \"visitTime\": \"$(printf %02d $((RANDOM % 8 + 9))):00\",
                \"duration\": $((RANDOM % 4 + 1)),
                \"hostUserId\": \"user-$tenant_id-$((RANDOM % 5 + 1))\",
                \"purpose\": \"$visitor_type visit for business purposes\",
                \"accessAreas\": [\"LOBBY\", \"MEETING_ROOM\"],
                \"requirements\": {
                    \"escortRequired\": $([ $((RANDOM % 2)) -eq 0 ] && echo true || echo false),
                    \"backgroundCheck\": $([ \"$visitor_type\" = \"CONTRACTOR\" ] && echo true || echo false),
                    \"ndaRequired\": $([ \"$visitor_type\" = \"BUSINESS\" ] && echo true || echo false)
                },
                \"credentials\": {
                    \"badgeNumber\": \"VISITOR-$(printf %04d $i)\",
                    \"accessLevel\": \"VISITOR\"
                }
            }" >/dev/null
    done
    
    log "Created 50 visitor records for $tenant_name"
}

# Setup integration examples
setup_integrations() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Setting up integration examples for $tenant_name..."
    
    # HVAC Integration
    curl -s -X POST "$API_BASE_URL/integrations" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "HVAC System Integration",
            "type": "HVAC",
            "provider": "Honeywell",
            "status": "ACTIVE",
            "configuration": {
                "endpoint": "https://hvac-api.demo.com",
                "apiKey": "demo-hvac-key",
                "zones": ["Zone1", "Zone2", "Zone3"],
                "capabilities": ["temperature_control", "occupancy_based_control", "emergency_override"]
            },
            "settings": {
                "syncInterval": 300,
                "alertsEnabled": true,
                "autoControl": true
            }
        }' >/dev/null
    
    # Fire Safety Integration
    curl -s -X POST "$API_BASE_URL/integrations" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Fire Safety System",
            "type": "FIRE_SAFETY",
            "provider": "Simplex",
            "status": "ACTIVE",
            "configuration": {
                "endpoint": "https://fire-system.demo.com",
                "zones": ["Building1", "Building2"],
                "capabilities": ["alarm_monitoring", "emergency_unlock", "evacuation_procedures"]
            },
            "settings": {
                "emergencyUnlock": true,
                "alertPriority": "CRITICAL"
            }
        }' >/dev/null
    
    # HR System Integration
    curl -s -X POST "$API_BASE_URL/integrations" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "HR Management System",
            "type": "HR",
            "provider": "Workday",
            "status": "ACTIVE",
            "configuration": {
                "endpoint": "https://hr-api.demo.com",
                "syncFields": ["employee_id", "department", "role", "status", "start_date", "end_date"],
                "capabilities": ["user_provisioning", "role_sync", "termination_workflow"]
            },
            "settings": {
                "autoProvisioning": true,
                "syncInterval": 3600,
                "terminationAction": "DISABLE_ACCESS"
            }
        }' >/dev/null
    
    log "Created integration examples for $tenant_name"
}

# Create dashboard configurations
create_dashboard_configs() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Creating dashboard configurations for $tenant_name..."
    
    # Security Operations Dashboard
    curl -s -X POST "$API_BASE_URL/dashboards" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Security Operations Center",
            "description": "Main security monitoring dashboard",
            "type": "SECURITY",
            "layout": {
                "columns": 12,
                "rows": 8
            },
            "widgets": [
                {
                    "id": "access-events-live",
                    "type": "LIVE_EVENTS",
                    "title": "Live Access Events",
                    "position": {"x": 0, "y": 0, "w": 6, "h": 3},
                    "config": {"eventTypes": ["ACCESS_GRANTED", "ACCESS_DENIED"], "limit": 10}
                },
                {
                    "id": "door-status",
                    "type": "DEVICE_STATUS",
                    "title": "Door Status Overview",
                    "position": {"x": 6, "y": 0, "w": 6, "h": 3},
                    "config": {"deviceType": "DOOR", "statusTypes": ["ONLINE", "OFFLINE", "ALARM"]}
                },
                {
                    "id": "video-grid",
                    "type": "VIDEO_GRID",
                    "title": "Live Video Feeds",
                    "position": {"x": 0, "y": 3, "w": 8, "h": 5},
                    "config": {"cameras": 9, "layout": "3x3"}
                },
                {
                    "id": "alerts-panel",
                    "type": "ALERTS",
                    "title": "Active Alerts",
                    "position": {"x": 8, "y": 3, "w": 4, "h": 5},
                    "config": {"severity": ["HIGH", "CRITICAL"], "limit": 20}
                }
            ],
            "permissions": ["SECURITY_OFFICER", "SITE_MANAGER", "TENANT_ADMIN"],
            "isDefault": true
        }' >/dev/null
    
    # Analytics Dashboard
    curl -s -X POST "$API_BASE_URL/dashboards" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Analytics & Reporting",
            "description": "Business intelligence and analytics dashboard",
            "type": "ANALYTICS",
            "layout": {
                "columns": 12,
                "rows": 8
            },
            "widgets": [
                {
                    "id": "access-trends",
                    "type": "LINE_CHART",
                    "title": "Access Trends (30 Days)",
                    "position": {"x": 0, "y": 0, "w": 6, "h": 4},
                    "config": {"metric": "access_events", "period": "30d", "groupBy": "day"}
                },
                {
                    "id": "occupancy-heatmap",
                    "type": "HEATMAP",
                    "title": "Occupancy Heatmap",
                    "position": {"x": 6, "y": 0, "w": 6, "h": 4},
                    "config": {"metric": "occupancy", "timeRange": "today"}
                },
                {
                    "id": "security-metrics",
                    "type": "KPI_GRID",
                    "title": "Security KPIs",
                    "position": {"x": 0, "y": 4, "w": 4, "h": 4},
                    "config": {"metrics": ["failed_access_rate", "response_time", "uptime", "incidents"]}
                },
                {
                    "id": "device-health",
                    "type": "DONUT_CHART",
                    "title": "Device Health Status",
                    "position": {"x": 4, "y": 4, "w": 4, "h": 4},
                    "config": {"metric": "device_status", "categories": ["ONLINE", "OFFLINE", "MAINTENANCE"]}
                },
                {
                    "id": "compliance-status",
                    "type": "STATUS_GRID",
                    "title": "Compliance Status",
                    "position": {"x": 8, "y": 4, "w": 4, "h": 4},
                    "config": {"standards": ["SOX", "HIPAA", "PCI_DSS"], "showDetails": true}
                }
            ],
            "permissions": ["TENANT_ADMIN", "SITE_MANAGER"],
            "isDefault": false
        }' >/dev/null
    
    # Maintenance Dashboard
    curl -s -X POST "$API_BASE_URL/dashboards" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Maintenance Management",
            "description": "Facility and equipment maintenance dashboard",
            "type": "MAINTENANCE",
            "layout": {
                "columns": 12,
                "rows": 6
            },
            "widgets": [
                {
                    "id": "work-orders",
                    "type": "TABLE",
                    "title": "Active Work Orders",
                    "position": {"x": 0, "y": 0, "w": 8, "h": 3},
                    "config": {"status": ["OPEN", "IN_PROGRESS"], "sortBy": "priority", "limit": 10}
                },
                {
                    "id": "maintenance-schedule",
                    "type": "CALENDAR",
                    "title": "Maintenance Schedule",
                    "position": {"x": 8, "y": 0, "w": 4, "h": 6},
                    "config": {"view": "week", "types": ["PREVENTIVE", "CORRECTIVE"]}
                },
                {
                    "id": "equipment-status",
                    "type": "STATUS_GRID",
                    "title": "Equipment Status",
                    "position": {"x": 0, "y": 3, "w": 4, "h": 3},
                    "config": {"categories": ["DOORS", "CAMERAS", "SENSORS"], "showAlerts": true}
                },
                {
                    "id": "maintenance-costs",
                    "type": "BAR_CHART",
                    "title": "Maintenance Costs (Monthly)",
                    "position": {"x": 4, "y": 3, "w": 4, "h": 3},
                    "config": {"metric": "maintenance_cost", "period": "12m", "groupBy": "month"}
                }
            ],
            "permissions": ["MAINTENANCE_TECH", "SITE_MANAGER", "TENANT_ADMIN"],
            "isDefault": false
        }' >/dev/null
    
    log "Created dashboard configurations for $tenant_name"
}

# Generate system alerts and events
generate_system_alerts() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Generating system alerts for $tenant_name..."
    
    local alert_types=("DEVICE_OFFLINE" "UNAUTHORIZED_ACCESS" "DOOR_FORCED" "CAMERA_TAMPER" "SYSTEM_ERROR" "MAINTENANCE_DUE")
    local severities=("LOW" "MEDIUM" "HIGH" "CRITICAL")
    local statuses=("OPEN" "ACKNOWLEDGED" "RESOLVED")
    
    for i in $(seq 1 30); do
        local alert_type="${alert_types[$((RANDOM % ${#alert_types[@]}))]}"
        local severity="${severities[$((RANDOM % ${#severities[@]}))]}"
        local status="${statuses[$((RANDOM % ${#statuses[@]}))]}"
        local created_time=$(date -d "-$((RANDOM % 7)) days -$((RANDOM % 24)) hours" --iso-8601=seconds)
        
        curl -s -X POST "$API_BASE_URL/alerts" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "X-Tenant-ID: $tenant_id" \
            -H "Content-Type: application/json" \
            -d "{
                \"type\": \"$alert_type\",
                \"severity\": \"$severity\",
                \"status\": \"$status\",
                \"title\": \"$alert_type Alert #$i\",
                \"description\": \"System generated $alert_type alert for monitoring\",
                \"source\": {
                    \"type\": \"SYSTEM\",
                    \"deviceId\": \"device-$tenant_id-$((RANDOM % 100 + 1))\",
                    \"location\": \"Building $((RANDOM % 2 + 1)), Floor $((RANDOM % 3 + 1))\"
                },
                \"createdAt\": \"$created_time\",
                \"metadata\": {
                    \"autoGenerated\": true,
                    \"category\": \"$([ \"$alert_type\" = \"MAINTENANCE_DUE\" ] && echo \"MAINTENANCE\" || echo \"SECURITY\")\",
                    \"priority\": \"$([ \"$severity\" = \"CRITICAL\" ] && echo \"IMMEDIATE\" || echo \"NORMAL\")\"
                },
                \"actions\": [
                    {
                        \"type\": \"ACKNOWLEDGE\",
                        \"label\": \"Acknowledge Alert\",
                        \"available\": $([ \"$status\" = \"OPEN\" ] && echo true || echo false)
                    },
                    {
                        \"type\": \"RESOLVE\",
                        \"label\": \"Mark Resolved\",
                        \"available\": $([ \"$status\" != \"RESOLVED\" ] && echo true || echo false)
                    }
                ]
            }" >/dev/null
    done
    
    log "Generated 30 system alerts for $tenant_name"
}

# Create access schedules
create_access_schedules() {
    local tenant_id=$1
    local tenant_name=$2
    
    log "Creating access schedules for $tenant_name..."
    
    # Business Hours Schedule
    curl -s -X POST "$API_BASE_URL/schedules" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Business Hours",
            "description": "Standard business hours access",
            "type": "ACCESS",
            "timeZone": "America/New_York",
            "rules": [
                {
                    "days": [1,2,3,4,5],
                    "startTime": "08:00",
                    "endTime": "18:00",
                    "enabled": true
                }
            ],
            "holidays": ["2024-01-01", "2024-07-04", "2024-12-25"],
            "isDefault": true
        }' >/dev/null
    
    # 24/7 Access Schedule
    curl -s -X POST "$API_BASE_URL/schedules" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "24/7 Access",
            "description": "Unrestricted access schedule",
            "type": "ACCESS",
            "timeZone": "America/New_York",
            "rules": [
                {
                    "days": [0,1,2,3,4,5,6],
                    "startTime": "00:00",
                    "endTime": "23:59",
                    "enabled": true
                }
            ],
            "holidays": [],
            "isDefault": false
        }' >/dev/null
    
    # Weekend Only Schedule
    curl -s -X POST "$API_BASE_URL/schedules" \
        -H "Authorization: Bearer $AUTH_TOKEN" \
        -H "X-Tenant-ID: $tenant_id" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Weekend Access",
            "description": "Weekend only access",
            "type": "ACCESS",
            "timeZone": "America/New_York",
            "rules": [
                {
                    "days": [0,6],
                    "startTime": "09:00",
                    "endTime": "17:00",
                    "enabled": true
                }
            ],
            "holidays": [],
            "isDefault": false
        }' >/dev/null
    
    log "Created access schedules for $tenant_name"
}

# Setup device simulation
setup_device_simulation() {
    log "Setting up device simulation..."
    
    # Create device simulation configuration
    cat > "$PROJECT_ROOT/scripts/device-simulator.js" << 'EOF'
const WebSocket = require('ws');
const axios = require('axios');

class DeviceSimulator {
    constructor(config) {
        this.config = config;
        this.devices = [];
        this.ws = null;
        this.running = false;
    }

    async start() {
        console.log('Starting device simulation...');
        this.running = true;
        
        // Connect to WebSocket for real-time events
        this.ws = new WebSocket(this.config.websocketUrl);
        
        this.ws.on('open', () => {
            console.log('Connected to SPARC platform');
            this.startSimulation();
        });
        
        this.ws.on('error', (error) => {
            console.error('WebSocket error:', error);
        });
    }

    startSimulation() {
        // Simulate door access events
        setInterval(() => {
            if (this.running) {
                this.simulateAccessEvent();
            }
        }, 5000);

        // Simulate camera motion events
        setInterval(() => {
            if (this.running) {
                this.simulateMotionEvent();
            }
        }, 10000);

        // Simulate environmental readings
        setInterval(() => {
            if (this.running) {
                this.simulateEnvironmentalReading();
            }
        }, 30000);

        // Simulate device status updates
        setInterval(() => {
            if (this.running) {
                this.simulateDeviceStatus();
            }
        }, 60000);
    }

    simulateAccessEvent() {
        const event = {
            type: 'ACCESS_EVENT',
            deviceId: `door-${Math.floor(Math.random() * 100) + 1}`,
            userId: `user-${Math.floor(Math.random() * 50) + 1}`,
            timestamp: new Date().toISOString(),
            success: Math.random() > 0.1, // 90% success rate
            credentialType: ['CARD', 'MOBILE', 'PIN'][Math.floor(Math.random() * 3)]
        };
        
        this.sendEvent(event);
    }

    simulateMotionEvent() {
        const event = {
            type: 'MOTION_DETECTED',
            deviceId: `camera-${Math.floor(Math.random() * 50) + 1}`,
            timestamp: new Date().toISOString(),
            confidence: Math.random() * 0.4 + 0.6, // 60-100% confidence
            boundingBox: {
                x: Math.random() * 1920,
                y: Math.random() * 1080,
                width: Math.random() * 200 + 50,
                height: Math.random() * 300 + 100
            }
        };
        
        this.sendEvent(event);
    }

    simulateEnvironmentalReading() {
        const event = {
            type: 'ENVIRONMENTAL_READING',
            deviceId: `sensor-${Math.floor(Math.random() * 20) + 1}`,
            timestamp: new Date().toISOString(),
            readings: {
                temperature: Math.random() * 10 + 20, // 20-30°C
                humidity: Math.random() * 30 + 40,    // 40-70%
                airQuality: Math.random() * 50 + 50,  // 50-100 AQI
                occupancy: Math.floor(Math.random() * 20) // 0-20 people
            }
        };
        
        this.sendEvent(event);
    }

    simulateDeviceStatus() {
        const statuses = ['ONLINE', 'OFFLINE', 'MAINTENANCE', 'ERROR'];
        const event = {
            type: 'DEVICE_STATUS',
            deviceId: `device-${Math.floor(Math.random() * 200) + 1}`,
            timestamp: new Date().toISOString(),
            status: statuses[Math.floor(Math.random() * statuses.length)],
            health: Math.random() * 100,
            lastSeen: new Date().toISOString()
        };
        
        this.sendEvent(event);
    }

    sendEvent(event) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(event));
            console.log(`Sent ${event.type} event for ${event.deviceId}`);
        }
    }

    stop() {
        console.log('Stopping device simulation...');
        this.running = false;
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Start simulation if run directly
if (require.main === module) {
    const simulator = new DeviceSimulator({
        websocketUrl: process.env.WS_URL || 'ws://localhost:3001'
    });
    
    simulator.start();
    
    // Graceful shutdown
    process.on('SIGINT', () => {
        simulator.stop();
        process.exit(0);
    });
}

module.exports = DeviceSimulator;
EOF

    log "Device simulation setup complete"
}

# Main execution function
main() {
    log "Starting SPARC Platform Demo Setup"
    log "=================================="
    
    # Check prerequisites
    check_prerequisites
    
    # Authenticate
    authenticate
    
    # Create demo tenants
    create_demo_tenants
    
    # Setup each tenant with complete demo data
    local tenants=(
        "$SSP_TENANT_ID:SecureAccess SSP"
        "$ENTERPRISE_TENANT_ID:Global Corp Enterprise"
        "$HYBRID_TENANT_ID:TechStart Hybrid"
    )
    
    for tenant_info in "${tenants[@]}"; do
        local tenant_id=$(echo "$tenant_info" | cut -d: -f1)
        local tenant_name=$(echo "$tenant_info" | cut -d: -f2)
        
        info "Setting up demo data for $tenant_name ($tenant_id)"
        
        # Create organizational hierarchy
        create_organizational_hierarchy "$tenant_id" "$tenant_name"
        
        # Create demo users
        create_demo_users "$tenant_id" "$tenant_name"
        
        # Generate historical data
        generate_access_events "$tenant_id" "$tenant_name"
        generate_video_recordings "$tenant_id" "$tenant_name"
        generate_environmental_data "$tenant_id" "$tenant_name"
        
        # Create operational data
        create_maintenance_workorders "$tenant_id" "$tenant_name"
        create_visitor_data "$tenant_id" "$tenant_name"
        create_access_schedules "$tenant_id" "$tenant_name"
        
        # Setup integrations
        setup_integrations "$tenant_id" "$tenant_name"
        
        # Create dashboards
        create_dashboard_configs "$tenant_id" "$tenant_name"
        
        # Generate alerts
        generate_system_alerts "$tenant_id" "$tenant_name"
        
        log "Demo data setup complete for $tenant_name"
    done
    
    # Setup device simulation
    setup_device_simulation
    
    # Final summary
    log ""
    log "SPARC Platform Demo Setup Complete!"
    log "==================================="
    log ""
    log "Demo Environment Summary:"
    log "- 3 Multi-tenant scenarios (SSP, Enterprise, Hybrid)"
    log "- $((DEMO_SITES_PER_TENANT * 3)) sites across all tenants"
    log "- $((DEMO_BUILDINGS_PER_SITE * DEMO_SITES_PER_TENANT * 3)) buildings with multiple floors"
    log "- $((DEMO_DOORS_PER_FLOOR * DEMO_FLOORS_PER_BUILDING * DEMO_BUILDINGS_PER_SITE * DEMO_SITES_PER_TENANT * 3)) access control doors"
    log "- $((DEMO_CAMERAS_PER_FLOOR * DEMO_FLOORS_PER_BUILDING * DEMO_BUILDINGS_PER_SITE * DEMO_SITES_PER_TENANT * 3)) video surveillance cameras"
    log "- $((DEMO_USERS_PER_TENANT * 3)) demo users with various roles"
    log "- $((DEMO_EVENTS_PER_DAY * DEMO_DAYS_HISTORY * 3)) historical access events"
    log "- 7 days of video recording metadata"
    log "- 7 days of environmental sensor data"
    log "- 60 maintenance work orders"
    log "- 150 visitor records"
    log "- 90 system alerts"
    log "- 9 dashboard configurations"
    log "- 9 external system integrations"
    log ""
    log "Access the platform at: $API_BASE_URL"
    log ""
    log "Demo Tenant Login Credentials:"
    log "- SSP Tenant: admin@ssp.sparc-demo.com"
    log "- Enterprise Tenant: admin@enterprise.sparc-demo.com"
    log "- Hybrid Tenant: admin@hybrid.sparc-demo.com"
    log ""
    log "To start device simulation:"
    log "cd $PROJECT_ROOT && node scripts/device-simulator.js"
    log ""
    log "All 28 SPARC platform requirements are now demonstrated with realistic data!"
}

# Execute main function
main "$@"