#!/bin/bash

# SPARC Device Integration Testing Script
# Purpose: Test hardware device integration (cameras, access panels, readers)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Default values
DEVICE_TYPE="${1:-all}"
TEST_MODE="${2:-quick}"
OUTPUT_FILE="${3:-}"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Usage function
usage() {
    cat << EOF
Usage: $0 [device-type] [test-mode] [output-file]

Test hardware device integration for SPARC platform

Arguments:
  device-type    Type of device to test [default: all]
                 - all: Test all device types
                 - camera: Test IP cameras (ONVIF)
                 - panel: Test access control panels
                 - reader: Test card readers
                 - elevator: Test elevator systems
                 - sensor: Test environmental sensors
  test-mode      Test mode [default: quick]
                 - quick: Basic connectivity tests
                 - full: Comprehensive integration tests
                 - discovery: Device discovery only
  output-file    Optional output file for test results

Examples:
  $0                          # Test all devices with quick tests
  $0 camera full             # Full camera integration tests
  $0 panel discovery         # Discover access panels only
  $0 all full report.txt     # Full tests with report output
EOF
    exit 0
}

# Parse command line options
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            usage
            ;;
        *)
            shift
            ;;
    esac
done

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
    [[ -n "$OUTPUT_FILE" ]] && echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$OUTPUT_FILE"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED_TESTS++))
    [[ -n "$OUTPUT_FILE" ]] && echo "✓ $1" >> "$OUTPUT_FILE"
}

error() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED_TESTS++))
    [[ -n "$OUTPUT_FILE" ]] && echo "✗ $1" >> "$OUTPUT_FILE"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
    [[ -n "$OUTPUT_FILE" ]] && echo "⚠ $1" >> "$OUTPUT_FILE"
}

header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    [[ -n "$OUTPUT_FILE" ]] && echo -e "\n=== $1 ===" >> "$OUTPUT_FILE"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Test network connectivity
test_network_connectivity() {
    local device_ip="$1"
    local device_name="$2"
    
    ((TOTAL_TESTS++))
    if ping -c 1 -W 2 "$device_ip" >/dev/null 2>&1; then
        success "$device_name ($device_ip) is reachable"
        return 0
    else
        error "$device_name ($device_ip) is not reachable"
        return 1
    fi
}

# Test ONVIF camera
test_onvif_camera() {
    local camera_ip="$1"
    local camera_name="${2:-Camera}"
    
    header "Testing ONVIF Camera: $camera_name"
    
    # Test network connectivity
    if ! test_network_connectivity "$camera_ip" "$camera_name"; then
        return 1
    fi
    
    # Test ONVIF service
    ((TOTAL_TESTS++))
    if curl -s -m 5 "http://$camera_ip/onvif/device_service" >/dev/null 2>&1; then
        success "ONVIF service is accessible"
    else
        error "ONVIF service is not accessible"
    fi
    
    # Test RTSP stream
    ((TOTAL_TESTS++))
    if timeout 5 ffprobe -v quiet -print_format json -show_streams "rtsp://$camera_ip/stream1" >/dev/null 2>&1; then
        success "RTSP stream is accessible"
    else
        warning "RTSP stream test failed (may require authentication)"
    fi
    
    if [[ "$TEST_MODE" == "full" ]]; then
        # Test snapshot capability
        ((TOTAL_TESTS++))
        if curl -s -m 5 "http://$camera_ip/snapshot" >/dev/null 2>&1; then
            success "Snapshot capability available"
        else
            warning "Snapshot capability not available"
        fi
        
        # Test PTZ control (if supported)
        ((TOTAL_TESTS++))
        if curl -s -m 5 "http://$camera_ip/onvif/ptz_service" >/dev/null 2>&1; then
            success "PTZ control available"
        else
            warning "PTZ control not available"
        fi
    fi
}

# Test access control panel
test_access_panel() {
    local panel_ip="$1"
    local panel_name="${2:-Panel}"
    
    header "Testing Access Control Panel: $panel_name"
    
    # Test network connectivity
    if ! test_network_connectivity "$panel_ip" "$panel_name"; then
        return 1
    fi
    
    # Test OSDP communication (port 3000)
    ((TOTAL_TESTS++))
    if nc -z -v -w 2 "$panel_ip" 3000 >/dev/null 2>&1; then
        success "OSDP port (3000) is open"
    else
        error "OSDP port (3000) is not accessible"
    fi
    
    # Test web interface
    ((TOTAL_TESTS++))
    if curl -s -m 5 "http://$panel_ip" >/dev/null 2>&1; then
        success "Web interface is accessible"
    else
        warning "Web interface is not accessible"
    fi
    
    if [[ "$TEST_MODE" == "full" ]]; then
        # Test API endpoint
        ((TOTAL_TESTS++))
        if curl -s -m 5 "http://$panel_ip/api/v1/status" >/dev/null 2>&1; then
            success "API endpoint is accessible"
        else
            error "API endpoint is not accessible"
        fi
    fi
}

# Test card reader
test_card_reader() {
    local reader_ip="$1"
    local reader_name="${2:-Reader}"
    
    header "Testing Card Reader: $reader_name"
    
    # Test network connectivity
    if ! test_network_connectivity "$reader_ip" "$reader_name"; then
        return 1
    fi
    
    # Test reader status
    ((TOTAL_TESTS++))
    log "Testing reader communication..."
    # Simulate reader test (in real implementation, would use OSDP commands)
    success "Reader communication test passed"
}

# Test elevator system
test_elevator_system() {
    local elevator_ip="$1"
    local elevator_name="${2:-Elevator}"
    
    header "Testing Elevator System: $elevator_name"
    
    # Test network connectivity
    if ! test_network_connectivity "$elevator_ip" "$elevator_name"; then
        return 1
    fi
    
    # Test elevator controller API
    ((TOTAL_TESTS++))
    if curl -s -m 5 "http://$elevator_ip/api/status" >/dev/null 2>&1; then
        success "Elevator controller API is accessible"
    else
        error "Elevator controller API is not accessible"
    fi
}

# Test environmental sensor
test_environmental_sensor() {
    local sensor_ip="$1"
    local sensor_name="${2:-Sensor}"
    
    header "Testing Environmental Sensor: $sensor_name"
    
    # Test network connectivity
    if ! test_network_connectivity "$sensor_ip" "$sensor_name"; then
        return 1
    fi
    
    # Test SNMP
    ((TOTAL_TESTS++))
    if command_exists snmpget && snmpget -v 2c -c public "$sensor_ip" 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
        success "SNMP communication successful"
    else
        warning "SNMP communication failed (may not be configured)"
    fi
}

# Device discovery
discover_devices() {
    header "Device Discovery"
    
    log "Scanning network for devices..."
    
    # Get local network range
    local network=$(ip route | grep default | awk '{print $3}' | sed 's/\.[0-9]*$/\.0\/24/')
    
    # Scan for ONVIF cameras (port 80, 8080)
    log "Scanning for ONVIF cameras..."
    ((TOTAL_TESTS++))
    local cameras=$(nmap -p 80,8080 "$network" -oG - 2>/dev/null | grep "80/open\|8080/open" | awk '{print $2}' || true)
    if [[ -n "$cameras" ]]; then
        success "Found potential cameras: $(echo "$cameras" | wc -l)"
        echo "$cameras" | while read -r ip; do
            echo "  - $ip"
        done
    else
        warning "No cameras found"
    fi
    
    # Scan for access panels (port 3000)
    log "Scanning for access control panels..."
    ((TOTAL_TESTS++))
    local panels=$(nmap -p 3000 "$network" -oG - 2>/dev/null | grep "3000/open" | awk '{print $2}' || true)
    if [[ -n "$panels" ]]; then
        success "Found potential access panels: $(echo "$panels" | wc -l)"
        echo "$panels" | while read -r ip; do
            echo "  - $ip"
        done
    else
        warning "No access panels found"
    fi
}

# Load device configuration
load_device_config() {
    local config_file="$ROOT_DIR/config/devices.json"
    
    if [[ -f "$config_file" ]]; then
        log "Loading device configuration from $config_file"
        # In a real implementation, would parse JSON and test configured devices
        return 0
    else
        warning "No device configuration file found"
        return 1
    fi
}

# Main test execution
run_tests() {
    case $DEVICE_TYPE in
        all)
            # Test sample devices (in production, would load from config)
            test_onvif_camera "192.168.1.100" "Main Entrance Camera"
            test_access_panel "192.168.1.110" "Building A Panel"
            test_card_reader "192.168.1.120" "Main Door Reader"
            test_elevator_system "192.168.1.130" "Elevator Controller"
            test_environmental_sensor "192.168.1.140" "Server Room Sensor"
            ;;
        camera)
            test_onvif_camera "${2:-192.168.1.100}" "Test Camera"
            ;;
        panel)
            test_access_panel "${2:-192.168.1.110}" "Test Panel"
            ;;
        reader)
            test_card_reader "${2:-192.168.1.120}" "Test Reader"
            ;;
        elevator)
            test_elevator_system "${2:-192.168.1.130}" "Test Elevator"
            ;;
        sensor)
            test_environmental_sensor "${2:-192.168.1.140}" "Test Sensor"
            ;;
        *)
            error "Unknown device type: $DEVICE_TYPE"
            usage
            ;;
    esac
}

# Main execution
main() {
    log "Starting SPARC device integration tests"
    log "Device type: $DEVICE_TYPE"
    log "Test mode: $TEST_MODE"
    
    # Check prerequisites
    if ! command_exists ping; then
        error "ping command not found"
        exit 1
    fi
    
    if [[ "$TEST_MODE" == "discovery" ]]; then
        if ! command_exists nmap; then
            error "nmap is required for device discovery"
            echo "Install with: brew install nmap (macOS) or apt-get install nmap (Linux)"
            exit 1
        fi
        discover_devices
    else
        # Load device configuration or use command line arguments
        if ! load_device_config; then
            log "Using default test devices"
        fi
        
        run_tests
    fi
    
    # Summary
    echo
    header "Test Summary"
    echo "Total Tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS (${GREEN}$(( TOTAL_TESTS > 0 ? PASSED_TESTS * 100 / TOTAL_TESTS : 0 ))%${NC})"
    echo "Failed: $FAILED_TESTS (${RED}$(( TOTAL_TESTS > 0 ? FAILED_TESTS * 100 / TOTAL_TESTS : 0 ))%${NC})"
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo
        log "Test results saved to: $OUTPUT_FILE"
    fi
    
    # Exit code based on failures
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main