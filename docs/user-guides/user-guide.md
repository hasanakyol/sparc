# SPARC Platform User Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard Overview](#dashboard-overview)
3. [Access Control Management](#access-control-management)
4. [Video Surveillance](#video-surveillance)
5. [Analytics and Reporting](#analytics-and-reporting)
6. [Visitor Management](#visitor-management)
7. [Environmental Monitoring](#environmental-monitoring)
8. [Device Management](#device-management)
9. [Mobile Credentials](#mobile-credentials)
10. [Maintenance Management](#maintenance-management)
11. [Security and Compliance](#security-and-compliance)
12. [Integration Management](#integration-management)
13. [Multi-Tenant Features](#multi-tenant-features)
14. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Initial Login

1. **Access the Platform**
   - Navigate to your SPARC platform URL
   - Enter your username and password
   - Complete multi-factor authentication if enabled
   - Select your organization/tenant if you have access to multiple

2. **First-Time Setup**
   - Complete your user profile
   - Set up notification preferences
   - Configure dashboard layout
   - Review available permissions and features

3. **Navigation Basics**
   - **Main Navigation**: Located in the left sidebar with collapsible menu
   - **Breadcrumbs**: Track your current location in the platform
   - **Search**: Global search bar for quick access to any resource
   - **User Menu**: Access profile, settings, and logout options
   - **Notifications**: Real-time alerts and system notifications

### Basic Concepts

- **Tenants**: Top-level organizational units with complete data isolation
- **Organizations**: Business entities within a tenant
- **Sites**: Physical locations (buildings, campuses, facilities)
- **Zones**: Logical groupings of areas within sites
- **Assets**: Doors, cameras, sensors, and other managed devices
- **Users**: People with access to the system and physical locations
- **Events**: Real-time activities and historical records

---

## Dashboard Overview

### Main Dashboard

The SPARC dashboard provides a customizable overview of your entire security ecosystem:

#### Available Widgets

1. **System Status**
   - Overall system health
   - Active alerts and warnings
   - Service availability indicators
   - Performance metrics

2. **Access Control Summary**
   - Total doors and access points
   - Active access sessions
   - Recent access events
   - Failed access attempts

3. **Video Surveillance**
   - Camera status overview
   - Live feed thumbnails
   - Recording status
   - Storage utilization

4. **Environmental Monitoring**
   - Temperature and humidity readings
   - Air quality metrics
   - HVAC system status
   - Environmental alerts

5. **Visitor Management**
   - Active visitors on-site
   - Pending visitor approvals
   - Today's visitor schedule
   - Visitor check-in/out status

6. **Analytics Insights**
   - Usage patterns and trends
   - Peak activity times
   - Occupancy statistics
   - Security incident summaries

7. **Maintenance Status**
   - Open work orders
   - Scheduled maintenance
   - Device health indicators
   - Preventive maintenance alerts

8. **Compliance Dashboard**
   - Audit trail summaries
   - Compliance status indicators
   - Regulatory reporting status
   - Data retention metrics

### Customizing Your Dashboard

1. **Adding Widgets**
   - Click "Customize Dashboard"
   - Select from available widget library
   - Drag and drop to desired position
   - Configure widget settings and filters

2. **Widget Configuration**
   - Resize widgets by dragging corners
   - Set refresh intervals
   - Configure data filters and time ranges
   - Set up widget-specific alerts

3. **Layout Management**
   - Save multiple dashboard layouts
   - Switch between different views
   - Share dashboard configurations
   - Export dashboard data

---

## Access Control Management

### Door Management

#### Adding and Configuring Doors

1. **Create New Door**
   - Navigate to Access Control > Doors
   - Click "Add Door"
   - Enter door details (name, location, type)
   - Configure hardware settings
   - Set security level and access rules

2. **Door Configuration Options**
   - **Basic Settings**: Name, description, location
   - **Hardware**: Controller type, reader configuration
   - **Security**: Encryption, anti-passback, tailgating detection
   - **Scheduling**: Operating hours, holiday schedules
   - **Notifications**: Alert preferences for door events

3. **Door Status Monitoring**
   - Real-time door status (open, closed, locked, unlocked)
   - Battery levels for wireless devices
   - Communication status with controllers
   - Recent access events and alerts

### User Management

#### Creating and Managing Users

1. **Add New User**
   - Go to Access Control > Users
   - Click "Add User"
   - Enter personal information
   - Assign roles and permissions
   - Configure access credentials

2. **User Profile Management**
   - **Personal Information**: Name, contact details, photo
   - **Employment Details**: Department, position, supervisor
   - **Access Credentials**: Cards, PINs, biometrics, mobile
   - **Permissions**: Role-based access control assignments
   - **Schedules**: Time-based access restrictions

3. **Bulk User Operations**
   - Import users from CSV/Excel
   - Bulk permission updates
   - Mass credential provisioning
   - Group operations and templates

### Permission Management

#### Role-Based Access Control

1. **Creating Roles**
   - Define role name and description
   - Set system permissions (view, edit, admin)
   - Configure physical access permissions
   - Assign to door groups and zones

2. **Permission Hierarchies**
   - **System Admin**: Full platform access
   - **Security Manager**: Security operations and monitoring
   - **Site Manager**: Site-specific management
   - **Operator**: Day-to-day operations
   - **Visitor**: Limited temporary access

3. **Dynamic Permissions**
   - Time-based access rules
   - Location-based restrictions
   - Conditional access based on events
   - Emergency override capabilities

### Access Schedules

#### Creating Time-Based Access

1. **Schedule Templates**
   - Business hours (9-5, Monday-Friday)
   - 24/7 access for critical personnel
   - Shift-based schedules
   - Holiday and exception handling

2. **Advanced Scheduling**
   - Multiple time zones support
   - Daylight saving time handling
   - Recurring patterns and exceptions
   - Integration with HR systems

---

## Video Surveillance

### Live Video Monitoring

#### Viewing Live Feeds

1. **Camera Grid View**
   - Select cameras from site hierarchy
   - Customize grid layout (1x1 to 6x6)
   - Full-screen and picture-in-picture modes
   - Audio monitoring where available

2. **Camera Controls**
   - **PTZ Controls**: Pan, tilt, zoom for supported cameras
   - **Presets**: Save and recall camera positions
   - **Digital Zoom**: Zoom into specific areas
   - **Image Enhancement**: Brightness, contrast, saturation

3. **Multi-Monitor Support**
   - Extend views across multiple monitors
   - Dedicated monitoring workstations
   - Video wall configurations
   - Operator-specific layouts

### Video Recording and Playback

#### Recording Management

1. **Recording Policies**
   - Continuous recording
   - Motion-triggered recording
   - Event-based recording
   - Schedule-based recording

2. **Playback Features**
   - Timeline navigation with event markers
   - Variable speed playback (0.25x to 16x)
   - Frame-by-frame analysis
   - Synchronized multi-camera playback

3. **Video Search**
   - Search by time and date
   - Motion detection search
   - Event-triggered search
   - Advanced analytics search (people, vehicles, objects)

### Privacy and Compliance

#### Privacy Masking

1. **Static Privacy Masks**
   - Define rectangular or polygonal masks
   - Permanent masking of sensitive areas
   - Role-based mask visibility
   - Audit trail for mask changes

2. **Dynamic Privacy Controls**
   - Time-based privacy activation
   - Event-triggered privacy modes
   - User permission-based unmasking
   - Emergency override capabilities

#### Video Export and Evidence

1. **Export Options**
   - Native format export
   - Standard format conversion (MP4, AVI)
   - Encrypted export with digital signatures
   - Chain of custody documentation

2. **Evidence Management**
   - Tamper-evident packaging
   - Legal hold capabilities
   - Retention policy enforcement
   - Court-ready documentation

---

## Analytics and Reporting

### Real-Time Analytics

#### Live Analytics Dashboard

1. **Occupancy Analytics**
   - Real-time people counting
   - Zone occupancy levels
   - Capacity management
   - Social distancing monitoring

2. **Traffic Flow Analysis**
   - Entry/exit patterns
   - Peak usage times
   - Bottleneck identification
   - Route optimization insights

3. **Security Analytics**
   - Unusual activity detection
   - Loitering alerts
   - Perimeter breach detection
   - Crowd formation monitoring

### Historical Reporting

#### Standard Reports

1. **Access Control Reports**
   - Door usage statistics
   - User access patterns
   - Failed access attempts
   - Time and attendance summaries

2. **Video Analytics Reports**
   - Camera uptime and health
   - Storage utilization trends
   - Motion detection summaries
   - Privacy compliance reports

3. **System Performance Reports**
   - Device health and status
   - Network performance metrics
   - System availability reports
   - Maintenance activity summaries

#### Custom Report Builder

1. **Report Configuration**
   - Select data sources and metrics
   - Define time ranges and filters
   - Choose visualization types
   - Set up automated scheduling

2. **Advanced Analytics**
   - Trend analysis and forecasting
   - Comparative analysis across sites
   - Anomaly detection reports
   - Predictive maintenance insights

### Data Visualization

#### Interactive Dashboards

1. **Chart Types**
   - Line charts for trends
   - Bar charts for comparisons
   - Heat maps for patterns
   - Pie charts for distributions

2. **Interactive Features**
   - Drill-down capabilities
   - Filter and search options
   - Real-time data updates
   - Export to various formats

---

## Visitor Management

### Pre-Registration Process

#### Visitor Pre-Registration

1. **Online Registration Portal**
   - Visitor self-registration
   - Host approval workflow
   - Document upload and verification
   - Background check integration

2. **Bulk Visitor Management**
   - Group visitor registration
   - Event-based visitor lists
   - Contractor management
   - Recurring visitor schedules

### Check-In and Check-Out

#### Visitor Reception

1. **Kiosk Check-In**
   - Self-service check-in terminals
   - ID verification and photo capture
   - Badge printing and assignment
   - Host notification system

2. **Reception Desk Management**
   - Staff-assisted check-in
   - Visitor verification process
   - Emergency contact collection
   - Special requirements handling

#### Visitor Tracking

1. **Real-Time Monitoring**
   - Visitor location tracking
   - Access attempt monitoring
   - Overstay alerts
   - Emergency evacuation lists

2. **Escort Management**
   - Escort assignment and tracking
   - Escort notification system
   - Unescorted area violations
   - Escort availability scheduling

### Visitor Compliance

#### Security Screening

1. **Background Checks**
   - Automated screening processes
   - Watchlist verification
   - Government database checks
   - Custom screening criteria

2. **Document Verification**
   - ID document scanning
   - Authenticity verification
   - Expiration date checking
   - Digital document storage

---

## Environmental Monitoring

### Sensor Management

#### Sensor Configuration

1. **Sensor Types**
   - Temperature and humidity sensors
   - Air quality monitors
   - Motion and occupancy sensors
   - Light and noise level monitors
   - Water leak detectors

2. **Sensor Installation**
   - Device discovery and pairing
   - Location assignment and mapping
   - Calibration and testing
   - Network configuration

### Threshold Management

#### Alert Configuration

1. **Threshold Settings**
   - Normal operating ranges
   - Warning level thresholds
   - Critical alert thresholds
   - Hysteresis settings

2. **Alert Actions**
   - Email and SMS notifications
   - Dashboard alerts
   - Integration with HVAC systems
   - Automated response triggers

### HVAC Integration

#### Climate Control

1. **System Integration**
   - BACnet protocol support
   - Modbus connectivity
   - Custom API integrations
   - Real-time control capabilities

2. **Automated Responses**
   - Temperature-based adjustments
   - Occupancy-driven optimization
   - Energy efficiency algorithms
   - Emergency shutdown procedures

---

## Device Management

### Device Discovery

#### Automatic Discovery

1. **Network Scanning**
   - IP range scanning
   - Protocol-specific discovery
   - Device fingerprinting
   - Automatic classification

2. **Manual Device Addition**
   - Device registration forms
   - Configuration wizards
   - Bulk import capabilities
   - Template-based setup

### Device Configuration

#### Configuration Management

1. **Device Settings**
   - Network configuration
   - Security parameters
   - Operational settings
   - Feature enablement

2. **Configuration Templates**
   - Device type templates
   - Site-specific configurations
   - Bulk configuration deployment
   - Version control and rollback

### Firmware Management

#### Update Management

1. **Firmware Updates**
   - Centralized update distribution
   - Scheduled update windows
   - Rollback capabilities
   - Update verification

2. **Version Control**
   - Firmware version tracking
   - Compatibility verification
   - Security patch management
   - Update history and logs

### Device Diagnostics

#### Health Monitoring

1. **Real-Time Diagnostics**
   - Device status monitoring
   - Performance metrics
   - Error detection and reporting
   - Predictive failure analysis

2. **Troubleshooting Tools**
   - Remote diagnostic commands
   - Log file analysis
   - Network connectivity tests
   - Performance benchmarking

---

## Mobile Credentials

### Mobile App Setup

#### User Enrollment

1. **App Installation**
   - Download from app stores
   - Organization-specific app configuration
   - User authentication and verification
   - Device registration process

2. **Credential Provisioning**
   - Secure credential delivery
   - Biometric enrollment
   - PIN setup and management
   - Backup credential options

### Mobile Access Management

#### Credential Management

1. **Credential Types**
   - Bluetooth Low Energy (BLE)
   - Near Field Communication (NFC)
   - QR code credentials
   - Biometric authentication

2. **Access Control**
   - Real-time credential validation
   - Offline access capabilities
   - Temporary credential issuance
   - Emergency access procedures

### Security Features

#### Mobile Security

1. **Device Security**
   - Device attestation
   - Jailbreak/root detection
   - Secure element utilization
   - Remote credential revocation

2. **Privacy Protection**
   - Location privacy controls
   - Data encryption standards
   - User consent management
   - Audit trail maintenance

---

## Maintenance Management

### Work Order Management

#### Creating Work Orders

1. **Work Order Types**
   - Preventive maintenance
   - Corrective maintenance
   - Emergency repairs
   - Upgrade projects

2. **Work Order Workflow**
   - Request submission
   - Approval processes
   - Technician assignment
   - Progress tracking
   - Completion verification

### Preventive Maintenance

#### Maintenance Scheduling

1. **Schedule Types**
   - Time-based schedules
   - Usage-based maintenance
   - Condition-based triggers
   - Seasonal maintenance

2. **Maintenance Templates**
   - Device-specific procedures
   - Checklist templates
   - Parts and materials lists
   - Safety requirements

### Asset Management

#### Asset Tracking

1. **Asset Information**
   - Device specifications
   - Warranty information
   - Service history
   - Performance metrics

2. **Lifecycle Management**
   - Installation tracking
   - Maintenance history
   - Replacement planning
   - Disposal procedures

---

## Security and Compliance

### Security Monitoring

#### Threat Detection

1. **Real-Time Monitoring**
   - Intrusion detection
   - Anomaly identification
   - Behavioral analysis
   - Threat intelligence integration

2. **Incident Response**
   - Automated alert generation
   - Escalation procedures
   - Investigation workflows
   - Response coordination

### Audit and Compliance

#### Audit Trail Management

1. **Audit Logging**
   - User activity tracking
   - System event logging
   - Data access monitoring
   - Configuration change tracking

2. **Compliance Reporting**
   - SOX compliance reports
   - HIPAA audit trails
   - PCI-DSS documentation
   - Custom compliance frameworks

### Data Protection

#### Privacy Controls

1. **Data Encryption**
   - Data at rest encryption
   - Data in transit protection
   - Key management
   - Encryption key rotation

2. **Access Controls**
   - Role-based permissions
   - Data classification
   - Need-to-know access
   - Regular access reviews

---

## Integration Management

### Third-Party Integrations

#### Integration Types

1. **HR System Integration**
   - Employee data synchronization
   - Automated user provisioning
   - Role assignment automation
   - Termination workflows

2. **Building Management Systems**
   - HVAC system integration
   - Lighting control systems
   - Fire safety systems
   - Energy management

3. **Security Systems**
   - Intrusion detection systems
   - Fire alarm systems
   - Emergency notification
   - Guard tour systems

#### API Management

1. **API Configuration**
   - Endpoint configuration
   - Authentication setup
   - Rate limiting
   - Error handling

2. **Data Mapping**
   - Field mapping configuration
   - Data transformation rules
   - Validation requirements
   - Synchronization schedules

### Webhook Management

#### Event Notifications

1. **Webhook Configuration**
   - Endpoint registration
   - Event type selection
   - Payload formatting
   - Retry policies

2. **Event Types**
   - Access events
   - System alerts
   - Device status changes
   - User management events

---

## Multi-Tenant Features

### Tenant Management

#### Tenant Administration

1. **Tenant Configuration**
   - Tenant creation and setup
   - Resource allocation
   - Feature enablement
   - Billing configuration

2. **Tenant Isolation**
   - Data segregation
   - User isolation
   - Resource boundaries
   - Security separation

### Organization Hierarchy

#### Site Management

1. **Hierarchical Structure**
   - Tenant > Organization > Site > Building > Floor > Zone
   - Inheritance of settings and permissions
   - Cascading policy application
   - Flexible organizational models

2. **Site Configuration**
   - Site-specific settings
   - Local administrator assignment
   - Resource allocation
   - Integration configurations

### Tenant Switching

#### Multi-Tenant Access

1. **Tenant Selection**
   - Tenant switching interface
   - Permission-based access
   - Context preservation
   - Audit trail maintenance

2. **Cross-Tenant Operations**
   - Shared resource management
   - Cross-tenant reporting
   - Consolidated dashboards
   - Global administration

---

## Troubleshooting

### Common Issues

#### Login and Authentication

**Issue**: Cannot log in to the system
- **Solution**: Verify username and password
- Check account status (active/disabled)
- Verify multi-factor authentication setup
- Contact administrator for password reset

**Issue**: Session timeout errors
- **Solution**: Check session timeout settings
- Verify network connectivity
- Clear browser cache and cookies
- Update browser to latest version

#### Access Control Issues

**Issue**: Door not responding to access attempts
- **Solution**: Check door controller status
- Verify network connectivity
- Check power supply to controller
- Review access permissions for user

**Issue**: Card reader not working
- **Solution**: Check reader LED status indicators
- Verify card format compatibility
- Clean card and reader surface
- Check reader configuration settings

#### Video Surveillance Problems

**Issue**: Camera not displaying video
- **Solution**: Check camera power and network connection
- Verify camera IP address and settings
- Check video codec compatibility
- Review bandwidth and network performance

**Issue**: Recording not working
- **Solution**: Check storage space availability
- Verify recording schedule configuration
- Check camera recording settings
- Review storage device health

#### System Performance

**Issue**: Slow system response
- **Solution**: Check system resource utilization
- Review network bandwidth usage
- Clear browser cache
- Contact administrator for system optimization

**Issue**: Mobile app connectivity issues
- **Solution**: Check mobile device network connection
- Verify app version and update if needed
- Check server connectivity
- Review mobile device permissions

### Getting Help

#### Support Resources

1. **Documentation**
   - User guides and manuals
   - Video tutorials
   - FAQ sections
   - Best practices guides

2. **Support Channels**
   - Help desk ticketing system
   - Live chat support
   - Phone support
   - Email support

3. **Training Resources**
   - Online training modules
   - Webinar sessions
   - Certification programs
   - User community forums

#### Escalation Procedures

1. **Level 1 Support**
   - Basic troubleshooting
   - User account issues
   - Configuration questions
   - General guidance

2. **Level 2 Support**
   - Technical issues
   - Integration problems
   - Performance optimization
   - Advanced configuration

3. **Level 3 Support**
   - System architecture issues
   - Custom development
   - Emergency support
   - Critical system failures

---

## Appendices

### Keyboard Shortcuts

- **Ctrl+/** : Open global search
- **Ctrl+D** : Open dashboard
- **Ctrl+A** : Access control module
- **Ctrl+V** : Video surveillance module
- **Ctrl+R** : Reports and analytics
- **Ctrl+M** : Maintenance management
- **Ctrl+S** : System settings
- **Esc** : Close current dialog/modal

### Browser Requirements

- **Supported Browsers**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **Required Features**: JavaScript enabled, cookies enabled, WebRTC support
- **Recommended**: Hardware acceleration enabled, popup blocker disabled for platform domain

### Mobile App Requirements

- **iOS**: Version 13.0 or later
- **Android**: Version 8.0 (API level 26) or later
- **Required Permissions**: Camera, location, notifications, biometric authentication
- **Network**: Wi-Fi or cellular data connection required

---

*This user guide covers the complete SPARC platform functionality. For additional support or questions not covered in this guide, please contact your system administrator or support team.*