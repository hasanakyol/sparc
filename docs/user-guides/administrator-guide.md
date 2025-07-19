# SPARC Platform Administrator Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Tenant Management](#tenant-management)
4. [User Management](#user-management)
5. [Access Control Configuration](#access-control-configuration)
6. [Video System Setup](#video-system-setup)
7. [Device Management](#device-management)
8. [Environmental Monitoring Configuration](#environmental-monitoring-configuration)
9. [System Maintenance](#system-maintenance)
10. [Troubleshooting](#troubleshooting)
11. [Security Best Practices](#security-best-practices)
12. [Appendices](#appendices)

## Introduction

The SPARC (Secure Physical Access and Resource Control) platform is a comprehensive enterprise security management system that provides unified access control, video surveillance, environmental monitoring, and visitor management capabilities. This administrator guide provides step-by-step instructions for configuring and managing all aspects of the SPARC platform.

### Key Features
- Multi-tenant architecture supporting multiple organizations
- Unified access control with mobile credentials
- Real-time video surveillance and analytics
- Environmental monitoring and alerting
- Visitor management and compliance tracking
- Offline resilience with 72-hour operation capability
- SOX, HIPAA, and PCI-DSS compliance features

### Administrator Roles
- **System Administrator**: Full platform access and configuration
- **Tenant Administrator**: Tenant-specific configuration and management
- **Security Administrator**: Security policies and access control
- **Facilities Administrator**: Environmental monitoring and device management

## Getting Started

### Initial Platform Access

1. **Login to SPARC Platform**
   - Navigate to your SPARC platform URL (e.g., `https://your-org.sparc.platform`)
   - Enter your administrator credentials
   - Complete multi-factor authentication if enabled
   - You will be directed to the main dashboard

2. **Dashboard Overview**
   The main dashboard provides:
   - System health status indicators
   - Active alerts and notifications
   - Quick access to key management functions
   - Real-time activity feeds
   - Performance metrics overview

3. **Navigation Menu**
   - **Dashboard**: System overview and metrics
   - **Tenants**: Multi-tenant management (System Admin only)
   - **Users**: User account management
   - **Access Control**: Door controllers and access policies
   - **Video**: Camera management and surveillance
   - **Devices**: Hardware device management
   - **Environmental**: Sensor monitoring and alerts
   - **Visitors**: Visitor management system
   - **Reports**: Compliance and audit reporting
   - **Settings**: System configuration

## Tenant Management

### Creating a New Tenant

1. **Access Tenant Management**
   - Navigate to **Tenants** in the main menu
   - Click **"Add New Tenant"** button

2. **Basic Tenant Information**
   - **Tenant Name**: Enter the organization name
   - **Tenant Code**: Unique identifier (auto-generated or custom)
   - **Domain**: Primary domain for the tenant
   - **Contact Information**: Primary contact details
   - **Billing Information**: Subscription and billing details

3. **Tenant Configuration**
   - **Time Zone**: Set the primary time zone
   - **Language**: Default language preference
   - **Compliance Requirements**: Select applicable regulations (SOX, HIPAA, PCI-DSS)
   - **Feature Enablement**: Enable/disable specific platform features
   - **Resource Limits**: Set maximum users, devices, and storage

4. **Security Settings**
   - **Password Policy**: Configure password requirements
   - **MFA Requirements**: Enable multi-factor authentication
   - **Session Timeout**: Set session duration limits
   - **IP Restrictions**: Configure allowed IP ranges
   - **Audit Logging**: Enable comprehensive audit trails

5. **Save and Activate**
   - Review all settings
   - Click **"Create Tenant"**
   - The system will provision tenant resources
   - Initial administrator account will be created

### Managing Existing Tenants

1. **Tenant List View**
   - View all tenants with status indicators
   - Search and filter tenants
   - Quick actions: Edit, Suspend, Delete

2. **Tenant Details**
   - Click on any tenant to view detailed information
   - Monitor resource usage and billing
   - View tenant-specific logs and activities

3. **Tenant Modifications**
   - Update tenant information
   - Modify resource limits
   - Change feature enablement
   - Suspend or reactivate tenants

## User Management

### Creating User Accounts

1. **Access User Management**
   - Navigate to **Users** in the main menu
   - Click **"Add New User"** button

2. **User Information**
   - **Personal Details**: Name, email, phone number
   - **Employee ID**: Unique identifier within the organization
   - **Department**: Organizational department
   - **Job Title**: User's role/position
   - **Manager**: Reporting manager (for approval workflows)

3. **Account Settings**
   - **Username**: Login username (auto-generated or custom)
   - **Temporary Password**: Initial password (user must change on first login)
   - **Account Status**: Active, Inactive, Suspended
   - **Account Expiration**: Set expiration date if applicable

4. **Role Assignment**
   - **Primary Role**: Select from predefined roles
   - **Additional Permissions**: Grant specific permissions
   - **Access Groups**: Assign to access control groups
   - **Tenant Access**: Multi-tenant access permissions

5. **Mobile Credentials**
   - **Enable Mobile Access**: Allow mobile credential usage
   - **Device Registration**: Pre-register mobile devices
   - **Credential Expiration**: Set mobile credential validity period

### User Role Management

1. **Predefined Roles**
   - **Administrator**: Full system access
   - **Security Officer**: Security operations and monitoring
   - **Facilities Manager**: Environmental and device management
   - **Visitor Coordinator**: Visitor management functions
   - **Employee**: Basic access and self-service functions

2. **Custom Role Creation**
   - Navigate to **Users** > **Roles**
   - Click **"Create Custom Role"**
   - Define role name and description
   - Select specific permissions from categories:
     - User Management
     - Access Control
     - Video Surveillance
     - Environmental Monitoring
     - Device Management
     - Reporting and Analytics
     - System Configuration

3. **Permission Categories**
   - **Read**: View information
   - **Write**: Create and modify
   - **Delete**: Remove items
   - **Execute**: Perform actions
   - **Admin**: Full administrative access

### Bulk User Operations

1. **Bulk Import**
   - Download CSV template
   - Populate user information
   - Upload CSV file
   - Review and validate import
   - Execute bulk creation

2. **Bulk Updates**
   - Select multiple users
   - Apply bulk changes:
     - Role assignments
     - Department changes
     - Status updates
     - Access group modifications

## Access Control Configuration

### Door Controller Setup

1. **Adding Door Controllers**
   - Navigate to **Access Control** > **Controllers**
   - Click **"Add Controller"**
   - Enter controller details:
     - **Name**: Descriptive name for the door
     - **Location**: Physical location description
     - **IP Address**: Network address of the controller
     - **MAC Address**: Hardware identifier
     - **Controller Type**: Select from supported models

2. **Controller Configuration**
   - **Network Settings**: IP configuration and connectivity
   - **Security Settings**: Encryption and authentication
   - **Operating Mode**: Online, offline, or hybrid
   - **Backup Settings**: Local storage and failover options

3. **Door Settings**
   - **Door Type**: Entry, exit, or bidirectional
   - **Unlock Duration**: How long door remains unlocked
   - **Anti-passback**: Prevent credential reuse
   - **Forced Door Monitoring**: Alert on forced entry
   - **Door Position Monitoring**: Monitor door open/closed status

### Access Groups and Policies

1. **Creating Access Groups**
   - Navigate to **Access Control** > **Access Groups**
   - Click **"Create Access Group"**
   - Define group properties:
     - **Group Name**: Descriptive name
     - **Description**: Purpose and scope
     - **Priority Level**: Access priority ranking

2. **Time Schedules**
   - **Schedule Name**: Descriptive identifier
   - **Time Zones**: Define allowed access times
   - **Days of Week**: Specify applicable days
   - **Holidays**: Configure holiday schedules
   - **Exceptions**: Special date overrides

3. **Access Rules**
   - **Door Assignments**: Select controlled doors
   - **User Groups**: Assign user groups to access
   - **Time Schedules**: Apply time-based restrictions
   - **Visitor Rules**: Configure visitor access
   - **Emergency Overrides**: Define emergency access procedures

### Mobile Credential Management

1. **Mobile Credential Policies**
   - Navigate to **Access Control** > **Mobile Credentials**
   - Configure policy settings:
     - **Credential Validity**: Expiration periods
     - **Device Limits**: Maximum devices per user
     - **Offline Duration**: Offline operation limits
     - **Revocation Policies**: Automatic revocation triggers

2. **Device Registration**
   - **Self-Registration**: Allow user self-registration
   - **Admin Registration**: Administrator-managed registration
   - **Device Approval**: Require approval for new devices
   - **Device Verification**: Multi-factor device verification

3. **Mesh Networking Configuration**
   - **Mesh Network Settings**: Configure peer-to-peer communication
   - **Credential Propagation**: Offline credential distribution
   - **Conflict Resolution**: Handle offline/online synchronization
   - **Security Keys**: Manage mesh network encryption

## Video System Setup

### Camera Configuration

1. **Adding Cameras**
   - Navigate to **Video** > **Cameras**
   - Click **"Add Camera"**
   - Enter camera details:
     - **Camera Name**: Descriptive identifier
     - **Location**: Physical location
     - **IP Address**: Network address
     - **Camera Model**: Select from supported models
     - **Stream URLs**: Primary and secondary streams

2. **Camera Settings**
   - **Video Quality**: Resolution and frame rate
   - **Compression**: H.264, H.265 settings
   - **Night Vision**: IR and low-light settings
   - **Motion Detection**: Sensitivity and zones
   - **Audio Recording**: Enable/disable audio capture

3. **Network Configuration**
   - **Bandwidth Management**: Limit bandwidth usage
   - **Stream Profiles**: Multiple quality profiles
   - **Failover Settings**: Backup stream configuration
   - **Security**: Authentication and encryption

### Video Analytics

1. **Analytics Configuration**
   - Navigate to **Video** > **Analytics**
   - Enable analytics features:
     - **Motion Detection**: Basic movement detection
     - **Object Recognition**: People, vehicles, objects
     - **Facial Recognition**: Identity verification
     - **Behavior Analysis**: Unusual activity detection
     - **Crowd Detection**: Occupancy monitoring

2. **Alert Configuration**
   - **Motion Alerts**: Configure motion-based alerts
   - **Recognition Alerts**: Identity-based notifications
   - **Behavior Alerts**: Unusual activity warnings
   - **System Alerts**: Camera offline, tampering detection

3. **Privacy Settings**
   - **Privacy Zones**: Mask sensitive areas
   - **Recording Restrictions**: Limit recording in certain areas
   - **Access Controls**: Restrict video access by role
   - **Retention Policies**: Automatic deletion schedules

### Video Storage Management

1. **Storage Configuration**
   - **Local Storage**: On-premises storage settings
   - **Cloud Storage**: Cloud backup configuration
   - **Retention Policies**: Define storage duration
   - **Compression Settings**: Optimize storage usage

2. **Backup and Archive**
   - **Automatic Backup**: Schedule regular backups
   - **Archive Policies**: Long-term storage rules
   - **Export Functions**: Video export capabilities
   - **Disaster Recovery**: Backup restoration procedures

## Device Management

### Device Registration

1. **Adding Devices**
   - Navigate to **Devices** > **Device Registry**
   - Click **"Register Device"**
   - Enter device information:
     - **Device Type**: Controller, sensor, camera, etc.
     - **Device ID**: Unique identifier
     - **Location**: Physical installation location
     - **Network Address**: IP or MAC address

2. **Device Configuration**
   - **Communication Settings**: Protocol and connectivity
   - **Security Settings**: Authentication and encryption
   - **Operating Parameters**: Device-specific settings
   - **Maintenance Schedule**: Planned maintenance intervals

3. **Device Groups**
   - **Group Creation**: Organize devices by location or type
   - **Bulk Configuration**: Apply settings to multiple devices
   - **Group Policies**: Standardized configuration policies

### Device Monitoring

1. **Health Monitoring**
   - **Status Dashboard**: Real-time device status
   - **Performance Metrics**: Device performance indicators
   - **Connectivity Monitoring**: Network connectivity status
   - **Battery Levels**: Wireless device battery monitoring

2. **Alert Configuration**
   - **Device Offline Alerts**: Connectivity loss notifications
   - **Performance Alerts**: Performance degradation warnings
   - **Maintenance Alerts**: Scheduled maintenance reminders
   - **Security Alerts**: Tampering or security breach notifications

3. **Diagnostic Tools**
   - **Device Testing**: Remote device testing capabilities
   - **Log Collection**: Gather device logs for troubleshooting
   - **Firmware Updates**: Remote firmware management
   - **Configuration Backup**: Device configuration backups

## Environmental Monitoring Configuration

### Sensor Setup

1. **Adding Environmental Sensors**
   - Navigate to **Environmental** > **Sensors**
   - Click **"Add Sensor"**
   - Configure sensor details:
     - **Sensor Type**: Temperature, humidity, air quality, etc.
     - **Location**: Physical installation location
     - **Measurement Range**: Operating range and units
     - **Calibration Settings**: Accuracy calibration

2. **Sensor Configuration**
   - **Sampling Rate**: Data collection frequency
   - **Transmission Interval**: Data transmission frequency
   - **Power Management**: Battery optimization settings
   - **Connectivity**: Wireless or wired connection settings

3. **Sensor Groups**
   - **Zone Configuration**: Group sensors by physical zones
   - **Monitoring Profiles**: Different monitoring configurations
   - **Correlation Rules**: Inter-sensor relationship rules

### Environmental Monitoring Rules

1. **Threshold Configuration**
   - **Normal Ranges**: Define acceptable value ranges
   - **Warning Thresholds**: Early warning levels
   - **Critical Thresholds**: Emergency alert levels
   - **Hysteresis Settings**: Prevent alert oscillation

2. **Alert Policies**
   - **Immediate Alerts**: Real-time critical notifications
   - **Escalation Rules**: Progressive alert escalation
   - **Notification Methods**: Email, SMS, dashboard alerts
   - **Response Procedures**: Automated response actions

3. **Compliance Monitoring**
   - **Regulatory Requirements**: Industry-specific compliance
   - **Audit Trails**: Environmental data logging
   - **Reporting Schedules**: Automated compliance reports
   - **Data Retention**: Long-term data storage policies

### HVAC Integration

1. **HVAC System Connection**
   - **System Discovery**: Automatic HVAC system detection
   - **Protocol Configuration**: BACnet, Modbus, or proprietary protocols
   - **Control Points**: Temperature, humidity, air flow controls
   - **Monitoring Points**: System status and performance metrics

2. **Automated Controls**
   - **Response Actions**: Automatic HVAC adjustments
   - **Energy Optimization**: Efficiency-based control algorithms
   - **Occupancy-Based Control**: Presence-aware climate control
   - **Emergency Procedures**: Emergency shutdown and safety protocols

## System Maintenance

### Backup and Recovery

1. **Backup Configuration**
   - Navigate to **Settings** > **Backup & Recovery**
   - Configure backup settings:
     - **Backup Schedule**: Daily, weekly, monthly schedules
     - **Backup Scope**: Full system or selective backups
     - **Storage Location**: Local or cloud storage
     - **Retention Policy**: Backup retention duration

2. **Recovery Procedures**
   - **System Recovery**: Full system restoration
   - **Selective Recovery**: Partial data restoration
   - **Point-in-Time Recovery**: Restore to specific timestamps
   - **Disaster Recovery**: Complete disaster recovery procedures

3. **Backup Verification**
   - **Backup Testing**: Regular backup integrity testing
   - **Recovery Testing**: Periodic recovery procedure testing
   - **Documentation**: Maintain recovery procedure documentation

### System Updates

1. **Software Updates**
   - **Update Notifications**: Automatic update notifications
   - **Update Scheduling**: Schedule updates during maintenance windows
   - **Rollback Procedures**: Revert to previous versions if needed
   - **Testing Environment**: Test updates before production deployment

2. **Firmware Updates**
   - **Device Firmware**: Update device firmware remotely
   - **Batch Updates**: Update multiple devices simultaneously
   - **Update Verification**: Verify successful firmware updates
   - **Rollback Capability**: Revert firmware if issues occur

3. **Security Patches**
   - **Security Notifications**: Critical security update alerts
   - **Emergency Patching**: Rapid deployment of security fixes
   - **Vulnerability Assessment**: Regular security vulnerability scans
   - **Patch Documentation**: Maintain patch deployment records

### Performance Monitoring

1. **System Performance**
   - **Resource Utilization**: CPU, memory, storage monitoring
   - **Network Performance**: Bandwidth and latency monitoring
   - **Database Performance**: Query performance and optimization
   - **Application Performance**: Response time and throughput metrics

2. **Capacity Planning**
   - **Growth Projections**: Predict future resource needs
   - **Scaling Recommendations**: Horizontal and vertical scaling options
   - **Resource Optimization**: Optimize current resource usage
   - **Cost Analysis**: Performance vs. cost optimization

3. **Performance Alerts**
   - **Threshold Monitoring**: Performance threshold alerts
   - **Trend Analysis**: Performance trend notifications
   - **Predictive Alerts**: Proactive performance warnings
   - **Automated Responses**: Automatic performance optimization actions

## Troubleshooting

### Common Issues

1. **Authentication Problems**
   - **Symptom**: Users cannot log in
   - **Causes**: Expired passwords, account lockouts, MFA issues
   - **Solutions**: 
     - Reset passwords through admin interface
     - Unlock accounts in user management
     - Verify MFA device registration
     - Check authentication service status

2. **Access Control Issues**
   - **Symptom**: Doors not responding to credentials
   - **Causes**: Controller offline, credential sync issues, time schedule conflicts
   - **Solutions**:
     - Verify controller connectivity
     - Force credential synchronization
     - Check access group assignments
     - Validate time schedules

3. **Video System Problems**
   - **Symptom**: Cameras offline or poor video quality
   - **Causes**: Network connectivity, bandwidth limitations, camera hardware issues
   - **Solutions**:
     - Check network connectivity
     - Adjust video quality settings
     - Restart camera devices
     - Verify power supply

### Diagnostic Tools

1. **System Health Dashboard**
   - **Service Status**: Real-time service health indicators
   - **Performance Metrics**: Key performance indicators
   - **Error Logs**: Recent error and warning messages
   - **Resource Usage**: System resource utilization

2. **Network Diagnostics**
   - **Connectivity Tests**: Test device connectivity
   - **Bandwidth Analysis**: Network bandwidth utilization
   - **Latency Monitoring**: Network latency measurements
   - **Packet Loss Detection**: Network reliability metrics

3. **Log Analysis**
   - **Centralized Logging**: Unified log collection and analysis
   - **Log Filtering**: Filter logs by service, severity, or time
   - **Error Correlation**: Correlate errors across services
   - **Export Capabilities**: Export logs for external analysis

### Support Procedures

1. **Internal Support**
   - **Documentation Review**: Check relevant documentation
   - **Knowledge Base**: Search internal knowledge base
   - **Escalation Procedures**: Internal escalation paths
   - **Issue Tracking**: Track and document issues

2. **Vendor Support**
   - **Support Contacts**: Vendor support contact information
   - **Support Levels**: Different support tier procedures
   - **Information Gathering**: Collect necessary diagnostic information
   - **Remote Access**: Provide secure remote access when needed

## Security Best Practices

### Access Control Security

1. **Principle of Least Privilege**
   - Grant minimum necessary permissions
   - Regular access reviews and audits
   - Remove unnecessary access promptly
   - Document access justifications

2. **Multi-Factor Authentication**
   - Enforce MFA for all administrative accounts
   - Use hardware tokens for high-privilege accounts
   - Regular MFA device audits
   - Backup authentication methods

3. **Password Policies**
   - Strong password requirements
   - Regular password changes
   - Password history enforcement
   - Account lockout policies

### Network Security

1. **Network Segmentation**
   - Isolate SPARC network segments
   - Implement VLANs for different device types
   - Use firewalls between network segments
   - Monitor inter-segment traffic

2. **Encryption**
   - Encrypt all data in transit
   - Use strong encryption algorithms
   - Regular encryption key rotation
   - Secure key management

3. **Monitoring and Logging**
   - Comprehensive audit logging
   - Real-time security monitoring
   - Automated threat detection
   - Regular log analysis

### Compliance Management

1. **Regulatory Compliance**
   - Understand applicable regulations
   - Implement required controls
   - Regular compliance assessments
   - Maintain compliance documentation

2. **Audit Preparation**
   - Maintain audit trails
   - Document security procedures
   - Regular internal audits
   - External audit coordination

## Appendices

### Appendix A: Default Port Configurations

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| Web Interface | 443 | HTTPS | Main web application |
| API Gateway | 8443 | HTTPS | REST API access |
| Database | 5432 | TCP | PostgreSQL database |
| Message Queue | 5672 | AMQP | RabbitMQ messaging |
| Video Streaming | 1935 | RTMP | Video stream protocol |
| Device Communication | 4001 | TCP | Device control protocol |

### Appendix B: API Endpoints Reference

#### Authentication Endpoints
- `POST /api/auth/login` - User authentication
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Token refresh
- `GET /api/auth/profile` - User profile

#### User Management Endpoints
- `GET /api/users` - List users
- `POST /api/users` - Create user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

#### Access Control Endpoints
- `GET /api/access/controllers` - List controllers
- `POST /api/access/controllers` - Add controller
- `GET /api/access/groups` - List access groups
- `POST /api/access/unlock/{controllerId}` - Unlock door

### Appendix C: Error Codes Reference

| Error Code | Description | Resolution |
|------------|-------------|------------|
| AUTH001 | Invalid credentials | Verify username and password |
| AUTH002 | Account locked | Contact administrator |
| AUTH003 | MFA required | Complete MFA verification |
| AC001 | Controller offline | Check network connectivity |
| AC002 | Access denied | Verify access permissions |
| VID001 | Camera offline | Check camera power and network |
| VID002 | Stream unavailable | Verify stream configuration |

### Appendix D: Maintenance Schedules

#### Daily Tasks
- Review system alerts and notifications
- Monitor system performance metrics
- Check backup completion status
- Review security event logs

#### Weekly Tasks
- Review user access reports
- Update device firmware if available
- Analyze performance trends
- Test backup restoration procedures

#### Monthly Tasks
- Conduct security access reviews
- Update system documentation
- Review and update emergency procedures
- Perform capacity planning analysis

#### Quarterly Tasks
- Conduct comprehensive security audits
- Review and update security policies
- Test disaster recovery procedures
- Update vendor contact information

### Appendix E: Contact Information

#### Internal Support
- **IT Helpdesk**: ext. 1234
- **Security Team**: ext. 5678
- **Facilities Management**: ext. 9012

#### Vendor Support
- **SPARC Platform Support**: support@sparc.platform
- **Emergency Support**: +1-800-SPARC-911
- **Documentation**: docs.sparc.platform

---

*This administrator guide is maintained by the SPARC Platform team. For updates and additional documentation, visit the internal documentation portal.*

**Document Version**: 1.0  
**Last Updated**: [Current Date]  
**Next Review**: [Date + 6 months]