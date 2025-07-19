# SPARC API Common Use Cases

This guide provides practical examples of common use cases for the SPARC Security Platform API. Each example includes complete code samples and best practices.

## Table of Contents

1. [Video Surveillance](#video-surveillance)
2. [Access Control Management](#access-control-management)
3. [Real-time Monitoring](#real-time-monitoring)
4. [Incident Management](#incident-management)
5. [Analytics and Reporting](#analytics-and-reporting)
6. [Visitor Management](#visitor-management)
7. [Integration Scenarios](#integration-scenarios)

## Video Surveillance

### 1. Display Live Video Feed

**Use Case**: Display live video from multiple cameras on a monitoring dashboard.

```javascript
// Initialize video monitoring dashboard
class VideoMonitor {
  constructor(apiClient) {
    this.api = apiClient;
    this.activeCameras = new Map();
  }

  async initializeDashboard(siteId) {
    // Get all cameras for the site
    const cameras = await this.api.get('/api/video/cameras', {
      params: { siteId, status: 'online' }
    });

    // Initialize video players
    for (const camera of cameras.data.cameras) {
      await this.startLiveStream(camera);
    }
  }

  async startLiveStream(camera) {
    // Get live stream URL
    const stream = await this.api.get(`/api/video/streams/${camera.id}/live`, {
      params: { protocol: 'hls', quality: 'auto' }
    });

    // Initialize HLS player
    const video = document.getElementById(`camera-${camera.id}`);
    if (Hls.isSupported()) {
      const hls = new Hls({
        enableWorker: true,
        lowLatencyMode: true,
        backBufferLength: 90
      });
      
      hls.loadSource(stream.data.urls.high);
      hls.attachMedia(video);
      
      hls.on(Hls.Events.MANIFEST_PARSED, () => {
        video.play();
      });

      this.activeCameras.set(camera.id, { camera, hls });
    }
  }

  async switchQuality(cameraId, quality) {
    const cameraData = this.activeCameras.get(cameraId);
    if (!cameraData) return;

    const stream = await this.api.get(`/api/video/streams/${cameraId}/live`, {
      params: { protocol: 'hls', quality }
    });

    cameraData.hls.loadSource(stream.data.urls[quality]);
  }

  cleanup() {
    // Clean up resources
    this.activeCameras.forEach(({ hls }) => {
      hls.destroy();
    });
    this.activeCameras.clear();
  }
}

// Usage
const monitor = new VideoMonitor(apiClient);
await monitor.initializeDashboard('site-123');
```

### 2. Search and Playback Recorded Video

**Use Case**: Search for recorded video by time range and play back with timeline navigation.

```javascript
class VideoPlayback {
  constructor(apiClient) {
    this.api = apiClient;
  }

  async searchRecordings(cameraId, timeRange) {
    const recordings = await this.api.get('/api/video/recordings', {
      params: {
        cameraId,
        startTime: timeRange.start.toISOString(),
        endTime: timeRange.end.toISOString(),
        hasEvents: true  // Only recordings with detected events
      }
    });

    return recordings.data.recordings;
  }

  async getTimeline(recordingId) {
    const timeline = await this.api.get(`/api/video/recordings/${recordingId}/timeline`);
    return timeline.data;
  }

  async playRecording(recordingId, startOffset = 0) {
    // Get playback stream
    const playback = await this.api.get(`/api/video/recordings/${recordingId}/stream`, {
      params: { startOffset, speed: 1 }
    });

    // Initialize player with timeline
    const timeline = await this.getTimeline(recordingId);
    
    return {
      url: playback.data.url,
      timeline: timeline,
      duration: playback.data.duration
    };
  }

  async exportClip(cameraId, startTime, endTime) {
    // Create export job
    const exportJob = await this.api.post('/api/video/exports', {
      cameraId,
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      format: 'mp4',
      quality: 'high',
      watermark: true
    });

    // Poll for completion
    return this.pollExportStatus(exportJob.data.id);
  }

  async pollExportStatus(exportId) {
    const checkStatus = async () => {
      const status = await this.api.get(`/api/video/exports/${exportId}`);
      
      if (status.data.status === 'completed') {
        return status.data;
      } else if (status.data.status === 'failed') {
        throw new Error(status.data.error);
      }
      
      // Check again in 2 seconds
      await new Promise(resolve => setTimeout(resolve, 2000));
      return checkStatus();
    };

    return checkStatus();
  }
}

// Usage
const playback = new VideoPlayback(apiClient);

// Search for incidents yesterday
const yesterday = new Date();
yesterday.setDate(yesterday.getDate() - 1);
const recordings = await playback.searchRecordings('camera-123', {
  start: new Date(yesterday.setHours(0, 0, 0, 0)),
  end: new Date(yesterday.setHours(23, 59, 59, 999))
});

// Play first recording
if (recordings.length > 0) {
  const { url, timeline } = await playback.playRecording(recordings[0].id);
  // Initialize video player with URL and timeline
}
```

### 3. PTZ Camera Control

**Use Case**: Control PTZ cameras for active monitoring and preset management.

```javascript
class PTZController {
  constructor(apiClient) {
    this.api = apiClient;
    this.activeControl = null;
  }

  async controlCamera(cameraId, action, parameters) {
    const response = await this.api.post(`/api/video/cameras/${cameraId}/ptz`, {
      action,
      parameters
    });
    
    return response.data;
  }

  // Continuous pan/tilt control
  async startContinuousMove(cameraId, direction, speed = 0.5) {
    this.activeControl = setInterval(async () => {
      await this.controlCamera(cameraId, 'pan', {
        direction,
        speed
      });
    }, 100); // Send command every 100ms
  }

  stopContinuousMove() {
    if (this.activeControl) {
      clearInterval(this.activeControl);
      this.activeControl = null;
    }
  }

  // Absolute positioning
  async moveToPosition(cameraId, x, y, zoom) {
    return this.controlCamera(cameraId, 'absolute', {
      x, // -1 to 1
      y, // -1 to 1
      zoom // 0 to 1
    });
  }

  // Preset management
  async getPresets(cameraId) {
    const response = await this.api.get(`/api/video/cameras/${cameraId}/ptz/presets`);
    return response.data.presets;
  }

  async goToPreset(cameraId, presetId) {
    return this.controlCamera(cameraId, 'preset', { presetId });
  }

  async createTour(cameraId, presets, dwellTime = 10) {
    let currentIndex = 0;
    
    const tour = setInterval(async () => {
      await this.goToPreset(cameraId, presets[currentIndex].id);
      currentIndex = (currentIndex + 1) % presets.length;
    }, dwellTime * 1000);

    return {
      stop: () => clearInterval(tour)
    };
  }
}

// Usage
const ptz = new PTZController(apiClient);

// Move camera left
await ptz.startContinuousMove('camera-123', 'left', 0.7);
setTimeout(() => ptz.stopContinuousMove(), 2000); // Stop after 2 seconds

// Go to entrance preset
await ptz.goToPreset('camera-123', 'preset-entrance');

// Create automatic tour
const presets = await ptz.getPresets('camera-123');
const tour = await ptz.createTour('camera-123', presets, 15);
// Stop tour after 5 minutes
setTimeout(() => tour.stop(), 5 * 60 * 1000);
```

## Access Control Management

### 1. Real-time Door Monitoring

**Use Case**: Monitor door status and access events in real-time.

```javascript
class AccessMonitor {
  constructor(apiClient) {
    this.api = apiClient;
    this.eventSource = null;
  }

  async monitorSite(siteId) {
    // Get all access points
    const accessPoints = await this.api.get('/api/access/access-points', {
      params: { siteId }
    });

    // Subscribe to real-time events
    this.subscribeToEvents(siteId);

    return accessPoints.data.accessPoints;
  }

  subscribeToEvents(siteId) {
    const eventSource = new EventSource(
      `${this.api.defaults.baseURL}/api/access/events/stream?siteId=${siteId}`,
      {
        headers: {
          'Authorization': `Bearer ${this.api.defaults.headers.Authorization}`
        }
      }
    );

    eventSource.addEventListener('access_event', (event) => {
      const data = JSON.parse(event.data);
      this.handleAccessEvent(data);
    });

    eventSource.addEventListener('door_status', (event) => {
      const data = JSON.parse(event.data);
      this.handleDoorStatus(data);
    });

    this.eventSource = eventSource;
  }

  handleAccessEvent(event) {
    console.log('Access event:', event);
    
    // Update UI based on event
    if (event.outcome === 'denied') {
      this.showAlert({
        type: 'warning',
        message: `Access denied at ${event.accessPointName}`,
        details: event
      });
    }
    
    // Log to activity feed
    this.updateActivityFeed(event);
  }

  handleDoorStatus(status) {
    // Update door status indicator
    const indicator = document.getElementById(`door-${status.accessPointId}`);
    if (indicator) {
      indicator.className = `door-status ${status.state}`;
      indicator.title = `${status.state} - ${status.alarm ? 'ALARM' : 'Normal'}`;
    }
  }

  async unlockDoor(accessPointId, duration = 5) {
    try {
      await this.api.post(`/api/access/access-points/${accessPointId}/control`, {
        command: 'momentary_unlock',
        duration,
        reason: 'Remote unlock by operator'
      });
      
      this.showNotification({
        type: 'success',
        message: 'Door unlocked successfully'
      });
    } catch (error) {
      this.showNotification({
        type: 'error',
        message: 'Failed to unlock door'
      });
    }
  }

  cleanup() {
    if (this.eventSource) {
      this.eventSource.close();
    }
  }
}

// Usage
const accessMonitor = new AccessMonitor(apiClient);
const accessPoints = await accessMonitor.monitorSite('site-123');

// Remote unlock
await accessMonitor.unlockDoor('door-456');
```

### 2. Credential Management

**Use Case**: Manage user credentials and access permissions.

```javascript
class CredentialManager {
  constructor(apiClient) {
    this.api = apiClient;
  }

  async createCredential(userId, type = 'badge') {
    // Generate unique badge number
    const badgeNumber = this.generateBadgeNumber();
    
    const credential = await this.api.post('/api/access/credentials', {
      type,
      code: badgeNumber,
      userId,
      expiresAt: this.getExpirationDate(),
      accessGroups: ['default-employee']
    });

    return credential.data;
  }

  async assignAccessGroups(credentialId, accessGroups) {
    const response = await this.api.put(`/api/access/credentials/${credentialId}`, {
      accessGroups
    });
    
    return response.data;
  }

  async createTemporaryAccess(visitorInfo, validHours = 8) {
    // Create visitor user
    const visitor = await this.api.post('/api/users/visitors', visitorInfo);
    
    // Create temporary credential
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + validHours);
    
    const credential = await this.api.post('/api/access/credentials', {
      type: 'badge',
      code: this.generateVisitorBadge(),
      userId: visitor.data.id,
      expiresAt: expiresAt.toISOString(),
      accessGroups: ['visitor-areas'],
      metadata: {
        host: visitorInfo.hostId,
        purpose: visitorInfo.purpose
      }
    });

    // Create access rules for specific areas
    if (visitorInfo.allowedAreas) {
      await this.createVisitorAccessRules(credential.data.id, visitorInfo.allowedAreas);
    }

    return {
      visitor: visitor.data,
      credential: credential.data
    };
  }

  async suspendCredential(credentialId, reason) {
    await this.api.put(`/api/access/credentials/${credentialId}`, {
      status: 'suspended',
      metadata: {
        suspendedAt: new Date().toISOString(),
        suspendedReason: reason
      }
    });
  }

  async trackCredentialUsage(credentialId, days = 30) {
    const endTime = new Date();
    const startTime = new Date();
    startTime.setDate(startTime.getDate() - days);

    const events = await this.api.get('/api/access/events', {
      params: {
        credentialId,
        startTime: startTime.toISOString(),
        endTime: endTime.toISOString(),
        pageSize: 100
      }
    });

    // Analyze usage patterns
    const usage = this.analyzeUsagePatterns(events.data.events);
    
    return {
      totalEvents: events.data.events.length,
      uniqueDoors: usage.uniqueDoors,
      peakHours: usage.peakHours,
      unusualActivity: usage.anomalies
    };
  }

  generateBadgeNumber() {
    // Generate unique badge number with facility code
    const facilityCode = '123';
    const cardNumber = Math.floor(Math.random() * 65535);
    return `${facilityCode}:${cardNumber}`;
  }

  generateVisitorBadge() {
    return `V${Date.now()}`;
  }
}

// Usage
const credManager = new CredentialManager(apiClient);

// Create employee badge
const credential = await credManager.createCredential('user-123', 'badge');

// Create visitor access
const visitorAccess = await credManager.createTemporaryAccess({
  firstName: 'John',
  lastName: 'Visitor',
  email: 'visitor@example.com',
  company: 'ABC Corp',
  hostId: 'user-456',
  purpose: 'Business meeting',
  allowedAreas: ['lobby', 'conference-room-a']
}, 4); // 4 hour access

// Monitor credential usage
const usage = await credManager.trackCredentialUsage(credential.id, 7);
```

## Real-time Monitoring

### 1. Unified Security Dashboard

**Use Case**: Create a real-time security operations center dashboard.

```javascript
class SecurityDashboard {
  constructor(apiClient) {
    this.api = apiClient;
    this.websocket = null;
    this.metrics = {};
  }

  async initialize(organizationId) {
    // Connect to WebSocket
    await this.connectWebSocket(organizationId);
    
    // Load initial metrics
    await this.loadMetrics();
    
    // Start metric refresh
    this.startMetricRefresh();
  }

  async connectWebSocket(organizationId) {
    const token = localStorage.getItem('accessToken');
    const ws = new WebSocket(`wss://api.sparc.security/v1/ws?token=${token}`);

    ws.onopen = () => {
      // Subscribe to multiple channels
      ws.send(JSON.stringify({
        type: 'subscribe',
        channels: ['alerts', 'events', 'system'],
        filters: {
          organizationId,
          severity: ['medium', 'high', 'critical']
        }
      }));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.handleRealtimeUpdate(data);
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      this.reconnectWebSocket();
    };

    this.websocket = ws;
  }

  async loadMetrics() {
    const metrics = await this.api.get('/api/analytics/metrics/realtime', {
      params: {
        metrics: [
          'active_incidents',
          'online_cameras',
          'active_users',
          'door_status',
          'alarm_count',
          'response_time'
        ]
      }
    });

    this.metrics = metrics.data.metrics;
    this.updateDashboard();
  }

  handleRealtimeUpdate(data) {
    switch (data.type) {
      case 'alert':
        this.handleNewAlert(data.payload);
        break;
      case 'incident_update':
        this.updateIncident(data.payload);
        break;
      case 'system_status':
        this.updateSystemStatus(data.payload);
        break;
      case 'metric_update':
        this.updateMetric(data.payload);
        break;
    }
  }

  handleNewAlert(alert) {
    // Add to alert queue
    this.addToAlertQueue(alert);
    
    // Show notification
    if (alert.severity === 'critical') {
      this.showCriticalAlert(alert);
      this.playAlarmSound();
    }
    
    // Update incident count
    this.metrics.active_incidents.value++;
    this.updateMetricDisplay('active_incidents');
  }

  async acknowledgeAlert(alertId) {
    await this.api.post(`/api/alert/alerts/${alertId}/acknowledge`, {
      acknowledgedBy: this.currentUser.id,
      notes: 'Acknowledged from dashboard'
    });
  }

  updateDashboard() {
    // Update all metric displays
    Object.entries(this.metrics).forEach(([key, data]) => {
      this.updateMetricDisplay(key, data);
    });
  }

  updateMetricDisplay(metricKey, data = this.metrics[metricKey]) {
    const element = document.getElementById(`metric-${metricKey}`);
    if (element) {
      element.querySelector('.value').textContent = data.value;
      element.querySelector('.unit').textContent = data.unit || '';
      element.className = `metric ${data.status}`;
      
      // Update trend indicator
      if (data.trend) {
        element.querySelector('.trend').className = `trend ${data.trend}`;
        element.querySelector('.change').textContent = `${data.change > 0 ? '+' : ''}${data.change}%`;
      }
    }
  }

  startMetricRefresh() {
    setInterval(() => this.loadMetrics(), 30000); // Refresh every 30 seconds
  }
}

// Usage
const dashboard = new SecurityDashboard(apiClient);
await dashboard.initialize('org-123');
```

### 2. Multi-Site Monitoring

**Use Case**: Monitor multiple sites from a central location.

```javascript
class MultiSiteMonitor {
  constructor(apiClient) {
    this.api = apiClient;
    this.sites = new Map();
    this.activeAlerts = new Map();
  }

  async loadSites() {
    const response = await this.api.get('/api/tenant/sites');
    
    for (const site of response.data.sites) {
      await this.initializeSite(site);
    }
  }

  async initializeSite(site) {
    // Get site overview
    const [cameras, doors, activeIncidents] = await Promise.all([
      this.api.get('/api/video/cameras', { params: { siteId: site.id } }),
      this.api.get('/api/access/access-points', { params: { siteId: site.id } }),
      this.api.get('/api/alert/alerts', {
        params: {
          siteId: site.id,
          status: 'active',
          startTime: new Date(Date.now() - 24*60*60*1000).toISOString()
        }
      })
    ]);

    const siteData = {
      info: site,
      cameras: cameras.data.cameras,
      doors: doors.data.accessPoints,
      incidents: activeIncidents.data.alerts,
      status: this.calculateSiteStatus(cameras.data, doors.data, activeIncidents.data)
    };

    this.sites.set(site.id, siteData);
    this.renderSiteCard(siteData);
  }

  calculateSiteStatus(cameras, doors, incidents) {
    const onlineCameras = cameras.cameras.filter(c => c.status === 'online').length;
    const totalCameras = cameras.cameras.length;
    const cameraHealth = totalCameras > 0 ? onlineCameras / totalCameras : 1;

    const criticalIncidents = incidents.alerts.filter(a => a.severity === 'critical').length;
    
    if (criticalIncidents > 0) return 'critical';
    if (cameraHealth < 0.8) return 'warning';
    if (incidents.alerts.length > 5) return 'elevated';
    return 'normal';
  }

  async focusOnSite(siteId) {
    const site = this.sites.get(siteId);
    if (!site) return;

    // Load detailed view
    const detailView = document.getElementById('site-detail');
    detailView.innerHTML = this.renderSiteDetail(site);

    // Start live camera feeds for top 4 cameras
    const topCameras = site.cameras.slice(0, 4);
    for (const camera of topCameras) {
      await this.startCameraFeed(camera);
    }

    // Subscribe to site-specific events
    this.subscribeToSiteEvents(siteId);
  }

  renderSiteCard(site) {
    return `
      <div class="site-card ${site.status}" data-site-id="${site.info.id}">
        <h3>${site.info.name}</h3>
        <div class="site-location">${site.info.address.city}, ${site.info.address.state}</div>
        <div class="site-metrics">
          <div class="metric">
            <span class="label">Cameras</span>
            <span class="value">${site.cameras.filter(c => c.status === 'online').length}/${site.cameras.length}</span>
          </div>
          <div class="metric">
            <span class="label">Active Incidents</span>
            <span class="value ${site.incidents.length > 0 ? 'alert' : ''}">${site.incidents.length}</span>
          </div>
        </div>
        <div class="site-status">
          Status: <span class="status-${site.status}">${site.status.toUpperCase()}</span>
        </div>
      </div>
    `;
  }
}

// Usage
const multiSite = new MultiSiteMonitor(apiClient);
await multiSite.loadSites();

// Focus on specific site
await multiSite.focusOnSite('site-123');
```

## Incident Management

### 1. Automated Incident Response

**Use Case**: Automatically respond to security incidents based on type and severity.

```javascript
class IncidentResponseSystem {
  constructor(apiClient) {
    this.api = apiClient;
    this.responseTemplates = new Map();
    this.activeIncidents = new Map();
  }

  async initialize() {
    // Load response templates
    await this.loadResponseTemplates();
    
    // Subscribe to new alerts
    this.subscribeToAlerts();
  }

  async loadResponseTemplates() {
    // Define automated response templates
    this.responseTemplates.set('intrusion_detected', {
      severity: 'critical',
      actions: [
        { type: 'lock_doors', zones: ['affected'] },
        { type: 'trigger_alarm', duration: 300 },
        { type: 'notify', recipients: ['security', 'management'] },
        { type: 'record_all_cameras', duration: 600 },
        { type: 'dispatch_security', priority: 'high' }
      ]
    });

    this.responseTemplates.set('fire_alarm', {
      severity: 'critical',
      actions: [
        { type: 'unlock_doors', zones: ['all'] },
        { type: 'trigger_alarm', pattern: 'evacuation' },
        { type: 'notify', recipients: ['all', 'fire_department'] },
        { type: 'display_message', message: 'EVACUATE IMMEDIATELY' },
        { type: 'activate_strobes', zones: ['all'] }
      ]
    });

    this.responseTemplates.set('unauthorized_access', {
      severity: 'high',
      actions: [
        { type: 'lock_door', immediate: true },
        { type: 'capture_snapshot', cameras: ['nearest'] },
        { type: 'notify', recipients: ['security'] },
        { type: 'track_person', duration: 300 }
      ]
    });
  }

  async handleAlert(alert) {
    // Check if automated response is enabled
    const template = this.responseTemplates.get(alert.type);
    if (!template) return;

    // Create incident
    const incident = await this.createIncident(alert);
    
    // Execute response actions
    for (const action of template.actions) {
      try {
        await this.executeAction(action, alert, incident);
      } catch (error) {
        console.error(`Failed to execute action ${action.type}:`, error);
      }
    }

    // Monitor incident
    this.monitorIncident(incident);
  }

  async createIncident(alert) {
    const incident = await this.api.post('/api/incident/incidents', {
      title: alert.title,
      description: alert.description,
      severity: alert.severity,
      type: alert.type,
      status: 'active',
      source: {
        type: 'automated',
        alertId: alert.id
      },
      location: {
        siteId: alert.siteId,
        zoneId: alert.zoneId
      },
      assignedTo: this.getOnCallSecurity()
    });

    this.activeIncidents.set(incident.data.id, incident.data);
    return incident.data;
  }

  async executeAction(action, alert, incident) {
    switch (action.type) {
      case 'lock_doors':
        await this.lockDoors(action, alert);
        break;
      case 'unlock_doors':
        await this.unlockDoors(action, alert);
        break;
      case 'trigger_alarm':
        await this.triggerAlarm(action, alert);
        break;
      case 'notify':
        await this.sendNotifications(action, alert, incident);
        break;
      case 'record_all_cameras':
        await this.startEmergencyRecording(action, alert);
        break;
      case 'capture_snapshot':
        await this.captureSnapshots(action, alert);
        break;
      case 'dispatch_security':
        await this.dispatchSecurity(action, incident);
        break;
    }

    // Log action
    await this.logAction(incident.id, action, 'completed');
  }

  async lockDoors(action, alert) {
    const zones = action.zones[0] === 'affected' 
      ? [alert.zoneId] 
      : await this.getAllZones(alert.siteId);

    for (const zoneId of zones) {
      const doors = await this.api.get('/api/access/access-points', {
        params: { zoneId, type: 'door' }
      });

      for (const door of doors.data.accessPoints) {
        await this.api.post(`/api/access/access-points/${door.id}/control`, {
          command: 'lock',
          reason: `Automated response: ${alert.type}`
        });
      }
    }
  }

  async sendNotifications(action, alert, incident) {
    const notification = {
      type: 'incident',
      severity: alert.severity,
      title: `SECURITY ALERT: ${alert.title}`,
      body: alert.description,
      data: {
        incidentId: incident.id,
        alertId: alert.id,
        location: `${alert.siteName} - ${alert.zoneName}`
      },
      actions: [
        { label: 'View Incident', url: `/incidents/${incident.id}` },
        { label: 'Acknowledge', action: 'acknowledge' }
      ]
    };

    // Determine recipients
    const recipients = await this.resolveRecipients(action.recipients, alert);

    // Send via multiple channels
    await Promise.all([
      this.sendPushNotifications(recipients, notification),
      this.sendSMSNotifications(recipients.filter(r => r.phone), notification),
      this.sendEmailNotifications(recipients.filter(r => r.email), notification)
    ]);
  }

  async monitorIncident(incident) {
    // Set up periodic status checks
    const monitor = setInterval(async () => {
      const updated = await this.api.get(`/api/incident/incidents/${incident.id}`);
      
      if (updated.data.status === 'resolved') {
        clearInterval(monitor);
        await this.finalizeIncident(updated.data);
      } else {
        // Check for escalation needs
        await this.checkEscalation(updated.data);
      }
    }, 30000); // Check every 30 seconds
  }

  async checkEscalation(incident) {
    const age = Date.now() - new Date(incident.createdAt).getTime();
    const ageMinutes = age / (1000 * 60);

    // Escalate if not acknowledged within 5 minutes
    if (incident.status === 'active' && ageMinutes > 5) {
      await this.escalateIncident(incident);
    }

    // Escalate to management if not resolved within 30 minutes
    if (incident.severity === 'critical' && ageMinutes > 30) {
      await this.escalateToManagement(incident);
    }
  }
}

// Usage
const incidentResponse = new IncidentResponseSystem(apiClient);
await incidentResponse.initialize();
```

## Analytics and Reporting

### 1. Generate Custom Reports

**Use Case**: Generate scheduled reports for management and compliance.

```javascript
class ReportGenerator {
  constructor(apiClient) {
    this.api = apiClient;
  }

  async generateSecurityReport(dateRange, sites) {
    // Gather data from multiple sources
    const [incidents, accessEvents, videoAnalytics, systemHealth] = await Promise.all([
      this.getIncidentData(dateRange, sites),
      this.getAccessData(dateRange, sites),
      this.getVideoAnalytics(dateRange, sites),
      this.getSystemHealth(dateRange, sites)
    ]);

    // Generate report
    const report = await this.api.post('/api/analytics/reports/generate', {
      templateId: 'security-executive-summary',
      parameters: {
        startDate: dateRange.start,
        endDate: dateRange.end,
        sites: sites,
        sections: {
          executiveSummary: this.generateExecutiveSummary(incidents, accessEvents),
          incidentAnalysis: this.analyzeIncidents(incidents),
          accessPatterns: this.analyzeAccessPatterns(accessEvents),
          videoInsights: videoAnalytics,
          systemPerformance: systemHealth,
          recommendations: this.generateRecommendations(incidents, accessEvents)
        }
      },
      format: 'pdf'
    });

    // Poll for completion
    return this.waitForReport(report.data.id);
  }

  async getIncidentData(dateRange, sites) {
    const incidents = await this.api.get('/api/analytics/incidents', {
      params: {
        startTime: dateRange.start,
        endTime: dateRange.end,
        siteIds: sites.join(','),
        includeResolved: true
      }
    });

    return this.processIncidentData(incidents.data);
  }

  processIncidentData(data) {
    return {
      total: data.total,
      bySeverity: this.groupBy(data.incidents, 'severity'),
      byType: this.groupBy(data.incidents, 'type'),
      byLocation: this.groupBy(data.incidents, 'siteId'),
      responseTime: {
        average: this.calculateAverageResponseTime(data.incidents),
        p95: this.calculatePercentile(data.incidents.map(i => i.responseTime), 95)
      },
      trends: this.calculateTrends(data.incidents)
    };
  }

  generateExecutiveSummary(incidents, accessEvents) {
    return {
      overview: `During the reporting period, ${incidents.total} security incidents were recorded across ${incidents.byLocation.size} sites.`,
      keyMetrics: [
        {
          label: 'Total Incidents',
          value: incidents.total,
          change: incidents.trends.percentChange,
          trend: incidents.trends.direction
        },
        {
          label: 'Critical Incidents',
          value: incidents.bySeverity.critical || 0,
          change: incidents.trends.criticalChange
        },
        {
          label: 'Avg Response Time',
          value: `${incidents.responseTime.average} min`,
          target: '5 min',
          status: incidents.responseTime.average <= 5 ? 'good' : 'needs-improvement'
        },
        {
          label: 'Access Violations',
          value: accessEvents.violations,
          change: accessEvents.trends.violationChange
        }
      ],
      highlights: this.generateHighlights(incidents, accessEvents)
    };
  }

  async scheduleReport(schedule) {
    const scheduledReport = await this.api.post('/api/analytics/reports/schedule', {
      name: schedule.name,
      templateId: schedule.templateId,
      parameters: schedule.parameters,
      schedule: {
        frequency: schedule.frequency, // daily, weekly, monthly
        time: schedule.time, // HH:mm
        dayOfWeek: schedule.dayOfWeek, // for weekly
        dayOfMonth: schedule.dayOfMonth, // for monthly
        timezone: schedule.timezone
      },
      recipients: schedule.recipients,
      format: schedule.format || 'pdf'
    });

    return scheduledReport.data;
  }
}

// Usage
const reporter = new ReportGenerator(apiClient);

// Generate on-demand report
const report = await reporter.generateSecurityReport(
  { start: '2024-01-01', end: '2024-01-31' },
  ['site-123', 'site-456']
);

// Schedule monthly report
await reporter.scheduleReport({
  name: 'Monthly Security Summary',
  templateId: 'security-executive-summary',
  parameters: { 
    lookback: '1month',
    includeAllSites: true 
  },
  frequency: 'monthly',
  dayOfMonth: 1,
  time: '08:00',
  timezone: 'America/New_York',
  recipients: ['security@company.com', 'executives@company.com']
});
```

### 2. Real-time Analytics Dashboard

**Use Case**: Create interactive analytics dashboards with drill-down capabilities.

```javascript
class AnalyticsDashboard {
  constructor(apiClient) {
    this.api = apiClient;
    this.charts = new Map();
  }

  async initialize(dashboardId) {
    // Load dashboard configuration
    const dashboard = await this.api.get(`/api/analytics/dashboards/${dashboardId}`);
    
    // Initialize widgets
    for (const widget of dashboard.data.widgets) {
      await this.initializeWidget(widget);
    }

    // Set up auto-refresh
    this.startAutoRefresh(dashboard.data.refreshInterval);
  }

  async initializeWidget(widget) {
    switch (widget.type) {
      case 'metric':
        await this.createMetricWidget(widget);
        break;
      case 'chart':
        await this.createChartWidget(widget);
        break;
      case 'heatmap':
        await this.createHeatmapWidget(widget);
        break;
      case 'table':
        await this.createTableWidget(widget);
        break;
    }
  }

  async createChartWidget(config) {
    // Fetch data
    const data = await this.api.get('/api/analytics/metrics/historical', {
      params: {
        metric: config.dataSource,
        startTime: this.getTimeRange(config.timeRange).start,
        endTime: this.getTimeRange(config.timeRange).end,
        granularity: config.granularity || 'hour',
        aggregation: config.aggregation || 'avg'
      }
    });

    // Create chart
    const chart = new Chart(document.getElementById(config.id), {
      type: config.chartType || 'line',
      data: {
        labels: data.data.data.map(d => this.formatTime(d.timestamp)),
        datasets: [{
          label: config.title,
          data: data.data.data.map(d => d.value),
          borderColor: config.color || '#007bff',
          tension: 0.1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: 'index'
        },
        onClick: (event, elements) => {
          if (elements.length > 0) {
            this.handleDrillDown(config, data.data.data[elements[0].index]);
          }
        }
      }
    });

    this.charts.set(config.id, chart);
  }

  async createHeatmapWidget(config) {
    const heatmapData = await this.api.get('/api/analytics/visualizations/heatmap', {
      params: {
        type: config.heatmapType,
        siteId: config.siteId,
        floor: config.floor,
        startTime: this.getTimeRange('24h').start,
        endTime: new Date().toISOString(),
        resolution: 20
      }
    });

    // Render heatmap
    const heatmap = L.map(config.id).setView([0, 0], 1);
    
    // Add floor plan overlay
    if (config.floorPlanUrl) {
      L.imageOverlay(config.floorPlanUrl, heatmapData.data.bounds).addTo(heatmap);
    }

    // Add heat layer
    const heatLayer = L.heatLayer(
      heatmapData.data.data.map(point => [point.y, point.x, point.value]),
      {
        radius: 25,
        blur: 15,
        maxZoom: 17,
        gradient: config.gradient || {
          0.0: 'blue',
          0.25: 'cyan',
          0.5: 'green',
          0.75: 'yellow',
          1.0: 'red'
        }
      }
    ).addTo(heatmap);
  }

  async handleDrillDown(widget, dataPoint) {
    // Create modal with detailed view
    const modal = this.createModal({
      title: `${widget.title} - Details`,
      size: 'large'
    });

    // Load detailed data
    const details = await this.api.get('/api/analytics/drill-down', {
      params: {
        metric: widget.dataSource,
        timestamp: dataPoint.timestamp,
        window: '1h'
      }
    });

    // Display breakdown
    modal.setContent(this.renderDrillDownContent(details.data));
    modal.show();
  }

  getTimeRange(range) {
    const end = new Date();
    const start = new Date();

    switch (range) {
      case '1h':
        start.setHours(start.getHours() - 1);
        break;
      case '24h':
        start.setDate(start.getDate() - 1);
        break;
      case '7d':
        start.setDate(start.getDate() - 7);
        break;
      case '30d':
        start.setDate(start.getDate() - 30);
        break;
    }

    return { start: start.toISOString(), end: end.toISOString() };
  }
}

// Usage
const analytics = new AnalyticsDashboard(apiClient);
await analytics.initialize('security-operations-dashboard');
```

## Visitor Management

### 1. Self-Service Visitor Registration

**Use Case**: Allow visitors to pre-register and receive mobile credentials.

```javascript
class VisitorManagementSystem {
  constructor(apiClient) {
    this.api = apiClient;
  }

  async preRegisterVisitor(visitorData) {
    // Create visitor record
    const visitor = await this.api.post('/api/visitor/visitors', {
      firstName: visitorData.firstName,
      lastName: visitorData.lastName,
      email: visitorData.email,
      phone: visitorData.phone,
      company: visitorData.company,
      hostEmail: visitorData.hostEmail,
      purpose: visitorData.purpose,
      expectedArrival: visitorData.expectedArrival,
      expectedDeparture: visitorData.expectedDeparture,
      requiresNDA: visitorData.requiresNDA,
      parkingRequired: visitorData.parkingRequired
    });

    // Send pre-registration confirmation
    await this.sendPreRegistrationEmail(visitor.data);

    // Notify host
    await this.notifyHost(visitor.data);

    return visitor.data;
  }

  async checkInVisitor(visitorId) {
    // Update visitor status
    const visitor = await this.api.put(`/api/visitor/visitors/${visitorId}`, {
      status: 'checked_in',
      actualArrival: new Date().toISOString()
    });

    // Create mobile credential
    const credential = await this.createMobileCredential(visitor.data);

    // Capture photo for badge
    const photo = await this.captureVisitorPhoto();
    
    // Print physical badge if needed
    if (visitor.data.requiresPhysicalBadge) {
      await this.printBadge(visitor.data, photo);
    }

    // Send mobile pass
    await this.sendMobilePass(visitor.data, credential);

    // Notify host of arrival
    await this.sendArrivalNotification(visitor.data);

    return {
      visitor: visitor.data,
      credential: credential
    };
  }

  async createMobileCredential(visitor) {
    const credential = await this.api.post('/api/access/credentials', {
      type: 'mobile',
      code: this.generateMobileCode(),
      userId: visitor.id,
      expiresAt: visitor.expectedDeparture,
      accessGroups: ['visitor-general'],
      metadata: {
        visitorId: visitor.id,
        hostId: visitor.hostId,
        allowedAreas: visitor.allowedAreas
      }
    });

    // Generate QR code
    const qrCode = await this.generateQRCode(credential.data);

    return {
      ...credential.data,
      qrCode
    };
  }

  async sendMobilePass(visitor, credential) {
    // Create Apple Wallet / Google Pay pass
    const pass = await this.createDigitalPass({
      type: 'visitor',
      holder: `${visitor.firstName} ${visitor.lastName}`,
      company: visitor.company,
      validFrom: visitor.actualArrival,
      validUntil: visitor.expectedDeparture,
      qrCode: credential.qrCode,
      locations: visitor.allowedLocations
    });

    // Send via email
    await this.api.post('/api/notifications/email', {
      to: visitor.email,
      template: 'visitor-mobile-pass',
      data: {
        visitor,
        passUrl: pass.url,
        qrCode: credential.qrCode
      }
    });

    // Send via SMS if phone provided
    if (visitor.phone) {
      await this.api.post('/api/notifications/sms', {
        to: visitor.phone,
        message: `Your visitor pass for ${visitor.siteName}: ${pass.shortUrl}`
      });
    }
  }

  async trackVisitorLocation(visitorId) {
    // Get recent access events
    const events = await this.api.get('/api/access/events', {
      params: {
        userId: visitorId,
        startTime: new Date(Date.now() - 3600000).toISOString(), // Last hour
        endTime: new Date().toISOString()
      }
    });

    // Build location trail
    const trail = events.data.events.map(event => ({
      time: event.timestamp,
      location: event.accessPointName,
      zone: event.zoneName,
      direction: event.direction
    }));

    // Get current location
    const currentLocation = trail.length > 0 ? trail[0] : null;

    return {
      currentLocation,
      trail,
      lastSeen: currentLocation?.time
    };
  }

  async checkOutVisitor(visitorId) {
    // Update visitor status
    const visitor = await this.api.put(`/api/visitor/visitors/${visitorId}`, {
      status: 'checked_out',
      actualDeparture: new Date().toISOString()
    });

    // Revoke credentials
    await this.api.delete(`/api/access/credentials/${visitor.data.credentialId}`);

    // Generate visit summary
    const summary = await this.generateVisitSummary(visitor.data);

    // Send to visitor and host
    await Promise.all([
      this.sendVisitSummary(visitor.data, summary),
      this.notifyHostOfDeparture(visitor.data, summary)
    ]);

    return summary;
  }

  async generateVisitSummary(visitor) {
    const [accessLog, incidentCheck] = await Promise.all([
      this.api.get(`/api/visitor/visitors/${visitor.id}/access-log`),
      this.api.get('/api/incident/incidents', {
        params: {
          startTime: visitor.actualArrival,
          endTime: visitor.actualDeparture,
          userId: visitor.id
        }
      })
    ]);

    return {
      visitor: {
        name: `${visitor.firstName} ${visitor.lastName}`,
        company: visitor.company
      },
      visit: {
        date: new Date(visitor.actualArrival).toLocaleDateString(),
        duration: this.calculateDuration(visitor.actualArrival, visitor.actualDeparture),
        host: visitor.hostName
      },
      access: {
        areasVisited: [...new Set(accessLog.data.events.map(e => e.zone))],
        totalDoors: accessLog.data.events.length
      },
      incidents: incidentCheck.data.incidents.length,
      status: 'completed'
    };
  }
}

// Usage
const visitorMgmt = new VisitorManagementSystem(apiClient);

// Pre-register visitor
const visitor = await visitorMgmt.preRegisterVisitor({
  firstName: 'Jane',
  lastName: 'Smith',
  email: 'jane.smith@example.com',
  company: 'ABC Corp',
  hostEmail: 'john.doe@sparc.com',
  purpose: 'Business Meeting',
  expectedArrival: '2024-01-20T09:00:00Z',
  expectedDeparture: '2024-01-20T17:00:00Z'
});

// Check in on arrival
const checkin = await visitorMgmt.checkInVisitor(visitor.id);

// Track location
const location = await visitorMgmt.trackVisitorLocation(visitor.id);

// Check out
const summary = await visitorMgmt.checkOutVisitor(visitor.id);
```

## Integration Scenarios

### 1. Building Management System Integration

**Use Case**: Integrate with BMS for unified building control.

```javascript
class BMSIntegration {
  constructor(apiClient, bmsClient) {
    this.api = apiClient;
    this.bms = bmsClient;
  }

  async syncBuildingState() {
    // Get current security state
    const [alarms, access, occupancy] = await Promise.all([
      this.api.get('/api/alert/alerts', { params: { status: 'active' } }),
      this.api.get('/api/access/access-points', { params: { status: 'alarmed' } }),
      this.api.get('/api/analytics/metrics/realtime', { 
        params: { metrics: ['occupancy'] } 
      })
    ]);

    // Update BMS
    await this.bms.updateSecurityState({
      activeAlarms: alarms.data.alerts.length,
      alarmedDoors: access.data.accessPoints,
      occupancy: occupancy.data.metrics.occupancy.value
    });

    // Subscribe to changes
    this.subscribeToSecurityEvents();
  }

  subscribeToSecurityEvents() {
    const ws = new WebSocket(`wss://api.sparc.security/v1/ws?token=${this.token}`);

    ws.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      
      switch (data.type) {
        case 'fire_alarm':
          await this.handleFireAlarm(data);
          break;
        case 'emergency':
          await this.handleEmergency(data);
          break;
        case 'environmental_alert':
          await this.handleEnvironmentalAlert(data);
          break;
      }
    };
  }

  async handleFireAlarm(alarm) {
    // Integrate with BMS fire system
    await Promise.all([
      // SPARC actions
      this.api.post('/api/access/emergency/unlock-all', {
        siteId: alarm.siteId,
        reason: 'Fire alarm activation'
      }),
      
      // BMS actions
      this.bms.activateFireMode({
        zone: alarm.zone,
        elevators: 'recall',
        hvac: 'shutdown',
        lighting: 'emergency'
      })
    ]);
  }

  async scheduleAfterHours() {
    // Coordinate security and building systems
    const schedule = {
      weekday: {
        start: '18:00',
        actions: [
          { system: 'access', action: 'restrict_to_authorized' },
          { system: 'video', action: 'enable_motion_recording' },
          { system: 'bms', action: 'reduce_hvac' },
          { system: 'lighting', action: 'security_mode' }
        ]
      },
      weekend: {
        actions: [
          { system: 'access', action: 'weekend_access_only' },
          { system: 'video', action: 'enhanced_analytics' },
          { system: 'bms', action: 'minimal_operations' }
        ]
      }
    };

    // Create coordinated schedule
    await this.api.post('/api/automation/schedules', {
      name: 'After Hours Security',
      triggers: schedule,
      notifications: ['security@company.com']
    });
  }
}

// Usage
const bmsIntegration = new BMSIntegration(sparcClient, bmsClient);
await bmsIntegration.syncBuildingState();
await bmsIntegration.scheduleAfterHours();
```

### 2. Third-Party Alert Integration

**Use Case**: Integrate external alerts and coordinate response.

```javascript
class AlertAggregator {
  constructor(apiClient) {
    this.api = apiClient;
    this.sources = new Map();
  }

  registerAlertSource(name, config) {
    this.sources.set(name, {
      name,
      webhook: config.webhook,
      transform: config.transform,
      filter: config.filter
    });
  }

  async handleExternalAlert(source, alert) {
    const config = this.sources.get(source);
    if (!config) return;

    // Transform to SPARC format
    const sparcAlert = config.transform(alert);

    // Apply filters
    if (config.filter && !config.filter(sparcAlert)) {
      return;
    }

    // Create alert in SPARC
    const created = await this.api.post('/api/alert/alerts', sparcAlert);

    // Correlate with existing incidents
    await this.correlateAlert(created.data);

    return created.data;
  }

  async correlateAlert(alert) {
    // Find related alerts
    const related = await this.api.get('/api/alert/alerts', {
      params: {
        siteId: alert.siteId,
        startTime: new Date(Date.now() - 3600000).toISOString(), // Last hour
        types: [alert.type],
        status: 'active'
      }
    });

    if (related.data.alerts.length > 2) {
      // Create correlated incident
      await this.api.post('/api/incident/incidents', {
        title: `Multiple ${alert.type} alerts`,
        description: `${related.data.alerts.length} related alerts detected`,
        severity: 'high',
        alerts: related.data.alerts.map(a => a.id),
        autoCorrelated: true
      });
    }
  }

  setupWeatherIntegration() {
    this.registerAlertSource('weather', {
      transform: (weatherAlert) => ({
        type: 'environmental',
        severity: this.mapWeatherSeverity(weatherAlert.severity),
        title: weatherAlert.event,
        description: weatherAlert.description,
        source: {
          type: 'external',
          system: 'weather',
          id: weatherAlert.id
        },
        metadata: {
          onset: weatherAlert.onset,
          expires: weatherAlert.expires,
          areas: weatherAlert.areas
        }
      }),
      filter: (alert) => alert.severity !== 'low'
    });
  }

  setupCyberSecurityIntegration() {
    this.registerAlertSource('cybersecurity', {
      transform: (cyberAlert) => ({
        type: 'cyber_threat',
        severity: cyberAlert.risk_score > 80 ? 'critical' : 'high',
        title: `Cyber Threat: ${cyberAlert.threat_type}`,
        description: cyberAlert.description,
        source: {
          type: 'external',
          system: 'siem',
          id: cyberAlert.incident_id
        },
        metadata: {
          indicators: cyberAlert.indicators,
          affected_systems: cyberAlert.systems,
          recommended_actions: cyberAlert.actions
        }
      })
    });
  }
}

// Usage
const alertAggregator = new AlertAggregator(apiClient);

// Setup integrations
alertAggregator.setupWeatherIntegration();
alertAggregator.setupCyberSecurityIntegration();

// Handle incoming alert
await alertAggregator.handleExternalAlert('weather', {
  id: 'NWS-001',
  event: 'Severe Thunderstorm Warning',
  severity: 'severe',
  description: 'Dangerous thunderstorm approaching',
  onset: '2024-01-20T14:00:00Z',
  expires: '2024-01-20T16:00:00Z'
});
```

## Best Practices

1. **Error Handling**: Always implement proper error handling and retry logic
2. **Rate Limiting**: Respect API rate limits and implement backoff strategies
3. **Caching**: Cache frequently accessed data to reduce API calls
4. **Batch Operations**: Use batch endpoints when available
5. **WebSocket Management**: Implement reconnection logic for real-time connections
6. **Security**: Never expose credentials in client-side code
7. **Monitoring**: Log API usage and monitor for anomalies

## Next Steps

- [API Reference](../openapi/) - Complete API documentation
- [WebSocket Guide](./websocket.md) - Real-time communication details
- [SDK Documentation](./sdks.md) - Language-specific libraries
- [Webhooks](./webhooks.md) - Event-driven integrations