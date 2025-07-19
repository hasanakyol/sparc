import http from 'k6/http';
import ws from 'k6/ws';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';

// Custom metrics
const apiResponseTime = new Trend('api_response_time');
const authFailureRate = new Rate('auth_failure_rate');
const videoStreamErrors = new Counter('video_stream_errors');
const accessControlErrors = new Counter('access_control_errors');
const concurrentUsers = new Counter('concurrent_users');

// Test data
const testUsers = new SharedArray('users', function () {
  const users = [];
  for (let i = 1; i <= 1000; i++) {
    users.push({
      username: `testuser${i}@sparc.com`,
      password: 'TestPassword123!',
      tenantId: `tenant-${Math.floor(i / 100) + 1}`,
      role: i % 10 === 0 ? 'admin' : 'operator'
    });
  }
  return users;
});

const testDoors = new SharedArray('doors', function () {
  const doors = [];
  for (let i = 1; i <= 10000; i++) {
    doors.push({
      id: `door-${i}`,
      buildingId: `building-${Math.floor(i / 100) + 1}`,
      floorId: `floor-${Math.floor(i / 10) + 1}`,
      name: `Door ${i}`,
      status: Math.random() > 0.1 ? 'online' : 'offline'
    });
  }
  return doors;
});

const testCameras = new SharedArray('cameras', function () {
  const cameras = [];
  for (let i = 1; i <= 1000; i++) {
    cameras.push({
      id: `camera-${i}`,
      buildingId: `building-${Math.floor(i / 10) + 1}`,
      floorId: `floor-${Math.floor(i / 5) + 1}`,
      name: `Camera ${i}`,
      streamUrl: `rtsp://camera${i}.sparc.local/stream`,
      status: Math.random() > 0.05 ? 'online' : 'offline'
    });
  }
  return cameras;
});

// Configuration
const BASE_URL = __ENV.BASE_URL || 'https://api.sparc.local';
const WS_URL = __ENV.WS_URL || 'wss://api.sparc.local';

// Test scenarios configuration
export const options = {
  scenarios: {
    // Requirement 5: API response time validation (200ms target)
    api_response_time_test: {
      executor: 'constant-vus',
      vus: 50,
      duration: '5m',
      tags: { test_type: 'api_response_time' },
      exec: 'apiResponseTimeTest'
    },

    // Requirement 12: Scalability - 10,000 doors concurrent access
    door_scalability_test: {
      executor: 'ramping-vus',
      startVUs: 10,
      stages: [
        { duration: '2m', target: 100 },
        { duration: '5m', target: 500 },
        { duration: '10m', target: 1000 },
        { duration: '5m', target: 500 },
        { duration: '2m', target: 0 }
      ],
      tags: { test_type: 'door_scalability' },
      exec: 'doorScalabilityTest'
    },

    // Requirement 12: Video streaming - 1,000 concurrent streams
    video_streaming_test: {
      executor: 'ramping-vus',
      startVUs: 10,
      stages: [
        { duration: '3m', target: 100 },
        { duration: '5m', target: 500 },
        { duration: '10m', target: 1000 },
        { duration: '5m', target: 500 },
        { duration: '2m', target: 0 }
      ],
      tags: { test_type: 'video_streaming' },
      exec: 'videoStreamingTest'
    },

    // Stress testing - beyond normal capacity
    stress_test: {
      executor: 'ramping-vus',
      startVUs: 100,
      stages: [
        { duration: '5m', target: 1000 },
        { duration: '10m', target: 2000 },
        { duration: '15m', target: 3000 },
        { duration: '10m', target: 2000 },
        { duration: '5m', target: 0 }
      ],
      tags: { test_type: 'stress' },
      exec: 'stressTest'
    },

    // Capacity planning - sustained load
    capacity_planning_test: {
      executor: 'constant-vus',
      vus: 500,
      duration: '30m',
      tags: { test_type: 'capacity_planning' },
      exec: 'capacityPlanningTest'
    },

    // Real-time events and WebSocket testing
    realtime_events_test: {
      executor: 'constant-vus',
      vus: 100,
      duration: '10m',
      tags: { test_type: 'realtime_events' },
      exec: 'realtimeEventsTest'
    },

    // Authentication and authorization load
    auth_load_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      stages: [
        { duration: '2m', target: 50 },
        { duration: '5m', target: 100 },
        { duration: '10m', target: 200 },
        { duration: '5m', target: 100 },
        { duration: '2m', target: 10 }
      ],
      tags: { test_type: 'auth_load' },
      exec: 'authLoadTest'
    }
  },
  thresholds: {
    // Requirement 5: API response times must be under 200ms
    'api_response_time': ['p(95)<200'],
    'http_req_duration': ['p(95)<200', 'p(99)<500'],
    
    // Error rates should be minimal
    'http_req_failed': ['rate<0.01'],
    'auth_failure_rate': ['rate<0.05'],
    
    // Concurrent user limits
    'concurrent_users': ['count>=1000'],
    
    // Video streaming specific thresholds
    'video_stream_errors': ['count<50'],
    'access_control_errors': ['count<10']
  }
};

// Authentication helper
function authenticate(user) {
  const loginPayload = {
    email: user.username,
    password: user.password,
    tenantId: user.tenantId
  };

  const response = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify(loginPayload), {
    headers: {
      'Content-Type': 'application/json',
    },
  });

  check(response, {
    'login successful': (r) => r.status === 200,
    'token received': (r) => r.json('token') !== undefined,
  });

  if (response.status === 200) {
    return response.json('token');
  }
  
  authFailureRate.add(1);
  return null;
}

// API Response Time Test - Requirement 5
export function apiResponseTimeTest() {
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  const token = authenticate(user);
  
  if (!token) return;

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  group('API Response Time Tests', () => {
    // Test various API endpoints
    const endpoints = [
      '/api/doors',
      '/api/cameras',
      '/api/events',
      '/api/users',
      '/api/tenants',
      '/api/access-groups',
      '/api/alerts'
    ];

    endpoints.forEach(endpoint => {
      const startTime = Date.now();
      const response = http.get(`${BASE_URL}${endpoint}?limit=50`, { headers });
      const responseTime = Date.now() - startTime;
      
      apiResponseTime.add(responseTime);
      
      check(response, {
        [`${endpoint} status is 200`]: (r) => r.status === 200,
        [`${endpoint} response time < 200ms`]: () => responseTime < 200,
      });
    });
  });

  sleep(1);
}

// Door Scalability Test - Requirement 12 (10,000 doors)
export function doorScalabilityTest() {
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  const token = authenticate(user);
  
  if (!token) return;

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  group('Door Scalability Tests', () => {
    // Test door operations at scale
    const door = testDoors[Math.floor(Math.random() * testDoors.length)];
    
    // Get door status
    let response = http.get(`${BASE_URL}/api/doors/${door.id}`, { headers });
    check(response, {
      'door status retrieved': (r) => r.status === 200,
    }) || accessControlErrors.add(1);

    // Simulate door control operation
    const controlPayload = {
      action: Math.random() > 0.5 ? 'unlock' : 'lock',
      duration: 5000
    };

    response = http.post(`${BASE_URL}/api/doors/${door.id}/control`, 
      JSON.stringify(controlPayload), { headers });
    
    check(response, {
      'door control successful': (r) => r.status === 200,
    }) || accessControlErrors.add(1);

    // Test access event creation
    const accessEvent = {
      doorId: door.id,
      userId: `user-${Math.floor(Math.random() * 1000)}`,
      credentialId: `card-${Math.floor(Math.random() * 10000)}`,
      eventType: 'access_granted',
      timestamp: new Date().toISOString()
    };

    response = http.post(`${BASE_URL}/api/events`, 
      JSON.stringify(accessEvent), { headers });
    
    check(response, {
      'access event logged': (r) => r.status === 201,
    }) || accessControlErrors.add(1);
  });

  sleep(Math.random() * 2);
}

// Video Streaming Test - Requirement 12 (1,000 streams)
export function videoStreamingTest() {
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  const token = authenticate(user);
  
  if (!token) return;

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  group('Video Streaming Tests', () => {
    const camera = testCameras[Math.floor(Math.random() * testCameras.length)];
    
    // Get camera stream URL
    let response = http.get(`${BASE_URL}/api/cameras/${camera.id}/stream`, { headers });
    check(response, {
      'stream URL retrieved': (r) => r.status === 200,
    }) || videoStreamErrors.add(1);

    // Test video recording retrieval
    const recordingParams = {
      startTime: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
      endTime: new Date().toISOString(),
      quality: 'medium'
    };

    response = http.get(`${BASE_URL}/api/cameras/${camera.id}/recordings?` + 
      Object.entries(recordingParams).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&'), 
      { headers });
    
    check(response, {
      'recordings retrieved': (r) => r.status === 200,
    }) || videoStreamErrors.add(1);

    // Test camera control
    const cameraControl = {
      action: 'ptz',
      direction: ['up', 'down', 'left', 'right'][Math.floor(Math.random() * 4)],
      speed: Math.floor(Math.random() * 10) + 1
    };

    response = http.post(`${BASE_URL}/api/cameras/${camera.id}/control`, 
      JSON.stringify(cameraControl), { headers });
    
    check(response, {
      'camera control successful': (r) => r.status === 200,
    }) || videoStreamErrors.add(1);
  });

  sleep(Math.random() * 3);
}

// Stress Test - Beyond normal capacity
export function stressTest() {
  concurrentUsers.add(1);
  
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  const token = authenticate(user);
  
  if (!token) return;

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  group('Stress Tests', () => {
    // Rapid-fire API calls
    const operations = [
      () => http.get(`${BASE_URL}/api/doors?limit=100`, { headers }),
      () => http.get(`${BASE_URL}/api/cameras?limit=100`, { headers }),
      () => http.get(`${BASE_URL}/api/events?limit=100`, { headers }),
      () => http.get(`${BASE_URL}/api/alerts?limit=100`, { headers }),
    ];

    // Execute multiple operations rapidly
    for (let i = 0; i < 5; i++) {
      const operation = operations[Math.floor(Math.random() * operations.length)];
      const response = operation();
      
      check(response, {
        'stress test response ok': (r) => r.status < 500,
      });
    }
  });

  sleep(0.1); // Minimal sleep for stress testing
}

// Capacity Planning Test - Sustained load
export function capacityPlanningTest() {
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  const token = authenticate(user);
  
  if (!token) return;

  const headers = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };

  group('Capacity Planning Tests', () => {
    // Simulate realistic user behavior patterns
    const scenarios = [
      // Dashboard viewing
      () => {
        http.get(`${BASE_URL}/api/dashboard/summary`, { headers });
        http.get(`${BASE_URL}/api/alerts/active`, { headers });
        http.get(`${BASE_URL}/api/events/recent?limit=20`, { headers });
      },
      
      // Access control management
      () => {
        const door = testDoors[Math.floor(Math.random() * testDoors.length)];
        http.get(`${BASE_URL}/api/doors/${door.id}`, { headers });
        http.get(`${BASE_URL}/api/doors/${door.id}/events?limit=10`, { headers });
      },
      
      // Video monitoring
      () => {
        const camera = testCameras[Math.floor(Math.random() * testCameras.length)];
        http.get(`${BASE_URL}/api/cameras/${camera.id}`, { headers });
        http.get(`${BASE_URL}/api/cameras/${camera.id}/stream`, { headers });
      },
      
      // Reporting
      () => {
        http.get(`${BASE_URL}/api/reports/access-summary?period=24h`, { headers });
        http.get(`${BASE_URL}/api/analytics/occupancy`, { headers });
      }
    ];

    // Execute random scenario
    const scenario = scenarios[Math.floor(Math.random() * scenarios.length)];
    scenario();
  });

  sleep(2 + Math.random() * 3); // Realistic user think time
}

// Real-time Events Test - WebSocket connections
export function realtimeEventsTest() {
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  const token = authenticate(user);
  
  if (!token) return;

  group('Real-time Events Tests', () => {
    const wsUrl = `${WS_URL}/api/events/stream?token=${token}`;
    
    const response = ws.connect(wsUrl, {}, function (socket) {
      socket.on('open', () => {
        // Subscribe to events
        socket.send(JSON.stringify({
          type: 'subscribe',
          channels: ['access_events', 'alerts', 'camera_events']
        }));
      });

      socket.on('message', (data) => {
        const message = JSON.parse(data);
        check(message, {
          'valid event message': (msg) => msg.type !== undefined,
          'event has timestamp': (msg) => msg.timestamp !== undefined,
        });
      });

      socket.setTimeout(() => {
        socket.close();
      }, 30000); // Keep connection for 30 seconds
    });

    check(response, {
      'websocket connection established': (r) => r && r.status === 101,
    });
  });
}

// Authentication Load Test
export function authLoadTest() {
  const user = testUsers[Math.floor(Math.random() * testUsers.length)];
  
  group('Authentication Load Tests', () => {
    // Test login
    const loginResponse = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify({
      email: user.username,
      password: user.password,
      tenantId: user.tenantId
    }), {
      headers: { 'Content-Type': 'application/json' }
    });

    const loginSuccess = check(loginResponse, {
      'login successful': (r) => r.status === 200,
      'token received': (r) => r.json('token') !== undefined,
    });

    if (loginSuccess) {
      const token = loginResponse.json('token');
      
      // Test token validation
      const validateResponse = http.get(`${BASE_URL}/api/auth/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      check(validateResponse, {
        'token validation successful': (r) => r.status === 200,
        'user info returned': (r) => r.json('id') !== undefined,
      });

      // Test logout
      const logoutResponse = http.post(`${BASE_URL}/api/auth/logout`, null, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      check(logoutResponse, {
        'logout successful': (r) => r.status === 200,
      });
    } else {
      authFailureRate.add(1);
    }
  });

  sleep(0.5);
}

// Setup function
export function setup() {
  console.log('Starting SPARC Performance Tests');
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`WebSocket URL: ${WS_URL}`);
  console.log(`Test Users: ${testUsers.length}`);
  console.log(`Test Doors: ${testDoors.length}`);
  console.log(`Test Cameras: ${testCameras.length}`);
  
  // Verify API is accessible
  const healthCheck = http.get(`${BASE_URL}/health`);
  if (healthCheck.status !== 200) {
    throw new Error(`API health check failed: ${healthCheck.status}`);
  }
  
  return { startTime: Date.now() };
}

// Teardown function
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Performance tests completed in ${duration} seconds`);
}

// Handle summary for custom reporting
export function handleSummary(data) {
  return {
    'performance-test-results.json': JSON.stringify(data, null, 2),
    'performance-test-summary.html': generateHtmlReport(data),
    stdout: generateConsoleReport(data)
  };
}

function generateConsoleReport(data) {
  const report = [
    '\n=== SPARC Performance Test Results ===\n',
    `Total Requests: ${data.metrics.http_reqs.values.count}`,
    `Failed Requests: ${data.metrics.http_req_failed.values.rate * 100}%`,
    `Average Response Time: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms`,
    `95th Percentile: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`,
    `99th Percentile: ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms`,
    '',
    '=== Requirement Validation ===',
    `✓ API Response Time (Req 5): ${data.metrics.http_req_duration.values['p(95)'] < 200 ? 'PASS' : 'FAIL'} (${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms < 200ms)`,
    `✓ Error Rate: ${data.metrics.http_req_failed.values.rate < 0.01 ? 'PASS' : 'FAIL'} (${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}% < 1%)`,
    '',
    '=== Custom Metrics ===',
    `Auth Failure Rate: ${((data.metrics.auth_failure_rate?.values.rate || 0) * 100).toFixed(2)}%`,
    `Video Stream Errors: ${data.metrics.video_stream_errors?.values.count || 0}`,
    `Access Control Errors: ${data.metrics.access_control_errors?.values.count || 0}`,
    '\n======================================\n'
  ];
  
  return report.join('\n');
}

function generateHtmlReport(data) {
  return `
<!DOCTYPE html>
<html>
<head>
    <title>SPARC Performance Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { margin: 10px 0; padding: 10px; border-left: 4px solid #007cba; }
        .pass { border-left-color: #28a745; }
        .fail { border-left-color: #dc3545; }
        .summary { background: #f8f9fa; padding: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>SPARC Performance Test Results</h1>
    <div class="summary">
        <h2>Test Summary</h2>
        <p><strong>Total Requests:</strong> ${data.metrics.http_reqs.values.count}</p>
        <p><strong>Failed Requests:</strong> ${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%</p>
        <p><strong>Average Response Time:</strong> ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms</p>
        <p><strong>95th Percentile:</strong> ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms</p>
    </div>
    
    <h2>Requirement Validation</h2>
    <div class="metric ${data.metrics.http_req_duration.values['p(95)'] < 200 ? 'pass' : 'fail'}">
        <strong>Requirement 5 - API Response Time:</strong> 
        ${data.metrics.http_req_duration.values['p(95)'] < 200 ? 'PASS' : 'FAIL'} 
        (${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms < 200ms target)
    </div>
    
    <div class="metric ${data.metrics.http_req_failed.values.rate < 0.01 ? 'pass' : 'fail'}">
        <strong>Error Rate:</strong> 
        ${data.metrics.http_req_failed.values.rate < 0.01 ? 'PASS' : 'FAIL'} 
        (${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}% < 1% target)
    </div>
</body>
</html>`;
}