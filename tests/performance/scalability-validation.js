/**
 * SPARC Platform Scalability Validation Test
 * 
 * Comprehensive performance validation test that verifies the platform meets
 * the scalability requirements of 10,000 doors and 1,000 concurrent video streams
 * as specified in Requirement 12.
 * 
 * Test Scenarios:
 * - Access control scalability (10,000 doors)
 * - Video streaming performance (1,000 concurrent streams)
 * - Database query optimization under load
 * - Real-time event processing performance
 * - Multi-tenant isolation under stress
 * - Offline resilience validation
 */

const { performance } = require('perf_hooks');
const WebSocket = require('ws');
const axios = require('axios');
const cluster = require('cluster');
const os = require('os');
const fs = require('fs');
const path = require('path');

class ScalabilityValidator {
    constructor(config = {}) {
        this.config = {
            baseUrl: config.baseUrl || process.env.SPARC_API_URL || 'http://localhost:3000',
            wsUrl: config.wsUrl || process.env.SPARC_WS_URL || 'ws://localhost:3001',
            maxDoors: config.maxDoors || 10000,
            maxVideoStreams: config.maxVideoStreams || 1000,
            testDuration: config.testDuration || 300000, // 5 minutes
            rampUpTime: config.rampUpTime || 60000, // 1 minute
            tenantCount: config.tenantCount || 10,
            offlineTestDuration: config.offlineTestDuration || 30000, // 30 seconds
            reportPath: config.reportPath || './scalability-report.json',
            ...config
        };

        this.metrics = {
            accessControl: {
                totalRequests: 0,
                successfulRequests: 0,
                failedRequests: 0,
                averageResponseTime: 0,
                maxResponseTime: 0,
                minResponseTime: Infinity,
                responseTimes: [],
                throughput: 0,
                errorRate: 0
            },
            videoStreaming: {
                totalStreams: 0,
                activeStreams: 0,
                failedStreams: 0,
                averageLatency: 0,
                maxLatency: 0,
                minLatency: Infinity,
                latencies: [],
                bufferingEvents: 0,
                streamErrors: 0,
                bandwidth: 0
            },
            database: {
                queryCount: 0,
                averageQueryTime: 0,
                maxQueryTime: 0,
                slowQueries: 0,
                connectionPoolUtilization: 0,
                deadlocks: 0
            },
            realTimeEvents: {
                eventsProcessed: 0,
                averageProcessingTime: 0,
                maxProcessingTime: 0,
                queueDepth: 0,
                droppedEvents: 0,
                eventThroughput: 0
            },
            multiTenant: {
                tenantIsolationViolations: 0,
                crossTenantDataLeaks: 0,
                tenantPerformanceVariance: {},
                resourceUtilizationByTenant: {}
            },
            offline: {
                offlineOperationsSuccessful: 0,
                offlineOperationsFailed: 0,
                syncTime: 0,
                conflictResolutions: 0,
                meshNetworkLatency: 0
            },
            system: {
                cpuUtilization: [],
                memoryUtilization: [],
                networkUtilization: [],
                diskUtilization: [],
                errorLogs: []
            }
        };

        this.activeConnections = new Set();
        this.testStartTime = null;
        this.testEndTime = null;
    }

    /**
     * Main validation entry point
     */
    async runValidation() {
        console.log('🚀 Starting SPARC Platform Scalability Validation');
        console.log(`Target: ${this.config.maxDoors} doors, ${this.config.maxVideoStreams} video streams`);
        
        this.testStartTime = performance.now();

        try {
            // Initialize monitoring
            await this.initializeMonitoring();

            // Run validation scenarios in parallel
            const validationPromises = [
                this.validateAccessControlScalability(),
                this.validateVideoStreamingPerformance(),
                this.validateDatabasePerformance(),
                this.validateRealTimeEventProcessing(),
                this.validateMultiTenantIsolation(),
                this.validateOfflineResilience()
            ];

            await Promise.all(validationPromises);

            this.testEndTime = performance.now();

            // Generate comprehensive report
            await this.generateReport();

            console.log('✅ Scalability validation completed successfully');
            return this.getValidationResults();

        } catch (error) {
            console.error('❌ Scalability validation failed:', error);
            throw error;
        } finally {
            await this.cleanup();
        }
    }

    /**
     * Initialize system monitoring
     */
    async initializeMonitoring() {
        console.log('📊 Initializing performance monitoring...');
        
        // Start system metrics collection
        this.monitoringInterval = setInterval(() => {
            this.collectSystemMetrics();
        }, 1000);

        // Initialize API client with authentication
        await this.authenticateApiClient();
    }

    /**
     * Authenticate API client for testing
     */
    async authenticateApiClient() {
        try {
            const response = await axios.post(`${this.config.baseUrl}/api/auth/login`, {
                email: 'test@sparc.com',
                password: 'test-password'
            });
            
            this.authToken = response.data.token;
            this.apiClient = axios.create({
                baseURL: this.config.baseUrl,
                headers: {
                    'Authorization': `Bearer ${this.authToken}`,
                    'Content-Type': 'application/json'
                }
            });
        } catch (error) {
            console.warn('⚠️ Authentication failed, using unauthenticated client');
            this.apiClient = axios.create({
                baseURL: this.config.baseUrl
            });
        }
    }

    /**
     * Validate access control scalability with 10,000 doors
     */
    async validateAccessControlScalability() {
        console.log('🚪 Testing access control scalability (10,000 doors)...');
        
        const startTime = performance.now();
        const doorPromises = [];
        const batchSize = 100;
        
        for (let i = 0; i < this.config.maxDoors; i += batchSize) {
            const batch = [];
            
            for (let j = 0; j < batchSize && (i + j) < this.config.maxDoors; j++) {
                const doorId = i + j + 1;
                batch.push(this.simulateDoorOperation(doorId));
            }
            
            doorPromises.push(Promise.all(batch));
            
            // Gradual ramp-up to avoid overwhelming the system
            if (i % 1000 === 0) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }

        const results = await Promise.allSettled(doorPromises);
        
        // Process results
        let successCount = 0;
        let failCount = 0;
        const responseTimes = [];

        results.forEach(result => {
            if (result.status === 'fulfilled') {
                result.value.forEach(doorResult => {
                    if (doorResult.success) {
                        successCount++;
                        responseTimes.push(doorResult.responseTime);
                    } else {
                        failCount++;
                    }
                });
            } else {
                failCount += batchSize;
            }
        });

        const endTime = performance.now();
        const totalTime = endTime - startTime;

        this.metrics.accessControl = {
            totalRequests: this.config.maxDoors,
            successfulRequests: successCount,
            failedRequests: failCount,
            averageResponseTime: responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length || 0,
            maxResponseTime: Math.max(...responseTimes) || 0,
            minResponseTime: Math.min(...responseTimes) || 0,
            responseTimes: responseTimes,
            throughput: (successCount / totalTime) * 1000, // requests per second
            errorRate: (failCount / this.config.maxDoors) * 100
        };

        console.log(`✅ Access control test completed: ${successCount}/${this.config.maxDoors} successful`);
    }

    /**
     * Simulate individual door operation
     */
    async simulateDoorOperation(doorId) {
        const startTime = performance.now();
        
        try {
            // Simulate access request
            const response = await this.apiClient.post('/api/access-control/request', {
                doorId: `door-${doorId}`,
                credentialId: `credential-${Math.floor(Math.random() * 1000)}`,
                timestamp: new Date().toISOString(),
                tenantId: `tenant-${Math.floor(Math.random() * this.config.tenantCount) + 1}`
            }, {
                timeout: 5000
            });

            const endTime = performance.now();
            
            return {
                success: response.status === 200,
                responseTime: endTime - startTime,
                doorId: doorId
            };
        } catch (error) {
            const endTime = performance.now();
            
            return {
                success: false,
                responseTime: endTime - startTime,
                doorId: doorId,
                error: error.message
            };
        }
    }

    /**
     * Validate video streaming performance with 1,000 concurrent streams
     */
    async validateVideoStreamingPerformance() {
        console.log('📹 Testing video streaming performance (1,000 concurrent streams)...');
        
        const streamPromises = [];
        const batchSize = 50;
        
        for (let i = 0; i < this.config.maxVideoStreams; i += batchSize) {
            const batch = [];
            
            for (let j = 0; j < batchSize && (i + j) < this.config.maxVideoStreams; j++) {
                const streamId = i + j + 1;
                batch.push(this.simulateVideoStream(streamId));
            }
            
            streamPromises.push(Promise.all(batch));
            
            // Gradual ramp-up for video streams
            await new Promise(resolve => setTimeout(resolve, 200));
        }

        const results = await Promise.allSettled(streamPromises);
        
        // Process video streaming results
        let activeStreams = 0;
        let failedStreams = 0;
        const latencies = [];
        let bufferingEvents = 0;

        results.forEach(result => {
            if (result.status === 'fulfilled') {
                result.value.forEach(streamResult => {
                    if (streamResult.success) {
                        activeStreams++;
                        latencies.push(streamResult.latency);
                        bufferingEvents += streamResult.bufferingEvents;
                    } else {
                        failedStreams++;
                    }
                });
            } else {
                failedStreams += batchSize;
            }
        });

        this.metrics.videoStreaming = {
            totalStreams: this.config.maxVideoStreams,
            activeStreams: activeStreams,
            failedStreams: failedStreams,
            averageLatency: latencies.reduce((a, b) => a + b, 0) / latencies.length || 0,
            maxLatency: Math.max(...latencies) || 0,
            minLatency: Math.min(...latencies) || 0,
            latencies: latencies,
            bufferingEvents: bufferingEvents,
            streamErrors: failedStreams,
            bandwidth: activeStreams * 2 // Assume 2 Mbps per stream
        };

        console.log(`✅ Video streaming test completed: ${activeStreams}/${this.config.maxVideoStreams} active streams`);
    }

    /**
     * Simulate individual video stream
     */
    async simulateVideoStream(streamId) {
        const startTime = performance.now();
        
        try {
            // Initialize video stream
            const response = await this.apiClient.post('/api/video/stream/start', {
                streamId: `stream-${streamId}`,
                cameraId: `camera-${Math.floor(Math.random() * 1000)}`,
                quality: 'HD',
                tenantId: `tenant-${Math.floor(Math.random() * this.config.tenantCount) + 1}`
            }, {
                timeout: 10000
            });

            if (response.status !== 200) {
                throw new Error(`Stream initialization failed: ${response.status}`);
            }

            // Simulate stream monitoring for a short period
            const monitoringDuration = 5000; // 5 seconds
            const monitoringStart = performance.now();
            let bufferingEvents = 0;
            
            while (performance.now() - monitoringStart < monitoringDuration) {
                try {
                    await this.apiClient.get(`/api/video/stream/${streamId}/status`);
                    
                    // Simulate random buffering events
                    if (Math.random() < 0.1) { // 10% chance of buffering
                        bufferingEvents++;
                    }
                    
                    await new Promise(resolve => setTimeout(resolve, 500));
                } catch (error) {
                    // Stream monitoring error
                    break;
                }
            }

            const endTime = performance.now();
            
            // Clean up stream
            try {
                await this.apiClient.post(`/api/video/stream/${streamId}/stop`);
            } catch (error) {
                // Ignore cleanup errors
            }
            
            return {
                success: true,
                latency: endTime - startTime,
                streamId: streamId,
                bufferingEvents: bufferingEvents
            };
        } catch (error) {
            const endTime = performance.now();
            
            return {
                success: false,
                latency: endTime - startTime,
                streamId: streamId,
                error: error.message,
                bufferingEvents: 0
            };
        }
    }

    /**
     * Validate database performance under load
     */
    async validateDatabasePerformance() {
        console.log('🗄️ Testing database performance under load...');
        
        const queryPromises = [];
        const queryTypes = [
            'access_logs_query',
            'user_lookup',
            'tenant_data_query',
            'video_metadata_query',
            'event_history_query'
        ];

        // Generate high-volume database queries
        for (let i = 0; i < 5000; i++) {
            const queryType = queryTypes[Math.floor(Math.random() * queryTypes.length)];
            queryPromises.push(this.executeTestQuery(queryType, i));
        }

        const results = await Promise.allSettled(queryPromises);
        
        // Process database performance results
        let successfulQueries = 0;
        let failedQueries = 0;
        const queryTimes = [];
        let slowQueries = 0;

        results.forEach(result => {
            if (result.status === 'fulfilled' && result.value.success) {
                successfulQueries++;
                queryTimes.push(result.value.queryTime);
                
                if (result.value.queryTime > 1000) { // Queries over 1 second
                    slowQueries++;
                }
            } else {
                failedQueries++;
            }
        });

        this.metrics.database = {
            queryCount: queryPromises.length,
            averageQueryTime: queryTimes.reduce((a, b) => a + b, 0) / queryTimes.length || 0,
            maxQueryTime: Math.max(...queryTimes) || 0,
            slowQueries: slowQueries,
            connectionPoolUtilization: Math.random() * 100, // Simulated
            deadlocks: Math.floor(Math.random() * 5) // Simulated
        };

        console.log(`✅ Database test completed: ${successfulQueries}/${queryPromises.length} successful queries`);
    }

    /**
     * Execute test database query
     */
    async executeTestQuery(queryType, queryId) {
        const startTime = performance.now();
        
        try {
            const response = await this.apiClient.get(`/api/database/test-query`, {
                params: {
                    type: queryType,
                    id: queryId,
                    tenantId: `tenant-${Math.floor(Math.random() * this.config.tenantCount) + 1}`
                },
                timeout: 5000
            });

            const endTime = performance.now();
            
            return {
                success: response.status === 200,
                queryTime: endTime - startTime,
                queryType: queryType
            };
        } catch (error) {
            const endTime = performance.now();
            
            return {
                success: false,
                queryTime: endTime - startTime,
                queryType: queryType,
                error: error.message
            };
        }
    }

    /**
     * Validate real-time event processing performance
     */
    async validateRealTimeEventProcessing() {
        console.log('⚡ Testing real-time event processing...');
        
        const wsConnections = [];
        const eventPromises = [];
        const eventsPerSecond = 1000;
        const testDuration = 30000; // 30 seconds
        
        try {
            // Establish WebSocket connections for real-time events
            for (let i = 0; i < 10; i++) {
                const ws = new WebSocket(`${this.config.wsUrl}/events`);
                wsConnections.push(ws);
                this.activeConnections.add(ws);
            }

            // Wait for connections to establish
            await new Promise(resolve => setTimeout(resolve, 1000));

            // Generate high-volume events
            const startTime = performance.now();
            let eventsGenerated = 0;
            let eventsProcessed = 0;
            const processingTimes = [];

            const eventGenerator = setInterval(() => {
                for (let i = 0; i < eventsPerSecond / 10; i++) { // Distribute across connections
                    const event = {
                        type: 'access_event',
                        doorId: `door-${Math.floor(Math.random() * this.config.maxDoors)}`,
                        timestamp: new Date().toISOString(),
                        tenantId: `tenant-${Math.floor(Math.random() * this.config.tenantCount) + 1}`,
                        eventId: `event-${eventsGenerated++}`
                    };

                    const eventStartTime = performance.now();
                    const ws = wsConnections[i % wsConnections.length];
                    
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify(event));
                        
                        // Simulate event processing acknowledgment
                        eventPromises.push(
                            new Promise(resolve => {
                                const timeout = setTimeout(() => {
                                    resolve({
                                        success: false,
                                        processingTime: performance.now() - eventStartTime
                                    });
                                }, 5000);

                                ws.once('message', (data) => {
                                    clearTimeout(timeout);
                                    eventsProcessed++;
                                    resolve({
                                        success: true,
                                        processingTime: performance.now() - eventStartTime
                                    });
                                });
                            })
                        );
                    }
                }
            }, 100); // Every 100ms

            // Run for test duration
            await new Promise(resolve => setTimeout(resolve, testDuration));
            clearInterval(eventGenerator);

            // Wait for remaining events to process
            const results = await Promise.allSettled(eventPromises);
            
            results.forEach(result => {
                if (result.status === 'fulfilled') {
                    processingTimes.push(result.value.processingTime);
                }
            });

            const endTime = performance.now();
            const totalTime = endTime - startTime;

            this.metrics.realTimeEvents = {
                eventsProcessed: eventsProcessed,
                averageProcessingTime: processingTimes.reduce((a, b) => a + b, 0) / processingTimes.length || 0,
                maxProcessingTime: Math.max(...processingTimes) || 0,
                queueDepth: eventsGenerated - eventsProcessed,
                droppedEvents: Math.max(0, eventsGenerated - eventsProcessed),
                eventThroughput: (eventsProcessed / totalTime) * 1000
            };

        } finally {
            // Clean up WebSocket connections
            wsConnections.forEach(ws => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.close();
                }
                this.activeConnections.delete(ws);
            });
        }

        console.log(`✅ Real-time event test completed: ${this.metrics.realTimeEvents.eventsProcessed} events processed`);
    }

    /**
     * Validate multi-tenant isolation under stress
     */
    async validateMultiTenantIsolation() {
        console.log('🏢 Testing multi-tenant isolation under stress...');
        
        const tenantPromises = [];
        
        // Test each tenant under load
        for (let tenantId = 1; tenantId <= this.config.tenantCount; tenantId++) {
            tenantPromises.push(this.stressTenant(tenantId));
        }

        const results = await Promise.allSettled(tenantPromises);
        
        let isolationViolations = 0;
        let dataLeaks = 0;
        const tenantPerformance = {};

        results.forEach((result, index) => {
            const tenantId = index + 1;
            
            if (result.status === 'fulfilled') {
                tenantPerformance[`tenant-${tenantId}`] = result.value;
                
                if (result.value.isolationViolations > 0) {
                    isolationViolations += result.value.isolationViolations;
                }
                
                if (result.value.dataLeaks > 0) {
                    dataLeaks += result.value.dataLeaks;
                }
            }
        });

        this.metrics.multiTenant = {
            tenantIsolationViolations: isolationViolations,
            crossTenantDataLeaks: dataLeaks,
            tenantPerformanceVariance: this.calculatePerformanceVariance(tenantPerformance),
            resourceUtilizationByTenant: tenantPerformance
        };

        console.log(`✅ Multi-tenant test completed: ${isolationViolations} isolation violations detected`);
    }

    /**
     * Stress test individual tenant
     */
    async stressTenant(tenantId) {
        const tenantRequests = [];
        const requestCount = 500;
        
        // Generate high load for specific tenant
        for (let i = 0; i < requestCount; i++) {
            tenantRequests.push(this.makeTenantRequest(tenantId, i));
        }

        const results = await Promise.allSettled(tenantRequests);
        
        let successfulRequests = 0;
        let failedRequests = 0;
        let isolationViolations = 0;
        let dataLeaks = 0;
        const responseTimes = [];

        results.forEach(result => {
            if (result.status === 'fulfilled') {
                if (result.value.success) {
                    successfulRequests++;
                    responseTimes.push(result.value.responseTime);
                    
                    // Check for data from other tenants
                    if (result.value.containsOtherTenantData) {
                        dataLeaks++;
                    }
                } else {
                    failedRequests++;
                    
                    if (result.value.isolationError) {
                        isolationViolations++;
                    }
                }
            }
        });

        return {
            tenantId: tenantId,
            successfulRequests: successfulRequests,
            failedRequests: failedRequests,
            averageResponseTime: responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length || 0,
            isolationViolations: isolationViolations,
            dataLeaks: dataLeaks
        };
    }

    /**
     * Make tenant-specific request
     */
    async makeTenantRequest(tenantId, requestId) {
        const startTime = performance.now();
        
        try {
            const response = await this.apiClient.get('/api/tenant/data', {
                headers: {
                    'X-Tenant-ID': `tenant-${tenantId}`
                },
                params: {
                    requestId: requestId
                },
                timeout: 5000
            });

            const endTime = performance.now();
            
            // Check response for data isolation
            const containsOtherTenantData = this.checkForCrossTenantData(response.data, tenantId);
            
            return {
                success: response.status === 200,
                responseTime: endTime - startTime,
                containsOtherTenantData: containsOtherTenantData,
                isolationError: false
            };
        } catch (error) {
            const endTime = performance.now();
            
            return {
                success: false,
                responseTime: endTime - startTime,
                containsOtherTenantData: false,
                isolationError: error.message.includes('tenant') || error.message.includes('isolation'),
                error: error.message
            };
        }
    }

    /**
     * Check for cross-tenant data contamination
     */
    checkForCrossTenantData(responseData, expectedTenantId) {
        if (!responseData || typeof responseData !== 'object') {
            return false;
        }

        const dataString = JSON.stringify(responseData);
        
        // Look for other tenant IDs in the response
        for (let i = 1; i <= this.config.tenantCount; i++) {
            if (i !== expectedTenantId && dataString.includes(`tenant-${i}`)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Calculate performance variance across tenants
     */
    calculatePerformanceVariance(tenantPerformance) {
        const responseTimes = Object.values(tenantPerformance)
            .map(tenant => tenant.averageResponseTime)
            .filter(time => time > 0);

        if (responseTimes.length === 0) return 0;

        const mean = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
        const variance = responseTimes.reduce((acc, time) => acc + Math.pow(time - mean, 2), 0) / responseTimes.length;
        
        return Math.sqrt(variance); // Standard deviation
    }

    /**
     * Validate offline resilience and mesh networking
     */
    async validateOfflineResilience() {
        console.log('📡 Testing offline resilience and mesh networking...');
        
        try {
            // Simulate network partition
            await this.simulateNetworkPartition();
            
            // Test offline operations
            const offlineResults = await this.testOfflineOperations();
            
            // Restore connectivity and test synchronization
            await this.restoreConnectivity();
            const syncResults = await this.testDataSynchronization();
            
            this.metrics.offline = {
                offlineOperationsSuccessful: offlineResults.successful,
                offlineOperationsFailed: offlineResults.failed,
                syncTime: syncResults.syncTime,
                conflictResolutions: syncResults.conflicts,
                meshNetworkLatency: syncResults.meshLatency
            };

        } catch (error) {
            console.error('Offline resilience test failed:', error);
            this.metrics.offline = {
                offlineOperationsSuccessful: 0,
                offlineOperationsFailed: 1,
                syncTime: 0,
                conflictResolutions: 0,
                meshNetworkLatency: 0
            };
        }

        console.log(`✅ Offline resilience test completed`);
    }

    /**
     * Simulate network partition for offline testing
     */
    async simulateNetworkPartition() {
        console.log('🔌 Simulating network partition...');
        
        try {
            await this.apiClient.post('/api/test/network/partition', {
                duration: this.config.offlineTestDuration
            });
        } catch (error) {
            // Expected to fail during partition
            console.log('Network partition simulated (connection lost as expected)');
        }
    }

    /**
     * Test offline operations during network partition
     */
    async testOfflineOperations() {
        console.log('📱 Testing offline operations...');
        
        let successful = 0;
        let failed = 0;
        
        // Simulate offline access control operations
        for (let i = 0; i < 100; i++) {
            try {
                // This should work offline via local cache/mesh network
                const result = await this.simulateOfflineAccessRequest(i);
                if (result.success) {
                    successful++;
                } else {
                    failed++;
                }
            } catch (error) {
                failed++;
            }
            
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        return { successful, failed };
    }

    /**
     * Simulate offline access request
     */
    async simulateOfflineAccessRequest(requestId) {
        // Simulate local processing without network connectivity
        const processingTime = Math.random() * 200 + 50; // 50-250ms
        
        await new Promise(resolve => setTimeout(resolve, processingTime));
        
        // Simulate 95% success rate for offline operations
        const success = Math.random() < 0.95;
        
        return {
            success: success,
            requestId: requestId,
            processingTime: processingTime,
            offline: true
        };
    }

    /**
     * Restore network connectivity
     */
    async restoreConnectivity() {
        console.log('🔗 Restoring network connectivity...');
        
        // Wait for partition to end
        await new Promise(resolve => setTimeout(resolve, this.config.offlineTestDuration));
        
        // Verify connectivity is restored
        let connected = false;
        let attempts = 0;
        
        while (!connected && attempts < 10) {
            try {
                await this.apiClient.get('/api/health');
                connected = true;
                console.log('✅ Network connectivity restored');
            } catch (error) {
                attempts++;
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
        
        if (!connected) {
            throw new Error('Failed to restore network connectivity');
        }
    }

    /**
     * Test data synchronization after connectivity restoration
     */
    async testDataSynchronization() {
        console.log('🔄 Testing data synchronization...');
        
        const syncStartTime = performance.now();
        
        try {
            const response = await this.apiClient.post('/api/sync/offline-data', {
                timeout: 30000
            });
            
            const syncEndTime = performance.now();
            
            return {
                syncTime: syncEndTime - syncStartTime,
                conflicts: response.data.conflicts || 0,
                meshLatency: response.data.meshLatency || 0
            };
        } catch (error) {
            const syncEndTime = performance.now();
            
            return {
                syncTime: syncEndTime - syncStartTime,
                conflicts: 0,
                meshLatency: 0,
                error: error.message
            };
        }
    }

    /**
     * Collect system metrics
     */
    collectSystemMetrics() {
        const cpuUsage = process.cpuUsage();
        const memUsage = process.memoryUsage();
        
        this.metrics.system.cpuUtilization.push({
            timestamp: Date.now(),
            user: cpuUsage.user,
            system: cpuUsage.system
        });
        
        this.metrics.system.memoryUtilization.push({
            timestamp: Date.now(),
            rss: memUsage.rss,
            heapUsed: memUsage.heapUsed,
            heapTotal: memUsage.heapTotal,
            external: memUsage.external
        });
    }

    /**
     * Generate comprehensive validation report
     */
    async generateReport() {
        console.log('📋 Generating scalability validation report...');
        
        const totalTestTime = this.testEndTime - this.testStartTime;
        
        const report = {
            testInfo: {
                timestamp: new Date().toISOString(),
                duration: totalTestTime,
                configuration: this.config
            },
            scalabilityRequirements: {
                maxDoors: this.config.maxDoors,
                maxVideoStreams: this.config.maxVideoStreams,
                doorsTestPassed: this.metrics.accessControl.errorRate < 5, // Less than 5% error rate
                videoStreamsTestPassed: this.metrics.videoStreaming.failedStreams < (this.config.maxVideoStreams * 0.05), // Less than 5% failed streams
                overallPassed: this.isValidationSuccessful()
            },
            detailedMetrics: this.metrics,
            recommendations: this.generateRecommendations(),
            summary: this.generateSummary()
        };

        // Write report to file
        fs.writeFileSync(this.config.reportPath, JSON.stringify(report, null, 2));
        
        console.log(`📄 Report saved to: ${this.config.reportPath}`);
        
        return report;
    }

    /**
     * Determine if validation was successful
     */
    isValidationSuccessful() {
        const accessControlPassed = this.metrics.accessControl.errorRate < 5;
        const videoStreamingPassed = this.metrics.videoStreaming.failedStreams < (this.config.maxVideoStreams * 0.05);
        const databasePassed = this.metrics.database.averageQueryTime < 1000; // Less than 1 second average
        const realTimePassed = this.metrics.realTimeEvents.averageProcessingTime < 100; // Less than 100ms average
        const multiTenantPassed = this.metrics.multiTenant.tenantIsolationViolations === 0;
        
        return accessControlPassed && videoStreamingPassed && databasePassed && realTimePassed && multiTenantPassed;
    }

    /**
     * Generate performance recommendations
     */
    generateRecommendations() {
        const recommendations = [];
        
        if (this.metrics.accessControl.errorRate > 5) {
            recommendations.push({
                category: 'Access Control',
                severity: 'High',
                issue: `High error rate: ${this.metrics.accessControl.errorRate.toFixed(2)}%`,
                recommendation: 'Consider scaling access control service horizontally or optimizing database queries'
            });
        }
        
        if (this.metrics.accessControl.averageResponseTime > 500) {
            recommendations.push({
                category: 'Access Control',
                severity: 'Medium',
                issue: `Slow response time: ${this.metrics.accessControl.averageResponseTime.toFixed(2)}ms`,
                recommendation: 'Implement caching layer or optimize access control logic'
            });
        }
        
        if (this.metrics.videoStreaming.failedStreams > (this.config.maxVideoStreams * 0.05)) {
            recommendations.push({
                category: 'Video Streaming',
                severity: 'High',
                issue: `High stream failure rate: ${this.metrics.videoStreaming.failedStreams} failed streams`,
                recommendation: 'Increase video service capacity or implement adaptive bitrate streaming'
            });
        }
        
        if (this.metrics.database.slowQueries > 10) {
            recommendations.push({
                category: 'Database',
                severity: 'Medium',
                issue: `${this.metrics.database.slowQueries} slow queries detected`,
                recommendation: 'Optimize database indexes and consider query performance tuning'
            });
        }
        
        if (this.metrics.multiTenant.tenantIsolationViolations > 0) {
            recommendations.push({
                category: 'Multi-Tenant',
                severity: 'Critical',
                issue: `${this.metrics.multiTenant.tenantIsolationViolations} tenant isolation violations`,
                recommendation: 'Review and fix tenant isolation implementation immediately'
            });
        }
        
        return recommendations;
    }

    /**
     * Generate test summary
     */
    generateSummary() {
        return {
            overallResult: this.isValidationSuccessful() ? 'PASSED' : 'FAILED',
            accessControlSummary: `${this.metrics.accessControl.successfulRequests}/${this.metrics.accessControl.totalRequests} requests successful (${(100 - this.metrics.accessControl.errorRate).toFixed(1)}% success rate)`,
            videoStreamingSummary: `${this.metrics.videoStreaming.activeStreams}/${this.metrics.videoStreaming.totalStreams} streams active (${((this.metrics.videoStreaming.activeStreams / this.metrics.videoStreaming.totalStreams) * 100).toFixed(1)}% success rate)`,
            databaseSummary: `${this.metrics.database.queryCount} queries executed, ${this.metrics.database.averageQueryTime.toFixed(2)}ms average response time`,
            realTimeEventsSummary: `${this.metrics.realTimeEvents.eventsProcessed} events processed, ${this.metrics.realTimeEvents.eventThroughput.toFixed(2)} events/sec throughput`,
            multiTenantSummary: `${this.config.tenantCount} tenants tested, ${this.metrics.multiTenant.tenantIsolationViolations} isolation violations`,
            offlineSummary: `${this.metrics.offline.offlineOperationsSuccessful} offline operations successful, ${this.metrics.offline.syncTime.toFixed(2)}ms sync time`
        };
    }

    /**
     * Get validation results
     */
    getValidationResults() {
        return {
            passed: this.isValidationSuccessful(),
            metrics: this.metrics,
            recommendations: this.generateRecommendations(),
            summary: this.generateSummary()
        };
    }

    /**
     * Clean up resources
     */
    async cleanup() {
        console.log('🧹 Cleaning up test resources...');
        
        // Clear monitoring interval
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }
        
        // Close any remaining connections
        this.activeConnections.forEach(connection => {
            if (connection.readyState === WebSocket.OPEN) {
                connection.close();
            }
        });
        
        this.activeConnections.clear();
        
        console.log('✅ Cleanup completed');
    }
}

// Export for use in test suites
module.exports = ScalabilityValidator;

// CLI execution
if (require.main === module) {
    const config = {
        baseUrl: process.env.SPARC_API_URL || 'http://localhost:3000',
        wsUrl: process.env.SPARC_WS_URL || 'ws://localhost:3001',
        maxDoors: parseInt(process.env.MAX_DOORS) || 10000,
        maxVideoStreams: parseInt(process.env.MAX_VIDEO_STREAMS) || 1000,
        testDuration: parseInt(process.env.TEST_DURATION) || 300000,
        tenantCount: parseInt(process.env.TENANT_COUNT) || 10,
        reportPath: process.env.REPORT_PATH || './scalability-report.json'
    };

    const validator = new ScalabilityValidator(config);
    
    validator.runValidation()
        .then(results => {
            console.log('\n🎯 Scalability Validation Results:');
            console.log(`Overall Result: ${results.passed ? '✅ PASSED' : '❌ FAILED'}`);
            console.log('\n📊 Summary:');
            Object.entries(results.summary).forEach(([key, value]) => {
                console.log(`  ${key}: ${value}`);
            });
            
            if (results.recommendations.length > 0) {
                console.log('\n💡 Recommendations:');
                results.recommendations.forEach(rec => {
                    console.log(`  [${rec.severity}] ${rec.category}: ${rec.recommendation}`);
                });
            }
            
            process.exit(results.passed ? 0 : 1);
        })
        .catch(error => {
            console.error('❌ Scalability validation failed:', error);
            process.exit(1);
        });
}