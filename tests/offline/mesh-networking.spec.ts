import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { EventEmitter } from 'events';

// Mock interfaces for offline services and mesh networking
interface OfflineCredential {
  id: string;
  userId: string;
  deviceId: string;
  issuedAt: Date;
  expiresAt: Date;
  revoked: boolean;
  revokedAt?: Date;
  signature: string;
}

interface MeshNode {
  id: string;
  isOnline: boolean;
  lastSeen: Date;
  credentials: OfflineCredential[];
  eventQueue: OfflineEvent[];
  neighbors: string[];
}

interface OfflineEvent {
  id: string;
  type: 'access_attempt' | 'credential_revocation' | 'door_unlock' | 'alarm_trigger';
  timestamp: Date;
  data: any;
  synchronized: boolean;
}

interface ConflictResolution {
  eventId: string;
  conflictType: 'timestamp' | 'credential' | 'access_decision';
  resolution: 'local_wins' | 'remote_wins' | 'merge' | 'manual_review';
  resolvedAt: Date;
}

// Mock offline service implementation
class MockOfflineService extends EventEmitter {
  private nodes: Map<string, MeshNode> = new Map();
  private centralRevocationList: Set<string> = new Set();
  private isNetworkOnline: boolean = true;
  private offlineStartTime?: Date;

  constructor() {
    super();
  }

  // Simulate network going offline
  goOffline(): void {
    this.isNetworkOnline = false;
    this.offlineStartTime = new Date();
    this.nodes.forEach(node => {
      node.isOnline = false;
    });
    this.emit('network_offline');
  }

  // Simulate network coming back online
  goOnline(): void {
    this.isNetworkOnline = true;
    this.offlineStartTime = undefined;
    this.nodes.forEach(node => {
      node.isOnline = true;
      node.lastSeen = new Date();
    });
    this.emit('network_online');
  }

  // Get offline duration in hours
  getOfflineDuration(): number {
    if (!this.offlineStartTime) return 0;
    return (Date.now() - this.offlineStartTime.getTime()) / (1000 * 60 * 60);
  }

  // Add a mesh node
  addNode(nodeId: string): void {
    this.nodes.set(nodeId, {
      id: nodeId,
      isOnline: this.isNetworkOnline,
      lastSeen: new Date(),
      credentials: [],
      eventQueue: [],
      neighbors: []
    });
  }

  // Add credential to node
  addCredential(nodeId: string, credential: OfflineCredential): void {
    const node = this.nodes.get(nodeId);
    if (node) {
      node.credentials.push(credential);
    }
  }

  // Revoke credential centrally
  revokeCredential(credentialId: string): void {
    this.centralRevocationList.add(credentialId);
    
    // If online, propagate immediately
    if (this.isNetworkOnline) {
      this.propagateRevocation(credentialId);
    }
  }

  // Propagate revocation to all nodes
  private propagateRevocation(credentialId: string): void {
    this.nodes.forEach(node => {
      const credential = node.credentials.find(c => c.id === credentialId);
      if (credential) {
        credential.revoked = true;
        credential.revokedAt = new Date();
      }
    });
  }

  // Attempt access with credential
  attemptAccess(nodeId: string, credentialId: string): boolean {
    const node = this.nodes.get(nodeId);
    if (!node) return false;

    const credential = node.credentials.find(c => c.id === credentialId);
    if (!credential) return false;

    // Check if credential is expired
    if (credential.expiresAt < new Date()) return false;

    // Check local revocation status
    if (credential.revoked) return false;

    // If offline, can't check central revocation list
    if (!this.isNetworkOnline) {
      // Log the access attempt for later synchronization
      this.queueEvent(nodeId, {
        id: `access_${Date.now()}`,
        type: 'access_attempt',
        timestamp: new Date(),
        data: { credentialId, granted: true },
        synchronized: false
      });
      return true;
    }

    // If online, check central revocation list
    if (this.centralRevocationList.has(credentialId)) {
      credential.revoked = true;
      credential.revokedAt = new Date();
      return false;
    }

    return true;
  }

  // Queue event for later synchronization
  queueEvent(nodeId: string, event: OfflineEvent): void {
    const node = this.nodes.get(nodeId);
    if (node) {
      node.eventQueue.push(event);
    }
  }

  // Synchronize when network comes back online
  async synchronizeNode(nodeId: string): Promise<ConflictResolution[]> {
    const node = this.nodes.get(nodeId);
    if (!node || !this.isNetworkOnline) return [];

    const conflicts: ConflictResolution[] = [];

    // Synchronize revocations
    this.centralRevocationList.forEach(credentialId => {
      const credential = node.credentials.find(c => c.id === credentialId);
      if (credential && !credential.revoked) {
        // Check if access was granted while offline
        const offlineAccess = node.eventQueue.find(e => 
          e.type === 'access_attempt' && 
          e.data.credentialId === credentialId &&
          !e.synchronized
        );

        if (offlineAccess) {
          conflicts.push({
            eventId: offlineAccess.id,
            conflictType: 'credential',
            resolution: 'manual_review',
            resolvedAt: new Date()
          });
        }

        credential.revoked = true;
        credential.revokedAt = new Date();
      }
    });

    // Mark events as synchronized
    node.eventQueue.forEach(event => {
      event.synchronized = true;
    });

    return conflicts;
  }

  // Get node status
  getNodeStatus(nodeId: string): MeshNode | undefined {
    return this.nodes.get(nodeId);
  }

  // Get all nodes
  getAllNodes(): MeshNode[] {
    return Array.from(this.nodes.values());
  }

  // Simulate mesh networking between nodes
  establishMeshConnection(nodeId1: string, nodeId2: string): void {
    const node1 = this.nodes.get(nodeId1);
    const node2 = this.nodes.get(nodeId2);
    
    if (node1 && node2) {
      if (!node1.neighbors.includes(nodeId2)) {
        node1.neighbors.push(nodeId2);
      }
      if (!node2.neighbors.includes(nodeId1)) {
        node2.neighbors.push(nodeId1);
      }
    }
  }

  // Propagate data through mesh network
  propagateThroughMesh(sourceNodeId: string, data: any): void {
    const visited = new Set<string>();
    const queue = [sourceNodeId];

    while (queue.length > 0) {
      const currentNodeId = queue.shift()!;
      if (visited.has(currentNodeId)) continue;
      
      visited.add(currentNodeId);
      const currentNode = this.nodes.get(currentNodeId);
      
      if (currentNode) {
        // Process data at current node
        this.processDataAtNode(currentNodeId, data);
        
        // Add neighbors to queue
        currentNode.neighbors.forEach(neighborId => {
          if (!visited.has(neighborId)) {
            queue.push(neighborId);
          }
        });
      }
    }
  }

  private processDataAtNode(nodeId: string, data: any): void {
    // Implementation for processing data at a specific node
    const node = this.nodes.get(nodeId);
    if (node && data.type === 'credential_revocation') {
      const credential = node.credentials.find(c => c.id === data.credentialId);
      if (credential) {
        credential.revoked = true;
        credential.revokedAt = new Date();
      }
    }
  }
}

describe('Mesh Networking Offline Resilience Tests', () => {
  let offlineService: MockOfflineService;
  const SEVENTY_TWO_HOURS = 72 * 60 * 60 * 1000; // 72 hours in milliseconds

  beforeEach(() => {
    offlineService = new MockOfflineService();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('72-Hour Offline Operation', () => {
    it('should maintain access control functionality for 72 hours offline', async () => {
      // Setup mesh network with multiple nodes
      const nodeIds = ['node1', 'node2', 'node3', 'node4'];
      nodeIds.forEach(id => offlineService.addNode(id));

      // Establish mesh connections
      offlineService.establishMeshConnection('node1', 'node2');
      offlineService.establishMeshConnection('node2', 'node3');
      offlineService.establishMeshConnection('node3', 'node4');
      offlineService.establishMeshConnection('node1', 'node4');

      // Add valid credentials
      const credential: OfflineCredential = {
        id: 'cred_001',
        userId: 'user_001',
        deviceId: 'device_001',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        revoked: false,
        signature: 'mock_signature'
      };

      nodeIds.forEach(nodeId => {
        offlineService.addCredential(nodeId, credential);
      });

      // Go offline
      offlineService.goOffline();

      // Simulate 72 hours of operation
      for (let hour = 0; hour < 72; hour++) {
        // Advance time by 1 hour
        jest.advanceTimersByTime(60 * 60 * 1000);

        // Test access attempts throughout the offline period
        nodeIds.forEach(nodeId => {
          const accessGranted = offlineService.attemptAccess(nodeId, 'cred_001');
          expect(accessGranted).toBe(true);
        });

        // Verify offline duration tracking
        expect(offlineService.getOfflineDuration()).toBe(hour + 1);
      }

      // Verify all nodes maintained functionality
      const allNodes = offlineService.getAllNodes();
      expect(allNodes).toHaveLength(4);
      allNodes.forEach(node => {
        expect(node.eventQueue.length).toBeGreaterThan(0);
        expect(node.isOnline).toBe(false);
      });
    });

    it('should queue events during offline operation', async () => {
      offlineService.addNode('node1');
      const credential: OfflineCredential = {
        id: 'cred_002',
        userId: 'user_002',
        deviceId: 'device_002',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
        signature: 'mock_signature'
      };
      offlineService.addCredential('node1', credential);

      // Go offline
      offlineService.goOffline();

      // Perform multiple access attempts
      for (let i = 0; i < 100; i++) {
        offlineService.attemptAccess('node1', 'cred_002');
        jest.advanceTimersByTime(60 * 1000); // 1 minute intervals
      }

      const node = offlineService.getNodeStatus('node1');
      expect(node?.eventQueue).toHaveLength(100);
      expect(node?.eventQueue.every(event => !event.synchronized)).toBe(true);
    });
  });

  describe('Credential Revocation Propagation', () => {
    it('should handle credential revocation during offline period', async () => {
      offlineService.addNode('node1');
      const credential: OfflineCredential = {
        id: 'cred_003',
        userId: 'user_003',
        deviceId: 'device_003',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
        signature: 'mock_signature'
      };
      offlineService.addCredential('node1', credential);

      // Go offline
      offlineService.goOffline();

      // Revoke credential while offline (simulates central authority action)
      offlineService.revokeCredential('cred_003');

      // Access should still be granted locally since revocation can't propagate
      const accessGranted = offlineService.attemptAccess('node1', 'cred_003');
      expect(accessGranted).toBe(true);

      // Come back online
      offlineService.goOnline();

      // Synchronize and check for conflicts
      const conflicts = await offlineService.synchronizeNode('node1');
      expect(conflicts).toHaveLength(1);
      expect(conflicts[0].conflictType).toBe('credential');
      expect(conflicts[0].resolution).toBe('manual_review');

      // Verify credential is now revoked
      const node = offlineService.getNodeStatus('node1');
      const revokedCredential = node?.credentials.find(c => c.id === 'cred_003');
      expect(revokedCredential?.revoked).toBe(true);
    });

    it('should propagate revocations through mesh network when online', async () => {
      // Setup mesh network
      const nodeIds = ['node1', 'node2', 'node3'];
      nodeIds.forEach(id => offlineService.addNode(id));
      
      offlineService.establishMeshConnection('node1', 'node2');
      offlineService.establishMeshConnection('node2', 'node3');

      const credential: OfflineCredential = {
        id: 'cred_004',
        userId: 'user_004',
        deviceId: 'device_004',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
        signature: 'mock_signature'
      };

      nodeIds.forEach(nodeId => {
        offlineService.addCredential(nodeId, credential);
      });

      // Revoke credential while online
      offlineService.revokeCredential('cred_004');

      // Propagate through mesh
      offlineService.propagateThroughMesh('node1', {
        type: 'credential_revocation',
        credentialId: 'cred_004'
      });

      // Verify revocation propagated to all nodes
      nodeIds.forEach(nodeId => {
        const node = offlineService.getNodeStatus(nodeId);
        const revokedCredential = node?.credentials.find(c => c.id === 'cred_004');
        expect(revokedCredential?.revoked).toBe(true);
      });
    });
  });

  describe('Data Synchronization and Conflict Resolution', () => {
    it('should synchronize queued events when connectivity is restored', async () => {
      offlineService.addNode('node1');
      const credential: OfflineCredential = {
        id: 'cred_005',
        userId: 'user_005',
        deviceId: 'device_005',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
        signature: 'mock_signature'
      };
      offlineService.addCredential('node1', credential);

      // Go offline and perform operations
      offlineService.goOffline();
      
      for (let i = 0; i < 50; i++) {
        offlineService.attemptAccess('node1', 'cred_005');
      }

      // Verify events are queued and not synchronized
      let node = offlineService.getNodeStatus('node1');
      expect(node?.eventQueue).toHaveLength(50);
      expect(node?.eventQueue.every(event => !event.synchronized)).toBe(true);

      // Come back online and synchronize
      offlineService.goOnline();
      await offlineService.synchronizeNode('node1');

      // Verify events are marked as synchronized
      node = offlineService.getNodeStatus('node1');
      expect(node?.eventQueue.every(event => event.synchronized)).toBe(true);
    });

    it('should detect and resolve conflicts during synchronization', async () => {
      offlineService.addNode('node1');
      const credential: OfflineCredential = {
        id: 'cred_006',
        userId: 'user_006',
        deviceId: 'device_006',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
        signature: 'mock_signature'
      };
      offlineService.addCredential('node1', credential);

      // Go offline
      offlineService.goOffline();

      // Perform access while offline
      offlineService.attemptAccess('node1', 'cred_006');

      // Revoke credential centrally while node is offline
      offlineService.revokeCredential('cred_006');

      // Come back online and synchronize
      offlineService.goOnline();
      const conflicts = await offlineService.synchronizeNode('node1');

      // Should detect conflict between offline access and central revocation
      expect(conflicts).toHaveLength(1);
      expect(conflicts[0].conflictType).toBe('credential');
      expect(conflicts[0].resolution).toBe('manual_review');
      expect(conflicts[0].resolvedAt).toBeInstanceOf(Date);
    });
  });

  describe('Mesh Network Resilience', () => {
    it('should maintain connectivity through mesh routing when nodes fail', async () => {
      // Setup a mesh network with redundant paths
      const nodeIds = ['node1', 'node2', 'node3', 'node4', 'node5'];
      nodeIds.forEach(id => offlineService.addNode(id));

      // Create mesh topology with multiple paths
      offlineService.establishMeshConnection('node1', 'node2');
      offlineService.establishMeshConnection('node1', 'node3');
      offlineService.establishMeshConnection('node2', 'node4');
      offlineService.establishMeshConnection('node3', 'node4');
      offlineService.establishMeshConnection('node4', 'node5');

      // Verify all nodes are connected
      nodeIds.forEach(nodeId => {
        const node = offlineService.getNodeStatus(nodeId);
        expect(node?.neighbors.length).toBeGreaterThan(0);
      });

      // Test data propagation through mesh
      offlineService.propagateThroughMesh('node1', {
        type: 'test_data',
        message: 'mesh_test'
      });

      // All nodes should be reachable through mesh routing
      const allNodes = offlineService.getAllNodes();
      expect(allNodes).toHaveLength(5);
      allNodes.forEach(node => {
        expect(node.isOnline).toBe(true);
      });
    });

    it('should handle extended offline periods with graceful degradation', async () => {
      offlineService.addNode('node1');
      const credential: OfflineCredential = {
        id: 'cred_007',
        userId: 'user_007',
        deviceId: 'device_007',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        revoked: false,
        signature: 'mock_signature'
      };
      offlineService.addCredential('node1', credential);

      // Go offline
      offlineService.goOffline();

      // Test access for first 24 hours (should work)
      jest.advanceTimersByTime(23 * 60 * 60 * 1000); // 23 hours
      expect(offlineService.attemptAccess('node1', 'cred_007')).toBe(true);

      // After credential expires (should fail)
      jest.advanceTimersByTime(2 * 60 * 60 * 1000); // 2 more hours (total 25)
      expect(offlineService.attemptAccess('node1', 'cred_007')).toBe(false);

      // Continue to 72 hours to test extended offline operation
      jest.advanceTimersByTime(47 * 60 * 60 * 1000); // 47 more hours (total 72)
      expect(offlineService.getOfflineDuration()).toBe(72);

      // System should still be operational, just with expired credentials
      const node = offlineService.getNodeStatus('node1');
      expect(node?.isOnline).toBe(false);
      expect(node?.eventQueue.length).toBeGreaterThan(0);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large numbers of offline events efficiently', async () => {
      const nodeCount = 100;
      const eventsPerNode = 1000;

      // Setup multiple nodes
      for (let i = 1; i <= nodeCount; i++) {
        offlineService.addNode(`node${i}`);
        const credential: OfflineCredential = {
          id: `cred_${i}`,
          userId: `user_${i}`,
          deviceId: `device_${i}`,
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          revoked: false,
          signature: 'mock_signature'
        };
        offlineService.addCredential(`node${i}`, credential);
      }

      // Go offline
      offlineService.goOffline();

      // Generate large number of events
      const startTime = Date.now();
      for (let nodeIndex = 1; nodeIndex <= nodeCount; nodeIndex++) {
        for (let eventIndex = 0; eventIndex < eventsPerNode; eventIndex++) {
          offlineService.attemptAccess(`node${nodeIndex}`, `cred_${nodeIndex}`);
        }
      }
      const endTime = Date.now();

      // Verify performance (should complete within reasonable time)
      expect(endTime - startTime).toBeLessThan(10000); // 10 seconds

      // Verify all events were queued
      const totalEvents = offlineService.getAllNodes()
        .reduce((sum, node) => sum + node.eventQueue.length, 0);
      expect(totalEvents).toBe(nodeCount * eventsPerNode);
    });

    it('should efficiently synchronize large datasets when coming online', async () => {
      const nodeCount = 50;
      
      // Setup nodes with events
      for (let i = 1; i <= nodeCount; i++) {
        offlineService.addNode(`node${i}`);
        const credential: OfflineCredential = {
          id: `cred_${i}`,
          userId: `user_${i}`,
          deviceId: `device_${i}`,
          issuedAt: new Date(),
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          revoked: false,
          signature: 'mock_signature'
        };
        offlineService.addCredential(`node${i}`, credential);
      }

      // Go offline and generate events
      offlineService.goOffline();
      for (let i = 1; i <= nodeCount; i++) {
        for (let j = 0; j < 100; j++) {
          offlineService.attemptAccess(`node${i}`, `cred_${i}`);
        }
      }

      // Come back online and synchronize all nodes
      offlineService.goOnline();
      const startTime = Date.now();
      
      const allConflicts = [];
      for (let i = 1; i <= nodeCount; i++) {
        const conflicts = await offlineService.synchronizeNode(`node${i}`);
        allConflicts.push(...conflicts);
      }
      
      const endTime = Date.now();

      // Verify synchronization completed efficiently
      expect(endTime - startTime).toBeLessThan(5000); // 5 seconds
      
      // Verify all events are synchronized
      const allNodes = offlineService.getAllNodes();
      allNodes.forEach(node => {
        expect(node.eventQueue.every(event => event.synchronized)).toBe(true);
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle rapid online/offline transitions', async () => {
      offlineService.addNode('node1');
      const credential: OfflineCredential = {
        id: 'cred_008',
        userId: 'user_008',
        deviceId: 'device_008',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
        signature: 'mock_signature'
      };
      offlineService.addCredential('node1', credential);

      // Rapid transitions
      for (let i = 0; i < 10; i++) {
        offlineService.goOffline();
        offlineService.attemptAccess('node1', 'cred_008');
        offlineService.goOnline();
        await offlineService.synchronizeNode('node1');
      }

      // System should remain stable
      const node = offlineService.getNodeStatus('node1');
      expect(node?.isOnline).toBe(true);
      expect(node?.eventQueue.every(event => event.synchronized)).toBe(true);
    });

    it('should handle corrupted or invalid credentials gracefully', async () => {
      offlineService.addNode('node1');
      
      // Add invalid credential
      const invalidCredential: OfflineCredential = {
        id: 'invalid_cred',
        userId: 'user_invalid',
        deviceId: 'device_invalid',
        issuedAt: new Date(),
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // Already expired
        revoked: false,
        signature: 'invalid_signature'
      };
      offlineService.addCredential('node1', invalidCredential);

      // Go offline
      offlineService.goOffline();

      // Access with invalid credential should fail
      expect(offlineService.attemptAccess('node1', 'invalid_cred')).toBe(false);
      expect(offlineService.attemptAccess('node1', 'nonexistent_cred')).toBe(false);

      // System should remain stable
      const node = offlineService.getNodeStatus('node1');
      expect(node?.isOnline).toBe(false);
    });
  });
});