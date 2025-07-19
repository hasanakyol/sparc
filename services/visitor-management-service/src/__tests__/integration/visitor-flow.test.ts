import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { Hono } from 'hono';
import { testClient } from 'hono/testing';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Client } from 'pg';
import Redis from 'ioredis';
import { Server as SocketIOServer } from 'socket.io';
import http from 'http';
import * as schema from '@db/schemas/visitor-management';
import { VisitorService } from '../../services/visitor.service';
import { WatchlistService } from '../../services/watchlist.service';
import { BadgeService } from '../../services/badge.service';
import { NotificationService } from '../../services/notification.service';
import { createVisitorRoutes } from '../../routes/visitors';
import { createWatchlistRoutes } from '../../routes/watchlist';
import { createBadgeRoutes } from '../../routes/badges';
import { VisitorStatus } from '../../types';

describe('Visitor Management Integration Tests', () => {
  let app: Hono;
  let db: ReturnType<typeof drizzle>;
  let redis: Redis;
  let pgClient: Client;
  let io: SocketIOServer;
  let httpServer: http.Server;
  
  // Services
  let visitorService: VisitorService;
  let watchlistService: WatchlistService;
  let badgeService: BadgeService;
  let notificationService: NotificationService;
  
  // Test data
  const testOrganizationId = 'test-org-123';
  const testUserId = 'test-user-123';
  const testSiteId = 'test-site-123';
  
  beforeAll(async () => {
    // Setup database
    pgClient = new Client({
      connectionString: process.env.DATABASE_URL || 'postgresql://test:test@localhost:5432/test_visitors',
    });
    await pgClient.connect();
    db = drizzle(pgClient, { schema });
    
    // Setup Redis
    redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      db: parseInt(process.env.REDIS_DB || '1'),
    });
    
    // Setup Socket.IO
    httpServer = http.createServer();
    io = new SocketIOServer(httpServer, {
      cors: { origin: '*' },
    });
    
    // Initialize services
    visitorService = new VisitorService(db, redis);
    watchlistService = new WatchlistService(db, redis);
    badgeService = new BadgeService(db, redis);
    notificationService = new NotificationService(db, redis);
    
    // Setup app with routes
    app = new Hono();
    
    // Add auth middleware mock
    app.use('*', async (c, next) => {
      c.set('user', { id: testUserId });
      c.set('organizationId', testOrganizationId);
      await next();
    });
    
    // Mount routes
    app.route('/visitors', createVisitorRoutes(visitorService, watchlistService, io));
    app.route('/watchlist', createWatchlistRoutes(watchlistService));
    app.route('/badges', createBadgeRoutes(badgeService));
    
    // Clear test data
    await db.delete(schema.visitors).where(eq(schema.visitors.organizationId, testOrganizationId));
    await db.delete(schema.watchlist).where(eq(schema.watchlist.organizationId, testOrganizationId));
  });
  
  afterAll(async () => {
    // Cleanup
    await redis.quit();
    await pgClient.end();
    io.close();
    httpServer.close();
  });
  
  describe('Complete Visitor Flow', () => {
    let visitorId: string;
    let credentialCode: string;
    
    it('should pre-register a visitor', async () => {
      const client = testClient(app);
      
      const response = await client.visitors['pre-register'].$post({
        json: {
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          phone: '+1234567890',
          company: 'Test Corp',
          hostId: 'host-123',
          hostName: 'Jane Smith',
          hostEmail: 'jane.smith@company.com',
          siteId: testSiteId,
          scheduledDate: new Date(Date.now() + 86400000).toISOString(), // Tomorrow
          scheduledTime: '10:00',
          purpose: 'Business Meeting',
          notifyHost: true,
        },
      });
      
      expect(response.status).toBe(201);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('id');
      expect(data.data.status).toBe(VisitorStatus.PRE_REGISTERED);
      expect(data.data).toHaveProperty('credentialCode');
      
      visitorId = data.data.id;
      credentialCode = data.data.credentialCode;
    });
    
    it('should check visitor against watchlist', async () => {
      const client = testClient(app);
      
      // First add someone to watchlist
      await client.watchlist.$post({
        json: {
          firstName: 'Bad',
          lastName: 'Person',
          email: 'bad@person.com',
          reason: 'Security threat',
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
        },
      });
      
      // Check our visitor
      const response = await client.watchlist.check.$post({
        json: {
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.isOnWatchlist).toBe(false);
    });
    
    it('should check in the visitor', async () => {
      const client = testClient(app);
      
      const response = await client.visitors['check-in'].$post({
        json: {
          credentialCode,
          actualSiteId: testSiteId,
          checkInLocation: 'Main Entrance',
          photoData: 'data:image/jpeg;base64,/9j/4AAQSkZJRg==',
          idVerified: true,
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.status).toBe(VisitorStatus.CHECKED_IN);
      expect(data.data.checkInTime).toBeDefined();
      expect(data.data.actualCheckInTime).toBeDefined();
    });
    
    it('should generate a badge for the visitor', async () => {
      const client = testClient(app);
      
      const response = await client.badges.print.$post({
        json: {
          visitorId,
          templateId: 'default',
          printerName: 'Test Printer',
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('badgeId');
      expect(data.data).toHaveProperty('pdfUrl');
    });
    
    it('should get visitor details', async () => {
      const client = testClient(app);
      
      const response = await client.visitors[':id'].$get({
        param: { id: visitorId },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.id).toBe(visitorId);
      expect(data.data.status).toBe(VisitorStatus.CHECKED_IN);
    });
    
    it('should list active visitors', async () => {
      const client = testClient(app);
      
      const response = await client.visitors.active.all.$get();
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data).toHaveLength(1);
      expect(data.data[0].id).toBe(visitorId);
    });
    
    it('should check out the visitor', async () => {
      const client = testClient(app);
      
      const response = await client.visitors[':id']['check-out'].$post({
        param: { id: visitorId },
        json: {
          checkOutLocation: 'Main Entrance',
          badgeReturned: true,
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.status).toBe(VisitorStatus.CHECKED_OUT);
      expect(data.data.checkOutTime).toBeDefined();
      expect(data.data.actualCheckOutTime).toBeDefined();
    });
    
    it('should no longer list visitor as active', async () => {
      const client = testClient(app);
      
      const response = await client.visitors.active.all.$get();
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data).toHaveLength(0);
    });
  });
  
  describe('Walk-in Visitor Flow', () => {
    it('should handle walk-in visitor registration and check-in', async () => {
      const client = testClient(app);
      
      // Register and check in simultaneously
      const response = await client.visitors['check-in'].$post({
        json: {
          // No credential code - indicates walk-in
          firstName: 'Walk',
          lastName: 'In',
          email: 'walkin@example.com',
          phone: '+1234567891',
          company: 'Walk-in Corp',
          hostName: 'Host Person',
          siteId: testSiteId,
          purpose: 'Delivery',
          checkInLocation: 'Reception',
          photoData: 'data:image/jpeg;base64,/9j/4AAQSkZJRg==',
          idVerified: true,
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.status).toBe(VisitorStatus.CHECKED_IN);
      expect(data.data.isWalkIn).toBe(true);
    });
  });
  
  describe('Group Visit Flow', () => {
    let groupId: string;
    const groupVisitorIds: string[] = [];
    
    it('should create a visitor group', async () => {
      const client = testClient(app);
      
      // First create group members
      for (let i = 1; i <= 3; i++) {
        const response = await client.visitors['pre-register'].$post({
          json: {
            firstName: `Group${i}`,
            lastName: 'Member',
            email: `group${i}@example.com`,
            phone: `+123456789${i}`,
            company: 'Group Corp',
            hostId: 'host-123',
            hostName: 'Group Host',
            hostEmail: 'host@company.com',
            siteId: testSiteId,
            scheduledDate: new Date(Date.now() + 86400000).toISOString(),
            scheduledTime: '14:00',
            purpose: 'Team Visit',
          },
        });
        
        const data = await response.json();
        groupVisitorIds.push(data.data.id);
      }
      
      // Create group
      const response = await client.groups.$post({
        json: {
          name: 'Team Visit Group',
          organizerName: 'Team Lead',
          organizerEmail: 'lead@group.com',
          organizerPhone: '+1234567899',
          visitDate: new Date(Date.now() + 86400000).toISOString(),
          visitTime: '14:00',
          purpose: 'Team building and facility tour',
          siteId: testSiteId,
          visitorIds: groupVisitorIds,
        },
      });
      
      expect(response.status).toBe(201);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('id');
      groupId = data.data.id;
    });
    
    it('should check in entire group', async () => {
      const client = testClient(app);
      
      const response = await client.groups[':id']['check-in'].$post({
        param: { id: groupId },
        json: {
          checkInLocation: 'Group Entrance',
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.checkedInCount).toBe(3);
    });
    
    it('should check out entire group', async () => {
      const client = testClient(app);
      
      const response = await client.groups[':id']['check-out'].$post({
        param: { id: groupId },
        json: {
          checkOutLocation: 'Group Entrance',
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.checkedOutCount).toBe(3);
    });
  });
  
  describe('Emergency Evacuation', () => {
    it('should get evacuation list with all on-site visitors', async () => {
      const client = testClient(app);
      
      // First check in some visitors
      await client.visitors['check-in'].$post({
        json: {
          firstName: 'Emergency',
          lastName: 'Test1',
          email: 'emergency1@example.com',
          phone: '+1234567801',
          company: 'Test Corp',
          hostName: 'Host 1',
          siteId: testSiteId,
          purpose: 'Meeting',
          checkInLocation: 'Main',
          idVerified: true,
        },
      });
      
      await client.visitors['check-in'].$post({
        json: {
          firstName: 'Emergency',
          lastName: 'Test2',
          email: 'emergency2@example.com',
          phone: '+1234567802',
          company: 'Test Corp',
          hostName: 'Host 2',
          siteId: testSiteId,
          purpose: 'Meeting',
          checkInLocation: 'Side',
          idVerified: true,
        },
      });
      
      // Get evacuation list
      const response = await client.visitors.emergency.evacuation.$get();
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data.visitors.length).toBeGreaterThanOrEqual(2);
      expect(data.data.totalCount).toBeGreaterThanOrEqual(2);
      expect(data.data.byLocation).toBeDefined();
      expect(data.data.byHost).toBeDefined();
    });
  });
  
  describe('Analytics', () => {
    it('should get visitor analytics summary', async () => {
      const client = testClient(app);
      
      const response = await client.visitors.analytics.summary.$get({
        query: {
          startDate: new Date(Date.now() - 7 * 86400000).toISOString(),
          endDate: new Date().toISOString(),
          groupBy: 'day',
        },
      });
      
      expect(response.status).toBe(200);
      const data = await response.json();
      expect(data.success).toBe(true);
      expect(data.data).toHaveProperty('totalVisitors');
      expect(data.data).toHaveProperty('uniqueVisitors');
      expect(data.data).toHaveProperty('averageDuration');
      expect(data.data).toHaveProperty('peakHours');
      expect(data.data).toHaveProperty('visitorsByDay');
    });
  });
});