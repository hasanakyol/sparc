import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { VisitorService } from '../../../services/visitor.service';
import * as db from '../../../db';
import { visitors, visitorCredentials, visitorAccessLogs } from '@sparc/database/schemas/visitor-management';
import { users } from '@sparc/database/schemas/user-management';

// Mock the database module
jest.mock('../../../db');

// Mock logger
jest.mock('@sparc/shared', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}));

describe('VisitorService', () => {
  let visitorService: VisitorService;
  let mockDb: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create mock database methods
    mockDb = {
      select: jest.fn().mockReturnThis(),
      from: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      leftJoin: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      offset: jest.fn().mockReturnThis(),
      insert: jest.fn().mockReturnThis(),
      values: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      returning: jest.fn().mockResolvedValue([]),
    };

    // Mock getDb to return our mock database
    (db.getDb as jest.Mock).mockReturnValue(mockDb);

    visitorService = new VisitorService();
  });

  describe('preRegisterVisitor', () => {
    const mockVisitorData = {
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      phone: '+1234567890',
      company: 'Test Corp',
      purpose: 'Business Meeting',
      hostUserId: 'host-123',
      expectedArrival: '2024-01-01T10:00:00Z',
      expectedDeparture: '2024-01-01T18:00:00Z',
      accessAreas: ['lobby', 'meeting-room-1'],
      requiresEscort: false,
    };

    it('should successfully pre-register a visitor', async () => {
      const mockHost = { id: 'host-123', organizationId: 'org-123' };
      const mockVisitor = {
        id: 'visitor-123',
        ...mockVisitorData,
        organizationId: 'org-123',
        invitationCode: 'ABC12345',
        status: 'PENDING',
        createdBy: 'user-123',
      };

      // Mock host lookup
      mockDb.limit.mockResolvedValueOnce([mockHost]);
      
      // Mock visitor creation
      mockDb.returning.mockResolvedValueOnce([mockVisitor]);

      const result = await visitorService.preRegisterVisitor(
        mockVisitorData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(result.data).toEqual({
        visitor: mockVisitor,
        invitationCode: mockVisitor.invitationCode,
      });

      // Verify database calls
      expect(mockDb.select).toHaveBeenCalled();
      expect(mockDb.from).toHaveBeenCalledWith(users);
      expect(mockDb.insert).toHaveBeenCalledWith(visitors);
    });

    it('should fail if host does not exist', async () => {
      // Mock host lookup returning empty
      mockDb.limit.mockResolvedValueOnce([]);

      const result = await visitorService.preRegisterVisitor(
        mockVisitorData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('HOST_NOT_FOUND');
      expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      // Mock host lookup
      mockDb.limit.mockResolvedValueOnce([{ id: 'host-123' }]);
      
      // Mock database error
      mockDb.returning.mockRejectedValueOnce(new Error('Database error'));

      const result = await visitorService.preRegisterVisitor(
        mockVisitorData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('REGISTRATION_FAILED');
    });
  });

  describe('checkInVisitor', () => {
    const mockCheckInData = {
      visitorId: 'visitor-123',
    };

    it('should successfully check in a pre-registered visitor', async () => {
      const mockVisitor = {
        id: 'visitor-123',
        firstName: 'John',
        lastName: 'Doe',
        status: 'APPROVED',
        organizationId: 'org-123',
        expectedDeparture: new Date('2024-01-01T18:00:00Z'),
        accessAreas: ['lobby'],
      };

      const mockUpdatedVisitor = {
        ...mockVisitor,
        status: 'CHECKED_IN',
        actualArrival: new Date(),
        checkedInBy: 'user-123',
      };

      const mockCredential = {
        id: 'cred-123',
        visitorId: 'visitor-123',
        credentialType: 'QR_CODE',
      };

      // Mock visitor lookup
      mockDb.limit.mockResolvedValueOnce([mockVisitor]);
      
      // Mock visitor update
      mockDb.returning.mockResolvedValueOnce([mockUpdatedVisitor]);
      
      // Mock credential creation
      mockDb.returning.mockResolvedValueOnce([mockCredential]);
      
      // Mock access log creation
      mockDb.values.mockResolvedValueOnce([]);

      const result = await visitorService.checkInVisitor(
        mockCheckInData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(result.data.visitor.status).toBe('CHECKED_IN');
      expect(result.data.credential).toBeDefined();

      // Verify database calls
      expect(mockDb.update).toHaveBeenCalledWith(visitors);
      expect(mockDb.insert).toHaveBeenCalledWith(visitorCredentials);
      expect(mockDb.insert).toHaveBeenCalledWith(visitorAccessLogs);
    });

    it('should fail if visitor is already checked in', async () => {
      const mockVisitor = {
        id: 'visitor-123',
        status: 'CHECKED_IN',
      };

      // Mock visitor lookup
      mockDb.limit.mockResolvedValueOnce([mockVisitor]);

      const result = await visitorService.checkInVisitor(
        mockCheckInData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ALREADY_CHECKED_IN');
      expect(mockDb.update).not.toHaveBeenCalled();
    });

    it('should fail if visitor is denied', async () => {
      const mockVisitor = {
        id: 'visitor-123',
        status: 'DENIED',
      };

      // Mock visitor lookup
      mockDb.limit.mockResolvedValueOnce([mockVisitor]);

      const result = await visitorService.checkInVisitor(
        mockCheckInData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('VISITOR_DENIED');
    });

    it('should handle walk-in visitors', async () => {
      const walkInData = {
        firstName: 'Jane',
        lastName: 'Smith',
        email: 'jane.smith@example.com',
        purpose: 'Delivery',
        hostUserId: 'host-123',
      };

      const mockHost = { id: 'host-123' };
      const mockNewVisitor = {
        id: 'visitor-456',
        ...walkInData,
        status: 'APPROVED',
        organizationId: 'org-123',
      };

      // Mock no existing visitor
      mockDb.limit.mockResolvedValueOnce([]);
      
      // Mock host lookup
      mockDb.limit.mockResolvedValueOnce([mockHost]);
      
      // Mock visitor creation
      mockDb.returning.mockResolvedValueOnce([mockNewVisitor]);
      
      // Mock visitor update
      mockDb.returning.mockResolvedValueOnce([{
        ...mockNewVisitor,
        status: 'CHECKED_IN',
      }]);
      
      // Mock credential creation
      mockDb.returning.mockResolvedValueOnce([{ id: 'cred-456' }]);

      const result = await visitorService.checkInVisitor(
        walkInData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(mockDb.insert).toHaveBeenCalledWith(visitors);
    });
  });

  describe('checkOutVisitor', () => {
    it('should successfully check out a visitor', async () => {
      const mockVisitor = {
        id: 'visitor-123',
        status: 'CHECKED_IN',
        organizationId: 'org-123',
      };

      const mockUpdatedVisitor = {
        ...mockVisitor,
        status: 'CHECKED_OUT',
        actualDeparture: new Date(),
        checkedOutBy: 'user-123',
      };

      // Mock visitor lookup
      mockDb.limit.mockResolvedValueOnce([mockVisitor]);
      
      // Mock visitor update
      mockDb.returning.mockResolvedValueOnce([mockUpdatedVisitor]);
      
      // Mock credential revocation
      mockDb.returning.mockResolvedValueOnce([]);

      const result = await visitorService.checkOutVisitor(
        'visitor-123',
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(result.data.visitor.status).toBe('CHECKED_OUT');

      // Verify database calls
      expect(mockDb.update).toHaveBeenCalledWith(visitors);
      expect(mockDb.update).toHaveBeenCalledWith(visitorCredentials);
    });

    it('should fail if visitor is not checked in', async () => {
      const mockVisitor = {
        id: 'visitor-123',
        status: 'PENDING',
      };

      // Mock visitor lookup
      mockDb.limit.mockResolvedValueOnce([mockVisitor]);

      const result = await visitorService.checkOutVisitor(
        'visitor-123',
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_CHECKED_IN');
      expect(mockDb.update).not.toHaveBeenCalledWith(visitors);
    });
  });

  describe('searchVisitors', () => {
    it('should search visitors with filters', async () => {
      const mockVisitors = [
        {
          visitor: {
            id: 'visitor-1',
            firstName: 'John',
            lastName: 'Doe',
            status: 'CHECKED_IN',
          },
          host: {
            id: 'host-1',
            firstName: 'Host',
            lastName: 'User',
            email: 'host@example.com',
          },
        },
      ];

      const searchParams = {
        query: 'John',
        status: 'CHECKED_IN' as const,
        page: 1,
        limit: 20,
        sortBy: 'expectedArrival' as const,
        sortOrder: 'desc' as const,
      };

      // Mock count query
      mockDb.where.mockReturnValueOnce([{ id: 'visitor-1' }]);
      
      // Mock paginated results
      mockDb.offset.mockResolvedValueOnce(mockVisitors);

      const result = await visitorService.searchVisitors(
        searchParams,
        'org-123'
      );

      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(1);
      expect(result.meta?.total).toBe(1);
      expect(result.meta?.page).toBe(1);
    });
  });

  describe('getActiveVisitors', () => {
    it('should return all checked-in visitors', async () => {
      const mockActiveVisitors = [
        {
          visitor: {
            id: 'visitor-1',
            firstName: 'John',
            lastName: 'Doe',
            status: 'CHECKED_IN',
            actualArrival: new Date(),
          },
          host: {
            id: 'host-1',
            firstName: 'Host',
            lastName: 'User',
          },
        },
      ];

      mockDb.orderBy.mockResolvedValueOnce(mockActiveVisitors);

      const result = await visitorService.getActiveVisitors('org-123');

      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(1);
      expect(mockDb.where).toHaveBeenCalled();
    });
  });

  describe('getOverstayVisitors', () => {
    it('should return visitors who have overstayed', async () => {
      const now = new Date();
      const mockOverstayVisitors = [
        {
          visitor: {
            id: 'visitor-1',
            firstName: 'John',
            lastName: 'Doe',
            status: 'CHECKED_IN',
            expectedDeparture: new Date(now.getTime() - 3600000), // 1 hour ago
          },
          host: {
            id: 'host-1',
            firstName: 'Host',
            lastName: 'User',
          },
        },
      ];

      mockDb.orderBy.mockResolvedValueOnce(mockOverstayVisitors);

      const result = await visitorService.getOverstayVisitors('org-123');

      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(1);
      expect(result.data[0].overstayMinutes).toBeGreaterThan(0);
    });
  });
});