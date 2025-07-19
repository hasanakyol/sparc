import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import { WatchlistService } from '../../../services/watchlist.service';
import * as db from '../../../db';
import { visitorWatchlist } from '@sparc/database/schemas/visitor-management';

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

describe('WatchlistService', () => {
  let watchlistService: WatchlistService;
  let mockDb: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create mock database methods
    mockDb = {
      select: jest.fn().mockReturnThis(),
      from: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      insert: jest.fn().mockReturnThis(),
      values: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      returning: jest.fn().mockResolvedValue([]),
    };

    // Mock getDb to return our mock database
    (db.getDb as jest.Mock).mockReturnValue(mockDb);

    watchlistService = new WatchlistService();
  });

  describe('checkWatchlist', () => {
    const mockCheckData = {
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      idNumber: 'ID123456',
      company: 'Test Corp',
    };

    it('should return true when visitor matches watchlist entry', async () => {
      const mockWatchlistEntry = {
        id: 'watchlist-123',
        organizationId: 'org-123',
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        status: 'ACTIVE',
        reason: 'SECURITY_THREAT',
        description: 'Previous security incident',
        createdAt: new Date(),
      };

      // Mock database query
      mockDb.where.mockResolvedValueOnce([mockWatchlistEntry]);

      const result = await watchlistService.checkWatchlist(mockCheckData, 'org-123');

      expect(result.success).toBe(true);
      expect(result.data.isOnWatchlist).toBe(true);
      expect(result.data.matches).toHaveLength(1);
      expect(result.data.matches[0].reason).toBe('SECURITY_THREAT');
    });

    it('should return false when no matches found', async () => {
      // Mock empty result
      mockDb.where.mockResolvedValueOnce([]);
      
      // Mock for alias check
      mockDb.where.mockResolvedValueOnce([]);

      const result = await watchlistService.checkWatchlist(mockCheckData, 'org-123');

      expect(result.success).toBe(true);
      expect(result.data.isOnWatchlist).toBe(false);
      expect(result.data.matches).toHaveLength(0);
    });

    it('should match by alias', async () => {
      // First query returns no direct matches
      mockDb.where.mockResolvedValueOnce([]);
      
      // Second query for alias check returns entries
      const mockAliasEntry = {
        id: 'watchlist-456',
        firstName: 'Jonathan',
        lastName: 'Smith',
        aliases: ['John Doe', 'J. Doe'],
        status: 'ACTIVE',
        reason: 'BANNED',
        description: 'Using alias',
        createdAt: new Date(),
      };
      
      mockDb.where.mockResolvedValueOnce([mockAliasEntry]);

      const result = await watchlistService.checkWatchlist(mockCheckData, 'org-123');

      expect(result.success).toBe(true);
      expect(result.data.isOnWatchlist).toBe(true);
      expect(result.data.matches).toHaveLength(1);
    });

    it('should only match active entries', async () => {
      const mockInactiveEntry = {
        id: 'watchlist-789',
        firstName: 'John',
        lastName: 'Doe',
        status: 'INACTIVE',
        reason: 'PREVIOUS_INCIDENT',
        description: 'Old incident - resolved',
      };

      // Query should filter out inactive entries
      mockDb.where.mockResolvedValueOnce([]);
      mockDb.where.mockResolvedValueOnce([]);

      const result = await watchlistService.checkWatchlist(mockCheckData, 'org-123');

      expect(result.success).toBe(false);
      expect(result.data.isOnWatchlist).toBe(false);
    });

    it('should handle database errors gracefully', async () => {
      // Mock database error
      mockDb.where.mockRejectedValueOnce(new Error('Database connection error'));

      const result = await watchlistService.checkWatchlist(mockCheckData, 'org-123');

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('WATCHLIST_CHECK_FAILED');
    });
  });

  describe('addToWatchlist', () => {
    const mockEntryData = {
      firstName: 'Bad',
      lastName: 'Actor',
      email: 'bad.actor@example.com',
      phone: '+1234567890',
      idNumber: 'ID999999',
      company: 'Suspicious Corp',
      reason: 'SECURITY_THREAT' as const,
      description: 'Caught attempting unauthorized access',
      aliases: ['B. Actor', 'BadGuy'],
    };

    it('should add new entry to watchlist', async () => {
      const mockCreatedEntry = {
        id: 'watchlist-new-123',
        ...mockEntryData,
        organizationId: 'org-123',
        status: 'ACTIVE',
        addedBy: 'user-123',
        createdAt: new Date(),
      };

      // Mock check for existing entry
      mockDb.limit.mockResolvedValueOnce([]);
      
      // Mock insert
      mockDb.returning.mockResolvedValueOnce([mockCreatedEntry]);

      const result = await watchlistService.addToWatchlist(
        mockEntryData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(result.data.entry).toEqual(mockCreatedEntry);
      expect(mockDb.insert).toHaveBeenCalledWith(visitorWatchlist);
    });

    it('should reject duplicate entries', async () => {
      // Mock existing entry found
      mockDb.limit.mockResolvedValueOnce([{ id: 'existing-entry' }]);

      const result = await watchlistService.addToWatchlist(
        mockEntryData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ENTRY_EXISTS');
      expect(mockDb.insert).not.toHaveBeenCalled();
    });

    it('should handle effectiveUntil date', async () => {
      const entryWithExpiry = {
        ...mockEntryData,
        effectiveUntil: '2024-12-31T23:59:59Z',
      };

      // Mock no existing entry
      mockDb.limit.mockResolvedValueOnce([]);
      
      // Mock successful insert
      mockDb.returning.mockResolvedValueOnce([{
        ...entryWithExpiry,
        id: 'watchlist-exp-123',
        effectiveUntil: new Date('2024-12-31T23:59:59Z'),
      }]);

      const result = await watchlistService.addToWatchlist(
        entryWithExpiry,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(mockDb.values).toHaveBeenCalledWith(
        expect.objectContaining({
          effectiveUntil: expect.any(Date),
        })
      );
    });
  });

  describe('updateWatchlistEntry', () => {
    it('should update existing watchlist entry', async () => {
      const mockExistingEntry = {
        id: 'watchlist-123',
        firstName: 'John',
        lastName: 'Doe',
        organizationId: 'org-123',
      };

      const updateData = {
        description: 'Updated description',
        reason: 'INVESTIGATION' as const,
      };

      const mockUpdatedEntry = {
        ...mockExistingEntry,
        ...updateData,
        updatedAt: new Date(),
      };

      // Mock find existing
      mockDb.limit.mockResolvedValueOnce([mockExistingEntry]);
      
      // Mock update
      mockDb.returning.mockResolvedValueOnce([mockUpdatedEntry]);

      const result = await watchlistService.updateWatchlistEntry(
        'watchlist-123',
        updateData,
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(result.data.entry).toEqual(mockUpdatedEntry);
      expect(mockDb.update).toHaveBeenCalledWith(visitorWatchlist);
    });

    it('should fail if entry not found', async () => {
      // Mock no entry found
      mockDb.limit.mockResolvedValueOnce([]);

      const result = await watchlistService.updateWatchlistEntry(
        'non-existent',
        { description: 'Updated' },
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ENTRY_NOT_FOUND');
      expect(mockDb.update).not.toHaveBeenCalled();
    });
  });

  describe('removeFromWatchlist', () => {
    it('should soft delete watchlist entry', async () => {
      const mockExistingEntry = {
        id: 'watchlist-123',
        status: 'ACTIVE',
        organizationId: 'org-123',
      };

      const mockUpdatedEntry = {
        ...mockExistingEntry,
        status: 'INACTIVE',
        reviewedBy: 'user-123',
        reviewedAt: new Date(),
        updatedAt: new Date(),
      };

      // Mock find existing
      mockDb.limit.mockResolvedValueOnce([mockExistingEntry]);
      
      // Mock update
      mockDb.returning.mockResolvedValueOnce([mockUpdatedEntry]);

      const result = await watchlistService.removeFromWatchlist(
        'watchlist-123',
        'org-123',
        'user-123'
      );

      expect(result.success).toBe(true);
      expect(result.data.entry.status).toBe('INACTIVE');
      expect(mockDb.set).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'INACTIVE',
          reviewedBy: 'user-123',
        })
      );
    });
  });

  describe('searchWatchlist', () => {
    it('should search watchlist entries', async () => {
      const mockEntries = [
        {
          id: 'watchlist-1',
          firstName: 'John',
          lastName: 'Doe',
          reason: 'SECURITY_THREAT',
        },
        {
          id: 'watchlist-2',
          firstName: 'Jane',
          lastName: 'Doe',
          reason: 'BANNED',
        },
      ];

      mockDb.orderBy.mockResolvedValueOnce(mockEntries);

      const result = await watchlistService.searchWatchlist('Doe', 'org-123', false);

      expect(result.success).toBe(true);
      expect(result.data).toEqual(mockEntries);
    });

    it('should include inactive entries when specified', async () => {
      const mockEntries = [
        { id: 'watchlist-1', status: 'ACTIVE' },
        { id: 'watchlist-2', status: 'INACTIVE' },
      ];

      mockDb.orderBy.mockResolvedValueOnce(mockEntries);

      const result = await watchlistService.searchWatchlist('', 'org-123', true);

      expect(result.success).toBe(true);
      expect(result.data).toHaveLength(2);
    });
  });

  describe('getWatchlistStats', () => {
    it('should return watchlist statistics', async () => {
      // Mock count queries
      mockDb.where.mockResolvedValueOnce([{ id: '1' }, { id: '2' }]); // Active: 2
      mockDb.where.mockResolvedValueOnce([{ id: '3' }]); // Inactive: 1
      mockDb.where.mockResolvedValueOnce([]); // Pending review: 0
      
      // Mock entries for reason distribution
      mockDb.where.mockResolvedValueOnce([
        { reason: 'SECURITY_THREAT' },
        { reason: 'SECURITY_THREAT' },
        { reason: 'BANNED' },
      ]);

      const result = await watchlistService.getWatchlistStats('org-123');

      expect(result.success).toBe(true);
      expect(result.data.active).toBe(2);
      expect(result.data.inactive).toBe(1);
      expect(result.data.pendingReview).toBe(0);
      expect(result.data.total).toBe(3);
      expect(result.data.byReason).toEqual({
        'SECURITY_THREAT': 2,
        'BANNED': 1,
      });
    });
  });
});