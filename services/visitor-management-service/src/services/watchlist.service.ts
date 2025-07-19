import { and, eq, or, like, isNull, gte } from 'drizzle-orm';
import { getDb } from '../db';
import { visitorWatchlist } from '@sparc/database/schemas/visitor-management';
import { logger } from '@sparc/shared';
import type { WatchlistCheck, WatchlistEntry, ServiceResponse } from '../types';

export class WatchlistService {
  private db = getDb();

  async checkWatchlist(
    data: WatchlistCheck,
    organizationId: string
  ): Promise<ServiceResponse<{ isOnWatchlist: boolean; matches: any[] }>> {
    try {
      const conditions = [
        eq(visitorWatchlist.organizationId, organizationId),
        eq(visitorWatchlist.status, 'ACTIVE'),
        or(
          isNull(visitorWatchlist.effectiveUntil),
          gte(visitorWatchlist.effectiveUntil, new Date())
        )!,
      ];

      // Build search conditions
      const searchConditions = [];

      // Check name match
      searchConditions.push(
        and(
          eq(visitorWatchlist.firstName, data.firstName),
          eq(visitorWatchlist.lastName, data.lastName)
        )!
      );

      // Check email match if provided
      if (data.email) {
        searchConditions.push(eq(visitorWatchlist.email, data.email));
      }

      // Check ID number match if provided
      if (data.idNumber) {
        searchConditions.push(eq(visitorWatchlist.idNumber, data.idNumber));
      }

      // Check company match if provided
      if (data.company) {
        searchConditions.push(eq(visitorWatchlist.company, data.company));
      }

      conditions.push(or(...searchConditions)!);

      const matches = await this.db
        .select()
        .from(visitorWatchlist)
        .where(and(...conditions));

      // Check aliases
      if (matches.length === 0) {
        // Search in aliases
        const aliasMatches = await this.db
          .select()
          .from(visitorWatchlist)
          .where(and(
            eq(visitorWatchlist.organizationId, organizationId),
            eq(visitorWatchlist.status, 'ACTIVE'),
            or(
              isNull(visitorWatchlist.effectiveUntil),
              gte(visitorWatchlist.effectiveUntil, new Date())
            )!
          ));

        // Check if the visitor name matches any aliases
        const fullName = `${data.firstName} ${data.lastName}`.toLowerCase();
        for (const entry of aliasMatches) {
          if (entry.aliases && Array.isArray(entry.aliases)) {
            for (const alias of entry.aliases) {
              if (alias.toLowerCase() === fullName) {
                matches.push(entry);
                break;
              }
            }
          }
        }
      }

      const isOnWatchlist = matches.length > 0;

      if (isOnWatchlist) {
        logger.warn('Visitor matched watchlist', {
          organizationId,
          visitorData: data,
          matchCount: matches.length,
        });
      }

      return {
        success: true,
        data: {
          isOnWatchlist,
          matches: matches.map(m => ({
            id: m.id,
            reason: m.reason,
            description: m.description,
            addedAt: m.createdAt,
          })),
        },
      };
    } catch (error) {
      logger.error('Failed to check watchlist', { error, data });
      return {
        success: false,
        error: {
          code: 'WATCHLIST_CHECK_FAILED',
          message: 'Failed to check watchlist',
        },
      };
    }
  }

  async addToWatchlist(
    data: WatchlistEntry,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse> {
    try {
      // Check if entry already exists
      const existing = await this.db
        .select()
        .from(visitorWatchlist)
        .where(and(
          eq(visitorWatchlist.organizationId, organizationId),
          eq(visitorWatchlist.firstName, data.firstName),
          eq(visitorWatchlist.lastName, data.lastName),
          eq(visitorWatchlist.status, 'ACTIVE')
        ))
        .limit(1);

      if (existing.length > 0) {
        return {
          success: false,
          error: {
            code: 'ENTRY_EXISTS',
            message: 'This person is already on the watchlist',
          },
        };
      }

      const [entry] = await this.db
        .insert(visitorWatchlist)
        .values({
          ...data,
          organizationId,
          status: 'ACTIVE',
          addedBy: userId,
          effectiveUntil: data.effectiveUntil ? new Date(data.effectiveUntil) : undefined,
        })
        .returning();

      logger.info('Added to watchlist', {
        entryId: entry.id,
        organizationId,
        addedBy: userId,
      });

      return {
        success: true,
        data: { entry },
      };
    } catch (error) {
      logger.error('Failed to add to watchlist', { error, data });
      return {
        success: false,
        error: {
          code: 'ADD_WATCHLIST_FAILED',
          message: 'Failed to add to watchlist',
        },
      };
    }
  }

  async updateWatchlistEntry(
    entryId: string,
    data: Partial<WatchlistEntry>,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse> {
    try {
      const [existing] = await this.db
        .select()
        .from(visitorWatchlist)
        .where(and(
          eq(visitorWatchlist.id, entryId),
          eq(visitorWatchlist.organizationId, organizationId)
        ))
        .limit(1);

      if (!existing) {
        return {
          success: false,
          error: {
            code: 'ENTRY_NOT_FOUND',
            message: 'Watchlist entry not found',
          },
        };
      }

      const [updated] = await this.db
        .update(visitorWatchlist)
        .set({
          ...data,
          updatedAt: new Date(),
        })
        .where(eq(visitorWatchlist.id, entryId))
        .returning();

      logger.info('Updated watchlist entry', {
        entryId,
        organizationId,
        updatedBy: userId,
      });

      return {
        success: true,
        data: { entry: updated },
      };
    } catch (error) {
      logger.error('Failed to update watchlist entry', { error, entryId, data });
      return {
        success: false,
        error: {
          code: 'UPDATE_WATCHLIST_FAILED',
          message: 'Failed to update watchlist entry',
        },
      };
    }
  }

  async removeFromWatchlist(
    entryId: string,
    organizationId: string,
    userId: string
  ): Promise<ServiceResponse> {
    try {
      const [existing] = await this.db
        .select()
        .from(visitorWatchlist)
        .where(and(
          eq(visitorWatchlist.id, entryId),
          eq(visitorWatchlist.organizationId, organizationId)
        ))
        .limit(1);

      if (!existing) {
        return {
          success: false,
          error: {
            code: 'ENTRY_NOT_FOUND',
            message: 'Watchlist entry not found',
          },
        };
      }

      // Soft delete by setting status to INACTIVE
      const [updated] = await this.db
        .update(visitorWatchlist)
        .set({
          status: 'INACTIVE',
          reviewedBy: userId,
          reviewedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(visitorWatchlist.id, entryId))
        .returning();

      logger.info('Removed from watchlist', {
        entryId,
        organizationId,
        removedBy: userId,
      });

      return {
        success: true,
        data: { entry: updated },
      };
    } catch (error) {
      logger.error('Failed to remove from watchlist', { error, entryId });
      return {
        success: false,
        error: {
          code: 'REMOVE_WATCHLIST_FAILED',
          message: 'Failed to remove from watchlist',
        },
      };
    }
  }

  async searchWatchlist(
    query: string,
    organizationId: string,
    includeInactive = false
  ): Promise<ServiceResponse> {
    try {
      const conditions = [eq(visitorWatchlist.organizationId, organizationId)];

      if (!includeInactive) {
        conditions.push(eq(visitorWatchlist.status, 'ACTIVE'));
      }

      if (query) {
        conditions.push(
          or(
            like(visitorWatchlist.firstName, `%${query}%`),
            like(visitorWatchlist.lastName, `%${query}%`),
            like(visitorWatchlist.email, `%${query}%`),
            like(visitorWatchlist.company, `%${query}%`),
            like(visitorWatchlist.idNumber, `%${query}%`),
            like(visitorWatchlist.description, `%${query}%`)
          )!
        );
      }

      const entries = await this.db
        .select()
        .from(visitorWatchlist)
        .where(and(...conditions))
        .orderBy(visitorWatchlist.createdAt);

      return {
        success: true,
        data: entries,
      };
    } catch (error) {
      logger.error('Failed to search watchlist', { error, query });
      return {
        success: false,
        error: {
          code: 'SEARCH_WATCHLIST_FAILED',
          message: 'Failed to search watchlist',
        },
      };
    }
  }

  async getWatchlistStats(organizationId: string): Promise<ServiceResponse> {
    try {
      const [
        activeCount,
        inactiveCount,
        pendingReviewCount,
        byReason,
      ] = await Promise.all([
        // Active entries
        this.db
          .select({ count: visitorWatchlist.id })
          .from(visitorWatchlist)
          .where(and(
            eq(visitorWatchlist.organizationId, organizationId),
            eq(visitorWatchlist.status, 'ACTIVE')
          )),
        
        // Inactive entries
        this.db
          .select({ count: visitorWatchlist.id })
          .from(visitorWatchlist)
          .where(and(
            eq(visitorWatchlist.organizationId, organizationId),
            eq(visitorWatchlist.status, 'INACTIVE')
          )),
        
        // Pending review
        this.db
          .select({ count: visitorWatchlist.id })
          .from(visitorWatchlist)
          .where(and(
            eq(visitorWatchlist.organizationId, organizationId),
            eq(visitorWatchlist.status, 'PENDING_REVIEW')
          )),
        
        // By reason (simplified - would need GROUP BY in real implementation)
        this.db
          .select()
          .from(visitorWatchlist)
          .where(and(
            eq(visitorWatchlist.organizationId, organizationId),
            eq(visitorWatchlist.status, 'ACTIVE')
          )),
      ]);

      // Calculate reason distribution
      const reasonCounts: Record<string, number> = {};
      for (const entry of byReason) {
        reasonCounts[entry.reason] = (reasonCounts[entry.reason] || 0) + 1;
      }

      return {
        success: true,
        data: {
          active: activeCount.length,
          inactive: inactiveCount.length,
          pendingReview: pendingReviewCount.length,
          total: activeCount.length + inactiveCount.length + pendingReviewCount.length,
          byReason: reasonCounts,
        },
      };
    } catch (error) {
      logger.error('Failed to get watchlist stats', { error, organizationId });
      return {
        success: false,
        error: {
          code: 'STATS_FAILED',
          message: 'Failed to get watchlist statistics',
        },
      };
    }
  }
}