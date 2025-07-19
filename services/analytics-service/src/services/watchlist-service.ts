import { BaseAnalyticsService, AnalyticsDependencies } from './base-analytics-service';

export class WatchlistService extends BaseAnalyticsService {
  private faceWatchlist: Set<string> = new Set();
  private licensePlateWatchlist: Set<string> = new Set();

  constructor(dependencies: AnalyticsDependencies) {
    super(dependencies);
    this.loadWatchlists();
  }

  private async loadWatchlists(): Promise<void> {
    try {
      // Load face watchlist from Redis
      const faceList = await this.redis.smembers('watchlist:faces');
      faceList.forEach(id => this.faceWatchlist.add(id));

      // Load license plate watchlist from Redis
      const plateList = await this.redis.smembers('watchlist:plates');
      plateList.forEach(plate => this.licensePlateWatchlist.add(plate.toUpperCase()));

      this.logger.info('Watchlists loaded', {
        faces: this.faceWatchlist.size,
        plates: this.licensePlateWatchlist.size
      });
    } catch (error) {
      this.logger.error('Failed to load watchlists', { error });
    }
  }

  async updateWatchlists(
    tenantId: string,
    type: 'face' | 'licensePlate',
    action: 'add' | 'remove',
    items: string[]
  ): Promise<void> {
    const redisKey = type === 'face' ? 'watchlist:faces' : 'watchlist:plates';
    const localSet = type === 'face' ? this.faceWatchlist : this.licensePlateWatchlist;

    try {
      if (action === 'add') {
        // Add to local set
        items.forEach(item => {
          const normalizedItem = type === 'licensePlate' ? item.toUpperCase() : item;
          localSet.add(normalizedItem);
        });

        // Add to Redis
        if (items.length > 0) {
          const normalizedItems = type === 'licensePlate' 
            ? items.map(i => i.toUpperCase()) 
            : items;
          await this.redis.sadd(redisKey, ...normalizedItems);
        }

        // Log additions
        await this.logWatchlistChange(tenantId, type, 'added', items);
      } else {
        // Remove from local set
        items.forEach(item => {
          const normalizedItem = type === 'licensePlate' ? item.toUpperCase() : item;
          localSet.delete(normalizedItem);
        });

        // Remove from Redis
        if (items.length > 0) {
          const normalizedItems = type === 'licensePlate' 
            ? items.map(i => i.toUpperCase()) 
            : items;
          await this.redis.srem(redisKey, ...normalizedItems);
        }

        // Log removals
        await this.logWatchlistChange(tenantId, type, 'removed', items);
      }

      // Broadcast watchlist update
      await this.broadcastUpdate('watchlist-updated', {
        tenantId,
        type,
        action,
        itemsCount: items.length,
        totalCount: localSet.size
      });

      this.logger.info('Watchlist updated', {
        tenantId,
        type,
        action,
        itemsCount: items.length,
        totalCount: localSet.size
      });
    } catch (error) {
      this.logger.error('Failed to update watchlist', { 
        error, 
        tenantId, 
        type, 
        action 
      });
      throw error;
    }
  }

  checkFaceWatchlist(personId: string): boolean {
    return this.faceWatchlist.has(personId);
  }

  checkLicensePlateWatchlist(plateNumber: string): boolean {
    return this.licensePlateWatchlist.has(plateNumber.toUpperCase());
  }

  async getWatchlistStats(tenantId: string): Promise<any> {
    const [faceMatches, plateMatches] = await Promise.all([
      this.getRecentWatchlistMatches(tenantId, 'face', 24),
      this.getRecentWatchlistMatches(tenantId, 'licensePlate', 24)
    ]);

    return {
      faces: {
        total: this.faceWatchlist.size,
        recentMatches: faceMatches.length,
        items: Array.from(this.faceWatchlist).slice(0, 100) // First 100
      },
      licensePlates: {
        total: this.licensePlateWatchlist.size,
        recentMatches: plateMatches.length,
        items: Array.from(this.licensePlateWatchlist).slice(0, 100) // First 100
      },
      lastUpdated: await this.redis.get('watchlist:lastUpdated') || null
    };
  }

  private async logWatchlistChange(
    tenantId: string,
    type: 'face' | 'licensePlate',
    action: string,
    items: string[]
  ): Promise<void> {
    await this.storeInOpenSearch(`${this.config.opensearchIndex}-watchlist-audit`, {
      tenantId,
      type,
      action,
      items,
      itemCount: items.length,
      timestamp: new Date().toISOString(),
      userId: 'system' // Would get from context in production
    });

    // Update last modified timestamp
    await this.redis.set('watchlist:lastUpdated', new Date().toISOString());
  }

  private async getRecentWatchlistMatches(
    tenantId: string,
    type: 'face' | 'licensePlate',
    hours: number
  ): Promise<any[]> {
    const index = type === 'face' 
      ? `${this.config.opensearchIndex}-video` 
      : `${this.config.opensearchIndex}-video`;

    const query = {
      query: {
        bool: {
          must: [
            { term: { tenantId } },
            { term: { isWatchlisted: true } },
            { term: { type: type === 'face' ? 'face_recognition' : 'license_plate' } },
            {
              range: {
                timestamp: {
                  gte: new Date(Date.now() - hours * 60 * 60 * 1000).toISOString()
                }
              }
            }
          ]
        }
      },
      size: 100,
      sort: [{ timestamp: { order: 'desc' } }]
    };

    return await this.queryOpenSearch(index, query);
  }

  async syncWatchlistsFromDatabase(tenantId: string): Promise<void> {
    try {
      // Sync face watchlist from database
      const watchlistedPeople = await this.prisma.person.findMany({
        where: {
          tenantId,
          isWatchlisted: true
        },
        select: { id: true }
      });

      const faceIds = watchlistedPeople.map(p => p.id);
      
      // Clear and repopulate Redis
      await this.redis.del('watchlist:faces');
      if (faceIds.length > 0) {
        await this.redis.sadd('watchlist:faces', ...faceIds);
      }

      // Update local set
      this.faceWatchlist.clear();
      faceIds.forEach(id => this.faceWatchlist.add(id));

      // Sync license plate watchlist (would need a vehicle/plate table)
      // For now, preserve existing Redis data

      this.logger.info('Watchlists synced from database', {
        tenantId,
        faces: faceIds.length
      });
    } catch (error) {
      this.logger.error('Failed to sync watchlists', { error, tenantId });
      throw error;
    }
  }
}