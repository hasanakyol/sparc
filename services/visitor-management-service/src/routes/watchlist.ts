import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { WatchlistService } from '../services/watchlist.service';
import { 
  WatchlistCheckSchema,
  WatchlistEntrySchema,
} from '../types';
import { logger } from '@sparc/shared';
import { z } from 'zod';

const watchlistRouter = new Hono();
const watchlistService = new WatchlistService();

// Check if a visitor is on the watchlist
watchlistRouter.post(
  '/check',
  zValidator('json', WatchlistCheckSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const data = c.req.valid('json');

    const result = await watchlistService.checkWatchlist(data, organizationId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Watchlist check failed' });
    }

    // Log watchlist check
    logger.info('Watchlist check performed', {
      organizationId,
      checkedBy: c.get('userId'),
      matched: result.data.isOnWatchlist,
      matchCount: result.data.matches.length,
    });

    return c.json(result);
  }
);

// Add entry to watchlist
watchlistRouter.post(
  '/',
  zValidator('json', WatchlistEntrySchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const data = c.req.valid('json');

    const result = await watchlistService.addToWatchlist(data, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Failed to add to watchlist' });
    }

    logger.info('Added to watchlist', {
      entryId: result.data.entry.id,
      organizationId,
      addedBy: userId,
    });

    return c.json(result);
  }
);

// Update watchlist entry
watchlistRouter.put(
  '/:id',
  zValidator('json', WatchlistEntrySchema.partial()),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const entryId = c.req.param('id');
    const data = c.req.valid('json');

    const result = await watchlistService.updateWatchlistEntry(entryId, data, organizationId, userId);
    
    if (!result.success) {
      throw new HTTPException(400, { message: result.error?.message || 'Failed to update watchlist entry' });
    }

    return c.json(result);
  }
);

// Remove from watchlist (soft delete)
watchlistRouter.delete('/:id', async (c) => {
  const organizationId = c.get('tenantId');
  const userId = c.get('userId');
  const entryId = c.req.param('id');

  const result = await watchlistService.removeFromWatchlist(entryId, organizationId, userId);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Failed to remove from watchlist' });
  }

  logger.info('Removed from watchlist', {
    entryId,
    organizationId,
    removedBy: userId,
  });

  return c.json(result);
});

// Search watchlist
watchlistRouter.get('/', async (c) => {
  const organizationId = c.get('tenantId');
  const query = c.req.query('q') || '';
  const includeInactive = c.req.query('includeInactive') === 'true';

  const result = await watchlistService.searchWatchlist(query, organizationId, includeInactive);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Search failed' });
  }

  return c.json(result);
});

// Get watchlist statistics
watchlistRouter.get('/stats', async (c) => {
  const organizationId = c.get('tenantId');

  const result = await watchlistService.getWatchlistStats(organizationId);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Failed to get statistics' });
  }

  return c.json(result);
});

// Bulk check multiple visitors
const BulkCheckSchema = z.object({
  visitors: z.array(WatchlistCheckSchema),
});

watchlistRouter.post(
  '/bulk-check',
  zValidator('json', BulkCheckSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const { visitors } = c.req.valid('json');

    const results = [];
    
    for (const visitor of visitors) {
      const result = await watchlistService.checkWatchlist(visitor, organizationId);
      results.push({
        visitor,
        isOnWatchlist: result.success ? result.data.isOnWatchlist : false,
        matches: result.success ? result.data.matches : [],
      });
    }

    logger.info('Bulk watchlist check performed', {
      organizationId,
      checkedBy: c.get('userId'),
      totalChecked: visitors.length,
      matchesFound: results.filter(r => r.isOnWatchlist).length,
    });

    return c.json({
      success: true,
      data: results,
    });
  }
);

// Import watchlist entries from external source
const ImportSchema = z.object({
  entries: z.array(WatchlistEntrySchema),
  source: z.string(),
});

watchlistRouter.post(
  '/import',
  zValidator('json', ImportSchema),
  async (c) => {
    const organizationId = c.get('tenantId');
    const userId = c.get('userId');
    const { entries, source } = c.req.valid('json');

    const results = {
      imported: [],
      failed: [],
    };

    for (const entry of entries) {
      const result = await watchlistService.addToWatchlist(
        { ...entry, sourceSystem: source },
        organizationId,
        userId
      );
      
      if (result.success) {
        results.imported.push(result.data.entry);
      } else {
        results.failed.push({
          entry,
          error: result.error,
        });
      }
    }

    logger.info('Watchlist import completed', {
      organizationId,
      importedBy: userId,
      source,
      successCount: results.imported.length,
      failureCount: results.failed.length,
    });

    return c.json({
      success: results.failed.length === 0,
      data: results,
    });
  }
);

// Export watchlist
watchlistRouter.get('/export', async (c) => {
  const organizationId = c.get('tenantId');
  const format = c.req.query('format') || 'json';
  const includeInactive = c.req.query('includeInactive') === 'true';

  const result = await watchlistService.searchWatchlist('', organizationId, includeInactive);
  
  if (!result.success) {
    throw new HTTPException(400, { message: result.error?.message || 'Export failed' });
  }

  if (format === 'csv') {
    // Convert to CSV
    const csv = [
      'First Name,Last Name,Email,Phone,Company,ID Number,Reason,Description,Status,Added Date',
      ...result.data.map(entry => [
        entry.firstName,
        entry.lastName,
        entry.email || '',
        entry.phone || '',
        entry.company || '',
        entry.idNumber || '',
        entry.reason,
        entry.description,
        entry.status,
        new Date(entry.createdAt).toISOString(),
      ].join(','))
    ].join('\n');

    c.header('Content-Type', 'text/csv');
    c.header('Content-Disposition', 'attachment; filename="watchlist.csv"');
    return c.text(csv);
  }

  // Default to JSON
  c.header('Content-Type', 'application/json');
  c.header('Content-Disposition', 'attachment; filename="watchlist.json"');
  return c.json(result.data);
});

export default watchlistRouter;