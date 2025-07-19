import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { 
  pluginReviewSchema,
  PluginType
} from '../types';
import { MarketplaceService } from '../services/marketplace.service';
import { z } from 'zod';

const marketplaceRouter = new Hono();

// Get service instances
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const marketplaceService = new MarketplaceService(prisma, redis);

// Public routes (no auth required for browsing)

// List marketplace plugins
marketplaceRouter.get('/', async (c) => {
  try {
    // Parse query parameters
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '20', 10);
    const category = c.req.query('category');
    const type = c.req.query('type') as PluginType | undefined;
    const search = c.req.query('search');
    const sort = c.req.query('sort') || 'popular';
    const verified = c.req.query('verified') === 'true';
    const featured = c.req.query('featured') === 'true';

    const response = await marketplaceService.listMarketplacePlugins({
      page,
      limit,
      category,
      type,
      search,
      sort: sort as 'popular' | 'recent' | 'rating' | 'name',
      verified,
      featured
    });

    return c.json(response);
  } catch (error) {
    logger.error('Failed to list marketplace plugins', { error });
    throw new HTTPException(500, { message: 'Failed to list marketplace plugins' });
  }
});

// Get marketplace plugin details
marketplaceRouter.get('/:pluginId', async (c) => {
  try {
    const pluginId = c.req.param('pluginId');

    const plugin = await marketplaceService.getMarketplacePlugin(pluginId);

    if (!plugin) {
      throw new HTTPException(404, { message: 'Plugin not found' });
    }

    return c.json(plugin);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get marketplace plugin', { error });
    throw new HTTPException(500, { message: 'Failed to get marketplace plugin' });
  }
});

// Get plugin reviews
marketplaceRouter.get('/:pluginId/reviews', async (c) => {
  try {
    const pluginId = c.req.param('pluginId');
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '10', 10);
    const sort = c.req.query('sort') || 'recent';

    const reviews = await marketplaceService.getPluginReviews(pluginId, {
      page,
      limit,
      sort: sort as 'recent' | 'helpful' | 'rating'
    });

    return c.json(reviews);
  } catch (error) {
    logger.error('Failed to get plugin reviews', { error });
    throw new HTTPException(500, { message: 'Failed to get plugin reviews' });
  }
});

// Get categories
marketplaceRouter.get('/categories/list', async (c) => {
  try {
    const categories = await marketplaceService.getCategories();
    return c.json(categories);
  } catch (error) {
    logger.error('Failed to get categories', { error });
    throw new HTTPException(500, { message: 'Failed to get categories' });
  }
});

// Get featured plugins
marketplaceRouter.get('/featured/list', async (c) => {
  try {
    const featured = await marketplaceService.getFeaturedPlugins();
    return c.json(featured);
  } catch (error) {
    logger.error('Failed to get featured plugins', { error });
    throw new HTTPException(500, { message: 'Failed to get featured plugins' });
  }
});

// Protected routes (auth required)
marketplaceRouter.use('*', authMiddleware);

// Install plugin from marketplace
marketplaceRouter.post('/:pluginId/install', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const pluginId = c.req.param('pluginId');
    const body = await c.req.json();

    const instance = await marketplaceService.installFromMarketplace(
      tenantId,
      userId,
      pluginId,
      {
        name: body.name,
        configuration: body.configuration || {}
      }
    );

    return c.json({
      success: true,
      instance,
      message: 'Plugin installed successfully'
    }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to install plugin from marketplace', { error });
    throw new HTTPException(500, { message: 'Failed to install plugin' });
  }
});

// Submit plugin review
marketplaceRouter.post('/:pluginId/review',
  zValidator('json', pluginReviewSchema.pick({
    rating: true,
    title: true,
    comment: true
  })),
  async (c) => {
    try {
      const userId = c.get('userId') as string;
      const pluginId = c.req.param('pluginId');
      const data = c.req.valid('json');

      const review = await marketplaceService.submitReview(
        pluginId,
        userId,
        data
      );

      return c.json(review, 201);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to submit plugin review', { error });
      if (error instanceof z.ZodError) {
        throw new HTTPException(400, { 
          message: 'Invalid review data',
          cause: error.errors 
        });
      }
      throw new HTTPException(500, { message: 'Failed to submit review' });
    }
  }
);

// Update plugin review
marketplaceRouter.put('/:pluginId/review',
  zValidator('json', pluginReviewSchema.pick({
    rating: true,
    title: true,
    comment: true
  }).partial()),
  async (c) => {
    try {
      const userId = c.get('userId') as string;
      const pluginId = c.req.param('pluginId');
      const data = c.req.valid('json');

      const review = await marketplaceService.updateReview(
        pluginId,
        userId,
        data
      );

      return c.json(review);
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      logger.error('Failed to update plugin review', { error });
      throw new HTTPException(500, { message: 'Failed to update review' });
    }
  }
);

// Delete plugin review
marketplaceRouter.delete('/:pluginId/review', async (c) => {
  try {
    const userId = c.get('userId') as string;
    const pluginId = c.req.param('pluginId');

    await marketplaceService.deleteReview(
      pluginId,
      userId
    );

    return c.json({ success: true });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to delete plugin review', { error });
    throw new HTTPException(500, { message: 'Failed to delete review' });
  }
});

// Mark review as helpful
marketplaceRouter.post('/reviews/:reviewId/helpful', async (c) => {
  try {
    const userId = c.get('userId') as string;
    const reviewId = c.req.param('reviewId');

    await marketplaceService.markReviewHelpful(
      reviewId,
      userId
    );

    return c.json({ success: true });
  } catch (error) {
    logger.error('Failed to mark review as helpful', { error });
    throw new HTTPException(500, { message: 'Failed to mark review as helpful' });
  }
});

// Get user's installed plugins from marketplace
marketplaceRouter.get('/installed/list', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const page = parseInt(c.req.query('page') || '1', 10);
    const limit = parseInt(c.req.query('limit') || '20', 10);

    const installed = await marketplaceService.getInstalledPlugins(
      tenantId,
      {
        page,
        limit
      }
    );

    return c.json(installed);
  } catch (error) {
    logger.error('Failed to get installed plugins', { error });
    throw new HTTPException(500, { message: 'Failed to get installed plugins' });
  }
});

// Check for plugin updates
marketplaceRouter.get('/updates/check', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;

    const updates = await marketplaceService.checkForUpdates(tenantId);

    return c.json(updates);
  } catch (error) {
    logger.error('Failed to check for updates', { error });
    throw new HTTPException(500, { message: 'Failed to check for updates' });
  }
});

// Update installed plugin
marketplaceRouter.post('/installed/:instanceId/update', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const instanceId = c.req.param('instanceId');

    const updated = await marketplaceService.updateInstalledPlugin(
      tenantId,
      userId,
      instanceId
    );

    return c.json({
      success: true,
      instance: updated,
      message: 'Plugin updated successfully'
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to update plugin', { error });
    throw new HTTPException(500, { message: 'Failed to update plugin' });
  }
});

// Get recommended plugins
marketplaceRouter.get('/recommendations/list', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const limit = parseInt(c.req.query('limit') || '10', 10);

    const recommendations = await marketplaceService.getRecommendations(
      tenantId,
      limit
    );

    return c.json(recommendations);
  } catch (error) {
    logger.error('Failed to get recommendations', { error });
    throw new HTTPException(500, { message: 'Failed to get recommendations' });
  }
});

export default marketplaceRouter;