import { db } from '@sparc/database';
import { 
  tenants, 
  organizations, 
  sites, 
  buildings, 
  floors, 
  zones,
  Tenant,
  Organization,
  Site,
  Building,
  Floor,
  Zone
} from '@sparc/database/schemas/tenant';
import { eq, and, ilike, or, sql, desc, asc } from 'drizzle-orm';
import type { 
  TenantWithRelations, 
  OrganizationWithRelations,
  SiteWithRelations,
  BuildingWithRelations,
  FloorWithRelations,
  ZoneWithRelations,
  PaginatedResponse,
  ResourceUsage
} from '@sparc/shared/src/types/tenant';
import { HTTPException } from 'hono/http-exception';
import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';

export class TenantService {
  constructor(private redis: Redis) {}

  // Tenant operations
  async getTenants(params: {
    page: number;
    limit: number;
    search?: string;
    status?: string;
    plan?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
    includeStats?: boolean;
  }): Promise<PaginatedResponse<TenantWithRelations>> {
    const { page, limit, search, status, plan, sortBy, sortOrder = 'desc', includeStats } = params;
    const offset = (page - 1) * limit;

    // Build where conditions
    const whereConditions = [];
    if (search) {
      whereConditions.push(
        or(
          ilike(tenants.name, `%${search}%`),
          ilike(tenants.domain, `%${search}%`),
          ilike(tenants.contactEmail, `%${search}%`)
        )
      );
    }
    if (status) {
      whereConditions.push(eq(tenants.status, status as any));
    }
    if (plan) {
      whereConditions.push(eq(tenants.plan, plan as any));
    }

    // Build order by
    const orderByColumn = sortBy ? tenants[sortBy as keyof typeof tenants] : tenants.createdAt;
    const orderByDirection = sortOrder === 'asc' ? asc : desc;

    // Execute queries
    const [results, totalCount] = await Promise.all([
      db
        .select()
        .from(tenants)
        .where(whereConditions.length > 0 ? and(...whereConditions) : undefined)
        .limit(limit)
        .offset(offset)
        .orderBy(orderByDirection(orderByColumn)),
      db
        .select({ count: sql<number>`count(*)` })
        .from(tenants)
        .where(whereConditions.length > 0 ? and(...whereConditions) : undefined)
    ]);

    // Add stats if requested
    let tenantsWithStats: TenantWithRelations[] = results;
    if (includeStats) {
      tenantsWithStats = await Promise.all(
        results.map(async (tenant) => {
          const stats = await this.getTenantStats(tenant.id);
          return { ...tenant, stats };
        })
      );
    }

    return {
      data: tenantsWithStats,
      pagination: {
        page,
        limit,
        total: Number(totalCount[0].count),
        totalPages: Math.ceil(Number(totalCount[0].count) / limit)
      }
    };
  }

  async getTenantById(id: string, includeRelations = false): Promise<TenantWithRelations | null> {
    const cacheKey = `tenant:${id}:${includeRelations}`;
    
    // Try cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      await this.redis.incr('metrics:tenant:cache_hits');
      return JSON.parse(cached);
    }
    
    await this.redis.incr('metrics:tenant:cache_misses');

    const tenant = await db.query.tenants.findFirst({
      where: eq(tenants.id, id),
      with: includeRelations ? {
        organizations: {
          with: {
            sites: {
              with: {
                buildings: {
                  with: {
                    floors: {
                      with: {
                        zones: true
                      }
                    }
                  }
                }
              }
            }
          }
        }
      } : undefined
    });

    if (!tenant) {
      return null;
    }

    // Add stats
    const stats = await this.getTenantStats(id);
    const result = { ...tenant, stats };

    // Cache the result
    await this.redis.setex(cacheKey, 300, JSON.stringify(result));

    return result;
  }

  async createTenant(data: any, createdBy?: string): Promise<Tenant> {
    // Check if domain already exists
    const existing = await db.query.tenants.findFirst({
      where: eq(tenants.domain, data.domain)
    });

    if (existing) {
      throw new HTTPException(409, { message: 'Tenant with this domain already exists' });
    }

    const [tenant] = await db
      .insert(tenants)
      .values({
        ...data,
        id: uuidv4(),
        createdBy,
        createdAt: new Date(),
        updatedAt: new Date()
      })
      .returning();

    // Invalidate cache
    await this.invalidateTenantCache();

    return tenant;
  }

  async updateTenant(id: string, data: any, updatedBy?: string): Promise<Tenant> {
    // Check if tenant exists
    const existing = await this.getTenantById(id);
    if (!existing) {
      throw new HTTPException(404, { message: 'Tenant not found' });
    }

    // Check domain uniqueness if domain is being updated
    if (data.domain && data.domain !== existing.domain) {
      const domainExists = await db.query.tenants.findFirst({
        where: eq(tenants.domain, data.domain)
      });

      if (domainExists) {
        throw new HTTPException(409, { message: 'Tenant with this domain already exists' });
      }
    }

    const [updated] = await db
      .update(tenants)
      .set({
        ...data,
        updatedBy,
        updatedAt: new Date()
      })
      .where(eq(tenants.id, id))
      .returning();

    // Invalidate cache
    await this.invalidateTenantCache(id);

    return updated;
  }

  async deleteTenant(id: string): Promise<void> {
    // Check if tenant has any organizations
    const orgCount = await db
      .select({ count: sql<number>`count(*)` })
      .from(organizations)
      .where(eq(organizations.tenantId, id));

    if (Number(orgCount[0].count) > 0) {
      throw new HTTPException(409, { 
        message: 'Cannot delete tenant with existing organizations. Please remove all associated data first.' 
      });
    }

    await db.delete(tenants).where(eq(tenants.id, id));

    // Invalidate cache
    await this.invalidateTenantCache(id);
  }

  async getTenantStats(tenantId: string): Promise<any> {
    const cacheKey = `tenant:stats:${tenantId}`;
    
    // Try cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get counts
    const [orgCount, siteCount, buildingCount, floorCount, zoneCount] = await Promise.all([
      db.select({ count: sql<number>`count(*)` }).from(organizations).where(eq(organizations.tenantId, tenantId)),
      db.select({ count: sql<number>`count(*)` }).from(sites).where(eq(sites.tenantId, tenantId)),
      db.select({ count: sql<number>`count(*)` }).from(buildings).where(eq(buildings.tenantId, tenantId)),
      db.select({ count: sql<number>`count(*)` }).from(floors).where(eq(floors.tenantId, tenantId)),
      db.select({ count: sql<number>`count(*)` }).from(zones).where(eq(zones.tenantId, tenantId))
    ]);

    const stats = {
      organizationCount: Number(orgCount[0].count),
      siteCount: Number(siteCount[0].count),
      buildingCount: Number(buildingCount[0].count),
      floorCount: Number(floorCount[0].count),
      zoneCount: Number(zoneCount[0].count),
      userCount: 0, // This would come from user service
      doorCount: 0, // This would come from access control service
      cameraCount: 0 // This would come from video service
    };

    // Cache the stats
    await this.redis.setex(cacheKey, 60, JSON.stringify(stats));

    return stats;
  }

  async getTenantResourceUsage(tenantId: string): Promise<ResourceUsage> {
    const tenant = await this.getTenantById(tenantId);
    if (!tenant) {
      throw new HTTPException(404, { message: 'Tenant not found' });
    }

    const stats = await this.getTenantStats(tenantId);
    const quotas = tenant.resourceQuotas as any || {
      maxUsers: 1000,
      maxDoors: 500,
      maxCameras: 100,
      storageQuotaGB: 100
    };

    return {
      users: {
        current: stats.userCount,
        quota: quotas.maxUsers,
        percentage: ((stats.userCount / quotas.maxUsers) * 100).toFixed(1)
      },
      doors: {
        current: stats.doorCount,
        quota: quotas.maxDoors,
        percentage: ((stats.doorCount / quotas.maxDoors) * 100).toFixed(1)
      },
      cameras: {
        current: stats.cameraCount,
        quota: quotas.maxCameras,
        percentage: ((stats.cameraCount / quotas.maxCameras) * 100).toFixed(1)
      },
      storage: {
        current: 0, // Would need to implement storage tracking
        quota: quotas.storageQuotaGB,
        percentage: '0.0'
      }
    };
  }

  // Organization operations
  async getOrganizations(params: {
    tenantId?: string;
    page: number;
    limit: number;
    search?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
  }): Promise<PaginatedResponse<OrganizationWithRelations>> {
    const { tenantId, page, limit, search, sortBy, sortOrder = 'desc' } = params;
    const offset = (page - 1) * limit;

    // Build where conditions
    const whereConditions = [];
    if (tenantId) {
      whereConditions.push(eq(organizations.tenantId, tenantId));
    }
    if (search) {
      whereConditions.push(
        or(
          ilike(organizations.name, `%${search}%`),
          ilike(organizations.description, `%${search}%`)
        )
      );
    }

    // Build order by
    const orderByColumn = sortBy ? organizations[sortBy as keyof typeof organizations] : organizations.createdAt;
    const orderByDirection = sortOrder === 'asc' ? asc : desc;

    // Execute queries
    const [results, totalCount] = await Promise.all([
      db
        .select()
        .from(organizations)
        .where(whereConditions.length > 0 ? and(...whereConditions) : undefined)
        .limit(limit)
        .offset(offset)
        .orderBy(orderByDirection(orderByColumn)),
      db
        .select({ count: sql<number>`count(*)` })
        .from(organizations)
        .where(whereConditions.length > 0 ? and(...whereConditions) : undefined)
    ]);

    return {
      data: results,
      pagination: {
        page,
        limit,
        total: Number(totalCount[0].count),
        totalPages: Math.ceil(Number(totalCount[0].count) / limit)
      }
    };
  }

  async getOrganizationById(id: string): Promise<OrganizationWithRelations | null> {
    const cacheKey = `org:${id}`;
    
    // Try cache first
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    const org = await db.query.organizations.findFirst({
      where: eq(organizations.id, id),
      with: {
        tenant: true,
        sites: {
          with: {
            buildings: {
              with: {
                floors: {
                  with: {
                    zones: true
                  }
                }
              }
            }
          }
        }
      }
    });

    if (org) {
      // Cache the result
      await this.redis.setex(cacheKey, 300, JSON.stringify(org));
    }

    return org;
  }

  async createOrganization(tenantId: string, data: any, createdBy?: string): Promise<Organization> {
    // Verify tenant exists
    const tenant = await this.getTenantById(tenantId);
    if (!tenant) {
      throw new HTTPException(404, { message: 'Tenant not found' });
    }

    // Check name uniqueness within tenant
    const existing = await db.query.organizations.findFirst({
      where: and(
        eq(organizations.tenantId, tenantId),
        eq(organizations.name, data.name)
      )
    });

    if (existing) {
      throw new HTTPException(409, { message: 'Organization with this name already exists in the tenant' });
    }

    const [org] = await db
      .insert(organizations)
      .values({
        ...data,
        id: uuidv4(),
        tenantId,
        createdBy,
        createdAt: new Date(),
        updatedAt: new Date()
      })
      .returning();

    // Invalidate cache
    await this.invalidateTenantCache(tenantId);

    return org;
  }

  async updateOrganization(id: string, data: any, updatedBy?: string): Promise<Organization> {
    const existing = await this.getOrganizationById(id);
    if (!existing) {
      throw new HTTPException(404, { message: 'Organization not found' });
    }

    const [updated] = await db
      .update(organizations)
      .set({
        ...data,
        updatedBy,
        updatedAt: new Date()
      })
      .where(eq(organizations.id, id))
      .returning();

    // Invalidate cache
    await this.redis.del(`org:${id}`);
    await this.invalidateTenantCache(existing.tenantId);

    return updated;
  }

  async deleteOrganization(id: string): Promise<void> {
    const org = await this.getOrganizationById(id);
    if (!org) {
      throw new HTTPException(404, { message: 'Organization not found' });
    }

    // Check if organization has sites
    const siteCount = await db
      .select({ count: sql<number>`count(*)` })
      .from(sites)
      .where(eq(sites.organizationId, id));

    if (Number(siteCount[0].count) > 0) {
      throw new HTTPException(409, { 
        message: 'Cannot delete organization with existing sites. Please remove all sites first.' 
      });
    }

    await db.delete(organizations).where(eq(organizations.id, id));

    // Invalidate cache
    await this.redis.del(`org:${id}`);
    await this.invalidateTenantCache(org.tenantId);
  }

  // Helper methods
  private async invalidateTenantCache(tenantId?: string): Promise<void> {
    if (tenantId) {
      const keys = await this.redis.keys(`tenant:${tenantId}*`);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    } else {
      const keys = await this.redis.keys('tenant:*');
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
    }
  }

  // Add similar methods for sites, buildings, floors, and zones...
}