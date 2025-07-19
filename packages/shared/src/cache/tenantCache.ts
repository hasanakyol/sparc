import { CacheService, CacheOptions } from './cacheService';
import { Tenant, Organization, Site, Building, Floor, Zone } from '../types';
import { logger } from '../logger';

export interface TenantCacheConfig {
  ttl?: {
    tenant?: number;
    organization?: number;
    site?: number;
    hierarchy?: number;
  };
  enableWarmup?: boolean;
}

export class TenantCache {
  private cache: CacheService;
  private config: TenantCacheConfig;
  private namespace = 'tenant';

  constructor(cache: CacheService, config: TenantCacheConfig = {}) {
    this.cache = cache;
    this.config = {
      ttl: {
        tenant: config.ttl?.tenant || 3600, // 1 hour
        organization: config.ttl?.organization || 1800, // 30 minutes
        site: config.ttl?.site || 1800, // 30 minutes
        hierarchy: config.ttl?.hierarchy || 600, // 10 minutes
      },
      enableWarmup: config.enableWarmup ?? true,
    };
  }

  /**
   * Get tenant by ID
   */
  async getTenant(tenantId: string): Promise<Tenant | null> {
    const key = `tenant:${tenantId}`;
    return this.cache.get<Tenant>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.tenant,
      tags: ['tenant', `tenant:${tenantId}`],
    });
  }

  /**
   * Set tenant
   */
  async setTenant(tenant: Tenant): Promise<boolean> {
    const key = `tenant:${tenant.id}`;
    return this.cache.set(key, tenant, {
      prefix: this.namespace,
      ttl: this.config.ttl?.tenant,
      tags: ['tenant', `tenant:${tenant.id}`],
    });
  }

  /**
   * Get organization by ID
   */
  async getOrganization(organizationId: string): Promise<Organization | null> {
    const key = `org:${organizationId}`;
    return this.cache.get<Organization>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.organization,
      tags: ['organization', `org:${organizationId}`],
    });
  }

  /**
   * Set organization
   */
  async setOrganization(organization: Organization): Promise<boolean> {
    const key = `org:${organization.id}`;
    return this.cache.set(key, organization, {
      prefix: this.namespace,
      ttl: this.config.ttl?.organization,
      tags: [
        'organization',
        `org:${organization.id}`,
        `tenant:${organization.tenant_id}`,
      ],
    });
  }

  /**
   * Get site by ID
   */
  async getSite(siteId: string): Promise<Site | null> {
    const key = `site:${siteId}`;
    return this.cache.get<Site>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.site,
      tags: ['site', `site:${siteId}`],
    });
  }

  /**
   * Set site
   */
  async setSite(site: Site): Promise<boolean> {
    const key = `site:${site.id}`;
    return this.cache.set(key, site, {
      prefix: this.namespace,
      ttl: this.config.ttl?.site,
      tags: [
        'site',
        `site:${site.id}`,
        `org:${site.organization_id}`,
        `tenant:${site.tenant_id}`,
      ],
    });
  }

  /**
   * Get tenant hierarchy (includes organizations and sites)
   */
  async getTenantHierarchy(tenantId: string): Promise<{
    tenant: Tenant;
    organizations: Organization[];
    sites: Record<string, Site[]>; // organizationId -> sites
  } | null> {
    const key = `hierarchy:${tenantId}`;
    return this.cache.get(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.hierarchy,
      tags: ['hierarchy', `tenant:${tenantId}`],
    });
  }

  /**
   * Set tenant hierarchy
   */
  async setTenantHierarchy(
    tenantId: string,
    hierarchy: {
      tenant: Tenant;
      organizations: Organization[];
      sites: Record<string, Site[]>;
    }
  ): Promise<boolean> {
    const key = `hierarchy:${tenantId}`;
    return this.cache.set(key, hierarchy, {
      prefix: this.namespace,
      ttl: this.config.ttl?.hierarchy,
      tags: ['hierarchy', `tenant:${tenantId}`],
    });
  }

  /**
   * Get organizations by tenant ID
   */
  async getOrganizationsByTenant(tenantId: string): Promise<Organization[] | null> {
    const key = `tenant:${tenantId}:orgs`;
    return this.cache.get<Organization[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.organization,
      tags: ['organization', `tenant:${tenantId}`],
    });
  }

  /**
   * Set organizations for a tenant
   */
  async setOrganizationsByTenant(
    tenantId: string,
    organizations: Organization[]
  ): Promise<boolean> {
    const key = `tenant:${tenantId}:orgs`;
    return this.cache.set(key, organizations, {
      prefix: this.namespace,
      ttl: this.config.ttl?.organization,
      tags: ['organization', `tenant:${tenantId}`],
    });
  }

  /**
   * Get sites by organization ID
   */
  async getSitesByOrganization(organizationId: string): Promise<Site[] | null> {
    const key = `org:${organizationId}:sites`;
    return this.cache.get<Site[]>(key, {
      prefix: this.namespace,
      ttl: this.config.ttl?.site,
      tags: ['site', `org:${organizationId}`],
    });
  }

  /**
   * Set sites for an organization
   */
  async setSitesByOrganization(
    organizationId: string,
    sites: Site[]
  ): Promise<boolean> {
    const key = `org:${organizationId}:sites`;
    const org = sites[0]; // Assuming all sites belong to the same org
    return this.cache.set(key, sites, {
      prefix: this.namespace,
      ttl: this.config.ttl?.site,
      tags: [
        'site',
        `org:${organizationId}`,
        `tenant:${org?.tenant_id}`,
      ],
    });
  }

  /**
   * Invalidate all tenant-related cache
   */
  async invalidateTenant(tenantId: string): Promise<void> {
    await this.cache.invalidateByTags([`tenant:${tenantId}`]);
    logger.info('Invalidated tenant cache', { tenantId });
  }

  /**
   * Invalidate organization-related cache
   */
  async invalidateOrganization(organizationId: string): Promise<void> {
    await this.cache.invalidateByTags([`org:${organizationId}`]);
    logger.info('Invalidated organization cache', { organizationId });
  }

  /**
   * Invalidate site-related cache
   */
  async invalidateSite(siteId: string): Promise<void> {
    await this.cache.invalidateByTags([`site:${siteId}`]);
    logger.info('Invalidated site cache', { siteId });
  }

  /**
   * Warm up cache with tenant data
   */
  async warmup(data: {
    tenants?: Tenant[];
    organizations?: Organization[];
    sites?: Site[];
  }): Promise<void> {
    const operations = [];

    if (data.tenants) {
      for (const tenant of data.tenants) {
        operations.push(this.setTenant(tenant));
      }
    }

    if (data.organizations) {
      for (const org of data.organizations) {
        operations.push(this.setOrganization(org));
      }
    }

    if (data.sites) {
      for (const site of data.sites) {
        operations.push(this.setSite(site));
      }
    }

    await Promise.all(operations);
    logger.info('Tenant cache warmed up', {
      tenants: data.tenants?.length || 0,
      organizations: data.organizations?.length || 0,
      sites: data.sites?.length || 0,
    });
  }

  /**
   * Get cache statistics
   */
  getStats() {
    return this.cache.getStats();
  }
}