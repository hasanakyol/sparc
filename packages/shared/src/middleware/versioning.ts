import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { z } from 'zod';

/**
 * API Version Configuration
 */
export interface VersionConfig {
  major: number;
  minor: number;
  patch: number;
  status: 'preview' | 'current' | 'deprecated' | 'sunset';
  deprecatedAt?: Date;
  sunsetAt?: Date;
  migrationGuide?: string;
}

/**
 * Version Registry - Central registry of all API versions
 */
export class VersionRegistry {
  private versions: Map<string, VersionConfig> = new Map();
  private defaultVersion: string = '2.0';
  private minimumVersion: string = '1.1';

  constructor() {
    // Initialize with current versions
    this.registerVersion('1.0', {
      major: 1,
      minor: 0,
      patch: 0,
      status: 'deprecated',
      deprecatedAt: new Date('2024-01-01'),
      sunsetAt: new Date('2024-06-30'),
      migrationGuide: 'https://docs.sparc.io/migration/v1.0-to-v1.1'
    });

    this.registerVersion('1.1', {
      major: 1,
      minor: 1,
      patch: 0,
      status: 'current'
    });

    this.registerVersion('2.0', {
      major: 2,
      minor: 0,
      patch: 0,
      status: 'current'
    });

    this.registerVersion('2.1', {
      major: 2,
      minor: 1,
      patch: 0,
      status: 'preview'
    });

    this.registerVersion('3.0', {
      major: 3,
      minor: 0,
      patch: 0,
      status: 'preview'
    });
  }

  registerVersion(version: string, config: VersionConfig): void {
    this.versions.set(version, config);
  }

  getVersion(version: string): VersionConfig | undefined {
    return this.versions.get(version);
  }

  getAllVersions(): Map<string, VersionConfig> {
    return this.versions;
  }

  getDefaultVersion(): string {
    return this.defaultVersion;
  }

  getMinimumVersion(): string {
    return this.minimumVersion;
  }

  isVersionSupported(version: string): boolean {
    const config = this.versions.get(version);
    return config !== undefined && config.status !== 'sunset';
  }

  isVersionDeprecated(version: string): boolean {
    const config = this.versions.get(version);
    return config?.status === 'deprecated';
  }

  isVersionPreview(version: string): boolean {
    const config = this.versions.get(version);
    return config?.status === 'preview';
  }

  compareVersions(v1: string, v2: string): number {
    const config1 = this.versions.get(v1);
    const config2 = this.versions.get(v2);

    if (!config1 || !config2) {
      throw new Error('Invalid version comparison');
    }

    if (config1.major !== config2.major) {
      return config1.major - config2.major;
    }
    if (config1.minor !== config2.minor) {
      return config1.minor - config2.minor;
    }
    return config1.patch - config2.patch;
  }
}

// Global version registry instance
export const versionRegistry = new VersionRegistry();

/**
 * Version Context - Stores version information for the request
 */
export interface VersionContext {
  requested: string;
  resolved: string;
  major: number;
  minor: number;
  patch: number;
  isDeprecated: boolean;
  isPreview: boolean;
  deprecationWarning?: string;
}

/**
 * Version Parser - Extracts version from various sources
 */
export class VersionParser {
  private static readonly URL_VERSION_REGEX = /^\/v(\d+)\//;
  private static readonly HEADER_VERSION_REGEX = /^(\d+)\.(\d+)(?:\.(\d+))?$/;
  private static readonly ACCEPT_VERSION_REGEX = /application\/vnd\.sparc\.v([\d.]+)\+json/;

  /**
   * Extract version from URL path
   */
  static extractFromPath(path: string): string | null {
    const match = path.match(this.URL_VERSION_REGEX);
    if (match) {
      return `${match[1]}.0`; // Convert major version to full version
    }
    return null;
  }

  /**
   * Extract version from headers
   */
  static extractFromHeaders(c: Context): string | null {
    // Check Accept-Version header
    const acceptVersion = c.req.header('Accept-Version');
    if (acceptVersion && this.HEADER_VERSION_REGEX.test(acceptVersion)) {
      return acceptVersion;
    }

    // Check X-API-Version header
    const apiVersion = c.req.header('X-API-Version');
    if (apiVersion && this.HEADER_VERSION_REGEX.test(apiVersion)) {
      return apiVersion;
    }

    // Check Accept header for content negotiation
    const accept = c.req.header('Accept');
    if (accept) {
      const match = accept.match(this.ACCEPT_VERSION_REGEX);
      if (match) {
        return match[1];
      }
    }

    return null;
  }

  /**
   * Parse version string into components
   */
  static parseVersion(version: string): { major: number; minor: number; patch: number } {
    const match = version.match(this.HEADER_VERSION_REGEX);
    if (!match) {
      throw new Error(`Invalid version format: ${version}`);
    }

    return {
      major: parseInt(match[1], 10),
      minor: parseInt(match[2] || '0', 10),
      patch: parseInt(match[3] || '0', 10)
    };
  }
}

/**
 * Version Negotiation Middleware
 */
export const versionMiddleware = async (c: Context, next: Next) => {
  try {
    // Extract version from various sources
    let requestedVersion: string | null = null;

    // 1. Check URL path
    requestedVersion = VersionParser.extractFromPath(c.req.path);

    // 2. If not in URL, check headers
    if (!requestedVersion) {
      requestedVersion = VersionParser.extractFromHeaders(c);
    }

    // 3. Use default version if none specified
    if (!requestedVersion) {
      requestedVersion = versionRegistry.getDefaultVersion();
    }

    // Validate version
    if (!versionRegistry.isVersionSupported(requestedVersion)) {
      const allVersions = Array.from(versionRegistry.getAllVersions().entries())
        .filter(([_, config]) => config.status !== 'sunset')
        .map(([version, config]) => ({
          version,
          status: config.status
        }));

      throw new HTTPException(400, {
        message: `Unsupported API version: ${requestedVersion}`,
        cause: {
          code: 'UNSUPPORTED_VERSION',
          requestedVersion,
          supportedVersions: allVersions,
          defaultVersion: versionRegistry.getDefaultVersion()
        }
      });
    }

    // Check if preview version requires opt-in
    if (versionRegistry.isVersionPreview(requestedVersion)) {
      const enablePreview = c.req.header('X-Enable-Preview');
      if (enablePreview !== 'true') {
        throw new HTTPException(400, {
          message: 'Preview version requires opt-in',
          cause: {
            code: 'PREVIEW_NOT_ENABLED',
            requestedVersion,
            hint: 'Set header X-Enable-Preview: true to use preview versions'
          }
        });
      }
    }

    // Parse version components
    const versionConfig = versionRegistry.getVersion(requestedVersion)!;
    const parsed = VersionParser.parseVersion(requestedVersion);

    // Create version context
    const versionContext: VersionContext = {
      requested: requestedVersion,
      resolved: requestedVersion,
      major: parsed.major,
      minor: parsed.minor,
      patch: parsed.patch,
      isDeprecated: versionRegistry.isVersionDeprecated(requestedVersion),
      isPreview: versionRegistry.isVersionPreview(requestedVersion)
    };

    // Add deprecation warning if applicable
    if (versionContext.isDeprecated) {
      const config = versionRegistry.getVersion(requestedVersion)!;
      versionContext.deprecationWarning = `API version ${requestedVersion} is deprecated`;
      
      if (config.sunsetAt) {
        versionContext.deprecationWarning += ` and will be removed on ${config.sunsetAt.toISOString().split('T')[0]}`;
      }
      
      if (config.migrationGuide) {
        versionContext.deprecationWarning += `. Migration guide: ${config.migrationGuide}`;
      }
    }

    // Set version context
    c.set('version', versionContext);

    // Add version headers to response
    c.header('X-API-Version', versionContext.resolved);
    
    if (versionContext.isDeprecated) {
      c.header('X-API-Deprecation', 'true');
      c.header('X-API-Deprecation-Message', versionContext.deprecationWarning!);
      
      const config = versionRegistry.getVersion(requestedVersion)!;
      if (config.sunsetAt) {
        c.header('X-API-Sunset-Date', config.sunsetAt.toISOString().split('T')[0]);
      }
      if (config.migrationGuide) {
        c.header('X-API-Migration-Guide', config.migrationGuide);
      }
    }

    if (versionContext.isPreview) {
      c.header('X-API-Preview', 'true');
    }

    await next();
  } catch (error) {
    if (error instanceof HTTPException) {
      throw error;
    }
    throw new HTTPException(500, {
      message: 'Version negotiation failed',
      cause: error
    });
  }
};

/**
 * Version-specific route handler
 */
export const versionRoute = (versions: Record<string, (c: Context) => Promise<Response> | Response>) => {
  return async (c: Context): Promise<Response> => {
    const versionContext = c.get('version') as VersionContext;
    if (!versionContext) {
      throw new HTTPException(500, {
        message: 'Version context not found'
      });
    }

    const versionKey = `${versionContext.major}.${versionContext.minor}`;
    const handler = versions[versionKey] || versions[`${versionContext.major}.0`] || versions.default;

    if (!handler) {
      throw new HTTPException(501, {
        message: `No implementation for version ${versionKey}`
      });
    }

    return await handler(c);
  };
};

/**
 * Version compatibility checker
 */
export const requireVersion = (minVersion: string, maxVersion?: string) => {
  return async (c: Context, next: Next) => {
    const versionContext = c.get('version') as VersionContext;
    if (!versionContext) {
      throw new HTTPException(500, {
        message: 'Version context not found'
      });
    }

    const currentVersion = versionContext.resolved;

    // Check minimum version
    if (versionRegistry.compareVersions(currentVersion, minVersion) < 0) {
      throw new HTTPException(400, {
        message: `This endpoint requires API version ${minVersion} or higher`,
        cause: {
          code: 'VERSION_TOO_OLD',
          currentVersion,
          requiredVersion: minVersion
        }
      });
    }

    // Check maximum version
    if (maxVersion && versionRegistry.compareVersions(currentVersion, maxVersion) > 0) {
      throw new HTTPException(400, {
        message: `This endpoint is not available in API version ${currentVersion}`,
        cause: {
          code: 'VERSION_TOO_NEW',
          currentVersion,
          maxVersion
        }
      });
    }

    await next();
  };
};

/**
 * Version transformation middleware
 */
export const transformResponse = (transformers: Record<string, (data: any) => any>) => {
  return async (c: Context, next: Next) => {
    await next();

    const versionContext = c.get('version') as VersionContext;
    if (!versionContext) {
      return;
    }

    const versionKey = `${versionContext.major}.${versionContext.minor}`;
    const transformer = transformers[versionKey];

    if (transformer && c.res.headers.get('content-type')?.includes('application/json')) {
      try {
        const body = await c.res.json();
        const transformed = transformer(body);
        c.res = new Response(JSON.stringify(transformed), {
          status: c.res.status,
          headers: c.res.headers
        });
      } catch (error) {
        console.error('Response transformation failed:', error);
        // Keep original response if transformation fails
      }
    }
  };
};

/**
 * Version discovery endpoint handler
 */
export const versionDiscoveryHandler = async (c: Context) => {
  const versions = Array.from(versionRegistry.getAllVersions().entries()).map(([version, config]) => ({
    version,
    status: config.status,
    major: config.major,
    minor: config.minor,
    patch: config.patch,
    deprecatedAt: config.deprecatedAt?.toISOString(),
    sunsetAt: config.sunsetAt?.toISOString(),
    migrationGuide: config.migrationGuide,
    endpoints: config.major === 1 ? '/v1' : `/v${config.major}`
  }));

  return c.json({
    versions,
    recommended: versionRegistry.getDefaultVersion(),
    minimum: versionRegistry.getMinimumVersion(),
    current: c.get('version') as VersionContext
  });
};