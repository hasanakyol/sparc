// Test utilities and mocks for comprehensive testing

// Mock Prisma client for unit tests
export const createMockPrismaClient = () => ({
  tenant: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  organization: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  site: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  building: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  floor: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  zone: {
    findMany: jest.fn(),
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
  },
  $queryRaw: jest.fn(),
  $disconnect: jest.fn(),
});

// Mock user contexts for authorization testing
export const createMockUser = (role: 'SUPER_ADMIN' | 'TENANT_ADMIN' | 'ORG_ADMIN' | 'USER', tenantId?: string) => ({
  id: 'test-user-id',
  email: 'test@example.com',
  role,
  tenantId: tenantId || 'test-tenant-id',
  organizationId: 'test-org-id',
});

// Test data factories
export const createTestTenant = (overrides = {}) => ({
  id: 'test-tenant-id',
  name: 'Test Tenant',
  domain: 'test.example.com',
  contactEmail: 'admin@test.example.com',
  status: 'ACTIVE',
  settings: {},
  resourceQuotas: {
    maxUsers: 1000,
    maxDoors: 500,
    maxCameras: 100,
    storageQuotaGB: 100,
  },
  brandingConfig: {},
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

export const createTestOrganization = (tenantId = 'test-tenant-id', overrides = {}) => ({
  id: 'test-org-id',
  name: 'Test Organization',
  description: 'Test organization description',
  tenantId,
  settings: {},
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

export const createTestSite = (organizationId = 'test-org-id', tenantId = 'test-tenant-id', overrides = {}) => ({
  id: 'test-site-id',
  name: 'Test Site',
  address: '123 Test Street',
  city: 'Test City',
  state: 'Test State',
  zipCode: '12345',
  country: 'Test Country',
  organizationId,
  tenantId,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

export const createTestBuilding = (siteId = 'test-site-id', organizationId = 'test-org-id', tenantId = 'test-tenant-id', overrides = {}) => ({
  id: 'test-building-id',
  name: 'Test Building',
  description: 'Test building description',
  siteId,
  organizationId,
  tenantId,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

export const createTestFloor = (buildingId = 'test-building-id', siteId = 'test-site-id', organizationId = 'test-org-id', tenantId = 'test-tenant-id', overrides = {}) => ({
  id: 'test-floor-id',
  name: 'Test Floor',
  level: 1,
  description: 'Test floor description',
  buildingId,
  siteId,
  organizationId,
  tenantId,
  createdAt: new Date(),
  updatedAt: new Date(),
  ...overrides,
});

// Helper to create authenticated request context
export const createAuthenticatedContext = (user: any, tenantId?: string) => ({
  get: jest.fn((key: string) => {
    if (key === 'user') return user;
    if (key === 'tenantId') return tenantId || user.tenantId;
    return undefined;
  }),
  set: jest.fn(),
  req: {
    method: 'GET',
    path: '/test',
    param: jest.fn(),
    query: jest.fn(),
    header: jest.fn(),
    json: jest.fn(),
    valid: jest.fn(),
  },
  json: jest.fn(),
  text: jest.fn(),
  status: jest.fn(),
});

// Performance test utilities
export const createLargeDataset = (count: number, factory: Function) => {
  return Array.from({ length: count }, (_, index) => factory({ id: `test-id-${index}` }));
};

// Database test utilities
export const setupTestDatabase = async () => {
  // Setup test database with clean state
  const { PrismaClient } = await import('@sparc/shared/prisma');
  const prisma = new PrismaClient({
    datasources: {
      db: {
        url: process.env.TEST_DATABASE_URL || 'postgresql://test:test@localhost:5432/sparc_test',
      },
    },
  });

  // Clean all tables in reverse dependency order
  await prisma.zone.deleteMany();
  await prisma.floor.deleteMany();
  await prisma.building.deleteMany();
  await prisma.site.deleteMany();
  await prisma.organization.deleteMany();
  await prisma.tenant.deleteMany();

  return prisma;
};

export const teardownTestDatabase = async (prisma: any) => {
  await prisma.$disconnect();
};

// Integration test helpers
export const createIntegrationTestSuite = () => ({
  beforeEach: async () => {
    const prisma = await setupTestDatabase();
    return prisma;
  },
  afterEach: async (prisma: any) => {
    await teardownTestDatabase(prisma);
  },
});

// Authorization test helpers
export const testEndpointAuthorization = async (app: any, endpoint: string, method: string, requiredRole: string) => {
  const roles = ['USER', 'ORG_ADMIN', 'TENANT_ADMIN', 'SUPER_ADMIN'];
  const results = [];

  for (const role of roles) {
    const user = createMockUser(role as any);
    const context = createAuthenticatedContext(user);
    
    // Mock the request with proper authentication
    const request = new Request(`http://localhost${endpoint}`, {
      method,
      headers: {
        'Authorization': `Bearer mock-jwt-token`,
        'X-Tenant-ID': user.tenantId,
      },
    });

    const response = await app.fetch(request);
    results.push({
      role,
      status: response.status,
      authorized: response.status !== 403,
    });
  }

  return results;
};

// Performance test helpers
export const measureEndpointPerformance = async (app: any, endpoint: string, iterations: number = 100) => {
  const times = [];
  
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    
    const request = new Request(`http://localhost${endpoint}`, {
      headers: {
        'Authorization': `Bearer mock-jwt-token`,
        'X-Tenant-ID': 'test-tenant-id',
      },
    });
    
    await app.fetch(request);
    const end = performance.now();
    times.push(end - start);
  }

  return {
    average: times.reduce((a, b) => a + b, 0) / times.length,
    min: Math.min(...times),
    max: Math.max(...times),
    p95: times.sort((a, b) => a - b)[Math.floor(times.length * 0.95)],
  };
};

// Validation test helpers
export const testInputValidation = async (app: any, endpoint: string, method: string, validPayload: any, invalidPayloads: any[]) => {
  const results = [];

  // Test valid payload
  const validRequest = new Request(`http://localhost${endpoint}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer mock-jwt-token`,
      'X-Tenant-ID': 'test-tenant-id',
    },
    body: JSON.stringify(validPayload),
  });

  const validResponse = await app.fetch(validRequest);
  results.push({
    payload: 'valid',
    status: validResponse.status,
    valid: validResponse.status < 400,
  });

  // Test invalid payloads
  for (const [index, invalidPayload] of invalidPayloads.entries()) {
    const invalidRequest = new Request(`http://localhost${endpoint}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer mock-jwt-token`,
        'X-Tenant-ID': 'test-tenant-id',
      },
      body: JSON.stringify(invalidPayload),
    });

    const invalidResponse = await app.fetch(invalidRequest);
    results.push({
      payload: `invalid-${index}`,
      status: invalidResponse.status,
      valid: invalidResponse.status < 400,
    });
  }

  return results;
};

// Multi-tenant isolation test helpers
export const testTenantIsolation = async (app: any, endpoint: string, tenant1Data: any, tenant2Data: any) => {
  // Create data for tenant 1
  const tenant1Request = new Request(`http://localhost${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer mock-jwt-token`,
      'X-Tenant-ID': 'tenant-1',
    },
    body: JSON.stringify(tenant1Data),
  });

  await app.fetch(tenant1Request);

  // Create data for tenant 2
  const tenant2Request = new Request(`http://localhost${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer mock-jwt-token`,
      'X-Tenant-ID': 'tenant-2',
    },
    body: JSON.stringify(tenant2Data),
  });

  await app.fetch(tenant2Request);

  // Try to access tenant 1 data from tenant 2 context
  const crossTenantRequest = new Request(`http://localhost${endpoint}`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer mock-jwt-token`,
      'X-Tenant-ID': 'tenant-2',
    },
  });

  const crossTenantResponse = await app.fetch(crossTenantRequest);
  const responseData = await crossTenantResponse.json();

  // Should not see tenant 1 data
  return {
    isolated: !responseData.data?.some((item: any) => 
      JSON.stringify(item).includes(JSON.stringify(tenant1Data))
    ),
    tenant2DataVisible: responseData.data?.some((item: any) => 
      JSON.stringify(item).includes(JSON.stringify(tenant2Data))
    ),
  };
};

// Test database configuration
export const testDatabaseConfig = {
  url: process.env.TEST_DATABASE_URL || 'postgresql://test:test@localhost:5432/sparc_test',
  schema: 'public',
};

// Performance test thresholds
export const performanceThresholds = {
  healthCheck: 100, // ms
  readinessCheck: 500, // ms
  crudOperations: 1000, // ms
  listOperations: 2000, // ms
  complexQueries: 5000, // ms
};

// Load test configuration
export const loadTestConfig = {
  concurrentUsers: 100,
  testDuration: 60, // seconds
  rampUpTime: 10, // seconds
  endpoints: [
    '/health',
    '/ready',
    '/api/tenants',
    '/api/organizations',
    '/api/sites',
    '/api/buildings',
    '/api/floors',
  ],
};