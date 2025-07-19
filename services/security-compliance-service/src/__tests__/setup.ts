import { jest } from '@jest/globals';

// Mock environment variables
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL = 'redis://localhost:6379';

// Mock Prisma
jest.mock('@prisma/client', () => ({
  PrismaClient: jest.fn().mockImplementation(() => ({
    $connect: jest.fn(),
    $disconnect: jest.fn(),
    $queryRaw: jest.fn(),
    $transaction: jest.fn(),
    auditLog: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      count: jest.fn(),
      groupBy: jest.fn(),
      updateMany: jest.fn()
    },
    complianceReport: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn()
    },
    complianceFinding: {
      create: jest.fn(),
      findMany: jest.fn(),
      update: jest.fn(),
      count: jest.fn()
    },
    securityPolicy: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn()
    },
    gdprRequest: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn()
    },
    dataRetentionPolicy: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn(),
      delete: jest.fn()
    },
    retentionRecord: {
      findMany: jest.fn(),
      count: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn()
    },
    organization: {
      findMany: jest.fn()
    },
    user: {
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn(),
      count: jest.fn()
    },
    userConsent: {
      findMany: jest.fn(),
      upsert: jest.fn()
    },
    attestation: {
      create: jest.fn()
    },
    complianceCheckResult: {
      findMany: jest.fn(),
      createMany: jest.fn()
    },
    scheduledAudit: {
      findMany: jest.fn()
    },
    accessLog: {
      findMany: jest.fn(),
      deleteMany: jest.fn()
    },
    alert: {
      deleteMany: jest.fn()
    }
  }))
}));

// Mock Redis
jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => ({
    ping: jest.fn().mockResolvedValue('PONG'),
    get: jest.fn(),
    set: jest.fn(),
    setex: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    keys: jest.fn().mockResolvedValue([]),
    publish: jest.fn(),
    subscribe: jest.fn(),
    on: jest.fn(),
    quit: jest.fn(),
    zadd: jest.fn(),
    zrange: jest.fn().mockResolvedValue([]),
    zpopmax: jest.fn().mockResolvedValue([]),
    zrem: jest.fn(),
    zcard: jest.fn().mockResolvedValue(0),
    hset: jest.fn(),
    hget: jest.fn(),
    hgetall: jest.fn().mockResolvedValue({}),
    hdel: jest.fn(),
    hlen: jest.fn().mockResolvedValue(0),
    llen: jest.fn().mockResolvedValue(0),
    lpush: jest.fn(),
    lrange: jest.fn().mockResolvedValue([]),
    lrem: jest.fn(),
    hincrby: jest.fn(),
    expire: jest.fn(),
    getBuffer: jest.fn()
  }));
});

// Mock telemetry
jest.mock('@sparc/shared/telemetry', () => ({
  telemetry: {
    initialize: jest.fn(),
    shutdown: jest.fn(),
    withSpan: jest.fn().mockImplementation(async (name, fn) => {
      const mockSpan = {
        setAttributes: jest.fn(),
        setAttribute: jest.fn(),
        setStatus: jest.fn(),
        end: jest.fn()
      };
      return fn(mockSpan);
    }),
    getCurrentTraceId: jest.fn().mockReturnValue('test-trace-id'),
    getCurrentSpanId: jest.fn().mockReturnValue('test-span-id')
  },
  telemetryMiddleware: jest.fn().mockReturnValue(async (c: any, next: any) => next()),
  SpanStatusCode: {
    OK: 0,
    ERROR: 2
  }
}));

// Mock axios
jest.mock('axios', () => ({
  default: {
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn()
  }
}));

// Mock node-cron
jest.mock('node-cron', () => ({
  schedule: jest.fn().mockReturnValue({
    start: jest.fn(),
    stop: jest.fn()
  })
}));

// Mock csv-writer
jest.mock('csv-writer', () => ({
  createObjectCsvStringifier: jest.fn().mockReturnValue({
    getHeaderString: jest.fn().mockReturnValue('header\n'),
    stringifyRecords: jest.fn().mockReturnValue('records\n')
  })
}));

// Mock pdfkit
jest.mock('pdfkit', () => {
  return jest.fn().mockImplementation(() => ({
    fontSize: jest.fn().mockReturnThis(),
    text: jest.fn().mockReturnThis(),
    moveDown: jest.fn().mockReturnThis(),
    addPage: jest.fn().mockReturnThis(),
    end: jest.fn(),
    on: jest.fn().mockImplementation((event, handler) => {
      if (event === 'end') {
        setTimeout(() => handler(), 0);
      }
    })
  }));
});

// Global test timeout
jest.setTimeout(30000);