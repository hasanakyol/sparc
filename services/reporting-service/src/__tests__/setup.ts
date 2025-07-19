import { jest } from '@jest/globals';
import dotenv from 'dotenv';

// Load test environment variables
dotenv.config({ path: '.env.test' });

// Set test environment
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';

// Mock external services
jest.mock('ioredis', () => {
  const Redis = jest.fn(() => ({
    get: jest.fn(),
    set: jest.fn(),
    setex: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    keys: jest.fn(),
    hgetall: jest.fn(),
    ping: jest.fn().mockResolvedValue('PONG'),
    quit: jest.fn(),
    disconnect: jest.fn(),
    on: jest.fn(),
    subscribe: jest.fn(),
    publish: jest.fn()
  }));
  return Redis;
});

jest.mock('@prisma/client', () => {
  const mockPrismaClient = {
    $connect: jest.fn().mockResolvedValue(undefined),
    $disconnect: jest.fn().mockResolvedValue(undefined),
    $queryRaw: jest.fn().mockResolvedValue([{ '1': 1 }]),
    $transaction: jest.fn((fn) => fn(mockPrismaClient)),
    
    user: {
      findMany: jest.fn().mockResolvedValue([]),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn()
    },
    
    accessEvent: {
      findMany: jest.fn().mockResolvedValue([]),
      count: jest.fn().mockResolvedValue(0),
      create: jest.fn(),
      groupBy: jest.fn().mockResolvedValue([])
    },
    
    door: {
      findMany: jest.fn().mockResolvedValue([]),
      groupBy: jest.fn().mockResolvedValue([])
    },
    
    camera: {
      findMany: jest.fn().mockResolvedValue([]),
      groupBy: jest.fn().mockResolvedValue([])
    },
    
    alert: {
      findMany: jest.fn().mockResolvedValue([]),
      count: jest.fn().mockResolvedValue(0)
    },
    
    incident: {
      findMany: jest.fn().mockResolvedValue([]),
      count: jest.fn().mockResolvedValue(0)
    },
    
    sensor: {
      groupBy: jest.fn().mockResolvedValue([])
    },
    
    cardReader: {
      groupBy: jest.fn().mockResolvedValue([])
    },
    
    videoEvent: {
      findMany: jest.fn().mockResolvedValue([])
    },
    
    auditLog: {
      findMany: jest.fn().mockResolvedValue([]),
      count: jest.fn().mockResolvedValue(0)
    },
    
    scheduledReport: {
      findMany: jest.fn().mockResolvedValue([]),
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      deleteMany: jest.fn()
    },
    
    complianceReport: {
      findMany: jest.fn().mockResolvedValue([]),
      create: jest.fn()
    }
  };

  return {
    PrismaClient: jest.fn(() => mockPrismaClient)
  };
});

jest.mock('bull', () => {
  const mockQueue = {
    add: jest.fn().mockResolvedValue({ id: 'job-123' }),
    process: jest.fn(),
    on: jest.fn(),
    getJobs: jest.fn().mockResolvedValue([]),
    getJob: jest.fn(),
    getWaitingCount: jest.fn().mockResolvedValue(0),
    getActiveCount: jest.fn().mockResolvedValue(0),
    getCompletedCount: jest.fn().mockResolvedValue(0),
    getFailedCount: jest.fn().mockResolvedValue(0),
    getDelayedCount: jest.fn().mockResolvedValue(0),
    getCompleted: jest.fn().mockResolvedValue([]),
    getFailed: jest.fn().mockResolvedValue([]),
    pause: jest.fn(),
    close: jest.fn(),
    isReady: jest.fn().mockResolvedValue(true)
  };

  return jest.fn(() => mockQueue);
});

jest.mock('nodemailer', () => ({
  createTransporter: jest.fn(() => ({
    sendMail: jest.fn().mockResolvedValue({ messageId: 'test-message-id' }),
    verify: jest.fn().mockResolvedValue(true),
    close: jest.fn()
  }))
}));

jest.mock('node-cron', () => ({
  schedule: jest.fn(() => ({
    start: jest.fn(),
    stop: jest.fn()
  })),
  validate: jest.fn((expression) => {
    // Basic cron validation
    const parts = expression.split(' ');
    return parts.length === 5;
  }),
  parseExpression: jest.fn(() => ({
    next: () => ({ toDate: () => new Date(Date.now() + 86400000) })
  }))
}));

jest.mock('pdfkit', () => {
  return jest.fn(() => ({
    fontSize: jest.fn().mockReturnThis(),
    font: jest.fn().mockReturnThis(),
    text: jest.fn().mockReturnThis(),
    moveDown: jest.fn().mockReturnThis(),
    addPage: jest.fn().mockReturnThis(),
    end: jest.fn(),
    on: jest.fn((event, callback) => {
      if (event === 'end') {
        setTimeout(() => callback(), 10);
      }
    }),
    bufferedPageRange: jest.fn(() => ({ count: 1 })),
    switchToPage: jest.fn().mockReturnThis(),
    page: { height: 800 },
    x: 50,
    y: 100
  }));
});

jest.mock('json2csv', () => ({
  Parser: jest.fn(() => ({
    parse: jest.fn(() => 'csv,data\\ntest,value')
  }))
}));

jest.mock('xlsx', () => ({
  utils: {
    book_new: jest.fn(() => ({})),
    json_to_sheet: jest.fn(() => ({ '!ref': 'A1:B2' })),
    book_append_sheet: jest.fn(),
    decode_range: jest.fn(() => ({ s: { c: 0 }, e: { c: 1 } })),
    encode_col: jest.fn((n) => String.fromCharCode(65 + n))
  },
  write: jest.fn(() => Buffer.from('xlsx data'))
}));

jest.mock('@aws-sdk/client-s3', () => ({
  S3Client: jest.fn(() => ({
    send: jest.fn()
  })),
  PutObjectCommand: jest.fn(),
  GetObjectCommand: jest.fn(),
  DeleteObjectCommand: jest.fn()
}));

jest.mock('@aws-sdk/s3-request-presigner', () => ({
  getSignedUrl: jest.fn().mockResolvedValue('https://s3.example.com/signed-url')
}));

jest.mock('chartjs-node-canvas', () => ({
  ChartJSNodeCanvas: jest.fn(() => ({
    renderToBuffer: jest.fn().mockResolvedValue(Buffer.from('chart image'))
  }))
}));

// Global test utilities
global.testUtils = {
  createMockContext: () => ({
    req: {
      header: jest.fn(),
      query: jest.fn(),
      param: jest.fn(),
      json: jest.fn(),
      valid: jest.fn()
    },
    get: jest.fn(),
    set: jest.fn(),
    json: jest.fn(),
    body: jest.fn(),
    header: jest.fn(),
    status: jest.fn().mockReturnThis()
  }),
  
  createMockConfig: () => ({
    serviceName: 'reporting-service',
    port: 3007,
    version: '1.0.0',
    jwtSecret: 'test-secret',
    redisUrl: 'redis://localhost:6379',
    databaseUrl: 'postgresql://test:test@localhost:5432/test',
    corsOrigins: ['http://localhost:3000'],
    enableAuth: true,
    enableRateLimit: true,
    enableMetrics: true,
    smtp: {
      host: 'smtp.test.com',
      port: 587,
      user: 'test@test.com',
      pass: 'test-pass',
      from: 'Test <test@test.com>'
    },
    storage: {
      path: '/tmp/test-reports',
      retentionDays: 30
    },
    reportGeneration: {
      maxConcurrent: 5,
      timeoutMs: 300000,
      queueName: 'test-queue'
    },
    otel: {
      enabled: false,
      serviceName: 'test-service',
      endpoint: 'http://localhost:4318',
      samplerType: 'always_on',
      samplerArg: 1.0
    },
    rateLimit: {
      windowMs: 900000,
      maxRequests: 100
    }
  })
};

// Increase test timeout
jest.setTimeout(30000);

// Suppress console logs during tests
if (process.env.SUPPRESS_LOGS === 'true') {
  global.console = {
    ...console,
    log: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn()
  };
}