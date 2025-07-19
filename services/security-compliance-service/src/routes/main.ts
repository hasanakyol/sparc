import { Hono } from 'hono';

export const mainRouter = new Hono();

mainRouter.get('/', (c) => {
  return c.json({
    service: 'security-compliance-service',
    version: '1.0.0',
    status: 'operational',
    endpoints: {
      audit: '/api/audit',
      compliance: '/api/compliance',
      gdpr: '/api/gdpr',
      policy: '/api/policy',
      security: '/api/security',
      retention: '/api/retention'
    },
    documentation: '/api-docs'
  });
});