import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '@sparc/shared/middleware/auth';
import { logger } from '@sparc/shared';
import { PrismaClient } from '@prisma/client';
import Redis from 'ioredis';
import { OAuthService } from '../services/oauth.service';
import { SAMLService } from '../services/saml.service';
import { z } from 'zod';

const oauthRouter = new Hono();

// Get service instances
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');
const oauthService = new OAuthService(prisma, redis);
const samlService = new SAMLService(prisma, redis);

// Public routes (no auth required)

// OAuth2 callback handler
oauthRouter.get('/callback', async (c) => {
  try {
    const code = c.req.query('code');
    const state = c.req.query('state');
    const error = c.req.query('error');
    const errorDescription = c.req.query('error_description');

    if (error) {
      logger.error('OAuth callback error', { error, errorDescription });
      return c.html(`
        <html>
          <body>
            <h1>OAuth Error</h1>
            <p>${error}: ${errorDescription}</p>
            <script>
              window.opener.postMessage({ 
                type: 'oauth-error', 
                error: '${error}',
                description: '${errorDescription}'
              }, '*');
              window.close();
            </script>
          </body>
        </html>
      `);
    }

    if (!code || !state) {
      throw new HTTPException(400, { message: 'Missing code or state parameter' });
    }

    // Exchange code for tokens
    const result = await oauthService.handleCallback(code, state);

    // Return HTML that posts message to opener window
    return c.html(`
      <html>
        <body>
          <h1>Authorization Successful</h1>
          <p>You can close this window.</p>
          <script>
            window.opener.postMessage({ 
              type: 'oauth-success', 
              integrationId: '${result.integrationId}'
            }, '*');
            window.close();
          </script>
        </body>
      </html>
    `);
  } catch (error) {
    logger.error('OAuth callback failed', { error });
    return c.html(`
      <html>
        <body>
          <h1>Authorization Failed</h1>
          <p>${error instanceof Error ? error.message : 'Unknown error'}</p>
          <script>
            window.opener.postMessage({ 
              type: 'oauth-error', 
              error: 'callback_failed'
            }, '*');
            window.close();
          </script>
        </body>
      </html>
    `);
  }
});

// SAML callback handler
oauthRouter.post('/saml/callback', async (c) => {
  try {
    const body = await c.req.parseBody();
    const samlResponse = body.SAMLResponse as string;
    const relayState = body.RelayState as string;

    if (!samlResponse) {
      throw new HTTPException(400, { message: 'Missing SAML response' });
    }

    const result = await samlService.handleCallback(samlResponse, relayState);

    // Return HTML for SAML flow completion
    return c.html(`
      <html>
        <body>
          <h1>SAML Authentication Successful</h1>
          <p>You can close this window.</p>
          <script>
            window.opener.postMessage({ 
              type: 'saml-success', 
              integrationId: '${result.integrationId}'
            }, '*');
            window.close();
          </script>
        </body>
      </html>
    `);
  } catch (error) {
    logger.error('SAML callback failed', { error });
    return c.html(`
      <html>
        <body>
          <h1>SAML Authentication Failed</h1>
          <p>${error instanceof Error ? error.message : 'Unknown error'}</p>
          <script>
            window.opener.postMessage({ 
              type: 'saml-error', 
              error: 'callback_failed'
            }, '*');
            window.close();
          </script>
        </body>
      </html>
    `);
  }
});

// SAML metadata endpoint
oauthRouter.get('/saml/metadata', async (c) => {
  try {
    const integrationId = c.req.query('integrationId');
    
    if (!integrationId) {
      throw new HTTPException(400, { message: 'Missing integrationId parameter' });
    }

    const metadata = await samlService.generateMetadata(integrationId);

    return c.text(metadata, 200, {
      'Content-Type': 'application/xml'
    });
  } catch (error) {
    logger.error('Failed to generate SAML metadata', { error });
    throw new HTTPException(500, { message: 'Failed to generate SAML metadata' });
  }
});

// Protected routes (auth required)
oauthRouter.use('*', authMiddleware);

// Get available OAuth providers
oauthRouter.get('/providers', async (c) => {
  try {
    const providers = await oauthService.getAvailableProviders();
    return c.json(providers);
  } catch (error) {
    logger.error('Failed to get OAuth providers', { error });
    throw new HTTPException(500, { message: 'Failed to get OAuth providers' });
  }
});

// Initialize OAuth flow
oauthRouter.post('/authorize', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const body = await c.req.json();

    const schema = z.object({
      integrationId: z.string().uuid(),
      provider: z.string(),
      scopes: z.array(z.string()).optional(),
      additionalParams: z.record(z.any()).optional()
    });

    const data = schema.parse(body);

    const authUrl = await oauthService.initiateOAuthFlow(
      tenantId,
      userId,
      data.integrationId,
      data.provider,
      data.scopes,
      data.additionalParams
    );

    return c.json({ 
      authUrl,
      message: 'Redirect user to the authorization URL'
    });
  } catch (error) {
    logger.error('Failed to initialize OAuth flow', { error });
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { 
        message: 'Invalid request data',
        cause: error.errors 
      });
    }
    throw new HTTPException(500, { message: 'Failed to initialize OAuth flow' });
  }
});

// Refresh OAuth tokens
oauthRouter.post('/refresh', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const body = await c.req.json();

    const schema = z.object({
      integrationId: z.string().uuid()
    });

    const data = schema.parse(body);

    const tokens = await oauthService.refreshTokens(
      tenantId,
      data.integrationId
    );

    return c.json({ 
      success: true,
      expiresAt: tokens.expiresAt
    });
  } catch (error) {
    logger.error('Failed to refresh OAuth tokens', { error });
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { 
        message: 'Invalid request data',
        cause: error.errors 
      });
    }
    throw new HTTPException(500, { message: 'Failed to refresh OAuth tokens' });
  }
});

// Revoke OAuth tokens
oauthRouter.post('/revoke', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const body = await c.req.json();

    const schema = z.object({
      integrationId: z.string().uuid()
    });

    const data = schema.parse(body);

    await oauthService.revokeTokens(
      tenantId,
      data.integrationId
    );

    return c.json({ 
      success: true,
      message: 'OAuth tokens revoked successfully'
    });
  } catch (error) {
    logger.error('Failed to revoke OAuth tokens', { error });
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { 
        message: 'Invalid request data',
        cause: error.errors 
      });
    }
    throw new HTTPException(500, { message: 'Failed to revoke OAuth tokens' });
  }
});

// Get OAuth token status
oauthRouter.get('/status/:integrationId', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('integrationId');

    const status = await oauthService.getTokenStatus(
      tenantId,
      integrationId
    );

    return c.json(status);
  } catch (error) {
    logger.error('Failed to get OAuth token status', { error });
    throw new HTTPException(500, { message: 'Failed to get OAuth token status' });
  }
});

// Initialize SAML flow
oauthRouter.post('/saml/authorize', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const userId = c.get('userId') as string;
    const body = await c.req.json();

    const schema = z.object({
      integrationId: z.string().uuid()
    });

    const data = schema.parse(body);

    const authRequest = await samlService.initiateSAMLFlow(
      tenantId,
      userId,
      data.integrationId
    );

    return c.json({ 
      authUrl: authRequest.url,
      samlRequest: authRequest.request,
      message: 'Redirect user to the SAML IdP'
    });
  } catch (error) {
    logger.error('Failed to initialize SAML flow', { error });
    if (error instanceof z.ZodError) {
      throw new HTTPException(400, { 
        message: 'Invalid request data',
        cause: error.errors 
      });
    }
    throw new HTTPException(500, { message: 'Failed to initialize SAML flow' });
  }
});

// Get SAML configuration for integration
oauthRouter.get('/saml/config/:integrationId', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('integrationId');

    const config = await samlService.getSAMLConfig(
      tenantId,
      integrationId
    );

    return c.json(config);
  } catch (error) {
    logger.error('Failed to get SAML config', { error });
    throw new HTTPException(500, { message: 'Failed to get SAML config' });
  }
});

// Test OAuth/SAML connection
oauthRouter.post('/test/:integrationId', async (c) => {
  try {
    const tenantId = c.get('tenantId') as string;
    const integrationId = c.req.param('integrationId');

    const integration = await prisma.integration.findFirst({
      where: {
        id: integrationId,
        tenantId
      }
    });

    if (!integration) {
      throw new HTTPException(404, { message: 'Integration not found' });
    }

    let result;
    if (integration.type === 'OAUTH2') {
      result = await oauthService.testConnection(tenantId, integrationId);
    } else if (integration.type === 'SAML') {
      result = await samlService.testConnection(tenantId, integrationId);
    } else {
      throw new HTTPException(400, { message: 'Integration is not OAuth2 or SAML type' });
    }

    return c.json(result);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to test OAuth/SAML connection', { error });
    throw new HTTPException(500, { message: 'Failed to test connection' });
  }
});

export default oauthRouter;