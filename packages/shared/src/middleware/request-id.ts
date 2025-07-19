import { Context, Next } from 'hono';
import { v4 as uuidv4 } from 'uuid';

export async function requestIdMiddleware(c: Context, next: Next) {
  const requestId = c.req.header('X-Request-ID') || uuidv4();
  c.set('requestId', requestId);
  c.header('X-Request-ID', requestId);
  await next();
}