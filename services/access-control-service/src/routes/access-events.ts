import { Hono } from 'hono';

const app = new Hono();

// Placeholder routes for access events
app.get('/', (c) => c.json({ message: 'Access events endpoint' }));
app.get('/:id', (c) => c.json({ message: 'Get access event', id: c.req.param('id') }));
app.post('/', (c) => c.json({ message: 'Log access event' }, 201));

export default app;