import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

const app = new Hono();

// Placeholder routes for access points
app.get('/', (c) => c.json({ message: 'Access points endpoint' }));
app.get('/:id', (c) => c.json({ message: 'Get access point', id: c.req.param('id') }));
app.post('/', (c) => c.json({ message: 'Create access point' }, 201));
app.put('/:id', (c) => c.json({ message: 'Update access point', id: c.req.param('id') }));
app.delete('/:id', (c) => c.json({ message: 'Delete access point', id: c.req.param('id') }));

export default app;