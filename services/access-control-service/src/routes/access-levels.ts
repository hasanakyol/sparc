import { Hono } from 'hono';

const app = new Hono();

// Placeholder routes for access levels
app.get('/', (c) => c.json({ message: 'Access levels endpoint' }));
app.get('/:id', (c) => c.json({ message: 'Get access level', id: c.req.param('id') }));
app.post('/', (c) => c.json({ message: 'Create access level' }, 201));
app.put('/:id', (c) => c.json({ message: 'Update access level', id: c.req.param('id') }));
app.delete('/:id', (c) => c.json({ message: 'Delete access level', id: c.req.param('id') }));

export default app;