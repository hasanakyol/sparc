import { Hono } from 'hono';

const app = new Hono();

// Placeholder routes for credentials
app.get('/', (c) => c.json({ message: 'Credentials endpoint' }));
app.get('/:id', (c) => c.json({ message: 'Get credential', id: c.req.param('id') }));
app.post('/', (c) => c.json({ message: 'Create credential' }, 201));
app.put('/:id', (c) => c.json({ message: 'Update credential', id: c.req.param('id') }));
app.delete('/:id', (c) => c.json({ message: 'Delete credential', id: c.req.param('id') }));

export default app;