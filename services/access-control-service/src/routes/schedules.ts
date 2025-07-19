import { Hono } from 'hono';

const app = new Hono();

// Placeholder routes for schedules
app.get('/', (c) => c.json({ message: 'Schedules endpoint' }));
app.get('/:id', (c) => c.json({ message: 'Get schedule', id: c.req.param('id') }));
app.post('/', (c) => c.json({ message: 'Create schedule' }, 201));
app.put('/:id', (c) => c.json({ message: 'Update schedule', id: c.req.param('id') }));
app.delete('/:id', (c) => c.json({ message: 'Delete schedule', id: c.req.param('id') }));

export default app;