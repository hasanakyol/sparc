import { Hono } from 'hono';

const app = new Hono();

// Placeholder routes for recordings
app.get('/', (c) => c.json({ message: 'Recordings endpoint' }));
app.get('/:id', (c) => c.json({ message: 'Get recording', id: c.req.param('id') }));
app.post('/search', (c) => c.json({ message: 'Search recordings' }));
app.delete('/:id', (c) => c.json({ message: 'Delete recording', id: c.req.param('id') }));

export default app;