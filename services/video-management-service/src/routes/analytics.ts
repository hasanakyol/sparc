import { Hono } from 'hono';

const app = new Hono();

// Placeholder routes for analytics
app.get('/', (c) => c.json({ message: 'Analytics endpoint' }));
app.get('/events', (c) => c.json({ message: 'Get analytics events' }));
app.post('/configure', (c) => c.json({ message: 'Configure analytics' }));
app.get('/reports', (c) => c.json({ message: 'Get analytics reports' }));

export default app;