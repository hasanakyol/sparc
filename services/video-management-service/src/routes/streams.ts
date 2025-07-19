import { Hono } from 'hono';

const app = new Hono();

// Placeholder routes for streams
app.get('/', (c) => c.json({ message: 'Streams endpoint' }));
app.get('/:cameraId/live', (c) => c.json({ message: 'Get live stream', cameraId: c.req.param('cameraId') }));
app.post('/:cameraId/start', (c) => c.json({ message: 'Start stream', cameraId: c.req.param('cameraId') }));
app.post('/:cameraId/stop', (c) => c.json({ message: 'Stop stream', cameraId: c.req.param('cameraId') }));

export default app;