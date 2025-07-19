import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { DeviceManagementService } from '../services/device-management-service';

export function createDiscoveryRoutes(deviceService: DeviceManagementService): Hono {
  const app = new Hono();

  // Perform general network discovery
  app.post('/network', async (c) => {
    try {
      const discoveries = await deviceService.performNetworkDiscovery();
      return c.json({ 
        discoveries,
        timestamp: new Date().toISOString(),
        count: discoveries.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Network discovery failed' });
    }
  });

  // ONVIF discovery for IP cameras
  app.post('/onvif', async (c) => {
    try {
      const discoveries = await deviceService.performONVIFDiscovery();
      return c.json({ 
        discoveries,
        protocol: 'ONVIF',
        timestamp: new Date().toISOString(),
        count: discoveries.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'ONVIF discovery failed' });
    }
  });

  // OSDP discovery for access control devices
  app.post('/osdp', async (c) => {
    try {
      const discoveries = await deviceService.performOSDPDiscovery();
      return c.json({ 
        discoveries,
        protocol: 'OSDP',
        timestamp: new Date().toISOString(),
        count: discoveries.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'OSDP discovery failed' });
    }
  });

  // BACnet discovery for building automation
  app.post('/bacnet', async (c) => {
    try {
      const discoveries = await deviceService.performBACnetDiscovery();
      return c.json({ 
        discoveries,
        protocol: 'BACnet',
        timestamp: new Date().toISOString(),
        count: discoveries.length
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'BACnet discovery failed' });
    }
  });

  // Scan specific IP range
  app.post('/scan', async (c) => {
    try {
      const { startIp, endIp, ports } = await c.req.json();
      
      if (!startIp || !endIp) {
        throw new HTTPException(400, { message: 'Start and end IP addresses required' });
      }
      
      const discoveries = await deviceService.scanIpRange(startIp, endIp, ports);
      return c.json({ 
        discoveries,
        range: `${startIp} - ${endIp}`,
        timestamp: new Date().toISOString(),
        count: discoveries.length
      });
    } catch (error) {
      if (error instanceof HTTPException) throw error;
      throw new HTTPException(500, { message: 'IP range scan failed' });
    }
  });

  // Get discovery status
  app.get('/status', async (c) => {
    try {
      const status = await deviceService.getDiscoveryStatus();
      return c.json({ 
        status,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to get discovery status' });
    }
  });

  // Stop all discovery processes
  app.post('/stop', async (c) => {
    try {
      await deviceService.stopDiscovery();
      return c.json({ 
        message: 'Discovery processes stopped',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      throw new HTTPException(500, { message: 'Failed to stop discovery' });
    }
  });

  return app;
}