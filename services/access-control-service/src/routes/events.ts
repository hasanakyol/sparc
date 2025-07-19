import { Hono } from 'hono';
import { zValidator } from '@hono/zod-validator';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { streamSSE } from 'hono/streaming';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { HTTPException } from 'hono/http-exception';

const prisma = new PrismaClient();
const events = new Hono();

// Middleware
events.use('*', cors());
events.use('*', logger());

// Validation schemas
const eventIngestionSchema = z.object({
  panelId: z.string().uuid(),
  doorId: z.string().uuid(),
  userId: z.string().uuid().optional(),
  credentialId: z.string().uuid().optional(),
  eventType: z.enum([
    'ACCESS_GRANTED',
    'ACCESS_DENIED',
    'DOOR_OPENED',
    'DOOR_CLOSED',
    'DOOR_FORCED',
    'DOOR_HELD_OPEN',
    'CARD_READ',
    'PIN_ENTERED',
    'BIOMETRIC_READ',
    'EMERGENCY_UNLOCK',
    'SYSTEM_LOCK',
    'TAMPER_DETECTED',
    'OFFLINE_EVENT'
  ]),
  timestamp: z.string().datetime(),
  details: z.record(z.any()).optional(),
  offline: z.boolean().default(false),
  sequenceNumber: z.number().optional(),
  tenantId: z.string().uuid()
});

const eventQuerySchema = z.object({
  tenantId: z.string().uuid().optional(),
  doorId: z.string().uuid().optional(),
  userId: z.string().uuid().optional(),
  eventType: z.string().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(1000).default(100),
  offset: z.coerce.number().min(0).default(0),
  includeOffline: z.coerce.boolean().default(true)
});

const offlineSyncSchema = z.object({
  panelId: z.string().uuid(),
  events: z.array(eventIngestionSchema),
  lastSyncTimestamp: z.string().datetime().optional(),
  tenantId: z.string().uuid()
});

// Event ingestion endpoint for hardware panels
events.post('/ingest', zValidator('json', eventIngestionSchema), async (c) => {
  try {
    const eventData = c.req.valid('json');
    const userAgent = c.req.header('User-Agent') || 'Unknown';
    const ipAddress = c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'Unknown';

    // Validate tenant access
    const tenant = await prisma.tenant.findUnique({
      where: { id: eventData.tenantId }
    });

    if (!tenant) {
      throw new HTTPException(404, { message: 'Tenant not found' });
    }

    // Validate door belongs to tenant
    const door = await prisma.door.findFirst({
      where: {
        id: eventData.doorId,
        tenantId: eventData.tenantId
      },
      include: {
        zone: {
          include: {
            floor: {
              include: {
                building: {
                  include: {
                    site: true
                  }
                }
              }
            }
          }
        }
      }
    });

    if (!door) {
      throw new HTTPException(404, { message: 'Door not found or access denied' });
    }

    // Create access event
    const accessEvent = await prisma.accessEvent.create({
      data: {
        tenantId: eventData.tenantId,
        doorId: eventData.doorId,
        userId: eventData.userId,
        credentialId: eventData.credentialId,
        eventType: eventData.eventType,
        timestamp: new Date(eventData.timestamp),
        details: eventData.details || {},
        offline: eventData.offline,
        sequenceNumber: eventData.sequenceNumber,
        ipAddress,
        userAgent
      },
      include: {
        door: {
          include: {
            zone: {
              include: {
                floor: {
                  include: {
                    building: {
                      include: {
                        site: true
                      }
                    }
                  }
                }
              }
            }
          }
        },
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        credential: {
          select: {
            id: true,
            type: true,
            identifier: true
          }
        }
      }
    });

    // Create audit log entry
    await prisma.auditLog.create({
      data: {
        tenantId: eventData.tenantId,
        userId: eventData.userId,
        action: 'ACCESS_EVENT_CREATED',
        resource: 'AccessEvent',
        resourceId: accessEvent.id,
        timestamp: new Date(),
        ipAddress,
        userAgent,
        details: {
          eventType: eventData.eventType,
          doorId: eventData.doorId,
          offline: eventData.offline
        }
      }
    });

    // Trigger real-time event processing (would integrate with event processing service)
    await triggerRealTimeAlert(accessEvent);

    return c.json({
      success: true,
      eventId: accessEvent.id,
      timestamp: accessEvent.timestamp,
      processed: true
    }, 201);

  } catch (error) {
    console.error('Event ingestion error:', error);
    
    if (error instanceof HTTPException) {
      throw error;
    }

    throw new HTTPException(500, { message: 'Failed to process access event' });
  }
});

// Bulk offline event synchronization
events.post('/sync', zValidator('json', offlineSyncSchema), async (c) => {
  try {
    const syncData = c.req.valid('json');
    const userAgent = c.req.header('User-Agent') || 'Unknown';
    const ipAddress = c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'Unknown';

    // Validate tenant access
    const tenant = await prisma.tenant.findUnique({
      where: { id: syncData.tenantId }
    });

    if (!tenant) {
      throw new HTTPException(404, { message: 'Tenant not found' });
    }

    const processedEvents = [];
    const failedEvents = [];

    // Process events in transaction for consistency
    await prisma.$transaction(async (tx) => {
      for (const eventData of syncData.events) {
        try {
          // Validate door belongs to tenant
          const door = await tx.door.findFirst({
            where: {
              id: eventData.doorId,
              tenantId: syncData.tenantId
            }
          });

          if (!door) {
            failedEvents.push({
              event: eventData,
              error: 'Door not found or access denied'
            });
            continue;
          }

          // Check for duplicate events using sequence number and timestamp
          const existingEvent = await tx.accessEvent.findFirst({
            where: {
              doorId: eventData.doorId,
              timestamp: new Date(eventData.timestamp),
              sequenceNumber: eventData.sequenceNumber,
              tenantId: syncData.tenantId
            }
          });

          if (existingEvent) {
            // Skip duplicate event
            continue;
          }

          // Create access event
          const accessEvent = await tx.accessEvent.create({
            data: {
              tenantId: syncData.tenantId,
              doorId: eventData.doorId,
              userId: eventData.userId,
              credentialId: eventData.credentialId,
              eventType: eventData.eventType,
              timestamp: new Date(eventData.timestamp),
              details: eventData.details || {},
              offline: true,
              sequenceNumber: eventData.sequenceNumber,
              ipAddress,
              userAgent,
              syncedAt: new Date()
            }
          });

          processedEvents.push(accessEvent.id);

          // Create audit log entry
          await tx.auditLog.create({
            data: {
              tenantId: syncData.tenantId,
              userId: eventData.userId,
              action: 'OFFLINE_EVENT_SYNCED',
              resource: 'AccessEvent',
              resourceId: accessEvent.id,
              timestamp: new Date(),
              ipAddress,
              userAgent,
              details: {
                eventType: eventData.eventType,
                doorId: eventData.doorId,
                originalTimestamp: eventData.timestamp,
                panelId: syncData.panelId
              }
            }
          });

        } catch (error) {
          failedEvents.push({
            event: eventData,
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      // Update panel sync status
      await tx.accessPanel.update({
        where: {
          id: syncData.panelId,
          tenantId: syncData.tenantId
        },
        data: {
          lastSyncAt: new Date(),
          offlineEventCount: 0
        }
      });
    });

    return c.json({
      success: true,
      processedCount: processedEvents.length,
      failedCount: failedEvents.length,
      processedEvents,
      failedEvents: failedEvents.length > 0 ? failedEvents : undefined,
      syncTimestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Offline sync error:', error);
    throw new HTTPException(500, { message: 'Failed to synchronize offline events' });
  }
});

// Query access events with filtering
events.get('/query', zValidator('query', eventQuerySchema), async (c) => {
  try {
    const query = c.req.valid('query');
    const userTenantId = c.get('tenantId'); // From auth middleware

    // Build where clause
    const where: any = {
      tenantId: query.tenantId || userTenantId
    };

    if (query.doorId) {
      where.doorId = query.doorId;
    }

    if (query.userId) {
      where.userId = query.userId;
    }

    if (query.eventType) {
      where.eventType = query.eventType;
    }

    if (query.startDate || query.endDate) {
      where.timestamp = {};
      if (query.startDate) {
        where.timestamp.gte = new Date(query.startDate);
      }
      if (query.endDate) {
        where.timestamp.lte = new Date(query.endDate);
      }
    }

    if (!query.includeOffline) {
      where.offline = false;
    }

    // Get total count for pagination
    const totalCount = await prisma.accessEvent.count({ where });

    // Get events with related data
    const events = await prisma.accessEvent.findMany({
      where,
      include: {
        door: {
          include: {
            zone: {
              include: {
                floor: {
                  include: {
                    building: {
                      include: {
                        site: {
                          select: {
                            id: true,
                            name: true
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        user: {
          select: {
            id: true,
            firstName: true,
            lastName: true,
            email: true
          }
        },
        credential: {
          select: {
            id: true,
            type: true,
            identifier: true
          }
        }
      },
      orderBy: {
        timestamp: 'desc'
      },
      take: query.limit,
      skip: query.offset
    });

    // Create audit log for query
    await prisma.auditLog.create({
      data: {
        tenantId: query.tenantId || userTenantId,
        userId: c.get('userId'),
        action: 'ACCESS_EVENTS_QUERIED',
        resource: 'AccessEvent',
        timestamp: new Date(),
        ipAddress: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'Unknown',
        userAgent: c.req.header('User-Agent') || 'Unknown',
        details: {
          filters: query,
          resultCount: events.length
        }
      }
    });

    return c.json({
      success: true,
      events,
      pagination: {
        total: totalCount,
        limit: query.limit,
        offset: query.offset,
        hasMore: query.offset + query.limit < totalCount
      }
    });

  } catch (error) {
    console.error('Event query error:', error);
    throw new HTTPException(500, { message: 'Failed to query access events' });
  }
});

// Real-time event streaming via Server-Sent Events
events.get('/stream', async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');

  if (!tenantId) {
    throw new HTTPException(401, { message: 'Authentication required' });
  }

  return streamSSE(c, async (stream) => {
    // Send initial connection confirmation
    await stream.writeSSE({
      data: JSON.stringify({
        type: 'connected',
        timestamp: new Date().toISOString(),
        tenantId
      }),
      event: 'connection'
    });

    // Create audit log for stream connection
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: 'EVENT_STREAM_CONNECTED',
        resource: 'EventStream',
        timestamp: new Date(),
        ipAddress: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'Unknown',
        userAgent: c.req.header('User-Agent') || 'Unknown',
        details: {
          streamType: 'access_events'
        }
      }
    });

    // Set up real-time event listener (would integrate with Redis/message queue)
    const eventListener = async (event: any) => {
      if (event.tenantId === tenantId) {
        await stream.writeSSE({
          data: JSON.stringify({
            type: 'access_event',
            event,
            timestamp: new Date().toISOString()
          }),
          event: 'access_event',
          id: event.id
        });
      }
    };

    // Simulate event subscription (in real implementation, would use Redis pub/sub)
    const intervalId = setInterval(async () => {
      // Send heartbeat
      await stream.writeSSE({
        data: JSON.stringify({
          type: 'heartbeat',
          timestamp: new Date().toISOString()
        }),
        event: 'heartbeat'
      });
    }, 30000);

    // Cleanup on connection close
    stream.onAbort(() => {
      clearInterval(intervalId);
      // Remove event listener
      console.log(`Event stream closed for tenant ${tenantId}`);
    });
  });
});

// Get event statistics
events.get('/stats', async (c) => {
  try {
    const tenantId = c.get('tenantId');
    const userId = c.get('userId');

    if (!tenantId) {
      throw new HTTPException(401, { message: 'Authentication required' });
    }

    const now = new Date();
    const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const last7Days = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const [
      totalEvents,
      eventsLast24h,
      eventsLast7d,
      offlineEvents,
      eventsByType,
      topDoors
    ] = await Promise.all([
      // Total events
      prisma.accessEvent.count({
        where: { tenantId }
      }),

      // Events in last 24 hours
      prisma.accessEvent.count({
        where: {
          tenantId,
          timestamp: { gte: last24Hours }
        }
      }),

      // Events in last 7 days
      prisma.accessEvent.count({
        where: {
          tenantId,
          timestamp: { gte: last7Days }
        }
      }),

      // Offline events pending sync
      prisma.accessEvent.count({
        where: {
          tenantId,
          offline: true,
          syncedAt: null
        }
      }),

      // Events by type (last 7 days)
      prisma.accessEvent.groupBy({
        by: ['eventType'],
        where: {
          tenantId,
          timestamp: { gte: last7Days }
        },
        _count: {
          id: true
        }
      }),

      // Top 10 most active doors (last 7 days)
      prisma.accessEvent.groupBy({
        by: ['doorId'],
        where: {
          tenantId,
          timestamp: { gte: last7Days }
        },
        _count: {
          id: true
        },
        orderBy: {
          _count: {
            id: 'desc'
          }
        },
        take: 10
      })
    ]);

    // Create audit log for stats query
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: 'EVENT_STATS_ACCESSED',
        resource: 'AccessEvent',
        timestamp: new Date(),
        ipAddress: c.req.header('X-Forwarded-For') || c.req.header('X-Real-IP') || 'Unknown',
        userAgent: c.req.header('User-Agent') || 'Unknown',
        details: {
          statsType: 'access_events_summary'
        }
      }
    });

    return c.json({
      success: true,
      stats: {
        totalEvents,
        eventsLast24h,
        eventsLast7d,
        offlineEvents,
        eventsByType: eventsByType.map(item => ({
          eventType: item.eventType,
          count: item._count.id
        })),
        topDoors: topDoors.map(item => ({
          doorId: item.doorId,
          count: item._count.id
        }))
      },
      generatedAt: new Date().toISOString()
    });

  } catch (error) {
    console.error('Event stats error:', error);
    throw new HTTPException(500, { message: 'Failed to generate event statistics' });
  }
});

// Helper function to trigger real-time alerts (would integrate with event processing service)
async function triggerRealTimeAlert(accessEvent: any) {
  try {
    // Check if event should trigger alerts
    const alertConditions = [
      'ACCESS_DENIED',
      'DOOR_FORCED',
      'DOOR_HELD_OPEN',
      'TAMPER_DETECTED',
      'EMERGENCY_UNLOCK'
    ];

    if (alertConditions.includes(accessEvent.eventType)) {
      // In real implementation, would publish to message queue or call event processing service
      console.log(`Alert triggered for event ${accessEvent.id}: ${accessEvent.eventType}`);
      
      // Create alert record
      await prisma.alert.create({
        data: {
          tenantId: accessEvent.tenantId,
          type: 'ACCESS_CONTROL',
          severity: getSeverityForEventType(accessEvent.eventType),
          title: `Access Control Alert: ${accessEvent.eventType}`,
          description: `${accessEvent.eventType} detected at ${accessEvent.door.name}`,
          sourceId: accessEvent.id,
          sourceType: 'ACCESS_EVENT',
          timestamp: new Date(),
          acknowledged: false,
          details: {
            doorId: accessEvent.doorId,
            doorName: accessEvent.door.name,
            userId: accessEvent.userId,
            eventType: accessEvent.eventType,
            location: {
              site: accessEvent.door.zone.floor.building.site.name,
              building: accessEvent.door.zone.floor.building.name,
              floor: accessEvent.door.zone.floor.name,
              zone: accessEvent.door.zone.name
            }
          }
        }
      });
    }
  } catch (error) {
    console.error('Failed to trigger real-time alert:', error);
  }
}

// Helper function to determine alert severity
function getSeverityForEventType(eventType: string): string {
  const severityMap: Record<string, string> = {
    'ACCESS_DENIED': 'MEDIUM',
    'DOOR_FORCED': 'HIGH',
    'DOOR_HELD_OPEN': 'MEDIUM',
    'TAMPER_DETECTED': 'HIGH',
    'EMERGENCY_UNLOCK': 'CRITICAL'
  };

  return severityMap[eventType] || 'LOW';
}

export default events;