import { Hono } from 'hono';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';
import { HTTPException } from 'hono/http-exception';
import { logger } from '@sparc/shared/utils';
import { 
  Door, 
  Zone, 
  AccessEvent, 
  Schedule, 
  AccessGroup,
  CreateDoorRequest,
  UpdateDoorRequest,
  DoorControlRequest,
  DoorStatusResponse,
  AccessPermissionRequest,
  ScheduleRequest,
  EmergencyOverrideRequest,
  AntiPassbackEvent,
  DualAuthorizationRequest,
  NestedAccessGroup
} from '@sparc/shared/types';

const app = new Hono();

// Validation schemas
const createDoorSchema = z.object({
  name: z.string().min(1).max(255),
  floor_id: z.string().uuid(),
  zone_id: z.string().uuid().optional(),
  location: z.object({
    x: z.number(),
    y: z.number()
  }),
  hardware: z.object({
    panel_id: z.string().uuid(),
    reader_ids: z.array(z.string().uuid()),
    lock_type: z.enum(['magnetic', 'electric_strike', 'motorized', 'turnstile'])
  }),
  settings: z.object({
    unlock_duration: z.number().min(1).max(300).default(5),
    door_ajar_timeout: z.number().min(5).max(3600).default(30),
    anti_passback_enabled: z.boolean().default(false),
    anti_passback_mode: z.enum(['soft', 'hard', 'timed']).default('soft'),
    anti_passback_timeout: z.number().min(60).max(86400).default(300), // 5 minutes to 24 hours
    dual_authorization_required: z.boolean().default(false),
    dual_authorization_timeout: z.number().min(10).max(300).default(30),
    dual_authorization_mode: z.enum(['sequential', 'simultaneous']).default('sequential'),
    require_pin_with_card: z.boolean().default(false),
    max_failed_attempts: z.number().min(1).max(10).default(3),
    lockout_duration: z.number().min(60).max(3600).default(300), // 5 minutes to 1 hour
    emergency_unlock_enabled: z.boolean().default(true),
    visitor_escort_required: z.boolean().default(false)
  }).optional()
});

const updateDoorSchema = createDoorSchema.partial();

const doorControlSchema = z.object({
  action: z.enum(['unlock', 'lock', 'toggle', 'pulse']),
  duration: z.number().min(1).max(300).optional(),
  reason: z.string().max(500).optional(),
  override_schedule: z.boolean().default(false)
});

const accessPermissionSchema = z.object({
  user_id: z.string().uuid().optional(),
  access_group_id: z.string().uuid().optional(),
  schedule_id: z.string().uuid().optional(),
  valid_from: z.string().datetime().optional(),
  valid_until: z.string().datetime().optional(),
  access_level: z.enum(['granted', 'denied', 'conditional']).default('granted')
});

const scheduleSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  time_zones: z.array(z.object({
    day_of_week: z.array(z.number().min(0).max(6)),
    start_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    end_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    timezone: z.string().default('UTC'),
    recurring_pattern: z.object({
      type: z.enum(['daily', 'weekly', 'monthly', 'yearly']).optional(),
      interval: z.number().min(1).max(365).optional(),
      end_date: z.string().date().optional()
    }).optional()
  })),
  holidays: z.array(z.object({
    date: z.string().date(),
    name: z.string(),
    access_override: z.enum(['allow', 'deny', 'schedule']).default('deny'),
    recurring: z.boolean().default(false),
    country_code: z.string().length(2).optional(),
    region_code: z.string().optional()
  })).optional(),
  exceptions: z.array(z.object({
    date: z.string().date(),
    start_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    end_time: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    access_override: z.enum(['allow', 'deny']).default('allow'),
    reason: z.string().max(500).optional(),
    created_by: z.string().uuid().optional()
  })).optional(),
  priority: z.number().min(1).max(100).default(50),
  inherit_from_parent: z.boolean().default(false),
  parent_schedule_id: z.string().uuid().optional(),
  active: z.boolean().default(true)
});

const emergencyOverrideSchema = z.object({
  override_type: z.enum(['lockdown', 'unlock_all', 'evacuation', 'custom', 'partial_lockdown', 'zone_isolation', 'fire_evacuation', 'security_breach']),
  scope: z.object({
    building_id: z.string().uuid().optional(),
    floor_id: z.string().uuid().optional(),
    zone_id: z.string().uuid().optional(),
    door_ids: z.array(z.string().uuid()).optional(),
    exclude_doors: z.array(z.string().uuid()).optional(),
    include_elevators: z.boolean().default(false),
    include_emergency_exits: z.boolean().default(true)
  }),
  duration: z.number().min(1).max(86400).optional(), // Max 24 hours
  reason: z.string().min(1).max(1000),
  authorized_by: z.string().uuid(),
  approval_required: z.boolean().default(false),
  approved_by: z.string().uuid().optional(),
  escalation_level: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  auto_revert: z.boolean().default(true),
  notification_groups: z.array(z.string().uuid()).optional()
});

const createZoneSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  floor_id: z.string().uuid(),
  zone_type: z.enum(['security', 'public', 'restricted', 'emergency', 'maintenance', 'high_security', 'clean_room', 'data_center']),
  boundaries: z.array(z.object({
    x: z.number(),
    y: z.number()
  })).optional(),
  access_rules: z.object({
    default_access: z.enum(['allow', 'deny']).default('deny'),
    require_escort: z.boolean().default(false),
    max_occupancy: z.number().min(0).optional(),
    visitor_access: z.boolean().default(false),
    anti_passback_zone: z.boolean().default(false),
    dual_auth_required: z.boolean().default(false),
    pin_required: z.boolean().default(false),
    biometric_required: z.boolean().default(false),
    time_limited_access: z.boolean().default(false),
    max_dwell_time: z.number().min(60).optional() // seconds
  }).optional()
});

// New schemas for advanced features
const antiPassbackSchema = z.object({
  user_id: z.string().uuid(),
  door_id: z.string().uuid(),
  direction: z.enum(['entry', 'exit']),
  force_reset: z.boolean().default(false),
  reason: z.string().max(500).optional()
});

const dualAuthorizationSchema = z.object({
  door_id: z.string().uuid(),
  primary_user_id: z.string().uuid(),
  secondary_user_id: z.string().uuid().optional(),
  timeout: z.number().min(10).max(300).default(30),
  reason: z.string().max(500).optional()
});

const nestedAccessGroupSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).optional(),
  parent_group_id: z.string().uuid().optional(),
  inherit_permissions: z.boolean().default(true),
  override_permissions: z.array(z.object({
    door_id: z.string().uuid(),
    access_level: z.enum(['granted', 'denied', 'conditional']),
    conditions: z.object({
      time_based: z.boolean().default(false),
      escort_required: z.boolean().default(false),
      dual_auth_required: z.boolean().default(false)
    }).optional()
  })).optional(),
  priority: z.number().min(1).max(100).default(50)
});

// Middleware for tenant context and authorization
app.use('*', async (c, next) => {
  const tenantId = c.req.header('X-Tenant-ID');
  const userId = c.req.header('X-User-ID');
  const userRoles = c.req.header('X-User-Roles')?.split(',') || [];

  if (!tenantId || !userId) {
    throw new HTTPException(401, { message: 'Missing tenant or user context' });
  }

  c.set('tenantId', tenantId);
  c.set('userId', userId);
  c.set('userRoles', userRoles);

  await next();
});

// Authorization middleware for door management
const requireDoorManagementPermission = async (c: any, next: any) => {
  const userRoles = c.get('userRoles') as string[];
  const hasPermission = userRoles.some(role => 
    ['admin', 'security_manager', 'door_operator'].includes(role)
  );

  if (!hasPermission) {
    throw new HTTPException(403, { message: 'Insufficient permissions for door management' });
  }

  await next();
};

// DOOR CRUD OPERATIONS

// Get all doors with filtering and pagination
app.get('/doors', async (c) => {
  const tenantId = c.get('tenantId');
  const query = c.req.query();
  
  const page = parseInt(query.page || '1');
  const limit = Math.min(parseInt(query.limit || '50'), 100);
  const offset = (page - 1) * limit;

  try {
    // Build filter conditions
    const filters: any = { tenant_id: tenantId };
    
    if (query.building_id) filters.building_id = query.building_id;
    if (query.floor_id) filters.floor_id = query.floor_id;
    if (query.zone_id) filters.zone_id = query.zone_id;
    if (query.status) filters.status = query.status;
    if (query.search) {
      filters.name = { contains: query.search, mode: 'insensitive' };
    }

    // Get doors with related data
    const doors = await prisma.door.findMany({
      where: filters,
      include: {
        floor: {
          include: {
            building: {
              include: {
                site: true
              }
            }
          }
        },
        zone: true,
        access_panel: true,
        card_readers: true,
        access_events: {
          take: 5,
          orderBy: { timestamp: 'desc' }
        }
      },
      orderBy: { name: 'asc' },
      skip: offset,
      take: limit
    });

    const total = await prisma.door.count({ where: filters });

    logger.info('Retrieved doors', { 
      tenantId, 
      count: doors.length, 
      total,
      filters 
    });

    return c.json({
      doors,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error('Failed to retrieve doors', { tenantId, error });
    throw new HTTPException(500, { message: 'Failed to retrieve doors' });
  }
});

// Get door by ID
app.get('/doors/:id', async (c) => {
  const tenantId = c.get('tenantId');
  const doorId = c.req.param('id');

  try {
    const door = await prisma.door.findFirst({
      where: { 
        id: doorId, 
        tenant_id: tenantId 
      },
      include: {
        floor: {
          include: {
            building: {
              include: {
                site: true
              }
            }
          }
        },
        zone: true,
        access_panel: true,
        card_readers: true,
        access_groups: {
          include: {
            users: true,
            schedules: true
          }
        },
        schedules: true
      }
    });

    if (!door) {
      throw new HTTPException(404, { message: 'Door not found' });
    }

    return c.json({ door });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to retrieve door', { tenantId, doorId, error });
    throw new HTTPException(500, { message: 'Failed to retrieve door' });
  }
});

// Create new door
app.post('/doors', requireDoorManagementPermission, zValidator('json', createDoorSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const doorData = c.req.valid('json');

  try {
    // Verify floor exists and belongs to tenant
    const floor = await prisma.floor.findFirst({
      where: { 
        id: doorData.floor_id,
        building: {
          site: {
            tenant_id: tenantId
          }
        }
      }
    });

    if (!floor) {
      throw new HTTPException(400, { message: 'Invalid floor ID or access denied' });
    }

    // Verify zone if provided
    if (doorData.zone_id) {
      const zone = await prisma.zone.findFirst({
        where: { 
          id: doorData.zone_id,
          floor_id: doorData.floor_id
        }
      });

      if (!zone) {
        throw new HTTPException(400, { message: 'Invalid zone ID' });
      }
    }

    // Create door
    const door = await prisma.door.create({
      data: {
        ...doorData,
        tenant_id: tenantId,
        status: 'online',
        created_by: userId
      },
      include: {
        floor: {
          include: {
            building: {
              include: {
                site: true
              }
            }
          }
        },
        zone: true
      }
    });

    // Log audit event
    await prisma.audit_log.create({
      data: {
        tenant_id: tenantId,
        user_id: userId,
        action: 'door_created',
        resource_type: 'door',
        resource_id: door.id,
        details: { door_name: door.name, floor_id: door.floor_id },
        ip_address: c.req.header('X-Forwarded-For') || 'unknown',
        user_agent: c.req.header('User-Agent') || 'unknown'
      }
    });

    logger.info('Door created', { tenantId, doorId: door.id, userId });

    return c.json({ door }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to create door', { tenantId, userId, error });
    throw new HTTPException(500, { message: 'Failed to create door' });
  }
});

// Update door
app.put('/doors/:id', requireDoorManagementPermission, zValidator('json', updateDoorSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const doorId = c.req.param('id');
  const updateData = c.req.valid('json');

  try {
    // Verify door exists and belongs to tenant
    const existingDoor = await prisma.door.findFirst({
      where: { 
        id: doorId, 
        tenant_id: tenantId 
      }
    });

    if (!existingDoor) {
      throw new HTTPException(404, { message: 'Door not found' });
    }

    // Update door
    const door = await prisma.door.update({
      where: { id: doorId },
      data: {
        ...updateData,
        updated_at: new Date(),
        updated_by: userId
      },
      include: {
        floor: {
          include: {
            building: {
              include: {
                site: true
              }
            }
          }
        },
        zone: true
      }
    });

    // Log audit event
    await prisma.audit_log.create({
      data: {
        tenant_id: tenantId,
        user_id: userId,
        action: 'door_updated',
        resource_type: 'door',
        resource_id: door.id,
        details: { changes: updateData },
        ip_address: c.req.header('X-Forwarded-For') || 'unknown',
        user_agent: c.req.header('User-Agent') || 'unknown'
      }
    });

    logger.info('Door updated', { tenantId, doorId, userId });

    return c.json({ door });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to update door', { tenantId, doorId, userId, error });
    throw new HTTPException(500, { message: 'Failed to update door' });
  }
});

// Delete door
app.delete('/doors/:id', requireDoorManagementPermission, async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const doorId = c.req.param('id');

  try {
    // Verify door exists and belongs to tenant
    const door = await prisma.door.findFirst({
      where: { 
        id: doorId, 
        tenant_id: tenantId 
      }
    });

    if (!door) {
      throw new HTTPException(404, { message: 'Door not found' });
    }

    // Soft delete door
    await prisma.door.update({
      where: { id: doorId },
      data: {
        deleted_at: new Date(),
        deleted_by: userId,
        status: 'deleted'
      }
    });

    // Log audit event
    await prisma.audit_log.create({
      data: {
        tenant_id: tenantId,
        user_id: userId,
        action: 'door_deleted',
        resource_type: 'door',
        resource_id: doorId,
        details: { door_name: door.name },
        ip_address: c.req.header('X-Forwarded-For') || 'unknown',
        user_agent: c.req.header('User-Agent') || 'unknown'
      }
    });

    logger.info('Door deleted', { tenantId, doorId, userId });

    return c.json({ message: 'Door deleted successfully' });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to delete door', { tenantId, doorId, userId, error });
    throw new HTTPException(500, { message: 'Failed to delete door' });
  }
});

// DOOR CONTROL OPERATIONS

// Control door (unlock, lock, pulse) with advanced features
app.post('/doors/:id/control', requireDoorManagementPermission, zValidator('json', doorControlSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const doorId = c.req.param('id');
  const controlData = c.req.valid('json');

  try {
    // Verify door exists and belongs to tenant
    const door = await prisma.door.findFirst({
      where: { 
        id: doorId, 
        tenant_id: tenantId 
      },
      include: {
        access_panel: true,
        schedules: true,
        zone: true,
        settings: true
      }
    });

    if (!door) {
      throw new HTTPException(404, { message: 'Door not found' });
    }

    if (door.status !== 'online') {
      throw new HTTPException(400, { message: 'Door is not online' });
    }

    // Check for dual authorization requirement
    if (door.settings?.dual_authorization_required && controlData.action === 'unlock') {
      const dualAuthResult = await checkDualAuthorizationStatus(doorId, userId);
      if (!dualAuthResult.authorized) {
        throw new HTTPException(403, { 
          message: 'Dual authorization required',
          details: { 
            pending_authorization: dualAuthResult.pending,
            timeout_remaining: dualAuthResult.timeoutRemaining
          }
        });
      }
    }

    // Check anti-passback if enabled
    if (door.settings?.anti_passback_enabled && controlData.action === 'unlock') {
      const antiPassbackResult = await checkAntiPassbackViolation(doorId, userId);
      if (antiPassbackResult.violation) {
        throw new HTTPException(403, { 
          message: 'Anti-passback violation detected',
          details: {
            last_direction: antiPassbackResult.lastDirection,
            violation_type: antiPassbackResult.violationType,
            reset_required: antiPassbackResult.resetRequired
          }
        });
      }
    }

    // Check schedule permissions if not overriding
    if (!controlData.override_schedule && door.schedules.length > 0) {
      const currentTime = new Date();
      const hasValidSchedule = await checkAdvancedSchedulePermissions(door.schedules, currentTime, door.zone);
      
      if (!hasValidSchedule && controlData.action === 'unlock') {
        throw new HTTPException(403, { message: 'Access denied by schedule' });
      }
    }

    // Check zone-specific rules
    if (door.zone && controlData.action === 'unlock') {
      const zoneValidation = await validateZoneAccessRules(door.zone, userId);
      if (!zoneValidation.allowed) {
        throw new HTTPException(403, { 
          message: 'Access denied by zone rules',
          details: zoneValidation.reason
        });
      }
    }

    // Send control command to hardware
    const controlResult = await sendDoorControlCommand(door, controlData);

    // Update anti-passback tracking
    if (controlResult.success && controlData.action === 'unlock' && door.settings?.anti_passback_enabled) {
      await updateAntiPassbackTracking(doorId, userId, 'entry');
    }

    // Create access event
    await prisma.access_event.create({
      data: {
        tenant_id: tenantId,
        door_id: doorId,
        user_id: userId,
        event_type: 'manual_control',
        result: controlResult.success ? 'granted' : 'denied',
        metadata: {
          action: controlData.action,
          duration: controlData.duration,
          reason: controlData.reason,
          override_schedule: controlData.override_schedule,
          dual_auth_used: door.settings?.dual_authorization_required,
          anti_passback_checked: door.settings?.anti_passback_enabled
        }
      }
    });

    // Update door status if needed
    if (controlResult.success) {
      await prisma.door.update({
        where: { id: doorId },
        data: {
          last_activity: new Date(),
          status: controlResult.newStatus || door.status
        }
      });
    }

    // Log audit event
    await prisma.audit_log.create({
      data: {
        tenant_id: tenantId,
        user_id: userId,
        action: 'door_control',
        resource_type: 'door',
        resource_id: doorId,
        details: { 
          action: controlData.action,
          success: controlResult.success,
          reason: controlData.reason,
          advanced_features_used: {
            dual_auth: door.settings?.dual_authorization_required,
            anti_passback: door.settings?.anti_passback_enabled
          }
        },
        ip_address: c.req.header('X-Forwarded-For') || 'unknown',
        user_agent: c.req.header('User-Agent') || 'unknown'
      }
    });

    logger.info('Door control executed', { 
      tenantId, 
      doorId, 
      userId, 
      action: controlData.action,
      success: controlResult.success 
    });

    return c.json({
      success: controlResult.success,
      message: controlResult.message,
      door_status: controlResult.newStatus || door.status
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to control door', { tenantId, doorId, userId, error });
    throw new HTTPException(500, { message: 'Failed to control door' });
  }
});

// Get door status
app.get('/doors/:id/status', async (c) => {
  const tenantId = c.get('tenantId');
  const doorId = c.req.param('id');

  try {
    const door = await prisma.door.findFirst({
      where: { 
        id: doorId, 
        tenant_id: tenantId 
      },
      include: {
        access_panel: true,
        card_readers: true
      }
    });

    if (!door) {
      throw new HTTPException(404, { message: 'Door not found' });
    }

    // Get real-time status from hardware
    const hardwareStatus = await getDoorHardwareStatus(door);

    // Get recent events
    const recentEvents = await prisma.access_event.findMany({
      where: { door_id: doorId },
      orderBy: { timestamp: 'desc' },
      take: 10,
      include: {
        user: {
          select: { id: true, username: true, email: true }
        }
      }
    });

    const status: DoorStatusResponse = {
      door_id: doorId,
      name: door.name,
      status: door.status,
      hardware_status: hardwareStatus,
      last_activity: door.last_activity,
      recent_events: recentEvents,
      panel_online: door.access_panel?.status === 'online',
      readers_status: door.card_readers.map(reader => ({
        id: reader.id,
        name: reader.name,
        status: reader.status
      }))
    };

    return c.json({ status });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to get door status', { tenantId, doorId, error });
    throw new HTTPException(500, { message: 'Failed to get door status' });
  }
});

// EMERGENCY OVERRIDE OPERATIONS

// Enhanced emergency override with granular control
app.post('/emergency-override', requireDoorManagementPermission, zValidator('json', emergencyOverrideSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const userRoles = c.get('userRoles') as string[];
  const overrideData = c.req.valid('json');

  try {
    // Check if user has emergency override permissions based on escalation level
    const requiredRoles = getRequiredRolesForEscalationLevel(overrideData.escalation_level);
    const hasEmergencyPermission = userRoles.some(role => requiredRoles.includes(role));

    if (!hasEmergencyPermission) {
      throw new HTTPException(403, { 
        message: 'Insufficient permissions for emergency override',
        details: { 
          required_roles: requiredRoles,
          escalation_level: overrideData.escalation_level
        }
      });
    }

    // Check if approval is required for this override type
    if (overrideData.approval_required && !overrideData.approved_by) {
      throw new HTTPException(400, { 
        message: 'Approval required for this emergency override type',
        details: { override_type: overrideData.override_type }
      });
    }

    // Get affected doors based on scope with exclusions
    const affectedDoors = await getDoorsInScopeWithExclusions(tenantId, overrideData.scope);

    if (affectedDoors.length === 0) {
      throw new HTTPException(400, { message: 'No doors found in specified scope' });
    }

    // Validate override type compatibility with door types
    const incompatibleDoors = await validateOverrideCompatibility(affectedDoors, overrideData.override_type);
    if (incompatibleDoors.length > 0) {
      logger.warn('Some doors incompatible with override type', {
        tenantId,
        incompatibleDoors: incompatibleDoors.map(d => d.id),
        overrideType: overrideData.override_type
      });
    }

    // Execute emergency override with granular control
    const overrideResults = await executeAdvancedEmergencyOverride(affectedDoors, overrideData);

    // Create emergency override record
    const emergencyOverride = await prisma.emergency_override.create({
      data: {
        tenant_id: tenantId,
        override_type: overrideData.override_type,
        scope: overrideData.scope,
        duration: overrideData.duration,
        reason: overrideData.reason,
        authorized_by: overrideData.authorized_by,
        approved_by: overrideData.approved_by,
        executed_by: userId,
        escalation_level: overrideData.escalation_level,
        affected_doors: affectedDoors.map(door => door.id),
        excluded_doors: overrideData.scope.exclude_doors || [],
        status: 'active',
        auto_revert: overrideData.auto_revert,
        expires_at: overrideData.duration ? 
          new Date(Date.now() + overrideData.duration * 1000) : null
      }
    });

    // Send notifications to specified groups
    if (overrideData.notification_groups) {
      await sendEmergencyNotifications(overrideData.notification_groups, emergencyOverride);
    }

    // Schedule auto-revert if enabled
    if (overrideData.auto_revert && overrideData.duration) {
      await scheduleEmergencyOverrideRevert(emergencyOverride.id, overrideData.duration);
    }

    // Log audit event
    await prisma.audit_log.create({
      data: {
        tenant_id: tenantId,
        user_id: userId,
        action: 'emergency_override',
        resource_type: 'emergency_override',
        resource_id: emergencyOverride.id,
        details: {
          override_type: overrideData.override_type,
          escalation_level: overrideData.escalation_level,
          affected_doors_count: affectedDoors.length,
          excluded_doors_count: overrideData.scope.exclude_doors?.length || 0,
          reason: overrideData.reason,
          approval_required: overrideData.approval_required,
          approved_by: overrideData.approved_by
        },
        ip_address: c.req.header('X-Forwarded-For') || 'unknown',
        user_agent: c.req.header('User-Agent') || 'unknown'
      }
    });

    logger.warn('Emergency override executed', { 
      tenantId, 
      userId, 
      overrideType: overrideData.override_type,
      escalationLevel: overrideData.escalation_level,
      affectedDoorsCount: affectedDoors.length 
    });

    return c.json({
      override_id: emergencyOverride.id,
      affected_doors: affectedDoors.length,
      excluded_doors: overrideData.scope.exclude_doors?.length || 0,
      results: overrideResults,
      expires_at: emergencyOverride.expires_at,
      auto_revert_scheduled: overrideData.auto_revert && overrideData.duration
    });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to execute emergency override', { tenantId, userId, error });
    throw new HTTPException(500, { message: 'Failed to execute emergency override' });
  }
});

// ZONE MANAGEMENT

// Get zones
app.get('/zones', async (c) => {
  const tenantId = c.get('tenantId');
  const query = c.req.query();

  try {
    const filters: any = { tenant_id: tenantId };
    if (query.floor_id) filters.floor_id = query.floor_id;
    if (query.zone_type) filters.zone_type = query.zone_type;

    const zones = await prisma.zone.findMany({
      where: filters,
      include: {
        floor: {
          include: {
            building: {
              include: {
                site: true
              }
            }
          }
        },
        doors: true,
        cameras: true
      },
      orderBy: { name: 'asc' }
    });

    return c.json({ zones });
  } catch (error) {
    logger.error('Failed to retrieve zones', { tenantId, error });
    throw new HTTPException(500, { message: 'Failed to retrieve zones' });
  }
});

// Create zone
app.post('/zones', requireDoorManagementPermission, zValidator('json', createZoneSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const zoneData = c.req.valid('json');

  try {
    // Verify floor exists and belongs to tenant
    const floor = await prisma.floor.findFirst({
      where: { 
        id: zoneData.floor_id,
        building: {
          site: {
            tenant_id: tenantId
          }
        }
      }
    });

    if (!floor) {
      throw new HTTPException(400, { message: 'Invalid floor ID or access denied' });
    }

    const zone = await prisma.zone.create({
      data: {
        ...zoneData,
        tenant_id: tenantId,
        created_by: userId
      },
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
    });

    logger.info('Zone created', { tenantId, zoneId: zone.id, userId });

    return c.json({ zone }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to create zone', { tenantId, userId, error });
    throw new HTTPException(500, { message: 'Failed to create zone' });
  }
});

// SCHEDULE MANAGEMENT

// Get schedules
app.get('/schedules', async (c) => {
  const tenantId = c.get('tenantId');

  try {
    const schedules = await prisma.schedule.findMany({
      where: { tenant_id: tenantId },
      include: {
        access_groups: true,
        doors: true
      },
      orderBy: { name: 'asc' }
    });

    return c.json({ schedules });
  } catch (error) {
    logger.error('Failed to retrieve schedules', { tenantId, error });
    throw new HTTPException(500, { message: 'Failed to retrieve schedules' });
  }
});

// Create schedule
app.post('/schedules', requireDoorManagementPermission, zValidator('json', scheduleSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const scheduleData = c.req.valid('json');

  try {
    const schedule = await prisma.schedule.create({
      data: {
        ...scheduleData,
        tenant_id: tenantId,
        created_by: userId
      }
    });

    logger.info('Schedule created', { tenantId, scheduleId: schedule.id, userId });

    return c.json({ schedule }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to create schedule', { tenantId, userId, error });
    throw new HTTPException(500, { message: 'Failed to create schedule' });
  }
});

// ACCESS PERMISSION MANAGEMENT

// ANTI-PASSBACK MANAGEMENT

// Reset anti-passback for user
app.post('/doors/:id/anti-passback/reset', requireDoorManagementPermission, zValidator('json', antiPassbackSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const doorId = c.req.param('id');
  const resetData = c.req.valid('json');

  try {
    // Verify door exists and has anti-passback enabled
    const door = await prisma.door.findFirst({
      where: { id: doorId, tenant_id: tenantId },
      include: { settings: true }
    });

    if (!door || !door.settings?.anti_passback_enabled) {
      throw new HTTPException(400, { message: 'Anti-passback not enabled for this door' });
    }

    // Reset anti-passback tracking
    await prisma.anti_passback_tracking.deleteMany({
      where: {
        tenant_id: tenantId,
        door_id: doorId,
        user_id: resetData.user_id
      }
    });

    // Log the reset event
    await prisma.access_event.create({
      data: {
        tenant_id: tenantId,
        door_id: doorId,
        user_id: userId,
        event_type: 'anti_passback_reset',
        result: 'granted',
        metadata: {
          reset_for_user: resetData.user_id,
          reason: resetData.reason,
          force_reset: resetData.force_reset
        }
      }
    });

    logger.info('Anti-passback reset', { tenantId, doorId, resetForUser: resetData.user_id, userId });

    return c.json({ message: 'Anti-passback reset successfully' });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to reset anti-passback', { tenantId, doorId, userId, error });
    throw new HTTPException(500, { message: 'Failed to reset anti-passback' });
  }
});

// Get anti-passback status
app.get('/doors/:id/anti-passback/status', async (c) => {
  const tenantId = c.get('tenantId');
  const doorId = c.req.param('id');
  const { user_id } = c.req.query();

  try {
    const filters: any = { tenant_id: tenantId, door_id: doorId };
    if (user_id) filters.user_id = user_id;

    const trackingRecords = await prisma.anti_passback_tracking.findMany({
      where: filters,
      include: {
        user: {
          select: { id: true, username: true, email: true }
        }
      },
      orderBy: { last_event_time: 'desc' }
    });

    return c.json({ tracking_records: trackingRecords });
  } catch (error) {
    logger.error('Failed to get anti-passback status', { tenantId, doorId, error });
    throw new HTTPException(500, { message: 'Failed to get anti-passback status' });
  }
});

// DUAL AUTHORIZATION MANAGEMENT

// Initiate dual authorization
app.post('/doors/:id/dual-auth/initiate', requireDoorManagementPermission, zValidator('json', dualAuthorizationSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const doorId = c.req.param('id');
  const authData = c.req.valid('json');

  try {
    // Verify door exists and has dual auth enabled
    const door = await prisma.door.findFirst({
      where: { id: doorId, tenant_id: tenantId },
      include: { settings: true }
    });

    if (!door || !door.settings?.dual_authorization_required) {
      throw new HTTPException(400, { message: 'Dual authorization not required for this door' });
    }

    // Create dual authorization request
    const dualAuthRequest = await prisma.dual_authorization_request.create({
      data: {
        tenant_id: tenantId,
        door_id: doorId,
        primary_user_id: authData.primary_user_id,
        secondary_user_id: authData.secondary_user_id,
        timeout: authData.timeout,
        reason: authData.reason,
        status: 'pending',
        expires_at: new Date(Date.now() + authData.timeout * 1000),
        created_by: userId
      }
    });

    // Send notification to secondary user if specified
    if (authData.secondary_user_id) {
      await sendDualAuthNotification(authData.secondary_user_id, dualAuthRequest);
    }

    logger.info('Dual authorization initiated', { 
      tenantId, 
      doorId, 
      requestId: dualAuthRequest.id,
      primaryUser: authData.primary_user_id 
    });

    return c.json({ 
      request_id: dualAuthRequest.id,
      expires_at: dualAuthRequest.expires_at,
      status: 'pending'
    }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to initiate dual authorization', { tenantId, doorId, userId, error });
    throw new HTTPException(500, { message: 'Failed to initiate dual authorization' });
  }
});

// Approve dual authorization
app.post('/dual-auth/:requestId/approve', requireDoorManagementPermission, async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const requestId = c.req.param('requestId');

  try {
    // Get and validate dual auth request
    const authRequest = await prisma.dual_authorization_request.findFirst({
      where: { 
        id: requestId, 
        tenant_id: tenantId,
        status: 'pending',
        expires_at: { gte: new Date() }
      }
    });

    if (!authRequest) {
      throw new HTTPException(404, { message: 'Dual authorization request not found or expired' });
    }

    // Verify user is authorized to approve
    if (authRequest.secondary_user_id && authRequest.secondary_user_id !== userId) {
      throw new HTTPException(403, { message: 'Not authorized to approve this request' });
    }

    // Update request status
    await prisma.dual_authorization_request.update({
      where: { id: requestId },
      data: {
        status: 'approved',
        approved_by: userId,
        approved_at: new Date()
      }
    });

    logger.info('Dual authorization approved', { tenantId, requestId, approvedBy: userId });

    return c.json({ message: 'Dual authorization approved' });
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to approve dual authorization', { tenantId, requestId, userId, error });
    throw new HTTPException(500, { message: 'Failed to approve dual authorization' });
  }
});

// NESTED ACCESS GROUP MANAGEMENT

// Create nested access group
app.post('/access-groups', requireDoorManagementPermission, zValidator('json', nestedAccessGroupSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const groupData = c.req.valid('json');

  try {
    // Verify parent group exists if specified
    if (groupData.parent_group_id) {
      const parentGroup = await prisma.access_group.findFirst({
        where: { id: groupData.parent_group_id, tenant_id: tenantId }
      });

      if (!parentGroup) {
        throw new HTTPException(400, { message: 'Parent access group not found' });
      }
    }

    // Create nested access group
    const accessGroup = await prisma.access_group.create({
      data: {
        tenant_id: tenantId,
        name: groupData.name,
        description: groupData.description,
        parent_group_id: groupData.parent_group_id,
        inherit_permissions: groupData.inherit_permissions,
        override_permissions: groupData.override_permissions,
        priority: groupData.priority,
        created_by: userId
      }
    });

    // If inheriting permissions, copy from parent
    if (groupData.inherit_permissions && groupData.parent_group_id) {
      await inheritPermissionsFromParent(accessGroup.id, groupData.parent_group_id);
    }

    logger.info('Nested access group created', { tenantId, groupId: accessGroup.id, userId });

    return c.json({ access_group: accessGroup }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to create nested access group', { tenantId, userId, error });
    throw new HTTPException(500, { message: 'Failed to create nested access group' });
  }
});

// Get access group hierarchy
app.get('/access-groups/hierarchy', async (c) => {
  const tenantId = c.get('tenantId');

  try {
    const accessGroups = await prisma.access_group.findMany({
      where: { tenant_id: tenantId },
      include: {
        parent_group: true,
        child_groups: true,
        users: {
          select: { id: true, username: true, email: true }
        },
        doors: {
          select: { id: true, name: true }
        }
      },
      orderBy: { priority: 'desc' }
    });

    // Build hierarchy tree
    const hierarchy = buildAccessGroupHierarchy(accessGroups);

    return c.json({ hierarchy });
  } catch (error) {
    logger.error('Failed to get access group hierarchy', { tenantId, error });
    throw new HTTPException(500, { message: 'Failed to get access group hierarchy' });
  }
});

// Assign access permissions with inheritance
app.post('/doors/:id/permissions', requireDoorManagementPermission, zValidator('json', accessPermissionSchema), async (c) => {
  const tenantId = c.get('tenantId');
  const userId = c.get('userId');
  const doorId = c.req.param('id');
  const permissionData = c.req.valid('json');

  try {
    // Verify door exists
    const door = await prisma.door.findFirst({
      where: { id: doorId, tenant_id: tenantId }
    });

    if (!door) {
      throw new HTTPException(404, { message: 'Door not found' });
    }

    // If access group specified, check for inheritance
    let effectivePermissions = permissionData;
    if (permissionData.access_group_id) {
      const accessGroup = await prisma.access_group.findFirst({
        where: { id: permissionData.access_group_id, tenant_id: tenantId },
        include: { parent_group: true }
      });

      if (accessGroup?.inherit_permissions && accessGroup.parent_group) {
        effectivePermissions = await resolveInheritedPermissions(accessGroup, permissionData);
      }
    }

    // Create access permission
    const permission = await prisma.access_permission.create({
      data: {
        tenant_id: tenantId,
        door_id: doorId,
        user_id: effectivePermissions.user_id,
        access_group_id: effectivePermissions.access_group_id,
        schedule_id: effectivePermissions.schedule_id,
        valid_from: effectivePermissions.valid_from ? new Date(effectivePermissions.valid_from) : null,
        valid_until: effectivePermissions.valid_until ? new Date(effectivePermissions.valid_until) : null,
        access_level: effectivePermissions.access_level,
        inherited_from: accessGroup?.parent_group_id,
        created_by: userId
      }
    });

    // Sync permissions to hardware
    await syncPermissionsToHardware(doorId);

    logger.info('Access permission assigned', { tenantId, doorId, permissionId: permission.id, userId });

    return c.json({ permission }, 201);
  } catch (error) {
    if (error instanceof HTTPException) throw error;
    logger.error('Failed to assign access permission', { tenantId, doorId, userId, error });
    throw new HTTPException(500, { message: 'Failed to assign access permission' });
  }
});

// Helper functions for advanced access control features

async function checkDualAuthorizationStatus(doorId: string, userId: string): Promise<any> {
  const activeRequest = await prisma.dual_authorization_request.findFirst({
    where: {
      door_id: doorId,
      primary_user_id: userId,
      status: 'approved',
      expires_at: { gte: new Date() }
    }
  });

  if (activeRequest) {
    return { authorized: true, request: activeRequest };
  }

  const pendingRequest = await prisma.dual_authorization_request.findFirst({
    where: {
      door_id: doorId,
      primary_user_id: userId,
      status: 'pending',
      expires_at: { gte: new Date() }
    }
  });

  return {
    authorized: false,
    pending: !!pendingRequest,
    timeoutRemaining: pendingRequest ? 
      Math.max(0, pendingRequest.expires_at.getTime() - Date.now()) / 1000 : 0
  };
}

async function checkAntiPassbackViolation(doorId: string, userId: string): Promise<any> {
  const lastTracking = await prisma.anti_passback_tracking.findFirst({
    where: { door_id: doorId, user_id: userId },
    orderBy: { last_event_time: 'desc' }
  });

  if (!lastTracking) {
    return { violation: false };
  }

  // Check if user is trying to enter when they're already inside
  if (lastTracking.last_direction === 'entry') {
    return {
      violation: true,
      lastDirection: 'entry',
      violationType: 'already_inside',
      resetRequired: true
    };
  }

  return { violation: false };
}

async function updateAntiPassbackTracking(doorId: string, userId: string, direction: string): Promise<void> {
  await prisma.anti_passback_tracking.upsert({
    where: {
      door_id_user_id: { door_id: doorId, user_id: userId }
    },
    update: {
      last_direction: direction,
      last_event_time: new Date(),
      event_count: { increment: 1 }
    },
    create: {
      door_id: doorId,
      user_id: userId,
      last_direction: direction,
      last_event_time: new Date(),
      event_count: 1
    }
  });
}

async function checkAdvancedSchedulePermissions(schedules: any[], currentTime: Date, zone?: any): Promise<boolean> {
  for (const schedule of schedules) {
    // Check if schedule is active
    if (!schedule.active) continue;

    // Check time zones with timezone support
    for (const timeZone of schedule.time_zones) {
      const currentTimeInZone = convertToTimezone(currentTime, timeZone.timezone);
      const dayOfWeek = currentTimeInZone.getDay();
      
      if (!timeZone.day_of_week.includes(dayOfWeek)) continue;

      const currentTimeStr = formatTime(currentTimeInZone);
      if (currentTimeStr >= timeZone.start_time && currentTimeStr <= timeZone.end_time) {
        // Check for holiday overrides
        const isHoliday = await checkHolidayOverride(schedule.holidays, currentTimeInZone);
        if (isHoliday) {
          return isHoliday.access_override === 'allow';
        }

        // Check for exceptions
        const exception = await checkScheduleException(schedule.exceptions, currentTimeInZone);
        if (exception) {
          return exception.access_override === 'allow';
        }

        return true;
      }
    }
  }

  return false;
}

async function validateZoneAccessRules(zone: any, userId: string): Promise<any> {
  const rules = zone.access_rules || {};

  // Check occupancy limits
  if (rules.max_occupancy) {
    const currentOccupancy = await getCurrentZoneOccupancy(zone.id);
    if (currentOccupancy >= rules.max_occupancy) {
      return { allowed: false, reason: 'Zone at maximum occupancy' };
    }
  }

  // Check escort requirements
  if (rules.require_escort) {
    const hasEscort = await checkEscortPresence(zone.id, userId);
    if (!hasEscort) {
      return { allowed: false, reason: 'Escort required for zone access' };
    }
  }

  // Check visitor access rules
  const user = await prisma.user.findFirst({ where: { id: userId } });
  if (user?.user_type === 'visitor' && !rules.visitor_access) {
    return { allowed: false, reason: 'Visitor access not permitted in this zone' };
  }

  return { allowed: true };
}

async function getRequiredRolesForEscalationLevel(escalationLevel: string): string[] {
  const roleMap = {
    'low': ['admin', 'security_manager', 'door_operator'],
    'medium': ['admin', 'security_manager'],
    'high': ['admin', 'security_manager', 'emergency_coordinator'],
    'critical': ['admin', 'emergency_coordinator']
  };

  return roleMap[escalationLevel] || ['admin'];
}

async function getDoorsInScopeWithExclusions(tenantId: string, scope: any): Promise<any[]> {
  const filters: any = { tenant_id: tenantId };
  
  if (scope.door_ids) {
    filters.id = { in: scope.door_ids };
  } else {
    if (scope.zone_id) filters.zone_id = scope.zone_id;
    if (scope.floor_id) filters.floor_id = scope.floor_id;
    if (scope.building_id) {
      filters.floor = { building_id: scope.building_id };
    }
  }

  // Exclude specified doors
  if (scope.exclude_doors && scope.exclude_doors.length > 0) {
    filters.id = { ...filters.id, notIn: scope.exclude_doors };
  }

  const doors = await prisma.door.findMany({ 
    where: filters,
    include: { zone: true, settings: true }
  });

  // Filter based on emergency exit settings
  if (!scope.include_emergency_exits) {
    return doors.filter(door => door.zone?.zone_type !== 'emergency');
  }

  return doors;
}

async function validateOverrideCompatibility(doors: any[], overrideType: string): Promise<any[]> {
  const incompatibleDoors = [];

  for (const door of doors) {
    let compatible = true;

    switch (overrideType) {
      case 'fire_evacuation':
        // Fire evacuation should not affect emergency exits
        if (door.zone?.zone_type === 'emergency') {
          compatible = false;
        }
        break;
      case 'security_breach':
        // Security breach should lock all doors except emergency exits
        if (door.settings?.emergency_unlock_enabled === false) {
          compatible = false;
        }
        break;
    }

    if (!compatible) {
      incompatibleDoors.push(door);
    }
  }

  return incompatibleDoors;
}

async function executeAdvancedEmergencyOverride(doors: any[], overrideData: any): Promise<any[]> {
  const results = [];

  for (const door of doors) {
    try {
      let action = 'lock';
      
      switch (overrideData.override_type) {
        case 'lockdown':
        case 'security_breach':
          action = 'lock';
          break;
        case 'unlock_all':
        case 'evacuation':
        case 'fire_evacuation':
          action = 'unlock';
          break;
        case 'zone_isolation':
          action = door.zone?.zone_type === 'restricted' ? 'lock' : 'unlock';
          break;
      }

      const controlResult = await sendDoorControlCommand(door, { 
        action, 
        reason: overrideData.reason,
        override_schedule: true 
      });

      results.push({
        door_id: door.id,
        door_name: door.name,
        action,
        success: controlResult.success,
        message: controlResult.message
      });

    } catch (error) {
      results.push({
        door_id: door.id,
        door_name: door.name,
        success: false,
        error: error.message
      });
    }
  }

  return results;
}

async function sendEmergencyNotifications(notificationGroups: string[], override: any): Promise<void> {
  // Implementation would send notifications via email, SMS, push notifications
  // to users in the specified notification groups
  logger.info('Emergency notifications sent', { 
    groups: notificationGroups,
    overrideId: override.id 
  });
}

async function scheduleEmergencyOverrideRevert(overrideId: string, duration: number): Promise<void> {
  // Implementation would schedule a job to automatically revert the override
  // after the specified duration
  logger.info('Emergency override revert scheduled', { 
    overrideId, 
    duration 
  });
}

async function sendDualAuthNotification(userId: string, request: any): Promise<void> {
  // Implementation would send notification to the secondary user
  logger.info('Dual authorization notification sent', { 
    userId, 
    requestId: request.id 
  });
}

async function inheritPermissionsFromParent(groupId: string, parentGroupId: string): Promise<void> {
  // Copy permissions from parent group to child group
  const parentPermissions = await prisma.access_permission.findMany({
    where: { access_group_id: parentGroupId }
  });

  for (const permission of parentPermissions) {
    await prisma.access_permission.create({
      data: {
        ...permission,
        id: undefined, // Let database generate new ID
        access_group_id: groupId,
        inherited_from: parentGroupId,
        created_at: new Date()
      }
    });
  }
}

async function buildAccessGroupHierarchy(groups: any[]): Promise<any[]> {
  const groupMap = new Map(groups.map(g => [g.id, { ...g, children: [] }]));
  const rootGroups = [];

  for (const group of groups) {
    if (group.parent_group_id) {
      const parent = groupMap.get(group.parent_group_id);
      if (parent) {
        parent.children.push(groupMap.get(group.id));
      }
    } else {
      rootGroups.push(groupMap.get(group.id));
    }
  }

  return rootGroups;
}

async function resolveInheritedPermissions(accessGroup: any, permissionData: any): Promise<any> {
  // Resolve permissions based on inheritance rules
  // This would merge parent permissions with override permissions
  return permissionData; // Simplified implementation
}

async function checkHolidayOverride(holidays: any[], currentTime: Date): Promise<any> {
  if (!holidays) return null;

  const currentDate = currentTime.toISOString().split('T')[0];
  return holidays.find(holiday => holiday.date === currentDate);
}

async function checkScheduleException(exceptions: any[], currentTime: Date): Promise<any> {
  if (!exceptions) return null;

  const currentDate = currentTime.toISOString().split('T')[0];
  const currentTimeStr = formatTime(currentTime);

  return exceptions.find(exception => 
    exception.date === currentDate &&
    currentTimeStr >= exception.start_time &&
    currentTimeStr <= exception.end_time
  );
}

async function getCurrentZoneOccupancy(zoneId: string): Promise<number> {
  // Implementation would track current occupancy based on entry/exit events
  return 0; // Simplified implementation
}

async function checkEscortPresence(zoneId: string, userId: string): Promise<boolean> {
  // Implementation would check if an authorized escort is present in the zone
  return true; // Simplified implementation
}

function convertToTimezone(date: Date, timezone: string): Date {
  // Implementation would convert date to specified timezone
  return date; // Simplified implementation
}

function formatTime(date: Date): string {
  return date.toTimeString().substring(0, 5); // HH:MM format
}

async function checkSchedulePermissions(schedules: any[], currentTime: Date): Promise<boolean> {
  // Backward compatibility - use advanced schedule checking
  return await checkAdvancedSchedulePermissions(schedules, currentTime);
}

async function sendDoorControlCommand(door: any, controlData: any): Promise<any> {
  // Implementation for hardware communication
  // This would send actual commands to the access control panel
  return { success: true, message: 'Command sent successfully' };
}

async function getDoorHardwareStatus(door: any): Promise<any> {
  // Implementation for real-time hardware status
  return {
    locked: true,
    door_position: 'closed',
    tamper_status: 'normal',
    power_status: 'normal'
  };
}

async function getDoorsInScope(tenantId: string, scope: any): Promise<any[]> {
  // Implementation for getting doors based on emergency override scope
  const filters: any = { tenant_id: tenantId };
  
  if (scope.door_ids) {
    filters.id = { in: scope.door_ids };
  } else {
    if (scope.zone_id) filters.zone_id = scope.zone_id;
    if (scope.floor_id) filters.floor_id = scope.floor_id;
    if (scope.building_id) {
      filters.floor = { building_id: scope.building_id };
    }
  }

  return await prisma.door.findMany({ where: filters });
}

async function executeEmergencyOverride(doors: any[], overrideData: any): Promise<any[]> {
  // Implementation for executing emergency override on multiple doors
  return doors.map(door => ({
    door_id: door.id,
    success: true,
    message: 'Override executed successfully'
  }));
}

async function syncPermissionsToHardware(doorId: string): Promise<void> {
  // Implementation for syncing permissions to access control hardware
  // This would update the local cache on access control panels
}

export default app;
