import { io, Socket } from 'socket.io-client';
import { v4 as uuidv4 } from 'uuid';
import {
  // Types
  ApiResponse,
  PaginatedResponse,
  ListQueryParams,
  LoginRequest,
  LoginResponse,
  RefreshTokenRequest,
  ChangePasswordRequest,
  RealtimeEvent,
  AccessEventRealtime,
  AlertRealtime,
  DeviceStatusRealtime,
  VideoStream,
  VideoPlaybackRequest,
  DashboardLayout,
  
  // Entity types
  Tenant,
  Organization,
  Site,
  Building,
  Floor,
  Zone,
  Door,
  User,
  Camera,
  AccessEvent,
  AccessPanel,
  CardReader,
  Credential,
  AccessGroup,
  Schedule,
  Alert,
  AuditLog,
  VideoRecording,
  Visitor,
  MaintenanceWorkOrder,
  IncidentReport,
  EnvironmentalSensor,
  EnvironmentalReading,
  MobileCredential,
  PrivacyMask,
  VideoExportLog,
  ElevatorControl,
  SystemConfiguration,
  
  // DTO types
  CreateTenantDTO,
  UpdateTenantDTO,
  CreateOrganizationDTO,
  UpdateOrganizationDTO,
  CreateSiteDTO,
  UpdateSiteDTO,
  CreateBuildingDTO,
  UpdateBuildingDTO,
  CreateFloorDTO,
  UpdateFloorDTO,
  CreateZoneDTO,
  UpdateZoneDTO,
  CreateDoorDTO,
  UpdateDoorDTO,
  CreateUserDTO,
  UpdateUserDTO,
  CreateCameraDTO,
  UpdateCameraDTO,
  CreateAccessEventDTO,
  CreateAccessPanelDTO,
  UpdateAccessPanelDTO,
  CreateCardReaderDTO,
  UpdateCardReaderDTO,
  CreateCredentialDTO,
  UpdateCredentialDTO,
  CreateAccessGroupDTO,
  UpdateAccessGroupDTO,
  CreateScheduleDTO,
  UpdateScheduleDTO,
  CreateAlertDTO,
  UpdateAlertDTO,
  CreateAuditLogDTO,
  CreateVideoRecordingDTO,
  UpdateVideoRecordingDTO,
  CreateVisitorDTO,
  UpdateVisitorDTO,
  CreateMaintenanceWorkOrderDTO,
  UpdateMaintenanceWorkOrderDTO,
  CreateIncidentReportDTO,
  UpdateIncidentReportDTO,
  CreateEnvironmentalSensorDTO,
  UpdateEnvironmentalSensorDTO,
  CreateEnvironmentalReadingDTO,
  CreateMobileCredentialDTO,
  UpdateMobileCredentialDTO,
  CreatePrivacyMaskDTO,
  UpdatePrivacyMaskDTO,
  CreateVideoExportLogDTO,
  UpdateVideoExportLogDTO,
  CreateElevatorControlDTO,
  UpdateElevatorControlDTO,
  CreateSystemConfigurationDTO,
  UpdateSystemConfigurationDTO,
} from '@sparc/shared';

// Configuration interface
interface ApiConfig {
  baseUrl: string;
  timeout: number;
  retries: number;
  retryDelay: number;
  enableLogging: boolean;
}

// Request configuration interface
interface RequestConfig {
  timeout?: number;
  retries?: number;
  skipAuth?: boolean;
  skipTenant?: boolean;
  signal?: AbortSignal;
}

// Authentication context interface
interface AuthContext {
  accessToken: string | null;
  refreshToken: string | null;
  user: User | null;
  tenant: Tenant | null;
  expiresAt: number | null;
}

// Tenant context interface
interface TenantContext {
  tenantId: string | null;
  tenant: Tenant | null;
}

// Error types
class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
    public details?: Record<string, any>,
    public requestId?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

class NetworkError extends Error {
  constructor(message: string, public originalError: Error) {
    super(message);
    this.name = 'NetworkError';
  }
}

class AuthenticationError extends ApiError {
  constructor(message: string, requestId?: string) {
    super('AUTHENTICATION_ERROR', message, 401, undefined, requestId);
    this.name = 'AuthenticationError';
  }
}

class AuthorizationError extends ApiError {
  constructor(message: string, requestId?: string) {
    super('AUTHORIZATION_ERROR', message, 403, undefined, requestId);
    this.name = 'AuthorizationError';
  }
}

// Default configuration
const defaultConfig: ApiConfig = {
  baseUrl: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
  timeout: 30000,
  retries: 3,
  retryDelay: 1000,
  enableLogging: process.env.NODE_ENV === 'development',
};

// Storage keys - Only store non-sensitive data
const STORAGE_KEYS = {
  USER: 'sparc_user',
  TENANT: 'sparc_tenant',
  TENANT_ID: 'sparc_tenant_id',
} as const;

// Event listeners
type EventListener<T = any> = (data: T) => void;
type EventListeners = {
  [K in keyof RealtimeEventMap]: EventListener<RealtimeEventMap[K]>[];
};

interface RealtimeEventMap {
  'access_event': AccessEventRealtime;
  'alert': AlertRealtime;
  'device_status': DeviceStatusRealtime;
  'connect': void;
  'disconnect': void;
  'error': Error;
}

class ApiClient {
  private config: ApiConfig;
  private authContext: AuthContext = {
    accessToken: null, // No longer stored, managed by HttpOnly cookies
    refreshToken: null, // No longer stored, managed by HttpOnly cookies
    user: null,
    tenant: null,
    expiresAt: null, // No longer stored, managed by HttpOnly cookies
  };
  private tenantContext: TenantContext = {
    tenantId: null,
    tenant: null,
  };
  private socket: Socket | null = null;
  private eventListeners: EventListeners = {
    access_event: [],
    alert: [],
    device_status: [],
    connect: [],
    disconnect: [],
    error: [],
  };
  private refreshPromise: Promise<void> | null = null;

  constructor(config: Partial<ApiConfig> = {}) {
    this.config = { ...defaultConfig, ...config };
    this.loadAuthFromStorage();
    this.loadTenantFromStorage();
  }

  // Storage management
  private loadAuthFromStorage(): void {
    if (typeof window === 'undefined') return;

    try {
      // Only load non-sensitive user and tenant data
      const userStr = localStorage.getItem(STORAGE_KEYS.USER);
      const tenantStr = localStorage.getItem(STORAGE_KEYS.TENANT);

      this.authContext = {
        accessToken: null, // Managed by HttpOnly cookies
        refreshToken: null, // Managed by HttpOnly cookies
        user: userStr ? JSON.parse(userStr) : null,
        tenant: tenantStr ? JSON.parse(tenantStr) : null,
        expiresAt: null, // Managed by HttpOnly cookies
      };
    } catch (error) {
      this.log('Error loading auth from storage:', error);
      this.clearAuthStorage();
    }
  }

  private saveAuthToStorage(): void {
    if (typeof window === 'undefined') return;

    try {
      // Only save non-sensitive user and tenant data
      if (this.authContext.user) {
        localStorage.setItem(STORAGE_KEYS.USER, JSON.stringify(this.authContext.user));
      } else {
        localStorage.removeItem(STORAGE_KEYS.USER);
      }

      if (this.authContext.tenant) {
        localStorage.setItem(STORAGE_KEYS.TENANT, JSON.stringify(this.authContext.tenant));
      } else {
        localStorage.removeItem(STORAGE_KEYS.TENANT);
      }
    } catch (error) {
      this.log('Error saving auth to storage:', error);
    }
  }

  private clearAuthStorage(): void {
    if (typeof window === 'undefined') return;

    Object.values(STORAGE_KEYS).forEach(key => {
      localStorage.removeItem(key);
    });
  }

  private getCSRFToken(): string | null {
    if (typeof document === 'undefined') return null;
    
    // Get CSRF token from cookie
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrfToken') {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  private loadTenantFromStorage(): void {
    if (typeof window === 'undefined') return;

    try {
      const tenantId = localStorage.getItem(STORAGE_KEYS.TENANT_ID);
      this.tenantContext.tenantId = tenantId;
      
      if (this.authContext.tenant && this.authContext.tenant.id === tenantId) {
        this.tenantContext.tenant = this.authContext.tenant;
      }
    } catch (error) {
      this.log('Error loading tenant from storage:', error);
    }
  }

  private saveTenantToStorage(): void {
    if (typeof window === 'undefined') return;

    try {
      if (this.tenantContext.tenantId) {
        localStorage.setItem(STORAGE_KEYS.TENANT_ID, this.tenantContext.tenantId);
      } else {
        localStorage.removeItem(STORAGE_KEYS.TENANT_ID);
      }
    } catch (error) {
      this.log('Error saving tenant to storage:', error);
    }
  }

  // Logging utility
  private log(...args: any[]): void {
    if (this.config.enableLogging) {
      console.log('[ApiClient]', ...args);
    }
  }

  // Authentication methods
  isAuthenticated(): boolean {
    // Since tokens are in HttpOnly cookies, we rely on the presence of user data
    // The actual authentication check happens server-side
    return !!this.authContext.user;
  }

  getUser(): User | null {
    return this.authContext.user;
  }

  getTenant(): Tenant | null {
    return this.tenantContext.tenant || this.authContext.tenant;
  }

  getCurrentTenantId(): string | null {
    return this.tenantContext.tenantId || this.authContext.tenant?.id || null;
  }

  async setTenant(tenantId: string): Promise<void> {
    this.tenantContext.tenantId = tenantId;
    this.saveTenantToStorage();
    
    // Fetch tenant details if not already available
    if (!this.tenantContext.tenant || this.tenantContext.tenant.id !== tenantId) {
      try {
        const tenant = await this.get<Tenant>(`/api/v1/tenants/${tenantId}`);
        this.tenantContext.tenant = tenant;
      } catch (error) {
        this.log('Error fetching tenant details:', error);
      }
    }

    // Reconnect socket with new tenant context
    if (this.socket) {
      this.disconnectRealtime();
      this.connectRealtime();
    }
  }

  private async refreshAccessToken(): Promise<void> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      try {
        // Refresh token is sent via HttpOnly cookie automatically
        const response = await this.request<LoginResponse>('/api/v1/auth/refresh-token', {
          method: 'POST',
          body: JSON.stringify({}), // Empty body, cookies are sent automatically
          skipAuth: true,
          credentials: 'include', // Ensure cookies are sent
        });

        // Only update user data, tokens are managed by cookies
        this.authContext.user = response.user;
        this.authContext.tenant = response.tenant;

        this.saveAuthToStorage();
        this.log('Access token refreshed successfully');
      } catch (error) {
        this.log('Failed to refresh access token:', error);
        this.logout();
        throw new AuthenticationError('Failed to refresh access token');
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  // Core request method
  private async request<T>(
    endpoint: string,
    options: RequestInit & RequestConfig = {}
  ): Promise<T> {
    const {
      timeout = this.config.timeout,
      retries = this.config.retries,
      skipAuth = false,
      skipTenant = false,
      signal,
      ...fetchOptions
    } = options;

    const url = `${this.config.baseUrl}${endpoint}`;
    const requestId = uuidv4();

    // Prepare headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Request-ID': requestId,
      ...((fetchOptions.headers as Record<string, string>) || {}),
    };

    // Authentication is handled by HttpOnly cookies
    // Add CSRF token for state-changing requests
    if (!skipAuth && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(fetchOptions.method || 'GET')) {
      // Get CSRF token from cookie
      const csrfToken = this.getCSRFToken();
      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }
    }

    // Add tenant header
    if (!skipTenant && this.getCurrentTenantId()) {
      headers['X-Tenant-ID'] = this.getCurrentTenantId()!;
    }

    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    // Combine signals
    const combinedSignal = signal ? 
      AbortSignal.any([signal, controller.signal]) : 
      controller.signal;

    const requestOptions: RequestInit = {
      ...fetchOptions,
      headers,
      signal: combinedSignal,
      credentials: 'include', // Always include cookies for authentication
    };

    let lastError: Error | null = null;

    // Retry logic
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        this.log(`Making request to ${endpoint} (attempt ${attempt}/${retries})`);

        const response = await fetch(url, requestOptions);
        clearTimeout(timeoutId);

        const responseText = await response.text();
        let responseData: any;

        try {
          responseData = responseText ? JSON.parse(responseText) : null;
        } catch (parseError) {
          responseData = responseText;
        }

        if (!response.ok) {
          const requestId = response.headers.get('X-Request-ID');
          
          if (response.status === 401) {
            // Try to refresh token once
            if (!skipAuth && attempt === 1) {
              try {
                await this.refreshAccessToken();
                // Retry the request with refreshed cookies
                continue;
              } catch (refreshError) {
                this.logout();
                throw new AuthenticationError(
                  responseData?.message || 'Authentication failed',
                  requestId || undefined
                );
              }
            } else {
              this.logout();
              throw new AuthenticationError(
                responseData?.message || 'Authentication failed',
                requestId || undefined
              );
            }
          }

          if (response.status === 403) {
            // Handle CSRF token errors specifically
            if (responseData?.error === 'CSRF_TOKEN_MISSING' || responseData?.error === 'CSRF_TOKEN_INVALID') {
              // Try to refresh token to get a new CSRF token
              if (!skipAuth && attempt === 1) {
                try {
                  await this.refreshAccessToken();
                  // Retry the request with refreshed cookies
                  continue;
                } catch (refreshError) {
                  throw new AuthorizationError(
                    'CSRF token invalid. Please refresh the page.',
                    requestId || undefined
                  );
                }
              }
            }
            
            throw new AuthorizationError(
              responseData?.message || 'Access denied',
              requestId || undefined
            );
          }

          throw new ApiError(
            responseData?.error || 'API_ERROR',
            responseData?.message || `HTTP ${response.status}`,
            response.status,
            responseData?.details,
            requestId || undefined
          );
        }

        this.log(`Request to ${endpoint} completed successfully`);
        return responseData;

      } catch (error) {
        clearTimeout(timeoutId);
        lastError = error as Error;

        if (error instanceof ApiError || error instanceof AuthenticationError || error instanceof AuthorizationError) {
          throw error;
        }

        if (error instanceof DOMException && error.name === 'AbortError') {
          throw new NetworkError('Request timeout', error);
        }

        this.log(`Request to ${endpoint} failed (attempt ${attempt}/${retries}):`, error);

        if (attempt === retries) {
          break;
        }

        // Exponential backoff
        await new Promise(resolve => 
          setTimeout(resolve, this.config.retryDelay * Math.pow(2, attempt - 1))
        );
      }
    }

    throw new NetworkError(
      `Request failed after ${retries} attempts`,
      lastError || new Error('Unknown error')
    );
  }

  // HTTP method helpers
  async get<T>(endpoint: string, config?: RequestConfig): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET', ...config });
  }

  async post<T>(endpoint: string, data?: any, config?: RequestConfig): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
      ...config,
    });
  }

  async put<T>(endpoint: string, data?: any, config?: RequestConfig): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
      ...config,
    });
  }

  async patch<T>(endpoint: string, data?: any, config?: RequestConfig): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
      ...config,
    });
  }

  async delete<T>(endpoint: string, config?: RequestConfig): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE', ...config });
  }

  // Paginated requests
  async getPaginated<T>(
    endpoint: string,
    params?: ListQueryParams,
    config?: RequestConfig
  ): Promise<PaginatedResponse<T>> {
    const searchParams = new URLSearchParams();
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          if (typeof value === 'object') {
            searchParams.append(key, JSON.stringify(value));
          } else {
            searchParams.append(key, value.toString());
          }
        }
      });
    }

    const url = searchParams.toString() ? `${endpoint}?${searchParams}` : endpoint;
    return this.get<PaginatedResponse<T>>(url, config);
  }

  // Authentication API methods
  async login(credentials: LoginRequest): Promise<LoginResponse> {
    const response = await this.post<LoginResponse>('/api/v1/auth/login', credentials, { 
      skipAuth: true,
      credentials: 'include' // Ensure cookies are set
    });
    
    // Only store user and tenant data, tokens are in HttpOnly cookies
    this.authContext.user = response.user;
    this.authContext.tenant = response.tenant;

    this.saveAuthToStorage();

    // Set tenant context
    if (response.tenant) {
      this.tenantContext.tenantId = response.tenant.id;
      this.tenantContext.tenant = response.tenant;
      this.saveTenantToStorage();
    }

    this.log('User logged in successfully');
    return response;
  }

  async logout(): Promise<void> {
    try {
      // Always attempt logout to clear server-side session and cookies
      await this.post('/api/v1/auth/logout', {}, { 
        timeout: 5000,
        credentials: 'include' 
      });
    } catch (error) {
      this.log('Error during logout:', error);
    } finally {
      this.authContext = {
        accessToken: null,
        refreshToken: null,
        user: null,
        tenant: null,
        expiresAt: null,
      };
      this.tenantContext = {
        tenantId: null,
        tenant: null,
      };
      this.clearAuthStorage();
      this.disconnectRealtime();
      this.log('User logged out');
    }
  }

  async changePassword(data: ChangePasswordRequest): Promise<void> {
    await this.post('/api/v1/auth/change-password', data);
  }

  async getCurrentUser(): Promise<User> {
    const user = await this.get<User>('/api/v1/auth/me');
    this.authContext.user = user;
    this.saveAuthToStorage();
    return user;
  }

  // Tenant API methods
  async getTenants(params?: ListQueryParams): Promise<PaginatedResponse<Tenant>> {
    return this.getPaginated<Tenant>('/api/v1/tenants', params);
  }

  async getTenantById(id: string): Promise<Tenant> {
    return this.get<Tenant>(`/api/v1/tenants/${id}`);
  }

  async createTenant(data: CreateTenantDTO): Promise<Tenant> {
    return this.post<Tenant>('/api/v1/tenants', data);
  }

  async updateTenant(id: string, data: UpdateTenantDTO): Promise<Tenant> {
    return this.put<Tenant>(`/api/v1/tenants/${id}`, data);
  }

  async deleteTenant(id: string): Promise<void> {
    await this.delete(`/api/v1/tenants/${id}`);
  }

  // Organization API methods
  async getOrganizations(params?: ListQueryParams): Promise<PaginatedResponse<Organization>> {
    return this.getPaginated<Organization>('/api/v1/organizations', params);
  }

  async getOrganizationById(id: string): Promise<Organization> {
    return this.get<Organization>(`/api/v1/organizations/${id}`);
  }

  async createOrganization(data: CreateOrganizationDTO): Promise<Organization> {
    return this.post<Organization>('/api/v1/organizations', data);
  }

  async updateOrganization(id: string, data: UpdateOrganizationDTO): Promise<Organization> {
    return this.put<Organization>(`/api/v1/organizations/${id}`, data);
  }

  async deleteOrganization(id: string): Promise<void> {
    await this.delete(`/api/v1/organizations/${id}`);
  }

  // Site API methods
  async getSites(params?: ListQueryParams): Promise<PaginatedResponse<Site>> {
    return this.getPaginated<Site>('/api/v1/sites', params);
  }

  async getSiteById(id: string): Promise<Site> {
    return this.get<Site>(`/api/v1/sites/${id}`);
  }

  async createSite(data: CreateSiteDTO): Promise<Site> {
    return this.post<Site>('/api/v1/sites', data);
  }

  async updateSite(id: string, data: UpdateSiteDTO): Promise<Site> {
    return this.put<Site>(`/api/v1/sites/${id}`, data);
  }

  async deleteSite(id: string): Promise<void> {
    await this.delete(`/api/v1/sites/${id}`);
  }

  // Building API methods
  async getBuildings(params?: ListQueryParams): Promise<PaginatedResponse<Building>> {
    return this.getPaginated<Building>('/api/v1/buildings', params);
  }

  async getBuildingById(id: string): Promise<Building> {
    return this.get<Building>(`/api/v1/buildings/${id}`);
  }

  async createBuilding(data: CreateBuildingDTO): Promise<Building> {
    return this.post<Building>('/api/v1/buildings', data);
  }

  async updateBuilding(id: string, data: UpdateBuildingDTO): Promise<Building> {
    return this.put<Building>(`/api/v1/buildings/${id}`, data);
  }

  async deleteBuilding(id: string): Promise<void> {
    await this.delete(`/api/v1/buildings/${id}`);
  }

  // Floor API methods
  async getFloors(params?: ListQueryParams): Promise<PaginatedResponse<Floor>> {
    return this.getPaginated<Floor>('/api/v1/floors', params);
  }

  async getFloorById(id: string): Promise<Floor> {
    return this.get<Floor>(`/api/v1/floors/${id}`);
  }

  async createFloor(data: CreateFloorDTO): Promise<Floor> {
    return this.post<Floor>('/api/v1/floors', data);
  }

  async updateFloor(id: string, data: UpdateFloorDTO): Promise<Floor> {
    return this.put<Floor>(`/api/v1/floors/${id}`, data);
  }

  async deleteFloor(id: string): Promise<void> {
    await this.delete(`/api/v1/floors/${id}`);
  }

  // Zone API methods
  async getZones(params?: ListQueryParams): Promise<PaginatedResponse<Zone>> {
    return this.getPaginated<Zone>('/api/v1/zones', params);
  }

  async getZoneById(id: string): Promise<Zone> {
    return this.get<Zone>(`/api/v1/zones/${id}`);
  }

  async createZone(data: CreateZoneDTO): Promise<Zone> {
    return this.post<Zone>('/api/v1/zones', data);
  }

  async updateZone(id: string, data: UpdateZoneDTO): Promise<Zone> {
    return this.put<Zone>(`/api/v1/zones/${id}`, data);
  }

  async deleteZone(id: string): Promise<void> {
    await this.delete(`/api/v1/zones/${id}`);
  }

  // Door API methods
  async getDoors(params?: ListQueryParams): Promise<PaginatedResponse<Door>> {
    return this.getPaginated<Door>('/api/v1/doors', params);
  }

  async getDoorById(id: string): Promise<Door> {
    return this.get<Door>(`/api/v1/doors/${id}`);
  }

  async createDoor(data: CreateDoorDTO): Promise<Door> {
    return this.post<Door>('/api/v1/doors', data);
  }

  async updateDoor(id: string, data: UpdateDoorDTO): Promise<Door> {
    return this.put<Door>(`/api/v1/doors/${id}`, data);
  }

  async deleteDoor(id: string): Promise<void> {
    await this.delete(`/api/v1/doors/${id}`);
  }

  async unlockDoor(id: string): Promise<void> {
    await this.post(`/api/v1/doors/${id}/unlock`);
  }

  async lockDoor(id: string): Promise<void> {
    await this.post(`/api/v1/doors/${id}/lock`);
  }

  async getDoorStatus(id: string): Promise<{ status: string; timestamp: string }> {
    return this.get(`/api/v1/doors/${id}/status`);
  }

  // Camera API methods
  async getCameras(params?: ListQueryParams): Promise<PaginatedResponse<Camera>> {
    return this.getPaginated<Camera>('/api/v1/cameras', params);
  }

  async getCameraById(id: string): Promise<Camera> {
    return this.get<Camera>(`/api/v1/cameras/${id}`);
  }

  async createCamera(data: CreateCameraDTO): Promise<Camera> {
    return this.post<Camera>('/api/v1/cameras', data);
  }

  async updateCamera(id: string, data: UpdateCameraDTO): Promise<Camera> {
    return this.put<Camera>(`/api/v1/cameras/${id}`, data);
  }

  async deleteCamera(id: string): Promise<void> {
    await this.delete(`/api/v1/cameras/${id}`);
  }

  async getCameraStream(id: string, resolution?: 'high' | 'medium' | 'low'): Promise<VideoStream> {
    const params = resolution ? `?resolution=${resolution}` : '';
    return this.get<VideoStream>(`/api/v1/cameras/${id}/stream${params}`);
  }

  async startRecording(id: string): Promise<void> {
    await this.post(`/api/v1/cameras/${id}/record/start`);
  }

  async stopRecording(id: string): Promise<void> {
    await this.post(`/api/v1/cameras/${id}/record/stop`);
  }

  // Access Event API methods
  async getAccessEvents(params?: ListQueryParams): Promise<PaginatedResponse<AccessEvent>> {
    return this.getPaginated<AccessEvent>('/api/v1/access-events', params);
  }

  async getAccessEventById(id: string): Promise<AccessEvent> {
    return this.get<AccessEvent>(`/api/v1/access-events/${id}`);
  }

  async createAccessEvent(data: CreateAccessEventDTO): Promise<AccessEvent> {
    return this.post<AccessEvent>('/api/v1/access-events', data);
  }

  // Alert API methods
  async getAlerts(params?: ListQueryParams): Promise<PaginatedResponse<Alert>> {
    return this.getPaginated<Alert>('/api/v1/alerts', params);
  }

  async getAlertById(id: string): Promise<Alert> {
    return this.get<Alert>(`/api/v1/alerts/${id}`);
  }

  async acknowledgeAlert(id: string): Promise<Alert> {
    return this.post<Alert>(`/api/v1/alerts/${id}/acknowledge`);
  }

  async resolveAlert(id: string): Promise<Alert> {
    return this.post<Alert>(`/api/v1/alerts/${id}/resolve`);
  }

  // Video Recording API methods
  async getVideoRecordings(params?: ListQueryParams): Promise<PaginatedResponse<VideoRecording>> {
    return this.getPaginated<VideoRecording>('/api/v1/recordings', params);
  }

  async getVideoRecordingById(id: string): Promise<VideoRecording> {
    return this.get<VideoRecording>(`/api/v1/recordings/${id}`);
  }

  async requestVideoPlayback(request: VideoPlaybackRequest): Promise<{ playback_url: string }> {
    return this.post('/api/v1/recordings/playback', request);
  }

  async exportVideo(data: CreateVideoExportLogDTO): Promise<VideoExportLog> {
    return this.post<VideoExportLog>('/api/v1/recordings/export', data);
  }

  // Visitor API methods
  async getVisitors(params?: ListQueryParams): Promise<PaginatedResponse<Visitor>> {
    return this.getPaginated<Visitor>('/api/v1/visitors', params);
  }

  async getVisitorById(id: string): Promise<Visitor> {
    return this.get<Visitor>(`/api/v1/visitors/${id}`);
  }

  async createVisitor(data: CreateVisitorDTO): Promise<Visitor> {
    return this.post<Visitor>('/api/v1/visitors', data);
  }

  async updateVisitor(id: string, data: UpdateVisitorDTO): Promise<Visitor> {
    return this.put<Visitor>(`/api/v1/visitors/${id}`, data);
  }

  async checkInVisitor(id: string): Promise<Visitor> {
    return this.post<Visitor>(`/api/v1/visitors/${id}/checkin`);
  }

  async checkOutVisitor(id: string): Promise<Visitor> {
    return this.post<Visitor>(`/api/v1/visitors/${id}/checkout`);
  }

  // Dashboard API methods
  async getDashboardLayouts(): Promise<DashboardLayout[]> {
    return this.get<DashboardLayout[]>('/api/v1/dashboards/layouts');
  }

  async saveDashboardLayout(layout: Omit<DashboardLayout, 'id'>): Promise<DashboardLayout> {
    return this.post<DashboardLayout>('/api/v1/dashboards/layouts', layout);
  }

  async updateDashboardLayout(id: string, layout: Partial<DashboardLayout>): Promise<DashboardLayout> {
    return this.put<DashboardLayout>(`/api/v1/dashboards/layouts/${id}`, layout);
  }

  async deleteDashboardLayout(id: string): Promise<void> {
    await this.delete(`/api/v1/dashboards/layouts/${id}`);
  }

  // Real-time connection methods
  connectRealtime(): void {
    if (this.socket?.connected) {
      return;
    }

    const socketUrl = this.config.baseUrl.replace(/^http/, 'ws');
    
    this.socket = io(socketUrl, {
      auth: {
        token: this.authContext.accessToken,
        tenantId: this.getCurrentTenantId(),
      },
      transports: ['websocket', 'polling'],
      timeout: 20000,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    this.socket.on('connect', () => {
      this.log('Real-time connection established');
      this.emit('connect', undefined);
    });

    this.socket.on('disconnect', (reason) => {
      this.log('Real-time connection disconnected:', reason);
      this.emit('disconnect', undefined);
    });

    this.socket.on('error', (error) => {
      this.log('Real-time connection error:', error);
      this.emit('error', error);
    });

    this.socket.on('access_event', (data: AccessEventRealtime) => {
      this.emit('access_event', data);
    });

    this.socket.on('alert', (data: AlertRealtime) => {
      this.emit('alert', data);
    });

    this.socket.on('device_status', (data: DeviceStatusRealtime) => {
      this.emit('device_status', data);
    });
  }

  disconnectRealtime(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.log('Real-time connection disconnected');
    }
  }

  isRealtimeConnected(): boolean {
    return this.socket?.connected || false;
  }

  // Event listener methods
  on<K extends keyof RealtimeEventMap>(
    event: K,
    listener: EventListener<RealtimeEventMap[K]>
  ): void {
    this.eventListeners[event].push(listener as any);
  }

  off<K extends keyof RealtimeEventMap>(
    event: K,
    listener: EventListener<RealtimeEventMap[K]>
  ): void {
    const listeners = this.eventListeners[event];
    const index = listeners.indexOf(listener as any);
    if (index > -1) {
      listeners.splice(index, 1);
    }
  }

  private emit<K extends keyof RealtimeEventMap>(
    event: K,
    data: RealtimeEventMap[K]
  ): void {
    this.eventListeners[event].forEach(listener => {
      try {
        listener(data);
      } catch (error) {
        this.log(`Error in event listener for ${event}:`, error);
      }
    });
  }

  // Utility methods
  async healthCheck(): Promise<{ status: string; services: Record<string, any> }> {
    return this.get('/health', { skipAuth: true, skipTenant: true });
  }

  setConfig(config: Partial<ApiConfig>): void {
    this.config = { ...this.config, ...config };
  }

  getConfig(): ApiConfig {
    return { ...this.config };
  }
}

// Create singleton instance
const apiClient = new ApiClient();

// Export singleton and classes
export default apiClient;
export { ApiClient, ApiError, NetworkError, AuthenticationError, AuthorizationError };
export type { ApiConfig, RequestConfig, AuthContext, TenantContext, RealtimeEventMap };