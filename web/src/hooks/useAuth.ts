'use client'

import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import toast from 'react-hot-toast'
import apiClient, { AuthenticationError, NetworkError, ApiError } from '@/lib/api'
import type { 
  User, 
  Tenant, 
  LoginRequest, 
  ChangePasswordRequest,
  RealtimeEventMap 
} from '@sparc/shared'

// Local types for compatibility
interface LoginCredentials extends LoginRequest {}

interface SignupData {
  email: string
  password: string
  firstName: string
  lastName: string
  tenantId: string
  role?: 'SUPER_ADMIN' | 'TENANT_ADMIN' | 'SITE_ADMIN' | 'OPERATOR' | 'VIEWER'
}

interface ChangePasswordData extends ChangePasswordRequest {}

interface AuthState {
  // State
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
  availableTenants: Tenant[]
  sessionExpiry: number | null
  isRefreshing: boolean
  lastActivity: number
  
  // Actions
  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => Promise<void>
  signup: (data: SignupData) => Promise<void>
  changePassword: (data: ChangePasswordData) => Promise<void>
  switchTenant: (tenantId: string) => Promise<void>
  clearError: () => void
  setLoading: (loading: boolean) => void
  checkAuthStatus: () => Promise<void>
  syncWithApiClient: () => void
  refreshSession: () => Promise<void>
  updateActivity: () => void
  
  // Internal actions
  setUser: (user: User) => void
  clearAuth: () => void
  setSessionExpiry: (expiry: number) => void
  setRefreshing: (refreshing: boolean) => void
}

// Zustand Store
const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      // Initial state
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      availableTenants: [],
      sessionExpiry: null, // No longer tracked client-side
      isRefreshing: false,
      lastActivity: Date.now(),

      // Actions
      login: async (credentials: LoginCredentials) => {
        try {
          set({ isLoading: true, error: null })
          
          const response = await apiClient.login(credentials)
          
          // Sync state with ApiClient (tokens are in HttpOnly cookies)
          set({
            user: response.user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
            sessionExpiry: null, // Managed server-side
            lastActivity: Date.now(),
          })

          // Connect to real-time events
          apiClient.connectRealtime()

          toast.success('Login successful')
        } catch (error) {
          let errorMessage = 'Login failed'
          
          if (error instanceof AuthenticationError) {
            errorMessage = 'Invalid credentials. Please check your email and password.'
          } else if (error instanceof NetworkError) {
            errorMessage = 'Network error. Please check your connection and try again.'
          } else if (error instanceof ApiError) {
            errorMessage = error.message
          } else if (error instanceof Error) {
            errorMessage = error.message
          }
          
          set({
            isLoading: false,
            error: errorMessage,
            isAuthenticated: false,
            sessionExpiry: null,
          })
          toast.error(errorMessage)
          throw error
        }
      },

      logout: async () => {
        try {
          set({ isLoading: true })
          
          // Disconnect real-time connection first
          apiClient.disconnectRealtime()
          
          // Call logout through ApiClient
          await apiClient.logout()
          
          set({
            user: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
            availableTenants: [],
            sessionExpiry: null,
            isRefreshing: false,
            lastActivity: Date.now(),
          })

          toast.success('Logged out successfully')
        } catch (error) {
          // Even if logout fails, clear local state
          set({
            user: null,
            isAuthenticated: false,
            isLoading: false,
            error: null,
            availableTenants: [],
            sessionExpiry: null,
            isRefreshing: false,
            lastActivity: Date.now(),
          })
          
          // Still show success message as local state is cleared
          toast.success('Logged out successfully')
        }
      },

      signup: async (data: SignupData) => {
        try {
          set({ isLoading: true, error: null })
          
          // Use ApiClient for signup with proper error handling
          const response = await apiClient.post('/api/v1/auth/signup', data, { skipAuth: true })
          
          set({
            isLoading: false,
            error: null,
          })

          toast.success('Account created successfully. Please log in.')
        } catch (error) {
          let errorMessage = 'Signup failed'
          
          if (error instanceof ApiError) {
            if (error.status === 409) {
              errorMessage = 'An account with this email already exists.'
            } else if (error.status === 400) {
              errorMessage = error.details?.message || 'Invalid signup data. Please check your information.'
            } else {
              errorMessage = error.message
            }
          } else if (error instanceof NetworkError) {
            errorMessage = 'Network error. Please check your connection and try again.'
          } else if (error instanceof Error) {
            errorMessage = error.message
          }
          
          set({
            isLoading: false,
            error: errorMessage,
          })
          toast.error(errorMessage)
          throw error
        }
      },

      changePassword: async (data: ChangePasswordData) => {
        try {
          if (!apiClient.isAuthenticated()) {
            throw new AuthenticationError('Not authenticated')
          }

          set({ isLoading: true, error: null })
          
          await apiClient.changePassword(data)
          
          set({
            isLoading: false,
            error: null,
            lastActivity: Date.now(),
          })

          toast.success('Password changed successfully')
        } catch (error) {
          let errorMessage = 'Password change failed'
          
          if (error instanceof AuthenticationError) {
            errorMessage = 'Current password is incorrect.'
            // Force logout if authentication fails
            get().logout()
          } else if (error instanceof ApiError) {
            if (error.status === 400) {
              errorMessage = error.details?.message || 'Invalid password data. Please check your input.'
            } else {
              errorMessage = error.message
            }
          } else if (error instanceof NetworkError) {
            errorMessage = 'Network error. Please check your connection and try again.'
          } else if (error instanceof Error) {
            errorMessage = error.message
          }
          
          set({
            isLoading: false,
            error: errorMessage,
          })
          toast.error(errorMessage)
          throw error
        }
      },

      switchTenant: async (tenantId: string) => {
        try {
          if (!apiClient.isAuthenticated()) {
            throw new AuthenticationError('Not authenticated')
          }

          set({ isLoading: true, error: null })

          // Use ApiClient's tenant switching
          await apiClient.setTenant(tenantId)
          
          // Update local state
          const user = apiClient.getUser()
          const tenant = apiClient.getTenant()
          
          set({
            user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
            lastActivity: Date.now(),
          })

          // Reconnect real-time with new tenant context
          if (apiClient.isRealtimeConnected()) {
            apiClient.disconnectRealtime()
            apiClient.connectRealtime()
          }

          toast.success(`Switched to ${tenant?.name || 'tenant'}`)
        } catch (error) {
          let errorMessage = 'Tenant switch failed'
          
          if (error instanceof AuthenticationError) {
            errorMessage = 'Authentication expired. Please log in again.'
            get().logout()
          } else if (error instanceof ApiError) {
            if (error.status === 403) {
              errorMessage = 'You do not have access to this tenant.'
            } else if (error.status === 404) {
              errorMessage = 'Tenant not found.'
            } else {
              errorMessage = error.message
            }
          } else if (error instanceof NetworkError) {
            errorMessage = 'Network error. Please check your connection and try again.'
          } else if (error instanceof Error) {
            errorMessage = error.message
          }
          
          set({
            isLoading: false,
            error: errorMessage,
          })
          toast.error(errorMessage)
          throw error
        }
      },

      checkAuthStatus: async () => {
        try {
          // Check if ApiClient is authenticated
          if (apiClient.isAuthenticated()) {
            const user = apiClient.getUser()
            if (user) {
              set({
                user,
                isAuthenticated: true,
                error: null,
                lastActivity: Date.now(),
              })
              
              // Ensure real-time connection is active
              if (!apiClient.isRealtimeConnected()) {
                apiClient.connectRealtime()
              }
              return
            }
          }

          // Try to get current user to verify authentication
          try {
            const user = await apiClient.getCurrentUser()
            set({
              user,
              isAuthenticated: true,
              error: null,
              lastActivity: Date.now(),
            })
            
            // Connect real-time if authenticated
            if (!apiClient.isRealtimeConnected()) {
              apiClient.connectRealtime()
            }
          } catch (error) {
            // Authentication failed, clear state
            set({
              user: null,
              isAuthenticated: false,
              error: null,
              sessionExpiry: null,
              isRefreshing: false,
            })
            
            // Disconnect real-time
            apiClient.disconnectRealtime()
          }
        } catch (error) {
          // Clear auth state if verification fails
          set({
            user: null,
            isAuthenticated: false,
            error: null,
            sessionExpiry: null,
            isRefreshing: false,
          })
          
          // Disconnect real-time
          apiClient.disconnectRealtime()
        }
      },

      refreshSession: async () => {
        const state = get()
        if (state.isRefreshing) {
          return // Already refreshing
        }

        try {
          set({ isRefreshing: true, error: null })
          
          // Try to refresh through ApiClient (it handles token refresh internally)
          const user = await apiClient.getCurrentUser()
          
          set({
            user,
            isAuthenticated: true,
            isRefreshing: false,
            error: null,
            lastActivity: Date.now(),
          })
        } catch (error) {
          // Refresh failed, logout user
          set({
            user: null,
            isAuthenticated: false,
            isRefreshing: false,
            sessionExpiry: null,
            error: null,
          })
          
          apiClient.disconnectRealtime()
          
          if (error instanceof AuthenticationError) {
            toast.error('Session expired. Please log in again.')
          }
        }
      },

      updateActivity: () => {
        set({ lastActivity: Date.now() })
      },

      syncWithApiClient: () => {
        const user = apiClient.getUser()
        const isAuthenticated = apiClient.isAuthenticated()
        
        set({
          user,
          isAuthenticated,
          lastActivity: Date.now(),
        })
      },

      clearError: () => set({ error: null }),
      setLoading: (loading: boolean) => set({ isLoading: loading }),
      
      // Internal actions
      setUser: (user: User) => {
        set({ user, isAuthenticated: true, lastActivity: Date.now() })
      },
      
      setSessionExpiry: (expiry: number) => {
        set({ sessionExpiry: expiry })
      },
      
      setRefreshing: (refreshing: boolean) => {
        set({ isRefreshing: refreshing })
      },
      
      clearAuth: () => {
        set({
          user: null,
          isAuthenticated: false,
          error: null,
          availableTenants: [],
          sessionExpiry: null,
          isRefreshing: false,
        })
        apiClient.disconnectRealtime()
      },
    }),
    {
      name: 'sparc-auth',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        // Only store minimal user info, no roles or permissions
        user: state.user ? {
          id: state.user.id,
          email: state.user.email,
          firstName: state.user.firstName,
          lastName: state.user.lastName,
          tenantId: state.user.tenantId,
          // Explicitly exclude role and other sensitive data
        } : null,
        isAuthenticated: state.isAuthenticated,
        lastActivity: state.lastActivity,
        // sessionExpiry removed - managed server-side
        // permissions removed - fetched from server
      }),
    }
  )
)

// Session monitoring and auto-refresh
let sessionCheckInterval: NodeJS.Timeout | null = null
let activityTimeout: NodeJS.Timeout | null = null

const SESSION_CHECK_INTERVAL = 60000 // Check every minute
const ACTIVITY_TIMEOUT = 30 * 60 * 1000 // 30 minutes of inactivity
const REFRESH_THRESHOLD = 5 * 60 * 1000 // Refresh when 5 minutes left

const startSessionMonitoring = () => {
  if (sessionCheckInterval) return

  sessionCheckInterval = setInterval(() => {
    const state = useAuthStore.getState()
    
    if (!state.isAuthenticated || !state.sessionExpiry) {
      return
    }

    const now = Date.now()
    const timeUntilExpiry = state.sessionExpiry - now
    const timeSinceActivity = now - state.lastActivity

    // Check for inactivity timeout
    if (timeSinceActivity > ACTIVITY_TIMEOUT) {
      state.logout()
      toast.error('Session expired due to inactivity')
      return
    }

    // Auto-refresh if session is about to expire
    if (timeUntilExpiry <= REFRESH_THRESHOLD && timeUntilExpiry > 0) {
      state.refreshSession()
    }

    // Force logout if session has expired
    if (timeUntilExpiry <= 0) {
      state.logout()
      toast.error('Session expired. Please log in again.')
    }
  }, SESSION_CHECK_INTERVAL)
}

const stopSessionMonitoring = () => {
  if (sessionCheckInterval) {
    clearInterval(sessionCheckInterval)
    sessionCheckInterval = null
  }
  if (activityTimeout) {
    clearTimeout(activityTimeout)
    activityTimeout = null
  }
}

// Activity tracking
const trackActivity = () => {
  const state = useAuthStore.getState()
  if (state.isAuthenticated) {
    state.updateActivity()
  }
}

// Set up activity listeners
if (typeof window !== 'undefined') {
  const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click']
  events.forEach(event => {
    document.addEventListener(event, trackActivity, { passive: true })
  })
}

// Main useAuth hook
export const useAuth = () => {
  const store = useAuthStore()
  const router = useRouter()
  const realtimeListenersRef = useRef<{ [key: string]: () => void }>({})

  // Sync with ApiClient on mount and when authentication changes
  useEffect(() => {
    store.syncWithApiClient()
    store.checkAuthStatus()
    
    // Start session monitoring when authenticated
    if (store.isAuthenticated) {
      startSessionMonitoring()
    } else {
      stopSessionMonitoring()
    }
    
    return () => {
      stopSessionMonitoring()
    }
  }, [store.isAuthenticated])

  // Set up real-time event listeners
  useEffect(() => {
    if (!store.isAuthenticated) {
      // Clean up listeners when not authenticated
      Object.values(realtimeListenersRef.current).forEach(cleanup => cleanup())
      realtimeListenersRef.current = {}
      return
    }

    // Authentication events
    const handleAuthEvent = () => {
      store.checkAuthStatus()
    }

    // Error events
    const handleRealtimeError = (error: Error) => {
      console.error('Real-time connection error:', error)
      
      // If it's an authentication error, logout
      if (error.message.includes('authentication') || error.message.includes('unauthorized')) {
        store.logout()
        toast.error('Real-time connection lost. Please log in again.')
      }
    }

    // Connection events
    const handleConnect = () => {
      console.log('Real-time connection established')
    }

    const handleDisconnect = () => {
      console.log('Real-time connection lost')
    }

    // Set up listeners
    apiClient.on('connect', handleConnect)
    apiClient.on('disconnect', handleDisconnect)
    apiClient.on('error', handleRealtimeError)

    // Store cleanup functions
    realtimeListenersRef.current = {
      connect: () => apiClient.off('connect', handleConnect),
      disconnect: () => apiClient.off('disconnect', handleDisconnect),
      error: () => apiClient.off('error', handleRealtimeError),
    }

    return () => {
      Object.values(realtimeListenersRef.current).forEach(cleanup => cleanup())
      realtimeListenersRef.current = {}
    }
  }, [store.isAuthenticated])

  // Enhanced login with redirect
  const loginWithRedirect = useCallback(
    async (credentials: LoginCredentials, redirectTo?: string) => {
      await store.login(credentials)
      router.push(redirectTo || '/')
    },
    [store.login, router]
  )

  // Enhanced logout with redirect
  const logoutWithRedirect = useCallback(
    async (redirectTo?: string) => {
      await store.logout()
      router.push(redirectTo || '/auth/login')
    },
    [store.logout, router]
  )

  // Role-based access control (server-side)
  const hasRole = useCallback(
    async (requiredRole: User['role'] | User['role'][]): Promise<boolean> => {
      if (!store.user || !apiClient.isAuthenticated()) return false
      
      try {
        const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole]
        const response = await apiClient.get(
          `/api/v1/auth/check-role?roles=${roles.join(',')}`
        )
        return response.hasRole
      } catch (error) {
        console.error('Role check failed:', error)
        return false
      }
    },
    [store.user]
  )

  // Permission checking (server-side)
  const hasPermission = useCallback(
    async (permission: string): Promise<boolean> => {
      if (!store.user || !apiClient.isAuthenticated()) return false
      
      try {
        const response = await apiClient.get(
          `/api/v1/auth/check-permission?permission=${encodeURIComponent(permission)}`
        )
        return response.hasPermission
      } catch (error) {
        console.error('Permission check failed:', error)
        return false
      }
    },
    [store.user]
  )

  // Batch permission checking for performance
  const hasPermissions = useCallback(
    async (permissions: string[]): Promise<Record<string, boolean>> => {
      if (!store.user || !apiClient.isAuthenticated()) {
        return permissions.reduce((acc, p) => ({ ...acc, [p]: false }), {})
      }
      
      try {
        const response = await apiClient.post(
          '/api/v1/auth/check-permissions',
          { permissions }
        )
        return response.permissions
      } catch (error) {
        console.error('Batch permission check failed:', error)
        return permissions.reduce((acc, p) => ({ ...acc, [p]: false }), {})
      }
    },
    [store.user]
  )

  // Get all user permissions
  const getUserPermissions = useCallback(
    async (): Promise<{ role: string; permissions: string[]; isAdmin: boolean } | null> => {
      if (!store.user || !apiClient.isAuthenticated()) return null
      
      try {
        const response = await apiClient.get('/api/v1/auth/user-permissions')
        return response
      } catch (error) {
        console.error('Get user permissions failed:', error)
        return null
      }
    },
    [store.user]
  )

  // Get current tenant from ApiClient
  const currentTenant = apiClient.getTenant()

  return {
    // State
    user: store.user,
    isAuthenticated: store.isAuthenticated,
    isLoading: store.isLoading,
    error: store.error,
    currentTenant,
    availableTenants: store.availableTenants,
    sessionExpiry: store.sessionExpiry,
    isRefreshing: store.isRefreshing,
    lastActivity: store.lastActivity,

    // Actions
    login: store.login,
    logout: store.logout,
    signup: store.signup,
    changePassword: store.changePassword,
    switchTenant: store.switchTenant,
    clearError: store.clearError,
    refreshSession: store.refreshSession,
    updateActivity: store.updateActivity,

    // Enhanced actions
    loginWithRedirect,
    logoutWithRedirect,

    // Utilities (now async)
    hasRole,
    hasPermission,
    hasPermissions,
    getUserPermissions,

    // Real-time status
    isRealtimeConnected: apiClient.isRealtimeConnected(),

    // ApiClient access
    apiClient,
  }
}

// Protected route hook
export const useRequireAuth = (
  requiredRole?: User['role'] | User['role'][],
  redirectTo = '/auth/login'
) => {
  const { isAuthenticated, user, hasRole } = useAuth()
  const router = useRouter()
  const [isAuthorized, setIsAuthorized] = useState<boolean | null>(null)

  useEffect(() => {
    const checkAuth = async () => {
      if (!isAuthenticated) {
        router.push(redirectTo)
        return
      }

      if (requiredRole) {
        const authorized = await hasRole(requiredRole)
        setIsAuthorized(authorized)
        if (!authorized) {
          router.push('/unauthorized')
        }
      } else {
        setIsAuthorized(true)
      }
    }

    checkAuth()
  }, [isAuthenticated, user, requiredRole, hasRole, router, redirectTo])

  return {
    isAuthenticated: isAuthenticated && (isAuthorized ?? false),
    isLoading: isAuthorized === null,
    user,
  }
}

// Tenant switching hook
export const useTenantSwitch = () => {
  const { switchTenant, isLoading, updateActivity } = useAuth()
  const currentTenant = apiClient.getTenant()

  const switchToTenant = useCallback(
    async (tenantId: string) => {
      if (currentTenant?.id === tenantId) {
        return // Already on this tenant
      }
      
      updateActivity() // Track activity
      await switchTenant(tenantId)
    },
    [switchTenant, currentTenant, updateActivity]
  )

  return {
    switchToTenant,
    isLoading,
    currentTenant,
  }
}

// Session management hook
export const useSessionManagement = () => {
  const { 
    sessionExpiry, 
    isRefreshing, 
    lastActivity, 
    refreshSession, 
    logout,
    isAuthenticated 
  } = useAuth()

  const getTimeUntilExpiry = useCallback(() => {
    if (!sessionExpiry) return null
    return Math.max(0, sessionExpiry - Date.now())
  }, [sessionExpiry])

  const getTimeSinceActivity = useCallback(() => {
    return Date.now() - lastActivity
  }, [lastActivity])

  const isSessionExpiringSoon = useCallback(() => {
    const timeUntilExpiry = getTimeUntilExpiry()
    return timeUntilExpiry !== null && timeUntilExpiry <= REFRESH_THRESHOLD
  }, [getTimeUntilExpiry])

  const forceRefresh = useCallback(async () => {
    if (!isAuthenticated) return
    await refreshSession()
  }, [refreshSession, isAuthenticated])

  const forceLogout = useCallback(async () => {
    await logout()
  }, [logout])

  return {
    sessionExpiry,
    isRefreshing,
    lastActivity,
    getTimeUntilExpiry,
    getTimeSinceActivity,
    isSessionExpiringSoon,
    forceRefresh,
    forceLogout,
  }
}

// Real-time events hook
export const useRealtimeEvents = () => {
  const { isAuthenticated, isRealtimeConnected } = useAuth()

  const subscribe = useCallback(
    <K extends keyof RealtimeEventMap>(
      event: K,
      listener: (data: RealtimeEventMap[K]) => void
    ) => {
      if (!isAuthenticated) return () => {}

      apiClient.on(event, listener)
      
      return () => {
        apiClient.off(event, listener)
      }
    },
    [isAuthenticated]
  )

  return {
    subscribe,
    isConnected: isRealtimeConnected,
  }
}

export default useAuth
