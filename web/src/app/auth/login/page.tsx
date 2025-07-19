'use client'

import { useState, useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Eye, EyeOff, Shield, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { useAuth } from '@/hooks/useAuth'
import type { Tenant } from '@sparc/shared'

// Validation Schema
const loginSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .email('Please enter a valid email address'),
  password: z.string()
    .min(1, 'Password is required')
    .min(8, 'Password must be at least 8 characters'),
  tenantId: z.string()
    .min(1, 'Please select an organization')
    .optional(),
  rememberMe: z.boolean().default(false)
})

type LoginFormData = z.infer<typeof loginSchema>

export default function LoginPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { login, isLoading: authLoading, error: authError, clearError, isAuthenticated } = useAuth()
  const [showPassword, setShowPassword] = useState(false)
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [tenantsLoading, setTenantsLoading] = useState(true)
  // Client-side lockout removed - handled server-side

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setValue,
    watch,
    setError,
    clearErrors,
    reset
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: '',
      password: '',
      tenantId: '',
      rememberMe: false
    }
  })

  const watchedEmail = watch('email')

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      const redirectTo = searchParams.get('redirect') || '/dashboard'
      router.push(redirectTo)
    }
  }, [isAuthenticated, router, searchParams])

  // Load tenants from API
  useEffect(() => {
    const loadTenants = async () => {
      try {
        setTenantsLoading(true)
        // Use a direct API call since we're not authenticated yet
        const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000'}/api/v1/tenants?public=true`, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
          },
        })

        if (response.ok) {
          const data = await response.json()
          setTenants(data.items || data || [])
        } else {
          console.warn('Failed to load tenants, using fallback')
          // Fallback to basic tenant structure if API fails
          setTenants([])
        }
      } catch (error) {
        console.warn('Error loading tenants:', error)
        setTenants([])
      } finally {
        setTenantsLoading(false)
      }
    }

    loadTenants()
  }, [])

  // Clear auth errors when form changes
  useEffect(() => {
    if (authError) {
      clearError()
    }
  }, [watchedEmail, clearError, authError])

  // Account lockout is handled server-side with proper rate limiting

  // Auto-detect tenant based on email domain
  useEffect(() => {
    if (watchedEmail && watchedEmail.includes('@') && tenants.length > 0) {
      const domain = watchedEmail.split('@')[1]
      const matchedTenant = tenants.find(tenant => 
        tenant.domain && tenant.domain.toLowerCase() === domain.toLowerCase()
      )
      
      if (matchedTenant) {
        setValue('tenantId', matchedTenant.id)
        clearErrors('tenantId')
      }
    }
  }, [watchedEmail, tenants, setValue, clearErrors])

  // Handle form submission
  const onSubmit = async (data: LoginFormData) => {

    try {
      // Clear any existing sessions
      clearError()

      // Prepare login credentials
      const credentials = {
        email: data.email,
        password: data.password,
        tenantId: data.tenantId || undefined,
      }

      // Attempt login using the unified auth system
      await login(credentials)

      // Handle remember me functionality
      if (data.rememberMe) {
        localStorage.setItem('rememberMe', 'true')
        localStorage.setItem('lastEmail', data.email)
      } else {
        localStorage.removeItem('rememberMe')
        localStorage.removeItem('lastEmail')
      }

      // Server handles session management and rate limiting

      // Get redirect URL based on search params or user role
      const redirectTo = searchParams.get('redirect') || getDashboardRoute()
      
      // Show success message and redirect
      toast.success('Login successful! Redirecting...')
      
      // Small delay to show success message
      setTimeout(() => {
        router.push(redirectTo)
      }, 500)

    } catch (error: any) {
      console.error('Login error:', error)
      
      // Handle specific error types
      const errorMessage = error.message || 'Login failed'
      
      if (errorMessage.includes('Invalid credentials') || errorMessage.includes('Authentication failed')) {
        setError('password', { 
          type: 'manual', 
          message: 'Invalid email or password' 
        })
      } else if (errorMessage.includes('Too many') || errorMessage.includes('rate limit')) {
        // Server-side rate limiting
        toast.error('Too many failed attempts. Please try again later.')
      } else if (errorMessage.includes('tenant') || errorMessage.includes('organization')) {
        setError('tenantId', { 
          type: 'manual', 
          message: 'Please select a valid organization or check your access permissions.' 
        })
      } else if (errorMessage.includes('disabled') || errorMessage.includes('suspended')) {
        setError('email', {
          type: 'manual',
          message: 'Your account has been disabled. Please contact support.'
        })
      } else {
        // Generic error handling
        toast.error(errorMessage)
      }
    }
  }

  // Get dashboard route based on user role
  const getDashboardRoute = (): string => {
    // Default dashboard route - the auth system will handle role-based routing
    return '/dashboard'
  }

  // Load remembered email on component mount
  useEffect(() => {
    const rememberMe = localStorage.getItem('rememberMe')
    const lastEmail = localStorage.getItem('lastEmail')
    
    if (rememberMe === 'true' && lastEmail) {
      setValue('email', lastEmail)
      setValue('rememberMe', true)
    }
  }, [setValue])

  // Removed client-side lockout - handled server-side

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <div className="bg-blue-600 p-3 rounded-xl">
              <Shield className="h-8 w-8 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-slate-900 mb-2">
            Welcome to SPARC
          </h1>
          <p className="text-slate-600">
            Unified Access Control & Video Surveillance Platform
          </p>
        </div>

        {/* Login Form */}
        <div className="bg-white rounded-2xl shadow-xl p-8 border border-slate-200">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-6" noValidate>
            {/* Email Field */}
            <div>
              <label 
                htmlFor="email" 
                className="block text-sm font-medium text-slate-700 mb-2"
              >
                Email Address
              </label>
              <input
                {...register('email')}
                type="email"
                id="email"
                autoComplete="email"
                disabled={false}
                className={`
                  w-full px-4 py-3 border rounded-lg transition-colors duration-200
                  focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                  disabled:bg-slate-50 disabled:text-slate-500 disabled:cursor-not-allowed
                  ${errors.email 
                    ? 'border-red-300 bg-red-50' 
                    : 'border-slate-300 hover:border-slate-400'
                  }
                `}
                placeholder="Enter your email address"
                aria-describedby={errors.email ? 'email-error' : undefined}
                aria-invalid={errors.email ? 'true' : 'false'}
              />
              {errors.email && (
                <div 
                  id="email-error" 
                  className="mt-2 flex items-center text-sm text-red-600"
                  role="alert"
                >
                  <AlertCircle className="h-4 w-4 mr-1 flex-shrink-0" />
                  {errors.email.message}
                </div>
              )}
            </div>

            {/* Organization/Tenant Selection */}
            <div>
              <label 
                htmlFor="tenantId" 
                className="block text-sm font-medium text-slate-700 mb-2"
              >
                Organization
                {tenantsLoading && (
                  <span className="ml-2 text-xs text-slate-500">(Loading...)</span>
                )}
              </label>
              <select
                {...register('tenantId')}
                id="tenantId"
                disabled={isLocked || tenantsLoading}
                className={`
                  w-full px-4 py-3 border rounded-lg transition-colors duration-200
                  focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                  disabled:bg-slate-50 disabled:text-slate-500 disabled:cursor-not-allowed
                  ${errors.tenantId 
                    ? 'border-red-300 bg-red-50' 
                    : 'border-slate-300 hover:border-slate-400'
                  }
                `}
                aria-describedby={errors.tenantId ? 'tenant-error' : undefined}
                aria-invalid={errors.tenantId ? 'true' : 'false'}
              >
                <option value="">
                  {tenantsLoading ? 'Loading organizations...' : 'Select your organization'}
                </option>
                {tenants.map((tenant) => (
                  <option key={tenant.id} value={tenant.id}>
                    {tenant.name}
                  </option>
                ))}
              </select>
              {errors.tenantId && (
                <div 
                  id="tenant-error" 
                  className="mt-2 flex items-center text-sm text-red-600"
                  role="alert"
                >
                  <AlertCircle className="h-4 w-4 mr-1 flex-shrink-0" />
                  {errors.tenantId.message}
                </div>
              )}
              {!tenantsLoading && tenants.length === 0 && (
                <div className="mt-2 text-sm text-slate-500">
                  No organizations available. Please contact support.
                </div>
              )}
            </div>

            {/* Password Field */}
            <div>
              <label 
                htmlFor="password" 
                className="block text-sm font-medium text-slate-700 mb-2"
              >
                Password
              </label>
              <div className="relative">
                <input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  autoComplete="current-password"
                  disabled={false}
                  className={`
                    w-full px-4 py-3 pr-12 border rounded-lg transition-colors duration-200
                    focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent
                    disabled:bg-slate-50 disabled:text-slate-500 disabled:cursor-not-allowed
                    ${errors.password 
                      ? 'border-red-300 bg-red-50' 
                      : 'border-slate-300 hover:border-slate-400'
                    }
                  `}
                  placeholder="Enter your password"
                  aria-describedby={errors.password ? 'password-error' : undefined}
                  aria-invalid={errors.password ? 'true' : 'false'}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={false}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-600 disabled:cursor-not-allowed"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5" />
                  ) : (
                    <Eye className="h-5 w-5" />
                  )}
                </button>
              </div>
              {errors.password && (
                <div 
                  id="password-error" 
                  className="mt-2 flex items-center text-sm text-red-600"
                  role="alert"
                >
                  <AlertCircle className="h-4 w-4 mr-1 flex-shrink-0" />
                  {errors.password.message}
                </div>
              )}
            </div>

            {/* Remember Me Checkbox */}
            <div className="flex items-center">
              <input
                {...register('rememberMe')}
                type="checkbox"
                id="rememberMe"
                disabled={false}
                className="h-4 w-4 text-blue-600 border-slate-300 rounded focus:ring-blue-500 disabled:cursor-not-allowed"
              />
              <label 
                htmlFor="rememberMe" 
                className="ml-2 text-sm text-slate-700 cursor-pointer"
              >
                Remember me for 30 days
              </label>
            </div>

            {/* Server-side rate limiting - removed client-side lockout */}

            {/* Server-side rate limiting handles attempt tracking */}

            {/* Global Auth Error Display */}
            {authError && !errors.password && !errors.tenantId && !errors.email && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-center">
                  <AlertCircle className="h-5 w-5 text-red-600 mr-2 flex-shrink-0" />
                  <p className="text-sm text-red-800">{authError}</p>
                </div>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting || authLoading || tenantsLoading}
              className={`
                w-full py-3 px-4 rounded-lg font-medium transition-all duration-200
                focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
                disabled:cursor-not-allowed
                bg-blue-600 hover:bg-blue-700 text-white disabled:bg-blue-400
              `}
              aria-describedby="submit-status"
            >
              {authLoading || isSubmitting ? (
                <div className="flex items-center justify-center">
                  <Loader2 className="h-5 w-5 mr-2 animate-spin" />
                  Signing in...
                </div>
              ) : tenantsLoading ? (
                'Loading...'
              ) : (
                'Sign In'
              )}
            </button>

            {/* Additional Links */}
            <div className="text-center space-y-2">
              <a 
                href="/auth/forgot-password" 
                className="text-sm text-blue-600 hover:text-blue-800 hover:underline focus:outline-none focus:underline"
              >
                Forgot your password?
              </a>
              <div className="text-sm text-slate-600">
                Need help? Contact{' '}
                <a 
                  href="mailto:support@sparc.com" 
                  className="text-blue-600 hover:text-blue-800 hover:underline focus:outline-none focus:underline"
                >
                  support@sparc.com
                </a>
              </div>
            </div>
          </form>
        </div>

        {/* Security Notice */}
        <div className="mt-6 text-center">
          <div className="flex items-center justify-center text-sm text-slate-500">
            <CheckCircle2 className="h-4 w-4 mr-1 text-green-500" />
            Secured with enterprise-grade encryption
          </div>
        </div>
      </div>
    </div>
  )
}
