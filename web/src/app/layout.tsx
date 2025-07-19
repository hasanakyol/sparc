import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { Providers } from '@/components/providers'
import { Navigation } from '@/components/navigation'
import { ErrorBoundary } from '@/components/error-boundary'
import { Toaster } from '@/components/ui/toaster'
import { SkipLink } from '@/components/accessibility/skip-link'
import { AnnouncementRegion } from '@/components/accessibility/announcement-region'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-inter',
})

export const metadata: Metadata = {
  title: {
    template: '%s | SPARC',
    default: 'SPARC - Unified Access Control & Video Surveillance Platform',
  },
  description: 'Enterprise-grade physical access control and video surveillance platform with multi-tenant architecture, real-time monitoring, and comprehensive security management.',
  keywords: ['access control', 'video surveillance', 'security', 'enterprise', 'multi-tenant'],
  authors: [{ name: 'SPARC Platform' }],
  creator: 'SPARC Platform',
  publisher: 'SPARC Platform',
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'),
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: '/',
    title: 'SPARC - Unified Access Control & Video Surveillance Platform',
    description: 'Enterprise-grade physical access control and video surveillance platform',
    siteName: 'SPARC Platform',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SPARC - Unified Access Control & Video Surveillance Platform',
    description: 'Enterprise-grade physical access control and video surveillance platform',
  },
  robots: {
    index: false, // Security platform - should not be indexed
    follow: false,
    googleBot: {
      index: false,
      follow: false,
    },
  },
  viewport: {
    width: 'device-width',
    initialScale: 1,
    maximumScale: 5,
  },
}

interface RootLayoutProps {
  children: React.ReactNode
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html 
      lang="en" 
      className={`${inter.variable} scroll-smooth`}
      suppressHydrationWarning
    >
      <head>
        {/* Preload critical resources */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        
        {/* Security headers */}
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        <meta httpEquiv="X-XSS-Protection" content="1; mode=block" />
        <meta httpEquiv="Referrer-Policy" content="strict-origin-when-cross-origin" />
        
        {/* PWA manifest */}
        <link rel="manifest" href="/manifest.json" />
        <meta name="theme-color" content="#1f2937" />
        
        {/* Favicons */}
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="icon" href="/icon.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
      </head>
      <body 
        className={`
          min-h-screen bg-background font-sans antialiased
          selection:bg-primary/20 selection:text-primary-foreground
          focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2
        `}
        suppressHydrationWarning
      >
        {/* Skip to main content link for screen readers */}
        <SkipLink />
        
        {/* Live region for dynamic announcements */}
        <AnnouncementRegion />
        
        <ErrorBoundary>
          <Providers>
            <div className="relative flex min-h-screen flex-col">
              {/* Main navigation */}
              <Navigation />
              
              {/* Main content area */}
              <main 
                id="main-content"
                className="flex-1"
                role="main"
                tabIndex={-1}
              >
                <div className="container mx-auto px-4 py-6 sm:px-6 lg:px-8">
                  {children}
                </div>
              </main>
              
              {/* Footer */}
              <footer 
                className="border-t bg-muted/50 py-6 md:py-8"
                role="contentinfo"
              >
                <div className="container mx-auto px-4 sm:px-6 lg:px-8">
                  <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
                    <div className="flex flex-col items-center gap-2 md:flex-row md:gap-4">
                      <p className="text-sm text-muted-foreground">
                        © {new Date().getFullYear()} SPARC Platform. All rights reserved.
                      </p>
                      <div className="flex items-center gap-4 text-sm">
                        <a 
                          href="/privacy" 
                          className="text-muted-foreground hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 rounded-sm"
                        >
                          Privacy Policy
                        </a>
                        <a 
                          href="/terms" 
                          className="text-muted-foreground hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 rounded-sm"
                        >
                          Terms of Service
                        </a>
                        <a 
                          href="/security" 
                          className="text-muted-foreground hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 rounded-sm"
                        >
                          Security
                        </a>
                      </div>
                    </div>
                    
                    {/* System status indicator */}
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 rounded-full bg-green-500" aria-hidden="true" />
                      <span className="text-sm text-muted-foreground">
                        All systems operational
                      </span>
                    </div>
                  </div>
                </div>
              </footer>
            </div>
            
            {/* Toast notifications */}
            <Toaster />
          </Providers>
        </ErrorBoundary>
        
        {/* Development tools */}
        {process.env.NODE_ENV === 'development' && (
          <div className="fixed bottom-4 right-4 z-50">
            <div className="rounded-lg bg-yellow-100 px-3 py-2 text-xs text-yellow-800 shadow-lg dark:bg-yellow-900 dark:text-yellow-200">
              Development Mode
            </div>
          </div>
        )}
      </body>
    </html>
  )
}