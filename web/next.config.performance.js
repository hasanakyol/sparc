/** @type {import('next').NextConfig} */
const withBundleAnalyzer = require('@next/bundle-analyzer')({
  enabled: process.env.ANALYZE === 'true',
})

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  
  // Performance optimizations
  swcMinify: true,
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
  },
  
  // Image optimization
  images: {
    domains: ['localhost', 'sparc-assets.s3.amazonaws.com', 'cdn.sparc.com'],
    formats: ['image/avif', 'image/webp'],
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    minimumCacheTTL: 60 * 60 * 24 * 365, // 1 year
  },
  
  // Enable ISR (Incremental Static Regeneration)
  experimental: {
    isrMemoryCacheSize: 50, // MB
    workerThreads: true,
    cpus: 4,
    
    // React 18 features
    serverComponents: true,
    
    // Optimize CSS
    optimizeCss: true,
    
    // Module federation for micro-frontends
    moduleFederation: true,
  },
  
  // Webpack configuration
  webpack: (config, { dev, isServer, webpack }) => {
    // Production optimizations
    if (!dev && !isServer) {
      // Enable module concatenation
      config.optimization.concatenateModules = true
      
      // Split chunks optimally
      config.optimization.splitChunks = {
        chunks: 'all',
        cacheGroups: {
          default: false,
          vendors: false,
          framework: {
            name: 'framework',
            chunks: 'all',
            test: /(?<!node_modules.*)[\\/]node_modules[\\/](react|react-dom|scheduler|prop-types|use-subscription)[\\/]/,
            priority: 40,
            enforce: true,
          },
          lib: {
            test(module) {
              return module.size() > 160000 &&
                /node_modules[/\\]/.test(module.identifier())
            },
            name(module) {
              const hash = crypto.createHash('sha1')
              hash.update(module.identifier())
              return hash.digest('hex').substring(0, 8)
            },
            priority: 30,
            minChunks: 1,
            reuseExistingChunk: true,
          },
          commons: {
            name: 'commons',
            chunks: 'all',
            minChunks: 2,
            priority: 20,
          },
          shared: {
            name(module, chunks) {
              return crypto
                .createHash('sha1')
                .update(chunks.reduce((acc, chunk) => acc + chunk.name, ''))
                .digest('hex')
                .substring(0, 8)
            },
            priority: 10,
            minChunks: 2,
            reuseExistingChunk: true,
          },
        },
        maxAsyncRequests: 30,
        maxInitialRequests: 30,
      }
      
      // Minimize bundle size
      config.optimization.minimize = true
      
      // Use contenthash for better caching
      config.output.filename = 'static/chunks/[name].[contenthash].js'
      config.output.chunkFilename = 'static/chunks/[name].[contenthash].js'
      
      // Add compression plugin
      const CompressionPlugin = require('compression-webpack-plugin')
      config.plugins.push(
        new CompressionPlugin({
          algorithm: 'gzip',
          test: /\.(js|css|html|svg)$/,
          threshold: 8192,
          minRatio: 0.8,
        })
      )
      
      // Add Brotli compression
      config.plugins.push(
        new CompressionPlugin({
          algorithm: 'brotliCompress',
          test: /\.(js|css|html|svg)$/,
          threshold: 8192,
          minRatio: 0.8,
          filename: '[path][base].br',
        })
      )
      
      // Add webpack bundle analyzer
      if (process.env.ANALYZE === 'true') {
        const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer')
        config.plugins.push(
          new BundleAnalyzerPlugin({
            analyzerMode: 'static',
            reportFilename: './analyze.html',
            openAnalyzer: true,
          })
        )
      }
    }
    
    // WebAssembly support
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
      layers: true,
    }
    
    // Add aliases for better imports
    config.resolve.alias = {
      ...config.resolve.alias,
      '@components': path.resolve(__dirname, 'components'),
      '@lib': path.resolve(__dirname, 'lib'),
      '@styles': path.resolve(__dirname, 'styles'),
      '@hooks': path.resolve(__dirname, 'hooks'),
      '@utils': path.resolve(__dirname, 'utils'),
    }
    
    // Ignore certain modules to reduce bundle size
    config.plugins.push(
      new webpack.IgnorePlugin({
        resourceRegExp: /^\.\/locale$/,
        contextRegExp: /moment$/,
      })
    )
    
    return config
  },
  
  // Headers configuration
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on'
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(self)'
          },
        ],
      },
      // Cache static assets
      {
        source: '/static/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
      // Cache images
      {
        source: '/_next/image(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
      // Service Worker
      {
        source: '/sw.js',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=0, must-revalidate',
          },
          {
            key: 'Service-Worker-Allowed',
            value: '/',
          },
        ],
      },
    ]
  },
  
  // Redirects for performance
  async redirects() {
    return [
      {
        source: '/home',
        destination: '/',
        permanent: true,
      },
    ]
  },
  
  // Rewrites for API optimization
  async rewrites() {
    return {
      beforeFiles: [
        // Rewrite API calls to bypass Next.js for better performance
        {
          source: '/api/v1/:path*',
          destination: `${process.env.NEXT_PUBLIC_API_URL}/v1/:path*`,
        },
      ],
      afterFiles: [
        // CDN rewrites for static assets
        {
          source: '/cdn/:path*',
          destination: `${process.env.CDN_URL}/:path*`,
        },
      ],
    }
  },
  
  // Output configuration
  output: 'standalone',
  
  // Enable build cache
  buildCache: true,
  
  // TypeScript configuration
  typescript: {
    ignoreBuildErrors: false,
  },
  
  // ESLint configuration
  eslint: {
    ignoreDuringBuilds: false,
  },
  
  // Environment variables
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:3000',
    NEXT_PUBLIC_CDN_URL: process.env.CDN_URL || 'https://cdn.sparc.com',
  },
  
  // Production source maps (disabled for security)
  productionBrowserSourceMaps: false,
  
  // Disable x-powered-by header
  poweredByHeader: false,
  
  // Generate build ID based on git commit
  generateBuildId: async () => {
    if (process.env.BUILD_ID) {
      return process.env.BUILD_ID
    }
    return `build-${Date.now()}`
  },
}

// Export with bundle analyzer if needed
module.exports = withBundleAnalyzer(nextConfig)