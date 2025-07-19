# Multi-stage Dockerfile for Next.js web application with production optimization
# Supports responsive design and performance requirements from Requirement 7

# Base stage - Common Node.js environment
FROM node:20.15-bookworm-slim AS base

# Install security updates and required packages
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Set environment variables for production
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Create non-root user for security
RUN groupadd --gid 1001 nodejs \
    && useradd --uid 1001 --gid nodejs --shell /bin/bash --create-home nextjs

# Dependencies stage - Install production dependencies
FROM base AS deps

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies with npm ci for faster, reliable builds
RUN npm ci --only=production --frozen-lockfile \
    && npm cache clean --force

# Development dependencies stage - Install all dependencies for building
FROM base AS dev-deps

# Copy package files
COPY package.json package-lock.json* ./

# Install all dependencies including dev dependencies
RUN npm ci --frozen-lockfile \
    && npm cache clean --force

# Builder stage - Build the Next.js application
FROM base AS builder

WORKDIR /app

# Copy all dependencies
COPY --from=dev-deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Set build-time environment variables
ARG NEXT_PUBLIC_APP_URL
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL
ARG NEXT_PUBLIC_SENTRY_DSN
ARG NEXT_PUBLIC_ENVIRONMENT

ENV NEXT_PUBLIC_APP_URL=$NEXT_PUBLIC_APP_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL
ENV NEXT_PUBLIC_SENTRY_DSN=$NEXT_PUBLIC_SENTRY_DSN
ENV NEXT_PUBLIC_ENVIRONMENT=$NEXT_PUBLIC_ENVIRONMENT

# Build the application with optimizations
RUN npm run build

# Production runner stage - Final optimized image
FROM base AS runner

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy production dependencies
COPY --from=deps --chown=nextjs:nodejs /app/node_modules ./node_modules

# Copy built application
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

# Copy additional configuration files
COPY --from=builder --chown=nextjs:nodejs /app/next.config.js ./
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./

# Create necessary directories with proper permissions
RUN mkdir -p /app/.next/cache \
    && chown -R nextjs:nodejs /app/.next/cache \
    && chmod -R 755 /app/.next/cache

# Set security-focused file permissions
RUN find /app -type f -exec chmod 644 {} \; \
    && find /app -type d -exec chmod 755 {} \; \
    && chmod +x /app/server.js

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Set runtime environment variables
ENV NODE_OPTIONS="--max-old-space-size=1024"
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Security labels
LABEL maintainer="SPARC Platform Team" \
      version="1.0.0" \
      description="SPARC Web Application - Next.js Frontend" \
      security.scan="enabled" \
      security.non-root="true" \
      org.opencontainers.image.title="SPARC Web Application" \
      org.opencontainers.image.description="Enterprise-grade access control and video surveillance web interface" \
      org.opencontainers.image.vendor="SPARC Platform" \
      org.opencontainers.image.licenses="Proprietary" \
      org.opencontainers.image.source="https://github.com/sparc-platform/sparc"

# Start the application with dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]