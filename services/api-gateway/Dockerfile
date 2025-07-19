# Multi-stage build for optimized production image
FROM node:18-alpine AS base

# Install security updates and required packages
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S sparc -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies stage
FROM base AS deps

# Install all dependencies (including dev dependencies for build)
RUN npm ci --only=production --silent && \
    npm cache clean --force

# Build stage
FROM base AS build

# Copy all dependencies
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY src ./src

# Install dev dependencies for build
RUN npm ci --silent

# Build TypeScript to JavaScript
RUN npm run build && \
    npm prune --production && \
    npm cache clean --force

# Production stage
FROM node:18-alpine AS production

# Install security updates and runtime dependencies only
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init curl && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S sparc -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Copy built application and production dependencies
COPY --from=build --chown=sparc:nodejs /app/dist ./dist
COPY --from=build --chown=sparc:nodejs /app/node_modules ./node_modules
COPY --from=build --chown=sparc:nodejs /app/package.json ./package.json

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && \
    chown -R sparc:nodejs /app/logs

# Security configurations
# Remove unnecessary packages and files
RUN rm -rf /tmp/* /var/tmp/* /root/.npm /root/.cache

# Set security-focused environment variables
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=512"
ENV UV_THREADPOOL_SIZE=4

# Expose port (non-privileged port)
EXPOSE 3000

# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Switch to non-root user
USER sparc

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "dist/index.js"]

# Metadata labels
LABEL maintainer="SPARC Team" \
      version="1.0.0" \
      description="SPARC API Gateway - Central routing and authentication service" \
      org.opencontainers.image.title="SPARC API Gateway" \
      org.opencontainers.image.description="Central routing and authentication service for SPARC platform" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="SPARC" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/sparc/api-gateway" \
      security.scan="enabled"