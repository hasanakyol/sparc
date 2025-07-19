# Build stage
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Copy workspace packages
COPY packages/shared ./packages/shared
COPY packages/database ./packages/database

# Copy service source
COPY services/maintenance-service ./services/maintenance-service

# Install dependencies
RUN npm ci --workspace=@sparc/maintenance-service

# Build the service
RUN npm run build --workspace=@sparc/maintenance-service

# Runtime stage
FROM node:20-alpine

# Install runtime dependencies
RUN apk add --no-cache tini

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/services/maintenance-service/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/services/maintenance-service/package*.json ./
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/packages ./packages

# Set user
USER nodejs

# Expose port
EXPOSE 3010

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3010/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

# Use tini for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start the service
CMD ["node", "dist/index.js"]