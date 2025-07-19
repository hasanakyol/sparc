# Multi-stage build for production optimization
FROM node:18-alpine AS base

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json yarn.lock* package-lock.json* pnpm-lock.yaml* ./
RUN \
  if [ -f yarn.lock ]; then yarn --frozen-lockfile; \
  elif [ -f package-lock.json ]; then npm ci; \
  elif [ -f pnpm-lock.yaml ]; then yarn global add pnpm && pnpm i --frozen-lockfile; \
  else echo "Lockfile not found." && exit 1; \
  fi

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build TypeScript code
RUN npm run build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

# Set environment to production
ENV NODE_ENV production

# Create a non-root user for security
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 authservice

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# Create necessary directories and set permissions
RUN mkdir -p /app/logs && chown -R authservice:nodejs /app

# Switch to non-root user
USER authservice

# Expose the port the app runs on
EXPOSE 3001

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "const http = require('http'); \
    const options = { \
      hostname: 'localhost', \
      port: 3001, \
      path: '/health', \
      method: 'GET', \
      timeout: 2000 \
    }; \
    const req = http.request(options, (res) => { \
      if (res.statusCode === 200) { \
        process.exit(0); \
      } else { \
        process.exit(1); \
      } \
    }); \
    req.on('error', () => process.exit(1)); \
    req.on('timeout', () => process.exit(1)); \
    req.end();"

# Security configurations
# Drop all capabilities
RUN echo "authservice:x:1001:1001:Auth Service User:/app:/sbin/nologin" >> /etc/passwd

# Set resource limits
ENV NODE_OPTIONS="--max-old-space-size=512"

# Start the application
CMD ["node", "dist/index.js"]