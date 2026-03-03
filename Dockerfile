# ─── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache libc6-compat openssl

RUN corepack enable && corepack prepare pnpm@latest --activate

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Create a Linux-compatible .npmrc (ignore platform restrictions during install)
RUN echo "os=linux" > .npmrc && \
    echo "cpu=x64,arm64" >> .npmrc && \
    echo "libc=musl,glibc" >> .npmrc

# Install all dependencies (including devDependencies for build)
RUN pnpm install --no-frozen-lockfile

COPY . .

RUN pnpm exec prisma generate
RUN pnpm run build
RUN pnpm prune --prod

# ─── Stage 2: Runner ──────────────────────────────────────────────────────────
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

RUN apk add --no-cache libc6-compat openssl

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package.json ./
COPY --from=builder --chown=appuser:appgroup /app/prisma ./prisma

# Create logs directory with correct ownership before switching user
RUN mkdir -p logs && chown -R appuser:appgroup logs

USER appuser

EXPOSE 3000

CMD ["node", "dist/src/main"]
