FROM node:22-bookworm-slim AS build
WORKDIR /app
ARG NEXT_PUBLIC_API_URL=http://localhost:4000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web/package.json ./apps/web/package.json
COPY apps/api/package.json ./apps/api/package.json
COPY packages/shared-types/package.json ./packages/shared-types/package.json
RUN pnpm install --frozen-lockfile
COPY apps/web ./apps/web
COPY packages/shared-types ./packages/shared-types
RUN pnpm --filter @dependencyshield/web build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build --chown=node:node /app/apps/web/.next/standalone ./
COPY --from=build --chown=node:node /app/apps/web/.next/static ./apps/web/.next/static
USER node
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
