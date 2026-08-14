# Production image. The base image is pinned to an immutable manifest digest;
# update it only through a reviewed dependency/image-refresh change.
FROM node:22.14.0-bookworm-slim@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json README.md ./
COPY src ./src
COPY artifacts ./artifacts
COPY circuits ./circuits
COPY contracts ./contracts
COPY config ./config
RUN npm run build
RUN npm prune --omit=dev --ignore-scripts

FROM node:22.14.0-bookworm-slim@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b AS runtime

ENV NODE_ENV=production
ENV PORT=8080
ENV ZK_TELE_AUTH_HOST=0.0.0.0
WORKDIR /app
RUN groupadd --system --gid 10001 zkapp && useradd --system --uid 10001 --gid 10001 --create-home zkapp
COPY --from=build --chown=zkapp:zkapp /app/package.json /app/package-lock.json ./
COPY --from=build --chown=zkapp:zkapp /app/node_modules ./node_modules
COPY --from=build --chown=zkapp:zkapp /app/dist ./dist
COPY --from=build --chown=zkapp:zkapp /app/artifacts ./artifacts
COPY --from=build --chown=zkapp:zkapp /app/config ./config
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["node", "dist/gateway/main.js"]

