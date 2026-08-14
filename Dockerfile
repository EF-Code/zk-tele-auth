# Production image. The base image is pinned to an immutable manifest digest;
# update it only through a reviewed dependency/image-refresh change.
FROM node:24.7.0-bookworm-slim@sha256:0104d9447ea3ddf7373643be7f9915fc7b7c896e41d0d33229338e457217cd78 AS build

ARG SOURCE_REVISION=unknown
ARG ARTIFACT_MANIFEST_DIGEST=unknown

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

FROM node:24.7.0-bookworm-slim@sha256:0104d9447ea3ddf7373643be7f9915fc7b7c896e41d0d33229338e457217cd78 AS runtime

ARG SOURCE_REVISION=unknown
ARG ARTIFACT_MANIFEST_DIGEST=unknown

ENV NODE_ENV=production
ENV PORT=8080
ENV ZK_TELE_AUTH_HOST=0.0.0.0
ENV TMPDIR=/tmp
WORKDIR /app
RUN groupadd --system --gid 10001 zkapp && useradd --system --uid 10001 --gid 10001 --create-home zkapp
RUN mkdir -p /tmp && chown 10001:10001 /tmp
COPY --from=build --chown=zkapp:zkapp /app/package.json /app/package-lock.json ./
COPY --from=build --chown=zkapp:zkapp /app/node_modules ./node_modules
COPY --from=build --chown=zkapp:zkapp /app/dist ./dist
COPY --from=build --chown=zkapp:zkapp /app/artifacts ./artifacts
COPY --from=build --chown=zkapp:zkapp /app/config ./config
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
LABEL org.opencontainers.image.source-revision=$SOURCE_REVISION \
      org.opencontainers.image.artifact-manifest-digest=$ARTIFACT_MANIFEST_DIGEST \
      org.opencontainers.image.title="zk-tele-auth gateway"
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:8080/livez').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
ENTRYPOINT ["node", "dist/gateway/main.js"]
