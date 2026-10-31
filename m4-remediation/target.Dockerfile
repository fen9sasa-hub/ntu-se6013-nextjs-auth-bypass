# check=skip=InvalidDefaultArgInFrom
# Every M4 target = M1's unchanged application source + exactly one named change (the change-* stages).
# Build context is the repository root; see compose.defences.yaml. Same pinned Node 22 image as M1.
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d
# No default on purpose: compose.defences.yaml always passes it, and a build without it must fail
# rather than pick a target. The check directive above silences BuildKit's lint for this deliberate case.
ARG M4_CHANGE

FROM ${NODE_IMAGE} AS m1-source
WORKDIR /lab/app
COPY m1-lab/app/ ./
COPY m1-lab/shared/ /lab/shared/

# patched: only the framework dependency and its lockfile (Next.js 14.2.25).
FROM m1-source AS change-patched
COPY m4-remediation/patched/package.json m4-remediation/patched/package-lock.json ./

# header-filter: no application change. The defence is the separate boundary service.
FROM m1-source AS change-header-filter

# server-auth: M1's protected page and records handler stay byte-for-byte as colocated, non-routable
# modules, wrapped by an independent server-side session check before any record is returned.
FROM m1-source AS change-server-auth
RUN mv app/dashboard/page.js app/dashboard/m1-page.js \
 && mv app/api/records/route.js app/api/records/m1-route.js
COPY m4-remediation/server-auth/overlay/ ./

# Test-only ablation (compose profile `check`): server-auth with middleware removed, so the guard is
# exercised on its own. Never a lab target.
FROM change-server-auth AS change-server-auth-guard-only
RUN rm middleware.js

FROM change-${M4_CHANGE} AS build
ARG LAB_TARGET_ID
ARG LAB_PROFILE
ENV NEXT_TELEMETRY_DISABLED=1 LAB_TARGET_ID=${LAB_TARGET_ID} LAB_PROFILE=${LAB_PROFILE}
RUN npm ci --ignore-scripts --no-audit --no-fund && npm run build

FROM ${NODE_IMAGE} AS runtime
WORKDIR /lab
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build --chown=node:node /lab/app/.next/standalone/ ./
COPY --from=build --chown=node:node /lab/app/.next/static/ ./app/.next/static/
USER node
EXPOSE 3000
CMD ["node", "app/server.js"]
