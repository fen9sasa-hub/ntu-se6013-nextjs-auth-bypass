# M1 handoff contract

Active case: CVE-2025-29927. This is the implementation proposal from M1 for M3 and M4 to review, not evidence that every member has accepted an interface.

## Current application

- Installed target ID: `vulnerable`.
- Next.js: exactly `14.2.24`, from the lockfile and the running health identity.
- Profile: `middleware-only`. Session validation lives in `app/middleware.js`. The page and records handler deliberately do not add the independent M4 server-authorisation defence.
- Public target page: `/lab/vulnerable`.
- Login page: `/lab/vulnerable/login`.
- Protected page: `/lab/vulnerable/dashboard`.
- Protected data: `/lab/vulnerable/api/records`.
- Stable protected-content marker: `M1-FICTIONAL-RECORDS-ONLY`. It appears only in the protected page/data response, not in public target pages or the public health identity. The marker is an assertion aid, not a secret.
- Internal target address: `http://vulnerable:3000`, reachable by service name only on the isolated Compose network. No target host port is published.
- Private health: `GET /lab/vulnerable/api/health`. Returns actual `target`, `version`, `profile`, `ready` values; no credentials or session material.
- Login: `POST /lab/vulnerable/api/login`, URL-encoded `username` and `password`, same-origin form only. Success issues the signed target cookie and responds `303` to the dashboard; failure redirects to the login error state without issuing a cookie.
- Logout: same-origin `POST /lab/vulnerable/api/logout`. Deletes the current browser cookie. Stateless-token limitations are in the M1 README.
- Anonymous/invalid-session page request: `307` to the login page, without following redirects. Anonymous/invalid-session records request: `401` JSON without the protected marker.

The operator Basic Auth gate is independent of this target session. The browser gateway forwards only the target cookie, acceptable content headers and a validated form origin. It never forwards the operator Authorization header or framework-internal headers. It is NOT the experiment runner and must not be used to evaluate the CVE or attribute a defence. M3's fixed scenarios must address the private target directly. Otherwise the gateway's header omission can mask the experiment.

## Reserved target IDs and member ownership

- `vulnerable`: M1 application baseline, installed here.
- `patched`: M4 historical framework-patch comparison, not installed by M1's compose; added by `m4-remediation/compose.defences.yaml` (see M4 Targets).
- `header-filter`: M4 dedicated header-rejection boundary, likewise added by the M4 compose file.
- `server-auth`: M4 independent server-side authorisation, likewise added by the M4 compose file.

The panel lists the three M4 IDs as not installed, honestly, until its registry is extended (proposed entry in M4 Targets). No framework version or experiment measurement is invented for them. Before adding another target, M4 and M1 must agree its base path, cookie name/signing secret, identity endpoint and gateway/registry entry. Reuse the same fictional records and normal authentication logic; keep each added defence isolated.

## M3 extension boundary

M1 owns `m1-lab/control-ui/` and the shared gateway. M3 owns the future test runner and evidence components. Coordinate shared-file changes through a PR; do not copy a second independent shell.

Reserved fixed scenario IDs:

- `anonymous-normal`
- `anonymous-cve`
- `valid-session`
- `invalid-session`

M3 must accept a target ID and scenario ID from a fixed registry, never an arbitrary URL, path, command or header dictionary. Anonymous scenarios start without target cookies. Keep response bodies escaped, bound bytes/time/concurrency, and do not follow the initial redirect automatically.

Suggested evidence object (types and semantics, not an invented result):

- `schema_version`: string, initially `1`.
- `run_id`: freshly generated string; unique per execution.
- `started_at`: ISO UTC timestamp.
- `source_commit`: exact Git commit, or explicit `null` plus dirty/uncommitted state.
- `target`: object with target ID, observed Next.js version and observed profile.
- `scenario`: fixed scenario ID.
- `expected`: separately labelled planned assertion, never a measurement.
- `request`: method, fixed path and redacted relevant headers. No cookies, passwords or operator credentials.
- `response`: status, redirect location, bounded escaped body and truncation flag; `null` on transport failure.
- `observed`: `denied`, `protected-content-returned`, `error` or `inconclusive`.
- `elapsed_ms`: measured duration.
- `error`: safe explanation or `null`.
- `logs`: optional correlated evidence; absence is not proof that middleware was skipped.

A `200` alone is not a bypass assertion. Require the intended route and protected-content marker, and record unexpected responses without relabelling them as successful blocks.

Future retained exports belong under `evidence/<run-id>/`; compute an integrity hash over the actual exported bytes. No exporter or run store is implemented by M1. A future reset must clear only the selected target's local session/run state, never unrelated host or production state. Session-key rotation affects outstanding tokens for that target and must not rewrite exported historical run identities.

## Review order

M2 reviews M1's application/setup. M3 co-reviews this interface. M4 adds the historical patched target and separate defences. M5 independently repeats the integrated experiment. M1 self-tests do not replace those reviews or establish whole-project completion.

## M4 Targets

M4 contributes three remediation targets alongside M1's `vulnerable` baseline. Each
isolates a single change and is evaluated with the fixed scenario IDs and the evidence
schema already defined in this contract.

All M4 targets:

- reuse M1's fictional records and normal authentication logic unchanged;
- expose the protected marker `M1-FICTIONAL-RECORDS-ONLY` only in protected page and data
  responses — never in public pages or the health/identity response;
- run on the isolated Compose network with no host port published, and are addressed
  directly (not via the browser gateway) for CVE evaluation;
- keep independent state; a reset clears only the selected target.

A `200` status alone is not a bypass assertion: a bypass requires the intended protected
route **and** the protected marker in the response body.

### Target registry

The three M4 targets are installed by `m4-remediation/compose.defences.yaml`, merged with M1's
`compose.yaml`. The **Health `profile`** column is the exact value each target's
`/api/health` reports.

| Target ID | Role | Next.js | Health `profile` | Base path | Internal address |
|---|---|---|---|---|---|
| `vulnerable` | M1 baseline, middleware-only authorisation | 14.2.24 | `middleware-only` | `/lab/vulnerable` | `http://vulnerable:3000` |
| `patched` | framework-patch comparison, middleware-only authorisation | `14.2.25` | `middleware-only` | `/lab/patched` | `http://patched:3000` |
| `header-filter` | 14.2.24 app behind a header-rejection boundary | 14.2.24 | `header-filter` | `/lab/header-filter` | `http://header-filter:3000` (the boundary; the app is `header-filter-app` on a backend-only network) |
| `server-auth` | middleware + independent route-layer authorisation | 14.2.24 | `server-auth` | `/lab/server-auth` | `http://server-auth:3000` |

Each target serves the same sub-routes as `vulnerable` under its base path: `/login`,
`/dashboard`, `/api/records`, `/api/health`, `/api/login`, `/api/logout`.

### Shared session parameters (proposed by M4; pending M1 confirmation)

- Session cookie name: `lab_<target ID with "-" as "_">_session`, i.e. `lab_vulnerable_session`,
  `lab_patched_session`, `lab_header_filter_session` and `lab_server_auth_session`. All use
  `Path=/lab/<target ID>`, `HttpOnly`, `SameSite=Strict` and a 15-minute expiry, derived in
  `m1-lab/app/lib/auth.mjs` from the build-time target ID.
- Session signing/verification: the same `m1-lab/shared/session.mjs` (HMAC-SHA256, token bound to its
  target ID), with a separate secret and password per target: `PATCHED_*`, `HEADER_FILTER_*` and
  `SERVER_AUTH_*` (`_SESSION_SECRET`, `_PASSWORD`). Each maps to the container's `LAB_SESSION_SECRET` /
  `LAB_PASSWORD`; the username `LAB_USER` is shared. `node ../m4-remediation/init-env.mjs` generates
  them into the private `m1-lab/.env`.
- `invalid-session` means (proposal for M3's runner): a well-formed, unexpired token for the same
  target ID, signed with a key that target does not hold, i.e. a signature mismatch. M4's checks also
  use a malformed value (`yes`) and another target's genuine token.
- The health/identity response carries no marker, credentials, or session material.

### Target notes

- **`patched`** — identical to `vulnerable` except the framework version (`14.2.25`, the
  14.x fix line; the base contract left the patched version open). Isolates the upstream fix.
- **`header-filter`** — an isolated `vulnerable` (14.2.24) instance (`header-filter-app`)
  behind a boundary that rejects the client-supplied `x-middleware-subrequest` header
  before it reaches the app. Compensating control, not a root-cause fix.
- **`server-auth`** — a `vulnerable` (14.2.24) instance that re-validates the session in
  the route/data layer (protected page and `/api/records`), independent of middleware.
  M1's two handlers are kept byte-for-byte and wrapped. The check runs before any record is
  rendered or returned.
- **`server-auth-guard-only`** — test fixture, not a target ID. It is the `server-auth` build with
  `middleware.js` removed, under the Compose `check` profile only. It shows the guard enforces
  access on its own, without the CVE request.

### Denial attribution

Each layer's refusal is distinguishable in the evidence:

- **Middleware** (all targets): page `307` to the absolute `<LAB_PUBLIC_ORIGIN>/lab/<id>/login`;
  records `401` `{"error": …}`.
- **server-auth guard**: page `307` to the relative `/lab/server-auth/login?denied=server-auth`;
  records `401` with `"layer": "server-auth"`.
- **header-filter boundary**: `400`, `X-Lab-Boundary-Decision: rejected-internal-header` and
  `"layer": "header-filter"`.

Every response the boundary relays or generates itself carries `X-Lab-Boundary: header-filter`. A
client that aborts or stalls its request body is logged `client-request-incomplete`, never as an
application failure. Node's HTTP parser refuses some requests before the boundary's code runs:
`400` for malformed syntax, `431` for oversized headers and `408` for a header timeout. Those
responses carry no `X-Lab-Boundary` header or JSON body and produce no log line. Record them as
`error`, never as `denied`.

Client-navigation (RSC) requests differ. When one reaches the server-auth page without middleware,
the guard's denial is `200 text/x-component`, with the redirect
`NEXT_REDIRECT;replace;/login?denied=server-auth;307;` inside the flight payload and no marker.
Classify RSC responses by the marker and that redirect, not by status. Malformed framework inputs
(an unparseable router-state header, a fake Server Action) return `500` before the guard runs.
Record those as `error`, never as `denied`.

### Expected evidence (planned; never a measurement)

Planned `observed` outcome per target for the fixed scenarios. (`observed` ∈ `denied` /
`protected-content-returned` / `error` / `inconclusive`.)

| Target | `anonymous-normal` | `anonymous-cve` | `valid-session` | `invalid-session` |
|---|---|---|---|---|
| `vulnerable` | denied | protected-content-returned | protected-content-returned | denied |
| `patched` | denied | denied | protected-content-returned | denied |
| `header-filter` | denied | denied | protected-content-returned | denied |
| `server-auth` | denied | denied | protected-content-returned | denied |

Only `vulnerable` returns protected content to `anonymous-cve`. `valid-session` returning
protected content is the correct authorized outcome — the scenario ID, not the status
code, carries the authentication context. The `anonymous-cve` request is defined and
validated by M3's fixed runner against the live `vulnerable` target; M4 does not construct
or assume it.

Two rules keep an ineffective `anonymous-cve` request from looking like a successful defence:

- **Positive control.** A `denied` result for `patched`, `header-filter` or `server-auth` counts
  only if `vulnerable` returned the marker to the identical `anonymous-cve` request in the same
  run. Otherwise record those rows as `inconclusive`.
- **Expected deciding layer** (see Denial attribution):
  - `patched`: the middleware shape (absolute login `Location`, or `401` without `layer`);
  - `header-filter`: the boundary's `400` with `rejected-internal-header`;
  - `server-auth`: the guard's shape (relative `Location` with `denied=server-auth`, or `401` with
    `"layer": "server-auth"`). A middleware-shaped denial here means the request did not reach the
    guard. Record it as `inconclusive`, not as evidence for the guard.

### Build & registry

- Targets build from M1's app source (`m1-lab/app`) via `m4-remediation/target.Dockerfile`. They do
  not copy the application.
  - Build args `LAB_TARGET_ID` and `LAB_PROFILE` are read by `m1-lab/app/next.config.mjs` and inlined
    at build time. The defaults (`vulnerable` / `middleware-only`) keep M1's own build unchanged.
  - The framework version comes from the committed manifest pair (M1's for 14.2.24,
    `m4-remediation/patched/` for 14.2.25), not from a version build arg, so `npm ci` stays
    lockfile-exact.
  - Each target's difference is one `change-*` stage.
- Proposed control-ui registry entry (not yet implemented; a coordinated M1/M3 change):
  `{ "id", "address", "basePath", "expected": { "target", "version", "profile" }, "boundary" }`.
  For example: `{ "id": "header-filter", "address": "http://header-filter:3000", "basePath":
  "/lab/header-filter", "expected": { "target": "header-filter", "version": "14.2.24", "profile":
  "header-filter" }, "boundary": "header-filter" }`. The panel verifies health as it does for
  `vulnerable` today, and for `header-filter` also requires the `X-Lab-Boundary` header.
