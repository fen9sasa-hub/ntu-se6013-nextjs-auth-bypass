# M4: patched target and two separate defences

M4's question: which individual change stops the same bypass attempt, and does legitimate access still work? This directory adds three targets next to M1's `vulnerable` baseline. Each differs from `vulnerable` by exactly one change, so a result can be attributed to that change alone.

This is runnable lab code and internal handoff documentation, not assessed report or presentation text. M4's own verification receipt is [VERIFICATION.md](VERIFICATION.md). The shared interface is the M4 section of [docs/contracts.md](../docs/contracts.md).

## Targets

| Target | The one change from `vulnerable` | Source | Health identity (`target` / `version` / `profile`) |
|---|---|---|---|
| `patched` | Next.js 14.2.24 → 14.2.25. Only `package.json` and the lockfile differ; the lockfile diff is limited to `next` and `@next/*`. | [patched/](patched/) | `patched` / `14.2.25` / `middleware-only` |
| `header-filter` | No application change. A separate boundary rejects any request carrying `x-middleware-subrequest` and relays everything else unchanged. The 14.2.24 app (`header-filter-app`) is reachable only through it. | [header-filter/](header-filter/) | `header-filter` / `14.2.24` / `header-filter`, plus `X-Lab-Boundary: header-filter` on every response the boundary relays or generates |
| `server-auth` | M1's dashboard page and records handler are wrapped by a server-side session check that runs before any record is rendered or returned. Middleware is unchanged and still runs. | [server-auth/overlay/](server-auth/overlay/) | `server-auth` / `14.2.24` / `server-auth` |

Not combined: `patched` has no boundary or guard, `header-filter` runs M1's unguarded handlers, and `server-auth` runs 14.2.24 without a boundary.

[tests/isolation.test.mjs](tests/isolation.test.mjs) fails if any of these drift: a `change-*` stage, the shared build or runtime stage, the overlay file set, the boundary's imports, or the Compose isolation settings. It cannot detect target-conditional code added to M1's shared source; review catches that.

A fourth build, `server-auth-guard-only`, is a test fixture, not a lab target. It is the `server-auth` build with `middleware.js` deleted. It runs only under the Compose `check` profile, on a network only the checker joins. It shows that the server-side guard enforces access on its own, without using the CVE request.

## How the targets are built

All targets build from M1's application source with [target.Dockerfile](target.Dockerfile). Each `change-*` stage holds one target's entire difference. The build and runtime stages are shared; the runtime stage is pinned to M1's step for step, and both use M1's pinned image.

- **Identity.** M1's `next.config.mjs` reads the build args `LAB_TARGET_ID` and `LAB_PROFILE` and inlines them, so the base path (`/lab/<id>`), cookie name (`lab_<id with _>_session`) and health identity are fixed per image. With no build args it builds M1's `vulnerable` target exactly as before.
- **Framework version.** It comes from the committed manifest pair: M1's for 14.2.24, `patched/` for 14.2.25. It is not a version build arg, because `npm ci` must match a committed lockfile.
- **server-auth.** M1's `page.js` and `route.js` are kept byte-for-byte as colocated `m1-page.js` / `m1-route.js`. Next.js does not route them. The overlay's `page.js` / `route.js` call the guard first, then delegate to M1's code. The guard reuses M1's `verify()` and cookie, so session validation is identical to every other target.
- **Secrets.** Each target has its own password and signing secret, and every session token is bound to its target ID. A cookie from one target is never valid on another; a live check covers every pair.

## Run

From `m1-lab/`, with Docker Compose v2. This lab has run end to end on Docker 29.9.2 with Compose v5.6.1 (see [VERIFICATION.md](VERIFICATION.md)). That run first built each service separately (`docker compose -f compose.yaml -f ../m4-remediation/compose.defences.yaml --profile check build <service>`), so only one Next.js build used memory at a time. Do the same on a small machine.

```sh
node deploy/init-env.mjs                 # once: M1's private .env
node ../m4-remediation/init-env.mjs      # once: adds the six M4 variables to the same .env
docker compose -f compose.yaml -f ../m4-remediation/compose.defences.yaml up --build -d --wait
```

Compose resolves relative paths in both files against `m1-lab/`, the directory of the first file. No M4 service publishes a host port. M1's control panel still lists the M4 targets as not installed: its registry is M1/M3's shared file, and the proposed entry format is in the contract. M3's runner addresses the targets directly at `http://patched:3000`, `http://header-filter:3000` and `http://server-auth:3000`.

Create `m1-lab/.env` only with `node deploy/init-env.mjs`, never by copying `.env.example`. `init-env.mjs` refuses to run if any of the six M4 variables, or M1's `CONTROL_PASSWORD`, `LAB_PASSWORD` or `LAB_SESSION_SECRET`, is empty or still an example placeholder. As a second line of defence, each target's health reports not-ready (`503`, which fails `--wait`) when its password or signing secret is shorter than the minimum. The M4 example placeholders are deliberately that short.

Shut down with the same file list plus the check profile. `run --rm` removes only `m4-check` itself, and the `server-auth-guard-only` fixture it started keeps running until this:

```sh
docker compose -f compose.yaml -f ../m4-remediation/compose.defences.yaml --profile check down --remove-orphans
```

## Checks

Without a running lab, from the repository root (Node 22+; the Compose check also needs Python 3 with PyYAML, otherwise it is skipped):

```sh
node --test m4-remediation/tests/header-filter.test.mjs m4-remediation/tests/isolation.test.mjs
```

- `header-filter.test.mjs` runs the real boundary on loopback in front of a recording stub upstream. It covers rejection in any header-name case or repetition, the upstream never seeing rejected requests, unchanged relaying (redirects not followed, multiple `Set-Cookie`, Host), body framing, size, time and concurrency bounds, upstream failures reported as errors, and slow or abandoned client bodies. Those hold no upstream slot, are cut near the configured deadline and are never blamed on the application.
- `isolation.test.mjs` is static. It checks the lockfile diff, the base image pin, the exact contents of each `change-*` stage, the server-auth wrapping order, that the boundary has no authorisation logic, M1's identity defaults, and the Compose networks, ports, privileges and per-target secrets.

Against the running targets, inside the private networks (from `m1-lab/`):

```sh
docker compose -f compose.yaml -f ../m4-remediation/compose.defences.yaml --profile check run --rm --build m4-check
```

`tests/targets.test.mjs` sends the same requests to `vulnerable`, `patched`, `header-filter` and `server-auth`:
- identity, and the public page without the marker;
- `anonymous-normal`, including a client-navigation (RSC) request;
- `invalid-session`: a malformed value, and a well-formed unexpired token signed with a key the target does not hold;
- `valid-session` (marker on page and data), logout, wrong credentials, cross-origin login;
- every cross-target cookie pair;
- the boundary's rejections, including alongside a valid session;
- the guard-only fixture.

It never sends the `anonymous-cve` request. Boundary checks send the internal header with the neutral value `external-untrusted`, as M1's baseline does.

## Denial attribution

Which layer refused a request is visible in the response, so evidence does not credit the wrong control:

| Layer | Page (`/dashboard`) | Data (`/api/records`) |
|---|---|---|
| Middleware (all targets) | `307`, absolute `Location: <LAB_PUBLIC_ORIGIN>/lab/<id>/login` | `401` `{"error": …}` |
| server-auth guard | `307`, relative `Location: /lab/server-auth/login?denied=server-auth` | `401` `{"error": …, "layer": "server-auth"}` |
| header-filter boundary | `400`, `X-Lab-Boundary-Decision: rejected-internal-header`, `{"layer": "header-filter"}` | same |

Responses relayed by the boundary carry `X-Lab-Boundary: header-filter`. The boundary logs one JSON line per decision: decision, status, method and bounded path, never header values. This supports M3's log correlation. Client-side failures (an aborted or too-slow request body) are logged as `client-request-incomplete`, never as an application failure. Requests that Node's HTTP parser refuses before the boundary's code runs are different: malformed syntax (`400`), oversized headers (`431`) and header timeouts (`408`). They carry no `X-Lab-Boundary` header or log line and count as `error`, not `denied`.

Client-navigation (RSC) requests are the exception to the table. When one reaches the page without middleware, the guard's denial is a `200 text/x-component` flight response whose payload carries `NEXT_REDIRECT;replace;/login?denied=server-auth;307;` and no marker. The guard-only check asserts this. Classify such responses by the marker and that redirect, never by status alone. Synthetic malformed framework inputs, such as an unparseable router-state header or a fake Server Action, return `500` before the guard runs; that is an `error`, not a block.

## Limits of each change

- **patched.** It addresses the framework behaviour named in the vendor advisory, but the application still authorises only in middleware: one layer. A later middleware gap would expose data again, such as a matcher that misses a new route or a different framework flaw. 14.2.25 is a historical comparison point, not a production recommendation. npm marks both 14.2.24 and 14.2.25 as deprecated, citing a later security update (https://nextjs.org/blog/security-update-2025-12-11) that this lab does not examine. Only the listed routes are tested.
- **header-filter.** A compensating control, not a root-cause fix. It works only while every request passes through the boundary. Compose enforces this here with a backend network, but in a real deployment any path to the application that skips the proxy also skips the rule. It covers exactly one header name. Both sides use Node's HTTP parser, so they agree on header parsing; a different proxy in front of Next.js would need its own parser-agreement check. It rejects rather than strips, so the decision is visible in evidence; legitimate clients never send this header.
- **server-auth.** It protects only the two handlers it wraps. Any new protected route needs the same guard, or that route falls back to middleware-only. It does not change the framework, and middleware still makes the normal-request decisions. The fictional records are a static module loaded at startup: the guard prevents them from being rendered or returned, not from being loaded into memory.
- **guard-only fixture.** It shows the guard's independence only for the requests tested. It is not a deployment.

## Not done here

- No `anonymous-cve` result exists for any target. The expected-outcome table in the contract is planned, not measured. M4 repeats M3's fixed scenarios once M3's runner exists, and retains those responses under `evidence/<run-id>/`.
- M1's control panel registry and browser gateway are unchanged; the proposed registry entry is in the contract.
- M1's Playwright browser checks were not rerun, and Docker was exercised only on Linux x86_64. See [VERIFICATION.md](VERIFICATION.md).

## Primary sources

- [Vendor advisory, GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw): affected and fixed versions, and the recommended mitigation when upgrading is not possible (block external requests that carry `x-middleware-subrequest`).
- [Vendor postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass): the vendor's response and timeline.
- [Original researcher disclosure](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware).

M2 owns the source-level trace of the vulnerable and patched releases.
