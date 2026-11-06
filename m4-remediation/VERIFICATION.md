# M4 verification receipt

First verified on 31 October 2026, then rerun on the final submitted source on 1 November 2026. This is an implementation self-review receipt. It is not M3's review of M4, M5's independent repetition, a CVE reproduction or a deployment result.

## Tested revision

A receipt cannot name the commit that contains it, so the tested source is identified by its prerequisite and a checksum.

- **Base:** `main` at `b4c21b2427459dfe4faf967416b1e7fc8d963aac`.
- **Prerequisite:** M1's build-time target identity, commit `d079d580c35eb92ebe241fff5f30ef793de6e493` ("feat(m1): make target identity a build-time setting", PR #4). Without it the M4 targets build as copies of `vulnerable`. It also carries the page label and health-readiness checks this receipt relies on.
- **Tested source:** `m1-lab/` and `m4-remediation/` as committed on top of that prerequisite, excluding this receipt. Checksum `295cbe09a35f3d37fbe42d996a49808dfacc2e0c63830569124b37aaa845200f`. To confirm a checkout holds the tested source, run from the repository root:

  ```sh
  git ls-tree -r HEAD -- m1-lab m4-remediation | grep -v 'm4-remediation/VERIFICATION.md$' | sha256sum
  ```

  The value depends only on file contents and paths, so rebases, merge commits, line-ending settings and edits to this receipt do not change it.
- **Reproduce:** the host suites under Checks in the [README](README.md), then, from `m1-lab/`, its Run and live-check commands.

## Execution environment

- Linux x86_64, 2 CPUs. The host reported 3.3 GB RAM during the local builds and 7.2 GiB during the container run.
- Local builds, runtimes and checks: Node v22.23.4 with npm 10.9.9. This is the official linux-x64 tarball, SHA-256-checked against nodejs.org's `SHASUMS256.txt`; it is the Node version M1's receipt reports for the pinned image. Host-only tests also ran on Node v26.13.0.
- Docker Engine 29.9.2 with Compose v5.6.1 and buildx 0.38.1. The machine owner installed it with apt at 13:03 on 31 October and added this account to the `docker` group at 16:20. Both container runs happened in sessions started after that.
- Python 3.14 with PyYAML 6.0.3 and jsonschema 4.19.2.

## Container run (Docker)

Rerun on 1 November 2026 against the tested revision above, from a clean `git archive` extraction: 66 files, with no `.env`, `node_modules` or `.next`. `node deploy/init-env.mjs` and `node ../m4-remediation/init-env.mjs` generated fresh credentials, which were never printed. The first run, on 31 October from a copy whose application code was byte-identical, gave the same results.

- **Base image.** M1's pinned `node:22-bookworm-slim@sha256:de170b…` is a multi-platform index that includes `linux/amd64` and `linux/arm64/v8`, so the pin works on both machine types used so far.
- **Builds.** All eight images were built one service at a time with `docker compose … --profile check build --no-cache <service>`: `vulnerable`, `control`, `header-filter`, `m4-check`, `patched`, `header-filter-app`, `server-auth`, `server-auth-guard-only`. Each Next.js build took 48–53 s. The only steps BuildKit reported as cached were `WORKDIR` instructions and the digest-pinned base image; every `COPY` and `RUN`, including `npm ci` and `next build`, ran fresh.
  - The build logs show BuildKit running each target's own change stage:
    - `change-patched` copied the patched manifests;
    - `change-server-auth` moved M1's two handlers and copied the overlay;
    - `change-server-auth-guard-only` removed `middleware.js`;
    - `header-filter-app` ran no change step.
  - No BuildKit check warnings appeared, so the `check=skip` directive works.
  - Read back inside each image, with no network and a read-only filesystem:
    - Next.js is 14.2.25 in `patched` only and 14.2.24 elsewhere;
    - the compiled base paths are `/lab/vulnerable`, `/lab/patched`, `/lab/header-filter` and `/lab/server-auth` (the guard-only image also uses `/lab/server-auth`);
    - the middleware manifest is empty only in the guard-only image;
    - all five route tables are identical (8 routes).
  - npm printed one warning per Next.js build: `npm warn deprecated next@14.2.24` (`next@14.2.25` for `patched`), "This version has a security vulnerability. Please upgrade to a patched version. See https://nextjs.org/blog/security-update-2025-12-11 for more details." That later security update was not examined or tested here.
- **Startup.** `docker compose -f compose.yaml -f ../m4-remediation/compose.defences.yaml up -d --wait` brought all six default-profile containers to healthy in 15 s. That includes the boundary's healthcheck, which requires `X-Lab-Boundary` on the relayed health response.
- **Identity and routes,** fetched from `control`. The `patched` image serves `/lab/patched/api/health` as `200` with `{"target":"patched","version":"14.2.25","profile":"middleware-only","ready":true}`, redirects an anonymous `/lab/patched/dashboard` with `307` to `/lab/patched/login`, and returns `404` for `/lab/vulnerable/api/health`. `header-filter`, `server-auth` and `vulnerable` each report their own target and version. Without the prerequisite, the same `patched` build serves `/lab/vulnerable` and answers as `vulnerable` instead.
- **Live checks in the private networks.** `--profile check run --rm m4-check`: 19 passed, 0 failed, 0 skipped. This is the same suite as the local run; it also started the guard-only fixture as a dependency.
- **M1's own acceptance check.** `node deploy/check.mjs`, run from the clean copy against the containerized lab through the control panel on `127.0.0.1:4317`: 8 passed, 0 failed. These are M1's six unit tests and two HTTP groups, the same check M1's receipt reports, now run against the image built from the parameterized source.
- **Hardening,** read back for all seven containers with `docker inspect` (environment never printed):
  - user `node`, read-only root, all capabilities dropped and none added, `no-new-privileges`, not privileged, `init`, no mounts, bounded `/tmp` tmpfs;
  - memory 512 MiB, 1 CPU and 128 PIDs for the five Next.js containers; 128 MiB, 0.5 CPU and 64 PIDs for `control` and the boundary;
  - only `control` publishes a port, `127.0.0.1:4317`.
- **Networks,** read back:
  - `edge` (not internal): `control`;
  - `lab` (internal, isolated gateway): `control`, `vulnerable`, `patched`, `header-filter`, `server-auth`;
  - `header-filter-backend` (internal, isolated): `header-filter`, `header-filter-app`;
  - `m4-check` (internal, isolated): `server-auth-guard-only`, plus `m4-check` while it runs.
- **Reachability,** probed from inside the containers with health fetches and bare TCP connects only:
  - From `control`: the boundary answered `200` with `X-Lab-Boundary`, and `patched` and `server-auth` answered `200`. `header-filter-app` and the guard-only fixture did not resolve (`ENOTFOUND`), so a runner on `lab` can neither skip the boundary nor reach the fixture.
  - From the `m4-check` position: the guard-only fixture and the boundary answered `200`; `header-filter-app` did not resolve.
  - From `header-filter-app`, none of `vulnerable`, `patched` or `control` resolved. From the guard-only fixture, neither `patched` nor `header-filter` resolved.
  - Egress: from `vulnerable`, `patched`, `header-filter-app`, `header-filter`, `server-auth` and the guard-only fixture, TCP connects to `1.1.1.1:443` and `169.254.169.254:80` returned `ENETUNREACH`. Nothing was sent.
- **Boundary log** from the container: 48 decision lines (41 `forwarded`, including healthchecks, and 7 `rejected-internal-header`), with no header values logged.
- **Health readiness in the image.** Given the `.env.example` placeholder as its password and secret, the `server-auth` image answered `503` with `"ready": false`.
- **Shutdown.** `--profile check down --remove-orphans` removed every project container and network, and none remained. The extraction's generated `.env` was deleted. The build cache this run created (1.75 GB) was pruned. The eight `se6013-m1-lab-*` images, rebuilt from the tested revision, remain, about 476 MB in total.

## Local checks (before Docker access)

Run on 31 October, before Docker access, on application code identical to the tested revision. The host suites were rerun on 1 November against the tested revision itself.

- **Patched manifests.** Changing only `next` to `14.2.25` and running `npm install --package-lock-only` gave byte-identical lockfiles with npm 10.9.2 and npm 10.9.9. Compared with M1's lockfile, 12 of 30 entries differ: the root dependency, `next` and ten `@next/*` packages. Every other installed package is identical.
- **Host tests.** `header-filter.test.mjs` + `isolation.test.mjs` + `session-guard.test.mjs`: 21 passed, 0 failed, 0 skipped, on both Node 22.23.4 and Node 26.13.0, including on a clean `git archive` extraction of the tested revision. M1's unit tests (`session`, `gateway`): 6 passed. The repository's Python identity-gate tests: 14 passed. `session-guard.test.mjs` exercises the exact `verifySession` the server-auth guard authorises with, across a genuine, expired, future-dated, malformed, wrong-key and cross-target token.
- **Mutation checks.** Nine deliberate regressions were each applied to a scratch copy, and every one fails at least one test:
  - a slot held while the body is read (fails in under 0.1 s);
  - Node's default 30 s timeout sweep;
  - a client failure reported as an upstream failure;
  - the dashboard guard deleted;
  - the records guard inverted;
  - an extra step in the shared build stage;
  - an extra step in the runtime stage;
  - a request header injected by the boundary;
  - the expiry check removed from the session module (the expired-token assertion fails).
- **Five production builds.** Each ran `next build` with `output: 'standalone'`, outside Docker, reproducing each `target.Dockerfile` stage's file operations and build args: M1's `vulnerable` with no build args, `patched`, `header-filter-app`, `server-auth` and `server-auth-guard-only`. They gave the same framework versions, route tables and middleware presence as the images above.
- **Live run.** Each build ran from its assembled standalone runtime, laid out as in the Dockerfile's runtime stage, on loopback ports. Credentials were fresh random per-target values held in memory and never printed. The boundary ran in front of `header-filter-app`; M1's unchanged control plane ran in front of `vulnerable`.
  - Health identities read back (`target` / `version` / `profile`):
    - `vulnerable` / `14.2.24` / `middleware-only`
    - `patched` / `14.2.25` / `middleware-only`
    - `header-filter` / `14.2.24` / `header-filter`, with `X-Lab-Boundary: header-filter` through the boundary
    - `server-auth` / `14.2.24` / `server-auth`
    - guard-only fixture: `server-auth` / `14.2.24` / `server-auth-guard-only`
  - `tests/targets.test.mjs`: 19 passed, 0 failed, 0 skipped. It covers identity; anonymous-normal, including RSC; two invalid-session forms; valid session, the logout cookie clear (name, `Max-Age=0`, `Path`), wrong credentials and cross-origin login on all four targets; all 12 cross-target cookie pairs; boundary rejection, including alongside a valid session; and the guard-only fixture.
  - The guard-only fixture had no middleware, so the guard alone decided:
    - anonymous and invalid sessions got `307` to `/lab/server-auth/login?denied=server-auth` and `401` with `"layer": "server-auth"`;
    - RSC requests got a `200 text/x-component` payload carrying the same redirect;
    - no denial contained the marker, and a valid session was admitted.
  - M1's `tests/baseline.test.mjs`, run through the unchanged control plane against the default `vulnerable` build: 2 passed, 0 failed.
- **Health readiness** on the local `server-auth` build:
  - 11-character password and secret (the size of the M4 example placeholders): `503`, `"ready": false`;
  - a 31-character secret: `503`;
  - real generated values: `200`, `"ready": true`.
- **Compose config.** In a scratch mirror with freshly generated env files, printing only structure:
  - `docker compose config` passed for M1 alone, for the merged M1 + M4 files with and without `--profile check`, and for the merge with `.env.example` placeholders;
  - without the M4 variables, interpolation fails with the `init-env.mjs` instruction;
  - resolved build contexts are identical from `m1-lab/` and from the repository root;
  - the M1, M4 and merged files validate against the current compose-spec JSON schema.
- **init-env.mjs:**
  - exits 1 without M1's `.env`;
  - adds six variables (48-character passwords, 64-character secrets) and keeps mode `600`;
  - a rerun changes nothing;
  - it refuses with exit 1, leaving the file unchanged, for a copied `.env.example` and for a file where only M1's three secrets are placeholders.
- **Advisory.** Re-read 31 October 2026: 14.x is fixed in 14.2.25, and the advisory's workaround is to prevent external requests carrying `x-middleware-subrequest` from reaching the application.

## Independent review

1. **First attempt** (four lenses). It stopped at the account's usage limit before returning findings. Its security probes were recovered, and none used anything but the neutral header value.
   - They found no boundary bypass. Malformed framing, obsolete line folding, lookalike names, trailers, header floods, pipelining, Expect, HTTP/1.0 and request-target forms were all refused or harmless.
   - Across 312 probe requests on four runtimes (`vulnerable`, `patched`, `server-auth`, guard-only), no unauthorised response contained the marker. These ran on the earlier builds; later fixes did not change header detection or the guard.
   - They exposed two boundary defects, both now fixed and mutation-checked: a slow body held a slot for about 30 s, and client aborts were logged as `upstream-unavailable`.
2. **Second run.** Runtime, validity and docs lenses, then an adversarial verifier over all 17 findings. 14 were confirmed and fixed:
   - The guard-order check was vacuous when the guard was missing or inverted.
   - The shared build and runtime stages were unpinned.
   - The relay test checked only a header prefix.
   - The logout test did not check `Path`.
   - Health reported ready with too-short secrets.
   - `init-env.mjs` accepted M1 placeholders.
   - BuildKit's `InvalidDefaultArgInFrom` lint on the deliberate argless `FROM` is now skipped by a parser directive; the container builds showed no check warnings.
   - The contract lacked a same-run positive-control rule and an expected deciding layer for `anonymous-cve`.
   - A contract sentence described inputs of the CVE request. It is now neutral; the request stays with M3.
   - Several stale or overclaiming documentation sentences, including M1's README pointer to this receipt.

   Three findings were refuted: a writing-style judgement, intended `layer` semantics on boundary errors, and a speculative misbuild scenario that the pinned Compose arguments rule out.

## Not verified

- **The CVE request.** M4 did not run `anonymous-cve` against any target. This receipt claims no bypass or blocking result for the CVE; the contract's expected-outcome table is planned, not measured.
- **Browser.** M1's Playwright acceptance was not rerun because Playwright is not installed here. The rendered target label was checked over HTTP on all four targets.
- **Other Docker hosts.** Only Linux x86_64 with Docker Engine 29.9.2 was exercised; Docker Desktop on Windows or macOS and ARM64 hosts were not.
- **One-step `up --build`.** The README's single-command build was not run as such. The same images were built per service, then started with `up -d --wait`.
- **Peer review.** M1's review of the parameterization, M3's review of M4, and M5's independent repetition have not happened.

The machine owner installed Docker Engine and changed this account's `docker` group membership. Apart from that, this work changed no public service, host configuration or shared environment file. Builds, runtimes and secrets lived only in a temporary directory outside the repository; the only lasting artifacts are the eight lab images listed above.
