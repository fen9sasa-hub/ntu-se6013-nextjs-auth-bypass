# M1: application, shared panel and local lab package

This contribution implements Member 1's scope for **Next.js CVE-2025-29927** in `sodiptabadiabanurea/ntu-se6013-nextjs-auth-bypass`, following the confirmed SE6013 Software Security plan. It is not the separate SMS spam project or the React2Shell case.

## What works in this contribution

- A real production build of Next.js `14.2.24`, pinned with React `18.3.1` and a committed dependency lockfile.
- Public page, target login/logout, protected dashboard and records JSON, with explicitly fictional records.
- Server-issued, HMAC-verified, target-specific sessions with a 15-minute expiry. A cookie's presence alone is not authentication.
- A separate operator-gated control plane, implemented with Node built-ins rather than the vulnerable framework.
- Shared panel shell with target selection, real identity/health checking, an application view and honest not-installed/error/pending states.
- An isolated Compose package, resource limits, shutdown instructions and a later-deployment handoff.
- Real baseline HTTP, session, gateway and browser acceptance checks.

No M3 attack runner, evidence exporter, comparison engine, M4 patched target, extra defence or M5 independent study is implemented here. Those slots are visibly labelled, not disguised as working features. The panel always says `Not run` for experiments.

## Requirements

Docker Engine/Desktop with Compose v2 or later and support for isolated bridge gateway mode (Docker 28 or later recommended). The exercised environment uses Linux ARM64, Docker 29 and Compose v5. Node 22 is the recommended host runtime for the small setup/test helpers; application and control runtime images use a pinned Node 22 image digest. The helpers also execute on the existing Node 18.19.1 host used for the local HTTP checks. Native Windows/macOS execution is not yet independently verified; Docker Desktop must use Linux containers.

Python/Playwright is only needed for automated browser acceptance, not to run the application. No external LLM/API key, database or cloud account is needed.

## Start from a clean checkout

From the repository root:

```sh
cd m1-lab
node deploy/init-env.mjs
docker compose config --quiet
docker compose up --build -d --wait
```

Open `http://127.0.0.1:4317`. The browser first asks for the operator login. Read `CONTROL_USER` and `CONTROL_PASSWORD` locally from `m1-lab/.env`. The passwords are randomly generated, separate and never committed.

The target application has a second login. Inside it, use `LAB_USER` and `LAB_PASSWORD` from the same private file. Operator authentication does not grant a target session.

If the port is busy, change both `LAB_PORT` and `LAB_PUBLIC_ORIGIN` before startup. Use exactly the configured origin. See [deployment handoff](deploy/README.md) for boundaries and rollback.

## First worked flow

1. Open the control panel and check that the selected target is `vulnerable`, the profile is `middleware-only`, and the observed framework is `Next.js 14.2.24`.
2. From the public target page, open the protected dashboard. Without a target session it returns to the target login.
3. Try incorrect target credentials. The form reports failure and does not issue a target session.
4. Log in with the disposable target account. The dashboard displays clearly fictional records and marker `M1-FICTIONAL-RECORDS-ONLY`.
5. Open the records JSON. It contains the same fictional marker/data.
6. Log out and revisit the protected dashboard. Normal anonymous access is denied again.
7. Select each M4 target in the panel. Each says `Not installed`, not a claimed successful defence.

These are normal application checks, not the CVE reproduction. The browser gateway intentionally omits framework-internal headers and must not be used to measure the attack. M3's fixed runner will send controlled requests directly to the private target. See [shared contract](../docs/contracts.md).

## Tests

The [verification receipt](VERIFICATION.md) records the real checks and remaining gates.

With the lab running:

```sh
node deploy/check.mjs
```

This reads the local private environment in-process, runs the unit and real HTTP tests, and never prints credentials or cookie values. It tests normal anonymous denial, invalid credentials/cookie, valid session, protected content, logout, cross-origin rejection, operator authentication and unknown-route rejection. It does not attempt the CVE.

To run only unit checks without a running lab:

```sh
node --experimental-global-webcrypto --test tests/session.test.mjs tests/gateway.test.mjs
```

Optional browser checks, in a separate Python environment:

```sh
python -m venv .browser-venv
# Activate that environment using your OS's normal command.
python -m pip install playwright==1.49.0
python -m playwright install chromium
python tests/browser.py
```

On this Linux machine the browser was exercised using an already installed Python/Playwright environment, not an added application runtime dependency. Browser receipts and screenshots go to the gitignored `artifacts/` directory. Do not add private cookies or environment files to evidence. To repeat the genuine target-outage UI check, stop only `vulnerable`, run `python tests/browser.py --unavailable`, then start that target again and wait for health.

The optional Python virtual environment is local tooling. Keep it out of Git and out of the Docker build context.

## Design and extension points

[Design direction](DESIGN.md) records why the interface is compact, dark-teal, text-led and free of invented metrics. The application uses a contrasting light surface so students can distinguish the target from the surrounding control plane. Controls are labelled, keyboard-operable and mobile-sized. No external fonts or images are fetched.

[Shared contract](../docs/contracts.md) fixes the current paths, marker, target IDs and proposed scenario/evidence semantics. M2 reviews the setup; M3 co-reviews the integration boundary. Shared-file changes need coordination, not a second copied shell.

Target identity is fixed at build time. `LAB_TARGET_ID` and `LAB_PROFILE` in `app/next.config.mjs` set the target ID, base path, cookie name and health profile; with no build args, this is the `vulnerable` target exactly as before. M4 builds its targets from this same source; see [m4-remediation](../m4-remediation/README.md). The health route also now reports not-ready when the password or signing secret is shorter than the handlers accept. This parameterisation (31 October) has been re-checked in Docker: the images built, the merged lab started healthy, and `node deploy/check.mjs` passed 8 of 8 against it (see [M4's receipt](../m4-remediation/VERIFICATION.md)). The Playwright browser checks in this directory's [VERIFICATION.md](VERIFICATION.md) predate it and were not rerun. M1's own review of the change is still pending.

## Session and environment limits

Sessions are signed bearer tokens, not an enterprise identity system. Logout deletes the current browser's cookie; a previously copied token remains valid until its 15-minute expiry or target signing-key rotation. Session revocation/persistence and per-user access roles are not claimed. A new target requires its own cookie name/path and signing secret. Never share the operator or target credentials with another profile.

The deliberately vulnerable profile checks access only in middleware. The dashboard and records handler intentionally lack independent backend authorisation; adding it here would contaminate M4's separate server-auth comparison. There are no protected-data mutations or real personal records.

The two runtime containers run non-root, read-only and without host mounts or privileged access. Only the operator panel is bound to a host loopback port. The vulnerable target has no published port, no edge-network attachment and no default route. These controls reduce the scope of this lab; they are not a claim that a container is a complete sandbox for arbitrary code execution.

Next.js `14.2.24` is an intentionally historical vulnerable dependency, not a production recommendation. `14.2.25` is the advisory's historical first fix for this CVE on 14.x, not advice about current production security. Public deployment, a team hostname, trusted HTTPS, independent reviewer acceptance and the full attack/defence comparison remain separate work.

This is runnable lab code and internal handoff documentation, not generated assessed report or presentation text. Each member writes and explains their own assessed contribution. GitHub activity supplements the course's required Knowledge Forum activity.

## Primary sources

- [Vendor advisory, GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [Vendor middleware-bypass postmortem](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)
- [Original researcher disclosure](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware)

The vendor advisory and postmortem were read on 27 October 2026. Root-cause tracing and the final source/patch explanation belong to M2 and M4.
