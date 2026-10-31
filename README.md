# SE6013 Software Security: Next.js authentication bypass

Group project workspace for studying CVE-2025-29927.

Maintainer: [@sodiptabadiabanurea](https://github.com/sodiptabadiabanurea).

## Contributing

Members work in their own forks and open pull requests against `main`. Members do not receive write access to this repository. Only the maintainer reviews and merges contributions.

Every member PR must include their full name and matriculation number. Missing or incomplete fields fail the required `Contributor identity` check and block normal merging. Completing the fields does not approve the code: the maintainer must also verify the identity and review the changes.

This repository and its pull requests are public.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the fork and PR steps.

## Repository controls

- `main` requires the identity status check and one approval from its code owner, @sodiptabadiabanurea.
- New code commits dismiss stale approvals; review conversations must be resolved.
- Force pushes and deletion of `main` are disabled.
- Members cannot push or merge into this repository. They push only to their own forks.
- The owner retains GitHub administrator override for owner-authored maintenance. This is not available to group members.

The identity check tests completed fields and basic identifier shape. It does not query university records or prove a person's identity. The maintainer checks authenticity before approval.

## Current contents

M1 is available in [m1-lab/](m1-lab/README.md): the Next.js 14.2.24 example application, independent operator-gated panel, isolated Docker Compose package and setup/shutdown instructions. The shared M3/M4 interface is in [docs/contracts.md](docs/contracts.md).

M4 is in [m4-remediation/](m4-remediation/README.md): the Next.js 14.2.25 `patched` target and the separate `header-filter` and `server-auth` defence profiles, built from M1's application source, with regression and profile-isolation checks.

Apart from M4's work in m4-remediation/, only the existing M1 contribution was imported. Other members' earlier code, private environment files and the old repository history are not included. The M3 runner and M5 evaluation remain separate work.

Start from the repository root:

```sh
cd m1-lab
node deploy/init-env.mjs
docker compose up --build -d --wait
```

Open `http://127.0.0.1:4317`. Follow the M1 README for the separate operator and target logins and local configuration.

No lab is deployed, and no CVE experiment or remediation result is claimed by this repository setup.

## Local checks

```sh
python3 -m unittest discover -s tests -v
```

The identity workflow runs trusted code from the base repository only. It never checks out or executes contributor code while holding the status-writing token.
