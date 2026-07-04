# Releasing

Releases are **fully automated**. Every merge/push to `main` runs the test
suite, bumps the patch version, tags it, builds the package, and publishes it to
PyPI — no manual version edits, no tokens.

## How it works

1. A merge lands on `main` → [`.github/workflows/release.yml`](.github/workflows/release.yml) runs.
1. The test gate must pass (ruff format + lint, mypy, pytest with coverage).
1. The workflow finds the latest `vX.Y.Z` tag and computes the next **patch**
   version (`v0.2.0` → `v0.2.1`). With no tags yet, the first release is `v0.1.0`.
1. It creates and pushes that tag. [`hatch-vcs`](https://github.com/ofek/hatch-vcs)
   derives the package version from the tag, so nothing is committed back to `main`
   (`src/asfops/_version.py` is generated at build time and git-ignored).
1. `uv build` produces the sdist + wheel, which are published to PyPI via
   **Trusted Publishing (OIDC)** and attached to a GitHub Release.

Pull requests and non-`main` pushes are tested separately by
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) across Python 3.13–3.14,
so broken code never reaches `main`.

## One-time setup (already configured for asfops)

### PyPI Trusted Publishing

GitHub Actions publishes without an API token. On PyPI
(<https://pypi.org/manage/account/publishing/>) the project `asfops` has a
trusted publisher bound to:

| Field             | Value                        |
| ----------------- | ---------------------------- |
| PyPI Project Name | `asfops`                     |
| Owner             | `brettbergin`                |
| Repository name   | `agentic-security-fleet-ops` |
| Workflow name     | `release.yml`                |
| Environment name  | `pypi`                       |

The publish job declares `environment: pypi`, which must match the binding
above. A matching `pypi` GitHub Environment exists in repo settings (add
required reviewers there if you want a manual release gate).

### Tag pushes

The workflow pushes tags with the built-in `GITHUB_TOKEN` (granted
`contents: write`). This works out of the box unless a **tag protection rule**
blocks it — if so, allow `v*` tags to be created by Actions.

## Everyday use

Just merge to `main`. A new patch version ships automatically.

### Cutting a minor or major release

The workflow only auto-bumps the **patch** segment. To move the minor or major,
create the tag yourself once; the next merge continues from there:

```bash
git tag -a v0.3.0 -m "Release v0.3.0"
git push origin v0.3.0        # publishes v0.3.0; the next merge -> v0.3.1
```

(Or run the **Release** workflow from the Actions tab via `workflow_dispatch`
after pushing the tag — it detects HEAD is already tagged and skips re-tagging.)

## Local sanity check

```bash
uv build            # version comes from `git describe`; a dev tree -> X.Y.Z.devN
uv run asfops version
```
