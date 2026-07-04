# Contributing to asfops

## Development setup

```bash
uv sync --group dev
```

## Checks (what CI runs)

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest --cov=asfops --cov-report=term
```

All of the above must pass. Coverage is gated at 85%. Tests never require a
GitHub Copilot subscription — the Copilot SDK is faked and pydantic-ai's
`TestModel`/`FunctionModel` stand in for live models. Live tests are marked
`@pytest.mark.copilot` and are deselected by default; run them with
`uv run pytest -m copilot` once you're authenticated.

## Architecture

- `models/` — the `CopilotModel` pydantic-ai provider (Copilot SDK bridge),
  the shared client lifecycle, the fallback `CopilotBridge`, and model-ref
  resolution. All Copilot-SDK touchpoints live here.
- `fleet/` — role schemas, the role registry, the 17-role roster, and the
  per-member agent builder.
- `orchestrator.py` — triage → fan-out → synthesis.
- `results.py` — result models, usage aggregation, markdown report assembly.
- `api.py` — the public `Fleet` and module-level helpers.
- `cli/` — the typer + rich command-line interface.

## Releasing to PyPI (trusted publishing)

Publishing is automated via GitHub Actions using PyPI
[trusted publishing](https://docs.pypi.org/trusted-publishers/) (OIDC — no API
tokens stored).

**One-time setup (maintainer):**

1. On <https://pypi.org>, add a **pending publisher** for the project `asfops`:
   - Owner: `brettbergin`
   - Repository: `agentic-security-fleet-ops`
   - Workflow: `release.yml`
   - Environment: `pypi`
2. In the GitHub repo settings, create an **Environment** named `pypi`
   (optionally add required reviewers as a release gate).

**Each release:**

1. Bump the version in `src/asfops/_version.py`.
2. Commit, then tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The `Release` workflow builds the sdist/wheel and publishes to PyPI.
