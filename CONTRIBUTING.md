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

## Releasing to PyPI

Releases are **fully automated** — see [RELEASING.md](RELEASING.md). In short:
every merge to `main` runs the test gate, auto-bumps the **patch** version by
creating a new `vX.Y.Z` tag, and publishes to PyPI via trusted publishing.
[`hatch-vcs`](https://github.com/ofek/hatch-vcs) derives the package version from
the tag, so `src/asfops/_version.py` is **generated at build time** and never
hand-edited. To move the minor/major, push that tag once yourself; the next
merge continues from there.
