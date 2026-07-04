# asfops — Agentic Security Fleet Ops

[![CI](https://github.com/brettbergin/agentic-security-fleet-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/brettbergin/agentic-security-fleet-ops/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/asfops.svg)](https://pypi.org/project/asfops/)
[![Python](https://img.shields.io/pypi/pyversions/asfops.svg)](https://pypi.org/project/asfops/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An entire security department as a fleet of LLM agents. Give `asfops` any security-relevant input — a code change, a design doc, an incident description, a compliance question — and the **Security Orchestrator** decides which security specialists should weigh in, runs them in parallel, and composes their findings into a single comprehensive markdown report.

Built on [pydantic-ai](https://ai.pydantic.dev/), with the [GitHub Copilot SDK](https://github.com/github/copilot-sdk) exposed as a first-class pydantic-ai provider (`CopilotModel`) — so the fleet runs on your GitHub Copilot subscription by default, or on any pydantic-ai model (OpenAI, Anthropic, …) you choose.

## Install

```bash
pip install asfops
# or
uv add asfops
```

## Quickstart

```python
import asfops

result = asfops.assess_sync(
    "Review this design: a public REST API that accepts file uploads "
    "to S3 using presigned URLs, authenticated with long-lived API keys."
)

print(result.report_md)          # the composed security report
print(result.triage.selected)    # which specialists were engaged, and why
print(result.metadata)           # per-agent model + token usage, per-model totals
```

Async, with configuration:

```python
from asfops import Fleet, FleetConfig

fleet = Fleet(FleetConfig(
    default_model="copilot:claude-sonnet-4.5",   # any pydantic-ai model ref works too
    model_overrides={"threat-model": "anthropic:claude-sonnet-4-5"},
    force_roles=("grc",),
    max_concurrency=5,
))
result = await fleet.assess("...")
```

## CLI

```bash
asfops assess "We're adding a webhook receiver that executes user-supplied templates"
asfops roster                       # meet the department
asfops run threat-model "..."       # engage a single specialist
asfops models                       # check Copilot availability / list models
```

## The fleet

17 specialists covering the modern security department: Product Security, Security Architecture, Threat Modeling, AppSec, Cloud Security, IAM, Pen Testing, Red Team, Bug Bounty, Vulnerability Management, Supply Chain Security, Threat Detection, SOC, Incident Response/DFIR, GRC & Compliance, Privacy, and CISO-level leadership framing. `asfops roster` shows each role's charter.

## Authentication

By default the fleet runs on the GitHub Copilot runtime (bundled CLI, auto-downloaded). You need a GitHub Copilot subscription and one of:

- being logged in via `gh auth login` / Copilot CLI, or
- `COPILOT_GITHUB_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN` set.

No Copilot? Point the fleet at any pydantic-ai provider: `FleetConfig(default_model="openai:gpt-5.2")` or `anthropic:claude-sonnet-4-5` with the corresponding API key.

## Result metadata

Every `FleetResult` optionally includes (`include_metadata=True`, default):

- per-agent: role, resolved model id, input/output/cache token counts, duration
- totals per model, plus a grand total across the whole assessment

## Development

```bash
uv sync --group dev
uv run pytest --cov=asfops
uv run ruff format --check . && uv run ruff check .
uv run mypy src tests
```

Releases: bump `src/asfops/_version.py`, tag `vX.Y.Z`, push the tag — GitHub Actions publishes to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/).

## License

MIT
