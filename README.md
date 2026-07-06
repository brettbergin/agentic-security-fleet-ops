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
    fallback_models=("anthropic:claude-sonnet-4-5",),  # retry here if the primary errors
    force_roles=("grc",),
    max_concurrency=5,
    temperature=0.1,             # steadier, more deterministic analysis
    max_tokens=4000,             # cap output length per agent
    per_agent_token_limit=200_000,  # hard budget guard; over-budget agents fail gracefully
))
result = await fleet.assess("...")
```

## CLI

```bash
asfops assess "We're adding a webhook receiver that executes user-supplied templates"
asfops roster                       # meet the department
asfops run threat-model "..."       # engage a single specialist
asfops models                       # check Copilot availability / list models
asfops dashboard                    # launch the Streamlit dashboard (needs the extra)
```

## Dashboard

A Streamlit dashboard over your run history (`~/.asfops/logs`): browse past assessments, a findings explorer (filter by severity/role), per-run severity + token charts, the roster, and a form to launch a new assessment. Install the optional extra and launch it:

```bash
pip install "asfops[dashboard]"
asfops dashboard            # opens http://localhost:8501
```

It reads the same structured logs the fleet already writes, so every `assess` run shows up automatically.

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

## Logging

Two separate logs are written per run, under one timestamped directory in
`~/.asfops/logs/` (created on first use; override the base with `--log-dir` or
the `ASFOPS_HOME` env var):

```
~/.asfops/logs/<UTC-timestamp>-<run_id>/
├── app.log                 # global application log (structlog JSON lines)
└── agents/
    ├── triage.json         # each agent's ENTIRE context…
    ├── appsec.json         # …full message history + model + usage + output
    ├── …
    └── synthesis.json
```

- **`app.log`** — application-wide lifecycle events (config, triage decision, per-agent start/finish/fail with token counts, synthesis, Copilot client start/stop, run totals), correlated by a fleet-level `run_id`.
- **`agents/<slug>.json`** — the complete context of one agent invocation (every specialist plus triage and synthesis): the full pydantic-ai message history (system prompt, user prompt, model response, retries) with a metadata header (model, token usage, duration, run_id, structured output).

Logging is **on by default** and configurable:

```bash
asfops assess "…" --log-dir ./logs --log-level DEBUG   # custom location/verbosity
asfops assess "…" --no-logs                            # disable entirely
```

```python
from pathlib import Path
from asfops import Fleet, FleetConfig, LoggingConfig

fleet = Fleet(FleetConfig(logging=LoggingConfig(base_dir=Path("./logs"), level="DEBUG")))
```

Logging auto-disables under pytest so test runs stay clean. `asfops.get_logger(__name__)` exposes the same structlog logger for your own code.

## Development

```bash
uv sync --group dev
uv run pytest --cov=asfops
uv run ruff format --check . && uv run ruff check .
uv run mypy src tests
```

Releases are **fully automated**: every merge to `main` auto-bumps the patch version, tags it, builds, and publishes to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/). The version comes from the git tag ([`hatch-vcs`](https://github.com/ofek/hatch-vcs)) — never hand-edited. See [RELEASING.md](RELEASING.md).

## License

MIT
