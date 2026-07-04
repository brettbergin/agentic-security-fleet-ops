from __future__ import annotations

import json
import sys
from typing import Any

import pytest
from pydantic_ai.models.test import TestModel
from typer.testing import CliRunner

from asfops import FleetConfig
from asfops.cli.app import app
from asfops.fleet.schemas import RoleSelection, SynthesisSummary, TriageDecision

from .conftest import scripted_model

# The package attribute `asfops.cli.app` is the Typer instance (exported by the
# package __init__), which shadows the submodule; fetch the real module here.
cli = sys.modules["asfops.cli.app"]

runner = CliRunner()


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force every Fleet built by the CLI to run fully offline."""
    orig_init = cli.Fleet.__init__

    def patched_init(self: Any, config: FleetConfig | None = None, **kw: Any) -> None:
        cfg = config or FleetConfig()
        cfg.default_model = TestModel()
        cfg.triage_model = scripted_model(
            TriageDecision(
                selected=[RoleSelection(slug="appsec", rationale="c", priority="primary")],
                overall_rationale="scripted",
            )
        )
        cfg.synthesis_model = scripted_model(
            SynthesisSummary(executive_summary="exec", top_risks=[], recommended_next_steps=[])
        )
        orig_init(self, cfg, **kw)

    monkeypatch.setattr(cli.Fleet, "__init__", patched_init)


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_roster_table() -> None:
    result = runner.invoke(app, ["roster"])
    assert result.exit_code == 0
    assert "appsec" in result.stdout


def test_roster_json() -> None:
    result = runner.invoke(app, ["roster", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data) == 17
    assert {"slug", "name", "charter", "tags"} <= set(data[0])


def test_assess_json(offline: None) -> None:
    result = runner.invoke(app, ["assess", "review my api", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["request"] == "review my api"
    assert data["report_md"].startswith("# Security Fleet Assessment")


def test_assess_markdown_to_file(offline: None, tmp_path: Any) -> None:
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["assess", "review", "--output", str(out)])
    assert result.exit_code == 0
    assert out.read_text().startswith("# Security Fleet Assessment")


def test_run_single_role(offline: None) -> None:
    result = runner.invoke(app, ["run", "threat-model", "model this", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["role_slug"] == "threat-model"


def test_run_unknown_role(offline: None) -> None:
    result = runner.invoke(app, ["run", "bogus", "x"])
    assert result.exit_code == 2


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    # no_args_is_help prints usage; exit code is 0 or 2 depending on typer version
    assert "assess" in result.stdout


def test_assess_markdown_stdout(offline: None) -> None:
    result = runner.invoke(app, ["assess", "review my api"])
    assert result.exit_code == 0
    assert "Security Fleet Assessment" in result.stdout


def test_assess_no_metadata(offline: None) -> None:
    result = runner.invoke(app, ["assess", "review", "--no-metadata", "--quiet"])
    assert result.exit_code == 0


def test_assess_forced_and_excluded_roles(offline: None) -> None:
    result = runner.invoke(
        app,
        ["assess", "review", "--role", "grc", "--exclude", "iam", "-c", "3", "--format", "json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    slugs = {r["role_slug"] for r in data["agent_results"]}
    assert "grc" in slugs
    assert "iam" not in slugs


def test_assess_from_file(offline: None, tmp_path: Any) -> None:
    req = tmp_path / "req.txt"
    req.write_text("assess this design")
    result = runner.invoke(app, ["assess", "--file", str(req), "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["request"] == "assess this design"


def test_models_handles_unavailable_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    import copilot

    class BrokenClient:
        def __init__(self, **kw: Any) -> None: ...

        async def start(self) -> None:
            raise RuntimeError("no auth")

        async def stop(self) -> None: ...

    monkeypatch.setattr(copilot, "CopilotClient", BrokenClient)
    result = runner.invoke(app, ["models"])
    assert result.exit_code == 0
    assert "unavailable" in result.stdout.lower() or "pydantic-ai model" in result.stdout


def test_models_lists_available(monkeypatch: pytest.MonkeyPatch) -> None:
    import copilot

    class Info:
        id = "claude-sonnet-4.5"

    class OkClient:
        def __init__(self, **kw: Any) -> None: ...

        async def start(self) -> None: ...

        async def list_models(self) -> list[Info]:
            return [Info()]

        async def stop(self) -> None: ...

    monkeypatch.setattr(copilot, "CopilotClient", OkClient)
    result = runner.invoke(app, ["models"])
    assert result.exit_code == 0
    assert "copilot:claude-sonnet-4.5" in result.stdout
