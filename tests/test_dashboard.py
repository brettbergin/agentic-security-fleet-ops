"""Tests for the dashboard data layer and launcher (Streamlit-free).

The Streamlit view (app.py) is exercised by an optional AppTest smoke test that
skips when streamlit isn't installed (it isn't in CI's dev group).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic_ai.models.test import TestModel

from asfops.dashboard import data as dash
from asfops.dashboard.launch import (
    DashboardNotInstalledError,
    build_command,
    launch,
)
from asfops.fleet.schemas import SynthesisSummary
from asfops.logs import LoggingConfig
from asfops.orchestrator import Orchestrator

from .conftest import scripted_model
from .test_orchestrator import config as orch_config
from .test_orchestrator import triage_decision


async def _make_run(tmp_path: Path) -> Path:
    """Produce a real run directory under tmp_path via an offline assessment."""
    cfg = orch_config(
        triage=scripted_model(triage_decision("appsec", "threat-model")),
        default=TestModel(),
        synthesis=scripted_model(
            SynthesisSummary(
                executive_summary="exec summary", top_risks=["r1"], recommended_next_steps=["s1"]
            )
        ),
        logging=LoggingConfig(base_dir=tmp_path, force=True, level="DEBUG"),
    )
    await Orchestrator(cfg).run("assess this design")
    return tmp_path


# --- data layer --------------------------------------------------------------


def test_list_runs_empty(tmp_path: Path) -> None:
    assert dash.list_runs(tmp_path) == []


async def test_parse_generated_run(tmp_path: Path) -> None:
    await _make_run(tmp_path)
    runs = dash.list_runs(tmp_path)
    assert len(runs) == 1
    run = runs[0]
    assert run.started_at is not None
    assert run.request_chars == len("assess this design")
    assert {a.slug for a in run.agents} == {"appsec", "threat-model"}
    assert run.triage is not None
    assert {s.slug for s in run.triage.selected} == {"appsec", "threat-model"}
    assert run.synthesis is not None and run.synthesis.executive_summary == "exec summary"
    assert run.failed == []
    assert run.ok_count == 2
    # rollups + row helpers are consistent
    assert run.total_input_tokens > 0
    assert isinstance(dash.finding_rows(run), list)
    usage = dash.usage_rows(run)
    assert {r["slug"] for r in usage} == {"appsec", "threat-model"}
    summary = dash.run_summary_rows(runs)[0]
    assert summary["agents"] == 2 and summary["failed"] == 0


async def test_summary_rows_shape(tmp_path: Path) -> None:
    await _make_run(tmp_path)
    rows = dash.run_summary_rows(dash.list_runs(tmp_path))
    assert rows and {"run", "agents", "findings", "tokens", "critical", "high"} <= set(rows[0])


def test_load_run_incomplete(tmp_path: Path) -> None:
    # A run that started but never finished (no run_finished, no synthesis).
    rd = tmp_path / "20260101T000000Z-deadbeef"
    (rd / "agents").mkdir(parents=True)
    (rd / "app.log").write_text(
        json.dumps(
            {
                "event": "run_started",
                "request_chars": 42,
                "run_id": "deadbeef",
                "timestamp": "2026-01-01T00:00:00Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (rd / "agents" / "appsec.json").write_text(
        json.dumps(
            {
                "slug": "appsec",
                "role_name": "AppSec",
                "model_id": "test:test",
                "status": "ok",
                "duration_s": 1.0,
                "usage": {"input_tokens": 10, "output_tokens": 5},
                "output": {"summary": "s", "findings": [], "confidence": "high"},
            }
        ),
        encoding="utf-8",
    )
    run = dash.load_run(rd)
    assert run.request_chars == 42
    assert run.synthesis is None
    assert run.duration_s is None
    assert run.agent_count == 1
    assert run.agents[0].report is not None


def test_load_run_tolerates_malformed_agent(tmp_path: Path) -> None:
    rd = tmp_path / "20260101T000000Z-cafef00d"
    (rd / "agents").mkdir(parents=True)
    (rd / "app.log").write_text('{"event": "run_started", "run_id": "x"}\n', encoding="utf-8")
    (rd / "agents" / "appsec.json").write_text("{ not json", encoding="utf-8")
    run = dash.load_run(rd)  # must not raise
    assert run.agents == []


# --- launcher ----------------------------------------------------------------


def test_build_command() -> None:
    cmd = build_command(port=9000, headless=True)
    assert "streamlit" in cmd and "run" in cmd
    assert "9000" in cmd
    assert cmd[-2:] == ["--server.headless", "true"]
    assert any(part.endswith("app.py") for part in cmd)

    # headless off omits the flag
    assert "--server.headless" not in build_command(port=8501, headless=False)


def test_launch_raises_when_streamlit_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import asfops.dashboard.launch as mod

    monkeypatch.setattr(mod, "streamlit_available", lambda: False)
    with pytest.raises(DashboardNotInstalledError, match="asfops\\[dashboard\\]"):
        launch()


def test_launch_invokes_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    import asfops.dashboard.launch as mod

    calls: list[list[str]] = []

    def fake_call(cmd: list[str]) -> int:
        calls.append(cmd)
        return 0

    monkeypatch.setattr(mod, "streamlit_available", lambda: True)
    monkeypatch.setattr(subprocess, "call", fake_call)
    assert launch(port=1234) == 0
    assert calls and "1234" in calls[0]


# --- optional Streamlit smoke (skips in CI where streamlit isn't installed) ---


def test_app_renders_all_pages() -> None:
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    from asfops.dashboard.launch import app_path

    at = AppTest.from_file(str(app_path()), default_timeout=30)
    at.run()
    assert not at.exception
    for page in ["Findings", "Usage", "Roster", "New assessment"]:
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, f"{page}: {at.exception}"
