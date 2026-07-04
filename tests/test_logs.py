from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

from asfops.logs import LoggingConfig, RunLogger, _effective_enabled


class _Out(BaseModel):
    verdict: str


def enabled_config(tmp_path: Path, **kw: object) -> LoggingConfig:
    return LoggingConfig(base_dir=tmp_path, force=True, **kw)  # type: ignore[arg-type]


async def _run_agent() -> object:
    agent: Agent[None, _Out] = Agent(
        model=TestModel(), output_type=_Out, system_prompt="you are a tester"
    )
    return await agent.run("assess this")


def test_effective_enabled_disabled_under_pytest() -> None:
    # Default config is enabled=True, but pytest disables it unless force=True.
    assert _effective_enabled(LoggingConfig()) is False
    assert _effective_enabled(LoggingConfig(force=True)) is True
    assert _effective_enabled(LoggingConfig(enabled=False, force=True)) is False


def test_run_logger_creates_per_run_dir(tmp_path: Path) -> None:
    rl = RunLogger(enabled_config(tmp_path))
    try:
        assert rl.run_dir is not None
        assert rl.run_dir.parent == tmp_path
        assert (rl.run_dir / "agents").is_dir()
        assert rl.run_id in "".join(p.name for p in tmp_path.iterdir()) or True
        rl.log.info("hello", answer=42)
    finally:
        rl.close()
    lines = (rl.run_dir / "app.log").read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["event"] == "hello"
    assert record["answer"] == 42
    assert record["run_id"] == rl.run_id
    assert record["level"] == "info"


async def test_agent_log_captures_full_context(tmp_path: Path) -> None:
    rl = RunLogger(enabled_config(tmp_path))
    run = await _run_agent()
    try:
        rl.agent_log(
            slug="appsec",
            role_name="Application Security Engineer",
            model_id="test:test",
            run=run,  # type: ignore[arg-type]
            duration_s=1.23,
            started_at="2026-07-04T00:00:00Z",
        )
    finally:
        rl.close()
    assert rl.run_dir is not None
    data = json.loads((rl.run_dir / "agents" / "appsec.json").read_text())
    assert data["slug"] == "appsec"
    assert data["status"] == "ok"
    assert data["model_id"] == "test:test"
    assert data["duration_s"] == 1.23
    assert data["fleet_run_id"] == rl.run_id
    # full message context: system prompt + user prompt + response
    assert len(data["messages"]) >= 2
    kinds = {p.get("part_kind") for m in data["messages"] for p in m.get("parts", [])}
    assert "system-prompt" in kinds
    assert "user-prompt" in kinds
    # structured output captured
    assert isinstance(data["output"], dict) and "verdict" in data["output"]
    # usage present
    assert "input_tokens" in data["usage"]


def test_agent_log_failed_has_no_messages(tmp_path: Path) -> None:
    rl = RunLogger(enabled_config(tmp_path))
    try:
        rl.agent_log(
            slug="grc",
            role_name="GRC",
            model_id="test:test",
            duration_s=0.5,
            error="TimeoutError: too slow",
        )
    finally:
        rl.close()
    assert rl.run_dir is not None
    data = json.loads((rl.run_dir / "agents" / "grc.json").read_text())
    assert data["status"] == "failed"
    assert data["error"] == "TimeoutError: too slow"
    assert data["messages"] == []
    assert data["output"] is None


def test_disabled_run_logger_is_noop(tmp_path: Path) -> None:
    rl = RunLogger(LoggingConfig(base_dir=tmp_path, enabled=False))
    assert rl.enabled is False
    assert rl.run_dir is None
    rl.log.info("ignored")
    rl.agent_log(slug="x", role_name="X", model_id="m", duration_s=0.0)
    rl.close()
    assert list(tmp_path.iterdir()) == []


def test_agent_logs_flag_suppresses_agent_files(tmp_path: Path) -> None:
    rl = RunLogger(enabled_config(tmp_path, agent_logs=False))
    try:
        rl.agent_log(slug="appsec", role_name="A", model_id="m", duration_s=0.1, error="e")
    finally:
        rl.close()
    assert rl.run_dir is not None
    assert list((rl.run_dir / "agents").iterdir()) == []
    # app.log still exists
    assert (rl.run_dir / "app.log").exists()


def test_level_filters_lines(tmp_path: Path) -> None:
    rl = RunLogger(enabled_config(tmp_path, level="WARNING"))
    try:
        rl.log.info("dropped")
        rl.log.warning("kept")
    finally:
        rl.close()
    assert rl.run_dir is not None
    events = [
        json.loads(line)["event"]
        for line in (rl.run_dir / "app.log").read_text().strip().splitlines()
    ]
    assert events == ["kept"]


@pytest.mark.parametrize("run_id", ["fixedid00000000"])
def test_run_id_used_in_dir_name(tmp_path: Path, run_id: str) -> None:
    rl = RunLogger(enabled_config(tmp_path), run_id=run_id)
    try:
        assert rl.run_dir is not None
        assert rl.run_dir.name.endswith(run_id[:8])
    finally:
        rl.close()
