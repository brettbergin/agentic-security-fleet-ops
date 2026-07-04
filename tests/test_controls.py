"""Tests for the pydantic-ai control features: model settings, usage limits,
output validators, and fallback models."""

from __future__ import annotations

import pytest
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.test import TestModel

from asfops.config import FleetConfig
from asfops.exceptions import CopilotRuntimeError
from asfops.fleet.member import build_agent, validate_report
from asfops.fleet.roles import REGISTRY
from asfops.fleet.schemas import AgentReport, Finding, Severity, SynthesisSummary
from asfops.orchestrator import Orchestrator

from .conftest import scripted_model
from .test_orchestrator import config as orch_config
from .test_orchestrator import triage_decision

# --- config builders ---------------------------------------------------------


def test_model_settings_none_by_default() -> None:
    assert FleetConfig().model_settings() is None


def test_model_settings_built_from_fields() -> None:
    cfg = FleetConfig(temperature=0.1, max_tokens=2000)
    settings = cfg.model_settings()
    assert settings == {"temperature": 0.1, "max_tokens": 2000}


def test_usage_limits_none_by_default() -> None:
    assert FleetConfig().usage_limits() is None


def test_usage_limits_built() -> None:
    limits = FleetConfig(per_agent_token_limit=5000).usage_limits()
    assert limits is not None
    assert limits.total_tokens_limit == 5000


# --- output validator --------------------------------------------------------


def _report(*, summary: str, findings: list[Finding]) -> AgentReport:
    return AgentReport(summary=summary, findings=findings, confidence="high")


def test_validator_rejects_actionable_finding_without_recommendation() -> None:
    from pydantic_ai import ModelRetry

    report = _report(
        summary="s",
        findings=[
            Finding(title="SQLi", severity=Severity.critical, description="d", recommendation="  ")
        ],
    )
    with pytest.raises(ModelRetry, match="critical"):
        validate_report(report)


def test_validator_rejects_findings_without_summary() -> None:
    from pydantic_ai import ModelRetry

    report = _report(
        summary="   ",
        findings=[Finding(title="x", severity=Severity.low, description="d", recommendation="fix")],
    )
    with pytest.raises(ModelRetry, match="summary"):
        validate_report(report)


def test_validator_passes_good_report() -> None:
    report = _report(
        summary="ok",
        findings=[
            Finding(title="x", severity=Severity.high, description="d", recommendation="patch it")
        ],
    )
    assert validate_report(report) is report


async def test_agent_retries_on_invalid_report() -> None:
    # First reply has a critical finding with no recommendation -> ModelRetry;
    # second reply is valid. The agent should retry and return the fixed report.
    calls = {"n": 0}

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        calls["n"] += 1
        rec = "" if calls["n"] == 1 else "apply bound parameters"
        report = _report(
            summary="found sqli",
            findings=[
                Finding(
                    title="SQLi",
                    severity=Severity.critical,
                    description="unparameterized query",
                    recommendation=rec,
                )
            ],
        )
        return ModelResponse(parts=[TextPart(content=report.model_dump_json())])

    role = REGISTRY.get("appsec")
    agent: Agent[None, AgentReport] = build_agent(role, FunctionModel(fn))
    result = await agent.run("review")
    assert result.output.findings[0].recommendation == "apply bound parameters"
    assert calls["n"] == 2  # retried once


# --- fallback models ---------------------------------------------------------


def _boom_model(exc: Exception) -> FunctionModel:
    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        raise exc

    return FunctionModel(fn)


async def test_fallback_recovers_from_copilot_error() -> None:
    # Primary raises CopilotRuntimeError; the fallback TestModel takes over.
    cfg = FleetConfig(
        default_model=_boom_model(CopilotRuntimeError("copilot down")),
        fallback_models=(TestModel(),),
    )
    orch = Orchestrator(cfg)
    results = await orch.fan_out(triage_decision("appsec"), "review")
    assert results[0].report is not None  # fell back successfully


async def test_no_fallback_when_unconfigured() -> None:
    # Without fallbacks, a failing primary just yields a failed AgentResult.
    orch = Orchestrator(
        orch_config(model_overrides={"appsec": _boom_model(CopilotRuntimeError("down"))})
    )
    results = await orch.fan_out(triage_decision("appsec"), "review")
    assert results[0].report is None
    assert results[0].error is not None


async def test_usage_limit_fails_agent_gracefully() -> None:
    # A tiny token cap trips UsageLimitExceeded, which is caught per-agent.
    cfg = orch_config(default="test", synthesis=None)
    cfg.per_agent_token_limit = 1
    orch = Orchestrator(cfg)
    results = await orch.fan_out(triage_decision("appsec"), "review this API in detail")
    assert results[0].report is None
    assert results[0].error is not None


async def test_full_run_with_settings_and_limits_offline() -> None:
    # Settings + a generous limit should not disturb a normal offline run.
    cfg = orch_config(
        triage=scripted_model(triage_decision("appsec")),
        default=TestModel(),
        synthesis=scripted_model(
            SynthesisSummary(executive_summary="e", top_risks=[], recommended_next_steps=[])
        ),
    )
    cfg.temperature = 0.2
    cfg.max_tokens = 4000
    cfg.per_agent_token_limit = 1_000_000
    result = await Orchestrator(cfg).run("assess")
    assert result.synthesis is not None
    assert any(r.report is not None for r in result.agent_results)
