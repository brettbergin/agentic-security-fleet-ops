from __future__ import annotations

from typing import Literal

import pytest
from pydantic_ai.models import Model
from pydantic_ai.models.test import TestModel

from asfops.config import FleetConfig
from asfops.exceptions import TriageError
from asfops.fleet.schemas import RoleSelection, SynthesisSummary, TriageDecision
from asfops.orchestrator import Orchestrator

from .conftest import (
    ConcurrencyTracker,
    ConcurrencyTrackingModel,
    failing_model,
    scripted_model,
)


def triage_decision(
    *slugs: str, priority: Literal["primary", "supporting"] = "primary"
) -> TriageDecision:
    return TriageDecision(
        selected=[RoleSelection(slug=s, rationale=f"needs {s}", priority=priority) for s in slugs],
        overall_rationale="scripted",
    )


def config(
    *,
    triage: Model | str = "test",
    default: Model | str = "test",
    synthesis: Model | str | None = None,
    **kw: object,
) -> FleetConfig:
    return FleetConfig(
        default_model=default,
        triage_model=triage,
        synthesis_model=synthesis,
        **kw,  # type: ignore[arg-type]
    )


async def test_triage_reconciles_unknown_and_exclude() -> None:
    orch = Orchestrator(
        config(
            triage=scripted_model(triage_decision("appsec", "threat-model", "not-a-real-role")),
            exclude_roles=("appsec",),
        )
    )
    decision = await orch.triage("do a review")
    assert [s.slug for s in decision.selected] == ["threat-model"]


async def test_force_roles_added() -> None:
    orch = Orchestrator(
        config(triage=scripted_model(triage_decision("appsec")), force_roles=("grc",))
    )
    decision = await orch.triage("x")
    assert {s.slug for s in decision.selected} == {"appsec", "grc"}


async def test_empty_triage_fallback() -> None:
    orch = Orchestrator(config(triage=scripted_model(triage_decision())))
    decision = await orch.triage("x")
    assert {s.slug for s in decision.selected} == {
        "security-architect",
        "threat-model",
        "appsec",
    }


async def test_empty_triage_error_mode() -> None:
    orch = Orchestrator(config(triage=scripted_model(triage_decision()), on_empty_triage="error"))
    with pytest.raises(TriageError):
        await orch.triage("x")


async def test_fan_out_partial_failure_keeps_others() -> None:
    orch = Orchestrator(config(model_overrides={"appsec": failing_model("agent exploded")}))
    results = await orch.fan_out(triage_decision("appsec", "threat-model"), "review")
    by_slug = {r.role_slug: r for r in results}
    assert by_slug["appsec"].report is None
    assert by_slug["appsec"].error is not None
    assert "agent exploded" in by_slug["appsec"].error
    assert by_slug["threat-model"].report is not None


async def test_concurrency_is_bounded() -> None:
    tracker = ConcurrencyTracker()
    orch = Orchestrator(config(default=ConcurrencyTrackingModel(tracker), max_concurrency=2))
    decision = triage_decision("appsec", "threat-model", "grc", "privacy", "iam")
    await orch.fan_out(decision, "x")
    assert tracker.peak <= 2
    assert tracker.peak >= 1


async def test_full_run_produces_report_and_metadata() -> None:
    orch = Orchestrator(
        config(
            triage=scripted_model(triage_decision("appsec", "threat-model")),
            default=TestModel(),
            synthesis=scripted_model(
                SynthesisSummary(
                    executive_summary="all good",
                    top_risks=["risk a"],
                    recommended_next_steps=["do x"],
                )
            ),
        )
    )
    result = await orch.run("Assess our upload service")
    assert "# Security Fleet Assessment" in result.report_md
    assert "## Executive Summary" in result.report_md
    assert "all good" in result.report_md
    assert result.metadata is not None
    # triage + 2 agents + synthesis all counted
    assert result.metadata.grand_total.requests >= 4
    assert any(u.slug == "triage" for u in result.metadata.per_agent)
    assert any(u.slug == "synthesis" for u in result.metadata.per_agent)
    assert {r.role_slug for r in result.agent_results} == {"appsec", "threat-model"}
    assert result.synthesis is not None


async def test_events_emitted() -> None:
    from asfops.results import FleetEvent

    events: list[FleetEvent] = []
    orch = Orchestrator(
        config(
            triage=scripted_model(triage_decision("appsec")),
            default=TestModel(),
            synthesis=scripted_model(
                SynthesisSummary(executive_summary="s", top_risks=[], recommended_next_steps=[])
            ),
        )
    )
    await orch.run("x", on_event=events.append)
    kinds = [e.kind for e in events]
    assert "triage_started" in kinds
    assert "agent_started" in kinds
    assert "agent_finished" in kinds
    assert "synthesis_finished" in kinds
